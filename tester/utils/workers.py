"""Build, configure and reap the shared native priority inversion workers."""

from contextlib import ExitStack
import ctypes
import ctypes.util
import os
from pathlib import Path
import subprocess
import tempfile

from .trace_helpers import REPO_DIR

SCHED_EXT = 7


def build_worker():
  source = REPO_DIR / "tester/work.c"
  binary = REPO_DIR / "tester/build/jlfp_worker"
  if not binary.exists() or binary.stat().st_mtime_ns < source.stat().st_mtime_ns:
    binary.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=binary.parent) as directory:
      built = Path(directory) / "worker"
      subprocess.run(["cc", "-O2", "-pthread", "-DSCHED_EXT=7", str(source),
                      "-lbpf", "-o", str(built)], check=True)
      built.replace(binary)
  return binary


def set_weights(workers):
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required to set task weights")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
  bpf.bpf_map_update_elem.restype = ctypes.c_int
  map_fd = bpf.bpf_obj_get(b"/sys/fs/bpf/scx/task_weights")
  if map_fd < 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), "/sys/fs/bpf/scx/task_weights")
  try:
    for process, weight in workers:
      pid_fd = os.pidfd_open(process.pid)
      try:
        key, value = ctypes.c_int(pid_fd), ctypes.c_uint64(weight)
        if bpf.bpf_map_update_elem(map_fd, ctypes.byref(key), ctypes.byref(value), 0) < 0:
          error = ctypes.get_errno()
          raise OSError(error, os.strerror(error), f"task weight for PID {process.pid}")
      finally:
        os.close(pid_fd)
      os.sched_setscheduler(process.pid, SCHED_EXT, os.sched_param(0))
  finally:
    os.close(map_fd)


def stop_workers(workers):
  # signal everyone before waiting so low-priority workers cannot delay cleanup
  for process, _ in workers:
    if process.poll() is None:
      process.terminate()
  for process, _ in workers:
    try:
      process.wait(timeout=3)
    except subprocess.TimeoutExpired:
      process.kill()
      process.wait()
    finally:
      process.stdin.close()
      process.stdout.close()


class TaskRTP(ctypes.Structure):
  _fields_ = [("period", ctypes.c_uint64), ("rel_dl", ctypes.c_uint64),
              ("is_periodic", ctypes.c_bool)]


def configure_workers(processes, workers):
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required to configure MC² workers")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
  bpf.bpf_map_update_elem.restype = ctypes.c_int
  with ExitStack() as maps:
    descriptors = {}
    for name in ("task_weights", "task_rtp_map"):
      fd = bpf.bpf_obj_get(f"/sys/fs/bpf/scx/{name}".encode())
      if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)
      maps.callback(os.close, fd)
      descriptors[name] = fd
    for process, _ in processes:
      worker = workers[process.pid]
      pid_fd = os.pidfd_open(process.pid)
      try:
        key = ctypes.c_int(pid_fd)
        if worker["policy"] == "scx_gedf":
          value = TaskRTP(worker["period_ns"], worker["period_ns"], False)
          name = "task_rtp_map"
        else:
          value = ctypes.c_uint64(worker["weight"])
          name = "task_weights"
        if bpf.bpf_map_update_elem(descriptors[name], ctypes.byref(key), ctypes.byref(value), 0) < 0:
          error = ctypes.get_errno()
          raise OSError(error, os.strerror(error), f"{name} for PID {process.pid}")
      finally:
        os.close(pid_fd)
      os.sched_setscheduler(process.pid, SCHED_EXT, os.sched_param(0))
      if os.sched_getscheduler(process.pid) != SCHED_EXT:
        raise RuntimeError(f"Worker {process.pid} did not enter SCHED_EXT")
