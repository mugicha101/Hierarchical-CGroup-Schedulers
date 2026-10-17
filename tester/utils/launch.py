"""Place one process and wait for controller verification before exec."""

import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import sys

from .common import cgroup_cpus, workload_cgroup

POLICIES = {"other": os.SCHED_OTHER, "fifo": os.SCHED_FIFO, "rr": os.SCHED_RR, "ext": 7, "deadline": 6}


def set_weight(weight, *, tid=None):
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required for JLFP task weights")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_uint64]
  bpf.bpf_map_update_elem.restype = ctypes.c_int
  bpf.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
  bpf.bpf_map_lookup_elem.restype = ctypes.c_int
  fd = bpf.bpf_obj_get(b"/sys/fs/bpf/scx/task_weights")
  if fd < 0:
    raise OSError(ctypes.get_errno(), "open JLFP task_weights")
  try:
    # PIDFD_THREAD is O_EXCL in linux/pidfd.h; task storage is per task
    pidfd = os.pidfd_open(os.getpid()) if tid is None else os.pidfd_open(tid, os.O_EXCL)
    try:
      key, value = ctypes.c_int(pidfd), ctypes.c_uint64(weight)
      if bpf.bpf_map_update_elem(fd, ctypes.byref(key), ctypes.byref(value), 0):
        raise OSError(ctypes.get_errno(), "set JLFP task weight")
      actual = ctypes.c_uint64()
      if bpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(actual)) or \
          actual.value != weight:
        raise RuntimeError("JLFP weight did not read back correctly")
    finally:
      os.close(pidfd)
  finally:
    os.close(fd)


def main(request, ready_fd, gate_fd):
  settings = json.loads(Path(request).read_text())
  cgroup = workload_cgroup(settings["config"])
  cpus = set(settings["cpus"])
  if not cpus or not cpus <= cgroup_cpus(cgroup):
    raise ValueError("workload CPUs must be within the test cpuset")
  policy = settings["policy"]
  if policy == "deadline":
    raise ValueError("DEADLINE workloads must install explicit reservations after exec")
  if policy not in POLICIES:
    raise ValueError(f"unsupported workload policy: {policy}")
  priority, nice, weight = settings["priority"], settings["nice"], settings["weight"]
  priorities = range(1, 100) if policy in ("fifo", "rr") else (0,)
  if type(priority) is not int or priority not in priorities:
    raise ValueError("invalid policy priority")
  if type(nice) is not int or not -20 <= nice <= 19:
    raise ValueError("nice must be between -20 and 19")
  if weight is not None and (policy != "ext" or type(weight) is not int or
                             not 1 <= weight < (1 << 63)):
    raise ValueError("JLFP weight must be a positive 63-bit EXT weight")
  (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n")
  os.sched_setaffinity(0, cpus)
  os.setpriority(os.PRIO_PROCESS, 0, nice)
  if weight is not None:
    set_weight(weight)
  os.sched_setscheduler(0, POLICIES[policy], os.sched_param(priority))
  os.write(ready_fd, b"ready\n")
  os.close(ready_fd)
  go = os.read(gate_fd, 1)
  os.close(gate_fd)
  if go != b"g":
    raise RuntimeError("controller closed the workload gate")
  os.execv(settings["command"][0], settings["command"])


if __name__ == "__main__":
  try:
    main(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
  except Exception as error:
    print(f"workload setup failed: {error}", file=sys.stderr, flush=True)
    raise SystemExit(2)
