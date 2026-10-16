"""Root scheduler ownership and process-based workload sessions."""

import os
from pathlib import Path
import select
import subprocess
import sys
import time

from . import common
from .launch import POLICIES
from .tracing import Recording

SCX_ROOT = Path("/sys/kernel/sched_ext")


def root_state():
  state = {"state": (SCX_ROOT / "state").read_text().strip(),
           "enable_seq": int((SCX_ROOT / "enable_seq").read_text())}
  try:
    state["ops"] = (SCX_ROOT / "root/ops").read_text().strip()
  except FileNotFoundError:
    state["ops"] = None
  return state


def process_state(pid):
  root = Path("/proc") / str(pid)
  tasks = {}
  for path in sorted((root / "task").iterdir()):
    tid = int(path.name)
    tasks[tid] = {"policy": os.sched_getscheduler(tid),
                  "priority": os.sched_getparam(tid).sched_priority,
                  "nice": os.getpriority(os.PRIO_PROCESS, tid),
                  "cpus": sorted(os.sched_getaffinity(tid))}
  return {"pid": pid, "cgroup": (root / "cgroup").read_text().strip(), "tasks": tasks}


def verify_state(state, settings, cgroup):
  expected_group = "0::/" + str(cgroup.relative_to(common.CGROUP_ROOT))
  if state["cgroup"] != expected_group:
    raise RuntimeError(f"workload cgroup differs: {state['cgroup']}")
  if not state["tasks"]:
    raise RuntimeError("workload has no verifiable threads")
  expected = {"policy": POLICIES[settings["policy"]], "priority": settings["priority"],
              "nice": settings["nice"], "cpus": sorted(settings["cpus"])}
  for tid, task in state["tasks"].items():
    if task != expected:
      raise RuntimeError(f"task {tid} attributes differ: expected {expected}, got {task}")


class Workload:
  def __init__(self, session, command, cpus, policy, priority, nice, weight):
    self.session = session
    self.gate = None
    self.process = None
    self.settings = {"config": session.config, "command": list(map(str, command)),
                     "cpus": sorted(cpus), "policy": policy, "priority": priority,
                     "nice": nice, "weight": weight}
    self.request = session.workloads.directory / f"workload-{len(session.jobs):02d}.json"

  def start(self):
    session = self.session
    common.write_json(self.request, self.settings)
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    gate_r, self.gate = os.pipe2(os.O_CLOEXEC)
    try:
      self.process = session.workloads.start(
          [sys.executable, "-m", "tester.utils.launch", self.request, ready_w, gate_r],
          stdin=subprocess.PIPE, pass_fds=(ready_w, gate_r))
      self.log = session.workloads.directory / session.workloads.commands[-1]["log"]
      os.close(ready_w)
      ready_w = None
      os.close(gate_r)
      gate_r = None
      if not select.select([ready_r], [], [], session.timeout)[0] or \
          os.read(ready_r, 64) != b"ready\n":
        raise RuntimeError(f"workload setup did not become ready; see {self.log}")
      self.verify("prepared")
    finally:
      for fd in (ready_r, ready_w, gate_r):
        if fd is not None:
          os.close(fd)

  def verify(self, phase="running"):
    self.session.check()
    if self.process.poll() is not None:
      raise RuntimeError(f"workload exited before verification; see {self.log}")
    state = process_state(self.process.pid)
    common.write_json(self.request.with_name(self.request.stem + f"-{phase}.json"), state)
    verify_state(state, self.settings, self.session.cgroup)
    return state

  def release(self):
    self.verify("release")
    os.write(self.gate, b"g")
    os.close(self.gate)
    self.gate = None
    self.session.note("workload-released")

  def wait(self, timeout):
    deadline = time.monotonic() + timeout
    while self.process.poll() is None:
      self.session.check()
      if time.monotonic() >= deadline:
        raise TimeoutError(f"workload timed out; see {self.log}")
      time.sleep(.02)
    if self.process.returncode:
      raise RuntimeError(f"workload exited with {self.process.returncode}; see {self.log}")
    self.session.check()

  def close(self):
    if self.gate is not None:
      os.close(self.gate)
      self.gate = None
    if self.process is not None and self.process.stdin is not None:
      self.process.stdin.close()


class Session:
  def __init__(self, config, directory, scheduler=None, *, events=()):
    self.config = config
    self.directory = Path(directory)
    self.timeout = config["process_timeout_s"]
    self.cgroup, _ = common.placement(config)
    self.scheduler = scheduler
    self.root_process = None
    self.attached = None
    self.initial = None
    self.jobs = []
    self.history = []
    self.controller = None
    self.closed = False
    for name in ("workloads", "scheduler"):
      (self.directory / name).mkdir()
    self.workloads = common.Processes(self.directory / "workloads", self.timeout)
    self.schedulers = common.Processes(self.directory / "scheduler", self.timeout)
    self.recording = Recording(self.directory, events, self.timeout)

  def note(self, action, **details):
    self.history.append({"action": action, "time_ns": time.monotonic_ns(), **details})
    common.write_json(self.directory / "lifecycle.json", self.history)

  def check(self):
    self.recording.check()
    current = root_state()
    if self.scheduler is None:
      if current != self.initial:
        raise RuntimeError("EXT state changed during a native baseline")
    elif self.root_process.poll() is not None or current != self.attached:
      raise RuntimeError("root scheduler exited, detached or restarted during the workload")

  def start_workload(self, command, cpus, *, policy, priority, nice, weight=None):
    if policy not in POLICIES:
      raise ValueError(f"unsupported workload policy: {policy}")
    if not set(cpus) or not set(cpus) <= common.cgroup_cpus(self.cgroup):
      raise ValueError("workload CPUs must be within the test cpuset")
    if policy == "ext" and self.scheduler is None:
      raise ValueError("EXT workloads require an attached experiment scheduler")
    if weight is not None and (self.scheduler is None or self.scheduler["target"] != "jlfp"):
      raise ValueError("explicit task weights are only supported under JLFP")
    self.check()
    job = Workload(self, command, cpus, policy, priority, nice, weight)
    self.jobs.append(job)
    job.start()
    self.note("workload-prepared", pid=job.process.pid)
    return job

  def __enter__(self):
    try:
      self.initial = root_state()
      if self.initial["state"] != "disabled" or self.initial["ops"] is not None:
        raise RuntimeError("a root scheduler is already active; refusing to replace it")
      controller = common.controller_placement(self.config)
      controller.__enter__()
      self.controller = controller
      self.recording.start()
      self.note("recorder-ready" if self.recording.events else "tracing-disabled")
      if self.scheduler is not None:
        manifest = self.scheduler
        target = manifest["target"]
        if target not in ("jlfp", "qmap", "simple") or not manifest.get("partial_switch"):
          raise ValueError("scheduler must be a partial-switch experiment build")
        if common.sha256(manifest["binary"]) != manifest["binary_sha256"]:
          raise ValueError("scheduler binary differs from its build manifest")
        args = [manifest["binary"], *manifest["launch_args"]]
        custom = any(e.startswith("scxtp:") for e in self.recording.events)
        if custom:
          if target != "jlfp" or not manifest.get("flags", {}).get("SCXTP_TRACING"):
            raise ValueError("custom emissions require a tracing-enabled JLFP build")
          args.append("--trace")
        self.root_process = self.schedulers.start(args)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
          self.recording.check()
          if self.root_process.poll() is not None:
            raise RuntimeError("scheduler exited before attachment; see scheduler command log")
          current = root_state()
          if current["state"] == "enabled" and current["ops"] == target and \
              current["enable_seq"] == self.initial["enable_seq"] + 1:
            self.attached = current
            break
          if current["enable_seq"] > self.initial["enable_seq"] + 1:
            raise RuntimeError("root scheduler restarted during attachment")
          time.sleep(.02)
        if self.attached is None:
          raise TimeoutError("root scheduler attachment timed out")
        self.note("scheduler-attached", **self.attached)
      self.check()
      return self
    except BaseException:
      self.close()
      raise

  def close(self):
    if self.closed:
      return
    self.closed = True
    errors = []
    with common.cleanup_interrupts():
      for cleanup in (self.workloads.close, self._close_jobs, self._detach,
                      self.recording.close, self._restore_controller):
        try:
          cleanup()
        except Exception as error:
          errors.append(f"{cleanup.__name__}: {error}")
      self.note("cleanup-failed" if errors else "cleanup-complete", errors=errors)
    if errors:
      raise common.CleanupError("; ".join(errors))

  def _close_jobs(self):
    for job in self.jobs:
      job.close()
    self.note("workloads-stopped")

  def _detach(self):
    self.schedulers.close()
    if self.attached is not None:
      deadline = time.monotonic() + self.timeout
      while time.monotonic() < deadline:
        state = root_state()
        if state["enable_seq"] != self.attached["enable_seq"]:
          raise RuntimeError("scheduler identity changed before detach completed")
        if state["state"] == "disabled" and state["ops"] is None:
          self.note("scheduler-detached", **state)
          return
        time.sleep(.02)
      raise TimeoutError("owned root scheduler did not detach")

  def _restore_controller(self):
    if self.controller is not None:
      self.controller.__exit__(None, None, None)
      self.controller = None

  def __exit__(self, *_):
    self.close()
