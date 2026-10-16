"""Prepare and verify E1 cyclictest threads and stress-ng process groups."""

import errno
import os
from pathlib import Path
import time

from . import common, cyclictest, e1_config, lifecycle
from .launch import POLICIES, set_weight


def cyclic_command(binary, directory, config, scheduler):
  overhead = config["experiments"]["overhead"]
  settings = overhead["e1"]
  primary = e1_config.policy(settings, scheduler, "cyclictest")
  command = cyclictest.cyclic_command(
      binary=binary,
      output=directory,
      cpus={overhead["cyclictest_cpu"]},
      main_cpus=common.cgroup_cpus(common.workload_cgroup(config)),
      mode="pinned",
      threads=1,
      duration=int(config["duration_s"]),
      interval_us=settings["interval_us"],
      histogram_us=settings["histogram_us"],
      policy=primary["policy"],
      priority=primary["priority"],
  )
  return ["/usr/bin/env", f"CGS_E1_READY={directory / 'cyclictest.ready'}",
          f"CGS_E1_GATE={directory / 'cyclictest.gate'}", *command]


def wait_cyclic(session, job, directory, cpu, primary, timer_slack_ns):
  deadline = time.monotonic() + session.timeout
  ready = directory / "cyclictest.ready"
  while time.monotonic() < deadline:
    session.check()
    if job.process.poll() is not None:
      raise RuntimeError(f"cyclictest exited before readiness; see {job.log}")
    if ready.exists() and (value := ready.read_text()).endswith("\n"):
      tid = int(value.strip())
      state = lifecycle.process_state(job.process.pid)
      if tid == job.process.pid or set(state["tasks"]) != {job.process.pid, tid}:
        raise RuntimeError("cyclictest must have one main thread and one measurement thread")
      if primary["weight"] is not None:
        set_weight(primary["weight"], tid=tid)
      settings = {**primary, "cpus": [cpu]}
      lifecycle.verify_state({**state, "tasks": {tid: state["tasks"][tid]}}, settings, session.cgroup)
      main = state["tasks"][job.process.pid]
      if main != {"policy": os.SCHED_OTHER, "priority": 0, "nice": primary["nice"],
                  "cpus": sorted(common.cgroup_cpus(session.cgroup))}:
        time.sleep(.01)
        continue
      slack = int((Path("/proc") / str(tid) / "timerslack_ns").read_text())
      expected = 0 if primary["policy"] in ("fifo", "rr") else timer_slack_ns
      if slack != expected:
        raise RuntimeError(f"cyclictest timer slack differs: expected {expected}, got {slack}")
      common.write_json(directory / "cyclictest-threads.json", {**state, "measurement_tid": tid,
                        "timer_slack_ns": slack, "task_weight": primary["weight"]})
      return tid
    time.sleep(.01)
  raise TimeoutError("cyclictest did not reach its pre-measurement gate")


def group_members(groups):
  result = {pgid: [] for pgid in groups}
  for path in Path("/proc").iterdir():
    if not path.name.isdecimal():
      continue
    try:
      fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
      pgid = int(fields[2])
      if pgid in result and fields[0] not in ("Z", "X"):
        result[pgid].append(int(path.name))
    except (FileNotFoundError, ProcessLookupError):
      continue
  return result


def open_gate(session, directory):
  deadline = time.monotonic() + session.timeout
  while time.monotonic() < deadline:
    session.check()
    try:
      return os.open(directory / "cyclictest.gate", os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
      if error.errno != errno.ENXIO:
        raise
      time.sleep(.01)
  raise TimeoutError("cyclictest did not open its measurement gate")


class Stress:
  def __init__(self, session, directory, config, scheduler, binary):
    self.session, self.directory = session, directory
    self.settings = config["experiments"]["overhead"]["e1"]["stress"]
    self.target = config["experiments"]["overhead"]["stress_utilization_percent"]
    self.policy = e1_config.policy(config["experiments"]["overhead"]["e1"], scheduler, "stress")
    self.jobs = []
    self.weighted = set()
    self.members = None
    count = self.settings["workers_per_cpu"]
    load = max(1, round(self.target / count))
    timeout = int(config["duration_s"] + config["warmup_s"] + 4 * session.timeout + 1)
    for cpu in sorted(common.cgroup_cpus(session.cgroup)):
      command = [binary, "--cpu", str(count), f"--cpu-load={load}",
                 f"--cpu-method={self.settings['cpu_method']}",
                 f"--cpu-load-slice={self.settings['busy_slice_ms']}",
                 f"--taskset={cpu}", f"--timeout={timeout}s", "--metrics-brief",
                 f"--sched={self.policy['policy']}"]
      if self.policy["policy"] in ("fifo", "rr"):
        command.append(f"--sched-prio={self.policy['priority']}")
      job = session.start_workload(command, {cpu}, **self.policy)
      self.jobs.append((job, cpu))
      job.release()

  def check(self, *, starting=False):
    groups = group_members({job.process.pid for job, _ in self.jobs})
    snapshots = []
    ready = True
    for job, cpu in self.jobs:
      if job.process.poll() is not None:
        raise RuntimeError(f"stress-ng exited before cyclictest completed; see {job.log}")
      workers = 0
      for pid in groups[job.process.pid]:
        try:
          state = lifecycle.process_state(pid)
          name = (Path("/proc") / str(pid) / "comm").read_text().strip()
          if name.startswith("stress-ng-cpu"):
            workers += 1
          if self.policy["weight"] is not None:
            for tid in state["tasks"]:
              if tid not in self.weighted:
                set_weight(self.policy["weight"], tid=tid)
                self.weighted.add(tid)
          lifecycle.verify_state(state, {**self.policy, "cpus": [cpu]}, self.session.cgroup)
          snapshots.append({**state, "comm": name, "task_weight": self.policy["weight"]})
        except (FileNotFoundError, ProcessLookupError):
          continue
      if workers != self.settings["workers_per_cpu"]:
        ready = False
    if not ready and not starting:
      raise RuntimeError("stress-ng worker count changed during measurement")
    if ready:
      members = {tid for state in snapshots for tid in state["tasks"]}
      if self.members is not None and members != self.members:
        raise RuntimeError("stress-ng processes or threads changed after readiness")
      if self.members is None:
        self.members = members
        common.write_json(self.directory / "stress-initial.json", snapshots)
      common.write_json(self.directory / "stress-processes.json", snapshots)
    return ready

  def wait_ready(self):
    deadline = time.monotonic() + self.session.timeout
    while time.monotonic() < deadline:
      self.session.check()
      if self.check(starting=True):
        return
      time.sleep(.02)
    raise TimeoutError("stress-ng workers did not become ready")
