"""Own E5's root and container JLFP instances without changing scheduler code."""

import os
from pathlib import Path
import time

from . import common, e5_config, launch, lifecycle

MAX_WEIGHT = (1 << 63) - 1
DEFAULT_WEIGHT = (1 << 64) - 1


def nginx_role(tid):
  title = Path(f"/proc/{tid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
  for role in ("worker", "master"):
    if title.startswith(f"nginx: {role} process"):
      return role
  raise ValueError(f"unrecognized Nginx task {tid}: {title}")


class Hierarchy:
  def __init__(self, config, directory, manifest, pair, recording=None):
    self.directory, self.pair = Path(directory), pair
    self.settings = e5_config.scheduling(config)
    self.timeout = config["process_timeout_s"]
    args = ["--max-shard-size", "1", "--slice-length", str(self.settings["slice_ns"])]
    self.manifest = {**manifest, "launch_args": [*manifest["launch_args"], *args]}
    self.session = lifecycle.Session(config, directory, self.manifest, recording=recording, hierarchy=True)
    leaf_dir = self.directory / "leaves"
    leaf_dir.mkdir()
    self.leaves = common.Processes(leaf_dir, self.timeout)
    self.instances, self.nginx_tids, self.checks = {}, set(), []
    self.started = False

  def start(self):
    periods = self.settings["nginx_period_ns"]
    if any(value is None for value in periods.values()):
      raise ValueError("set E5 nginx_period_ns before running the SCX hierarchy")
    self.started = True
    self.session.__enter__()
    for name, item in self.pair.services.items():
      group = item["cgroup"]
      identity = group.stat().st_ino
      sysfs = lifecycle.SCX_ROOT / "root/sub" / f"sub-{identity}"
      if sysfs.exists():
        raise RuntimeError("container already has a subscheduler")
      process = self.leaves.start([self.manifest["binary"], *self.manifest["launch_args"], "-c", group])
      self.instances[name] = {"process": process, "sysfs": sysfs, "cgroup": str(group), "id": identity}
      deadline = time.monotonic() + self.timeout
      while not (sysfs / "ops").exists():
        self.session.check()
        if process.poll() is not None:
          raise RuntimeError(f"{name} subscheduler exited before attachment; see leaves logs")
        if time.monotonic() >= deadline:
          raise TimeoutError(f"{name} subscheduler attachment timed out")
        time.sleep(.02)
      key = "nginx" if name == "nginx" else "database"
      (group / "cpu.weight").write_text(str(self.settings["container_weights"][key]))
    self.check()

  def configure_tasks(self):
    # clients are connected and containers frozen, including PostgreSQL backends
    for name, item in self.pair.services.items():
      tids = {int(tid) for tid in (item["cgroup"] / "cgroup.threads").read_text().split()}
      if not tids:
        raise ValueError(f"{name} has no server tasks")
      if name == "nginx":
        self.nginx_tids = tids
      for tid in sorted(tids):
        weight = MAX_WEIGHT
        if name == "nginx":
          weight -= self.settings["nginx_period_ns"][nginx_role(tid)]
        launch.set_weight(weight, tid=tid)
        os.sched_setscheduler(tid, 7, os.sched_param(0))
    self.verify_tasks()

  def check(self):
    self.session.check()
    for name, item in self.instances.items():
      if item["process"].poll() is not None or (item["sysfs"] / "ops").read_text().strip() != "jlfp":
        raise RuntimeError(f"{name} subscheduler detached or exited")

  def verify_tasks(self):
    self.check()
    report = {}
    for name, item in self.pair.services.items():
      group = item["cgroup"]
      key = "nginx" if name == "nginx" else "database"
      weight = int((group / "cpu.weight").read_text())
      if weight != self.settings["container_weights"][key]:
        raise ValueError(f"{name} container priority changed")
      tasks = {}
      for value in (group / "cgroup.threads").read_text().split():
        tid = int(value)
        try:
          role = nginx_role(tid) if name == "nginx" else "equal_priority"
          expected = MAX_WEIGHT - self.settings["nginx_period_ns"][role] if name == "nginx" else MAX_WEIGHT
          actual = launch.task_weight(tid=tid)
          effective = (DEFAULT_WEIGHT if actual is None else actual) & MAX_WEIGHT
          policy, affinity = os.sched_getscheduler(tid), sorted(os.sched_getaffinity(tid))
          if effective != expected or policy != 7 or affinity != [self.pair.prepared["cpu"]]:
            raise ValueError(f"{name} task {tid} policy/affinity/weight changed")
          tasks[value] = {"role": role, "policy": policy, "cpus": affinity,
                          "stored_weight": actual, "effective_weight": effective}
        except ProcessLookupError:
          continue
      if not tasks or (name == "nginx" and {int(tid) for tid in tasks} != self.nginx_tids):
        raise ValueError(f"{name} tasks disappeared or Nginx restarted")
      report[name] = {"cgroup": str(group), "cgroup_id": self.instances[name]["id"],
                      "container_weight": weight, "tasks": tasks}
    self.checks.append({"time_ns": time.monotonic_ns(), "root": self.session.attached, "services": report})
    common.write_json(self.directory / "task-checks.json", self.checks)
    return report

  def close(self):
    errors = []
    with common.cleanup_interrupts():
      try:
        self.leaves.close()
        deadline = time.monotonic() + self.timeout
        while any(item["sysfs"].exists() for item in self.instances.values()):
          if time.monotonic() >= deadline:
            raise TimeoutError("owned leaf scheduler remains attached")
          time.sleep(.02)
      except Exception as error:
        errors.append(f"leaves: {error}")
      if self.started:
        try:
          self.session.close()
        except Exception as error:
          errors.append(f"root: {error}")
    common.write_json(self.directory / "hierarchy.json", {
        "root_build": self.manifest, "attached_root": self.session.attached, "leaves": {name: {
            key: str(value) if isinstance(value, Path) else value
            for key, value in item.items() if key != "process"} for name, item in self.instances.items()},
        "cleanup": "failed" if errors else "complete", "errors": errors,
        "rules": "root: nginx > database; nginx: shorter nominal period first; database: equal priority",
        "semantics": "JLFP fixed priority; no periodic releases, exact FIFO or bandwidth enforcement"})
    if errors:
      raise common.CleanupError("; ".join(errors))
