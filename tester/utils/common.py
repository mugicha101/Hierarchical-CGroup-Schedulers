"""Configuration, artifacts and bounded subprocesses shared by experiments."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

from . import experiment_config

REPO = Path(__file__).resolve().parents[2]
CGROUP_ROOT = Path("/sys/fs/cgroup")
OUTPUT = REPO / "tester/build/experiments"
DEFAULT_CONFIG = REPO / "tester/experiments/config.json"
BPF_CLANG = "clang-22"
CONFIG_KEYS = {"workload_cgroup", "test_cpus", "controller_cpus", "cyclictest_cpu",
               "duration_s", "stress_utilization_percent", "max_attempts",
               "process_timeout_s", "build_timeout_s", "warmup_s", "experiments"}


def cpu_set(value):
  result = set()
  for item in value.split(","):
    bounds = item.split("-")
    if len(bounds) not in (1, 2) or any(not bound.isdecimal() for bound in bounds):
      raise ValueError(f"invalid CPU list: {value!r}")
    first, last = int(bounds[0]), int(bounds[-1])
    if first > last:
      raise ValueError(f"invalid CPU range: {item}")
    result.update(range(first, last + 1))
  return result


def load_config(path=DEFAULT_CONFIG):
  config = json.loads(Path(path).read_text())
  if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
    raise ValueError(f"configuration keys must be {sorted(CONFIG_KEYS)}")
  if cpu_set(config["test_cpus"]) != set(range(8, 16)) or \
      cpu_set(config["controller_cpus"]) != set(range(8)):
    raise ValueError("experiments require test CPUs 8-15 and controller CPUs 0-7")
  if type(config["cyclictest_cpu"]) is not int or config["cyclictest_cpu"] != 9:
    raise ValueError("E1 requires logical CPU 9")
  for key in ("duration_s", "process_timeout_s", "build_timeout_s"):
    value = config[key]
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
      raise ValueError(f"{key} must be finite and positive")
  experiment_config.number(config, "warmup_s", inclusive=True)
  experiment_config.validate(config["experiments"])
  value = config["stress_utilization_percent"]
  if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
    raise ValueError("stress_utilization_percent must be between 0 and 100")
  if type(config["max_attempts"]) is not int or not 1 <= config["max_attempts"] <= 10:
    raise ValueError("max_attempts must be between 1 and 10")
  value = config["workload_cgroup"]
  if value is not None:
    if not isinstance(value, str) or not value.strip():
      raise ValueError("workload_cgroup must be null or a cgroup path")
    path = Path(value)
    path = (path if path.is_absolute() else CGROUP_ROOT / path).resolve()
    if path == CGROUP_ROOT or not path.is_relative_to(CGROUP_ROOT):
      raise ValueError("workload_cgroup must be below /sys/fs/cgroup")
    config["workload_cgroup"] = str(path)
  return config


def workload_cgroup(config, *, leaf=True):
  if config["workload_cgroup"] is None:
    raise ValueError("set workload_cgroup in config.json to an existing prepared leaf")
  path = Path(config["workload_cgroup"]).resolve(strict=True)
  if path == CGROUP_ROOT or not path.is_relative_to(CGROUP_ROOT):
    raise ValueError("workload cgroup must be below /sys/fs/cgroup")
  if (path / "cgroup.type").read_text().strip() != "domain":
    raise ValueError("workloads require an existing process cgroup domain")
  if leaf and (path / "cgroup.subtree_control").read_text().strip():
    raise ValueError("workloads require an existing process cgroup leaf")
  if cpu_set((path / "cpuset.cpus.effective").read_text().strip()) != cpu_set(config["test_cpus"]):
    raise ValueError("workload cgroup must allow exactly the configured test CPUs")
  return path


def write_json(path, value):
  path = Path(path)
  temporary = path.with_suffix(path.suffix + ".tmp")
  temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
  temporary.replace(path)


def sha256(path):
  with Path(path).open("rb") as source:
    return hashlib.file_digest(source, "sha256").hexdigest()


def repository_state(path):
  path = Path(path).resolve()
  root = next(parent for parent in (path, *path.parents) if (parent / ".git").exists())
  def git(*args):
    return subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(path), *args], check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()
  return {"path": str(path), "revision": git("rev-parse", "HEAD"),
          "status": git("status", "--short", "--untracked-files=normal")}


def new_run(config, name):
  stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
  path = OUTPUT / f"{name}-{stamp}-{uuid.uuid4().hex[:8]}"
  path.mkdir(parents=True, exist_ok=False)
  write_json(path / "run.json", {
      "kind": name, "config": config, "kernel": os.uname().release,
      "repository": repository_state(REPO), "measurement": False,
      "utilization_cpus": sorted(cpu_set(config["test_cpus"])),
      "duration_kind": "final" if config["duration_s"] == 60 else "development"})
  return path


class CleanupError(RuntimeError):
  pass


@contextmanager
def cleanup_interrupts():
  previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
  try:
    yield
  finally:
    signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def group_alive(pgid):
  for path in Path("/proc").iterdir():
    if not path.name.isdecimal():
      continue
    try:
      fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
      if int(fields[2]) == pgid and fields[0] not in ("Z", "X"):
        return True
    except (FileNotFoundError, ProcessLookupError):
      continue
  return False


class Processes:
  def __init__(self, directory, timeout):
    self.directory = Path(directory)
    self.timeout = timeout
    self.children = []
    self.commands = []

  def start(self, command, *, cwd=REPO, stdin=None, pass_fds=()):
    command = list(map(str, command))
    record = {"command": command, "cwd": str(cwd), "started_ns": time.monotonic_ns()}
    self.commands.append(record)
    write_json(self.directory / "commands.json", self.commands)
    log = self.directory / f"command-{len(self.commands):02d}.log"
    with log.open("xb") as output:
      process = subprocess.Popen(command, cwd=cwd, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True,
                                 stdin=stdin, pass_fds=pass_fds)
    self.children.append((process, record))
    record.update(pid=process.pid, log=log.name)
    write_json(self.directory / "commands.json", self.commands)
    return process

  def run(self, command, *, cwd=REPO, timeout=None):
    process = self.start(command, cwd=cwd)
    status = process.wait(timeout=timeout or self.timeout)
    if status:
      raise RuntimeError(f"command exited with {status}: {command}; see command logs")
    return process

  def close(self):
    errors = []
    # signal all groups before waiting, including descendants of exited leaders
    for process, _ in self.children:
      try:
        os.killpg(process.pid, signal.SIGTERM)
      except ProcessLookupError:
        pass
      except OSError as error:
        errors.append(str(error))
    deadline = time.monotonic() + self.timeout
    for process, record in reversed(self.children):
      try:
        while group_alive(process.pid) and time.monotonic() < deadline:
          process.poll()
          time.sleep(.02)
        if group_alive(process.pid):
          record["forced_kill"] = True
          try:
            os.killpg(process.pid, signal.SIGKILL)
          except ProcessLookupError:
            pass
        process.wait(timeout=self.timeout)
        deadline_kill = time.monotonic() + self.timeout
        while group_alive(process.pid) and time.monotonic() < deadline_kill:
          time.sleep(.02)
        if group_alive(process.pid):
          raise CleanupError(f"live processes remain in group {process.pid}")
        record.update(return_code=process.returncode, stopped_ns=time.monotonic_ns())
      except Exception as error:
        errors.append(str(error))
    write_json(self.directory / "commands.json", self.commands)
    if errors:
      raise CleanupError("; ".join(errors))


def run_attempts(config, name, action):
  root = new_run(config, name)
  print(f"Artifacts: {root}", flush=True)
  for number in range(1, config["max_attempts"] + 1):
    directory = root / f"attempt-{number:02d}"
    directory.mkdir()
    processes = Processes(directory, config["process_timeout_s"])
    state = {"status": "running", "measurement": False}
    write_json(directory / "status.json", state)
    error = None
    try:
      state["result"] = action(directory, processes)
    except BaseException as caught:
      error = caught
      state["error"] = f"{type(caught).__name__}: {caught}"
    with cleanup_interrupts():
      try:
        processes.close()
        state["cleanup"] = "complete"
      except BaseException as caught:
        state.update(status="cleanup_failed", cleanup=str(caught))
        write_json(directory / "status.json", state)
        raise CleanupError(f"cleanup failed; no retry; see {directory}") from caught
      if isinstance(error, CleanupError):
        state.update(status="cleanup_failed", cleanup="incomplete")
      else:
        state["status"] = "failed" if error else "succeeded"
      write_json(directory / "status.json", state)
    if error is None:
      return root
    if not isinstance(error, Exception) or isinstance(error, CleanupError):
      raise error
    if number == config["max_attempts"]:
      raise RuntimeError(f"all attempts failed; see {root}") from error
    print(f"Attempt {number} failed: {error}; retrying after cleanup", flush=True)


def cpu_times(cpus, path=Path("/proc/stat")):
  result = {}
  for line in path.read_text().splitlines():
    fields = line.split()
    if fields and fields[0].startswith("cpu") and fields[0][3:].isdecimal():
      cpu = int(fields[0][3:])
      if cpu in cpus:
        values = list(map(int, fields[1:]))
        # guest times are already included in user/nice
        result[cpu] = {"total": sum(values[:8]), "idle": values[3],
                       "iowait": values[4]}
  if set(result) != set(cpus):
    raise ValueError("/proc/stat is missing utilization CPUs")
  return result


def utilization(before, after):
  if before.keys() != after.keys():
    raise ValueError("utilization CPU set changed")
  total = idle = 0
  for cpu in before:
    delta = {key: after[cpu][key] - before[cpu][key] for key in before[cpu]}
    if any(value < 0 for value in delta.values()) or delta["total"] <= 0 or \
        delta["idle"] + delta["iowait"] > delta["total"]:
      raise ValueError("invalid CPU counter interval")
    total += delta["total"]
    idle += delta["idle"] + delta["iowait"]
  if total <= 0:
    raise ValueError("no utilization interval")
  return {"cpus": sorted(before), "busy_percent": 100 * (total - idle) / total,
          "total_ticks": total, "idle_iowait_ticks": idle,
          "before": before, "after": after}


@contextmanager
def controller_affinity(cpus):
  previous = os.sched_getaffinity(0)
  allowed = previous & set(cpus)
  if not allowed:
    raise ValueError("controller cannot run on housekeeping CPUs")
  try:
    os.sched_setaffinity(0, allowed)
    yield
  finally:
    os.sched_setaffinity(0, previous)


def report_progress(message):
  print(message, file=sys.stderr, flush=True)


def report_analysis_progress(percent, events, elapsed):
  report_progress(f"Analysing trace: {percent:.1f}% of measurement interval; "
                  f"{events:,} model events; {elapsed:.1f}s elapsed")
