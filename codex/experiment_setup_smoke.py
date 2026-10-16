"""Run unprivileged checks of the shared experiment setup."""

import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tester.experiments import common
from tester.experiments.run import plan

config = common.load_config()
config.update(max_attempts=2, process_timeout_s=.3)
assert plan(config)["utilization_cpus"] == "8-15"
assert "deadline" not in plan(config)["overhead_e1"]
assert plan(config)["overhead_e2"] == ["other", "fifo", "qmap", "jlfp"]

with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
  path = Path(temporary) / "config.json"
  for key, value in (("workload_cgroup", "/tmp/not-a-cgroup"), ("max_attempts", 0),
                     ("duration_s", -1), ("stress_utilization_percent", 101),
                     ("test_cpus", "0-15")):
    bad = {**config, key: value}
    path.write_text(json.dumps(bad))
    try:
      common.load_config(path)
    except ValueError:
      pass
    else:
      raise AssertionError(f"accepted invalid {key}")

initial = common.cpu_times(set(range(8, 16)))
time.sleep(.1)
measured = common.utilization(initial, common.cpu_times(set(range(8, 16))))
assert measured["cpus"] == list(range(8, 16))
assert 0 <= measured["busy_percent"] <= 100
# guest ticks must not inflate the denominator, and other CPUs must be excluded
with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
  path = Path(temporary) / "stat"
  path.write_text("cpu0 999 0 0 0 0 0 0 0 0 0\ncpu8 10 0 0 90 0 0 0 0 10 0\n")
  assert common.cpu_times({8}, path)[8]["total"] == 100
before = {8: {"total": 100, "idle": 50, "iowait": 0}}
after = {8: {"total": 200, "idle": 55, "iowait": 0}}
assert common.utilization(before, after)["busy_percent"] == 95

def retry(directory, processes):
  code = 7 if directory.name == "attempt-01" else 0
  processes.run([sys.executable, "-c", f"raise SystemExit({code})"])
  return {"checked": "retry"}

root = common.run_attempts(config, "smoke-retry", retry)
assert json.loads((root / "attempt-01/status.json").read_text())["status"] == "failed"
assert json.loads((root / "attempt-02/status.json").read_text())["status"] == "succeeded"

grandchild = None
def descendants(directory, processes):
  global grandchild
  source = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(60)']); print(p.pid,flush=True)")
  process = processes.run([sys.executable, "-c", source])
  grandchild = process.pid
  assert common.group_alive(grandchild)
  return {"checked": "descendant of exited leader"}

common.run_attempts(config, "smoke-descendants", descendants)
assert not common.group_alive(grandchild)

def timeout(directory, processes):
  processes.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=.05)

try:
  common.run_attempts({**config, "max_attempts": 1}, "smoke-timeout", timeout)
except RuntimeError:
  pass
else:
  raise AssertionError("timeout accepted")

previous = common.Processes.close
calls = []
def failed_cleanup(self):
  calls.append(self)
  raise common.CleanupError("simulated cleanup failure with no spawned processes")

try:
  common.Processes.close = failed_cleanup
  try:
    common.run_attempts(config, "smoke-cleanup-failure", lambda *_: {})
  except common.CleanupError:
    pass
  else:
    raise AssertionError("cleanup failure accepted")
finally:
  common.Processes.close = previous
assert len(calls) == 1

interrupted_group = None
def interrupted(directory, processes):
  global interrupted_group
  process = processes.start([sys.executable, "-c", "import time; time.sleep(60)"])
  interrupted_group = process.pid
  raise KeyboardInterrupt

try:
  common.run_attempts(config, "smoke-interrupt", interrupted)
except KeyboardInterrupt:
  pass
else:
  raise AssertionError("interruption swallowed")
assert not common.group_alive(interrupted_group)

def interrupt(*_):
  raise KeyboardInterrupt

handler = signal.signal(signal.SIGTERM, interrupt)
finished = False
try:
  try:
    with common.cleanup_interrupts():
      os.kill(os.getpid(), signal.SIGTERM)
      finished = True
  except KeyboardInterrupt:
    assert finished
  else:
    raise AssertionError("cleanup interruption lost")
finally:
  signal.signal(signal.SIGTERM, handler)

original = os.sched_getaffinity(0)
with common.controller_affinity(set(range(8))):
  assert os.sched_getaffinity(0) <= set(range(8))
assert os.sched_getaffinity(0) == original
print("PASS: configuration, matrix, utilization, retries, descendant cleanup, timeout,")
print("      cleanup-failure retry stop, interruption cleanup and affinity restoration")
