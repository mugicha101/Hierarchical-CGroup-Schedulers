"""Check lifecycle failure paths without root or kernel configuration changes."""

import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.experiments import common, lifecycle, tracing
from tester.codex import root_session


def rejects(error, action):
  try:
    action()
  except error:
    return
  raise AssertionError(f"expected {error.__name__}")


config = common.load_config()
config.update(max_attempts=2, process_timeout_s=.3)
original_affinity = os.sched_getaffinity(0)
disabled = {"state": "disabled", "enable_seq": 12, "ops": None}
with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
  root = Path(temporary)
  cgroup = root / "cgroup/workload"
  cgroup.mkdir(parents=True)
  for name, value in (("cgroup.type", "domain"), ("cgroup.subtree_control", ""),
                      ("cpuset.cpus.effective", "8-15")):
    (cgroup / name).write_text(value)
  config["workload_cgroup"] = str(cgroup)
  with patch.object(common, "CGROUP_ROOT", cgroup.parent), \
      patch.object(lifecycle, "root_state", return_value=disabled) as state:
    assert common.workload_cgroup(config) == cgroup
    settings = {"policy": "other", "priority": 0, "nice": 0, "cpus": [9]}
    task = {"policy": 0, "priority": 0, "nice": 0, "cpus": [9]}
    actual = {"cgroup": "0::/workload", "tasks": {1: task, 2: task}}
    lifecycle.verify_state(actual, settings, cgroup)
    for key, value in (("policy", 7), ("priority", 1), ("nice", 1), ("cpus", [8])):
      bad = {**actual, "tasks": {1: task, 2: {**task, key: value}}}
      rejects(RuntimeError, lambda: lifecycle.verify_state(bad, settings, cgroup))
    rejects(RuntimeError, lambda: lifecycle.verify_state(
        {**actual, "cgroup": "0::/other"}, settings, cgroup))

    directory = root / "existing-root"
    directory.mkdir()
    state.return_value = {"state": "enabled", "enable_seq": 13, "ops": "other"}
    session = lifecycle.Session(config, directory)
    rejects(RuntimeError, session.__enter__)
    assert not session.schedulers.children and not session.workloads.children

    state.return_value = disabled
    directory = root / "interrupted"
    directory.mkdir()
    try:
      with lifecycle.Session(config, directory) as session:
        assert session.recording.session is None
        child = session.workloads.start([sys.executable, "-c", "import time; time.sleep(60)"])
        state.return_value = {**disabled, "enable_seq": 13}
        rejects(RuntimeError, session.check)
        state.return_value = disabled
        with patch.object(session.recording, "check", side_effect=RuntimeError("recorder exited")):
          rejects(RuntimeError, session.check)
        raise KeyboardInterrupt
    except KeyboardInterrupt:
      pass
    assert not common.group_alive(child.pid)
    assert json.loads((directory / "lifecycle.json").read_text())[-1]["action"] == "cleanup-complete"
    assert os.sched_getaffinity(0) == original_affinity

  calls = []
  def cleanup_failure(*_):
    calls.append(True)
    raise common.CleanupError("injected session cleanup failure; no processes spawned")
  output = root / "attempts"
  output.mkdir()
  with patch.object(common, "OUTPUT", output):
    rejects(common.CleanupError, lambda: common.run_attempts(config, "cleanup-error", cleanup_failure))
  assert len(calls) == 1
  status = json.loads(next(output.glob("*/attempt-01/status.json")).read_text())
  assert status["status"] == "cleanup_failed" and status["cleanup"] == "incomplete"

  recording = tracing.Recording(root, ("sched:sched_process_exit",), .3)
  recording.session = SimpleNamespace(close=lambda: None,
                                      cleanup_error=RuntimeError("prior startup cleanup failed"))
  rejects(common.CleanupError, recording.close)

  trace = root / "trace.dat"
  metadata = {"errors": [], "controls": {"tracing_on": "0", "trace_clock": "[mono]"},
              "cpu_stats": {"cpu9": "overrun: 1\ncommit overrun: 0\ndropped events: 0\n"}}
  common.write_json(trace.with_suffix(".dat.metadata.json"), metadata)
  rejects(ValueError, lambda: tracing.summarize(trace))
  report = json.loads(trace.with_suffix(".dat.analysis.json").read_text())
  assert not report["valid"] and "lost events" in report["error"]
  metadata["cpu_stats"] = {"cpu9": "overrun: 0\n"}
  common.write_json(trace.with_suffix(".dat.metadata.json"), metadata)
  rejects(ValueError, lambda: tracing.summarize(trace))

rejects(ValueError, lambda: root_session.command({"action": "shell", "command": "id"}))
rejects(ValueError, lambda: root_session.command({"action": "smoke", "scheduler": "unknown"}))
print("PASS: placement rejection, thread attributes, existing-root refusal, root-state changes,")
print("      recorder failure, interrupted teardown, cleanup-error retry stop and trace-loss rejection")
