"""Check setup with a blocked native worker and an already-expired schedule."""

import time

from tester.utils import builds, preflight, tracing
from tester.utils.common import new_run, run_attempts, write_json
from tester.utils.lifecycle import Session


def run(config, scheduler, traced=False, basic=False):
  report = preflight.inspect(config, traced=traced, basic=basic)
  output = new_run(config, "smoke-preflight")
  write_json(output / "preflight.json", report)
  if not report["ok"]:
    raise RuntimeError(f"live setup prerequisites are missing; see {output / 'preflight.json'}")
  worker = builds.result(builds.build(config, "worker"))
  manifest = None if scheduler == "none" else builds.result(builds.build(config, scheduler))
  events = ("sched:sched_process_exit",) if traced else ()

  def action(directory, _):
    with Session(config, directory, manifest, events=events) as session:
      job = session.start_workload(
          [worker["binary"], "--jlfp-worker"],
          {config["experiments"]["overhead"]["cyclictest_cpu"]},
          policy="other" if manifest is None else "ext",
          priority=0,
          nice=0,
          weight=1 if scheduler == "jlfp" else None,
      )
      job.release()
      deadline = time.monotonic() + config["process_timeout_s"]
      while "ready" not in job.log.read_text().splitlines():
        session.check()
        if job.process.poll() is not None or time.monotonic() >= deadline:
          raise RuntimeError(f"native worker did not become ready; see {job.log}")
        time.sleep(.02)

      job.verify("native-worker")
      job.process.stdin.write(f"0 {time.monotonic_ns()} 0 0 0\n".encode())
      job.process.stdin.flush()
      job.wait(config["process_timeout_s"])
    trace = tracing.summarize(directory / "trace.dat", events) if traced else None
    return {
        "scheduler": scheduler,
        "measurement": False,
        "trace": trace,
        "worker_schedule": "expired; no busy loop",
        "basic_setup_check": basic,
    }

  return run_attempts(config, f"smoke-{scheduler}", action)
