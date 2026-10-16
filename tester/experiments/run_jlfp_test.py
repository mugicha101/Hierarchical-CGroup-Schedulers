#!/usr/bin/env python3
"""Run weighted, migratable JLFP workers and check an offline ftrace capture."""

from contextlib import closing, redirect_stdout
import json
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, inversion, jlfp_capture
from tester.utils.trace_helpers import defer_trace_interrupts


def main(*, periodic=False):
  name = "jlfp_dynamic" if periodic else "jlfp_static"
  description = "Run periodic JLFP workers and analyse dynamic inversions." if periodic else __doc__
  args = arguments.parse_experiment(name, description)
  output = None
  try:
    output = arguments.output_directory(args, "jlfp-dynamic-test-" if periodic else "jlfp-test-")
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
      run["weights"] = {int(pid): weight for pid, weight in run["weights"].items()}
      print(f"Analysing existing capture: {output}", flush=True)
    else:
      workload = {"period_ns": round(args.settings["period_ms"] * 1e6),
                  "runtime_ns": round(args.settings["runtime_ms"] * 1e6)} if periodic else None
      with arguments.capture_context(args) as (cgroup, cpus):
        run = jlfp_capture.capture(output, args.scx_build_path, cpus,
            len(cpus) * args.settings["tasks_per_cpu"], args.config["warmup_s"],
            args.config["duration_s"], periodic=workload, relative_to=cgroup)
    common.report_progress(f"Reading finalized trace ({(output / 'trace.dat').stat().st_size / 2**20:.1f} MiB); "
                    "starting offline analysis...")
    with defer_trace_interrupts() as check_interrupt:
      with (output / "analysis.log").open("w") as log, redirect_stdout(log):
        with closing(inversion.trace_events(output / "trace.dat", check_interrupt=check_interrupt)) as events:
          result = inversion.analyse(events, run["weights"], run["start_ns"], run["end_ns"],
                           progress=common.report_analysis_progress,
                           **({"scheduler_id": run["scheduler_id"], "scheduler_ids": run["scheduler_ids"]}
                              if "scheduler_id" in run else {}))
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Time spent inverted: {result['inversion_percent']:.3f}% of measurement time")
    print(f"Inversions: {result['inversion_intervals']}; total {result['inversion_ns'] / 1000:.3f} us; "
          f"longest {result['longest_inversion_ns'] / 1000:.3f} us")
    if run.get("workload", {}).get("kind") == "periodic":
      print(f"Worker transitions: {result['worker_wakeups']} wakeups; {result['worker_blocks']} blocks")
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


def cli(*, periodic=False):
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  return main(periodic=periodic)


if __name__ == "__main__":
  raise SystemExit(cli())
