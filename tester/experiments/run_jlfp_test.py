#!/usr/bin/env python3
"""Run weighted, migratable JLFP workers and check an offline ftrace capture."""

import argparse
from contextlib import closing, redirect_stdout
from datetime import datetime
import json
import math
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import cgroups as placement, common, inversion, jlfp_capture
from tester.utils.trace_helpers import REPO_DIR, defer_trace_interrupts


def main(*, periodic=False):
  description = "Run periodic, weighted JLFP workers and check dynamic priority inversions." \
      if periodic else __doc__
  parser = argparse.ArgumentParser(description=description)
  output_args = parser.add_mutually_exclusive_group()
  output_args.add_argument("--output-dir", type=Path, help="new directory for capture, logs, and results")
  output_args.add_argument("--analyse-only", type=Path, metavar="CAPTURE_DIR",
                           help="analyse an existing trace.dat and run.json without running workers")
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--relative-to", type=Path, help="existing workload cgroup; must contain whole CPU shards")
  parser.add_argument("--duration", type=float, default=5, help="measurement seconds (default: 5)")
  parser.add_argument("--warmup", type=float, default=1, help="warmup seconds (default: 1)")
  parser.add_argument("--tasks-per-cpu", type=int, default=2)
  parser.add_argument("--isolate", action="store_true",
                      help="isolate background work; default to four worker CPUs at the root")
  if periodic:
    parser.add_argument("--period-ms", type=float, default=20,
                        help="worker release period in milliseconds (default: 20)")
    parser.add_argument("--runtime-ms", type=float, default=10,
                        help="CPU budget per release in milliseconds (default: 10)")
  parser.add_argument("--keep-bandwidth-servers", action="store_true",
                      help="keep FAIR and SCX bandwidth servers unchanged with --isolate")
  args = parser.parse_args()
  if not all(math.isfinite(value) for value in (args.duration, args.warmup)) or \
     args.duration <= 0 or args.warmup < 0 or args.tasks_per_cpu < 2:
    parser.error("duration must be positive, warmup nonnegative, and tasks-per-cpu at least 2")
  workload = None
  if periodic:
    if not all(math.isfinite(value) for value in (args.period_ms, args.runtime_ms)) or \
       not 0 < args.runtime_ms < args.period_ms:
      parser.error("runtime-ms must be positive and less than period-ms")
    workload = {"period_ns": round(args.period_ms * 1e6),
                "runtime_ns": round(args.runtime_ms * 1e6)}
    if not 0 < workload["runtime_ns"] < workload["period_ns"]:
      parser.error("runtime-ms and period-ms must remain distinct, positive nanosecond values")
  prefix = "jlfp-dynamic-test-" if periodic else "jlfp-test-"
  output = args.analyse_only or args.output_dir or REPO_DIR / "tester/build" / (prefix + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))
  output = output.resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
      run["weights"] = {int(pid): weight for pid, weight in run["weights"].items()}
      print(f"Analysing existing capture: {output}", flush=True)
    else:
      try:
        cpus = placement.select_test_cpus(args.isolate, relative_to=args.relative_to)
      except (OSError, ValueError) as error:
        parser.error(str(error))
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      print(f"Worker CPUs: {sorted(cpus)}; JLFP shard size: {placement.SHARD_SIZE}", flush=True)
      options = {"keep_bandwidth_servers": args.keep_bandwidth_servers, "isolate": args.isolate}
      if args.relative_to is not None:
        options["relative_to"] = args.relative_to
      if periodic:
        options["periodic"] = workload
        print(f"Periodic workers: {args.runtime_ms:g} ms CPU budget / {args.period_ms:g} ms period; "
              "staggered releases", flush=True)
      run = jlfp_capture.capture(output, args.scx_build_path, cpus, len(cpus) * args.tasks_per_cpu,
                    args.warmup, args.duration, **options)
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
