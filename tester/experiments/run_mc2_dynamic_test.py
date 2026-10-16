#!/usr/bin/env python3
"""Run the MC² A/B/C hierarchy and measure dynamic priority inversions."""

import argparse
from contextlib import closing, redirect_stdout
from datetime import datetime
import json
import math
import os
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import cgroups as placement, common, inversion, mc2_analysis, mc2_capture
from tester.utils.trace_helpers import REPO_DIR, defer_trace_interrupts


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  outputs = parser.add_mutually_exclusive_group()
  outputs.add_argument("--output-dir", type=Path)
  outputs.add_argument("--analyse-only", type=Path, metavar="CAPTURE_DIR")
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--relative-to", type=Path, help="existing base cgroup; must contain whole CPU shards")
  parser.add_argument("--isolate", action="store_true",
                      help="isolate background work; default to four worker CPUs at the root")
  parser.add_argument("--keep-bandwidth-servers", action="store_true")
  parser.add_argument("--duration", type=float, default=5)
  parser.add_argument("--warmup", type=float, default=1)
  parser.add_argument("--tasks-per-cpu", type=int, default=2, help="workers per CPU in each class (default: 2)")
  parser.add_argument("--period-ms", type=float, default=20, help="base period; worker periods are successive multiples")
  parser.add_argument("--runtime-ms", type=float, default=2, help="CPU budget per job (default: 2)")
  args = parser.parse_args()
  if not all(math.isfinite(value) for value in (args.duration, args.warmup, args.period_ms, args.runtime_ms)) or \
     args.duration <= 0 or args.warmup < 0 or args.tasks_per_cpu < 2 or not 0 < args.runtime_ms < args.period_ms:
    parser.error("duration must be positive, warmup nonnegative, tasks-per-cpu at least 2, and 0 < runtime-ms < period-ms")
  period, runtime = round(args.period_ms * 1e6), round(args.runtime_ms * 1e6)
  if not 0 < runtime < period:
    parser.error("runtime-ms and period-ms must remain distinct positive nanosecond values")
  output = (args.analyse_only or args.output_dir or REPO_DIR / "tester/build" /
            ("mc2-dynamic-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      if os.geteuid() != 0:
        parser.error("root is required for BPF, ftrace, and cgroup setup")
      cpus = placement.select_test_cpus(args.isolate, relative_to=args.relative_to)
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      run = mc2_capture.capture(output, args.scx_build_path, cpus, args.tasks_per_cpu, args.warmup,
                    args.duration, period, runtime, isolate=args.isolate,
                    keep_bandwidth_servers=args.keep_bandwidth_servers,
                    **({"relative_to": args.relative_to} if args.relative_to is not None else {}))
    common.report_progress("Reading MC² trace and checking affinity-aware inversions...")
    with defer_trace_interrupts() as check_interrupt:
      with (output / "analysis.log").open("w") as log, redirect_stdout(log):
        with closing(inversion.trace_events(output / "trace.dat", check_interrupt=check_interrupt)) as events:
          result = mc2_analysis.analyse(events, run, progress=common.report_analysis_progress)
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    mc2_analysis.print_report(result, run, output)
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
