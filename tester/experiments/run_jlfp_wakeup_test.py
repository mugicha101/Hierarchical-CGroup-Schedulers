#!/usr/bin/env python3
"""Measure wakeup placement and latency while JLFP worker CPUs are mostly idle."""

import argparse
from contextlib import closing
from datetime import datetime
import json
import math
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import cgroups as placement, jlfp_capture, wakeup
from tester.utils.trace_helpers import REPO_DIR, defer_trace_interrupts


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  outputs = parser.add_mutually_exclusive_group()
  outputs.add_argument("--output-dir", type=Path)
  outputs.add_argument("--analyse-only", type=Path)
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--relative-to", type=Path, help="existing workload cgroup; must contain whole CPU shards")
  parser.add_argument("--cpus", help="worker affinity, e.g. 12-15; default all allowed CPUs")
  parser.add_argument("--isolate", action="store_true",
                      help="isolate background work; default to four worker CPUs at the root")
  parser.add_argument("--workers", type=int, default=1)
  parser.add_argument("--duration", type=float, default=5)
  parser.add_argument("--warmup", type=float, default=1)
  parser.add_argument("--period-ms", type=float, default=1)
  parser.add_argument("--runtime-us", type=float, default=50)
  parser.add_argument("--keep-bandwidth-servers", action="store_true",
                      help="keep FAIR and SCX bandwidth servers unchanged with --isolate")
  args = parser.parse_args()
  try:
    cpus = wakeup.parse_cpus(args.cpus) if args.cpus else None
  except ValueError:
    parser.error("invalid --cpus list")
  if not all(math.isfinite(value) for value in
             (args.duration, args.warmup, args.period_ms, args.runtime_us)):
    parser.error("duration, warmup, period, and runtime must be finite")
  period, runtime = round(args.period_ms * 1e6), round(args.runtime_us * 1e3)
  if not args.analyse_only:
    try:
      cpus = placement.select_test_cpus(args.isolate, cpus, relative_to=args.relative_to)
    except (OSError, ValueError) as error:
      parser.error(str(error))
    if args.duration <= 0 or args.warmup < 0 or not 1 <= args.workers <= 32 or not 0 < runtime < period:
      parser.error("require positive duration, nonnegative warmup, 1-32 workers, 0 < runtime < period")
  output = (args.analyse_only or args.output_dir or REPO_DIR / "tester/build" /
            ("jlfp-wakeup-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      run = jlfp_capture.capture(output, args.scx_build_path, cpus, args.workers, args.warmup, args.duration,
                    keep_bandwidth_servers=args.keep_bandwidth_servers,
                    isolate=args.isolate,
                    periodic={"period_ns": period, "runtime_ns": runtime},
                    **({"relative_to": args.relative_to} if args.relative_to is not None else {}))
    with defer_trace_interrupts() as check_interrupt:
      with closing(wakeup.trace_events(output / "trace.dat", check_interrupt)) as events:
        result = wakeup.analyse(events, run["weights"], run["cpus"], run["start_ns"], run["end_ns"])
    (output / "wakeup-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
