#!/usr/bin/env python3
"""Measure wakeup placement and latency while JLFP worker CPUs are mostly idle."""

from contextlib import closing
import json
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, jlfp_capture, wakeup
from tester.utils.trace_helpers import defer_trace_interrupts


def main():
  args = arguments.parse_experiment("wakeup", __doc__)
  output = None
  try:
    output = arguments.output_directory(args, "jlfp-wakeup-test-")
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      with arguments.capture_context(args) as (cgroup, cpus):
        run = jlfp_capture.capture(output, args.scx_build_path, cpus, args.settings["workers"],
            args.config["warmup_s"], args.config["duration_s"], relative_to=cgroup,
            periodic={"period_ns": round(args.settings["period_ms"] * 1e6),
                      "runtime_ns": round(args.settings["runtime_us"] * 1e3)})
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
