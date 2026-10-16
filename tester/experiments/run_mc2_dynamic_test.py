#!/usr/bin/env python3
"""Run the MC² A/B/C hierarchy and measure dynamic priority inversions."""

from contextlib import closing, redirect_stdout
import json
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, inversion, mc2_analysis, mc2_capture
from tester.utils.trace_helpers import defer_trace_interrupts


def main():
  args = arguments.parse_experiment("mc2", __doc__)
  output = None
  try:
    output = arguments.output_directory(args, "mc2-dynamic-test-")
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      with arguments.capture_context(args, hierarchy=True) as (cgroup, cpus):
        run = mc2_capture.capture(output, args.scx_build_path, cpus, args.settings["classes"],
            args.config["warmup_s"], args.config["duration_s"], relative_to=cgroup)
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
