#!/usr/bin/env python3
"""Measure wakeup placement and latency while JLFP worker CPUs are mostly idle."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, jlfp_capture, wakeup


def capture_run(args, output):
  settings = args.settings
  config = args.config
  workload = {
      "period_ns": round(settings["period_ms"] * 1e6),
      "runtime_ns": round(settings["runtime_us"] * 1e3),
  }

  with arguments.capture_context(args) as (cgroup, cpus):
    return jlfp_capture.capture(
        output=output,
        build_path=args.scx_build_path,
        cpus=cpus,
        count=settings["workers"],
        warmup=config["warmup_s"],
        duration=config["duration_s"],
        relative_to=cgroup,
        periodic=workload,
    )


def main():
  args = arguments.parse_experiment("wakeup", __doc__)
  output = None

  try:
    output = arguments.output_directory(args, "jlfp-wakeup-test-")
    if args.analyse_only:
      run = common.read_json(output / "run.json")
    else:
      run = capture_run(args, output)

    result = wakeup.analyse_capture(output, run)
    common.write_json(output / "wakeup-results.json", result)
    wakeup.print_report(result)
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
