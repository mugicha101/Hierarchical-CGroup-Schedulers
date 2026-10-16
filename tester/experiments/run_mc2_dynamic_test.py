#!/usr/bin/env python3
"""Run the MC² A/B/C hierarchy and measure dynamic priority inversions."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, mc2_analysis, mc2_capture


def capture_run(args, output):
  config = args.config
  with arguments.capture_context(args, hierarchy=True) as (cgroup, cpus):
    return mc2_capture.capture(
        output=output,
        build_path=args.scx_build_path,
        cpus=cpus,
        class_settings=args.settings["classes"],
        warmup=config["warmup_s"],
        duration=config["duration_s"],
        relative_to=cgroup,
    )


def main():
  args = arguments.parse_experiment("mc2", __doc__)
  output = None

  try:
    output = arguments.output_directory(args, "mc2-dynamic-test-")
    if args.analyse_only:
      run = common.read_json(output / "run.json")
    else:
      run = capture_run(args, output)

    result = mc2_analysis.analyse_capture(output, run)
    common.write_json(output / "results.json", result)
    mc2_analysis.print_report(result, run, output)
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
