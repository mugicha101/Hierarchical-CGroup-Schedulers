#!/usr/bin/env python3
"""Compare JLFP sleep/wakeup latency with the local SCHED_EXT cyclictest."""

import json
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, cyclictest


def capture_run(args, output):
  binary = cyclictest.resolve_cyclictest(args.cyclictest, args.scx_build_path)
  with arguments.capture_context(args) as (cgroup, cpus):
    return cyclictest.capture(
        output=output,
        build_path=args.scx_build_path,
        binary=binary,
        cpus=cpus,
        duration=int(args.config["duration_s"]),
        relative_to=cgroup,
        **args.settings,
    )


def main():
  args = arguments.parse_experiment("latency", __doc__)
  output = None

  try:
    output = arguments.output_directory(args, "jlfp-latency-test-")
    result = capture_run(args, output)
    common.write_json(output / "results.json", result)
    print(json.dumps(result, indent=2))
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
