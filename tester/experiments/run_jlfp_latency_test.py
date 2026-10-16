#!/usr/bin/env python3
"""Compare JLFP sleep/wakeup latency with the local SCHED_EXT cyclictest."""

import json
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tester.utils import arguments, cyclictest


def main():
  args = arguments.parse_experiment("latency", __doc__)
  output = None
  try:
    output = arguments.output_directory(args, "jlfp-latency-test-")
    binary = cyclictest.resolve_cyclictest(args.cyclictest, args.scx_build_path)
    with arguments.capture_context(args) as (cgroup, cpus):
      result = cyclictest.capture(output, args.scx_build_path, binary, cpus,
          duration=int(args.config["duration_s"]), relative_to=cgroup, **args.settings)
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
