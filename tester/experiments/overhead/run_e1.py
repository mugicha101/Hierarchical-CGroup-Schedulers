#!/usr/bin/env python3
"""Run E1 cyclictest latency cases with and without stress-ng, without tracing."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tester.utils import arguments, common, e1


def main():
  args = arguments.parse_e1(__doc__)
  try:
    config = common.load_config(args.config)
    e1.run(config, scheduler=args.scheduler, stress=args.stress, analyse_only=args.analyse_only)
    return 0
  except KeyboardInterrupt:
    print("Interrupted; E1 artifacts retained", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
