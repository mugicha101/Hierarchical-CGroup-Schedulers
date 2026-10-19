#!/usr/bin/env python3
"""Run E5's native one-CPU Nginx/database capacity baseline."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tester.utils import arguments, common, e5


def main():
  args = arguments.parse_e5(__doc__)
  try:
    config = common.load_config(args.config)
    result = e5.run(config, database=args.database, analyse_only=args.analyse_only)
    return 0 if result["all_screening_fit"] else 2
  except KeyboardInterrupt:
    print("Interrupted; E5 artifacts retained", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
