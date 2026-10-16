#!/usr/bin/env python3
"""Compute E1 histogram statistics offline; this does not validate a live trial."""

import json
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tester.utils import arguments, common, e1_config, e1_results


def main():
  args = arguments.parse_e1_analysis(__doc__)
  try:
    config = common.load_config(args.config)
    settings = e1_config.statistics(config["experiments"]["overhead"]["e1"])
    output = args.output or args.cyclictest_json.with_name("e1-results.json")
    result = e1_results.analyse(args.cyclictest_json, output, settings)
    print(json.dumps(result, indent=2))
    print(f"Histogram statistics: {output}", file=sys.stderr)
    return 0
  except KeyboardInterrupt:
    return 130
  except (OSError, TypeError, ValueError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
