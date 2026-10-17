#!/usr/bin/env python3
"""Analyse normalized E2/E3 operation records without running workloads or changing tracing."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, operation_analysis


def main():
  args = arguments.parse_operation_analysis(__doc__)
  output = args.output_dir or args.capture_dir / "operation-analysis"
  try:
    report = operation_analysis.analyse(args.capture_dir, output)
    print(f"Paired {report['pairing_counts']['paired_calls']} calls; results: {output}")
    return 0
  except KeyboardInterrupt:
    return 130
  except (OSError, KeyError, TypeError, ValueError) as error:
    print(f"ERROR: {error}; diagnostics, if created: {output / 'analysis.json'}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
