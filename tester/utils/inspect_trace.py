#!/usr/bin/env python3
"""List recorded trace.dat events, payload fields, CPUs and timestamp ranges offline."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, trace_inventory


def main():
  args = arguments.parse_trace_inventory(__doc__)
  output = args.output or args.trace.with_suffix(args.trace.suffix + ".inventory.json")
  try:
    report = trace_inventory.inspect(args.trace, output)
    for name, event in sorted(report["events"].items()):
      print(f"{name}: {event['count']} events; fields: {', '.join(event['payload_fields'])}")
    print(f"Inventory: {output}")
    return 0
  except KeyboardInterrupt:
    return 130
  except (OSError, KeyError, TypeError, ValueError, RuntimeError, ImportError) as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
