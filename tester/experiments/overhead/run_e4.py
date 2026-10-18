#!/usr/bin/env python3
"""Run E4 JLFP callback attribution with migratable workers."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tester.utils import arguments, common, overhead


def main():
  args = arguments.parse_operation_experiment('e4', __doc__)
  try:
    config = common.load_config(args.config)
    overhead.run(config, 'e4', scheduler=args.scheduler, stress=args.stress,
                 analyse_only=args.analyse_only)
    return 0
  except KeyboardInterrupt:
    print('Interrupted; E4 artifacts retained', file=sys.stderr)
    return 130
  except Exception as error:
    print(f'ERROR: {error}', file=sys.stderr)
    return 2


if __name__ == '__main__':
  raise SystemExit(common.run_cli(main))
