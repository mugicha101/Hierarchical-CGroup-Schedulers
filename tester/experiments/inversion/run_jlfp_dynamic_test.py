#!/usr/bin/env python3
"""Run JLFP workers that periodically block and wake to test dynamic inversions."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tester.experiments.inversion import run_jlfp_test
from tester.utils import common


def main():
  return run_jlfp_test.main(periodic=True)


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
