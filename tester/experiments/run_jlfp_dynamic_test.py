#!/usr/bin/env python3
"""Run JLFP workers that periodically block and wake to test dynamic inversions."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.experiments.run_jlfp_test import cli


if __name__ == "__main__":
  raise SystemExit(cli(periodic=True))
