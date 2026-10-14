#!/usr/bin/env python3
"""Run JLFP workers that periodically block and wake to test dynamic inversions."""

if __package__:
  from .run_jlfp_test import cli
else:
  from run_jlfp_test import cli


if __name__ == "__main__":
  raise SystemExit(cli(periodic=True))
