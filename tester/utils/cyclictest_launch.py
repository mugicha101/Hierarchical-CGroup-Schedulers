"""Place the cyclictest process before exec, preserving inherited timer slack."""

import os
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import cgroups, cyclictest


if __name__ == "__main__":
  cyclictest.set_timer_slack(int(sys.argv[3]))
  command_index = 4
  cgroup = cgroups.CGROUP_ROOT
  if sys.argv[4] == "--cgroup":
    cgroup = cgroups.existing_test_cgroup(sys.argv[5])
    command_index = 6
  (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n")
  os.sched_setaffinity(0, set(map(int, sys.argv[2].split(","))))
  os.execv(sys.argv[command_index], sys.argv[command_index:])
