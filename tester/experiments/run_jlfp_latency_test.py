#!/usr/bin/env python3
"""Compare JLFP sleep/wakeup latency with the local SCHED_EXT cyclictest."""

import argparse
from datetime import datetime
import json
import os
import signal
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import ctypes

from tester.utils import cgroups as placement, cyclictest
from tester.utils.trace_helpers import REPO_DIR


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--relative-to", type=Path, help="existing workload cgroup; must contain whole CPU shards")
  parser.add_argument("--cyclictest", type=Path,
                      help="explicit binary; default: build-directory cyclictest, then repository copy")
  parser.add_argument("--output-dir", type=Path)
  parser.add_argument("--cpus", help="comma-separated test CPUs; defaults to all allowed CPUs")
  parser.add_argument("--isolate", action="store_true",
                      help="isolate background work; default to four worker CPUs at the root")
  parser.add_argument("--mode", choices=("pinned", "migratable"), default="migratable")
  parser.add_argument("--policy", choices=("ext", "fifo", "other"), default="ext",
                      help="worker policy: EXT for JLFP, OTHER for FAIR, FIFO for RT")
  parser.add_argument("--no-jlfp", action="store_true",
                      help="run an OTHER/FIFO baseline without attaching JLFP")
  parser.add_argument("--diagnostic-trace", action="store_true",
                      help="record scheduler/timer/IRQ events and timestamped spikes; adds tracing overhead")
  parser.add_argument("--spike-us", type=int, default=100,
                      help="log samples above this threshold with --diagnostic-trace (default: 100 us)")
  parser.add_argument("--priority", type=int, help="default: 0 for EXT/OTHER, 50 for FIFO")
  parser.add_argument("--threads", type=int, default=1,
                      help="one thread leaves idle CPUs available for same-core wakeup testing")
  parser.add_argument("--duration", type=int, default=20)
  parser.add_argument("--interval-us", type=int, default=1000)
  parser.add_argument("--histogram-us", type=int, default=10000)
  parser.add_argument("--cpu-dma-latency-us", type=int, default=0,
                      help="temporary idle-exit latency request; -1 keeps ambient power settings")
  parser.add_argument("--timer-slack-ns", type=int, default=1,
                      help="per-worker timer slack before exec (default: 1 ns; 0 restores defaults)")
  parser.add_argument("--keep-bandwidth-servers", action="store_true",
                      help="keep FAIR and SCX bandwidth servers unchanged with --isolate")
  args = parser.parse_args()
  if min(args.duration, args.threads, args.interval_us, args.histogram_us) <= 0 or \
     args.histogram_us > 1_000_000:
    parser.error("duration, threads, and interval must be positive; histogram must be 1..1000000")
  priority = (50 if args.policy == "fifo" else 0) if args.priority is None else args.priority
  if args.policy in ("ext", "other") and priority != 0 or args.policy == "fifo" and not 1 <= priority <= 99:
    parser.error("EXT/OTHER require priority 0; FIFO requires priority 1..99")
  if args.no_jlfp and args.policy == "ext":
    parser.error("EXT requires JLFP; use OTHER or FIFO with --no-jlfp")
  if args.spike_us <= 0:
    parser.error("spike threshold must be positive")
  if not -1 <= args.cpu_dma_latency_us <= 2**31 - 1:
    parser.error("cpu-dma-latency-us must be -1 or a nonnegative signed 32-bit integer")
  if not 1 <= args.timer_slack_ns <= ctypes.c_ulong(-1).value:
    parser.error("timer-slack-ns must be positive; zero restores the inherited default")
  if os.geteuid() != 0:
    parser.error("root is required for the scheduler and trace session")
  try:
    requested = set(map(int, args.cpus.split(","))) if args.cpus else None
  except ValueError:
    parser.error("cpus must be comma-separated integers")
  try:
    cpus = placement.select_test_cpus(args.isolate, requested, relative_to=args.relative_to)
  except (OSError, ValueError) as error:
    parser.error(str(error))
  output = (args.output_dir or REPO_DIR / "tester/build" /
            ("jlfp-latency-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    args.cyclictest = cyclictest.resolve_cyclictest(args.cyclictest, args.scx_build_path)
    output.mkdir(parents=True, exist_ok=False)
    result = cyclictest.capture(output, args.scx_build_path, args.cyclictest, cpus, args.mode,
                     args.threads, args.duration, args.interval_us, args.histogram_us,
                     args.keep_bandwidth_servers, args.policy, priority, args.cpu_dma_latency_us,
                     args.timer_slack_ns, isolate=args.isolate, diagnostic_trace=args.diagnostic_trace,
                     spike_us=args.spike_us, no_jlfp=args.no_jlfp,
                     **({"relative_to": args.relative_to} if args.relative_to is not None else {}))
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
