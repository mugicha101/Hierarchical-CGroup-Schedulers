#!/usr/bin/env python3
"""Compare JLFP sleep/wakeup latency with the local SCHED_EXT cyclictest."""

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager, nullcontext
import ctypes
from datetime import datetime
import json
import math
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

if __package__:
  from .run_jlfp_test import (SHARD_SIZE, controller_affinity, disabled_bandwidth_servers,
                              isolated_root_tasks, report_progress, select_test_cpus,
                              existing_test_cgroup, cgroup_cpu_set, worker_cgroup, load_relative_config)
  from .trace_helpers import CGROUP_ROOT, REPO_DIR, TraceSession, defer_trace_interrupts
else:
  from run_jlfp_test import (SHARD_SIZE, controller_affinity, disabled_bandwidth_servers,
                            isolated_root_tasks, report_progress, select_test_cpus,
                            existing_test_cgroup, cgroup_cpu_set, worker_cgroup, load_relative_config)
  from trace_helpers import CGROUP_ROOT, REPO_DIR, TraceSession, defer_trace_interrupts


LATENCY_EVENTS = ("sched:sched_process_exit",)
DIAGNOSTIC_EVENTS = ("sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new",
                     "timer:hrtimer_start", "timer:hrtimer_expire_entry", "timer:hrtimer_expire_exit",
                     "irq:irq_handler_entry", "irq:irq_handler_exit",
                     "irq:softirq_entry", "irq:softirq_exit",
                     "workqueue:workqueue_execute_start", "workqueue:workqueue_execute_end")


def cpu_list(cpus):
  return ",".join(map(str, sorted(cpus)))


def resolve_cyclictest(binary, build_path):
  if binary is not None:
    return binary.resolve(strict=True)
  candidate = build_path / "cyclictest"
  if candidate.is_file():
    return candidate.resolve(strict=True)
  return (REPO_DIR / "cyclictest/rt-tests/cyclictest").resolve(strict=True)


def set_timer_slack(timer_slack_ns):
  if not 1 <= timer_slack_ns <= ctypes.c_ulong(-1).value:
    raise ValueError("timer slack must be a positive unsigned-long integer")
  libc = ctypes.CDLL(None, use_errno=True)
  libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]
  libc.prctl.restype = ctypes.c_int
  if libc.prctl(29, timer_slack_ns, 0, 0, 0) != 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), "PR_SET_TIMERSLACK")
  actual = int(Path("/proc/self/timerslack_ns").read_text())
  if actual != timer_slack_ns:
    raise RuntimeError(f"timer slack did not apply: requested {timer_slack_ns}, actual {actual}")


@contextmanager
def temporary_timer_slack(timer_slack_ns):
  original = int(Path("/proc/self/timerslack_ns").read_text())
  if original <= 0:
    raise RuntimeError("the launcher requires a non-RT controller with positive timer slack")
  try:
    # fork copies current slack into the child's default, which cyclictest's privilege probe restores
    set_timer_slack(timer_slack_ns)
    yield
  finally:
    set_timer_slack(original)


@contextmanager
def temporary_cpu_dma_latency(latency_us):
  if latency_us == -1:
    yield {"requested_us": None, "applied": False, "released": True}
    return
  if not 0 <= latency_us <= 2**31 - 1:
    raise ValueError("CPU DMA latency must be -1 or a nonnegative signed 32-bit integer")
  state = {"requested_us": latency_us, "applied": False, "released": False}
  fd = os.open("/dev/cpu_dma_latency", os.O_WRONLY | os.O_CLOEXEC)
  try:
    request = struct.pack("i", latency_us)
    if os.write(fd, request) != len(request):
      raise RuntimeError("failed to install temporary CPU DMA latency request")
    state["applied"] = True
    yield state
  finally:
    os.close(fd)
    state["released"] = True


def cyclic_command(binary, output, cpus, controller_cpus, mode, threads, duration,
                   interval_us, histogram_us, policy="ext", priority=None, *, spike_us=None):
  priority = (50 if policy == "fifo" else 0) if priority is None else priority
  # cyclictest's priority option resets other policies to FIFO; set the requested policy afterward
  command = [str(binary), f"--priority={priority}", f"--policy={policy}", f"--threads={threads}",
             f"--interval={interval_us}", f"--duration={duration}s", "--mlockall",
             "--quiet", "--clock=monotonic", "--default-system", f"--mainaffinity={cpu_list(controller_cpus)}",
             f"--histogram={histogram_us}", f"--histfile={output / 'histogram.txt'}",
             f"--json={output / 'cyclictest.json'}"]
  if mode == "pinned":
    command.append(f"--affinity={cpu_list(cpus)}")
  if spike_us is not None:
    command.extend([f"--spike={spike_us}", "--spike-nodes=16384"])
  return command


def histogram_summary(threads):
  cycles = sum(int(thread["cycles"]) for thread in threads)
  if cycles <= 0 or any(int(thread["cycles"]) <= 0 for thread in threads):
    raise ValueError("cyclictest produced no samples for a measurement thread")
  histogram = {}
  for thread in threads:
    entries = {int(bucket): int(count) for bucket, count in thread["histogram"].items()}
    if any(bucket < 0 or count < 0 for bucket, count in entries.items()) or \
       sum(entries.values()) > int(thread["cycles"]):
      raise ValueError("invalid cyclictest histogram")
    for bucket, count in entries.items():
      histogram[bucket] = histogram.get(bucket, 0) + count
  ordered = sorted(histogram.items())
  percentiles = {}
  for name, fraction in (("p50_us", .5), ("p95_us", .95), ("p99_us", .99),
                         ("p999_us", .999)):
    rank = math.ceil(cycles * fraction)
    cumulative = 0
    percentiles[name] = None
    for bucket, count in ordered:
      cumulative += count
      if cumulative >= rank:
        percentiles[name] = bucket
        break
  return {"samples": cycles, "histogram_bucket_us": 1,
          "histogram_samples": sum(histogram.values()),
          "overflow_samples": cycles - sum(histogram.values()),
          "min_us": min(int(thread["min"]) for thread in threads),
          "max_us": max(int(thread["max"]) for thread in threads),
          "avg_us": sum(float(thread["avg"]) * int(thread["cycles"])
                        for thread in threads) / cycles, **percentiles}


def summarize(raw, expected_threads):
  if raw.get("return_code", 0) != 0:
    raise ValueError("cyclictest reported a failed run")
  if raw.get("resolution_in_ns") != 0:
    raise ValueError("expected microsecond cyclictest histograms")
  threads = raw["thread"]
  if len(threads) != expected_threads or raw["num_threads"] != expected_threads:
    raise ValueError("cyclictest thread count differs from the requested count")
  summary = histogram_summary(list(threads.values()))
  summary["threads"] = {tid: histogram_summary([thread]) for tid, thread in threads.items()}
  return summary


def stop_process(process):
  if process.poll() is None:
    process.terminate()
    try:
      process.wait(timeout=5)
    except subprocess.TimeoutExpired:
      process.kill()
      process.wait()


def check_thread_policies(process, count, cpus, mode, policy=7, timer_slack_ns=None):
  deadline = time.monotonic() + 10
  while process.poll() is None:
    workers = {}
    try:
      for path in (Path("/proc") / str(process.pid) / "task").iterdir():
        tid = int(path.name)
        if tid != process.pid:
          workers[tid] = {"policy": os.sched_getscheduler(tid),
                          "cpus": sorted(os.sched_getaffinity(tid))}
    except (FileNotFoundError, ProcessLookupError):
      pass
    if len(workers) == count and all(worker["policy"] == policy for worker in workers.values()):
      masks = [tuple(worker["cpus"]) for worker in workers.values()]
      allowed = sorted(cpus)
      expected = [(allowed[index % len(allowed)],) for index in range(count)] if mode == "pinned" \
          else [tuple(allowed)] * count
      if Counter(masks) != Counter(expected):
        raise RuntimeError(f"cyclictest worker affinities differ from {mode} request: {workers}")
      if timer_slack_ns is not None:
        expected_slack = 0 if policy == 1 else timer_slack_ns
        for tid, worker in workers.items():
          # the per-task proc directory omits this file; direct /proc/tid exposes it
          worker["timer_slack_ns"] = int((Path("/proc") / str(tid) / "timerslack_ns").read_text())
          if worker["timer_slack_ns"] != expected_slack:
            raise RuntimeError(f"cyclictest worker {tid} timer slack: expected {expected_slack} ns, "
                               f"actual {worker['timer_slack_ns']} ns")
      return workers
    if time.monotonic() >= deadline:
      raise RuntimeError(f"cyclictest did not start {count} threads with policy {policy}: {workers}")
    time.sleep(.02)
  raise RuntimeError("cyclictest exited before its worker policies and affinities could be verified")


def run_cyclic(command, output, cpus, duration, count, mode="migratable", policy=7,
               timer_slack_ns=1, *, cgroup=None):
  launcher = [sys.executable, str(Path(__file__).resolve()), "--exec-cyclic",
              cpu_list(cpus), str(timer_slack_ns)]
  if cgroup is not None:
    launcher.extend(["--cgroup", str(cgroup)])
  launcher.extend(command)
  with (output / "cyclictest.log").open("w") as log:
    with temporary_timer_slack(timer_slack_ns):
      process = subprocess.Popen(launcher, stdout=log, stderr=subprocess.STDOUT)
    try:
      workers = check_thread_policies(process, count, cpus, mode, policy, timer_slack_ns)
      status = process.wait(timeout=duration + 20)
      if status != 0:
        raise RuntimeError(f"cyclictest exited with {status}; see {log.name}")
      return workers
    finally:
      # workloads must stop before the scheduler and isolation contexts unwind
      with defer_trace_interrupts():
        stop_process(process)


def capture(output, build_path, binary, cpus, mode, threads, duration, interval_us,
            histogram_us, keep_bandwidth_servers=False, policy="ext", priority=None,
            cpu_dma_latency_us=0, timer_slack_ns=1, *, isolate=False, diagnostic_trace=False,
            spike_us=100, no_jlfp=False, relative_to=None):
  if no_jlfp and policy == "ext":
    raise ValueError("EXT requires JLFP; use OTHER or FIFO with --no-jlfp")
  if spike_us <= 0:
    raise ValueError("spike threshold must be positive")
  cgroup = existing_test_cgroup(relative_to) if relative_to is not None else CGROUP_ROOT
  relative_to = cgroup if cgroup != CGROUP_ROOT else None
  cpus = select_test_cpus(isolate, cpus, relative_to=relative_to)
  destination = worker_cgroup(cgroup) if relative_to is not None else cgroup
  if relative_to is not None and destination.exists() and not cpus <= cgroup_cpu_set(destination):
    raise ValueError(f"Worker cgroup {destination} does not allow CPUs {sorted(cpus)}")
  available = os.sched_getaffinity(0)
  other_cpus = available - set(cpus)
  config = output / "config.json"
  settings = {"policy": "none" if no_jlfp else "scx_jlfp", "trace": False,
              "max_shard_size": SHARD_SIZE}
  if isolate:
    settings["subs"] = {"other": {"policy": "none", "weight": 1, "cpus": cpu_list(other_cpus)}}
  config.write_text(json.dumps(settings, indent=2) + "\n")
  # the cyclictest main thread must remain inside the destination cpuset
  main_cpus = cpus if relative_to is not None else other_cpus if isolate else available
  command = cyclic_command(binary, output, cpus, main_cpus, mode, threads, duration,
                           interval_us, histogram_us, policy, priority,
                           spike_us=spike_us if diagnostic_trace else None)
  events = LATENCY_EVENTS + (DIAGNOSTIC_EVENTS if diagnostic_trace else ())
  run = {"mode": mode, "cpus": sorted(cpus), "scx_build_path": str(build_path.resolve()),
         "command": command, "threads": threads, "duration_s": duration,
         "interval_us": interval_us, "histogram_us": histogram_us, "policy": policy,
         "measurement_clock": "CLOCK_MONOTONIC",
         "power_settings": "governors unchanged; cyclictest --default-system",
         "cpu_dma_latency_requested_us": cpu_dma_latency_us,
         "timer_slack_requested_ns": timer_slack_ns,
         "jlfp_attached": not no_jlfp, "diagnostic_trace": diagnostic_trace,
         "trace_events": list(events),
         "spike_logging": {"threshold_us": spike_us, "max_records": 16384,
                           "timestamp_clock": "CLOCK_MONOTONIC", "timestamp_unit": "us",
                           "output": "cyclictest.log"} if diagnostic_trace else None,
         "samples_include_startup": True}
  (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
  servers = nullcontext({"disabled": False}) if not isolate or keep_bandwidth_servers else \
      disabled_bandwidth_servers(cpus, output / "bandwidth_servers.json")
  controller = controller_affinity(cpus) if isolate else nullcontext()
  session = None
  try:
    with temporary_cpu_dma_latency(cpu_dma_latency_us) as qos, \
         controller, servers as state:
      run["cpu_dma_latency"] = qos
      run["bandwidth_servers"] = state
      # diagnostic runs record timer delivery separately from runnable scheduling delay
      with TraceSession(events=events, scx_build_path=build_path,
                        monitor=True) as session, ExitStack() as isolation:
        session.start_trace(output / "trace.dat")
        session.load_config(config)
        if relative_to is not None:
          run["cgroup"] = load_relative_config(session, output, cgroup, {
              "policy": "none" if no_jlfp else "scx_jlfp", "trace": False,
              "max_shard_size": SHARD_SIZE}, check_shards=not no_jlfp, destination=destination)
          run["worker_cgroup"] = str(destination)
        run["cpu_isolation"] = isolation.enter_context(
            isolated_root_tasks(output / "cpu_isolation.json")) if isolate else {"enabled": False}
        report_progress(f"Running {mode} cyclictest on CPUs {sorted(cpus)} for {duration}s...")
        run["verified_threads"] = run_cyclic(command, output, cpus, duration, threads, mode,
                                             {"ext": 7, "fifo": 1, "other": 0}[policy], timer_slack_ns,
                                             **({"cgroup": destination} if relative_to is not None else {}))
  finally:
    (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    if session is not None:
      (output / "scheduler.log").write_text("\n".join(session.manager_output) + "\n")
  return summarize(json.loads((output / "cyclictest.json").read_text()), threads)


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
    cpus = select_test_cpus(args.isolate, requested, relative_to=args.relative_to)
  except (OSError, ValueError) as error:
    parser.error(str(error))
  output = (args.output_dir or REPO_DIR / "tester/build" /
            ("jlfp-latency-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    args.cyclictest = resolve_cyclictest(args.cyclictest, args.scx_build_path)
    output.mkdir(parents=True, exist_ok=False)
    result = capture(output, args.scx_build_path, args.cyclictest, cpus, args.mode,
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
  if len(sys.argv) > 2 and sys.argv[1] == "--exec-cyclic":
    set_timer_slack(int(sys.argv[3]))
    command_index = 4
    cgroup = CGROUP_ROOT
    if sys.argv[4] == "--cgroup":
      cgroup = existing_test_cgroup(sys.argv[5])
      command_index = 6
    (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n")
    os.sched_setaffinity(0, set(map(int, sys.argv[2].split(","))))
    os.execv(sys.argv[command_index], sys.argv[command_index:])
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
