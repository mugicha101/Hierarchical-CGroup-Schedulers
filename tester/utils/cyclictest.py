"""Cyclictest launch, validation, temporary controls and histogram analysis."""

from collections import Counter
from contextlib import contextmanager
import ctypes
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from . import cgroups as placement, common
from .trace_helpers import REPO_DIR, TraceSession, defer_trace_interrupts

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
  launcher = [sys.executable, str(Path(__file__).with_name("cyclictest_launch.py")), "--exec-cyclic",
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
      # workloads must stop before the scheduler and temporary controls unwind
      with defer_trace_interrupts():
        stop_process(process)


def capture(output, build_path, binary, cpus, mode, threads, duration, interval_us,
            histogram_us, policy="ext", priority=None,
            cpu_dma_latency_us=0, timer_slack_ns=1, *, diagnostic_trace=False,
            spike_us=100, no_jlfp=False, relative_to):
  if no_jlfp and policy == "ext":
    raise ValueError("EXT requires JLFP; use OTHER or FIFO with --no-jlfp")
  if spike_us <= 0:
    raise ValueError("spike threshold must be positive")
  cgroup = placement.existing_test_cgroup(relative_to)
  cpus = placement.select_test_cpus(cpus, relative_to=cgroup)
  config = output / "config.json"
  settings = {"policy": "none" if no_jlfp else "scx_jlfp", "trace": False,
              "max_shard_size": placement.SHARD_SIZE}
  config.write_text(json.dumps(settings, indent=2) + "\n")
  # the cyclictest main thread must remain inside the configured cpuset
  main_cpus = cpus
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
         "samples_include_startup": True, "host_controls": "external"}
  (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
  session = None
  try:
    with temporary_cpu_dma_latency(cpu_dma_latency_us) as qos:
      run["cpu_dma_latency"] = qos
      # diagnostic runs record timer delivery separately from runnable scheduling delay
      with TraceSession(events=events, scx_build_path=build_path,
                        monitor=True) as session:
        session.start_trace(output / "trace.dat")
        session.load_config(config)
        run["cgroup"] = placement.load_relative_config(session, output, cgroup, {
            "policy": "none" if no_jlfp else "scx_jlfp", "trace": False,
            "max_shard_size": placement.SHARD_SIZE}, check_shards=not no_jlfp)
        run["worker_cgroup"] = str(cgroup)
        common.report_progress(f"Running {mode} cyclictest on CPUs {sorted(cpus)} for {duration}s...")
        run["verified_threads"] = run_cyclic(command, output, cpus, duration, threads, mode,
                                             {"ext": 7, "fifo": 1, "other": 0}[policy], timer_slack_ns,
                                             cgroup=cgroup)
  finally:
    (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    if session is not None:
      (output / "scheduler.log").write_text("\n".join(session.manager_output) + "\n")
  return summarize(json.loads((output / "cyclictest.json").read_text()), threads)
