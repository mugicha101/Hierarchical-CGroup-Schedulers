#!/usr/bin/env python3
"""Run weighted, migratable JLFP workers and check an offline ftrace capture."""

# TODO: AI written, code messy
# TODO: replace python workers with C
# TODO: run inversion check separate, this should just capture trace

import argparse
from contextlib import contextmanager, redirect_stdout
import ctypes
import ctypes.util
from datetime import datetime
import json
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import bt2

if __package__:
  from .parse_events import ExecModel, parse_trace
  from .trace_helpers import REPO_DIR, TraceParser, TraceSession
else:
  from parse_events import ExecModel, parse_trace
  from trace_helpers import REPO_DIR, TraceParser, TraceSession

EVENTS = ("scxtp:*", "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new")
SCHED_EXT = 7
SHARD_SIZE = 4


def worker():
  # remain blocked while the parent installs the weight and scheduling policy
  print("ready", flush=True)
  deadline = int(sys.stdin.readline())
  while time.monotonic_ns() < deadline:
    pass


def set_weights(workers):
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required to set task weights")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
  bpf.bpf_map_update_elem.restype = ctypes.c_int
  map_fd = bpf.bpf_obj_get(b"/sys/fs/bpf/scx/task_weights")
  if map_fd < 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), "/sys/fs/bpf/scx/task_weights")
  try:
    for process, weight in workers:
      pid_fd = os.pidfd_open(process.pid)
      try:
        key, value = ctypes.c_int(pid_fd), ctypes.c_uint64(weight)
        if bpf.bpf_map_update_elem(map_fd, ctypes.byref(key), ctypes.byref(value), 0) < 0:
          error = ctypes.get_errno()
          raise OSError(error, os.strerror(error), f"task weight for PID {process.pid}")
      finally:
        os.close(pid_fd)
      os.sched_setscheduler(process.pid, SCHED_EXT, os.sched_param(0))
  finally:
    os.close(map_fd)


def stop_workers(workers):
  # signal everyone before waiting so low-priority workers cannot delay cleanup
  for process, _ in workers:
    if process.poll() is None:
      process.terminate()
  for process, _ in workers:
    try:
      process.wait(timeout=3)
    except subprocess.TimeoutExpired:
      process.kill()
      process.wait()
    finally:
      process.stdin.close()
      process.stdout.close()


@contextmanager
def controller_affinity(worker_cpus):
  original = os.sched_getaffinity(0)
  reserved = original - set(worker_cpus)
  if not reserved:
    raise RuntimeError("At least one CPU outside the worker shard is required for the controller")
  os.sched_setaffinity(0, reserved)
  try:
    yield
  finally:
    os.sched_setaffinity(0, original)


def capture(output, build_path, cpus, count, warmup, duration):
  config = output / "config.json"
  config.write_text(json.dumps({"policy": "scx_jlfp", "trace": True,
                               "max_shard_size": SHARD_SIZE}, indent=2) + "\n")
  workers = []
  with controller_affinity(cpus), (output / "workers.log").open("w") as log:
    with TraceSession(events=EVENTS, scx_build_path=build_path) as session:
      session.start_trace(output / "trace.dat")
      session.load_config(config)
      try:
        for weight in range(1, count + 1):
          process = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), "--worker"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
          workers.append((process, weight))
          os.sched_setaffinity(process.pid, cpus)
          ready, _, _ = select.select([process.stdout], [], [], 30)
          if not ready or process.stdout.readline().strip() != "ready":
            raise RuntimeError(f"Worker {process.pid} did not become ready; see {log.name}")
        set_weights(workers)
        release = time.monotonic_ns()
        start = release + round(warmup * 1e9)
        end = start + round(duration * 1e9)
        run = {"weights": {process.pid: weight for process, weight in workers},
               "cpus": sorted(cpus), "start_ns": start, "end_ns": end}
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        for process, _ in workers:
          process.stdin.write(f"{end}\n")
          process.stdin.flush()
        for process, _ in workers:
          status = process.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9) + 10)
          if status != 0:
            raise RuntimeError(f"Worker {process.pid} exited with status {status}; see {log.name}")
      finally:
        stop_workers(workers)
  return run


def trace_events(trace):
  with TraceParser(trace) as parser:
    for message in parser.messages:
      if isinstance(message, bt2._DiscardedEventsMessageConst):
        raise RuntimeError("Capture lost events; inversion results would be incomplete")
      if isinstance(message, bt2._EventMessageConst):
        yield from parse_trace((message,))


def analyse(events, weights, start, end):
  model = ExecModel(0, use_sched_switch=True)
  for pid, weight in weights.items():
    model.assign_sched(pid, 0)
    model.update_task_weight(pid, weight)
  previous = start
  total = longest = current = intervals = switches = 0
  saw_init = False
  saw_switch = False
  observed_execution = False
  observed_weights = set()
  last_time = -1
  for event in events:
    if event.time < last_time:
      raise RuntimeError("Trace events are not ordered across CPUs; use the mono trace clock")
    last_time = event.time
    if event.event_type == "scxtp:scxtp_exit" and event.sched == 0 and event.time < end:
      raise RuntimeError("JLFP detached before the measurement interval ended; check scheduler/kernel logs")
    saw_init |= event.event_type == "scxtp:scxtp_init" and event.sched == 0
    saw_switch |= event.event_type == "sched:sched_switch"
    if event.event_type in ("scxtp:scxtp_set_task_weight", "scxtp:scxtp_running"):
      tid = event.details["tid"]
      if tid in weights and (event.details["weight"] & ((1 << 63) - 1)) == weights[tid]:
        observed_weights.add(tid)
    # only compare test workers; unrelated tasks do not have test priorities
    if "tid" in event.details and event.details["tid"] not in weights:
      continue
    until = min(event.time, end)
    if until > previous:
      observed_execution |= bool(model.running_weights)
      inversion = bool(model.pending_weights and model.running_weights and model.pi)
      if inversion:
        if current == 0:
          intervals += 1
        current += until - previous
        total += until - previous
        longest = max(longest, current)
      else:
        current = 0
      previous = until
    if event.time > end:
      break
    if event.event_type == "sched:sched_switch" and start <= event.time < end:
      switches += event.details["next_pid"] in weights
    model.handle_event(event)
  if previous < end:
    raise RuntimeError("Capture ended before the measurement interval")
  if not saw_init or not saw_switch or not observed_weights or not observed_execution:
    raise RuntimeError("Missing JLFP emissions, applied worker weights, or worker switches; check tracing setup")
  return {"inversion_percent": 100 * total / (end - start),
          "duration_ns": end - start, "inversion_ns": total,
          "longest_inversion_ns": longest, "inversion_intervals": intervals,
          "worker_switches": switches}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--output-dir", type=Path, help="new directory for capture, logs, and results")
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--duration", type=float, default=5, help="measurement seconds (default: 5)")
  parser.add_argument("--warmup", type=float, default=1, help="warmup seconds (default: 1)")
  parser.add_argument("--tasks-per-cpu", type=int, default=2)
  args = parser.parse_args()
  if not all(math.isfinite(value) for value in (args.duration, args.warmup)) or \
     args.duration <= 0 or args.warmup < 0 or args.tasks_per_cpu < 2:
    parser.error("duration must be positive, warmup nonnegative, and tasks-per-cpu at least 2")
  available = sorted(os.sched_getaffinity(0))
  if len(available) <= SHARD_SIZE:
    parser.error("at least five CPUs are required: four for workers and one for the controller")
  cpus = set(available[-SHARD_SIZE:])
  output = args.output_dir or REPO_DIR / "tester/build" / ("jlfp-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))
  output = output.resolve()
  try:
    output.mkdir(parents=True, exist_ok=False)
    print(f"Capture and results: {output}", flush=True)
    print(f"Worker CPUs: {sorted(cpus)}; JLFP shard size: {SHARD_SIZE}", flush=True)
    run = capture(output, args.scx_build_path, cpus, len(cpus) * args.tasks_per_cpu,
                  args.warmup, args.duration)
    with (output / "analysis.log").open("w") as log, redirect_stdout(log):
      result = analyse(trace_events(output / "trace.dat"), run["weights"], run["start_ns"], run["end_ns"])
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Time spent inverted: {result['inversion_percent']:.3f}% of measurement time")
    print(f"Inversions: {result['inversion_intervals']}; total {result['inversion_ns'] / 1000:.3f} us; "
          f"longest {result['longest_inversion_ns'] / 1000:.3f} us")
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  if sys.argv[1:] == ["--worker"]:
    worker()
  else:
    def interrupt(*_):
      raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
