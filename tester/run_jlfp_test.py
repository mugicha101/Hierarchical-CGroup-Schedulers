#!/usr/bin/env python3
"""Run weighted, migratable JLFP workers and check an offline ftrace capture."""

# TODO: AI written, code messy
# TODO: run inversion check separate, this should just capture trace

import argparse
from contextlib import ExitStack, closing, contextmanager, nullcontext, redirect_stdout
import ctypes
import ctypes.util
from datetime import datetime
import errno
import json
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

import bt2

if __package__:
  from .parse_events import ExecModel, TASK_REPORT_MAX, parse_trace
  from .trace_helpers import CGROUP_ROOT, REPO_DIR, TraceParser, TraceSession, defer_trace_interrupts
else:
  from parse_events import ExecModel, TASK_REPORT_MAX, parse_trace
  from trace_helpers import CGROUP_ROOT, REPO_DIR, TraceParser, TraceSession, defer_trace_interrupts

EVENTS = ("scxtp:*", "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new")
# placement diagnostics remain in the capture for debugging, but do not change the model
ANALYSIS_EVENTS = {
    "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new",
    "scxtp:scxtp_init", "scxtp:scxtp_exit", "scxtp:scxtp_cid_topo",
    "scxtp:scxtp_init_task_args", "scxtp:scxtp_exit_task_args",
    "scxtp:scxtp_set_task_weight", "scxtp:scxtp_running", "scxtp:scxtp_stopping",
    "scxtp:scxtp_enqueue_args", "scxtp:scxtp_cgroup_init_args",
    "scxtp:scxtp_set_weight_args", "scxtp:scxtp_sub_params_update",
}
SCHED_EXT = 7
PF_KTHREAD = 0x00200000
SHARD_SIZE = 4
SCHED_DEBUG = Path("/sys/kernel/debug/sched")


def report_progress(message):
  print(message, file=sys.stderr, flush=True)


def report_analysis_progress(percent, events, elapsed):
  report_progress(f"Analysing trace: {percent:.1f}% of measurement interval; "
                  f"{events:,} model events; {elapsed:.1f}s elapsed")


def build_worker():
  source = REPO_DIR / "tester/work.c"
  binary = REPO_DIR / "tester/build/jlfp_worker"
  if not binary.exists() or binary.stat().st_mtime_ns < source.stat().st_mtime_ns:
    binary.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=binary.parent) as directory:
      built = Path(directory) / "worker"
      subprocess.run(["cc", "-O2", "-pthread", "-DSCHED_EXT=7", str(source),
                      "-lbpf", "-o", str(built)], check=True)
      built.replace(binary)
  return binary


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


def select_test_cpus(isolate=False, cpus=None):
  available = os.sched_getaffinity(0)
  if cpus is None:
    cpus = sorted(available)[-SHARD_SIZE:] if isolate else available
  selected = set(cpus)
  if not selected or not selected <= available:
    raise ValueError("worker CPUs must be nonempty and available")
  if isolate and not available - selected:
    raise ValueError("isolation requires at least one CPU outside the worker set")
  return selected


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


@contextmanager
def isolated_root_tasks(state_path):
  root_procs = CGROUP_ROOT / "cgroup.procs"
  other = CGROUP_ROOT / "other"
  other_procs = other / "cgroup.procs"
  state = {"other_cpus": (other / "cpuset.cpus").read_text().strip(),
           "moved_pids": [], "skipped_kernel_pids": []}
  state_path.write_text(json.dumps(state, indent=2) + "\n")
  skip = {0, 1, os.getpid()}
  try:
    report_progress(f"Moving root processes to other on CPUs {state['other_cpus']}...")
    with defer_trace_interrupts():
      while True:
        moved = 0
        for pid in map(int, root_procs.read_text().split()):
          if pid in skip:
            continue
          try:
            # leave kernel threads in root, including those bound to worker CPUs
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[6]) & PF_KTHREAD:
              skip.add(pid)
              state["skipped_kernel_pids"].append(pid)
              continue
            other_procs.write_text(f"{pid}\n")
          except OSError as error:
            if error.errno in (errno.ESRCH, errno.ENOENT):
              continue
            raise
          moved += 1
          state["moved_pids"].append(pid)
        if not moved:
          break
      state_path.write_text(json.dumps(state, indent=2) + "\n")
    yield state
  finally:
    with defer_trace_interrupts():
      report_progress("Returning processes from other to root...")
      errors = []
      failed = set()
      while True:
        moved = 0
        for pid in map(int, other_procs.read_text().split()):
          if pid <= 1 or pid in failed:
            continue
          try:
            root_procs.write_text(f"{pid}\n")
          except OSError as error:
            if error.errno not in (errno.ESRCH, errno.ENOENT):
              failed.add(pid)
              errors.append(f"PID {pid}: {error}")
            continue
          moved += 1
        if not moved:
          break
      state_path.write_text(json.dumps(state, indent=2) + "\n")
      if errors:
        raise RuntimeError("Failed to restore root processes: " + "; ".join(errors))


@contextmanager
def disabled_bandwidth_servers(cpus, state_path):
  saved = {}
  state = {"disabled": True, "cpus": sorted(cpus), "original": {}}
  for server in ("fair_server", "ext_server"):
    state["original"][server] = {}
    for cpu in sorted(cpus):
      path = SCHED_DEBUG / server / f"cpu{cpu}" / "runtime"
      saved[path] = path.read_text()
      state["original"][server][str(cpu)] = {
          "runtime_ns": int(saved[path]),
          "period_ns": int(path.with_name("period").read_text()),
      }
  # retain the originals even if setup fails before run.json is written
  state_path.write_text(json.dumps(state, indent=2) + "\n")
  changed = []
  try:
    report_progress(f"Disabling FAIR and SCX bandwidth servers on CPUs {sorted(cpus)}...")
    with defer_trace_interrupts():
      for path, runtime in saved.items():
        if int(runtime):
          changed.append(path)
          path.write_text("0\n")
        if int(path.read_text()) != 0:
          raise RuntimeError(f"Bandwidth server did not disable: {path}")
    yield state
  finally:
    # a second interrupt must not skip restoration of the remaining CPUs
    with defer_trace_interrupts():
      report_progress("Restoring bandwidth server runtimes...")
      errors = []
      for path in changed:
        try:
          path.write_text(saved[path])
          if int(path.read_text()) != int(saved[path]):
            raise RuntimeError("runtime did not restore")
        except (OSError, ValueError, RuntimeError) as error:
          errors.append(f"{path}: {error}")
      if errors:
        raise RuntimeError("Failed to restore bandwidth servers: " + "; ".join(errors))


def capture(output, build_path, cpus, count, warmup, duration, *, keep_bandwidth_servers=False,
            periodic=None, isolate=False):
  cpus = select_test_cpus(isolate, cpus)
  worker_binary = build_worker()
  other_cpus = os.sched_getaffinity(0) - set(cpus)
  config = output / "config.json"
  settings = {"policy": "scx_jlfp", "trace": True, "max_shard_size": SHARD_SIZE}
  if isolate:
    settings["subs"] = {"other": {"policy": "none", "weight": 1,
                                  "cpus": ",".join(map(str, sorted(other_cpus)))}}
  config.write_text(json.dumps(settings, indent=2) + "\n")
  workers = []
  servers = nullcontext({"disabled": False}) if not isolate or keep_bandwidth_servers else \
      disabled_bandwidth_servers(cpus, output / "bandwidth_servers.json")
  controller = controller_affinity(cpus) if isolate else nullcontext()
  with controller, servers as server_state, (output / "workers.log").open("w") as log:
    report_progress("Starting scheduler manager...")
    with TraceSession(events=EVENTS, scx_build_path=build_path, monitor=True) as session, ExitStack() as isolation:
      report_progress("Starting ftrace recorder...")
      session.start_trace(output / "trace.dat")
      report_progress("Loading JLFP...")
      session.load_config(config)
      isolation_state = isolation.enter_context(isolated_root_tasks(output / "cpu_isolation.json")) \
          if isolate else {"enabled": False}
      try:
        for weight in range(1, count + 1):
          report_progress(f"Starting worker {weight}/{count}...")
          process = subprocess.Popen([str(worker_binary), "--jlfp-worker"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
          workers.append((process, weight))
          # workers must not inherit the controller's existing cgroup
          (CGROUP_ROOT / "cgroup.procs").write_text(f"{process.pid}\n")
          os.sched_setaffinity(process.pid, cpus)
          ready, _, _ = select.select([process.stdout], [], [], 30)
          if not ready or process.stdout.readline().strip() != "ready":
            raise RuntimeError(f"Worker {process.pid} did not become ready; see {log.name}")
        report_progress("Applying worker weights and SCHED_EXT policy...")
        set_weights(workers)
        release = time.monotonic_ns()
        if periodic is not None:
          # give all workers time to receive the shared release schedule
          release += 50_000_000
        start = release + round(warmup * 1e9)
        end = start + round(duration * 1e9)
        run = {"weights": {process.pid: weight for process, weight in workers},
               "cpus": sorted(cpus), "start_ns": start, "end_ns": end,
               "worker_binary": str(worker_binary),
               "bandwidth_servers": server_state, "cpu_isolation": isolation_state}
        phases = {process.pid: index * periodic["period_ns"] // count
                  for index, (process, _) in enumerate(workers)} if periodic is not None else {}
        run["workload"] = {"kind": "continuous"} if periodic is None else {
            "kind": "periodic", **periodic, "release_ns": release, "phases_ns": phases}
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        report_progress(f"Running workers: {warmup:g}s warmup + {duration:g}s measurement...")
        for process, _ in workers:
          request = (0, end, 0, 0, 0) if periodic is None else (
              release, end, periodic["period_ns"], periodic["runtime_ns"], phases[process.pid])
          process.stdin.write(" ".join(map(str, request)) + "\n")
          process.stdin.flush()
        for process, _ in workers:
          status = process.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9) + 10)
          if status != 0:
            raise RuntimeError(f"Worker {process.pid} exited with status {status}; see {log.name}")
      finally:
        report_progress("Stopping workers...")
        stop_workers(workers)
      report_progress("Detaching JLFP and finalizing trace...")
  return run


def trace_events(trace, *, check_interrupt=None):
  if check_interrupt is not None:
    check_interrupt()
  with TraceParser(trace) as parser:
    for message in parser.messages:
      if check_interrupt is not None:
        check_interrupt()
      if isinstance(message, bt2._DiscardedEventsMessageConst):
        raise RuntimeError("Capture lost events; inversion results would be incomplete")
      if isinstance(message, bt2._EventMessageConst):
        yield from parse_trace((message,), event_types=ANALYSIS_EVENTS)


def analyse(events, weights, start, end, *, progress=None):
  model = ExecModel(0, use_sched_switch=True)
  for pid, weight in weights.items():
    model.assign_sched(pid, 0)
    model.update_task_weight(pid, weight)
  previous = start
  total = longest = current = intervals = switches = 0
  wakeups = blocks = 0
  saw_init = False
  saw_switch = False
  observed_execution = False
  observed_weights = set()
  last_time = -1
  started = last_progress = time.monotonic()
  event_count = 0
  for event_count, event in enumerate(events, 1):
    if progress is not None and event_count % 1000 == 0:
      now = time.monotonic()
      if now - last_progress >= 2:
        percent = 100 * max(0, min(event.time - start, end - start)) / (end - start)
        progress(percent, event_count, now - started)
        last_progress = now
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
    if start <= event.time < end:
      if event.event_type == "sched:sched_switch":
        switches += event.details["next_pid"] in weights
        blocks += event.details["prev_pid"] in weights and \
            (event.details["prev_state"] & (TASK_REPORT_MAX - 1)) != 0
      elif event.event_type in ("sched:sched_wakeup", "sched:sched_wakeup_new"):
        wakeups += event.details["pid"] in weights
    model.handle_event(event)
  if previous < end:
    raise RuntimeError("Capture ended before the measurement interval")
  if not saw_init or not saw_switch or not observed_weights or not observed_execution:
    raise RuntimeError("Missing JLFP emissions, applied worker weights, or worker switches; check tracing setup")
  if progress is not None:
    progress(100, event_count, time.monotonic() - started)
  return {"inversion_percent": 100 * total / (end - start),
          "duration_ns": end - start, "inversion_ns": total,
          "longest_inversion_ns": longest, "inversion_intervals": intervals,
          "worker_switches": switches, "worker_wakeups": wakeups, "worker_blocks": blocks}


def main(*, periodic=False):
  description = "Run periodic, weighted JLFP workers and check dynamic priority inversions." \
      if periodic else __doc__
  parser = argparse.ArgumentParser(description=description)
  output_args = parser.add_mutually_exclusive_group()
  output_args.add_argument("--output-dir", type=Path, help="new directory for capture, logs, and results")
  output_args.add_argument("--analyse-only", type=Path, metavar="CAPTURE_DIR",
                           help="analyse an existing trace.dat and run.json without running workers")
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--duration", type=float, default=5, help="measurement seconds (default: 5)")
  parser.add_argument("--warmup", type=float, default=1, help="warmup seconds (default: 1)")
  parser.add_argument("--tasks-per-cpu", type=int, default=2)
  parser.add_argument("--isolate", action="store_true",
                      help="use the last four allowed CPUs and set up background-work isolation")
  if periodic:
    parser.add_argument("--period-ms", type=float, default=20,
                        help="worker release period in milliseconds (default: 20)")
    parser.add_argument("--runtime-ms", type=float, default=10,
                        help="CPU budget per release in milliseconds (default: 10)")
  parser.add_argument("--keep-bandwidth-servers", action="store_true",
                      help="keep FAIR and SCX bandwidth servers unchanged with --isolate")
  args = parser.parse_args()
  if not all(math.isfinite(value) for value in (args.duration, args.warmup)) or \
     args.duration <= 0 or args.warmup < 0 or args.tasks_per_cpu < 2:
    parser.error("duration must be positive, warmup nonnegative, and tasks-per-cpu at least 2")
  workload = None
  if periodic:
    if not all(math.isfinite(value) for value in (args.period_ms, args.runtime_ms)) or \
       not 0 < args.runtime_ms < args.period_ms:
      parser.error("runtime-ms must be positive and less than period-ms")
    workload = {"period_ns": round(args.period_ms * 1e6),
                "runtime_ns": round(args.runtime_ms * 1e6)}
    if not 0 < workload["runtime_ns"] < workload["period_ns"]:
      parser.error("runtime-ms and period-ms must remain distinct, positive nanosecond values")
  prefix = "jlfp-dynamic-test-" if periodic else "jlfp-test-"
  output = args.analyse_only or args.output_dir or REPO_DIR / "tester/build" / (prefix + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))
  output = output.resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
      run["weights"] = {int(pid): weight for pid, weight in run["weights"].items()}
      print(f"Analysing existing capture: {output}", flush=True)
    else:
      try:
        cpus = select_test_cpus(args.isolate)
      except ValueError as error:
        parser.error(str(error))
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      print(f"Worker CPUs: {sorted(cpus)}; JLFP shard size: {SHARD_SIZE}", flush=True)
      options = {"keep_bandwidth_servers": args.keep_bandwidth_servers, "isolate": args.isolate}
      if periodic:
        options["periodic"] = workload
        print(f"Periodic workers: {args.runtime_ms:g} ms CPU budget / {args.period_ms:g} ms period; "
              "staggered releases", flush=True)
      run = capture(output, args.scx_build_path, cpus, len(cpus) * args.tasks_per_cpu,
                    args.warmup, args.duration, **options)
    report_progress(f"Reading finalized trace ({(output / 'trace.dat').stat().st_size / 2**20:.1f} MiB); "
                    "starting offline analysis...")
    with defer_trace_interrupts() as check_interrupt:
      with (output / "analysis.log").open("w") as log, redirect_stdout(log):
        with closing(trace_events(output / "trace.dat", check_interrupt=check_interrupt)) as events:
          result = analyse(events, run["weights"], run["start_ns"], run["end_ns"],
                           progress=report_analysis_progress)
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Time spent inverted: {result['inversion_percent']:.3f}% of measurement time")
    print(f"Inversions: {result['inversion_intervals']}; total {result['inversion_ns'] / 1000:.3f} us; "
          f"longest {result['longest_inversion_ns'] / 1000:.3f} us")
    if run.get("workload", {}).get("kind") == "periodic":
      print(f"Worker transitions: {result['worker_wakeups']} wakeups; {result['worker_blocks']} blocks")
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


def cli(*, periodic=False):
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  return main(periodic=periodic)


if __name__ == "__main__":
  raise SystemExit(cli())
