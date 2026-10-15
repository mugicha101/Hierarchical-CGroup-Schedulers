#!/usr/bin/env python3
"""Run the MC² A/B/C hierarchy and measure dynamic priority inversions."""

import argparse
from contextlib import ExitStack, closing, nullcontext, redirect_stdout
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

if __package__:
  from . import run_jlfp_test as base
  from .parse_events import ExecModel, TASK_REPORT_MAX, TaskStatus
else:
  import run_jlfp_test as base
  from parse_events import ExecModel, TASK_REPORT_MAX, TaskStatus


CONFIG = Path(__file__).with_name("mc2") / "mc2_config.json"
TASK_WEIGHT_MASK = (1 << 63) - 1


class MC2ExecModel(ExecModel):
  def update_pi(self):
    # analyse compares priorities only on CPUs where the waiting task can run
    self.pi = False


def mc2_layout(cpus):
  settings = json.loads(CONFIG.read_text())
  classes = []
  for name, policy, weight, affinity in (("class_a", "scx_jlfp", 4, "pinned"),
                                          ("class_b", "scx_gedf", 3, "pinned"),
                                          ("class_c", "scx_gedf", 2, "global")):
    node = settings["subs"][name]
    if node["policy"] != policy or node["weight"] != weight:
      raise ValueError(f"Unexpected MC² policy or weight for {name}")
    node.update(trace=True, max_shard_size=base.SHARD_SIZE,
                cpus=",".join(map(str, sorted(cpus))))
    if affinity == "pinned":
      node["subs"] = {f"cpu{cpu}": {"policy": "none", "cpus": str(cpu)} for cpu in sorted(cpus)}
    classes.append({"path": name, "policy": policy, "weight": weight, "affinity": affinity})
  settings.update(trace=True, max_shard_size=base.SHARD_SIZE)
  return settings, classes


class TaskRTP(ctypes.Structure):
  _fields_ = [("period", ctypes.c_uint64), ("rel_dl", ctypes.c_uint64),
              ("is_periodic", ctypes.c_bool)]


def configure_workers(processes, workers):
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required to configure MC² workers")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
  bpf.bpf_map_update_elem.restype = ctypes.c_int
  with ExitStack() as maps:
    descriptors = {}
    for name in ("task_weights", "task_rtp_map"):
      fd = bpf.bpf_obj_get(f"/sys/fs/bpf/scx/{name}".encode())
      if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)
      maps.callback(os.close, fd)
      descriptors[name] = fd
    for process, _ in processes:
      worker = workers[process.pid]
      pid_fd = os.pidfd_open(process.pid)
      try:
        key = ctypes.c_int(pid_fd)
        if worker["policy"] == "scx_gedf":
          value = TaskRTP(worker["period_ns"], worker["period_ns"], False)
          name = "task_rtp_map"
        else:
          value = ctypes.c_uint64(worker["weight"])
          name = "task_weights"
        if bpf.bpf_map_update_elem(descriptors[name], ctypes.byref(key), ctypes.byref(value), 0) < 0:
          error = ctypes.get_errno()
          raise OSError(error, os.strerror(error), f"{name} for PID {process.pid}")
      finally:
        os.close(pid_fd)
      os.sched_setscheduler(process.pid, base.SCHED_EXT, os.sched_param(0))
      if os.sched_getscheduler(process.pid) != base.SCHED_EXT:
        raise RuntimeError(f"Worker {process.pid} did not enter SCHED_EXT")


def capture(output, build_path, cpus, tasks_per_cpu, warmup, duration, period_ns, runtime_ns,
            *, isolate=False, keep_bandwidth_servers=False):
  cpus = base.select_test_cpus(isolate, cpus)
  binary = base.build_worker()
  settings, classes = mc2_layout(cpus)
  other_cpus = os.sched_getaffinity(0) - cpus
  if isolate:
    settings["subs"]["other"] = {"policy": "none", "weight": 1,
                                  "cpus": ",".join(map(str, sorted(other_cpus)))}
  config = output / "config.json"
  config.write_text(json.dumps(settings, indent=2) + "\n")
  processes = []
  workers = {}
  servers = base.disabled_bandwidth_servers(cpus, output / "bandwidth_servers.json") \
      if isolate and not keep_bandwidth_servers else nullcontext({"disabled": False})
  controller = base.controller_affinity(cpus) if isolate else nullcontext()
  with controller, servers as server_state, (output / "workers.log").open("w") as log:
    with base.TraceSession(events=base.EVENTS, scx_build_path=build_path, monitor=True) as session, \
         ExitStack() as isolation:
      session.start_trace(output / "trace.dat")
      base.report_progress("Loading MC²: pinned JLFP A, pinned GEDF B, global GEDF C...")
      session.load_config(config)
      cgroups = [{"path": "", "id": 0, "weight": 0xffff, "policy": "scx_jlfp"}]
      for group in classes:
        path = base.CGROUP_ROOT / group["path"]
        if int((path / "cpu.weight").read_text()) != group["weight"]:
          raise RuntimeError(f"Cgroup weight did not apply: {path}")
        cgroups.append({**group, "id": path.stat().st_ino})
      isolation_state = isolation.enter_context(base.isolated_root_tasks(output / "cpu_isolation.json")) \
          if isolate else {"enabled": False}
      try:
        for group in classes:
          for index, cpu in enumerate(sorted(cpus)):
            for slot in range(tasks_per_cpu):
              pinned = group["affinity"] == "pinned"
              path = group["path"] + (f"/cpu{cpu}" if pinned else "")
              worker_cpus = {cpu} if pinned else cpus
              command = "--gedf-worker" if group["policy"] == "scx_gedf" else "--jlfp-worker"
              process = subprocess.Popen([str(binary), command], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=log, text=True)
              processes.append((process, 0))
              workers[process.pid] = {"class": group["path"], "cgroup": path,
                                     "cpus": sorted(worker_cpus), "policy": group["policy"],
                                     "period_ns": period_ns * (slot + 1), "runtime_ns": runtime_ns,
                                     "phase_ns": slot * period_ns // tasks_per_cpu +
                                                 index * period_ns // (len(cpus) * tasks_per_cpu),
                                     "weight": tasks_per_cpu - slot}
              (base.CGROUP_ROOT / path / "cgroup.procs").write_text(f"{process.pid}\n")
              os.sched_setaffinity(process.pid, worker_cpus)
              if os.sched_getaffinity(process.pid) != worker_cpus:
                raise RuntimeError(f"Worker affinity did not apply: {process.pid}")
              ready, _, _ = select.select([process.stdout], [], [], 30)
              if not ready or process.stdout.readline().strip() != "ready":
                raise RuntimeError(f"Worker {process.pid} did not become ready; see {log.name}")
        configure_workers(processes, workers)
        release = time.monotonic_ns() + 100_000_000
        start = release + round(warmup * 1e9)
        end = start + round(duration * 1e9)
        for worker in workers.values():
          if worker["policy"] == "scx_gedf":
            worker["weight"] = (1 << 64) - 1 - (release + worker["phase_ns"] + worker["period_ns"])
        run = {"setup": "mc2-abc", "cpus": sorted(cpus), "workers": workers, "cgroups": cgroups,
               "start_ns": start, "end_ns": end, "worker_binary": str(binary),
               "scx_build_path": str(build_path.resolve()), "bandwidth_servers": server_state,
               "cpu_isolation": isolation_state,
               "workload": {"kind": "periodic-releases", "release_ns": release,
                            "gedf_is_periodic": False, "tasks_per_cpu_per_class": tasks_per_cpu}}
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        base.report_progress(f"Running {len(workers)} MC² workers: {warmup:g}s warmup + {duration:g}s measurement...")
        for process, _ in processes:
          worker = workers[process.pid]
          request = (release, end, worker["period_ns"], runtime_ns, worker["phase_ns"])
          process.stdin.write(" ".join(map(str, request)) + "\n")
          process.stdin.flush()
        for process, _ in processes:
          status = process.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9) + 10)
          if status:
            raise RuntimeError(f"Worker {process.pid} exited with status {status}; see {log.name}")
      finally:
        base.report_progress("Stopping MC² workers...")
        base.stop_workers(processes)
  return run


def analyse(events, run, *, progress=None):
  workers = {int(pid): worker for pid, worker in run["workers"].items()}
  cgroups = {group["path"]: group for group in run["cgroups"]}
  expected = {group["id"] for group in cgroups.values()}
  start, end = run["start_ns"], run["end_ns"]
  if not workers or not end > start or any(worker["class"] not in cgroups for worker in workers.values()):
    raise ValueError("Invalid MC² worker or cgroup metadata")
  model = MC2ExecModel(0, use_sched_switch=True)
  for group in cgroups.values():
    model.get_sched(group["id"]).weight = group["weight"]
  for pid, worker in workers.items():
    model.assign_sched(pid, cgroups[worker["class"]]["id"])
    model.update_task_weight(pid, worker["weight"])
  stats = {name: {"total": 0, "current": 0, "longest": 0, "intervals": 0}
           for name in ("all", "cross_cgroup", "within_cgroup")}
  pair_time = {}
  cpu_time = {name: 0 for name in cgroups if name}
  class_stats = {name: {"total": 0, "current": 0, "longest": 0, "intervals": 0}
                 for name in cpu_time}
  task_pair_time = {name: {} for name in class_stats}
  all_stats = {**stats, **class_stats}
  initialized, observed_weights = set(), set()
  previous = start
  last_time = -1
  switches = wakeups = blocks = 0
  saw_switch = False
  observed_execution = False
  began = last_progress = time.monotonic()
  for count, event in enumerate(events, 1):
    if event.time < last_time:
      raise RuntimeError("Trace events are not ordered across CPUs; use the mono trace clock")
    last_time = event.time
    if event.event_type == "scxtp:scxtp_exit" and event.sched in expected and event.time < end:
      raise RuntimeError(f"MC² scheduler {event.sched} detached before measurement ended")
    if event.event_type == "scxtp:scxtp_init" and event.time <= start:
      initialized.add(event.sched)
    if "tid" in event.details and event.details["tid"] not in workers:
      continue
    until = min(event.time, end)
    if until > previous:
      running = [task for task in model.tasks.values() if task.status == TaskStatus.RUNNING]
      pending = [task for task in model.tasks.values() if task.status == TaskStatus.READY]
      active = set()
      pairs = set()
      task_pairs = set()
      for task in running:
        cpu_time[workers[task.pid]["class"]] += until - previous
        for waiter in pending:
          if task.cpu not in workers[waiter.pid]["cpus"] or model.get_weight(waiter.pid) <= model.get_weight(task.pid):
            continue
          cross = workers[waiter.pid]["class"] != workers[task.pid]["class"]
          active.update(("all", "cross_cgroup" if cross else "within_cgroup"))
          if cross:
            pairs.add(workers[waiter.pid]["class"] + ">" + workers[task.pid]["class"])
          else:
            name = workers[waiter.pid]["class"]
            active.add(name)
            task_pairs.add((name, f"{waiter.pid}>{task.pid}"))
      for pair in pairs:
        pair_time[pair] = pair_time.get(pair, 0) + until - previous
      for name, pair in task_pairs:
        task_pair_time[name][pair] = task_pair_time[name].get(pair, 0) + until - previous
      for name, value in all_stats.items():
        if name in active:
          if not value["current"]:
            value["intervals"] += 1
            print(f"{name} inversion starts at {previous}")
            if name == "all":
              print("  pending:", [(task.pid, workers[task.pid]["class"], model.get_weight(task.pid),
                                     workers[task.pid]["cpus"]) for task in pending])
              print("  running:", [(task.pid, workers[task.pid]["class"], model.get_weight(task.pid),
                                     task.cpu) for task in running])
          value["current"] += until - previous
          value["total"] += until - previous
          value["longest"] = max(value["longest"], value["current"])
        else:
          if value["current"]:
            print(f"{name} inversion ends at {previous}; duration {value['current']} ns")
          value["current"] = 0
      observed_execution |= bool(running)
      previous = until
    if event.time > end:
      break
    tid = event.details.get("tid")
    if tid in workers:
      group = cgroups[workers[tid]["class"]]
      if start <= event.time < end and event.sched != group["id"]:
        raise RuntimeError(f"Worker {tid} left its expected MC² scheduler")
      if event.event_type == "scxtp:scxtp_set_task_weight" and event.sched == group["id"] and \
         (event.details["weight"] & TASK_WEIGHT_MASK) == (workers[tid]["weight"] & TASK_WEIGHT_MASK):
        observed_weights.add(tid)
    saw_switch |= event.event_type == "sched:sched_switch"
    if start <= event.time < end:
      if event.event_type == "sched:sched_switch":
        next_pid = event.details["next_pid"]
        if next_pid in workers and event.cpu not in workers[next_pid]["cpus"]:
          raise RuntimeError(f"Worker {next_pid} ran outside its configured affinity")
        switches += event.details["next_pid"] in workers
        blocks += event.details["prev_pid"] in workers and \
            (event.details["prev_state"] & (TASK_REPORT_MAX - 1)) != 0
      elif event.event_type in ("sched:sched_wakeup", "sched:sched_wakeup_new"):
        wakeups += event.details["pid"] in workers
    model.handle_event(event)
    if progress is not None and count % 1000 == 0:
      now = time.monotonic()
      if now - last_progress >= 2:
        progress(100 * max(0, min(event.time - start, end - start)) / (end - start), count, now - began)
        last_progress = now
  if previous < end:
    raise RuntimeError("Capture ended before the measurement interval")
  if not expected <= initialized or observed_weights != set(workers) or not saw_switch or not observed_execution:
    raise RuntimeError("Missing MC² scheduler initialization, worker weights, or execution events")
  if progress is not None:
    progress(100, count, time.monotonic() - began)
  result = {"duration_ns": end - start, "worker_switches": switches,
            "worker_wakeups": wakeups, "worker_blocks": blocks,
            "cross_cgroup_pairs_ns": pair_time, "class_cpu_time_ns": cpu_time}
  for name, value in stats.items():
    prefix = "" if name == "all" else name + "_"
    result.update({prefix + "inversion_ns": value["total"],
                   prefix + "inversion_percent": 100 * value["total"] / (end - start),
                   prefix + "inversion_intervals": value["intervals"],
                   "longest_" + prefix + "inversion_ns": value["longest"]})
  result["within_class_inversions"] = {
      name: {"inversion_ns": value["total"],
             "inversion_percent": 100 * value["total"] / (end - start),
             "inversion_intervals": value["intervals"],
             "longest_inversion_ns": value["longest"], "task_pairs_ns": task_pair_time[name]}
      for name, value in class_stats.items()}
  return result


def print_report(result, run, output):
  duration = result["duration_ns"]
  def row(label, metrics, prefix=""):
    percent = f"{metrics[prefix + 'inversion_percent']:.3f}%"
    elapsed = f"{metrics[prefix + 'inversion_ns'] / 1e6:.3f} ms"
    longest = f"{metrics['longest_' + prefix + 'inversion_ns'] / 1e6:.3f} ms"
    print(f"{label:<20} {percent:>17} {elapsed:>16} {metrics[prefix + 'inversion_intervals']:>10,} {longest:>12}")
  header = f"{'Scope':<20} {'% of measurement':>17} {'Time inverted':>16} {'Intervals':>10} {'Longest':>12}"
  print(f"\nMC² measurement: {duration / 1e9:.3f} s; {len(run['workers'])} workers; "
        f"CPUs {', '.join(map(str, run['cpus']))}")
  print(header)
  for label, prefix in (("Any inversion", ""), ("Between classes", "cross_cgroup_"),
                         ("Within classes", "within_cgroup_")):
    row(label, result, prefix)
  print("Percentages use elapsed wall time. Categories and class-pair times can overlap.")
  print("\nClasses: A = pinned JLFP/RM; B = pinned EDF; C = global EDF. Priority: A > B > C.")
  def class_name(name):
    return name.removeprefix("class_").upper()
  class_results = result.get("within_class_inversions", {})
  if class_results:
    print("\nTask inversions within each class:")
    print(header)
    for name, metrics in sorted(class_results.items()):
      row("Within class " + class_name(name), metrics)
    print("Simultaneous inversions in different classes overlap in the combined total.")
    print("Largest task-pair totals (higher-priority waiting PID -> lower-priority running PID):")
    for name, metrics in sorted(class_results.items()):
      pairs = sorted(metrics["task_pairs_ns"].items(), key=lambda item: (-item[1], item[0]))
      if not pairs:
        print(f"  Class {class_name(name)}: no task inversions.")
      for pair, elapsed in pairs[:3]:
        higher, lower = pair.split(">")
        print(f"  Class {class_name(name)}: {higher} -> {lower}: {elapsed / 1e6:.3f} ms "
              f"({100 * elapsed / duration:.3f}%)")
      if len(pairs) > 3:
        print(f"  Class {class_name(name)}: {len(pairs) - 3} more task pairs in results.json.")
    print("Task-pair totals can overlap; pair priorities follow the traced RM weights or EDF deadlines.")
  print()
  print("Higher-priority waiting class -> lower-priority running class:")
  if result["cross_cgroup_pairs_ns"]:
    for pair, elapsed in sorted(result["cross_cgroup_pairs_ns"].items()):
      higher, lower = map(class_name, pair.split(">"))
      print(f"  {higher} -> {lower}: {elapsed / 1e6:.3f} ms ({100 * elapsed / duration:.3f}%)")
  else:
    print("  No inversions between classes.")
  print("\nWorker CPU time (summed across CPUs):")
  for name, elapsed in sorted(result["class_cpu_time_ns"].items()):
    print(f"  Class {class_name(name)}: {elapsed / 1e9:.3f} CPU-seconds")
  print(f"Worker activity: {result['worker_switches']:,} switches; "
        f"{result['worker_wakeups']:,} wakeups; {result['worker_blocks']:,} blocks")
  print(f"Detailed results: {output / 'results.json'}")


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  outputs = parser.add_mutually_exclusive_group()
  outputs.add_argument("--output-dir", type=Path)
  outputs.add_argument("--analyse-only", type=Path, metavar="CAPTURE_DIR")
  parser.add_argument("--scx-build-path", type=Path, default=base.REPO_DIR / "scheds/build")
  parser.add_argument("--isolate", action="store_true", help="use the last four allowed CPUs and isolate background work")
  parser.add_argument("--keep-bandwidth-servers", action="store_true")
  parser.add_argument("--duration", type=float, default=5)
  parser.add_argument("--warmup", type=float, default=1)
  parser.add_argument("--tasks-per-cpu", type=int, default=2, help="workers per CPU in each class (default: 2)")
  parser.add_argument("--period-ms", type=float, default=20, help="base period; worker periods are successive multiples")
  parser.add_argument("--runtime-ms", type=float, default=2, help="CPU budget per job (default: 2)")
  args = parser.parse_args()
  if not all(math.isfinite(value) for value in (args.duration, args.warmup, args.period_ms, args.runtime_ms)) or \
     args.duration <= 0 or args.warmup < 0 or args.tasks_per_cpu < 2 or not 0 < args.runtime_ms < args.period_ms:
    parser.error("duration must be positive, warmup nonnegative, tasks-per-cpu at least 2, and 0 < runtime-ms < period-ms")
  period, runtime = round(args.period_ms * 1e6), round(args.runtime_ms * 1e6)
  if not 0 < runtime < period:
    parser.error("runtime-ms and period-ms must remain distinct positive nanosecond values")
  output = (args.analyse_only or args.output_dir or base.REPO_DIR / "tester/build" /
            ("mc2-dynamic-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      if os.geteuid() != 0:
        parser.error("root is required for BPF, ftrace, and cgroup setup")
      cpus = base.select_test_cpus(args.isolate)
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      run = capture(output, args.scx_build_path, cpus, args.tasks_per_cpu, args.warmup,
                    args.duration, period, runtime, isolate=args.isolate,
                    keep_bandwidth_servers=args.keep_bandwidth_servers)
    base.report_progress("Reading MC² trace and checking affinity-aware inversions...")
    with base.defer_trace_interrupts() as check_interrupt:
      with (output / "analysis.log").open("w") as log, redirect_stdout(log):
        with closing(base.trace_events(output / "trace.dat", check_interrupt=check_interrupt)) as events:
          result = analyse(events, run, progress=base.report_analysis_progress)
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print_report(result, run, output)
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
