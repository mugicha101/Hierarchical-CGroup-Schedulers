"""Offline MC² class and task inversion analysis and reporting."""

import time

from . import common, inversion
from .parse_events import ExecModel, TASK_REPORT_MAX, TaskStatus

TASK_WEIGHT_MASK = (1 << 63) - 1


class MC2ExecModel(ExecModel):
  def update_pi(self):
    # analyse compares priorities only on CPUs where the waiting task can run
    self.pi = False


def analyse_capture(output, run):
  common.report_progress("Reading MC² trace and checking affinity-aware inversions...")
  with inversion.capture_events(output) as events:
    return analyse(events, run, progress=common.report_analysis_progress)


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
  result["class_utilization_percent"] = {name: 100 * elapsed / ((end - start) * len(run["cpus"]))
                                        for name, elapsed in cpu_time.items()}
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
  for name, load in run.get("workload", {}).get("class_utilization", {}).items():
    achieved = result["class_utilization_percent"][name]
    print(f"  Class {class_name(name)} load: target {load['target_percent']:.3f}%, "
          f"nominal {load['nominal_percent']:.3f}%, observed worker execution {achieved:.3f}%")
  if "system_utilization" in run:
    print(f"Observed system utilization: {run['system_utilization']['busy_percent']:.3f}% "
          f"across CPUs {run['cpus']}")
  print(f"Detailed results: {output / 'results.json'}")
