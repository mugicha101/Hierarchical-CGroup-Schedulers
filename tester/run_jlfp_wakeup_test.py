#!/usr/bin/env python3
"""Measure wakeup placement and latency while JLFP worker CPUs are mostly idle."""

import argparse
from contextlib import closing
from datetime import datetime
import json
import math
from pathlib import Path
import signal
import sys

import bt2

if __package__:
  from .parse_events import Event, TASK_REPORT_MAX
  from .run_jlfp_test import capture, select_test_cpus
  from .trace_helpers import REPO_DIR, TraceParser, defer_trace_interrupts
else:
  from parse_events import Event, TASK_REPORT_MAX
  from run_jlfp_test import capture, select_test_cpus
  from trace_helpers import REPO_DIR, TraceParser, defer_trace_interrupts

NATIVE_EVENTS = {"sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new"}


def trace_events(path, check_interrupt=None):
  with TraceParser(path) as parser:
    for message in parser.messages:
      if check_interrupt is not None:
        check_interrupt()
      if isinstance(message, bt2._DiscardedEventsMessageConst):
        raise RuntimeError("Capture lost events; wakeup results would be incomplete")
      if not isinstance(message, bt2._EventMessageConst) or message.event.name not in NATIVE_EVENTS:
        continue
      event = message.event
      fields = {name: str(value) if name in ("prev_comm", "next_comm", "comm") else int(value)
                for name, value in event.payload_field.items()}
      yield Event(None, message.default_clock_snapshot.ns_from_origin,
                  int(event.packet.context_field["cpu_id"]), event.name, fields)


def latency_summary(samples):
  values = sorted(sample["latency_ns"] for sample in samples)
  if not values:
    return {"count": 0, "median_ns": None, "p95_ns": None, "p99_ns": None, "max_ns": None}
  middle = len(values) // 2
  median = values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2
  return {"count": len(values), "median_ns": median,
          "p95_ns": values[math.ceil(len(values) * .95) - 1],
          "p99_ns": values[math.ceil(len(values) * .99) - 1], "max_ns": values[-1]}


def summarize(samples):
  migrated = sum(sample["execution_cpu"] != sample["previous_cpu"] for sample in samples)
  return {"wakeups": len(samples), "migrations": migrated,
          "migration_percent": 100 * migrated / len(samples) if samples else None,
          "latency": latency_summary(samples)}


def analyse(events, pids, cpus, start, end):
  if end <= start:
    raise ValueError("measurement end must follow start")
  states = {int(pid): {"blocked": None, "wake": None} for pid in pids}
  running = {}
  samples = []
  duplicate_wakeups = unmatched_executions = 0
  previous_time = -1
  for event in events:
    if event.time < previous_time:
      raise RuntimeError("Trace timestamps are not ordered")
    previous_time = event.time
    if event.time >= end:
      break
    fields = event.details
    if event.event_type == "sched:sched_switch":
      previous_pid, next_pid = fields["prev_pid"], fields["next_pid"]
      running[event.cpu] = {"pid": next_pid, "comm": fields.get("next_comm", ""),
                            "replaced_pid": previous_pid}
      if previous_pid in states:
        state = states[previous_pid]
        # runnable switches are preemption, not a new sleeping activation
        if fields["prev_state"] not in (0, TASK_REPORT_MAX):
          state["blocked"] = {"cpu": event.cpu, "time": event.time}
          state["wake"] = None
      if next_pid in states:
        state = states[next_pid]
        wake = state["wake"]
        if wake is not None and start <= wake["wake_ns"]:
          samples.append({**wake, "execution_ns": event.time,
                          "execution_cpu": event.cpu, "latency_ns": event.time - wake["wake_ns"]})
        elif state["blocked"] is not None and event.time >= start:
          unmatched_executions += 1
        state["blocked"] = state["wake"] = None
    elif event.event_type in ("sched:sched_wakeup", "sched:sched_wakeup_new"):
      pid = fields["pid"]
      if pid not in states or states[pid]["blocked"] is None:
        continue
      state = states[pid]
      if state["wake"] is not None:
        duplicate_wakeups += start <= event.time
        continue
      previous_cpu = state["blocked"]["cpu"]
      previous_current = running.get(previous_cpu, {})
      local = event.cpu == previous_cpu
      timer = previous_current.get("comm", "").startswith("ktimers")
      timer_from_idle = timer and previous_current.get("replaced_pid") == 0
      state["wake"] = {"pid": pid, "wake_ns": event.time, "previous_cpu": previous_cpu,
                       "waker_cpu": event.cpu, "target_cpu": fields.get("target_cpu"),
                       "local_wakeup": local, "local_timer_from_idle": local and timer_from_idle,
                       "previous_cpu_current": dict(previous_current),
                       "other_observed_idle_cpus": sorted(cpu for cpu in cpus if cpu != previous_cpu
                                                          and running.get(cpu, {}).get("pid") == 0)}
  if not samples:
    raise RuntimeError("No completed blocking wakeups in measurement window")
  local = [sample for sample in samples if sample["local_wakeup"]]
  timer_idle = [sample for sample in samples if sample["local_timer_from_idle"]]
  return {"duration_ns": end - start, **summarize(samples),
          "local_wakeups": summarize(local),
          "remote_wakeups": summarize([sample for sample in samples if not sample["local_wakeup"]]),
          "local_timer_from_idle": summarize(timer_idle),
          "local_timer_from_idle_with_other_idle_cpus": summarize(
              [sample for sample in timer_idle if sample["other_observed_idle_cpus"]]),
          "duplicate_wakeups": duplicate_wakeups,
          "unmatched_executions": unmatched_executions,
          "unfinished_wakeups": sum(state["wake"] is not None and state["wake"]["wake_ns"] >= start
                                     for state in states.values()),
          "samples": samples}


def parse_cpus(text):
  cpus = set()
  for group in text.split(","):
    limits = list(map(int, group.split("-")))
    if len(limits) == 1:
      cpus.add(limits[0])
    elif len(limits) == 2 and limits[0] <= limits[1]:
      cpus.update(range(limits[0], limits[1] + 1))
    else:
      raise ValueError("invalid CPU list")
  return cpus


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  outputs = parser.add_mutually_exclusive_group()
  outputs.add_argument("--output-dir", type=Path)
  outputs.add_argument("--analyse-only", type=Path)
  parser.add_argument("--scx-build-path", type=Path, default=REPO_DIR / "scheds/build")
  parser.add_argument("--relative-to", type=Path, help="existing workload cgroup; must contain whole CPU shards")
  parser.add_argument("--cpus", help="worker affinity, e.g. 12-15; default all allowed CPUs")
  parser.add_argument("--isolate", action="store_true",
                      help="isolate background work; default to four worker CPUs at the root")
  parser.add_argument("--workers", type=int, default=1)
  parser.add_argument("--duration", type=float, default=5)
  parser.add_argument("--warmup", type=float, default=1)
  parser.add_argument("--period-ms", type=float, default=1)
  parser.add_argument("--runtime-us", type=float, default=50)
  parser.add_argument("--keep-bandwidth-servers", action="store_true",
                      help="keep FAIR and SCX bandwidth servers unchanged with --isolate")
  args = parser.parse_args()
  try:
    cpus = parse_cpus(args.cpus) if args.cpus else None
  except ValueError:
    parser.error("invalid --cpus list")
  if not all(math.isfinite(value) for value in
             (args.duration, args.warmup, args.period_ms, args.runtime_us)):
    parser.error("duration, warmup, period, and runtime must be finite")
  period, runtime = round(args.period_ms * 1e6), round(args.runtime_us * 1e3)
  if not args.analyse_only:
    try:
      cpus = select_test_cpus(args.isolate, cpus, relative_to=args.relative_to)
    except (OSError, ValueError) as error:
      parser.error(str(error))
    if args.duration <= 0 or args.warmup < 0 or not 1 <= args.workers <= 32 or not 0 < runtime < period:
      parser.error("require positive duration, nonnegative warmup, 1-32 workers, 0 < runtime < period")
  output = (args.analyse_only or args.output_dir or REPO_DIR / "tester/build" /
            ("jlfp-wakeup-test-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  try:
    if args.analyse_only:
      run = json.loads((output / "run.json").read_text())
    else:
      output.mkdir(parents=True, exist_ok=False)
      print(f"Capture and results: {output}", flush=True)
      run = capture(output, args.scx_build_path, cpus, args.workers, args.warmup, args.duration,
                    keep_bandwidth_servers=args.keep_bandwidth_servers,
                    isolate=args.isolate,
                    periodic={"period_ns": period, "runtime_ns": runtime},
                    **({"relative_to": args.relative_to} if args.relative_to is not None else {}))
    with defer_trace_interrupts() as check_interrupt:
      with closing(trace_events(output / "trace.dat", check_interrupt)) as events:
        result = analyse(events, run["weights"], run["cpus"], run["start_ns"], run["end_ns"])
    (output / "wakeup-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
