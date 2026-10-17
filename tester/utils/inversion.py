"""Offline JLFP inversion analysis and filtered model event reading."""

from contextlib import closing, contextmanager, redirect_stdout
import time

import bt2

from . import common
from .parse_events import ExecModel, TASK_REPORT_MAX, parse_trace
from .trace_helpers import TraceParser, defer_trace_interrupts

# placement diagnostics remain in the capture for debugging, but do not change the model
ANALYSIS_EVENTS = {
    "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new",
    "scxtp:scxtp_init", "scxtp:scxtp_exit", "scxtp:scxtp_cid_topo",
    "scxtp:scxtp_init_task_args", "scxtp:scxtp_exit_task_args",
    "scxtp:scxtp_set_task_weight", "scxtp:scxtp_running", "scxtp:scxtp_stopping",
    "scxtp:scxtp_enqueue_args", "scxtp:scxtp_cgroup_init_args",
    "scxtp:scxtp_set_weight_args", "scxtp:scxtp_sub_params_update",
}


def trace_events(trace, *, check_interrupt=None):
  if check_interrupt is not None:
    check_interrupt()
  with TraceParser(trace) as parser:
    for message in parser.messages:
      if check_interrupt is not None:
        check_interrupt()
      if isinstance(message, (bt2._DiscardedEventsMessageConst, bt2._DiscardedPacketsMessageConst)):
        raise RuntimeError("Capture lost events or packets; inversion results would be incomplete")
      if isinstance(message, bt2._EventMessageConst):
        yield from parse_trace((message,), event_types=ANALYSIS_EVENTS)


@contextmanager
def capture_events(output):
  # close native trace resources before restoring signal handlers
  with defer_trace_interrupts() as check_interrupt:
    with (output / "analysis.log").open("w") as log, redirect_stdout(log):
      with closing(trace_events(output / "trace.dat", check_interrupt=check_interrupt)) as events:
        yield events


def analyse_capture(output, run):
  trace_size_mib = (output / "trace.dat").stat().st_size / 2**20
  common.report_progress(
      f"Reading finalized trace ({trace_size_mib:.1f} MiB); starting offline analysis...")

  options = {"progress": common.report_analysis_progress}
  if "scheduler_id" in run:
    options["scheduler_id"] = run["scheduler_id"]
    options["scheduler_ids"] = run["scheduler_ids"]

  with capture_events(output) as events:
    return analyse(events, run["weights"], run["start_ns"], run["end_ns"], **options)


def print_report(result, run):
  total_us = result["inversion_ns"] / 1000
  longest_us = result["longest_inversion_ns"] / 1000
  print(f"Time spent inverted: {result['inversion_percent']:.3f}% of measurement time")
  print(f"Inversions: {result['inversion_intervals']}; total {total_us:.3f} us; "
        f"longest {longest_us:.3f} us")
  if run.get("workload", {}).get("kind") == "periodic":
    print(f"Worker transitions: {result['worker_wakeups']} wakeups; {result['worker_blocks']} blocks")


def analyse(events, weights, start, end, *, progress=None, scheduler_id=0, scheduler_ids=None):
  model = ExecModel(0, use_sched_switch=True)
  expected = set(scheduler_ids or [scheduler_id])
  for pid, weight in weights.items():
    model.assign_sched(pid, scheduler_id)
    model.update_task_weight(pid, weight)
  previous = start
  total = longest = current = intervals = switches = 0
  wakeups = blocks = 0
  initialized = set()
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
    if event.event_type == "scxtp:scxtp_exit" and event.sched in expected and event.time < end:
      raise RuntimeError("JLFP detached before the measurement interval ended; check scheduler/kernel logs")
    if event.event_type == "scxtp:scxtp_init":
      initialized.add(event.sched)
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
  if not expected <= initialized or not saw_switch or not observed_weights or not observed_execution:
    raise RuntimeError("Missing JLFP emissions, applied worker weights, or worker switches; check tracing setup")
  if progress is not None:
    progress(100, event_count, time.monotonic() - started)
  return {"inversion_percent": 100 * total / (end - start),
          "duration_ns": end - start, "inversion_ns": total,
          "longest_inversion_ns": longest, "inversion_intervals": intervals,
          "worker_switches": switches, "worker_wakeups": wakeups, "worker_blocks": blocks}
