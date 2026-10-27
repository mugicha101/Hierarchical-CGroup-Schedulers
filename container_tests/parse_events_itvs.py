"""
script to derive priority inversions in hierarchical scheduling trace

pre-pass:
  figure out total cpus
  figure out cid -> cpu mapping
  --skip SECONDS retains earlier state but excludes warm-up from reported intervals

first pass: parse events and construct timelines and scheduling contexts

  timelines for cpus:
  intervals with (sched_class, cgroup_weight, task_weight (0 if not scx))

  timelines for runnable tasks:
  intervals with (sched_id, cgroup_weight, pinned_cpu (-1 if not pinned), task_weight, task_state (PENDING=0, RUNNING=1))
  if task weight or cpuset changes, split into separate tasks
  pinned cpu can be derived by looking at task's eventual running cpu, since it must run to enable migration again
  in case where doesn't run, don't consider it since it gets cut off by the end of the trace
  note: pinned tasks keep their pinned weight and cpumask until their nmig bit is dropped (toggleable behavior, --real-nmig drops this)

  ensure that all migrateable tasks in the same scheduler share the same cpumask
  if scheduler cpumask not provided, derive from event cpus + cmask updates
  initial cgroup weights can be supplied with --weights for late-start captures; recorded updates still apply

  construct scheduling contexts: tasks sharing same (scheduler, cpumask), cpumask only differs from cgroup's cpumask if tasks are all nmig

second pass: calculate metric intervals for each scheduling context
  track hp blocking intervals when a cpu is occupied by a higher priority scheduling class and pending tasks exist
  IRQ handlers, softirqs and IRQ vector entry/exit intervals count as higher-class work
  interrupted tasks accrue blocking time; IRQ time is excluded from CPU task time
  track global priority inversion intervals when a task is pending when a lower priority task or scheduling class is running (including idle)
  track local priority inversion intervals when a task is pending when a lower priority task in the same context is running
  global and partitioned PI totals group intervals by context type
"""

import argparse
import math
import shlex
import sys
from bisect import bisect_right
from collections import defaultdict, namedtuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

TASK_WEIGHT_MASK = (1 << 64) - 1
NMIG_MASK = 1 << 63
DEFAULT_TASK_WEIGHT = TASK_WEIGHT_MASK & ~NMIG_MASK
DEFAULT_CGROUP_WEIGHT = 100
TASK_REPORT_MAX = 0x100
IRQ_EVENTS = {"irq:irq_handler_entry", "irq:irq_handler_exit", "irq:softirq_entry", "irq:softirq_exit"}

class TaskStatus(Enum):
  RUNNING = 0
  READY = 1
  BLOCKED = 2

Event = namedtuple("Event", "sched time cpu event_type details")

# identify native classes that take precedence over SCX
def is_higher_class(prio):
  return prio is not None and prio < 100

# recognize paired interrupt tracepoints without including softirq raises
def is_irq_event(name):
  return name in IRQ_EVENTS or (name.startswith("irq_vectors:") and name.endswith(("_entry", "_exit")))

# read native ftrace events with an installed or explicitly supplied babeltrace plugin
def read_trace(path, plugin_path=None):
  import bt2
  if plugin_path:
    plugins = bt2.find_plugins_in_path(str(Path(plugin_path).resolve()), fail_on_load_error=True) or []
    plugin = next((plugin for plugin in plugins if "tracedat" in plugin.source_component_classes), None)
  else:
    plugin = bt2.find_plugin("ftrace")
  if plugin is None:
    raise RuntimeError("No ftrace plugin found; supply --plugin /path/to/babeltrace-plugin-ftrace.so")
  source = bt2.ComponentSpec(plugin.source_component_classes["tracedat"],
                            {"inputs": [str(Path(path).resolve())], "lttng": False})
  for msg in bt2.TraceCollectionMessageIterator([source]):
    if isinstance(msg, (bt2._DiscardedEventsMessageConst, bt2._DiscardedPacketsMessageConst)):
      raise RuntimeError("Capture lost events or packets; analysis would be incomplete")
    if isinstance(msg, bt2._EventMessageConst):
      yield msg

# decode relevant trace records with physical CPU ids and numeric payloads
def parse_trace(msgs, *, event_types=None):
  for msg in msgs:
    event = msg.event
    name = event.name
    if event_types is not None and name not in event_types:
      continue
    if not (name.startswith("scxtp:scxtp_") or is_irq_event(name) or name in
            ("sched:sched_switch", "sched:sched_waking", "sched:sched_wakeup", "sched:sched_wakeup_new")):
      continue
    fields = {key: int(value) for key, value in event.payload_field.items()
              if key not in ("prev_comm", "next_comm", "comm", "name")}
    yield Event(fields.get("sched_cgrp_id"), msg.default_clock_snapshot.ns_from_origin,
                int(event.packet.context_field["cpu_id"]), name, fields)

# parse explicit scheduler domains from cgroup=cpu-list specs
def parse_cpumasks(specs):
  masks = {}
  for spec in " ".join(specs).split():
    group, sep, cpu_list = spec.partition("=")
    if not sep or not group.isdecimal() or not cpu_list:
      raise ValueError(f"Invalid CPU mapping {spec!r}; expected CGROUP=0-5,8")
    group = int(group)
    if group in masks:
      raise ValueError(f"Duplicate CPU mapping for cgroup {group}")
    cpus = set()
    for item in cpu_list.split(","):
      bounds = item.split("-")
      if len(bounds) not in (1, 2) or any(not bound.isdecimal() for bound in bounds):
        raise ValueError(f"Invalid CPU list {cpu_list!r}")
      first, last = int(bounds[0]), int(bounds[-1])
      if first > last:
        raise ValueError(f"Invalid CPU range {item!r}")
      cpus.update(range(first, last + 1))
    masks[group] = cpus
  return masks

# parse initial cgroup priorities when setup events precede the capture
def parse_weights(specs):
  weights = {}
  for spec in " ".join(specs).split():
    group, sep, weight = spec.partition("=")
    if not sep or not group.isdecimal() or not weight.isdecimal() or int(weight) > 0xffff:
      raise ValueError(f"Invalid weight mapping {spec!r}; expected CGROUP=0..65535")
    group = int(group)
    if group in weights:
      raise ValueError(f"Duplicate weight mapping for cgroup {group}")
    weights[group] = int(weight)
  return weights

# format CPU sets as ranges for display and replay commands
def format_cpu_list(cpus):
  ranges = []
  for cpu in sorted(cpus):
    if ranges and cpu == ranges[-1][1] + 1:
      ranges[-1][1] = cpu
    else:
      ranges.append([cpu, cpu])
  return ",".join(str(first) if first == last else f"{first}-{last}"
                  for first, last in ranges) or "-"

@dataclass
class Itv:
  start: int
  end: int
  value: object = None

# merge overlapping or touching intervals before measuring their union
def cover(itvs):
  result = []
  for itv in sorted(itvs, key=lambda itv: (itv.start, itv.end)):
    if itv.end <= itv.start:
      continue
    if result and itv.start <= result[-1].end:
      result[-1].end = max(result[-1].end, itv.end)
    else:
      result.append(Itv(itv.start, itv.end))
  return result

# sum elapsed time after overlapping intervals have been merged
def duration(itvs):
  return sum(itv.end - itv.start for itv in itvs)

class Timeline:
  # index interval starts for fast overlap queries
  def __init__(self, itvs):
    self.itvs = list(itvs)
    self.starts = [itv.start for itv in self.itvs]

  # turn ordered changes into intervals with fixed state
  @classmethod
  def from_changes(cls, changes, start, end, value=None):
    itvs = []
    for time, new_value in changes:
      if new_value == value:
        continue
      if time > start:
        itvs.append(Itv(start, time, value))
      # retain pre-window state without moving the window start backward
      start, value = max(start, time), new_value
    if end > start:
      itvs.append(Itv(start, end, value))
    return cls(itvs)

  # yield clipped intersections with the requested [start, end) window
  def overlaps(self, start, end):
    i = max(0, bisect_right(self.starts, start) - 1)
    while i < len(self.itvs) and self.itvs[i].start < end:
      itv = self.itvs[i]
      if itv.end > start:
        yield Itv(max(start, itv.start), min(end, itv.end), itv.value)
      i += 1

# intersect each left interval with the timeline selected by its value
def join(left, lookup):
  return Timeline(Itv(b.start, b.end, (a.value, b.value))
                  for a in left.itvs for b in lookup(a.value).overlaps(a.start, a.end))

# build interrupt occupancy per CPU, including nesting and partial capture boundaries
def irq_timelines(events, start, end):
  active, spans, seen = defaultdict(list), defaultdict(list), set()
  for event in events:
    if not is_irq_event(event.event_type):
      continue
    name, fields = event.event_type, event.details
    key = (event.cpu, name.rsplit("_", 1)[0], fields.get("irq", fields.get("vec")))
    if name.endswith("_entry"):
      active[key].append(event.time)
    else:
      if active[key]:
        begin = active[key].pop()
      elif key not in seen:
        begin = events[0].time
      else:
        raise ValueError(f"Unmatched IRQ exit on CPU {event.cpu} at {event.time}")
      spans[event.cpu].append(Itv(begin, event.time))
    seen.add(key)
  for (cpu, _, _), starts in active.items():
    spans[cpu].extend(Itv(begin, end) for begin in starts)
  return {cpu: Timeline.from_changes(((time, value) for itv in cover(itvs)
                                     for time, value in ((itv.start, True), (itv.end, False))), start, end, False)
          for cpu, itvs in spans.items()}

@dataclass(frozen=True)
class TaskRun:
  sched: int | None
  weight: int
  partition_cpu: int
  status: TaskStatus
  cpu: int

@dataclass(frozen=True)
class CpuRun:
  higher_class: bool
  priority: tuple | None
  available: bool

TASK_EVENTS = {
    "scxtp:scxtp_init_task_args", "scxtp:scxtp_exit_task_args",
    "scxtp:scxtp_enqueue_args", "scxtp:scxtp_running", "scxtp:scxtp_stopping",
    "scxtp:scxtp_set_task_weight", "scxtp:scxtp_set_cmask"}

# group events by task, CPU and scheduler weight for independent passes
def index_events(events, native, waking):
  tasks, cpus, weights = defaultdict(list), defaultdict(list), defaultdict(list)
  owners = {}
  for event in events:
    name, fields = event.event_type, event.details
    if event.sched is not None:
      weights[event.sched]
    if name in TASK_EVENTS:
      pid = fields["tid"]
      tasks[pid].append(("meta", event))
      weights[event.sched]
      if name == "scxtp:scxtp_exit_task_args":
        owners.pop(pid, None)
      else:
        owners[pid] = event.sched
    elif name == "scxtp:scxtp_exit":
      for pid in [pid for pid, owner in owners.items() if owner == event.sched]:
        tasks[pid].append(("exit", event))
        del owners[pid]
    elif name == "sched:sched_switch" and native:
      cpus[event.cpu].append((event.time, (fields["next_pid"], fields.get("next_prio"))))
      for pid in {fields["prev_pid"], fields["next_pid"]} - {0}:
        tasks[pid].append(("switch", event))
    elif name in ("sched:sched_waking", "sched:sched_wakeup", "sched:sched_wakeup_new"):
      if name == "sched:sched_wakeup_new" or (name == "sched:sched_waking") == waking:
        tasks[fields["pid"]].append(("wake", event))
    if not native:
      if name == "scxtp:scxtp_running" and fields["weight"]:
        cpus[event.cpu].append((event.time, (fields["tid"], None)))
      elif name == "scxtp:scxtp_stopping":
        cpus[event.cpu].append((event.time, (0, None)))
    if name in ("scxtp:scxtp_cgroup_init_args", "scxtp:scxtp_set_weight_args"):
      weights[fields["cgrp_id"]].append((event.time, fields["weight"]))
    elif name == "scxtp:scxtp_sub_params_update" and fields["cgrp_id"]:
      weights[fields["cgrp_id"]].append((event.time, fields["weight"]))
  return tasks, cpus, weights

# annotate events with future dispatch CPUs and resolved CID mappings
def prepare_events(events, *, use_sched_switch, use_waking):
  # resolve future execution within each task lifetime
  streams, _, _ = index_events(events, use_sched_switch, use_waking)
  for event in events:
    event.details.pop("_next_cpus", None)
  for pid, stream in streams.items():
    next_cpu = None
    for kind, event in reversed(stream):
      name, fields = event.event_type, event.details
      if kind == "exit" or name == "scxtp:scxtp_exit_task_args":
        next_cpu = None
      elif kind == "switch" and fields["next_pid"] == pid and not is_higher_class(fields.get("next_prio")):
        next_cpu = event.cpu
      elif name == "scxtp:scxtp_running" and not use_sched_switch and fields["weight"]:
        next_cpu = event.cpu
      fields.setdefault("_next_cpus", {})[pid] = next_cpu
      if name == "sched:sched_wakeup_new" or (name == "scxtp:scxtp_init_task_args" and fields.get("fork")):
        next_cpu = None
  # use later topology when initialization preceded its first emission
  topo = {}
  for event in events:
    if event.event_type == "scxtp:scxtp_cid_topo":
      topo.setdefault(event.details["cid"], event.details["cpu"])
  for event in events:
    fields = event.details
    if event.event_type == "scxtp:scxtp_cid_topo":
      topo[fields["cid"]] = fields["cpu"]
    elif event.event_type == "scxtp:scxtp_enqueue_args" and "prev_cid" in fields:
      cpu = topo.get(fields["prev_cid"], fields["_next_cpus"][fields["tid"]])
      if cpu is not None:
        fields["_partition_cpu"] = cpu
    elif event.event_type == "scxtp:scxtp_set_cmask" and fields["cmask"]:
      fields["_nmig_cpu"] = (-1 if fields["cmask"].bit_count() > 1 else
                            topo.get(fields["cmask"].bit_length() - 1))

# collect scheduler relations and CPU domains from ownership and mask events
def discover_scheds(events):
  groups = defaultdict(lambda: {"parents": set(), "cpus": set(), "cpumask": set(), "missing_cids": set()})
  owners, pending_owners, scx_pids = {}, {}, set()
  topo = {}
  for event in events:
    if event.event_type == "scxtp:scxtp_cid_topo":
      topo.setdefault(event.details["cid"], event.details["cpu"])
  for event in events:
    name, fields = event.event_type, event.details
    if event.sched is not None:
      groups[event.sched]
    if name == "scxtp:scxtp_sub_params_update" and fields["cgrp_id"]:
      child = groups[fields["cgrp_id"]]
      child["parents"].add(event.sched)
    elif name == "scxtp:scxtp_init_task_args":
      pid = fields["tid"]
      if pid not in owners:
        scx_pids.discard(pid)
      if pid in owners and owners[pid] != event.sched:
        pending_owners[pid] = event.sched
      else:
        owners[pid] = event.sched
    elif name in TASK_EVENTS - {"scxtp:scxtp_exit_task_args"}:
      pid = fields["tid"]
      owners[pid] = event.sched
      if pending_owners.get(pid) == event.sched:
        pending_owners.pop(pid)
      if name in ("scxtp:scxtp_enqueue_args", "scxtp:scxtp_set_task_weight"):
        scx_pids.add(pid)
      elif name == "scxtp:scxtp_running":
        if fields["weight"]:
          scx_pids.add(pid)
          groups[event.sched]["cpus"].add(event.cpu)
        else:
          scx_pids.discard(pid)
    elif name == "scxtp:scxtp_exit_task_args":
      pid = fields["tid"]
      if owners.get(pid) == event.sched:
        owners.pop(pid, None)
        if pid in pending_owners:
          owners[pid] = pending_owners.pop(pid)
        else:
          scx_pids.discard(pid)
      elif pending_owners.get(pid) == event.sched:
        pending_owners.pop(pid)
    elif name == "scxtp:scxtp_exit":
      owners = {pid: owner for pid, owner in owners.items() if owner != event.sched}
      pending_owners = {pid: owner for pid, owner in pending_owners.items() if owner != event.sched}
    elif name == "sched:sched_switch":
      owner = owners.get(fields["next_pid"])
      if owner is not None and fields["next_pid"] in scx_pids and not is_higher_class(fields.get("next_prio")):
        groups[owner]["cpus"].add(event.cpu)
    if name == "scxtp:scxtp_cid_topo":
      topo[fields["cid"]] = fields["cpu"]
    elif name == "scxtp:scxtp_set_cmask":
      mask = fields["cmask"]
      info = groups[event.sched]
      while mask:
        bit = mask & -mask
        cid = bit.bit_length() - 1
        if cid in topo:
          info["cpumask"].add(topo[cid])
        else:
          info["missing_cids"].add(cid)
        mask ^= bit
  for info in groups.values():
    info["cpumask"].update(info["cpus"])
  return groups

# reduce a task's events into runnable state, priority and partition changes
def task_changes(pid, events, native, real_nmig):
  state = None
  for kind, event in events:
    name, fields = event.event_type, event.details
    if kind == "exit" or name == "scxtp:scxtp_exit_task_args":
      state = None
    elif kind == "meta" and state is None:
      state = dict(sched=event.sched, weight=DEFAULT_TASK_WEIGHT, scx=False,
                   status=TaskStatus.BLOCKED, cpu=-1, partition_cpu=-1,
                   nmig_cpu=None, prio=None, future=True)
    if state is None:
      yield event.time, None
      continue
    hints = fields.get("_next_cpus", {})
    if pid in hints:
      state["future"] = hints[pid] is not None
      if state["partition_cpu"] < 0 and hints[pid] is not None:
        state["partition_cpu"] = hints[pid]
    if kind == "meta":
      state["sched"] = event.sched
      if name == "scxtp:scxtp_set_task_weight" or (name == "scxtp:scxtp_running" and fields["weight"]):
        state.update(weight=fields["weight"] & TASK_WEIGHT_MASK, scx=True)
      elif name == "scxtp:scxtp_running":
        state["scx"] = False
      if name == "scxtp:scxtp_set_cmask" and real_nmig and fields["cmask"]:
        state["nmig_cpu"] = fields["_nmig_cpu"]
        if state["nmig_cpu"] is None:
          raise ValueError("No CPU topology for task mask; capture scxtp_cid_topo")
      if name == "scxtp:scxtp_enqueue_args":
        state["scx"] = True
        state["partition_cpu"] = fields.get("_partition_cpu", state["partition_cpu"])
        if not native:
          state["status"] = TaskStatus.READY
      if name == "scxtp:scxtp_running" and fields["weight"]:
        state["partition_cpu"] = event.cpu
        if not native:
          state.update(status=TaskStatus.RUNNING, cpu=event.cpu)
      elif name == "scxtp:scxtp_stopping" and not native:
        state.update(cpu=-1, partition_cpu=event.cpu,
                     status=TaskStatus.READY if fields["runnable"] else TaskStatus.BLOCKED)
    elif kind == "switch":
      if fields["prev_pid"] == pid:
        runnable = (fields["prev_state"] & (TASK_REPORT_MAX - 1)) == 0
        state.update(cpu=-1, partition_cpu=event.cpu, prio=fields.get("prev_prio", state["prio"]),
                     status=TaskStatus.READY if runnable else TaskStatus.BLOCKED)
      if fields["next_pid"] == pid:
        state.update(cpu=event.cpu, partition_cpu=event.cpu, status=TaskStatus.RUNNING,
                     prio=fields.get("next_prio", state["prio"]))
    elif kind == "wake" and state["status"] != TaskStatus.RUNNING:
      state.update(status=TaskStatus.READY, prio=fields.get("prio", state["prio"]),
                   partition_cpu=fields.get("target_cpu", state["partition_cpu"]))
    weight = state["weight"]
    if real_nmig and state["nmig_cpu"] is not None:
      cpu = state["nmig_cpu"]
      weight = (weight & ~NMIG_MASK) | (NMIG_MASK if cpu >= 0 else 0)
      if cpu >= 0:
        state["partition_cpu"] = cpu
    active = state["scx"] and state["status"] != TaskStatus.BLOCKED
    if state["status"] == TaskStatus.READY:
      active = active and state["future"] and not is_higher_class(state["prio"])
    value = (TaskRun(state["sched"], weight, state["partition_cpu"], state["status"], state["cpu"])
             if active else None)
    yield event.time, value

class SchedCtx:
  def __init__(self, cpus, nmig_bit):
    self.cpus, self.nmig_bit = cpus, nmig_bit
    self.pending, self.pi, self.blocked = [], [], []

  # compare pending intervals directly with eligible CPU execution intervals
  def analyze(self, cpus):
    for pending in self.pending:
      cgrp_weight, weight = pending.value
      for cpu in self.cpus:
        for itv in cpus[cpu].overlaps(pending.start, pending.end):
          run = itv.value
          if run.higher_class:
            self.blocked.append(itv)
            continue
          if run.priority is None:
            inverted = run.available
          else:
            run_cgrp, run_weight = run.priority
            ctx_priority = (cgrp_weight, self.nmig_bit)
            run_priority = (run_cgrp, run_weight & NMIG_MASK)
            if self.nmig_bit is None:
              ctx_priority, run_priority = cgrp_weight, run_cgrp
            inverted = (run_priority < ctx_priority or
                        (run_priority == ctx_priority and run_weight < weight))
          if inverted:
            self.pi.append(itv)
    self.pi, self.blocked = cover(self.pi), cover(self.blocked)

class Sched:
  # create one context per partition and a global context when needed
  def __init__(self, cpus):
    self.cpus = cpus
    self.contexts = {cpu: SchedCtx({cpu}, None if len(cpus) == 1 else NMIG_MASK) for cpu in cpus}
    if len(cpus) > 1:
      self.contexts[None] = SchedCtx(cpus, 0)

  # route pending or interrupted intervals to their global or pinned CPU context
  def add(self, itv, *, blocked=False):
    task, cgrp_weight = itv.value
    if task is None or (task.status != TaskStatus.READY and not blocked):
      return
    cpu = task.partition_cpu if task.weight & NMIG_MASK else None
    if len(self.cpus) == 1:
      sole_cpu = next(iter(self.cpus))
      if cpu is not None and cpu >= 0 and cpu != sole_cpu:
        return
      cpu = sole_cpu
    ctx = self.contexts.get(cpu)
    if ctx is not None:
      if blocked:
        ctx.blocked.append(Itv(itv.start, itv.end))
      else:
        ctx.pending.append(Itv(itv.start, itv.end, (cgrp_weight, task.weight)))

  # union context intervals into per-scheduler PI and blocking totals
  def analyze(self, cpus):
    for ctx in self.contexts.values():
      if ctx.pending or ctx.blocked:
        ctx.analyze(cpus)
    self.global_pi = self.contexts[None].pi if None in self.contexts else []
    self.partitioned_pi = cover(itv for cpu, ctx in self.contexts.items() if cpu is not None for itv in ctx.pi)
    self.pi = cover([*self.global_pi, *self.partitioned_pi])
    self.blocked = cover(itv for ctx in self.contexts.values() for itv in ctx.blocked)

# build independent timelines, join their metadata and evaluate contexts
def analyze(events, cpumasks, *, native, waking, real_nmig=False, cgrp_weights=None, skip_ns=0):
  start, end = events[0].time + skip_ns, events[-1].time
  if skip_ns < 0 or (skip_ns and start >= end):
    raise ValueError("Skip must leave a nonempty analysis window")
  cgrp_weights = cgrp_weights or {}
  # first pass: reduce each task, CPU and scheduler-weight stream independently
  task_events, cpu_events, weight_events = index_events(events, native, waking)
  groups = discover_scheds(events)
  unknown = Timeline.from_changes([], start, end)
  weights = {sid: Timeline.from_changes(changes, start, end,
                                        cgrp_weights.get(sid, DEFAULT_CGROUP_WEIGHT if sid else 0xffff))
             for sid, changes in weight_events.items()}
  tasks = {pid: Timeline.from_changes(task_changes(pid, stream, native, real_nmig), start, end)
           for pid, stream in task_events.items()}
  # join scheduler weights onto task intervals, then tasks onto CPU execution
  tasks = {pid: join(task, lambda value: weights[value.sched] if value else unknown)
           for pid, task in tasks.items()}
  untracked = Timeline.from_changes([], start, end, (None, None))
  all_cpus = {event.cpu for event in events}
  all_cpus.update(event.details["cpu"] for event in events if event.event_type == "scxtp:scxtp_cid_topo")
  irqs = irq_timelines(events, start, end)
  cpus = {}
  for cpu in range(max(all_cpus.union(*cpumasks.values())) + 1):
    raw = Timeline.from_changes(cpu_events[cpu], start, end, (None, None) if native else (0, None))
    joined = join(raw, lambda run: tasks.get(run[0], untracked))
    itvs = []
    for itv in joined.itvs:
      (pid, prio), (task, cgrp_weight) = itv.value
      tracked = task is not None and task.status == TaskStatus.RUNNING and task.cpu == cpu
      priority = (cgrp_weight, task.weight) if tracked else None
      itvs.append(Itv(itv.start, itv.end, CpuRun(is_higher_class(prio), priority,
                                                     available=not native or pid == 0)))
    cpus[cpu] = Timeline(itvs)
    if cpu in irqs:
      overlay = join(cpus[cpu], lambda _: irqs[cpu])
      cpus[cpu] = Timeline(Itv(itv.start, itv.end, CpuRun(True, None, False) if itv.value[1] else itv.value[0])
                           for itv in overlay.itvs)
  # second pass: route pending intervals and analyze their contexts
  scheds = {}
  for sid in weights:
    info = groups[sid]
    if sid not in cpumasks and info["missing_cids"]:
      cid = min(info["missing_cids"])
      raise ValueError(f"No CPU topology for scheduler {sid} mask CID {cid}; "
                       "capture scxtp_cid_topo or supply --cmasks")
    scheds[sid] = Sched(cpumasks.get(sid, info["cpumask"]))
  for task in tasks.values():
    for itv in task.itvs:
      if itv.value[0] is not None:
        run = itv.value[0]
        sched = scheds[run.sched]
        sched.add(itv)
        if run.status == TaskStatus.RUNNING and run.cpu in irqs and run.cpu in sched.cpus:
          for irq in irqs[run.cpu].overlaps(itv.start, itv.end):
            if irq.value:
              sched.add(Itv(irq.start, irq.end, itv.value), blocked=True)
  for sched in scheds.values():
    sched.analyze(cpus)
  return cpus, scheds

# print scheduler and CPU totals, with optional inversion boundaries
def report(cpus, scheds, total, verbose=False):
  # interval cover: combine context results without adding overlapping durations
  pi = cover(itv for sched in scheds.values() for itv in sched.pi)
  blocked = cover(itv for sched in scheds.values() for itv in sched.blocked)
  print(f"Total time: {total}ns")
  if not total:
    return
  def metric(label, time):
    print(f"{label}: {time}ns ({time / total * 100:.2f}%)")
  metric("Priority Inversion", duration(pi))
  metric("Higher-class blocking", duration(blocked))
  for sid, sched in scheds.items():
    if sid is not None:
      print(f"Scheduler {sid} effective CPUs: {sorted(sched.cpus)}")
      metric(f"Scheduler {sid} Priority Inversion", duration(sched.pi))
      metric("  Global PI", duration(sched.global_pi))
      metric("  Partitioned PI", duration(sched.partitioned_pi))
      metric("  Higher-class blocking", duration(sched.blocked))
  for cpu, timeline in cpus.items():
    task_time = sum(itv.end - itv.start for itv in timeline.itvs if itv.value.priority is not None)
    higher_time = sum(itv.end - itv.start for itv in timeline.itvs if itv.value.higher_class)
    print(f"CPU {cpu}:")
    metric("  Other/idle time", total - task_time)
    metric("  Task time", task_time)
    metric("  Higher-class time", higher_time)
  if verbose:
    groups = [("PI", pi), *((f"Scheduler {sid} PI", sched.pi) for sid, sched in scheds.items())]
    changes = [(time, f"{label} {kind}") for label, itvs in groups for itv in itvs
                   for time, kind in ((itv.start, "START"), (itv.end, "END"))]
    for time, label in sorted(changes):
      print(f"{label} at time {time}")

# display discovered relations and dispatch CPUs with a suggested replay command
def dump_hierarchy(groups, trace, cgrp_weights=None, *, plugin_path=None, skip=0):
  print("Scheduler hierarchy (all observed relations; CPUs dispatched to):")
  for group, info in sorted(groups.items()):
    parents = ",".join(map(str, sorted(info["parents"]))) or "-"
    print(f"  {group}: parents={parents} cpus={format_cpu_list(info['cpus'])}")
  cpumasks = " ".join(f"{group}={format_cpu_list(info['cpus'])}"
                       for group, info in sorted(groups.items()) if info["cpus"])
  command = [sys.executable, sys.argv[0], str(trace)]
  if cpumasks:
    command.extend(["--cmasks", cpumasks])
  if cgrp_weights:
    command.extend(["--weights", " ".join(f"{sid}={weight}" for sid, weight in sorted(cgrp_weights.items()))])
  if plugin_path:
    command.extend(["--plugin", plugin_path])
  if skip:
    command.extend(["--skip", str(skip)])
  print("\nSuggested command (adjust observed masks to match your workload):")
  print("  " + shlex.join(command))

# read CLI options and run hierarchy discovery or interval analysis
def main():
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("trace", metavar="TRACE.dat")
  parser.add_argument("-v", "--verbose", action="store_true", help="print inversion interval boundaries")
  parser.add_argument("--real-nmig", action="store_true", help="derive nmig from effective task masks when available")
  parser.add_argument("--dump-hierarchy", action="store_true", help="dump scheduler relations, execution CPUs and a suggested command")
  parser.add_argument("--plugin", metavar="PATH", help="ftrace babeltrace plugin file or directory (default: installed ftrace plugin)")
  parser.add_argument("--skip", type=float, default=0, metavar="SECONDS",
                      help="exclude the first SECONDS from results while retaining their state (default: 0)")
  parser.add_argument("--cmasks", nargs="+", action="extend", default=[], metavar="CGROUP=CPUS",
                      help='fixed Linux CPU mappings, e.g. "3029=0-5 3903=6" (default: task execution CPUs and mask updates)')
  parser.add_argument("--weights", nargs="+", action="extend", default=[], metavar="CGROUP=WEIGHT",
                      help='initial cgroup weights, e.g. "3029=200 3903=100"; recorded updates still apply '
                           '(default: 100; root: 65535)')
  args = parser.parse_args()
  if not math.isfinite(args.skip) or args.skip < 0:
    parser.error("--skip must be a finite, nonnegative number of seconds")
  try:
    cpumasks = parse_cpumasks(args.cmasks)
    cgrp_weights = parse_weights(args.weights)
  except ValueError as error:
    parser.error(str(error))
  print("Reading trace:", args.trace)
  events = list(parse_trace(read_trace(args.trace, args.plugin)))
  print(f"Read {len(events)} scheduler events.")
  print(f"IRQ entry/exit events: {sum(is_irq_event(event.event_type) for event in events)}")
  if not events:
    print("No scheduler events found.")
    return
  if args.dump_hierarchy:
    dump_hierarchy(discover_scheds(events), args.trace, cgrp_weights, plugin_path=args.plugin, skip=args.skip)
    return
  native = any(event.event_type == "sched:sched_switch" for event in events)
  waking = any(event.event_type == "sched:sched_waking" for event in events)
  if not native and not any(event.event_type == "scxtp:scxtp_running" for event in events):
    print("No execution events found, capture sched:sched_switch or enable hotpath tracing.")
    return
  # pre-pass: resolve future dispatches, topology and effective mask CPUs
  prepare_events(events, use_sched_switch=native, use_waking=waking)
  if args.real_nmig:
    print("NMIG definition: effective task masks (weight-bit fallback before each task's first mask)")
  skip_ns = int(args.skip * 1_000_000_000)
  if skip_ns and skip_ns >= events[-1].time - events[0].time:
    parser.error("--skip must leave a nonempty analysis window")
  if skip_ns:
    print(f"Skipping {skip_ns}ns of warm-up; retaining earlier task and CPU state")
  print("Building timelines and analyzing contexts")
  cpus, scheds = analyze(events, cpumasks, native=native, waking=waking,
                        real_nmig=args.real_nmig, cgrp_weights=cgrp_weights, skip_ns=skip_ns)
  report(cpus, scheds, events[-1].time - events[0].time - skip_ns, args.verbose)

if __name__ == "__main__":
  main()
