# checks for priority inversions based on switch + trace events

from bisect import insort
import sys
import traceback
from collections import namedtuple
from enum import Enum

if __package__:
  from .trace_helpers import TraceParser
else:
  from trace_helpers import TraceParser

# assume migratable tasks; ignore the nmig flag in traced weights
TASK_WEIGHT_MASK = (1 << 63) - 1
DEFAULT_TASK_WEIGHT = TASK_WEIGHT_MASK
DEFAULT_CGROUP_WEIGHT = 100

# sched_switch uses this bit to mark a runnable, preempted task
TASK_REPORT_MAX = 0x100

class ExecBlock:
  def __init__(self, sched, start_time, end_time, cpu):
    self.sched = sched
    self.start_time = start_time
    self.end_time = end_time
    self.cpu = cpu

  def __str__(self):
    return f"ExecBlock(sched={self.sched}, start_time={self.start_time}, end_time={self.end_time}, cpu={self.cpu})"

class TaskExecBlock(ExecBlock):
  def __init__(self, sched, start_time, end_time, cpu, pid, weight):
    super().__init__(sched, start_time, end_time, cpu)
    self.pid = pid
    self.weight = weight

  def __str__(self):
    return f"TaskExecBlock(sched={self.sched}, start_time={self.start_time}, end_time={self.end_time}, cpu={self.cpu}, pid={self.pid})"

class RunState(Enum):
  IDLE = 0
  TASK = 1

class TaskStatus(Enum):
  RUNNING = 0
  READY = 1
  BLOCKED = 2 # also includes tasks moving from READY to RUNNING

class TaskState:
  def __init__(self, pid):
    self.pid = pid
    self.weight = DEFAULT_TASK_WEIGHT
    self.cpu = -1
    self.status = TaskStatus.BLOCKED
    self.sched = None

class SchedState:
  def __init__(self, cgrp_id):
    self.cgrp_id = cgrp_id
    self.weight = DEFAULT_CGROUP_WEIGHT if cgrp_id else 0xffff

class CPUState:
  def __init__(self, cpu, start_time):
    self.cid = -1
    self.cpu = cpu
    self.task_running = None
    self.task_exec_blocks = []
    self.idle_time = 0
    self.task_time = 0
    self.curr_time = start_time

  def update_time(self, time):
    match self.run_state():
      case RunState.TASK:
        self.task_time += time - self.curr_time
      case RunState.IDLE:
        self.idle_time += time - self.curr_time
    self.curr_time = time

  def run_state(self):
    if self.task_running is not None:
      return RunState.TASK
    return RunState.IDLE

  def task_start(self, time, sched, pid, weight):
    self.update_time(time)
    assert(self.task_running is None)
    self.task_running = TaskExecBlock(sched, time, None, self.cpu, pid, weight)

  def task_end(self, time, sched, pid):
    self.update_time(time)
    if self.run_state() == RunState.IDLE:
      return

    assert(self.task_running is not None)
    assert(self.task_running.pid == pid)
    self.task_running.end_time = time
    self.task_exec_blocks.append(self.task_running)
    self.task_running = None

  def __str__(self):
    return f"CPU {self.cpu}\n  task_running: {self.task_running}\n"

class ExecModel:
  def __init__(self, start_time, *, use_sched_switch=False):
    self.cpus = []
    self.start_time = start_time
    self.curr_time = start_time
    self.pi_time = 0
    self.tasks = {}
    self.scheds = {}
    self.pending_weights = [] # (cgroup_weight, task_weight)
    self.running_weights = [] # (cgroup_weight, task_weight)
    self.pi = False # priority inversion?
    self.use_sched_switch = use_sched_switch
  
  def fetch_cpu(self, cpu_id):
    while len(self.cpus) <= cpu_id:
      self.cpus.append(CPUState(len(self.cpus), self.start_time))
    return self.cpus[cpu_id]

  def get_sched(self, sched):
    if sched not in self.scheds:
      self.scheds[sched] = SchedState(sched)
    return self.scheds[sched]

  def get_task(self, pid):
    if pid not in self.tasks:
      self.tasks[pid] = TaskState(pid)
    return self.tasks[pid]

  def get_weight(self, pid):
    task_state = self.get_task(pid)
    sched_state = self.get_sched(task_state.sched)
    return (sched_state.weight, task_state.weight)

  def update_pi(self):
    max_pending_weight = self.pending_weights[-1] if len(self.pending_weights) > 0 else (0, 0)
    min_running_weight = self.running_weights[0] if len(self.running_weights) > 0 else (0, 0)
    self.pi = max_pending_weight > min_running_weight

  def change_status(self, pid, new_status):
    task_state = self.get_task(pid)
    weight = self.get_weight(pid)
    if task_state.status == new_status:
      return
    match task_state.status:
      case TaskStatus.READY:
        self.pending_weights.remove(weight)
      case TaskStatus.RUNNING:
        self.running_weights.remove(weight)
    task_state.status = new_status
    match new_status:
      case TaskStatus.READY:
        insort(self.pending_weights, weight)
      case TaskStatus.RUNNING:
        insort(self.running_weights, weight)
    self.update_pi()
  
  def dump_pi_info(self):
    print(f"Time {self.curr_time}: PI {'YES' if self.pi else 'NO'}")
    print(f"  Pending weights: {list(self.pending_weights)}")
    print(f"  Running weights: {list(self.running_weights)}")

  def update_task_weight(self, pid, weight):
    task_state = self.get_task(pid)
    status = task_state.status
    self.change_status(pid, TaskStatus.BLOCKED)
    task_state.weight = weight & TASK_WEIGHT_MASK
    self.change_status(pid, status)
    self.update_pi()

  def refresh_weights(self):
    self.pending_weights.clear()
    self.running_weights.clear()
    for task_state in self.tasks.values():
      weight = self.get_weight(task_state.pid)
      if task_state.status == TaskStatus.READY:
        insort(self.pending_weights, weight)
      elif task_state.status == TaskStatus.RUNNING:
        insort(self.running_weights, weight)
    self.update_pi()

  def assign_sched(self, pid, sched):
    task_state = self.get_task(pid)
    status = task_state.status
    self.change_status(pid, TaskStatus.BLOCKED)
    task_state.sched = sched
    self.change_status(pid, status)

  def task_start(self, time, cpu, pid):
    task = self.get_task(pid)
    self.change_status(pid, TaskStatus.RUNNING)
    task.cpu = cpu
    self.fetch_cpu(cpu).task_start(time, task.sched, pid, task.weight)

  def task_stop(self, time, cpu, pid, runnable):
    task = self.get_task(pid)
    self.fetch_cpu(cpu).task_end(time, task.sched, pid)
    task.cpu = -1
    self.change_status(pid, TaskStatus.READY if runnable else TaskStatus.BLOCKED)

  def remove_task(self, time, pid):
    if pid not in self.tasks:
      return
    task = self.tasks[pid]
    if task.cpu >= 0:
      self.task_stop(time, task.cpu, pid, False)
    self.change_status(pid, TaskStatus.BLOCKED)
    del self.tasks[pid]

  def handle_event(self, event):
    assert(event.time >= self.curr_time)
    delta = event.time - self.curr_time
    if self.pi:
      self.pi_time += delta
    self.curr_time = event.time
    old_pi = self.pi
    fields = event.details
    match event.event_type:
      case "scxtp:scxtp_stopping":
        pid = fields["tid"]
        self.assign_sched(pid, event.sched)
        if not self.use_sched_switch:
          self.task_stop(event.time, event.cpu, pid, fields["runnable"])
      case "scxtp:scxtp_running":
        pid = fields["tid"]
        self.assign_sched(pid, event.sched)
        self.update_task_weight(pid, fields["weight"])
        if not self.use_sched_switch:
          self.task_start(event.time, event.cpu, pid)
      case "scxtp:scxtp_enqueue_args":
        pid = fields["tid"]
        self.assign_sched(pid, event.sched)
        if not self.use_sched_switch:
          self.change_status(pid, TaskStatus.READY)
      case "scxtp:scxtp_set_task_weight":
        pid = fields["tid"]
        self.assign_sched(pid, event.sched)
        self.update_task_weight(pid, fields["weight"])
      case "scxtp:scxtp_init":
        sched_state = self.get_sched(event.sched)
        sched_state.cgrp_id = fields["cgrp_id"]
      case "scxtp:scxtp_cgroup_init_args" | "scxtp:scxtp_set_weight_args" | "scxtp:scxtp_sub_params_update":
        # a zeroed sub slot describes detachment, not a root weight update
        if event.event_type != "scxtp:scxtp_sub_params_update" or fields["cgrp_id"]:
          self.get_sched(fields["cgrp_id"]).weight = fields["weight"]
          self.refresh_weights()
      case "scxtp:scxtp_init_task_args":
        self.assign_sched(fields["tid"], event.sched)
      case "scxtp:scxtp_exit_task_args":
        self.remove_task(event.time, fields["tid"])
      case "scxtp:scxtp_exit":
        for pid, task in list(self.tasks.items()):
          if task.sched == event.sched:
            self.remove_task(event.time, pid)
      case "scxtp:scxtp_cid_topo":
        self.fetch_cpu(fields["cpu"]).cid = fields["cid"]
      case "sched:sched_wakeup" | "sched:sched_wakeup_new":
        pid = fields["pid"]
        if pid in self.tasks and self.tasks[pid].status != TaskStatus.RUNNING:
          self.change_status(pid, TaskStatus.READY)
      case "sched:sched_switch":
        prev_pid = fields["prev_pid"]
        next_pid = fields["next_pid"]
        if prev_pid in self.tasks:
          runnable = (fields["prev_state"] & (TASK_REPORT_MAX - 1)) == 0
          self.task_stop(event.time, event.cpu, prev_pid, runnable)
        if next_pid in self.tasks:
          self.task_start(event.time, event.cpu, next_pid)
    if self.pi and not old_pi:
      print(f"PI START at time {self.curr_time}")
      self.dump_pi_info()
    elif not self.pi and old_pi:
      print(f"PI END at time {self.curr_time}")
      self.dump_pi_info()
        
  def finish(self):
    for cpu in self.cpus:
      cpu.update_time(self.curr_time)

    total_time = self.curr_time - self.start_time
    print(f"Total time: {total_time}ns")
    if total_time == 0:
      return
    print(f"Priority Inversion: {self.pi_time}ns ({self.pi_time / total_time * 100:.2f}%)")
    for cpu in self.cpus:
      print(f"CPU {cpu.cpu}:")
      print(f"  Other/idle time: {cpu.idle_time}ns ({cpu.idle_time / total_time * 100:.2f}%)")
      print(f"  Task time: {cpu.task_time}ns ({cpu.task_time / total_time * 100:.2f}%)")

  def __str__(self):
    return "\n".join([str(cpu) for cpu in self.cpus])

Event = namedtuple('Event', ['sched', 'time', 'cpu', 'event_type', 'details'])

def parse_trace(messages):
  for message in messages:
    event = message.event
    if not (event.name.startswith("scxtp:scxtp_") or event.name in
            ("sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new")):
      continue
    fields = {name: int(value) for name, value in event.payload_field.items() if name not in
              ("prev_comm", "next_comm", "comm")}
    yield Event(sched=fields.get("sched_cgrp_id"),
                time=message.default_clock_snapshot.ns_from_origin,
                cpu=int(event.packet.context_field["cpu_id"]),
                event_type=event.name, details=fields)

def main():
  if len(sys.argv) != 2:
    raise SystemExit("Usage: parse_events.py TRACE.dat")
  print("Reading trace:", sys.argv[1])
  with TraceParser(sys.argv[1]) as parser:
    events = list(parse_trace(parser))
  print(f"Read {len(events)} scheduler events.")
  if not events:
    print("No scheduler events found.")
    return

  print("Building exec model")
  # use one execution source when native and custom events are both recorded
  use_sched_switch = any(e.event_type == "sched:sched_switch" for e in events)
  if not use_sched_switch and not any(e.event_type == "scxtp:scxtp_running" for e in events):
    print("No execution events found; capture sched:sched_switch or enable hotpath tracing.")
    return
  model = ExecModel(events[0].time, use_sched_switch=use_sched_switch)
  for i, event in enumerate(events):
    try:
      model.handle_event(event)
    except Exception as e:
      print(f"Error while handling event {i}: {event}\n{e}")
      print(model)
      traceback.print_exc()
      exit(1)
  model.finish()

if __name__ == "__main__":
  main()
