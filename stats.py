# python script to combine trace files and generate stats

import re
import sys
import os
import traceback
import time
import multiprocessing as mp
from sortedcontainers import SortedList
from concurrent.futures import ProcessPoolExecutor
from collections import namedtuple
from enum import Enum

DEFAULT_TASK_WEIGHT = (1 << 64) - 1
DEFAULT_CGROUP_WEIGHT = 1

class ExecBlock:
  def __init__(self, sched, start_time, end_time, cpu):
    self.sched = sched
    self.start_time = start_time
    self.end_time = end_time
    self.cpu = cpu

  def __str__(self):
    return f"ExecBlock(sched={self.sched}, start_time={self.start_time}, end_time={self.end_time}, cpu={self.cpu})"

class ScxExecBlock(ExecBlock):
  # func is only the top-level function so that helper functions and nested dispatches can be flattened
  def __init__(self, sched, start_time, end_time, cpu, func):
    super().__init__(sched, start_time, end_time, cpu)
    self.func = func

  def __str__(self):
    return f"ScxExecBlock(sched={self.sched}, start_time={self.start_time}, end_time={self.end_time}, cpu={self.cpu}, func={self.func})"

class TaskExecBlock(ExecBlock):
  def __init__(self, sched, start_time, end_time, cpu, pid, weight):
    super().__init__(sched, start_time, end_time, cpu)
    self.pid = pid
    self.weight = weight

  def __str__(self):
    return f"TaskExecBlock(sched={self.sched}, start_time={self.start_time}, end_time={self.end_time}, cpu={self.cpu}, pid={self.pid})"

class RunState(Enum):
  IDLE = 0
  SCX = 1
  TASK = 2

class TaskStatus(Enum):
  RUNNING = 0
  READY = 1
  BLOCKED = 2 # also includes tasks moving from READY to RUNNING

IGNORED_FUNCS = set(["running", "stopping"])

class TaskState:
  def __init__(self, pid):
    self.pid = pid
    self.weight = DEFAULT_TASK_WEIGHT
    self.cpu = -1
    self.status = TaskStatus.BLOCKED
    self.sched = None

class SchedState:
  def __init__(self):
    self.cgrp_id = 0
    self.weight = DEFAULT_CGROUP_WEIGHT

class CPUState:
  def __init__(self, cpu, start_time):
    self.cpu = cpu
    self.task_running = None
    self.scx_running = None
    self.task_exec_blocks = []
    self.scx_exec_blocks = []
    self.scx_stack = []
    self.idle_time = 0
    self.scx_time = 0
    self.task_time = 0
    self.curr_time = start_time

  def update_time(self, time):
    match self.run_state():
      case RunState.SCX:
        self.scx_time += time - self.curr_time
      case RunState.TASK:
        self.task_time += time - self.curr_time
      case RunState.IDLE:
        self.idle_time += time - self.curr_time
    self.curr_time = time

  def run_state(self):
    if self.scx_running is not None:
      return RunState.SCX
    elif self.task_running is not None:
      return RunState.TASK
    return RunState.IDLE

  def scx_func_start(self, time, sched, func):
    self.update_time(time)
    if func in IGNORED_FUNCS:
      return
    
    if self.scx_running is None:
      assert(len(self.scx_stack) == 0)
      self.scx_running = ScxExecBlock(sched, time, None, self.cpu, func)

    self.scx_stack.append(func)
    
  def scx_func_end(self, time, sched, func):
    self.update_time(time)
    if func in IGNORED_FUNCS:
      return
    if self.scx_running is None:
      print("WARNING: FUNC_END with no running block (ignoring)")
      return
      
    assert(self.run_state() == RunState.SCX)
    assert(len(self.scx_stack) > 0)
    assert(self.scx_stack[-1] == func)
    self.scx_stack.pop()
    if len(self.scx_stack) == 0:
      self.scx_running.end_time = time
      self.task_exec_blocks.append(self.scx_running)
      self.scx_running = None

  def task_start(self, time, sched, pid, weight):
    self.update_time(time)
    assert(self.task_running is None)
    self.task_running = TaskExecBlock(sched, time, None, self.cpu, pid, weight)

  def task_end(self, time, sched, pid):
    self.update_time(time)
    if self.run_state() == RunState.IDLE:
      print("WARNING: STOP_TASK with no running block (ignoring)")
      return

    assert(self.task_running is not None)
    assert(self.task_running.pid == pid)
    self.task_running.end_time = time
    self.task_exec_blocks.append(self.task_running)
    self.task_running = None

  def __str__(self):
    return f"CPU {self.cpu}\n  scx_stack: {self.scx_stack}\n  scx_running: {self.scx_running}\n  task_running: {self.task_running}\n"

class ExecModel:
  def __init__(self, start_time):
    self.cpus = []
    self.start_time = start_time
    self.curr_time = start_time
    self.pi_time = 0
    self.tasks = {}
    self.scheds = {}
    self.pending_weights = SortedList() # (cgroup_weight, task_weight)
    self.running_weights = SortedList() # (cgroup_weight, task_weight)
    self.pi = False # priority inversion?
  
  def fetch_cpu(self, cpu_id):
    while len(self.cpus) <= cpu_id:
      self.cpus.append(CPUState(len(self.cpus), self.start_time))
    return self.cpus[cpu_id]

  def get_sched(self, sched):
    if sched not in self.scheds:
      self.scheds[sched] = SchedState()
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
        self.pending_weights.add(weight)
      case TaskStatus.RUNNING:
        self.running_weights.add(weight)
    self.update_pi()
  
  def dump_pi_info(self):
    print(f"Time {self.curr_time}: PI {'YES' if self.pi else 'NO'}")
    print(f"  Pending weights: {list(self.pending_weights)}")
    print(f"  Running weights: {list(self.running_weights)}")

  def update_task_weight(self, pid, weight):
    task_state = self.get_task(pid)
    status = task_state.status
    self.change_status(pid, TaskStatus.BLOCKED)
    task_state.weight = weight
    self.change_status(pid, status)
    self.update_pi()

  def refresh_weights(self):
    self.pending_weights.clear()
    self.running_weights.clear()
    for task_state in self.tasks.values():
      weight = self.get_weight(task_state.pid)
      if task_state.status == TaskStatus.READY:
        self.pending_weights.add(weight)
      elif task_state.status == TaskStatus.RUNNING:
        self.running_weights.add(weight)
    self.update_pi()

  def assign_sched(self, pid, sched):
    task_state = self.get_task(pid)
    status = task_state.status
    self.change_status(pid, TaskStatus.BLOCKED)
    task_state.sched = sched
    self.change_status(pid, status)

  def handle_event(self, event):
    assert(event.time >= self.curr_time)
    delta = event.time - self.curr_time
    if self.pi:
      self.pi_time += delta
    self.curr_time = event.time
    old_pi = self.pi
    match event.event_type:
      case "STOP_TASK":
        pid = int(event.details[0].removeprefix("pid=").strip())
        self.assign_sched(pid, event.sched)
        self.change_status(pid, TaskStatus.BLOCKED)
        cpu_state = self.fetch_cpu(int(event.cpu))
        cpu_state.task_end(event.time, event.sched, pid)
      case "RUN_TASK":
        pid = int(event.details[0].removeprefix("pid=").strip())
        self.assign_sched(pid, event.sched)
        self.change_status(pid, TaskStatus.RUNNING)
        task_state = self.get_task(pid)
        cpu_state = self.fetch_cpu(int(event.cpu))
        cpu_state.task_start(event.time, event.sched, pid, task_state.weight)
      case "FUNC_START":
        func = event.details[0].strip()
        cpu_state = self.fetch_cpu(int(event.cpu))
        cpu_state.scx_func_start(event.time, event.sched, func)
      case "FUNC_END":
        func = event.details[0].strip()
        cpu_state = self.fetch_cpu(int(event.cpu))
        cpu_state.scx_func_end(event.time, event.sched, func)
      case "ENQUEUE_TASK":
        pid = int(event.details[0].removeprefix("pid=").strip())
        self.assign_sched(pid, event.sched)
        self.change_status(pid, TaskStatus.READY)
      case "DEQUEUE_TASK":
        pid = int(event.details[0].removeprefix("pid=").strip())
        self.assign_sched(pid, event.sched)
        self.change_status(pid, TaskStatus.BLOCKED)
      case "SET_TASK_WEIGHT":
        pid = int(event.details[0].removeprefix("pid=").strip())
        weight = int(event.details[1].removeprefix("weight=").strip())
        self.assign_sched(pid, event.sched)
        self.update_task_weight(pid, weight)
      case "SELF":
        cgrp_id = int(event.details[0].removeprefix("cgrp_id=").strip())
        weight = int(event.details[1].removeprefix("weight=").strip())
        sched_state = self.get_sched(event.sched)
        sched_state.weight = weight
        sched_state.cgrp_id = cgrp_id
        self.refresh_weights()
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
    print(f"Priority Inversion: {self.pi_time}ns ({self.pi_time / (self.curr_time - self.start_time) * 100:.2f}%)")
    total_idle_time = 0
    total_scx_time = 0
    total_task_time = 0
    for cpu in self.cpus:
      print(f"CPU {cpu.cpu}:")
      print(f"  Idle time: {cpu.idle_time}ns ({cpu.idle_time / total_time * 100:.2f}%)")
      print(f"  SCX time: {cpu.scx_time}ns ({cpu.scx_time / total_time * 100:.2f}%)")
      print(f"  Task time: {cpu.task_time}ns ({cpu.task_time / total_time * 100:.2f}%)")
      total_idle_time += cpu.idle_time
      total_scx_time += cpu.scx_time
      total_task_time += cpu.task_time

  def __str__(self):
    return "\n".join([str(cpu) for cpu in self.cpus])

Event = namedtuple('Event', ['sched', 'time', 'rel_time', 'cpu', 'event_type', 'details'])

def parse_trace(lines):
  for i in range(len(lines)):
    line = lines[i]
    line, start_time = line.split(" st=")
    start_time = int(start_time)
    sched, meta, event_type, *details = [x.removeprefix("[").removesuffix("]") for x in line.strip().split(" ") if x]
    rel_time, cpu = [ int(x.split("=")[1]) for x in meta.split(":") ]
    time = start_time + rel_time
    event_type = event_type.removesuffix(":")
    lines[i] = Event(sched=sched, time=time, rel_time=rel_time, cpu=cpu, event_type=event_type, details=details)
  return lines

def main():
  trace_dir = sys.argv[1]
  print("Reading trace files from directory:", trace_dir)
  lines = []
  for root, dirs, files in os.walk(trace_dir):
    for filename in files:
      if filename.endswith(".trace"):
        file_path = os.path.join(root, filename)
        print(f"Reading trace file: {file_path}")
        with open(file_path, 'r') as f:
          file_lines = f.readlines()
          start_time = f" st={int(file_lines[0].removeprefix('start time:').strip())}"
          lines.extend([l + start_time for l in file_lines[1:]])
  nlines = len(lines)
  print(f"Read {nlines} lines from trace files.")
  print("Parsing trace events")
  events = parse_trace(lines)

  # procs = 4
  # chunk_size = nlines // procs
  # rem = nlines % procs

  # chunks = [[]] * procs
  # offset = 0
  # for i in range(procs):
  #   size = chunk_size + (1 if i < rem else 0)
  #   end = offset + size
  #   chunks[i] = lines[offset:end]
  #   offset = end

  # events = []
  # with ProcessPoolExecutor(max_workers=procs) as executor:
  #   for r in executor.map(parse_trace, chunks):
  #     print(f"Received {len(r)} events from worker")
  #     events.extend(r)
  events = [e for e in events if e is not None]

  print("Sorting events")
  for e in events:
    assert(type(e.time) == int)
  events.sort(key=lambda x: x.time)

  print("Building exec model")
  model = ExecModel(events[0].time)
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