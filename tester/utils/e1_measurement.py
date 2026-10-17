"""E1 warmup, gated measurement timing and workload-CPU utilization counters."""

import os
import time

from . import common, e1_workloads


def warmup(session, stress, duration):
  finish = time.monotonic() + duration
  while time.monotonic() < finish:
    session.check()
    stress.check()
    time.sleep(min(.05, max(0, finish - time.monotonic())))


def record_interval(config, session, job, directory, cpus, capture, *, stress=None, partitions=None):
  gate = e1_workloads.open_gate(session, directory)
  try:
    before = common.cpu_times(cpus)
    capture["start_ns"] = time.monotonic_ns()
    os.write(gate, b"g")
  finally:
    os.close(gate)
  finish = time.monotonic() + config["duration_s"] + config["process_timeout_s"]
  next_stress_check = time.monotonic()
  while job.process.poll() is None:
    session.check()
    if partitions:
      partitions.check()
    if time.monotonic() >= finish:
      raise TimeoutError("cyclictest exceeded its configured duration and shutdown timeout")
    if stress and time.monotonic() >= next_stress_check:
      stress.check()
      next_stress_check = time.monotonic() + 1
    time.sleep(.02)
  capture["end_ns"] = time.monotonic_ns()
  after = common.cpu_times(cpus)
  if job.process.returncode:
    raise RuntimeError(f"cyclictest exited with {job.process.returncode}; see {job.log}")
  if capture["end_ns"] - capture["start_ns"] < round(config["duration_s"] * 1e9):
    raise ValueError("cyclictest exited before the full measurement duration")
  session.check()
  if stress:
    stress.check()
  capture["utilization"] = common.utilization(before, after)
  capture["counter_window"] = "cyclictest gate release through observed process exit; includes shutdown"
