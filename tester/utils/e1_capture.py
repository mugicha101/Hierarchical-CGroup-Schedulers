"""Capture one trace-free E1 case with an owned root scheduler and workloads."""

from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import time

from . import deadline as deadline_support
from . import common, cyclictest, e1_config, e1_results, e1_workloads, lifecycle


def scheduler_manifest(manifest, settings, scheduler):
  manifest = deepcopy(manifest)
  if manifest["trace_profile"] != "off":
    raise ValueError("E1 requires a trace-free scheduler build")
  group = settings["policies"][scheduler]
  if scheduler == "jlfp":
    manifest["launch_args"] += ["--slice-length", str(group["slice_ns"]),
                                "--max-shard-size", str(group["max_shard_size"])]
  elif scheduler == "qmap":
    manifest["launch_args"] += ["-s", str(group["slice_ns"] // 1000)]
  return manifest


def check_tracing(directory, *, phase="before"):
  root = Path("/sys/kernel/tracing")
  states = {}
  if (root / "current_tracer").exists():
    for path in (root, *(root / "instances").iterdir()):
      state = {name: (path / name).read_text().strip() for name in
               ("current_tracer", "events/enable", "tracing_on")}
      states[str(path)] = state
    common.write_json(directory / f"tracing-{phase}.json", states)
    if any(state["current_tracer"] != "nop" or state["events/enable"] != "0"
           for state in states.values()):
      raise ValueError("E1 requires externally disabled ftrace events and function tracers")
  else:
    common.write_json(directory / f"tracing-{phase}.json", {"tracefs": "not mounted"})
  return states


def capture(config, directory, case, cyclic_binary, manifest, stress_binary):
  settings = config["experiments"]["overhead"]["e1"]
  cpu = config["experiments"]["overhead"]["cyclictest_cpu"]
  scheduler = case["scheduler"]
  primary = e1_config.policy(settings, scheduler, "cyclictest")
  if manifest is not None:
    manifest = scheduler_manifest(manifest, settings, scheduler)
  check_tracing(directory)
  run = {"case": case, "measurement": False, "trace_events": [], "samples_include_startup": True,
         "clock": "CLOCK_MONOTONIC", "cpu": cpu, "settings": settings,
         "scheduler_build": manifest, "host_controls": "external",
         "kernel_timer_support": "external prerequisite; assumed installed"}
  os.mkfifo(directory / "cyclictest.gate", 0o600)
  try:
    cpus = common.cgroup_cpus(common.workload_cgroup(config))
    with ExitStack() as resources:
      partitions = None
      measurement_config = config
      if scheduler == "deadline":
        partition_cpus = cpus if case["stress"] else {cpu}
        partitions = resources.enter_context(deadline_support.partitions(config, directory, partition_cpus))
        measurement_config = partitions.config_for(cpu)
      qos = resources.enter_context(cyclictest.temporary_cpu_dma_latency(settings["cpu_dma_latency_us"]))
      run["cpu_dma_latency"] = qos
      session = resources.enter_context(lifecycle.Session(measurement_config, directory, manifest))
      if cpu not in cpus:
        raise ValueError("E1 measurement CPU is outside the workload cgroup")
      run.update(workload_cgroup=str(session.cgroup), utilization_cpus=sorted(cpus))
      command = e1_workloads.cyclic_command(cyclic_binary, directory, measurement_config, scheduler)
      with cyclictest.temporary_timer_slack(settings["timer_slack_ns"]):
        job = session.start_workload(command, common.cgroup_cpus(session.cgroup),
                                     policy="other", priority=0, nice=primary["nice"])
      run["command"] = command
      job.release()
      reservation = settings["policies"]["deadline"]["cyclictest"] if partitions else None
      e1_workloads.wait_cyclic(session, job, directory, cpu, primary, settings["timer_slack_ns"],
                               reservation=reservation)
      stress = None
      if case["stress"]:
        stress = e1_workloads.Stress(session, directory, config, scheduler, stress_binary,
                                     partitions=partitions)
        resources.callback(stress.close)
        stress.wait_ready()
        deadline = time.monotonic() + config["warmup_s"]
        while time.monotonic() < deadline:
          session.check()
          stress.check()
          time.sleep(min(.05, max(0, deadline - time.monotonic())))
      gate = e1_workloads.open_gate(session, directory)
      try:
        before = common.cpu_times(cpus)
        run["start_ns"] = time.monotonic_ns()
        os.write(gate, b"g")
      finally:
        os.close(gate)
      deadline = time.monotonic() + config["duration_s"] + config["process_timeout_s"]
      next_check = time.monotonic()
      while job.process.poll() is None:
        session.check()
        if partitions:
          partitions.check()
        if time.monotonic() >= deadline:
          raise TimeoutError("cyclictest exceeded its configured duration and shutdown timeout")
        if stress and time.monotonic() >= next_check:
          stress.check()
          next_check = time.monotonic() + 1
        time.sleep(.02)
      run["end_ns"] = time.monotonic_ns()
      after = common.cpu_times(cpus)
      if job.process.returncode:
        raise RuntimeError(f"cyclictest exited with {job.process.returncode}; see {job.log}")
      if run["end_ns"] - run["start_ns"] < round(config["duration_s"] * 1e9):
        raise ValueError("cyclictest exited before the full measurement duration")
      session.check()
      if stress:
        stress.check()
      run["utilization"] = common.utilization(before, after)
      run["counter_window"] = "cyclictest gate release through observed process exit; includes shutdown"
      raw = common.read_json(directory / "cyclictest.json")
      run["cyclictest_sha256"] = common.sha256(directory / "cyclictest.json")
      if any(thread["cpu"] != cpu for thread in raw["thread"].values()):
        raise ValueError("cyclictest JSON reports a different measurement CPU")
      run["statistics"] = e1_results.summarize(raw, **e1_config.statistics(settings))
      if stress:
        achieved = run["utilization"]["busy_percent"]
        if abs(achieved - case["target_utilization_percent"]) > settings["stress"]["utilization_tolerance_percent"]:
          raise ValueError(f"achieved workload-CPU utilization {achieved:.2f}% differs from target "
                           f"{case['target_utilization_percent']}% beyond configured tolerance")
      check_tracing(directory, phase="after")
    run["measurement"] = True
    return run
  finally:
    common.write_json(directory / "capture.json", run)
