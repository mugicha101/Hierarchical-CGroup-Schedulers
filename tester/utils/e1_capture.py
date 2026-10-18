"""Capture one trace-free E1 case with an owned root scheduler and workloads."""

from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path

from . import deadline as deadline_support
from . import common, cyclictest, e1_config, e1_measurement, e1_results, e1_workloads, lifecycle


def scheduler_manifest(manifest, settings, scheduler, *, trace="off"):
  manifest = deepcopy(manifest)
  if manifest["trace_profile"] != trace:
    raise ValueError(f"scheduler requires the {trace} trace profile")
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
        e1_measurement.warmup(session, stress, config["warmup_s"])
      e1_measurement.record_interval(config, session, job, directory, cpus, run,
                                     stress=stress, partitions=partitions)
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
