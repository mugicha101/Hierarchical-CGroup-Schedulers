"""Capture weighted JLFP workers using a shared monotonic schedule."""

from contextlib import ExitStack, nullcontext
import json
import os
import select
import subprocess
import time

from . import cgroups as placement, common, isolation as host, workers as worker_tools
from .trace_helpers import TraceSession

EVENTS = ("scxtp:*", "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new")


def capture(output, build_path, cpus, count, warmup, duration, *, keep_bandwidth_servers=False,
            periodic=None, isolate=False, relative_to=None):
  cgroup = placement.existing_test_cgroup(relative_to) if relative_to is not None else placement.CGROUP_ROOT
  relative_to = cgroup if cgroup != placement.CGROUP_ROOT else None
  cpus = placement.select_test_cpus(isolate, cpus, relative_to=relative_to)
  destination = placement.worker_cgroup(cgroup) if relative_to is not None else cgroup
  if relative_to is not None and destination.exists() and not cpus <= placement.cgroup_cpu_set(destination):
    raise ValueError(f"Worker cgroup {destination} does not allow CPUs {sorted(cpus)}")
  worker_binary = worker_tools.build_worker()
  other_cpus = os.sched_getaffinity(0) - set(cpus)
  config = output / "config.json"
  settings = {"policy": "scx_jlfp", "trace": True, "max_shard_size": placement.SHARD_SIZE}
  if isolate:
    settings["subs"] = {"other": {"policy": "none", "weight": 1,
                                  "cpus": ",".join(map(str, sorted(other_cpus)))}}
  config.write_text(json.dumps(settings, indent=2) + "\n")
  workers = []
  servers = nullcontext({"disabled": False}) if not isolate or keep_bandwidth_servers else \
      host.disabled_bandwidth_servers(cpus, output / "bandwidth_servers.json")
  controller = host.controller_affinity(cpus) if isolate else nullcontext()
  with controller, servers as server_state, (output / "workers.log").open("w") as log:
    common.report_progress("Starting scheduler manager...")
    with TraceSession(events=EVENTS, scx_build_path=build_path, monitor=True) as session, ExitStack() as isolation:
      common.report_progress("Starting ftrace recorder...")
      session.start_trace(output / "trace.dat")
      common.report_progress("Loading JLFP...")
      session.load_config(config)
      cgroup_state = None
      scheduler_id = 0
      if relative_to is not None:
        cgroup_state = placement.load_relative_config(session, output, cgroup, {
            "policy": "scx_jlfp", "trace": True, "max_shard_size": placement.SHARD_SIZE}, destination=destination)
        scheduler_id = destination.stat().st_ino
      isolation_state = isolation.enter_context(host.isolated_root_tasks(output / "cpu_isolation.json")) \
          if isolate else {"enabled": False}
      try:
        for weight in range(1, count + 1):
          common.report_progress(f"Starting worker {weight}/{count}...")
          process = subprocess.Popen([str(worker_binary), "--jlfp-worker"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
          workers.append((process, weight))
          # workers must not inherit the controller's existing cgroup
          (destination / "cgroup.procs").write_text(f"{process.pid}\n")
          os.sched_setaffinity(process.pid, cpus)
          if relative_to is not None and os.sched_getaffinity(process.pid) != cpus:
            raise RuntimeError(f"Worker affinity did not apply: {process.pid}")
          ready, _, _ = select.select([process.stdout], [], [], 30)
          if not ready or process.stdout.readline().strip() != "ready":
            raise RuntimeError(f"Worker {process.pid} did not become ready; see {log.name}")
        common.report_progress("Applying worker weights and SCHED_EXT policy...")
        worker_tools.set_weights(workers)
        release = time.monotonic_ns()
        if periodic is not None:
          # give all workers time to receive the shared release schedule
          release += 50_000_000
        start = release + round(warmup * 1e9)
        end = start + round(duration * 1e9)
        run = {"weights": {process.pid: weight for process, weight in workers},
               "cpus": sorted(cpus), "start_ns": start, "end_ns": end,
               "worker_binary": str(worker_binary),
               "bandwidth_servers": server_state, "cpu_isolation": isolation_state}
        if cgroup_state is not None:
          run.update(cgroup=cgroup_state, worker_cgroup=str(destination),
                     scheduler_id=scheduler_id, scheduler_ids=[0, scheduler_id])
        phases = {process.pid: index * periodic["period_ns"] // count
                  for index, (process, _) in enumerate(workers)} if periodic is not None else {}
        run["workload"] = {"kind": "continuous"} if periodic is None else {
            "kind": "periodic", **periodic, "release_ns": release, "phases_ns": phases}
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        common.report_progress(f"Running workers: {warmup:g}s warmup + {duration:g}s measurement...")
        for process, _ in workers:
          request = (0, end, 0, 0, 0) if periodic is None else (
              release, end, periodic["period_ns"], periodic["runtime_ns"], phases[process.pid])
          process.stdin.write(" ".join(map(str, request)) + "\n")
          process.stdin.flush()
        for process, _ in workers:
          status = process.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9) + 10)
          if status != 0:
            raise RuntimeError(f"Worker {process.pid} exited with status {status}; see {log.name}")
      finally:
        common.report_progress("Stopping workers...")
        worker_tools.stop_workers(workers)
      common.report_progress("Detaching JLFP and finalizing trace...")
  return run
