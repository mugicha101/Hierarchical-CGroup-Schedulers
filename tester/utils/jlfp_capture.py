"""Capture weighted JLFP workers using a shared monotonic schedule."""

import json
import os
import select
import subprocess
import time

from . import cgroups as placement, common, workers as worker_tools
from .trace_helpers import TraceSession

EVENTS = ("scxtp:*", "sched:sched_switch", "sched:sched_wakeup", "sched:sched_wakeup_new")


def capture(output, build_path, cpus, count, warmup, duration, *, periodic=None, relative_to):
  cgroup = placement.existing_test_cgroup(relative_to)
  cpus = placement.select_test_cpus(cpus, relative_to=cgroup)
  worker_binary = worker_tools.build_worker()
  config = output / "config.json"
  settings = {"policy": "scx_jlfp", "trace": True, "max_shard_size": placement.SHARD_SIZE}
  config.write_text(json.dumps(settings, indent=2) + "\n")
  workers = []
  with (output / "workers.log").open("w") as log:
    common.report_progress("Starting scheduler manager...")
    with TraceSession(events=EVENTS, scx_build_path=build_path, monitor=True) as session:
      common.report_progress("Starting ftrace recorder...")
      session.start_trace(output / "trace.dat")
      common.report_progress("Loading JLFP...")
      session.load_config(config)
      cgroup_state = placement.load_relative_config(session, output, cgroup, {
          "policy": "scx_jlfp", "trace": True, "max_shard_size": placement.SHARD_SIZE})
      scheduler_id = cgroup.stat().st_ino
      try:
        for weight in range(1, count + 1):
          common.report_progress(f"Starting worker {weight}/{count}...")
          process = subprocess.Popen([str(worker_binary), "--jlfp-worker"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
          workers.append((process, weight))
          # workers must not inherit the controller's existing cgroup
          (cgroup / "cgroup.procs").write_text(f"{process.pid}\n")
          os.sched_setaffinity(process.pid, cpus)
          if os.sched_getaffinity(process.pid) != cpus:
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
               "host_controls": "external"}
        run.update(cgroup=cgroup_state, worker_cgroup=str(cgroup),
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
