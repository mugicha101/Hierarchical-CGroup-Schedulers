"""Configure the MC² class hierarchy and capture its periodic workers."""

import json
import os
import select
import subprocess
import time

from . import cgroups as placement, common, jlfp_capture, mc2_workload, workers as worker_tools
from .trace_helpers import REPO_DIR, TraceSession

CONFIG = REPO_DIR / "tester/mc2/mc2_config.json"


def mc2_layout(cpus):
  settings = json.loads(CONFIG.read_text())
  classes = []
  for name, policy, weight, affinity in (("class_a", "scx_jlfp", 4, "pinned"),
                                          ("class_b", "scx_gedf", 3, "pinned"),
                                          ("class_c", "scx_gedf", 2, "global")):
    node = settings["subs"][name]
    if node["policy"] != policy or node["weight"] != weight:
      raise ValueError(f"Unexpected MC² policy or weight for {name}")
    node.update(trace=True, max_shard_size=placement.SHARD_SIZE,
                cpus=",".join(map(str, sorted(cpus))))
    if affinity == "pinned":
      node["subs"] = {f"cpu{cpu}": {"policy": "none", "cpus": str(cpu)} for cpu in sorted(cpus)}
    classes.append({"path": name, "policy": policy, "weight": weight, "affinity": affinity})
  settings.update(trace=True, max_shard_size=placement.SHARD_SIZE)
  return settings, classes


def capture(output, build_path, cpus, class_settings, warmup, duration, *, relative_to):
  cgroup = placement.existing_test_cgroup(relative_to)
  cpus = placement.select_test_cpus(cpus, relative_to=cgroup)
  mc2_workload.validate(class_settings)
  plans = {name: mc2_workload.class_plan(group, cpus) for name, group in class_settings.items()}
  binary = worker_tools.build_worker()
  settings, classes = mc2_layout(cpus)
  subtrees = settings.pop("subs")
  for group in classes:
    path = cgroup / group["path"]
    if path.exists():
      raise FileExistsError(f"MC² test cgroup already exists: {path}")
  config = output / "config.json"
  config.write_text(json.dumps(settings, indent=2) + "\n")
  processes = []
  workers = {}
  with (output / "workers.log").open("w") as log:
    with TraceSession(events=jlfp_capture.EVENTS, scx_build_path=build_path, monitor=True) as session:
      session.start_trace(output / "trace.dat")
      common.report_progress("Loading MC²: pinned JLFP A, pinned GEDF B, global GEDF C...")
      session.load_config(config)
      cgroup_state = placement.load_relative_config(session, output, cgroup, {"policy": "none"})
      for name, node in subtrees.items():
        class_config = output / f"{name}_config.json"
        class_config.write_text(json.dumps(node, indent=2) + "\n")
        session.load_config(class_config, relative_to=cgroup / name)
      cgroups = [{"path": "", "id": 0, "weight": 0xffff, "policy": "scx_jlfp"}]
      for group in classes:
        path = cgroup / group["path"]
        if int((path / "cpu.weight").read_text()) != group["weight"]:
          raise RuntimeError(f"Cgroup weight did not apply: {path}")
        cgroups.append({**group, "id": path.stat().st_ino})
      try:
        for group in classes:
          for task in plans[group["path"]][0]:
            cpu = task["cpu"]
            pinned = group["affinity"] == "pinned"
            path = group["path"] + (f"/cpu{cpu}" if pinned else "")
            path = str((cgroup / path).relative_to(placement.CGROUP_ROOT))
            worker_cpus = {cpu} if pinned else cpus
            command = "--gedf-worker" if group["policy"] == "scx_gedf" else "--jlfp-worker"
            process = subprocess.Popen([str(binary), command], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=log, text=True)
            processes.append((process, 0))
            workers[process.pid] = {"class": group["path"], "cgroup": path,
                                   "cpus": sorted(worker_cpus), "policy": group["policy"],
                                   **{key: task[key] for key in ("period_ns", "runtime_ns", "phase_ns", "weight")}}
            (placement.CGROUP_ROOT / path / "cgroup.procs").write_text(f"{process.pid}\n")
            os.sched_setaffinity(process.pid, worker_cpus)
            if os.sched_getaffinity(process.pid) != worker_cpus:
              raise RuntimeError(f"Worker affinity did not apply: {process.pid}")
            ready, _, _ = select.select([process.stdout], [], [], 30)
            if not ready or process.stdout.readline().strip() != "ready":
              raise RuntimeError(f"Worker {process.pid} did not become ready; see {log.name}")
        worker_tools.configure_workers(processes, workers)
        release = time.monotonic_ns() + 100_000_000
        start = release + round(warmup * 1e9)
        end = start + round(duration * 1e9)
        for worker in workers.values():
          if worker["policy"] == "scx_gedf":
            worker["weight"] = (1 << 64) - 1 - (release + worker["phase_ns"] + worker["period_ns"])
        run = {"setup": "mc2-abc", "cpus": sorted(cpus), "workers": workers, "cgroups": cgroups,
               "start_ns": start, "end_ns": end, "worker_binary": str(binary),
               "scx_build_path": str(build_path.resolve()), "host_controls": "external",
               "workload": {"kind": "periodic-releases", "release_ns": release,
                            "gedf_is_periodic": False, "classes": class_settings,
                            "class_utilization": {name: plan[1] for name, plan in plans.items()},
                            "target_utilization_percent": sum(group["utilization_percent"] for group in class_settings.values())}}
        run["cgroup"] = cgroup_state
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
        common.report_progress(f"Running {len(workers)} MC² workers: {warmup:g}s warmup + {duration:g}s measurement...")
        for process, _ in processes:
          worker = workers[process.pid]
          request = (release, end, worker["period_ns"], worker["runtime_ns"], worker["phase_ns"])
          process.stdin.write(" ".join(map(str, request)) + "\n")
          process.stdin.flush()
        time.sleep(max(0, (start - time.monotonic_ns()) / 1e9))
        sample_start = time.monotonic_ns()
        before = common.cpu_times(cpus)
        for process, _ in processes:
          status = process.wait(timeout=max(0, (end - time.monotonic_ns()) / 1e9) + 10)
          if status:
            raise RuntimeError(f"Worker {process.pid} exited with status {status}; see {log.name}")
        after = common.cpu_times(cpus)
        run["system_utilization"] = {**common.utilization(before, after),
                                     "sample_start_ns": sample_start,
                                     "sample_end_ns": time.monotonic_ns(),
                                     "before": before, "after": after}
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
      finally:
        common.report_progress("Stopping MC² workers...")
        worker_tools.stop_workers(processes)
  return run
