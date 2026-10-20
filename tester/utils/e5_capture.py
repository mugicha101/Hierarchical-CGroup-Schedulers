"""Capture one container pair with a gated native or SCX measurement window."""

from pathlib import Path
import sys
import time

from . import common, e5_config, e5_docker, e5_hierarchy, e5_overhead, lifecycle


def sample(pair, hierarchy):
  if hierarchy is not None:
    hierarchy.verify_tasks()
  elif lifecycle.root_state() != pair.prepared["initial_scx"]:
    raise RuntimeError("SCX root state changed during the capacity baseline")
  cpu = pair.prepared["cpu"]
  times = common.cpu_times({cpu})[cpu]
  counters = {}
  for name, item in pair.services.items():
    counters[name] = {key: int(value) for key, value in
                     (line.split() for line in (item["cgroup"] / "cpu.stat").read_text().splitlines())}
  return {"time_ns": time.monotonic_ns(), "host": {f"cpu{cpu}": {
      "total": times["total"], "busy": times["total"] - times["idle"] - times["iowait"]}},
      "containers": counters}


def prepare_clients(config, directory, case, pair, processes):
  settings = config["experiments"]["containers"]["e5"]
  jobs = []
  for name, rate in case["rates"].items():
    for shard in range(settings["shards"]):
      output = directory / f"{name}-{shard}"
      output.mkdir()
      request = {**pair.client_settings(name), "output": str(output), "start_file": str(directory / "window.json"),
                 "startup_timeout_s": config["process_timeout_s"] * 4,
                 "rate": rate / settings["shards"], "phase": shard / settings["shards"], "seed": shard + 10}
      common.write_json(output / "config.json", request)
      child = processes.start([sys.executable, e5_docker.CLIENT, "run", output / "config.json"])
      jobs.append((child, output))
  deadline = time.monotonic() + config["process_timeout_s"]
  while not all((output / "ready").exists() for _, output in jobs):
    if any(child.poll() is not None for child, _ in jobs):
      raise RuntimeError("E5 client exited before readiness; see client command logs")
    if time.monotonic() >= deadline:
      raise TimeoutError("E5 clients did not become ready")
    time.sleep(.01)
  return jobs


def measure(config, directory, case, pair, processes, record, hierarchy):
  jobs = prepare_clients(config, directory, case, pair, processes)
  if hierarchy is not None:
    with pair.paused():
      hierarchy.start()
      hierarchy.configure_tasks()
  record["placement"] = pair.placement()
  start = time.monotonic_ns() + 100_000_000
  measure_ns = start + round(config["warmup_s"] * 1e9)
  window = {"start_ns": start, "measure_ns": measure_ns,
            "end_ns": measure_ns + round(config["duration_s"] * 1e9)}
  common.write_json(directory / "window.json", window)
  time.sleep(max(0, (measure_ns - time.monotonic_ns()) / 1e9))
  samples = [sample(pair, hierarchy)]
  for second in range(1, int(config["duration_s"]) + 1):
    time.sleep(max(0, (measure_ns + second * 1_000_000_000 - time.monotonic_ns()) / 1e9))
    samples.append(sample(pair, hierarchy))
    common.write_json(directory / "cpu.json", samples)
  deadline = time.monotonic() + config["process_timeout_s"]
  for child, _ in jobs:
    child.wait(timeout=max(.001, deadline - time.monotonic()))
    if child.returncode:
      raise RuntimeError("E5 client failed; see client command logs")
  return window


def close_resources(processes, hierarchy, pair):
  cleanups = [processes.close]
  if hierarchy is not None:
    cleanups.append(hierarchy.close)
  cleanups.append(pair.close)
  errors = []
  with common.cleanup_interrupts():
    for close in cleanups:
      try:
        close()
      except Exception as error:
        errors.append(str(error))
  return errors


def freeze_inputs(directory, record):
  raw = [path for path in directory.rglob("*") if path.is_file() and
         (path.suffix == ".bin" or path.name in ("client.json", "config.json", "cpu.json", "window.json"))]
  raw += [directory / name for name in (*e5_overhead.RAW_FILES, "hierarchy.json", "task-checks.json")
          if (directory / name).is_file()]
  record["raw_sha256"] = {str(path.relative_to(directory)): common.sha256(path) for path in sorted(raw)}
  common.write_json(directory / "capture.json", record)


def capture(config, directory, case, prepared, manifest=None, profile=None):
  directory = Path(directory)
  pair = e5_docker.Pair(config, directory, case["database"], prepared)
  clients = directory / "clients"
  clients.mkdir()
  processes = common.Processes(clients, config["process_timeout_s"])
  hierarchy = None
  if manifest is not None:
    recorder = e5_overhead.recording(config, directory, profile, prepared["cpu"]) if profile else None
    hierarchy = e5_hierarchy.Hierarchy(config, directory, manifest, pair, recorder)
  record = {"measurement": False, "cleanup": "pending", "case": case, "cpu": prepared["cpu"],
            "duration_s": config["duration_s"], "warmup_s": config["warmup_s"],
            "settings": config["experiments"]["containers"]["e5"], "stage": e5_config.stage(config),
            "policy": "ext" if hierarchy else "other", "trace_used": profile is not None,
            "overhead": "pending" if profile else "disabled explicitly; no overhead measurement",
            "experiment_validated": False}
  try:
    pair.start()
    record["window"] = measure(config, directory, case, pair, processes, record, hierarchy)
    record["final_placement"] = pair.placement()
    if record["placement"] != record["final_placement"]:
      raise ValueError("container placement or memory events changed during measurement")
    record["measurement"] = True
  except BaseException as error:
    record["error"] = f"{type(error).__name__}: {error}"
    raise
  finally:
    errors = close_resources(processes, hierarchy, pair)
    record["cleanup"] = "failed" if errors else "complete"
    record["cleanup_errors"] = errors
    record["measurement"] &= not errors
    try:
      if record["measurement"] and profile:
        record["overhead"] = e5_overhead.finish(directory, record, config, profile)
    except BaseException as error:
      record.update(measurement=False, error=f"{type(error).__name__}: {error}")
      raise
    finally:
      freeze_inputs(directory, record)
    if errors:
      raise common.CleanupError("; ".join(errors))
  return record
