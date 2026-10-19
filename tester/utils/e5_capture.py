"""Capture one native container pair and its clients, then remove owned resources."""

from pathlib import Path
import sys
import time

from . import common, e5_docker, lifecycle


def sample(pair):
  if lifecycle.root_state() != pair.prepared["initial_scx"]:
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


def measure(config, directory, case, pair, processes):
  settings = config["experiments"]["containers"]["e5"]
  gate = directory / "window.json"
  jobs = []
  for name, rate in case["rates"].items():
    for shard in range(settings["shards"]):
      output = directory / f"{name}-{shard}"
      output.mkdir()
      request = {**pair.client_settings(name), "output": str(output), "start_file": str(gate),
                 "startup_timeout_s": config["process_timeout_s"],
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
  start = time.monotonic_ns() + 100_000_000
  measure_ns = start + round(config["warmup_s"] * 1e9)
  window = {"start_ns": start, "measure_ns": measure_ns,
            "end_ns": measure_ns + round(config["duration_s"] * 1e9)}
  common.write_json(gate, window)
  time.sleep(max(0, (measure_ns - time.monotonic_ns()) / 1e9))
  samples = [sample(pair)]
  for second in range(1, int(config["duration_s"]) + 1):
    time.sleep(max(0, (measure_ns + second * 1_000_000_000 - time.monotonic_ns()) / 1e9))
    samples.append(sample(pair))
    common.write_json(directory / "cpu.json", samples)
  deadline = time.monotonic() + config["process_timeout_s"]
  for child, _ in jobs:
    child.wait(timeout=max(.001, deadline - time.monotonic()))
    if child.returncode:
      raise RuntimeError("E5 client failed; see client command logs")
  return window


def capture(config, directory, case, prepared):
  directory = Path(directory)
  pair = e5_docker.Pair(config, directory, case["database"], prepared)
  clients = directory / "clients"
  clients.mkdir()
  processes = common.Processes(clients, config["process_timeout_s"])
  record = {"measurement": False, "cleanup": "pending", "case": case, "cpu": prepared["cpu"],
            "duration_s": config["duration_s"], "warmup_s": config["warmup_s"],
            "settings": config["experiments"]["containers"]["e5"], "stage": "capacity_baseline",
            "policy": "other", "trace_used": False, "experiment_validated": False}
  try:
    pair.start()
    record["placement"] = pair.placement()
    record["window"] = measure(config, directory, case, pair, processes)
    record["final_placement"] = pair.placement()
    if record["placement"] != record["final_placement"]:
      raise ValueError("container placement or memory events changed during measurement")
    record["measurement"] = True
  except BaseException as error:
    record["error"] = f"{type(error).__name__}: {error}"
    raise
  finally:
    errors = []
    with common.cleanup_interrupts():
      for close in (processes.close, pair.close):
        try:
          close()
        except Exception as error:
          errors.append(str(error))
      record["cleanup"] = "failed" if errors else "complete"
      record["cleanup_errors"] = errors
      record["measurement"] &= not errors
      raw = [path for path in directory.rglob("*") if path.is_file() and
             (path.suffix == ".bin" or path.name in ("client.json", "config.json", "cpu.json", "window.json"))]
      record["raw_sha256"] = {str(path.relative_to(directory)): common.sha256(path) for path in sorted(raw)}
      common.write_json(directory / "capture.json", record)
    if errors:
      raise common.CleanupError("; ".join(errors))
  return record
