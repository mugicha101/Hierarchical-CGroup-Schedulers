"""Replay E5 request samples and CPU counters without Docker or root access."""

from array import array
import math
from pathlib import Path
import statistics
import sys

from . import common, e5_config, e5_hierarchy, e5_overhead


def verify_hierarchy(directory, capture):
  hierarchy = common.read_json(directory / "hierarchy.json")
  if hierarchy["cleanup"] != "complete" or set(hierarchy["leaves"]) != set(capture["case"]["rates"]):
    raise ValueError("E5 hierarchy attachment/cleanup evidence is incomplete")
  build = hierarchy["root_build"]
  if build["target"] != "jlfp" or build["trace_profile"] != "off" or any(build["flags"].values()):
    raise ValueError("E5 requires tracing/statistics-off JLFP builds")
  root = hierarchy["attached_root"]
  if root is None or root["state"] != "enabled" or root["ops"] != "jlfp":
    raise ValueError("E5 root attachment evidence is missing")
  checks = common.read_json(directory / "task-checks.json")
  window = capture["window"]
  if len(checks) < capture["duration_s"] + 2 or checks[0]["time_ns"] >= window["measure_ns"] or \
      checks[-1]["time_ns"] < window["end_ns"] or any(
          after["time_ns"] <= before["time_ns"] for before, after in zip(checks, checks[1:])):
    raise ValueError("E5 task checks do not cover the measurement window")
  settings = capture["settings"]["scheduling"]
  nginx_tids = None
  for check in checks:
    if check["root"] != root or set(check["services"]) != set(capture["case"]["rates"]):
      raise ValueError("E5 task check omits a container")
    for name, service in check["services"].items():
      leaf = hierarchy["leaves"][name]
      key = "nginx" if name == "nginx" else "database"
      if service["cgroup"] != leaf["cgroup"] or service["cgroup_id"] != leaf["id"] or \
          service["cgroup"] != capture["placement"][name]["cgroup"] or \
          service["container_weight"] != settings["container_weights"][key] or not service["tasks"]:
        raise ValueError("E5 leaf identity or container priority changed")
      if name == "nginx":
        tids = set(service["tasks"])
        if nginx_tids is not None and tids != nginx_tids:
          raise ValueError("E5 Nginx tasks restarted")
        nginx_tids = tids
        if {task["role"] for task in service["tasks"].values()} != {"worker", "master"}:
          raise ValueError("E5 requires Nginx master and worker priority checks")
      for task in service["tasks"].values():
        weight = e5_hierarchy.MAX_WEIGHT
        if name == "nginx":
          weight -= settings["nginx_period_ns"][task["role"]]
        actual = task["stored_weight"]
        effective = (e5_hierarchy.DEFAULT_WEIGHT if actual is None else actual) & e5_hierarchy.MAX_WEIGHT
        if task["policy"] != 7 or task["cpus"] != [capture["cpu"]] or \
            task["effective_weight"] != weight or effective != weight:
          raise ValueError("E5 observed task policy/affinity/priority differs from configuration")


def samples(path, byteorder):
  values = array("Q")
  if values.itemsize != 8 or path.stat().st_size % 8 or byteorder not in ("little", "big"):
    raise ValueError(f"invalid E5 uint64 sample file: {path}")
  with path.open("rb") as source:
    values.fromfile(source, path.stat().st_size // 8)
  if byteorder != sys.byteorder:
    values.byteswap()
  return values


def summarize(values):
  ordered = sorted(values)
  if not ordered:
    return {"samples": 0, "p99_ms": None, "max_ms": None}
  return {"samples": len(ordered), "p99_ms": ordered[math.ceil(.99 * len(ordered)) - 1] / 1e6,
          "max_ms": ordered[-1] / 1e6}


def analyse_case(directory):
  directory = Path(directory)
  capture = common.read_json(directory / "capture.json")
  if not capture["measurement"] or capture["cleanup"] != "complete":
    raise ValueError(f"E5 capture is incomplete: {directory}")
  expected = {"cpu.json", "window.json"}
  expected.update(f"{name}-{shard}/{filename}" for name in capture["case"]["rates"]
                  for shard in range(capture["settings"]["shards"]) for filename in
                  ("client.json", "config.json", "latency_ns.bin", "service_ns.bin",
                   "admission_lag_ns.bin", "queue_wait_ns.bin"))
  scx = capture["stage"] == "scx_hierarchy"
  if capture["policy"] != ("ext" if scx else "other"):
    raise ValueError("E5 capture policy differs from its stage")
  if "scheduling" in capture["settings"]:
    scheduling = capture["settings"]["scheduling"]
    if (scheduling["mode"] == "scx") != scx or scheduling["trace"] != capture["trace_used"]:
      raise ValueError("E5 capture differs from the requested scheduling/tracing mode")
  if scx:
    expected.update(("hierarchy.json", "task-checks.json"))
  if capture["trace_used"]:
    expected.update(e5_overhead.RAW_FILES)
  if set(capture["raw_sha256"]) != expected:
    raise ValueError("E5 raw manifest is incomplete")
  for relative, digest in capture["raw_sha256"].items():
    path = (directory / relative).resolve(strict=True)
    if not path.is_relative_to(directory.resolve()) or common.sha256(path) != digest:
      raise ValueError(f"E5 raw file changed or escapes capture: {relative}")
  window = common.read_json(directory / "window.json")
  if capture["window"] != window or window["end_ns"] - window["measure_ns"] != round(capture["duration_s"] * 1e9):
    raise ValueError("E5 declared measurement window differs from the retained client gate")
  cpu = common.read_json(directory / "cpu.json")
  case, settings = capture["case"], capture["settings"]
  if len(cpu) != int(capture["duration_s"]) + 1 or any(
      after["time_ns"] <= before["time_ns"] for before, after in zip(cpu, cpu[1:])):
    raise ValueError("E5 CPU samples are incomplete or out of order")
  result = {**case, "services": {}, "stage": capture["stage"], "policy": capture["policy"],
            "experiment_validated": False, "cpu": capture["cpu"], "duration_s": capture["duration_s"]}
  for name, rate in case["rates"].items():
    latency, service, reports = array("Q"), array("Q"), []
    for shard in range(settings["shards"]):
      path = directory / f"{name}-{shard}"
      report = common.read_json(path / "client.json")
      request = common.read_json(path / "config.json")
      if request["service"] != name or request["rate"] != rate / settings["shards"]:
        raise ValueError("E5 client identity or offered rate changed")
      values = samples(path / "latency_ns.bin", report["byteorder"])
      durations = samples(path / "service_ns.bin", report["byteorder"])
      stats = summarize(values)
      if len(values) != len(durations) or len(values) != report["completed"] or \
          stats["p99_ms"] != report["p99_ms"] or stats["max_ms"] != report["max_ms"]:
        raise ValueError("E5 client counts or quantiles differ from raw samples")
      for filename, count in (("admission_lag_ns.bin", report["scheduled"]),
                              ("queue_wait_ns.bin", report["completed"])):
        if len(samples(path / filename, report["byteorder"])) != count:
          raise ValueError(f"E5 timing sample count differs: {path / filename}")
      if any(type(report[key]) is not int or report[key] < 0 for key in
             ("scheduled", "completed", "skipped", "error_count", "completed_after_window")) or \
          report["completed"] + report["skipped"] + report["error_count"] != report["scheduled"]:
        raise ValueError("E5 request accounting is incomplete")
      latency.extend(values)
      service.extend(durations)
      reports.append(report)
    counts = {key: sum(report[key] for report in reports) for key in
              ("scheduled", "completed", "skipped", "error_count", "completed_after_window")}
    if counts["scheduled"] != rate * capture["duration_s"]:
      raise ValueError("E5 generated request count differs from the offered rate/window")
    elapsed_us = (cpu[-1]["time_ns"] - cpu[0]["time_ns"]) / 1000
    usage = cpu[-1]["containers"][name]["usage_usec"] - cpu[0]["containers"][name]["usage_usec"]
    if usage < 0 or any(point["containers"][name]["nr_throttled"] != 0 for point in cpu):
      raise ValueError("E5 CPU accounting reset or a container was quota-throttled")
    pooled = summarize(latency)
    counts.update(cpu_percent=100 * usage / elapsed_us, achieved_rps=counts["completed"] / capture["duration_s"],
                  p99_ms=pooled["p99_ms"], max_ms=pooled["max_ms"],
                  service_p99_ms=summarize(service)["p99_ms"],
                  shard_half_p99_ms=[report["half_p99_ms"] for report in reports],
                  max_admission_lag_ms=max((report["max_admission_lag_ms"] for report in reports
                                            if report["max_admission_lag_ms"] is not None), default=None),
                  max_queue_wait_ms=max((report["max_queue_wait_ms"] for report in reports
                                         if report["max_queue_wait_ms"] is not None), default=None),
                  queue_peak=max(report["queue_peak"] for report in reports))
    result["services"][name] = counts
  for placements in (capture["placement"], capture["final_placement"]):
    if set(placements) != set(case["rates"]) or any(
        item["affinities"] != [[capture["cpu"]]] or item["policies"] != [7 if scx else 0] or
        item["cpus"] != str(capture["cpu"]) or not item["cpu_max"].startswith("max ")
        for item in placements.values()):
      raise ValueError("E5 policy, cpuset or quota verification is missing")
  if capture["placement"] != capture["final_placement"]:
    raise ValueError("E5 placement or memory events changed")
  if scx:
    verify_hierarchy(directory, capture)
  result["trace_used"] = capture["trace_used"]
  result["overhead"] = e5_overhead.replay(directory) if capture["trace_used"] else None
  busy = []
  for before, after in zip(cpu, cpu[1:]):
    old, new = before["host"][f"cpu{capture['cpu']}"], after["host"][f"cpu{capture['cpu']}"]
    total, used = new["total"] - old["total"], new["busy"] - old["busy"]
    if not 0 <= used <= total or total <= 0:
      raise ValueError("E5 host CPU counters are invalid")
    busy.append(100 * used / total)
  result.update(combined_cpu_percent=sum(item["cpu_percent"] for item in result["services"].values()),
                host_cpu_mean_percent=statistics.mean(busy), host_cpu_max_percent=max(busy))
  result["screening_fit"] = e5_config.fits(result, settings["screening"])
  return result


def analyse(directory):
  directory = Path(directory).resolve(strict=True)
  suite = common.read_json(directory / "suite.json")
  config = common.read_json(directory / "run.json")["config"]
  if suite["status"] != "succeeded" or not suite["cases"] or \
      [item["case"] for item in suite["cases"]] != suite["planned_cases"]:
    raise ValueError("E5 suite is incomplete or its case matrix changed")
  rows, roots = [], set()
  for item in suite["cases"]:
    root = (directory / item["directory"]).resolve(strict=True)
    if not root.is_relative_to(directory) or root in roots:
      raise ValueError("E5 case path escapes the suite or is duplicated")
    roots.add(root)
    capture = common.read_json(root / "capture.json")
    if capture["case"] != item["case"]:
      raise ValueError("E5 captured case differs from the planned case")
    if capture["settings"] != config["experiments"]["containers"]["e5"] or any(
        capture[key] != config[key] for key in ("duration_s", "warmup_s")):
      raise ValueError("E5 case parameters differ from the retained suite configuration")
    rows.append(analyse_case(root))
  if any(row["stage"] != suite["stage"] for row in rows):
    raise ValueError("E5 suite mixes native and SCX stages")
  report = {"stage": suite["stage"], "experiment_validated": False,
            "all_screening_fit": all(row["screening_fit"] for row in rows), "cases": rows}
  common.write_json(directory / "results.json", report)
  return report
