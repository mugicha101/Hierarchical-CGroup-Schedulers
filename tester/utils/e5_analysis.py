"""Replay E5 request samples and CPU counters without Docker or root access."""

from array import array
import math
from pathlib import Path
import statistics
import sys

from . import common, e5_config


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
  if set(capture["raw_sha256"]) != expected:
    raise ValueError("E5 raw manifest is incomplete")
  for relative, digest in capture["raw_sha256"].items():
    path = (directory / relative).resolve(strict=True)
    if not path.is_relative_to(directory.resolve()) or common.sha256(path) != digest:
      raise ValueError(f"E5 raw file changed or escapes capture: {relative}")
  cpu = common.read_json(directory / "cpu.json")
  case, settings = capture["case"], capture["settings"]
  if len(cpu) != int(capture["duration_s"]) + 1 or any(
      after["time_ns"] <= before["time_ns"] for before, after in zip(cpu, cpu[1:])):
    raise ValueError("E5 CPU samples are incomplete or out of order")
  result = {**case, "services": {}, "stage": "capacity_baseline", "policy": "other",
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
        item["affinities"] != [[capture["cpu"]]] or item["policies"] != [0] or
        item["cpus"] != str(capture["cpu"]) or not item["cpu_max"].startswith("max ")
        for item in placements.values()):
      raise ValueError("E5 native policy, cpuset or quota verification is missing")
  if capture["placement"] != capture["final_placement"]:
    raise ValueError("E5 placement or memory events changed")
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
    rows.append(analyse_case(root))
  report = {"stage": "capacity_baseline", "experiment_validated": False,
            "all_screening_fit": all(row["screening_fit"] for row in rows), "cases": rows}
  common.write_json(directory / "results.json", report)
  return report
