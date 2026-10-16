"""E1 builds, case orchestration and offline replay; capture and statistics are separate."""

import csv
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import builds, common, e1_capture, e1_config, e1_results, preflight


def save_results(directory, rows):
  common.write_json(directory / "results.json", {"cases": rows})
  fields = ("scheduler", "stress", "target_utilization_percent", "repetition",
            "achieved_utilization_percent", "samples", "max_us", "mean_us", "median_us",
            "p99_us", "p999_us", "stddev_us", "directory")
  with (directory / "results.csv").open("w", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows({field: row.get(field) for field in fields} for row in rows)


def analyse(directory):
  directory = Path(directory).resolve(strict=True)
  suite = common.read_json(directory / "suite.json")
  rows = []
  for item in suite["cases"]:
    root = directory / item["directory"]
    if not root.resolve(strict=True).is_relative_to(directory):
      raise ValueError("E1 case directory escapes the suite")
    attempts = sorted(root.glob("attempt-*/status.json"))
    successful = [path for path in attempts if common.read_json(path)["status"] == "succeeded"]
    if len(successful) != 1:
      raise ValueError(f"expected exactly one successful E1 attempt: {root}")
    attempt = successful[0].parent
    status = common.read_json(successful[0])
    capture = common.read_json(attempt / "capture.json")
    if not status["measurement"] or not capture["measurement"] or status["cleanup"] != "complete":
      raise ValueError(f"E1 attempt is not a validated measurement: {attempt}")
    raw_path = attempt / "cyclictest.json"
    if capture["case"] != item["case"] or common.sha256(raw_path) != capture["cyclictest_sha256"]:
      raise ValueError(f"E1 case metadata or raw histogram changed: {attempt}")
    statistics = e1_results.summarize(common.read_json(raw_path),
                                    **e1_config.statistics(capture["settings"]))
    rows.append({**capture["case"], **statistics,
                 "achieved_utilization_percent": capture["utilization"]["busy_percent"],
                 "raw_sha256": common.sha256(raw_path),
                 "directory": str(attempt.relative_to(directory))})
  if suite["status"] != "succeeded" or len(rows) != len(suite["planned_cases"]):
    raise ValueError("E1 suite is incomplete; failed attempts and successful partial cases are retained")
  save_results(directory, rows)
  return rows


def prepare_builds(config, cases, directory):
  manifests = {}
  targets = ["cyclictest"]
  targets += [name for name in ("qmap", "simple", "jlfp")
              if any(case["scheduler"] == name for case in cases)]
  for target in targets:
    root = builds.build(config, target, trace="off")
    manifests[target] = builds.result(root)
  if not manifests["cyclictest"].get("e1_startup_gate"):
    raise ValueError("E1 requires cyclictest built with its worker readiness gate")
  common.write_json(directory / "builds.json", manifests)
  return manifests


def run(config, *, scheduler=None, stress=None, analyse_only=None):
  if analyse_only is not None:
    rows = analyse(analyse_only)
    print_report(rows)
    return Path(analyse_only)
  if os.geteuid() != 0:
    raise PermissionError("root is required for E1 policy, scheduler and cgroup placement")
  if not float(config["duration_s"]).is_integer():
    raise ValueError("E1 requires duration_s to be a whole number of seconds")
  directory = common.new_run(config, "e1")
  print(f"E1 artifacts: {directory}", flush=True)
  report = preflight.inspect(config, traced=False)
  common.write_json(directory / "preflight.json", report)
  if not report["ok"]:
    raise ValueError(f"E1 prerequisites are missing; see {directory / 'preflight.json'}")
  cases = [case for case in e1_config.cases(config)
           if (scheduler is None or case["scheduler"] == scheduler) and
              (stress is None or case["stress"] == (stress == "on"))]
  if not cases:
    raise ValueError("no E1 cases selected")
  suite = {"status": "running", "command": sys.argv, "planned_cases": cases, "cases": []}
  common.write_json(directory / "suite.json", suite)
  try:
    with common.controller_placement(config):
      manifests = prepare_builds(config, cases, directory)
      stress_binary = shutil.which("stress-ng")
      version = subprocess.run([stress_binary, "--version"], check=True, capture_output=True,
                               text=True, timeout=config["process_timeout_s"])
      common.write_json(directory / "stress-ng.json", {"binary": stress_binary,
                        "sha256": common.sha256(stress_binary), "version": version.stdout.strip()})
      binary = manifests["cyclictest"]["binary"]
      if common.sha256(binary) != manifests["cyclictest"]["binary_sha256"]:
        raise ValueError("cyclictest differs from its build manifest")
      for case in cases:
        name = f"{case['scheduler']}-stress-{'on' if case['stress'] else 'off'}-r{case['repetition']}"
        print(f"E1: {name}", flush=True)
        def capture(attempt, processes):
          return e1_capture.capture(config, attempt, case, binary,
                                    manifests.get(case["scheduler"]), stress_binary)
        root = common.run_attempts(config, name, capture, parent=directory, measurement=True)
        suite["cases"].append({"directory": root.name, "case": case})
        common.write_json(directory / "suite.json", suite)
    suite["status"] = "succeeded"
    common.write_json(directory / "suite.json", suite)
    rows = analyse(directory)
  except BaseException as error:
    suite.update(status="failed", error=f"{type(error).__name__}: {error}")
    raise
  finally:
    common.write_json(directory / "suite.json", suite)
  metadata = common.read_json(directory / "run.json")
  common.write_json(directory / "run.json", {**metadata, "measurement": True})
  print_report(rows)
  print(f"E1 table: {directory / 'results.csv'}", flush=True)
  return directory


def print_report(rows):
  print("scheduler stress achieved% max_us mean_us median_us p99_us p999_us stddev_us")
  for row in rows:
    print(f"{row['scheduler']} {'on' if row['stress'] else 'off'} "
          f"{row['achieved_utilization_percent']:.2f} {row['max_us']} {row['mean_us']:.3f} "
          f"{row['median_us']} {row['p99_us']} {row['p999_us']} {row['stddev_us']:.3f}")
