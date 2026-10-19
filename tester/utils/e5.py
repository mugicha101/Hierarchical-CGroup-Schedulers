"""E5 capacity cases with shared configuration, artifacts and offline replay."""

import csv
import os
from pathlib import Path
import sys

from . import common, e5_analysis, e5_capture, e5_config, e5_docker


def print_report(result):
  print("database repetition combined_cpu% host_peak% HTTP_p99_ms DB_p99_ms fit")
  for row in result["cases"]:
    print(f"{row['database']} {row['repetition']} {row['combined_cpu_percent']:.2f} "
          f"{row['host_cpu_max_percent']:.2f} {row['services']['nginx']['p99_ms']} "
          f"{row['services'][row['database']]['p99_ms']} {row['screening_fit']}")


def analyse(directory):
  result = e5_analysis.analyse(directory)
  fields = ("database", "repetition", "combined_cpu_percent", "host_cpu_mean_percent",
            "host_cpu_max_percent", "screening_fit", "nginx_rps", "database_rps",
            "nginx_cpu_percent", "database_cpu_percent", "http_p99_ms", "database_p99_ms",
            "errors", "queue_drops")
  with (Path(directory) / "results.csv").open("w", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in result["cases"]:
      http, database = row["services"]["nginx"], row["services"][row["database"]]
      flat = {**row, "nginx_rps": row["rates"]["nginx"], "database_rps": row["rates"][row["database"]],
              "nginx_cpu_percent": http["cpu_percent"], "database_cpu_percent": database["cpu_percent"],
              "http_p99_ms": http["p99_ms"], "database_p99_ms": database["p99_ms"],
              "errors": http["error_count"] + database["error_count"],
              "queue_drops": http["skipped"] + database["skipped"]}
      writer.writerow({key: flat[key] for key in fields})
  print_report(result)
  return result


def run(config, *, database=None, analyse_only=None):
  if analyse_only is not None:
    return analyse(analyse_only)
  if os.geteuid() != 0:
    raise PermissionError("root is required for E5 Docker and cgroup placement")
  if not float(config["duration_s"]).is_integer():
    raise ValueError("E5 requires a whole number of measurement seconds")
  cases = e5_config.cases(config, database)
  directory = common.new_run(config, "e5")
  print(f"E5 artifacts: {directory}", flush=True)
  suite = {"status": "running", "stage": "capacity_baseline", "planned_cases": cases,
           "cases": [], "command": sys.argv}
  common.write_json(directory / "suite.json", suite)
  try:
    with common.controller_placement(config):
      prepared = e5_docker.prepare(config, directory, cases)
      for case in cases:
        name = f"{case['database']}-r{case['repetition']}"
        print(f"E5: {name} {case['rates']}", flush=True)
        output = directory / name
        output.mkdir()
        e5_capture.capture(config, output, case, prepared)
        suite["cases"].append({"case": case, "directory": name})
        common.write_json(directory / "suite.json", suite)
    suite["status"] = "succeeded"
  except BaseException as error:
    suite.update(status="failed", error=f"{type(error).__name__}: {error}")
    raise
  finally:
    common.write_json(directory / "suite.json", suite)
  result = analyse(directory)
  metadata = common.read_json(directory / "run.json")
  common.write_json(directory / "run.json", {**metadata, "measurement": True,
                    "experiment_validated": False, "stage": "capacity_baseline"})
  print(f"E5 table: {directory / 'results.csv'}", flush=True)
  return result
