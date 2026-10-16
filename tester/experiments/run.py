#!/usr/bin/env python3
"""Prepare experiments and check their lifecycle; no benchmark cases run yet."""

import json
from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.experiments import smoke
from tester.utils import arguments, builds, common, preflight


def plan(config):
  return {
      "duration_s": config["duration_s"],
      "warmup_s": config["warmup_s"],
      "workload_cgroup": config["workload_cgroup"],
      "test_cpus": config["test_cpus"],
      "controller_cpus": config["controller_cpus"],
      "utilization_cpus": config["test_cpus"],
      "stress_utilization_percent": config["stress_utilization_percent"],
      "overhead_e1": ["other", "fifo", "rr", "qmap", "simple", "jlfp"],
      "overhead_e2": ["other", "fifo", "qmap", "jlfp"],
      "overhead_e3_e4": ["jlfp"],
      "deferred_policies": {"deadline": "pending methodology"},
      "benchmark_implementation": "pending stages 3-6",
      "legacy_experiments": config["experiments"],
  }


def check_environment(config, *, traced):
  report = preflight.inspect(config, traced=traced)
  output = common.new_run(config, "preflight")
  common.write_json(output / "preflight.json", report)

  for check in report["checks"]:
    if check["ok"]:
      status = "ok"
    elif check["required"]:
      status = "missing"
    else:
      status = "note"
    print(f"{status}: {check['name']}: {check['detail']}")
  print(f"Report: {output / 'preflight.json'}")
  return 0 if report["ok"] else 2


def main():
  args = arguments.parse_driver(__doc__)
  try:
    config = common.load_config(args.config)
    if args.command == "plan":
      print(json.dumps(plan(config), indent=2))
    elif args.command == "preflight":
      return check_environment(config, traced=args.traced)
    elif args.command == "build":
      if args.trace != "off" and args.target != "jlfp":
        raise ValueError("custom trace profiles apply only to JLFP")
      builds.build(config, target=args.target, trace=args.trace)
    else:
      smoke.run(config, scheduler=args.scheduler, traced=args.traced, basic=args.basic)
    return 0
  except KeyboardInterrupt:
    print("Interrupted; attempt artifacts retained", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
