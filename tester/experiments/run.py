#!/usr/bin/env python3
"""Prepare experiments and check their lifecycle; no benchmark cases run yet."""

import json
from pathlib import Path
import signal
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, builds, preflight
from tester.utils.common import load_config, new_run, write_json


def plan(config):
  return {"duration_s": config["duration_s"], "warmup_s": config["warmup_s"], "workload_cgroup": config["workload_cgroup"],
          "test_cpus": config["test_cpus"], "controller_cpus": config["controller_cpus"],
          "utilization_cpus": config["test_cpus"],
          "stress_utilization_percent": config["stress_utilization_percent"],
          "overhead_e1": ["other", "fifo", "rr", "qmap", "simple", "jlfp"],
          "overhead_e2": ["other", "fifo", "qmap", "jlfp"],
          "overhead_e3_e4": ["jlfp"], "deferred_policies": {"deadline": "pending methodology"},
          "benchmark_implementation": "pending stages 3-6",
          "legacy_experiments": config["experiments"]}


def main():
  args = arguments.parse_driver(__doc__)
  try:
    config = load_config(args.config)
    if args.command == "plan":
      print(json.dumps(plan(config), indent=2))
    elif args.command == "preflight":
      report = preflight.inspect(config, traced=args.traced)
      output = new_run(config, "preflight")
      write_json(output / "preflight.json", report)
      for check in report["checks"]:
        status = "ok" if check["ok"] else "missing" if check["required"] else "note"
        print(f"{status}: {check['name']}: {check['detail']}")
      print(f"Report: {output / 'preflight.json'}")
      return 0 if report["ok"] else 2
    elif args.command == "build":
      if args.trace != "off" and args.target != "jlfp":
        raise ValueError("custom trace profiles apply only to JLFP")
      builds.build(config, args.target, args.trace)
    else:
      from tester.experiments import smoke
      smoke.run(config, args.scheduler, args.traced, args.basic)
    return 0
  except KeyboardInterrupt:
    print("Interrupted; attempt artifacts retained", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  def interrupt(*_):
    raise KeyboardInterrupt
  signal.signal(signal.SIGTERM, interrupt)
  raise SystemExit(main())
