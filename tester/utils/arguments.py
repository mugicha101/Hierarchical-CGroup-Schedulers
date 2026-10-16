"""Shared CLI parsing and configured placement for experiment entry points."""

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
import os
from pathlib import Path
import sys

from . import common, experiment_config


def parse_experiment(suite, name, description):
  is_latency = suite == "diagnostics" and name == "latency"
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("--config", type=Path, default=common.DEFAULT_CONFIG)
  output = parser.add_mutually_exclusive_group()
  output.add_argument("--output-dir", type=Path)
  if not is_latency:
    output.add_argument("--analyse-only", type=Path, metavar="CAPTURE_DIR")
  parser.add_argument("--scx-build-path", type=Path, default=common.REPO / "scheds/build",
                      help="debug scheduler build override")
  if is_latency:
    parser.add_argument("--cyclictest", type=Path, help="debug binary override")
    parser.add_argument("--mode", choices=("pinned", "migratable"), default=argparse.SUPPRESS)
    parser.add_argument("--policy", choices=("ext", "fifo", "other"), default=argparse.SUPPRESS)
    parser.add_argument("--no-jlfp", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--diagnostic-trace", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("--spike-us", type=int, default=argparse.SUPPRESS)
  args = parser.parse_args()
  try:
    config = common.load_config(args.config)
    settings = config["experiments"][suite][name]
    for key in tuple(settings):
      if hasattr(args, key):
        settings[key] = getattr(args, key)
    experiment_config.validate(config["experiments"])
    if is_latency and not float(config["duration_s"]).is_integer():
      raise ValueError("cyclictest requires duration_s to be a whole number of seconds")
  except (OSError, ValueError, TypeError, KeyError) as error:
    parser.error(str(error))
  args.config_path = args.config.resolve()
  args.config = config
  args.settings = deepcopy(settings)
  args.analyse_only = getattr(args, "analyse_only", None)
  return args


def output_directory(args, prefix):
  if args.analyse_only:
    return args.analyse_only.resolve(strict=True)
  output = (args.output_dir or common.REPO / "tester/build" /
            (prefix + datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f"))).resolve()
  output.mkdir(parents=True, exist_ok=False)
  common.write_json(output / "experiment.json", {
      "config_file": str(args.config_path), "config": args.config, "command": sys.argv,
      "placement": common.placement_snapshot(args.config),
      "duration_kind": "final" if args.config["duration_s"] == 60 else "development"})
  print(f"Capture and results: {output}", flush=True)
  return output


@contextmanager
def capture_context(args, *, hierarchy=False):
  if os.geteuid() != 0:
    raise PermissionError("root is required for the scheduler, trace and cgroup placement")
  cgroup, _ = common.placement(args.config, hierarchy=hierarchy)
  cpus = common.cgroup_cpus(cgroup)
  with common.controller_placement(args.config):
    yield cgroup, cpus


def parse_driver(description):
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("--config", type=Path, default=common.DEFAULT_CONFIG)
  commands = parser.add_subparsers(dest="command", required=True)
  commands.add_parser("plan", help="show the non-DEADLINE case matrix without running anything")
  check = commands.add_parser("preflight", help="read and record live-run prerequisites")
  check.add_argument("--traced", action="store_true")
  build = commands.add_parser("build", help="build isolated artifacts without attaching schedulers")
  build.add_argument("target", choices=("worker", "jlfp", "qmap", "simple", "cyclictest"))
  build.add_argument("--trace", choices=("off", "events", "hotpath"), default="off")
  smoke = commands.add_parser("smoke", help="check lifecycle with an expired worker schedule")
  smoke.add_argument("scheduler", choices=("none", "jlfp", "qmap", "simple"))
  smoke.add_argument("--traced", action="store_true")
  smoke.add_argument("--basic", action="store_true",
                     help="development check without housekeeping-slice validation")
  return parser.parse_args()


def parse_isolation(description):
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("--config", type=Path, default=common.DEFAULT_CONFIG)
  parser.add_argument("command", choices=("enable", "disable", "status"))
  return parser.parse_args()
