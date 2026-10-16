#!/usr/bin/env python3
"""Run weighted, migratable JLFP workers and check an offline ftrace capture."""

from pathlib import Path
import sys

if not __package__:
  sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tester.utils import arguments, common, inversion, jlfp_capture


def capture_run(args, output, *, periodic):
  settings = args.settings
  config = args.config
  workload = None
  if periodic:
    workload = {
        "period_ns": round(settings["period_ms"] * 1e6),
        "runtime_ns": round(settings["runtime_ms"] * 1e6),
    }

  with arguments.capture_context(args) as (cgroup, cpus):
    return jlfp_capture.capture(
        output=output,
        build_path=args.scx_build_path,
        cpus=cpus,
        count=len(cpus) * settings["tasks_per_cpu"],
        warmup=config["warmup_s"],
        duration=config["duration_s"],
        relative_to=cgroup,
        periodic=workload,
    )


def main(*, periodic=False):
  if periodic:
    name = "jlfp_dynamic"
    prefix = "jlfp-dynamic-test-"
    description = "Run periodic JLFP workers and analyse dynamic inversions."
  else:
    name = "jlfp_static"
    prefix = "jlfp-test-"
    description = __doc__
  args = arguments.parse_experiment(name, description)
  output = None

  try:
    output = arguments.output_directory(args, prefix)
    if args.analyse_only:
      run = common.read_json(output / "run.json")
      run["weights"] = {int(pid): weight for pid, weight in run["weights"].items()}
      print(f"Analysing existing capture: {output}", flush=True)
    else:
      run = capture_run(args, output, periodic=periodic)

    result = inversion.analyse_capture(output, run)
    common.write_json(output / "results.json", result)
    inversion.print_report(result, run)
    return 0
  except KeyboardInterrupt:
    print(f"Interrupted; capture and logs retained in {output}", file=sys.stderr)
    return 130
  except Exception as error:
    print(f"ERROR: {error}; capture and logs retained in {output}", file=sys.stderr)
    return 2


if __name__ == "__main__":
  raise SystemExit(common.run_cli(main))
