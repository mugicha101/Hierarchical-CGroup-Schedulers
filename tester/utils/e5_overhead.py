"""E3-style class/callback measurements for the complete E5 hierarchy."""

from pathlib import Path
import tempfile

from . import bpftrace_capture, bpftrace_convert, common, e1_capture, operation_analysis, overhead_config

RAW_FILES = ("bpftrace.stdout", "bpftrace.stderr", "bpftrace.json", "sched_trace.bt",
             "sched_trace_config.h", "operations.jsonl", "operations.metadata.json", "conversion.json")
SCOPE = ("aggregate root and leaf callbacks on the workload CPU; generic op IDs do not identify "
         "the scheduler instance or container; remote CPU work excluded")


def prepare(config, directory):
  profile = overhead_config.binding(config, "e5", "jlfp")
  report = overhead_config.inspect_events(profile, "e5")
  common.write_json(Path(directory) / "trace-preflight.json", report)
  e1_capture.check_tracing(directory)
  return profile


def recording(config, directory, profile, cpu):
  return bpftrace_capture.Recording(directory, profile, {cpu},
      config["experiments"]["overhead"]["operation_tracing"], config["process_timeout_s"])


def summarize(report):
  if not report["valid"] or not any(row["layer"] == "kernel" and row["samples"]
                                   for row in report["operations"]) or not any(
      row.get("kernel_callback_reported_ns", 0) for row in report["operations"]):
    raise ValueError("E5 requires callback samples nested within measured class operations")
  return {"valid": True, "scope": SCOPE, "operations": report["operations"],
          "pairing_counts": report["pairing_counts"],
          "calibration": "pending; inclusive elapsed time, no probe/IRQ/preemption cost subtraction"}


def finish(directory, capture, config, profile):
  e1_capture.check_tracing(directory, phase="after")
  window = capture["window"]
  trace = {"experiment": "e5", "case": {**capture["case"], "scheduler": "jlfp"},
           "trace_binding": profile, "utilization_cpus": [capture["cpu"]],
           "start_ns": window["measure_ns"], "end_ns": window["end_ns"],
           "statistics": overhead_config.statistics(config)}
  bpftrace_convert.convert(directory, trace)
  return summarize(operation_analysis.analyse(directory, Path(directory) / "operation-analysis"))


def replay(directory):
  with tempfile.TemporaryDirectory(prefix="e5-replay-", dir=directory) as temporary:
    return summarize(operation_analysis.analyse(directory, Path(temporary) / "analysis"))
