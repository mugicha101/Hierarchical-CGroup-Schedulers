"""Analyse completed operation captures offline and preserve exact paired-call samples."""

from collections import Counter, defaultdict
import csv
import json
from pathlib import Path

from . import common, latency_stats, operation_pairs, operation_trace


class Statistics:
  def __init__(self, metadata):
    self.metadata = metadata
    self.histograms = defaultdict(Counter)
    self.callback_time = Counter()
    self.has_callbacks = any(item["layer"] == "scx" for item in metadata["expected_operations"])

  def add(self, call):
    for cpu in (None, call["cpu"]):
      key = cpu, call["layer"], call["operation"]
      self.histograms[key][call["duration_ns"]] += 1
      self.callback_time[key] += call.get("observed_scx_union_ns", 0)

  def rows(self):
    for item in self.metadata["expected_operations"]:
      for cpu in (None, *self.metadata["cpus"]):
        key = cpu, item["layer"], item["operation"]
        histogram = self.histograms[key]
        stats = latency_stats.summarize(histogram, **self.metadata["statistics"])
        row = {"scheduler": self.metadata["scheduler"], "cpu": cpu, **item,
               **{name: stats[name] for name in ("samples", "quantile_method", "stddev_kind")},
               **{name + "_ns": stats[name] for name in
                  ("min", "max", "mean", "median", "p99", "p999", "stddev")}}
        total = sum(value * count for value, count in histogram.items())
        measured = self.has_callbacks and item["layer"] == "class"
        row["observed_scx_union_ns"] = self.callback_time[key] if measured else None
        row["duration_weighted_scx_percent"] = 100 * self.callback_time[key] / total if measured and total else None
        yield row


def save_table(path, rows):
  with path.open("x", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=tuple(rows[0]))
    writer.writeheader()
    writer.writerows(rows)


def analyse(capture, output):
  capture = Path(capture).resolve(strict=True)
  source = capture / "operations.jsonl"
  metadata_path = capture / "operations.metadata.json"
  output = Path(output).resolve()
  output.mkdir(parents=True, exist_ok=False)
  pairing = operation_pairs.Pairing()
  report = {"valid": False, "analysis_only": True, "experiment_validated": False,
            "capture": str(capture), "timing": "inclusive elapsed nanoseconds; no IRQ/preemption or probe-cost subtraction",
            "attribution": "union of recorded descendant SCX calls, same execution CPU/context; declared callbacks only"}
  partial = output / "paired-calls.partial.jsonl"
  try:
    report["inputs_sha256"] = {path.name: common.sha256(path) for path in (source, metadata_path)}
    metadata = common.read_json(metadata_path)
    expected = operation_trace.validate_metadata(metadata)
    statistics = Statistics(metadata)
    latency_stats.summarize({}, **metadata["statistics"])
    report["metadata"] = metadata
    report["scx_instrumented"] = statistics.has_callbacks
    with partial.open("x") as calls:
      for record in operation_trace.read_records(source, metadata, expected):
        call = pairing.consume(record)
        if call is None:
          continue
        if not statistics.has_callbacks:
          call = {key: value for key, value in call.items() if not key.startswith("observed_scx_")}
        statistics.add(call)
        calls.write(json.dumps(call, allow_nan=False) + "\n")
    pairing.finish()
    records_read = pairing.counts["enter"] + pairing.counts["exit"]
    if records_read != metadata["record_count"]:
      raise ValueError("record count differs from capture metadata; the stream may be truncated")
    if any(common.sha256(capture / name) != value for name, value in report["inputs_sha256"].items()):
      raise ValueError("operation capture changed during analysis")
    rows = list(statistics.rows())
    save_table(output / "latencies.csv", rows)
    partial.rename(output / "paired-calls.jsonl")
    report.update(valid=True, operations=rows)
    return report
  except BaseException as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise
  finally:
    report.update(pairing_counts=dict(pairing.counts), unmatched_entries=pairing.open_calls())
    common.write_json(output / "analysis.json", report)
