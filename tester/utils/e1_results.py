"""Validate one cyclictest histogram and compute E1 latency statistics offline."""

from pathlib import Path

from . import common, latency_stats
from .latency_stats import order_statistic, quantile


def integer(value, name, *, minimum=0):
  if type(value) is not int or value < minimum:
    raise ValueError(f"invalid cyclictest {name}: {value!r}")
  return value


def read_histogram(raw):
  if integer(raw["return_code"], "return code") != 0:
    raise ValueError("cyclictest reported a failed run")
  if integer(raw["resolution_in_ns"], "resolution") != 0:
    raise ValueError("E1 requires integer microsecond samples")
  if integer(raw["num_threads"], "thread count") != 1 or len(raw["thread"]) != 1:
    raise ValueError("E1 requires exactly one measurement thread")
  thread = next(iter(raw["thread"].values()))
  samples = integer(thread["cycles"], "sample count", minimum=1)
  histogram = {}
  for bucket, count in thread["histogram"].items():
    if not isinstance(bucket, str) or not bucket.isdecimal() or str(int(bucket)) != bucket:
      raise ValueError(f"invalid cyclictest histogram bucket: {bucket!r}")
    count = integer(count, "bucket count")
    if count:
      histogram[int(bucket)] = count
  total = sum(histogram.values())
  if total < samples:
    raise ValueError(f"incomplete cyclictest histogram: {samples - total} samples overflowed or are missing")
  if total > samples:
    raise ValueError("cyclictest histogram has more entries than recorded samples")
  minimum = integer(thread["min"], "minimum")
  maximum = integer(thread["max"], "maximum")
  if min(histogram) != minimum or max(histogram) != maximum:
    raise ValueError("cyclictest histogram extrema differ from reported minimum/maximum")
  return dict(sorted(histogram.items()))


def summarize(raw, *, quantile_method, stddev):
  histogram = read_histogram(raw)
  statistics = latency_stats.summarize(histogram, quantile_method=quantile_method, stddev=stddev)
  if stddev == "sample" and statistics["samples"] < 2:
    raise ValueError("sample standard deviation requires at least two samples")
  result = {key: statistics[key] for key in ("samples", "quantile_method", "stddev_kind")}
  result.update(histogram_samples=statistics["samples"], overflow_samples=0, histogram_bucket_us=1)
  result.update({name + "_us": statistics[name] for name in
                 ("min", "max", "mean", "median", "p99", "p999", "stddev")})
  return result


def analyse(source, output, settings):
  source, output = Path(source).resolve(strict=True), Path(output).resolve()
  if source == output:
    raise ValueError("analysis output must not overwrite the raw cyclictest JSON")
  report = {"valid": False, "analysis_only": True, "experiment_validated": False,
            "source": str(source), "source_sha256": common.sha256(source),
            "settings": settings}
  try:
    report["statistics"] = summarize(common.read_json(source), **settings)
    report["valid"] = True
    return report
  except (KeyError, TypeError, ValueError) as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise ValueError(f"E1 histogram analysis failed: {error}") from error
  finally:
    common.write_json(output, report)
