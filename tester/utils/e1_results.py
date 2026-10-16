"""Validate one cyclictest histogram and compute E1 latency statistics offline."""

from fractions import Fraction
import math
from pathlib import Path

from . import common


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


def order_statistic(histogram, rank):
  cumulative = 0
  for bucket, count in histogram.items():
    cumulative += count
    if cumulative >= rank:
      return bucket
  raise ValueError("quantile rank exceeds the histogram sample count")


def quantile(histogram, fraction, method):
  samples = sum(histogram.values())
  if method == "nearest_rank":
    return order_statistic(histogram, math.ceil(samples * fraction))
  position = (samples - 1) * fraction
  lower = math.floor(position)
  first = order_statistic(histogram, lower + 1)
  if position == lower:
    return first
  second = order_statistic(histogram, lower + 2)
  return float(first + (second - first) * (position - lower))


def summarize(raw, *, quantile_method, stddev):
  if quantile_method not in ("nearest_rank", "linear"):
    raise ValueError("set E1 quantile_method to nearest_rank or linear")
  if stddev not in ("population", "sample"):
    raise ValueError("set E1 stddev to population or sample")
  histogram = read_histogram(raw)
  samples = sum(histogram.values())
  if stddev == "sample" and samples < 2:
    raise ValueError("sample standard deviation requires at least two samples")
  total = sum(bucket * count for bucket, count in histogram.items())
  squares = sum(bucket * bucket * count for bucket, count in histogram.items())
  denominator = samples * (samples if stddev == "population" else samples - 1)
  result = {
      "samples": samples,
      "histogram_samples": samples,
      "overflow_samples": 0,
      "histogram_bucket_us": 1,
      "quantile_method": quantile_method,
      "stddev_kind": stddev,
      "min_us": min(histogram),
      "max_us": max(histogram),
      "mean_us": total / samples,
      "stddev_us": math.sqrt(Fraction(samples * squares - total * total, denominator)),
  }
  for name, fraction in (("median_us", Fraction(1, 2)), ("p99_us", Fraction(99, 100)),
                          ("p999_us", Fraction(999, 1000))):
    result[name] = quantile(histogram, fraction, quantile_method)
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
