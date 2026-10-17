"""Exact moments and quantiles for integer latency histograms."""

from fractions import Fraction
import math


def order_statistic(histogram, rank):
  cumulative = 0
  for value, count in histogram.items():
    cumulative += count
    if cumulative >= rank:
      return value
  raise ValueError("quantile rank exceeds the histogram sample count")


def quantile(histogram, fraction, method):
  samples = sum(histogram.values())
  if method == "nearest_rank":
    return order_statistic(histogram, math.ceil(samples * fraction))
  if method != "linear":
    raise ValueError("quantile_method must be nearest_rank or linear")
  position = (samples - 1) * fraction
  lower = math.floor(position)
  first = order_statistic(histogram, lower + 1)
  if position == lower:
    return first
  second = order_statistic(histogram, lower + 2)
  return float(first + (second - first) * (position - lower))


def summarize(histogram, *, quantile_method, stddev):
  if quantile_method not in ("nearest_rank", "linear") or stddev not in ("population", "sample"):
    raise ValueError("choose nearest_rank/linear quantiles and population/sample standard deviation")
  if any(type(value) is not int or value < 0 or type(count) is not int or count < 0
         for value, count in histogram.items()):
    raise ValueError("latencies and histogram counts must be nonnegative integers")
  histogram = dict(sorted((value, count) for value, count in histogram.items() if count))
  samples = sum(histogram.values())
  result = dict.fromkeys(("min", "max", "mean", "median", "p99", "p999", "stddev"))
  result.update(samples=samples, quantile_method=quantile_method, stddev_kind=stddev)
  if not samples:
    return result
  total = sum(value * count for value, count in histogram.items())
  squares = sum(value * value * count for value, count in histogram.items())
  result.update(min=min(histogram), max=max(histogram), mean=total / samples)
  if stddev == "population" or samples > 1:
    denominator = samples * (samples if stddev == "population" else samples - 1)
    result["stddev"] = math.sqrt(Fraction(samples * squares - total * total, denominator))
  for name, fraction in (("median", Fraction(1, 2)), ("p99", Fraction(99, 100)),
                          ("p999", Fraction(999, 1000))):
    result[name] = quantile(histogram, fraction, quantile_method)
  return result
