"""Derive MC² task budgets from each class's share of the configured CPUs."""

from fractions import Fraction
import math

CLASSES = ("class_a", "class_b", "class_c")


def class_plan(settings, cpus):
  count = settings["tasks_per_cpu"]
  periods = [round(value * 1e6) for value in settings["periods_ms"]]
  share = Fraction(str(settings["utilization_percent"])) / 100
  if not share:
    return [], {"target_percent": 0, "nominal_percent": 0, "tasks": 0}
  # every CPU gets the same period mix; one common budget preserves that mix's load ratios
  density = sum((Fraction(1, period) for period in periods), Fraction())
  runtime = round(share / density)
  if runtime <= 0 or any(runtime >= period for period in periods):
    raise ValueError("MC2 class load requires 0 < task runtime < period after rounding")
  order = sorted(set(periods))
  ranks = {period: len(order) - index for index, period in enumerate(order)}
  base_period = min(periods)
  workers = []
  for index, cpu in enumerate(sorted(cpus)):
    for slot, period in enumerate(periods):
      phase = slot * base_period // count + index * base_period // (len(cpus) * count) \
          if settings["stagger"] else 0
      workers.append({"cpu": cpu, "period_ns": period, "runtime_ns": runtime,
                      "phase_ns": phase, "weight": ranks[period]})
  return workers, {"target_percent": float(100 * share),
                   "nominal_percent": float(100 * runtime * density), "tasks": len(workers)}


def validate(settings):
  if not isinstance(settings, dict) or set(settings) != set(CLASSES):
    raise ValueError("mc2.classes must contain class_a, class_b and class_c")
  for name, group in settings.items():
    if not isinstance(group, dict) or set(group) != {
        "utilization_percent", "tasks_per_cpu", "periods_ms", "stagger"}:
      raise ValueError(f"invalid MC2 settings for {name}")
    count = group["tasks_per_cpu"]
    if type(count) is not int or count < 1:
      raise ValueError(f"{name}.tasks_per_cpu must be positive")
    periods = group["periods_ms"]
    if not isinstance(periods, list) or len(periods) != count or any(
        type(value) not in (int, float) or not math.isfinite(value) or value <= 0 or
        round(value * 1e6) < 1 for value in periods):
      raise ValueError(f"{name}.periods_ms needs one positive period per task per CPU")
    target = group["utilization_percent"]
    if type(target) not in (int, float) or not math.isfinite(target) or not 0 <= target <= 100:
      raise ValueError(f"{name}.utilization_percent must be between 0 and 100")
    if type(group["stagger"]) is not bool:
      raise ValueError(f"{name}.stagger must be boolean")
    class_plan(group, {0})
  if not any(group["utilization_percent"] for group in settings.values()):
    raise ValueError("MC2 needs at least one class with positive utilization")
