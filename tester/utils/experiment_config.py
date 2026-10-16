"""Validate experiment-specific settings without touching the running system."""

import ctypes
import math

from . import e1_config, mc2_workload


def number(settings, key, *, minimum=0, inclusive=False, integer=False):
  value = settings[key]
  if type(value) not in ((int,) if integer else (int, float)) or not math.isfinite(value) or \
      (value < minimum if inclusive else value <= minimum):
    raise ValueError(f"invalid {key}: {value!r}")
  return value


def require_keys(settings, keys, name):
  if not isinstance(settings, dict) or set(settings) != set(keys):
    raise ValueError(f"{name} must contain {sorted(keys)}")


def validate(settings):
  require_keys(settings, {"inversion", "overhead", "diagnostics"}, "experiments")
  validate_inversion(settings["inversion"])
  validate_overhead(settings["overhead"])
  validate_diagnostics(settings["diagnostics"])


def validate_inversion(settings):
  keys = {
      "jlfp_static": {"tasks_per_cpu"},
      "jlfp_dynamic": {"tasks_per_cpu", "period_ms", "runtime_ms"},
      "mc2": {"classes"},
  }
  require_keys(settings, keys, "experiments.inversion")
  for name, expected in keys.items():
    require_keys(settings[name], expected, f"inversion.{name}")
  for name in ("jlfp_static", "jlfp_dynamic"):
    number(settings[name], "tasks_per_cpu", minimum=2, inclusive=True, integer=True)
  group = settings["jlfp_dynamic"]
  period_ns = round(number(group, "period_ms") * 1e6)
  runtime_ns = round(number(group, "runtime_ms") * 1e6)
  if not 0 < runtime_ns < period_ns:
    raise ValueError("jlfp_dynamic requires 0 < runtime < period after nanosecond rounding")
  mc2_workload.validate(settings["mc2"]["classes"])


def validate_overhead(settings):
  require_keys(settings, {"cyclictest_cpu", "stress_utilization_percent", "e1"}, "experiments.overhead")
  if type(settings["cyclictest_cpu"]) is not int or settings["cyclictest_cpu"] != 9:
    raise ValueError("overhead E1 requires logical CPU 9")
  value = number(settings, "stress_utilization_percent", inclusive=True)
  if value > 100:
    raise ValueError("overhead.stress_utilization_percent must be between 0 and 100")
  e1_config.validate(settings["e1"])


def validate_diagnostics(settings):
  keys = {
      "wakeup": {"workers", "period_ms", "runtime_us"},
      "latency": {"mode", "policy", "no_jlfp", "priority", "threads", "interval_us",
                  "histogram_us", "cpu_dma_latency_us", "timer_slack_ns", "diagnostic_trace", "spike_us"},
  }
  require_keys(settings, keys, "experiments.diagnostics")
  for name, expected in keys.items():
    require_keys(settings[name], expected, f"diagnostics.{name}")
  group = settings["wakeup"]
  period_ns = round(number(group, "period_ms") * 1e6)
  runtime_ns = round(number(group, "runtime_us") * 1e3)
  if not 0 < runtime_ns < period_ns:
    raise ValueError("wakeup requires 0 < runtime < period after nanosecond rounding")
  if number(settings["wakeup"], "workers", integer=True) > 32:
    raise ValueError("wakeup.workers must be at most 32")
  group = settings["latency"]
  if group["mode"] not in ("pinned", "migratable") or group["policy"] not in ("ext", "fifo", "other"):
    raise ValueError("invalid latency mode or policy")
  for key in ("no_jlfp", "diagnostic_trace"):
    if type(group[key]) is not bool:
      raise ValueError(f"latency.{key} must be boolean")
  priority = group["priority"]
  if priority is not None and (type(priority) is not int or
      not (1 <= priority <= 99 if group["policy"] == "fifo" else priority == 0)):
    raise ValueError("latency priority must be 1..99 for FIFO, 0 for EXT/OTHER, or null for the policy default")
  if group["no_jlfp"] and group["policy"] == "ext":
    raise ValueError("EXT requires JLFP")
  for key in ("threads", "interval_us", "histogram_us", "spike_us", "timer_slack_ns"):
    number(group, key, integer=True)
  if group["histogram_us"] > 1_000_000 or group["timer_slack_ns"] > ctypes.c_ulong(-1).value:
    raise ValueError("latency histogram or timer slack is out of range")
  number(group, "cpu_dma_latency_us", minimum=-1, inclusive=True, integer=True)
  if group["cpu_dma_latency_us"] > 2**31 - 1:
    raise ValueError("CPU DMA latency is out of range")
