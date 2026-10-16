"""Validate experiment-specific settings without touching the running system."""

import ctypes
import math

from . import mc2_workload


def number(settings, key, *, minimum=0, inclusive=False, integer=False):
  value = settings[key]
  if type(value) not in ((int,) if integer else (int, float)) or not math.isfinite(value) or \
      (value < minimum if inclusive else value <= minimum):
    raise ValueError(f"invalid {key}: {value!r}")
  return value


def validate(settings):
  keys = {
      "jlfp_static": {"tasks_per_cpu"},
      "jlfp_dynamic": {"tasks_per_cpu", "period_ms", "runtime_ms"},
      "mc2": {"classes"},
      "wakeup": {"workers", "period_ms", "runtime_us"},
      "latency": {"mode", "policy", "no_jlfp", "priority", "threads", "interval_us",
                  "histogram_us", "cpu_dma_latency_us", "timer_slack_ns", "diagnostic_trace", "spike_us"},
  }
  if not isinstance(settings, dict) or set(settings) != set(keys):
    raise ValueError(f"experiments must contain {sorted(keys)}")
  for name, expected in keys.items():
    if not isinstance(settings[name], dict) or set(settings[name]) != expected:
      raise ValueError(f"{name} settings must contain {sorted(expected)}")
  for name in ("jlfp_static", "jlfp_dynamic"):
    number(settings[name], "tasks_per_cpu", minimum=2, inclusive=True, integer=True)
  for name, runtime, scale in (("jlfp_dynamic", "runtime_ms", 1e6), ("wakeup", "runtime_us", 1e3)):
    group = settings[name]
    period_ns = round(number(group, "period_ms") * 1e6)
    runtime_ns = round(number(group, runtime) * scale)
    if not 0 < runtime_ns < period_ns:
      raise ValueError(f"{name} requires 0 < runtime < period after nanosecond rounding")
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
  mc2_workload.validate(settings["mc2"]["classes"])
