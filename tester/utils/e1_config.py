"""Configuration and policy parameters for the E1 cyclictest matrix."""

import ctypes

SCHEDULERS = ("other", "fifo", "rr", "qmap", "simple", "jlfp")


def validate(settings):
  from .experiment_config import number, require_keys
  require_keys(settings, {"quantile_method", "stddev", "interval_us", "histogram_us",
                         "timer_slack_ns", "cpu_dma_latency_us", "repetitions", "stress", "policies"},
               "experiments.overhead.e1")
  if settings["quantile_method"] not in ("nearest_rank", "linear"):
    raise ValueError("E1 quantile_method must be nearest_rank or linear")
  if settings["stddev"] not in ("population", "sample"):
    raise ValueError("E1 stddev must be population or sample")
  for key in ("interval_us", "histogram_us", "timer_slack_ns", "repetitions"):
    number(settings, key, integer=True)
  if settings["histogram_us"] > 1_000_000 or settings["timer_slack_ns"] > ctypes.c_ulong(-1).value:
    raise ValueError("E1 histogram or timer slack is out of range")
  number(settings, "cpu_dma_latency_us", minimum=-1, inclusive=True, integer=True)
  if settings["cpu_dma_latency_us"] > 2**31 - 1:
    raise ValueError("E1 CPU DMA latency is out of range")
  stress = settings["stress"]
  require_keys(stress, {"cpu_method", "busy_slice_ms", "workers_per_cpu", "utilization_tolerance_percent"},
               "E1 stress")
  if not isinstance(stress["cpu_method"], str) or not stress["cpu_method"].isidentifier():
    raise ValueError("E1 stress cpu_method must name one CPU method")
  number(stress, "busy_slice_ms", integer=True)
  number(stress, "workers_per_cpu", integer=True)
  if number(stress, "utilization_tolerance_percent") > 100:
    raise ValueError("E1 utilization tolerance must be at most 100 percentage points")
  require_keys(settings["policies"], SCHEDULERS, "E1 policies")
  for scheduler, group in settings["policies"].items():
    if scheduler in ("fifo", "rr"):
      require_keys(group, {"cyclictest_priority", "stress_priority"}, f"E1 {scheduler}")
      primary = number(group, "cyclictest_priority", integer=True)
      background = number(group, "stress_priority", integer=True)
      if not background < primary <= 99:
        raise ValueError(f"E1 {scheduler} requires 1 <= stress priority < cyclictest priority <= 99")
    elif scheduler == "jlfp":
      require_keys(group, {"cyclictest_weight", "stress_weight", "slice_ns", "max_shard_size"}, "E1 JLFP")
      primary = number(group, "cyclictest_weight", integer=True)
      background = number(group, "stress_weight", integer=True)
      if not background < primary < 1 << 63:
        raise ValueError("E1 JLFP requires stress weight < cyclictest weight < 2^63")
      number(group, "slice_ns", integer=True)
      number(group, "max_shard_size", integer=True)
    else:
      keys = {"cyclictest_nice", "stress_nice"} | ({"slice_ns"} if scheduler == "qmap" else set())
      require_keys(group, keys, f"E1 {scheduler}")
      primary = number(group, "cyclictest_nice", minimum=-20, inclusive=True, integer=True)
      background = number(group, "stress_nice", minimum=-20, inclusive=True, integer=True)
      if not primary < background <= 19:
        raise ValueError(f"E1 {scheduler} requires cyclictest nice < stress nice <= 19")
      if scheduler == "qmap":
        if number(group, "slice_ns", integer=True) % 1000:
          raise ValueError("qmap slice_ns must be a whole number of microseconds")


def policy(settings, scheduler, role):
  group = settings["policies"][scheduler]
  return {"policy": scheduler if scheduler in ("other", "fifo", "rr") else "ext",
          "priority": group.get(f"{role}_priority", 0),
          "nice": group.get(f"{role}_nice", 0), "weight": group.get(f"{role}_weight")}


def statistics(settings):
  return {key: settings[key] for key in ("quantile_method", "stddev")}


def cases(config):
  settings = config["experiments"]["overhead"]
  target = settings["stress_utilization_percent"]
  for repetition in range(1, settings["e1"]["repetitions"] + 1):
    for scheduler in SCHEDULERS:
      for stressed in (False, True):
        yield {"scheduler": scheduler, "stress": stressed,
               "target_utilization_percent": target if stressed else None,
               "repetition": repetition}
