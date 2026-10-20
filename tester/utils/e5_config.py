"""Configuration and case selection for E5 container experiments."""

import re

DATABASES = ("redis", "postgres", "mongo")
SERVICES = ("nginx", *DATABASES)


def validate(settings):
  from .experiment_config import number, require_keys
  require_keys(settings, {"repetitions", "shards", "connections_per_shard", "queue_capacity",
                          "records", "payload_bytes", "response_bytes", "request_timeout_s",
                          "images", "memory_mb", "profiles", "screening", "scheduling"}, "containers.e5")
  for key in ("repetitions", "shards", "connections_per_shard", "queue_capacity",
              "records", "payload_bytes", "response_bytes"):
    number(settings, key, integer=True)
  number(settings, "request_timeout_s")
  for key in ("images", "memory_mb"):
    require_keys(settings[key], SERVICES, f"containers.e5.{key}")
  for service in SERVICES:
    image = settings["images"][service]
    if not isinstance(image, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image):
      raise ValueError(f"E5 {service} image must be pinned by sha256 digest")
    number(settings["memory_mb"], service, integer=True)
  require_keys(settings["profiles"], DATABASES, "containers.e5.profiles")
  for name, profile in settings["profiles"].items():
    require_keys(profile, {"nginx_rps", "database_rps"}, f"containers.e5.profiles.{name}")
    number(profile, "nginx_rps", integer=True)
    number(profile, "database_rps", integer=True)
  require_keys(settings["screening"], {"minimum_completion_percent", "max_combined_cpu_percent",
                                     "max_cpu_busy_percent"}, "containers.e5.screening")
  for key in settings["screening"]:
    if number(settings["screening"], key) > 100:
      raise ValueError(f"E5 {key} must be at most 100")
  scheduling = settings["scheduling"]
  require_keys(scheduling, {"mode", "trace", "slice_ns", "container_weights", "nginx_period_ns"},
               "containers.e5.scheduling")
  if scheduling["mode"] not in ("scx", "native") or type(scheduling["trace"]) is not bool:
    raise ValueError("E5 scheduling requires mode scx/native and boolean trace")
  if scheduling["mode"] == "native" and scheduling["trace"]:
    raise ValueError("E5 native capacity baseline does not collect SCX overhead")
  number(scheduling, "slice_ns", integer=True)
  require_keys(scheduling["container_weights"], {"nginx", "database"}, "E5 container_weights")
  weights = scheduling["container_weights"]
  for name in weights:
    number(weights, name, integer=True)
  if not 1 <= weights["database"] < weights["nginx"] <= 10000:
    raise ValueError("E5 requires nginx > database container weights within 1..10000")
  periods = scheduling["nginx_period_ns"]
  require_keys(periods, {"worker", "master"}, "E5 nginx_period_ns")
  for role, period in periods.items():
    if period is not None and (type(period) is not int or not 0 < period < (1 << 63) - 1):
      raise ValueError(f"E5 {role} period must be null or a positive 63-bit integer")


def scheduling(config):
  return config["experiments"]["containers"]["e5"]["scheduling"]


def stage(config):
  return "scx_hierarchy" if scheduling(config)["mode"] == "scx" else "capacity_baseline"


def cases(config, database=None):
  settings = config["experiments"]["containers"]["e5"]
  if database is not None and database not in DATABASES:
    raise ValueError(f"unknown E5 database: {database}")
  return [{"database": name, "repetition": repetition,
           "rates": {"nginx": settings["profiles"][name]["nginx_rps"],
                     name: settings["profiles"][name]["database_rps"]}}
          for name in DATABASES if database is None or name == database
          for repetition in range(1, settings["repetitions"] + 1)]


def fits(result, screening):
  services = result["services"].values()
  return bool(all(item["completed"] >= item["scheduled"] * screening["minimum_completion_percent"] / 100
                  and item["skipped"] == 0 and item["error_count"] == 0 for item in services)
              and result["combined_cpu_percent"] <= screening["max_combined_cpu_percent"]
              and result["host_cpu_max_percent"] <= screening["max_cpu_busy_percent"])
