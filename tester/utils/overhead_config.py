"""E2-E4 matrices and explicit target-kernel tracepoint bindings."""

import re
from pathlib import Path

from . import e1_config

SCHEDULERS = {"e2": ("other", "fifo", "qmap", "jlfp"), "e3": ("jlfp",), "e4": ("jlfp",)}
IRQ_EVENTS = ("irq:irq_handler_entry", "irq:irq_handler_exit", "irq:softirq_entry", "irq:softirq_exit")
SCX_EVENTS = ("scxtp:scxtp_op_entry", "scxtp:scxtp_op_exit")
# callback names use the canonical sched_ext_ops members, including CID equivalents
SCX_CALLBACKS = {"init", "exit", "select_cpu", "enqueue", "dispatch", "running", "stopping",
                 "update_idle", "init_task", "exit_task", "set_cpumask", "cgroup_set_weight",
                 "sub_attach", "sub_detach", "tick"}


def scx_operations(profile):
  if profile["scope"] != "scx_dispatch":
    raise ValueError("JLFP callback IDs require the target's SCX_OP_IDX callback mapping")
  return {int(key): name for key, name in profile["operations"].items() if name in SCX_CALLBACKS}


def validate(settings):
  from .experiment_config import number, require_keys
  for name in SCHEDULERS:
    require_keys(settings[name], {"repetitions"}, f"overhead.{name}")
    number(settings[name], "repetitions", integer=True)
  tracing = settings["operation_tracing"]
  require_keys(tracing, {"class_events", "scx_kernel_events"}, "overhead.operation_tracing")
  require_keys(tracing["class_events"], {"other", "fifo", "ext"}, "class_events")
  for profile in (*tracing["class_events"].values(), tracing["scx_kernel_events"]):
    if profile is None:
      continue
    require_keys(profile, {"enter_event", "exit_event", "operations", "scope", "duration_field"},
                 "operation tracepoint binding")
    for key in ("enter_event", "exit_event"):
      if not isinstance(profile[key], str) or not re.fullmatch(r"\w+:\w+", profile[key]):
        raise ValueError(f"{key} must be a literal system:event")
    if profile["enter_event"] == profile["exit_event"]:
      raise ValueError("operation entry and exit events must differ")
    if profile["scope"] not in (None, "sched_class", "scx_dispatch"):
      raise ValueError("operation scope must be sched_class, scx_dispatch or null pending confirmation")
    if profile["duration_field"] is not None and not re.fullmatch(r"\w+", profile["duration_field"]):
      raise ValueError("duration_field must name a field or be null")
    operations = profile["operations"]
    if not isinstance(operations, dict) or any(not re.fullmatch(r"0|[1-9]\d*", key) or
        int(key) >= 2**32 or not isinstance(value, str) or not value.strip()
        for key, value in operations.items()):
      raise ValueError("operations must map decimal u32 IDs to nonempty operation names")
    if len(set(operations.values())) != len(operations):
      raise ValueError("operation names must be distinct within a binding")


def binding(config, experiment, scheduler):
  tracing = config["experiments"]["overhead"]["operation_tracing"]
  if experiment == "e2":
    key = scheduler if scheduler in ("other", "fifo") else "ext"
    profile = tracing["class_events"][key]
  else:
    profile = tracing["scx_kernel_events"]
  if profile is None or profile["scope"] is None or not profile["operations"]:
    raise ValueError(f"{experiment}/{scheduler}: set confirmed kernel tracepoint scope and operation IDs "
                     "in overhead.operation_tracing; kernel IDs cannot be inferred from scxtp IDs")
  if experiment == "e2" and profile["scope"] != "sched_class":
    raise ValueError("E2 requires sched_class method boundaries; callback dispatch is a different layer")
  return profile


def events(profile, experiment):
  result = (profile["enter_event"], profile["exit_event"], *IRQ_EVENTS)
  return result + SCX_EVENTS if experiment != "e2" else result


def inspect_events(profile, experiment, tracefs=Path("/sys/kernel/tracing")):
  report = {}
  for event in events(profile, experiment):
    system, name = event.split(":")
    text = (tracefs / "events" / system / name / "format").read_text()
    required = {"common_pid", "common_flags"}
    if event not in IRQ_EVENTS:
      required.add("op")
      if event == profile["exit_event"] and profile["duration_field"]:
        required.add(profile["duration_field"])
    if event.startswith("scxtp:"):
      required.add("sched_cgrp_id")
    fields = set(re.findall(r"field:[^;]*\b(\w+)(?:\[[^]]*\])?;", text))
    if not required <= fields:
      raise ValueError(f"{event} is missing required fields: {sorted(required - fields)}")
    report[event] = text
  return report


def cases(config, experiment, scheduler=None, stress=None):
  overhead = config["experiments"]["overhead"]
  if scheduler is not None and scheduler not in SCHEDULERS[experiment]:
    raise ValueError(f"{experiment} supports {', '.join(SCHEDULERS[experiment])}")
  for repetition in range(1, overhead[experiment]["repetitions"] + 1):
    for policy in SCHEDULERS[experiment]:
      if scheduler is not None and scheduler != policy:
        continue
      for loaded in (False, True):
        if stress is not None and loaded != (stress == "on"):
          continue
        yield {"scheduler": policy, "stress": loaded, "repetition": repetition,
               "target_utilization_percent": overhead["stress_utilization_percent"] if loaded else None}


def statistics(config):
  return e1_config.statistics(config["experiments"]["overhead"]["e1"])
