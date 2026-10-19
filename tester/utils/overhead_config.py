"""E2-E4 matrices, explicit function coverage and target callback bindings."""

import re
from pathlib import Path

from . import bpf_capture_info, e1_config

SCHEDULERS = {"e2": ("other", "fifo", "deadline", "qmap", "jlfp"), "e3": ("jlfp",), "e4": ("jlfp",)}
# retained for replaying the older tracepoint adapter
IRQ_EVENTS = ("irq:irq_handler_entry", "irq:irq_handler_exit", "irq:softirq_entry", "irq:softirq_exit")
SCX_EVENTS = ("scxtp:scxtp_op_entry", "scxtp:scxtp_op_exit")
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
  require_keys(tracing, {"class_functions", "excluded_functions", "scx_kernel_events",
                         "buffer_pages", "drain_s"}, "overhead.operation_tracing")
  require_keys(tracing["class_functions"], {"other", "fifo", "deadline", "ext"}, "class_functions")
  for functions in tracing["class_functions"].values():
    if not isinstance(functions, dict) or not functions or any(
        not re.fullmatch(r"\w+", key) or not isinstance(value, str) or
        not re.fullmatch(r"[A-Za-z_]\w*", value) for key, value in functions.items()):
      raise ValueError("class_functions must map operation names to literal function names")
    if len(set(functions.values())) != len(functions):
      raise ValueError("class function names must be distinct within a class")
  if not isinstance(tracing["excluded_functions"], dict) or any(
      not re.fullmatch(r"[A-Za-z_]\w*", key) or not isinstance(reason, str) or not reason.strip()
      for key, reason in tracing["excluded_functions"].items()):
    raise ValueError("excluded_functions must map literal names to explicit reasons")
  pages = number(tracing, "buffer_pages", integer=True)
  if pages > 8192 or pages & (pages - 1):
    raise ValueError("buffer_pages must be a power of two no larger than 8192")
  if number(tracing, "drain_s") > 5:
    raise ValueError("operation drain_s must be at most five seconds")
  profile = tracing["scx_kernel_events"]
  require_keys(profile, {"enter_event", "exit_event", "duration_field"}, "scx_kernel_events")
  for key in ("enter_event", "exit_event"):
    if not isinstance(profile[key], str) or not re.fullmatch(r"\w+:\w+", profile[key]):
      raise ValueError(f"{key} must be a literal system:event")
  if profile["enter_event"] == profile["exit_event"] or not re.fullmatch(r"\w+", profile["duration_field"]):
    raise ValueError("callback events must differ and duration_field must name a field")


def binding(config, experiment, scheduler):
  tracing = config["experiments"]["overhead"]["operation_tracing"]
  key = scheduler if scheduler in ("other", "fifo", "deadline") else "ext"
  declared = tracing["class_functions"][key]
  excluded = tracing["excluded_functions"]
  functions = {op: fn for op, fn in declared.items() if fn not in excluded}
  if not functions:
    raise ValueError("no class functions remain after exclusions")
  return {"class_operations": functions,
          "excluded_functions": {fn: excluded[fn] for fn in declared.values() if fn in excluded},
          "context_expression": bpf_capture_info.context_expression(),
          "callbacks": bpf_capture_info.callback_ids() if experiment != "e2" else {},
          **tracing["scx_kernel_events"]}


def inspect_events(profile, experiment, tracefs=Path("/sys/kernel/tracing")):
  available = {line.split()[0] for line in (tracefs / "available_filter_functions").read_text().splitlines()}
  missing = set(profile["class_operations"].values()) - available
  if missing:
    raise ValueError(f"declared class functions lack ftrace instrumentation: {sorted(missing)}; "
                     "review target coverage and explicitly configure exclusions")
  report = {"functions": profile["class_operations"], "excluded_functions": profile["excluded_functions"],
            "scope": "function calls executed on workload CPUs, including direct calls", "formats": {}}
  if experiment != "e2":
    for phase in ("enter", "exit"):
      event = profile[phase + "_event"]
      system, name = event.split(":")
      try:
        text = (tracefs / "events" / system / name / "format").read_text()
      except FileNotFoundError as error:
        raise ValueError(f"{experiment.upper()} requires target kernel event {event}; "
                         "install the kernel instrumentation externally") from error
      required = {"op"} | ({profile["duration_field"]} if phase == "exit" else set())
      fields = set(re.findall(r"field:[^;]*\b(\w+)(?:\[[^]]*\])?;", text))
      if not required <= fields:
        raise ValueError(f"{event} lacks {sorted(required - fields)}")
      report["formats"][event] = text
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
        if policy == "deadline" and not e1_config.deadline_ready(overhead["e1"], stressed=loaded):
          if scheduler == "deadline":
            raise ValueError("DEADLINE reservations remain unset")
          continue
        yield {"scheduler": policy, "stress": loaded, "repetition": repetition,
               "target_utilization_percent": overhead["stress_utilization_percent"] if loaded else None}


def statistics(config):
  return e1_config.statistics(config["experiments"]["overhead"]["e1"])
