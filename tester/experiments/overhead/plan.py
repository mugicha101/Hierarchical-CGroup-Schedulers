"""Describe overhead experiments and distinguish analysis from pending captures."""


def plan(settings):
  return {
      "status": "E1 implemented; E2-E4 pending methodology and tracing prerequisites",
      "settings": settings,
      "e1": {
          "measurement": "end-to-end cyclictest scheduling latency",
          "schedulers": ["other", "fifo", "rr", "deadline", "qmap", "simple", "jlfp"],
          "deadline": "cases enabled only when their explicit reservations are configured",
          "status": "implemented; full live matrix validation pending",
          "load_conditions": ["no stress-ng", f"{settings['stress_utilization_percent']}% system utilization"],
      },
      "e2": {
          "measurement": "scheduling class operation latency",
          "schedulers": ["other", "fifo", "qmap", "jlfp"],
          "status": "deferred: required class-operation tracepoints are not installed",
      },
      "e3": {
          "measurement": "JLFP callback versus class operation latency",
          "schedulers": ["jlfp"],
      },
      "e4": {
          "measurement": "JLFP operation latency with migratable workers",
          "schedulers": ["jlfp"],
      },
      "deadline_placement": "temporary single-CPU partitions below the existing workload cgroup",
  }
