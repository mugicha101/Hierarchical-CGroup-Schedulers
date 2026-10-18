"""Describe overhead measurements and the target validation still required."""


def plan(settings):
  return {
      "status": "E1 implemented; E2-E4 draft runners; target validation pending",
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
          "placement": "cyclictest on CPU 9; stress-ng pinned per workload CPU",
          "status": "draft; confirmed class tracepoint bindings and target validation pending",
      },
      "e3": {
          "measurement": "JLFP callback versus enclosing kernel operation latency",
          "schedulers": ["jlfp"],
          "placement": "same pinned workload as E2",
          "status": "draft; kernel op IDs/scope and target validation pending",
          "tick_emission_calibration": "pending by request; no cost subtraction",
      },
      "e4": {
          "measurement": "JLFP operation latency with migratable workers",
          "schedulers": ["jlfp"],
          "placement": "cyclictest and stress-ng may migrate throughout workload cpuset",
          "status": "draft; kernel op IDs/scope and target validation pending",
          "tick_emission_calibration": "pending by request; no cost subtraction",
      },
      "deadline_placement": "E1 only; temporary single-CPU partitions below the existing workload cgroup",
  }
