"""Describe upcoming overhead experiments; no benchmark workloads are implemented."""


def plan(settings):
  return {
      "status": "not implemented; methodology and tracing prerequisites pending",
      "settings": settings,
      "e1": {
          "measurement": "end-to-end cyclictest scheduling latency",
          "schedulers": ["other", "fifo", "rr", "qmap", "simple", "jlfp"],
      },
      "e2": {
          "measurement": "scheduling class operation latency",
          "schedulers": ["other", "fifo", "qmap", "jlfp"],
      },
      "e3": {
          "measurement": "JLFP callback versus class operation latency",
          "schedulers": ["jlfp"],
      },
      "e4": {
          "measurement": "JLFP operation latency with migratable workers",
          "schedulers": ["jlfp"],
      },
      "deferred_policies": {"deadline": "pending methodology"},
  }
