"""Private recording and offline capture-integrity checks."""

from collections import Counter
import json
from pathlib import Path

from .common import CleanupError, write_json


class Recording:
  def __init__(self, directory, events, timeout):
    self.path = Path(directory) / "trace.dat"
    self.events = tuple(events)
    self.timeout = timeout
    self.session = None

  def start(self):
    if not self.events:
      return
    if any(event.startswith("scxtp:") for event in self.events) and \
        not Path("/sys/kernel/btf/scxtp").exists():
      raise RuntimeError("load the matching scxtp module externally before custom tracing")
    from .trace_helpers import TraceSession
    self.session = TraceSession(events=self.events, timeout=self.timeout, manage_schedulers=False)
    self.session.start_trace(self.path)

  def check(self):
    if self.session is not None and (self.session._trace is None or
                                    self.session._trace.poll() is not None):
      raise RuntimeError("private recorder exited during the workload")

  def close(self):
    if self.session is not None:
      session, self.session = self.session, None
      try:
        session.close()
        if session.cleanup_error is not None:
          raise session.cleanup_error
      except Exception as error:
        raise CleanupError("private recorder cleanup failed") from error


def summarize(path, required_events=()):
  from .trace_helpers import TraceParser, defer_trace_interrupts
  path = Path(path)
  report = {"valid": False, "events": {}, "cpus": {}, "error": None}
  events, cpus = Counter(), Counter()
  try:
    metadata = json.loads(path.with_suffix(path.suffix + ".metadata.json").read_text())
    if metadata["errors"] or not metadata["cpu_stats"]:
      raise ValueError("missing trace controls or per-CPU loss statistics")
    if metadata["controls"].get("tracing_on") != "0" or \
        "[mono]" not in metadata["controls"].get("trace_clock", ""):
      raise ValueError("trace metadata requires frozen buffers and the monotonic clock")
    for text in metadata["cpu_stats"].values():
      counters = {}
      for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in ("overrun", "commit overrun", "dropped events"):
          counters[key.strip()] = int(value.strip())
      if len(counters) != 3:
        raise ValueError("trace loss counters are incomplete")
      if any(counters.values()):
        raise ValueError(f"trace buffer lost events: {counters}")
    with defer_trace_interrupts() as check_interrupt, TraceParser(path) as parser:
      for message in parser:
        events[message.event.name] += 1
        cpus[int(message.event.packet.context_field["cpu_id"])] += 1
        check_interrupt()
    missing = set(required_events) - events.keys()
    if missing:
      raise ValueError(f"required trace events are missing: {sorted(missing)}")
    report["valid"] = True
  except BaseException as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise
  finally:
    report.update(events=dict(events), cpus=dict(cpus))
    write_json(path.with_suffix(path.suffix + ".analysis.json"), report)
  return report
