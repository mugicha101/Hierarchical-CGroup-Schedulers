"""Inspect existing trace.dat events and schemas without changing tracing state."""

from collections import Counter
from pathlib import Path

from . import common, tracing


def inspect(source, output):
  source = Path(source).resolve(strict=True)
  output = Path(output).resolve()
  if source == output:
    raise ValueError("inventory must not overwrite its source trace")
  with output.open("x"):
    pass
  report = {"valid": False, "analysis_only": True, "experiment_validated": False,
            "source": str(source), "events": {}, "cpus": {}}
  events, cpus, last_timestamp = report["events"], Counter(), {}
  try:
    metadata_path = source.with_suffix(source.suffix + ".metadata.json")
    report["metadata_sha256"] = common.sha256(metadata_path)
    report["capture_metadata"] = tracing.capture_metadata(source)
    report["source_sha256"] = common.sha256(source)
    from .trace_helpers import TraceParser, defer_trace_interrupts
    with defer_trace_interrupts() as check_interrupt, TraceParser(source) as parser:
      for message in parser:
        event = message.event
        cpu = int(event.packet.context_field["cpu_id"])
        timestamp = message.default_clock_snapshot.ns_from_origin
        if cpu in last_timestamp and timestamp < last_timestamp[cpu]:
          raise ValueError(f"trace timestamps moved backwards on CPU {cpu}")
        last_timestamp[cpu] = timestamp
        fields = sorted(event.payload_field.keys()) if event.payload_field is not None else []
        item = events.setdefault(event.name, {"count": 0, "payload_fields": fields,
                                 "first_ns": timestamp, "last_ns": timestamp})
        if fields != item["payload_fields"]:
          raise ValueError(f"event payload schema changed: {event.name}")
        item.update(count=item["count"] + 1, first_ns=min(item["first_ns"], timestamp),
                    last_ns=max(item["last_ns"], timestamp))
        cpus[cpu] += 1
        check_interrupt()
    report.update(events=events, cpus=dict(cpus))
    if not events:
      raise ValueError("trace contains no events")
    if common.sha256(source) != report["source_sha256"] or \
        common.sha256(metadata_path) != report["metadata_sha256"]:
      raise ValueError("trace changed during inventory")
    report["valid"] = True
    return report
  except BaseException as error:
    report["error"] = f"{type(error).__name__}: {error}"
    raise
  finally:
    report["cpus"] = dict(cpus)
    common.write_json(output, report)
