"""Pair nested calls by execution CPU/context and attribute SCX intervals to class calls."""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Call:
  entry: dict
  callbacks: list = field(default_factory=list)


def union_duration(intervals):
  total, covered_until = 0, 0
  for start, stop in sorted(intervals):
    total += max(0, stop - max(start, covered_until))
    covered_until = max(stop, covered_until)
  return total


class Pairing:
  def __init__(self):
    self.stacks = {}
    self.last_timestamp = {}
    self.last_call_id = {}
    self.counts = Counter()

  def consume(self, record):
    cpu, context = record["cpu"], record["context"]
    timestamp = record["timestamp_ns"]
    if timestamp < self.last_timestamp.get(cpu, 0):
      raise ValueError(f"timestamps moved backwards on CPU {cpu}; records must already be ordered per CPU")
    self.last_timestamp[cpu] = timestamp
    self.counts[record["phase"]] += 1
    stack = self.stacks.setdefault((cpu, context), [])
    if record["phase"] == "enter":
      if record["call_id"] <= self.last_call_id.get(cpu, 0):
        raise ValueError(f"entry call_id must increase on CPU {cpu}")
      self.last_call_id[cpu] = record["call_id"]
      parent = stack[-1].entry["call_id"] if stack else None
      if record["parent_id"] != parent:
        raise ValueError(f"parent_id differs from the active call on CPU {cpu}, context {context}")
      stack.append(Call(record))
      return None
    if not stack or stack[-1].entry["call_id"] != record["call_id"]:
      raise ValueError(f"unmatched or out-of-order exit on CPU {cpu}, context {context}, call {record['call_id']}")
    call = stack.pop()
    boundary_duration = timestamp - call.entry["timestamp_ns"]
    duration = record.get("reported_duration_ns", boundary_duration)
    result = {**call.entry, "end_ns": timestamp, "duration_ns": duration}
    if "reported_duration_ns" in record:
      result.update(boundary_duration_ns=boundary_duration, reported_duration_ns=duration)
    result.pop("phase")
    if call.entry["layer"] == "scx":
      parents = [frame for frame in stack if frame.entry["layer"] in ("class", "kernel")]
      for parent in parents:
        parent.callbacks.append((call.entry["timestamp_ns"], timestamp))
      result["class_call_id"] = (parents[-1].entry["call_id"]
                                 if parents and parents[-1].entry["layer"] == "class" else None)
      result["kernel_call_id"] = (parents[-1].entry["call_id"]
                                  if parents and parents[-1].entry["layer"] == "kernel" else None)
      result["outer_layer"] = parents[-1].entry["layer"] if parents else None
      self.counts["scx_without_class"] += not parents
    else:
      union = union_duration(call.callbacks)
      result.update(observed_scx_calls=len(call.callbacks),
                    observed_scx_sum_ns=sum(end - start for start, end in call.callbacks),
                    observed_scx_union_ns=union, observed_scx_percent=100 * union / duration if duration else None)
      self.counts[call.entry["layer"] + "_calls"] += 1
      self.counts[call.entry["layer"] + "_without_observed_scx"] += not call.callbacks
    self.counts["paired_calls"] += 1
    return result

  def finish(self):
    if self.open_calls():
      raise ValueError("capture ended with unmatched operation entries")
    if not self.counts["class_calls"] + self.counts["kernel_calls"]:
      raise ValueError("no complete outer operation calls were captured")

  def open_calls(self):
    return [frame.entry for stack in self.stacks.values() for frame in stack]
