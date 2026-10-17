"""Read the producer-neutral operation trace format; never infer missing boundaries."""

import json

LAYERS = ("class", "scx")
COMMON_FIELDS = {"phase", "timestamp_ns", "cpu", "context", "call_id"}
ENTRY_FIELDS = {"layer", "operation", "parent_id", "rq_cpu"}


def integer(value, name, *, minimum=0):
  if type(value) is not int or not minimum <= value <= 2**64 - 1:
    raise ValueError(f"{name} must be an integer in [{minimum}, 2^64-1]")
  return value


def text(value, name):
  if not isinstance(value, str) or not value.strip():
    raise ValueError(f"{name} must be a nonempty string")
  return value


def operation(value):
  if not isinstance(value, dict) or set(value) != {"layer", "operation"} or value["layer"] not in LAYERS:
    raise ValueError("expected operation must contain layer (class/scx) and operation")
  return value["layer"], text(value["operation"], "operation")


def validate_metadata(metadata):
  if not isinstance(metadata, dict):
    raise ValueError("operation metadata must be a JSON object")
  if type(metadata.get("schema_version")) is not int or metadata["schema_version"] != 1:
    raise ValueError("operation trace schema_version must be 1")
  if metadata.get("clock") != "monotonic" or metadata.get("complete") is not True:
    raise ValueError("operation trace requires a completed capture and monotonic nanosecond clock")
  integer(metadata["record_count"], "record_count")
  text(metadata["scheduler"], "scheduler")
  text(metadata["producer"], "producer")
  cpus = metadata["cpus"]
  if not isinstance(cpus, list) or not cpus or len(cpus) != len(set(cpus)):
    raise ValueError("cpus must be a nonempty list without duplicates")
  for cpu in cpus:
    integer(cpu, "CPU")
  operations = metadata["expected_operations"]
  if not isinstance(operations, list):
    raise ValueError("expected_operations must be a list")
  expected = [operation(value) for value in operations]
  if not any(layer == "class" for layer, _ in expected) or len(expected) != len(set(expected)):
    raise ValueError("declare distinct expected operations, including at least one class operation")
  loss = metadata["loss"]
  if not isinstance(loss, dict) or set(loss) != {"lost_records", "missed_probes"}:
    raise ValueError("loss must declare lost_records and missed_probes")
  for name, value in loss.items():
    if integer(value, name):
      raise ValueError(f"operation capture is incomplete: {name}={value}")
  return set(expected)


def validate_record(record, cpus, expected):
  if not isinstance(record, dict) or record.get("phase") not in ("enter", "exit"):
    raise ValueError("operation record phase must be enter or exit")
  keys = COMMON_FIELDS | ENTRY_FIELDS if record["phase"] == "enter" else COMMON_FIELDS
  if set(record) != keys:
    raise ValueError(f"{record['phase']} record must contain {sorted(keys)}")
  integer(record["timestamp_ns"], "timestamp_ns")
  integer(record["cpu"], "CPU")
  if record["cpu"] not in cpus:
    raise ValueError("record CPU is absent from capture metadata")
  text(record["context"], "execution context")
  integer(record["call_id"], "call_id", minimum=1)
  if record["phase"] == "enter":
    if (record["layer"], record["operation"]) not in expected:
      raise ValueError("record operation is absent from capture metadata")
    for name in ("parent_id", "rq_cpu"):
      if record[name] is not None:
        integer(record[name], name, minimum=1 if name == "parent_id" else 0)
  return record


def read_records(path, metadata, expected):
  with path.open() as source:
    for line_number, line in enumerate(source, 1):
      try:
        yield validate_record(json.loads(line), metadata["cpus"], expected)
      except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"operation record line {line_number}: {error}") from error
