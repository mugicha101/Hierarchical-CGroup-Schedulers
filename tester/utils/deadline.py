"""Explicit DEADLINE reservations and temporary single-CPU cgroup partitions."""

from contextlib import contextmanager
from copy import deepcopy
import ctypes
import uuid

from . import common

RESERVATION_KEYS = ("runtime_ns", "deadline_ns", "period_ns")


def validate_reservation(settings, *, allow_unset=False):
  from .experiment_config import require_keys
  require_keys(settings, RESERVATION_KEYS, "DEADLINE reservation")
  if allow_unset and all(value is None for value in settings.values()):
    return
  if any(type(value) is not int or not 1024 <= value <= 2**63 - 1
         for value in settings.values()):
    raise ValueError("DEADLINE requires explicit integer runtime/deadline/period in nanoseconds")
  if not settings["runtime_ns"] <= settings["deadline_ns"] <= settings["period_ns"]:
    raise ValueError("DEADLINE requires runtime <= deadline <= period")


def options(reservation, *, cyclictest):
  validate_reservation(reservation)
  prefix = "dl" if cyclictest else "sched"
  return [f"--{prefix}-{key.removesuffix('_ns')}={reservation[key]}"
          for key in RESERVATION_KEYS]


class SchedAttr(ctypes.Structure):
  _fields_ = [("size", ctypes.c_uint32), ("policy", ctypes.c_uint32),
              ("flags", ctypes.c_uint64), ("nice", ctypes.c_int32),
              ("priority", ctypes.c_uint32), ("runtime_ns", ctypes.c_uint64),
              ("deadline_ns", ctypes.c_uint64), ("period_ns", ctypes.c_uint64)]


def verify_reservation(tid, expected):
  libc = ctypes.CDLL(None, use_errno=True)
  if not hasattr(libc, "sched_getattr"):
    raise RuntimeError("DEADLINE verification requires libc sched_getattr (glibc 2.41 or newer)")
  libc.sched_getattr.argtypes = [ctypes.c_int, ctypes.POINTER(SchedAttr), ctypes.c_uint, ctypes.c_uint]
  libc.sched_getattr.restype = ctypes.c_int
  attr = SchedAttr(size=ctypes.sizeof(SchedAttr))
  if libc.sched_getattr(tid, ctypes.byref(attr), attr.size, 0):
    raise OSError(ctypes.get_errno(), "read DEADLINE reservation")
  actual = {key: getattr(attr, key) for key in RESERVATION_KEYS}
  if attr.policy != 6 or attr.priority != 0 or actual != expected:
    raise RuntimeError(f"DEADLINE reservation differs for TID {tid}: {actual}")
  return {**actual, "flags": attr.flags}


class Partitions:
  def __init__(self, config, directory, cpus):
    self.config = config
    self.directory = directory
    self.parent = common.workload_cgroup(config)
    self.cpus = set(cpus)
    self.children = {}
    self.original = None
    self.enabled_cpuset = False
    self.changed_partition = False
    self.changed_cpus = False

  def snapshot(self):
    return {name: (self.parent / name).read_text().strip() for name in
            ("cpuset.cpus.partition", "cpuset.cpus", "cpuset.cpus.effective", "cgroup.subtree_control")}

  def start(self):
    self.original = self.snapshot()
    common.write_json(self.directory / "deadline-partitions-before.json", self.original)
    if not self.cpus or not self.cpus <= common.cgroup_cpus(self.parent):
      raise ValueError("DEADLINE partition CPUs must belong to the workload cgroup")
    if (self.parent / "cgroup.procs").read_text().strip() or any(
        path.is_dir() for path in self.parent.iterdir()):
      raise ValueError("DEADLINE requires an empty workload cgroup without existing children")
    kind = self.original["cpuset.cpus.partition"]
    if kind == "member":
      ancestor = self.parent.parent
      parent_kind = "root" if ancestor == common.CGROUP_ROOT else (
          ancestor / "cpuset.cpus.partition").read_text().strip()
      if parent_kind not in ("root", "isolated"):
        raise ValueError("prepare the workload cgroup below a valid partition root for DEADLINE; "
                         "the runner will not reconfigure ancestors")
      kind = parent_kind
      if not self.original["cpuset.cpus"]:
        self.changed_cpus = True
        (self.parent / "cpuset.cpus").write_text(self.original["cpuset.cpus.effective"] + "\n")
      self.changed_partition = True
      (self.parent / "cpuset.cpus.partition").write_text(kind + "\n")
      if (self.parent / "cpuset.cpus.partition").read_text().strip() != kind:
        raise RuntimeError("workload cgroup could not become a valid DEADLINE partition")
    elif kind not in ("root", "isolated"):
      raise ValueError("workload cgroup has an invalid CPU partition")
    if "cpuset" not in self.original["cgroup.subtree_control"].split():
      self.enabled_cpuset = True
      (self.parent / "cgroup.subtree_control").write_text("+cpuset\n")
    prefix = "e1-deadline-" + uuid.uuid4().hex
    for cpu in sorted(self.cpus):
      child = self.parent / f"{prefix}-cpu{cpu}"
      with common.cleanup_interrupts():
        child.mkdir()
        self.children[cpu] = child
      (child / "cpuset.mems").write_text((self.parent / "cpuset.mems.effective").read_text())
      (child / "cpuset.cpus").write_text(f"{cpu}\n")
      (child / "cpuset.cpus.partition").write_text(kind + "\n")
    self.check()
    common.write_json(self.directory / "deadline-partitions-active.json", {
        str(cpu): {"path": str(path), "partition": kind, "cpus": [cpu]}
        for cpu, path in self.children.items()})

  def check(self):
    for cpu, child in self.children.items():
      kind = (child / "cpuset.cpus.partition").read_text().strip()
      if kind not in ("root", "isolated") or common.cgroup_cpus(child) != {cpu}:
        raise RuntimeError(f"DEADLINE single-CPU partition became invalid: {child}")

  def config_for(self, cpu):
    config = deepcopy(self.config)
    config["workload_cgroup"] = str(self.children[cpu])
    return config

  def close(self):
    if self.original is None:
      return
    errors = []
    with common.cleanup_interrupts():
      for child in reversed(tuple(self.children.values())):
        try:
          if (child / "cgroup.procs").read_text().strip():
            raise RuntimeError(f"DEADLINE partition still contains processes: {child}")
          (child / "cpuset.cpus.partition").write_text("member\n")
          child.rmdir()
        except Exception as error:
          errors.append(str(error))
      if not errors:
        try:
          if self.enabled_cpuset:
            (self.parent / "cgroup.subtree_control").write_text("-cpuset\n")
          if self.changed_partition:
            (self.parent / "cpuset.cpus.partition").write_text(
                self.original["cpuset.cpus.partition"] + "\n")
          if self.changed_cpus:
            (self.parent / "cpuset.cpus").write_text(self.original["cpuset.cpus"] + "\n")
          if self.snapshot() != self.original:
            raise RuntimeError("DEADLINE partition controls were not restored")
        except Exception as error:
          errors.append(str(error))
      common.write_json(self.directory / "deadline-partitions-cleanup.json",
                        {"complete": not errors, "errors": errors})
    if errors:
      raise common.CleanupError("; ".join(errors))


@contextmanager
def partitions(config, directory, cpus):
  owned = Partitions(config, directory, cpus)
  try:
    owned.start()
    yield owned
  finally:
    owned.close()
