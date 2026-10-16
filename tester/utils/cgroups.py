"""Worker cgroup placement, CPU selection and scheduler shard validation."""

import ctypes
import ctypes.util
import json
import os
import struct

from .common import CGROUP_ROOT

SHARD_SIZE = 4


def existing_test_cgroup(relative_to):
  path = (CGROUP_ROOT / relative_to).resolve(strict=True)
  if not path.is_relative_to(CGROUP_ROOT) or not (path / "cgroup.procs").is_file():
    raise ValueError(f"Not a cgroup under {CGROUP_ROOT}: {path}")
  return path


def parse_cpu_list(value):
  cpus = set()
  for item in value.strip().split(","):
    bounds = item.split("-")
    if len(bounds) not in (1, 2) or any(not bound.isdecimal() for bound in bounds):
      raise ValueError(f"Invalid CPU list: {value!r}")
    first, last = int(bounds[0]), int(bounds[-1])
    if first > last:
      raise ValueError(f"Invalid CPU range: {item}")
    cpus.update(range(first, last + 1))
  return cpus


def cgroup_cpu_set(cgroup):
  return parse_cpu_list((cgroup / "cpuset.cpus.effective").read_text())


def scheduler_shards():
  library = ctypes.util.find_library("bpf")
  if library is None:
    raise RuntimeError("libbpf is required to check shard alignment")
  bpf = ctypes.CDLL(library, use_errno=True)
  bpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  bpf.bpf_obj_get.restype = ctypes.c_int
  bpf.bpf_obj_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
  bpf.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
  fd = bpf.bpf_obj_get(b"/sys/fs/bpf/scx/topo")
  if fd < 0:
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error), "open scheduler topology")
  try:
    # the map info prefix contains type, id, key size, and value size
    info = (ctypes.c_uint32 * 4)()
    size = ctypes.c_uint32(ctypes.sizeof(info))
    if bpf.bpf_obj_get_info_by_fd(fd, ctypes.byref(info), ctypes.byref(size)) < 0:
      error = ctypes.get_errno()
      raise OSError(error, os.strerror(error), "read topology map info")
    if info[2] != 4 or info[3] < 20:
      raise RuntimeError("Unexpected scheduler topology map layout")
    value = ctypes.create_string_buffer(info[3])
    key = ctypes.c_uint32(0)
    if bpf.bpf_map_lookup_elem(fd, ctypes.byref(key), value) < 0:
      error = ctypes.get_errno()
      raise OSError(error, os.strerror(error), "read scheduler topology")
    nr_cids, nr_shards = struct.unpack_from("=II", value)
    if not nr_cids or nr_cids > (len(value) - 20) // 20 or not nr_shards:
      raise RuntimeError("Invalid scheduler topology")
    shards = {}
    for cid in range(nr_cids):
      cpu, shard = struct.unpack_from("=Ii", value, 20 + cid * 20)
      if not 0 <= shard < nr_shards:
        raise RuntimeError("Invalid scheduler shard index")
      shards.setdefault(shard, set()).add(cpu)
    return shards
  finally:
    os.close(fd)


def check_cgroup_shards(cgroup):
  cpus = cgroup_cpu_set(cgroup)
  shards = scheduler_shards()
  if cpus - set().union(*shards.values()):
    raise ValueError(f"Cgroup {cgroup} includes CPUs outside the scheduler topology")
  for shard, members in shards.items():
    if cpus & members and not members <= cpus:
      raise ValueError(f"Cgroup {cgroup} is not shard aligned: shard {shard} has CPUs "
                       f"{sorted(members)}, missing {sorted(members - cpus)}")
  return {"path": str(cgroup), "cpus": sorted(cpus),
          "shards": [shard for shard, members in shards.items() if members <= cpus]}


def load_relative_config(session, output, cgroup, settings, *, check_shards=True, destination=None):
  state = check_cgroup_shards(cgroup) if check_shards else {
      "path": str(cgroup), "cpus": sorted(cgroup_cpu_set(cgroup))}
  config = output / "workload_config.json"
  config.write_text(json.dumps(settings, indent=2) + "\n")
  if destination is not None and destination != cgroup:
    base_config = output / "workload_base_config.json"
    base_config.write_text(json.dumps({"policy": "none"}) + "\n")
    session.load_config(base_config, relative_to=cgroup, existing=True)
  target = destination or cgroup
  session.load_config(config, relative_to=target, existing=target.exists())
  return state


def select_test_cpus(cpus=None, *, relative_to):
  cgroup = existing_test_cgroup(relative_to)
  available = cgroup_cpu_set(cgroup)
  selected = set(cpus) if cpus is not None else available
  if not selected or not selected <= available:
    raise ValueError("worker CPUs must be nonempty and available in the configured cgroup")
  return selected
