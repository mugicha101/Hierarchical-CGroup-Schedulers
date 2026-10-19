"""Read target BTF and retain tracer program references through final miss accounting."""

import ctypes
from functools import lru_cache
import json
import os
from pathlib import Path
import platform
import subprocess


@lru_cache(maxsize=1)
def target_types():
  result = subprocess.run(['bpftool', '-j', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux',
                           'format', 'raw'], check=True, capture_output=True, text=True, timeout=30)
  return json.loads(result.stdout)['types']


def structure(name):
  return next(item for item in target_types() if item['kind'] == 'STRUCT' and item.get('name') == name)


def context_expression():
  if platform.machine() != 'x86_64':
    raise ValueError('operation tracing currently requires the verified x86_64 preempt-count layout')
  symbols = {line.split()[-1] for line in Path('/proc/kallsyms').read_text().splitlines()}
  if '__preempt_count' in symbols:
    count = '*(uint32 *)percpu_kaddr("__preempt_count")'
  elif 'pcpu_hot' in symbols:
    members = {m['name'] for m in structure('pcpu_hot')['members']}
    if 'preempt_count' not in members:
      raise ValueError('pcpu_hot lacks the required preempt_count field')
    count = '((struct pcpu_hot *)percpu_kaddr("pcpu_hot"))->preempt_count'
  else:
    raise ValueError('no supported per-CPU preempt_count symbol')
  rt = any(member['name'] == 'softirq_disable_cnt' for member in structure('task_struct')['members'])
  soft = '((struct task_struct *)curtask)->softirq_disable_cnt' if rt else count
  # ignore preemption/BH disable counts; retain hardirq nesting, NMI and serving-softirq
  return f'((({count}) & 0x00ff0000) | (({soft}) & 0x100))'


def callback_ids():
  types = {item['id']: item for item in target_types()}
  result = {}
  for member in structure('sched_ext_ops')['members']:
    pointer = types[member['type_id']]
    if pointer['kind'] == 'PTR' and types.get(pointer['type_id'], {}).get('kind') == 'FUNC_PROTO':
      if member['bits_offset'] % 64:
        raise ValueError('unaligned sched_ext_ops callback slot')
      result[str(member['bits_offset'] // 64)] = member['name']
  return result


class Programs:
  def __init__(self):
    self.fds = {}
    self.library = ctypes.CDLL('libbpf.so.1', use_errno=True)
    self.library.bpf_prog_get_fd_by_id.argtypes = [ctypes.c_uint32]
    self.library.bpf_prog_get_fd_by_id.restype = ctypes.c_int
    self.library.bpf_obj_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_uint32)]
    self.library.bpf_obj_get_info_by_fd.restype = ctypes.c_int
    layout = structure('bpf_prog_info')
    self.size = layout['size']
    self.miss_offset = next(m['bits_offset'] // 8 for m in layout['members']
                            if m['name'] == 'recursion_misses')

  def retain(self, pid):
    for path in Path(f'/proc/{pid}/fdinfo').iterdir():
      try:
        fields = dict(line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)
      except FileNotFoundError:
        continue
      if 'prog_id' not in fields:
        continue
      identity = int(fields['prog_id'])
      if identity not in self.fds:
        fd = self.library.bpf_prog_get_fd_by_id(identity)
        if fd < 0:
          raise OSError(ctypes.get_errno(), f'cannot retain BPF program {identity}')
        self.fds[identity] = fd
    if not self.fds:
      raise ValueError('tracer has no observable BPF program references')

  def snapshot(self):
    result = {}
    for identity, fd in self.fds.items():
      data, size = ctypes.create_string_buffer(self.size), ctypes.c_uint32(self.size)
      if self.library.bpf_obj_get_info_by_fd(fd, data, ctypes.byref(size)):
        raise OSError(ctypes.get_errno(), f'cannot read BPF program {identity} statistics')
      if size.value < self.miss_offset + 8:
        raise ValueError('kernel program info does not expose recursion_misses')
      result[str(identity)] = int.from_bytes(data.raw[self.miss_offset:self.miss_offset + 8], 'little')
    return result

  def close(self):
    for fd in self.fds.values():
      os.close(fd)
    self.fds.clear()
