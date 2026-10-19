"""Own one bounded bpftrace recorder without changing global ftrace controls."""

import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

from . import bpf_capture_info, common


class Recording:
  def __init__(self, directory, profile, cpus, settings, timeout):
    self.directory, self.profile = Path(directory), profile
    self.cpus, self.settings, self.timeout = sorted(cpus), settings, timeout
    self.events = tuple(profile['class_operations'].values())
    self.process = self.programs = None
    self.streams = []
    self.closed = False
    self.report = {'status': 'not-started', 'kernel': os.uname().release,
                   'profile': profile, 'cpus': self.cpus,
                   'scope': 'executing workload CPUs only; remote waker work outside them excluded',
                   'context': 'current TID, CPU and x86 hardirq nesting/serving-softirq state; NMI rejected',
                   'timing': 'inclusive; probe handlers execute on measured CPUs',
                   'buffer_pages': settings['buffer_pages'], 'drain_s': settings['drain_s']}

  def prepare(self):
    self.directory.mkdir(parents=True, exist_ok=True)
    functions = list(self.profile['class_operations'].values())
    values = {'CLASS_ENTRY_PROBES': ','.join('fentry:vmlinux:' + name for name in functions),
              'CLASS_EXIT_PROBES': ','.join('fexit:vmlinux:' + name for name in functions),
              'CPU_ALLOWED': '(' + ' || '.join(f'cpu == {cpu}' for cpu in self.cpus) + ')',
              'IRQ_CONTEXT': self.profile['context_expression'], 'CONTROL_PID': str(os.getpid())}
    if self.profile['callbacks']:
      values.update(SCX_CALLBACKS='1', SCX_ENTRY_PROBE='tracepoint:' + self.profile['enter_event'],
                    SCX_EXIT_PROBE='tracepoint:' + self.profile['exit_event'],
                    SCX_DURATION='args.' + self.profile['duration_field'])
    header = ''.join(f'#define {name} {value}\n' for name, value in values.items())
    (self.directory / 'sched_trace_config.h').write_text(header)
    template = (common.REPO / 'tester/sched_trace.bt').read_text()
    text = template.replace('#include "sched_trace_config.h"', '')
    before, callbacks = text.split('#ifdef SCX_CALLBACKS\n')
    body, after = callbacks.split('#endif\n')
    text = before + (body if self.profile['callbacks'] else '') + after
    for name, value in values.items():
      text = re.sub(r'\b' + name + r'\b', lambda _: value, text)
    (self.directory / 'sched_trace.bt').write_text(text)
    binary = shutil.which('bpftrace')
    if binary is None:
      raise FileNotFoundError('bpftrace is required for E2-E4')
    version = subprocess.run([binary, '--version'], capture_output=True, text=True,
                             check=True, timeout=self.timeout)
    self.report.update(binary=binary, version=version.stdout.strip(), binary_sha256=common.sha256(binary),
                       script_sha256=common.sha256(self.directory / 'sched_trace.bt'),
                       template_sha256=common.sha256(common.REPO / 'tester/sched_trace.bt'),
                       btf_sha256=common.sha256('/sys/kernel/btf/vmlinux'))
    return [binary, '-q', '-k', '-B', 'line', str(self.directory / 'sched_trace.bt')]

  def start(self):
    try:
      command = self.prepare()
      self.report.update(status='starting', command=command)
      common.write_json(self.directory / 'bpftrace.json', self.report)
      self.streams = [(self.directory / name).open('xb') for name in ('bpftrace.stdout', 'bpftrace.stderr')]
      environment = {**os.environ, 'BPFTRACE_PERF_RB_PAGES': str(self.settings['buffer_pages'])}
      self.process = subprocess.Popen(command, stdout=self.streams[0], stderr=self.streams[1],
                                      env=environment, start_new_session=True)
      self.programs = bpf_capture_info.Programs()
      deadline = time.monotonic() + self.timeout
      with (self.directory / 'bpftrace.stdout').open() as output:
        while time.monotonic() < deadline:
          self.check()
          if output.readline().strip() == 'CGS_READY':
            self.programs.retain(self.process.pid)
            expected = 2 * len(self.profile['class_operations']) + 3 + 2 * bool(self.profile['callbacks'])
            if len(self.programs.fds) != expected:
              raise ValueError(f'expected {expected} tracer programs, found {len(self.programs.fds)}')
            self.report.update(status='recording', initial_misses=self.programs.snapshot())
            os.getpgid(1)
            while time.monotonic() < deadline:
              self.check()
              if output.readline().strip() == 'CGS_CONTROL 1':
                self.control_offset = output.tell()
                break
              time.sleep(.01)
            else:
              raise TimeoutError('bpftrace collection gate did not acknowledge enable')
            common.write_json(self.directory / 'bpftrace.json', self.report)
            return
          time.sleep(.02)
      raise TimeoutError('bpftrace did not become ready; see bpftrace.stderr')
    except BaseException as error:
      self.report.update(status='failed', error=f'{type(error).__name__}: {error}')
      self.close()
      raise

  def check(self):
    if self.process is not None and self.process.poll() is not None:
      raise RuntimeError('bpftrace exited before capture finished; see bpftrace.stderr')
    error = self.directory / 'bpftrace.stderr'
    if error.exists() and error.stat().st_size:
      raise RuntimeError('bpftrace reported a helper, attachment or transport error; see bpftrace.stderr')

  def close(self):
    if self.closed:
      return
    self.closed = True
    try:
      if self.process is not None:
        if self.process.poll() is None:
          time.sleep(self.settings['drain_s'])
          os.getpgid(0)
          deadline = time.monotonic() + self.timeout
          acknowledged = False
          with (self.directory / 'bpftrace.stdout').open() as output:
            output.seek(getattr(self, 'control_offset', 0))
            while time.monotonic() < deadline and self.process.poll() is None:
              line = output.readline()
              if line.strip() == 'CGS_CONTROL 0':
                acknowledged = True
                break
              if not line:
                time.sleep(.01)
          self.report['stop_acknowledged'] = acknowledged
          # allow every CPU's perf buffer to drain, including CPUs other than the controller
          previous, quiet = -1, time.monotonic()
          while acknowledged and time.monotonic() < deadline and self.process.poll() is None:
            size = (self.directory / 'bpftrace.stdout').stat().st_size
            if size != previous:
              previous, quiet = size, time.monotonic()
            elif time.monotonic() - quiet >= .3:
              break
            time.sleep(.02)
          os.killpg(self.process.pid, signal.SIGINT)
        try:
          self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
          os.killpg(self.process.pid, signal.SIGKILL)
          self.process.wait(timeout=self.timeout)
          raise common.CleanupError('bpftrace required forced termination; capture is invalid')
        self.report['return_code'] = self.process.returncode
        misses = self.programs.snapshot() if self.programs and self.programs.fds else None
        self.report.update(final_misses=misses, missed_probes=sum(misses.values()) if misses else None,
                           stderr_bytes=(self.directory / 'bpftrace.stderr').stat().st_size)
        if self.process.returncode or misses is None or any(misses.values()) or self.report['stderr_bytes'] or \
            not self.report.get('stop_acknowledged'):
          self.report.update(status='failed', error='bpftrace failed or has missing records/probes; see stderr and counters')
        elif 'error' not in self.report:
          self.report['status'] = 'complete'
    except BaseException as error:
      self.report.update(status='failed', error=f'{type(error).__name__}: {error}')
      raise
    finally:
      if self.programs:
        self.programs.close()
      for stream in self.streams:
        stream.close()
      common.write_json(self.directory / 'bpftrace.json', self.report)
