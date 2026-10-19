"""Validate raw bpftrace boundaries and normalize complete calls for offline analysis."""

from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess

from . import common, operation_convert


def record(line, profile):
  words = line.split()
  if len(words) != 9 or words[0] != 'CGS' or words[5] not in ('C', 'K') or words[6] not in ('E', 'X'):
    raise ValueError(f'malformed bpftrace record: {line[:200]}')
  timestamp, cpu, pid, context = map(int, words[1:5])
  if min(timestamp, cpu, pid, context) < 0:
    raise ValueError('negative bpftrace timestamp, CPU, TID or context')
  layer = 'class' if words[5] == 'C' else 'kernel'
  operation = words[7]
  if layer == 'class':
    if operation not in profile['class_operations'].values():
      raise ValueError(f'undeclared class function {operation}')
  else:
    try:
      operation = profile['callbacks'][operation]
    except KeyError as error:
      raise ValueError(f'unknown kernel callback ID {operation}; verify target SCX_OP_IDX mapping') from error
  duration = int(words[8])
  if (layer == 'class' or words[6] == 'E') and duration != 0:
    raise ValueError('unexpected duration on a class boundary or callback entry')
  result = {'timestamp_ns': timestamp, 'cpu': cpu, 'pid': pid, 'irq_context': context,
            'layer': layer, 'phase': 'enter' if words[6] == 'E' else 'exit', 'operation': operation}
  if layer == 'kernel' and result['phase'] == 'exit':
    result['reported_duration_ns'] = duration
    if result['reported_duration_ns'] < 0:
      raise ValueError(f'negative kernel delta_ns: {line.strip()}')
  return result


def prepare_boundaries(directory, capture):
  profile = capture['trace_binding']
  observed, reported = Counter(), Counter()
  ready = ended = 0
  controls = []
  output = directory / 'boundaries.txt'
  with (directory / 'bpftrace.stdout').open() as source, output.open('x') as boundaries:
    for line in source:
      if line.startswith('CGS '):
        event = record(line, profile)
        if event['cpu'] not in capture['utilization_cpus']:
          raise ValueError('bpftrace emitted a CPU outside the declared workload cpuset')
        kind = (0 if event['layer'] == 'class' else 2) + (event['phase'] == 'exit')
        observed[event['cpu'], kind] += 1
        boundaries.write(line)
      elif line.strip() == 'CGS_READY':
        ready += 1
      elif line.strip() == 'CGS_END':
        ended += 1
      elif line.startswith('CGS_CONTROL '):
        controls.append(int(line.split()[1]))
      elif match := re.fullmatch(r'@counts\[(\d+),\s*(\d+)\]:\s*(\d+)\s*', line):
        key = int(match[1]), int(match[2])
        if key in reported:
          raise ValueError('duplicate bpftrace counter')
        reported[key] = int(match[3])
      elif line.strip():
        raise ValueError(f'unexpected bpftrace output: {line[:200]}')
  if ready != 1 or ended != 1 or controls != [1, 0] or observed != +reported:
    raise ValueError(f'bpftrace capture/counter mismatch: ready={ready}, end={ended}, '
                     f'observed={observed}, reported={reported}')
  # probe handlers can be interrupted between timestamping and perf-buffer output
  ordered = directory / 'boundaries.sorted.txt'
  with ordered.open('xb') as stream:
    subprocess.run(['sort', '--stable', '-k3,3n', '-k2,2n', '-T', str(directory), str(output)],
                   check=True, stdout=stream, stderr=subprocess.PIPE, timeout=120,
                   env={**os.environ, 'LC_ALL': 'C'})
  return ordered, {f'{cpu}:{kind}': count for (cpu, kind), count in observed.items()}


def convert(directory, capture):
  directory = Path(directory)
  diagnostics = {'valid': False, 'experiment_validated': False}
  converter = None
  try:
    frozen = common.read_json(directory / 'bpftrace.json')
    if frozen['status'] != 'complete' or frozen['missed_probes'] or frozen['stderr_bytes']:
      raise ValueError('bpftrace capture failed, reported helper/transport errors, or missed probes')
    paths = ('bpftrace.stdout', 'bpftrace.stderr', 'bpftrace.json', 'sched_trace.bt', 'sched_trace_config.h')
    hashes = {name: common.sha256(directory / name) for name in paths}
    ordered, counts = prepare_boundaries(directory, capture)
    profile = capture['trace_binding']
    with (directory / 'operations.jsonl').open('x') as output:
      converter = operation_convert.Converter(profile, capture['experiment'], capture['utilization_cpus'],
                    capture['start_ns'], capture['end_ns'], lambda item: output.write(json.dumps(item) + '\n'))
      with ordered.open() as source:
        for line in source:
          converter.consume(record(line, profile))
      converter.finish()
    if any(common.sha256(directory / name) != value for name, value in hashes.items()):
      raise ValueError('raw bpftrace capture changed during conversion')
    expected = [{'layer': 'class', 'operation': name} for name in profile['class_operations'].values()]
    expected += [{'layer': 'kernel', 'operation': name} for name in profile['callbacks'].values()]
    metadata = {'schema_version': 1, 'producer': 'bpftrace-fentry-adapter',
                'scheduler': capture['case']['scheduler'], 'clock': 'monotonic', 'complete': True,
                'record_count': converter.counts['records'], 'cpus': capture['utilization_cpus'],
                'loss': {'lost_records': 0, 'missed_probes': frozen['missed_probes']},
                'loss_evidence': 'raw records equal BPF counters; clean stderr/END; retained program miss counters',
                'capture_controls': frozen, 'inputs_sha256': hashes, 'trace_binding': profile,
                'statistics': capture['statistics'], 'expected_operations': expected,
                'callback_layer': 'kernel' if profile['callbacks'] else None,
                'timing': 'class: fentry/fexit elapsed; kernel callback: reported delta_ns, boundary time retained; '
                          'inclusive; no interrupt, preemption or probe-cost subtraction'}
    common.write_json(directory / 'operations.metadata.json', metadata)
    diagnostics.update(valid=True, inputs_sha256=hashes, raw_counts=counts)
    ordered.unlink()
    (directory / 'boundaries.txt').unlink()
  except BaseException as error:
    diagnostics['error'] = f'{type(error).__name__}: {error}'
    raise
  finally:
    diagnostics['counts'] = dict(converter.counts) if converter else {}
    common.write_json(directory / 'conversion.json', diagnostics)
