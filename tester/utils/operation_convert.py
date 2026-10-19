"""Convert verified tracepoint pairs to complete calls in a declared measurement window."""

from collections import Counter, defaultdict
import json
from pathlib import Path

from . import common, overhead_config, tracing


class Contexts:
  def __init__(self):
    self.handlers = defaultdict(list)
    self.sequence = Counter()

  def update(self, event):
    name, cpu = event['name'], event['cpu']
    if name not in overhead_config.IRQ_EVENTS:
      return False
    kind = 'hard' if 'irq_handler_' in name else 'soft'
    stack = self.handlers[cpu]
    if name.endswith('_entry'):
      self.sequence[cpu] += 1
      stack.append((kind, self.sequence[cpu]))
    elif stack:
      if stack[-1][0] != kind:
        raise ValueError(f'interrupt handler nesting differs on CPU {cpu}')
      stack.pop()
    return True

  def key(self, event):
    flags = event['flags'] & 0x58
    if flags & 0x40:
      raise ValueError('operation in NMI context is unsupported; nesting is not observable')
    handlers = tuple(self.handlers[event['cpu']])
    return f"pid:{event['pid']}/irq-flags:{flags}/handlers:{handlers}"


class Converter:
  def __init__(self, profile, experiment, cpus, start_ns, end_ns, emit):
    self.profile, self.experiment, self.cpus = profile, experiment, set(cpus)
    self.start_ns, self.end_ns, self.emit = start_ns, end_ns, emit
    self.contexts = Contexts()
    self.stacks = defaultdict(list)
    self.sequence, self.counts, self.last = Counter(), Counter(), {}
    if 'class_operations' in profile:
      self.bindings = {}
      return
    layer = 'class' if profile['scope'] == 'sched_class' else 'kernel'
    mapping = {int(key): value for key, value in profile['operations'].items()}
    self.bindings = {profile['enter_event']: ('enter', layer, mapping),
                     profile['exit_event']: ('exit', layer, mapping)}
    if experiment != 'e2':
      callbacks = overhead_config.scx_operations(profile)
      self.bindings.update({overhead_config.SCX_EVENTS[0]: ('enter', 'scx', callbacks),
                            overhead_config.SCX_EVENTS[1]: ('exit', 'scx', callbacks)})

  def consume(self, event):
    cpu, timestamp = event['cpu'], event['timestamp_ns']
    if cpu not in self.cpus:
      return
    if timestamp < self.last.get(cpu, 0):
      raise ValueError(f'trace timestamps moved backwards on CPU {cpu}')
    self.last[cpu] = timestamp
    if 'phase' in event:
      phase, layer, operation = event['phase'], event['layer'], event['operation']
      if event['irq_context'] & 0x00f00000:
        raise ValueError('operation in NMI context is unsupported')
      context = f"pid:{event['pid']}/irq:{event['irq_context']}"
    else:
      if self.contexts.update(event) or event['name'] not in self.bindings:
        return
      phase, layer, mapping = self.bindings[event['name']]
      op = event['fields']['op']
      if op not in mapping:
        raise ValueError(f"unknown operation ID {op} in {event['name']}; update the confirmed binding")
      if layer == 'scx' and event['fields']['sched_cgrp_id'] != 0:
        raise ValueError('E3/E4 expects only the root JLFP scheduler (sched_cgrp_id=0)')
      context = self.contexts.key(event)
      operation = mapping[op]
    stack = self.stacks[cpu, context]
    if phase == 'enter':
      self.sequence[cpu] += 1
      selected = stack[0]['selected'] if stack else self.start_ns <= timestamp < self.end_ns
      frame = {'selected': selected, 'layer': layer, 'operation': operation,
               'timestamp_ns': timestamp, 'call_id': self.sequence[cpu]}
      parent = stack[-1]['call_id'] if stack else None
      stack.append(frame)
      if selected:
        self.write({'phase': phase, 'timestamp_ns': timestamp, 'cpu': cpu, 'context': context,
                    'call_id': frame['call_id'], 'layer': layer, 'operation': operation,
                    'parent_id': parent, 'rq_cpu': None})
      else:
        self.counts['entries_outside_window'] += 1
      return
    if not stack:
      if timestamp >= self.start_ns:
        raise ValueError(f'unmatched exit in or after the window: CPU {cpu}, {layer}/{operation}')
      self.counts['leading_boundary_exits'] += 1
      return
    frame = stack.pop()
    if (frame['layer'], frame['operation']) != (layer, operation):
      raise ValueError(f'operation nesting mismatch on CPU {cpu}: {frame} -> {layer}/{operation}')
    if frame['selected']:
      record = {'phase': phase, 'timestamp_ns': timestamp, 'cpu': cpu, 'context': context,
                'call_id': frame['call_id']}
      if 'reported_duration_ns' in event or ('phase' not in event and layer != 'scx' and self.profile['duration_field']):
        value = event['reported_duration_ns'] if 'phase' in event else event['fields'][self.profile['duration_field']]
        if type(value) is not int or value < 0:
          raise ValueError('kernel operation duration must be nonnegative nanoseconds')
        record['reported_duration_ns'] = value
      self.write(record)

  def write(self, record):
    self.emit(record)
    self.counts['records'] += 1
    self.counts[record['phase']] += 1

  def finish(self):
    unfinished = [frame for stack in self.stacks.values() for frame in stack if frame['selected']]
    if unfinished:
      raise ValueError(f'selected calls are incomplete (including possible CPU migration): {unfinished[:5]}')
    if not self.counts['enter']:
      raise ValueError('no operation entries in the measurement window')
    self.counts['trailing_unselected_entries'] = sum(len(stack) for stack in self.stacks.values())


def irq_flags(context):
  if 'common_flags' in context:
    return int(context['common_flags']) & 0x58
  # the existing ftrace plugin exposes libtraceevent's latency format instead
  latency = str(context['latency'])
  values = {'.': 0, 'h': 8, 'H': 24, 's': 16, 'z': 64, 'Z': 72}
  if len(latency) < 3 or latency[2] not in values:
    raise ValueError(f'unknown ftrace interrupt-context encoding: {latency!r}')
  return values[latency[2]]


def trace_events(path):
  from .trace_helpers import TraceParser, defer_trace_interrupts
  with defer_trace_interrupts() as check_interrupt, TraceParser(path) as parser:
    for message in parser:
      event = message.event
      fields = {}
      for key, value in event.payload_field.items():
        try:
          fields[key] = int(value)
        except (TypeError, ValueError):
          fields[key] = str(value)
      context = event.specific_context_field
      yield {'name': event.name, 'cpu': int(event.packet.context_field['cpu_id']),
             'timestamp_ns': message.default_clock_snapshot.ns_from_origin,
             'pid': int(context['common_pid']), 'flags': irq_flags(context), 'fields': fields}
      check_interrupt()


def convert(directory, capture, *, reader=trace_events):
  directory = Path(directory)
  source = directory / 'trace.dat'
  output = directory / 'operations.jsonl'
  diagnostics = {'valid': False, 'experiment_validated': False,
                 'window': 'root calls entered during the interval, including complete descendants and exits after it',
                 'contexts': 'PID, ftrace hard/soft IRQ flags and explicit IRQ handler nesting; NMI rejected',
                 'rq_cpu': 'unavailable in supplied events; never inferred from execution CPU',
                 'boundary_policy': 'leading exits before interval and unselected boundary calls counted, not measured'}
  converter = None
  try:
    frozen = tracing.capture_metadata(source)
    paths = (source, source.with_suffix('.dat.metadata.json'))
    hashes = {path.name: common.sha256(path) for path in paths}
    profile = capture['trace_binding']
    expected = [{'layer': 'class' if profile['scope'] == 'sched_class' else 'kernel', 'operation': name}
                for name in profile['operations'].values()]
    if capture['experiment'] != 'e2':
      expected += [{'layer': 'scx', 'operation': name} for name in overhead_config.scx_operations(profile).values()]
    with output.open('x') as records:
      converter = Converter(profile, capture['experiment'], capture['utilization_cpus'],
                            capture['start_ns'], capture['end_ns'],
                            lambda record: records.write(json.dumps(record) + '\n'))
      for event in reader(source):
        converter.consume(event)
      converter.finish()
    if any(common.sha256(directory / name) != digest for name, digest in hashes.items()):
      raise ValueError('raw trace or loss metadata changed during conversion')
    metadata = {'schema_version': 1, 'producer': 'kernel-tracepoint-adapter',
                'scheduler': capture['case']['scheduler'], 'clock': 'monotonic', 'complete': True,
                'record_count': converter.counts['records'], 'cpus': capture['utilization_cpus'],
                'loss': {'lost_records': 0, 'missed_probes': 0},
                'loss_evidence': 'direct static tracepoints; frozen per-CPU counters and parser loss messages checked',
                'capture_controls': frozen, 'inputs_sha256': hashes, 'trace_binding': profile,
                'statistics': capture['statistics'], 'expected_operations': expected,
                'timing': 'outer: kernel delta_ns when configured, otherwise boundary elapsed time; '
                          'SCX: boundary elapsed time; inclusive, no interrupt or emission-cost subtraction'}
    common.write_json(directory / 'operations.metadata.json', metadata)
    diagnostics.update(valid=True, inputs_sha256=hashes)
    return diagnostics
  except BaseException as error:
    diagnostics['error'] = f'{type(error).__name__}: {error}'
    raise
  finally:
    diagnostics['counts'] = dict(converter.counts) if converter else {}
    common.write_json(directory / 'conversion.json', diagnostics)
