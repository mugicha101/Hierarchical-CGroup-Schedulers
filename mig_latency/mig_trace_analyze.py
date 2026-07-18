# program to measure latency of migrations between each CPU pair
# this only measures the time the migration takes, not the time it takes to run the task on the destination CPU
# thus scheduling logic should have negligible impact
# latency is measured by time between sched_migrate_task (kernel initiates move) and next sched_switch on CPU (migration work finished)

import re
import sys
from collections import defaultdict
from decimal import Decimal
import statistics as stats

def parse_trace(target="mig_program"):
  with open("mig_program_output.txt", "r") as f:
    mig_program_output = ''.join(f.readlines())
  match = re.search(r'^mig\sseq:\s(?P<seq>.*)$', mig_program_output, re.MULTILINE)
  if not match:
    raise ValueError(f"mig_program_output.txt does not contain migration sequence")
  
  exp_mig_seq = [int(x) for x in match.group('seq').strip().split()]
  
  with open("trace_report.txt", "r") as f:
    lines = f.readlines()
  
  num_cpus = int(lines[0].split('=')[1])
  
  line_rg = re.compile(r'^\s*(?P<comm>([^\s\[]+(\s+[^\s\[]+)*))\-(?P<pid>\d+)\s+\[(?P<cpu>(\S+))\]\s+(?P<time>\d+(\.\d*)?)\:\s+(?P<event>\S+)\:(?P<details>.*)$')
  switch_rg = re.compile(r'^\s*(?P<old_comm>.+)\:(?P<old_pid>\d+)\s+\[(?P<old_prio>\d+)\].*==>\s+(?P<new_comm>.+)\:(?P<new_pid>\d+)\s+\[(?P<new_prio>\d+)\].*$')
  mig_kvp_rg = re.compile(r'\s*(?P<key>\S+)=(?P<value>[^=]+)(\s+|\s*$)')
  
  cpu_active_migs = [None] * num_cpus
  num_migs = 0
  mig_seq = []
  
  mig_latency_samples = [[[] for _ in range(num_cpus)] for _ in range(num_cpus)]
  
  def record_mig(src_cpu, dest_cpu, start_time, end_time):
    nonlocal num_migs, mig_seq, mig_latency_samples
    num_migs += 1
    if len(mig_seq) == 0:
      mig_seq += [src_cpu]
    else:
      assert mig_seq[-1] == src_cpu, f"Migration source CPU {src_cpu} does not match last recorded CPU {mig_seq[-1]}"
    mig_seq += [dest_cpu]
    latency = int((end_time - start_time) * 1e9)
    mig_latency_samples[src_cpu][dest_cpu].append(latency)
  
  # extract basic info (enough to sort by time)
  entries = []
  for line in lines[1:]:
    match = line_rg.match(line)
    if not match:
      raise ValueError(f"Line does not match expected format: {line}")
    
    cpu = int(match.group('cpu'))
    time = float(match.group('time'))
    event = match.group('event')
    details = match.group('details')
    entries.append((cpu, time, event, details))
  entries.sort(key=lambda x: x[1])
    
  for e in entries:
    cpu, time, event, details = e
    if event == 'sched_migrate_task':
      mig_fields = {}
      for kv_match in mig_kvp_rg.finditer(details):
        key = kv_match.group('key')
        value = kv_match.group('value')
        mig_fields[key] = value
      if mig_fields.get('comm', None) != target:
        continue
      
      assert 'orig_cpu' in mig_fields and 'dest_cpu' in mig_fields, f"Migration fields missing orig_cpu or dest_cpu: {mig_fields}"
      mig_fields['orig_cpu'] = int(mig_fields['orig_cpu'])
      mig_fields['dest_cpu'] = int(mig_fields['dest_cpu'])
      
      assert cpu_active_migs[cpu] is None, f"CPU {cpu} already has an active migration: {cpu_active_migs[cpu]}"
      mig_fields['time'] = time
      cpu_active_migs[cpu] = mig_fields
      
    elif event == 'sched_switch':
      if cpu_active_migs[cpu] is None:
        continue
      
      switch_match = switch_rg.match(details)
      if not switch_match:
        raise ValueError(f"Switch event details do not match expected format: {details}")
      
      old_comm = switch_match.group('old_comm')
      old_pid = switch_match.group('old_pid')
      old_prio = int(switch_match.group('old_prio'))
      new_comm = switch_match.group('new_comm')
      new_pid = switch_match.group('new_pid')
      new_prio = int(switch_match.group('new_prio'))
      assert old_comm.startswith(f"migration/{cpu}"), f"Old comm does not match expected migration thread for CPU {cpu}: {old_comm}"
      
      record_mig(cpu_active_migs[cpu]['orig_cpu'], cpu_active_migs[cpu]['dest_cpu'], cpu_active_migs[cpu]['time'], time)
      
      cpu_active_migs[cpu] = None
    else:
      raise ValueError(f"Unexpected event type: {event}")
    
  # ensure sequence matches mig_program's sequence of migrations
  # since mig_program can migrate before first cpumask is set, check suffix
  assert len(mig_seq) >= len(exp_mig_seq), f"Migration sequence is shorter than expected sequence:\nexp:{exp_mig_seq}\ngot:{mig_seq}"
  assert mig_seq[-len(exp_mig_seq):] == exp_mig_seq, f"Expected migration sequence is not a suffix of the actual sequence:\nexpected:{exp_mig_seq}\nactual:{mig_seq}"

  for src_cpu in range(num_cpus):
    for dest_cpu in range(num_cpus):
      if src_cpu == dest_cpu:
        continue
      samples = mig_latency_samples[src_cpu][dest_cpu]
      count = len(samples)
      mean = stats.mean(samples) if count > 0 else -1
      median = stats.median(samples) if count > 0 else -1
      stdev = stats.stdev(samples) if count > 1 else -1
      minv = min(samples) if count > 0 else -1
      maxv = max(samples) if count > 0 else -1
      print(f"CPU {src_cpu}=>{dest_cpu}: cnt={count} avg={mean:.3f}ns med={median:.1f}ns std={stdev:.3f}ns min={minv:.0f}ns max={maxv:.0f}ns")

if __name__ == "__main__":
  parse_trace(sys.argv[1])
