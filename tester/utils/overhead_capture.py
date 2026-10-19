"""Capture one E2-E4 case using the shared cyclictest and stress-ng lifecycle."""

from contextlib import ExitStack
import os

from . import common, cyclictest, e1_capture, e1_config, e1_measurement, e1_workloads
from . import bpftrace_capture, bpftrace_convert, deadline as deadline_support
from . import lifecycle, operation_analysis, overhead_config


def capture(config, directory, experiment, case, cyclic_binary, manifest, stress_binary, profile):
  settings = config['experiments']['overhead']['e1']
  cpu = config['experiments']['overhead']['cyclictest_cpu']
  scheduler = case['scheduler']
  migratable = experiment == 'e4'
  primary = e1_config.policy(settings, scheduler, 'cyclictest')
  if manifest is not None:
    manifest = e1_capture.scheduler_manifest(manifest, settings, scheduler, trace='off')
  cpus = common.cgroup_cpus(common.workload_cgroup(config))
  if cpus != set(range(8, 16)):
    raise ValueError('E2-E4 requires the prepared workload cpuset to be CPUs 8-15')
  run = {'experiment': experiment, 'case': case, 'measurement': False,
         'experiment_validated': False, 'target_validation': 'pending',
         'settings': settings, 'statistics': overhead_config.statistics(config),
         'trace_binding': profile, 'trace_events': [profile['enter_event'], profile['exit_event']]
             if experiment != 'e2' else [],
         'scheduler_build': manifest, 'utilization_cpus': sorted(cpus),
         'worker_affinity': sorted(cpus) if migratable else [cpu],
         'placement': 'migratable within workload cpuset' if migratable else 'pinned per CPU',
         'tick_emission_calibration': 'pending; no calibration or cost subtraction',
         'samples_include_startup': True, 'kernel_timer_support': 'external prerequisite'}
  os.mkfifo(directory / 'cyclictest.gate', 0o600)
  try:
    e1_capture.check_tracing(directory)
    with ExitStack() as resources:
      partitions = None
      measurement_config = config
      if scheduler == 'deadline':
        partitions = resources.enter_context(deadline_support.partitions(
            config, directory, cpus if case['stress'] else {cpu}))
        measurement_config = partitions.config_for(cpu)
      run['cpu_dma_latency'] = resources.enter_context(
          cyclictest.temporary_cpu_dma_latency(settings['cpu_dma_latency_us']))
      recorder = bpftrace_capture.Recording(directory, profile, cpus,
          config['experiments']['overhead']['operation_tracing'], config['process_timeout_s'])
      session = resources.enter_context(lifecycle.Session(measurement_config, directory, manifest,
                                                           recording=recorder))
      command = e1_workloads.cyclic_command(cyclic_binary, directory, measurement_config, scheduler,
                                            migratable=migratable)
      with cyclictest.temporary_timer_slack(settings['timer_slack_ns']):
        job = session.start_workload(command, common.cgroup_cpus(session.cgroup),
                                     policy='other', priority=0, nice=primary['nice'])
      run['command'] = command
      job.release()
      tid = e1_workloads.wait_cyclic(session, job, directory, cpu, primary, settings['timer_slack_ns'],
                                    migratable=migratable,
                                    reservation=settings['policies']['deadline']['cyclictest'] if partitions else None)
      run['measurement_tid'] = tid
      stress = None
      if case['stress']:
        stress = e1_workloads.Stress(session, directory, config, scheduler, stress_binary,
                                     migratable=migratable, partitions=partitions)
        resources.callback(stress.close)
        stress.wait_ready()
        e1_measurement.warmup(session, stress, config['warmup_s'])
      e1_measurement.record_interval(config, session, job, directory, cpus, run,
                                      stress=stress, partitions=partitions)
      raw = common.read_json(directory / 'cyclictest.json')
      # the histogram is ancillary; E2-E4 measure operations rather than latency tails
      run['cyclictest_summary'] = cyclictest.summarize(raw, expected_threads=1)
      run['cyclictest_sha256'] = common.sha256(directory / 'cyclictest.json')
      achieved = run['utilization']['busy_percent']
      if case['stress'] and abs(achieved - case['target_utilization_percent']) > \
          settings['stress']['utilization_tolerance_percent']:
        raise ValueError(f'achieved utilization {achieved:.2f}% misses the configured target')
    run['cleanup'] = 'complete'
    e1_capture.check_tracing(directory, phase='after')
    bpftrace_convert.convert(directory, run)
    analysis = operation_analysis.analyse(directory, directory / 'operation-analysis')
    if experiment != 'e2' and not any(row['layer'] == 'kernel' and row['samples']
                                     for row in analysis['operations']):
      raise ValueError('JLFP callback events were enabled but no callbacks were measured')
    if experiment != 'e2' and not any(row.get('kernel_callback_reported_ns', 0)
                                     for row in analysis['operations']):
      raise ValueError('no JLFP callback was nested within a kernel operation')
    run['measurement'] = True
    return run
  finally:
    common.write_json(directory / 'capture.json', run)
