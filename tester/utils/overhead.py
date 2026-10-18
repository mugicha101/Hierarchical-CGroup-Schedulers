"""Build, run and replay E2-E4 suites; preserve each attempt and its raw trace."""

import csv
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from . import builds, common, operation_analysis, overhead_capture, overhead_config, preflight


def prepare(config, experiment, cases, directory):
  profile = 'off' if experiment == 'e2' else 'ops'
  targets = ['cyclictest'] + [name for name in ('qmap', 'jlfp')
                             if any(case['scheduler'] == name for case in cases)]
  manifests = {}
  for target in targets:
    manifests[target] = builds.result(builds.build(config, target, trace=profile if target == 'jlfp' else 'off'))
  if not manifests['cyclictest'].get('e1_startup_gate'):
    raise ValueError('cyclictest requires the pre-measurement readiness gate')
  common.write_json(directory / 'builds.json', manifests)
  binary = shutil.which('stress-ng')
  version = subprocess.run([binary, '--version'], check=True, capture_output=True, text=True,
                           timeout=config['process_timeout_s'])
  common.write_json(directory / 'stress-ng.json', {'binary': binary, 'sha256': common.sha256(binary),
                    'version': version.stdout.strip()})
  return manifests, binary


def successful_attempt(directory):
  paths = [path for path in directory.glob('attempt-*/status.json')
           if common.read_json(path)['status'] == 'succeeded']
  if len(paths) != 1:
    raise ValueError(f'expected exactly one successful attempt in {directory}')
  status = common.read_json(paths[0])
  if not status['measurement'] or status['cleanup'] != 'complete':
    raise ValueError('attempt is not a complete measurement')
  return paths[0].parent


def analyse(directory):
  directory = Path(directory).resolve(strict=True)
  suite = common.read_json(directory / 'suite.json')
  if suite['status'] != 'succeeded' or not suite['cases'] or \
      [item['case'] for item in suite['cases']] != suite['planned_cases']:
    raise ValueError('completed cases differ from the planned matrix or the suite is incomplete')
  seen, rows = set(), []
  for item in suite['cases']:
    root = (directory / item['directory']).resolve(strict=True)
    if not root.is_relative_to(directory) or root in seen:
      raise ValueError('duplicate case directory or path outside suite')
    seen.add(root)
    attempt = successful_attempt(root)
    capture = common.read_json(attempt / 'capture.json')
    if capture['case'] != item['case'] or capture['experiment'] != suite['experiment'] or \
        not capture['measurement'] or capture['cleanup'] != 'complete':
      raise ValueError('case differs from its capture metadata or cleanup is incomplete')
    inputs = capture['analysis_inputs_sha256']
    if any(common.sha256(attempt / name) != value for name, value in inputs.items()):
      raise ValueError(f'raw capture or analysis inputs changed: {attempt}')
    # replay recomputes all statistics without trusting saved analysis tables
    output = attempt / ('operation-replay-' + uuid.uuid4().hex[:8])
    report = operation_analysis.analyse(attempt, output)
    failures = [path.parent.name for path in root.glob('attempt-*/status.json')
                if common.read_json(path)['status'] != 'succeeded']
    for row in report['operations']:
      rows.append({**item['case'], **row, 'experiment': suite['experiment'],
                   'achieved_utilization_percent': capture['utilization']['busy_percent'],
                   'accepted_attempt': attempt.name, 'failed_attempts': len(failures),
                   'directory': str(attempt.relative_to(directory)), 'experiment_validated': False})
  common.write_json(directory / 'results.json', {'experiment': suite['experiment'], 'cases': rows,
                    'experiment_validated': False, 'target_validation': 'pending',
                    'tick_emission_calibration': 'pending'})
  with (directory / 'results.csv').open('w', newline='') as output:
    writer = csv.DictWriter(output, fieldnames=tuple(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
  return rows


def run(config, experiment, *, scheduler=None, stress=None, analyse_only=None):
  if analyse_only is not None:
    rows = analyse(analyse_only)
    print(f'Recomputed {len(rows)} operation rows: {analyse_only}')
    return Path(analyse_only)
  cases = list(overhead_config.cases(config, experiment, scheduler, stress))
  profiles = {case['scheduler']: overhead_config.binding(config, experiment, case['scheduler']) for case in cases}
  if os.geteuid() != 0:
    raise PermissionError('root is required for scheduling policy, cgroup placement and private tracing')
  if not float(config['duration_s']).is_integer():
    raise ValueError('cyclictest requires a whole number of seconds')
  directory = common.new_run(config, experiment)
  print(f'{experiment.upper()} artifacts: {directory}', flush=True)
  suite = {'experiment': experiment, 'config': config, 'status': 'running', 'command': sys.argv,
           'planned_cases': cases, 'cases': [], 'target_validation': 'pending',
           'tick_emission_calibration': 'pending'}
  common.write_json(directory / 'suite.json', suite)
  try:
    report = preflight.inspect(config, traced=True)
    common.write_json(directory / 'preflight.json', report)
    if not report['ok']:
      raise ValueError(f'prerequisites missing; see {directory / "preflight.json"}')
    formats = {policy: overhead_config.inspect_events(profile, experiment) for policy, profile in profiles.items()}
    common.write_json(directory / 'event-formats.json', formats)
    with common.controller_placement(config):
      manifests, stress_binary = prepare(config, experiment, cases, directory)
      binary = manifests['cyclictest']['binary']
      if common.sha256(binary) != manifests['cyclictest']['binary_sha256']:
        raise ValueError('cyclictest binary differs from its build manifest')
      for case in cases:
        name = f"{case['scheduler']}-stress-{'on' if case['stress'] else 'off'}-r{case['repetition']}"
        def capture(attempt, processes):
          result = overhead_capture.capture(config, attempt, experiment, case, binary,
                      manifests.get(case['scheduler']), stress_binary, profiles[case['scheduler']])
          names = ('trace.dat', 'trace.dat.metadata.json', 'operations.jsonl', 'operations.metadata.json',
                   'cyclictest.json', 'conversion.json')
          result['analysis_inputs_sha256'] = {name: common.sha256(attempt / name) for name in names}
          common.write_json(attempt / 'capture.json', result)
          return result
        root = common.run_attempts(config, name, capture, parent=directory, measurement=True)
        suite['cases'].append({'case': case, 'directory': root.name})
        common.write_json(directory / 'suite.json', suite)
    suite['status'] = 'succeeded'
    common.write_json(directory / 'suite.json', suite)
    rows = analyse(directory)
    metadata = common.read_json(directory / 'run.json')
    common.write_json(directory / 'run.json', {**metadata, 'measurement': True})
    print(f"{experiment.upper()}: {len(rows)} operation rows; {directory / 'results.csv'}", flush=True)
    return directory
  except BaseException as error:
    suite.update(status='failed', error=f'{type(error).__name__}: {error}')
    raise
  finally:
    common.write_json(directory / 'suite.json', suite)
