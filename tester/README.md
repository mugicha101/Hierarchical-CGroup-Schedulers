# Scheduler Tests

Run all commands below from the repository root (`cgs/`).

Experiment entry points live in `tester/experiments/`; shared implementation lives
in `tester/utils/`. The directory layout matches the config's experiment groups:

```text
tester/experiments/
  config.json                 shared settings and experiment groups
  debug.json                  complete development configuration
  run.py                      shared plan/preflight/build/smoke driver
  smoke.py                    infrastructure checks, no benchmark measurements
  inversion/
    run_jlfp_test.py           static JLFP inversions
    run_jlfp_dynamic_test.py   dynamic JLFP inversions
    run_mc2_dynamic_test.py    inter/intra-class MC² inversions
  diagnostics/
    run_jlfp_wakeup_test.py    wakeup placement and latency
    run_jlfp_latency_test.py   existing traced cyclictest comparison
  overhead/
    plan.py                   upcoming overhead E1–E4; no runnable benchmarks
```

The JLFP and MC² runners delegate worker capture, cgroup placement and offline
analysis to separate utility modules. Wakeup analysis and cyclictest setup follow
the same layout. Local unit tests and
development checks remain untracked under `tester/codex/`.

Each runner's `capture_run()` shows its configured workload parameters with named
arguments. Its `main()` selects a new or saved capture, analyses it, saves results
and prints a report. Analysis utilities own trace-reader cleanup and log handling;
the shared CLI wrapper handles termination signals.

## Staged Experiment Setup

The overhead/inversion experiment driver and its configuration live in
`tester/experiments/`, with build, preflight, lifecycle and tracing helpers in
`tester/utils/`. Benchmark cases are still pending later stages;
these commands inspect prerequisites or build private artifacts:

```sh
python3 tester/experiments/run.py plan
python3 tester/experiments/run.py preflight
python3 tester/experiments/run.py build worker
python3 tester/experiments/run.py build jlfp
python3 tester/experiments/run.py build qmap
python3 tester/experiments/run.py build simple
python3 tester/experiments/run.py build cyclictest
```

Edit `tester/experiments/config.json` to set `workload_cgroup` and
`controller_cgroup` to existing process cgroups below `/sys/fs/cgroup`; both are
deliberately unset by default. Their `cpuset.cpus.effective` files determine CPU
placement, with nonempty, disjoint sets. Prepare CPUs 8-15 for workloads and 0-7
for the controller on the final machine. Ordinary runs require leaves with no
child controllers. All threads of each workload process share its cgroup.
Preflight and builds do not attach schedulers. The runner never creates either
configured cgroup, configures isolation, loads modules or installs packages.
Recurring experiment settings belong in this configuration;
the switches below select development checks and build profiles.

`experiments.overhead.stress_utilization_percent` targets aggregate busy time
across the workload cgroup's effective CPUs (8-15 on the final machine).
The shared `/proc/stat` reader excludes idle and iowait from busy time and does
not count guest time twice. It retains raw counters; stress-ng's per-worker load
option must not be treated as proof that the aggregate target was achieved.
Final duration defaults to 60 seconds; other durations are marked development.
DEADLINE cases are explicitly deferred. E2's EXT variants are qmap/JLFP.

Each command's artifacts go to a new `tester/build/experiments/` directory.
Build attempts retain commands, logs, source/binary hashes and failures, with a
fixed attempt limit and process-group cleanup. Cleanup failure stops retries.
Builds run in the controller cgroup and leave existing builds untouched. Running
without root requires permission to enter that cgroup and return to the original
cgroup, or launching from the controller cgroup itself. A runner invoked through
sudo delegates compilation to the original user. JLFP/GEDF builds disable timing
statistics and custom trace emissions
by default; `build jlfp --trace events` or `--trace hotpath` selects a separate
tracing build. Qmap/simple's operational counters are left alone.
All BPF scheduler builds use `clang-22`, including preflight's compiler check;
build manifests retain the compiler path/version. Clang 21.1.8 can omit arena
pointer casts after combining adjacent stores into a memory intrinsic.
Qmap/simple are fetched into private sparse checkouts using `LINUX_REPO` and
`LINUX_REF` from `scheds/setup.sh`, currently Torvalds' `v7.3-rc7` at
`24a19b953e2a3d0ea5a8c4951a0ab8f32720c907`. Manifests retain the resolved commit
and setup-script hash. These builds require network access for fetching; they
do not use or modify the enclosing kernel checkout. Simple's partial-switch
loader patch stays in its private build output; qmap source is unmodified.

Short lifecycle checks use the existing native worker with an expired schedule,
so no busy loop or benchmark measurement runs:

```sh
sudo python3 tester/experiments/run.py smoke none
sudo python3 tester/experiments/run.py smoke jlfp --traced
sudo python3 tester/experiments/run.py smoke qmap
sudo python3 tester/experiments/run.py smoke simple
```

Each check builds fresh artifacts, places the workload process in the configured
cgroup, verifies every thread's policy/priority/nice/affinity, and releases it
through a controller gate. JLFP additionally checks a task-weight map write and
readback. EXT loaders attach only at root using partial switching; simple's
private loader receives a saved `-p` patch. Existing schedulers are never replaced.
Root identity and recorder liveness are checked throughout; teardown stops
workload groups before the owned loader and recorder, then restores the
controller's original cgroup and affinity.
Trace-free checks start neither a recorder nor a scheduler manager.

`--traced` records `sched:sched_process_exit` in a private monotonic-clock
instance before attachment. Captures retain trace controls, per-CPU loss counters,
offline event/CPU counts and parsing diagnostics. Missing events/metadata or lost
events fail the attempt. No custom module is needed for these smoke captures;
custom scxtp events require a matching module and a tracing-enabled JLFP build.

On a development host, `smoke ... --basic` relaxes only the housekeeping-slice
isolation checks. It still requires both prepared, disjoint cgroups, marks
the output as a setup check, and never produces benchmark results. All final-run
prerequisites remain mandatory for normal checks. Earlier qmap checks built with
Clang 21 failed in `qmap_dequeue` (`R7 invalid mem access 'scalar'`); Clang 22 fixes
the arena-memory-intrinsic cast bug. Qmap also requires working BPF timers on
PREEMPT_RT; the current development kernel rejects them. Experiment runs never
install dependencies or prepare cgroups.

The new cyclictest build uses upstream revision
`62da2befac98f811af8e56f2b7992fb09faa33d6` in a private checkout with only EXT
policy support and the existing inherited-affinity fix applied. Its patch is
saved with the build. It does not replace `cyclictest/rt-tests` or build/use
cyclicdeadline. Preflight returns status 2 and preserves a JSON report when
prerequisites are missing; `preflight --traced` additionally checks trace tools.
The harnesses below use the same configuration file for placement and timing.

Follow the [scheduler build instructions](../scheds/README.md#setup). Inversion tests also require the [tracing module](../scheds/README.md#structured-scheduler-tracepoints). Live captures require sudo for BPF, ftrace, and cgroup setup.

Trace analysis uses Python 3, `bt2`, and the Babeltrace2 ftrace plugin. [setup_bt2_ftrace.sh](setup_bt2_ftrace.sh) builds the plugin; its comments list the required development packages.

## Configured Experiments

All entry points read `tester/experiments/config.json`. Set `workload_cgroup` and
`controller_cgroup` to existing prepared cgroups with disjoint effective cpusets.
Ordinary JLFP, wakeup and latency runs require a process cgroup leaf. MC² uses
the workload path as the base of its owned class hierarchy and refuses existing
`class_a`, `class_b` or `class_c` children. The Python controller, scheduler
loaders, recorders and build helpers
run in the controller cgroup; workload launchers move their processes into the
workload cgroup. The controller restores its original cgroup and affinity afterward.
Both configured cgroups and their cpusets are left intact. Per-task affinity
still selects CPUs within the workload cpuset when an experiment requires pinning.
The runners never create `other`, migrate unrelated processes or change host
noise controls. MC²'s per-CPU child cgroups inherit from the configured base and
restrict the pinned A/B workers to their assigned CPUs.

Shared `duration_s` is 60 seconds; `warmup_s` is 1 second for native-worker runs.
Cyclictest histograms include startup and do not use the native-worker warmup.
Experiment-specific parameters live under three explicit `experiments` groups:

| Section | Settings |
| --- | --- |
| `inversion.jlfp_static` | Workers per CPU; continuous runnable workers with distinct JLFP weights. |
| `inversion.jlfp_dynamic` | Workers per CPU, period and CPU budget in milliseconds. |
| `inversion.mc2.classes` | Each class's utilization percentage, task count per CPU, periods in milliseconds, and release staggering. |
| `overhead` | Upcoming E1–E4: measurement CPU (`cyclictest_cpu`) and aggregate stress utilization target. Remaining methodology is pending. |
| `diagnostics.wakeup` | Worker count, period in milliseconds, CPU budget in microseconds. |
| `diagnostics.latency` | Pinning mode, policy/priority, thread count, interval, histogram range, timer slack, temporary CPU DMA latency, scheduler attachment and diagnostics. |

`tester/experiments/debug.json` is a complete alternate config with 3-second runs,
0.2-second native-worker warmup and one attempt. Set both its cgroups for the
development machine too. It is loaded explicitly; there is no implicit merge
or auto-detection.

```sh
python3 tester/experiments/run.py --config tester/experiments/debug.json plan
sudo python3 tester/experiments/inversion/run_jlfp_dynamic_test.py --config tester/experiments/debug.json
```

Durations, cgroup paths and workload parameters come from config rather than
CLI flags. `--output-dir` and `--analyse-only CAPTURE_DIR` remain available; saved
inversion/wakeup captures can be analysed without root or a live workload cgroup.
Each new capture saves the resolved config, effective cpusets and command in
`experiment.json`. Utilization and worker counts use the workload's effective
cpuset; there are no separate CPU-mask settings in config. Planning and offline
analysis do not require either cgroup to be available.
`--scx-build-path` is an optional debug build override. Latency also retains
`--cyclictest`, `--mode`, `--policy`, `--no-jlfp`, `--diagnostic-trace` and
`--spike-us`; absent overrides use the config values.

Native workers come from `tester/work.c`, built automatically into
`tester/build/jlfp_worker`. They wait for cgroup placement, CPU affinity, weights
and SCHED_EXT policy before running. Periodic workers use absolute monotonic
release times, thread CPU-time budgets and skipped missed releases. Cleanup reaps
workers before detaching schedulers or finalizing the private trace. Scheduler
and capture failures retain diagnostic output.

## Upcoming Overhead Experiments

`experiments.overhead` contains the agreed overhead settings. The read-only
matrix in `tester/experiments/overhead/plan.py` describes E1 (trace-free cyclictest
latency), E2 (scheduling class operations), E3 (JLFP callback/class operation
timing), and E4 (operation timing with migratable workers). View it with
`python3 tester/experiments/run.py plan`.

These benchmarks are not implemented. Remaining methodology and tracing
prerequisites must be resolved before adding their runners. The existing
`diagnostics/` scripts retain their current capture behavior and are not E1–E4.

## Manual Noise Isolation

These commands are separate from every experiment:

```sh
sudo python3 tester/utils/isolation.py --config tester/experiments/debug.json enable
sudo python3 tester/utils/isolation.py status
sudo python3 tester/utils/isolation.py disable
```

`enable` saves original settings to `/run/cgs-tester-isolation.json`, disables the
Wi-Fi radio, unloads the detected Wi-Fi driver modules, and sets FAIR/SCX bandwidth
server runtimes to zero on the configured test CPUs. It needs those debugfs runtime
controls and removable Wi-Fi modules when Wi-Fi is present. Driver removal
interrupts Wi-Fi until restored. It makes no cgroup, cpuset, governor or background
process changes. CPU placement always comes from the prepared cgroup and config.

`disable` restores the saved driver/radio state and bandwidth runtimes, then
removes the snapshot. It uses the original snapshot even if config has changed.
Repeated `enable` refuses to overwrite an outstanding snapshot. Setup failure rolls
back; incomplete restoration retains the snapshot for another `disable` attempt.
The utility exits after enabling, so restore explicitly when development tests end.

## JLFP Inversions

```sh
sudo python3 tester/experiments/inversion/run_jlfp_test.py
sudo python3 tester/experiments/inversion/run_jlfp_dynamic_test.py
```

Static JLFP defaults to two continuous workers per CPU. Dynamic JLFP defaults to
two workers per CPU, a 20 ms period and 10 ms CPU budget, with staggered releases.

Replay a saved capture with the same runner's `--analyse-only CAPTURE_DIR`. Its
`trace.dat` and `run.json` supply measurement metadata; analysis rewrites the
analysis log/results while preserving raw captures. Existing saved captures remain
supported. JLFP placement diagnostics are excluded from inversion calculations.

## MC² Hierarchy and Utilization

```sh
sudo python3 tester/experiments/inversion/run_mc2_dynamic_test.py
```

The fixed hierarchy is root JLFP, pinned JLFP/RM class A (weight 4), pinned GEDF
class B (weight 3), and migratable GEDF class C (weight 2). Each class has its own
config entry, for example:

```json
"class_a": {
  "utilization_percent": 15,
  "tasks_per_cpu": 2,
  "periods_ms": [20, 40],
  "stagger": true
}
```

A class's percentage is relative to the capacity of the entire configured CPU set:
15% of eight CPUs is 1.2 CPU-seconds per second. `tasks_per_cpu` repeats the period
mix on each CPU; C's resulting workers can migrate across the full set. There must
be one period per configured task. The class gets one common CPU-time budget so
`sum(runtime / period) / number_of_CPUs * 100` equals its utilization target, subject
to nanosecond rounding. Thus the example gives each task a 2 ms budget. Changing a
class's target scales its budgets without changing the other classes. RM weights
follow period order, equal periods have equal priority, and optional staggering
retains the existing phase layout. A zero-load class stays attached without workers.

The default remains 15% per class, or 45% total offered load, preserving the old
2 ms, 20/40 ms workload. Class contributions can sum above 100% for deliberate
overload; each task must still have a positive budget shorter than its period.
These are offered workload targets. Missed releases, preemption and unrelated
activity can change achieved utilization. Metadata retains requested/rounded class
loads plus raw `/proc/stat` counters and their actual sampling window across CPUs
8-15, excluding warmup. Offline results report each class's executed CPU time as a
percentage of total configured CPU capacity, separately from system utilization.

Analysis reports inversions between classes and within each class, including class
and task pairs. Overlapping category times use a union for the overall inversion
time. Missing initialization, applied weights, tracing or premature scheduler
detach invalidates the capture. Non-root JLFP/GEDF self-weight initialization remains
an existing scheduler issue that this harness can expose; scheduler logic is unchanged.

## Wakeup Diagnostics

```sh
sudo python3 tester/experiments/diagnostics/run_jlfp_wakeup_test.py
```

Wakeup defaults to one migratable worker, a 1 ms period and 50 us CPU budget.
Native switch/wakeup events distinguish blocking from preemption. Wakeup analysis
retains individual samples and reports wake-to-run latency and migration ratios.
Use `experiments.diagnostics.wakeup` to configure it and `--analyse-only` to replay
a saved capture.

## Cyclictest Diagnostics

This existing traced comparison is separate from the upcoming trace-free overhead
E1 experiment. Its settings live under `experiments.diagnostics.latency`.

The older utility builder uses `cyclictest/rt-tests` and the repository's modified
source in a private copy. The staged build instead patches pinned upstream source.

```sh
python3 tester/utils/build_jlfp_cyclictest.py --output-dir tester/build/cyclictest-affinity
sudo python3 tester/experiments/diagnostics/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest
```

Set `experiments.diagnostics.latency` in the config for recurring comparisons.
Its default is one migratable EXT thread, a 1000 us interval, 10000 us histogram
range, 1 ns timer slack and a temporary 0 us CPU DMA latency request. Set
`cpu_dma_latency_us` to -1
to omit that request. The request is released after capture. The harness verifies
actual worker policies, affinities and slack, uses CLOCK_MONOTONIC and saves pooled
and per-thread histogram summaries. Cyclictest's main thread also stays inside the
configured workload cpuset.

`policy: "other"` retains JLFP attachment for a FAIR comparison; `no_jlfp: true`
selects a native OTHER/FIFO baseline. EXT requires JLFP. `priority: null` selects
0 for EXT/OTHER and 50 for FIFO. To inspect outliers, set `diagnostic_trace: true`
and `spike_us` in debug config, or use the corresponding CLI overrides. Diagnostic
runs record native scheduler/timer/IRQ/workqueue events and timestamped spikes in
`cyclictest.log`; timestamps use CLOCK_MONOTONIC microseconds, while trace events
use nanoseconds. These legacy latency runs always record an exit event and are
separate from the pending trace-free E1 implementation.
