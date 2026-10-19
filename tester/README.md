# Scheduler Tests

## AI Disclosure

OpenAI Codex Sol 6.1 was used to implement experiment scripts with human supervision.

## Overview

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
    run_e1.py                 trace-free cyclictest E1 matrix
    analyse_e1.py             standalone raw-histogram statistics
    run_e2.py                 class-operation trace matrix
    run_e3.py                 JLFP callback attribution, pinned workers
    run_e4.py                 JLFP callback attribution, migratable workers
    plan.py                   measurement definitions and pending prerequisites
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
`tester/utils/`. E1–E4 are implemented with development validation; full live
target validation remains pending. E2 uses function probes; E3/E4 additionally
require the target kernel's SCX callback events described below.
These commands inspect prerequisites or build private artifacts:

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
E1 DEADLINE cases require explicit reservations and temporary CPU partitions
(described below). E2's EXT variants are qmap/JLFP; its DEADLINE cases also require
configured reservations. E3/E4 use JLFP only.

Each command's artifacts go to a new `tester/build/experiments/` directory.
Build attempts retain commands, logs, source/binary hashes and failures, with a
fixed attempt limit and process-group cleanup. Cleanup failure stops retries.
Builds run in the controller cgroup and leave existing builds untouched. Running
without root requires permission to enter that cgroup and return to the original
cgroup, or launching from the controller cgroup itself. A runner invoked through
sudo delegates compilation to the original user. JLFP/GEDF builds disable timing
statistics and custom trace emissions
by default; `build jlfp --trace events` or `--trace hotpath` selects a separate
tracing build. `build jlfp --trace ops` enables only the custom operation-event
family, with low-frequency/hotpath events and latency statistics compiled out.
JLFP/GEDF callbacks emit operation entry/exit events when tracing is enabled.
Qmap/simple's operational counters are left alone.
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
PREEMPT_RT. Treat the separately installed timer patches as an external
prerequisite. Experiments never install dependencies or create the two configured
cgroups; E1 DEADLINE temporarily manages child CPU partitions as described below.

The cyclictest implementation lives in `cyclictest/modified_cyclictest.c`, based on
upstream revision `62da2befac98f811af8e56f2b7992fb09faa33d6`. It contains EXT and
explicit-reservation DEADLINE support, inherited-affinity support, and an optional
E1 worker startup gate. The experiment builder copies it into a private pinned
checkout and saves its source hash and a generated diff against upstream.
It does not replace `cyclictest/rt-tests` or build/use cyclicdeadline.
Both cyclictest builders use upstream's Makefile without overriding optimization
or repairing unrelated upstream bugs. Build metadata records inherited build
variables, and build logs retain compiler commands. In this pinned upstream
version, a nonempty `DEBUG` value selects `-O0 -g`; otherwise it selects `-O2 -g`.
Check these recorded settings when comparing runs or papers. The EXT/DEADLINE,
startup-gate and affinity changes required by the tests remain explicit in the
saved patches. Preflight returns status 2 and preserves a
JSON report when prerequisites are missing; `preflight --traced` additionally
checks trace tools.
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
| `overhead` | Measurement CPU (`cyclictest_cpu`) and aggregate stress utilization target (95% by default). |
| `overhead.e1` | Cyclictest interval/histogram, timer slack, CPU DMA latency request, repetitions, quantile/stddev conventions, stress-ng settings and per-scheduler priorities. |
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

## Overhead E1

```sh
sudo python3 tester/experiments/run.py e1
sudo python3 tester/experiments/overhead/run_e1.py --config tester/experiments/debug.json --scheduler other --stress off
python3 tester/experiments/overhead/run_e1.py --analyse-only SUITE_DIR
```

The default matrix has twelve cases: OTHER, FIFO, RR, qmap, simple and JLFP,
each without stress-ng and with a 95% aggregate system-utilization target across
the workload cgroup's effective CPUs. No additional utilization levels are run.
The no-stress condition does not assert zero system utilization. Config controls
the target through `experiments.overhead.stress_utilization_percent`.
Final cases last 60 seconds; the debug profile uses 3 seconds. `--scheduler` and
`--stress off|on` select partial reruns. DEADLINE adds up to two cases once its
reservation fields are configured; unset cases are explicitly reported as pending.

The private cyclictest build supports `--policy=deadline` (or `dl`) with three
required per-worker options: `--dl-runtime=NS`, `--dl-deadline=NS`, and
`--dl-period=NS`. Values are integer nanoseconds, with
`1024 <= runtime <= deadline <= period <= INT64_MAX`. Use priority zero;
priority spreading is rejected. The implementation uses current `sched_setattr` and
`sched_getattr`, rather than the experimental syscall in the
[original DEADLINE cyclictest PR](https://github.com/jlelli/rt-tests/pull/1).
It verifies every worker's installed reservation before sampling and retains
cyclictest's timer/histogram behavior. All cyclictest changes, including EXT,
the startup gate and the NUMA affinity guard, are maintained in
`cyclictest/modified_cyclictest.c`. Builders copy this file and save a generated
`cyclictest.patch` in each build's artifacts; no maintained header patch is needed.

Configure E1 reservations under `experiments.overhead.e1.policies.deadline`:
`cyclictest` and `stress` each contain `runtime_ns`, `deadline_ns`, and `period_ns`.
Both triples are deliberately `null` until the experiment parameters are supplied.
Filling cyclictest's triple enables the unstressed case; filling both enables
both. `--scheduler deadline --stress off` requests just the unstressed case and
fails clearly if its reservation is unset. The stress reservation applies to each
CPU worker. Cyclictest's relative deadline must be shorter than stress-ng's;
this expresses relative urgency, not a strict fixed-priority guarantee.

For DEADLINE only, E1 creates temporary single-CPU partitions below the configured
workload cgroup: CPU 9 for an unstressed case, or every workload CPU for a stressed
case. This is required by
[DEADLINE's root-domain affinity rule](https://docs.kernel.org/scheduler/sched-deadline.html).
The existing workload cgroup must be empty and have no children. It must already
be a valid partition root, or be directly below one; ancestors are not changed.
When needed, the runner temporarily makes it a partition root and enables its
cpuset controller. Existing `root`/`isolated` partition behavior is preserved.
Cyclictest's entire process occupies the CPU-9 child. Each stress-ng process group
occupies its CPU's child. Stress supervisors remain OTHER so they can fork;
CPU workers select DEADLINE themselves. The runner verifies actual policy,
reservation and placement, using libc `sched_getattr` (glibc 2.41 or newer).

All partition validity checks remain active during measurement. Cleanup stops
owned processes before removing children and restoring parent controls; a populated
child or restoration failure stops retries and keeps the failure artifacts.
Utilization still covers the **original** workload CPU set, including CPU 9.
The kernel's reservation admission limit also applies: all stress-worker
reservations plus cyclictest's reservation must fit on CPU 9. A 95% offered-load
target is not a 95% reservation budget. The runner never disables admission
control or changes system bandwidth settings. Admission failures invalidate the
attempt. Real DEADLINE admission, achieved load and partition restoration still
need validation on the prepared target after the reservation values are supplied.

Each invocation builds fresh cyclictest and the selected EXT schedulers, using
trace profile `off`. EXT attaches at root with partial switching; native cases
require EXT detached. No recorder, trace instance, scheduler manager or tracing
parser is used. E1 checks available tracefs controls and refuses enabled events
or function tracers; it does not change them. Kernel BPF timer support and host
preparation remain external prerequisites. E1 never installs kernel patches.

One cyclictest measurement thread is pinned to CPU 9. Its main thread stays
within the workload cgroup's effective cpuset (the CPU-9 partition for DEADLINE).
A private cyclictest startup gate
lets the controller verify the measurement TID's policy, priority, nice, affinity
and timer slack, and set/read back its JLFP task weight before the first sample.
The gate is inactive for ordinary cyclictest users. It discards no samples.

E1 starts one pinned stress-ng CPU worker per workload CPU by default, using the
`loop` CPU method and 10 ms busy slices. `workers_per_cpu`, method and busy slice
are configurable. Per-worker load is rounded from target/workers-per-CPU; this
is only the initial offered load. The shared warmup precedes measurement on
stressed cases. `/proc/stat` counters cover only the effective workload CPUs,
from cyclictest gate release through observed process exit, including shutdown.
Raw counters and monotonic timestamps are saved. Trials outside the configured
2 percentage point utilization tolerance fail and retain their artifacts for
bounded retries. The runner does not silently equate `--cpu-load` with achieved
system utilization. Stress-ng supervisors, workers and threads are checked
for the expected policy, priority, nice, affinity and cgroup; the DEADLINE
supervisor/worker distinction is described above.

Initial priority settings are explicit in `overhead.e1.policies`: FIFO/RR use
50 for cyclictest and 10 for stress-ng; OTHER/qmap/simple use nice 0 versus 19;
JLFP uses task weights 100 versus 1. JLFP and qmap use 1 ms slices, and JLFP uses
four-CPU shards. Simple retains its existing weighted-vtime mode and built-in
`SCX_SLICE_DFL` slice; it has no runtime slice option. Qmap/simple weight service
is approximate and does not become strict fixed-priority scheduling. Scheduler
algorithms are unchanged. Qmap's normal timers remain part of its execution.
Single-CPU affinity selects JLFP's non-migratable task path for both cyclictest
and these stress workers. This workload does not measure its migratable-task
selection path; E4 exercises the migratable path separately.

Measurement defaults are a 1 ms interval, integer microsecond histogram samples
with a 10 ms histogram range, 1 ns timer slack, and a temporary 0 us CPU DMA
latency request. All samples, including the first, are included. One fixed-order
trial per case is configured initially. These values live in `overhead.e1` and
can be changed in either complete profile. Timer slack and CPU DMA latency are
restored/released, and owned workloads stop before the scheduler detaches.

Each suite retains builds, commands, per-thread/process checks, histograms,
cyclictest JSON and failed attempts. Successful suites produce `results.json`
and `results.csv`: max, mean, median, p99, p99.9 and standard deviation in us,
plus sample counts and achieved utilization. Means and standard deviation use
the integer sample histogram, not cyclictest's rounded JSON average. Defaults
are nearest-rank quantiles and population standard deviation. `linear` quantiles
use interpolation at `(n-1)*p`; `sample` standard deviation uses `n-1`.
Overflowed or inconsistent histograms, short runs, incorrect placement/policy,
unexpected process exits or incomplete cleanup invalidate the attempt. Offline
suite replay requires successful capture/cleanup records and unchanged raw hashes.
Completed cases must match the planned matrix in order and identity, with distinct
case directories. Failed attempts remain available even when a retry succeeds.
Review those attempts before comparing latency tails: retrying after histogram
overflow or a utilization miss can favour the trials that pass those checks.

For histogram-only inspection:

```sh
python3 tester/experiments/overhead/analyse_e1.py CYCLICTEST_JSON
```

This writes `e1-results.json` beside the raw JSON and labels the report analysis
only: a valid histogram does not by itself validate an experimental trial.
Live FIFO/RR/EXT E1 validation is still pending on the prepared target machine.

The read-only `overhead/plan.py` describes each experiment and pending target
prerequisites. The `diagnostics/` scripts remain separate from these experiments.

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

Both builders use `cyclictest/modified_cyclictest.c`. The diagnostic utility makes
a private copy of `cyclictest/rt-tests` (cloned at the shared pin if absent); the
experiment builder creates a fresh pinned upstream checkout. Existing source
checkouts are preserved.

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
separate from overhead E1.

## Overhead E2–E4

```sh
sudo python3 tester/experiments/overhead/run_e2.py --config tester/experiments/debug.json
sudo python3 tester/experiments/overhead/run_e3.py --config tester/experiments/debug.json
sudo python3 tester/experiments/overhead/run_e4.py --config tester/experiments/debug.json
python3 tester/experiments/overhead/run_e3.py --analyse-only SUITE_DIR
```

The shared driver also accepts `e2`, `e3` and `e4`. Use `--scheduler` or
`--stress off|on` for a partial rerun. Configuration controls duration, repetition,
workload and tracing; no extra recurring command-line parameters are needed.
E2 uses fentry/fexit probes for sched_class functions. E3/E4 add the target
kernel's `sched_ext:sched_ext_op_enter` and `sched_ext:sched_ext_op_exit` events,
using `op` and exit `delta_ns`. All scheduler builds disable custom emissions
and latency statistics. These experiments do not require the scxtp module.
No runner patches the kernel, loads a module or enables global BPF runtime stats.

E2 compares OTHER/FIFO/qmap/JLFP without stress and with the configured 95%
aggregate workload-CPU utilization target. DEADLINE cases are deferred while
reservation fields are unset; configured cases reuse E1's temporary partitions.
E3 uses pinned JLFP; E4 allows one cyclictest thread and the same total stress
worker count throughout the workload cpuset. Permitting migration does not force
migration. All three share E1's workload, QoS, timing and policy settings.
Existing workload/controller cgroups provide placement; no isolation setup is done.

`overhead.operation_tracing.class_functions` explicitly maps class operations to
concrete function names; qmap/JLFP share EXT functions. The initial inventory is
based on the inspected kernel's actual class tables, extending the supplied
`tester/sched_trace.bt` probe list. Missing declared functions fail preflight.
`excluded_functions` records deliberate omissions: `set_next_task_rt` lacks a
ftrace site on the inspected build. Review this list on the target; excluded
functions are not reported as zero-cost operations. Shared implementations and
direct calls to these functions are included. Function probes are scoped to
execution CPUs 8–15, so remote wakeup work executing on CPUs 0–7 is excluded.

The recorder renders `tester/sched_trace.bt` with literal probes, CPU filters and
verified x86_64 preemption-context fields. The template is used through the
runners; each capture saves its fully rendered `sched_trace.bt`. On PREEMPT_RT,
softirq context comes from the current task; hardirq nesting comes from the
per-CPU preempt count. Unsupported layouts/NMI operations fail explicitly.
Kernel callback IDs are decoded from the target BTF's exact `sched_ext_ops`
layout using SCX_OP_IDX; no manually maintained numeric enum is required.

`buffer_pages` sets the per-CPU bpftrace buffer size; `drain_s` sets the grace
period for completing calls after workload shutdown. A read-only getpgid control
probe gates collection after attachment and acknowledges collection shutdown.
The recorder drains output before detaching. It retains its own BPF program
references until final recursion-miss counters are read. Helper/transport warnings,
missing acknowledgements, nonzero misses or mismatched raw/BPF event counts fail
the attempt. No missing counters are assumed to be zero.
The default 4096 pages is 16 MiB per CPU with 4 KiB pages; bpftrace allocates
buffers for online CPUs even when the record filter selects only 8–15. The
smaller development buffer dropped records under cyclictest and was rejected.
Review buffer memory and measured utilization on the final target; tracing itself
adds load, so stress-ng's offered load does not guarantee 95% observed utilization.

Conversion uses monotonic nanoseconds, orders buffered records per CPU, and selects
root calls entered between cyclictest gate release and observed exit, retaining
complete descendants and exits. It distinguishes idle threads by CPU and separates
interrupted contexts. Selected incomplete calls, cross-CPU calls, unknown IDs,
invalid nesting and negative kernel deltas fail with retained diagnostics.

E3/E4 report class elapsed time and kernel-reported callback durations. Each class
call receives the sum of its outermost nested callback delta_ns values, avoiding
double-counting nested callbacks. Per-call fractions and duration-weighted
aggregate fractions are retained, alongside callback boundary unions. Class time
minus callback time is an uncalibrated residual, including probe effects; it is
not pure kernel execution time. Fractions/residuals are not clamped. Tick emission
calibration remains pending with no cost subtraction.

Accepted attempts retain raw bpftrace stdout/stderr, generated script/config,
program miss evidence, cyclictest output, normalized operations and exact paired
samples. Suites save pooled/per-CPU statistics, accepted attempt numbers and failed
attempt counts. Offline replay verifies hashes and recomputes statistics without
root. Failed attempts remain; cleanup failure stops retries. Target validation,
full stress matrices and calibration remain separate from structural validation;
reports keep `experiment_validated: false` pending target review.

## Operation trace utilities for E2–E4

```sh
python3 tester/utils/inspect_trace.py TRACE.dat --output NEW_INVENTORY.json
python3 tester/utils/analyse_operations.py CAPTURE_DIR
```

The first command inventories an existing capture with the shared Babeltrace
reader and loss checks. The second pairs normalized operation entry/exit records,
retains exact per-call durations, reports per-CPU/pooled latency statistics and
attributes recorded nested SCX callbacks to class calls. Both are offline tools;
the operation analyser uses only the standard library. Existing outputs are
refused, and incomplete input produces retained diagnostics with an invalid result.

See [the input format and output definitions](experiments/overhead/TRACE_FORMAT.md)
for call IDs, interrupt-context handling, loss counters and callback percentages.
The E2–E4 runners use `utils/bpftrace_convert.py` to produce this format from
individual function/callback boundaries. The older `operation_convert.py` adapter
remains available for historical tracepoint captures. Standalone analysis does not
start experiments or establish scientific validity.
