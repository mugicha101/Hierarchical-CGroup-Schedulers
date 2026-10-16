# Scheduler Tests

Run all commands below from the repository root (`cgs/`).

## Staged Experiment Setup

The shared setup for the overhead/inversion experiment suite lives in
`tester/experiments/`. Experiment workloads are still pending later stages;
these commands only inspect prerequisites or build private artifacts:

```sh
python3 tester/experiments/run.py plan
python3 tester/experiments/run.py preflight
python3 tester/experiments/run.py build worker
python3 tester/experiments/run.py build jlfp
python3 tester/experiments/run.py build qmap
python3 tester/experiments/run.py build simple
python3 tester/experiments/run.py build cyclictest
```

Edit `tester/experiments/config.json` to set `workload_cgroup` to an existing
writable process cgroup below `/sys/fs/cgroup`; it is deliberately unset by
default. The prepared workload leaf must allow exactly CPUs 8-15 and distribute
no child controllers. All threads of each workload process share its cgroup.
Housekeeping processes remain on CPUs 0-7. Setup does not create cgroups,
configure isolation, load modules, attach schedulers or install packages.

`stress_utilization_percent` targets aggregate busy time only across CPUs 8-15.
The shared `/proc/stat` reader excludes idle and iowait from busy time and does
not count guest time twice. It retains raw counters; stress-ng's per-worker load
option must not be treated as proof that the aggregate target was achieved.
Final duration defaults to 60 seconds; other durations are marked development.
DEADLINE cases are explicitly deferred. E2's EXT variants are qmap/JLFP.

Each command's artifacts go to a new `tester/build/experiments/` directory.
Build attempts retain commands, logs, source/binary hashes and failures, with a
fixed attempt limit and process-group cleanup. Cleanup failure stops retries.
Builds run on the controller CPUs, do not require root, and leave existing builds
untouched. JLFP/GEDF builds disable timing statistics and custom trace emissions
by default; `build jlfp --trace events` or `--trace hotpath` selects a separate
tracing build. Qmap/simple's operational counters are left alone.

The new cyclictest build uses upstream revision
`62da2befac98f811af8e56f2b7992fb09faa33d6` in a private checkout with only EXT
policy support and the existing inherited-affinity fix applied. Its patch is
saved with the build. It does not replace `cyclictest/rt-tests` or build/use
cyclicdeadline. Preflight returns status 2 and preserves a JSON report when
prerequisites are missing; `preflight --traced` additionally checks trace tools.
The harnesses described below retain their existing behavior.

Follow the [scheduler build instructions](../scheds/README.md#setup). Inversion tests also require the [tracing module](../scheds/README.md#structured-scheduler-tracepoints). Live captures require sudo for BPF, ftrace, and cgroup setup.

Trace analysis uses Python 3, `bt2`, and the Babeltrace2 ftrace plugin. [setup_bt2_ftrace.sh](setup_bt2_ftrace.sh) builds the plugin; its comments list the required development packages.

## Common Behavior

The static, dynamic, wakeup, and latency test scripts default to all CPUs allowed by their inherited affinity and assume the environment is already configured to remove noise. They leave controller affinity and bandwidth server runtimes unchanged and do not create `other` or migrate background processes. Workers are still placed in the root cgroup for JLFP. The static and dynamic tests default to two workers per allowed CPU; wakeup and latency tests retain their explicit worker/thread counts. Wakeup and latency tests accept `--cpus` to override the worker CPU set without enabling isolation.

Static, dynamic, and wakeup tests use the native busy-loop worker in `tester/work.c`; Python handles setup and trace analysis. They automatically build `tester/build/jlfp_worker` with `cc`, pthread support, and libbpf when missing or older than the source. Each worker is a separate C process that blocks until the controller installs affinity, weight, and SCHED_EXT policy. Periodic workloads use absolute monotonic sleeps, thread CPU-time budgets, staggered phases, and skipped missed releases. The original standalone pthread workload remains available through `tester/build.sh`; the latency harness already uses C cyclictest workers.

JLFP inversion tests save scheduler output in `scheduler.log` if setup or cleanup fails, including verifier diagnostics.

## Isolation

Add `--isolate` to restrict workers to the last four allowed CPUs (the configured shard size) and set up cyclictest's `other` arrangement. Wakeup and latency `--cpus` overrides still apply. Isolation requires a CPU outside the worker set for the controller. The scripts create `/sys/fs/cgroup/other` with its CPU set limited to the non-worker CPUs, move root processes there before starting workers, and explicitly place workers in the root cgroup. PID 1, the controller, and kernel threads remain in root when already there; the controller runs on non-worker CPUs. Cleanup returns processes from `other` to root and removes the test's cgroup, including on failure or interruption. An existing `other` cgroup causes setup to fail rather than overwrite it. Isolation also saves the Wi-Fi radio state, disables it, and unloads the wireless device driver during the test; cleanup reloads the driver and restores the previous radio state. This briefly disconnects Wi-Fi. `wifi_isolation.json` records setup and restoration. `cpu_isolation.json` and `run.json` record the CPU set and moved/skipped PIDs. Existing cgroup hierarchies and their CPU sets are left unchanged, so their tasks and per-CPU kernel threads can still contend with workers.

With `--isolate`, the scripts temporarily disable the FAIR deadline server and SCX bandwidth server on the worker CPUs by setting their debugfs runtimes to 0. They save their original settings in `bandwidth_servers.json` and `run.json`, then restore the runtimes after scheduler detach, including on failure or interruption. Run the tests with sudo for BPF and ftrace; isolation also requires the `fair_server` and `ext_server` controls under `/sys/kernel/debug/sched`. Use `--isolate --keep-bandwidth-servers` for isolation with the original bandwidth settings.

The MC² test uses the same background isolation while keeping workers in their class cgroups.

## Static JLFP Inversions

```sh
sudo python3 tester/run_jlfp_test.py
```

The JLFP test reports capture stages and offline analysis progress. From the repository root, use `python3 tester/run_jlfp_test.py --analyse-only tester/build/jlfp-test-<timestamp>` to analyse a saved capture without running workers again. The directory must contain `trace.dat` and `run.json`; this rewrites `analysis.log` and `results.json`. Saved captures containing placement diagnostics are still supported; those events are skipped by the inversion calculation.

## Dynamic JLFP Inversions

```sh
sudo python3 tester/run_jlfp_dynamic_test.py --isolate
```

To test periodic blocking and wakeups, run `sudo python3 tester/run_jlfp_dynamic_test.py`. By default, two weighted workers per allowed CPU share the full allowed CPU set, each consuming a 10 ms CPU budget per 20 ms period before sleeping. Releases are staggered across the period; preemption does not consume the CPU budget, and missed releases are skipped. Adjust `--runtime-ms`, `--period-ms`, `--tasks-per-cpu`, `--warmup`, and `--duration` to vary the load. The test uses native sleep/wakeup events to exclude blocked workers from priority comparisons and reports inversion time, longest inversion, and worker wakeup/block counts. Captures use `tester/build/jlfp-dynamic-test-<timestamp>` and save the period, budget, and phases in `run.json`; use `--analyse-only CAPTURE_DIR` to reanalyse them.

## MC² Hierarchy

For inversions between MC² classes and between tasks within each class, run from the repository root. The terminal summary prints explicit percentages of measurement time and durations in milliseconds. Each class has its own task-inversion time, count, longest interval, and top three task pairs. A uses RM priorities; B/C follow changing EDF deadlines. Detailed nanosecond values and all task pairs remain in `results.json` under `within_class_inversions`. Per-class and task-pair totals can overlap; the combined within-class time counts their union:

```sh
sudo python3 tester/run_mc2_dynamic_test.py --isolate
```

The test expands `tester/mc2/mc2_config.json` into root JLFP without workers, class A pinned JLFP (weight 4), class B pinned GEDF (weight 3), and class C global GEDF (weight 2). Class D is omitted. Per-CPU child cgroups enforce A/B affinity; C shares the worker CPU set. Each class defaults to two workers per CPU, with 20/40 ms periods and 2 ms CPU budgets. Class A uses rate-monotonic weights. B/C use implicit-deadline sporadic EDF parameters and atomic job-completion notifications, allowing the native workers to skip missed releases. Matching initial phases make the classes compete on wakeup. Use `--tasks-per-cpu`, `--period-ms`, and `--runtime-ms` to change the load.

Results separately report inversions between and within classes, per-class CPU time, and offending class pairs. A waiting worker counts only when it outranks a running worker on a CPU allowed by its affinity. The category times can overlap; the overall inversion time counts their union. Captures use `tester/build/mc2-dynamic-test-<timestamp>`; replay with `python3 tester/run_mc2_dynamic_test.py --analyse-only CAPTURE_DIR`. The test verifies initialization of all four schedulers and traced weights for every worker; missing tracing or premature detach fails analysis. Current non-root JLFP/GEDF initialization uses a self-weight of 100 rather than the configured class weight; this test compares against the configured MC² priorities so it can expose that behavior.

## Wakeup Latency and Migration

```sh
sudo python3 tester/run_jlfp_wakeup_test.py --isolate
```

To measure idle-core wakeup migration, run `sudo python3 tester/run_jlfp_wakeup_test.py` from the repository root. By default, one migratable worker runs for a 50 us CPU budget every 1 ms across all allowed CPUs. Add `--isolate` for the isolated four-CPU comparison. The test matches native blocking, wakeup, and first-execution events, saves `wakeup-results.json`, and reports actual migration ratios and wake-to-run latency. It separately identifies local timer wakeups that followed an observed idle-to-timer transition. Use `--scx-build-path BUILD` to compare scheduler builds and `--analyse-only CAPTURE_DIR` to replay a capture. Opt-in isolation and bandwidth settings restore through the existing helpers.

## Cyclictest Comparisons

The older `build_jlfp_cyclictest.py` builder uses `cyclictest/rt-tests`, cloning a
pinned checkout when it is absent and applying the repository's modified source
in a separate build copy. The staged setup above instead patches upstream source.

For cyclictest comparisons, first build a separate copy that preserves unpinned threads' inherited CPU affinity:

```sh
python3 tester/build_jlfp_cyclictest.py --output-dir tester/build/cyclictest-affinity
sudo python3 tester/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest --isolate --mode migratable --threads 1
sudo python3 tester/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest --isolate --mode migratable --threads 1 --policy other
sudo python3 tester/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest --isolate --mode pinned --threads 4
```

Use `--policy other` for FAIR (SCHED_OTHER) workers with the same isolation and timing settings. JLFP remains attached for this comparison, but its partial-switch mode leaves SCHED_OTHER workers under FAIR. Add `--no-jlfp` for a FAIR or FIFO baseline with sched_ext disabled. EXT workers require JLFP.

To investigate individual outliers, add `--diagnostic-trace --spike-us 100`. This records native scheduler, hrtimer, IRQ, and workqueue events in the private trace instance and logs samples above 100 us with their observed CLOCK_MONOTONIC timestamps in `cyclictest.log`. The trace uses nanoseconds; spike timestamps and latencies use microseconds. Match the worker's timer expiry, wakeup, and first execution to distinguish late timer delivery from runnable scheduling delay. Diagnostic tracing adds overhead, so compare equally traced runs and keep ordinary runs as a reference. These options do not use cyclictest's global `--breaktrace` controls.

The builder leaves the original rt-tests checkout intact and saves its patch, build log, and hashes. The harness explicitly selects CLOCK_MONOTONIC, verifies the actual worker policy, affinity, and timer slack, saves cyclictest JSON/histograms and per-thread percentiles, and disables scheduler trace emissions. It gives SCHED_EXT workers 1 ns timer slack so inherited timer coalescing does not dominate the comparison; use `--timer-slack-ns 50000` to reproduce the usual inherited slack. It holds a temporary 0 us `/dev/cpu_dma_latency` request during the test, releasing it afterward; other power settings stay unchanged. Use `--cpu-dma-latency-us -1` for an untuned comparison, `--policy fifo` to measure ordinary RT latency while JLFP is attached, and `--scx-build-path BUILD` for alternate scheduler builds. On PREEMPT_RT, FIFO sleepers use hard timer delivery while EXT and OTHER sleepers use soft timer delivery; differences include that timer path as well as scheduling. Compare variants serially on the same CPUs with repeated runs; histograms use 1 us buckets and include startup. Existing cgroup workloads and hardware interrupts can still affect the tails.
