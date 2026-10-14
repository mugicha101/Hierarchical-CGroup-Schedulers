# Scheduler Implementations

Implementation of various sched_ext cgroup schedulers for Linux 7.3.

## Running the Schedulers

### Requirements

- Linux kernel compatible with the one used in `scheds/setup.sh` (TODO: will be updated to 7.3 tag instead of a commit hash once 7.3 released)
- Git, make, GCC, bpftool, and clang-21
- Development libs/headers for libbpf, libelf, and zlib
- Kernel BTF at /sys/kernel/btf/vmlinux

### Setup Environment

clone https://github.com/torvalds/linux.git or git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (linux 7.1 has cgroup subscheduling v3)

install clang-21
make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
install kernel

### Setup

Navigate to `scheds` directory.

Fetch the sched_ext headers before the first build:

```sh
./setup.sh
```

Build the schedulers:

```sh
make CLANG=clang-21
```

This puts the scheduler binaries and the `check_tracing` helper in `./build`.

Give the scheduler permission to run (will ask for sudo permission):

```sh
./setcaps.sh
```

This grants the cap_bpf and cap_perfmon capabilities to the scheduler binaries and sets up permissions for `/sys/fs/bpf/scx`.

If tracing is enabled for a scheduler (`SCXTP_TRACING=1`), it also grants cap_sys_admin. This capability is needed for module BTF discovery, otherwise custom ftrace emissions will fail silently.

Note: these capabilities is not meant for actual security, just to ensure a bug in the scheduler has less places it can reach.

Note: Rerun `setcaps.sh` after each rebuild of the scheduler binaries.

### Run

To see how to attach a specific scheduler with a userspace program, run `./build/scx_<policy> -h`.

### Tracing

#### General Debugging

For general scheduler debugging without needing a kernel module, use the native `bpf_printk()` macro. Its output is emitted through ftrace as `bpf_trace:bpf_trace_printk` and can be read from `/sys/kernel/tracing/trace_pipe`. This output is independent of the per-scheduler `--trace` flag.

#### Structured Scheduler Tracepoints

To trace BPF schedulers with low overhead, we use custom ftrace kernel tracepoints defined in `trace/`, which requires a kernel module to work. Without the kernel module loaded, trace emissions will become no-ops at scheduler load-time. This kernel module is used to add custom kernel tracepoints, since forwarding tracepoints to userspace would add overhead and complexity. Events are fixed size and written to per-CPU buffers.

Build and load the kernel module before starting a scheduler as follows:

```sh
make trace-module KDIR=/path/to/kernel/build
sudo insmod trace/scxtp.ko
```

Schedulers still work without the module. If the module is loaded later, restart the scheduler to enable tracing.

When running without sudo, run `./setcaps.sh` after building the scheduler. Libbpf needs cap_sys_admin to discover the module's emission kfuncs through BTF. Without it, the optional kfuncs can remain unresolved and custom events will be skipped even with the module loaded and `-t` passed.

At the top of `trace/helpers.h`, various compilation flags are set. These enable specific tracing behavior if set to 1 (disabled if 0). They can also be defined before including `trace/events.bpf.h`. In addition to these flags, `scxtp_enabled` must be set to true when loading the scheduler, which is done via the userspace CLI programs by passing the `-t/--trace` flag (ex: `./build/scx_jlfp -t`). Emissions are disabled by default for each scheduler. GEDF accepts the same flag.

`SCXTP_TRACING`: This flag enables the custom scheduler tracepoints (default: 1). Low-frequency events record cgroup property changes, sub-scheduler attachment and detachment, task creation and exit, task weights, affinity, and topology. Combine these with generic scheduling events such as `sched_switch`, `sched_wakeup`, and `sched_wakeup_new` to check scheduler policy behavior.

`SCXTP_HOTPATH_TRACING`: When combined with `SCXTP_TRACING`, hotpath events are emitted. These record task enqueue and execution transitions. These are intended to replace generic scheduling events so that the captured trace is smaller, with the tradeoff of not capturing external scheduling events. Set `SCXTP_HOTPATH_TRACING` to 1 to enable them (default: 0).

Build schedulers with existing hotpath events enabled using `make -W scx_jlfp.bpf.h SCXTP_HOTPATH_TRACING=1` from `scheds/`. Use the same command with `SCXTP_HOTPATH_TRACING=0` to disable them. After changing event definitions, rebuild and reload the trace module with schedulers and recorders stopped before starting a capture.

JLFP/GEDF treat timer-occupied CPUs as unavailable through the switch observer. A same-core wakeup can bypass normal placement once when a per-CPU FIFO/RR kthread entered from idle, the local/global/per-CID queues are empty, and no preemption reservation exists. The observer preserves this idle origin only across qualifying kthread switches; the handoff consumes it and reserves the CPU before insertion. Other wakeups use normal priority selection. Queue counts are snapshots, so the shortcut retains the existing dispatch-race tradeoff. Running-weight metadata uses the reserved misc bits without changing the pinned map layout; rebuild JLFP and GEDF together before attaching a hierarchy.

Workers preempted with slice remaining retain their cached CPU weight until the next execution state replaces it; exhausted running workers return to their priority DSQ instead of selecting another local placement. On starting migratable work, a nonempty global queue's head is checked for a higher eligible task and triggers preemption when needed. These checks reduce long dynamic inversions while retaining finite slices and the existing shard-lock model. Both tests save scheduler output in `scheduler.log` if setup or cleanup fails, including verifier diagnostics.

Rebuild schedulers after changing these flags. In `sched_manager`, use `attach scx_jlfp <cgroup_path> --trace` or set `"trace": true` for individual schedulers in a configuration file. This setting defaults to false and is not inherited by sub-schedulers. The emission flag does not control generic kernel events or `bpf_printk()` output.

The JLFP test reports capture stages and offline analysis progress. From the repository root, use `python3 tester/run_jlfp_test.py --analyse-only tester/build/jlfp-test-<timestamp>` to analyse a saved capture without running workers again. The directory must contain `trace.dat` and `run.json`; this rewrites `analysis.log` and `results.json`. Saved captures containing placement diagnostics are still supported; those events are skipped by the inversion calculation.

To test changing runnable priorities, run `sudo python3 tester/run_jlfp_dynamic_test.py`. By default, two weighted workers per allowed CPU share the full allowed CPU set, each consuming a 10 ms CPU budget per 20 ms period before sleeping. Releases are staggered across the period; preemption does not consume the CPU budget, and missed releases are skipped. Adjust `--runtime-ms`, `--period-ms`, `--tasks-per-cpu`, `--warmup`, and `--duration` to vary the load. The test uses native sleep/wakeup events to exclude blocked workers from priority comparisons and reports inversion time, longest inversion, and worker wakeup/block counts. Captures use `tester/build/jlfp-dynamic-test-<timestamp>` and save the period, budget, and phases in `run.json`; use `--analyse-only CAPTURE_DIR` to reanalyse them.

The static, dynamic, wakeup, and latency test scripts default to all CPUs allowed by their inherited affinity and assume the environment is already configured to remove noise. They leave controller affinity and bandwidth server runtimes unchanged and do not create `other` or migrate background processes. Workers are still placed in the root cgroup for JLFP. The static and dynamic tests default to two workers per allowed CPU; wakeup and latency tests retain their explicit worker/thread counts. Wakeup and latency tests accept `--cpus` to override the worker CPU set without enabling isolation.

Static, dynamic, and wakeup tests use the native busy-loop worker in `tester/work.c`; Python handles setup and trace analysis. They automatically build `tester/build/jlfp_worker` with `cc`, pthread support, and libbpf when missing or older than the source. Each worker is a separate C process that blocks until the controller installs affinity, weight, and SCHED_EXT policy. Periodic workloads use absolute monotonic sleeps, thread CPU-time budgets, staggered phases, and skipped missed releases. The original standalone pthread workload remains available through `tester/build.sh`; the latency harness already uses C cyclictest workers.

Add `--isolate` to restrict workers to the last four allowed CPUs (the configured shard size) and set up cyclictest's `other` arrangement. Wakeup and latency `--cpus` overrides still apply. Isolation requires a CPU outside the worker set for the controller. The scripts create `/sys/fs/cgroup/other` with its CPU set limited to the non-worker CPUs, move root processes there before starting workers, and explicitly place workers in the root cgroup. PID 1, the controller, and kernel threads remain in root when already there; the controller runs on non-worker CPUs. Cleanup returns processes from `other` to root and removes the test's cgroup, including on failure or interruption. An existing `other` cgroup causes setup to fail rather than overwrite it. `cpu_isolation.json` and `run.json` record the CPU set and moved/skipped PIDs. Existing cgroup hierarchies and their CPU sets are left unchanged, so their tasks and per-CPU kernel threads can still contend with workers.

With `--isolate`, the scripts temporarily disable the FAIR deadline server and SCX bandwidth server on the worker CPUs by setting their debugfs runtimes to 0. They save their original settings in `bandwidth_servers.json` and `run.json`, then restore the runtimes after scheduler detach, including on failure or interruption. Run the tests with sudo for BPF and ftrace; isolation also requires the `fair_server` and `ext_server` controls under `/sys/kernel/debug/sched`. Use `--isolate --keep-bandwidth-servers` for isolation with the original bandwidth settings.

To measure idle-core wakeup migration, run `sudo python3 tester/run_jlfp_wakeup_test.py` from the repository root. By default, one migratable worker runs for a 50 us CPU budget every 1 ms across all allowed CPUs. Add `--isolate` for the isolated four-CPU comparison. The test matches native blocking, wakeup, and first-execution events, saves `wakeup-results.json`, and reports actual migration ratios and wake-to-run latency. It separately identifies local timer wakeups that followed an observed idle-to-timer transition. Use `--scx-build-path BUILD` to compare scheduler builds and `--analyse-only CAPTURE_DIR` to replay a capture. Opt-in isolation and bandwidth settings restore through the existing helpers.

For cyclictest comparisons, first build a separate copy that preserves unpinned threads' inherited CPU affinity:

```sh
python3 tester/build_jlfp_cyclictest.py --output-dir tester/build/cyclictest-affinity
sudo python3 tester/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest --isolate --mode migratable --threads 1
sudo python3 tester/run_jlfp_latency_test.py --cyclictest tester/build/cyclictest-affinity/cyclictest --isolate --mode pinned --threads 4
```

The builder leaves the original rt-tests checkout intact and saves its patch, build log, and hashes. The harness verifies the actual worker policy, affinity, and timer slack, saves cyclictest JSON/histograms and per-thread percentiles, and disables scheduler trace emissions. It gives SCHED_EXT workers 1 ns timer slack so inherited timer coalescing does not dominate the comparison; use `--timer-slack-ns 50000` to reproduce the usual inherited slack. It holds a temporary 0 us `/dev/cpu_dma_latency` request during the test, releasing it afterward; other power settings stay unchanged. Use `--cpu-dma-latency-us -1` for an untuned comparison, `--policy fifo` to measure ordinary RT latency while JLFP is attached, and `--scx-build-path BUILD` for alternate scheduler builds. Compare variants serially on the same CPUs with repeated runs; histograms use 1 us buckets and include startup. Existing cgroup workloads and hardware interrupts can still affect the tails.

#### Capturing Ftrace Events

Schedulers do not create trace files or configure recording. In another terminal, start an external recorder before attaching the schedulers:

```sh
sudo trace-cmd record -e 'scxtp:*' -e 'bpf_trace:bpf_trace_printk' -o scheduler.dat
```

Stop recording with Ctrl-C after the schedulers exit, then read the file with `trace-cmd report -i scheduler.dat`. Add generic kernel events such as `sched:sched_switch`, `sched:sched_wakeup`, and `sched:sched_wakeup_new` with additional `-e` options when needed.

For integration with Babeltrace2, use an ftrace to CTF converter such as [bt2-ftrace-to-ctf](https://github.com/siemens/bt2-ftrace-to-ctf).

## Scheduling Policies

### JLFP: Job-Level Fixed Priority

- Tasks are prioritized by their weights in `/sys/fs/bpf/scx/task_weights`.
- Tasks on different cgroups are prioritized by cgroup weight first, then task weight.
- We assume task cpu affinity masks are either a superset of the cgroup's affinity mask or pinned to a single logical cpu (includes tasks in non-migrateable sections).
- Pinned / non-migrateable tasks are prioritized over migrateable tasks if they are both handled by the same scheduler instance.
- Tasks that cannot run directly are considered pending and put on one of two weight-ordered dsqs:
  - Per CPU DSQ for non-migrateable tasks.
  - Global DSQ for migrateable tasks.
- Dispatch checks pending task dsqs and favors a runnable `prev` if highest pending task has equal weight.
- Weights can be updated by updating `task_weights` and yielding/re-enqueuing.
- Subschedulers are prioritized by their cgroup weights set via `/sys/fs/cgroup/.../cpu.weight`.
- Subscheduler cgroups must have lower weights than parent cgroups, which means a cgroup's own tasks always take precedence over sub-scheduler tasks. This allows dispatch to skip sub-scheduler dispatch logic when tasks exist.

#### Updating Task Weights

Example of setting weight via `/sys/fs/bpf/scx/task_weights`

```c
#include <bpf/bpf.h>
#include <fcntl.h>

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

// on thread init
int file_fd = bpf_obj_get("/sys/fs/bpf/scx/task_weights");
uint64_t tid = syscall(SYS_gettid);
int pid_fd = syscall(SYS_pidfd_open, tid, PIDFD_THREAD);

// during update
uint64_t weight = rand() % 100 + 1;
int err = bpf_map_update_elem(file_fd, &pid_fd, &weight, BPF_ANY);
// task weight refreshed on selection, enqueue, or dispatch
sched_yield();
```

### GEDF: Global Earliest Deadline First

GEDF is a leaf scheduler and only supports tasks.

- Sub-policy of JLFP.
- Uses JLFP's per-cid queues and nmig weight boost for migration-disabled and single-CPU pinned tasks.
- Task GEDF parameters will be stored in `/sys/fs/bpf/scx/task_sporadic_params` and will persist if the task moves to another scheduler instance.
- Deadline-derived priorities will reuse the JLFP `task_weights` map, so task weights should not be set manually.
- Job completions are marked in the memory-mapped `job_completion_flags` bitmap, with one bit per TID. Atomically OR `1ULL << (tid & 63)` into the `u64` word at `flags[tid >> 6]` before sleeping or yielding. The scheduler advances the deadline and clears the bit on wakeup or yield.
- Subschedulers use JLFP ordering.

## Limitations and Behavior

By default, the linux kernel supports at most 4 layers of nested schedulers (including root scheduler). This can be configured within the kernel by modifying the `SCX_SUB_MAX_DEPTH` enum constant.

Must have a root scheduler to have subschedulers, but can have gaps between schedulers. Tasks enqueued to a cgroup without a scheduler get enqueued to the nearest ancestor scheduler.

When a scheduler exits (either by crash or gracefully), its tasks are enqueued into the nearest ancestor scheduler.

As of the release of Linux 7.3, `struct bpf_timer` cannot be used with PREEMPT_RT enabled. Since timers are very useful for realtime systems, a kernel patch must be used to bypass this behavior. Slices are not a suitable replacement since they are only enforced in ops.tick and certain scheduler events, rather than using an hrtimer callback. To enable bpf_timer, we can add a patch that adds a workaround that is sufficient for our schedulers but not bpf_timers in general: (TODO: add patch that fix this)

As of the release of 7.3, `sched_class_ext` tasks have lower priority than `sched_class_fair`. This means SCHED_EXT cannot preempt tasks scheduled under the default CFS/EEVDF scheduler, which means running a realtime workload with SCHED_EXT requires careful management of all tasks in the system (either by scheduling them all with SCHED_EXT by omitting the `SCX_OPS_SWITCH_PARTIAL` flag or by using systemd slices / an equivalent CPU partitioning system). The fix to this is to patch the kernel to add a config flag to swap the order of SCX and FAIR: (TODO: add patch that fixes this)

## Measuring Overhead

### Average BPF Struct Ops Latency

Enable BPF runtime and run count tracking before running the workload:

```sh
previous_bpf_stats=$(sysctl -n kernel.bpf_stats_enabled)
sudo sysctl -w kernel.bpf_stats_enabled=1
```

While the scheduler is attached, list its BPF programs:

```sh
sudo bpftool prog show
```

Each callback has its own program ID. `run_time_ns` is the accumulated runtime in nanoseconds, and `run_cnt` is the number of calls. The average runtime is `run_time_ns / run_cnt` when `run_cnt` is nonzero. For a specific measurement interval, read the counters before and after the workload and use `delta(run_time_ns) / delta(run_cnt)`. Use `sudo bpftool prog show id <ID>` to inspect a single callback before the scheduler detaches.

Tracking adds overhead to BPF execution. Restore the previous setting afterward in the same shell:

```sh
sudo sysctl -w kernel.bpf_stats_enabled="$previous_bpf_stats"
```

See the [bpftool prog documentation](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-prog.rst) for the runtime counters.

### Scheduling Logic Latency

Schedulers can also output timings for selected scheduling logic using `-s/--stats PATH`:

```sh
./build/scx_jlfp -s jlfp_stats.json
```

Run the workload, then stop the scheduler with Ctrl-C to write the JSON file. GEDF accepts the same option. The file contains one object per CID, with `n` (sample count), `sum` (total nanoseconds), and `max` (maximum observed nanoseconds) for each measured section. Compute the mean as `sum / n` when `n` is nonzero. To combine CIDs, add their counts and sums and take the largest maximum.

These timings cover sections such as CID selection, task and sub-scheduler dispatch, and pending-order updates. They can overlap, so their sums should not be added together to estimate total scheduler overhead. Measurement is already compiled into the scheduling logic; `-s` controls saving the results and does not require `-t` or the trace module. The maximum is an observed value, not a worst-case bound.

### Cyclictest

Cyclictest measures the delay between a timer's expected wakeup and the test thread actually running. This includes timer, interrupt, and scheduling delays, rather than just BPF execution time.

To test JLFP/GEDF, run the measurement threads with `SCHED_EXT` inside the managed cgroup. These schedulers use `SCX_OPS_SWITCH_PARTIAL`, so threads using `SCHED_OTHER` or `SCHED_FIFO` do not exercise their scheduling policy. The [modified cyclictest](../cyclictest/modified_cyclictest.c) supports `--policy=ext`; the existing scripts in `cyclictest/` use it. Cyclictest reports microseconds by default, or nanoseconds with `-N`.

Keep the workload, CPU affinity, and tracing settings consistent when comparing runs.

## File structure

- `scx_<policy>.h` files define shared userspace and BPF structures.
- `scx_<policy>.bpf.h` files define BPF specific logic that can be reused by sub-policies.
- `scx_<policy>_cli.h` files define userspace only logic and structures used in the userspace CLI program that can be reused by sub-policies
- `scx_<policy>.bpf.c` files implement the `sched_ops` for a scheduler. If the policy is abstract only (such as `scx_base`) there is no corresponding `.bpf.c` file.
- `scx_<policy>.c` files implement a userspace CLI program for managing the scheduler implemented in `scx_<policy>.bpf.c`.
- `trace/check_tracing.c` reads the compiled tracing setting for each scheduler so `setcaps.sh` can select its capabilities.
- `trace/event_types.h` defines fixed-size event payloads and the shared event list.
- `trace/events.h` defines the kernel ftrace events and their output formats.
- `trace/events.bpf.h` includes the BPF tracing API and declares optional emission kfuncs.
- `trace/helpers.h` provides tracing flags and macros for defining and emitting events.
- `trace/ftrace_setup.h` sets the ftrace system name and trace header inclusion settings.
- `trace/scxtp.c` implements the kernel module that creates tracepoints and registers emission kfuncs for BPF schedulers.
