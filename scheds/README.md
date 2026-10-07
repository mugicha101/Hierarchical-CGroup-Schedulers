# Scheduler Implementations

Implementation of various sched_ext cgroup schedulers for Linux 7.3.

## Running the Schedulers

### Requirements

- Linux kernel compatible with the one used in `scheds/setup.sh` (TODO: will be updated to 7.3 tag instead of a commit hash once 7.3 released)
- Development libs/headers for libbpf, libelf, and zlib
- Kernel BTF at /sys/kernel/btf/vmlinux

### Setup

Navigate to `scheds` directory.

Build the schedulers:

```sh
make
```

This puts the scheduler binaries in `./build`.

Give the scheduler permission to run (will ask for sudo permission):

```sh
./setcaps.sh
```

Note: this grants the cap_bpf and cap_perfmon capabilities to the scheduler binaries and changes the owner of `/sys/fs/bpf` to the current user.

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

At the top of `trace/helpers.h`, various compilation flags are set. These enable specific tracing behavior if set to 1 (disabled if 0). They can also be defined before including `trace/events.bpf.h`. In addition to these flags, `scxtp_enabled` must be set to true when loading the scheduler, which is done via the userspace CLI programs by passing the `-t/--trace` flag (ex: `./build/scx_jlfp -t`). Emissions are disabled by default for each scheduler. GEDF accepts the same flag.

`SCXTP_TRACING`: This flag enables the custom scheduler tracepoints (default: 1). Low-frequency events record cgroup property changes, sub-scheduler attachment and detachment, task creation and exit, task weights, affinity, and topology. Combine these with generic scheduling events such as `sched_switch`, `sched_wakeup`, and `sched_wakeup_new` to check scheduler policy behavior.

`SCXTP_HOTPATH_TRACING`: When combined with `SCXTP_TRACING`, hotpath events are emitted. These record task enqueue and execution transitions. These are intended to replace generic scheduling events so that the captured trace is smaller, with the tradeoff of not capturing external scheduling events. Set `SCXTP_HOTPATH_TRACING` to 1 to enable them (default: 0).

Rebuild schedulers after changing these flags. In `sched_manager`, use `attach scx_jlfp <cgroup_path> --trace` or set `"trace": true` for individual schedulers in a configuration file. This setting defaults to false and is not inherited by sub-schedulers. The emission flag does not control generic kernel events or `bpf_printk()` output.

#### Capturing Ftrace Events

Schedulers do not create trace files or configure recording. In another terminal, start an external recorder before attaching the schedulers:

```sh
sudo trace-cmd record -e 'scxtp:*' -o scheduler.dat
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

### GEDF: Global Earliest Deadline First

- Sub-policy of JLFP.
- Uses JLFP's per-cid queues and nmig weight boost for migration-disabled and single-CPU pinned tasks.
- Task GEDF parameters will be stored in `/sys/fs/bpf/scx/task_sporadic_params` and will persist if the task moves to another scheduler instance.
- Deadline-derived priorities will reuse the JLFP `task_weights` map, so task weights should not be set manually.
- Job completions are marked in the memory-mapped `job_completion_flags` bitmap, with one bit per TID. Atomically OR `1ULL << (tid & 63)` into the `u64` word at `flags[tid >> 6]` before sleeping or yielding. The scheduler advances the deadline and clears the bit on wakeup or yield.
- Subschedulers use JLFP ordering.

## File structure

- `scx_<policy>.h` files define shared userspace and BPF structures.
- `scx_<policy>.bpf.h` files define BPF specific logic that can be reused by sub-policies.
- `scx_<policy>_cli.h` files define userspace only logic and structures used in the userspace CLI program that can be reused by sub-policies
- `scx_<policy>.bpf.c` files implement the `sched_ops` for a scheduler. If the policy is abstract only (such as `scx_base`) there is no corresponding `.bpf.c` file.
- `scx_<policy>.c` files implement a userspace CLI program for managing the scheduler implemented in `scx_<policy>.bpf.c`.
- `trace/event_types.h` defines fixed-size event payloads and the shared event list.
- `trace/events.h` defines the kernel ftrace events and their output formats.
- `trace/events.bpf.h` includes the BPF tracing API and declares optional emission kfuncs.
- `trace/helpers.h` provides tracing flags and macros for defining and emitting events.
- `trace/ftrace_setup.h` sets the ftrace system name and trace header inclusion settings.
- `trace/scxtp.c` implements the kernel module that creates tracepoints and registers emission kfuncs for BPF schedulers.
