## Project Goal

The goal of this project is to provide a framework for implementing realtime schedulers using the latest Linux scheduling features as of kernel version 7.3. Specifically, we utilize Linux's native extendible scheduling framework (sched_ext) with new features such as hierarchical cgroup schedulers, userspace-shared arena memory, and topologically aware CPU to CID mappings, to implement various realtime scheduling policies such as Global Earliest Deadline First. The benefits of using mainline Linux over forks such as LITMUS-RT is maintenance cost: It's a lot easier to update to the newest kernel build and keep the system stable if there's minimal kernel modifications. As such, this project uses kernel modifications sparingly, and most features work without kmods/patches. Additionally, non-realtime sched_ext schedulers such as the community-made Rust userspace schedulers can be used as sub-policies for mixed-criticality scheduling.

## Linux Schedulers Setup

### Setup Environment

clone https://github.com/torvalds/linux.git or git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (linux 7.1 has cgroup subscheduling v3)

install clang-21
make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
install kernel

### Build Schedulers

go to tools/sched_ext

copy everything in `scheds` into `tools/sched_ext`

modify in Makefile:
```
c-sched-targets = scx_simple scx_cpu0 scx_qmap scx_central scx_flatcg scx_userland scx_pair scx_sdt scx_eaf scx_wrr scx_fp
```

To enable/disable tracing, modify `trace_events.h` to define `TRACING` to 1 or 0 respectively.

To limit CPUs, uncomment out the NR_CPU redefine in `trace_events.h`.

Compile the schedulers
```
sudo bear -- make CC="clang-21 -Wno-unused-command-line-argument" CLANG=clang-21 LLVM_STRIP=llvm-strip-21 VMLINUX_BTF=/sys/kernel/btf/vmlinux
```

To ensure scheduler binaries can load schedulers without sudo, change the capabilities
```
find ./build/bin/ -type f -name "scx_*" -executable -exec setcap 'cap_bpf,cap_perfmon=ep' {} \;
```

Additionally, if running without the cgroup_server node, you need to chown /sys/fs/bpf so that the scheduler binaries can access them without root.

Built schedulers can be run like so: `./build/bin/scx_wrr`.

Brief description of schedulers (see their bpf code for more details)

- scx_fp: Fixed Priority Scheduler. Supports both sub cgroups and tasks. Supports job-level fixed priority by calling the `set_weight` bpf program pinned to `/sys/fs/bpf/set_weight` (~0.5s) or by writing to `/sys/fs/bpf/task_weights` and then `sched_yield()` (~50us).

- scx_wrr: Weighted Round Robin Scheduler (per-cpu round robin queues). Only supports sub cgroups, not tasks.

- scx_eaf: FIFO Scheduler (Earliest Arrival First). Only supports tasks.

Example of setting weight via `/sys/fs/bpf/task_weights`
```c
#include <bpf/bpf.h>
#include <fcntl.h>

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

// on thread init
int file_fd = bpf_obj_get("/sys/fs/bpf/task_weights");
uint64_t tid = syscall(SYS_gettid);
int pid_fd = syscall(SYS_pidfd_open, tid, PIDFD_THREAD);

// during update
uint64_t weight = rand() % 100 + 1;
int err = bpf_map_update_elem(file_fd, &pid_fd, &weight, BPF_ANY);
sched_yield(); // task weight only updated on enqueue
```

Example of calling `/sys/fs/bpf/update_weight` from a C program:
```c
#include <bpf/bpf.h>

// on thread init
const char *pin_path = "/sys/fs/bpf/update_weight";
int prog_fd = bpf_obj_get(pin_path);
uint64_t tid = syscall(SYS_gettid);

// during update
uint64_t weight = rand() % 100 + 1;
__u64 bpf_args[2] = { tid, weight };
DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
  .ctx_in = bpf_args,
  .ctx_size_in = sizeof(bpf_args),
);
int err = bpf_prog_test_run_opts(prog_fd, &opts);
```

### Trace Schedulers (WIP)

To trace schedulers with low overheads, we use custom ftrace kernel tracepoints defined in `trace`. Standard scheduler use does not require a kernel module.

Build the optional trace module against the configured, built kernel you will run:

```sh
make -C scheds trace-module KDIR=/path/to/kernel/build
sudo insmod scheds/trace/scxtp.ko
```

The `trace/` BPF API skips event emission when the module is unavailable at scheduler load time. Load the module before loading the scheduler to enable this tracing; loading the module later requires reloading the scheduler. Existing ringbuffer tracing is unchanged.

At the top of `scheds/trace/helpers.h`, various compilation flags are set. These enable specific tracing behavior if set to 1 (disabled if 0). They can also be defined before including `trace/events.bpf.h`.

`SCXTP_TRACING`: This flag enables tracing; no ftrace events will be emitted without this set. By default, low-frequency events record cgroup property changes, sub-scheduler attachment and detachment, and task creation and exit. Combine these with generic scheduling events such as `sched_switch`, `sched_wakeup`, and `sched_wakeup_new` to check scheduler policy behavior, with initial priorities, affinity, and hierarchy recorded.

`SCXTP_HOTPATH_TRACING`: When combined with `SCXTP_TRACING`, hotpath events are emitted. These record task enqueue, CPU selection, and execution transitions. These are intended to replace generic scheduling events so that the captured trace is smaller, with the tradeoff of not capturing external scheduling events. Set `SCXTP_HOTPATH_TRACING` to 1 to enable them.

`SCXTP_BACKTRACE`: This enables the use of callstack dumps (up to current scx op) in the scheduler for easier debugging, and is enabled indepdendent of `SCXTP_TRACING`. The scheduler must implement `SCXTP_FUNC_ENTRY(args...)` and `SCXTP_FUNC_EXIT()` on all function entry/exit locations, which are tracked via per-cpu bpf maps. `SCXTP_BACKTRACE_DUMP()` and `SCXTP_BACKTRACE_DUMP_IF()` are used to dump the callstack via `bpf_printk`, which can be read via `/sys/kernel/debug/tracing/trace_pipe`. As this has significant overheads, it should only be enabled for debugging. For generic scheduler debugging, `bpf_printk()` is usually sufficient if used sparingly.

Note: Only use for functions that are non-reentrant, non-sleeping, since assumes each CPU runs 1 op at a time.

The instrumented stack uses a per-CPU BPF map scoped to one op. Call `SCXTP_BACKTRACE_RESET()` at op entry, then `SCXTP_FUNC_ENTRY("arg=%d", arg)` in each instrumented function and `SCXTP_FUNC_EXIT()` before every return. `SCXTP_FUNC_ENTRY()` also works without arguments. Entry captures the function name and formatted argument values; dumps print the active frames from innermost to outermost. The defaults are 16 frames and 128 bytes per frame, configurable with `SCXTP_BACKTRACE_MAX_DEPTH` and `SCXTP_BACKTRACE_FRAME_SIZE`. Dumps report omitted frames, truncated text, and unmatched exits. When disabled, the map and helpers are omitted, and macro arguments are not evaluated.

This per-CPU stack assumes a non-sleeping, non-reentrant op that remains on the same CPU until exit. Sleepable or nested ops can overwrite another op's frames and must not use this shared stack. Scheduler instrumentation still needs to be added at the desired call sites.

For integration with babeltrace2, use an ftrace to CTF converter such as https://github.com/siemens/bt2-ftrace-to-ctf.

### Limitations and Behavior

By default, the linux kernel supports at most 4 layers of nested schedulers (including root scheduler). This can be configured within the kernel by modifying the `SCX_SUB_MAX_DEPTH` macro.

Must have a root scheduler to have subschedulers, but can have gaps between schedulers. Tasks enqueued to a cgroup without a scheduler get enqueued to the nearest ancestor scheduler.

When a scheduler exits (either by crash or gracefully), its tasks are enqueued into the nearest ancestor scheduler.

As of the release of Linux 7.3, `struct bpf_timer` cannot be used with PREEMPT_RT enabled. Since timers are very useful for realtime systems, a kernel module must be used to bypass this behavior. Slices are not a suitable replacement since they are only enforced in ops.tick and certain scheduler events, rather than using an hrtimer callback. To enable bpf_timer, we can add a patch that adds a workaround that is sufficient for our schedulers but not bpf_timers in general: (TODO: add patch that fix this)

As of the release of 7.3, `sched_class_ext` tasks have lower priority than `sched_class_fair`. This means SCHED_EXT cannot preempt tasks scheduled under the default CFS/EEVDF scheduler, which means running a realtime workload with SCHED_EXT requires careful management of all tasks in the system (either by scheduling them all with SCHED_EXT by omitting the `SCHED_SWITCH_PARTIAL` flag or by using systemd slices / an equivalent CPU partitioning system). The fix to this is to patch the kernel to add a config flag to swap the order of SCX and FAIR: (TODO: add patch that fixes this)

### Measuring Overhead

Enable bpf runtime and run count tracking
```
sudo sysctl -w kernel.bpf_stats_enabled=1
```

Then listing bpf programs will show both runtime in ns and number of calls
```
sudo bpftool prog show
```

Schedulers can also output the mean and worst case latencies of various scheduling logic by specifying a stats output file (`/scx_<policy> -h` for more info).


## Scheduler Manager Setup (Outside of ROS 2)

`sched_manager.py` lives in `tools/`.

The `sched_manager.py` script manages cgroups and SCHED_EXT schedulers without requiring sudo.

An instance is created by the `cgroup_server` ROS2 node in order to manage cgroups and schedulers.

### Dependencies

Python 3

### Use Scheduler Manager CLI

Run `sudo sh tools/perm_setup.sh` to set permissions for `/sys/fs/bpf` and `/sys/fs/cgroup` to allow the current user to create/manage cgroups and access bpf maps. Allows you to run `sched_manager` without sudo.

Run `python3 tools/sched_manager.py` from the repository root to manage the scheduler hierarchy using binaries in `scheds/build`. Build them with `make -C scheds` first.

To use a different build, run `python3 tools/sched_manager.py <scheduler binary dir>`. The directory must contain `scx_jlfp` and `scx_gedf` directly.

NOTE: if you get `ERR: Root cgroup already has attached sub-cgroup /sys/fs/cgroup/<cgroup>. Use --force to overwrite.`

run `echo S | sudo tee /proc/sysrq-trigger` to detach SCHED_EXT schedulers.

### Loading Configuration Files

Example hierarchy defined in `example_cgroup_config.json`.

Format is defined hierarchically, with root as top level and direct subschedulers defined within `subs` field.

Run `load_config -h` for more details from within `sched_manager`.

#### Schedulers have the following fields

`trace_dir`: string, path to the directory to dump the trace output to. file name created by replacing `/` with `__`. If not provided, no trace is written to. Takes precedence over ancestor `trace_dir` fields. Creates if doesn't exist.

`policy`: string, which sched_ext policy to use, supports `scx_jlfp`, `scx_gedf`, and `none`. JLFP supports sub-schedulers; GEDF is a leaf scheduler.

`trace`: boolean, specifies whether to record traces or not. If schedulers were built without tracing, will not trace. Likewise, if schedulers were built with tracing, will incur trace overehads but will not store the trace output anywhere.

`weight`: int, cgroup weight (1 to 10000), can also be set externally using the cgroup fs interface.

`cpus`: string, cpus assigned to this cgroup. For format, see https://docs.kernel.org/admin-guide/cgroup-v2.html#cpuset-interface-files, specifically cpuset.cpus.

## ROS 2 Component Scheduling Setup

TODO
