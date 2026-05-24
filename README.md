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

Built schedulers can be run like so: `./build/bin/scx_wrr`.

Brief description of schedulers (see their bpf code for more details)

- scx_fp: Fixed Priority Scheduler. Supports both sub cgroups and tasks. Supports job-level fixed priority by calling the `set_weight` bpf program pinned to `/sys/fs/bpf/set_weight` (~0.5s) or by writing to `/sys/fs/bpf/task_weights` and then `sched_yield()` (~50us).

- scx_wrr: Weighted Round Robin Scheduler (per-cpu round robin queues). Only supports sub cgroups, not tasks.

- scx_eaf: FIFO Scheduler (Earliest Arrival First). Only supports tasks.

Example of setting weight via `/sys/fs/bpf/task_weights`
```c
int file_fd = bpf_obj_get("/sys/fs/bpf/task_weights");
int err = bpf_map_update_elem(file_fd, &pid_fd, &weight, BPF_ANY);
sched_yield(); // task weight only updated on enqueue
```

Example of calling `set_weight` from a C program:
```c
#include <bpf/bpf.h>
...
const char *pin_path = "/sys/fs/bpf/update_weight";
int prog_fd = bpf_obj_get(pin_path);
uint64_t tid = syscall(SYS_gettid);
uint64_t weight = rand() % 100 + 1;
__u64 bpf_args[2] = { tid, weight };
DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
  .ctx_in = bpf_args,
  .ctx_size_in = sizeof(bpf_args),
);
int err = bpf_prog_test_run_opts(prog_fd, &opts);
```

TODO: implement weight change + conditional yielding by using mmaped arrays
- array mapping cpu -> running cgroup weight + pid (to determine which cgroup weight + cpu a pid is mapped to)
- array mapping cgroup weight -> max weight in system + cpu set
- ringbuffer to handle weight update requests on enqueue in any FP scheduler

### Cgroup Hierarchical Scheduler Limitations and Behavior

By default, the linux kernel supports at most 4 layers of nested schedulers (including root scheduler). This can be configured within the kernel by modifying the `SCX_SUB_MAX_DEPTH` macro.

Must have a root scheduler to have subschedulers, but can have gaps between schedulers.

Tasks enqueued to a cgroup without a scheduler get enqueued to the nearest ancestor scheduler.

Due to limitations with the current v3 patchset, `clone3` with flag `CLONE_INTO_CGROUP` must be used to enqueue into a cgroup subscheduler. Using fork or trying to write to `cgroup.procs` will result in enqueueing to the root.

When a scheduler exits (either by crash or gracefully), its tasks are enqueued into the nearest ancestor scheduler.

With PREEMPT_RT enabled, `struct bpf_timer` cannot be used. This breaks `scx_wrr`.

### Measuring Overhead

Enable bpf runtime and run count tracking
```
sudo sysctl -w kernel.bpf_stats_enabled=1
```

Then listing bpf programs will show both runtime in ns and number of calls
```
sudo bpftool prog show
```


## Scheduler Manager Setup (Outside of ROS 2)

`cd rosrtmc/src/cgroup_server/cgroup_server`

The `sched_manager.py` script manages cgroups and SCHED_EXT schedulers without requiring sudo.

An instance is created by the `cgroup_server` ROS2 node in order to manage cgroups and schedulers.

### Dependencies

Python 3

### Use Scheduler Manager CLI

Run `sudo sh perm_setup.sh` to set permissions for `/sys/fs/bpf` and `/sys/fs/cgroup` to allow the current user to create/manage cgroups and access bpf maps. Allows you to run `sched_manager` without sudo.

Run `sched_manager.py <scx build dir>` as a Python 3 program, which acts as an CLI for managing the scheduler hierarchy.

`<scx build dir>` should look something like `/home/.../linux/tools/sched_ext/` if using the mainline kernel.

### Loading Configuration Files

Example hierarchy defined in `example_cgroup_config.json`.

Format is defined hierarchically, with root as top level and direct subschedulers defined within `subs` field.

Run `load_config -h` for more details from within `sched_manager`.

#### Schedulers have the following fields

`trace_dir`: string, path to the directory to dump the trace output to. file name created by replacing `/` with `__`. If not provided, no trace is written to. Takes precedence over ancestor `trace_dir` fields. Creates if doesn't exist.

`policy`: string, which sched_ext policy to use, currently supports scx_fp, scx_wrr, scx_eaf, none.

`trace`: boolean, specifies whether to record traces or not. If schedulers were built without tracing, will not trace. Likewise, if schedulers were built with tracing, will incur trace overehads but will not store the trace output anywhere.

`weight`: int, cgroup weight (1 to 10000), can also be set externally using the cgroup fs interface.

`cpus`: string, cpus assigned to this cgroup. For format, see https://docs.kernel.org/admin-guide/cgroup-v2.html#cpuset-interface-files, specifically cpuset.cpus.

## ROS 2 Component Scheduling Setup

TODO