## Project Goal

The goal of this project is to provide a framework for implementing realtime schedulers using the latest Linux scheduling features planned for kernel version 7.3. Specifically, we utilize Linux's native extendible scheduling framework (sched_ext) with new features such as hierarchical cgroup schedulers, userspace-shared arena memory, and topologically aware CPU to CID mappings, to implement various realtime scheduling policies such as Global Earliest Deadline First. The benefits of using mainline Linux over forks such as LITMUS-RT is maintenance cost: It's a lot easier to update to the newest kernel build and keep the system stable if there's minimal kernel modifications. As such, this project uses kernel modifications sparingly, and most features work without kmods/patches. Additionally, non-realtime sched_ext schedulers such as the community-made Rust userspace schedulers can be used as sub-policies for mixed-criticality scheduling.

## Linux Schedulers Setup

### Setup Environment

clone https://github.com/torvalds/linux.git or git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (linux 7.1 has cgroup subscheduling v3)

install clang-21
make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
install kernel

### Build Schedulers

go to the repository root

For a fresh clone, install Git, make, GCC, bpftool, and development libraries/headers for libbpf, libelf, and zlib. Kernel BTF must be available at `/sys/kernel/btf/vmlinux`.

Fetch the sched_ext headers before the first build
```
(cd scheds && ./setup.sh)
```

Compile the schedulers
```
make -C scheds CLANG=clang-21
```

To ensure scheduler binaries can load schedulers without sudo, run the setup script (will ask for sudo permission)
```
(cd scheds && ./setcaps.sh)
```

This grants the cap_bpf and cap_perfmon capabilities to the scheduler binaries and sets up permissions for `/sys/fs/bpf/scx`.

Built schedulers can be run like so: `./scheds/build/scx_jlfp`.

Brief description of schedulers (see their bpf code for more details)

- scx_jlfp: Job-Level Fixed Priority Scheduler. Supports both sub cgroups and tasks. Supports job-level fixed priority by writing to `/sys/fs/bpf/scx/task_weights` and then `sched_yield()`.

- scx_gedf: Global Earliest Deadline First Scheduler. Only supports tasks.

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

### Tracing Schedulers

See [Tracing in the scheduler README](scheds/README.md#tracing) for debugging, trace module setup, emission controls, and external recording and parsing.

### Limitations and Behavior

By default, the linux kernel supports at most 4 layers of nested schedulers (including root scheduler). This can be configured within the kernel by modifying the `SCX_SUB_MAX_DEPTH` enum constant.

Must have a root scheduler to have subschedulers, but can have gaps between schedulers. Tasks enqueued to a cgroup without a scheduler get enqueued to the nearest ancestor scheduler.

When a scheduler exits (either by crash or gracefully), its tasks are enqueued into the nearest ancestor scheduler.

As of the release of Linux 7.3, `struct bpf_timer` cannot be used with PREEMPT_RT enabled. Since timers are very useful for realtime systems, a kernel patch must be used to bypass this behavior. Slices are not a suitable replacement since they are only enforced in ops.tick and certain scheduler events, rather than using an hrtimer callback. To enable bpf_timer, we can add a patch that adds a workaround that is sufficient for our schedulers but not bpf_timers in general: (TODO: add patch that fix this)

As of the release of 7.3, `sched_class_ext` tasks have lower priority than `sched_class_fair`. This means SCHED_EXT cannot preempt tasks scheduled under the default CFS/EEVDF scheduler, which means running a realtime workload with SCHED_EXT requires careful management of all tasks in the system (either by scheduling them all with SCHED_EXT by omitting the `SCX_OPS_SWITCH_PARTIAL` flag or by using systemd slices / an equivalent CPU partitioning system). The fix to this is to patch the kernel to add a config flag to swap the order of SCX and FAIR: (TODO: add patch that fixes this)

### Measuring Overhead

Enable bpf runtime and run count tracking
```
sudo sysctl -w kernel.bpf_stats_enabled=1
```

Then listing bpf programs will show both runtime in ns and number of calls
```
sudo bpftool prog show
```

Schedulers can also output the mean (via sum/count) and worst case latencies of various scheduling logic by specifying a stats output file (`./scheds/build/scx_<policy> -h` for more info).


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

`policy`: string, which sched_ext policy to use, supports `scx_jlfp`, `scx_gedf`, and `none`. JLFP supports sub-schedulers; GEDF is a leaf scheduler.

`trace`: boolean, enables custom ftrace event emissions for this scheduler (default: false). See [Tracing in the scheduler README](scheds/README.md#tracing).

`weight`: int, cgroup weight (1 to 10000), can also be set externally using the cgroup fs interface.

`cpus`: string, cpus assigned to this cgroup. For format, see https://docs.kernel.org/admin-guide/cgroup-v2.html#cpuset-interface-files, specifically cpuset.cpus.

## ROS 2 Component Scheduling Setup

`rosrtmc` is currently unfinished code for integrating cgroup scheduling into ROS2.
