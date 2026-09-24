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

## Scheduling Policies

### Terminology

- Sub-policies extend other policies, such as GEDF extending JLFP.
- Leaf schedulers only operate on tasks, no sub-scheduler support.
- Hierarchical schedulers operate on both tasks and sub-schedulers.

### JLFP: Job-Level Fixed Priority (hierarchical)

- Tasks are prioritized by their weights in `/sys/fs/bpf/scx/task_weights`.
- Tasks on different cgroups are prioritized by cgroup weight first, then task weight.
- Weights can be updated by updating `task_weights` and yielding/re-enqueuing.
- Subschedulers are prioritized by their cgroup weights set via `/sys/fs/cgroup/.../cpu.weight`.
- Subscheduler cgroups must have lower weights than parent cgroups, which means a cgroup's own tasks always take precedence over sub-scheduler tasks. This allows dispatch to skip sub-scheduler dispatch logic when tasks exist.

### GEDF: Global Earliest Deadline First (leaf)

- Sub-policy of JLFP.
- Task GEDF parameters will be stored in `/sys/fs/bpf/scx/task_sporadic_params` and will persist if the task moves to another scheduler instance.
- Deadline-derived priorities will reuse the JLFP `task_weights` map, so task weights should not be set manually.
- Job completions are marked by settings a flag in a memmapped BPF array with tid as index. Internally represented as u64 array, but userspace should index assuming a u8 array. These completion are handled on the next runnable transition (after task sleeps), or the next yield (if task doesn't sleep).

## File structure

- `scx_<policy>.h` files define shared userspace and BPF structures.
- `scx_<policy>.bpf.h` files define BPF specific logic that can be reused by sub-policies.
- `scx_<policy>_cli.h` files define userspace only logic and structures used in the userspace CLI program that can be reused by sub-policies
- `scx_<policy>.bpf.c` files implement the `sched_ops` for a scheduler. If the policy is abstract only (such as `scx_base`) there is no corresponding `.bpf.c` file.
- `scx_<policy>.c` files implement a userspace CLI program for managing the scheduler implemented in `scx_<policy>.bpf.c`.