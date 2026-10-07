## Project Goal

The goal of this project is to provide a framework for implementing realtime schedulers using the latest Linux scheduling features planned for kernel version 7.3. Specifically, we utilize Linux's native extendible scheduling framework (sched_ext) with new features such as hierarchical cgroup schedulers, userspace-shared arena memory, and topologically aware CPU to CID mappings, to implement various realtime scheduling policies such as Global Earliest Deadline First. The benefits of using mainline Linux over forks such as LITMUS-RT is maintenance cost: It's a lot easier to update to the newest kernel build and keep the system stable if there's minimal kernel modifications. As such, this project uses kernel modifications sparingly, and most features work without kmods/patches. Additionally, non-realtime sched_ext schedulers such as the community-made Rust userspace schedulers can be used as sub-policies for mixed-criticality scheduling.

## Linux Schedulers Setup

See the scheduler README for:

- [Kernel environment setup](scheds/README.md#setup-environment).
- [Dependencies, build instructions, and capability setup](scheds/README.md#running-the-schedulers).
- [Scheduling policies and task-weight updates](scheds/README.md#scheduling-policies).
- [Tracing setup and capture](scheds/README.md#tracing).
- [Limitations and behavior](scheds/README.md#limitations-and-behavior).
- [Measuring overhead](scheds/README.md#measuring-overhead).

## Scheduler Manager Setup (Outside of ROS 2)

`sched_manager.py` lives in `tools/`.

The `sched_manager.py` script manages cgroups and SCHED_EXT schedulers without requiring sudo.

An instance is created by the `cgroup_server` ROS2 node in order to manage cgroups and schedulers.

### Dependencies

Python 3

### Use Scheduler Manager CLI

Run `sudo sh tools/perm_setup.sh` to set permissions for `/sys/fs/bpf` and `/sys/fs/cgroup` to allow the current user to create/manage cgroups and access bpf maps. Allows you to run `sched_manager` without sudo.

Run `python3 tools/sched_manager.py` from the repository root to manage the scheduler hierarchy using binaries in `scheds/build`. Follow the [scheduler build instructions](scheds/README.md#setup) first.

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
