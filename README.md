## Schedulers Setup

### Setup Environment

clone git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (anything 7.1 should have cgroup sub scheduling v3+)

install clang-21
make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
install kernel

go to tools/sched_ext

copy everything in `scheds` into `tools/sched_ext`

modify in Makefile:
```
c-sched-targets = scx_simple scx_cpu0 scx_qmap scx_central scx_flatcg scx_userland scx_pair scx_sdt scx_eaf scx_wrr scx_fp
```

Built schedulers can be run like so: `./build/bin/scx_wrr`

To enable/disable tracing, modify `trace_events.h` to define `TRACING` to 1 or 0 respectively.

To limit CPUs, uncomment out the NR_CPU redefine in `trace_events.h`.

### Build WRR scheduler

```
sudo bear -- make CC="clang-21 -Wno-unused-command-line-argument" CLANG=clang-21 LLVM_STRIP=llvm-strip-21 VMLINUX_BTF=/sys/kernel/btf/vmlinux BPFTOOL=/<path to tj_sched_ext_kernel>/tools/bpf/bpftool/bpftool
```

### Build FP scheduler

```
sudo bear -- make CC="clang-21 -Wno-unused-command-line-argument" CLANG=clang-21 LLVM_STRIP=llvm-strip-21 VMLINUX_BTF=/sys/kernel/btf/vmlinux BPFTOOL=/<path to tj_sched_ext_kernel>/tools/bpf/bpftool/bpftool
```

## Scheduler Manager Setup

### Dependencies

Python 3

Python libraries: `pip install -r requirements.txt`

### Use Scheduler Manager

Run `sched_manager.py <scx build dir>` as a Python 3 program, which acts as an CLI for managing the scheduler hierarchy.

`<scx build dir>` should look something like `/home/.../tj_sched_ext_kernel/tools/sched_ext/` if using tj_sched_ext_kernel repo.

### Configuration Files

Example hierarchy defined in `cgroup_config.json`.

Format is defined hierarchically, with root as top level and direct subschedulers defined within `subs` field.

Run `load_config -h` for more details from within `sched_manager`.

#### Schedulers have the following fields

`trace_dir`: string, path to the directory to dump the trace output to. file name created by replacing `/` with `__`. If not provided, no trace is written to. Takes precedence over ancestor `trace_dir` fields. Creates if doesn't exist.

`policy`: string, which sched_ext policy to use, currently supports scx_fp, scx_wrr, scx_eaf, none.

`trace`: boolean, specifies whether to record traces or not. If schedulers were built without tracing, will not trace. Likewise, if schedulers were built with tracing, will incur trace overehads but will not store the trace output anywhere.

`weight`: int, cgroup weight (1 to 10000), can also be set externally using the cgroup fs interface.

`cpus`: string, cpus assigned to this cgroup. For format, see https://docs.kernel.org/admin-guide/cgroup-v2.html#cpuset-interface-files, specifically cpuset.cpus.