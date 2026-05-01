### SETUP

clone git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (anything 7.1 should have cgroup sub scheduling v3+)

install clang-21
make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
install kernel

go to tools/sched_ext

copy scx_**.c files into tools/sched_ext

modify in Makefile:
```
c-sched-targets = scx_simple scx_cpu0 scx_qmap scx_central scx_flatcg scx_userland scx_pair scx_sdt scx_wrr scx_eaf
$(BINDIR)/scx_wrr: $(INCLUDE_DIR)/scx_eaf.bpf.skel.h
```

build and run WRR scheduler (need sudo):
```
echo "+cpu" | sudo tee /sys/fs/cgroup/cgroup.subtree_control
bear -- make CC="clang-21 -Wno-unused-command-line-argument" CLANG=clang-21 LLVM_STRIP=llvm-strip-21 VMLINUX_BTF=/sys/kernel/btf/vmlinux BPFTOOL=/<path to tj_sched_ext_kernel>/tools/bpf/bpftool/bpftool && ./build/bin/scx_wrr
```