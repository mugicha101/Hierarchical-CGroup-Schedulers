SETUP

clone git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git and select branch with cgroup sub-scheduling (anything 7.1 should have cgroup sub scheduling v3+)

modify in Makefile:
c-sched-targets = scx_simple scx_cpu0 scx_qmap scx_central scx_flatcg scx_userland scx_pair scx_sdt scx_wrr scx_eaf
$(BINDIR)/scx_wrr: $(INCLUDE_DIR)/scx_eaf.bpf.skel.h

make sure pahole is 1.31+ since uses KF_IMPLICIT_ARGS
