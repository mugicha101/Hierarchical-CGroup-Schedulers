Clone `https://git.kernel.org/pub/scm/utils/rt-tests/rt-tests.git` into `./rt-tests`
and check out revision `62da2befac98f811af8e56f2b7992fb09faa33d6`.

Copy `modified_cyclictest.c` to `rt-tests/src/cyclictest/cyclictest.c` and build
with `make -C rt-tests cyclictest`. This file contains the EXT/DEADLINE support,
optional experiment startup gate and inherited-affinity guard. No header changes
are required. The tester's experiment and diagnostic builders use this same source
in private builds; see `../tester/README.md` for those commands.

Launch cgroup server with `cyclictest_config.json` as config file

Run one of the `run_cyclictest` scripts (isolated variant moves all tasks on system to other cores to prevent interference, must be modified if system doesn't have at least 16 cores)

If something fails when CPUs isolated, run `isolate_cpus_end.sh` to reset system

Note: `/sys/fs/bpf/ffp_cpu_stats` must be deleted between tests, otherwise stats carry over
