Clone `https://github.com/jlelli/rt-tests.git` into `./rt-tests` (tested on version 0.84 which hasn't changed in 14 years)

Modify `rt-tests/src/cyclictest/cyclictest.c` to match `modified_cyclictest.c` to allow cyclictest to set its policy to SCHED_EXT

Launch cgroup server with `cyclictest_config.json` as config file

Run one of the `run_cyclictest` scripts (isolated variant moves all tasks on system to other cores to prevent interference, must be modified if system doesn't have at least 16 cores)

If something fails when CPUs isolated, run `isolate_cpus_end.sh` to reset system

Note: `/sys/fs/bpf/ffp_cpu_stats` must be deleted between tests, otherwise stats carry over
