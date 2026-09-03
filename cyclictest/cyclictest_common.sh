#!/bin/sh

secs=${1:-10}

# no cpu pinning
echo $$ > /sys/fs/cgroup/foo/cgroup.procs && exec ./rt-tests/cyclictest \
	-t \
    -i 1000 \
    -l 500000 \
    -m \
    -p 0 \
    -D "${secs}s" \
    --policy=ext

# trace spikes

# echo $$ > /sys/fs/cgroup/foo/cgroup.procs && ./rt-tests/cyclictest \
#     -t \
#     -i 1000 \
#     -l 500000 \
#     -p 0 \
#     -D "${secs}s" \
#     -m \
#     --spike=1000 \
#     --spike-nodes=10000 \
#     --policy=ext

# cpu pinning + smi detection (only works on some cpus)
# echo $$ > /sys/fs/cgroup/foo/cgroup.procs && exec ./rt-tests/cyclictest \
#     -t \
#     -i 1000 \
#     -l 500000 \
#     -m \
#     -p 0 \
#     -D "${secs}s" \
#     --smi \
#     -a \
#     --policy=ext
