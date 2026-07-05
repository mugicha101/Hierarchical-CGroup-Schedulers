secs=${1:-10}
echo "Running cyclictest for $secs seconds"

sudo sh ./isolate_cpus_begin.sh && sudo sh -c "echo \$$ > /sys/fs/cgroup/foo/cgroup.procs && exec ./rt-tests/cyclictest -t -i 1000 -l 500000 -p 0 -D ${secs}s --policy=ext"
sudo sh ./isolate_cpus_end.sh

python3 readstats.py
