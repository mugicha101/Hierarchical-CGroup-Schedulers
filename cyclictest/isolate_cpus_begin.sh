# ensure cgroup other exists
if [ ! -d /sys/fs/cgroup/other ]; then
  echo "cgroup other does not exist, please run cgroup_server with cyclictest_config.json"
  exit 1
fi

# Disabled realtime bandwidth throttling
echo -1 | sudo tee /proc/sys/kernel/sched_rt_runtime_us

# Disable fair scx deadline servers for those cpus
for f in /sys/kernel/debug/sched/fair_server/cpu*/runtime; do
  echo 0 | sudo tee "$f" > /dev/null
done

# move all tasks in root to cgroup other (assuming it already exists)
echo "Moving tasks from root cgroup to other"
while [ -s /sys/fs/cgroup/cgroup.procs ]; do
    moved=0

    while read -r pid; do
        [ "$pid" = "1" ] && continue

        if echo "$pid" > /sys/fs/cgroup/other/cgroup.procs 2>/dev/null; then
            moved=$((moved + 1))
        fi
    done < /sys/fs/cgroup/cgroup.procs

    [ "$moved" -eq 0 ] && break
done
echo "Done"