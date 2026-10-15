# move all tasks from other to root cgroup
echo "Moving tasks from other to root cgroup"
while [ -s /sys/fs/cgroup/other/cgroup.procs ]; do
    moved=0

    while read -r pid; do
        [ "$pid" = "1" ] && continue

        if echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; then
            moved=$((moved + 1))
        fi
    done < /sys/fs/cgroup/other/cgroup.procs

    [ "$moved" -eq 0 ] && break
done
echo "Done"

# Enable realtime bandwidth throttling
echo 950000 | sudo tee /proc/sys/kernel/sched_rt_runtime_us

# Enable fair scx deadline servers for those cpus
for f in /sys/kernel/debug/sched/fair_server/cpu*/runtime; do
  echo 50000000 | sudo tee "$f" > /dev/null
done
