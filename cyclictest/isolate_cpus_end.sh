# move all tasks from other to root cgroup
echo "Moving tasks from other to root cgroup"
sudo sh -c 'while read -r pid; do echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null; done < /sys/fs/cgroup/other/cgroup.procs'
echo "Done"

# Enable realtime bandwidth throttling
echo 950000 | sudo tee /proc/sys/kernel/sched_rt_runtime_us

# Enable fair scx deadline servers for those cpus
echo 50000000 | sudo tee /sys/kernel/debug/sched/fair_server/cpu0/runtime
echo 50000000 | sudo tee /sys/kernel/debug/sched/fair_server/cpu1/runtime
echo 50000000 | sudo tee /sys/kernel/debug/sched/fair_server/cpu2/runtime
echo 50000000 | sudo tee /sys/kernel/debug/sched/fair_server/cpu3/runtime
