# ensure cgroup other exists
if [ ! -d /sys/fs/cgroup/other ]; then
  echo "cgroup other does not exist, please run cgroup_server with cyclictest_config.json"
  exit 1
fi

# Disabled realtime bandwidth throttling
echo -1 | sudo tee /proc/sys/kernel/sched_rt_runtime_us

# Disable fair scx deadline servers for those cpus
echo 0 | sudo tee /sys/kernel/debug/sched/fair_server/cpu0/runtime
echo 0 | sudo tee /sys/kernel/debug/sched/fair_server/cpu1/runtime
echo 0 | sudo tee /sys/kernel/debug/sched/fair_server/cpu2/runtime
echo 0 | sudo tee /sys/kernel/debug/sched/fair_server/cpu3/runtime

# move all tasks in root to cgroup other (assuming it already exists)
echo "Moving tasks from root cgroup to other"
sudo sh -c 'while read -r pid; do echo "$pid" > /sys/fs/cgroup/other/cgroup.procs 2>/dev/null; done < /sys/fs/cgroup/cgroup.procs'
echo "Done"