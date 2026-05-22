#!/bin/sh
# sets ownership of cgroup filesystem to current user
# run as sudo

if [ -z "$SUDO_USER" ]; then
  echo "This script must be run with sudo."
  exit 1
fi
chown $SUDO_USER:$SUDO_USER /sys/fs/cgroup /sys/fs/bpf /sys/fs/cgroup/cgroup.subtree_control /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.threads
chmod u+rwx /sys/fs/cgroup /sys/fs/bpf
chmod u+rw /sys/fs/cgroup/cgroup.subtree_control /sys/fs/cgroup/cgroup.procs /sys/fs/cgroup/cgroup.threads