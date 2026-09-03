#!/bin/bash
set -euo pipefail
for f in ./build/scx_*; do
    [ -x "$f" ] && sudo setcap cap_bpf,cap_perfmon=ep "$f"
done
CALLING_USER="${SUDO_USER:-$USER}"
CALLING_GROUP="$(id -gn "$CALLING_USER")"

sudo mkdir -p /sys/fs/bpf/scx
sudo chown "$CALLING_USER:$CALLING_GROUP" /sys/fs/bpf/scx
sudo chmod 700 /sys/fs/bpf/scx
sudo chgrp "$(id -gn)" /sys/fs/bpf
sudo chmod g+x /sys/fs/bpf
