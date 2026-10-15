#!/bin/bash
set -euo pipefail
if [ ! -x ./build/check_tracing ]; then
    echo "Missing ./build/check_tracing; run make before setcaps.sh" >&2
    exit 1
fi
for f in ./build/scx_*; do
    [ -x "$f" ] || continue
    tracing=$(./build/check_tracing "${f##*/}")
    caps=cap_bpf,cap_perfmon
    case "$tracing" in
        # module BTF enumeration requires CAP_SYS_ADMIN
        1) caps+=,cap_sys_admin ;;
        0) ;;
        *) echo "Invalid tracing configuration for $f: $tracing" >&2; exit 1 ;;
    esac
    sudo setcap "$caps=ep" "$f"
done
CALLING_USER="${SUDO_USER:-$USER}"
CALLING_GROUP="$(id -gn "$CALLING_USER")"

sudo mkdir -p /sys/fs/bpf/scx
sudo chown "$CALLING_USER:$CALLING_GROUP" /sys/fs/bpf/scx
sudo chmod 700 /sys/fs/bpf/scx
sudo chgrp "$(id -gn)" /sys/fs/bpf
sudo chmod g+x /sys/fs/bpf
