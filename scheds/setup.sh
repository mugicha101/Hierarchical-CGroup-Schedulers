#!/bin/bash
set -euo pipefail

LINUX_REPO=https://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext.git
LINUX_REF="e158e309cd90249a90cc84e6d29e46a3d5551b7b"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git -c init.defaultBranch=main init "$TMP/linux"
git -C "$TMP/linux" remote add origin "$LINUX_REPO"
git -C "$TMP/linux" sparse-checkout init --cone
git -C "$TMP/linux" sparse-checkout set tools/sched_ext/include/scx
git -C "$TMP/linux" fetch --depth=1 --filter=blob:none --no-tags origin "$LINUX_REF"
git -C "$TMP/linux" checkout --detach FETCH_HEAD

mkdir -p include
rm -rf include/scx
cp -a "$TMP/linux/tools/sched_ext/include/scx" include/
