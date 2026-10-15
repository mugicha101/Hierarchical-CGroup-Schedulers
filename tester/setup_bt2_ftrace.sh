#!/bin/bash
set -euo pipefail

# clones and builds bt2 ftrace plugin
# requires meson, ninja, python3-bt2, and development packages for
# babeltrace2, tracecmd, traceevent, tracefs, glib, json-glib, and uuid
TESTER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SETUP_DIR="$TESTER_DIR/build/bt2-ftrace-to-ctf"
SOURCE_DIR="$SETUP_DIR/source"
BUILD_DIR="$SETUP_DIR/build"

mkdir -p "$SETUP_DIR"
: > "$SETUP_DIR/setup.log"
trap 'cat "$SETUP_DIR/setup.log" >&2' ERR

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git clone --quiet --depth=1 https://github.com/siemens/bt2-ftrace-to-ctf.git "$SOURCE_DIR" >> "$SETUP_DIR/setup.log" 2>&1
fi
if [[ ! -f "$BUILD_DIR/meson-private/coredata.dat" ]]; then
  meson setup "$BUILD_DIR" "$SOURCE_DIR" --buildtype=release -Dwith-live-source=false >> "$SETUP_DIR/setup.log" 2>&1
fi
meson compile -C "$BUILD_DIR" >> "$SETUP_DIR/setup.log" 2>&1
