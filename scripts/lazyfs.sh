#!/bin/sh
# Builds and mounts LazyFS for T-STORE-8 (spec 14.5; M9). CI only: the
# sandbox cannot reach GitHub. Writes the variables tests/store.rs reads
# (PWV_LAZYFS_DIR, PWV_LAZYFS_FIFO) to the file named by $GITHUB_ENV if set,
# else prints them.
#
# Usage: sh scripts/lazyfs.sh WORKDIR
#   LAZYFS_REF  commit to check out (empty: the default branch; the commit
#               used is printed so it can be pinned)
#
# LazyFS (github.com/dsrhaslab/lazyfs) is a FUSE filesystem with its own page
# cache: data reaches the backing directory only on fsync, and the fault
# command `lazyfs::clear-cache` (written to its FIFO) drops everything else,
# as a power loss would. Needs fuse3, libfuse3-dev, cmake, g++, and
# `user_allow_other` in /etc/fuse.conf (its mount script passes allow_other).
set -eu

work=$1
mkdir -p "$work"
work=$(cd "$work" && pwd)
src="$work/lazyfs"

if [ ! -d "$src" ]; then
  git clone --quiet https://github.com/dsrhaslab/lazyfs.git "$src"
  if [ -n "${LAZYFS_REF:-}" ]; then
    git -C "$src" checkout --quiet "$LAZYFS_REF"
  fi
fi
echo "LazyFS commit: $(git -C "$src" rev-parse HEAD)"
# CMake 4 (ubuntu-26.04) refuses `cmake_minimum_required` below 3.5, which
# the TOML library LazyFS fetches at configure time still declares (M9, first
# full run on main, 2026-11-17). CMake reads this variable from the
# environment, so it reaches both build.sh scripts and their FetchContent
# sub-builds without patching LazyFS. Older CMake ignores it.
export CMAKE_POLICY_VERSION_MINIMUM=3.5
if [ ! -x "$src/lazyfs/build/lazyfs" ]; then
  (cd "$src/libs/libpcache" && ./build.sh)
  (cd "$src/lazyfs" && ./build.sh)
fi

mkdir -p "$work/root" "$work/mnt"
fifo="$work/faults.fifo"
[ -p "$fifo" ] || mkfifo "$fifo"

# Start from LazyFS's own default configuration and change only the fault
# FIFO's path, so this script does not depend on the rest of its schema.
cfg="$work/pwv-lazyfs.toml"
python3 -I - "$src/lazyfs/config/default.toml" "$cfg" "$fifo" <<'EOF'
import re, sys
src, dst, fifo = sys.argv[1:4]
text = open(src, encoding="utf-8").read()
text, n = re.subn(r'(?m)^\s*fifo_path\s*=.*$', f'fifo_path="{fifo}"', text)
if n != 1:
    sys.exit(f"expected one fifo_path line in {src}, found {n}")
open(dst, "w", encoding="utf-8").write(text)
EOF
echo "--- $cfg"
cat "$cfg"

(cd "$src/lazyfs" && nohup ./scripts/mount-lazyfs.sh -c "$cfg" -m "$work/mnt" -r "$work/root" \
  >"$work/lazyfs.log" 2>&1 &)
i=0
until grep -q " $work/mnt " /proc/mounts; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "LazyFS did not mount; its log:"
    cat "$work/lazyfs.log"
    exit 1
  fi
  sleep 1
done
grep " $work/mnt " /proc/mounts
stat -f -c 'filesystem: %T (magic 0x%t)' "$work/mnt"

vars="PWV_LAZYFS_DIR=$work/mnt
PWV_LAZYFS_FIFO=$fifo"
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "$vars" >>"$GITHUB_ENV"
fi
echo "$vars"
