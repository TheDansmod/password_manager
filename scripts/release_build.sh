#!/bin/sh
# Release build with T-REPRO-1 and T-ENG-7 (spec 14.11, 14.12, 15.3).
#
#   sh scripts/release_build.sh OUTDIR
#
# 1. T-REPRO-1: two clean `--locked` release builds of the committed tree,
#    from two different absolute paths, with a fixed SOURCE_DATE_EPOCH (the
#    commit time) and --remap-path-prefix for the source tree and
#    CARGO_HOME. The two binaries must be bit-identical.
# 2. Link hardening (spec 15.1) still holds: setting RUSTFLAGS would
#    replace `.cargo/config.toml`'s flags, so the full list is passed in
#    CARGO_ENCODED_RUSTFLAGS (which also replaces them), and the binary is
#    checked for BIND_NOW, GNU_RELRO, and PIE.
# 3. T-ENG-7: the artefact contains neither PWV_MEMTEST nor PWV_TESTKDF.
#    Positive control: a `memtest,testkdf` release build contains both, so
#    the search can find them.
# 4. OUTDIR gets the binary, pwv's licence, the word-list licence (the
#    binary embeds the list), and SHA256SUMS. Signing is the caller's job (release workflow).
#
# Each build uses its own clean target directory under the work directory.
# PWV_REPRO_TARGET=<dir> instead uses <dir> for both builds, removing its
# `release` profile output before each one (the sandbox may not create new
# target directories; DESIGN_NOTES, M9).
set -eu

out=${1:?usage: release_build.sh OUTDIR}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/pwv-repro.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
out=$(cd "$out" && pwd)

cargo_home=${CARGO_HOME:-$HOME/.cargo}
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
arch=$(uname -m)
name="pwv-$version-$arch-linux"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH
export LC_ALL=C TZ=UTC
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH; $(rustc --version)"

# Copies the tracked sources (no target/, no .git) to $1.
copy_tree() {
    mkdir -p "$1"
    (cd "$root" && tar --exclude=./target --exclude=./.git --exclude=./fuzz/target \
        -cf - .) | (cd "$1" && tar -xf -)
}

# Builds the tree at $1 into target dir $2 with features $3; prints the path.
build() {
    src=$1 tgt=$2 feat=$3
    us=$(printf '\037')
    flags="-C${us}link-arg=-Wl,-z,relro,-z,now"
    flags="$flags$us--remap-path-prefix=$src=/build/pwv"
    flags="$flags$us--remap-path-prefix=$cargo_home=/cargo"
    if [ -n "${PWV_REPRO_TARGET:-}" ]; then
        rm -rf "$tgt/release"
    fi
    (cd "$src" && CARGO_TARGET_DIR="$tgt" CARGO_ENCODED_RUSTFLAGS="$flags" \
        cargo build --locked --release --bin pwv $feat >&2)
    echo "$tgt/release/pwv"
}

for d in a b-longer-path; do copy_tree "$work/$d"; done
tgt_a=${PWV_REPRO_TARGET:-$work/a/target}
tgt_b=${PWV_REPRO_TARGET:-$work/b-longer-path/target}

bin_a=$(build "$work/a" "$tgt_a" "")
cp "$bin_a" "$work/pwv-a"
bin_b=$(build "$work/b-longer-path" "$tgt_b" "")
cp "$bin_b" "$work/pwv-b"

echo "T-REPRO-1: $(sha256sum "$work/pwv-a" | cut -d' ' -f1) (a)"
echo "T-REPRO-1: $(sha256sum "$work/pwv-b" | cut -d' ' -f1) (b)"
if ! cmp -s "$work/pwv-a" "$work/pwv-b"; then
    echo "T-REPRO-1 FAILED: the two release builds differ"
    cmp -l "$work/pwv-a" "$work/pwv-b" | wc -l | sed 's/^/differing bytes: /'
    exit 1
fi
# The build paths must not leak into the binary.
for p in "$work" "$cargo_home" "$root"; do
    if grep -aqF "$p" "$work/pwv-a"; then
        echo "T-REPRO-1 FAILED: the binary contains a build path"
        exit 1
    fi
done
echo "T-REPRO-1 ok: bit-identical"

# Spec 15.1 link hardening.
readelf -h "$work/pwv-a" | grep -Eq 'Type:[[:space:]]+DYN' || { echo "not PIE"; exit 1; }
readelf -l "$work/pwv-a" | grep -q GNU_RELRO || { echo "no GNU_RELRO"; exit 1; }
readelf -d "$work/pwv-a" | grep -Eq 'BIND_NOW|FLAGS_1.*NOW' || { echo "no BIND_NOW"; exit 1; }
echo "hardening ok: PIE, RELRO, BIND_NOW"

# T-ENG-7, with its positive control first.
bin_t=$(build "$work/a" "$tgt_a" "--features memtest,testkdf")
for m in PWV_MEMTEST PWV_TESTKDF; do
    grep -aqF "$m" "$bin_t" || { echo "T-ENG-7 control: $m not found in a test build"; exit 1; }
done
for m in PWV_MEMTEST PWV_TESTKDF; do
    if grep -aqF "$m" "$work/pwv-a"; then
        echo "T-ENG-7 FAILED: the release artefact contains $m"
        exit 1
    fi
done
echo "T-ENG-7 ok: no marker strings (the control build has both)"

cp "$work/pwv-a" "$out/$name"
cp "$root/LICENSE" "$out/$name.LICENSE"
cp "$root/src/wordlist.LICENSE" "$out/$name.wordlist.LICENSE"
(cd "$out" && sha256sum "$name" "$name.LICENSE" "$name.wordlist.LICENSE" > SHA256SUMS && cat SHA256SUMS)
