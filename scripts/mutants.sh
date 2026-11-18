#!/bin/sh
# T-MUT-1 (spec 14.11) for one module and one shard; the weekly workflow
# mutants.yml runs it per (module, shard). Owner decision 6 (2026-11-16):
#
#   1. Fast pass: this shard's mutants of src/MODULE.rs against that
#      module's own tests (lib unit tests plus its tests/*.rs; T-STORE-3 and
#      T-STORE-8's kill loops are skipped there), default features.
#   2. Every mutant the fast pass missed (or that timed out) is re-run
#      against the full suite (`cargo test`, every target), default features.
#   3. Those still missed are re-run against the full suite with
#      `--features memtest,testkdf` (feature-gated code, such as memtest's
#      zero checks, is only compiled there).
#
# A weaker first pass can only add survivors, which the full suite then
# judges, so nothing is skipped. What survives pass 3 is written to
# OUT/survivors.txt; each must be justified in docs/DESIGN_NOTES.md
# (scripts/mutants_check.py). Timeouts in pass 3 count as caught: the
# mutant made the suite hang, which a run notices.
#
# Usage: sh scripts/mutants.sh MODULE K/N OUT
set -eu

module=$1
shard=$2
out=$3
mkdir -p "$out"
out=$(cd "$out" && pwd)
file="src/$module.rs"

case "$module" in
  format) tests="--test=format --test=format_alloc" ;;
  crypto) tests="--test=crypto --test=kdf_region" ;;
  gen) tests="--test=gen" ;;
  store) tests="--test=store" ;;
  vault) tests="--test=vault" ;;
  *) echo "unknown module: $module"; exit 1 ;;
esac

common="--file $file --cap-lints true --no-shuffle"

# cargo-mutants exits 2 for missed mutants and 3 for timeouts: both are
# results here, not errors.
run() {
  status=0
  cargo mutants "$@" || status=$?
  case "$status" in
    0 | 2 | 3) ;;
    *) echo "cargo mutants failed with $status"; exit "$status" ;;
  esac
}

survivors() {
  cat "$1/mutants.out/missed.txt" "$1/mutants.out/timeout.txt" 2>/dev/null | sort -u
}

# Pass 1.
fast_args=""
for t in $tests; do
  fast_args="$fast_args --cargo-test-arg=$t"
done
# cargo-mutants appends what follows its `--` to `cargo test`'s own
# arguments, so the test binaries' `--skip` needs a second `--` (the first
# mutants run failed with "cargo test: unexpected argument '--skip'").
# shellcheck disable=SC2086
run $common --shard "$shard" --cargo-test-arg=--lib $fast_args -o "$out/fast" \
  -- -- --skip t_store_3_kill_loop --skip t_store_8_kill_loop_with_power_loss
survivors "$out/fast" > "$out/fast-survivors.txt"
echo "pass 1: $(wc -l < "$out/fast-survivors.txt") survivors"

# Passes 2 and 3 re-run exactly those mutants: every other mutant of the
# file is marked as already caught, and --iterate skips them.
# shellcheck disable=SC2086
cargo mutants $common --list > "$out/all.txt"
full() { # full PASS_NAME INPUT_LIST [cargo-mutants args...]
  name=$1
  list=$2
  shift 2
  mkdir -p "$out/$name/mutants.out"
  grep -vxF -f "$list" "$out/all.txt" > "$out/$name/mutants.out/previously_caught.txt" || true
  if [ ! -s "$list" ]; then
    : > "$out/$name-survivors.txt"
    return
  fi
  # shellcheck disable=SC2086
  run $common --iterate -o "$out/$name" "$@"
  cat "$out/$name/mutants.out/missed.txt" 2>/dev/null | sort -u > "$out/$name-survivors.txt"
  if [ "$name" = full-default ]; then
    # A timeout with default features is retried with the other features.
    cat "$out/$name/mutants.out/timeout.txt" 2>/dev/null >> "$out/$name-survivors.txt" || true
    sort -u -o "$out/$name-survivors.txt" "$out/$name-survivors.txt"
  fi
  echo "$name: $(wc -l < "$out/$name-survivors.txt") survivors"
}
full full-default "$out/fast-survivors.txt"
full full-memtest-testkdf "$out/full-default-survivors.txt" --features memtest,testkdf
cp "$out/full-memtest-testkdf-survivors.txt" "$out/survivors.txt"
echo "survivors after the full suite:"
cat "$out/survivors.txt"
