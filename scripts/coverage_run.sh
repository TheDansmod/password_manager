#!/bin/sh
# One instrumented coverage run (spec Section 14.13; M9), for the CI jobs
# `coverage` (stable, line/region/function) and `coverage-branch` (nightly,
# `--branch`). Writes into OUTDIR what scripts/coverage_report.py merges:
# lcov.info, cov.json, html/, meta.json, unsafe_blocks.tsv, test.log.
#
# Usage: sh scripts/coverage_run.sh [--branch] OUTDIR NAME [cargo args...]
#   e.g. sh scripts/coverage_run.sh cov/memtest memtest --features memtest
# `--branch` (nightly toolchain, selected by the caller with
# RUSTUP_TOOLCHAIN) instruments branches too; `report` reads them from the
# profiles, so it is a build flag only.
#
# The whole test suite runs (`cargo llvm-cov test`, every target): the PTY
# tests' `pwv` children are the instrumented binary and inherit
# LLVM_PROFILE_FILE (`pwv-%p-%m.profraw`), so they write their own
# profiles when they exit through `std::process::exit`. Processes killed by
# SIGKILL or SIGSEGV write none (expected; spec 14.13).
#
# Determinism (spec 14.13): proptest seeds come from PROPTEST_RNG_SEED and
# T-STORE-3's from PWV_T_STORE_3_SEED, both fixed by the caller; case
# counts are fixed in the tests. Only exit statuses, counts and test names
# reach the log: tests print no secrets (rule 9).
#
# cargo-llvm-cov sets RUSTFLAGS, which replaces .cargo/config.toml's link
# hardening flags: acceptable for a test-only build (T-REPRO-1's script
# checks the release artefact).
set -eu

branch=
if [ "${1:-}" = --branch ]; then
  branch=--branch
  shift
fi
out=$1
name=$2
shift 2
mkdir -p "$out"
out=$(cd "$out" && pwd)

: "${PROPTEST_RNG_SEED:?set a fixed seed}"
: "${PWV_T_STORE_3_SEED:?set a fixed seed}"

cargo llvm-cov clean --workspace
status=0
PWV_UNSAFE_BLOCKS="$out/unsafe_blocks.tsv" \
  cargo llvm-cov $branch --no-report --locked --no-fail-fast "$@" >"$out/test.log" 2>&1 || status=$?
# The log holds test names and results only; show the outcome lines.
grep -E "^test result:|FAILED|panicked at|^error" "$out/test.log" || true
profiles=$(find "${CARGO_LLVM_COV_TARGET_DIR:-target/llvm-cov-target}" -name '*.profraw' | wc -l)
echo "profiles written: $profiles"

cargo llvm-cov report "$@" --lcov --output-path "$out/lcov.info"
cargo llvm-cov report "$@" --json --output-path "$out/cov.json"
cargo llvm-cov report "$@" --html --output-dir "$out/html"
# The per-file summary table (counts only) for the job log.
cargo llvm-cov report "$@"

COV_BRANCH=$branch python3 -I - "$out/meta.json" "$name" "$*" <<'EOF'
import json, os, subprocess, sys
path, name, args = sys.argv[1:4]
def ver(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().split("\n")[0]
meta = {
    "run": name,
    "branch coverage": "yes" if os.environ.get("COV_BRANCH") else "no",
    "cargo args": args or "(default features)",
    "rustc": ver("rustc", "-V"),
    "cargo-llvm-cov": ver("cargo", "llvm-cov", "--version"),
    "PROPTEST_RNG_SEED": os.environ.get("PROPTEST_RNG_SEED", ""),
    "PWV_T_STORE_3_SEED": os.environ.get("PWV_T_STORE_3_SEED", ""),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2, sort_keys=True)
EOF
test -s "$out/unsafe_blocks.tsv" || { echo "tests/eng.rs did not write the unsafe block list"; exit 1; }
exit "$status"
