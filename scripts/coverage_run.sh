#!/bin/sh
# One instrumented coverage run (spec Section 14.13; M9), for the CI jobs
# `coverage` (stable, line/region/function) and `coverage-branch` (nightly,
# `--branch`). Writes into OUTDIR what scripts/coverage_report.py merges:
# lcov.info, cov.json, html/, meta.json, unsafe_blocks.tsv, test.log; and
# for diagnosis profiles.txt, unreadable_profiles.txt, report.log.
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
profdir=${CARGO_LLVM_COV_TARGET_DIR:-target/llvm-cov-target}
find "$profdir" -name '*.profraw' > "$out/profiles.txt"
profiles=$(wc -l < "$out/profiles.txt")
echo "profiles written: $profiles"

# A process killed while it writes its profile (at exit) leaves a truncated
# file, and one unreadable profile fails the whole merge. In M9 CI round 2
# every run's first `report` failed after all tests had passed: one of 219
# profiles had a corrupt header ("no profile can be merged"). Each profile
# is checked with llvm-profdata, and unreadable ones are set aside and
# listed with llvm-profdata's first error line (file names hold only a pid
# and a binary signature). Dropping one has
# the same effect as a SIGKILL before the write: it can only lower the
# measured coverage, never raise it. The count is in meta.json, so in the
# report's summary.
host=$(rustc -vV | sed -n 's/^host: //p')
profdata="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-profdata"
: > "$out/unreadable_profiles.txt"
while IFS= read -r p; do
  if ! "$profdata" show "$p" > /dev/null 2> "$out/profdata.err"; then
    echo "$(basename "$p"): $(head -n 1 "$out/profdata.err")" >> "$out/unreadable_profiles.txt"
    rm -f "$p"
  fi
done < "$out/profiles.txt"
rm -f "$out/profdata.err"
unreadable=$(wc -l < "$out/unreadable_profiles.txt")
echo "unreadable profiles set aside: $unreadable"
head -n 20 "$out/unreadable_profiles.txt"

COV_BRANCH=$branch COV_PROFILES=$profiles COV_UNREADABLE=$unreadable \
  python3 -I - "$out/meta.json" "$name" "$*" <<'EOF'
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
    "profiles": os.environ.get("COV_PROFILES", "").strip(),
    "unreadable profiles set aside": os.environ.get("COV_UNREADABLE", "").strip(),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2, sort_keys=True)
EOF

# Errors of `report` also go to report.log, which the artefact keeps.
# `report` takes no build options (`--features` and `--no-default-features`
# are rejected: M9 CI round 3); it reads the profiles and binaries this run
# left in the target directory, which `clean` emptied first.
report() {
  if ! cargo llvm-cov report "$@" 2>> "$out/report.log"; then
    echo "cargo llvm-cov report failed:"
    cat "$out/report.log"
    exit 1
  fi
}
report --lcov --output-path "$out/lcov.info"
report --json --output-path "$out/cov.json"
report --html --output-dir "$out/html"
# The per-file summary table (counts only) for the job log.
report
test -s "$out/unsafe_blocks.tsv" || { echo "tests/eng.rs did not write the unsafe block list"; exit 1; }
exit "$status"
