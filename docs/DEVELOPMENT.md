# Developing pwv

pwv is specified in [`SPECIFICATION.md`](SPECIFICATION.md); design
decisions and CI history are in [`DESIGN_NOTES.md`](DESIGN_NOTES.md), the
file format in [`FORMAT.md`](FORMAT.md), the threat model in
[`THREAT_MODEL.md`](THREAT_MODEL.md) (all in `docs/`). How to contribute:
[`CONTRIBUTING.md`](../CONTRIBUTING.md). Paths below are relative to the
repository root. The toolchain is pinned in `rust-toolchain.toml`.

## Checks

Each line names the Section 14 test IDs it covers.

```sh
cargo build --locked
cargo fmt --all --check                                         # T-ENG-1
cargo clippy --locked --all-targets --all-features -- -D warnings  # T-ENG-1, T-ENG-4
cargo test --locked --test eng                                  # T-ENG-2, T-ENG-3, T-ENG-4
python3 -I scripts/loc_budget.py src                            # T-ENG-6 (needs tokei)
cargo deny --locked check && cargo audit --deny warnings        # T-SUPPLY-1
cargo test --locked                       # T-MEM-1, T-MEM-6, T-ENG-5, ...
cargo test --locked --features memtest    # T-MEM-2, T-MEM-3
cargo test --locked --release             # T-MEM-5 (release binary)
cargo test --locked --features testkdf    # T-FMT-*, T-COMPAT-1, T-CRY-1 on golden vaults
cargo test --locked --features memtest,testkdf --test kdf_region   # T-MEM-7
cargo test --locked --test crypto         # T-KAT-1, T-KAT-2, T-CRY-1 .. T-CRY-6
python3 -I scripts/verify_golden.py       # T-COMPAT-1, independently (argon2-cffi, pynacl)
cargo test --locked --test format --test format_alloc   # T-FMT-1 .. T-FMT-4
cargo test --locked --lib store           # T-STORE-2 (fault injection), T-STORE-1 owner override
cargo test --locked --test store          # T-STORE-1, -3 .. -7, -9
PWV_T_STORE_3_ITERATIONS=5000 cargo test --locked --release --test store -- --exact t_store_3_kill_loop
PWV_FOREIGN_DIR=/mnt/vfat cargo test --locked --test store t_store_1_foreign_fs_real_mount
cargo test --locked --test gen            # T-GEN-1 .. T-GEN-6
cargo test --locked --test cli            # tokenizer, parsers, sanitize, strength, doctor
cargo test --locked --test e2e            # T-E2E-1 .. T-E2E-12 through a PTY
PWV_REQUIRE_X11=1 xvfb-run -a cargo test --locked --test clip   # T-CLIP-1 .. T-CLIP-4 (needs xclip)
cargo test --locked --test mig            # T-MIG-1 .. T-MIG-3 (legacy migration; real gpg in CI)
cargo +nightly miri test --no-default-features --test format   # T-SAN-2 (format)
cargo +nightly fuzz run fuzz_body -- -max_total_time=60   # T-FUZZ-2 (see fuzz/README.md)
cargo +nightly fuzz run --features testkdf fuzz_open -- -max_total_time=60   # T-FUZZ-3
cargo +nightly fuzz run fuzz_tokenizer -- -max_total_time=60   # T-FUZZ-4
cargo +nightly fuzz run fuzz_sanitize -- -max_total_time=60    # T-FUZZ-5
sh scripts/release_build.sh dist          # T-REPRO-1, T-ENG-7, link hardening; release files
python3 -I scripts/test_ids.py --markdown # every Section 14 test ID and what proves it
PWV_PERF=1 cargo test --locked --release --test perf -- --test-threads=1   # T-PERF-1
cargo test --locked --test eng t_cov_3    # T-COV-3's list of unsafe blocks
python3 -I scripts/coverage_report.py --self-test   # the coverage report's own checks
sh scripts/mutants.sh crypto 0/1 /tmp/mut           # T-MUT-1 for one module (slow)
```

CI only (they need tools a typical development machine lacks):

- **Coverage** (spec 14.13): `scripts/coverage_run.sh` runs the whole
  suite instrumented with `cargo-llvm-cov`, once per configuration;
  `scripts/coverage_report.py` merges the runs and checks T-COV-1 ..
  T-COV-5: at least 95 % of lines in `format`, `crypto`, `gen`, `store`,
  `vault` and 85 % overall, every function of those five covered, every
  `unsafe` block fully covered, and no module more than 0.5 points below
  `coverage/baseline.json`. Uncovered lines must be covered or justified in
  `docs/DESIGN_NOTES.md` ("Coverage exceptions"). The job summary of
  `coverage-report` shows the tables and every test ID's status.
- **T-STORE-8**: `scripts/lazyfs.sh` builds and mounts LazyFS; then
  `PWV_REQUIRE_LAZYFS=1 PWV_LAZYFS_DIR=... PWV_LAZYFS_FIFO=... cargo test
  --release --test store -- --exact t_store_8_kill_loop_with_power_loss`.
- **T-MUT-1**: the workflow `mutants.yml`.

## CI workflows

| Workflow | Runs on | What it does |
| --- | --- | --- |
| `ci.yml` | every pull request (a new push cancels the PR's older run) and every push to `main` | every job except the nightly ones; branches without a pull request get no CI (open a draft PR) |
| `ci.yml` | nightly (04:17 UTC) and "Run workflow" | every job, including Miri, ASan, LazyFS, aarch64, branch coverage, long fuzzing, performance |
| `mutants.yml` | weekly (Saturday 01:23 UTC) and "Run workflow" | T-MUT-1: 13 jobs, one per module shard; surviving mutants must be justified in `docs/DESIGN_NOTES.md` |
| `ci.yml`, job `ci-ok` | every run, last | passes only if every other job passed or was skipped (nightly-only jobs on pushes and pull requests); the one status check branch protection requires |
| `release.yml` | pushing a `v*` tag | calls `release-build.yml` |
| `release-build.yml` | only when `release.yml` calls it | checks the tag against `Cargo.toml`'s version, builds twice (T-REPRO-1), checks T-ENG-7 and hardening, attests the files, keeps them as the artefact `pwv-release-<tag>` |

**Badges.** `coverage-report` renders two SVGs and force-pushes them to
the orphan `badges` branch, only from runs on `main` that no fork can
start (pushes, nightly, "Run workflow"; never pull requests). The
coverage badge is overall line coverage from the latest such run. The
test-ID badge counts the Section 14 IDs that passed in the latest full run
(nightly or "Run workflow"); a push run keeps the previous one, because it
skips the nightly gates. T-MUT-1 counts the latest completed
`mutants.yml` run on `main`, if it finished within the last 8 days.

## Releasing

Release files are built only by CI, from a `v*` tag, and attested there.
The tag must equal `v` + `Cargo.toml`'s version (`release-build.yml`
fails otherwise). Nothing is published automatically: you create the
GitHub release and attach the files yourself.

Below, `X` is the version without the `v` (for example `0.1.0`, or
`0.1.0-rc.1` for a rehearsal).

1. **`main` is green.** Every job of `ci.yml`, including a nightly or
   "Run workflow" run.
2. **Set the version** (on `main`, or on a branch merged to `main`):

   ```sh
   sh scripts/set_version.sh X     # Cargo.toml, Cargo.lock, fuzz/Cargo.lock
   git diff --stat                 # exactly these three files, one line each
   ```

   The script needs only `sh` and `awk`: no Rust toolchain, no network, no
   build. CI builds with `--locked`, so it fails if a lock file disagrees
   with `Cargo.toml`. (`cargo update -p pwv` does the same edit but needs
   the crate index; `--offline` fails on a machine that never built pwv.)
   For a real release (not a rehearsal), also update
   `SECURITY.md`'s "Supported versions". Commit, push, and wait for the
   push run to be green.
3. **Mutation testing on that commit.** Unless the latest `mutants.yml` run
   is newer than the last change to `src/`, start one and wait for it to
   be green:

   ```sh
   gh workflow run mutants.yml --ref main
   gh run watch "$(gh run list --workflow=mutants.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
   ```

4. **Tag and push the tag** (the commit from step 2):

   ```sh
   git switch main && git pull
   git tag -a vX -m "pwv X"
   git push origin vX
   ```

   This starts `release` (tags do not start `ci.yml`).
5. **Download the files** once the `release` run is green:

   ```sh
   run=$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
   gh run download "$run" -n pwv-release-vX -D dist-vX
   ls dist-vX   # pwv-X-x86_64-linux, its two .LICENSE files, SHA256SUMS, pwv.sigstore.json
   ```

6. **Verify them** as a user would:

   ```sh
   cd dist-vX
   gh attestation verify pwv-X-x86_64-linux --repo TheDansmod/password_manager \
     --signer-workflow TheDansmod/password_manager/.github/workflows/release-build.yml
   sha256sum -c SHA256SUMS
   ./pwv-X-x86_64-linux doctor
   ```

7. **Publish.** Add `--prerelease` for a release candidate, or `--draft`
   to keep it private until you publish it from the web page:

   ```sh
   gh release create vX dist-vX/* --verify-tag --title "pwv X" --notes "..."
   ```

### Rehearsal

To try the whole procedure without making a real release, use a
pre-release version such as `0.1.0-rc.1` (tag `v0.1.0-rc.1`) and publish
it with `--draft` (visible only to you) or `--prerelease`. Things to know:

- The attestation is a permanent, public record that this repository built
  `pwv-0.1.0-rc.1-x86_64-linux`. That is harmless: the name says it is a
  release candidate, and a later `0.1.0` build gets its own name and its
  own attestation.
- Afterwards, delete the draft release if you made one
  (`gh release delete vX`); the tag can stay or be deleted
  (`git push --delete origin vX && git tag -d vX`).
- Set the version to the real one (step 2) before the real release.
