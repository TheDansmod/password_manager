# Fuzz targets

`cargo-fuzz` targets (spec Section 14.10). Present: T-FUZZ-1 `fuzz_header`,
T-FUZZ-2 `fuzz_body` (M2), T-FUZZ-3 `fuzz_open` (M3; full unlock with
`testkdf` parameters, and save-then-unlock of fuzzed bodies). T-FUZZ-4 to
T-FUZZ-6 arrive in M5 and M7.

`fuzz_open` needs the lowered KDF floor: add `--features testkdf`
(`cargo +nightly fuzz run --features testkdf fuzz_open ...`). The other
targets are built without it, so `fuzz_header` sees the production floor.

Smoke run, as in CI (`fuzz-smoke`), from the repository root:

```sh
mkdir -p /tmp/corpus-fuzz_body
ASAN_OPTIONS=quarantine_size_mb=32 cargo +nightly fuzz run fuzz_body /tmp/corpus-fuzz_body fuzz/corpus/fuzz_body -- \
  -max_total_time=60 -rss_limit_mb=256 -malloc_limit_mb=64 -timeout=1 -max_len=24576
```

`quarantine_size_mb=32`: ASan's default 256 MiB quarantine of freed blocks
counts towards `-rss_limit_mb=256` and trips it without any leak
(DESIGN_NOTES.md, 2026-11-11). The scratch corpus comes first, so new units do not land in the committed
corpus. On stable Rust, add `-s none` (no AddressSanitizer).

`corpus/<target>/seed-*` are generated and checked by
`cargo test --test format corpus` and, for `fuzz_open` (from the golden
vault `v1-small.pwv`), `cargo test --features testkdf --test crypto golden`
(`PWV_WRITE_CORPUS=1` to regenerate).
Every crash becomes a regression unit test in `tests/` before it is fixed.
