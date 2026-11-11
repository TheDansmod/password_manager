# Fuzz targets

`cargo-fuzz` targets (spec Section 14.10). Present: T-FUZZ-1 `fuzz_header`,
T-FUZZ-2 `fuzz_body` (M2). T-FUZZ-3 to T-FUZZ-6 arrive in M3, M5, and M7.

Smoke run, as in CI (`fuzz-smoke`), from the repository root:

```sh
mkdir -p /tmp/corpus-fuzz_body
cargo +nightly fuzz run fuzz_body /tmp/corpus-fuzz_body fuzz/corpus/fuzz_body -- \
  -max_total_time=60 -rss_limit_mb=256 -malloc_limit_mb=64 -timeout=1 -max_len=24576
```

The scratch corpus comes first, so new units do not land in the committed
corpus. On stable Rust, add `-s none` (no AddressSanitizer).

`corpus/<target>/seed-*` are generated and checked by
`cargo test --test format corpus` (`PWV_WRITE_CORPUS=1` to regenerate).
Every crash becomes a regression unit test in `tests/` before it is fixed.
