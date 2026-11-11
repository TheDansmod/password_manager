# pwv

A single-binary, Linux-first terminal password manager written in Rust,
specified in `rust_password_manager_specification.md` (one level up).

**Status: M4 (storage).** Process hardening, the secure arena, the
zeroizing allocator, the vault file format (`FORMAT.md`, `src/format.rs`),
the key hierarchy (`src/crypto.rs`; init, unlock, save, and passwd at
library level in `src/vault.rs`), and storage (`src/store.rs`: XDG paths,
open-time checks, `flock`, atomic save, five backups, rollback-state file)
exist; no commands yet. The binary hardens itself, waits for one line on the
terminal, and exits with code 5.

## Building and checking

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
cargo +nightly miri test --no-default-features --test format   # T-SAN-2 (format)
cargo +nightly fuzz run fuzz_body -- -max_total_time=60   # T-FUZZ-2 (see fuzz/README.md)
cargo +nightly fuzz run --features testkdf fuzz_open -- -max_total_time=60   # T-FUZZ-3
```

The quick start, command reference, migration checklist (spec Section 12.3)
and EFF word-list attribution (CC BY 3.0 US) are added in later milestones.
