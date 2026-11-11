# Test vectors

- `MANIFEST`: for each golden vault, its SHA-256, the password as typed
  (hex UTF-8, before NFC), alternative spellings that must also open it,
  the generation, and the exact expected model (T-COMPAT-1).
- `v1-small.pwv` (4,296 bytes; also the T-CRY-1 bit-flip target and the
  `fuzz_open` seed), `v1-empty.pwv`, `v1-multiblock.pwv` (3 blocks,
  generation 5), `v1-rekeyed.pwv` (written after `passwd`).

All were built once with the `testkdf` feature (KDF memory 8–256 KiB) by
`PWV_WRITE_GOLDEN=1 cargo test --features testkdf --test crypto golden`,
which refuses to run while `MANIFEST` exists. They are **never regenerated**
except on a format-version bump; production builds must refuse them
(KDF memory below the read floor), which `t_compat_1_golden_vaults` checks.

Checked by `cargo test --features testkdf --test crypto` (pwv) and,
independently, by `scripts/verify_golden.py` (argon2-cffi + libsodium; CI job
`compat`).

KAT vectors live in `tests/crypto.rs`: T-KAT-1 is RFC 9106 Section 5.3
(Argon2id), T-KAT-2 is draft-irtf-cfrg-xchacha-03 Appendix A.3.1.
