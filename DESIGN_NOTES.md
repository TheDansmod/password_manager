# Design notes

Deviations from the specification, dependency justifications, interpretations
of ambiguous text (spec Section 17, rule 10), and surviving-mutant
justifications. Each entry is dated.

## Pinned versions (2026-11-10, M0)

Toolchain: Rust 1.99.1 stable (`rust-toolchain.toml`), edition 2024,
`rust-version = "1.99"`.

| Crate | Version | Features | API verified (rule 4) |
| --- | --- | --- | --- |
| `argon2` | 0.6.0 | `zeroize` only (defaults off: no `password-hash`, no `getrandom`) | `Argon2::hash_password_into_with_memory` present (src/lib.rs:307) |
| `chacha20poly1305` | 0.11.0 | `zeroize` only (defaults off: no `alloc`, no `getrandom`) In `aead` 0.6.1 `encrypt_in_place_detached` / `decrypt_in_place_detached` are on the deprecated `AeadInPlace` trait, which forwards to `AeadInOut::{en,de}crypt_inout_detached`; M3 calls those in place (see 2026-11-11, M3) |
| `zeroize` | 1.9.1 | default | — |
| `getrandom` | 0.4.3 | default | — |
| `rustix` | 1.1.6 | `event fs mm param process stdio termios` | `mm::Advice::LinuxDontDump`, `LinuxWipeOnFork`; `process::set_dumpable_behavior`, `setrlimit`, `umask`; `fs::flock`, `fstatfs` present. `mlock` re-checked in M1 |
| `libc` | 0.2.191 | default | see below |
| `unicode-normalization` | 0.1.26 | default | — |
| `arboard` (feature `clipboard`) | 3.7.0 | `wayland-data-control` only (defaults off: no `image-data`) | `SetExtLinux::exclude_from_history` present (src/platform/linux/mod.rs:380) |
| `zxcvbn` (feature `strength`) | 3.1.1 | defaults off (no `derive_builder`) | — |

Dev-only (unconstrained by the budget): `expectrl` 0.9.0, `proptest` 1.12.0,
`rand_chacha` 0.10.0, `static_assertions` 1.1.0, `tempfile` 3.27.0, `sha2`
0.11.1 (M3: golden-vault checksums).
`libfuzzer-sys` lives in the separate `fuzz/` crate (M2).

Default features were disabled wherever they pull in code the spec does not
need (heap-allocating AEAD helpers, image support, a builder derive macro).
This shrinks the audited graph; it does not add any crate.

## 2026-11-10 — `libc` included from M0

Section 3 lists "`rustix` (or `libc` if a call is missing)". rustix 1.1.6 has
no stable safe `sigaction` (needed for Section 9.3's signal flag), so `libc` is
needed and is added now so the M0 dependency set is complete. It is already in
the graph transitively. Rule: only `sys.rs` may name `libc` or `rustix`
(enforced from M1 on). The 50-lines-by-hand alternative (rule 3) does not apply:
`libc` *is* the hand-written-bindings option the spec names.

## 2026-11-10 — `gen` is a reserved keyword in edition 2024

Edition 2024 reserves `gen`. The module keeps the file name `src/gen.rs` and is
declared `pub mod r#gen;` and referenced as `crate::r#gen`. The layering
scanner (tests/eng.rs) strips the `r#` prefix.

## 2026-11-10 — `clippy::pedantic` and the deny list live in crate attributes

T-ENG-1 says "the `clippy::pedantic` subset listed in `clippy.toml`", but
`clippy.toml` configures lints and cannot set lint levels. Lint levels are
therefore set by crate attributes in `src/lib.rs` and `src/main.rs`, exactly as
Section 15.1 lists them: `#![warn(clippy::pedantic)]` (an error under
`-D warnings`) and, outside `cfg(test)`, `deny(clippy::unwrap_used,
clippy::expect_used, clippy::indexing_slicing, clippy::panic)`. The full
pedantic group is enabled (no subset). Any pedantic lint that must be allowed
later is allowed at item level with a comment, and listed here.

## 2026-11-10 — T-ENG-4 exemption mechanism

`clippy.toml` bans apply crate-wide; clippy has no per-path configuration.
Exemptions for `term.rs` (std stdio) and `store.rs` (file creation) are made by
item-level `#[allow(clippy::disallowed_methods)]` /
`#[allow(clippy::disallowed_macros)]`. `tests/eng.rs` fails if such an allow
appears in any other file, or module-wide (`#![allow(...)]`) anywhere.
Conservative additions to the spec's list: `std::fs::File::create_new` and
`rand::rng` (the current name of `rand::thread_rng`). The `rand` entries use
`allow-invalid = true` because `rand` is not a dependency.

## 2026-11-10 — T-ENG-3: "no global state except the allocator"

Section 9.3 requires a signal handler that sets an atomic flag, which is
necessarily a `static`. E1 forbids "`static mut` and lazy globals". Resolution:
the scanner permits exactly two kinds of `static` item: the
`#[global_allocator]`, and statics whose type is an `Atomic*`. `static mut`,
`thread_local!`, `OnceLock`, `OnceCell`, `LazyLock`, `LazyCell`,
`lazy_static`, `once_cell`, and any other `static` are rejected.

## 2026-11-10 — layering is strict between bands

Section 4's order is read as bands: `cli` (4); `clip term store vault gen`
(3); `format crypto` (2); `secmem` (1); `sys` (0). A module may use only
modules in a strictly lower band, so modules in the same band may not use each
other (the more conservative reading). `alloc` may use no crate module and only
`main.rs` may use it. `main.rs` may use only `pwv::{cli, sys, alloc}`; `lib.rs`
only declares modules. The scanner checks every `crate::` path, not only `use`
statements (stricter than the spec's wording).

## 2026-11-10 — T-ENG-2 also requires SAFETY comments on `unsafe impl`/`unsafe fn`

The scanner requires a `// SAFETY:` comment directly above (or on the same
line as) every token `unsafe` in code, which covers blocks, `unsafe impl`
(for example `GlobalAlloc`), and `unsafe fn`. For `unsafe fn`/`unsafe trait`
a `# Safety` doc section is accepted instead. This is stricter than "each
`unsafe` block".

## 2026-11-10 — LOC accounting (T-ENG-6)

`scripts/loc_budget.py` copies `src/`, removes every `#[cfg(test)]` item, and
counts code lines with `tokei` (blank lines and comments excluded). `lib.rs`
is not named in Section 3's table; it is charged to `cli + main` (the
conservative choice). Any `.rs` file not assigned to a group fails the script.

## 2026-11-10 — files and directories not in the Section 4 layout

- `scripts/loc_budget.py`: the T-ENG-6 "tokei-based script".
- `tests/eng.rs`: T-ENG-2, T-ENG-3 and the scope part of T-ENG-4 as a
  `cargo test` target, so they cannot be skipped locally.
- `.cargo/config.toml`: link hardening flags (Section 15.1).
- `.github/workflows/ci.yml`: CI (Section 15.3).
- `SECURITY.md` is in Section 15.4 but not Section 4's layout; created.
- `src/wordlist.txt` is deferred to M6, where T-GEN-6 pins its digest.

## 2026-11-10 — `cargo deny` duplicate skip: `hashbrown@0.15.5`

`arboard` 3.7.0 → `wl-clipboard-rs` 0.9.5 → `tree_magic_mini` 3.2.2 →
`petgraph` 0.8.3, which requires `hashbrown ^0.15`, while `indexmap` ≥ 2.12
uses `hashbrown` 0.17. Pinning `indexmap` 2.11.4 (last release on 0.15) in
`Cargo.lock` was tried and fails: Cargo resolves one `indexmap` 2.x for the
whole graph, and the dev-only chain `proptest` → `bit-vec` 0.10 → `borsh` →
`proc-macro-crate` → `toml_edit` requires `indexmap ^2.13`. The duplicate is
transitive, confined to the optional clipboard feature's Wayland MIME-sniffing
path, and not under this crate's control. It is skipped by exact version in
`deny.toml`; remove the skip once `petgraph` moves to `hashbrown` 0.17.

## 2026-11-10 — `cli::run` in M0

The M0 binary has no commands. `cli::run` returns exit code 5 (internal error)
without output, so a skeleton build can never be mistaken for a working one.

## 2026-11-10 — RUSTSEC-2026-0441 (`pin-utils` unmaintained) ignored, dev-only

Reported by `cargo deny check advisories` and `cargo audit` (run by the owner;
the sandbox cannot reach the advisory DB). Severity judged **low**:

- It is an *unmaintained* notice (upstream archived 2026-10-01), not a
  vulnerability; `pin-utils` is a tiny macro crate with no I/O or parsing.
- It is reachable only through `expectrl` 0.9.0 → `nix` 0.26.4 (and
  `ptyprocess` → `nix`), i.e. the dev-only PTY test harness. It is not linked
  into the `pwv` binary and never handles real secrets.
- No fixed upgrade exists, and `expectrl` 0.9.0 is the latest release.

Action: ignored by advisory ID in `deny.toml` and `.cargo/audit.toml`.
Revisit in M7 when the PTY end-to-end tests are written: if `expectrl` is still
on `nix` 0.26 then, consider replacing it with a small PTY helper over
`rustix::pty` in test code. The ignore is removed as soon as the dependency is.

## 2026-11-10 — M1 memory foundation: structure

- `sys::GuardedRegion` owns the `[guard | data | guard]` mapping: `PROT_NONE`
  guards; data `mprotect`ed RW, `MADV_DONTDUMP`, `MADV_WIPEONFORK`, optionally
  `mlock`ed. Its teardown zeroizes the data, `munlock`s, then `munmap`s. The
  arena is built on it, and M3's `KdfRegion` will reuse it, so every mapping
  primitive and every `unsafe` mapping call lives in `sys`. `secmem` currently
  contains no `unsafe` block.
- Teardown zeroizes only once the data part is actually read-write (a
  `writable` flag set after `mprotect` succeeds), so a failure inside
  `GuardedRegion::new` cannot fault while cleaning up.
- `SecureArena::slots()` carves the region once into the fixed `Slots` of
  Section 5.2, in table order. `VaultA`/`VaultB` split the remainder;
  `VaultB` ends at the last data byte, directly below the upper guard page.
- `SecretSlot` has a zero-tail invariant: bytes past `len` are always zero.
  `set_len` grows by exposing zeros and zeroizes on shrink; `clear` and `Drop`
  zeroize the used prefix. Reads go only through `expose` / `expose_mut`.
  `!Send`/`!Sync` come from a `PhantomData<*mut u8>` marker.
- `--allow-unlocked-memory` maps to `SecureArena::new(size, allow_unlocked)`;
  `is_locked()` reports the truth for the prompt warning (M7).
- No `Display` on module errors; each has a fixed `message()`. The top-level
  error type (M7) owns exit codes and output.
- The method is `size()` rather than `len()` on the arena and region, which
  avoids a required-but-meaningless `is_empty()` (LOC budget).

## 2026-11-10 — M1: `memtest` hooks and test-only probes

- Arena address range: printed to fd 2 as `PWV_MEMTEST arena <start>-<end>`
  when an arena is created. `PWV_MEMTEST` is the T-ENG-7 marker string.
- `PR_SET_DUMPABLE` is skipped in `memtest` builds (Section 5.8).
- T-MEM-3 snapshot: `SecureArena::close_with_snapshot(hook)` runs the normal
  teardown and calls `hook` with the zeroized data region after `munlock` and
  just before `munmap`. It uses a callback rather than global state (E1).
- T-MEM-2 probe: `SecureArena::probe_guard(overflow)` writes one byte just
  past the last slot (and, stricter than the spec, just before the first slot).
  It is deliberately out of bounds; the guard page turns it into SIGSEGV.
- The `__pause` REPL command is **deferred to M7**, where the REPL exists. It
  is first needed by T-MEM-4 (M8).

## 2026-11-10 — M1: zeroizing allocator and T-MEM-6

- One type, `ZeroizingAlloc::new(verify)`. With `verify = true` (the
  asserting layer of T-MEM-6), every block is checked to be all-zero after
  wiping and just before `System::dealloc`, and the process aborts otherwise.
  A counter (`verified_count`) lets a test prove the layer is active.
- `main.rs` installs `new(false)`; `lib.rs` installs `new(true)` under
  `cfg(test)`; every `tests/*.rs` crate installs `new(true)`, which
  `tests/eng.rs` enforces ("across the whole test suite").
- Wipes go through `[MaybeUninit<u8>]::zeroize`, because freed blocks may hold
  uninitialised bytes. `realloc` never grows in place: allocate, copy, then
  free the old block through the wiping `dealloc`.

## 2026-11-10 — M1 placeholder behaviour of the binary

`main` installs the allocator and calls `sys::harden()` first. On failure it
writes `pwv: <fixed message>` to fd 2 and exits 4 (environment refusal). With
no commands yet, `cli::run` waits for one line or end of file on fd 0
(`term::wait_line`, raw `read(2)` into a stack buffer; no secret is ever read
in M1), then exits 5. This keeps a hardened process alive for T-MEM-5. Both are
replaced in M7.

## 2026-11-10 — M1 test mechanics

- T-MEM-1 inspects `/proc/self/smaps` for an arena created in the test process
  (no CLI exists yet). It checks: the data VMA is exactly the data region,
  `rw-p`, `Locked:` equals its size, and `VmFlags` include `dd`, `wf`, `lo`; the
  VMAs at `start - 1` and `end` are `---p`.
- T-MEM-2 and the panic-hook test re-run the test binary as a child
  (`tests/common::run_child`). The T-MEM-2 child sets `RLIMIT_CORE` to 0 first,
  so the deliberate crash does not ship a core to the host's `systemd-coredump`.
- T-MEM-5 drives the real `pwv` binary under a PTY (`expectrl`) and checks:
  - core limit `0 0` in `/proc/<pid>/limits`;
  - non-dumpable: `/proc/<pid>/mem` is no longer owned by our UID (checked
    manually to discriminate: the `memtest` build stays owned by UID 1000);
  - `umask` is 0077 and the soft memlock limit equals the hard limit;
  - a sibling (not parent) process cannot open or read `/proc/<pid>/mem`, and
    `PTRACE_ATTACH` fails. The sibling reports success with exit code 42, so a
    vacuous no-op run cannot pass;
  - after SIGSEGV the process dies by that signal, the kernel's
    `WCOREDUMP` bit is clear, and no file appears in its working directory.
- Test crates may spawn processes (`std::process::Command`, item-level
  `#[allow(clippy::disallowed_methods)]` in `tests/common`), and may use
  `rustix`/`libc`/`unsafe`; the T-ENG-2/T-ENG-4/sys-only rules bind `src/`.
  The print-macro ban applies to tests too, so children report through exit
  codes.

## 2026-11-10 — RESOLVED: core dumps under `fs.suid_dumpable = 2`

Section 5.1 relies on "the default `fs.suid_dumpable = 0`". systemd's
`50-coredump.conf` sets `fs.suid_dumpable = 2` and a piped `core_pattern`
(`|systemd-coredump ...`); this machine has exactly that. With value 2 the
kernel still pipes cores of non-dumpable processes to the helper, and
`RLIMIT_CORE = 0` is not enforced for pipes. The arena and KDF region are
excluded anyway (`MADV_DONTDUMP`), and `systemd-coredump` does not *store* a
core when the passed limit is 0. It may still log a journal entry, which would
fail T-MEM-5's "no `coredumpctl` entry".

In this sandbox the kernel reported no core dump (`WCOREDUMP` clear), but
`coredumpctl` runs on the host and cannot be checked from here. Two options
for the owner:

1. Keep `{0, 0}` as specified, and have `doctor` fail on
   `suid_dumpable != 0` (already in Section 9.4).
2. Use `RLIMIT_CORE = {1, 1}`. The kernel aborts *piped* dumps when the limit
   is exactly 1 (its recursion guard, `fs/coredump.c`), and file dumps are
   skipped because 1 byte is below the ELF minimum. This suppresses dumps
   regardless of `suid_dumpable`, at the cost of a kernel log line per crash.
   It deviates from T-MEM-5's literal "core limit 0".

**Owner decision (2026-11-10): option 1.** `RLIMIT_CORE` stays `{0, 0}` as
specified. `doctor` (M7) fails the "Core dumps" check whenever
`/proc/sys/fs/suid_dumpable` is not `0`, with a remedy line (for example a
`/etc/sysctl.d/` drop-in setting `fs.suid_dumpable = 0`). T-MEM-5's
"no `coredumpctl` entry" therefore assumes a host with `suid_dumpable = 0`;
it must be checked by the owner on a real host (the sandbox cannot run
`coredumpctl`).

## 2026-11-10 — RESOLVED: LOC: `sys + secmem + alloc` is at 475 / 500 after M1

tokei 15 already excludes `///`/`//!` doc comments (it classifies them as
embedded Markdown), so this is real code. M1 was trimmed from 518 to 475. Still
to land in `sys` per the spec: `sigaction` (M7), termios, `poll`, `/dev/tty`
open (M7), and the file syscalls `store` needs (`openat` with `O_NOFOLLOW`,
`flock`, `fsync`, `renameat`, `linkat`, `fstatfs`, `lstat`, M4). These are very
likely to push the group past the 500 hard cap. A decision is needed before M4:
either let `store` and `term` call `rustix` directly for **safe** calls (only
`unsafe` calls must stay in `sys`; Section 4 says `sys` is "the only module that
names `rustix` or `libc`"), or raise the cap with a justification here.

**Owner decision (2026-11-10): raise the cap.** The spec's Section 3 table now
reads target 400, hard cap **800** for `sys + secmem + alloc` (owner edited
the spec; `scripts/loc_budget.py` matches). Justification: `sys` must hold
every syscall wrapper of Sections 5, 8, 9.3 and 11 under the "only `sys`
names `rustix`/`libc`" rule, which M1 alone brought to 475. The **Total**
row of the table (2,700) was deliberately not changed. If the cap is hit
again the owner will decide then.

## 2026-11-10 — Miri not run (T-SAN-2 is gated from M2)

The `cfg(miri)` heap backend (no guards, no `mlock`, heap block) compiles
cleanly with and without `memtest` (`cargo rustc --lib -- --cfg miri`; CI
`lint`). Running Miri needs a nightly toolchain. This sandbox cannot download
one (static.rust-lang.org is blocked, and the rustup home is read-only).

## 2026-11-10 — M2 format: structure and interpretations

- **Zero-copy, allocation-free parsers.** `parse_header` and `split_file`
  read from the caller's slice and never allocate, so T-FMT-4 holds by
  construction (and is asserted with a counting allocator). `parse_body`
  validates the whole body in place and returns an `Entries` iterator
  (`Clone`; `.count()` is N) whose items and their `fields` iterators yield
  slices borrowed from the caller's buffer (an arena slot in production). No plaintext is copied to the heap (rule 5).
  `EntryRef::offset` is the record's offset within the body, for M5's index.
- **The serializer validates its own output.** `BodyWriter` writes records
  into a caller-provided buffer (the scratch slot), then `finish` writes the
  prefix and minimal zero padding and runs `parse_body` over the result. A
  non-canonical body (unsorted names, duplicate keys, bad text) is therefore
  an error at save time, never a file. Exceeding the buffer is
  `Error::Capacity`, the "clean, reported error on save" of Section 5.2.
- **No `Debug` on types that reach content.** `EntryRef`, `FieldRef`,
  `Entries`, `Fields`, `BodyWriter` have none.
  `Header` derives `Debug`: it holds no secret (the DEK is wrapped).
- **Errors.** One flat `format::Error` enum, one variant per constraint,
  so each T-FMT-2 case asserts its exact variant. Entry-level variants carry
  only the 0-based entry index (Section 12.2: "naming at most the entry
  index"; rule 8). Unsorted and duplicate names are distinct variants
  (`NameOrder`, `NameDuplicate`), as T-FMT-2 lists them separately.
  There is no programming-error variant: a writer `field` before any
  `entry` yields bytes that `finish`'s self-validation rejects.
- **Definitions** (recorded in `FORMAT.md`): "control" = Unicode category
  Cc (C0, DEL, C1, exactly Rust's `char::is_control`); "whitespace" = the
  Unicode `White_Space` property (`str::trim`), the conservative reading of
  "no leading or trailing whitespace"; key case-folding is ASCII-only as the
  spec says. Bidi overrides are valid content (made visible by
  `term::sanitize`).
- **Check order.** Body: length → magic → `content_len` bound →
  `entry_count` bound → padding bytes → padding minimality → records in
  order → exact consumption. Header: fields in offset order, then
  `payload_len`; `split_file` then checks the exact file length.
- **`testkdf` marker.** Under `testkdf`, `KDF_M_MIN` is 8 KiB (Section 6.4)
  and the `KdfMemory` error message contains `PWV_TESTKDF`, so the T-ENG-7
  marker exists in any binary that can report that error.
- **Fixed header fields are implied.** `Header` has no fields for `magic`,
  `format_version`, `flags`, `kdf_id`, reserved, or `kdf_p`; `encode` writes
  their only valid values. The write floor (m ≥ 65,536, t ≥ 3) is enforced
  where headers are created (M3), not by `encode`.
- **LOC: RESOLVED (see 2026-11-11 below).** `format` alone is
  **458** (group target 450, hard cap 550), after one simplification pass
  (from 494: the `Body` wrapper, a misuse error variant, and a hand-rolled
  header copy loop were removed). The spec's "about 300 lines" for the
  parser underestimates: about 100 lines are the error enum and its fixed
  messages (one variant per constraint, required by T-FMT-2's "specific
  error variant" and Section 12.2's "exact constraint"), and about 60 are
  the serializer. That leaves **92 lines** for M3's `crypto` (NFC,
  Argon2id into the KDF region, wrap/unwrap, seal/open in place, rekey),
  which is very likely too few (estimate 130–200). Options: raise the
  `crypto + format` cap; or merge error variants (for example one `Utf8` and
  one `Control` for name, key, and value), saving about 10 lines at the cost
  of less precise import errors. The Total cap (2,700) is not at risk yet
  (1,000 used).

## 2026-11-10 — M2 tests: mechanics

- T-FMT-1 runs both identities with `proptest` at 10,000 cases each. The
  parse-then-serialize property draws from random bytes, valid bodies, and
  valid bodies with 1–3 bytes overwritten (so accepted non-trivial inputs
  occur; a separate test proves one mutation still parses).
  Generated text mixes ASCII, combining marks, astral characters,
  bidi controls, U+00A0, U+3000, and limit-length strings.
- T-FMT-2 asserts the exact variant for every constraint, with each length
  field at 0, max, and max + 1 (`name_len`, `field_count`, `key_len`,
  `value_len`, `content_len`, `entry_count`, `payload_len`, `kdf_m_kib`,
  `kdf_t`), including a full 10,000-entry body and a 16 MiB body with no
  padding.
- T-FMT-3 truncates a file and a body at every offset, and (stricter)
  truncates the entries region at every offset while keeping `content_len`,
  `entry_count`, and minimal padding consistent.
- T-FMT-4 is in its own test crate (`tests/format_alloc.rs`) with one
  `#[test]`, so the counting layer around the verifying allocator sees only
  that test's allocations. It is extended with the store read path in M4.
- **Miri (T-SAN-2).** Under `cfg(miri)` only: proptest runs 8 cases without
  failure persistence, and two tests are compiled out: the 16 MiB body (out
  of reach for an interpreter; the same loop runs on small bodies) and the
  corpus-file check (file I/O under Miri isolation). Also reduced under Miri
  (2026-11-11, after the first CI Miri run stalled for 25 min inside
  `t_fmt_2_body_length`): that test's 16 MiB + 4 KiB length case becomes
  3 × 4096 − 1 under Miri (the length check is O(1); the zeroizing
  allocator wipes and verifies a 16 MiB buffer byte by byte, which Miri
  interprets). Measured on CI, Miri handles about 20 KB of buffers in
  `t_fmt_2_value_len_*` in 144 s, so the 16 MiB case would need days. The
  10,000-entry case and the full `testkdf` suite were reduced at first and
  are **restored** (M3, owner: long runs are fine if they progress); the
  10,000-entry test runs as its own Miri job. The native run is
  unchanged. Miri itself could not run in the sandbox (no nightly); see the
  entry "Miri not run".
- A hand mutation check (12 mutants: each body and header constraint
  removed or loosened) killed all 12. This is not T-MUT-1, which is M9.

## 2026-11-10 — M2 fuzzing

- `fuzz/` is a separate crate (`pwv-fuzz`, its own `[workspace]`), using
  `libfuzzer-sys` 0.4.13 (dev-only). Its `Cargo.lock` was seeded from pwv's,
  so every shared crate has the identical version; only `libfuzzer-sys`,
  `arbitrary`, `jobserver`, and the fuzz crate itself are new. It depends on
  `pwv` with default features off (no clipboard, no zxcvbn).
- Targets install the verifying `ZeroizingAlloc`, as the tests do.
  `fuzz_header` (T-FUZZ-1) asserts header re-encoding identity and the split
  lengths; `fuzz_body` (T-FUZZ-2) asserts serialize(parse(b)) = b.
- Seeds: `fuzz/corpus/<target>/seed-*`, generated by
  `PWV_WRITE_CORPUS=1 cargo test --test format corpus` and checked to be
  current by that test. Golden vectors join the seeds in M3. Runs write new
  units to a scratch corpus listed first, so the committed corpus holds only
  seeds and promoted regressions.
- Flags (Section 14.10): `-max_total_time=60 -rss_limit_mb=256
  -malloc_limit_mb=64 -timeout=1 -max_len=24576`.
- **Sandbox run (2026-11-10):** stable 1.99.1, `cargo-fuzz` 0.13.2 with
  `-s none` (no ASan; ASan needs nightly). 60 s each, clean:
  `fuzz_header` ≈ 151 M execs, `fuzz_body` ≈ 774 K execs, RSS ≈ 28 MB.
  CI's `fuzz-smoke` runs the same with nightly and ASan.

## 2026-11-11 — RESOLVED: LOC caps for `crypto + format` and Total

**Owner decision (2026-11-11):** the Section 3 table now reads hard cap
**750** for `crypto + format` (was 550; +200) and **3,000** for the Total
(was 2,700). Targets are unchanged. `scripts/loc_budget.py` matches.
Justification: the M2 entry above (`format` is 458 lines, about 100 of them
the per-constraint error enum that T-FMT-2 and Section 12.2 require, leaving
92 lines for M3's `crypto`, estimated at 130–200).

## 2026-11-11 — First CI run: fixes, and all gates on every push

- **T-MEM-5 race (test failure).** GitHub runners start processes with a
  soft core limit of 0 and a hard limit of `unlimited`. The test waited for
  "soft limit == 0" as its signal that `harden()` had run, so on CI it read
  `/proc/<pid>/limits` before `harden()` ran and saw `0 unlimited`. The
  test now waits for the observable end state of steps 1–3 (core `{0, 0}`,
  non-dumpable, umask 0077, or a 10 s deadline), then re-reads every value
  it asserts. Reproduced and verified locally with `ulimit -Sc 0`.
- **`fuzz_body` out-of-memory (fuzz-smoke failure).** No leak and no large
  allocation: ASan's quarantine keeps freed blocks resident (256 MiB by
  default on x86_64), and `-rss_limit_mb=256` counts them. `fuzz_body`
  allocates an output buffer per input; `fuzz_header` allocates nothing,
  which is why only `fuzz_body` failed. `fuzz-smoke` now sets
  `ASAN_OPTIONS=quarantine_size_mb=32`; `-rss_limit_mb=256` and
  `-malloc_limit_mb=64` (the "no allocation above 64 MiB" invariant) stay as
  specified. (Inferred: the log excerpt lacked libFuzzer's detail line.)
- **Miri (T-SAN-2) on every push.** Section 15.3 schedules `sanitizers`
  nightly; it now also runs on every push (it was skipped on the first push),
  so the M2 gate does not depend on a local nightly toolchain. Running more
  often than specified is a strict superset.
- **New `coredump` job: T-MEM-5's "no `coredumpctl` entry".** On the runner:
  install `systemd-coredump`, apply its `core_pattern`, set
  `fs.suid_dumpable = 0` (the host the 2026-11-10 owner decision assumes),
  run a positive control (a dumpable process killed by SIGSEGV *is*
  recorded, so the check is not vacuous), run T-MEM-5 against the release
  binary, then fail if `coredumpctl list pwv` finds an entry.

## 2026-11-11 — M3: cryptography

- **Where the lifecycle lives.** `format` and `crypto` share a layer, and
  same-layer modules may not use each other (2026-11-10 entry). `crypto`
  therefore holds only byte-level primitives: `normalize`, `derive_kek` /
  `argon2_in_region`, `wrap_dek` / `unwrap_dek`, in-place `seal` / `open`,
  `fill_random`, `ct_eq`. The file-level key lifecycle of Section 6.3
  (`init`, `unlock`, `open_with_kek`, `save`, `passwd`, `adopt_dek`) needs
  header bytes as associated data, so it is in `vault` (layer 3, pure),
  which the unlock and save data flows of Section 4 already route through.
- **AEAD API (rule 4 and rule 10).** Section 3 names
  `encrypt_in_place_detached` / `decrypt_in_place_detached`. In
  `aead` 0.6.1 these are on the deprecated `AeadInPlace` trait, whose
  blanket impl forwards to `AeadInOut::{en,de}crypt_inout_detached(nonce,
  aad, buf.into())`. `crypto` calls those forwarded-to methods with an
  `InOutBuf` made from a single `&mut [u8]`: the same in-place operation,
  without deprecated calls (CI denies warnings). No out-of-place or
  allocating API is used. On a failed tag the buffer is zeroized.
- **Password normalisation.** Section 6.2's formula is normative:
  P′ = UTF8(NFC(P)). The OpaqueString profile's extra mapping of non-ASCII
  spaces to U+0020 is not applied, since it is not in the formula.
  Non-UTF-8 input is rejected (`crypto::Error::Password`, also when the
  NFC form exceeds the 1 KiB slot: NFC can expand, e.g. U+0958 is 3 bytes
  and normalises to 6). Empty passwords and the strength policy are the
  CLI's job (M7). `normalize` writes NFC output char by char straight into
  the slot; `unicode-normalization`'s internal buffer is covered by the
  zeroizing allocator.
- **KDF memory (Section 5.4).** `secmem::KdfRegion` is a `GuardedRegion`
  (guards, `MADV_DONTDUMP`, `MADV_WIPEONFORK`) viewed as `argon2::Block`s
  through one `unsafe` slice cast (alignment checked at run time,
  size/alignment at compile time). `mlock` is attempted; the result is
  `KdfOutcome::locked`, so the CLI can print the step 3 notice once per
  unlock, and `require_locked` (`--require-locked-kdf`) turns failure into
  `KdfUnlocked` (exit 4). The region is zeroized, `munlock`ed, and unmapped
  before `argon2_in_region` returns, then `sys::scrub_stack()` runs: Argon2
  keeps a 1 KiB block hash and address blocks on its own stack, which it
  does not wipe (Section 18 residual risk). `KdfOutcome` carries the
  region's address range for T-MEM-7 and, in `memtest`, whether every byte
  was zero just before `munmap`.
- **`testkdf` lowers the write floor too.** Section 6.4 says `testkdf`
  "lowers the read floor to 8 KiB". Golden vaults are "built with
  `testkdf`" (T-COMPAT-1), which requires writing at low cost, so under
  `testkdf` `KDF_M_WRITE_MIN` = 8 KiB as well. The t ≥ 3 write floor is
  unchanged. Production builds keep both floors at 64 MiB and refuse the
  golden vaults on read (asserted by `t_compat_1_golden_vaults`).
- **Save.** `vault::save` validates the body with `parse_body` (a
  non-canonical body is never encrypted), increments the generation
  (checked), draws a fresh payload nonce, validates the new header,
  encrypts the body in place in its arena slot, copies header, ciphertext,
  and tag into the file `Vec`, then decrypts the slot back in place. The
  decryption verifies the file just produced, and the slot stays plaintext
  so the scratch half can become the live half (Section 4, save step 3).
  `h` changes only on success.
- **Generations.** `init` returns a header with generation 0 that is never
  written: the first `save` writes generation 1, as Section 6.3 requires.
  `passwd` keeps the vault ID and generation and draws a fresh salt, DEK
  (into `NewDek`), and wrap nonce; the re-encrypting `save` draws the fresh
  payload nonce and increments the generation. The caller adopts the new
  DEK (`adopt_dek`) only after the new file is safely written (M4).
- **Unlock.** Parses the header, normalises `Pw1` into `Pw2`, wipes `Pw1`,
  derives the KEK, wipes `Pw2`, unwraps the DEK into `Dek` (in place),
  wipes the KEK, copies the ciphertext into the vault slot, decrypts in
  place, and validates the body (data-flow step 7). Any failure leaves
  `Dek` and the vault slot empty; the password slots and `Kek` are always
  empty on return. A payload larger than the vault slot is
  `vault::Error::Capacity` (exit 1, "raise --arena-size"), reported only
  after the DEK unwrap succeeded.
- **Exit codes.** `cli::exit_code` maps lifecycle errors: authentication
  2, format/generation 3, KDF memory 4, password/parameters/capacity 1,
  RNG/length 5. The spec gives no exit code for capacity; 1 (user error) is
  used because `--arena-size` fixes it.
- **Constant-time comparison.** `crypto::ct_eq` is the "small hand-written
  constant-time loop" of Section 5.2; adding `subtle` is not needed.
- **Tests.** `tests/crypto.rs`: T-KAT-1 (through `argon2_in_region` with
  p = 4, secret, and associated data), T-KAT-2 (in place), T-CRY-1 (every
  bit of `v1-small.pwv`, 34,368 cases with the KEK cached, plus 100 random
  full-path cases; random flips that would raise `kdf_m_kib` above 64 MiB
  are redrawn, because the full path would derive with up to 4 GiB per
  case, and the cached-KEK sweep covers them), T-CRY-2 (also checks
  `cli::exit_code` = 2), T-CRY-3 (10⁵ saves), T-CRY-4 (including splicing
  the old wrap into the new file), T-CRY-5 (each header byte × 3 masks,
  checked at the exact layer: unwrap for bytes 0..148, open for 148..184),
  T-CRY-6 (both directions), T-COMPAT-1. Without `testkdf`, T-CRY-1 runs
  on a fresh vault at the production floor. `tests/kdf_region.rs` is T-MEM-7
  (one test per crate, so no other thread maps memory during the
  `/proc/self/maps` check). A child process with `RLIMIT_MEMLOCK` = 0
  checks `--require-locked-kdf`.
- **Golden vectors.** Four vaults (`tests/vectors/`, `MANIFEST` in a
  line-based hex format), generated once; the generator refuses to run
  while `MANIFEST` exists. `scripts/verify_golden.py` re-implements
  Section 6.2 and the body parser with argon2-cffi and libsodium (CI job
  `compat`, with a tampered-copy negative control).
- **T-FUZZ-3** (`fuzz/fuzz_targets/fuzz_open.rs`): mode byte, then either a
  file unlocked with the golden password (KDF cost capped at 256 KiB and 4
  passes per input; costlier headers take the post-KDF path) or a body
  that is saved under a fresh vault and must round-trip exactly when
  `parse_body` accepts it. The fuzz crate's `testkdf` feature is enabled
  only for this target (`required-features`), so `fuzz_header` keeps the
  production floor. Sandbox run (stable, `-s none`, 60 s): about 295,000
  execs, clean.
- **Test speed.** `[profile.dev.package."*"] opt-level = 3` optimises
  dependencies (Argon2, ChaCha20, proptest) in dev and test builds; pwv
  itself stays unoptimised with debug assertions. Release builds are
  unaffected.
- **Miri (T-SAN-2).** CI runs Miri on the `crypto`/`vault` tests that fit
  an interpreter (KATs, primitives, lifecycle, T-CRY-2, -4, -6), which also
  covers the `KdfRegion` cast. The heavy sweeps (T-CRY-1, -3, -5), the 6 MiB
  capacity case, file I/O, and child processes (Miri isolation) run
  natively. Under Miri the test arena is 256 KiB, not 1 MiB.
- **LOC after M3.** `crypto + format` 666 / 750; `vault` 196 / 300 (the
  lifecycle). M5's model operations must fit the remaining 104 lines of
  `vault`'s cap (target 250); a decision may be needed then.


## 2026-11-11 — M3 gate green on CI

All jobs passed on the first M3 push. Miri job durations (parallel):
`crypto-vault` 37m 39s, `format-testkdf` 33m 02s, `format-10000-entries`
15m 41s, `format` 11m 41s — all far inside the 6 h job limit (the
`sanitizers` job timeout is 350 min), so no test was reduced for time.
Owner decision: LOC caps (notably `vault` 196 / 300) are revisited before
M5; the specification is unchanged until then.

## 2026-11-11 — M4: storage

- **API.** `store::Paths::resolve(flag, env)` (Section 8.1);
  `Store::open(paths, allow_foreign_fs) -> (Store, file bytes)`;
  `Store::create(paths, allow_foreign_fs)` for `init` (the first
  `save` writes the file); `Store::save(file)`; `Store::freshness(header)`
  (Section 8.4). The session `flock` lives as long as the `Store`. `cli`
  gains `store_exit_code`, `rollback_warning`, and `confirm_rollback`: the
  logic of the Section 8.4 prompt, which M7 wires to the terminal.
- **Paths.** XDG values that are empty or relative are ignored (XDG Base
  Directory specification), and so is a relative `HOME`. An empty
  `--vault` or `PWV_VAULT` is an error (`Error::Path`, exit 4), never a
  silent fallback to another vault. The state path needs `HOME` or
  `XDG_STATE_HOME` even with `--vault`. Names beside the vault:
  `<name>.lock`, `<name>.1` … `.5`, temporaries `.<name>.tmp.<16 hex>`.
  The backup copy (fallback) also uses the vault's temporary name, so the
  open-time cleanup covers it; T-STORE-2 found this. The state directory
  holds `state`, `state.lock`, `.state.tmp.<16 hex>`.
- **Open-time checks (8.2), as implemented.** (a) Open the directory with
  `O_DIRECTORY | O_NOFOLLOW` (= "lstat, must be a directory, no symlink",
  without a race). (b) **`statfs` first**, then the directory's owner and
  mode. This is a deviation in order only: on a foreign filesystem, owner
  and mode are synthetic (ntfs-3g reports `nobody`, 0777, as this
  sandbox's `/workspace` does), so checking them first gave a misleading
  "wrong owner" instead of the S8 refusal. (c) `lstat` of the vault (a
  regular file, owner, mode) **before** the lock file is created, so open
  never creates anything when the vault is missing (B1). (d) The lock
  file: `O_NOFOLLOW`, created 0600, owner/type/mode checked (stricter than
  the spec), `flock(LOCK_EX | LOCK_NB)`. (e) Stale-temp cleanup. (f) The
  vault is opened again **after** the lock (`O_NOFOLLOW | O_NONBLOCK`, so a
  planted FIFO cannot block), `fstat`-checked, the 184-byte header parsed,
  and its claimed length compared with the file size **before** the
  buffer is allocated (Section 7.1). Reading before the lock could return
  the inode a concurrent session was replacing.
- **`--allow-foreign-fs` waives only the `statfs` check.** Owner and mode
  are still enforced, so a default ntfs-3g mount (0777, `nobody`) stays
  refused even with the flag. It opens only if the mount reports our UID
  and private modes (for example `uid=`, `umask=077`). Fail closed. The
  state directory gets the same checks and the same flag.
- **Foreign magic numbers.** `statfs` reports one magic number for every
  FUSE mount, so `fuseblk` cannot be told apart from sshfs or gocryptfs
  without parsing `/proc/self/mountinfo`. All FUSE mounts are refused (the
  conservative choice); the flag overrides. The legacy in-kernel `ntfs`
  driver (0x5346544e) is refused along with `ntfs3`. **Open question for
  the owner:** WSL2 exposes Windows drives through 9p (`drvfs`,
  0x01021997) or virtiofs, and neither is in Section 8.2's list. Since
  that list says "namely", they are not refused. *Resolved in the CI
  round 1 entry below: 9p is refused.*
- **Rollback check after authentication.** `freshness` takes the header
  returned by `vault::unlock`, never the unauthenticated bytes, so M7
  runs unlock → `freshness` → prompt. `confirm_rollback` accepts exactly
  `yes`; `term` (M7) strips the line ending first. On `yes`, the header's
  generation is raised to g_s, so the next save writes max(g_f, g_s) + 1.
- **State file.** One line `<32 lowercase hex> <decimal>\n` per vault,
  parsed strictly: no sign, no CR, no missing final newline, no duplicate
  IDs, cap 1 MiB. A malformed file is `Error::State` (exit 3): refusing is
  the conservative option, because ignoring it would silently disable G3.
  The user can inspect or delete it. Writes never lower a recorded value
  (`max`), and they happen under `state.lock`, because sessions on
  *different* vaults may save at the same time and a read-modify-write
  would lose one record.
- **Save.** `split_file` first, so a malformed file is refused before
  anything on disk changes. Hard links that are unsupported (`EPERM`,
  `EOPNOTSUPP`, `ENOSYS`) fall back to copying via the same atomic
  write. On an I/O error after the temporary file exists, it is unlinked.
  The backups were already rotated, as in the crash table's
  "steps 1–2" row (`failed_save_leaves_vault_state_and_no_temp_file`,
  which uses `RLIMIT_FSIZE` to cause `EFBIG`). **Known edge for M7:** if
  the directory `fsync` fails *after* the rename, `save` returns `Io`
  although the new file is in place. Section 8.5's "a failed command
  leaves disk unchanged" cannot hold there. M7 should treat any save error
  as fatal for the session (wipe, exit 4) rather than keep a model that
  may disagree with the disk.
- **Exit codes.** `NoVault` and `Exists`: 1. `Format` and `State`: 3.
  `Path`, `Kind`, `Owner`, `Mode`, `ForeignFs`, `InUse`, `Io`: 4.
- **Fault hook (T-STORE-2).** A `#[cfg(test)]` boxed closure, not a
  trait; rule 7 allows one but none is needed. It is called at 17 points
  of a save (23 with the copy fallback): 4 renames, link, then 6 points
  each for the temporary-file write of the vault and of the state (plus 6
  for the copy fallback). A
  crash is a panic in the hook: unwinding only closes fds, so no
  error-path cleanup runs, exactly as when the process dies. The page
  cache survives, as with SIGKILL; power loss is T-STORE-8 (M9). Since a
  unit test in `store` may not use `vault` (same layer), T-STORE-2
  asserts **byte identity** with the old or the new file, which is
  stronger than model equality. It also checks the exact old/new boundary
  (the vault rename), the recorded state generation (the state rename),
  freshness, backups, temp cleanup, and that the next save recovers. Runs
  from 1, 2, and 7 prior saves, with and without the link fallback.
- **T-STORE-1 owner.** The test-only UID override is the private
  `Store::open_as(.., euid)` plus unit tests of `check()` for each object.
  The integration test also uses a real root-owned directory (`/`).
  `t_store_1_foreign_fs_real_mount` runs when `PWV_FOREIGN_DIR` is set.
  CI sets it to a vfat loop mount, which also exercises the copy fallback
  on a filesystem without hard links. Locally the refusal half passed on
  a `fuseblk` mount.
- **T-STORE-3.** Children receive the KEK through the environment (test
  only), so they start saving within milliseconds instead of spending the
  0–50 ms window in Argon2. The delay is measured from the child's
  `PWV ready` report. Checks per kill: SIGKILL was the cause of death;
  reports are consecutive; the vault opens and its generation is the last
  reported commit or one more (killed between rename and report); its
  content matches its generation; it is fresh; every backup decrypts to
  its own generation's model; no temporary file survives the open. The
  seed is random and printed in every failure (`PWV_T_STORE_3_SEED`
  replays it); `PWV_T_STORE_3_ITERATIONS` ≥ 500. Local run (tmpfs): 500
  kills, 2,897 commits, 40 kills before the first commit, ~30 s. The CI
  job `durability` runs 5,000 iterations on ext4, on every push.
- **T-STORE-4.** The second process (a re-run of the test binary) measures
  ~3 ms spawn-to-exit locally against the 100 ms bound, even while the
  kill loop runs in parallel. The message contains both "in use"
  (T-STORE-4) and "open in another session" (Section 8.2). The lock is
  released on a clean exit and on SIGKILL.
- **T-STORE-9 at M4** is store-level: three open → decrypt → freshness →
  close sessions leave inode, mtime, ctime, size, and link count unchanged
  for every file and both directories, with a positive control (a save
  changes them). M7 repeats it with the read-only commands.
- **T-FMT-4** now includes `Store::open` on planted files (1 GiB sparse
  file, 16 MiB claimed for 200 bytes, hostile `payload_len`/`kdf_m_kib`,
  short file): each refused, largest allocation ≤ 64 KiB.
- **Test harness: fork vs. `flock`.** The first full local run was flaky
  (4 of 6 memtest runs; `InUse` on a reopen). Cause: `tests/store.rs`
  spawns children (T-STORE-3, T-STORE-4, the `RLIMIT_FSIZE` test, `sh`
  for the remedies) from other test threads. Between `fork` and `exec` a
  child holds copies of every fd, including another test's lock fd, so a
  just-closed session's `flock` briefly stays held. The `pwv` binary
  never forks (Section 5.7), so production is unaffected. Fix, in the
  test crate only: a `RwLock` that spawns hold for writing and asserted
  opens/creates hold for reading (`Command::spawn`/`output` return after
  `exec`). No retry, and no assertion was loosened. Afterwards 10 of 10
  memtest runs passed, plus all five configurations.
- **Hand mutation check** (not T-MUT-1): 18 mutants of `store`; 16
  killed (the temp-unlink mutant survived at first and is now killed by
  the `RLIMIT_FSIZE` test). Survivors: removing the temp-file `fsync` and the directory
  `fsync`, which only power loss can reveal (T-STORE-8, LazyFS, M9).
- **LOC.** `store` is 400 (target 250). **Owner decision (2026-11-11):**
  the `store` hard cap is raised to **450**; the owner edits the Section 3
  table and `scripts/loc_budget.py` matches. Justification: the error
  enum (~60 lines, with the exact `chmod` remedy), XDG resolution (~28),
  open-time checks for directory, vault, and lock with
  header-before-allocation (~110), rotation, copy fallback, and atomic
  write (~70), and the locked state file (~80). A simplification pass
  went from 413 to 400; reaching 300 would mean deleting required
  behaviour. `sys` gained the file wrappers (613 / 800 for the group).

## 2026-11-11 — M4 CI round 1: durability failure fixed

- **CI result.** Every job passed, including the vfat loop-mount step of
  T-STORE-1, except `durability`. T-STORE-3 failed at iteration 87
  (seed 0xab3c76d5e01867c1): a child exited on its own instead of dying
  by SIGKILL. Its stderr went to `/dev/null`, so the log showed no cause,
  and the seed did not reproduce on this sandbox's tmpfs.
- **Cause: a real bug in the save protocol, not in the test.** If a save
  is killed after step 2's `link(vault, .1)` and before step 4's rename,
  `.1` is a hard link to the vault. Every further crash in that window
  shifts the duplicate up one slot. After five such crashes in a row,
  `.1`–`.5` and the vault are all links to one inode. `rename(2)` is a
  no-op when both names link one inode (POSIX), so the whole rotation
  does nothing, `.1` survives, and `link` fails with EEXIST on every
  later save. The vault stays readable, but it can never be saved again.
  CI's ext4 `fsync` makes the temp-file write most of a child's first
  save, so consecutive kills inside that window are likely there and
  almost impossible on tmpfs.
- **Why T-STORE-2 missed it.** It injected each crash once and then made
  one recovery save. It now repeats each crash BACKUPS + 1 times at the
  same point. Recovery then saves through a whole backup cycle and checks
  that `.1`–`.5` hold the last five generations with `nlink == 1`. The
  extended test failed with `Err(Io)` from `link` before the fix and
  passes after it.
- **Fix.** After each rotation rename, `unlink(.i)`, ignoring ENOENT. The
  old name only still exists when the rename was a no-op, and then it
  duplicates `.i+1`, so nothing is lost. A crash between the rename and
  the unlink leaves the same state the next rotation already handles.
- **Not changed: backup depth after repeated crashes.** A crash in the
  link-to-rename window costs one backup slot, because the next rotation
  shifts the duplicate up. That matches Section 8.3's crash table
  ("backups shifted"). Skipping the rotation when `.1` is already the
  vault's inode would keep the depth, but it needs inode comparison.
  Raise it if wanted.
- **Kill loop diagnostics.** T-STORE-3 now captures each child's stderr
  and prints it if the child exits on its own or never becomes ready.
- **9p refused (owner decision).** WSL2 DrvFs mounts Windows drives over
  9p (V9FS_MAGIC 0x01021997), and its permission bits are synthetic unless
  it is mounted with `metadata`. Under the owner's rule (refuse any
  filesystem that allows synthetic bits), 9p joins the foreign list;
  `--allow-foreign-fs` still waives it. WSL2's virtiofs reports the FUSE
  magic, which is already refused. The spec's Section 8.2 "namely" list
  does not name 9p yet; the owner edits the spec.
- **Spec change (owner request):** Section 8.5 now says that a failed
  save is fatal to the session, because a failure after the step 4
  rename may already have replaced the file. M7 implements this.
- **CI:** the `test` job has a new step, "M4 gate by name", that lists
  every T-STORE test in the log and fails if any one did not run. T-STORE-4
  was already running inside each `cargo test` step, but no step name
  showed it.
