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

## 2026-11-11 — M4 CI round 2: M4 gate green on CI

- **CI result.** Every job green, including `durability` (5,000 kills in
  161 s) and the new "M4 gate by name" step, which listed all 14 gate
  tests. The owner added 9p to Section 8.2's list.
- **CI maintenance.**
  - `actions/checkout@v4` → `@v5` (Node 24 runtime, removing GitHub's
    Node 20 deprecation warning). `actions/upload-artifact@v4` → `@v6`
    for the same reason. A missing tag would fail at "Set up job", so the
    next run verifies both.
  - Runners are pinned to `ubuntu-24.04`. `ubuntu-latest` moves to 26.04
    from 2026-10-19, and during that migration jobs could land on either
    image. Spec 15.3 names `ubuntu-latest` only as an example. Moving to
    26.04 will be a separate change with a full run.
  - Every job has a `timeout-minutes`: 120, or 350 for Miri. A stall
    therefore fails within 2 h instead of 6 h. `durability` went from
    350 to 120 minutes, more than 10 times its measured runtime.
- **T-STORE-3 statistics.** The loop now prints its seed and its counts on
  every run (`--nocapture` in `durability`): kills before the first
  commit, kills after commits, kills between `link` and rename, the
  longest run of those, and the final generation. These are information
  only. A "kills in the link window" assertion would be flaky: this
  sandbox saw only 1–6 of 500 in debug.
- **Known local-only flake, test unchanged.** The non-vacuity guard
  `none > 0` needs a kill before the child's first commit. In release on
  tmpfs a save takes about 0.1 ms, so a uniform 0–50 ms delay misses it in
  roughly a third of runs (2 of 6 in this sandbox). It holds on CI's
  ext4, where the first save includes real `fsync`s. Rule 2 forbids
  weakening the guard, so it stays; the owner may decide otherwise.

## 2026-11-11 — CI round 3: timeouts from measurements; runners to 26.04

- The owner reported every job green, both deprecation messages gone,
  and these runtimes: lint 4m10, test 21m05, compat 0m10, fuzz-smoke
  2m41–2m54, sanitizers 12m21–28m35, durability 4m10, coredump 5m16,
  supply 6m57.
- **Timeouts** (about 3× the measured runtime, minimum 10 min): lint 15,
  test 60, compat 10, fuzz-smoke 15, sanitizers 90, durability 20,
  coredump 20, supply 25. Raise a cap only together with a new
  measurement, for example when M9 adds LazyFS to `durability`.
- **Runners: `ubuntu-24.04` → `ubuntu-26.04`.** On the owner's request
  this went in a round with no functional change, so any difference in
  results comes from the image. The parts that depend on the image:
  `rustup` preinstalled; apt `dosfstools` (vfat step) and
  `systemd-coredump` (coredump job); `python3 -m venv` with the pinned
  argon2-cffi 23.1.0 and PyNaCl 1.5.0 (`compat`; both ship abi3 wheels);
  and loop mounts under `sudo`.
- **T-STORE-3 on CI (5,000 kills, seed 0xc4012390fca09c1b):** 101 kills
  before the first commit, 4,899 after; 1,185 between `link` and rename,
  with a longest run of 5. That is exactly the length that broke saves
  before round 1's fix, so CI now exercises the regression case directly.

## 2026-11-11 — CI round 4: first run on ubuntu-26.04

- **coredump failed: the positive control broke on the new image.**
  Ubuntu 26.04 ships uutils (Rust coreutils) as one multicall binary that
  dispatches on `argv[0]`. The control copied `/bin/sleep` to `pwvctl`,
  and the copy exited at once with "unknown program 'pwvctl'". The SIGSEGV
  then hit no process. The control is now a one-line Rust program,
  `std::process::abort()`, compiled by `rustc` in the job. It dumps core by
  itself (SIGABRT), so it doesn't depend on the image's coreutils and has
  no sleep/kill race. Checked locally: it exits 134 and dumps core. The
  T-MEM-5 checks themselves did not change.
- **LOC caps (spec Section 3, owner decision):** store 450 (as decided in
  round 1; the spec row is now 450), vault 300 → 500, `term` + `clip` 350,
  Total 3,000 → 3,200. `scripts/loc_budget.py` matches. Current usage:
  store 409/450, vault 196/500, total 1,992/3,200.
- **Runtimes on 26.04:** lint 5m22, test 25m49, compat 0m09, fuzz-smoke
  2m50–3m03, sanitizers 15m35–37m48, durability 4m09, supply 6m50.
  coredump took 3m29 but failed early. Under the 3× rule this sets lint
  to 16, test to 80 and sanitizers to 115 minutes. Every other cap already
  has at least 3× headroom.
- **T-STORE-3 on 26.04 (seed 0xb90fbed75c1b5f5):** 174 kills before the
  first commit, 4,826 after; 1,108 between `link` and rename, with a
  longest run of 5, so the round-1 regression case was exercised again.

## 2026-11-11 — M5: model

- **API.** `vault::Model<'a>` owns the two vault slots (live and scratch,
  taken from `Slots`) and an index: a `Vec<usize>` of entry offsets, which
  is not secret. `Model::new(live, scratch)` takes a decrypted body (unlock)
  or an empty slot (init: the empty vault). Reads: `body`, `len`,
  `entries`, and `get` (binary search over the index, through the new
  `format::entry_at`). Operations: `add`, `set`, `unset`, `mv`, `mvfield`,
  `rm`, `import`. Saving: `seal(dek, &mut header)`.
- **Every operation is a full rewrite (principle 3).** It validates the
  input, builds the list of output entries (`Vec<Item>`: borrowed slices
  of the live slot and the caller's input slot, so pointers only, never
  bytes), checks lookups, collisions, and limits, and writes the new body
  with `BodyWriter` into scratch. `finish` re-validates the body. The
  halves are then swapped and the old live half zeroized. On any error,
  scratch is wiped and live is byte-identical to before. No secret byte is
  ever copied outside the arena: suffixed import names are written in
  two parts (`BodyWriter::entry_suffixed`), not joined first.
- **Save sequence (Section 4, deviation in order only).** The data flow
  says: serialise into scratch, encrypt there, then make scratch live.
  Here the operation makes the new body live first (in memory). `seal` then
  copies live into scratch, encrypts it in place there (`save`, which
  also decrypts it back to verify), copies the ciphertext out, and wipes
  scratch. The invariant is the same: plaintext exists only in the two
  halves. Keeping save separate from the operation lets M7's guided `add`
  run `add` followed by one `set` per field, then save once. Cancelling is
  `rm`, which restores the identical body (the canonical form is unique),
  without a save. A failed save is fatal to the session (Section 8.5), so
  the in-memory model never outlives a disk that disagrees with it.
- **Import (Section 12.2) uses one slot.** stdin is read into scratch, as
  the spec says. There is no third buffer for the merge, so `import`
  first validates the body (`parse_body`; an error is
  `Invalid(<exact constraint, entry index>)`). It then moves the body to
  the top of scratch (`copy_within`) and writes the merge into the bottom
  (`split_at_mut`: the two regions are disjoint). The cost is that
  **merged body + import body must fit the slot**; otherwise `Capacity`
  is a clean error (fail closed). At the default 1 MiB arena the slot is
  about 510 KiB, against kilobytes for a migrated vault.
- **Suffix and collisions.** The suffix is ` (imported)`. The spec's
  backticks hold stray spaces, and a name may not end in whitespace, so
  no other reading is valid. Suffixed names can sort after other imported
  names (`a (imported)` > `a !`), so the merge sorts the item list rather
  than streaming. Rules: without `--on-conflict suffix`, any imported name
  equal to an existing one is `EntryExists`. With it, the colliding name
  gets the suffix; if the suffixed name is over 256 bytes, the result is
  `Invalid(NameLength(i))` (i = the import's entry index). If the
  suffixed name is itself taken (by a live entry or another imported
  one), the result is `EntryExists`, never a second suffix. Then come
  10,000 entries (`Invalid(EntryCount)`) and capacity. One import is one
  operation, so the CLI does one save and one generation increment.
- **Interpretations (rule 10).**
  - Collision means "the new name or key belongs to a *different* entry
    or field". `mv x x` is therefore a no-op, and `mvfield e password
    Password` (case only; keys are unique under ASCII folding) renames that
    field. Refusing these would block a harmless rename without protecting
    anything, and B4 is about overwriting another item.
  - `set`, `unset`, and `mvfield` address keys ASCII-case-insensitively,
    the same rule the format uses for uniqueness. `set` on an existing key
    replaces the value and flag in place and keeps the stored key
    spelling (`mvfield` renames it). The sensitive-replacement
    confirmation and hidden double entry are M7 (CLI).
  - Check order, which the reference model mirrors: input validity
    (`format::check_name`/`check_key`/`check_value`, in the parser's
    order), lookups (`NoEntry`, `NoField`), collisions, count limits
    (64 fields, 10,000 entries), then capacity.
- **Errors.** New `vault::Error` variants: `Invalid(format::Error)` (user
  input or an imported body; distinct from `Format`, which is integrity,
  exit 3), `EntryExists`, `FieldExists`, `NoEntry`, `NoField`. All exit 1.
  The messages are fixed, and an index in a user-operation error is 0.
- **`format` additions** (+30 lines, 696/750): `check_name`, `check_key`,
  `check_value` (the parser now calls them; same order, same variants),
  `entry_at` (the record parser at an index offset), and
  `BodyWriter::entry_suffixed`.
- **Rule 7.** The per-operation plan is a `&mut dyn FnMut` (a trait object,
  as in `store`/`secmem`), not a generic. `entries()` and the sort key
  return `impl Iterator` (an opaque return type, not a type parameter).
- **Section 15.5 checklist.** New parsing paths: the import body (the
  existing strict `parse_body`) and `entry_at`. Fuzz target: T-FUZZ-6
  `fuzz_import`. It imports two bodies, the second in either mode, and
  compares with an independent merge oracle: exact merged model, or the
  same error class with the body unchanged; scratch empty; the index finds
  every entry. Truncation tests: `import_rejects_invalid_bodies_and_every_truncation`
  (raw cut at every offset, and entries cut at every offset with a
  consistent prefix) and `entry_at_on_truncations_and_every_offset`.
  Local run (stable, `-s none`, 60 s): 249,730 execs, clean.
  No new `unsafe`; no new disk write path; no secret outside the arena.
- **T-VAULT-1** (`tests/vault.rs`): 256 cases. Each case uses a 256 KiB
  or 1 MiB arena (cases in the 256 KiB arena start from 0–30 synthetic
  4 KiB filler entries, so they reach `Capacity`) and 0–200 operations.
  Every operation runs on the model and on a `BTreeMap` reference that
  implements the rules independently, including the error precedence
  and capacity (merged + import ≤ slot for import). After every operation
  the test compares: the exact `Result`; entries, keys, flags, values, and
  order; index lookups for every name the operation touches; scratch
  empty; and, on an error, the body unchanged. Every 10 operations it
  seals, saves through `store` (temporary directory under `/tmp`), closes,
  reopens with `Store::open`, unwraps the DEK, decrypts, and compares the
  exact canonical bytes. Generators: adversarial names (case, NFC/NFD,
  leading and trailing whitespace including U+00A0/U+3000, the suffix,
  limit lengths 245/246/256/257 bytes, 64 astral characters, controls
  C0/DEL/C1, invalid UTF-8), keys and values at their limits, and
  selectors that pick existing names and keys (in another ASCII case) at
  run time, so hits and collisions are frequent. A non-vacuity check
  requires every operation to succeed somewhere and every error class
  to occur. One KDF run per test: the KEK and DEK are derived once and
  shared by the cases.
- **T-VAULT-2:** exhaustive on a near-duplicate fixture (every colliding
  `add`, `mv` over ordered pairs, `mvfield` over ordered key pairs in
  three ASCII cases, and `import` in abort mode alone and between new
  names, plus suffix-mode secondary collisions; 100+ cases), and
  property-based on 64 random models. Each case asserts: the exact `Err`;
  the model body byte-identical; scratch wiped; the file on disk and the
  directory listing unchanged. A positive control saves a real change.
- **Test output holds no content (rule 9).** Generated content is a `Txt`
  whose `Debug` is `[REDACTED; n bytes]`. Proptest's failure report and
  `tests/vault.proptest-regressions` therefore show only op kinds,
  lengths, and selector indices, and assertion messages name only
  indices and error variants. An early run printed a raw model from a
  strategy that yielded a bare `BTreeMap`; that strategy now yields
  `Txt`, and the model is built inside the test. The regression file
  that run wrote held the same bytes; it was deleted (its seed belonged
  to the old strategy). To debug a failure,
  replay its seed and inspect the arena with the `memtest` hooks
  (`raw_data`), never by printing.
- **Miri (T-SAN-2), new `vault-model` job.** T-VAULT-1 runs 2 cases,
  without the prefill and without file I/O (save and reopen go through
  the sealed file in memory), plus T-VAULT-2 and the operation tests. The
  10,000-entry, capacity, and every-offset truncation sweeps run natively
  only. Its runtime is not measured yet (no nightly in the sandbox).
- **LOC.** `vault` 486/500 (lifecycle 196 + model 291), `crypto + format`
  696/750, total 2,318/3,200. A simplification pass took `vault` from
  504 to 486 (an `Item` constructor, a shorter field lookup, and one
  reindex path). That pass also fixed a latent leak: `adopt` could return
  before wiping scratch if reindexing failed.
- **Local runtimes (this sandbox, tmpfs).** `cargo test --locked`: debug
  511 s (`tests/vault` 328 s, of which T-VAULT-1 is most), memtest 566 s,
  release 71 s, testkdf 527 s, memtest+testkdf 549–600 s. The debug cost
  is pwv at `opt-level 0` validating bodies of up to ~120 KiB about four
  times per operation; release takes seconds. No test was reduced for
  speed: the exact-bytes comparison runs at every reopen and end of
  segment, the entry, field, and flag comparison after every operation,
  and the "before" copy is taken only when an error is expected. CI
  `test` timeout: 80 → **150 min (provisional)**. M4 measured 25m49 on
  26.04 and M5 adds about 4 × 5.5 min, so about 50 min is expected; set
  the final cap to 3× once CI reports its runtime. The M5 gate-by-name
  step runs in release (about 1 min). The Miri `vault-model` runtime is
  unknown (the job cap is 115 min).
- **Local-only failure found while measuring (not M5 code; reported to
  the owner, not changed).** `tests/store.rs::state_file_damage_and_permissions_refused`
  failed with `open: InUse` in 3 of 12 full parallel `testkdf` runs of
  `tests/store`, 0 of 8 single-threaded, and 0 of 8 without
  `t_store_3_kill_loop`. Likely cause: in `execve` the kernel releases a
  vfork parent (`exec_mmap`) *before* it closes the child's `O_CLOEXEC`
  fds (`do_close_on_exec`). So `Command::spawn` can return while the
  child still holds a copy of another test's lock fd, and the M4 `FORK`
  RwLock (held only around `spawn`) does not cover that window. Only the
  kill loop spawns fast enough to hit it. The `pwv` binary never forks.
  Possible harness fix, which loosens no assertion: keep the write lock
  after `spawn` until `/proc/<pid>/fd` no longer lists a lock file.
  Awaiting the owner's decision.

## 2026-11-12 — M5 CI round 1: Miri cost, store-harness flake, caps

**Results.** Every job passed except `sanitizers (vault-model)`, which hit
its 115 min cap: 12 of 15 tests finished (their `--report-time` times sum
to 62 min); T-VAULT-1 and both T-VAULT-2 tests never finished. Times:
`test` 1h02m17 (M5 gate-by-name step 36 s), `lint` 5m29, `compat` 10 s,
`fuzz-smoke` 2m21–2m56 (`fuzz_import` 2m50), `sanitizers` format 13m03,
format-10000-entries 9m06, format-testkdf 24m15, crypto-vault 37m43,
`durability` 3m58, `coredump` 1m54, `supply` 9m13.

**Where Miri spent the time.** These figures are inferred from the
per-test times; Miri cannot run in the sandbox. A test that only builds
and drops a 256 KiB Miri arena took about 130 s. The drop wipes the region
byte by byte, then `ZeroizingAlloc` wipes and scans it again (about
768 K volatile byte steps). Each operation added about 30 s, because every
rewrite exposed the whole scratch half (126 KiB) and then wiped all of it
past the new body. So Miri pays about 0.2 ms per volatile byte, and each
operation's cost was set by the slot size, not by the body. Two changes
follow; no test was reduced.

- **`vault`: wipe what was used.** A rewrite exposes only
  `min(slot, live.len() + 2 × BLOCK)`. One operation adds at most
  4 + 64 + 4096 content bytes (`set`), and `live.len()` is at least
  12 + content, so the new padded body always fits. The exposed part is
  shorter than the slot only when the body fits anyway, so `Capacity`
  occurs exactly as before.
  `import` exposes `min(slot, live.len() + 5 × len + BLOCK)`. The merge
  adds at most the import's content plus 11 bytes per imported entry, and
  every entry is at least 5 bytes, so that is under `4 × len`. The
  single-slot rule (merged + import ≤ slot) is unchanged.
  The wipe after an operation now covers about body + 8 KiB instead of
  half the arena, which also helps native runs with large arenas.
  T-VAULT-1, `capacity_is_a_clean_error`, `import_capacity_rule`, and
  `fuzz_import` (273,793 runs locally) confirm the error behaviour is
  unchanged. `vault` stays at 486/500.
- **`sys`, Miri backend only.** The region is allocated from `System`, as
  `mmap` is natively, not through the global `ZeroizingAlloc`. The
  region's own zeroize-on-drop (T-MEM-3) still runs; only the second wipe
  and scan of already-zero memory are gone.
- **Three Miri jobs.** `vault-model` (the 12 unit tests),
  `vault-model-t-vault-1`, and `vault-model-t-vault-2` run the same tests
  as before with the same arguments, in parallel. `timeout-minutes` is now
  per matrix entry. The three vault caps are **180 min, provisional**:
  there is no measurement since the change, and the estimate is about
  15–45 min each. Set them to 3× the next measurement.

**Caps reset from the round 1 times (3×, floor 10):** `lint` 16 → 17,
`test` 150 → 190, `compat` 10, `fuzz-smoke` 15 → 10, `sanitizers` format
40, format-10000-entries 28, format-testkdf 73, crypto-vault 115,
`durability` 20 → 12, `coredump` 20 → 10, `supply` 25 → 28 (9m13 was
over a third of 25).

**Store harness: fork vs. `flock`, fixed (owner decision 2026-11-12).**
This is the `InUse` flake reported in the M5 entry. `Command::spawn`
returns before the child's close-on-exec has run, so the M4 `FORK` lock
did not cover the window in which a child still held a copy of another
test's lock fd. `SpawnLocked::spawn_locked` now works as follows:

1. Under the write lock, it adds a `pre_exec` hook.
2. In the child, the hook `fstat`s fds 3 to the parent's highest fd and
   closes the regular files and directories. Every fd is close-on-exec,
   so `exec` would close them anyway. Pipes and devices are kept, which
   covers the signal pipe and `Command`'s own pipes.
3. The hook then writes one byte to a pipe.
4. The parent reads that byte before releasing the lock. Once the child's
   `close` calls have returned, the kernel has dropped its references and
   any `flock` they kept alive.

`output` already waits for the child to exit, and exit closes every fd
before `wait` returns. No assertion changed, and no retry was added.
The first version listed the parent's file fds *before* creating the
signal pipe. The listing's directory fd could then be reused for the
pipe's write end, which the child closed, so `spawn` failed (1 run in 16).
Classifying fds in the child removes that race. Local runs after the fix:
24 of 24 clean runs of `tests/store` (16
`testkdf`, 8 `memtest`), plus 28 earlier runs during development, with no
`InUse`. Before the fix it failed in 3 of 12. Full local matrix after all round-2 changes, all green:
default 518 s, memtest 628 s, release 75 s, testkdf 495 s,
memtest+testkdf 550 s. Two kill-loop failures in one development batch
were `ENOSPC`: build directories had filled the 512 MiB `/tmp` tmpfs,
not a test fault.

## 2026-11-13 — M5 CI round 2: T-VAULT-1 under Miri split; word-wide wipes

**Results.** Every job passed except `sanitizers (vault-model-t-vault-1)`,
which hit its provisional 180 min cap with T-VAULT-1's 2 Miri cases in
one job. A test that does not finish reports no time, so how long the two
cases need is unknown.

**Options considered.** GitHub ends any job on a hosted runner at 6 h
(360 min). That is the ceiling for every cap, in private repositories as
well. (In private repositories the runner minutes are also billed against
the plan's monthly quota.)
1. Raise the cap toward 360 min: blind, and a stall costs up to 6 h.
2. Fewer operations or cases under Miri: weakens the Miri half of
   T-VAULT-1 (rule 2). Not done; it needs the owner's decision.
3. Run the sanitizers only nightly (spec Section 15.3): saves minutes but
   does not shorten the job. Not done: the owner chose every push.
4. Make each interpreted step cheaper, and split the job: done, below.

**Changes (no test weakened).**
- **`sys::wipe`: volatile `u64` stores.** The function covers the
  aligned middle of the buffer with `zeroize` on `u64`, and the ends byte
  by byte. It is used for every slot wipe (`SecretSlot::set_len`,
  `clear`), the region teardown, and `scrub_stack`. `ZeroizingAlloc`
  wipes the same way (`MaybeUninit<u64>`, one volatile store per word),
  and its T-MEM-6 check reads `u64` words. The erasure is the same:
  volatile stores, none of which may be elided. There are 8× fewer
  stores, and Miri pays per store (about 0.2 ms per volatile byte,
  inferred in round 1). This speeds up every Miri job; natively the
  change is negligible. New tests: `wipe_zeroes_exactly_the_slice_at_every_alignment`
  (`tests/secmem.rs`) and `every_size_and_offset_is_wiped_before_free`
  (`tests/alloc.rs`). Two new `unsafe` blocks, `align_to_mut`/`align_to`
  to `u64`, each with a `// SAFETY:` comment. `sys + secmem + alloc` is now
  624/800.
- **T-VAULT-1 under Miri: one case per job.** `cases()` keeps 2 cases
  under Miri unless `PROPTEST_CASES` is set. CI runs two jobs,
  `vault-model-t-vault-1-case-1` and `-case-2`. Each job runs one case
  with `PROPTEST_RNG_SEED` 1 or 2, forwarded through Miri's isolation
  with `-Zmiri-env-forward`. The case count is unchanged (2), and each
  case now gets its own `--report-time` result. The seeds are simply the
  first two integers, not chosen for size. Replaying the generation
  natively (`--cfg miri` build, the same strategies) shows their size:
  seed 1 has 153 operations, all seven kinds, and bodies up to 45 KiB;
  seed 2 has 25 operations. Natively nothing changes (256 cases;
  `PROPTEST_CASES` is ignored there, as before).
- **Caps.** The two case jobs are capped at 330 min, a provisional value
  below the 360 min job limit, so that this round yields a measurement
  rather than another blind timeout. `vault-model` and
  `vault-model-t-vault-2` stay at 180 min. Once measured, every cap goes
  to 3× its time. If case 1 still exceeds 330 min, the remaining lever
  is option 2, which the owner decides.

**Why round 2 was slow (an estimate; Miri cannot run here).** A
T-VAULT-1 operation validates the body three times: the parse in
`items`, `finish`, and `reindex`. It also wipes about body + 8 KiB in the
arena. On the test side, it wipes and checks the freed reference clone
(body size) in `ZeroizingAlloc`. The cost therefore grows with the body,
and without the prefill the body still reaches tens of KiB through 4 KiB
`set` values.

## 2026-11-13 — M6: generator

**API (`src/gen.rs`).** `generate(rng: &mut dyn ByteSource, policy:
&Policy, out: &mut SecretSlot) -> Result<Entropy, Error>`. `Policy` is an
enum: `Chars { len, classes: [bool; 4] /* l u d s */, symbols,
no_ambiguous }` or `Words { count, sep }`, with `DEFAULT_CHARS` (20, luds,
all 32 symbols) and `DEFAULT_WORDS` (6, `-`). `Policy::validate` checks
every Section 10.1 constraint; option parsing is M7. Also public, for the
gate tests: `map_draw` (stage 1), `sample` (two-stage sampling over an
explicit alphabet of `(character, class)` pairs), `valid_count` (exact
N(L), `u128`), `log2_count` (log2 N(L) in `f64`), and the constants
(`WORDS`, `WORD_COUNT`, `MAX_ATTEMPTS`, the class sets, `AMBIGUOUS`).
`OsBytes` wraps `crypto::fill_random`. Nothing names `getrandom`,
`rustix`, or `libc`.

**Deviation: the word list (owner instruction in spec Section 10.3).** The
spec's last paragraph of 10.3 replaces the EFF large list with
`/workspace/full_wordlist.txt`. It is copied byte-for-byte to
`src/wordlist.txt` (the M0 location) and embedded with `include_str!`.
Its SHA-256, `9b7bb4cc…a93320`, matches the owner's
`full_wordlist_sha256sum.txt`, and its 205,690 lines match the line count
the spec gives. Checked properties: LF line ends with a final LF; unique;
sorted; every word `[a-z-]+` (lower-case ASCII; `drop-down`, `felt-tip`,
`t-shirt`, and `yo-yo` contain a hyphen); 5 to 24 letters.
`.gitattributes` marks it `-text`. Every spec number derived from the EFF
list changes:

| Item | Spec (EFF) | Now |
| --- | --- | --- |
| Words n (9.2, 10.1, T-GEN-6) | 7,776 | 205,690 |
| Draw (10.2) | u16, accept below 62,208 (65,536 mod 7,776 = 3,328) | 24-bit big-endian (3 bytes), accept below 16,660,890 (2^24 mod n = 116,326), so 81 values per word, acceptance 0.99307 |
| Bits per word (10.2) | 12.925 | 17.650 |
| 6-word default H (10.2) | 77.5 bits | 105.90 bits (4 words: 70.6; 16: 282.4) |
| T-GEN-6 | 7,776 lines, `[a-z-]+`, pinned SHA-256 | 205,690 lines, `[a-z-]+` (holds), unique and sorted, pinned SHA-256 |
| Attribution (README) | CC BY 3.0 US (EFF) | MIT, Copyright (c) 2012 Rochester Institute of Technology (owner, 2026-11-13) |

A 16-bit draw cannot index 205,690 words, so the draw is 3 bytes with the
same construction as stage 1 (threshold = 2^24 − 2^24 mod n), and T-GEN-1
tests that mapping exhaustively over all 2^24 values, as it tests the byte
mapping. **Gen slot:** the longest passphrase is 16 × (24 + 1) − 1 = 399
bytes, within the 1,024-byte `Gen` slot (T-GEN-6 asserts it). No arena
change. **Supply chain:** the list is a data file, not a crate, so `cargo
deny` does not cover it. The pinned digest in `tests/gen.rs` is its
integrity control. The binary grows by 2.2 MB.

**Deviation (rule 10): separator rule.** Section 10.1 allows any printable
ASCII separator. A lower-case letter would make passphrases ambiguous:
with `--sep e`, different word sequences can give the same string. Then
the true entropy is below k · log2 n, and the displayed H would overstate
it. The conservative choice is to refuse `a`–`z` (`Error::Separator`).
Allowed: 0x20–0x7E except a–z (space, digits, upper case, punctuation).
With `-`, decoding is still unique: no list word ends where another word
has a hyphen (`drop`, `felt`, `t`, `yo` are not words), so the list is a
prefix code over `-`-separated tokens. T-GEN-6 asserts that property, and
T-GEN-4 checks that every generated passphrase decodes in exactly one way.

**Interpretation (rule 10): the ambiguous set.** In the raw spec text,
`` `I l 1 O 0 \` ' "`` can read as a backslash or an escaped backtick.
`AMBIGUOUS` removes both: `I l 1 O 0 \ ` ' "` (nine characters). It
applies to every class, including a custom `--symbols`.

**Deviation (rule 7): no generic.** Section 10.1 writes `generate<R:
ByteSource>`. Rule 7 forbids generics, so `generate` and `sample` take
`&mut dyn ByteSource`, as M5 did with `&mut dyn FnMut`. `ByteSource` is
the one trait rule 7 allows; it returns `gen::Error`.

**Policy rules (rule 10, conservative).**
- Constraints are checked in this order, and the first failure is
  reported: length (8–128) or word count (4–16); classes non-empty;
  symbols only ASCII punctuation (`is_ascii_punctuation`: printable
  0x21–0x7E, not alphanumeric); no duplicate symbol; the symbol class
  non-empty after `--no-ambiguous`; separator.
- `--symbols` is validated even when `s` is not in `--classes`.
- "L ≥ the number of required classes" always holds, because L ≥ 8 ≥ 4.
  No separate check exists, since it could never fail.

**Errors.** `gen::Error` has `Length`, `NoClasses`, `SymbolChar`,
`SymbolDuplicate`, `SymbolsEmpty`, `WordCount`, `Separator`, `Attempts`,
`Random`, `Capacity`, and `WordList` (internal: the list is shorter than
`WORD_COUNT`). Messages are fixed and name the constraint, never content.
Mapping these to exit codes in `cli::exit_code` is M7 work.

**Secrets.**
- Characters are drawn straight into `out`. A rejected stage-2 attempt is
  overwritten in place by the next one (same length), and every error
  clears the slot.
- Words are appended to the slot one at a time. Each one is found by a
  scan of `WORDS`, so no index table and no global is needed (T-ENG-3
  forbids lazy globals).
- Random bytes go through a 4-byte stack buffer, zeroized after each draw.
- `generate` calls `sys::scrub_stack()` once at the end, so the drawn
  indices and locals do not outlive the call (best effort, Section 5.6).
- Nothing is formatted or put on the heap. The entropy is not secret.

**Entropy.** `valid_count` is the exact inclusion–exclusion count, with
checked `u128` arithmetic (`None` if it overflows; at most 16 classes).
`log2_count` gives the displayed H as L log2 n + log2 Σ ±((n − m_S)/n)^L.
The ratios stay in [0, 1], so no length overflows. T-GEN-5 checks
`valid_count` against brute force for every composition of n ≤ 6 and every
L ≤ 6, and `log2_count` against log2 of the exact count. Values from
Python big integers: default 130.926 bits (L = 20, where the count
overflows `u128`, so only the log path exists); L = 128 838.987;
`--no-ambiguous` 127.969. The attempt cap: the smallest P(valid) of any
valid policy is 0.0798 (L = 8, luds, `--no-ambiguous`, one symbol). The
cap is therefore reached with probability below 2^−1199, consistent with
the spec's (1 − 0.066)^10000 bound.

**Tests (`tests/gen.rs`, 19 tests).**
- **T-GEN-1:** every n in 2..256 over all 256 bytes, and the 24-bit word
  mapping over all 2^24 values.
- **T-GEN-2:** {a, b, C, 1}, L = 4. Running every 4-byte sequence (2^32
  runs) is not practical. Instead, the source enumerates every residue
  sequence (4^4) with 64 byte values per residue, so every byte value
  occurs at every position. An attempt that asks for a fifth byte was
  rejected at stage 2. Result: all 96 = N(4) valid strings, 64 times
  each, and no invalid one.
- **T-GEN-3:** seeded `ChaCha20Rng` (seed 3), 50,000 default passwords.
  The expected frequencies are the exact conditional ones. Stage 2 makes
  digits 11.88 % of the characters, not 1/94 per character, and the test
  asserts that this shift shows. The critical value is 172.747 for 93
  degrees of freedom at α = 10⁻⁶ (mpmath 1.3.0), used per position and
  pooled.
- **T-GEN-4:** 512 random valid policies (characters and words) and 4,096
  arbitrary policies (validate equals an independent rule reading,
  generate fails the same way with an empty slot, and no byte is drawn),
  plus a limit table.
- **T-GEN-5:** as above.
- **T-GEN-6:** as above.
- **Others:** the exact attempt cap (80,000 bytes for L = 8), RNG failure
  at every point, malformed `sample` input, the ambiguous set, `OsBytes`,
  the error messages, and slot capacity.
- **Mutation sanity check (manual):** six injected faults (no stage-1
  rejection, stage-2 accepting anything, the ambiguous filter always on,
  the separator rule, the entropy exponent, the trailing separator) each
  failed between 1 and 6 tests.
- Debug run of `tests/gen`: about 11 s.
- Full local matrix, all green: default 471 s, memtest 431 s, release
  66 s, testkdf 419 s, memtest+testkdf 420 s. The proptest regression
  file written by the injected faults was deleted (it held only
  policies and seeds, from bugs that never existed).

**Miri (T-SAN-2 for `gen`).**
- **Subset under Miri:** T-GEN-1 for n ∈ {2, 3, 7, 94, 128, 129, 255,
  256} and a stride of 24-bit values with the boundaries; T-GEN-2 with 2
  byte values per residue; T-GEN-4 with 8 + 16 cases; T-GEN-5 for
  n, L ≤ 4; entropy for L 8–9; the unit tests.
- **Native only:** T-GEN-3 and T-GEN-6.
- **CI jobs:** `gen` and `gen-words`. `gen-words` holds the tests that
  draw passphrases, because each word is a scan of the 2.2 MB list,
  whose Miri cost is unknown.
- **Caps:** provisional 120 and 180 min. Set them to 3× the first
  measurement.

**LOC.** `gen` measures 268. Getting under the 200 cap would have meant
cutting validation or robustness checks. The owner chose to raise the cap
instead (2026-11-13): `scripts/loc_budget.py` now has `gen` 150 / 300, and
the owner updated the spec's Section 3 table to match. The total
is 2,597 / 3,200. No lint is allowed in `gen`.

**Section 15.5 checklist.** No new place for secrets outside the arena.
No `unsafe`. No parser of untrusted input: policies come from the M7
tokenizer, which T-FUZZ-4 fuzzes. The "fuzz target and truncation test"
item is therefore N/A. No disk writes. The LOC cap is raised by the owner.
In Section 13, S3, generator bias, B2, B9, and E6 now have passing
generator tests (T-GEN-1..6); the T-FUZZ-4 part of B2 is M7.

**Spec updated for the new word list (owner request, 2026-11-13).**
Targeted edits replace the EFF-based numbers: Section 4 layout comment,
6.5 (6 words ≈ 105.9 bits), 10.1 (`--words` row), 10.2 (24-bit draw,
threshold 16,660,890, 17.650 bits per word, 105.9-bit default), 10.3
(205,690 entries, pinned digest, 399-byte maximum, MIT), and T-GEN-6
(205,690 lines). The owner chose to refuse a–z as a separator; 10.1's
`--sep` row now reads "One printable ASCII character other than a–z".

**Word-list licence file.** `src/wordlist.LICENSE` holds the standard MIT
text with the owner-supplied copyright line ("Copyright (c) 2012 Rochester
Institute of Technology"). It is not in Section 4's layout. MIT requires the
notice in all copies, so M9's release artefacts must ship it (the binary
embeds the list).

## 2026-11-13 — Spec: coverage measurement and reporting (owner request)

At the owner's request the spec now defines coverage in full (new Section
14.13; T-COV-1 to T-COV-6). It covers: the production-code denominator
(the T-ENG-6 rules), the merged runs (five feature configurations plus
e2e with an instrumented binary), fixed property-test seeds, function
coverage, mechanised rule 6 for `unsafe` blocks, a committed baseline
with a 0.5 pp no-regression rule, nightly branch coverage, report-only
fuzz-corpus coverage, a "Coverage exceptions" table in this file, the
job-summary report, and self-hosted README badges (an orphan `badges`
branch; no third-party upload). Related edits: 14 intro (thirteen
families), the 14.11 T-COV row, 15.1 (nightly for T-COV-5), 15.3
(`coverage`, `coverage-branch`, `coverage-report`), 15.4 (README badges),
15.5 (checklist item), 13 (E4 row), and 16 (M9 scope and gate). Everything
is M9 work; nothing is implemented now.

## 2026-11-14 — M6 CI round 1: timings, caps, and a `gen-words` failure

**Results (wall time per job, ubuntu-26.04).** lint 3m01, test 48m00,
compat 9 s, fuzz-smoke (header 1m54, body 2m04, open 1m58, import 2m37),
durability 3m24, coredump 1m19, supply 5m31. Sanitizers: format 9m34,
format-10000-entries 11m10, format-testkdf 13m48, crypto-vault 9m43,
vault-model 11m11, vault-model-t-vault-1-case-1 5h09m44,
vault-model-t-vault-1-case-2 8m39, vault-model-t-vault-2 57m42, gen 3m24,
gen-words hit its 180 min cap (cancelled). All passed except gen-words.
`test` steps: default 12m35, memtest 9m57, release 2m52, testkdf 10m30,
memtest+testkdf 10m26, M4 gate by name 40 s, M5 49 s, M6 3 s, vfat 1 s.

**M5 open item closed.** Both T-VAULT-1 Miri cases pass (case 1 in
5h09m44 of wall time, case 2 in 8m39). The M5 gate is complete on CI.

**Miri's `--report-time` is not wall time.** Case 1 reports 30,623 s
(8h30) inside a 5h10 job, and `gen` reports 235 s inside a 3m24 job.
Under isolation Miri's clock is virtual (it advances with interpreted
work), and libtest runs tests in parallel threads, which Miri interleaves
on one host thread, so the per-test times overlap. Use the figures to rank
tests, not to set caps; caps come from job wall times.

**`gen-words`: a real failure, not only a timeout.** The log has
`t_gen_4_valid_policies_produce_valid_output ... FAILED <6406.966s>`.
libtest prints that only when the test has finished, so it failed. The job
was cancelled later, while `word_draw_maps_three_bytes_to_the_listed_word`
still ran, so the panic message (printed at the end) is missing. It passes
natively in every configuration. Most likely cause: the test asserts
`h.bits == log2_count(..)` with exact `f64` equality (tests/gen.rs, both
arms), and recent Miri adds deliberate, non-deterministic error of a few
ULP to non-exact float operations (`powi`, `log2`), so two calls of the
same function differ. Every other float check in tests/gen.rs already uses
a 1e-9 tolerance and passed under Miri. Fix (a test change, approved by
the owner on 2026-11-14): `same_bits` in tests/gen.rs keeps exact equality
natively and allows 1e-9 bits only under `cfg(miri)`, so the native check
is unchanged. Not confirmed by the panic text; CI round 2 will show it.

**No manual job selection (owner, 2026-11-14).** A `workflow_dispatch`
input to run only chosen jobs was offered and declined: every change must
run the whole suite so that unintended regressions surface. Running CI
jobs on the owner's host was also declined: the sandbox exists to isolate
agent work from the host.

**Caps (3x measured, 10 min floor; all < 360).** lint 17→10, test
190→144, compat 10, fuzz-smoke 10, durability 12→11, coredump 10, supply
28→17; format 40→29, format-10000-entries 28→34, format-testkdf 73→42,
crypto-vault 115→30, vault-model 180→34, case-2 330→26, vault-model-t-
vault-2 180→173, gen 120→11. Exception: case 1 at 3x (15.5 h) cannot fit
under the 360 min job limit, so it is capped at 350 (about 40 min of
margin over the measurement). If runner variance pushes it over, the
options are those of M5 CI round 2 (fewer Miri operations or another seed
need the owner's approval; or make the interpreted code cheaper).

**`gen-words` split.** One matrix entry per test (six, `--exact`), so a
slow test no longer starves the others and each gets a wall time. At the
owner's request (2026-11-14) each cap is a provisional 350 min, so that
every test can finish and report. Not done yet: the one-pass word scan in
`gen::words` (draw all k indices, one scan of the list; about 15 LOC; gen
is at 268/300). It would cut the interpreted scan work per passphrase by
about k/2 and is the preferred lever if the times stay long.

## 2026-11-14 — M6 CI round 2: timings, and `word_draw` at the job limit

**Results (wall time per job, ubuntu-26.04; owner screenshots).** lint
2m58, test 51m27, compat 10 s, fuzz-smoke (header 2m08, body 1m54, open
1m55, import 2m05), durability 3m38, coredump 53 s, supply 5m20.
Sanitizers: format 8m51, format-10000-entries 12m02, format-testkdf 25m47,
crypto-vault 9m37, vault-model 9m06, vault-model-t-vault-1-case-1
5h11m24 (cap 350), vault-model-t-vault-1-case-2 6m25,
vault-model-t-vault-2 2h04m49, gen 2m43, gen-words-t-gen-4-valid 1h08m36,
gen-words-os-bytes 10m11, gen-words-entropy-known 11m58,
gen-words-rng-failure 11m59, gen-words-passphrase-too-long 10m12. All
passed except gen-words-word-draw, cancelled at its provisional cap
(5h50m16).

**The round 1 `gen-words` failure is fixed.** `t_gen_4_valid` passes
under Miri with `same_bits` (M6 CI round 1), which confirms the float
non-determinism diagnosis.

**Caps.** Only the jobs first measured in this round changed (owner: no
repeated resets of the 3x caps of older jobs): gen-words-t-gen-4-valid
350→206, os-bytes 350→31, entropy-known 350→36, rng-failure 350→36,
passphrase-too-long 350→31. Older jobs keep their round 1 caps. All
round 2 times are under them; vault-model-t-vault-2 (2h04m49, cap 173)
and format-testkdf (25m47, cap 42) are slower than in round 1, but within
the cap.

**Why `word_draw` is not explained by the list scans.** Each passphrase
word is found by a scan of the 2.2 MB list. The scan work of each Miri test
was counted by replaying its exact draws natively (fractions of one full
scan):

| Test | Full scans | Wall time |
|---|---|---|
| passphrase-too-long | about 0.5 to 1 | 10m12 |
| rng-failure | about 3.0 | 11m59 |
| entropy-known | about 4.8 | 11m58 |
| word-draw | about 18.6 | > 5h50 (cancelled) |

The first three differ by up to 4 scans but finish within 2 minutes of
each other. So about 9–10 minutes of each job is fixed (setup and build),
and a scan costs well under a minute. Even at t-gen-4-valid's implied
upper bound of about 3 minutes per scan, word-draw would take about an
hour. Something else in the test costs 15 to 20 times more than its
scans. Word-draw's scan count is about 18.6, not 9.8 as first estimated:
five words share the 24-byte maximum, and `max_by_key` picks the last of
them, at index 175,813 (85% into the list). The draws of that index make
up most of the scans.

The step that only this test has is its first line: a pass over all 205,690
words with `(0u32..).zip(..).max_by_key(..)` to find the longest word.
This step is the leading suspect. A plausible mechanism (not verified) is a
Stacked Borrows cost in that iterator chain, or one that it leaves for the
later scans. The sandbox cannot run Miri (no nightly toolchain, a read-only
rustup home, no network), so it could not be measured.

**Fix (owner approved items 1, 2 and 4 of the proposal, 2026-11-14).**
1. **Split.** `word_draw_maps_three_bytes_to_the_listed_word` keeps the
   longest word drawn 16 times (3-byte draws, a rejected value redrawn,
   399 bytes in the `Gen` slot). The first, middle and last index with `-`
   move unchanged to the new `word_draw_first_middle_and_last_index`. Each
   is its own Miri job (`gen-words-word-draw`, `gen-words-word-draw-ends`),
   so each part gets a wall time and neither starves the other. Every
   assertion is kept.
2. **The longest word's index under Miri.** A new constant `LONGEST =
   175_813` holds the word `max_by_key` selects. Natively, the test still
   finds the word with the scan and now also asserts the index equals
   `LONGEST`, which is stricter than before. Under Miri, it takes the word
   by `nth_word(LONGEST)` and asserts its length of 24. The maximality of
   24 bytes is still checked natively here and by T-GEN-6. Under Miri,
   the iterator pass is the one check removed (owner approved under rule
   2). The drawn word and the 16 draws are unchanged.
3. Not done: the one-pass word scan in `gen::words` (draw all k indices,
   then one scan). The numbers above suggest scans are not the cost. It
   stays available if round 3 shows otherwise.
4. **Phase markers.** Under Miri only, both tests write short markers
   (`[miri] <test>: start`, `longest word found`, `16 words drawn`, `4
   words drawn`, `expected words read`, `done`) to fd 2. They hold phase
   names only, no content (rule 9). They are written by raw `write(2)`
   through `sys::write_stderr`, because std stdio is banned (T-ENG-4,
   no new lint exemption needed), and rustix 1.1.6 selects its libc
   backend under Miri, which Miri supports. A raw write is not captured
   by libtest; the two jobs pass `--nocapture` as well. GitHub's log
   timestamps then show when each phase ended. A run cancelled at its cap
   shows the last phase it reached.

Both word-draw jobs keep a provisional 350 min cap until measured. The
`gen` job's `--skip word_draw` covers both tests.

**Local verification.** fmt; clippy in the five lint configurations; the
`cfg(miri)` compile check of tests/gen.rs; `tests/eng` (T-ENG-4 scan:
no new allow); `tests/gen` in all five feature configurations: 20
passed each, including both word-draw tests and the new `LONGEST` check.

**Miri access (owner offer, 2026-11-14).** A read-only volume with a
nightly toolchain that includes Miri would let these costs be measured
locally. It needs the `miri` and `rust-src` components and a prebuilt Miri
sysroot (`cargo miri setup` downloads std's dependencies, which the
sandbox cannot do), pointed to by `MIRI_SYSROOT`.

## 2026-11-15 — M6 CI round 3: `word_draw` timeout, cause measured with Miri

**Miri is now available in the sandbox** (owner, 2026-11-15):
`nightly-2026-11-15` (miri 0.1.0, 5f4effd579) with a prebuilt sysroot
(`MIRI_SYSROOT`). All figures below are local wall times on that
toolchain, measured while other Miri processes ran, so they are upper
bounds for this machine.

**Cause of the 5h50 timeout: `max_by_key`, quadratic under Stacked
Borrows.** The round 2 test found the longest list word with
`(0u32..).zip(WORDS.split_terminator('\n')).max_by_key(|(_, w)| w.len())`.
Measured on the first n words of the list:

| n words | `max_by_key` (default Miri) | plain `nth(n)` scan |
|---|---|---|
| 500 | 0.9 s | — |
| 1,000 | 2.3 s | — |
| 2,000 | 4.8 s | 1.9 s |
| 4,000 | 18.9 s | — |
| 8,000 | about 88 s | — |
| 20,000 | — | 16 s |

- The scan is linear (about 0.8 ms per line, 2–4 min per full scan of the
  205,690 lines). `max_by_key` grows about fourfold per doubling.
  Extrapolated to the whole list it needs about 14 h, which alone exceeds
  the 360 min job limit.
- It is a Stacked Borrows cost: with `-Zmiri-disable-stacked-borrows` or
  `-Zmiri-tree-borrows` the same pass is linear (4,000 → 8,000 words:
  18.5 s → 28 s).
- It is `max_by_key` itself, not `zip`: `max_by_key` without `zip` is
  just as quadratic, and `zip` with `filter().count()` is linear. A loop
  that keeps only `(index, length)`, and a `fold` over `&str`, are linear
  too. The exact mechanism inside Miri was not traced further.
- The list scans in `gen::words` are not the problem, as the round 2
  entry had inferred.

**Fix (test only; `src/` unchanged).** `word_draw_maps_three_bytes_to_the_listed_word`
now finds the longest word with a loop that tracks `(index, length)` and
selects the last maximum, as `max_by_key` did. It runs natively and under
Miri, asserts the index equals `LONGEST` and the length equals the word's.
This restores under Miri the check that round 2 had removed (item 2 of
that entry), so the test is stricter than in round 2 and no weaker than
before it. The split into two tests and the phase markers stay.

**Local Miri results, both tests pass.**
- `word_draw_first_middle_and_last_index`: 13m03 (4 words drawn after
  7m28; expected words read after another 5m07).
- `word_draw_maps_three_bytes_to_the_listed_word`, round 2 form (known
  index): 55m14. The 16 draws of index 175,813 (13.7 full scans) took
  50 min.
- The same test with the restored check: the full-list pass plus one
  lookup took 6m00, the 16 draws 41m31; total 47m35.

**Caps.** Both word-draw jobs keep the provisional 350 min until CI
reports a wall time; then 3x. In round 2 CI ran a scan faster than this
sandbox does (entropy-known: 4.8 scans in an 11m58 job), so the CI times
should be below the local ones.

**Not done: cheaper scans in `gen::words`.** Each word still costs one
scan. A byte loop over the list ran about 7x faster under Miri than
`split_terminator('\n').nth(i)` (20,000 lines: 2.4 s against 16 s), and
the one-pass variant of round 1 would cut `word_draw` to one scan. Both
change production code only to speed up the interpreter, and no job
needs it now. They remain the lever for `gen-words-t-gen-4-valid`
(1h08m36) if wanted.

**Local verification.** fmt; clippy `--all-targets` (default features);
the `cfg(miri)` compile check of tests/gen.rs; both word-draw tests
natively.

## 2026-11-15 — M7: terminal, CLI, clipboard

Started on the owner's go-ahead (2026-11-15), while M6 CI round 3 is
still running. If that round fails, M6 is fixed first.

### Owner decisions (2026-11-15)

1. **stdin and stdout.** `/dev/tty` is opened first; exit 4 if that
   fails. stdout must always be a terminal. A non-terminal stdin is
   allowed only for `import --from-stdin`.
2. **Rule 5 exception: `arboard` accepted, `zxcvbn` not.** See "Heap
   copies" below. The strength check is written by hand and works in the
   arena. The passphrase is strongly recommended; a chosen password stays
   possible, with a warning.
3. **Clipboard timeout default 10 s** (spec 9.1 says 20), because the
   copied value sits on the unlocked heap inside `arboard` for that long.
   The range 5–300 is unchanged.
4. **T-CLIP-4 mock manager in Rust with x11rb.**
5. **LOC caps raised:** `sys + secmem + alloc` 800 → 900, `term + clip`
   350 → 450, `cli + main` 500 → 1,300, Total 3,200 → 4,500.

**Spec edits these decisions need (the owner's; not made here):**
Section 3 (LOC table; the `zxcvbn` row), 6.5 (the strength rule), 9.1
(`--clip-timeout` default), 15.1 (the `strength` feature row).

### Heap copies (rule 5 exceptions; rule 4 check of the pinned sources)

- **`arboard` 3.7.0, accepted.** `Set::text` turns the borrowed value
  into an owned `String` (`into_owned`, src/platform/linux/x11.rs and
  wayland.rs) and keeps it in a process-global until it is replaced; its
  X11 server thread serves it from there. `get_text` returns a heap
  `String`. The zeroizing allocator wipes each copy when it is freed.
  `clip` replaces the value by the empty string on expiry and on every
  exit path, which frees the copy. The `String` from `get_text` is
  compared in constant time with the `Clip` slot and dropped at once.
  T-MEM-4 (M8) must scan with a value on the clipboard, and expect it
  outside the arena only inside `arboard`'s buffers.
- **`zxcvbn` 3.1.1, not used.** It copies the first 100 characters of the
  password into a `String` and builds match lists of substrings. The
  dependency and the `strength` feature are removed (`Cargo.toml`, both
  lock files; 35 packages leave `Cargo.lock`, among them `chrono`,
  `time`, `fancy-regex`, `itertools`, `bit-set`, and `bit-vec`). No other master-password
  copy leaves the arena.
- **Inherent, not a library:** the arguments of a one-shot command
  (`pwv show <name>`) are in the kernel's argv block (`/proc/<pid>/cmdline`)
  and in std's `args_os` vector, so entry names given that way are visible
  to other processes. They are copied into the `Input` slot and used from
  there. The README says to use a session for private names. Values and
  passwords are never arguments.

### Master-password policy (`cli::weakness`, `cli::strength_bits`)

A chosen password needs at least 16 characters (the spec's rule for
builds without `zxcvbn`) **and** an estimate of at least 46.5 bits
(10^14 guesses, the spec's `zxcvbn` threshold). The estimate reads the
password in place in `Pw1` and allocates nothing:

- a run of 3 or more bytes that occurred earlier in the password: 1 bit;
- a word of the embedded list (5–24 letters, any letter case, longest
  match, binary search over the list in place): 11 bits, about a
  2,000-word common vocabulary, far below the 17.65 bits of a random
  list word;
- any other character: log2 of its class (26 letters, 10 digits, 33
  ASCII punctuation, 64 otherwise), or 1 bit if it repeats the previous
  character, is its neighbour in code-point order or on a keyboard row,
  or completes a character pair seen earlier.

It is a heuristic. It bounds repeats, runs, keyboard walks, and word
combinations; it knows no names, dates, or leet spellings, and no words
shorter than 5 letters. That limit is why the passphrase is the default.
Refused, for example: `password1password1`, `qwertyuiopasdfghjkl`,
`correct horse battery`, 144 times `a`. A generated 6-word passphrase
typed as a chosen password passes (66 bits by this count).

**Flow.** "Use a generated passphrase? [Y/n]", default yes. Generated:
shown once, Enter clears screen and scrollback, then it is typed back
hidden and compared in constant time with the `Gen` slot (this is the
second entry Section 6.5 asks for). Chosen: a warning, two hidden
entries compared in constant time, then the policy. `--accept-weak-password`
is an option of `init` and `passwd`; it also needs the typed sentence
`I accept a weak master password`.

### Structure

- **`sys`** (+75 lines): `open_tty`, `tty_state` / `set_tty` (termios),
  `wait_readable` (poll), `read_fd` (returns `EINTR`), `write_fd`,
  `stdin`, and the signal flag: one `static AtomicU8`, set by a
  `sigaction` handler without `SA_RESTART` (libc 0.2.191; one new
  `unsafe` block, exercised by T-E2E-7). `harden` step 4 now requires
  only stdout to be a terminal and records `stdin_tty`.
- **`term`**: `Term` owns `/dev/tty` and the saved termios; `hide()`
  returns the `EchoGuard` (the spec's `TermiosGuard`); `read_line` reads
  by raw `read(2)` straight into a slot; `wait` is the poll primitive;
  `sanitize` is pure and streams from the caller's slice.
- **`clip`**: `Clip::copy` and `clear_if_unchanged`. Same-layer modules
  may not use each other, so the deadline and the single poll loop are in
  `cli` (`Session::prompt`).
- **`cli`**: tokenizer, command table (`COMMANDS`, one row per command,
  `#[rustfmt::skip]` so that it stays a table), parser, `gen` options,
  strength, `doctor`, the `Session` context passed by reference (E1), and
  one handler per command.
- **Rule 7.** Handlers are `fn` pointers; no new trait, no generic, no
  macro. `impl From<..> for Fail` are impls of a std trait, as `vault`
  already has; `folded` returns `impl Iterator`.

### Secrets in the CLI

- A line is read into `Input` and tokenized **in place**: quotes and
  escapes are removed by compacting bytes towards the front, and
  arguments are byte ranges into the slot.
- Arguments needed after a later prompt (which overwrites `Input`) are
  parked in `Pw1` (entry name) and `Pw2` (field key). These slots are
  free outside `init`, unlock, and `passwd`. This use is not in Section
  5.2's table; it stays inside the arena.
- A hidden value is entered twice: the first entry waits in the vault's
  scratch half and is compared in constant time.
- Every command ends with `tidy`: `Input`, `Pw1`, `Pw2`, `Gen`, and the
  scratch half are wiped.
- **Bug found by the first PTY run and fixed:** echo was turned off only
  when the line was read, after the prompt and the wait. The kernel
  echoes at typing time, so a password typed quickly was echoed. Echo now
  goes off before the prompt is written. T-E2E-1 asserts that no typed
  password is on the screen, with a positive control that echo is on.

### Interpretations (rule 10)

- **Tokenizer.** Separators are space and tab. A quote may start or end
  inside an argument (`a"b c"d` is `ab cd`); `""` is an empty argument.
  `\"` and `\\` are the only escapes, inside and outside quotes. At most
  24 arguments. A bare `--` ends the options, so a name starting with
  `--` can be addressed; without it such an entry (possible through
  import) could never be shown or removed.
- **One-shot arguments are not tokenized.** They are copied as they are.
- **`sanitize`.** C0 and DEL: `\x1b`. C1 and the bidi overrides:
  `\u{202e}`. A byte that is not UTF-8: `\xff`. LF is a C0 control, so a
  multi-line value is shown with `\x0a`. A backslash is **not** escaped:
  `reveal` must show a password exactly, so a literal `\x1b` in a value
  looks like an escaped ESC. No injection follows from that.
- **T-E2E-8.** The format refuses every control character in a name, a
  key, and (except LF) a value, so an entry "named with ESC, BEL" cannot
  exist. The test shows (a) that such input is refused and no raw ESC or
  BEL reaches the terminal, and (b) that a stored U+202E, U+2066, U+202A
  in a name, key, and value is displayed as an escape and never raw.
- **Signals.** SIGINT cancels the current command (a guided `add` is
  undone with `rm`, without a save). SIGTERM, SIGHUP, SIGQUIT, and
  Ctrl-D end the session with exit code 0 ("exit cleanly").
- **Idle timeout** runs at every prompt, including one-shot commands;
  exit code 0 with "Locked after N s without input."
- **Unlock** takes one attempt; a wrong password exits with code 2.
- **`init`** is a one-shot command: a session needs a vault to start.
- **Sensitivity.** `--plain` and `--sensitive` decide; otherwise a field
  is sensitive if it is generated, was sensitive before, or its key is
  in Section 9.3's list. In `add`, choosing `hidden` makes it sensitive.
- **`gen` and `copy` without a clipboard** fail with exit code 4 and a
  fixed message (no display), or "this build has no clipboard support"
  (no `clipboard` feature). `gen --show` prints the value first.
- **`import`.** "stdin must be a pipe" is checked as "not a terminal".
  A refusal names the constraint and the entry index, never content.
- **`passwd`** verifies the current password by deriving its KEK and
  unwrapping the DEK into `NewDek` (wiped at once): one extra key
  derivation. Salt, DEK, and both nonces rotate; the vault ID stays.
- **`doctor`.** "KDF memory lockable" and "ptrace scope" warn; "Arena
  lockable", "Swap", "Hibernation", "Core dumps", and a refused vault
  location fail (exit 1). "Clipboard history" is informational. A swap
  device counts as protected only if it is `/dev/zram*`, or `/dev/dm-*`
  with a `CRYPT-` UUID. The checks are a pure function over `Facts`.
- **Over-long input** is drained and refused. The kernel's canonical
  mode already limits a line to 4,095 bytes, so this is reachable for
  the 1 KiB password slots only (tested there).
- **`__pause`** (`memtest`, Section 5.8) blocks until SIGUSR1. The pause
  before exit that T-MEM-4 needs is M8 work.

### Clipboard (verified in `arboard` 3.7.0; tests run only in CI)

- `Set::exclude_from_history()` adds `x-kde-passwordManagerHint` with the
  value `secret`. When the owned data carries that hint, `arboard`'s
  `Drop` does **not** hand it to a clipboard manager; it gives up the
  selection instead. `clip` clears with the empty string, also with the
  hint, before the `Clipboard` is dropped. So at exit a manager is asked
  for nothing.
- **T-CLIP-4** therefore asserts: the manager never receives the copied
  value, anything it receives at exit is empty, and the clipboard is
  empty afterwards. A positive control (an ordinary `arboard` client
  that exits owning a value) proves the mock manager does receive
  hand-overs.
- **Not run locally.** The sandbox has no X server and no `xclip`.
  `tests/clip.rs` compiles in every configuration and returns at once
  without `DISPLAY`. CI sets `PWV_REQUIRE_X11=1`, which makes a missing
  display a failure (the `PWV_FOREIGN_DIR` pattern of T-STORE-1). The
  first `e2e` run on CI is the first real run of T-CLIP-1 to T-CLIP-4,
  of the clipboard half of T-E2E-6, and of the x11rb mock manager.

### Existing tests

- `harden_refuses_non_tty_with_exit_4` is unchanged and passes.
- **T-MEM-5** now starts `pwv init` in a scratch home, because a bare
  `pwv` exits at once without a vault. Every assertion is unchanged.
- New: `harden_refuses_non_tty_stdout_for_every_command`.
- The PTY harness (`tests/common/pty.rs`) never prints the screen.
  ptyprocess starts children with echo off, which would make "not
  visible" checks vacuous, so the child runs `stty echo` first.

### Tests added

- `tests/e2e.rs` (26): T-E2E-1 (5 tests), -2, -3, -4, -5 (3), -6, -7 (2),
  -8, -9, -10, -11, -12; the binary-level T-CRY-2 (same bytes on screen
  and exit code 2 for a wrong password and a damaged payload), T-STORE-5
  (rollback prompt: only `yes` continues, the counter never regresses),
  T-STORE-9 (read-only commands leave inode, mtime, size, directory, and
  state file unchanged; positive control); one-shot mode, `gen`,
  `doctor`, `copy` without a clipboard. Vault content is checked by
  decrypting the file independently of the binary.
- `tests/cli.rs` (21): tokenizer table, limits, every truncation, and
  properties (2,000 cases); the parser for every command and option;
  `gen` options; sanitize for every unsafe character, properties, and
  truncation; default sensitivity; `ls` matching; strength; `doctor`;
  exit codes; the fuzz seeds.
- `tests/clip.rs` (6, CI only): T-CLIP-1 to -4, T-E2E-6's clipboard
  half, clearing on SIGTERM.
- **T-FUZZ-4** `fuzz_tokenizer` (tokenizer, command and `gen` option
  parsers, strength, `ls` matching; re-quoting round trip) and
  **T-FUZZ-5** `fuzz_sanitize` (output is UTF-8 with no control or bidi
  override; clean input is unchanged). Local run, stable, `-s none`,
  60 s each: 1,124,637 and 7,092,554 runs, clean.
- Two defects found by the new unit tests and fixed: a swap *file* named
  `zram...` counted as zram, and `letmeinletmeinletmein` passed the
  strength check (now caught by the repeated-run rule).

### Section 13 rows that M7 makes true

S5 (T-E2E-1), S6 (T-E2E-3, T-E2E-4), S9 (T-E2E-6), B1 (T-E2E-1, -2),
B3 and B5 (T-E2E-5), B6 (T-E2E-5, with T-VAULT-1), B7 (T-E2E-8), B8
(T-E2E-6, -7, T-FUZZ-4, -5), B10 (T-E2E-3), the T-FUZZ-4 part of B2, and
the T-E2E-9 part of S1 all pass locally. **S7 (T-CLIP-1 to -4) is
written but has not run anywhere yet**; it is true only once CI passes.

### Section 15.5 checklist

- New places for secrets outside the arena: `arboard`'s copies (accepted
  exception) and one-shot argv (inherent). Nothing else.
- New `unsafe`: one block (`sigaction`), in `sys`, with `// SAFETY:`.
- New parsing paths: tokenizer, command parser, `gen` options: fuzz
  target T-FUZZ-4 and truncation tests. `sanitize`: T-FUZZ-5.
- New disk writes: none outside `store`.
- LOC: see below; one cap is exceeded. Section 13: as above.
- Coverage is M9.

### LOC

| Group | LOC | Cap |
| --- | --- | --- |
| `sys + secmem + alloc` | 699 | 900 |
| `crypto + format` | 696 | 750 |
| `store` | 409 | 450 |
| `vault` | 486 | 500 |
| `gen` | 268 | 300 |
| `term + clip` | 275 | 450 |
| `cli + main` | 1,605 | 1,300 (**over by 305**) |
| Total | 4,438 | 4,500 |

The estimate given to the owner (1,400–1,700 for all of M7) was close for
the total (1,841 added), but `cli` took more of it than expected and
`term + clip` less. T-ENG-6 fails locally until the cap is decided.
Request: `cli + main` 1,700, and Total 4,800 to leave room for M8's
`__pause` and M9 fixes. Nothing was cut to fit.

### Not verifiable in the sandbox

T-CLIP and the mock manager (no X server); the ASan builds of the two new
fuzz targets (stable only here); `cargo deny` and `cargo audit` after the
lock-file change (no advisory database; a `deny.toml` skip or ignore
that matched only a removed package may now be reported as unused);
T-MEM-5's `coredumpctl` clause.

### Local gate result (2026-11-15)

- `cargo test --locked`, all green: default 528 s, `memtest` 502 s,
  `testkdf` 508 s, `memtest,testkdf` 515 s, release 80 s. `tests/e2e`
  takes about 37–41 s (T-E2E-6 waits 31 s).
- The first release run failed in `t_store_3_kill_loop` on its
  `none > 0` guard: the known local-only flake of the M4 CI round 2
  entry (release on tmpfs), not an M7 change. The full release rerun and
  four more runs of `tests/store` passed.
- `--no-default-features`: `tests/cli`, `tests/e2e`, `tests/clip` green.
- fmt (crate and `fuzz/`); clippy `-D warnings` in six configurations
  (default, all features, no default features, `memtest`, `testkdf`,
  `memtest,testkdf`) and on the fuzz crate; the six `cfg(miri)` compile
  checks; `tests/eng`: all clean.
- **T-ENG-6 fails**: `cli + main` 1,605 against 1,300 (see LOC).

### After hand-over (2026-11-15): caps and spec

- **LOC caps (owner, spec Section 3 table):** `cli + main` 1,700 and
  Total 4,800. The owner left `sys + secmem + alloc` at 800 and
  `term + clip` at 350 in the table (not the 900 and 450 discussed
  earlier); usage is 699 and 275, so both hold. `scripts/loc_budget.py`
  matches the table, and T-ENG-6 passes: total 4,438 / 4,800.
- **Spec edited at the owner's request (minimal):** Section 3 (the
  `zxcvbn` row removed), 5.1 step 4 (stdin may be a pipe for
  `import --from-stdin`), 5.3 (no `zxcvbn` example), 6.5 (16 characters
  and a built-in estimate of 10^14 guesses, computed in the arena; the
  warning), 9.1 and 11.3 (`--clip-timeout` default 10 s), 13 (S5 row),
  15.1 (the `strength` row removed).
- **The M7 CI round the owner started** was pushed before the
  `loc_budget.py` change, so its `lint` job is expected to fail at
  T-ENG-6 (1,605 against the old 1,300) for that reason alone.

## 2026-11-16 — M6 CI round 3: M6 gate green on CI

Every job passed (owner's report, 2026-11-16). **The M6 gate is passed.**

- `sanitizers (gen-words-word-draw)` 41m43 and
  `sanitizers (gen-words-word-draw-ends)` 13m26 (local Miri: 47m35 and
  13m03). The `max_by_key` diagnosis of round 3 is confirmed on CI.
- `sanitizers (vault-model-t-vault-1-case-1)` 5h13m04 against its 350 min
  cap.
- `test` 25m38 (48m00 in round 1: the same job, the same five
  configurations; runner speed varies this much).

Caps: see the next entry (both rounds are used together).

## 2026-11-16 — M7 CI round 1: runner lost in `test`; cause not established

**Result (owner's report, 2026-11-16).** Every job passed except `test`.
The M7 gate is **not** passed: it needs another CI round.

- New jobs: `e2e` 6m02 (T-E2E-1 .. T-E2E-12 and T-CLIP-1 .. T-CLIP-4 ran
  for the first time anywhere and passed, in three configurations);
  `fuzz-smoke (fuzz_tokenizer)` 2m13; `fuzz-smoke (fuzz_sanitize)` 1m57;
  `supply` 5m26 (no complaint after the lock-file change).
- `lint` passed (2m41), so the push did include the `loc_budget.py`
  change; the failure predicted in the M7 hand-over did not happen.
- `test` ended after 1h02m02 with GitHub's annotation "The hosted runner
  lost communication with the server", during the step "Debug, testkdf".
  The steps before it (default, `memtest`, release) had passed, each
  including all of `tests/e2e.rs`.

### What the log shows

- The log ends inside `tests/e2e.rs`: 25 of its 26 tests are reported
  `ok`. The missing one is `t_e2e_6_idle_timeout_locks_and_exits_0`, the
  test that waits 30 s for the idle timeout. It always finishes last and
  alone.
- libtest prints "test … has been running for over 60 seconds" for a slow
  test (it did so for `t_cry_3` in the same log). There is no such line
  for T-E2E-6. So the log stream stopped within about a minute of that
  test's start: **this was a sudden loss, not a test that hung for a long
  time.** (A plain hang would also have run into the 144 min job cap, not
  into a lost runner.)
- A lost runner uploads no further log, so the log cannot say more.

### What was examined (2026-11-16, sandbox)

1. **Reproduction: none.** `tests/e2e.rs` (debug, `testkdf`, the CI
   configuration) ran 89 times: once alone, 24 times on 4-core slices, 64
   times on 2-core slices with eight copies in parallel, each run under
   a 150 s limit and a 6 GB address-space limit. No run hit either
   limit, and no process was left behind afterwards.
2. **`pwv` at the prompt does not write or spin.** A live session at
   `pwv> ` was given: nothing, SIGCONT, SIGWINCH, SIGINT, SIGTSTP then
   SIGCONT, Ctrl-D, a partial line then Ctrl-D, Ctrl-Z, Ctrl-S, NUL
   bytes, invalid UTF-8, a 4,000-byte line, a second open of the slave, a
   closed master, and a terminal switched to non-canonical mode. In every
   case: at most one error line, 0 CPU ticks in 3 s, and a clean exit
   where one is specified.
3. **Source reading.** `Session::prompt` (the one `poll` loop), the idle
   exit, `term::read_raw`, `sys::write_fd`, and the signal flag have no
   path that repeats output. Neither `pwv` nor the tests send a signal to
   anything but the child's own PID (`ptyprocess` 0.5.0 `kill`, read in
   the pinned source). No orphan processes after the suite.
4. **One real defect in the harness, found by reading.** `Pty::pump`
   (`tests/common/pty.rs`) read "whatever is available" in a loop with no
   bound, into a `Vec` with no cap, and the deadline of `expect` was only
   checked after `pump` returned. A child that writes without end would
   have kept the test inside `pump` for ever and grown the buffer until
   the machine ran out of memory, which is one of the ways GitHub
   documents for losing a runner. **Nothing found makes a child do
   that**, and the rate looks too low to fit the log: the bounded reader
   takes about 4 s for 4 MiB from `yes`; the unbounded one was not
   measured, but at any rate a PTY carries, a 16 GB runner would last
   minutes at least, and the "over 60 seconds" line would have appeared
   (an estimate, not a measurement). It is fixed because it is wrong,
   not because it is shown to be the cause.

### Conclusion: not established

The evidence fits none of the explanations fully:

| Explanation | For | Against |
|---|---|---|
| A child flooded the PTY and the unbounded `pump` exhausted memory | the only mechanism in the code that can starve a runner; the log ends in the PTY tests | no child was found to flood; too slow for the missing "60 seconds" line |
| A fault of the hosted runner or its image (ubuntu-26.04), unrelated to pwv | no mechanism found in pwv; 89 clean local runs; three earlier steps and the `e2e` job ran the same tests cleanly | the log ends exactly in the newest, most terminal-heavy test binary, which would be a coincidence |
| Something in the environment that the sandbox does not have (kernel, PTY behaviour) | would explain why it does not reproduce | no evidence |

This is recorded as **open**, not as solved.

### Changes (rule 2: no check is weakened)

- **`tests/common/pty.rs`:** `pump` reads at most 256 KiB per call
  (`PUMP_MAX`), so every caller's deadline is checked however fast the
  child writes. Above 4 MiB of output per child (`SCREEN_CAP`; the tests
  produce a few kilobytes) it kills the child and panics with a fixed
  message. The screen is still never printed (rule 9).
- **`tests/e2e.rs`, new test** `harness_stops_a_child_that_floods_the_terminal`:
  `yes` on a PTY must end in that panic (`should_panic`), in about 4 s.
- **`tests/e2e.rs`, a flake fixed** (seen once in the 89 runs, not on CI):
  `gen_reports_entropy_and_shows_the_value_only_on_request` waited for
  the `Entropy:` line and then read the value line with `between`, which
  looks only at what has arrived; `pwv` writes the value with a later
  `write(2)`. The test now waits for the value's line end first. The
  assertions are unchanged.
- **`scripts/ci_guard.sh`, new**, around the eight `cargo test` commands
  of `test` and `e2e`. While the command runs it prints one line a
  minute (UTC time, available memory, load), names the largest test
  process when available memory is below 2 GiB, and kills that process
  below 1 GiB. It reads `/proc` only, prints program paths under the
  target directory and never arguments (rule 9), and returns the
  command's status. Purpose: a repeat of the loss leaves a record of the
  minute before it, and a memory exhaustion becomes a failed step with a
  named process instead of a lost runner. Checked locally: the kill
  path, the quiet path, the heartbeat, and status pass-through. It can be
  removed once the cause is known or the loss has not recurred.
- No change to `src/`. LOC is unchanged (4,438 / 4,800).

### Caps (both rounds)

The Miri jobs ran the same code in M6 round 3 and M7 round 1, and the
same job differed by up to 1.9x between them (`gen-words-word-draw`
41m43 and 1h16m20; `gen-words-rng-failure` 8m05 and 15m47). Each cap is
now 3x the **slower** measurement (10 min floor, below 360).

| Job | M6 r3 | M7 r1 | Cap before | Cap now |
|---|---|---|---|---|
| `format-10000-entries` | 11m58 | 9m55 | 34 | 36 |
| `format-testkdf` | 17m03 | 20m16 | 42 | 61 |
| `crypto-vault` | 7m34 | 10m02 | 30 | 31 |
| `vault-model-t-vault-1-case-1` | 5h13m04 | 5h32m29 | 350 | 350 |
| `vault-model-t-vault-1-case-2` | 8m47 | 6m00 | 26 | 27 |
| `vault-model-t-vault-2` | 1h45m42 | 1h05m47 | 173 | 318 |
| `gen-words-t-gen-4-valid` | 1h18m57 | 2h01m10 | 206 | 350 (3x is 364) |
| `gen-words-word-draw` | 41m43 | 1h16m20 | 350 (provisional) | 230 |
| `gen-words-word-draw-ends` | 13m26 | 20m06 | 350 (provisional) | 61 |
| `gen-words-os-bytes` | 15m59 | 11m52 | 31 | 48 |
| `gen-words-entropy-known` | 12m07 | 11m43 | 36 | 37 |
| `gen-words-rng-failure` | 8m05 | 15m47 | 36 | 48 |
| `e2e` | — | 6m02 | 30 (provisional) | 19 |

Unchanged, still within 3x: `lint`, `test` (144), `compat`, `fuzz-smoke`
(10 min floor; the two new targets are measured now), `format`,
`vault-model`, `gen`, `gen-words-passphrase-too-long`, `durability`,
`coredump`, `supply`.

### Open items for the owner

1. **The cause of the lost runner.** Two things would narrow it down:
   the timestamps in the raw log of the failed job (the last `... ok`
   line against the time the job ended), and whether a re-run of that
   job on the same commit passes.
2. **`vault-model-t-vault-1-case-1` ran 5h32m29 against a 350 min cap**
   (and GitHub's 360 min limit): 17 min of margin, less than the
   difference between two runs. It will time out on a slow runner. Not
   changed here: every remedy changes what Miri covers or how the job is
   split, which is the owner's decision.

## 2026-11-16 — M8: verification of Invariant M, and migration

Started on the owner's go-ahead (2026-11-16) while M7 CI round 2 is still
running; the test lost in round 1 had passed by then. If round 2 fails, M7
is fixed first.

### Owner decisions (2026-11-16)

1. **The legacy format is GnuPG-encrypted JSON**, the format of the
   provided `encrypted_pw_mgr.py`: one file, `{entry: {key: value}}`,
   `gpg --symmetric` AES-256. Spec Section 12.1 describes another program
   (pickle, Fernet, PBKDF2, a separate `salt` file); that path is **not**
   implemented. No `--salt` argument and no unpickler.
2. **`gpg` decrypts**, called by the script. gpg asks for the legacy
   passphrase on the terminal itself, so it never enters Python. The
   script needs only the standard library (not `cryptography`).
3. **`pwv import` reads the pipe to its end, then unlocks.** In the pipe
   both programs prompt on the same terminal; reading first serialises
   the prompts, and an empty pipe (the legacy side failed) is refused
   before any password is asked. This reverses steps 1 and 2 of 12.2.
4. **The clipboard handle is dropped at every expiry** (see "Clipboard"
   below).

**Spec edits these decisions need** (made on 2026-11-16 at the owner's
request; see "M8 CI round 1"): 12.1
(format, arguments, gpg, no `cryptography`, steps 3 and 4), 12.2 (order:
read, then unlock), 12.3 (legacy file names), 14.12 T-MIG-2 (the pickle
is given as the vault file and as the decrypted content; no salt file),
13 row S2 (legacy data is parsed as JSON only).

### T-MEM-4 (`tests/mem.rs`, `memtest` builds)

- **Exit pause (production, `memtest` only):** `cli::wiped_pause` runs in
  `cli::run` after the arena is dropped and the stack scrubbed. With
  `PWV_MEMTEST_EXIT_PAUSE` set it writes `PWV_MEMTEST wiped` to fd 2 and
  waits for SIGUSR1 (or SIGTERM) on the signal flag alone, sleeping in
  `sys::nap` (a `poll(2)` with no fds). Opt-in by variable, so every other
  suite's `memtest` run exits at once (`exit_pause_needs_the_environment_variable`).
- **Parent:** confirmed: `Pty::spawn` runs `sh -c '... exec pwv'`, the PID
  is kept, and the test process (the parent) opens `/proc/<pid>/mem`
  under Yama `ptrace_scope = 1`.
- **The scan** reads every readable mapping, finds each canary in UTF-8
  and UTF-16LE, and requires completeness (more than 1 MiB read; heap,
  stack, and the `pwv` image readable; only `[vvar]`/`[vsyscall]`-style
  mappings may fail). Positive control: the vault path is found on the
  heap.
- **Canaries:** P (master password), C1 (in the vault, from an earlier
  process), C2 (typed hidden in `set`), C5 (typed with echo in `set` of a
  plain field), C3 (generated by `set --gen`), C4 (`gen --show`, on the
  clipboard where there is one). Commands: `show`, `reveal` (twice),
  `copy`, `set` (three ways), `gen`.
- **Assertions:** right after unlock, P nowhere and C1 only in the arena;
  mid-session, P nowhere, stored secrets in the arena and only there, no
  UTF-16LE copy of anything; C4 (on the clipboard) exactly once in the
  arena (the `Clip` slot) and otherwise only in private anonymous
  memory (the accepted `arboard` exception, asserted narrowly); after
  the clipboard expired, nothing outside the arena at all; after `lock`,
  zero matches of anything anywhere. Exits by SIGTERM, SIGHUP, end of
  input, and the idle timeout are scanned the same way.
- **Checked against deliberate defects:** a heap copy of a revealed value
  (`mem::forget(value.to_vec())`) and a skipped wipe of the NFC password
  in `vault::unlock` each fail it, naming the canary and the mapping.
- Locally there is no display: `copy` and `gen` fail cleanly and the
  clipboard branch is not run. In CI (`e2e`, xvfb) it is, including a
  paste by `xclip`.

### Clipboard: residue in the X11 send buffer (finding)

Read in the pinned sources: when another client pastes, `arboard` 3.7.0
(`handle_selection_request`) sends the value with `change_property8`;
x11rb 0.13.2 copies small requests into the connection's
`WriteBuffer::data_buf` (`VecDeque<u8>`), and `drain` after the write
leaves the bytes in the deque's storage until overwritten or freed. So a
pasted value stayed in `pwv`'s heap after expiry, until exit. **Fix:**
`Clip::clear_if_unchanged` drops the `arboard::Clipboard` (the next copy
creates a new one); the connection and its buffer are freed, and the
zeroizing allocator wipes them. T-MEM-4 pastes in CI and requires no
match outside the arena after expiry. **Not run locally** (no X server):
CI is the first run.

### Migration

- **`tools/migrate_legacy.py`** (191 lines, standard library): refuses
  unless stdout is a FIFO (before anything else); runs `gpg --quiet
  --no-symkey-cache --pinentry-mode loopback --decrypt -- <vault>`; parses
  the output with `json.loads` only (duplicate keys and NaN refused);
  validates every FORMAT.md rule; collects all refusals, then aborts
  without writing anything if there are any. Names in messages are
  `json.dumps`-escaped (ASCII: controls and bidi marks are escapes), never
  keys or values. `None` → empty value with a warning (B2). Sensitivity:
  Section 9.3's list, A–Z folding as in `cli`. Body: sorted by name
  bytes, field order kept, minimal padding; summary on stderr.
- **Interpretation (rule 10):** spec 12.1 step 5 aborts on a control
  character "listing the entry names"; this applies to every refusal, and
  all are listed in one run.
- **`pwv import`** (`cli::cmd_import`, `read_pipe`): no longer marked as
  needing the vault in `COMMANDS`; it reads stdin into the scratch half
  first, refuses an empty pipe, then unlocks. A terminal stdin still
  unlocks first and is then refused, as T-E2E-10 asserts.
- **Legacy fixture:** `tests/legacy/encrypted_pw_mgr.py` is the owner's
  file, unchanged. `make_fixture.py` imports it and calls its own
  `add_secure_password` (which returns `None` for a length below 8) and
  `encrypt_data`, so the fixture is written by the original code.

### Tests added

- `tests/mem.rs` (3): T-MEM-4 mid-session and after lock; the signal,
  EOF, and idle exits; the pause is opt-in.
- `tests/mig.rs` (8): T-MIG-1 (expected model, B2 warning, a second run
  refused and then suffixed; key-case collision and seven other refusals,
  names escaped; wrong passphrase; a vault larger than the pipe buffer),
  T-MIG-2 (live malicious pickle as the vault and as the decrypted
  content, with a positive control that it does create the marker; a
  static check that the script has no code-executing parser), T-MIG-3
  (terminal, regular file, `/dev/null`; gpg never started; positive
  control), `--vault` required.
- **Stand-in `gpg`:** every T-MIG test runs with a stand-in that checks
  the script's exact gpg arguments, prompts on `/dev/tty` with echo off,
  and decrypts a test cipher. Where `PWV_LEGACY_PYTHON` is set (CI `e2e`)
  each also runs with the real gpg on the legacy program's fixture;
  `PWV_REQUIRE_GPG` makes that mandatory. **The real-gpg half has not run
  anywhere yet** (no gpg in the sandbox).
- `tests/e2e.rs`: T-E2E-10 gains the ordering test (a producer that
  prompts on the terminal first; a failed producer; a wrong master
  password after a good pipe). In `t_e2e_10_import_valid_invalid_and_tty`
  the empty-pipe case moved out of the "refused after unlock" loop into
  its own check, which is stricter (refused, and no password asked). This
  edits an existing test (rule 2: stricter, nothing removed).
- Script mutations each caught: no FIFO check, a pickle fallback,
  unsorted output, an extra gpg flag.

### Section 13 rows

S2 (T-MIG-2) passes locally with the stand-in; S10 now has T-MEM-4. Both
are true only once CI's real-gpg and X11 runs pass.

### Section 15.5 checklist

- New places for secrets outside the arena: none in `pwv`. The script is
  Python and outside the binary (best-effort hygiene, documented).
- New `unsafe`: none.
- New parsing paths: none in Rust (`import` reuses `format::parse_body`).
  The script's JSON is parsed by Python's `json`.
- New disk writes: none.
- LOC: below. Section 13: as above.
- Coverage is M9.

### LOC

| Group | M7 | M8 | Cap |
| --- | --- | --- | --- |
| `sys + secmem + alloc` | 699 | 707 | 800 |
| `term + clip` | 275 | 279 | 350 |
| `cli + main` | 1,605 | 1,633 | 1,700 |
| Total | 4,438 | 4,478 | 4,800 |

Others unchanged. `tools/` and tests are not counted.

### Local gate result (2026-11-16)

- `cargo test --locked --no-fail-fast`: default 430 s, `memtest` 577 s,
  `testkdf` 476 s, `memtest,testkdf` 514 s, all green. Release 121 s:
  everything green except `t_store_3_kill_loop`'s `none > 0` guard, the
  known local-tmpfs flake (M4 CI round 2); three reruns of `tests/store`
  in release: 1 fail, 2 pass, as usual.
- After the matrix, two test-only changes to `tests/mig.rs` for the real
  gpg (`--no-symkey-cache` on the test's own `gpg --symmetric`, so the
  agent cannot cache the passphrase and skip the prompt; `gpgconf --kill
  gpg-agent` when a rig is dropped). `tests/mig`, `tests/mem`
  (`memtest`), and `tests/e2e` were rerun: green.
- `--no-default-features`: `cli`, `e2e`, `clip`, `mig` green.
- fmt (crate and `fuzz/`); clippy `-D warnings` in six configurations and
  on the fuzz crate; the six `cfg(miri)` compile checks; `tests/eng`;
  `loc_budget.py`: all clean.
- `tests/mem` takes about 34 s (the idle exit waits 30 s); `tests/mig`
  about 3 s with the stand-in.

## 2026-11-16 — M7 CI round 2: M7 gate green on CI

Every job passed (owner's report, 2026-11-16). **The M7 gate is passed.**
The runner loss of round 1 did not recur; its cause stays unestablished
(the M7 CI round 1 entry). `scripts/ci_guard.sh` stays for now.

Timings: `test` 46m38, `e2e` 6m19, `lint` 2m50, `supply` 5m10,
`coredump` 1m00, `durability` 3m24, `compat` 8 s, `fuzz-smoke` 1m48 to
2m13. Miri: `vault-model-t-vault-1-case-1` 5h17m23, `-case-2` 8m49,
`vault-model-t-vault-2` 1h11m34, `vault-model` 8m56, `crypto-vault` 9m32,
`format` 6m39, `format-10000-entries` 9m45, `format-testkdf` 17m04, `gen`
2m31, `gen-words-t-gen-4-valid` 1h18m49, `gen-words-word-draw` 1h17m43,
`gen-words-word-draw-ends` 17m54, `gen-words-os-bytes` 11m52,
`gen-words-entropy-known` 11m37, `gen-words-rng-failure` 15m40,
`gen-words-passphrase-too-long` 13m42.

Caps (3x the slowest measurement): `gen-words-word-draw` 230 → 234,
`gen-words-passphrase-too-long` 31 → 42; all others still hold.

## 2026-11-16 — M8 CI round 1: a masked test failure; T-VAULT-1 split

**Result (owner's report).** `e2e` failed after 1m27, in "M8 gate by
name": `missing: scan::t_mem_4_canary_scan_mid_session_and_after_lock`.
The step that ran the tests was green.

**A CI defect, older than M8.** Steps without `shell:` run under GitHub's
default `bash -e {0}`, without `pipefail`. So `cargo test ... | tee m8.txt`
had the status of `tee`, and the failing test passed its step; only the
by-name check noticed. The same pattern is in the M4–M7 gate steps and in
the M7 `e2e` test steps: until now a failing test there that is not listed
by name would not have failed CI. (All those runs were green in fact: each
listed test was found `ok`, and the unlisted ones are in `test`, which does
not pipe.) **Fix:** `defaults: run: shell: bash` for the whole workflow
(`bash -eo pipefail`); the one pipeline that could fail for a harmless
reason under `pipefail` (`gpg --version | head -1`, SIGPIPE) is now
`sed -n 1p`.

**The test failure (owner's log, 2026-11-16).** Both T-MEM-4 scans
failed in the scanner's completeness check (`tests/mem.rs:193`, "a
readable mapping could not be read: \"\""), not in a canary assertion.
Diagnosis:

- The canary test's first scan (after unlock, before any `copy`) must
  have passed, since it runs the same check first; the failing scan comes
  after `copy`, which starts `arboard`'s X11 server thread. The other test
  scans only after the wipe, when that thread has ended but glibc keeps
  its stack mapped for reuse. Locally there is no display, so no thread.
- glibc 2.42 (Ubuntu 26.04; the sandbox has 2.36) places a thread
  stack's guard page **inside** the stack's anonymous `rw-p` mapping with
  `madvise(MADV_GUARD_INSTALL)` (Linux 6.13), instead of a separate
  `---p` mapping. Such a page faults on any access: `/proc/<pid>/mem`
  returns `EIO`, so reading the whole mapping failed.
- Measured in the sandbox (its kernel supports guard regions; a ctypes
  probe): a guard page inside a 4-page `rw-p` mapping, `/proc/self/mem`
  `EIO` for that page only, and `pagemap` bit 58 (`PM_GUARD_REGION`) set
  for that page only.

**Fix (test only, rule 2: nothing weakened).** A mapping that cannot be
read whole is read page by page; a page may be skipped only if `pagemap`
marks it as a guard region (it can hold no data: the process faults on
it too). Any other unreadable page still fails the scan, now naming the
mapping's permissions, name, and the count of such pages. New test
`scan_skips_guard_pages_and_nothing_else`: a child process installs a
guard page between two pages holding a canary; the scanner must skip
exactly one page and find both canaries at their addresses. Negative
control: with the wrong pagemap bit, it fails.

**Not run on CI:** `cargo test` stops at the first failing test binary,
so `tests/mig.rs` (the real-gpg half of T-MIG) did not run in this round.
The step now uses `--no-fail-fast`. The clipboard branch of T-MEM-4 has
still never completed: a copy of the clipboard value left on `arboard`'s
thread stack would now be found (glibc does not wipe cached stacks).

**T-VAULT-1 under Miri split in four (owner's request: only if no test is
weakened).** The case with seed 1 (153 operations, 16 segments of 10)
ran 5h09m44 to 5h32m29 in one job, against the 360 min limit.

- The implementation reloads its state from the file at the start of
  every segment (`open_with_kek` into `vault_a`), so the saved file is the
  only state that crosses a segment boundary.
- `PWV_T_VAULT_1_PART=j/n` runs part `j`: the earlier operations are
  applied to the reference model alone (cheap), the reference's canonical
  body is sealed as the starting file (canonical form is unique, so these
  are the bytes the full run would reopen there), and the part's own
  segments then run with every check unchanged, ending with the reopen
  of its last file.
- So each operation is applied to both sides and checked in exactly one
  part, and every file the implementation saves is reopened and checked.
  The added starting save is extra coverage. Without the variable
  (natively, and in every other job) nothing changes.
- Segment `k` weighs `k + 1` (later segments hold bigger bodies): seed 1
  splits into segments 0–7, 8–10, 11–13, 14–15.
- New test `t_vault_1_parts_cover_every_segment_once` (native): for up to
  40 segments and 1 to 8 parts, the parts are contiguous and cover every
  segment once; and the CI split above is pinned.
- Checked natively: all four parts pass with 256 cases each; a planted
  defect (`unset` of a 3-byte key does nothing) fails every part.
- CI: four jobs `vault-model-t-vault-1-case-1-part-1` .. `-4`, the variable
  forwarded through Miri isolation, provisional caps 350.

**Spec edited (owner's request, minimal):** 11.3 steps 1 and 3 (drop the
`Clipboard` at expiry), 12 intro, 12.1 (heading, steps 1, 3, 4, 5), 12.2
steps 1–2 (read, then unlock), 12.3 (legacy file names), 13 row S2, 14.12
T-MIG-2.

## 2026-11-16 — M8 CI round 2: M8 gate green on CI

Every job passed (owner's report and run-time screenshots, 2026-11-16).
**The M8 gate is passed:** T-MEM-4 (including its clipboard branch under
`xvfb-run`, for the first time), T-MIG-1 .. T-MIG-3 with the real `gpg`
and a fixture written by the original `encrypted_pw_mgr.py`, and T-E2E-10
(including `t_e2e_10_import_reads_the_pipe_before_asking_for_the_master_password`,
first run on CI). `test` also passed under `pipefail`, so no failure had
been masked there. Section 13 rows **S2** (T-MIG-2) and **S10** (T-MEM-4)
are now verified on CI; S7 (T-CLIP-1 .. -4) was verified in M7 CI round 2.

Timings: `test` 49m39, `e2e` 6m41, `lint` 2m53, `supply` 5m19,
`coredump` 1m11, `durability` 4m07, `compat` 10 s, `fuzz-smoke` 1m53 to
2m17. Miri: `vault-model-t-vault-1-case-1-part-1` 46m30, `-part-2`
1h28m23, `-part-3` 3h03m16, `-part-4` 1h46m54, `-case-2` 6m41,
`vault-model-t-vault-2` 18m46, `vault-model` 11m35, `crypto-vault` 7m45,
`format` 9m38, `format-10000-entries` 7m16, `format-testkdf` 26m13, `gen`
2m09, `gen-words-t-gen-4-valid` 2h01m12, `gen-words-word-draw` 58m43,
`gen-words-word-draw-ends` 15m19, `gen-words-os-bytes` 10m30,
`gen-words-entropy-known` 8m52, `gen-words-rng-failure` 10m27,
`gen-words-passphrase-too-long` 6m54. Total runner time 13h49m30.

Caps (3x the slowest measurement): `test` 144 → 149, `e2e` 25
(provisional) → 21, `format-testkdf` 61 → 79, `vault-model` 34 → 35,
`durability` 11 → 13; T-VAULT-1 parts 1, 2, 4 → 140, 266, 321. Part 3
stays at 350: 3x does not fit under GitHub's 360 min limit (the same
exception as `gen-words-t-gen-4-valid`).

**The T-VAULT-1 split is uneven.** The parts sum to 7h05 against 5h17 for
the whole case in M7 round 2. Per unit of the `k + 1` weight model the
parts cost 1.3, 2.9, 4.7 and 3.4 min, so the model underweights later
segments, and segments 11–13 of seed 1 seem to be the costly ones (the
operations are random; one segment may be dominated by a large import or
by bigger values). Part 3 has 1.9x headroom against its cap, which is the
largest runner-speed spread seen between rounds (M7 CI round 1). Not
changed in this entry; options are put to the owner (M9 decisions).

## 2026-11-16 — M9 started: inventory and tool checks

The owner gave the go-ahead for M9 on 2026-11-16. Done before the M9
decisions (signing, triggers, badges, T-PERF-1, T-SAN-1, T-MUT-1, aarch64,
rule-12 review, `ci_guard.sh`) are settled:

**Section 14 inventory: `scripts/test_ids.py`.** One row per test ID: the
milestone of its gate (Section 16) and its evidence, which is a list of
`#[test]` functions, a CI job whose success is the result (clippy, fuzzing,
Miri, `supply`, `coredump`), or "to do". `--check` fails if a named test
function does not exist (or, with `--spec`, if the table and Section 14
disagree); it also lists the named tests that no gate-by-name step greps.
`--markdown` prints the table; `--logs` turns test logs into a
pass/fail/not-run verdict per ID, for the coverage report's item 5
(Section 14.13). Kept as a script, not a table here, so the report and the
inventory cannot drift. `lint` runs `--check`.

- Locally against the spec: 81 IDs, table and spec agree, every named
  test exists. Negative control: an invented ID and function both fail.
- **12 IDs are not implemented:** T-STORE-8, T-ENG-7, T-SAN-1, T-MUT-1,
  T-COV-1 .. T-COV-6, T-REPRO-1, T-PERF-1.
- **24 implemented IDs are not checked by name** (their 57 tests run in
  `test`/`lint`, and a failure fails CI, but nothing proves they ran):
  T-KAT-1, -2, T-COMPAT-1, T-FMT-1 .. -4, T-CRY-1 .. -6, T-MEM-1, -2, -3,
  -5, -6, -7, the seed test of T-FUZZ-3, T-ENG-2, -3, -4; T-STORE-1's
  vfat test is checked by its own `1 passed` grep. "Every test ID green"
  (the M9 gate) needs them listed. Plan: tee each `test` configuration's
  output to a log, check names against those logs (no reruns), and keep
  the logs as artefacts for the coverage report.

**Tools verified in the sandbox.**
- `cargo-mutants` 27.1.0 installs from crates.io (`cargo install
  --locked`); version to pin in CI.
- AddressSanitizer on `nightly-2026-11-15`:
  `RUSTFLAGS=-Zsanitizer=address cargo +nightly-2026-11-15 test --locked
  --target x86_64-unknown-linux-gnu --test alloc --test secmem` builds and
  passes with `detect_leaks=1` in 45 s, including T-MEM-6's asserting
  layer under ASan's `malloc` interceptors and T-MEM-1's smaps checks. (A
  test build only: `RUSTFLAGS` replaces `.cargo/config.toml`'s link
  hardening flags, which the test build does not need.) The full suite,
  the PTY children and T-MEM-4 are still to try.
- `cargo-llvm-cov`: CI only (no `llvm-tools` locally).
- LazyFS: CI only (GitHub unreachable).

## 2026-11-16 — M9 decisions (owner) and CI round 1 contents

**The repository is now public** (owner, 2026-11-16: the private plan's
monthly CI minutes ran out). Consequences: standard GitHub-hosted runners,
including the Arm ones, cost nothing; GitHub artifact attestations are
available; CI logs and artefacts are public (tests print no secrets by
design, rule 9, and the canaries are test values); pull requests from forks
run with a read-only token and no secrets. Only `push` events on `main`
may write (the `badges` branch, later in M9).

**Owner decisions (2026-11-16):**
1. Signing: GitHub artifact attestations (Sigstore, keyless), aiming at
   SLSA v1.0 Build Level 3; only tag builds are signed.
2. Triggers: pushes and pull requests run every job except Miri
   (`sanitizers`), `sanitizers-asan`, `durability`, `test-arm64`; these run
   nightly and on "Run workflow" (`workflow_dispatch`), which also run
   everything else. Spec 15.3 asks exactly this for `sanitizers` and
   `durability`.
3. Badges: default branch `main`; one job (`coverage-report`) may have
   `contents: write`; branch protection allows it.
4. T-PERF-1: "excluding fsync" is measured on tmpfs (where `fsync` costs
   nearly nothing), with no production code added; allocator overhead is
   an in-process benchmark of a representative workload, `System` vs
   `ZeroizingAlloc::new(false)`, median of several runs, nightly.
5. T-SAN-1: `tests/mem.rs` is left out of the ASan run (its scanner reads
   every mapping, and ASan's reserved shadow is terabytes); T-MEM-4 still
   runs in `e2e`. LeakSanitizer on (`detect_leaks=1`); any harmless report
   gets a named, dated suppression, never a global off switch.
6. T-MUT-1: per-module weekly jobs, sharded, running that module's tests;
   a fast first pass with reduced case counts, and every survivor re-run
   against the full suite before it counts (a weaker first pass can only
   add survivors, which the full run then judges).
7. aarch64: nightly, on GitHub's Arm runners.
8. Rule 12: a separate Claude Code session on an exported tree without
   history or DESIGN_NOTES; brief and file list prepared for the owner
   (outside the repository).
9. `scripts/ci_guard.sh` stays.
10. T-VAULT-1 under Miri: re-split into five parts from measured times.

**Release (spec 15.3).** The spec asks for a `release` job on tags:
T-REPRO-1, T-ENG-7, build, `sha256sum`, and a *signed checksum file*. It
does not name a signing method. Interpretation: the checksum file is
"signed" by a Sigstore attestation, like the binary and the word-list
licence. `release.yml` (on `v*` tags) calls the reusable
`release-build.yml`, which builds (scripts/release_build.sh), attests with
`actions/attest-build-provenance`, and uploads the files plus the Sigstore
bundle. Build and signing are both in the reusable workflow, so the
signer identity is that workflow (GitHub's route to Build L3). Users
verify with `gh attestation verify <file> --repo <owner>/pwv
--signer-workflow <owner>/pwv/.github/workflows/release-build.yml`. Nothing
is published automatically: the owner attaches the artefact to a GitHub
release, so no release job needs `contents: write` (spec 14.13 reserves it
for `coverage-report`). Caveat: a reusable workflow in the *same*
repository is isolated from the caller's steps but changes with the same
commits. A separate repository holding `release-build.yml` would be
stronger; not done (owner may choose).

**scripts/release_build.sh (T-REPRO-1, T-ENG-7).** Two `--locked` release
builds of copies of the tree at two different absolute paths, each in a
clean target directory, `SOURCE_DATE_EPOCH` = the commit time,
`--remap-path-prefix` for the tree and `CARGO_HOME`; `cmp` must find them
identical, and neither the work directory, `CARGO_HOME`, nor the checkout
path may appear in the binary. The flags go in `CARGO_ENCODED_RUSTFLAGS`
**with the link-hardening flags repeated** (any `RUSTFLAGS`-style variable
replaces `.cargo/config.toml`'s list), and `readelf` then checks PIE,
`GNU_RELRO`, and `BIND_NOW`. T-ENG-7: a `memtest,testkdf` release build
must contain both marker strings (positive control), the artefact
neither. Runs on every push in the new `release-check` job and in the
release workflow. `PWV_REPRO_TARGET` makes both builds share one target
directory (wiping its `release/` first); only for this sandbox, which may
not create target directories.

**Gate by name for the 24 IDs** (previous entry): the five `test`
configurations now `tee` into `logs/`, a new step requires an `ok` line
and no `FAILED` line for every named test of those IDs
(`scripts/test_ids.py --require`), and the logs are kept as an artefact
(for the coverage report's test-ID table).

**T-VAULT-1 re-split (decision 10).** The M8 weight model (`k + 1`) did not
fit (M8 CI round 2). From the measured parts, minus about 5 min of job
setup, the segments of seed 1 cost about 5 min each for 0–7, 28 for 8–10,
59 for 11–13 and 51 for 14–15 under Miri (resolution: the old parts). No
power-law weight separates 11, 12 and 13, so CI now gives explicit
segment ranges: `PWV_T_VAULT_1_PART=a..b` (or `a..` up to the end), with
0..10, 10..12, 12..13, 13..14, 14.. (estimated 1h41, 1h32, 1h04, 1h04,
1h47). `j/n` still works, and its test is unchanged. New test
`t_vault_1_ci_ranges_cover_every_segment_once` reads the `part:` values in
ci.yml and checks they are contiguous from 0, the last open-ended, and
cover every segment once for 0–40 segments, so a mistyped range cannot
leave a segment unchecked; it also pins the seed-1 split and the parser.
Caps provisional (350) until measured.

**T-SAN-1 (`sanitizers-asan`, nightly).** The full suite under ASan was
run locally first (`nightly-2026-11-15`, default features, every test
target except `tests/mem.rs`, `--lib --bins`, `ASAN_OPTIONS=detect_leaks=1:
handle_segv=0:log_path=...`): 657 s, every test passed. One finding:
LeakSanitizer reported the test binary `cli` itself, 10 leaks, all from
`tests/cli.rs`'s `policy` helper, which leaks each parsed buffer on
purpose to get a `'static` `Policy`. Harmless (test data, test process),
but it fails the run. Fixed in the test, not by a suppression: the leaked
buffers are pushed into a test-only `static KEPT: Mutex<Vec<&'static
[u8]>>`, so they stay reachable; assertions unchanged. (A suppression
would match only on symbolized frames, so it would depend on CI having
`llvm-symbolizer`.) Rerun of `cli` under ASan: no reports.
- `handle_segv=0`: T-MEM-2's child must die by SIGSEGV and T-MEM-5 sends
  one; with ASan's handler the process exits 1 instead. Invalid accesses
  are still caught by ASan's instrumentation; only the handler of a real
  SIGSEGV is the kernel's.
- `log_path`: reports from `pwv` children would otherwise go to their PTY,
  which tests never print. A last step fails the job if any report file
  exists, and prints them (stack traces, addresses, shadow bytes: no
  memory contents). `llvm` is installed so CI reports are symbolized.
- Four configurations (default, `memtest`, `testkdf`, `memtest,testkdf`)
  under `xvfb-run` with `PWV_REQUIRE_X11`; release is left out (ASan is a
  debug-build check here, and T-MEM-5 runs in `coredump`/`test`).
  `--no-default-features` only removes `arboard`; covered by the others.
- Local runtime 11 min (default); provisional cap 120.

**Page size (aarch64, owner question).** `src` already uses the kernel's
page size (`sys::Region::new`, `rustix::param::page_size`), but two tests
assumed 4096:
- `tests/mem.rs` (T-MEM-4's scanner): `pagemap` has one entry per *real*
  page, so on a 16 or 64 KiB kernel `addr / 4096` would read the wrong
  entry, and an unreadable non-guard chunk could be skipped as a guard
  (a hole in the completeness check) or a guard page reported as
  unreadable. Its self-test `scan_skips_guard_pages_and_nothing_else`
  placed the guard at a 4 KiB offset, which `madvise` refuses there, so it
  would have returned at its "unsupported kernel" branch and passed
  without testing anything. Both now use the real page size
  (`rustix::param::page_size()`; Python `mmap.PAGESIZE`). Nothing changes
  on 4 KiB kernels.
- `tests/secmem.rs`: the rounding check expects `(MIN_ARENA + 1)` rounded
  to the real page size (equal to the old `MIN_ARENA + 4096` on 4 KiB).
GitHub's Arm runners are expected to use 4 KiB pages; `test-arm64` prints
`getconf PAGESIZE` so the log shows it.

**Local gate result (2026-11-16, M9 round 1).** `cargo test --locked
--no-fail-fast`: default 462 s, `memtest` 552 s, release 150 s (T-STORE-3
passed), `testkdf` 504 s, `memtest,testkdf` 574 s, all green;
`--no-default-features` (`cli`, `e2e`, `clip`, `mig`) 43 s, green.
`test_ids.py --require` over the five logs: 23 IDs, 0 problems. fmt
(crate, `fuzz/`), clippy `-D warnings` in six configurations and on the
fuzz crate, the six `cfg(miri)` compile checks, `loc_budget.py` (4,478 /
4,800, no `src/` change in this round): clean. `release_build.sh`: T-REPRO-1
bit-identical, PIE/RELRO/BIND_NOW, T-ENG-7 with its control: ok (51 s with
a warm dependency cache). ASan: full default suite as above; `cli` rerun
without reports after the fix. The workflows parse (PyYAML) with the
intended triggers. Not runnable here: Miri's five new parts, the Arm
runner, attestation, xvfb under ASan.

## 2026-11-16 — Licence; release workflow placement; vulnerability reporting

- **Licence (owner):** MIT, text supplied by the owner, committed as
  `LICENSE`. `Cargo.toml`'s `license` changes from `MIT OR Apache-2.0`
  (no Apache text existed) to `MIT`. `release_build.sh` ships `LICENSE`
  next to the binary and the word-list licence, and all three are in
  `SHA256SUMS` and attested. README has a Licence section.
- **Reusable release workflow** stays in this repository (owner): the
  same-repository caveat in the M9 decisions entry stands.
- **Private vulnerability reporting** is enabled on GitHub (owner);
  `SECURITY.md` points to it.

## 2026-11-17 — M9 CI round 1: `e2e` failed (clipboard race in `tests/mem.rs`)

**Result (owner's report, push run on the M9 branch).** Every push job
passed except `e2e` (2m01). In its step "T-MEM-4 (memtest), T-MIG,
T-E2E-10 with the real gpg", `scan::t_mem_4_signal_eof_and_idle_exits_are_wiped`
panicked at `tests/mem.rs:503`, "C1 is on the clipboard" (the `xclip`
paste after `copy site password` returned something other than C1). The
other three `mem` tests and all eight `mig` tests passed. The `mem`
binary finished in 9.21 s, so the failure came before the `idle`
iteration (which waits 25 s). The test had passed in M8 CI round 2.

**Cause: two tests share one X clipboard.** `xvfb-run -a` starts one X
server for the whole `cargo test` command, and libtest runs a binary's
tests in parallel. Both T-MEM-4 tests copy to the CLIPBOARD selection:
the canary test copies C1, then `gen` puts C4 there, and the selection is
cleared when its 5 s timeout runs out. The signal test copies C1 and pastes
straight away. Any of those events from the other test, happening between
the signal test's copy and its paste, changes or empties what `xclip`
reads. `tests/clip.rs` has serialised its tests with a `static X: Mutex`
since M7; `tests/mem.rs` (M8) never got that lock, and M8 round 2 passed
because the timing happened to work out. Not a `pwv` defect.

**Fix (test harness only; rule 2: no assertion changed).** `tests/mem.rs`
gets the same `static X: Mutex<()>` and `turn()` as `tests/clip.rs`, and
both T-MEM-4 tests hold the guard for their whole run. Cost: the two tests
now run one after the other, about 40 s locally (from ~30 s), well inside
`e2e`'s cap of 21 min. The other test binaries run under `xvfb-run`
one after another (cargo runs binaries sequentially), and the only other
clipboard use, `t_store_9_read_only_commands_never_write` in `tests/e2e.rs`,
never reads the clipboard back.

**Verified locally:** `cargo fmt --check`, clippy `-D warnings` (default
and `memtest`), `cargo test --features memtest --test mem --test eng`
(all pass, 42 s), `test_ids.py --check`. There is no X server locally, so
the clipboard branch can only be confirmed on CI.

## 2026-11-17 — M9 CI round 1: push results; M9 round 2 contents

**Push run on the M9 branch (owner's report, 2026-11-17).** After the
`e2e` fix above, every push job passed: `test` 1h00m08, `e2e` 6m22,
`supply` 5m22, `fuzz-smoke` 1m50 to 2m38, `lint` 1m49, `coredump` 1m26,
`release-check` 1m25 (so T-REPRO-1, link hardening and T-ENG-7 passed on
CI), `compat` 10 s. The nightly set was started by the owner; its results
are still to come.

Caps from these times (3x the slowest measurement, floor 10): `test`
149 → 181 (3 x 60m08; it took 49m39 in M8 round 2), `release-check`
30 (provisional) → 10. The others stay (their 3x of earlier, slower runs
is larger). In `scripts/test_ids.py`, T-ENG-7 and T-REPRO-1 are now
`("job", "release-check ...")`; T-SAN-1 is `("job", "sanitizers-asan")`
and counts once that nightly job reports.

**Round 2 (this entry) implements the rest of M9's tooling**, as one CI
round (owner preference): coverage (T-COV-1 .. T-COV-6), T-MUT-1, T-STORE-8,
T-PERF-1, `fuzz-long`, the documents, and the Section 13 verification.
`src/` is unchanged (LOC 4,478 / 4,800). Every Section 14 ID now has an
implementation (`test_ids.py --check`: 0 to do).

### Coverage (spec 14.13)

- **Shared definition of production code.** The `#[cfg(test)]` item
  stripping moved unchanged from `loc_budget.py` into `scripts/prodcode.py`
  (generalised to any `#[cfg(...)]` marker); `loc_budget.py` imports it and
  prints the same table as before (4,478). The coverage report uses the
  same module: production lines are code lines of `src/*.rs` outside
  `#[cfg(test)]` and `#[cfg(miri)]` items. Only two `#[cfg(miri)]` items
  exist (`sys.rs`'s Miri `map` and `unmap`); the report lists them as
  excluded. **Interpretation:** a line counts if it is a production line
  *and* LLVM instruments it (comments, blank lines, and lines with no
  executable code have no counter). My line classifier differs from
  tokei's count by at most 7 lines per file (multi-line string literals);
  it does not matter, since only instrumented lines count.
- **Runs** (`coverage` job, every push): one job per configuration of
  `test` (default, `memtest`, `--no-default-features`, `testkdf`,
  `memtest,testkdf`), each `scripts/coverage_run.sh` = `cargo llvm-cov
  --no-report --no-fail-fast` over every target, then LCOV, JSON and HTML
  exports. The default and `memtest` runs have a display (`xvfb-run`,
  `PWV_REQUIRE_X11`) and the real `gpg` with the legacy program's Python
  (`PWV_REQUIRE_GPG`), so T-E2E, T-CLIP, T-MEM-4's clipboard branch and
  T-MIG run as in `e2e`; the other three have no display, so the "no
  clipboard" paths are measured too. Release builds, Miri, sanitizers,
  fuzzing, mutants and `durability` are not included (spec).
- **Child processes:** cargo-llvm-cov 0.9.1 (source read) sets
  `LLVM_PROFILE_FILE=<target>/pwv-%p-%m.profraw`; children inherit it
  (no `env_clear` in the harness), and `pwv` exits through
  `std::process::exit`, which writes the profile.
- **Determinism:** `PROPTEST_RNG_SEED=20261117` and
  `PWV_T_STORE_3_SEED=0x5eed5eed5eed5eed` in the coverage jobs. proptest
  1.12's `Config::with_cases` keeps the environment-derived defaults
  (source read), so the seed reaches every runner natively; case counts
  are fixed in the tests. Normal runs are unchanged (no test edit needed).
  Timing-dependent paths (where a SIGKILL lands) can still vary a little.
- **Merging** (`scripts/coverage_report.py`): the spec allows splitting
  across jobs and merging by line. Lines: covered if any run executed
  them. **Interpretation:** regions, functions and branches are merged the
  same way, keyed by their exact source span (the source is the same in
  every run; a span compiled only under some features is counted once);
  a function is identified by the span of its first region. Per-job HTML
  reports are kept as artefacts.
- **T-COV-3:** the list of `unsafe` blocks comes from T-ENG-2's own scanner:
  new `tests/eng.rs` test `t_cov_3_unsafe_blocks_listed` (with the
  self-test `selftest_unsafe_uses`) classifies every `unsafe` token on the
  same stripped lines as a block (extent by brace matching) or a
  declaration, fails on anything else, and with `PWV_UNSAFE_BLOCKS=<path>`
  writes `file, first, last` per block. 23 blocks today. A block is
  "fully covered" if every code region starting in it and every
  instrumented line in it ran; blocks inside `#[cfg(miri)]` items are
  listed as excluded.
- **Gates:** T-COV-1 (lines ≥ 95 % in `format`, `crypto`, `gen`, `store`,
  `vault`; ≥ 85 % overall), T-COV-2 (every function of those five, unless
  listed below), every uncovered line of the five listed with
  "justified: yes/no" (an unjustified one fails), T-COV-3, T-COV-4
  (no file more than 0.5 pp below `coverage/baseline.json` in lines or
  regions; branches too once the baseline has them, T-COV-5).
  **"Module" = source file** (the five gated modules are one file each).
- **First run: `coverage-report` will fail, by design.** There is no
  baseline yet (no local `llvm-tools`), and the uncovered lines are not
  yet known, let alone justified. The job uploads
  `baseline-candidate.json`; after the owner reports the figures, the
  next round commits `coverage/baseline.json` (a deliberate commit with a
  dated entry, as T-COV-4 requires), adds tests for uncovered lines or
  lists them under "Coverage exceptions" below.
- **Report:** job summary with the five items of 14.13 (tables per
  Section 3 group and file, T-COV-3 list, uncovered lines, toolchains and
  seeds, every test ID with milestone and status). Test-ID statuses come
  from `test`'s and `e2e`'s kept logs plus the coverage runs' logs, and,
  for evidence that is a job, from that job's result (`toJSON(needs)`);
  a job skipped in the run (nightly-only, on a push) counts as not run.
  `test_ids.py` gained `verdicts()` (used by `--logs` and the report) and a
  4-field test evidence `("test", file, name, job)` for tests that act
  only in one job (T-STORE-8, T-PERF-1: elsewhere they return at once, so
  their `ok` lines prove nothing).
- **Badges:** `coverage.svg` (overall line coverage) and `test-ids.svg`
  (IDs passing out of 81), rendered by the report script, pushed by
  `coverage-report` to an orphan `badges` branch only on pushes to `main`
  (checkout with `persist-credentials: false`; the token is used in that
  one step). `coverage-report` is the only job with `contents: write`. On a
  push run the nightly gates count as not run, so the test-ID badge shows
  fewer than 81 there.
- **Branch coverage (T-COV-5):** `coverage-branch`, nightly, the same five
  runs on nightly with `--branch`; the report adds a branch column and
  records the nightly version in the seeds/toolchain list.
- Local checks: report self-test (parsers, exception table, badge) and an
  end-to-end run on synthetic data (two half-covered runs merge to 100 %,
  a planted uncovered line is listed as unjustified, a planted test
  failure shows as `fail`, a baseline 0.6 pp above fails T-COV-4 and one
  0.4 pp above passes). **Not run locally:** cargo-llvm-cov itself
  (no `llvm-tools` in the sandbox).

### T-MUT-1 (weekly workflow `mutants.yml`)

- Separate workflow (weekly cron, and "Run workflow"), so its schedule
  cannot trigger `ci.yml`'s nightly jobs. 13 jobs: `format` 3 shards,
  `crypto` 1, `gen` 2, `store` 3, `vault` 4 (`--shard k/n`, 0-based).
- `scripts/mutants.sh` (owner decision 6): **pass 1** this shard's mutants
  of `src/<module>.rs` against `--lib` plus the module's own test files
  (`format`: format, format_alloc; `crypto`: crypto, kdf_region; others:
  their file), default features, the two kill loops skipped. **Pass 2**:
  every survivor (missed or timed out) against the full suite, default
  features. **Pass 3**: those still missed against the full suite with
  `memtest,testkdf`. Passes 2 and 3 re-run exactly the survivors: every
  other mutant of the file is written to `previously_caught.txt` and
  `--iterate` skips it (cargo-mutants 27.1.0 book, "iterate"). What
  survives pass 3 must be justified below ("Surviving mutants"; checked by
  `scripts/mutants_check.py`).
- **Interpretations (rule 10):** a mutant that times out in pass 3 counts
  as caught (it hangs the suite, which any run notices). `--cap-lints true`
  so that the crate's `deny` lints do not make mutants unviable.
  Feature-gated code: `memtest`-only code is judged by pass 3; `testkdf`
  constants by pass 3 (the production ones by passes 1 and 2). There is no
  `cfg(miri)` code in the five modules, so nothing is excluded for that.
- `store` jobs mount LazyFS, so T-STORE-8 runs in passes 2 and 3: the M4
  note expects the temp-file `fsync` mutant to be killable only by a power
  loss. Directory `fsync` mutants may still survive: LazyFS passes
  metadata operations (rename, link) straight through, so it cannot lose
  a rename. To be judged when the first run reports.
- **Local trial** (2026-11-17, `crypto`, shard 0/4, pass 1 only): 9
  mutants in 6 min (baseline 5 s build + 82 s tests): 5 caught, 3
  unviable, 1 missed: `src/crypto.rs:197:69: replace == with != in
  argon2_in_region`, which is inside `#[cfg(feature = "memtest")]`
  (compiled out in pass 1; T-MEM-7's memtest test should catch it in
  pass 3). This is the case the full-suite passes exist for.
- Trap found: cargo-mutants builds its copy of the tree in the shared
  target directory, after which cargo considered an old test binary of
  the real tree fresh (it ran tests from before an edit). `touch` of the
  sources fixed it. Locally only; CI jobs are fresh.
- README "Releasing": a tag needs a green `mutants.yml` run on the commit.

### T-STORE-8 (LazyFS, nightly `durability`)

- `scripts/lazyfs.sh` clones github.com/dsrhaslab/lazyfs (ref
  `LAZYFS_REF`; empty = default branch, and the job prints the commit:
  **pin it after the first green run**), builds `libs/libpcache` and
  `lazyfs`, copies LazyFS's own `config/default.toml` changing only
  `fifo_path`, and mounts with its `scripts/mount-lazyfs.sh` (needs
  `user_allow_other`). Written without access to the repository (the
  sandbox cannot reach GitHub): its layout and commands are from my
  knowledge of LazyFS and are **unverified** until CI runs it.
- `tests/store.rs`: T-STORE-3's loop is now `kill_loop(fixture, id,
  lazy)` (rule 2: T-STORE-3's assertions and defaults are unchanged; its
  environment variables keep their names). New
  `t_store_8_kill_loop_with_power_loss`: the vault and state live on the
  mount, and after every SIGKILL the test sends `lazyfs::clear-cache`
  (unsynced data dropped: a power loss) before T-STORE-3's checks (opens;
  generation is the last reported commit or one more; content matches;
  fresh; backups decrypt to their generations; no temp files).
- Non-vacuity and synchronisation: before each command a probe file is
  written without `fsync`; after the command it must lose its data
  (within 60 s), which shows the clear took effect and that the mount
  really drops unsynced data. An optional `PWV_LAZYFS_DONE` FIFO is
  supported but not used (unsure which commands LazyFS confirms).
- `store` refuses FUSE mounts: the test checks that refusal first, then
  uses the `--allow-foreign-fs` override (`Store::open(.., true)`), which
  waives only the `statfs` check; owner and mode are still enforced. The
  child gets `PWV_T_FOREIGN=1`. `PWV_REQUIRE_LAZYFS` makes a missing mount
  a failure in CI. 5,000 iterations nightly; provisional cap 60.

### T-PERF-1 (`tests/perf.rs`, nightly `perf`)

- Owner decision 4. Three tests, active only with `PWV_PERF=1` (release,
  one test thread): unlock at the default parameters (Argon2id 256 MiB,
  t = 3, then unwrap and decrypt), median of 5, ≤ 3 s; a save of 1,000
  entries on tmpfs (serialise, encrypt, `Store::save` with its
  `fsync`s, renames, backups and state file; the directory must be tmpfs,
  checked by `statfs`; CI uses `/dev/shm`), median of 11, ≤ 50 ms; the
  allocator overhead, ≤ 5 %.
- **Allocator benchmark, in process:** the test crate's global allocator
  is a switch that frees through T-MEM-6's verifying `ZeroizingAlloc`
  by default, and during the benchmark through `System` or
  `ZeroizingAlloc::new(false)` (what `main.rs` installs). Every mode
  allocates from and frees to `System`, so a block may change mode
  between allocation and free. T-MEM-6 holds for this crate outside the
  benchmark (and `tests/eng.rs`'s check still finds the verifying
  allocator). Workload: a 1,000-entry model built as owned strings,
  serialised, encrypted, decrypted, parsed back and compared, 200 times
  per run (about 0.3 s); System and zeroizing alternate, 9 runs each,
  medians compared. **Interpretation:** the spec's "on the test suite's
  wall time" is read as this representative workload (owner decision 4).
- Local results (release): unlock 0.285 s; save 0.39 ms; allocator
  overhead +0.18 %, −0.13 %, −0.02 % in three runs. With 20 iterations per
  run (31 ms) the overhead swung between −1 % and +4 %, so runs were made
  10x longer. In a debug build the overhead was 5.3 %: the gate is the
  release build, which the nightly job uses.

### `fuzz-long` and T-COV-6

- Nightly, 30 min per target, the `fuzz-smoke` limits and ASan options,
  seeded by the committed corpus and the previous night's corpus
  (`actions/cache` restore by prefix, saved under a per-run key), corpus
  kept as an artefact. Then `cargo fuzz coverage` over that corpus,
  `llvm-cov export`, and `scripts/fuzz_cov.py`: region coverage of
  `format.rs` and `vault.rs` (production regions) per target, compared with
  the previous night's figure from the cache; a drop of more than 2 pp is
  a warning, never a failure (report-only). Paths checked in cargo-fuzz
  0.13.2's source (`fuzz/coverage/<target>/coverage.profdata`; the binary
  is found with `find`).

### Documents, Section 13

- README: CI, coverage and test-ID badges (`<owner>` placeholders: the
  owner's GitHub name is not known to me), Install, the new checks, and a
  "Releasing" checklist. FORMAT.md: re-checked against Section 7 (all
  constraints present; the spec's size-leakage estimate added); both
  hexdumps checked byte by byte against `tests/vectors/v1-small.pwv` and
  `fuzz/corpus/fuzz_body/seed-sample`; status changed from "draft (M3)".
  THREAT_MODEL.md: Sections 2 and 18 compared mechanically with the spec:
  verbatim. SECURITY.md: unchanged until a release (supported versions).
- **Section 13, line by line:** `scripts/test_ids.py --matrix <spec>` reads
  the spec's Section 13 rows, expands the ID ranges (`T-FMT-1–4`,
  `T-FUZZ-\*`, `T-COV-1 – T-COV-5`), and lists for each row the tests and
  the CI job that checks each test by name; it fails on an unknown ID.
  All 34 rows resolve; every named test is now checked by name somewhere
  (`t_store_1_foreign_fs_real_mount` got a by-name loop in its vfat step;
  T-COV-3 joined `test`'s `--require` list). Which rows are *verified*
  is the coverage report's test-ID table on a nightly run; S7 (T-CLIP),
  S2 (T-MIG-2), S10 (T-MEM-4) were verified on CI in M7/M8; R1 needs
  T-STORE-8 and E4 needs T-MUT-1 and T-COV-1 .. T-COV-5 to pass.

### Unverified until CI runs (named so a failure is quick to place)

`actions/download-artifact@v6` and `actions/cache@v4` (tags assumed, not
checked from here), LazyFS's layout, mount script and fault command,
`cargo-llvm-cov` 0.9.1 on toolchain 1.99.1 (its README lists Rust
1.99–1.100 with LLVM 23 as supported), the instrumented suite under
`xvfb-run` and the real `gpg`, `cargo fuzz coverage` on this tree, and
every new job's runtime (all caps provisional).

### Local gate result (2026-11-17, round 2)

`cargo test --locked --no-fail-fast`: default 551 s, `memtest` 582 s,
release 132 s, `testkdf` 517 s, `memtest,testkdf` 576 s, all green
(T-STORE-3 passed in each); `--no-default-features` (`cli`, `e2e`, `clip`,
`mig`) 42 s, green. `test_ids.py --require` over the five logs: 24 IDs
(the 23 of round 1 plus T-COV-3), 0 problems; `--check --spec`: 81 IDs,
0 to do, every named test checked by name. fmt (crate, `fuzz/`), clippy
`-D warnings` in six configurations and on the fuzz crate, the six
`cfg(miri)` compile checks, `loc_budget.py` (4,478 / 4,800; `src/`
unchanged), `sh -n` on every script, both workflows parse (PyYAML).
T-PERF-1 locally in release: as above. **Instrumented suite** (local
stand-in for the coverage jobs, since `llvm-tools` is missing): a
`RUSTC_WRAPPER` adding `-C instrument-coverage` to the pwv crates; the full
default suite passed (495 s); `e2e`, `cli`, `mig`, `clip` passed with the
instrumented `pwv` binary and its children wrote 156 profiles; `mem`,
`harden`, `secmem`, `kdf_region` (memtest) passed too. So instrumentation
changes no test outcome here, and children write profiles.

### Coverage exceptions

Uncovered production lines and functions of `format`, `crypto`, `gen`,
`store`, `vault` that are justified (spec 14.13). Read by
`scripts/coverage_report.py`: one row per line or range,
`| src/<file>:<line>[-<line>] | line or function | date | reason |`.
Empty until the first coverage report.

| Location | Kind | Date | Reason |
| --- | --- | --- | --- |

### Surviving mutants

Mutants that survive the full suite (T-MUT-1), each with its exact
cargo-mutants name in backticks, the date, and the reason. Read by
`scripts/mutants_check.py`. Empty until the first weekly run.

| Mutant | Date | Reason |
| --- | --- | --- |
