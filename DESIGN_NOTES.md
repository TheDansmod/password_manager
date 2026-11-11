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
| `chacha20poly1305` | 0.11.0 | `zeroize` only (defaults off: no `alloc`, no `getrandom`) | `AeadInOut::encrypt_in_place_detached` / `decrypt_in_place_detached` present in `aead` 0.6.1 |
| `zeroize` | 1.9.1 | default | — |
| `getrandom` | 0.4.3 | default | — |
| `rustix` | 1.1.6 | `event fs mm param process stdio termios` | `mm::Advice::LinuxDontDump`, `LinuxWipeOnFork`; `process::set_dumpable_behavior`, `setrlimit`, `umask`; `fs::flock`, `fstatfs` present. `mlock` re-checked in M1 |
| `libc` | 0.2.191 | default | see below |
| `unicode-normalization` | 0.1.26 | default | — |
| `arboard` (feature `clipboard`) | 3.7.0 | `wayland-data-control` only (defaults off: no `image-data`) | `SetExtLinux::exclude_from_history` present (src/platform/linux/mod.rs:380) |
| `zxcvbn` (feature `strength`) | 3.1.1 | defaults off (no `derive_builder`) | — |

Dev-only (unconstrained by the budget): `expectrl` 0.9.0, `proptest` 1.12.0,
`rand_chacha` 0.10.0, `static_assertions` 1.1.0, `tempfile` 3.27.0.
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
  corpus-file check (file I/O under Miri isolation). The native run is
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

