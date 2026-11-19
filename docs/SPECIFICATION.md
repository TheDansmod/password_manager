# pwv: Rust Password Manager Specification

> **About this document.** This is the design specification pwv was built
> from, edited for contributors. Section numbers are unchanged, because code
> comments, tests and other documents cite them ("spec Section 9.3"). Two
> kinds of content were removed: the specification of a one-off importer
> for a predecessor program, which matters only to that program's users
> (Sections 12.1 and 12.3), and instructions addressed to the original
> implementer. Where [`DESIGN_NOTES.md`](DESIGN_NOTES.md) records a later
> decision or a deviation, that dated entry takes precedence over this
> text. Test IDs (`T-...`) are listed, with what proves each one, by
> `python3 -I scripts/test_ids.py --markdown`.

## 1. Purpose, scope, and S10 verdict

This document specifies `pwv`, a single-binary, Linux-first, terminal password manager in Rust. pwv was designed to replace a predecessor Python program, and it resolves every finding of a security audit of that program (identified as S1–S13, R1–R4, B1–B10 and E1–E6; Section 13 maps each to the design and its tests). The specification is meant to leave no design decision open; where one is left open, the section says so explicitly.

**Verdict on S10.** Rust makes S10 robustly solvable for the threats a userspace program can address, but not absolutely. Four properties make the difference relative to CPython:

1. **Deterministic destruction.** `Drop` runs at a known program point, so secret buffers are wiped exactly once and at a known time. There is no garbage collector that moves or duplicates objects.
2. **Allocation control.** Every secret byte can be confined to a single page-aligned, `mmap`-backed region that the program owns, rather than to immutable `str` objects scattered across the heap.
3. **Compiler-resistant erasure.** The `zeroize` crate uses volatile writes plus a compiler fence, so the wipe is not elided as a dead store.
4. **Direct syscall access.** `mlock`, `madvise(MADV_DONTDUMP | MADV_WIPEONFORK)`, `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)`, guard pages, and raw `read(2)`/`write(2)` on the terminal are all reachable without an interpreter in between.

The resulting guarantee is stated as a testable invariant:

> **Invariant M.** While the vault is unlocked, every byte of plaintext secret material that resides in this process's memory, and is not transiently held in CPU registers or a bounded stack frame, lies inside the locked secure arena. After lock or exit, no plaintext secret byte remains anywhere in the process's writable address space.

No userspace program in any language can protect against the following residual exposures. Section 18 enumerates them precisely:

- copies held by the kernel (TTY line-discipline buffers, pipe buffers);
- copies held by the terminal emulator, which displays revealed values and keeps them in scrollback;
- the X11 server or Wayland compositor, which holds the clipboard selection;
- the hibernation image, which includes `mlock`ed pages;
- a root or kernel adversary, and physical attacks such as cold boot or DMA.

**Scope (v1).** Linux on x86\_64 and aarch64, interactive terminal use, a single user, and a single local vault file. Windows and macOS are non-goals for v1. Platform-specific code is isolated in one module so that later ports touch nothing else.

## 2. Threat model and security goals

The design defends confidentiality and integrity of the vault against the adversaries A1–A5. Adversaries A6–A8 are explicitly out of scope. Every security test in Section 14 traces to one of these rows.

| ID | Adversary and capability | In scope | Required outcome |
| --- | --- | --- | --- |
| A1 | Offline attacker holding the vault file and all backups (stolen disk, cloud sync, Windows-side malware) | Yes | Cost of recovery bounded below by Argon2id over the master password; no information beyond padded size, KDF parameters, and generation counter |
| A2 | Attacker with write access to the vault directory (other local user, Windows side, sync client) | Yes | No code execution; tampering is detected (AEAD failure); rollback to an older valid file is detected and reported |
| A3 | Post-session forensic attacker reading swap, core dumps, crash reports, or the freed heap of the terminated process | Yes | Invariant M: no plaintext secret recoverable |
| A4 | Same-UID, non-root process that starts after unlock and tries to attach to or read the running process | Yes | `ptrace` attach and `/proc/<pid>/mem` reads refused (non-dumpable process) |
| A5 | Crash, power loss, `SIGKILL`, full disk during save | Yes | Vault is always the complete old state or the complete new state; never neither |
| A6 | Same-UID malware present before launch (`LD_PRELOAD`, modified binary, shell alias, keylogger, X11 clipboard sniffer) | No | Documented residual risk |
| A7 | Root, kernel, hypervisor, or firmware adversary | No | Documented residual risk |
| A8 | Physical attacks (cold boot, DMA, side channels) | No | Documented residual risk |

**Security goals**, each of which must be verified by at least one test:

- **G1 (confidentiality at rest).** The file reveals nothing about entries except an upper bound on total size. Plaintext is padded (Section 7).
- **G2 (integrity).** Any modification of any byte of the file causes open to fail with a single generic error. The header is authenticated as associated data.
- **G3 (freshness).** A file whose generation counter is lower than the last value recorded locally triggers a rollback warning that requires explicit acknowledgement.
- **G4 (memory hygiene).** Invariant M holds (Section 5).
- **G5 (durability).** Every committed change survives crash and power loss once the save call returns. Five prior versions are retained.
- **G6 (no unsafe parsing).** No input file is interpreted by any parser capable of executing code. All parsers are total functions that return an error and never panic, as established by fuzzing.
- **G7 (minimal exposure in the UI).** Secrets are never displayed unless explicitly requested, and clipboard copies expire.

## 3. Design principles, simplicity budget, dependency policy

Auditability is the primary engineering constraint: a reviewer must be able to read the entire production codebase in one sitting.

**Principles**

1. **One crate, one binary, no workspace.** It has a `lib` target (for tests and fuzzing) and a thin `main.rs`.
2. **No database, no serde, no TUI framework.** Persistence is one binary file in a hand-specified format, parsed by about 300 lines of strict code. The UI is line-oriented prompts.
3. **Whole-vault rewrite on every mutation.** Vaults are kilobytes, so O(n) rewrites are free. This removes the need for any partial-update, indexing, or journaling logic.
4. **Secrets never become `String` or `Vec<u8>`.** They live only in the secure arena (Section 5) and are passed as borrowed `&[u8]` slices.
5. **`unsafe` is quarantined.** The crate root sets `#![deny(unsafe_code)]`. Exactly three modules carry `#[allow(unsafe_code)]`: `sys`, `secmem`, and `alloc`. Every `unsafe` block has a `// SAFETY:` comment stating the invariant it relies on.
6. **Fail closed.** Any check that cannot be performed (for example, `mlock` failing) is reported, and the program refuses to proceed unless the user passes an explicit, documented override flag.
7. **One error message per failure class.** Errors never contain secret bytes, entry names, or file contents.

**Simplicity budget (hard limits for production code, excluding tests, fuzz targets, and comments)**

| Module group | Target LOC | Hard cap |
| --- | --- | --- |
| `sys` + `secmem` + `alloc` (all `unsafe`) | 400 | 800 |
| `crypto` + `format` | 450 | 750 |
| `store` (atomic write, lock, backups, state) | 250 | 450 |
| `vault` (model operations) | 250 | 500 |
| `gen` | 150 | 300 |
| `term` + `clip` | 300 | 350 |
| `cli` + `main` | 400 | 1,700 |
| **Total** | **2,200** | **4,800** |

If a change exceeds a hard cap, simplify before proceeding, or record a written justification in `DESIGN_NOTES.md`.

**Dependency policy.** Runtime dependencies are limited to the list below. Each additional crate requires a justification line in `DESIGN_NOTES.md` and must pass `cargo deny`. Pin exact versions in `Cargo.lock` and verify APIs against the pinned version at implementation time.

| Crate | Purpose | Notes |
| --- | --- | --- |
| `argon2` (RustCrypto), features `zeroize` | KDF | Use `hash_password_into_with_memory` with arena-owned blocks; the allocating `hash_password_into` leaves derived blocks in an unwiped `Vec` |
| `chacha20poly1305` (RustCrypto) | AEAD | `XChaCha20Poly1305`; in-place `encrypt_in_place_detached` and `decrypt_in_place_detached` only |
| `zeroize` | Wiping | Volatile writes plus compiler fence |
| `getrandom` | OS CSPRNG | `getrandom(2)`; no userspace RNG state to leak |
| `rustix` (or `libc` if a call is missing) | Syscalls | `mmap`, `mprotect`, `mlock`, `madvise`, `prctl`, `setrlimit`, `termios`, `poll`, `flock`, `fsync`, `statfs` |
| `unicode-normalization` | NFC normalisation of the master password | Per RFC 8265 |
| `arboard`, features `wayland-data-control` (optional cargo feature `clipboard`, default on) | Clipboard | Use `SetExtLinux::exclude_from_history()` |

No argument-parsing crate: the command grammar in Section 9 is small enough to parse by hand. Dev-only dependencies (`proptest`, `rand_chacha`, `tempfile`, `expectrl`, `libfuzzer-sys`) are unconstrained by this budget.

## 4. Architecture

The program is a strict layering of twelve small modules with no dependency cycles. The two parsing-and-crypto modules, `format` and `crypto`, are pure: they perform no I/O and are therefore directly fuzzable.

**Module responsibilities**

| Module | Responsibility | Pure | `unsafe` |
| --- | --- | --- | --- |
| `main.rs` | Calls `sys::harden()` before any other code; installs the global allocator; parses arguments; dispatches | No | No |
| `cli` | Command grammar, REPL loop, idle timeout, confirmation prompts, rendering of entries | No | No |
| `term` | Raw `read(2)` and `write(2)` on fds 0 and 1, echo control via `termios`, `poll`-based idle timeout, control-character sanitisation, screen and scrollback clearing | No | No |
| `clip` | Copy with expiry, clear-if-unchanged, clear at exit | No | No |
| `vault` | In-memory model: an index over the decrypted plaintext held in the arena; all entry operations and their validation | Yes | No |
| `format` | Byte-level encode and decode of the header and the plaintext body; canonical form; padding | Yes | No |
| `crypto` | Argon2id into arena-owned memory; XChaCha20-Poly1305 seal and open in place; key wrapping | Yes | No |
| `gen` | Password and passphrase generation, entropy computation, embedded word list | Yes (RNG injected) | No |
| `store` | Path resolution, permission checks, `flock`, atomic write, backup rotation, rollback-state file | No | No |
| `secmem` | `SecureArena` and `SecretBuf`: locked, guarded, non-dumpable memory | — | Yes |
| `alloc` | Zeroizing global allocator (defence in depth) | — | Yes |
| `sys` | Process hardening and thin syscall wrappers; the only module that names `rustix` or `libc` | — | Yes |

**Layering rule.** A module may depend only on modules below it in this order: `cli` → `clip`, `term`, `store`, `vault`, `gen` → `format`, `crypto` → `secmem` → `sys`. `alloc` is independent. The rule is enforced by a test that greps `use crate::` statements (Section 14, T-ENG-3).

```text
cli
clip  term  store  vault  gen
format  crypto
secmem
sys
(alloc: independent)
```

Dependencies run only downward. `secmem` is the single destination for secret bytes, and only the bottom band may contain `unsafe` code.

**Data flow on unlock**

1. `term` reads the master password with echo disabled, by raw `read(2)` directly into an arena slot.
2. `store` acquires the lock, checks permissions, and reads the file into an ordinary `Vec<u8>`. Ciphertext is not secret.
3. `format` parses and bounds-checks the header.
4. `crypto` NFC-normalises the password into a second arena slot, then runs Argon2id. The Argon2 working memory is an arena-external locked region where possible (Section 5.4). The result is the KEK, which is written into the arena.
5. `crypto` unwraps the DEK into the arena, then wipes the KEK and both password slots.
6. The payload ciphertext is copied into the arena and decrypted in place.
7. `format` validates the canonical plaintext, and `vault` builds an index of offsets into it.

**Data flow on save**

1. `vault` serialises the new canonical plaintext into the arena's scratch half and pads it.
2. `crypto` encrypts it in place there, so plaintext never exists outside the arena.
3. The resulting ciphertext is copied into a heap `Vec`, and the scratch half becomes the live half. The previous live half is zeroised.
4. `store` performs the atomic write and the backup rotation, then updates the rollback-state file.

**Repository layout**

```
pwv/
  Cargo.toml, Cargo.lock, rust-toolchain.toml, deny.toml, clippy.toml
  README.md, CONTRIBUTING.md, SECURITY.md, LICENSE
  docs/    SPECIFICATION.md, FORMAT.md, THREAT_MODEL.md, DESIGN_NOTES.md,
           DEVELOPMENT.md
  src/  main.rs lib.rs cli.rs term.rs clip.rs vault.rs format.rs
        crypto.rs gen.rs store.rs secmem.rs alloc.rs sys.rs
        wordlist.txt   (205,690-word list, MIT licence, embedded with include_str!)
  tests/   integration, PTY end-to-end, memory-canary, crash-consistency
  tests/vectors/   golden vault files, KAT vectors
  fuzz/    cargo-fuzz targets and seed corpora
  scripts/ CI helpers (coverage report, test-ID inventory, LOC budget,
           release build, mutation testing, version bump)
  coverage/baseline.json   coverage no module may fall below (Section 14.13)
  tools/   project-specific import tool for the predecessor program
           (not part of the binary; Section 12)
  .github/ workflows, pull-request and issue templates, CODEOWNERS
```

## 5. Secure memory subsystem (S10)

Invariant M is achieved by four layers: process hardening, a single locked arena that holds every secret, a zeroizing global allocator for incidental copies, and a ban on standard-library stdio. Each layer is independently tested (Section 14, T-MEM).

### 5.1 Process hardening (`sys::harden`, first statement of `main`)

These steps execute in this order, before argument parsing and before any allocation that could hold user input. Failure of any step except step 6 aborts the program.

1. `setrlimit(RLIMIT_CORE, {0, 0})`. This disables file core dumps and lowers the hard limit irreversibly.
2. `prctl(PR_SET_DUMPABLE, 0)`. With the default `fs.suid_dumpable = 0`, this suppresses core dumps entirely, including those collected through a piped `core_pattern` (for example `systemd-coredump`). It also blocks `ptrace` attach and `/proc/<pid>/mem` access by same-UID, non-root processes (adversary A4).
3. `umask(0o077)`, so every file the process creates is private by construction.
4. Verify that fd 1 is a TTY (`isatty`), and fd 0 too, except that `import --from-stdin` reads fd 0 from a pipe (Section 12.2). Refuse otherwise, to prevent accidental piping of secrets into logs. Tests use a PTY.
5. Install a panic hook that writes one fixed string (`"internal error"`) by raw `write(2)` to fd 2 and never formats the panic payload. Use `panic = "unwind"` so that `Drop`, and therefore zeroisation, runs during unwinding.
6. Read `RLIMIT_MEMLOCK`. If the soft limit is below the hard limit, raise the soft limit to the hard limit. Record the effective value for Sections 5.2 and 5.4.

### 5.2 `SecureArena`: the single home of all secrets

One anonymous private mapping is created at startup with the layout `[guard page | data region | guard page]`.

- **Guard pages** are `PROT_NONE`, so a linear overflow or underflow faults instead of reading neighbouring memory.
- **Data region** is `PROT_READ | PROT_WRITE`, `mlock`ed, and marked `madvise(MADV_DONTDUMP)` and `madvise(MADV_WIPEONFORK)`. Default size is 1 MiB (`--arena-size`, range 256 KiB to 6 MiB). The upper bound keeps the arena below the 8 MiB default `RLIMIT_MEMLOCK` that Linux has used since 5.16, with headroom.
- If `mlock` fails, the program refuses to unlock. The override is `--allow-unlocked-memory`, which prints a persistent warning in the prompt.

The data region is partitioned once into **fixed, named slots**. There is no general-purpose allocator inside the arena; this is a deliberate simplification.

| Slot | Size | Contents |
| --- | --- | --- |
| `Input` | 4 KiB | Raw bytes of any line typed by the user (commands, field values, passwords) |
| `Pw1`, `Pw2` | 1 KiB each | Master password entry and confirmation; NFC-normalised copy |
| `Kek`, `Dek`, `NewDek` | 32 B each | Key material |
| `Gen` | 1 KiB | Freshly generated password or passphrase |
| `Clip` | 1 KiB | The value currently on the clipboard, for clear-if-unchanged comparison |
| `VaultA`, `VaultB` | (data − above) / 2 each | Live and scratch copies of the canonical plaintext body (double buffer) |

**Type contract** (Rust-level, enforced by the compiler):

- `SecureArena` is `!Send`, `!Sync`, and not `Clone`. Its `Drop` runs `zeroize` over the full data region, then `munlock`, then `munmap`.
- `SecretSlot<'a>` is a `&'a mut` view of one slot plus a current length. Borrowing rules make concurrent aliasing of a slot impossible. Its `Drop` zeroizes the used prefix. `clear()` zeroizes eagerly.
- Neither type implements `Clone`, `Copy`, `Display`, `Serialize`, or a `Deref` to `[u8]`. `Debug` prints `[REDACTED; n bytes]`. Access is only through `expose(&self) -> &[u8]` and `expose_mut(&mut self) -> &mut [u8]`, so every read site is greppable.
- Comparisons of secret values use `subtle::ConstantTimeEq`, or a small hand-written constant-time loop if adding `subtle` would breach the dependency budget.

**Vault body capacity.** `VaultA` and `VaultB` bound the maximum plaintext. At the default 1 MiB this is about 500 KiB, which corresponds to roughly 3,000 typical entries. Exceeding it is a clean, reported error on save, never a reallocation.

### 5.3 Zeroizing global allocator (`alloc`)

This is a `#[global_allocator]` wrapper around `std::alloc::System`. It provides defence in depth for copies made by dependencies, for example `arboard`'s internal buffers or `unicode-normalization`'s iterator state.

- `dealloc`: `zeroize` the full `layout.size()` bytes, then free.
- `realloc`: allocate a new block, copy, `zeroize` the old block, then free it. Never grow in place, so no stale prefix survives a move.
- `alloc_zeroed` is delegated unchanged.

Limitation: this layer does not cover allocations that are never freed, such as `std`'s global stdout `LineWriter`. Section 5.5 removes that path entirely. The measured overhead is negligible at this program's allocation volume; T-PERF-1 confirms it.

### 5.4 Argon2 working memory

Argon2id memory is password-derived. Its first block is B\[0\]\[0\] = H′(H₀ ‖ 0 ‖ 0), where H₀ hashes the password and the salt. An adversary who recovers any early block from swap can therefore test candidate passwords at the cost of about two BLAKE2b evaluations instead of m·t block operations. That is a speed-up of about 7.9 × 10⁵ at m = 2¹⁸ KiB and t = 3, which effectively removes the KDF.

Therefore:

1. Allocate the blocks in a dedicated `mmap` region (`KdfRegion`, guard pages, `MADV_DONTDUMP`) and pass them to `Argon2::hash_password_into_with_memory`. Never use `hash_password_into`, which allocates an ordinary `Vec` and frees it unwiped.
2. Attempt to `mlock` the region. On success, proceed silently.
3. On failure, typically because a 256 MiB region exceeds the 8 MiB default limit, proceed but print a single notice per unlock. The notice names the effective `RLIMIT_MEMLOCK` and the remedy: encrypted swap, or a raised limit via `/etc/security/limits.d/` or `LimitMEMLOCK=` in a systemd user unit. `--require-locked-kdf` turns this case into a refusal.
4. `zeroize` the region immediately after derivation, then `munmap` it. The exposure window equals the derivation time, which is about 1 s.

### 5.5 Prohibition of standard stdio

`std::io::Stdin` and `std::io::Stdout` keep process-lifetime heap buffers that are never freed, so neither the arena nor the allocator can clean them. All terminal I/O therefore goes through `term`, which uses raw `read(2)` and `write(2)` on fds 0 and 1:

- input goes directly into the `Input` slot;
- output that contains a secret is written from the slot itself, without an intermediate buffer.

`clippy.toml` bans the following everywhere except `term.rs`: `std::io::stdin`, `std::io::stdout`, `std::io::stderr`, `print!`, `println!`, `eprint!`, `eprintln!`, and `dbg!`.

### 5.6 Stack and register residue (best effort)

Secrets pass transiently through registers and stack frames inside the cipher and KDF implementations, and Rust cannot guarantee their erasure. Mitigation is limited to two measures:

- After unlock, after each save, and before exit, call `sys::scrub_stack()`. This is an `#[inline(never)]` function that `zeroize`s a 64 KiB local array and passes it through `core::hint::black_box`.
- The program is single-threaded, so no other thread's stack can retain secrets. `arboard`'s internal X11 server thread receives only the clipboard value, and Section 11 governs it.

### 5.7 No child processes

The program never `fork`s or `exec`s: no editor, no pager, no `xclip` or `wl-copy`. `MADV_WIPEONFORK` exists only as defence in depth against future regressions. T-ENG-4 enforces the absence of `std::process::Command` by lint.

### 5.8 Test-only introspection (cargo feature `memtest`)

Verification of Invariant M (T-MEM-4) requires reading the process's memory from a test harness. The feature `memtest` therefore does the following:

- it skips `PR_SET_DUMPABLE`, so the harness, as parent under Yama `ptrace_scope = 1`, may read `/proc/<pid>/mem`;
- it prints the arena's address range to fd 2 at startup;
- it adds a `__pause` REPL command that blocks until the harness signals;
- it adds a `__panic` command that panics, so that tests reach the unwinding path (clipboard cleared, exit code 5);
- with `PWV_MEMTEST_EXIT_PAUSE` set, it pauses after the wipe, before exit, for a last scan.

The feature is excluded from release builds, and CI fails if a release binary contains the marker string `PWV_MEMTEST`.

## 6. Cryptographic design and key hierarchy

A password-derived key-encryption key (KEK) wraps a random data-encryption key (DEK), and the DEK encrypts the body. Both layers use XChaCha20-Poly1305, with the file header bound as associated data.

### 6.1 Primitives

| Role | Primitive | Parameters |
| --- | --- | --- |
| Password hashing / KEK derivation | Argon2id, version 0x13 | Default m = 262,144 KiB (256 MiB), t = 3, p = 1, 32-byte output, 32-byte salt from `getrandom` |
| AEAD (wrap and body) | XChaCha20-Poly1305 | 256-bit key, 192-bit random nonce, 128-bit tag |
| Randomness | `getrandom(2)` | Used for salt, DEK, nonces, vault ID, generated passwords |
| Password normalisation | Unicode NFC (RFC 8265 OpaqueString) | Then UTF-8 encoding |

**Why XChaCha20-Poly1305.** Its 192-bit nonces may be drawn at random without state. After q saves under one DEK, the collision probability is at most q(q − 1)/2¹⁹³. That is below 2⁻¹⁵³ even for q = 2²⁰. It is also constant-time in software, independent of AES-NI.

**Key commitment** was considered and rejected for v1. Poly1305 does not commit to the key, but the attacks that exploit this require several recipients or keys. A single-user vault has exactly one valid key per file.

### 6.2 Key hierarchy

```latex
\begin{aligned}
P' &= \mathrm{UTF8}(\mathrm{NFC}(P)) \\
\mathrm{KEK} &= \mathrm{Argon2id}(P',\ \mathit{salt};\ m, t, p=1,\ \ell=32) \\
W &= \mathrm{XChaCha20Poly1305.Seal}(\mathrm{KEK},\ n_w,\ \mathrm{DEK},\ \mathit{AAD}_w = \mathit{hdr}[0..76)) \\
C &= \mathrm{XChaCha20Poly1305.Seal}(\mathrm{DEK},\ n_p,\ \mathrm{pad}(\mathit{body}),\ \mathit{AAD}_p = \mathit{hdr}[0..184))
\end{aligned}
```

- `AAD_w` covers the magic, version, flags, vault ID, KDF identifier and parameters, and salt. Tampering with the KDF parameters therefore makes unwrap fail rather than silently deriving a different key.
- `AAD_p` additionally covers the wrapped DEK, the generation counter, the payload nonce, and the payload length.
- The generation counter lies outside `AAD_w`. A save therefore does not need the KEK, and the KEK is wiped immediately after unlock.

### 6.3 Lifecycle rules

- **init.** Generate the salt, DEK, and vault ID; derive the KEK; wrap; write generation 1.
- **unlock.** Derive the KEK, unwrap the DEK, wipe the KEK and the password, then decrypt. A tag failure at either layer produces exactly one message, "wrong password or damaged vault". This prevents an oracle that distinguishes the two cases.
- **save.** Fresh `n_p` from `getrandom`; generation incremented by 1 with overflow checked; `W` and `n_w` unchanged.
- **passwd.** Fresh salt, fresh DEK, fresh `n_w` and `n_p`, with optionally new KDF parameters, then a full re-encryption. Rotating the DEK is mandatory. Otherwise an attacker holding an old file plus the old password could unwrap the unchanged DEK and decrypt every future file.

### 6.4 Parameter policy

- **Accepted on read:** m ∈ \[65,536, 4,194,304\] KiB (64 MiB to 4 GiB), t ∈ \[1, 20\], p = 1, salt length 32. Out-of-range values are rejected before any allocation, which defeats denial of service through a crafted header.
- **Written:** never below m = 65,536 KiB and t = 3. Configurable via `init` or `passwd` with `--kdf-memory <MiB>` and `--kdf-time <t>`.
- **Test builds only:** the cargo feature `testkdf` lowers the read floor to 8 KiB so that tests run fast. CI verifies that release artefacts are built without it.

### 6.5 Master-password policy and cost model

Let H be the min-entropy of the master password in bits. Let r be the attacker's Argon2id throughput per device and G the number of devices. The expected exhaustive-search time is

```latex
\mathbb{E}[T] = \frac{2^{H-1}}{r \cdot G}, \qquad r \lesssim \frac{\lfloor M_{\mathrm{dev}} / m \rfloor}{\tau_{\mathrm{dev}}}
```

Here M\_dev is device memory and τ\_dev is one evaluation's latency on that device. Memory-hardness caps parallelism at M\_dev / m. With m = 256 MiB, a 24 GiB accelerator runs at most 96 evaluations concurrently.

**Policy.** `init` and `passwd` offer a generated 6-word passphrase as the default choice. That gives H = 6 log₂ 205,690 ≈ 105.9 bits.

A user-chosen password must have at least 16 characters and an estimate of at least 10¹⁴ guesses. The estimate is computed by `pwv` itself, in place in the arena, so the password never reaches the heap; no strength library is used. It penalises repeated runs, sequences, keyboard walks (rows, columns, and diagonals, shifted digits included), words of the embedded list and a few common roots it lacks (also in "leet" spelling), years 1900–2099, and common or repeated separators between words. Below either limit, the password is rejected, unless the user passes `--accept-weak-password` and types a confirmation sentence. A user who declines the generated passphrase is warned that a chosen password is usually weaker.

The password must be entered twice; the two entries are compared in constant time inside the arena.

## 7. Vault file format (normative; mirrored in `FORMAT.md`)

The file is a fixed 184-byte header, the body ciphertext, and a 16-byte tag. All integers are little-endian, and every parse is strict: any deviation is a hard error, and no field is ever ignored.

### 7.1 Header

| Offset | Size | Field | Constraint |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | ASCII `PWVAULT` followed by 0x00 |
| 8 | 2 | `format_version` | = 1 |
| 10 | 2 | `flags` | = 0 (reserved) |
| 12 | 16 | `vault_id` | Random at init; never changes, including across `passwd` |
| 28 | 1 | `kdf_id` | = 1 (Argon2id v0x13) |
| 29 | 3 | reserved | = 0 |
| 32 | 4 | `kdf_m_kib` | Bounds in Section 6.4 |
| 36 | 4 | `kdf_t` | Bounds in Section 6.4 |
| 40 | 4 | `kdf_p` | = 1 |
| 44 | 32 | `salt` | Random |
| 76 | 24 | `wrap_nonce` | Random |
| 100 | 48 | `wrapped_dek` | 32-byte ciphertext and 16-byte tag; AAD = bytes \[0, 76) |
| 148 | 8 | `generation` | ≥ 1; incremented by 1 per save |
| 156 | 24 | `payload_nonce` | Random, fresh per save |
| 180 | 4 | `payload_len` L | L ≥ 4096, L ≡ 0 (mod 4096), L ≤ 16 MiB |
| 184 | L | `payload_ct` | AAD = bytes \[0, 184) |
| 184 + L | 16 | `payload_tag` | — |

The file length must equal exactly 200 + L. The reader checks the length against the file size before allocating, and reads at most 200 + 16 MiB.

### 7.2 Body (plaintext, after decryption)

| Offset | Size | Field | Constraint |
| --- | --- | --- | --- |
| 0 | 4 | `body_magic` | ASCII `PWVB` |
| 4 | 4 | `content_len` C | 12 + C ≤ L |
| 8 | 4 | `entry_count` N | N ≤ 10,000 |
| 12 | C | entries | N consecutive entry records, consuming exactly C bytes |
| 12 + C | L − 12 − C | padding | All bytes = 0x00 |

**Entry record**

| Field | Size | Constraint |
| --- | --- | --- |
| `name_len` | u16 | 1 – 256 |
| `name` | `name_len` | UTF-8; no C0, DEL, or C1 controls; no leading or trailing whitespace |
| `field_count` | u16 | 0 – 64 |
| then `field_count` field records |  |  |

**Field record**

| Field | Size | Constraint |
| --- | --- | --- |
| `key_len` | u8 | 1 – 64 |
| `key` | `key_len` | UTF-8; no controls; unique within its entry under ASCII case-folding |
| `flags` | u8 | bit 0 = sensitive; bits 1–7 = 0 |
| `value_len` | u16 | 0 – 4,096 |
| `value` | `value_len` | UTF-8; no controls except LF (0x0A) |

### 7.3 Canonical form

The canonical form requires three things:

- entries appear in strictly increasing byte-lexicographic order of `name`, which implies names are unique;
- fields appear in user insertion order, which is meaningful to the user and is preserved;
- padding is minimal, so L = 4096 · ⌈(12 + C) / 4096⌉.

The parser rejects every non-canonical input. Consequently, `parse` and `serialize` are mutual inverses on valid inputs:

```latex
\forall b:\ \mathrm{parse}(b) = \mathsf{Ok}(x) \implies \mathrm{serialize}(x) = b, \qquad \forall x \in \mathcal{V}:\ \mathrm{parse}(\mathrm{serialize}(x)) = \mathsf{Ok}(x)
```

Here 𝒱 is the set of models satisfying the constraints above. These two identities are the core property tests of T-FMT.

**Size leakage.** An observer learns only ⌈(12 + C)/4096⌉, which is roughly the number of entries to within about 30–60.

### 7.4 Versioning

Any change to these tables increments `format_version`. A version-N binary reads every version ≤ N through frozen per-version parsers and always writes version N. Each version has committed golden vectors (T-COMPAT) that must decrypt forever.

## 8. Persistence

Every mutation is saved immediately with a write-to-temp, `fsync`, rename, `fsync`-directory protocol. As a result, the vault on disk is always a complete, authenticated version: old or new, never partial.

### 8.1 Locations

| File | Default path | Mode |
| --- | --- | --- |
| Vault directory | `$XDG_DATA_HOME/pwv/`, falling back to `~/.local/share/pwv/` | 0700 |
| Vault | `<dir>/vault.pwv` | 0600 |
| Lock file | `<dir>/vault.pwv.lock` | 0600 |
| Backups | `<dir>/vault.pwv.1` … `vault.pwv.5` (`.1` newest) | 0600 |
| Rollback state | `$XDG_STATE_HOME/pwv/state`, falling back to `~/.local/state/pwv/state` | 0600 |

Overrides are `--vault <path>` and the environment variable `PWV_VAULT`. No other paths are hard-coded (E2).

### 8.2 Open-time checks (fail closed)

1. `lstat` the directory and the vault. Each must be owned by the effective UID; the directory must be a directory and the vault a regular file, never a symlink. Open with `O_NOFOLLOW | O_CLOEXEC`.
2. `mode & 0o077 == 0` for both. A violation produces an exact `chmod` remedy in the error message.
3. `statfs`: refuse filesystems whose permission bits are synthetic, namely `fuseblk` (ntfs-3g), `ntfs3`, `vfat`, `exfat`, and `msdos`, `9p`. Override with `--allow-foreign-fs`. This closes S8: a vault on the Windows partition is refused by default.
4. `flock(LOCK_EX | LOCK_NB)` on the lock file for the whole session. If the lock is held, report "vault is open in another session" and exit (R3).
5. Remove any stale `.vault.pwv.tmp.*` files left by an interrupted save. They are ciphertext, so removal is hygiene only.
6. Read the file. Size cap: 200 bytes + 16 MiB.

### 8.3 Save protocol

1. Produce the new file bytes in memory (Section 4).
2. **Rotate backups.** Rename `.4` → `.5`, `.3` → `.4`, `.2` → `.3`, and `.1` → `.2`. Then `link(vault.pwv, vault.pwv.1)`. If hard links are unsupported, fall back to copy and `fsync`.
3. Create `.vault.pwv.tmp.<16 hex>` with `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC`, mode 0600. Write all bytes, then `fsync` the file.
4. `renameat` the temporary file over `vault.pwv`. This step is atomic.
5. `fsync` the directory file descriptor.
6. Update the rollback-state file by the same protocol (temp, `fsync`, rename, `fsync` its directory).
7. Only now report success to the UI.

**Crash-state analysis**, which T-STORE-2 verifies at each point:

| Interrupted during | `vault.pwv` on restart | Recovery action |
| --- | --- | --- |
| Steps 1–2 | Old version; backups shifted | None |
| Step 3 | Old version; partial or unsynced temp file | Temp file removed at next open |
| Step 4 | Old or new (atomic) | None |
| Step 5 | Old or new after power loss | None; at worst the last change is lost, and it was never reported as saved |
| Step 6 | New version; state file lags | Next open sees generation > recorded, which is benign |

### 8.4 Rollback detection (S11)

The state file holds one line per known vault, `<vault_id hex> <generation>`. On open, let g\_f be the file's generation and g\_s the recorded one.

- **g\_f ≥ g\_s, or unknown vault.** Proceed. The vault may have been saved elsewhere, for example after sync.
- **g\_f < g\_s.** Show "This vault is older than the last version saved on this machine (generation g\_f < g\_s). It may have been rolled back or restored from backup." Continuing requires typing `yes`. The next save writes generation max(g\_f, g\_s) + 1, so the counter never regresses.

This detects rollback but cannot prevent it. Prevention would require trusted monotonic storage (Section 19).

### 8.5 Write discipline (R4)

Read-only commands (`ls`, `show`, `reveal`, `copy`, `gen` without storing) never write. Each mutating command saves exactly once on success, and a failed command leaves both memory and disk unchanged. There is therefore no "unsaved changes" state and no save-on-exit path. A failed save is fatal to the session: the error is reported and `pwv` exits, because a failure after step 4 of Section 8.3 may already have replaced the file, so memory and disk can no longer be assumed to agree.

## 9. Features and command reference

`pwv` has seventeen commands, usable either in an interactive session (`pwv` with no command) or as a one-shot invocation (`pwv <command> …`). Both modes share one parser and one implementation per command.

### 9.1 Global flags

| Flag | Default | Range or meaning |
| --- | --- | --- |
| `--vault <path>` (or `PWV_VAULT`) | Section 8.1 | Vault file path |
| `--idle-timeout <s>` | 300 | 30 – 3600; on expiry: clear clipboard, wipe, exit |
| `--clip-timeout <s>` | 10 | 5 – 300 |
| `--arena-size <KiB>` | 1024 | 256 – 6144 |
| `--allow-unlocked-memory` | off | Proceed if `mlock` of the arena fails (Section 5.2) |
| `--require-locked-kdf` | off | Refuse if Argon2 memory cannot be locked (Section 5.4) |
| `--allow-foreign-fs` | off | Permit NTFS, FAT, or exFAT vault locations (Section 8.2) |
| `--no-color` (or `NO_COLOR`) | off | Disable ANSI styling |

### 9.2 Commands

| Command | Effect | Writes | Safeguards |
| --- | --- | --- | --- |
| `init [--kdf-memory MiB] [--kdf-time t]` | Create a vault | Yes | Refuses if the vault exists; password twice; strength policy (Section 6.5); offers a generated passphrase |
| `ls [pattern]` | List entry names containing `pattern` (Unicode-aware case-insensitive substring) | No | Names only; never values (B10) |
| `show <name>` | Show all fields | No | Sensitive values masked as a fixed 8 bullets, so length is not leaked (S6) |
| `reveal <name> <field>` | Print one value, wait for Enter, then clear screen and scrollback | No | Explicit per-field request only |
| `copy <name> [field]` | Copy to clipboard with expiry; the default field is the first sensitive field | No | Section 11.3 (S7) |
| `add <name>` | Guided creation: repeatedly prompt for key, then value (`typed`, `hidden`, or `gen [opts]`); `.` finishes | Yes | Refuses an existing name; warns on a case-insensitive near-duplicate; refuses duplicate keys and shows the prompt again (B3, B6) |
| `set <name> <field> [--gen [opts]] [--sensitive or --plain]` | Create or replace one field | Yes | Replacing a sensitive value requires confirmation; hidden input is entered twice |
| `unset <name> <field>` | Remove a field | Yes | Confirmation |
| `mv <old> <new>` | Rename an entry | Yes | Refuses if `new` exists (B4) |
| `mvfield <name> <old> <new>` | Rename a field key | Yes | Refuses if `new` exists in the entry (B4) |
| `rm <name>` | Delete an entry | Yes | User must type the exact entry name |
| `gen [opts]` | Generate a password or passphrase and copy it, without storing it | No | Prints only the entropy estimate unless `--show` |
| `passwd [--kdf-memory] [--kdf-time] [--purge-backups]` | Change the master password; rotate salt and DEK (Section 6.3) | Yes | KDF parameters checked before any prompt; current password re-entered; new password twice; strength policy (E3). The backups still open with the old password: a notice says so, and `--purge-backups` deletes them after the durable save |
| `import --from-stdin [--on-conflict abort or suffix]` | Merge a canonical body read from the stdin pipe (Section 12) | Yes | stdin must be a pipe; the strict parser validates; default `abort` on name conflict |
| `doctor` | Report the security posture of the environment (Section 9.4) | No | Read-only |
| `help`, `quit` (alias `exit`, `lock`) | Help; wipe and exit | No | — |

The `gen` options `--len`, `--classes`, `--symbols`, `--no-ambiguous`, `--words`, and `--sep` are specified in Section 10.

**Deliberately absent: plaintext export (S1).** The vault file itself is the portable artefact. A future export would be encrypted only; this is a non-goal for v1.

### 9.3 Interaction rules

- All prompts and all output go to `/dev/tty`, never to fd 0 or fd 1. This is why `import` can read data from a stdin pipe while still prompting on the terminal.
- **Tokenizer:** whitespace-separated arguments, double quotes for names containing spaces, and backslash escapes only for `\"` and `\\`. Any other backslash sequence is an error, never silently accepted. The tokenizer is fuzzed (T-FUZZ).
- **Default sensitivity:** a field is marked sensitive if its key, compared case-insensitively, is one of `password`, `passphrase`, `pin`, `secret`, `otp`, `totp`, `cvv`, `token`, `api key`, `recovery codes`, or if its value was generated. Users override with `--sensitive` or `--plain`.
- **Display sanitisation:** every name, key, and value printed is passed through `term::sanitize`. It renders C0 and C1 controls, DEL, and the bidirectional overrides U+202A–U+202E and U+2066–U+2069 as visible escapes such as `\x1b` or `\u{202e}`. This prevents terminal-escape injection and display spoofing from imported data.
- **Signals:** a minimal `sigaction` handler for SIGINT, SIGTERM, SIGHUP, and SIGQUIT only sets an atomic flag. SIGINT cancels the current command and returns to the prompt. The others trigger an orderly exit: clear clipboard, restore `termios`, wipe, exit. `termios` is also restored by a `Drop` guard.
- **Exit codes:** 0 success; 1 user error; 2 authentication failure; 3 vault integrity or rollback refusal; 4 environment refusal (permissions, `mlock`, filesystem); 5 internal error.

### 9.4 `doctor` checks

`doctor` prints a pass, warn, or fail line per check with a one-line remedy, and exits 0 or 1 accordingly.

| Check | Source | Pass condition |
| --- | --- | --- |
| Arena lockable | `RLIMIT_MEMLOCK` | ≥ arena size |
| KDF memory lockable | `RLIMIT_MEMLOCK` | ≥ m from the vault header |
| Swap | `/proc/swaps`, `/sys/block/dm-*/dm/uuid` (prefix `CRYPT-`), zram | None, zram only, or dm-crypt |
| Hibernation | `/sys/power/state`, `/sys/power/disk` | Disabled, or swap encrypted |
| Core dumps | `/proc/sys/kernel/core_pattern`, `/proc/sys/fs/suid_dumpable` | `suid_dumpable = 0` |
| ptrace scope | `/proc/sys/kernel/yama/ptrace_scope` | ≥ 1 |
| Vault location | Section 8.2 | All checks pass |
| Clipboard history | `XDG_CURRENT_DESKTOP` | Informational: whether the history-exclusion hint is likely honoured |

## 10. Password and passphrase generation

The generator outputs a string drawn exactly uniformly from the set of policy-valid strings. It uses the OS CSPRNG and two-stage rejection sampling, and writes directly into the `Gen` arena slot (S3 and the distributional-bias finding).

### 10.1 Interface

`trait ByteSource { fn fill(&mut self, buf: &mut [u8]) -> Result<()>; }` and `fn generate<R: ByteSource>(rng: &mut R, policy: &Policy, out: &mut SecretSlot) -> Result<Entropy>`. The trait is a one-method trait defined in `gen`, which avoids a `rand_core` dependency.

Production passes `OsBytes`, a thin wrapper over `getrandom`. Tests pass either a `ByteSource` adapter over a seeded `ChaCha20Rng` (dev-dependency `rand_chacha`) or an exhaustive enumerating mock. Injecting the source is what makes T-GEN deterministic and exhaustive.

**Character policy**

| Option | Default | Constraint |
| --- | --- | --- |
| `--len L` | 20 | 8 – 128 and ≥ the number of required classes |
| `--classes` | `luds` (lower, upper, digit, symbol) | Non-empty subset; each listed class must appear at least once |
| `--symbols S` | All 32 ASCII punctuation characters | Printable ASCII 0x21–0x7E, no duplicates, no alphanumerics |
| `--no-ambiguous` | off | Removes `I l 1 O 0 \` ' " |

**Passphrase policy**

| Option | Default | Constraint |
| --- | --- | --- |
| `--words k` | 6 | 4 – 16; uses the embedded list of 205,690 words |
| `--sep c` | `-` | One printable ASCII character other than a–z |

### 10.2 Algorithm and correctness argument

**Stage 1: unbiased index.** For an alphabet Σ of size n ≤ 256, draw a byte b. Accept it if b < 256 − (256 mod n) and output Σ\[b mod n\]; otherwise draw again. Each residue class modulo n contains exactly ⌊256/n⌋ accepted bytes, so the output is exactly uniform over Σ.

The acceptance probability is n⌊256/n⌋/256, which is at least 1/2 (worst case n = 129) and equals 188/256 ≈ 0.734 for n = 94. Word indices use the same construction over 24-bit values (3 bytes, big-endian), since 205,690 exceeds the 65,536 values of a u16. Since 2²⁴ mod 205,690 = 116,326, a 24-bit value is accepted if it is below 16,660,890, with probability ≈ 0.993; each word then has exactly 81 accepted values.

**Stage 2: class coverage.** Draw L i.i.d. characters, which gives a uniform element of Σᴸ. Accept the string if every required class occurs at least once; otherwise redraw all L characters. Conditioning a uniform distribution on the event V yields the uniform distribution on V. Hence the output is uniform over the valid set, whose size is given by inclusion–exclusion over the required classes c₁…c\_k with sizes n₁…n\_k:

```latex
N(L) = \sum_{S \subseteq \{1,\dots,k\}} (-1)^{|S|} \Big(n - \sum_{i \in S} n_i\Big)^{L}, \qquad H = \log_2 N(L) \text{ bits}
```

The expected number of stage-2 iterations is nᴸ / N(L). That is about 1.2 at L = 16 and 1.0 at L = 20 for the default policy. Iterations are capped at 10,000; exceeding the cap returns an error. For any valid policy the probability of reaching the cap is below (1 − 0.066)¹⁰⁰⁰⁰, which is effectively zero, so the cap exists only to guarantee termination.

For a passphrase, H = k · log₂ 205,690 ≈ 17.650 · k bits.

**Defaults.** With L = 20 over all 94 characters, H ≈ 131 bits. With the 6-word passphrase, H ≈ 105.9 bits. The computed H is shown to the user after each generation.

### 10.3 Word list integrity

The word list (`src/wordlist.txt`, supplied by the project in place of the EFF large list) is embedded with `include_str!`. Tests assert that it has exactly 205,690 unique, lower-case ASCII entries matching `[a-z-]+`, and that its SHA-256 equals the digest pinned in the test file (`9b7bb4cc2ede3e5573174339e0547c774b67e769cfda1fbbc93038ec66a93320`). The longest word has 24 letters, so a 16-word passphrase is at most 399 bytes and fits the 1 KiB `Gen` slot. The list is MIT-licensed; record the attribution in `README.md`.

## 11. Terminal I/O and clipboard

All interaction passes through two small modules. `term` owns `/dev/tty`, and `clip` owns the clipboard. Both are driven by one single-threaded `poll` loop, which also enforces the idle and clipboard deadlines, so no timer threads exist.

### 11.1 `term`: input

- Open `/dev/tty` once with `O_RDWR | O_CLOEXEC`. If it cannot be opened, exit with code 4.
- Lines are read in canonical mode by raw `read(2)` into the `Input` slot. The slot is 4 KiB, matching the kernel's canonical line limit of 4,095 bytes.
- An over-long line is drained to the newline and rejected. It is never truncated silently.
- **Hidden input** clears `ECHO` (keeping `ICANON` and `ISIG`) under a `TermiosGuard` whose `Drop` restores the saved settings. The signal path restores them as well.
- **Waiting** is `poll(tty, timeout)`, where timeout = min(idle deadline, clipboard deadline) − now.
  - Idle expiry: orderly exit (Section 9.3).
  - Clipboard expiry: the clip check in 11.3, then resume waiting.
- Input bytes are validated as UTF-8 before use. Invalid input is rejected with a generic message that never echoes the bytes back.

### 11.2 `term`: output

- Writes go by raw `write(2)` to the TTY fd. Non-secret strings may be formatted on the heap; any allocation is wiped by the allocator when freed.
- A secret is written directly from its slot in at most three calls: prefix, value, suffix. It is never concatenated into a heap buffer.
- `sanitize` (Section 9.3) is applied to everything derived from vault content. Sanitising a secret writes escape sequences chunk by chunk from the slot, again without an intermediate copy.
- `clear_screen` writes `ESC[H ESC[2J ESC[3J`. `ESC[3J`, which clears scrollback, is honoured by most modern emulators. Section 18 notes the exceptions.
- Masking prints a constant 8 bullets, independent of value length.
- Styling uses bold for names and dim for masked values. It is emitted only if the TTY is a real terminal, `TERM` ≠ `dumb`, and `NO_COLOR` is unset.

### 11.3 `clip`: copy with expiry

The pinned `arboard` exposes `SetExtLinux::exclude_from_history()`. It adds the `x-kde-passwordManagerHint` MIME type so that compliant clipboard managers, such as KDE Klipper, skip the entry.

1. The `arboard::Clipboard` object is created lazily on the first copy and reused until the copy expires. Use the `CLIPBOARD` selection only, never `PRIMARY`.
2. **copy(v):** first validate v as UTF-8. Then call `set().exclude_from_history().text(Cow::Borrowed(v))`. Copy v into the `Clip` slot, and set deadline = now + clip timeout.
3. **On expiry,** and on every exit path: read the clipboard text. If it equals the `Clip` slot in constant time, set the clipboard to the empty string. Then zero the `Clip` slot. If the clipboard demonstrably holds something else (other text, nothing, another format, text that is not UTF-8), leave it. If it cannot be read at all, set it to the empty string anyway (fail closed: on Wayland the value would otherwise be served until replaced). Zero the slot in every case. Then drop the `Clipboard` object: a value pasted by another client passed through its X11 connection's send buffer, which keeps the bytes until it is freed.
4. **Ordering at exit:** clear-if-unchanged first, then drop the `Clipboard` object. On X11, `arboard` may hand the current selection to a clipboard manager when it is dropped. Clearing first guarantees that the hand-over carries nothing sensitive.
5. **One-shot `pwv copy`** stays alive until the deadline, or until Enter is pressed. While waiting it shows `Copied. Clearing in 10 s (Enter to clear now).` The wait is required: on X11, the selection lives only as long as its owning process.

**Known limitation.** GNOME's compositor does not implement the Wayland data-control protocol, so `arboard` falls back to XWayland there. History exclusion depends on each clipboard manager honouring the KDE hint. `doctor` reports this, and T-CLIP covers X11 under Xvfb.

## 12. Importing entries

`pwv import --from-stdin` merges entries from a pipe into an existing vault. Its input is a canonical `pwv` body (Section 7.2), produced by any program that converts another password manager's data, for example `converter | pwv import --from-stdin`. `pwv` validates that body with the same strict parser it uses for vault bodies, so no second parser exists, and the plaintext never touches a disk on `pwv`'s side.

### 12.1 Producers of import data (project-specific; omitted)

The project also contains a one-off importer for its predecessor program (`tools/`, tested by T-MIG-1 – T-MIG-3). It concerns only data from that program and is not part of `pwv`; its specification is omitted here. A producer should refuse to write the body anywhere but a pipe, parse its own input with no parser that can execute code, and emit the canonical form of Section 7.3.

### 12.2 `pwv import --from-stdin`

1. The vault must already be initialised. stdin must be a pipe.
2. Raw-read stdin to its end into `VaultB`, the scratch half; the size cap is the slot size. An empty pipe is refused. Only then unlock through `/dev/tty`, so that the prompts of the pipe's producer and of `pwv` never overlap.
3. Parse with `format::parse_body`. Any error aborts with the exact constraint violated, naming at most the entry index and never any content.
4. Merge. A name conflict either aborts (the default) or appends `  (imported) `, with `--on-conflict suffix`. The result is one save and one generation increment.
5. Print `Imported N entries`, so the user can compare it with the producer's own count.

## 13. Traceability: audit findings to resolutions

Every finding from the audit of the predecessor program maps to a design element and at least one test. Every change must keep this table true: a finding without a passing test is not resolved.

| Finding | Resolution in `pwv` | Section | Verifying tests |
| --- | --- | --- | --- |
| S1 plaintext dump | No plaintext export exists | 9.2 | T-ENG-4 (no file-write path outside `store`), T-E2E-9 |
| S2 unsafe pickle | Hand-specified binary format; strict total parsers; imported data parsed by the strict body parser only | 7, 12 | T-FMT-1–4, T-FUZZ-1–3, T-MIG-2 |
| S3 non-CSPRNG | `getrandom` only; injected `ByteSource` | 10 | T-GEN-1–4, T-ENG-4 (no `rand::thread_rng`) |
| Generator bias | Two-stage rejection; exact uniformity | 10.2 | T-GEN-1, T-GEN-2, T-GEN-5 |
| S4 weak, rigid KDF | Argon2id 256 MiB, t = 3; parameters in authenticated header | 6.1, 6.4, 7.1 | T-KAT-1, T-CRY-5, T-FMT-4 |
| S5 master-password strength | Twice-entered; at least 16 characters and a built-in estimate ≥ 10¹⁴ guesses, or generated passphrase | 6.5 | T-E2E-1 |
| S6 plaintext display | Fixed-width masking; explicit `reveal`; screen and scrollback clearing | 9.2, 11.2 | T-E2E-3, T-E2E-4 |
| S7 clipboard persistence | Expiry; clear-if-unchanged; history-exclusion hint; clear before drop | 11.3 | T-CLIP-1–4 |
| S8 NTFS location | `statfs` refusal of foreign filesystems; mode and owner checks; XDG paths | 8.1, 8.2 | T-STORE-1 |
| S9 no auto-lock | `poll`-based idle timeout | 11.1 | T-E2E-6 |
| S10 memory residue | Locked guarded arena; zeroizing allocator; no std stdio; hardening; locked KDF memory | 5 | T-MEM-1–7 |
| S11 rollback; separate salt | Generation counter plus state file; salt inside the header | 7.1, 8.4 | T-STORE-5 |
| S12 timestamp leak | Format contains no timestamps | 7 | T-FMT-1 |
| S13 UTF-16, no normalisation | NFC then UTF-8 | 6.1 | T-CRY-6 |
| R1 non-atomic write | temp, `fsync`, rename, `fsync`-directory | 8.3 | T-STORE-2, T-STORE-3, T-STORE-8 |
| R2 no backups | 5 rotating backups | 8.3 | T-STORE-7 |
| R3 no locking | `flock` for the session | 8.2 | T-STORE-4 |
| R4 needless rewrites | Mutations only; one save per mutation | 8.5 | T-STORE-9 |
| B1 first-run crash | Explicit `init`; open never creates | 9.2 | T-E2E-1, T-E2E-2 |
| B2 `None` password | `Result`-returning generator with validated policy | 10 | T-GEN-4, T-FUZZ-4 |
| B3 `break` commits a partial entry | `add` refuses duplicate keys and prompts again | 9.2 | T-E2E-5 |
| B4 silent overwrite on rename | `mv` and `mvfield` refuse collisions; state unchanged on error | 9.2 | T-VAULT-2 |
| B5 abort on invalid key | Error message; session continues | 9.3 | T-E2E-5 |
| B6 inconsistent overwrite | One rule: `add` refuses, `set` confirms replacement of sensitive values | 9.2 | T-VAULT-1 |
| B7 escaped prompts | No markup library; one sanitiser | 9.3 | T-E2E-8 |
| B8 unhandled exceptions | `Result` everywhere; signal handling; defined exit codes | 9.3 | T-E2E-6, T-E2E-7, T-FUZZ-\* |
| B9 word-list loading | Embedded list with pinned digest | 10.3 | T-GEN-6 |
| B10 empty search dumps secrets | `ls` prints names only | 9.2 | T-E2E-3 |
| E1 hidden global | Explicit `Session` context passed by reference; no `static mut` and no lazy globals except the allocator | 4 | T-ENG-3 |
| E2 hard-coded paths | XDG defaults and overrides | 8.1 | T-STORE-1 |
| E3 no rotation | `passwd` rotates salt and DEK | 6.3 | T-CRY-4 |
| E4 code quality | Table-driven commands; typed errors; LOC budget; full test plan | 3, 14 | T-ENG-6, T-MUT-1, T-COV-1 – T-COV-5 |
| E5 unpinned dependencies | `Cargo.lock`, `--locked`, `cargo deny`, `cargo audit` | 15 | T-SUPPLY-1 |
| E6 rigid generator | Per-invocation policies | 10.1 | T-GEN-4 |

## 14. Testing and verification plan

The test suite is the specification's enforcement mechanism. Thirteen families of tests run in CI, and each test ID below is referenced by Section 13. A test may be added or strengthened but never weakened, skipped, or marked `#[ignore]` to make a build pass (Section 17).

### 14.1 Known-answer and compatibility tests

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-KAT-1 | Argon2id test vector from RFC 9106 §5.3, called through `crypto`'s own arena-backed wrapper | Exact tag match |
| T-KAT-2 | XChaCha20-Poly1305 vector from draft-irtf-cfrg-xchacha (AEAD test vector, Appendix A.3.1), through the in-place API | Exact ciphertext and tag |
| T-COMPAT-1 | Golden vaults in `tests/vectors/` (built with `testkdf`; password, expected entries, and file SHA-256 recorded in a manifest) | Decrypt to the exact expected model forever; never regenerated except on a format-version bump |

### 14.2 Format (`format`)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-FMT-1 | Property tests (`proptest`, ≥ 10,000 cases): for random valid models x, parse(serialize(x)) = x; for random bytes b with parse(b) = Ok(x), serialize(x) = b | Both identities hold |
| T-FMT-2 | One targeted test per constraint in Section 7: unsorted names, duplicate names, case-folded duplicate keys, bad UTF-8, each forbidden control class, non-zero padding, non-minimal padding, trailing bytes, every length field at 0, at max, at max + 1 | Each rejected with the specific error variant |
| T-FMT-3 | Truncate a valid file and a valid body at every byte offset | Error, never panic |
| T-FMT-4 | Header with extreme `kdf_m_kib` (0, 2³² − 1), `payload_len` ≥ file size, and `payload_len` near u32::MAX | Rejected before any allocation larger than 64 KiB (asserted with a counting allocator in tests) |

### 14.3 Cryptography (`crypto`)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-CRY-1 | Flip each of the 8 bits of every byte of a small golden vault (about 4.3 KiB, so about 35,000 cases; run against the post-KDF open path with the derived KEK cached, plus 100 random full-path cases) | Every case fails authentication, except flips that the format layer itself refuses first (`format::split_file`); those are counted separately, and every payload and tag flip fails authentication |
| T-CRY-2 | Wrong password versus a corrupted payload | Byte-identical user-visible message and the same exit code (2) |
| T-CRY-3 | 10⁵ saves of one vault | All payload nonces distinct; wrap nonce unchanged between saves |
| T-CRY-4 | `passwd`, then try the old password on an old file copy to decrypt the new file's payload | Fails; salt, DEK, and both nonces all differ |
| T-CRY-5 | Tamper with any header byte inside `AAD_w` or `AAD_p` | Unwrap or open fails |
| T-CRY-6 | Vault created with a password containing composed `é` (U+00E9), opened with decomposed `e` + U+0301 | Opens |

### 14.4 Generator (`gen`)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-GEN-1 | For every n in 2…256, enumerate all 256 byte values through the stage-1 mapping | Each residue receives exactly ⌊256/n⌋ accepted bytes |
| T-GEN-2 | Exhaustive uniformity: alphabet {a, b, C, 1} with classes {lower, upper, digit}, L = 4. An enumerating `ByteSource` drives every accepted draw sequence; count outputs | Every valid string appears equally often; invalid strings never appear |
| T-GEN-3 | Seeded `ChaCha20Rng`, default policy, 10⁶ characters | Per-position and pooled chi-square tests pass at α = 10⁻⁶ (deterministic seed, so no flakiness) |
| T-GEN-4 | Property: random valid policies produce output of exactly length L, containing every required class and only allowed characters; invalid policies return `Err` | Always |
| T-GEN-5 | Inclusion–exclusion N(L) versus brute-force count for every alphabet partition with n ≤ 6, L ≤ 6 | Exact equality |
| T-GEN-6 | Word list: 205,690 lines, unique, `[a-z-]+`, SHA-256 equal to the pinned digest | Exact |

### 14.5 Storage (`store`)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-STORE-1 | Permissions: directory 0700 and file 0600 accepted; any group or other bit refused; wrong owner refused (via a test-only UID override); symlinked vault refused; `statfs` classifier refuses each foreign-filesystem magic number | As specified, with exit code 4 |
| T-STORE-2 | Fault injection: a `#[cfg(test)]` hook aborts the save at each step of Section 8.3, including partial write, before and after each `fsync` and rename, and between backup renames | After each, open yields exactly the old or the new model; never an error |
| T-STORE-3 | Kill loop: a child process saves repeatedly, reporting each committed generation on a pipe. The parent sends `SIGKILL` at a uniformly random 0–50 ms; 500 iterations | Vault always opens; generation ≥ last reported commit |
| T-STORE-4 | Two processes open the same vault | Second exits within 100 ms with "in use" and code 4 |
| T-STORE-5 | Save to generation 5, restore a generation-3 file | Rollback warning; `no` exits with code 3; `yes` continues; next save writes generation 6 |
| T-STORE-6 | Stale temp files present at open | Removed |
| T-STORE-7 | Seven saves | Exactly backups `.1`–`.5`, each decrypting to the expected prior generations |
| T-STORE-8 (nightly) | Run T-STORE-3 under LazyFS with "clear unsynced data" faults | Same as T-STORE-3 |
| T-STORE-9 | Read-only commands | File modification time and inode unchanged |

### 14.6 Model (`vault`)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-VAULT-1 | Model-based testing: `proptest` generates sequences of up to 200 operations (`add`, `set`, `unset`, `mv`, `mvfield`, `rm`, `import`) with adversarial names and values (Unicode, limit lengths, near-duplicates). Apply them to the implementation and to a reference `BTreeMap`; compare after every operation; save and reopen every 10 operations | Always equal |
| T-VAULT-2 | Every colliding `mv`, `mvfield`, `add`, or `import` | Returns `Err`; model and file byte-identical to before |

### 14.7 End-to-end, through a PTY (`expectrl`)

| ID | Scenario | Pass criterion |
| --- | --- | --- |
| T-E2E-1 | `init`: weak password refused; mismatch refused; generated passphrase accepted | Exact behaviour; typed password never visible in the captured screen |
| T-E2E-2 | Any command with a missing vault | Error naming `pwv init`; nothing created |
| T-E2E-3 | `ls` and `show` | `ls` prints names only; `show` prints 8 bullets for sensitive values whatever their length |
| T-E2E-4 | `reveal` | Value appears once; after Enter the emitted bytes include `ESC[2J ESC[3J` |
| T-E2E-5 | `add` and `set` with duplicate keys, invalid keys, over-length input | Error; prompt shown again; session continues |
| T-E2E-6 | Idle for timeout + 1 s | Process exits with code 0, the locked message, and a cleared clipboard |
| T-E2E-7 | SIGINT at a prompt; SIGTERM, SIGHUP, SIGQUIT mid-session | SIGINT cancels the command; the others exit cleanly; `stty -a` afterwards matches the saved state |
| T-E2E-8 | Entry named with ESC, BEL, and U+202E | Displayed as visible escapes; the terminal title is unchanged |
| T-E2E-9 | `rm` with a wrong confirmation; `export` or `dump` typed | Nothing deleted; unknown command |
| T-E2E-10 | `import` from a valid pipe, an invalid pipe, and a TTY stdin | Merge; precise refusal; refusal |
| T-E2E-11 | `passwd`, then reopen with the new password | Opens; old password fails |
| T-E2E-12 | stdin or stdout redirected and `/dev/tty` unavailable (`setsid` without a controlling TTY) | Exit code 4 |

### 14.8 Clipboard (X11 via Xvfb in CI)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-CLIP-1 | `copy`, then query `TARGETS` with `xclip -o -t TARGETS` | Contains `x-kde-passwordManagerHint` |
| T-CLIP-2 | Wait for the timeout | Clipboard empty |
| T-CLIP-3 | Another client sets the clipboard before the timeout | Not cleared |
| T-CLIP-4 | Exit while the clipboard is still ours, with a mock clipboard manager running | Manager receives empty content |

### 14.9 Memory hygiene (S10)

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-MEM-1 | Parse `/proc/<pid>/smaps` for the arena | `Locked:` equals the data-region size; `VmFlags` contains `dd` and `wf`; both guard mappings are `---p` |
| T-MEM-2 | A test-only command writes one byte past the last slot, in a child process | Child dies by SIGSEGV |
| T-MEM-3 | Drop a slot, then the arena (via the `memtest` snapshot hook taken just before `munmap`) | All bytes zero |
| T-MEM-4 | **Canary scan** (`memtest` build). The vault holds secret canary C₁; the master password is canary P; the user types C₂ in `set`, and C₃ is generated. Run `show`, `reveal`, `copy`, `set`, and `gen`, then pause; the harness reads every readable mapping via `/proc/<pid>/mem` and searches for each canary in UTF-8 and UTF-16LE. Then `lock`, which wipes, pauses before `exit`, and is scanned again. Also: an entry name and field key as canaries, `add` with a generated value, `passwd` to a chosen password and to a generated passphrase (scanned mid-session); `init` with the generated passphrase, `import` of a canary body from a pipe, a wrong password, and a refused rollback (each scanned after the wipe) | Mid-session: matches only inside the arena; no master password (old or new) found anywhere. After lock or any exit: zero matches anywhere |
| T-MEM-5 | Release build. Read `/proc/<pid>/limits`; attempt `ptrace(PTRACE_ATTACH)` and a `/proc/<pid>/mem` read from a sibling (non-parent) process; send SIGSEGV | Core limit 0; attach and read refused; no core file and no `coredumpctl` entry |
| T-MEM-6 | In tests, the global allocator wraps an asserting layer that checks every block is zero when it reaches `System::dealloc`, across the whole test suite | Never violated |
| T-MEM-7 | After unlock, `/proc/<pid>/maps` | KDF region no longer mapped; in `memtest`, its bytes were zero before `munmap` |

### 14.10 Fuzzing (`cargo-fuzz`, libFuzzer)

Targets: T-FUZZ-1 header parser; T-FUZZ-2 body parser; T-FUZZ-3 full open with `testkdf` parameters; T-FUZZ-4 REPL tokenizer and command parser; T-FUZZ-5 `sanitize`; T-FUZZ-6 import merge.

- **Invariants:** no panic; no allocation above 64 MiB (`-rss_limit_mb=256`); no input taking more than 1 s; for T-FUZZ-2, any accepted input satisfies the round-trip identity.
- **Budget:** 60 s per target on every pull request; 30 min per target nightly.
- **Corpus:** committed and seeded with golden vectors. Every crash becomes a regression unit test before it is fixed.

### 14.11 Static, sanitizer, mutation, and coverage gates

| ID | Gate | Pass criterion |
| --- | --- | --- |
| T-ENG-1 | `cargo fmt --check`; `cargo clippy --all-targets -D warnings` with the `clippy::pedantic` subset listed in `clippy.toml` | Clean |
| T-ENG-2 | Script: `unsafe` appears only in `sys.rs`, `secmem.rs`, `alloc.rs`; each `unsafe` block is preceded by `// SAFETY:` | Clean |
| T-ENG-3 | Script: the `use crate::` graph respects the layering of Section 4; no `static mut`; no global state except the allocator | Clean |
| T-ENG-4 | `clippy.toml` `disallowed-methods` and `disallowed-macros`: std stdio and print macros (except in `term`), `std::process::Command`, `rand::thread_rng`, `std::fs::write`, `File::create`, `OpenOptions::open`, `fs::copy`, `fs::rename`, and `fs::hard_link` outside `store`; and only `store` calls the `sys` file primitives (`open_at`, `rename_at`, `link_at`, `unlink_at`) | Clean |
| T-ENG-5 | `static_assertions`: `SecretSlot` and `SecureArena` are not `Clone`, `Copy`, `Display`, or `Send` | Compiles |
| T-ENG-6 | `tokei`-based script enforces the LOC caps of Section 3 | Within caps |
| T-ENG-7 | Release artefact contains neither `PWV_MEMTEST` nor `PWV_TESTKDF` marker strings | Absent |
| T-SAN-1 | Full test suite under AddressSanitizer (nightly) | Clean |
| T-SAN-2 | Miri on `format`, `gen`, and `vault`, using a heap-backed arena backend selected under `cfg(miri)` | Clean |
| T-MUT-1 | `cargo-mutants` on `format`, `crypto`, `gen`, `store`, `vault` | 0 surviving mutants, or each one justified in `DESIGN_NOTES.md` |
| T-COV-1 – T-COV-6 | `cargo-llvm-cov`; defined in Section 14.13 | As in Section 14.13 |

### 14.12 Supply chain, reproducibility, performance, predecessor import

| ID | Test | Pass criterion |
| --- | --- | --- |
| T-SUPPLY-1 | `cargo deny check` (advisories; license allow-list MIT, Apache-2.0, BSD-2/3, ISC, Unicode, Zlib; bans duplicate major versions) and `cargo audit` | Clean |
| T-REPRO-1 | Two clean `--locked` release builds with fixed `SOURCE_DATE_EPOCH` and `--remap-path-prefix` | Bit-identical binaries |
| T-PERF-1 | Unlock at default parameters on the CI reference runner; save of 1,000 entries excluding `fsync`; allocator overhead versus `System` | ≤ 3 s; ≤ 50 ms; ≤ 5 % on the test suite's wall time |
| T-MIG-1 | Project-specific importer (Section 12.1): a fixture written by the predecessor program, piped into `pwv import` | Expected model, warnings, and refusals |
| T-MIG-2 | Project-specific importer: input that would execute code if deserialised unsafely | Importer aborts; no code runs |
| T-MIG-3 | Project-specific importer: standard output is a TTY or a regular file | Refuses |

### 14.13 Coverage measurement and reporting

Coverage shows which production code the test suite executes. It complements mutation testing (T-MUT-1), which shows whether the tests would notice a change to that code. Path coverage is not measured: no Rust tool provides it, and T-MUT-1 covers that need.

**Tooling.** Coverage uses `cargo-llvm-cov`, the compiler's built-in LLVM source-based coverage, at a version pinned in CI like the other tools. Line, region, and function coverage are measured on the pinned stable toolchain, using its `llvm-tools` component; these are the gating figures. Branch coverage needs nightly (`--branch`). It is measured in a separate nightly run, and the report records the exact nightly version.

**Denominator: production code only.** "Production code" means the same lines T-ENG-6 counts: every `src/*.rs` file, minus `#[cfg(test)]` items, comments, and blank lines. Also excluded are `tests/`, `fuzz/`, `tools/`, `scripts/`, and code compiled only under `cfg(miri)`. Miri-only code is verified by T-SAN-2 and listed in the report as excluded. The report script uses the same stripping logic as `scripts/loc_budget.py`, so the two definitions cannot drift apart.

**Runs included.** All of these are merged into one report:

- `cargo test --locked` with default features, `--no-default-features`, `memtest`, `testkdf`, and `memtest,testkdf`;
- the e2e suite (T-E2E, T-CLIP under `xvfb-run`), with the `pwv` binary instrumented so that child processes write coverage data;
- the default iteration counts of all tests, including T-STORE-3.

Runs in the same job are merged by `cargo-llvm-cov` itself, which is exact. If the work is split across several jobs for time, each exports LCOV and JSON, and the reporting job merges them by line. Region and branch figures are then reported per job.

**Runs excluded:**

- Miri, sanitizers, fuzzing, mutation testing, and `durability` (5,000 iterations).
- Release-profile runs. Coverage is measured in the dev profile; T-MEM-5 and T-ENG-7 verify the release-only behaviour.
- Processes that end by SIGKILL or SIGSEGV. They write no coverage data; this is expected.

**Determinism.** The coverage job fixes every property-test seed (`PROPTEST_RNG_SEED`) and the number of cases, so repeated runs on the same commit give identical figures.

| ID | Measure | Pass criterion |
| --- | --- | --- |
| T-COV-1 | Line coverage of production code, merged over all included runs | ≥ 95 % in each of `format`, `crypto`, `gen`, `store`, `vault`; ≥ 85 % overall |
| T-COV-2 | Function coverage | 100 % of production functions in the five modules above; any exception listed in `DESIGN_NOTES.md` |
| T-COV-3 | `unsafe` blocks (rule 6, mechanised) | Every `unsafe` block found by T-ENG-2 is fully covered natively, except blocks compiled only under `cfg(miri)`, which are listed |
| T-COV-4 | No regression | No module's line or region coverage falls more than 0.5 percentage points below the committed baseline `coverage/baseline.json`. Raising or lowering the baseline is a deliberate commit with a dated `DESIGN_NOTES.md` entry |
| T-COV-5 | Branch coverage (nightly) | Reported per module. M9 records the first measurement as the baseline; after that, T-COV-4's no-regression rule applies to branches as well |
| T-COV-6 | Fuzz corpus coverage (`cargo fuzz coverage`, in `fuzz-long`) | Region coverage of `format` and `vault` per fuzz target, reported. A drop of more than 2 percentage points between nightly runs is flagged, since it suggests a lost corpus. Report-only |

**Uncovered code.** The report lists every uncovered production line in the five gated modules by `file:line`. Before the M9 gate, each one is either covered or justified in a "Coverage exceptions" table in `DESIGN_NOTES.md`, dated, with the reason. A typical reason is a defensive check that cannot fail after validation. This is the same mechanism T-MUT-1 uses for surviving mutants.

**Report.** The `coverage-report` job runs after all coverage runs. It writes into the GitHub job summary:

1. a table per module group, using the Section 3 groups, then per file: lines, regions, functions, and branches (covered, total, percentage), the threshold, the change against the baseline, and pass or fail;
2. the T-COV-3 list of `unsafe` blocks with their status;
3. the uncovered lines in the gated modules, marked as justified or not;
4. the toolchain versions and the seeds used;
5. a table of every Section 14 test ID with its milestone and its pass or fail status in the latest run, collected from the gate-by-name steps.

It uploads HTML, LCOV, and JSON reports as artefacts, kept for 30 days. Coverage figures never include program output, because tests print no content (Section 17, rule 9).

**Badges.** On runs on `main` (pushes, the nightly schedule, and manual runs; never pull requests), `coverage-report` renders SVG badges for overall line coverage (T-COV-1) and for the number of Section 14 test IDs passing, and pushes them to an orphan `badges` branch, which holds only those files. The test-ID badge comes from full runs only (nightly or manual); T-MUT-1 is taken from the latest weekly `mutants` run if it finished within eight days. It is the only job of the CI workflow with `contents: write`; the other job that has it is the release workflow's `publish` (Section 15.3). `README.md` references the badges, together with GitHub's CI status badge. CI never commits to `main` or edits `README.md`. No coverage data is sent to third-party services.

**When it is introduced.** The coverage jobs, the report, and the badges are added at M9 and gate from then on.

## 15. Engineering practices, tooling, CI

The build is pinned, locked, and reproducible, and CI runs every gate of Section 14 on each change, with long-running gates nightly.

### 15.1 Toolchain and build profile

- **Toolchain:** `rust-toolchain.toml` pins a specific stable release, with the components `rustfmt`, `clippy`, and `llvm-tools`. Edition 2024. Record the MSRV in `Cargo.toml` (`rust-version`). Nightly is used only for ASan, Miri, fuzzing, and branch-coverage (T-COV-5) jobs.
- **Crate attributes:** `#![deny(unsafe_code)]`, `#![deny(unsafe_op_in_unsafe_fn)]`, `#![deny(missing_docs)]` on the public `lib` API, `#![warn(clippy::pedantic)]`, plus selected `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]` in non-test code. Parsers use checked slicing (`get`) exclusively.
- **`[profile.release]`:** `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "unwind"` (needed so that `Drop` zeroises), `overflow-checks = true`, `debug = false`, `strip = "symbols"`.
- **Link hardening:** `-C link-arg=-Wl,-z,relro,-z,now`; a PIE executable (the default).
- **Cargo features:**

| Feature | Default | Purpose |
| --- | --- | --- |
| `clipboard` | on | Enables `arboard` |
| `memtest` | off; tests only | Section 5.8 |
| `testkdf` | off; tests only | Section 6.4 |

### 15.2 Error handling and style

- One `enum Error` per module. The top-level `Error` maps each variant to an exit code and a fixed message. No `anyhow` or `thiserror` is needed; a manual `Display` keeps the dependency budget.
- No `unwrap` or `expect` outside tests. Arithmetic on lengths uses `checked_*`. Integer casts use `try_from`.
- Commands are table-driven: one `const COMMANDS: &[CommandSpec]` holds the name, argument arity, handler, and help text. Help output and the parser derive from that table, so they cannot drift apart.
- Every public function has a doc comment stating its preconditions and, where relevant, its secret-handling contract ("borrows the DEK; never copies it").

### 15.3 CI jobs (GitHub Actions; runners pinned to `ubuntu-26.04`, x86\_64; an aarch64 runner nightly)

`ci.yml` runs on pull requests, on pushes to `main`, nightly, and on demand ("Run workflow"). A new push to a pull request cancels that pull request's older run. Nightly and on-demand runs include every job; pull requests and pushes to `main` skip the jobs marked nightly.

| Job | Trigger | Contents |
| --- | --- | --- |
| `lint` | Every run | T-ENG-1 – T-ENG-6; the Section 14 inventory check |
| `test` | Every run | `cargo test --locked` in debug and release, with the `testkdf` and `memtest` test builds |
| `release-check` | Every run | T-REPRO-1, T-ENG-7, link hardening (Section 15.1), without signing |
| `e2e` | Every run | T-E2E-\*, T-CLIP-\* (under `xvfb-run`), T-MEM-4, T-MIG-\* |
| `compat` | Every run | T-COMPAT-1: golden vaults checked by an independent implementation |
| `fuzz-smoke` | Every run | 60 s per target |
| `coredump` | Every run | T-MEM-5's core-dump clause |
| `supply` | Every run | T-SUPPLY-1 (nightly runs pick up new advisories) |
| `coverage` | Every run | Instrumented runs of Section 14.13, one job per configuration |
| `coverage-report` | After `coverage` | Merge; T-COV-1 – T-COV-5; job summary table; artefacts; badges (Section 14.13) |
| `sanitizers` | Nightly | T-SAN-2 (Miri) |
| `sanitizers-asan` | Nightly | T-SAN-1 (AddressSanitizer and LeakSanitizer) |
| `test-arm64` | Nightly | The test suite on aarch64 |
| `durability` | Nightly | T-STORE-3 (5,000 iterations), T-STORE-8 (LazyFS) |
| `perf` | Nightly | T-PERF-1 |
| `coverage-branch` | Nightly | T-COV-5 on nightly |
| `fuzz-long` | Nightly | 30 min per target; corpus saved; T-COV-6 |
| `ci-ok` | Every run, last | Passes only if every other job passed or was skipped; the status check that branch protection requires |
| `mutants` (workflow `mutants.yml`) | Weekly, on demand, and before release | T-MUT-1 |
| `release` (workflows `release.yml`, `release-build.yml`) | Version tag `v*` | The tagged commit is on `main` and has a green full CI run, and a green `mutants` run tested the same `src/` and `tests/`; tag must equal `v` + the `Cargo.toml` version; T-REPRO-1, T-ENG-7, then build, `sha256sum`, and an attested (signed) checksum file; then an immutable GitHub release of those files, a draft until every file is uploaded and checked, a pre-release for a pre-release version, verified after publication |

### 15.4 Documentation deliverables

| File | Content |
| --- | --- |
| `README.md` | What pwv is and how it compares, install, quick start, commands, building, verifying a release, licence, word-list attribution, CI status, coverage, and test-ID badges (Section 14.13) |
| `CONTRIBUTING.md` | How to contribute: scope, setup, rules, tests, pull requests and review |
| `docs/SPECIFICATION.md` | This document |
| `docs/THREAT_MODEL.md` | Section 2 and Section 18 verbatim and maintained |
| `docs/FORMAT.md` | Section 7, normative, with hexdumps of one golden vector annotated field by field |
| `docs/DEVELOPMENT.md` | Every check, the CI workflows, and the release procedure |
| `docs/DESIGN_NOTES.md` | Every deviation, dependency justification, coverage exception, and surviving-mutant justification, each dated |
| `SECURITY.md` | How to report vulnerabilities; supported versions |

### 15.5 Review checklist (attach to every pull request)

- [ ] Does the change introduce a new place where secret bytes can exist outside the arena?
- [ ] Does any new `unsafe` block have a `// SAFETY:` comment, and is it inside `sys`, `secmem`, or `alloc`?
- [ ] Does any new parsing path have a fuzz target and a truncation test?
- [ ] Does any new on-disk write go through `store`'s atomic protocol?
- [ ] Are the LOC caps respected, and is the Section 13 matrix still true?
- [ ] Is every new production line covered, or justified in the coverage exceptions table, and is no module below its coverage baseline?

## 16. Milestones and acceptance criteria

The initial implementation proceeded through ten strictly sequential milestones, M0 to M9, kept here because tests and notes refer to them. Each is one reviewable change set and ends at a gate: the listed tests are green in CI. Work on milestone k + 1 begins only after gate k passes. Within a milestone, write the tests first.

1. **M0: Skeleton and guard rails.** Repository layout (Section 4), toolchain pin, `Cargo.toml` with the exact dependency set, `deny.toml`, `clippy.toml` bans, empty modules with layering, CI jobs `lint` and `supply`.
   - Gate: T-ENG-1 – T-ENG-4, T-ENG-6, T-SUPPLY-1.
2. **M1: Memory foundation.** `sys::harden`, `SecureArena` and `SecretSlot` with guard pages and flags, the zeroizing allocator, the `memtest` hooks, and a `cfg(miri)` heap backend.
   - Gate: T-MEM-1, T-MEM-2, T-MEM-3, T-MEM-5, T-MEM-6, T-ENG-5.
3. **M2: Format.** Header and body encode and decode, canonical rules, padding, `FORMAT.md` draft, fuzz targets 1 and 2.
   - Gate: T-FMT-1 – T-FMT-4, T-FUZZ-1, T-FUZZ-2 (smoke), T-SAN-2 for `format`.
4. **M3: Cryptography.** NFC normalisation, Argon2id into the KDF region, wrap and unwrap, in-place seal and open, `passwd` rekeying logic (library level), golden vectors.
   - Gate: T-KAT-1, T-KAT-2, T-CRY-1 – T-CRY-6, T-COMPAT-1, T-MEM-7, T-FUZZ-3 (smoke).
5. **M4: Storage.** Path resolution, open-time checks, `flock`, the atomic save protocol, backups, the rollback-state file, fault-injection hooks.
   - Gate: T-STORE-1 – T-STORE-7, T-STORE-9.
6. **M5: Model.** The `vault` index over the arena body; all operations with collision rules; serialisation into the scratch half.
   - Gate: T-VAULT-1, T-VAULT-2, T-FUZZ-6.
7. **M6: Generator.** Character and passphrase modes, entropy computation, embedded word list.
   - Gate: T-GEN-1 – T-GEN-6, T-SAN-2 for `gen`.
8. **M7: Terminal, CLI, clipboard.** `/dev/tty` I/O, hidden input, `poll` loop with idle and clipboard deadlines, signal handling, sanitisation, the command table, all seventeen commands, `doctor`.
   - Gate: T-E2E-1 – T-E2E-12, T-CLIP-1 – T-CLIP-4, T-FUZZ-4, T-FUZZ-5.
9. **M8: Verification of Invariant M, and the predecessor importer.** Canary-scan harness; the project-specific importer of Section 12.1 plus fixtures.
   - Gate: T-MEM-4, T-MIG-1 – T-MIG-3, T-E2E-10.
10. **M9: Hardening and release readiness.** Long fuzzing, sanitizers, mutation testing, coverage with its report and README badges (Section 14.13), durability under LazyFS, reproducibility, performance, documentation complete, LOC audit.
    - Gate: every test ID in Section 14 green; T-MUT-1, T-COV-1 – T-COV-5, T-REPRO-1, T-PERF-1, T-ENG-7, T-STORE-8; `README.md`, `THREAT_MODEL.md`, `FORMAT.md`, `DESIGN_NOTES.md`, and `SECURITY.md` complete; the Section 13 matrix verified line by line.

**Definition of done for v1:** M9's gate passes on two consecutive nightly runs, and an independent review pass (Section 17, rule 12) reports no unresolved findings rated High or above.

## 17. Rules for contributors

These rules take precedence over convenience. If a rule appears to block progress, stop and raise the conflict in an issue or pull request (and record the outcome in `DESIGN_NOTES.md`). Never silently work around a rule. `CONTRIBUTING.md` restates them with examples.

1. **Keep every gate green.** During the initial implementation this meant following the milestone order of Section 16; now it means that a change merges only when CI is green, and a nightly failure on `main` is fixed before further feature work.
2. **Tests are immutable once written,** except to make them stricter. Never delete, weaken, `#[ignore]`, or widen the tolerance of a test to obtain a pass. Fix the code instead.
3. **No new runtime dependency** beyond Section 3 without a dated justification in `DESIGN_NOTES.md`. That justification must state the alternative of writing 50 lines by hand, and why that was rejected.
4. **Verify every third-party API** against the pinned version's documentation or source before use; record the version in a code comment at the first use site. In particular, verify `argon2`'s `hash_password_into_with_memory`, `arboard`'s `SetExtLinux::exclude_from_history`, `chacha20poly1305`'s in-place detached APIs, and the `rustix` coverage of `prctl`, `madvise`, and `mlock`. Where `rustix` lacks a call, use `libc` inside `sys` only.
5. **Secret-handling invariant.** No secret byte may be stored in a `String`, `Vec`, `Box`, array on the heap, or `static`. Secrets live only in arena slots and are passed as `&[u8]` or `&mut SecretSlot`. Any exception must be listed in `DESIGN_NOTES.md` and covered by T-MEM-4.
6. **`unsafe` discipline.** Only in `sys`, `secmem`, and `alloc`. Each block is minimal, has a `// SAFETY:` comment, and has at least one test that exercises it.
7. **Simplicity budget.** Respect the LOC caps of Section 3. Prefer deleting code to adding abstractions. No traits except `ByteSource` and the test-only fault hook. No generics beyond those required by dependencies. No macros except `include_str!` and test macros.
8. **Errors** never contain secret bytes, entry names, field keys, field values, or file contents. Parsers report positions and constraint names only.
9. **Never write plaintext to disk,** to a log, to stderr, or into a panic message, including during debugging. Use the `memtest` hooks, never print statements.
10. **Specification precedence.** The spec wins over personal preferences. Where the spec is ambiguous, choose the more conservative option, document it in `DESIGN_NOTES.md`, and continue. Where the spec is wrong (for example, an API no longer exists), stop and report.
11. **Report per change:** each pull request states what changed, LOC against the caps where code grew, the tests added, and any deviation, explicitly.
12. **Independent review before declaring v1 done.** A fresh reviewer who did not write the code and has no access to the implementation history audits the code against Sections 2, 5, 7, 8, and 13. It must attempt to break Invariant M, the parsers, and the save protocol. Its findings are fixed or justified before release.

## 18. Residual risks and non-goals

The following exposures remain after a correct implementation. Each is outside the reach of a userspace program, or deliberately out of scope for v1. `THREAT_MODEL.md` must list them verbatim.

| Residual exposure | Why it remains | Mitigation outside `pwv` |
| --- | --- | --- |
| Kernel TTY and line-discipline buffers hold typed secrets transiently | Kernel memory, not process memory | None needed against A1–A5; root is out of scope |
| Terminal emulator holds revealed values in its scrollback and render buffers | Separate process | `reveal` sends `ESC[3J`; prefer emulators that honour it; avoid recording or session-logging terminals |
| X server, compositor, and clipboard managers hold copied values | Separate processes | Expiry, history hint, clearing before hand-over (Section 11.3) |
| Hibernation image contains `mlock`ed pages | Kernel writes all RAM | Disable hibernation or encrypt swap; `doctor` warns. Section 19.1 removes this for kernels with `memfd_secret` |
| Argon2 working memory is unlocked when `RLIMIT_MEMLOCK` is too low | Default limit is 8 MiB | Raise the limit, or use encrypted swap; `--require-locked-kdf` |
| Registers and stack residue inside third-party crypto code | Not controllable from Rust | `scrub_stack` (best effort) |
| Same-UID malware present before launch (A6) | Can preload, replace, or keylog | Out of scope: keep the account clean; verify the binary's checksum |
| Root, kernel, firmware (A7); physical attacks (A8) | Beyond any process's privilege | Full-disk encryption, Secure Boot, physical security |
| Rollback is detected, not prevented | No trusted monotonic store | Section 19.2 |

**Non-goals for v1:** Windows and macOS; a GUI or browser integration; autotype; TOTP generation; sharing or sync; plaintext export; multiple vaults per session; a recovery key or hardware keyslot. The format reserves room for a keyslot list in a future version 2 through `format_version`; v1 implements exactly one password keyslot.

## 19. Unconventional alternatives

Two departures from standard practice would each close a residual risk from Section 18 at a cost of roughly 100–200 additional lines. Both are optional post-v1 work and must not delay M0–M9.

### 19.1 `memfd_secret(2)` as the arena backend

Instead of anonymous `mmap` plus `mlock`, back the arena and the KDF region with a file descriptor from `memfd_secret(2)`. This syscall has existed since Linux 5.14, and since Linux 6.5 it is enabled by default; earlier kernels need the boot parameter `secretmem.enable=y`. glibc has no wrapper, so it is called via `syscall(SYS_memfd_secret, 0)` inside `sys`.

According to `memfd_secret(2)`, such pages are:

- **removed from the kernel's direct map,** so they cannot be reached through `get_user_pages`, which also means `/proc/<pid>/mem` and `process_vm_readv` cannot read them;
- **locked like `mlock`,** and charged to `RLIMIT_MEMLOCK`;
- **a hibernation inhibitor:** the kernel refuses to hibernate while any such region exists.

The last property removes the hibernation entry of Section 18 outright, which no `mlock`-based design can do. The first raises the bar against kernel-memory disclosure bugs. It does not stop a determined root user, and the man page itself states that there is no absolute guarantee.

**Design.**

1. Reserve `PROT_NONE` anonymous space for guard + data + guard.
2. `ftruncate` the secret fd to the data size.
3. Map it with `MAP_SHARED | MAP_FIXED` over the middle of the reservation.
4. If the syscall returns `ENOSYS`, fall back to the v1 backend and report the fact in `doctor`.

**Test impact.** T-MEM-4 can no longer read the arena from outside, which is itself the property to verify. The canary scan then asserts zero matches in every readable mapping, during the session as well as after lock.

### 19.2 Rollback prevention with a TPM 2.0 monotonic NV counter

Section 8.4 detects rollback but cannot prevent it, because the state file is as writable as the vault. A TPM 2.0 NV index of type counter (`TPM_NT_COUNTER`) can only be incremented. It therefore provides the trusted monotonic store the design lacks, without trusting the filesystem.

The protocol has three parts:

- **At `init`,** define one NV counter index protected by an `authValue` derived from the DEK, for example HKDF(DEK, "pwv-nv"). Only an unlocked session can increment it, which prevents denial-of-service increments by other software.
- **On save,** write the file first, with generation = c + 1 where c is the current counter value, and only then execute `TPM2_NV_Increment`.
- **On open,** accept the file if and only if g\_f ≥ c.

With this ordering, a crash between the write and the increment leaves g\_f = c + 1 ≥ c, which is accepted. Any older file has g\_f ≤ c − 1 < c, which is refused. Rollback by even a single version is therefore cryptographically impossible without TPM-level compromise; the accept and refuse conditions follow directly from the counter's monotonicity.

**Rekeying.** `passwd` rotates the DEK, so it must define a fresh NV index (authValue from the new DEK) and undefine the old one. The TPM 2.0 specification initialises a new counter index at or above the largest counter value present on the TPM, so monotonicity carries over; verify this against the target TPM before relying on it. The first save after rekeying writes generation = the new index's value + 1.

**Lockout risk.** Malware that obtains the authValue could increment the counter and make the current vault appear rolled back. Opening then falls back to the Section 8.4 confirmation prompt rather than refusing permanently, so this costs availability but never confidentiality.

**Lightweight implementation.** Speak raw TPM2 command buffers over `/dev/tpmrm0`: `TPM2_NV_DefineSpace`, `TPM2_NV_Read`, and `TPM2_NV_Increment` with password authorisation. That is about 150 lines, instead of linking the large `tss-esapi` and `tpm2-tss` stack.

The counter is machine-bound. A vault copied to another machine falls back to the Section 8.4 detection mode, and `doctor` reports which mode is active. The NV index is invisible to and unaffected by the Windows installation on a dual-boot machine.
