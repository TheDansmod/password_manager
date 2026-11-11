# pwv threat model

This file reproduces Sections 2 and 18 of the pwv specification verbatim (spec Section 15.4). Keep it in sync with the specification.

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
