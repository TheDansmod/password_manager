# pwv

A single-binary, Linux-first terminal password manager written in Rust,
specified in `rust_password_manager_specification.md` (one level up).

**Status: M7 (terminal, CLI, clipboard).** All seventeen commands exist,
in an interactive session (`pwv`) and as one-shot invocations
(`pwv <command> ...`). Still to come: the memory canary scan and the
legacy migration script (M8), and release hardening (M9).

## Quick start

```sh
pwv init          # create the vault; a generated 6-word passphrase is offered
pwv               # unlock and start a session
pwv> add github   # guided: field key, then typed / hidden / gen [options]
pwv> show github  # sensitive values are masked
pwv> copy github  # first sensitive field to the clipboard, cleared after 10 s
pwv> quit
pwv doctor        # check swap, core dumps, memory locking, vault location
```

Every prompt and all output use `/dev/tty`. Standard output must be a
terminal; standard input may be a pipe only for `pwv import --from-stdin`.

| Command | Effect |
| --- | --- |
| `init [--kdf-memory MiB] [--kdf-time t]` | Create a vault |
| `ls [pattern]` | List entry names (case-insensitive substring) |
| `show <name>` | Show an entry; sensitive values as 8 bullets |
| `reveal <name> <field>` | Print one value; Enter clears screen and scrollback |
| `copy <name> [field]` | Copy with expiry (`--clip-timeout`, default 10 s) |
| `add <name>` | Create an entry field by field |
| `set <name> <field> [--gen [options]] [--sensitive\|--plain]` | Create or replace a field |
| `unset <name> <field>` | Remove a field |
| `mv <old> <new>`, `mvfield <name> <old> <new>` | Rename an entry or a field |
| `rm <name>` | Delete an entry (type its name to confirm) |
| `gen [--len L] [--classes luds] [--symbols S] [--no-ambiguous] [--words k] [--sep c] [--show]` | Generate and copy, without storing |
| `passwd [--kdf-memory MiB] [--kdf-time t]` | Change the master password (rotates salt and key) |
| `import --from-stdin [--on-conflict abort\|suffix]` | Merge a canonical body from a pipe |
| `doctor` | Report the security posture of the environment |
| `help`, `quit` (`exit`, `lock`) | Help; wipe and exit |

In a session, arguments are separated by spaces; double quotes group, and
`\"` and `\\` are the only escapes. A bare `--` ends the options, so a
name that starts with `--` can be addressed. Names given to a one-shot
command are visible to other processes in the process list; use a session
for names you consider private.

**Master password.** `init` and `passwd` offer a generated passphrase and
strongly recommend it. A password you choose is entered twice and must
have at least 16 characters and an estimated 10^14 guesses; the estimate
is a built-in heuristic (repeats, runs, keyboard rows, words of the
embedded list), not a dictionary attack simulation. `--accept-weak-password`
plus a typed sentence overrides it.

Exit codes: 0 success, 1 user error, 2 wrong password or damaged vault,
3 integrity or rollback refusal, 4 environment refusal, 5 internal error.

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
cargo test --locked --test gen            # T-GEN-1 .. T-GEN-6
cargo test --locked --test cli            # tokenizer, parsers, sanitize, strength, doctor
cargo test --locked --test e2e            # T-E2E-1 .. T-E2E-12 through a PTY
PWV_REQUIRE_X11=1 xvfb-run -a cargo test --locked --test clip   # T-CLIP-1 .. T-CLIP-4 (needs xclip)
cargo +nightly miri test --no-default-features --test format   # T-SAN-2 (format)
cargo +nightly fuzz run fuzz_body -- -max_total_time=60   # T-FUZZ-2 (see fuzz/README.md)
cargo +nightly fuzz run --features testkdf fuzz_open -- -max_total_time=60   # T-FUZZ-3
cargo +nightly fuzz run fuzz_tokenizer -- -max_total_time=60   # T-FUZZ-4
cargo +nightly fuzz run fuzz_sanitize -- -max_total_time=60    # T-FUZZ-5
```

## Word list

Passphrases use the embedded list `src/wordlist.txt`: 205,690 unique
lower-case words (5 to 24 letters; four contain a hyphen), SHA-256
`9b7bb4cc2ede3e5573174339e0547c774b67e769cfda1fbbc93038ec66a93320`,
supplied by the project owner in place of the EFF large list (spec Section
10.3). Each word carries about 17.65 bits; the 6-word default about 105.9.
The list is MIT-licensed: Copyright (c) 2012 Rochester Institute of
Technology. The full licence text is in `src/wordlist.LICENSE`; it must
accompany any copy of the list, including release artefacts (the binary
embeds the list).

## Migrating from `encrypted_pw_mgr.py`

The legacy program keeps its vault as JSON encrypted by GnuPG. The one-off
migration is a pipe; the plaintext never touches a disk:

    python3 -I tools/migrate_legacy.py --vault <legacy vault> | pwv import --from-stdin

1. `gpg` asks for the **legacy** passphrase first (the script never sees
   it). The script then prints `N entries, M fields, K warnings` and any
   refusals, by entry name only.
2. Then `pwv` asks for its **master password**. It asks only after the
   pipe has ended, so the two prompts never overlap, and not at all if the
   legacy side failed.
3. A name already in the vault aborts the import; add
   `--on-conflict suffix` to import it as `<name> (imported)`.

The script needs Python 3 and GnuPG 2.2.7 or later, nothing from PyPI.
Fields named like a secret (`password`, `pin`, `api key`, ...; spec
Section 9.3) become sensitive. A missing value (`null`, which the legacy
password generator could store) becomes empty, with a warning. Two keys
in one entry that differ only in letter case, control characters, and
values that are not text abort the whole migration, listing every
affected entry: fix them in the legacy program and run it again.

Checklist (spec Section 12.3):

- [ ] Run `pwv init`, then the migration pipe; compare the counts.
- [ ] Spot-check three entries with `show` and `reveal`.
- [ ] Securely delete the legacy files: the encrypted vault, its dumps
      (`password_dump-*.enc`), and especially any `password_dump.txt`.
- [ ] If `password_dump.txt` ever existed on a synced or indexed folder,
      rotate the credentials it contained, starting with email and
      financial accounts.

Run the migration once, preferably with swap disabled
(`sudo swapoff -a`): Python cannot wipe the decrypted data from its
memory.
