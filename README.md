# pwv

[![ci](https://github.com/TheDansmod/password_manager/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/TheDansmod/password_manager/actions/workflows/ci.yml)
![line coverage](https://raw.githubusercontent.com/TheDansmod/password_manager/badges/coverage.svg)
![Section 14 test IDs passing](https://raw.githubusercontent.com/TheDansmod/password_manager/badges/test-ids.svg)

**pwv is a small, offline password manager for the Linux terminal.** It
keeps your passwords and other secrets in one encrypted file on your own
disk, and it is built to leave as few traces of them as possible: on disk,
in memory, on screen, and on the clipboard.

> **Status: pre-release.** Every feature is implemented and tested, but
> there is no published release yet; until there is, [build it from
> source](#building-from-source).

## Why pwv

- **Everything is encrypted, names included.** The vault is one file
  encrypted as a whole (XChaCha20-Poly1305, key derived with Argon2id at
  256 MiB by default). Without the master password, it does not reveal
  how many entries you have, what they are called, or which sites you
  use; only roughly how big it is. Any change to the file is detected.
- **Secrets stay out of memory leaks.** While the vault is open, every
  secret lives in one locked memory region that never goes to swap or
  into a core dump, and it is wiped when you lock or quit. Other programs
  running as you cannot attach a debugger to pwv or read its memory.
- **Safe saves.** Every change is saved at once, atomically: after a crash
  or power cut you have either the old vault or the new one, never a
  broken one. The five previous versions are kept next to it. If someone
  swaps in an older copy of your vault, pwv notices and warns you.
- **Careful on screen and clipboard.** Secret values are masked unless you
  ask for one. Copies expire from the clipboard after 10 s, are flagged
  so that clipboard managers that honour the hint keep them out of their
  history, and are cleared before pwv exits. `reveal` clears the screen
  and the scrollback afterwards.
- **Good generator.** Random passwords and passphrases drawn exactly
  uniformly from the operating system's random source, with the strength
  shown in bits. The default passphrase has six words from a list of
  205,690 (about 106 bits).
- **Nothing else to trust.** No network access, no cloud account, no
  browser extension, no plugins, no helper processes: one binary and one
  file. The code is small, and each of the properties above is checked by
  automated tests (see the badges). Releases are built reproducibly
  and signed by GitHub's build system, so you can check that a download
  is exactly what this repository builds.

**pwv is probably not for you if** you need sync between devices, a
browser extension or autofill, a graphical interface, Windows or macOS,
TOTP codes, or sharing with other people. Tools such as KeePassXC,
Bitwarden or `pass` offer those. pwv trades them for a smaller,
offline, terminal-only design. You can still sync the vault file
yourself (it is safe to store on cloud storage), but pwv does not merge
copies edited in two places.

**There is no recovery.** If you forget your master password, your
vault cannot be opened, by you or by anyone else. Keep a copy of the
master password somewhere safe.

## Quick start

### 1. Install

Linux only. Releases are for x86_64; on aarch64 (and until the first
release), [build from source](#building-from-source).

From a release: download `pwv-<version>-x86_64-linux` and `SHA256SUMS`
from the [releases page](https://github.com/TheDansmod/password_manager/releases),
[verify them](#verifying-a-release), then:

```sh
install -m 0755 pwv-<version>-x86_64-linux ~/.local/bin/pwv
```

From source (needs [Rust](https://rustup.rs); the right version is picked
up automatically):

```sh
git clone https://github.com/TheDansmod/password_manager.git pwv
cd pwv
cargo build --locked --release
install -m 0755 target/release/pwv ~/.local/bin/pwv
```

### 2. Check your system

```sh
pwv doctor
```

This reports anything on your machine that weakens pwv's protections
(unencrypted swap, hibernation, core dumps, memory-locking limits, the
vault's location), each with a one-line fix.

### 3. Create a vault and use it

```text
$ pwv init                 # create the vault and choose a master password
$ pwv                      # unlock and start a session
pwv> add github            # add an entry, one field at a time
Field key (. to finish): username
Value: typed, hidden, or gen [options]? [typed]
Value: octocat
Field key (. to finish): password
Value: typed, hidden, or gen [options]? [hidden] gen
Field key (. to finish): .
pwv> ls                    # list entry names
pwv> show github           # the password is shown as ••••••••
pwv> copy github           # copy the password; cleared after 10 s
pwv> quit                  # wipe memory and exit
```

`init` offers a generated six-word passphrase as your master password. Take
it unless you have a good reason not to (see [Master
password](#master-password)).

Every command also works on its own, without a session:

```sh
pwv copy github            # unlock, copy, wait until the copy expires
pwv gen --words 6 --show   # a new passphrase; no vault needed
```

## Using pwv

### Entries and fields

A vault holds **entries** (for example `github` or `bank`). Each entry
holds **fields**: a key such as `username`, `password` or `recovery codes`,
and a value. Fields are either plain (shown by `show`) or **sensitive**
(masked as eight bullets, whatever their length). A field is sensitive
automatically when its key is one of `password`, `passphrase`, `pin`,
`secret`, `otp`, `totp`, `cvv`, `token`, `api key` or `recovery codes`
(any letter case), or when its value was generated. `--sensitive` and
`--plain` override this.

### Commands

| Command | What it does |
| --- | --- |
| `init [--kdf-memory MiB] [--kdf-time t]` | Create a vault |
| `ls [pattern]` | List entry names (case-insensitive substring) |
| `show <name>` | Show an entry; sensitive values masked |
| `reveal <name> <field>` | Print one value; press Enter to clear the screen and scrollback |
| `copy <name> [field]` | Copy a value (default: the first sensitive field); it expires from the clipboard |
| `add <name>` | Create an entry, field by field (`typed`, `hidden`, or `gen [options]`; `.` to finish) |
| `set <name> <field> [--gen [options]] [--sensitive\|--plain]` | Create or replace one field |
| `unset <name> <field>` | Remove a field |
| `mv <old> <new>` | Rename an entry |
| `mvfield <name> <old> <new>` | Rename a field |
| `rm <name>` | Delete an entry (you type its name to confirm) |
| `gen [options]` | Generate a password or passphrase and copy it, without storing it |
| `passwd [--kdf-memory MiB] [--kdf-time t]` | Change the master password (re-encrypts everything with new keys) |
| `import --from-stdin [--on-conflict abort\|suffix]` | Add entries from a pipe (see [Importing](#importing)) |
| `doctor` | Check the system's security settings |
| `help` | List the commands |
| `quit` (or `exit`, `lock`) | Wipe memory and exit |

Changes are saved immediately; there is no "save" command and nothing to
lose on exit. Commands that only read (`ls`, `show`, `reveal`, `copy`,
`gen`) never write to the vault.

**Arguments** are separated by spaces. Put names that contain spaces in
double quotes (`show "my bank"`); inside quotes, `\"` and `\\` are the
only escapes. A bare `--` ends the options, for names that start with `--`.

**Session or one-shot?** In a session you unlock once and run many
commands. A one-shot command (`pwv show github`) unlocks, runs, and exits.
Arguments of one-shot commands, such as entry names, are visible to other
users in the process list; use a session for names you want to keep
private. Sessions lock themselves after 5 minutes without input.

### Generating passwords

```text
gen                          20 characters: lower, upper, digits, symbols (~131 bits)
gen --len 32                 a longer password (8 to 128)
gen --classes lud            only lower case, upper case and digits
gen --symbols '!@#%'         only these symbols
gen --no-ambiguous           without the look-alikes I l 1 O 0 ` ' "
gen --words 6 --sep .        a 6-word passphrase (4 to 16 words), words joined by .
gen ... --show               also print it (by default it is only copied)
```

The same options work in `add` (answer `gen [options]`) and in
`set <name> <field> --gen [options]`. Every listed character class appears
at least once, and every allowed password is equally likely; pwv shows the
resulting strength in bits.

### Clipboard

`copy` puts a value on the clipboard for 10 seconds (`--clip-timeout`, 5 to
300). When the time is up, pwv clears the clipboard if it still holds that
value, and it does the same when it exits. A one-shot `pwv copy` waits
until then; press Enter to clear early. Works on X11 and on Wayland
compositors with the data-control protocol (GNOME uses XWayland).
Clipboard managers that honour KDE's password-manager hint (such as
Klipper) keep the copy out of their history; others may not, which
`doctor` points out.

### Master password

`init` and `passwd` offer a generated six-word passphrase. If you choose
your own instead, it must have at least 16 characters and resist an
estimated 10^14 guesses (pwv penalises repeats, sequences, keyboard rows
and dictionary words), and you type it twice. `--accept-weak-password`,
followed by a typed confirmation, overrides the check.

Opening the vault deliberately takes a noticeable moment (about 0.3 s on
a modern machine): the key is derived with Argon2id using 256 MiB of
memory, which makes every guess just as expensive for an attacker.
`--kdf-memory` and `--kdf-time` on `init` or `passwd` raise this (never
below 64 MiB and 3 passes).

### Options

These go before the command (`pwv --idle-timeout 60`, `pwv --vault x.pwv ls`).

| Option | Default | Meaning |
| --- | --- | --- |
| `--vault <path>` (or `PWV_VAULT`) | see below | Use another vault file |
| `--idle-timeout <s>` | 300 | Lock and exit after this much inactivity (30 to 3600) |
| `--clip-timeout <s>` | 10 | Clipboard expiry (5 to 300) |
| `--arena-size <KiB>` | 1024 | Size of the locked memory for secrets (256 to 6144); raise it for very large vaults |
| `--allow-unlocked-memory` | off | Run even if memory cannot be locked (secrets could reach swap) |
| `--require-locked-kdf` | off | Refuse to run if the key derivation's memory cannot be locked |
| `--allow-foreign-fs` | off | Allow a vault on NTFS, FAT or exFAT, where file permissions are not real |
| `--no-color` (or `NO_COLOR`) | off | No colours or bold text |

### Where things are stored

| What | Where |
| --- | --- |
| Vault | `$XDG_DATA_HOME/pwv/vault.pwv` (normally `~/.local/share/pwv/vault.pwv`) |
| Backups | Next to the vault: `vault.pwv.1` (newest) to `vault.pwv.5` |
| Rollback record | `$XDG_STATE_HOME/pwv/state` (normally `~/.local/state/pwv/state`) |

The vault directory must be yours and private (mode 0700, files 0600);
pwv refuses otherwise and tells you the `chmod` to run. Only one session
can open a vault at a time. To back up, copy the vault file (and its
backups) anywhere; it is useless without the master password. To restore,
copy a backup over `vault.pwv`. If the copy is older than the last version
this machine saw, pwv warns that the vault may have been rolled back and
asks you to type `yes` before opening it.

### Importing

`pwv import --from-stdin` adds entries read from a pipe, in pwv's own
plain-text body format (documented in [`FORMAT.md`](FORMAT.md), Section 3),
for example from a script that converts another manager's data:

```sh
my-converter | pwv import --from-stdin
```

The input is checked strictly; if anything is wrong, or a name already
exists, nothing is imported (`--on-conflict suffix` imports clashes as
`<name> (imported)` instead). pwv has no plain-text export, on purpose:
the vault file itself is the portable copy.

### Exit codes

0 success, 1 user error, 2 wrong password or damaged vault, 3 integrity or
rollback refusal, 4 environment refusal (permissions, memory locking,
filesystem), 5 internal error.

### What pwv cannot protect against

No program can protect your secrets from malware already running as your
user (a keylogger, a modified `pwv`), from root or the kernel, or from
someone with physical access to the running machine. Values you reveal
also pass through your terminal emulator, and values you copy through the
clipboard. [`THREAT_MODEL.md`](THREAT_MODEL.md) lists exactly what pwv
defends against and what it does not. For the best protection, use full
disk encryption, encrypted swap (or none), and no hibernation; `pwv doctor`
checks the last two.

## Building from source

You need Linux, [rustup](https://rustup.rs) and a C linker (`cc`, from
your distribution's build tools). The repository pins its Rust version in
`rust-toolchain.toml`; rustup installs it on first use.

```sh
cargo build --locked --release        # target/release/pwv
cargo build --locked --release --no-default-features   # without clipboard support
```

To build exactly what a release contains, run the release script: it
builds twice from two different directories, checks that both binaries are
identical and hardened, and writes the binary, the licences and
`SHA256SUMS`:

```sh
sh scripts/release_build.sh dist
```

The test suite, the full list of checks CI runs, and the release procedure
are in [`DEVELOPMENT.md`](DEVELOPMENT.md). The vault file format is
specified in [`FORMAT.md`](FORMAT.md).

## Verifying a release

Each release file is built by GitHub Actions from a version tag, and comes
with a signed record (an attestation) of exactly which workflow and commit
built it. Before running a download, check it with the
[GitHub CLI](https://cli.github.com):

```sh
gh attestation verify pwv-<version>-x86_64-linux \
  --repo TheDansmod/password_manager \
  --signer-workflow TheDansmod/password_manager/.github/workflows/release-build.yml
sha256sum -c --ignore-missing SHA256SUMS
```

The first command proves that the file was built by this repository's
release workflow; the second, that it matches the signed checksum list.
The release build also checks that two independent builds of the tagged
commit are byte-identical (reproducible builds). See
[`SECURITY.md`](SECURITY.md) for details and for how to report a
vulnerability privately.

## Licence

pwv is released under the MIT licence; see [`LICENSE`](LICENSE).

## Word list

Passphrases use the embedded list `src/wordlist.txt`: 205,690 unique
lower-case words (5 to 24 letters; four contain a hyphen), SHA-256
`9b7bb4cc2ede3e5573174339e0547c774b67e769cfda1fbbc93038ec66a93320`.
Each word carries about 17.65 bits; the 6-word default about 105.9. The
list is MIT-licensed: Copyright (c) 2012 Rochester Institute of
Technology. The full licence text is in `src/wordlist.LICENSE`; it must
accompany any copy of the list, including release files (the binary
embeds the list), which include it.
