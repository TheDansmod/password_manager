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
> source](#building-from-source). pwv has **not yet been independently
> audited** and has no track record of real-world use; see [How pwv
> compares](#how-pwv-compares) before you trust it with your only copy of
> your passwords.

## Why pwv

- **Everything is encrypted, names included.** The vault is one file
  encrypted as a whole (XChaCha20-Poly1305, key derived with Argon2id at
  256 MiB by default). Without the master password, it does not reveal
  how many entries you have, what they are called, or which sites you
  use; only roughly how big it is. Any change to the file is detected.
- **Secrets leave as few traces in memory as possible.** While the vault
  is open, every secret lives in one locked memory region that never goes
  to swap or into a core dump, and it is wiped when you lock or quit.
  Other programs running as you cannot attach a debugger to pwv or read
  its memory (malware that was already running as you before pwv
  started is a different matter; see below).
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
copies edited in two places. For a side-by-side look at what pwv does
better and worse than those tools, see [How pwv compares](#how-pwv-compares).

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
| `passwd [--kdf-memory MiB] [--kdf-time t] [--purge-backups]` | Change the master password (re-encrypts everything with new keys); `--purge-backups` also deletes the backups, which the old password still opens |
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
estimated 10^14 guesses (pwv penalises repeats, sequences, keyboard walks
along rows, columns and diagonals, dictionary words also in "leet"
spelling such as `P@ssw0rd`, years, and common separators between words),
and you type it twice. `--accept-weak-password`, followed by a typed
confirmation, overrides the check. The estimate is a heuristic: it catches
common patterns, not every weak password, which is why the generated
passphrase is the default.

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

After `passwd`, the backups still open with the **old** password until
five more saves have replaced them. If you change the password because
the old one may be known, use `passwd --purge-backups`, which deletes
them once the vault is saved under the new password (copies you made
elsewhere are not affected).

### Importing

`pwv import --from-stdin` adds entries read from a pipe, in pwv's own
plain-text body format (documented in [`docs/FORMAT.md`](docs/FORMAT.md), Section 3),
for example from a script that converts another manager's data. Standard
input must be a pipe; a terminal or a regular file is refused, so the
plain text never has to be written to disk:

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
clipboard. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) lists exactly what pwv
defends against and what it does not. For the best protection, use full
disk encryption, encrypted swap (or none), and no hibernation; `pwv doctor`
checks the last two.

## How pwv compares

This section compares pwv with three popular open-source password managers
**only on what pwv itself does**: keeping a local vault, unlocking it,
showing and copying secrets, generating passwords, and keeping the vault
safe on disk. Browser extensions, autofill, sync services, mobile apps and
sharing are left out; if you need those, pwv is not the right tool anyway.

- **KeePassXC**: a desktop app (with a command-line tool, `keepassxc-cli`)
  using the KeePass file format (KDBX).
- **pass**: "the standard Unix password manager", a shell script that
  keeps each entry as a separate GnuPG-encrypted file.
- **Bitwarden CLI** (`bw`): the command-line client of Bitwarden, an
  account-based manager with a server (Bitwarden's or self-hosted).

What we say about the other tools comes from their documentation, their
maintainers' public statements and published reviews, checked in November
2026 (sources at the end of this section). Where we could not confirm
something, we say **"not checked"** or **"not known to us"**: that means
we don't know, not that the tool lacks it. Corrections are welcome
(open an issue).

### At a glance

| | pwv | KeePassXC | pass | Bitwarden CLI |
| --- | --- | --- | --- | --- |
| Where the vault lives | One encrypted file, local | One encrypted file, local | A folder of encrypted files, one per entry | Your account on a server, cached locally |
| Entry names hidden from someone with the file(s) | Yes | Yes | **No**: file names are in plain text | Yes (encrypted on your device) |
| File size reveals roughly how much is stored | Padded: only an upper bound | Not checked | Yes (one file per entry) | Not applicable (server-side) |
| Default master-password hashing | Argon2id, 256 MiB, 3 passes | Argon2 (d or id, depending on version), 64 MiB, tuned to about 1 s | GnuPG's protection of your private key: iterated hashing, not memory-hard | PBKDF2-SHA256, 600,000 iterations; Argon2id (32 MiB) optional |
| Second factor for unlocking (key file, hardware key) | **No**: password only | **Yes**: key file and/or YubiKey | Your GnuPG key (can live on a smart card) | Account two-step login (protects the server account) |
| Tampering with the file detected | Yes, any byte | Yes | Each file is checked, but entries are not signed: anyone with your *public* key can add or replace an entry | Yes |
| Detects an older copy swapped in (rollback) | **Yes**, warns before opening | Not known to us | No (git history can show it, if you use git) | Not checked |
| Secrets in memory while open | Kept in one locked region: never swapped, excluded from core dumps, wiped on lock and exit; checked by a test that scans the process memory | Blocks debugging and core dumps, zeroes memory it frees; maintainers say memory managed by Qt cannot be locked, and a 2024 report (CVE-2024-33901, disputed) recovered passwords from a memory dump | Secrets pass through shell variables, pipes and `gpg-agent`, which caches your key passphrase | Runs on Node.js, whose memory management does not allow secrets to be reliably wiped |
| Saves survive a crash or power cut | Atomic saves, 5 backups, tested with simulated power loss | Has safe-save and backup options; how they were tested not checked | Ordinary file writes; git history helps you recover | The server holds the authoritative copy |
| Clipboard | Cleared after 10 s (only if it still holds the copy); flagged to stay out of clipboard history | Cleared after a configurable timeout; details not checked | Restored to its previous content after 45 s | Not checked |
| Password generator | Exactly uniform (proven and tested); shows bits | Shows entropy; uniformity not checked | Reads `/dev/urandom`; uniformity not checked | Yes; uniformity not checked |
| Platforms | Linux only | Linux, Windows, macOS | Linux, macOS, BSD | Linux, Windows, macOS |
| Open the vault in other apps | **No**: pwv's own format, and no export | **Yes**: many KeePass-compatible apps on every platform | Yes: any GnuPG tool reads each file | Export to several formats |
| Independent security review | **None yet** | Independent review in 2023 (positive) | None known to us (a very small script on top of GnuPG, which is widely scrutinised) | Regular third-party audits published |
| Years of real-world use | **None** | About ten | More than ten | About ten |

### Where pwv is stronger

- **Protecting secrets in memory.** This is pwv's main difference. While
  the vault is open, every secret sits in one memory region that is
  locked (never written to swap), left out of core dumps, and wiped when
  you lock or quit; a test plants known values and scans the running
  program's memory to check that none leak. KeePassXC's maintainers
  describe its protection as keeping other programs out rather than
  keeping secrets out of ordinary memory, and accept that decrypted data
  can remain readable to someone who already has your user rights. Note
  that pwv cannot stop such an attacker either (see [What pwv cannot
  protect against](#what-pwv-cannot-protect-against)); it limits what
  is left behind afterwards: in swap, in crash dumps, or in memory after
  the vault is locked.
- **Rollback warning.** If someone replaces your vault with an older copy
  (for example through a sync folder), pwv notices and asks before
  opening it. We know of no such check in the other three.
- **A harder-to-guess vault by default.** pwv's default password hashing
  uses 256 MiB of memory per guess, against 64 MiB (KeePassXC) and 32 MiB
  or PBKDF2 (Bitwarden). That makes each guess against a stolen vault
  more expensive. KeePassXC lets you raise its setting; its own 2023
  reviewer recommended stronger defaults.
- **Names and size stay private.** Unlike `pass`, nobody with your files
  can see which sites you have accounts for, and pwv pads the vault so
  its size does not reveal how many entries you have.
- **Tested durability and testing depth.** pwv's saves are tested under
  simulated power loss, and its code is checked by mutation testing (the
  tests must catch deliberately planted bugs), memory-error detectors,
  fuzzing and over 96 % line coverage. Whether the other projects do the
  same is **not known to us**: we did not review their test suites.
- **Verifiable releases.** Release files are built reproducibly (two
  builds must be identical) and signed by GitHub's build system, so you
  can check where a download came from. Whether the others' releases are
  reproducible was **not checked**; KeePassXC signs its releases with
  GnuPG (how the others sign theirs was not checked).
- **Small and offline.** One binary, no network code, no account, no
  helper processes. The code is small enough to be reviewed in full.

### Where pwv is weaker

- **No independent review and no track record.** The other three have had
  outside reviews or years of use by many people who report bugs. pwv
  has neither yet. It has one maintainer and was written with the help of
  an AI coding assistant; its tests are thorough, but they were written
  by the same project, so they share its blind spots. **This is the most
  important difference today.** Until pwv has been reviewed and used for
  a while, consider keeping your existing password manager alongside it.
- **Password only.** KeePassXC can require a key file or a YubiKey as
  well, so a stolen file plus a guessed password is not enough. pwv
  relies on the master password alone (which is why it suggests a
  generated six-word passphrase and uses expensive hashing).
- **Your data is tied to pwv.** The vault format is pwv's own, only pwv
  opens it, only on Linux, and there is deliberately no plain-text
  export. KeePassXC's files open in many apps on every platform. If pwv
  stopped being maintained, you would need to build it yourself to get
  your data out.
- **Less history.** pwv keeps the five previous versions of the whole
  vault, not a history per entry as KeePassXC does.
- **One machine at a time.** You can copy or sync the vault file, but pwv
  cannot merge changes made on two machines. If both copies are edited,
  whichever file your sync keeps wins and the other machine's changes
  are lost. pwv warns only when a vault is older than one it saved
  itself, which does not cover every such case.
- **Linux and the terminal only.** No Windows, macOS, phone or graphical
  version.

### Which should you choose?

- **You want the most protection for secrets in memory and on disk, use
  only Linux and the terminal, and accept a new, unaudited tool:** pwv.
- **You want a mature, audited local vault, a second factor (key file or
  YubiKey), or other platforms:** KeePassXC.
- **You want git-based history and sharing through GnuPG, and don't mind
  entry names being visible:** `pass`.
- **You want sync across devices and are happy with a server:** Bitwarden.

### Sources

- KeePassXC: [audit report (2023)](https://keepassxc.org/blog/2023-04-15-audit-report/),
  [the review itself](https://keepassxc.org/assets/pdf/KeePassXC-Review-V1-Molotnikov.pdf),
  [user guide](https://keepassxc.org/docs/KeePassXC_UserGuide),
  [default settings (issue 7396)](https://github.com/keepassxreboot/keepassxc/issues/7396),
  memory protection ([issue 2718](https://github.com/keepassxreboot/keepassxc/issues/2718),
  [issue 7335](https://github.com/keepassxreboot/keepassxc/issues/7335),
  [issue 10784](https://github.com/keepassxreboot/keepassxc/issues/10784)),
  [CVE-2024-33901](https://nvd.nist.gov/vuln/detail/cve-2024-33901).
- pass: [project page](https://git.zx2c4.com/password-store/about/),
  [manual](https://www.mankier.com/1/pass).
- Bitwarden: [key derivation](https://bitwarden.com/help/kdf-algorithms/),
  [security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).
- Privacy of local managers: [BSI study, 2025](https://cyberinsider.com/bsi-finds-security-and-privacy-gaps-in-popular-password-managers/).

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
are in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md); the full design, with the
reasoning behind it, is in [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).

## Contributing

Bug reports, fixes, tests, documentation and security reviews are welcome.
Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first: it explains what
kinds of change fit pwv, the security rules every change must follow, and
how pull requests are reviewed. Report vulnerabilities privately, as
described in [`SECURITY.md`](SECURITY.md), never in a public issue. The vault file format is
specified in [`docs/FORMAT.md`](docs/FORMAT.md).

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
