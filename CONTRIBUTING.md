# Contributing to pwv

Thank you for helping. pwv is a password manager, so every change is held
to a high bar: it must keep secrets safe, stay small enough to review in
one sitting, and come with tests that prove it. This guide explains how
to get a change accepted with as little back-and-forth as possible.

**Security vulnerabilities:** do not open an issue or pull request.
Report them privately as described in [`SECURITY.md`](SECURITY.md).

**Never** put real passwords, vault files, or other secrets into an issue,
a pull request, a test, a log, or a commit. Use throwaway values.

## Contents

- [What contributions are welcome](#what-contributions-are-welcome)
- [Before you start](#before-you-start)
- [Setting up](#setting-up)
- [How the code is organised](#how-the-code-is-organised)
- [The rules](#the-rules)
- [Tests](#tests)
- [Before you open a pull request](#before-you-open-a-pull-request)
- [Pull requests and review](#pull-requests-and-review)
- [What CI checks](#what-ci-checks)
- [Recording decisions: `docs/DESIGN_NOTES.md`](#recording-decisions-docsdesign_notesmd)
- [Licence](#licence)

## What contributions are welcome

- Bug reports with a way to reproduce them, and fixes for them.
- Tests that make existing guarantees stricter, or that find a bug.
- Documentation fixes: anything unclear, wrong, or out of date.
- Reviews of security-relevant code (`sys`, `secmem`, `alloc`, `crypto`,
  `format`, `store`): questions and findings are valuable even without a
  patch.
- Small, focused improvements that keep the code at the same size or make
  it smaller.

Likely to be declined, because version 1 deliberately leaves them out:
sync, a graphical interface, browser integration, autotype, TOTP codes,
sharing, plain-text export, multiple vaults per session, Windows or macOS
support (see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), "Non-goals"). New
runtime dependencies are also very unlikely to be accepted (see
[The rules](#the-rules)). If you want to propose one of these anyway,
open an issue first and explain the case.

## Before you start

- **Small fixes** (typos, an obvious bug with a test): open a pull request
  directly.
- **Anything larger** (a new command or option, a change to the file
  format, the save protocol, memory handling or cryptography, a new
  dependency): open an issue first and describe what you want to change
  and why. Agreeing on the approach first saves you from writing code that
  cannot be merged.
- Check open issues and pull requests to avoid duplicate work, and say in
  the issue that you are working on it.

## Setting up

You need **Linux** (x86_64 or aarch64) and [rustup](https://rustup.rs).
The Rust version is pinned in `rust-toolchain.toml`; rustup installs it,
with `rustfmt` and `clippy`, the first time you run `cargo` in the
repository.

```sh
git clone https://github.com/TheDansmod/password_manager.git pwv
cd pwv
cargo build --locked
cargo test --locked
```

Always pass `--locked`: dependency versions are pinned in `Cargo.lock`, and
CI fails if the lock file would change.

Optional tools, for the checks that need them (CI runs all of them, so you
only need what your change touches):

| Tool | Used for |
| --- | --- |
| Rust nightly (`rustup toolchain install nightly`) | Miri, fuzzing, AddressSanitizer |
| `cargo-fuzz` | Fuzz targets (`fuzz/README.md`) |
| `xvfb-run` and `xclip` | Clipboard tests |
| `gpg` | Legacy-migration tests (`tests/mig.rs`) |
| `tokei` | Line-count budget (`scripts/loc_budget.py`) |
| `cargo-deny`, `cargo-audit` | Dependency licence and advisory checks |
| `cargo-mutants` | Mutation testing (slow) |
| Python 3 | Scripts in `scripts/` (standard library only, except `verify_golden.py`: `argon2-cffi`, `pynacl`) |

## How the code is organised

One crate with a library (used by tests and fuzzing) and a thin binary.
Modules are layered; a module may use only modules below it, and a test
(`tests/eng.rs`) enforces this:

```text
cli                               commands, session loop, prompts
clip  term  store  vault  gen     clipboard, terminal I/O, file storage, entries, generator
format  crypto                    file format parser/writer, encryption
secmem                            the locked memory region that holds secrets
sys                               system calls (the only Linux-specific code)
alloc                             memory allocator that wipes freed memory (independent)
```

Other places:

| Path | Contents |
| --- | --- |
| `tests/` | Integration tests, one file per area (`format.rs`, `store.rs`, `e2e.rs`, ...) |
| `tests/vectors/` | Golden vault files; `docs/FORMAT.md` annotates one of them byte by byte |
| `fuzz/` | Fuzz targets and their seed corpora |
| `scripts/` | CI helpers: coverage report, test-ID inventory, line-count budget, release build, mutation testing |
| `tools/` | The legacy migration script (not part of the binary) |
| `coverage/baseline.json` | Coverage figures no module may fall below |
| `docs/SPECIFICATION.md` | The design specification: threat model, memory design, cryptography, file format, storage, commands, test plan |
| `docs/FORMAT.md` | The vault file format, normative |
| `docs/THREAT_MODEL.md` | What pwv defends against, and what it does not |
| `docs/DESIGN_NOTES.md` | Dated record of decisions, deviations and exceptions (newest last) |
| `docs/DEVELOPMENT.md` | Full list of checks, CI workflows, release procedure |

Code comments and notes often cite "spec Section N" or test IDs such as
`T-STORE-3`. The section numbers refer to pwv's design specification,
[`docs/SPECIFICATION.md`](docs/SPECIFICATION.md), which explains the
reasoning behind every rule below; where a dated entry in
`docs/DESIGN_NOTES.md` records a later decision, that entry wins. The test IDs and what proves each one are listed by
`python3 -I scripts/test_ids.py --markdown`.

## The rules

These are not style preferences: each one protects a security property,
and CI or review enforces it. A pull request that breaks one will not be
merged, however useful it is otherwise. If a rule blocks something you
think is right, open an issue and make the case; do not work around it.

**Secrets**

1. **Secrets live only in the secure arena** (`secmem`). A password,
   key, or field value must never be stored in a `String`, `Vec`, `Box`,
   heap array, or `static`, not even briefly. Pass secrets as `&[u8]`
   borrowed from an arena slot.
2. **Nothing secret leaves the process except where documented**: never
   write plaintext to disk, a log, standard error, or a panic message,
   including while debugging. Use the test-only `memtest` hooks instead of
   print statements.
3. **Error messages carry no data**: never a secret, an entry name, a
   field key or value, or file contents. Parsers report positions and the
   name of the violated constraint only. Each kind of failure has one
   fixed message.
4. **All terminal output** goes through `term`, and everything derived
   from vault content passes through `term::sanitize`.
5. **All disk writes** go through `store`'s atomic save protocol (write a
   temporary file, `fsync`, rename, `fsync` the directory).

**Code**

6. **`unsafe` only in `sys`, `secmem` and `alloc`.** Every `unsafe` block
   is as small as possible, has a `// SAFETY:` comment stating the
   invariant it relies on, and is executed by at least one test (CI checks
   that every `unsafe` block is fully covered).
7. **No panics in production code:** no `unwrap`, `expect`, `panic!`, or
   direct indexing (`x[i]`); use `get`, `checked_*` arithmetic and
   `try_from` for casts. Clippy denies these outside tests.
8. **Fail closed.** If a safety check cannot be performed, report it and
   stop, unless the user passed a documented override flag.
9. **Keep it small and plain.** Each group of modules has a hard line-count
   cap (`python3 -I scripts/loc_budget.py src` shows them); the code is
   close to some of them, so prefer deleting code to adding abstractions.
   No new traits, generics or macros beyond what already exists.
10. **No new runtime dependency** without an issue agreeing to it first
   and a dated justification in `docs/DESIGN_NOTES.md` that explains why 50
   lines written by hand would not do. Dev-only dependencies (for tests)
   are less strict but still need a reason.
11. **When you use a third-party API**, check it against the exact version
   in `Cargo.lock` (its documentation or source) and note that version in
   a comment where you first use it.
12. **Every public item has a doc comment** stating its preconditions and,
   where relevant, how it handles secrets (for example "borrows the key;
   never copies it").

**Tests**

13. **Tests may only become stricter.** Never delete, weaken, `#[ignore]`,
   or loosen a tolerance in an existing test to make a change pass; fix
   the code. If you believe a test is wrong, say so in the pull request
   and explain why.
14. **New code needs tests**, and new parsing code needs a fuzz target and
   a test with truncated input.
15. **Changes to the file format** need an issue first; they require a
   new format version, updates to `docs/FORMAT.md`, and new golden vectors.

## Tests

Run these before opening a pull request (a few minutes on a laptop):

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --features memtest,testkdf
```

Feature flags used only by tests (never in releases; CI checks this):

- `testkdf` lowers the minimum key-derivation cost so that tests run fast.
- `memtest` adds hooks that let tests inspect the secure arena.

Run the tests of the area you changed in more depth, for example
`cargo test --locked --test store` or the clipboard tests under
`xvfb-run`. [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) lists every check, with the
test IDs each one covers. Some tests are slow (the save-protocol kill loop,
Miri); CI runs them for you.

Tests must not depend on the machine they run on beyond what is documented
(Linux, a terminal for the PTY tests), must not touch the user's real vault
or home directory (use temporary directories and `--vault`), and must not
be timing-sensitive without a generous margin.

## Before you open a pull request

- [ ] The four commands under [Tests](#tests) pass.
- [ ] `python3 -I scripts/loc_budget.py src` reports every group within its
      cap (needs `tokei`; CI also checks it).
- [ ] New production code is covered by tests (CI measures this; see
      [What CI checks](#what-ci-checks)).
- [ ] User-visible changes are documented in `README.md`; format changes in
      `docs/FORMAT.md`.
- [ ] Decisions, deviations and exceptions are recorded in
      `docs/DESIGN_NOTES.md`.
- [ ] Commits are focused, with messages that say what changed and why
      (a short summary line, then details if needed).

## Pull requests and review

1. Fork the repository (or create a branch if you have write access) and
   branch from `main`.
2. Open the pull request against `main` and fill in the template,
   including the review checklist. Draft pull requests are welcome for
   early feedback.
3. CI runs automatically on the pull request (pushes to a branch without
   a pull request do not start CI; open a draft pull request to get it). For first-time contributors, a maintainer has to
   approve the CI run first; this is a GitHub safeguard, not a judgement
   of your change.
4. The maintainer reviews every change. Expect questions, especially on
   code that touches secrets, `unsafe`, the file format, or the save
   protocol. Please reply to each comment, and push fixes as new commits
   so the review is easy to follow.
5. A pull request is merged when the required CI check (`ci-ok`) is green,
   every review conversation is resolved, and the maintainer approves.
   Pull requests are squash-merged into one commit on `main`.

Please be patient and kind; this is a small project. Reviews may take a
few days.

**Tools that generate code** (including AI assistants) are fine to use,
but you are responsible for every line you submit: you must understand
it, and it must follow the rules above. pwv itself was written with an AI
coding assistant under these same rules.

## What CI checks

On every pull request, CI runs (about an hour): formatting, Clippy, the
line-count budget and other code-structure checks; the whole test suite
in several feature configurations, debug and release; end-to-end tests
through a real terminal, with the clipboard under a virtual X server; an
independent check of the golden vault files; one minute of fuzzing per
target; dependency licence and advisory checks; a reproducible release
build; and coverage. The single check `ci-ok` passes only if all of them
pass.

**Coverage** is measured across five build configurations and merged.
The five core modules (`format`, `crypto`, `gen`, `store`, `vault`) need at
least 95 % of their lines covered and every function called; all `unsafe`
blocks must be fully covered; overall coverage must stay at or above 85 %,
and no module may drop more than 0.5 points below `coverage/baseline.json`.
A line that cannot reasonably be covered (for example a defensive error
path the operating system never takes) can be listed, with a reason,
under "Coverage exceptions" in `docs/DESIGN_NOTES.md`. The `coverage-report`
job's summary shows exactly which lines are uncovered.

**Nightly** (on `main`), CI also runs Miri and AddressSanitizer, long
fuzzing, the save protocol under simulated power loss, tests on aarch64,
branch coverage and a performance check. **Weekly**, mutation testing
checks that the tests catch deliberately planted bugs. These do not block
a pull request; if one fails after a merge, the maintainer follows up,
and may ask you for help.

## Recording decisions: `docs/DESIGN_NOTES.md`

`docs/DESIGN_NOTES.md` is the project's memory. Add a dated entry at the end
(`## YYYY-MM-DD — short title`) when your change:

- deviates from a rule above, or interprets something ambiguous;
- adds a dependency (with the justification described in rule 10);
- adds a coverage exception (in the "Coverage exceptions" table, with the
  date and the reason);
- leaves a surviving mutant (in the "Surviving mutants" table, with its
  exact `cargo-mutants` name, the date, and why no test can catch it).

Keep entries factual: what changed, why, and how it was checked.

## Licence

pwv is licensed under the MIT licence ([`LICENSE`](LICENSE)). By submitting
a contribution, you agree that it is licensed under the same terms.
