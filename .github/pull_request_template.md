<!-- Thank you for contributing to pwv. Please read CONTRIBUTING.md first.
Never paste real passwords, vault files, or other secrets here. -->

## What and why

<!-- What does this change do, and why? Link the issue it addresses (e.g. "Fixes #12"). -->

## How it was tested

<!-- Commands you ran locally (see CONTRIBUTING.md, "Before you open a pull request"),
and any new tests. CI runs the rest. -->

## Review checklist

Answer each item; "n/a" is fine where it does not apply, but say why if it is not obvious.

- [ ] **Secrets:** no new place where secret bytes can exist outside the secure arena (no `String`, `Vec`, `Box`, heap array or `static` holding a secret).
- [ ] **`unsafe`:** any new `unsafe` block is in `sys`, `secmem` or `alloc`, is minimal, has a `// SAFETY:` comment, and is exercised by a test.
- [ ] **Parsing:** any new parsing path has a fuzz target and a truncation test.
- [ ] **Disk writes:** any new on-disk write goes through `store`'s atomic save protocol.
- [ ] **Size:** the line-count caps still hold (`python3 -I scripts/loc_budget.py src`).
- [ ] **Coverage:** every new production line is covered by a test, or justified under "Coverage exceptions" in `docs/DESIGN_NOTES.md`.
- [ ] **Tests:** no existing test was deleted, weakened, ignored or loosened.
- [ ] **Dependencies:** no new runtime dependency, or a dated justification is in `docs/DESIGN_NOTES.md`.
- [ ] **Errors and output:** no error message, log line or panic can contain a secret, an entry name, a field key or value, or file contents.
- [ ] **Docs:** user-visible changes are reflected in `README.md` (and `docs/FORMAT.md` / `docs/THREAT_MODEL.md` if affected); deviations and decisions are recorded in `docs/DESIGN_NOTES.md`.
