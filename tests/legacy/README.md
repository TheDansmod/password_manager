# Legacy program (T-MIG-1)

- `encrypted_pw_mgr.py`: the owner's legacy program, copied unchanged
  from `/workspace/encrypted_pw_mgr.py` (2026-11-16). Never edited: the
  T-MIG-1 fixture must come from the original code.
- `make_fixture.py`: imports it and calls its own `encrypt_data` (and its
  `add_secure_password` for the `None` value of audit finding B2), so the
  fixture is written by the legacy `json.dumps` and GnuPG arguments. The
  test data arrives on stdin; no plaintext file is written.

Run by `tests/mig.rs` when `PWV_LEGACY_PYTHON` names a Python with
`python-gnupg`, `rich`, and `pyperclip` (CI job `e2e`, pinned versions).
