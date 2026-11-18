# Tools

`migrate_legacy.py` (spec Section 12.1, adapted to the legacy program's
real format, `DESIGN_NOTES`, M8): decrypts a legacy `encrypted_pw_mgr.py`
vault (GnuPG-encrypted JSON) with `gpg`, validates it, and writes a
canonical pwv body to a pipe into `pwv import --from-stdin`. Standard
library only. It is not part of the binary, and it is for the owner's own
legacy vault, so the user-facing `README.md` does not describe it. Usage:
the script's docstring. Tests: `tests/mig.rs`.
