# Tools

`migrate_legacy.py` (spec Section 12.1, adapted to the legacy program's
real format, `DESIGN_NOTES`, M8): decrypts a legacy `encrypted_pw_mgr.py`
vault (GnuPG-encrypted JSON) with `gpg`, validates it, and writes a
canonical pwv body to a pipe into `pwv import --from-stdin`. Standard
library only. It is not part of the binary. Usage: `README.md`,
"Migrating from `encrypted_pw_mgr.py`". Tests: `tests/mig.rs`.
