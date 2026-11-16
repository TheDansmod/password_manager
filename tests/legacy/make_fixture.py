#!/usr/bin/env python3
"""Writes a legacy vault with the ORIGINAL program's own code (T-MIG-1).

    python make_fixture.py <out file>    (data on stdin, passphrase in
                                          PWV_LEGACY_PASSPHRASE)

`encrypted_pw_mgr.py`, next to this file, is the owner's legacy program,
unchanged. This driver imports it, puts the test data into a
`PasswordManager`, and calls its `encrypt_data`: the file is therefore
written by the legacy `json.dumps` and the legacy GnuPG arguments. Every
value equal to "@@B2@@" is replaced by what the original
`add_secure_password` returns for a length below 8, which is `None`
(audit finding B2).

The data arrives on stdin, so no plaintext is written to disk. It needs
the legacy program's imports (python-gnupg, rich, pyperclip) and `gpg`.
Test data only: never use it with a real vault.
"""

import builtins
import importlib.util
import json
import os
import sys
import types


def main():
    out = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "encrypted_pw_mgr", os.path.join(here, "encrypted_pw_mgr.py"))
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)  # __name__ != "__main__": nothing runs
    data = json.load(sys.stdin)
    # The legacy code reads the passphrase from a module-level `config`.
    legacy.config = types.SimpleNamespace(
        access_password=os.environ["PWV_LEGACY_PASSPHRASE"])
    manager = legacy.PasswordManager.__new__(legacy.PasswordManager)
    asked = builtins.input
    builtins.input = lambda _prompt="": "4"  # "Enter Length: " below 8
    try:
        b2 = manager.add_secure_password()
    finally:
        builtins.input = asked
    if b2 is not None:
        sys.exit("the legacy add_secure_password did not return None for length 4")
    manager.data = {
        name: {key: (b2 if value == "@@B2@@" else value) for key, value in fields.items()}
        for name, fields in data.items()
    }
    manager.encrypt_data(out)
    if not os.path.getsize(out):
        sys.exit("the legacy encrypt_data wrote nothing")


if __name__ == "__main__":
    main()
