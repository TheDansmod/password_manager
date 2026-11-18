#!/usr/bin/env python3
"""One-off migration of a legacy `encrypted_pw_mgr.py` vault into pwv.

    python3 -I tools/migrate_legacy.py --vault <legacy file> | pwv import --from-stdin

The legacy vault is JSON, `{entry: {key: value}}`, encrypted by GnuPG with
a passphrase. This script lets `gpg` decrypt it (gpg asks for the legacy
passphrase on the terminal; the passphrase never enters this process),
validates the structure, and writes a canonical pwv body (docs/FORMAT.md,
Section 3) to the pipe. `pwv import` validates that body again with its
strict parser, and asks for the master password only after this script
has finished.

The plaintext exists only in memory and in the two pipes: the script
refuses to run unless its standard output is a pipe. The decrypted data is
parsed as JSON and by nothing else: no parser that can execute code is
ever applied to it. Python cannot wipe its strings, so run this once,
preferably with swap disabled (`sudo swapoff -a`).

Standard library only. Needs GnuPG 2.2.7 or later as `gpg` on PATH.
"""

import argparse
import gc
import json
import os
import stat
import struct
import subprocess
import sys

# Keys whose fields are sensitive by default (spec Section 9.3), compared
# after folding A-Z only, as pwv does.
SENSITIVE = {b"password", b"passphrase", b"pin", b"secret", b"otp", b"totp", b"cvv",
             b"token", b"api key", b"recovery codes"}
# Unicode White_Space, as Rust's char::is_whitespace (docs/FORMAT.md).
WHITE = set(map(chr, [*range(9, 14), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B),
                      0x2028, 0x2029, 0x202F, 0x205F, 0x3000]))
MAX_ENTRIES, MAX_NAME, MAX_FIELDS, MAX_KEY, MAX_VALUE, BLOCK = 10_000, 256, 64, 64, 4096, 4096


class Abort(Exception):
    """A refusal; the message never contains a key or a value."""


def control(text, lf_ok=False):
    """Whether `text` has a control character (category Cc); LF if not `lf_ok`."""
    return any((ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F) and not (lf_ok and c == "\n")
               for c in text)


def unique(pairs):
    """JSON object hook: an object with a repeated key is refused."""
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate key")
    return obj


def refuse_constant(_):
    raise ValueError("NaN or Infinity")


def decrypt(path):
    """The plaintext of the legacy vault, decrypted by gpg (never by a fallback)."""
    cmd = ["gpg", "--quiet", "--no-symkey-cache", "--pinentry-mode", "loopback",
           "--decrypt", "--", path]
    try:
        done = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)
    except OSError:
        raise Abort("cannot run gpg (GnuPG 2.2.7 or later is needed on PATH)") from None
    if done.returncode != 0:
        raise Abort("gpg could not decrypt the vault (wrong passphrase, or not a GnuPG file)")
    return done.stdout


def utf8(text):
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return None


def convert(data):
    """Validates the legacy structure. Returns (model, warnings, problems);
    each warning and problem names an entry and a rule, never a key or value."""
    if not isinstance(data, dict):
        raise Abort("the vault is not a JSON object of entries")
    if len(data) > MAX_ENTRIES:
        raise Abort(f"more than {MAX_ENTRIES} entries")
    model, warnings, problems = [], [], []
    for name, fields in data.items():
        shown = json.dumps(name)  # ASCII only: controls and bidi marks are escaped
        bad = []
        raw_name = utf8(name)
        if raw_name is None or not 1 <= len(raw_name) <= MAX_NAME:
            bad.append(f"the name must be 1 to {MAX_NAME} bytes of UTF-8")
        elif control(name):
            bad.append("control character in the name")
        elif name[0] in WHITE or name[-1] in WHITE:
            bad.append("leading or trailing whitespace in the name")
        if not isinstance(fields, dict):
            problems.append(f"entry {shown}: not an object of fields")
            continue
        if len(fields) > MAX_FIELDS:
            bad.append(f"more than {MAX_FIELDS} fields")
        out, seen = [], set()
        for key, value in fields.items():
            raw_key = utf8(key)
            if value is None:  # legacy bug B2: a refused password length stored None
                warnings.append(f"entry {shown}: an empty value replaces a missing one")
                value = ""
            if not isinstance(value, str):
                bad.append("a value is not text")
                continue
            raw_value = utf8(value)
            if raw_key is None or not 1 <= len(raw_key) <= MAX_KEY:
                bad.append(f"a key must be 1 to {MAX_KEY} bytes of UTF-8")
            elif control(key):
                bad.append("control character in a key")
            elif raw_key.lower() in seen:  # bytes.lower folds A-Z only
                bad.append("two keys differ only in letter case")
            elif raw_value is None or len(raw_value) > MAX_VALUE:
                bad.append(f"a value must be at most {MAX_VALUE} bytes of UTF-8")
            elif control(value, lf_ok=True):
                bad.append("control character other than a line feed in a value")
            else:
                seen.add(raw_key.lower())
                out.append((raw_key, raw_key.lower() in SENSITIVE, raw_value))
        problems.extend(f"entry {shown}: {b}" for b in dict.fromkeys(bad))
        if not bad:
            model.append((raw_name, out))
    return sorted(model), warnings, problems


def encode(model):
    """The canonical body: entries in byte order of their names, fields in
    their original order, zero padding to the next multiple of 4,096."""
    content = bytearray()
    for name, fields in model:
        content += struct.pack("<H", len(name)) + name + struct.pack("<H", len(fields))
        for key, sensitive, value in fields:
            content += bytes([len(key)]) + key + bytes([int(sensitive)])
            content += struct.pack("<H", len(value)) + value
    body = b"PWVB" + struct.pack("<II", len(content), len(model)) + bytes(content)
    return body + bytes(-len(body) % BLOCK)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--vault", required=True, help="the legacy vault file (no default)")
    args = ap.parse_args()
    try:
        if not stat.S_ISFIFO(os.fstat(1).st_mode):
            raise Abort("standard output must be a pipe into `pwv import --from-stdin`; "
                        "a terminal or a file is refused, so the plaintext never lands "
                        "on screen or on disk")
        plain = decrypt(args.vault)
        try:
            data = json.loads(plain.decode("utf-8"), object_pairs_hook=unique,
                              parse_constant=refuse_constant)
        except (ValueError, RecursionError):
            raise Abort("the decrypted data is not the legacy JSON; nothing was "
                        "interpreted or written") from None
        model, warnings, problems = convert(data)
        for line in warnings:
            sys.stderr.write(f"warning: {line}\n")
        if problems:
            for line in problems:
                sys.stderr.write(f"refused: {line}\n")
            raise Abort("nothing was written; correct these entries in the legacy "
                        "program and run the migration again")
        body = encode(model)
        try:
            sent = 0
            while sent < len(body):
                sent += os.write(1, body[sent:])
        except OSError:
            raise Abort("the reader of the pipe went away") from None
        fields = sum(len(f) for _, f in model)
        sys.stderr.write(f"{len(model)} entries, {fields} fields, {len(warnings)} warnings\n")
        del plain, data, model, body  # best effort only: Python does not wipe memory
        gc.collect()
    except Abort as e:
        sys.stderr.write(f"migrate_legacy: {e}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
