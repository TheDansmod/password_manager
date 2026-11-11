#!/usr/bin/env python3
"""T-COMPAT-1, independent half: decrypt every golden vault in
tests/vectors/ with code that shares nothing with pwv (argon2-cffi for
Argon2id, PyNaCl/libsodium for XChaCha20-Poly1305), parse the body, and
compare against tests/vectors/MANIFEST. Also checks T-KAT-2's vector
against libsodium.

Usage: python3 -I scripts/verify_golden.py [tests/vectors]
Requires: argon2-cffi, pynacl (CI pins the versions).
"""

import hashlib
import os
import struct
import sys
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as xdec
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as xenc


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def parse_manifest(text):
    out, cur = [], None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        w = line.split(" ")
        if w[0] == "vault":
            cur = {"file": w[1], "sha256": w[2], "also": [], "model": []}
        elif w[0] == "password":
            cur["password"] = bytes.fromhex(w[1])
        elif w[0] == "also":
            cur["also"].append(bytes.fromhex(w[1]))
        elif w[0] == "generation":
            cur["generation"] = int(w[1])
        elif w[0] == "entry":
            cur["model"].append((bytes.fromhex(w[1]).decode(), []))
        elif w[0] == "field":
            v = w[3] if len(w) > 3 else ""
            f = (bytes.fromhex(w[1]).decode(), w[2] == "1", bytes.fromhex(v).decode())
            cur["model"][-1][1].append(f)
        elif w[0] == "end":
            out.append(cur)
            cur = None
        else:
            fail(f"bad manifest line {line!r}")
    return out


def parse_header(f):
    if len(f) < 184:
        fail("short file")
    h = {}
    (magic, ver, flags, vid, kdf_id, res, m, t, p) = struct.unpack_from(
        "<8sHH16sB3sIII", f, 0
    )
    if (magic, ver, flags, kdf_id, res, p) != (b"PWVAULT\0", 1, 0, 1, b"\0\0\0", 1):
        fail("fixed header fields")
    h.update(m=m, t=t, salt=f[44:76], wrap_nonce=f[76:100], wrapped=f[100:148])
    (h["generation"],) = struct.unpack_from("<Q", f, 148)
    h["payload_nonce"] = f[156:180]
    (h["L"],) = struct.unpack_from("<I", f, 180)
    if h["L"] < 4096 or h["L"] % 4096 or len(f) != 200 + h["L"]:
        fail("payload length")
    return h


def is_ctrl(c, allow_lf=False):
    if allow_lf and c == "\n":
        return False
    return unicodedata.category(c) == "Cc"


def parse_body(b):
    """Strict body parser, written from spec Section 7.2 / 7.3."""
    if b[:4] != b"PWVB":
        fail("body magic")
    c, n = struct.unpack_from("<II", b, 4)
    if 12 + c > len(b) or n > 10000:
        fail("content_len / entry_count")
    if any(b[12 + c :]) or len(b) != -(-(12 + c) // 4096) * 4096:
        fail("padding")
    pos, end, model, prev = 12, 12 + c, [], None
    for _ in range(n):
        (nl,) = struct.unpack_from("<H", b, pos)
        name_b = b[pos + 2 : pos + 2 + nl]
        name = name_b.decode()
        if not 1 <= nl <= 256 or any(is_ctrl(ch) for ch in name) or name != name.strip():
            fail("name")
        if prev is not None and not prev < name_b:
            fail("name order")
        prev = name_b
        pos += 2 + nl
        (fc,) = struct.unpack_from("<H", b, pos)
        pos += 2
        if fc > 64:
            fail("field_count")
        fields, keys = [], set()
        for _ in range(fc):
            kl = b[pos]
            key = b[pos + 1 : pos + 1 + kl].decode()
            flags = b[pos + 1 + kl]
            (vl,) = struct.unpack_from("<H", b, pos + 2 + kl)
            val = b[pos + 4 + kl : pos + 4 + kl + vl].decode()
            if not 1 <= kl <= 64 or flags & 0xFE or vl > 4096:
                fail("field lengths/flags")
            if any(is_ctrl(ch) for ch in key) or any(is_ctrl(ch, True) for ch in val):
                fail("field controls")
            if key.encode().lower() in keys:
                fail("duplicate key")
            keys.add(key.encode().lower())
            fields.append((key, bool(flags & 1), val))
            pos += 4 + kl + vl
        model.append((name, fields))
    if pos != end:
        fail("trailing bytes")
    return model


def open_vault(f, pw):
    h = parse_header(f)
    p = unicodedata.normalize("NFC", pw.decode()).encode()
    kek = hash_secret_raw(p, h["salt"], h["t"], h["m"], 1, 32, Type.ID, 19)
    dek = xdec(h["wrapped"], f[:76], h["wrap_nonce"], kek)
    body = xdec(f[184:], f[:184], h["payload_nonce"], dek)
    return h, parse_body(body)


def kats():
    """T-KAT-2 in libsodium. (T-KAT-1 needs Argon2's secret and associated
    data inputs, which argon2-cffi's low-level API does not expose.)"""
    key = bytes(range(0x80, 0xA0))
    nonce = bytes(range(0x40, 0x58))
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
        b"tip for the future, sunscreen would be it."
    )
    ct = xenc(pt, aad, nonce, key)
    if ct[-16:].hex() != "c0875924c1c7987947deafd8780acf49":
        fail("T-KAT-2 tag in libsodium")


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join("tests", "vectors")
    with open(os.path.join(d, "MANIFEST"), encoding="utf-8") as fh:
        gs = parse_manifest(fh.read())
    if len(gs) < 4:
        fail("expected at least 4 golden vaults")
    kats()
    for g in gs:
        with open(os.path.join(d, g["file"]), "rb") as fh:
            f = fh.read()
        # Decrypt before the checksum, so a tampered file is caught by the
        # cryptography itself (the CI negative control relies on this).
        for pw in [g["password"]] + g["also"]:
            try:
                h, model = open_vault(f, pw)
            except Exception as e:  # nacl.exceptions.CryptoError
                if type(e).__name__ != "CryptoError":
                    raise
                fail(f"{g['file']}: authentication failed")
            if h["generation"] != g["generation"]:
                fail(f"{g['file']}: generation")
            if model != g["model"]:
                fail(f"{g['file']}: model differs")
        if hashlib.sha256(f).hexdigest() != g["sha256"]:
            fail(f"{g['file']}: sha256")
        try:
            open_vault(f, g["password"] + b"!")
            fail(f"{g['file']}: wrong password accepted")
        except Exception as e:  # nacl.exceptions.CryptoError
            if type(e).__name__ != "CryptoError":
                raise
        print(f"ok {g['file']} (generation {g['generation']}, {len(g['model'])} entries)")


if __name__ == "__main__":
    main()
