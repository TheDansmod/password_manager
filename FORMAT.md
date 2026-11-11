# pwv vault file format, version 1

**Status: draft (M3).** This is spec Section 7, restated normatively, plus
the cryptographic binding of Section 6.2 (section 5 below) and annotated
hexdumps: the header of the golden vault `tests/vectors/v1-small.pwv`
(T-COMPAT-1) and the body of the fuzz seed
`fuzz/corpus/fuzz_body/seed-sample`. Implementation: `src/format.rs`
(layout), `src/crypto.rs` (primitives), `src/vault.rs` (lifecycle).
Where this file and the spec disagree, the spec wins and this file is a bug.

## Conventions

- All integers are unsigned little-endian.
- Every parse is strict: any deviation is a hard error, no field is ignored,
  and there is exactly one valid encoding of every vault (canonical form).
- Errors name the violated constraint and at most an entry index, never
  content.

## 1. File

```
+----------------+------------------------+---------------+
| header (184 B) | payload_ct (L bytes)   | tag (16 B)    |
+----------------+------------------------+---------------+
```

The file length must be exactly 200 + L. A reader parses the header (no
allocation), compares 200 + L with the file size, and only then allocates;
it never reads more than 200 + 16 MiB.

## 2. Header

| Offset | Size | Field | Constraint |
| --- | --- | --- | --- |
| 0 | 8 | `magic` | ASCII `PWVAULT` followed by 0x00 |
| 8 | 2 | `format_version` | = 1 |
| 10 | 2 | `flags` | = 0 (reserved) |
| 12 | 16 | `vault_id` | Random at init; never changes, including across `passwd` |
| 28 | 1 | `kdf_id` | = 1 (Argon2id v0x13) |
| 29 | 3 | reserved | = 0 |
| 32 | 4 | `kdf_m_kib` | 65,536 ≤ m ≤ 4,194,304 (read; `testkdf` builds: 8 ≤ m) |
| 36 | 4 | `kdf_t` | 1 ≤ t ≤ 20 |
| 40 | 4 | `kdf_p` | = 1 |
| 44 | 32 | `salt` | Random |
| 76 | 24 | `wrap_nonce` | Random |
| 100 | 48 | `wrapped_dek` | 32-byte ciphertext and 16-byte tag; AAD = bytes [0, 76) |
| 148 | 8 | `generation` | ≥ 1; incremented by 1 per save |
| 156 | 24 | `payload_nonce` | Random, fresh per save |
| 180 | 4 | `payload_len` L | 4096 ≤ L ≤ 16 MiB, L ≡ 0 (mod 4096) |
| 184 | L | `payload_ct` | AAD = bytes [0, 184) |
| 184 + L | 16 | `payload_tag` | — |

Writers never write m < 65,536 or t < 3 (spec Section 6.4). Test builds
with the `testkdf` feature lower both floors of m to 8 KiB; such files are
rejected by production builds.

### Annotated header (`tests/vectors/v1-small.pwv`, golden vault)

Built with `testkdf` (m = 64 KiB, below the production read floor);
password and contents are in `tests/vectors/MANIFEST`.

```
0000  50 57 56 41 55 4c 54 00                          magic "PWVAULT\0"
0008  01 00                                            format_version = 1
000a  00 00                                            flags = 0
000c  30 9f 3b d8 61 0f 6e 77 bb f4 e7 79 53 a9 3a 17  vault_id
001c  01                                               kdf_id = 1 (Argon2id)
001d  00 00 00                                         reserved
0020  40 00 00 00                                      kdf_m_kib = 64 (testkdf)
0024  03 00 00 00                                      kdf_t = 3
0028  01 00 00 00                                      kdf_p = 1
002c  2a 77 d0 41 a9 84 39 ab 17 b5 2b 3f ad 04 d7 42  salt
003c  30 6c 00 f4 ca 30 da 9f 73 0e bd 46 28 ac ec 77
004c  13 a0 1d 52 12 22 44 be e8 14 40 53 58 b9 e5 f7  wrap_nonce   (AAD_w = bytes 0x00..0x4b)
005c  09 6b ee 32 34 8b 89 b6
0064  c6 2e 50 88 5f a7 b1 c3 ef ab 1d 28 43 9a 5b 43  wrapped_dek  (DEK ciphertext 32 B, tag 16 B)
0074  10 a1 a7 04 f3 7f 68 ed 8a ed 5e 70 20 b0 51 64
0084  c5 9a 77 ba ad 0e 97 63 a8 9a e4 a9 4c 6b 3a 07
0094  01 00 00 00 00 00 00 00                          generation = 1
009c  ae a0 2a fb 0a e4 91 0d e6 c1 cc c6 a7 30 de 64  payload_nonce
00ac  1e 03 9d 04 19 dd 4c 20
00b4  00 10 00 00                                      payload_len = 4096 (AAD_p = bytes 0x00..0xb7)
00b8  ...                                              payload_ct (4096 B)
10b8  9d 9c f2 0e 88 1b 9f ff 26 c3 8e b0 3c 71 73 ff  payload_tag
```

## 3. Body (plaintext of the payload, L bytes)

| Offset | Size | Field | Constraint |
| --- | --- | --- | --- |
| 0 | 4 | `body_magic` | ASCII `PWVB` |
| 4 | 4 | `content_len` C | 12 + C ≤ L |
| 8 | 4 | `entry_count` N | N ≤ 10,000 |
| 12 | C | entries | N consecutive entry records, consuming exactly C bytes |
| 12 + C | L − 12 − C | padding | All bytes = 0x00 |

**Entry record**

| Field | Size | Constraint |
| --- | --- | --- |
| `name_len` | u16 | 1 – 256 |
| `name` | `name_len` | UTF-8; no C0, DEL, or C1 controls; no leading or trailing whitespace |
| `field_count` | u16 | 0 – 64 |
| then `field_count` field records | | |

**Field record**

| Field | Size | Constraint |
| --- | --- | --- |
| `key_len` | u8 | 1 – 64 |
| `key` | `key_len` | UTF-8; no controls; unique within its entry under ASCII case-folding |
| `flags` | u8 | bit 0 = sensitive; bits 1–7 = 0 |
| `value_len` | u16 | 0 – 4,096 |
| `value` | `value_len` | UTF-8; no controls except LF (0x0A) |

Definitions used by the implementation:

- *Control* means Unicode general category Cc: U+0000–U+001F (C0),
  U+007F (DEL), U+0080–U+009F (C1). Other format characters, such as the
  bidirectional overrides, are allowed in the file and made visible on
  display by `term::sanitize` (spec Section 9.3).
- *Whitespace* means the Unicode `White_Space` property (Rust
  `char::is_whitespace`), for example U+0020, U+00A0, U+3000.
- *ASCII case-folding* folds only A–Z to a–z; `É` and `é` are distinct keys.

### Canonical form

1. Entries appear in strictly increasing byte-lexicographic order of `name`
   (so names are unique).
2. Fields appear in user insertion order.
3. Padding is minimal: L = 4096 · ⌈(12 + C) / 4096⌉.

The parser rejects every non-canonical input, so for every byte string b and
every valid model x: parse(b) = Ok(x) ⇒ serialize(x) = b, and
parse(serialize(x)) = Ok(x). The serializer validates its own output with
the parser and so cannot emit a non-canonical body.

Size leakage: an observer learns only ⌈(12 + C) / 4096⌉.

### Annotated body (`seed-sample`)

Three entries: `bank` (user, password [sensitive], notes with LF), `empty`
(no fields), and `mail été` (pin [sensitive], empty value).

```
0000  50 57 56 42              body_magic "PWVB"
0004  5c 00 00 00              content_len C = 92
0008  03 00 00 00              entry_count N = 3
000c  04 00 "bank"             name_len 4, name                  entry 0
0012  03 00                    field_count 3
0014  04 "user" 00 05 00 "alice"          key_len, key, flags=0, value_len, value
0021  08 "password" 01 07 00 "hunter2"    flags = 1 (sensitive)
0034  05 "notes" 00 0d 00 "line 1\nline 2"
004a  05 00 "empty" 00 00      name_len 5, name, field_count 0   entry 1
0053  0a 00 "mail été" 01 00   name (10 UTF-8 bytes), field_count 1   entry 2
0061  03 "pin" 01 00 00        key "pin", sensitive, value_len 0
0068  00 × 3992                padding to L = 4096
```

## 4. Versioning

Any change to these tables increments `format_version`. A version-N binary
reads every version ≤ N through frozen per-version parsers and always
writes version N. Each version has committed golden vectors (T-COMPAT-1)
that must decrypt forever.

## 5. Cryptographic binding (spec Section 6.2)

```
P'  = UTF8(NFC(P))                         # Unicode NFC only; P must be UTF-8
KEK = Argon2id v0x13(P', salt; m = kdf_m_kib, t = kdf_t, p = 1, 32 bytes)
W   = XChaCha20Poly1305.Seal(KEK, wrap_nonce,    DEK,       AAD = hdr[0, 76))
C   = XChaCha20Poly1305.Seal(DEK, payload_nonce, body (L B), AAD = hdr[0, 184))
```

`wrapped_dek` is W (32-byte ciphertext then 16-byte tag); the file is
`hdr ‖ C ‖ tag`. Both tag failures produce the same error ("wrong password
or damaged vault"). A save draws a fresh `payload_nonce` and increments
`generation`, leaving `wrap_nonce` and `wrapped_dek` unchanged; `passwd`
draws a fresh salt, DEK, and both nonces, and keeps `vault_id`.
`scripts/verify_golden.py` is an independent implementation of this
section (argon2-cffi and libsodium) and decrypts every golden vault.

