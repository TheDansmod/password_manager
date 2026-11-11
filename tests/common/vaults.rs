//! Helpers for M3 tests: models, bodies in arena slots, whole vault files,
//! and the golden-vector manifest (`tests/vectors/MANIFEST`).

use pwv::crypto::{self, KdfParams};
use pwv::format::{BodyWriter, Header, parse_body};
use pwv::secmem::{DEFAULT_ARENA, MIN_ARENA, SecretSlot, SecureArena};
use pwv::vault;
use std::path::PathBuf;

/// (key, sensitive, value).
pub type Field = (String, bool, String);
/// Entries in canonical (sorted) order.
pub type Model = Vec<(String, Vec<Field>)>;

/// An unlocked-memory-tolerant arena: these tests are about crypto, not
/// locking (T-MEM-1 covers that), and run many arenas in parallel.
/// Under Miri the smallest arena keeps the byte-by-byte wipes affordable.
pub fn arena() -> SecureArena {
    let size = if cfg!(miri) { MIN_ARENA } else { DEFAULT_ARENA };
    SecureArena::new(size, true).expect("arena")
}

/// Puts `bytes` into `slot`.
pub fn put(slot: &mut SecretSlot<'_>, bytes: &[u8]) {
    slot.set_len(bytes.len()).expect("fits");
    slot.expose_mut().copy_from_slice(bytes);
}

/// Serialises `m` into `slot` (the padded canonical body).
pub fn write_body(m: &Model, slot: &mut SecretSlot<'_>) {
    let cap = slot.capacity();
    slot.set_len(cap).expect("cap");
    let mut w = BodyWriter::new(slot.expose_mut());
    for (name, fields) in m {
        w.entry(name.as_bytes()).expect("entry");
        for (k, s, v) in fields {
            w.field(k.as_bytes(), *s, v.as_bytes()).expect("field");
        }
    }
    let l = w.finish().expect("finish");
    slot.set_len(l).expect("len");
}

/// Reads the model out of a validated body.
pub fn read_body(body: &[u8]) -> Model {
    let utf8 = |b: &[u8]| String::from_utf8(b.to_vec()).expect("utf8");
    parse_body(body)
        .expect("valid body")
        .map(|e| {
            let fields = e
                .fields
                .map(|f| (utf8(f.key), f.sensitive, utf8(f.value)))
                .collect();
            (utf8(e.name), fields)
        })
        .collect()
}

/// Lowest parameters this build may write, with t = 3.
pub fn floor_params() -> KdfParams {
    KdfParams::for_write(crypto::KDF_M_WRITE_MIN, 3).expect("floor")
}

/// A new vault file for `pw` (raw; NFC-normalised here) holding `m`,
/// after `saves` saves (generation = `saves`). Also returns the header.
pub fn make_vault(pw: &str, m: &Model, params: KdfParams, saves: u64) -> (Vec<u8>, Header) {
    let mut a = arena();
    let mut s = a.slots().expect("slots");
    put(&mut s.pw1, pw.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).expect("nfc");
    let (mut h, _) =
        vault::init(s.pw2.expose(), params, &mut s.kek, &mut s.dek, false).expect("init");
    write_body(m, &mut s.vault_a);
    let mut file = Vec::new();
    for _ in 0..saves {
        file = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).expect("save");
    }
    (file, h)
}

/// Full-path unlock of `file` with `pw`; returns the model or the error.
pub fn unlock_model(file: &[u8], pw: &[u8]) -> Result<(Header, Model), vault::Error> {
    let mut a = arena();
    let mut s = a.slots().expect("slots");
    put(&mut s.pw1, pw);
    let (h, _) = vault::unlock(
        file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_a,
        false,
    )?;
    Ok((h, read_body(s.vault_a.expose())))
}

/// A small model exercising the text rules: Unicode names, sensitive
/// flags, an LF in a value, an empty value, an entry without fields.
pub fn sample_model() -> Model {
    let f = |k: &str, s: bool, v: &str| (k.to_owned(), s, v.to_owned());
    vec![
        (
            "bank".into(),
            vec![
                f("username", false, "alice"),
                f("password", true, "c0rrect-h0rse"),
                f("notes", false, "line 1\nline 2"),
            ],
        ),
        ("e-mail \u{2709}".into(), vec![f("pin", true, "")]),
        ("no fields".into(), vec![]),
        (
            "\u{65e5}\u{672c}".into(),
            vec![f("Cl\u{e9}", true, "\u{1f511} \u{202e}rtl")],
        ),
    ]
}

/// `n` entries `entry-00000` .. with two fields each.
pub fn big_model(n: usize) -> Model {
    (0..n)
        .map(|i| {
            (
                format!("entry-{i:05}"),
                vec![
                    ("user".into(), false, format!("user{i}@example.org")),
                    ("password".into(), true, format!("pw-{i:08x}-{}", i * 7919)),
                ],
            )
        })
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// One golden vault of the manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Golden {
    pub file: String,
    pub sha256: String,
    /// Raw (as typed) password bytes.
    pub password: Vec<u8>,
    /// Other spellings that must open it (e.g. decomposed, T-CRY-6).
    pub also_opens: Vec<Vec<u8>>,
    pub generation: u64,
    pub model: Model,
}

/// Renders the manifest. Lines: `vault <file> <sha256>`, `password <hex>`,
/// `also <hex>`, `generation <n>`, `entry <hex>`, `field <hex> <0|1> <hex>`,
/// `end`. `#` starts a comment line.
pub fn render_manifest(gs: &[Golden]) -> String {
    let mut o = String::from(MANIFEST_HEAD);
    for g in gs {
        o += &format!("\nvault {} {}\n", g.file, g.sha256);
        o += &format!("password {}\n", hex(&g.password));
        for a in &g.also_opens {
            o += &format!("also {}\n", hex(a));
        }
        o += &format!("generation {}\n", g.generation);
        for (n, fs) in &g.model {
            o += &format!("entry {}\n", hex(n.as_bytes()));
            for (k, s, v) in fs {
                let (k, v) = (hex(k.as_bytes()), hex(v.as_bytes()));
                o += &format!("field {k} {} {v}\n", u8::from(*s));
            }
        }
        o += "end\n";
    }
    o
}

const MANIFEST_HEAD: &str = "\
# T-COMPAT-1 golden vaults: format version 1, built with the `testkdf`
# feature (KDF memory below the production read floor). They must decrypt
# to exactly these models forever and are never regenerated except on a
# format-version bump. Independent check: scripts/verify_golden.py.
# Strings are hex-encoded UTF-8; passwords are as typed (before NFC).
";

/// Parses the manifest (the inverse of [`render_manifest`]).
pub fn parse_manifest(text: &str) -> Vec<Golden> {
    let mut out = Vec::new();
    let mut cur: Option<Golden> = None;
    for line in text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let w: Vec<&str> = line.split(' ').collect();
        let g = cur.as_mut();
        match (w[0], g) {
            ("vault", None) => {
                cur = Some(Golden {
                    file: w[1].into(),
                    sha256: w[2].into(),
                    password: vec![],
                    also_opens: vec![],
                    generation: 0,
                    model: vec![],
                });
            }
            ("password", Some(g)) => g.password = unhex(w[1]),
            ("also", Some(g)) => g.also_opens.push(unhex(w[1])),
            ("generation", Some(g)) => g.generation = w[1].parse().expect("generation"),
            ("entry", Some(g)) => {
                g.model
                    .push((String::from_utf8(unhex(w[1])).expect("utf8"), vec![]));
            }
            ("field", Some(g)) => {
                let s = String::from_utf8;
                g.model.last_mut().expect("entry first").1.push((
                    s(unhex(w[1])).expect("utf8"),
                    w[2] == "1",
                    s(unhex(w.get(3).copied().unwrap_or(""))).expect("utf8"),
                ));
            }
            ("end", Some(_)) => out.push(cur.take().expect("open")),
            _ => panic!("bad manifest line: {line}"),
        }
    }
    assert!(cur.is_none(), "unterminated manifest record");
    out
}
