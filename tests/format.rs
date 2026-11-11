//! Format tests (spec Section 14.2): T-FMT-1 (round-trip properties),
//! T-FMT-2 (one targeted test per constraint), T-FMT-3 (truncation), plus
//! header layout, writer, and fuzz-corpus checks. T-FMT-4 lives in
//! `tests/format_alloc.rs`, which needs its own counting allocator.
//!
//! Test data here is synthetic, so ordinary `String`/`Vec` are fine.

use proptest::prelude::*;
use pwv::format::{
    BLOCK, BODY_PREFIX, BodyWriter, Error, HEADER_LEN, Header, KDF_M_MAX, KDF_M_MIN, KDF_T_MAX,
    MAX_ENTRIES, MAX_FIELDS, MAX_KEY, MAX_NAME, MAX_PAYLOAD, MAX_VALUE, TAG_LEN, padded_len,
    parse_body, parse_header, split_file,
};
use std::collections::{BTreeMap, HashSet};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

// ---------------------------------------------------------------- helpers

type Field = (String, bool, String);
type Model = Vec<(String, Vec<Field>)>;

fn content_size(m: &Model) -> usize {
    m.iter()
        .map(|(n, fs)| {
            4 + n.len()
                + fs.iter()
                    .map(|(k, _, v)| 4 + k.len() + v.len())
                    .sum::<usize>()
        })
        .sum()
}

/// Serialises a model with the production writer into an exactly-sized buffer.
fn serialize(m: &Model) -> Result<Vec<u8>, Error> {
    let mut out = vec![0xEE; padded_len(content_size(m)).expect("size")];
    let mut w = BodyWriter::new(&mut out);
    for (name, fields) in m {
        w.entry(name.as_bytes())?;
        for (k, s, v) in fields {
            w.field(k.as_bytes(), *s, v.as_bytes())?;
        }
    }
    let l = w.finish()?;
    out.truncate(l);
    Ok(out)
}

/// Parses a body into a model.
fn parse(b: &[u8]) -> Result<Model, Error> {
    let entries = parse_body(b)?;
    let s = |x: &[u8]| String::from_utf8(x.to_vec()).expect("validated UTF-8");
    Ok(entries
        .map(|e| {
            let fields = e
                .fields
                .map(|f| (s(f.key), f.sensitive, s(f.value)))
                .collect();
            (s(e.name), fields)
        })
        .collect())
}

fn u16le(n: usize) -> [u8; 2] {
    u16::try_from(n).expect("u16").to_le_bytes()
}

/// Raw field record; no validation.
fn rec_field(key: &[u8], flags: u8, value: &[u8]) -> Vec<u8> {
    let kl = u8::try_from(key.len()).expect("u8");
    [&[kl][..], key, &[flags], &u16le(value.len()), value].concat()
}

/// Raw entry record with an explicit `field_count`; no validation.
fn rec_entry_n(name: &[u8], count: usize, fields: &[Vec<u8>]) -> Vec<u8> {
    [
        &u16le(name.len())[..],
        name,
        &u16le(count),
        &fields.concat(),
    ]
    .concat()
}

fn rec_entry(name: &[u8], fields: &[Vec<u8>]) -> Vec<u8> {
    rec_entry_n(name, fields.len(), fields)
}

/// Raw body: prefix with `c` and `n`, then `content`, zero-padded to `len`.
fn raw_body_full(c: u32, n: u32, content: &[u8], len: usize) -> Vec<u8> {
    let mut b = [&b"PWVB"[..], &c.to_le_bytes(), &n.to_le_bytes(), content].concat();
    b.resize(len, 0);
    b
}

/// Raw body with correct `content_len` and minimal padding.
fn raw_body(n: u32, content: &[u8]) -> Vec<u8> {
    let c = u32::try_from(content.len()).expect("u32");
    raw_body_full(c, n, content, padded_len(content.len()).expect("len"))
}

fn one_entry(name: &[u8], fields: &[Vec<u8>]) -> Vec<u8> {
    raw_body(1, &rec_entry(name, fields))
}

fn sample_model() -> Model {
    vec![
        (
            "bank".into(),
            vec![
                ("user".into(), false, "alice".into()),
                ("password".into(), true, "hunter2".into()),
                ("notes".into(), false, "line 1\nline 2".into()),
            ],
        ),
        ("empty".into(), vec![]),
        (
            "mail \u{e9}t\u{e9}".into(),
            vec![("pin".into(), true, String::new())],
        ),
    ]
}

fn sample_header() -> Header {
    Header {
        vault_id: [0x11; 16],
        kdf_m_kib: 262_144,
        kdf_t: 3,
        salt: [0x22; 32],
        wrap_nonce: [0x33; 24],
        wrapped_dek: [0x44; 48],
        generation: 7,
        payload_nonce: [0x55; 24],
        payload_len: 4096,
    }
}

fn sample_file() -> Vec<u8> {
    let h = sample_header();
    let mut f = h.encode().to_vec();
    f.extend(std::iter::repeat_n(0xC7, 4096));
    f.extend([0x7A; TAG_LEN]);
    f
}

/// Header bytes with `patch` written at `off`.
fn header_with(off: usize, patch: &[u8]) -> Vec<u8> {
    let mut h = sample_header().encode().to_vec();
    h[off..off + patch.len()].copy_from_slice(patch);
    h
}

// ---------------------------------------------------------------- T-FMT-1

fn cases() -> ProptestConfig {
    // Miri (T-SAN-2) interprets every instruction; the case count is reduced
    // there only. DESIGN_NOTES.md, 2026-11-10 (M2).
    let mut c = ProptestConfig::with_cases(if cfg!(miri) { 8 } else { 10_000 });
    if cfg!(miri) {
        c.failure_persistence = None;
    }
    c
}

const TEXT: &[char] = &[
    'a',
    'b',
    'z',
    'A',
    'Z',
    '0',
    '9',
    ' ',
    '-',
    '_',
    '.',
    '\u{e9}',
    'e',
    '\u{301}',
    '\u{20ac}',
    '\u{1f600}',
    '\u{202e}',
    '\u{2066}',
    '\u{a0}',
    '\u{3000}',
    '\u{ff}',
    '\u{7e}',
];

fn text(
    max_chars: usize,
    max_bytes: usize,
    extra: &'static [char],
) -> impl Strategy<Value = String> {
    let pool: Vec<char> = TEXT.iter().chain(extra).copied().collect();
    let long = (0..=max_bytes).prop_map(|n| "x".repeat(n));
    prop_oneof![
        8 => prop::collection::vec(prop::sample::select(pool), 0..=max_chars)
            .prop_map(|v| v.into_iter().collect::<String>()),
        1 => long,
    ]
    .prop_map(move |s| {
        let mut end = s.len().min(max_bytes);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_owned()
    })
}

fn name() -> impl Strategy<Value = String> {
    text(24, MAX_NAME, &[])
        .prop_map(|s| s.trim().to_owned())
        .prop_filter("non-empty", |s| !s.is_empty())
}

fn fields() -> impl Strategy<Value = Vec<Field>> {
    let key = text(12, MAX_KEY, &[]).prop_filter("non-empty", |s| !s.is_empty());
    let value = text(40, MAX_VALUE, &['\n']);
    prop::collection::vec((key, any::<bool>(), value), 0..8).prop_map(|v| {
        let mut seen = HashSet::new();
        v.into_iter()
            .filter(|(k, _, _)| seen.insert(k.to_ascii_lowercase()))
            .collect()
    })
}

fn model() -> impl Strategy<Value = Model> {
    prop::collection::btree_map(name(), fields(), 0..12)
        .prop_map(|m: BTreeMap<String, Vec<Field>>| m.into_iter().collect())
}

/// Random bytes, valid bodies, and valid bodies with a few bytes overwritten.
fn body_bytes() -> impl Strategy<Value = Vec<u8>> {
    let valid = || model().prop_map(|m| serialize(&m).expect("valid model"));
    let mutated = (
        valid(),
        prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    )
        .prop_map(|(mut b, edits)| {
            for (i, v) in edits {
                let at = i.index(b.len());
                b[at] = v;
            }
            b
        });
    prop_oneof![
        1 => prop::collection::vec(any::<u8>(), 0..9000),
        2 => valid(),
        4 => mutated,
    ]
}

proptest! {
    #![proptest_config(cases())]

    /// T-FMT-1: parse(serialize(x)) = x for random valid models x.
    #[test]
    fn t_fmt_1_parse_of_serialize_is_identity(m in model()) {
        let b = serialize(&m).expect("valid model serialises");
        prop_assert_eq!(b.len() % BLOCK, 0);
        prop_assert_eq!(parse(&b).expect("parses"), m);
    }

    /// T-FMT-1: parse(b) = Ok(x) implies serialize(x) = b.
    #[test]
    fn t_fmt_1_serialize_of_parse_is_identity(b in body_bytes()) {
        if let Ok(m) = parse(&b) {
            prop_assert_eq!(serialize(&m).expect("re-serialises"), b);
        }
    }

    /// Header: parse(encode(h)) = h for valid headers.
    #[test]
    fn header_round_trip(
        id in any::<[u8; 16]>(), m in KDF_M_MIN..=KDF_M_MAX, t in 1..=KDF_T_MAX,
        salt in any::<[u8; 32]>(), wn in any::<[u8; 24]>(), wd in prop::collection::vec(any::<u8>(), 48),
        g in 1..=u64::MAX, pn in any::<[u8; 24]>(), blocks in 1..=4096u32,
    ) {
        let h = Header {
            vault_id: id, kdf_m_kib: m, kdf_t: t, salt, wrap_nonce: wn,
            wrapped_dek: wd.try_into().expect("48"), generation: g, payload_nonce: pn,
            payload_len: blocks * 4096,
        };
        prop_assert_eq!(parse_header(&h.encode()).expect("valid"), h);
    }

    /// Header: any 184 bytes either fail or re-encode to themselves.
    #[test]
    fn header_parse_then_encode_is_identity(b in prop::collection::vec(any::<u8>(), HEADER_LEN)) {
        if let Ok(h) = parse_header(&b) {
            prop_assert_eq!(&h.encode()[..], &b[..]);
        }
    }
}

#[test]
fn t_fmt_1_samples_round_trip_and_mutations_can_still_parse() {
    let m = sample_model();
    let b = serialize(&m).expect("serialise");
    assert_eq!(b.len(), BLOCK);
    assert_eq!(parse(&b).expect("parse"), m);
    // A value-byte substitution stays valid: the parse-then-serialize
    // property above is therefore not vacuous on mutated inputs.
    let at = b.windows(7).position(|w| w == b"hunter2").expect("value");
    let mut c = b.clone();
    c[at] = b'H';
    let mc = parse(&c).expect("still canonical");
    assert_eq!(serialize(&mc).expect("serialise"), c);
}

// ---------------------------------------------------------------- T-FMT-2: body

#[test]
fn t_fmt_2_empty_body_is_valid() {
    let b = raw_body(0, &[]);
    assert_eq!(b.len(), BLOCK);
    assert_eq!(parse_body(&b).expect("empty body").count(), 0);
    assert_eq!(&b[4..12], &[0; 8], "content_len = entry_count = 0");
    assert_eq!(serialize(&vec![]).expect("empty"), b);
}

#[test]
fn t_fmt_2_body_magic() {
    let mut b = raw_body(0, &[]);
    b[3] = b'C';
    assert_eq!(parse_body(&b).err(), Some(Error::BodyMagic));
}

#[test]
fn t_fmt_2_body_length() {
    for len in [
        0,
        1,
        11,
        12,
        BLOCK - 1,
        BLOCK + 1,
        2 * BLOCK - 1,
        // A 16 MiB buffer is out of reach for Miri (the zeroizing allocator
        // wipes and verifies it byte by byte); the length check is O(1), so
        // the small lengths exercise the same code. DESIGN_NOTES.md (M2).
        if cfg!(miri) {
            3 * BLOCK - 1
        } else {
            MAX_PAYLOAD + BLOCK
        },
    ] {
        let b = raw_body_full(0, 0, &[], len);
        assert_eq!(parse_body(&b).err(), Some(Error::BodyLength), "len {len}");
    }
}

#[test]
fn t_fmt_2_unsorted_names() {
    let c = [rec_entry(b"b", &[]), rec_entry(b"a", &[])].concat();
    assert_eq!(
        parse_body(&raw_body(2, &c)).err(),
        Some(Error::NameOrder(1))
    );
    // A prefix sorts first; byte order, not character order.
    let c = [rec_entry(b"ab", &[]), rec_entry(b"a", &[])].concat();
    assert_eq!(
        parse_body(&raw_body(2, &c)).err(),
        Some(Error::NameOrder(1))
    );
    let c = [rec_entry(b"a", &[]), rec_entry(b"Z", &[])].concat();
    assert_eq!(
        parse_body(&raw_body(2, &c)).err(),
        Some(Error::NameOrder(1))
    );
    let ok = [
        rec_entry(b"Z", &[]),
        rec_entry(b"a", &[]),
        rec_entry(b"ab", &[]),
        rec_entry("\u{e9}".as_bytes(), &[]),
    ]
    .concat();
    assert!(parse_body(&raw_body(4, &ok)).is_ok());
}

#[test]
fn t_fmt_2_duplicate_names() {
    let c = [
        rec_entry(b"a", &[]),
        rec_entry(b"b", &[]),
        rec_entry(b"b", &[]),
    ]
    .concat();
    assert_eq!(
        parse_body(&raw_body(3, &c)).err(),
        Some(Error::NameDuplicate(2))
    );
}

#[test]
fn t_fmt_2_case_folded_duplicate_keys() {
    for (k1, k2) in [("password", "Password"), ("API KEY", "api key"), ("x", "x")] {
        let f = [
            rec_field(k1.as_bytes(), 1, b"1"),
            rec_field(k2.as_bytes(), 1, b"2"),
        ];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::KeyDuplicate(0)),
            "{k1} / {k2}"
        );
    }
    // The duplicate need not be adjacent; the index is the entry's.
    let f = [
        rec_field(b"a", 0, b""),
        rec_field(b"b", 0, b""),
        rec_field(b"A", 0, b""),
    ];
    let c = [rec_entry(b"x", &[]), rec_entry(b"y", &f)].concat();
    assert_eq!(
        parse_body(&raw_body(2, &c)).err(),
        Some(Error::KeyDuplicate(1))
    );
    // ASCII folding only: non-ASCII case variants are distinct keys.
    let f = [
        rec_field("\u{e9}".as_bytes(), 0, b""),
        rec_field("\u{c9}".as_bytes(), 0, b""),
    ];
    assert!(parse_body(&one_entry(b"e", &f)).is_ok());
}

const BAD_UTF8: &[&[u8]] = &[
    b"\xff",
    b"a\x80",
    b"\xc0\x80",         // overlong NUL
    b"\xed\xa0\x80",     // surrogate
    b"\xe2\x82",         // truncated sequence
    b"\xf4\x90\x80\x80", // above U+10FFFF
];

#[test]
fn t_fmt_2_bad_utf8() {
    for bad in BAD_UTF8 {
        assert_eq!(
            parse_body(&one_entry(bad, &[])).err(),
            Some(Error::NameUtf8(0))
        );
        let f = [rec_field(bad, 0, b"v")];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::KeyUtf8(0))
        );
        let f = [rec_field(b"k", 0, bad)];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::ValueUtf8(0))
        );
    }
}

/// One representative of each forbidden control class, plus edges.
const CONTROLS: &[&str] = &[
    "\u{0}", "\u{9}", "\u{d}", "\u{1b}", "\u{1f}", // C0
    "\u{7f}", // DEL
    "\u{80}", "\u{85}", "\u{9b}", "\u{9f}", // C1
];

#[test]
fn t_fmt_2_control_characters() {
    for c in CONTROLS {
        let s = format!("a{c}b");
        assert_eq!(
            parse_body(&one_entry(s.as_bytes(), &[])).err(),
            Some(Error::NameControl(0)),
            "{c:?}"
        );
        let f = [rec_field(s.as_bytes(), 0, b"v")];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::KeyControl(0)),
            "{c:?}"
        );
        let f = [rec_field(b"k", 0, s.as_bytes())];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::ValueControl(0)),
            "{c:?}"
        );
    }
    // LF: allowed in values only.
    assert_eq!(
        parse_body(&one_entry(b"a\nb", &[])).err(),
        Some(Error::NameControl(0))
    );
    let f = [rec_field(b"a\nb", 0, b"v")];
    assert_eq!(
        parse_body(&one_entry(b"e", &f)).err(),
        Some(Error::KeyControl(0))
    );
    let f = [rec_field(b"k", 0, b"\nline\n")];
    assert!(parse_body(&one_entry(b"e", &f)).is_ok());
    // Neighbours of the control ranges are fine; so are bidi controls
    // (rendered visibly by `term::sanitize`, Section 9.3).
    for ok in [
        "\u{20}", "\u{7e}", "\u{a0}x", "\u{a1}", "\u{202e}", "\u{2066}",
    ] {
        let s = format!("x{ok}y");
        let f = [rec_field(s.as_bytes(), 0, s.as_bytes())];
        assert!(parse_body(&one_entry(s.as_bytes(), &f)).is_ok(), "{ok:?}");
    }
}

#[test]
fn t_fmt_2_name_whitespace() {
    for bad in [" a", "a ", "\u{a0}a", "a\u{3000}", "\u{2003}", " "] {
        assert_eq!(
            parse_body(&one_entry(bad.as_bytes(), &[])).err(),
            Some(Error::NameWhitespace(0)),
            "{bad:?}"
        );
    }
    assert!(parse_body(&one_entry("a b\u{a0}c".as_bytes(), &[])).is_ok());
}

#[test]
fn t_fmt_2_field_flags() {
    for bit in 1..8 {
        let f = [rec_field(b"k", 1 << bit, b"v")];
        assert_eq!(
            parse_body(&one_entry(b"e", &f)).err(),
            Some(Error::FieldFlags(0)),
            "bit {bit}"
        );
    }
    let m = parse(&one_entry(
        b"e",
        &[rec_field(b"a", 0, b""), rec_field(b"b", 1, b"")],
    ))
    .expect("ok");
    assert_eq!(
        m[0].1.iter().map(|f| f.1).collect::<Vec<_>>(),
        [false, true]
    );
}

#[test]
fn t_fmt_2_non_zero_padding() {
    let c = rec_entry(b"e", &[]);
    for at in [BODY_PREFIX + c.len(), BLOCK - 1] {
        let mut b = raw_body(1, &c);
        b[at] = 1;
        assert_eq!(parse_body(&b).err(), Some(Error::Padding), "at {at}");
    }
}

#[test]
fn t_fmt_2_non_minimal_padding() {
    let c = rec_entry(b"e", &[]);
    let b = raw_body_full(u32::try_from(c.len()).expect("u32"), 1, &c, 2 * BLOCK);
    assert_eq!(parse_body(&b).err(), Some(Error::PaddingLength));
    let b = raw_body_full(0, 0, &[], 2 * BLOCK);
    assert_eq!(parse_body(&b).err(), Some(Error::PaddingLength));
}

#[test]
fn t_fmt_2_trailing_bytes_and_count_mismatch() {
    // content_len covers bytes no entry consumes.
    let c = [rec_entry(b"e", &[]), vec![0]].concat();
    assert_eq!(
        parse_body(&raw_body(1, &c)).err(),
        Some(Error::TrailingBytes)
    );
    // entry_count smaller than the records present.
    let c = [rec_entry(b"a", &[]), rec_entry(b"b", &[])].concat();
    assert_eq!(
        parse_body(&raw_body(1, &c)).err(),
        Some(Error::TrailingBytes)
    );
    // entry_count larger than the records present.
    assert_eq!(
        parse_body(&raw_body(3, &c)).err(),
        Some(Error::EntryTruncated(2))
    );
    // A record running past content_len, even into (zero) padding.
    let c = rec_entry(b"abc", &[]);
    let b = raw_body_full(u32::try_from(c.len() - 1).expect("u32"), 1, &c, BLOCK);
    assert_eq!(parse_body(&b).err(), Some(Error::EntryTruncated(0)));
}

#[test]
fn t_fmt_2_name_len_0_max_max_plus_1() {
    assert_eq!(
        parse_body(&one_entry(b"", &[])).err(),
        Some(Error::NameLength(0))
    );
    assert!(parse_body(&one_entry(&[b'n'; MAX_NAME], &[])).is_ok());
    assert_eq!(
        parse_body(&one_entry(&[b'n'; MAX_NAME + 1], &[])).err(),
        Some(Error::NameLength(0))
    );
    // A multi-byte name at exactly 256 bytes.
    let n = "\u{e9}".repeat(MAX_NAME / 2);
    assert!(parse_body(&one_entry(n.as_bytes(), &[])).is_ok());
}

fn n_fields(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| rec_field(format!("k{i}").as_bytes(), 0, b"v"))
        .collect()
}

#[test]
fn t_fmt_2_field_count_0_max_max_plus_1() {
    assert!(parse_body(&one_entry(b"e", &[])).is_ok());
    let max = usize::from(MAX_FIELDS);
    let m = parse(&one_entry(b"e", &n_fields(max))).expect("64 fields");
    assert_eq!(m[0].1.len(), max);
    assert_eq!(
        parse_body(&one_entry(b"e", &n_fields(max + 1))).err(),
        Some(Error::FieldCount(0))
    );
    // field_count disagreeing with the records present.
    let c = rec_entry_n(b"e", 2, &n_fields(1));
    assert_eq!(
        parse_body(&raw_body(1, &c)).err(),
        Some(Error::EntryTruncated(0))
    );
}

#[test]
fn t_fmt_2_key_len_0_max_max_plus_1() {
    let f = |k: &[u8]| parse_body(&one_entry(b"e", &[rec_field(k, 0, b"v")])).err();
    assert_eq!(f(b""), Some(Error::KeyLength(0)));
    assert_eq!(f(&[b'k'; MAX_KEY]), None);
    assert_eq!(f(&[b'k'; MAX_KEY + 1]), Some(Error::KeyLength(0)));
    assert_eq!(f(&[b'k'; 255]), Some(Error::KeyLength(0)));
}

#[test]
fn t_fmt_2_value_len_0_max_max_plus_1() {
    let f = |v: &[u8]| parse_body(&one_entry(b"e", &[rec_field(b"k", 1, v)])).err();
    assert_eq!(f(b""), None);
    assert_eq!(f(&[b'v'; MAX_VALUE]), None);
    assert_eq!(f(&[b'v'; MAX_VALUE + 1]), Some(Error::ValueLength(0)));
    assert_eq!(f(&[b'v'; 65_535]), Some(Error::ValueLength(0)));
}

#[test]
fn t_fmt_2_content_len_0_max_max_plus_1() {
    assert!(parse_body(&raw_body(0, &[])).is_ok());
    // Max: the entries fill the block exactly (12 + C = L), no padding.
    let value = vec![b'v'; BLOCK - BODY_PREFIX - (4 + 1) - (4 + 1)];
    let c = rec_entry(b"e", &[rec_field(b"k", 0, &value)]);
    assert_eq!(BODY_PREFIX + c.len(), BLOCK);
    assert!(parse_body(&raw_body(1, &c)).is_ok());
    // C one above L - 12, and the extreme value.
    let cl = u32::try_from(BLOCK - BODY_PREFIX + 1).expect("u32");
    assert_eq!(
        parse_body(&raw_body_full(cl, 0, &[], BLOCK)).err(),
        Some(Error::ContentLength)
    );
    assert_eq!(
        parse_body(&raw_body_full(u32::MAX, 0, &[], BLOCK)).err(),
        Some(Error::ContentLength)
    );
}

#[test]
fn t_fmt_2_entry_count_0_max_max_plus_1() {
    // entry_count is bounded before any record is read, so max + 1 is
    // rejected even with no records present.
    assert_eq!(
        parse_body(&raw_body(MAX_ENTRIES + 1, &[])).err(),
        Some(Error::EntryCount)
    );
    assert_eq!(
        parse_body(&raw_body(u32::MAX, &[])).err(),
        Some(Error::EntryCount)
    );
    // 10,000 real records are out of reach for Miri; the record loop runs
    // there on smaller bodies. DESIGN_NOTES.md (M2).
    if cfg!(miri) {
        return;
    }
    let names: Vec<Vec<u8>> = (0..=MAX_ENTRIES)
        .map(|i| format!("e{i:05}").into_bytes())
        .collect();
    let max = usize::try_from(MAX_ENTRIES).expect("usize");
    let c: Vec<u8> = names[..max]
        .iter()
        .flat_map(|n| rec_entry(n, &[]))
        .collect();
    let body = raw_body(MAX_ENTRIES, &c);
    assert_eq!(parse_body(&body).expect("10,000 entries").count(), max);
    let c: Vec<u8> = names.iter().flat_map(|n| rec_entry(n, &[])).collect();
    assert_eq!(
        parse_body(&raw_body(MAX_ENTRIES + 1, &c)).err(),
        Some(Error::EntryCount)
    );
}

/// The largest body: exactly 16 MiB, with no padding at all.
#[cfg(not(miri))] // 16 MiB is out of reach for Miri; DESIGN_NOTES.md (M2).
#[test]
fn t_fmt_2_body_len_max() {
    let target = MAX_PAYLOAD - BODY_PREFIX;
    let mut c = Vec::with_capacity(target);
    let mut n = 0u32;
    while c.len() < target {
        let name = format!("e{n:05}");
        let mut fields = Vec::new();
        let mut size = 4 + name.len();
        for k in 0..usize::from(MAX_FIELDS) {
            let key = format!("k{k:02}");
            let room = target - c.len() - size;
            if room < 4 + key.len() {
                break;
            }
            let v = (room - 4 - key.len()).min(MAX_VALUE);
            size += 4 + key.len() + v;
            fields.push(rec_field(key.as_bytes(), 0, &vec![b'v'; v]));
        }
        c.extend(rec_entry(name.as_bytes(), &fields));
        n += 1;
    }
    assert_eq!(c.len(), target);
    let b = raw_body(n, &c);
    assert_eq!(b.len(), MAX_PAYLOAD);
    let count = parse_body(&b).expect("16 MiB body").count();
    assert_eq!(count, usize::try_from(n).expect("usize"));
}

#[test]
fn t_fmt_2_error_metadata_is_content_free() {
    assert_eq!(Error::KeyDuplicate(7).entry(), Some(7));
    assert_eq!(Error::Padding.entry(), None);
    assert!(Error::NameOrder(3).message().contains("sorted"));
    assert!(!Error::Magic.message().is_empty());
}

// ---------------------------------------------------------------- T-FMT-2: header

#[test]
fn header_layout_matches_spec_offsets() {
    let h = sample_header();
    let b = h.encode();
    assert_eq!(&b[0..8], b"PWVAULT\0");
    assert_eq!(&b[8..10], &[1, 0]);
    assert_eq!(&b[10..12], &[0, 0]);
    assert_eq!(&b[12..28], &[0x11; 16]);
    assert_eq!(&b[28..32], &[1, 0, 0, 0]);
    assert_eq!(&b[32..36], &262_144u32.to_le_bytes());
    assert_eq!(&b[36..40], &3u32.to_le_bytes());
    assert_eq!(&b[40..44], &1u32.to_le_bytes());
    assert_eq!(&b[44..76], &[0x22; 32]);
    assert_eq!(&b[76..100], &[0x33; 24]);
    assert_eq!(&b[100..148], &[0x44; 48]);
    assert_eq!(&b[148..156], &7u64.to_le_bytes());
    assert_eq!(&b[156..180], &[0x55; 24]);
    assert_eq!(&b[180..184], &4096u32.to_le_bytes());
    assert_eq!(parse_header(&b).expect("valid"), h);
    assert_eq!(h.file_len(), 200 + 4096);
}

#[test]
fn t_fmt_2_header_fixed_fields() {
    let e = |off: usize, patch: &[u8]| parse_header(&header_with(off, patch)).err();
    assert_eq!(
        parse_header(&[0; HEADER_LEN - 1]).err(),
        Some(Error::HeaderLength)
    );
    assert_eq!(e(0, b"X"), Some(Error::Magic));
    assert_eq!(e(7, b"\x01"), Some(Error::Magic));
    assert_eq!(e(8, &[0, 0]), Some(Error::Version));
    assert_eq!(e(8, &[2, 0]), Some(Error::Version));
    assert_eq!(e(8, &[1, 1]), Some(Error::Version));
    assert_eq!(e(10, &[1, 0]), Some(Error::Flags));
    assert_eq!(e(10, &[0, 0x80]), Some(Error::Flags));
    assert_eq!(e(28, &[0]), Some(Error::KdfId));
    assert_eq!(e(28, &[2]), Some(Error::KdfId));
    for off in 29..32 {
        assert_eq!(e(off, &[1]), Some(Error::Reserved), "reserved byte {off}");
    }
    assert_eq!(e(40, &0u32.to_le_bytes()), Some(Error::KdfParallelism));
    assert_eq!(e(40, &2u32.to_le_bytes()), Some(Error::KdfParallelism));
}

#[test]
fn t_fmt_2_header_kdf_bounds() {
    let m = |v: u32| parse_header(&header_with(32, &v.to_le_bytes())).err();
    assert_eq!(m(0), Some(Error::KdfMemory));
    assert_eq!(m(KDF_M_MIN - 1), Some(Error::KdfMemory));
    assert_eq!(m(KDF_M_MIN), None);
    assert_eq!(m(KDF_M_MAX), None);
    assert_eq!(m(KDF_M_MAX + 1), Some(Error::KdfMemory));
    assert_eq!(m(u32::MAX), Some(Error::KdfMemory));
    let want_min = if cfg!(feature = "testkdf") { 8 } else { 65_536 };
    assert_eq!(KDF_M_MIN, want_min, "Section 6.4 read floor");
    let t = |v: u32| parse_header(&header_with(36, &v.to_le_bytes())).err();
    assert_eq!(t(0), Some(Error::KdfTime));
    assert_eq!(t(1), None);
    assert_eq!(t(KDF_T_MAX), None);
    assert_eq!(t(KDF_T_MAX + 1), Some(Error::KdfTime));
    assert_eq!(t(u32::MAX), Some(Error::KdfTime));
}

#[test]
fn t_fmt_2_header_generation_and_payload_len() {
    let g = |v: u64| parse_header(&header_with(148, &v.to_le_bytes())).err();
    assert_eq!(g(0), Some(Error::Generation));
    assert_eq!(g(1), None);
    assert_eq!(g(u64::MAX), None);
    let l = |v: usize| {
        parse_header(&header_with(
            180,
            &u32::try_from(v).expect("u32").to_le_bytes(),
        ))
        .err()
    };
    for bad in [
        0,
        1,
        BLOCK - 1,
        BLOCK + 1,
        MAX_PAYLOAD - 1,
        MAX_PAYLOAD + BLOCK,
        0xFFFF_F000,
        0xFFFF_FFFF,
    ] {
        assert_eq!(l(bad), Some(Error::PayloadLength), "L = {bad}");
    }
    for good in [BLOCK, 2 * BLOCK, MAX_PAYLOAD] {
        assert_eq!(l(good), None, "L = {good}");
    }
}

#[test]
fn t_fmt_2_file_length_exact() {
    let f = sample_file();
    let (h, ct, tag) = split_file(&f).expect("valid file");
    assert_eq!((ct.len(), tag.len()), (4096, TAG_LEN));
    assert!(ct.iter().all(|&b| b == 0xC7) && tag.iter().all(|&b| b == 0x7A));
    assert_eq!(h, sample_header());
    let mut longer = f.clone();
    longer.push(0);
    assert_eq!(split_file(&longer).err(), Some(Error::FileLength));
    assert_eq!(split_file(&f[..f.len() - 1]).err(), Some(Error::FileLength));
}

// ---------------------------------------------------------------- writer

#[test]
fn writer_matches_raw_encoding_and_validates() {
    let m = sample_model();
    let raw: Vec<u8> = m
        .iter()
        .flat_map(|(n, fs)| {
            let recs: Vec<Vec<u8>> = fs
                .iter()
                .map(|(k, s, v)| rec_field(k.as_bytes(), u8::from(*s), v.as_bytes()))
                .collect();
            rec_entry(n.as_bytes(), &recs)
        })
        .collect();
    let want = raw_body(u32::try_from(m.len()).expect("u32"), &raw);
    assert_eq!(serialize(&m).expect("serialise"), want);
    // The writer refuses to produce a non-canonical body.
    let unsorted: Model = vec![("b".into(), vec![]), ("a".into(), vec![])];
    assert_eq!(serialize(&unsorted).err(), Some(Error::NameOrder(1)));
    let dup: Model = vec![(
        "e".into(),
        vec![
            ("K".into(), false, String::new()),
            ("k".into(), true, String::new()),
        ],
    )];
    assert_eq!(serialize(&dup).err(), Some(Error::KeyDuplicate(0)));
    let long_key: Model = vec![("e".into(), vec![("k".repeat(300), false, String::new())])];
    assert_eq!(serialize(&long_key).err(), Some(Error::KeyLength(0)));
}

#[test]
fn writer_capacity_and_misuse() {
    let mut small = [0u8; 100];
    let mut w = BodyWriter::new(&mut small);
    w.entry(b"e").expect("fits");
    assert_eq!(
        w.field(b"k", false, &[b'v'; 200]).err(),
        Some(Error::Capacity)
    );
    // The record fits but the padded body (one block) does not.
    assert_eq!(w.finish().err(), Some(Error::Capacity));
    let mut tiny = [0u8; 4];
    assert_eq!(
        BodyWriter::new(&mut tiny).finish().err(),
        Some(Error::Capacity)
    );
    // Stale bytes in the output buffer become zero padding.
    let mut buf = vec![0xAB; 2 * BLOCK];
    let mut w = BodyWriter::new(&mut buf);
    w.entry(b"e").expect("entry");
    let l = w.finish().expect("finish");
    assert_eq!(l, BLOCK);
    assert!(parse_body(&buf[..l]).is_ok());
    // A field before any entry cannot produce a body.
    let mut buf = vec![0; BLOCK];
    let mut w = BodyWriter::new(&mut buf);
    w.field(b"k", false, b"v").expect("fits");
    assert!(w.finish().is_err());
    let mut buf = vec![0; BLOCK];
    let mut w = BodyWriter::new(&mut buf);
    w.field(b"k", false, b"v").expect("fits");
    w.entry(b"e").expect("fits");
    assert!(w.finish().is_err());
}

// ---------------------------------------------------------------- T-FMT-3

#[test]
fn t_fmt_3_truncated_file_at_every_offset() {
    let f = sample_file();
    assert!(split_file(&f).is_ok());
    for k in 0..f.len() {
        assert!(split_file(&f[..k]).is_err(), "prefix {k}");
        let _ = parse_header(&f[..k]);
    }
}

#[test]
fn t_fmt_3_truncated_body_at_every_offset() {
    let b = serialize(&sample_model()).expect("serialise");
    for k in 0..b.len() {
        assert!(parse_body(&b[..k]).is_err(), "prefix {k}");
    }
    // Stronger: truncate the entries region at every offset while keeping
    // a consistent content_len, entry_count, and minimal padding.
    let n = u32::try_from(sample_model().len()).expect("u32");
    let c = u32::from_le_bytes(b[4..8].try_into().expect("4"));
    let entries = &b[BODY_PREFIX..BODY_PREFIX + usize::try_from(c).expect("usize")];
    for k in 0..entries.len() {
        assert!(
            parse_body(&raw_body(n, &entries[..k])).is_err(),
            "entries prefix {k}"
        );
    }
}

// ---------------------------------------------------------------- fuzz corpus

/// Seed inputs for the fuzz targets (spec Section 14.10: corpus committed
/// and seeded). Golden vectors are added to the seeds in M3.
#[cfg_attr(miri, allow(dead_code))] // its only caller is not(miri)
fn corpus_seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut big = sample_model();
    big.push((
        "\u{202e}rtl \u{1f600}".into(),
        (0..20)
            .map(|i| (format!("key{i}"), i % 2 == 0, "x\n".repeat(i * 50)))
            .collect(),
    ));
    vec![
        ("fuzz_header", "seed-file", sample_file()),
        (
            "fuzz_header",
            "seed-header-only",
            sample_header().encode().to_vec(),
        ),
        (
            "fuzz_body",
            "seed-empty",
            serialize(&vec![]).expect("empty"),
        ),
        (
            "fuzz_body",
            "seed-sample",
            serialize(&sample_model()).expect("sample"),
        ),
        ("fuzz_body", "seed-big", serialize(&big).expect("big")),
    ]
}

/// The committed seed files equal the generated seeds. To regenerate after
/// a deliberate change: `PWV_WRITE_CORPUS=1 cargo test --test format corpus`.
#[cfg(not(miri))]
#[test]
#[allow(clippy::disallowed_methods, reason = "writes fuzz seeds; test-only")]
fn fuzz_corpus_seeds_are_committed() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let write = std::env::var_os("PWV_WRITE_CORPUS").is_some();
    for (target, name, bytes) in corpus_seeds() {
        let path = root.join(target).join(name);
        if write {
            std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
            std::fs::write(&path, &bytes).expect("write seed");
        }
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(got, bytes, "{} is stale", path.display());
    }
}
