//! M5 gate (spec Section 14.6): T-VAULT-1 (model-based test against a
//! reference `BTreeMap`) and T-VAULT-2 (colliding operations leave model and
//! file byte-identical). Also: import parsing and truncation (Section 15.5
//! checklist), limits, capacity, the index, and the T-FUZZ-6 corpus seeds.
//!
//! Test output carries no content (rule 9). Generated names, keys, and
//! values are wrapped in `Txt`, whose `Debug` is `[REDACTED; n bytes]`, and
//! every assertion message names only operation, entry, and field indices
//! or error variants. Proptest's failure report and regression file
//! therefore hold op kinds, lengths, and selector indices, never bytes.
//!
//! Vaults on disk live under the system temporary directory (`tempfile`).
//! Under Miri (T-SAN-2) there is no file I/O: "save and reopen" goes
//! through the sealed file in memory.

mod common;

use common::vaults::{arena, floor_params, put};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::{Config, FileFailurePersistence, TestCaseError, TestRunner};
use pwv::crypto;
use pwv::format::{self, BLOCK, BodyWriter, Error as F, Header, entry_at, padded_len, parse_body};
use pwv::secmem::{DEFAULT_ARENA, MIN_ARENA, SecureArena};
use pwv::store::{Paths, Store};
use pwv::vault::{self, Error as E, IMPORT_SUFFIX, Model};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

const PW: &str = "model test \u{e9}";

// ------------------------------------------------------------ reference

/// (key, sensitive, value).
type RField = (Vec<u8>, bool, Vec<u8>);
/// The reference model: names in byte order, fields in insertion order.
type Ref = BTreeMap<Vec<u8>, Vec<RField>>;

fn text_err(b: &[u8], lf: bool, utf8: F, control: F) -> Option<F> {
    match std::str::from_utf8(b) {
        Err(_) => Some(utf8),
        Ok(s) if s.chars().any(|c| c.is_control() && !(lf && c == '\n')) => Some(control),
        Ok(_) => None,
    }
}

/// Section 7.2 name rules, in the documented check order.
fn name_err(b: &[u8]) -> Option<F> {
    if !(1..=format::MAX_NAME).contains(&b.len()) {
        return Some(F::NameLength(0));
    }
    text_err(b, false, F::NameUtf8(0), F::NameControl(0)).or_else(|| {
        let s = std::str::from_utf8(b).expect("checked");
        (s.trim() != s).then_some(F::NameWhitespace(0))
    })
}

fn key_err(b: &[u8]) -> Option<F> {
    if !(1..=format::MAX_KEY).contains(&b.len()) {
        return Some(F::KeyLength(0));
    }
    text_err(b, false, F::KeyUtf8(0), F::KeyControl(0))
}

fn value_err(b: &[u8]) -> Option<F> {
    if b.len() > format::MAX_VALUE {
        return Some(F::ValueLength(0));
    }
    text_err(b, true, F::ValueUtf8(0), F::ValueControl(0))
}

fn invalid(e: Option<F>) -> Result<(), E> {
    e.map_or(Ok(()), |e| Err(E::Invalid(e)))
}

fn ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn suffixed(n: &[u8]) -> Vec<u8> {
    [n, IMPORT_SUFFIX].concat()
}

/// Padded body length of `r`.
fn body_len(r: &Ref) -> usize {
    let c: usize = r
        .iter()
        .map(|(n, fs)| {
            4 + n.len()
                + fs.iter()
                    .map(|(k, _, v)| 4 + k.len() + v.len())
                    .sum::<usize>()
        })
        .sum();
    padded_len(c).expect("len")
}

/// The canonical body of `r`, written by the production writer.
fn serialize(r: &Ref) -> Vec<u8> {
    let mut out = vec![0; body_len(r)];
    let mut w = BodyWriter::new(&mut out);
    for (n, fs) in r {
        w.entry(n).expect("entry");
        for (k, s, v) in fs {
            w.field(k, *s, v).expect("field");
        }
    }
    assert_eq!(w.finish().expect("finish"), out.len());
    out
}

/// A concrete operation (selectors resolved against the reference).
#[derive(Clone)]
enum Act {
    Add(Vec<u8>),
    Set(Vec<u8>, Vec<u8>, bool, Vec<u8>),
    Unset(Vec<u8>, Vec<u8>),
    Mv(Vec<u8>, Vec<u8>),
    MvField(Vec<u8>, Vec<u8>, Vec<u8>),
    Rm(Vec<u8>),
    Import(Ref, bool),
}

impl Act {
    fn kind(&self) -> &'static str {
        match self {
            Act::Add(..) => "add",
            Act::Set(..) => "set",
            Act::Unset(..) => "unset",
            Act::Mv(..) => "mv",
            Act::MvField(..) => "mvfield",
            Act::Rm(..) => "rm",
            Act::Import(_, false) => "import",
            Act::Import(_, true) => "import-suffix",
        }
    }

    /// Entry names the operation mentions (checked through `Model::get`).
    fn names(&self) -> Vec<&[u8]> {
        match self {
            Act::Add(n) | Act::Set(n, ..) | Act::Unset(n, _) | Act::MvField(n, ..) | Act::Rm(n) => {
                vec![n]
            }
            Act::Mv(o, n) => vec![o, n],
            Act::Import(i, _) => i.keys().map(Vec::as_slice).collect(),
        }
    }
}

/// Applies `act` to the reference. On `Err` the reference is unchanged.
/// `cap` is the scratch slot's capacity. Check order (the contract the
/// implementation must match): input validity, lookups, collisions,
/// count limits, then capacity.
fn ref_apply(r: &mut Ref, act: &Act, cap: usize) -> Result<usize, E> {
    let mut n = r.clone();
    let mut count = 0;
    let mut room = cap;
    match act {
        Act::Add(name) => {
            invalid(name_err(name))?;
            if n.contains_key(name) {
                return Err(E::EntryExists);
            }
            if n.len() >= format::MAX_ENTRIES as usize {
                return Err(E::Invalid(F::EntryCount));
            }
            n.insert(name.clone(), vec![]);
        }
        Act::Set(name, k, s, v) => {
            invalid(key_err(k))?;
            invalid(value_err(v))?;
            let fs = n.get_mut(name).ok_or(E::NoEntry)?;
            if let Some(f) = fs.iter_mut().find(|f| ci(&f.0, k)) {
                (f.1, f.2) = (*s, v.clone());
            } else if fs.len() >= usize::from(format::MAX_FIELDS) {
                return Err(E::Invalid(F::FieldCount(0)));
            } else {
                fs.push((k.clone(), *s, v.clone()));
            }
        }
        Act::Unset(name, k) => {
            let fs = n.get_mut(name).ok_or(E::NoEntry)?;
            let p = fs.iter().position(|f| ci(&f.0, k)).ok_or(E::NoField)?;
            fs.remove(p);
        }
        Act::Mv(old, new) => {
            invalid(name_err(new))?;
            if !n.contains_key(old) {
                return Err(E::NoEntry);
            }
            if old != new && n.contains_key(new) {
                return Err(E::EntryExists);
            }
            let fs = n.remove(old).expect("present");
            n.insert(new.clone(), fs);
        }
        Act::MvField(name, old, new) => {
            invalid(key_err(new))?;
            let fs = n.get_mut(name).ok_or(E::NoEntry)?;
            let p = fs.iter().position(|f| ci(&f.0, old)).ok_or(E::NoField)?;
            if fs.iter().enumerate().any(|(q, f)| q != p && ci(&f.0, new)) {
                return Err(E::FieldExists);
            }
            fs[p].0.clone_from(new);
        }
        Act::Rm(name) => {
            n.remove(name).ok_or(E::NoEntry)?;
        }
        Act::Import(imp, suffix) => {
            for (i, name) in imp.keys().enumerate() {
                if r.contains_key(name) {
                    if !suffix {
                        return Err(E::EntryExists);
                    }
                    if name.len() + IMPORT_SUFFIX.len() > format::MAX_NAME {
                        let i = u32::try_from(i).expect("index");
                        return Err(E::Invalid(F::NameLength(i)));
                    }
                }
            }
            for (name, fs) in imp {
                let target = if r.contains_key(name) {
                    suffixed(name)
                } else {
                    name.clone()
                };
                if n.insert(target, fs.clone()).is_some() {
                    return Err(E::EntryExists);
                }
            }
            if n.len() > format::MAX_ENTRIES as usize {
                return Err(E::Invalid(F::EntryCount));
            }
            count = imp.len();
            room = cap - body_len(imp);
        }
    }
    if body_len(&n) > room {
        return Err(E::Capacity);
    }
    *r = n;
    Ok(count)
}

/// Applies `act` to the implementation.
fn model_apply(m: &mut Model<'_>, act: &Act) -> Result<usize, E> {
    match act {
        Act::Add(n) => m.add(n).map(|()| 0),
        Act::Set(n, k, s, v) => m.set(n, k, *s, v).map(|()| 0),
        Act::Unset(n, k) => m.unset(n, k).map(|()| 0),
        Act::Mv(o, n) => m.mv(o, n).map(|()| 0),
        Act::MvField(n, o, k) => m.mvfield(n, o, k).map(|()| 0),
        Act::Rm(n) => m.rm(n).map(|()| 0),
        Act::Import(imp, suffix) => {
            put(m.scratch(), &serialize(imp));
            m.import(*suffix)
        }
    }
}

/// The model equals the reference: entries, fields, flags, order, index
/// lookups, and the exact canonical body bytes.
fn same(m: &Model<'_>, r: &Ref, at: usize, bytes: bool) -> Result<(), TestCaseError> {
    prop_assert_eq!(m.len(), r.len(), "op {}: entry count", at);
    prop_assert_eq!(m.is_empty(), r.is_empty(), "op {}: is_empty", at);
    for (i, (e, (rn, rf))) in m.entries().zip(r).enumerate() {
        prop_assert!(e.name == rn.as_slice(), "op {at}: entry {i}: name differs");
        let fs: Vec<_> = e.fields.collect();
        prop_assert_eq!(fs.len(), rf.len(), "op {}: entry {}: field count", at, i);
        for (j, (f, (k, s, v))) in fs.iter().zip(rf).enumerate() {
            prop_assert!(
                f.key == k.as_slice(),
                "op {at}: entry {i} field {j}: key differs"
            );
            prop_assert!(
                f.sensitive == *s,
                "op {at}: entry {i} field {j}: flag differs"
            );
            prop_assert!(
                f.value == v.as_slice(),
                "op {at}: entry {i} field {j}: value differs"
            );
        }
        let hit = m.get(rn).is_some_and(|g| g.offset == e.offset);
        prop_assert!(hit, "op {at}: entry {i}: index lookup failed");
    }
    if bytes {
        prop_assert!(m.body() == serialize(r), "op {at}: body is not canonical");
    }
    Ok(())
}

// ------------------------------------------------------------ generators

/// Generated content. `Debug` never shows the bytes.
#[derive(Clone, PartialEq)]
struct Txt(Vec<u8>);

impl fmt::Debug for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0.len())
    }
}

/// An entry name: literal, or an existing one picked at run time (bare or
/// with the import suffix appended, for secondary collisions).
#[derive(Clone, Debug)]
enum NameSel {
    Lit(Txt),
    Pick(Index),
    PickSuffixed(Index),
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Same,
    Upper,
    Lower,
}

/// A field key: literal, or an existing key of the entry in some ASCII case.
#[derive(Clone, Debug)]
enum KeySel {
    Lit(Txt),
    Pick(Index, Case),
}

type GenEntry = (NameSel, Vec<(Txt, bool, Txt)>);

#[derive(Clone, Debug)]
enum Op {
    Add(NameSel),
    Set(NameSel, KeySel, bool, Txt),
    Unset(NameSel, KeySel),
    Mv(NameSel, NameSel),
    MvField(NameSel, KeySel, KeySel),
    Rm(NameSel),
    Import(Vec<GenEntry>, bool),
}

fn name_of(r: &Ref, s: &NameSel) -> Vec<u8> {
    let pick = |i: &Index| {
        r.keys()
            .nth(i.index(r.len().max(1)))
            .cloned()
            .unwrap_or_else(|| b"a".to_vec())
    };
    match s {
        NameSel::Lit(t) => t.0.clone(),
        NameSel::Pick(i) => pick(i),
        NameSel::PickSuffixed(i) => suffixed(&pick(i)),
    }
}

fn key_of(r: &Ref, entry: &[u8], s: &KeySel) -> Vec<u8> {
    match s {
        KeySel::Lit(t) => t.0.clone(),
        KeySel::Pick(i, c) => match r.get(entry).filter(|fs| !fs.is_empty()) {
            None => b"password".to_vec(),
            Some(fs) => {
                let k = &fs[i.index(fs.len())].0;
                match c {
                    Case::Same => k.clone(),
                    Case::Upper => k.to_ascii_uppercase(),
                    Case::Lower => k.to_ascii_lowercase(),
                }
            }
        },
    }
}

/// Keeps the valid part of a generated import: valid names (first wins),
/// valid keys and values, keys unique under ASCII case-folding.
fn import_ref(r: &Ref, gen_entries: &[GenEntry]) -> Ref {
    let mut out = Ref::new();
    for (sel, fields) in gen_entries {
        let name = name_of(r, sel);
        if name_err(&name).is_some() || out.contains_key(&name) {
            continue;
        }
        let mut fs: Vec<RField> = Vec::new();
        for (k, s, v) in fields {
            let ok = key_err(&k.0).is_none() && value_err(&v.0).is_none();
            if ok && !fs.iter().any(|f| ci(&f.0, &k.0)) {
                fs.push((k.0.clone(), *s, v.0.clone()));
            }
        }
        out.insert(name, fs);
    }
    out
}

fn resolve(r: &Ref, op: &Op) -> Act {
    match op {
        Op::Add(n) => Act::Add(name_of(r, n)),
        Op::Set(n, k, s, v) => {
            let n = name_of(r, n);
            let k = key_of(r, &n, k);
            Act::Set(n, k, *s, v.0.clone())
        }
        Op::Unset(n, k) => {
            let n = name_of(r, n);
            let k = key_of(r, &n, k);
            Act::Unset(n, k)
        }
        Op::Mv(o, n) => Act::Mv(name_of(r, o), name_of(r, n)),
        Op::MvField(n, o, k) => {
            let n = name_of(r, n);
            let (o, k) = (key_of(r, &n, o), key_of(r, &n, k));
            Act::MvField(n, o, k)
        }
        Op::Rm(n) => Act::Rm(name_of(r, n)),
        Op::Import(e, s) => Act::Import(import_ref(r, e), *s),
    }
}

const CHARS: &[char] = &[
    'a',
    'b',
    'A',
    'B',
    'k',
    '\u{e9}',
    'e',
    '\u{301}',
    '\u{df}',
    '\u{130}',
    '\u{1f511}',
    '\u{202e}',
    ' ',
    '\u{a0}',
    '\u{3000}',
    '\n',
    '\u{1b}',
    '\u{85}',
    '\u{7f}',
    '(',
    ')',
];

fn chars(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop::sample::select(CHARS), 0..=max)
        .prop_map(|cs| cs.into_iter().collect::<String>().into_bytes())
}

fn s(x: &str) -> Vec<u8> {
    x.as_bytes().to_vec()
}

/// Adversarial names: near-duplicates (case, NFC/NFD, whitespace, the
/// import suffix), every limit length, and invalid ones.
fn name_pool() -> Vec<Vec<u8>> {
    vec![
        s("a"),
        s("A"),
        s("a "),
        s(" a"),
        s("a (imported)"),
        s("a (imported) (imported)"),
        s("\u{e9}"),
        s("e\u{301}"),
        s("bank"),
        s("Bank"),
        s("BANK"),
        s(&"x".repeat(256)),
        s(&"x".repeat(257)),
        s(&"y".repeat(245)),
        s(&"y".repeat(246)),
        s(&"\u{1f511}".repeat(64)),
        s(&("\u{1f511}".repeat(64) + "a")),
        s("\u{202e}evil"),
        s(""),
        s("a\u{1b}b"),
        s("a\u{85}"),
        s("\u{a0}a"),
        s("a\nb"),
        vec![0xff],
        vec![b'a', 0xc3],
    ]
}

fn key_pool() -> Vec<Vec<u8>> {
    vec![
        s("password"),
        s("Password"),
        s("PASSWORD"),
        s("user"),
        s("pin"),
        s("notes"),
        s(&"k".repeat(64)),
        s(&"k".repeat(65)),
        s("\u{fc}"),
        s("\u{dc}"),
        s(" lead"),
        s("trail "),
        s("x y"),
        s(""),
        s("a\tb"),
        vec![0xff],
    ]
}

fn value_pool() -> Vec<Vec<u8>> {
    vec![
        s(""),
        s("hunter2"),
        s("line 1\nline 2"),
        s("\r"),
        s("\0"),
        s("a\u{85}"),
        vec![0xff, 0xfe],
    ]
}

fn txt(v: impl Strategy<Value = Vec<u8>>) -> impl Strategy<Value = Txt> {
    v.prop_map(Txt)
}

fn lit_name() -> impl Strategy<Value = Txt> {
    txt(prop_oneof![
        8 => prop::sample::select(name_pool()),
        3 => chars(6),
        1 => (120usize..=130).prop_map(|n| s(&"\u{e9}".repeat(n))),
    ])
}

fn name_sel() -> impl Strategy<Value = NameSel> {
    prop_oneof![
        4 => lit_name().prop_map(NameSel::Lit),
        5 => any::<Index>().prop_map(NameSel::Pick),
        1 => any::<Index>().prop_map(NameSel::PickSuffixed),
    ]
}

/// An existing entry, mostly: the target of set, unset, mvfield, rm.
fn target_sel() -> impl Strategy<Value = NameSel> {
    prop_oneof![
        1 => lit_name().prop_map(NameSel::Lit),
        6 => any::<Index>().prop_map(NameSel::Pick),
    ]
}

fn lit_key() -> impl Strategy<Value = Txt> {
    txt(prop_oneof![
        8 => prop::sample::select(key_pool()),
        2 => chars(5),
        1 => (60usize..=66).prop_map(|n| s(&"k".repeat(n))),
    ])
}

fn key_sel() -> impl Strategy<Value = KeySel> {
    let case = prop_oneof![Just(Case::Same), Just(Case::Upper), Just(Case::Lower)];
    prop_oneof![
        3 => lit_key().prop_map(KeySel::Lit),
        2 => (any::<Index>(), case).prop_map(|(i, c)| KeySel::Pick(i, c)),
    ]
}

fn value() -> impl Strategy<Value = Txt> {
    txt(prop_oneof![
        4 => chars(20),
        2 => prop::sample::select(value_pool()),
        3 => Just(s(&"v".repeat(4096))),
        2 => (4090usize..=4097).prop_map(|n| s(&"v".repeat(n))),
        1 => (2046usize..=2049).prop_map(|n| s(&"\u{e9}".repeat(n))),
    ])
}

fn import_entries() -> impl Strategy<Value = Vec<GenEntry>> {
    let field = (lit_key(), any::<bool>(), value());
    prop::collection::vec((name_sel(), prop::collection::vec(field, 0..4)), 0..5)
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => name_sel().prop_map(Op::Add),
        8 => (target_sel(), key_sel(), any::<bool>(), value())
            .prop_map(|(n, k, s, v)| Op::Set(n, k, s, v)),
        2 => (target_sel(), key_sel()).prop_map(|(n, k)| Op::Unset(n, k)),
        2 => (name_sel(), name_sel()).prop_map(|(o, n)| Op::Mv(o, n)),
        2 => (target_sel(), key_sel(), key_sel()).prop_map(|(n, o, k)| Op::MvField(n, o, k)),
        1 => target_sel().prop_map(Op::Rm),
        2 => (import_entries(), any::<bool>()).prop_map(|(e, s)| Op::Import(e, s)),
    ]
}

// ------------------------------------------------------------ fixtures

/// Key material shared by every case of a test: one KDF run per test.
struct Keys<'k> {
    kek: &'k [u8],
    dek: &'k [u8],
    h0: Header,
}

fn with_keys(f: impl FnOnce(&Keys<'_>)) {
    let mut a = arena();
    let mut s = a.slots().expect("slots");
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).expect("nfc");
    let params = floor_params();
    let (h0, _) = vault::init(s.pw2.expose(), params, &mut s.kek, &mut s.dek, false).expect("init");
    crypto::derive_kek(s.pw2.expose(), &h0.salt, params, &mut s.kek, false).expect("kek");
    f(&Keys {
        kek: s.kek.expose(),
        dek: s.dek.expose(),
        h0,
    });
}

/// The vault file: on disk through `store` (natively), or only the last
/// sealed file (Miri isolation forbids file I/O).
struct Disk {
    tmp: Option<tempfile::TempDir>,
    store: Option<Store>,
    last: Vec<u8>,
}

impl Disk {
    fn new() -> Disk {
        let tmp = (!cfg!(miri)).then(|| tempfile::tempdir().expect("tempdir"));
        let store = tmp
            .as_ref()
            .map(|t| Store::create(paths(t), false).expect("create"));
        Disk {
            tmp,
            store,
            last: Vec::new(),
        }
    }

    fn save(&mut self, file: Vec<u8>) {
        if let Some(st) = &mut self.store {
            st.save(&file).expect("store save");
        }
        self.last = file;
    }

    /// Closes and reopens the store; returns the file read from disk.
    fn reopen(&mut self) -> Vec<u8> {
        let Some(t) = &self.tmp else {
            return self.last.clone();
        };
        self.store = None;
        let (st, file) = Store::open(paths(t), false).expect("open");
        self.store = Some(st);
        assert!(file == self.last, "file on disk differs from the last save");
        file
    }

    /// Bytes on disk and the directory listing (natively).
    fn snapshot(&self) -> (Vec<u8>, Vec<String>) {
        let Some(t) = &self.tmp else {
            return (self.last.clone(), Vec::new());
        };
        let p = paths(t);
        let dir = p.vault.parent().expect("dir");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf8"))
            .collect();
        names.sort();
        (std::fs::read(&p.vault).expect("read"), names)
    }
}

fn paths(t: &tempfile::TempDir) -> Paths {
    Paths {
        vault: t.path().join("data/vault.pwv"),
        state: t.path().join("state/state"),
    }
}

/// Puts the canonical body of `r` into a fresh model's live half.
fn model_of<'a>(
    live: pwv::secmem::SecretSlot<'a>,
    scratch: pwv::secmem::SecretSlot<'a>,
    r: &Ref,
) -> Model<'a> {
    let mut live = live;
    put(&mut live, &serialize(r));
    Model::new(live, scratch).expect("model")
}

fn label(r: &Result<usize, E>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(E::EntryExists) => "EntryExists",
        Err(E::FieldExists) => "FieldExists",
        Err(E::NoEntry) => "NoEntry",
        Err(E::NoField) => "NoField",
        Err(E::Invalid(_)) => "Invalid",
        Err(E::Capacity) => "Capacity",
        Err(_) => "other",
    }
}

fn cases(native: u32) -> Config {
    // Miri (T-SAN-2) interprets every instruction: fewer cases there only,
    // 2 unless PROPTEST_CASES is set (CI runs T-VAULT-1's two cases in two
    // jobs, one case each with its own PROPTEST_RNG_SEED).
    let miri = std::env::var("PROPTEST_CASES").map_or(2, |_| Config::default().cases);
    let mut c = Config::with_cases(if cfg!(miri) { miri } else { native });
    c.source_file = Some(file!());
    c.failure_persistence = if cfg!(miri) {
        None
    } else {
        Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        )))
    };
    c
}

// ------------------------------------------------------------ T-VAULT-1

/// One T-VAULT-1 case: an empty vault is created and saved, then the
/// operations run in segments of 10. Each segment reopens the vault from
/// disk (store open, DEK unwrap, decrypt), checks it against the reference,
/// applies its operations to both sides comparing the result and the state
/// after every one, then seals and saves.
fn t_vault_1_case(
    keys: &Keys<'_>,
    size: usize,
    fill: usize,
    ops: &[Op],
    seen: &RefCell<BTreeMap<String, usize>>,
) -> Result<(), TestCaseError> {
    let fill = if size == MIN_ARENA { fill } else { 0 };
    let mut arena = SecureArena::new(size, true).expect("arena");
    let mut disk = Disk::new();
    let mut h = keys.h0.clone();
    {
        let s = arena.slots().expect("slots");
        prop_assert_eq!(s.vault_a.capacity(), s.vault_b.capacity());
        let mut m = if fill == 0 {
            Model::new(s.vault_a, s.vault_b).expect("empty model")
        } else {
            model_of(s.vault_a, s.vault_b, &filler(fill))
        };
        disk.save(m.seal(keys.dek, &mut h).expect("first save"));
    }
    let mut r = filler(fill);
    let mut at = 0;
    for seg in ops.chunks(10).chain([&[][..]]) {
        let file = disk.reopen();
        let mut s = arena.slots().expect("slots");
        let opened = vault::open_with_kek(&file, keys.kek, &mut s.dek, &mut s.vault_a);
        prop_assert!(opened.as_ref().is_ok_and(|o| *o == h), "op {at}: reopen");
        let cap = s.vault_b.capacity();
        let mut m = Model::new(s.vault_a, s.vault_b).expect("model");
        same(&m, &r, at, true)?;
        for op in seg {
            let act = resolve(&r, op);
            let want = ref_apply(&mut r, &act, cap);
            let before = want.is_err().then(|| m.body().to_vec());
            let got = model_apply(&mut m, &act);
            prop_assert_eq!(got, want, "op {} ({})", at, act.kind());
            *seen
                .borrow_mut()
                .entry(format!("{}:{}", act.kind(), label(&want)))
                .or_default() += 1;
            prop_assert!(m.scratch().is_empty(), "op {at}: scratch not wiped");
            if let Some(b) = before {
                prop_assert!(m.body() == b, "op {at}: failed op changed the model");
            }
            same(&m, &r, at, false)?;
            for n in act.names() {
                let hit = m.get(n).is_some();
                prop_assert_eq!(hit, r.contains_key(n), "op {}: get", at);
            }
            at += 1;
        }
        same(&m, &r, at, true)?;
        let g = h.generation;
        let file = m.seal(s.dek.expose(), &mut h).expect("seal");
        prop_assert_eq!(h.generation, g + 1);
        prop_assert!(m.scratch().is_empty(), "op {at}: scratch not wiped by seal");
        disk.save(file);
    }
    Ok(())
}

/// `n` synthetic entries of about 4 KiB each, so cases in the smallest
/// arena start near its capacity and reach `Capacity` errors.
fn filler(n: usize) -> Ref {
    (0..n)
        .map(|i| {
            (
                s(&format!("fill {i:02}")),
                vec![(s("f"), false, s(&"f".repeat(4000)))],
            )
        })
        .collect()
}

#[test]
fn t_vault_1_model_matches_reference() {
    let seen = RefCell::new(BTreeMap::new());
    with_keys(|keys| {
        let sizes = if cfg!(miri) {
            vec![MIN_ARENA]
        } else {
            vec![MIN_ARENA, DEFAULT_ARENA]
        };
        let strategy = (
            prop::sample::select(sizes),
            // Under Miri, no prefill: ~120 KiB bodies per op are out of reach.
            0usize..=if cfg!(miri) { 0 } else { 30 },
            prop::collection::vec(op(), 0..=200),
        );
        let mut runner = TestRunner::new(cases(256));
        let res = runner.run(&strategy, |(size, fill, ops)| {
            t_vault_1_case(keys, size, fill, &ops, &seen)
        });
        if let Err(e) = res {
            panic!("T-VAULT-1: {e}");
        }
    });
    if cfg!(miri) {
        return;
    }
    // Non-vacuity: every operation succeeded somewhere, and every error
    // class was produced. Counts are summed over all cases.
    let seen = seen.into_inner();
    let count = |k: &str| seen.get(k).copied().unwrap_or(0);
    for kind in [
        "add",
        "set",
        "unset",
        "mv",
        "mvfield",
        "rm",
        "import",
        "import-suffix",
    ] {
        assert!(
            count(&format!("{kind}:ok")) > 0,
            "{kind} never succeeded: {seen:?}"
        );
    }
    for (kind, e) in [
        ("add", "EntryExists"),
        ("add", "Invalid"),
        ("mv", "EntryExists"),
        ("mv", "NoEntry"),
        ("mvfield", "FieldExists"),
        ("mvfield", "NoField"),
        ("set", "Invalid"),
        ("set", "Capacity"),
        ("unset", "NoField"),
        ("rm", "NoEntry"),
        ("import", "EntryExists"),
        ("import-suffix", "EntryExists"),
        ("import-suffix", "Invalid"),
    ] {
        assert!(
            count(&format!("{kind}:{e}")) > 0,
            "{kind}:{e} never seen: {seen:?}"
        );
    }
}

// ------------------------------------------------------------ T-VAULT-2

/// Near-duplicates and limit lengths: "a" and "a (imported)", "A", NFC
/// and NFD spellings, keys differing only in ASCII case.
fn collision_fixture() -> Ref {
    let f = |k: &str, sens, v: &str| (s(k), sens, s(v));
    BTreeMap::from([
        (
            s("a"),
            vec![f("user", false, "u1"), f("Password", true, "p1")],
        ),
        (s("a (imported)"), vec![f("pin", true, "0000")]),
        (s("A"), vec![]),
        (
            s("bank"),
            vec![
                f("username", false, "alice"),
                f("password", true, "c0rrect"),
                f("Notes", false, "l1\nl2"),
                f(&"k".repeat(64), false, ""),
            ],
        ),
        (s("\u{e9}"), vec![f("\u{fc}", false, "x")]),
        (
            s("e\u{301}"),
            vec![f("\u{dc}", false, "y"), f("\u{fc}", true, "z")],
        ),
        (s(&"x".repeat(256)), vec![]),
        (s(&"y".repeat(245)), vec![f("pin", true, "1")]),
    ])
}

/// Every colliding `add`, `mv`, `mvfield`, and `import` of `r`, with the
/// error it must return.
fn colliding(r: &Ref) -> Vec<(Act, E)> {
    let mut out = Vec::new();
    let one = |n: &[u8]| Ref::from([(n.to_vec(), vec![(s("k"), false, s("v"))])]);
    for (n, fs) in r {
        out.push((Act::Add(n.clone()), E::EntryExists));
        for o in r.keys().filter(|o| *o != n) {
            out.push((Act::Mv(o.clone(), n.clone()), E::EntryExists));
        }
        for (i, (old, ..)) in fs.iter().enumerate() {
            for (_, (new, ..)) in fs.iter().enumerate().filter(|(j, _)| *j != i) {
                for k in [
                    new.clone(),
                    new.to_ascii_uppercase(),
                    new.to_ascii_lowercase(),
                ] {
                    out.push((Act::MvField(n.clone(), old.clone(), k), E::FieldExists));
                }
            }
        }
        // Abort mode: the colliding name alone, and between new names.
        out.push((Act::Import(one(n), false), E::EntryExists));
        let mut mixed = one(n);
        mixed.insert(s("0 new first"), vec![]);
        mixed.insert(s("~ new last"), vec![(s("k"), true, s("v"))]);
        out.push((Act::Import(mixed, false), E::EntryExists));
        // Suffix mode: the suffixed name is taken too.
        if r.contains_key(&suffixed(n)) {
            out.push((Act::Import(one(n), true), E::EntryExists));
        }
        // Suffix mode: the suffixed name collides with another import.
        if n.len() + IMPORT_SUFFIX.len() <= format::MAX_NAME && !r.contains_key(&suffixed(n)) {
            let mut both = one(n);
            both.insert(suffixed(n), vec![]);
            out.push((Act::Import(both, true), E::EntryExists));
        }
    }
    out
}

/// T-VAULT-2 for one model: every colliding operation returns the expected
/// `Err`, and the model body and the vault file (bytes and directory) are
/// byte-identical to before. The CLI saves only after a successful
/// operation, so this applies the same rule.
fn t_vault_2_check(keys: &Keys<'_>, r: &Ref) -> Result<usize, TestCaseError> {
    let mut a = arena();
    let s = a.slots().expect("slots");
    let mut m = model_of(s.vault_a, s.vault_b, r);
    let mut disk = Disk::new();
    let mut h = keys.h0.clone();
    disk.save(m.seal(keys.dek, &mut h).expect("seal"));
    let file = disk.snapshot();
    let body = m.body().to_vec();
    let acts = colliding(r);
    for (i, (act, want)) in acts.iter().enumerate() {
        let got = model_apply(&mut m, act);
        prop_assert_eq!(got, Err(*want), "collision {} ({})", i, act.kind());
        if got.is_ok() {
            disk.save(m.seal(keys.dek, &mut h).expect("seal"));
        }
        prop_assert!(m.body() == body, "collision {i}: model changed");
        prop_assert!(m.scratch().is_empty(), "collision {i}: scratch not wiped");
        prop_assert!(disk.snapshot() == file, "collision {i}: file changed");
        same(&m, r, i, true)?;
    }
    // Positive control: a non-colliding change is saved and changes the file.
    m.add(b"zz fresh").expect("add");
    disk.save(m.seal(keys.dek, &mut h).expect("seal"));
    prop_assert!(disk.snapshot() != file, "positive control");
    Ok(acts.len())
}

#[test]
fn t_vault_2_collisions_leave_model_and_file_identical() {
    with_keys(|keys| {
        let n = t_vault_2_check(keys, &collision_fixture()).expect("T-VAULT-2");
        assert!(n > 100, "only {n} collisions exercised");
    });
}

/// A random valid model: generated entries (redacted in failure output),
/// built into a reference by [`build_ref`] inside the test.
#[derive(Clone, Debug)]
struct RefGen(Vec<GenEntry>, Vec<Index>);

fn ref_gen() -> impl Strategy<Value = RefGen> {
    let field = (lit_key(), any::<bool>(), value());
    let entry = (
        lit_name().prop_map(NameSel::Lit),
        prop::collection::vec(field, 0..5),
    );
    (
        prop::collection::vec(entry, 1..8),
        prop::collection::vec(any::<Index>(), 0..3),
    )
        .prop_map(|(es, sfx)| RefGen(es, sfx))
}

/// The valid part of `g`, at least one entry, plus some "x (imported)"
/// partners for secondary collisions.
fn build_ref(g: &RefGen) -> Ref {
    let mut r = import_ref(&Ref::new(), &g.0);
    if r.is_empty() {
        r.insert(s("a"), vec![]);
    }
    for i in &g.1 {
        let n = suffixed(&name_of(&r, &NameSel::Pick(*i)));
        if name_err(&n).is_none() {
            r.entry(n).or_default();
        }
    }
    r
}

#[test]
fn t_vault_2_random_models() {
    with_keys(|keys| {
        let mut runner = TestRunner::new(cases(64));
        let res = runner.run(&ref_gen(), |g| {
            t_vault_2_check(keys, &build_ref(&g)).map(|_| ())
        });
        if let Err(e) = res {
            panic!("T-VAULT-2: {e}");
        }
    });
}

// ------------------------------------------------------------ operations

fn sample() -> Ref {
    let mut r = collision_fixture();
    r.retain(|n, _| n.len() < 10);
    r
}

/// Runs `f` on a model holding `r` in a default-size arena.
fn with_model(r: &Ref, f: impl FnOnce(&mut Model<'_>)) {
    let mut a = arena();
    let s = a.slots().expect("slots");
    let mut m = model_of(s.vault_a, s.vault_b, r);
    f(&mut m);
}

/// One operation against the reference: same result, same state.
fn check_act(m: &mut Model<'_>, r: &mut Ref, act: &Act) -> Result<usize, E> {
    let cap = m.scratch().capacity();
    let want = ref_apply(r, act, cap);
    let got = model_apply(m, act);
    assert_eq!(got, want, "{}", act.kind());
    same(m, r, 0, true).expect("same");
    got
}

#[test]
fn new_on_empty_slot_is_the_empty_vault() {
    let mut a = arena();
    let s = a.slots().expect("slots");
    let m = Model::new(s.vault_a, s.vault_b).expect("model");
    assert!(m.is_empty());
    assert_eq!(m.body(), serialize(&Ref::new()));
    assert!(m.get(b"a").is_none());
}

#[test]
fn new_rejects_an_invalid_body() {
    let mut a = arena();
    let s = a.slots().expect("slots");
    let mut live = s.vault_a;
    let mut b = serialize(&sample());
    b[0] = b'X';
    put(&mut live, &b);
    assert!(matches!(
        Model::new(live, s.vault_b),
        Err(E::Format(F::BodyMagic))
    ));
}

#[test]
fn set_replaces_in_place_and_keeps_the_key_spelling() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        let act = Act::Set(s("bank"), s("PASSWORD"), false, s("new"));
        check_act(m, &mut r, &act).expect("set");
        let e = m.get(b"bank").expect("bank");
        let f: Vec<_> = e.fields.collect();
        assert_eq!(f[1].key, b"password");
        assert!(!f[1].sensitive);
        assert_eq!(f[1].value, b"new");
        assert_eq!(f.len(), 4);
    });
}

#[test]
fn renames_to_self_are_not_collisions() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        let before = m.body().to_vec();
        check_act(m, &mut r, &Act::Mv(s("bank"), s("bank"))).expect("mv self");
        assert_eq!(m.body(), before);
        // A case-only change of a key renames that field.
        let act = Act::MvField(s("bank"), s("password"), s("PassWord"));
        check_act(m, &mut r, &act).expect("mvfield case");
        let f: Vec<_> = m.get(b"bank").expect("bank").fields.collect();
        assert_eq!(f[1].key, b"PassWord");
        // Non-ASCII case is not folded: U+00FC and U+00DC are different keys.
        let act = Act::MvField(s("\u{e9}"), s("\u{fc}"), s("\u{dc}"));
        check_act(m, &mut r, &act).expect("mvfield non-ascii");
    });
}

#[test]
fn mv_reorders_and_keeps_fields() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        check_act(m, &mut r, &Act::Mv(s("bank"), s("0 first"))).expect("mv");
        check_act(m, &mut r, &Act::Mv(s("0 first"), s("\u{ff}last"))).expect("mv");
        assert_eq!(
            m.entries().last().expect("last").name,
            "\u{ff}last".as_bytes()
        );
    });
}

#[test]
fn input_validation_is_checked_first_and_named() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        let cases = [
            (Act::Add(s("")), F::NameLength(0)),
            (Act::Add(s(&"x".repeat(257))), F::NameLength(0)),
            (Act::Add(vec![0xff]), F::NameUtf8(0)),
            (Act::Add(s("a\u{1b}")), F::NameControl(0)),
            (Act::Add(s("a\u{85}")), F::NameControl(0)),
            (Act::Add(s("\u{a0}a")), F::NameWhitespace(0)),
            (Act::Add(s("a\u{3000}")), F::NameWhitespace(0)),
            (Act::Mv(s("nope"), s(" a")), F::NameWhitespace(0)),
            (Act::Set(s("nope"), s(""), false, s("v")), F::KeyLength(0)),
            (
                Act::Set(s("a"), s(&"k".repeat(65)), false, s("v")),
                F::KeyLength(0),
            ),
            (Act::Set(s("a"), vec![0xc3], false, s("v")), F::KeyUtf8(0)),
            (Act::Set(s("a"), s("a\tb"), false, s("v")), F::KeyControl(0)),
            (
                Act::Set(s("a"), s("k"), false, s(&"v".repeat(4097))),
                F::ValueLength(0),
            ),
            (Act::Set(s("a"), s("k"), false, vec![0xff]), F::ValueUtf8(0)),
            (
                Act::Set(s("a"), s("k"), false, s("a\rb")),
                F::ValueControl(0),
            ),
            (Act::MvField(s("nope"), s("x"), s("")), F::KeyLength(0)),
        ];
        for (i, (act, e)) in cases.iter().enumerate() {
            let before = m.body().to_vec();
            assert_eq!(check_act(m, &mut r, act), Err(E::Invalid(*e)), "case {i}");
            assert_eq!(m.body(), before, "case {i}");
        }
        // At the limits: accepted.
        let ok = [
            Act::Add(s(&"x".repeat(256))),
            Act::Add(s(&"\u{1f511}".repeat(64))),
            Act::Set(s("a"), s(&"k".repeat(64)), true, s(&"v".repeat(4096))),
            Act::Set(s("a"), s("multi"), false, s(&"\u{e9}".repeat(2048))),
            Act::Set(s("a"), s("empty"), false, s("")),
            Act::Set(s("a"), s(" spaced key "), false, s("l1\nl2")),
            Act::Add(s("\u{202e}rtl")),
        ];
        for act in &ok {
            check_act(m, &mut r, act).expect("at the limit");
        }
    });
}

#[test]
fn missing_entries_and_fields() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        let cases = [
            (Act::Set(s("nope"), s("k"), false, s("v")), E::NoEntry),
            (Act::Set(s("Bank"), s("k"), false, s("v")), E::NoEntry),
            (Act::Unset(s("nope"), s("k")), E::NoEntry),
            (Act::Unset(s("bank"), s("nope")), E::NoField),
            (Act::Mv(s("nope"), s("new")), E::NoEntry),
            (Act::MvField(s("nope"), s("k"), s("j")), E::NoEntry),
            (Act::MvField(s("bank"), s("nope"), s("j")), E::NoField),
            (Act::Rm(s("nope")), E::NoEntry),
            (Act::Rm(s("e")), E::NoEntry),
        ];
        for (act, e) in &cases {
            assert_eq!(check_act(m, &mut r, act), Err(*e), "{}", act.kind());
        }
        check_act(m, &mut r, &Act::Unset(s("bank"), s("NOTES"))).expect("unset");
        check_act(m, &mut r, &Act::Rm(s("bank"))).expect("rm");
        assert!(m.get(b"bank").is_none());
    });
}

#[test]
fn field_and_entry_limits() {
    let mut r = Ref::from([(s("e"), Vec::new())]);
    with_model(&r.clone(), |m| {
        for i in 0..64 {
            let act = Act::Set(s("e"), s(&format!("k{i}")), false, s("v"));
            check_act(m, &mut r, &act).expect("field");
        }
        let act = Act::Set(s("e"), s("k64"), false, s("v"));
        assert_eq!(
            check_act(m, &mut r, &act),
            Err(E::Invalid(F::FieldCount(0)))
        );
        // Replacing an existing field at the limit is fine.
        check_act(m, &mut r, &Act::Set(s("e"), s("K63"), true, s("w"))).expect("replace");
    });
    // 10,000 entries: one more add or import entry is refused.
    let full: Ref = (0..format::MAX_ENTRIES)
        .map(|i| (s(&format!("{i:05}")), vec![]))
        .collect();
    let mut r = full.clone();
    let mut a = SecureArena::new(DEFAULT_ARENA, true).expect("arena");
    let s2 = a.slots().expect("slots");
    let mut m = model_of(s2.vault_a, s2.vault_b, &full);
    assert_eq!(m.len(), 10_000);
    let act = Act::Add(s("new"));
    assert_eq!(
        check_act(&mut m, &mut r, &act),
        Err(E::Invalid(F::EntryCount))
    );
    let act = Act::Import(Ref::from([(s("new"), vec![])]), false);
    assert_eq!(
        check_act(&mut m, &mut r, &act),
        Err(E::Invalid(F::EntryCount))
    );
    check_act(&mut m, &mut r, &Act::Rm(s("00000"))).expect("rm");
    check_act(&mut m, &mut r, &Act::Add(s("new"))).expect("add at the limit");
}

#[test]
fn capacity_is_a_clean_error() {
    let mut a = SecureArena::new(MIN_ARENA, true).expect("arena");
    let s2 = a.slots().expect("slots");
    let cap = s2.vault_b.capacity();
    let mut r = Ref::from([(s("e"), Vec::new())]);
    let mut m = model_of(s2.vault_a, s2.vault_b, &r);
    let mut errors = 0;
    for i in 0..64 {
        let name = s(&format!("e{i:02}"));
        if check_act(&mut m, &mut r, &Act::Add(name.clone())).is_err() {
            errors += 1;
            continue;
        }
        for j in 0..10 {
            let act = Act::Set(
                name.clone(),
                s(&format!("k{j}")),
                true,
                s(&"v".repeat(4096)),
            );
            let before = m.body().to_vec();
            match check_act(&mut m, &mut r, &act) {
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(e, E::Capacity);
                    assert_eq!(m.body(), before);
                    errors += 1;
                }
            }
        }
    }
    assert!(errors > 0, "capacity never reached");
    assert!(m.body().len() <= cap);
}

#[test]
fn error_messages_are_fixed_and_content_free() {
    for e in [
        E::EntryExists,
        E::FieldExists,
        E::NoEntry,
        E::NoField,
        E::Capacity,
        E::Invalid(F::NameControl(3)),
    ] {
        let msg = e.message();
        assert!(!msg.is_empty());
        for secret in ["bank", "password", "hunter2", "3"] {
            assert!(!msg.contains(secret), "{e:?}");
        }
    }
}

// ------------------------------------------------------------ import

#[test]
fn import_merges_with_suffixes_and_counts() {
    let mut r = sample();
    with_model(&r.clone(), |m| {
        let imp = Ref::from([
            (s("0 new"), vec![(s("k"), true, s("v"))]),
            (s("bank"), vec![(s("password"), true, s("other"))]),
            (s("e\u{301}"), vec![]),
            (s("zz"), vec![]),
        ]);
        let act = Act::Import(imp.clone(), false);
        assert_eq!(check_act(m, &mut r, &act), Err(E::EntryExists));
        assert_eq!(check_act(m, &mut r, &Act::Import(imp, true)), Ok(4));
        assert!(m.get(b"bank (imported)").is_some());
        assert!(m.get("e\u{301} (imported)".as_bytes()).is_some());
        // A suffixed name can sort after other imported names.
        let imp = Ref::from([(s("a"), vec![]), (s("a !"), vec![])]);
        assert_eq!(check_act(m, &mut r, &Act::Import(imp, true)), Ok(2));
        // Empty import: nothing changes, count 0.
        let before = m.body().to_vec();
        assert_eq!(check_act(m, &mut r, &Act::Import(Ref::new(), false)), Ok(0));
        assert_eq!(m.body(), before);
    });
}

#[test]
fn import_suffix_respects_the_name_limit() {
    let long = s(&"y".repeat(245));
    let longer = s(&"z".repeat(246));
    let mut r = Ref::from([(long.clone(), vec![]), (longer.clone(), vec![])]);
    with_model(&r.clone(), |m| {
        let imp = Ref::from([(s("a"), vec![]), (longer.clone(), vec![])]);
        let act = Act::Import(imp, true);
        assert_eq!(
            check_act(m, &mut r, &act),
            Err(E::Invalid(F::NameLength(1)))
        );
        let act = Act::Import(Ref::from([(long.clone(), vec![])]), true);
        assert_eq!(check_act(m, &mut r, &act), Ok(1));
        assert_eq!(m.get(&suffixed(&long)).expect("256 bytes").name.len(), 256);
    });
}

#[test]
fn import_one_save_one_generation() {
    with_keys(|keys| {
        let mut a = arena();
        let s2 = a.slots().expect("slots");
        let mut r = sample();
        let mut m = model_of(s2.vault_a, s2.vault_b, &r);
        let mut h = keys.h0.clone();
        let _ = m.seal(keys.dek, &mut h).expect("seal");
        let g = h.generation;
        let imp: Ref = (0..50).map(|i| (s(&format!("imp {i}")), vec![])).collect();
        let cap = m.scratch().capacity();
        assert_eq!(
            model_apply(&mut m, &Act::Import(imp.clone(), false)),
            Ok(50)
        );
        ref_apply(&mut r, &Act::Import(imp, false), cap).expect("ref");
        let file = m.seal(keys.dek, &mut h).expect("seal");
        assert_eq!(h.generation, g + 1);
        drop(m);
        let mut a2 = arena();
        let mut s3 = a2.slots().expect("slots");
        vault::open_with_kek(&file, keys.kek, &mut s3.dek, &mut s3.vault_a).expect("open");
        assert!(
            s3.vault_a.expose() == serialize(&r),
            "decrypted body differs"
        );
    });
}

/// The capacity rule of import: merged body + import body <= slot.
#[test]
fn import_capacity_rule() {
    let mut a = SecureArena::new(MIN_ARENA, true).expect("arena");
    let s2 = a.slots().expect("slots");
    let cap = s2.vault_b.capacity();
    let big = |tag: &str, n: usize| -> Ref {
        (0..n)
            .map(|i| {
                (
                    s(&format!("{tag}{i:03}")),
                    vec![(s("v"), false, s(&"v".repeat(4000)))],
                )
            })
            .collect()
    };
    let mut r = big("live", 8);
    let mut m = model_of(s2.vault_a, s2.vault_b, &r);
    let mut ok = 0;
    let mut refused = 0;
    for n in 0..30 {
        let imp = big("imp", n);
        let before = m.body().to_vec();
        let mut probe = r.clone();
        match check_act(&mut m, &mut r, &Act::Import(imp.clone(), false)) {
            Ok(k) => {
                assert_eq!(k, n);
                ok += 1;
                // Undo, so every size is tried against the same live body.
                for name in imp.keys() {
                    check_act(&mut m, &mut r, &Act::Rm(name.clone())).expect("rm");
                }
                assert_eq!(m.body(), before);
            }
            Err(e) => {
                assert_eq!(e, E::Capacity);
                assert_eq!(m.body(), before);
                probe.extend(imp.clone());
                assert!(body_len(&probe) + body_len(&imp) > cap);
                refused += 1;
            }
        }
    }
    assert!(ok > 1 && refused > 1, "ok {ok}, refused {refused}");
}

/// Section 15.5: the import parsing path rejects every truncation of a
/// valid body (raw cut, and entries cut with a consistent prefix), with
/// the model unchanged and the scratch half wiped.
#[test]
fn import_rejects_invalid_bodies_and_every_truncation() {
    let imp = Ref::from([
        (
            s("i1"),
            vec![(s("password"), true, s("x\ny")), (s("u"), false, s(""))],
        ),
        (s("i2 \u{1f511}"), vec![(s("k"), false, s("\u{202e}"))]),
        (s("i3"), vec![]),
    ]);
    let body = serialize(&imp);
    let r = sample();
    with_model(&r, |m| {
        let before = m.body().to_vec();
        let mut check = |input: &[u8], what: &str| {
            put(m.scratch(), input);
            let got = m.import(false);
            assert!(matches!(got, Err(E::Invalid(_))), "{what}: {got:?}");
            assert_eq!(m.body(), before, "{what}");
            assert!(m.scratch().is_empty(), "{what}");
        };
        for cut in 0..body.len() {
            check(&body[..cut], &format!("cut {cut}"));
        }
        let content = u32::from_le_bytes(body[4..8].try_into().expect("4")) as usize;
        for cut in 0..content {
            let mut b = body[..12 + cut].to_vec();
            b[4..8].copy_from_slice(&u32::try_from(cut).expect("u32").to_le_bytes());
            b.resize(padded_len(cut).expect("len"), 0);
            check(&b, &format!("entries cut {cut}"));
        }
        let mut b = body.clone();
        b.extend_from_slice(&[0; BLOCK]);
        check(&b, "non-minimal padding");
        put(m.scratch(), &body);
        assert_eq!(m.import(false), Ok(3));
    });
}

/// `entry_at` (the index's parser) on every truncation of a body, at every
/// offset: never panics, and on the full body yields exactly the entries.
#[test]
fn entry_at_on_truncations_and_every_offset() {
    let body = serialize(&sample());
    let offsets: Vec<usize> = parse_body(&body)
        .expect("valid")
        .map(|e| e.offset)
        .collect();
    for cut in 0..=body.len() {
        for at in 0..=body.len() + 1 {
            let _ = entry_at(&body[..cut], at).map(|e| e.fields.count());
        }
    }
    for (e, &o) in parse_body(&body).expect("valid").zip(&offsets) {
        let got = entry_at(&body, o).expect("entry");
        assert_eq!(got.name, e.name);
        assert_eq!(got.offset, o);
        assert!(got.fields.map(|f| f.value).eq(e.fields.map(|f| f.value)));
    }
}

// ------------------------------------------------------------ seal

#[test]
fn seal_leaves_the_model_and_wipes_scratch() {
    with_keys(|keys| {
        let r = sample();
        with_model(&r, |m| {
            let before = m.body().to_vec();
            let mut h = keys.h0.clone();
            let file = m.seal(keys.dek, &mut h).expect("seal");
            assert_eq!(h.generation, 1);
            assert_eq!(m.body(), before);
            assert!(m.scratch().is_empty());
            let mut a = arena();
            let mut s2 = a.slots().expect("slots");
            vault::open_with_kek(&file, keys.kek, &mut s2.dek, &mut s2.vault_a).expect("open");
            assert!(
                s2.vault_a.expose() == before.as_slice(),
                "decrypted body differs"
            );
        });
    });
}

// ------------------------------------------------------------ T-FUZZ-6 corpus

/// `fuzz_import` input: flags (bit 0: suffix mode), u16 length of the
/// first body (imported into an empty vault), then the second body.
#[cfg_attr(miri, allow(dead_code))]
fn fuzz_input(flags: u8, first: &Ref, second: &Ref) -> Vec<u8> {
    let (a, b) = (serialize(first), serialize(second));
    let len = u16::try_from(a.len()).expect("u16").to_le_bytes();
    [&[flags][..], &len, &a, &b].concat()
}

#[cfg_attr(miri, allow(dead_code))]
fn corpus_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let live = sample();
    let fresh = Ref::from([(s("new"), vec![(s("k"), true, s("v"))])]);
    let clash = Ref::from([(s("bank"), vec![]), (s("zz"), vec![])]);
    let secondary = Ref::from([(s("a"), vec![])]);
    vec![
        ("seed-disjoint", fuzz_input(0, &live, &fresh)),
        ("seed-clash-abort", fuzz_input(0, &live, &clash)),
        ("seed-clash-suffix", fuzz_input(1, &live, &clash)),
        ("seed-secondary", fuzz_input(1, &live, &secondary)),
    ]
}

/// The committed seeds equal the generated ones. To regenerate after a
/// deliberate change: `PWV_WRITE_CORPUS=1 cargo test --test vault corpus`.
#[cfg(not(miri))]
#[test]
#[allow(clippy::disallowed_methods, reason = "writes fuzz seeds; test-only")]
fn fuzz_import_corpus_seeds_are_committed() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/fuzz_import");
    let write = std::env::var_os("PWV_WRITE_CORPUS").is_some();
    for (name, bytes) in corpus_seeds() {
        let path = dir.join(name);
        if write {
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(&path, &bytes).expect("write seed");
        }
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(got == bytes, "{} is stale", path.display());
    }
}
