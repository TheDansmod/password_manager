//! T-FUZZ-6: import merge (spec Sections 12.2 and 14.10).
//!
//! Input: flags (bit 0: `--on-conflict suffix` for the second import),
//! u16 LE length of the first body, the first body, then the second body.
//! The first body is imported into an empty vault (abort mode); the second
//! is imported into the result. Each body is read into the scratch half,
//! as `import --from-stdin` does.
//!
//! Invariants: no panic; the scratch half is empty after every import; an
//! error leaves the live body byte-identical; an invalid body is refused
//! as `Invalid`; the outcome (merged entries, or the error class) equals
//! an independent oracle's; every merged entry is found through the index.

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::format::{MAX_ENTRIES, MAX_NAME, padded_len, parse_body};
use pwv::secmem::{MIN_ARENA, SecureArena};
use pwv::vault::{Error, IMPORT_SUFFIX, Model};
use std::collections::BTreeMap;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

type Fields = Vec<(Vec<u8>, bool, Vec<u8>)>;
type Map = BTreeMap<Vec<u8>, Fields>;

fn entries(body: &[u8]) -> Option<Vec<(Vec<u8>, Fields)>> {
    let es = parse_body(body).ok()?;
    let field = |f: pwv::format::FieldRef<'_>| (f.key.to_vec(), f.sensitive, f.value.to_vec());
    Some(
        es.map(|e| (e.name.to_vec(), e.fields.map(field).collect()))
            .collect(),
    )
}

fn len_of(m: &Map) -> usize {
    let c = m.iter().map(|(n, fs)| {
        4 + n.len()
            + fs.iter()
                .map(|(k, _, v)| 4 + k.len() + v.len())
                .sum::<usize>()
    });
    padded_len(c.sum()).unwrap()
}

/// The oracle: the merged model, or the error class (Section 12.2 and the
/// check order documented on `Model::import`).
fn expected(live: &Map, input: &[u8], suffix: bool, cap: usize) -> Result<Map, Error> {
    let Some(imp) = entries(input) else {
        return Err(Error::Invalid(parse_body(input).err().unwrap()));
    };
    for (i, (name, _)) in imp.iter().enumerate() {
        if live.contains_key(name) {
            if !suffix {
                return Err(Error::EntryExists);
            }
            if name.len() + IMPORT_SUFFIX.len() > MAX_NAME {
                let i = u32::try_from(i).unwrap();
                return Err(Error::Invalid(pwv::format::Error::NameLength(i)));
            }
        }
    }
    let mut out = live.clone();
    for (name, fs) in imp {
        let target = if live.contains_key(&name) {
            [&name[..], IMPORT_SUFFIX].concat()
        } else {
            name
        };
        if out.insert(target, fs).is_some() {
            return Err(Error::EntryExists);
        }
    }
    if out.len() > MAX_ENTRIES as usize {
        return Err(Error::Invalid(pwv::format::Error::EntryCount));
    }
    if len_of(&out) + input.len() > cap {
        return Err(Error::Capacity);
    }
    Ok(out)
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let (len, rest) = rest.split_at_checked(2).unwrap_or((&[0, 0], rest));
    let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
    let (first, second) = rest.split_at(len.min(rest.len()));
    let mut arena = SecureArena::new(MIN_ARENA, true).unwrap();
    let s = arena.slots().unwrap();
    let mut m = Model::new(s.vault_a, s.vault_b).unwrap();
    for (input, suffix) in [(first, false), (second, flags & 1 == 1)] {
        let before = m.body().to_vec();
        let live: Map = entries(&before).unwrap().into_iter().collect();
        let cap = m.scratch().capacity();
        let slot = m.scratch();
        if slot.set_len(input.len()).is_err() {
            continue;
        }
        slot.expose_mut().copy_from_slice(input);
        let got = m.import(suffix);
        assert!(m.scratch().is_empty(), "scratch not wiped");
        let want = expected(&live, input, suffix, cap);
        match (&got, &want) {
            (Ok(n), Ok(merged)) => {
                assert_eq!(*n, merged.len() - live.len());
                let now: Map = entries(m.body()).unwrap().into_iter().collect();
                assert!(now == *merged, "merge differs from the oracle");
                assert_eq!(m.len(), merged.len());
                for (name, fs) in merged {
                    let e = m.get(name).expect("index finds every entry");
                    assert_eq!(e.fields.count(), fs.len());
                }
            }
            (Err(g), Err(w)) => {
                assert_eq!(g, w);
                assert_eq!(m.body(), &before[..], "failed import changed the model");
            }
            _ => panic!(
                "import {:?} but the oracle says {:?}",
                got,
                want.map(|_| ())
            ),
        }
    }
});
