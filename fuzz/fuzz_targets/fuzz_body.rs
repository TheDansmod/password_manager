//! T-FUZZ-2: body parser. Invariants: no panic; any accepted input
//! satisfies the round-trip identity serialize(parse(b)) = b (Section 7.3).

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::format::{BodyWriter, parse_body};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

fuzz_target!(|data: &[u8]| {
    let Ok(entries) = parse_body(data) else {
        return;
    };
    let count = entries.clone().count();
    let mut out = vec![0xA5u8; data.len()];
    let mut w = BodyWriter::new(&mut out);
    let mut n = 0u32;
    for e in entries {
        w.entry(e.name).unwrap();
        for f in e.fields {
            w.field(f.key, f.sensitive, f.value).unwrap();
        }
        n += 1;
    }
    assert_eq!(usize::try_from(n).unwrap(), count);
    assert_eq!(w.finish().unwrap(), data.len());
    assert_eq!(out, data);
});
