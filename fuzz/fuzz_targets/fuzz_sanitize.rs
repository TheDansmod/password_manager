//! T-FUZZ-5: `term::sanitize`. Invariants: no panic; the output is valid
//! UTF-8 and holds no control character and no bidirectional override;
//! clean input passes through unchanged.

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::term::{is_unsafe, sanitize};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    sanitize(data, &mut |chunk| {
        assert!(!chunk.is_empty());
        out.extend_from_slice(chunk);
    });
    let text = std::str::from_utf8(&out).expect("output is UTF-8");
    assert!(!text.chars().any(is_unsafe));
    assert!(out.len() >= data.len());
    if std::str::from_utf8(data).is_ok_and(|s| !s.chars().any(is_unsafe)) {
        assert_eq!(out, data);
    }
});
