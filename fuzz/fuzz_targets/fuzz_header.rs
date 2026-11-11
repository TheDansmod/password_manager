//! T-FUZZ-1: header parser. Invariants: no panic; any accepted header
//! re-encodes to exactly its input bytes; an accepted file splits into
//! header, payload of `payload_len` bytes, and a 16-byte tag.

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::format::{HEADER_LEN, TAG_LEN, parse_header, split_file};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = parse_header(data) {
        assert_eq!(&h.encode()[..], &data[..HEADER_LEN]);
        assert!(h.file_len() <= pwv::format::MAX_FILE);
    }
    if let Ok((h, ct, tag)) = split_file(data) {
        assert_eq!(data.len(), h.file_len());
        assert_eq!(ct.len(), usize::try_from(h.payload_len).unwrap());
        assert_eq!(tag.len(), TAG_LEN);
    }
});
