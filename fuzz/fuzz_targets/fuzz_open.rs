//! T-FUZZ-3: full open with `testkdf` parameters (spec Section 14.10).
//!
//! First byte selects the mode; the rest is the input:
//! - even: the input is a vault file, unlocked with the fixed password of
//!   the golden vault `v1-small.pwv` (seed: that vault). Headers whose KDF
//!   cost exceeds 256 KiB or 4 passes take the post-KDF path with a fixed
//!   KEK instead, so one input cannot cost seconds.
//! - odd: the input is a candidate plaintext body. It is saved under a fresh
//!   vault (init + save) and must be accepted exactly when `parse_body`
//!   accepts it, then unlock must return the identical bytes.
//!
//! Invariants: no panic; failures leave the DEK and body slots empty.

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::crypto::{self, KdfParams};
use pwv::format::{parse_body, parse_header};
use pwv::secmem::{MIN_ARENA, SecretSlot, SecureArena};
use pwv::vault;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

const PASSWORD: &[u8] = "pwv golden \u{e9}t\u{e9}".as_bytes();

fn put(slot: &mut SecretSlot<'_>, b: &[u8]) -> bool {
    slot.set_len(b.len()).is_ok() && {
        slot.expose_mut().copy_from_slice(b);
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    let mut arena = SecureArena::new(MIN_ARENA, true).unwrap();
    let mut s = arena.slots().unwrap();
    if mode % 2 == 0 {
        let cheap = parse_header(input).is_ok_and(|h| h.kdf_m_kib <= 256 && h.kdf_t <= 4);
        let r = if cheap {
            put(&mut s.pw1, PASSWORD);
            let r = vault::unlock(
                input,
                &mut s.pw1,
                &mut s.pw2,
                &mut s.kek,
                &mut s.dek,
                &mut s.vault_a,
                false,
            )
            .map(|(h, _)| h);
            assert!(s.pw1.is_empty() && s.pw2.is_empty() && s.kek.is_empty());
            r
        } else {
            vault::open_with_kek(input, &[0x4b; 32], &mut s.dek, &mut s.vault_a)
        };
        match r {
            Ok(h) => {
                assert_eq!(h.file_len(), input.len());
                assert!(parse_body(s.vault_a.expose()).is_ok());
            }
            Err(_) => assert!(s.dek.is_empty() && s.vault_a.is_empty()),
        }
        return;
    }
    let params = KdfParams::for_write(crypto::KDF_M_WRITE_MIN, 3).unwrap();
    let pw = b"fuzz";
    let (mut h, _) = vault::init(pw, params, &mut s.kek, &mut s.dek, false).unwrap();
    if !put(&mut s.vault_a, input) {
        return;
    }
    let saved = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut());
    assert_eq!(saved.is_ok(), parse_body(input).is_ok());
    assert_eq!(s.vault_a.expose(), input, "save restores the plaintext");
    let Ok(file) = saved else {
        return;
    };
    put(&mut s.pw1, pw);
    vault::unlock(
        &file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_b,
        false,
    )
    .unwrap();
    assert_eq!(s.vault_b.expose(), input);
});
