//! M3 gate: T-KAT-1, T-KAT-2, T-CRY-1 – T-CRY-6, T-COMPAT-1 (spec Sections
//! 6 and 14.1, 14.3), plus the crypto primitives' contracts.
//!
//! Golden vaults are built with `testkdf`; without it they must be refused
//! by the production KDF floor, and T-CRY-1 runs on a fresh vault instead.

mod common;

use common::vaults::{
    self, Golden, Model, arena, floor_params, make_vault, put, read_body, unlock_model, write_body,
};
use pwv::crypto::{self, KdfParams, NONCE_LEN};
use pwv::format::{self, AAD_W_LEN, HEADER_LEN, parse_header};
use pwv::{cli, vault};
use std::collections::HashSet;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

const AUTH: vault::Error = vault::Error::Crypto(crypto::Error::Auth);

/// Deterministic test RNG (splitmix64).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

// ------------------------------------------------------------- KATs

/// T-KAT-1: RFC 9106 Section 5.3 (Argon2id v0x13, m = 32 KiB, t = 3,
/// p = 4, secret and associated data), through crypto's region wrapper.
#[test]
fn t_kat_1_argon2id_rfc9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let secret = [0x03; 8];
    let ctx =
        Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut a = arena();
    let mut s = a.slots().unwrap();
    s.kek.set_len(32).unwrap();
    let out = crypto::argon2_in_region(&ctx, &[0x01; 32], &[0x02; 16], s.kek.expose_mut(), false)
        .expect("argon2");
    assert_eq!(
        vaults::hex(s.kek.expose()),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
    assert!(out.region.1 > out.region.0);
}

/// T-KAT-2: draft-irtf-cfrg-xchacha-03, Appendix A.3.1, in place.
#[test]
fn t_kat_2_xchacha20poly1305_draft_a31() {
    let key: Vec<u8> = (0x80..=0x9f).collect();
    let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap());
    let aad = vaults::unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
               tip for the future, sunscreen would be it.";
    let ct = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
              731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
              2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
              21f9664c97637da9768812f615c68b13b52e";
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.dek, &key);
    put(&mut s.input, pt);
    let tag = crypto::seal(s.dek.expose(), &nonce, &aad, s.input.expose_mut()).unwrap();
    assert_eq!(vaults::hex(s.input.expose()), ct);
    assert_eq!(vaults::hex(&tag), "c0875924c1c7987947deafd8780acf49");
    crypto::open(s.dek.expose(), &nonce, &aad, s.input.expose_mut(), &tag).unwrap();
    assert_eq!(s.input.expose(), pt);
}

// ------------------------------------------------------------- primitives

#[test]
fn normalize_nfc_utf8_and_capacity() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    crypto::normalize("e\u{301}A\u{30a}".as_bytes(), &mut s.pw2).unwrap();
    assert_eq!(s.pw2.expose(), "\u{e9}\u{c5}".as_bytes());
    assert_eq!(
        crypto::normalize(b"\xff", &mut s.pw2),
        Err(crypto::Error::Password)
    );
    assert!(s.pw2.is_empty());
    // NFC can expand (U+0958 -> U+0915 U+093C, 3 -> 6 bytes); the result
    // must still fit the 1 KiB slot.
    let ok = "\u{958}".repeat(170);
    crypto::normalize(ok.as_bytes(), &mut s.pw2).unwrap();
    assert_eq!(s.pw2.len(), 1020);
    let long = "\u{958}".repeat(171);
    assert_eq!(
        crypto::normalize(long.as_bytes(), &mut s.pw2),
        Err(crypto::Error::Password)
    );
    assert!(s.pw2.is_empty(), "no partial password left behind");
}

#[test]
fn kdf_write_policy() {
    use crypto::{KDF_M_MAX, KDF_M_WRITE_MIN, KDF_T_MAX};
    let w = KdfParams::for_write;
    assert!(w(KDF_M_WRITE_MIN, 3).is_ok() && w(KDF_M_MAX, KDF_T_MAX).is_ok());
    assert_eq!(w(KDF_M_WRITE_MIN - 1, 3), Err(crypto::Error::KdfParams));
    assert_eq!(w(KDF_M_MAX + 1, 3), Err(crypto::Error::KdfParams));
    assert_eq!(w(KDF_M_WRITE_MIN, 2), Err(crypto::Error::KdfParams));
    assert_eq!(
        w(KDF_M_WRITE_MIN, KDF_T_MAX + 1),
        Err(crypto::Error::KdfParams)
    );
    assert_eq!(KdfParams::DEFAULT, w(262_144, 3).unwrap());
    #[cfg(not(feature = "testkdf"))]
    assert_eq!(KDF_M_WRITE_MIN, 65_536);
    assert_eq!(KDF_M_WRITE_MIN, format::KDF_M_MIN);
    assert_eq!(
        (KDF_M_MAX, KDF_T_MAX),
        (format::KDF_M_MAX, format::KDF_T_MAX)
    );
    // init refuses to write below the floor.
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let low = KdfParams {
        m_kib: KDF_M_WRITE_MIN - 1,
        t: 3,
    };
    let r = vault::init(b"pw", low, &mut s.kek, &mut s.dek, false);
    assert_eq!(
        r.err(),
        Some(vault::Error::Crypto(crypto::Error::KdfParams))
    );
    assert!(s.kek.is_empty() && s.dek.is_empty());
}

#[test]
fn ct_eq_and_wrap_contracts() {
    assert!(crypto::ct_eq(b"abc", b"abc"));
    assert!(!crypto::ct_eq(b"abc", b"abd") && !crypto::ct_eq(b"abc", b"ab"));
    assert!(crypto::ct_eq(b"", b""));
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.kek, &[7; 32]);
    put(&mut s.new_dek, &[9; 32]);
    let aad = [1u8; AAD_W_LEN];
    let (n1, w1) = crypto::wrap_dek(s.kek.expose(), s.new_dek.expose(), &aad).unwrap();
    let (n2, w2) = crypto::wrap_dek(s.kek.expose(), s.new_dek.expose(), &aad).unwrap();
    assert!(n1 != n2 && w1 != w2, "fresh wrap nonce per wrap");
    assert_ne!(&w1[..32], &[9; 32], "the DEK is encrypted");
    crypto::unwrap_dek(s.kek.expose(), &n1, &w1, &aad, &mut s.dek).unwrap();
    assert_eq!(s.dek.expose(), &[9; 32]);
    let r = crypto::unwrap_dek(s.kek.expose(), &n1, &w1, &[2; AAD_W_LEN], &mut s.dek);
    assert_eq!(r, Err(crypto::Error::Auth));
    assert!(s.dek.is_empty(), "failed unwrap leaves no bytes");
    assert_eq!(
        crypto::wrap_dek(&[0; 31], s.new_dek.expose(), &aad).err(),
        Some(crypto::Error::Length)
    );
    assert_eq!(
        crypto::wrap_dek(s.kek.expose(), &[0; 31], &aad).err(),
        Some(crypto::Error::Length)
    );
    // A failed open zeroizes the buffer.
    let mut buf = [5u8; 64];
    let tag = crypto::seal(&[1; 32], &[0; NONCE_LEN], b"", &mut buf).unwrap();
    let mut bad = tag;
    bad[0] ^= 1;
    assert_eq!(
        crypto::open(&[1; 32], &[0; NONCE_LEN], b"", &mut buf, &bad),
        Err(crypto::Error::Auth)
    );
    assert_eq!(buf, [0; 64]);
}

const MEMLOCK_ENV: &str = "PWV_KDF_MEMLOCK_CHILD";

/// Child half: with `RLIMIT_MEMLOCK` = 0 the KDF region cannot be locked.
/// `--require-locked-kdf` (`require_locked`) refuses; otherwise derivation
/// proceeds and reports `locked: false` (Section 5.4 steps 2-3). Exit 42 on
/// success; 10 + n identifies the failed step (the print ban applies here).
#[test]
fn kdf_memlock_child() {
    if std::env::var(MEMLOCK_ENV).is_err() {
        return;
    }
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit with a valid pointer to an initialised struct.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const zero) } != 0 {
        std::process::exit(10);
    }
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let p = floor_params();
    let r = crypto::derive_kek(b"pw", &[1; 32], p, &mut s.kek, true);
    if r != Err(crypto::Error::KdfUnlocked) || !s.kek.is_empty() {
        std::process::exit(11);
    }
    match crypto::derive_kek(b"pw", &[1; 32], p, &mut s.kek, false) {
        Ok(out) if !out.locked && s.kek.len() == 32 => std::process::exit(42),
        _ => std::process::exit(12),
    }
}

#[test]
fn kdf_lock_failure_refused_only_when_required() {
    let out = common::run_child("kdf_memlock_child", &[(MEMLOCK_ENV, "1")]);
    assert_eq!(
        out.status.code(),
        Some(42),
        "10/11/12: see kdf_memlock_child"
    );
    assert_eq!(
        cli::exit_code(vault::Error::Crypto(crypto::Error::KdfUnlocked)),
        cli::EXIT_ENV
    );
}

// ------------------------------------------------------------- lifecycle

#[test]
fn lifecycle_round_trip_and_slot_hygiene() {
    let m = vaults::sample_model();
    let (file, h) = make_vault("hunter2", &m, floor_params(), 3);
    assert_eq!(h.generation, 3);
    assert_eq!(file.len(), h.file_len());
    assert_eq!(parse_header(&file).unwrap(), h);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, b"hunter2");
    let (h2, out) = vault::unlock(
        &file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_a,
        false,
    )
    .unwrap();
    assert_eq!(h2, h);
    assert_eq!(read_body(s.vault_a.expose()), m);
    assert!(s.pw1.is_empty() && s.pw2.is_empty() && s.kek.is_empty());
    assert_eq!(s.dek.len(), 32);
    assert!(out.region.1 - out.region.0 >= usize::try_from(h.kdf_m_kib).unwrap() * 1024);
    // Failure leaves every secret slot empty.
    put(&mut s.pw1, b"wrong");
    let r = vault::unlock(
        &file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_a,
        false,
    );
    assert_eq!(r.err(), Some(AUTH));
    for slot in [&s.pw1, &s.pw2, &s.kek, &s.dek, &s.vault_a] {
        assert!(slot.is_empty());
    }
}

#[test]
fn save_refuses_invalid_bodies_and_keeps_plaintext() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let (mut h, _) = vault::init(b"pw", floor_params(), &mut s.kek, &mut s.dek, false).unwrap();
    write_body(&vaults::sample_model(), &mut s.vault_a);
    let before = s.vault_a.expose().to_vec();
    let file = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
    assert_eq!(
        s.vault_a.expose(),
        &before[..],
        "body is plaintext again after save"
    );
    assert_eq!(h.generation, 1);
    assert_ne!(&file[HEADER_LEN..HEADER_LEN + 16], &before[..16]);
    // A non-canonical body is never encrypted; the header is unchanged.
    let g = h.clone();
    s.vault_a.expose_mut()[before.len() - 1] = 1;
    let r = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut());
    assert_eq!(r.err(), Some(vault::Error::Format(format::Error::Padding)));
    assert_eq!(h, g);
    // Generation overflow is refused.
    s.vault_a.expose_mut()[before.len() - 1] = 0;
    h.generation = u64::MAX;
    let r = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut());
    assert_eq!(r.err(), Some(vault::Error::Generation));
    // Capacity: a vault written from a large arena does not fit the
    // default arena's vault slot: a clean error, after authentication.
    let mut big = pwv::secmem::SecureArena::new(pwv::secmem::MAX_ARENA, true).unwrap();
    let mut b = big.slots().unwrap();
    let (mut bh, _) = vault::init(b"pw", floor_params(), &mut b.kek, &mut b.dek, false).unwrap();
    write_body(&vaults::big_model(9_000), &mut b.vault_a);
    assert!(b.vault_a.len() > s.vault_b.capacity());
    let big_file = vault::save(b.dek.expose(), &mut bh, b.vault_a.expose_mut()).unwrap();
    put(&mut s.pw1, b"pw");
    let r = vault::unlock(
        &big_file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_b,
        false,
    );
    assert_eq!(r.err(), Some(vault::Error::Capacity));
    assert!(s.dek.is_empty() && s.vault_b.is_empty());
    assert_eq!(cli::exit_code(vault::Error::Capacity), 1);
}

// ------------------------------------------------------------- T-CRY-1

/// The vault T-CRY-1 attacks: the small golden vault with `testkdf`;
/// otherwise a fresh vault at the production floor with the same model.
fn cry1_vault() -> (Vec<u8>, Vec<u8>) {
    #[cfg(feature = "testkdf")]
    {
        let g = &goldens()[0];
        assert_eq!(g.file, "v1-small.pwv");
        (read_golden(g), g.password.clone())
    }
    #[cfg(not(feature = "testkdf"))]
    {
        let pw = "pwv golden \u{e9}t\u{e9}";
        let (f, _) = make_vault(pw, &vaults::sample_model(), floor_params(), 1);
        (f, pw.as_bytes().to_vec())
    }
}

/// T-CRY-1: every single-bit flip of a ~4.3 KiB vault fails, against the
/// post-KDF path with the KEK cached (~35,000 cases), plus 100 random
/// full-path cases.
#[test]
fn t_cry_1_every_bit_flip_fails() {
    let (file, pw) = cry1_vault();
    assert_eq!(file.len(), HEADER_LEN + 4096 + 16);
    let h = parse_header(&file).unwrap();
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, &pw);
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let p = KdfParams {
        m_kib: h.kdf_m_kib,
        t: h.kdf_t,
    };
    crypto::derive_kek(s.pw2.expose(), &h.salt, p, &mut s.kek, false).unwrap();
    vault::open_with_kek(&file, s.kek.expose(), &mut s.dek, &mut s.vault_a).expect("intact");
    let mut f = file.clone();
    let mut cases = 0;
    for i in 0..f.len() {
        for bit in 0..8 {
            f[i] ^= 1 << bit;
            let r = vault::open_with_kek(&f, s.kek.expose(), &mut s.dek, &mut s.vault_a);
            match r {
                Err(AUTH) => {}
                Err(vault::Error::Format(_)) if i < HEADER_LEN => {}
                other => panic!("byte {i} bit {bit}: {:?}", other.map(|_| ())),
            }
            assert!(s.dek.is_empty() && s.vault_a.is_empty(), "byte {i}");
            f[i] ^= 1 << bit;
            cases += 1;
        }
    }
    assert_eq!(cases, 8 * file.len());
    // Full path: KDF each time. Flips that raise kdf_m_kib above 64 MiB
    // are resampled (the cached-KEK sweep above covers them; deriving with
    // up to 4 GiB per case is out of budget).
    let mut rng = Rng(0x5157_4352_5931);
    let mut full = 0;
    while full < 100 {
        let (i, bit) = (rng.below(f.len()), rng.below(8));
        f[i] ^= 1 << bit;
        let m = parse_header(&f).map(|h| h.kdf_m_kib).unwrap_or(0);
        if m <= 65_536 {
            let r = unlock_model(&f, &pw);
            assert!(
                matches!(r, Err(AUTH | vault::Error::Format(_))),
                "full path, byte {i} bit {bit}"
            );
            full += 1;
        }
        f[i] ^= 1 << bit;
    }
}

// ------------------------------------------------------------- T-CRY-2..6

/// T-CRY-2: wrong password versus a corrupted payload: the same error,
/// byte-identical message, and exit code 2.
#[test]
fn t_cry_2_wrong_password_equals_damaged_payload() {
    let (file, _) = make_vault("right", &vaults::sample_model(), floor_params(), 1);
    let wrong = unlock_model(&file, b"wrong").unwrap_err();
    let mut damaged = file.clone();
    damaged[HEADER_LEN + 100] ^= 0x40;
    let corrupt = unlock_model(&damaged, b"right").unwrap_err();
    let mut tag = file.clone();
    *tag.last_mut().unwrap() ^= 1;
    let bad_tag = unlock_model(&tag, b"right").unwrap_err();
    for e in [wrong, corrupt, bad_tag] {
        assert_eq!(e, AUTH);
        assert_eq!(e.message().as_bytes(), b"wrong password or damaged vault");
        assert_eq!(cli::exit_code(e), 2);
    }
    assert_eq!(cli::EXIT_AUTH, 2);
}

/// T-CRY-3: 10^5 saves of one vault: all payload nonces distinct; the
/// wrap nonce and wrapped DEK never change.
#[test]
fn t_cry_3_nonces_fresh_over_100k_saves() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let (mut h, _) = vault::init(b"pw", floor_params(), &mut s.kek, &mut s.dek, false).unwrap();
    write_body(&vaults::sample_model(), &mut s.vault_a);
    let first = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
    let (wn, wd) = (h.wrap_nonce, h.wrapped_dek);
    let mut seen = HashSet::new();
    assert!(seen.insert(h.payload_nonce));
    let mut last = first.clone();
    for g in 2..=100_000u64 {
        last = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
        assert!(seen.insert(h.payload_nonce), "nonce repeated at save {g}");
        assert_eq!((h.wrap_nonce, h.wrapped_dek, h.generation), (wn, wd, g));
        assert_ne!(h.payload_nonce, wn);
    }
    assert_eq!(seen.len(), 100_000);
    assert_eq!(
        first[..148],
        last[..148],
        "wrap and everything in AAD_w unchanged"
    );
    vault::open_with_kek(&last, &[0; 32], &mut s.dek, &mut s.vault_b).unwrap_err();
    let (h2, m) = unlock_model(&last, b"pw").unwrap();
    assert_eq!((h2.generation, m), (100_000, vaults::sample_model()));
}

/// T-CRY-4: after `passwd`, the old password plus an old file copy cannot
/// decrypt the new file's payload; salt, DEK, and both nonces all differ.
#[test]
fn t_cry_4_passwd_rotates_everything() {
    let m = vaults::sample_model();
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let (mut h, _) = vault::init(b"old", floor_params(), &mut s.kek, &mut s.dek, false).unwrap();
    write_body(&m, &mut s.vault_a);
    let old_file = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
    let old_dek = s.dek.expose().to_vec(); // test-only copy for comparison
    let params = KdfParams::for_write(crypto::KDF_M_WRITE_MIN, 4).unwrap();
    let (mut nh, _) =
        vault::passwd(&h, b"new", Some(params), &mut s.kek, &mut s.new_dek, false).unwrap();
    assert!(s.kek.is_empty());
    let new_file = vault::save(s.new_dek.expose(), &mut nh, s.vault_a.expose_mut()).unwrap();
    vault::adopt_dek(&mut s.dek, &mut s.new_dek).unwrap();
    assert!(s.new_dek.is_empty());
    assert_ne!(s.dek.expose(), &old_dek[..], "DEK rotated");
    assert_ne!(nh.salt, h.salt);
    assert_ne!(nh.wrap_nonce, h.wrap_nonce);
    assert_ne!(nh.payload_nonce, h.payload_nonce);
    assert_ne!(nh.wrapped_dek, h.wrapped_dek);
    assert_eq!(nh.vault_id, h.vault_id, "vault ID survives passwd");
    assert_eq!((nh.generation, nh.kdf_t), (h.generation + 1, 4));
    // The attack: old password + old file -> old DEK; try it on the new payload.
    let mut b = arena();
    let mut t = b.slots().unwrap();
    put(&mut t.pw1, b"old");
    vault::unlock(
        &old_file,
        &mut t.pw1,
        &mut t.pw2,
        &mut t.kek,
        &mut t.dek,
        &mut t.vault_a,
        false,
    )
    .unwrap();
    assert_eq!(t.dek.expose(), &old_dek[..]);
    let (nh2, ct, tag) = format::split_file(&new_file).unwrap();
    put(&mut t.vault_b, ct);
    let r = crypto::open(
        t.dek.expose(),
        &nh2.payload_nonce,
        &new_file[..HEADER_LEN],
        t.vault_b.expose_mut(),
        tag,
    );
    assert_eq!(r, Err(crypto::Error::Auth));
    // Splicing the old wrap into the new file does not help either.
    let mut spliced = new_file.clone();
    spliced[..148].copy_from_slice(&old_file[..148]);
    assert_eq!(unlock_model(&spliced, b"old").unwrap_err(), AUTH);
    assert_eq!(unlock_model(&new_file, b"old").unwrap_err(), AUTH);
    assert_eq!(unlock_model(&new_file, b"new").unwrap().1, m);
    assert_eq!(unlock_model(&old_file, b"new").unwrap_err(), AUTH);
    // passwd with no new parameters keeps the old ones.
    let (kh, _) = vault::passwd(&nh, b"x", None, &mut s.kek, &mut s.new_dek, false).unwrap();
    assert_eq!((kh.kdf_m_kib, kh.kdf_t), (nh.kdf_m_kib, nh.kdf_t));
}

/// T-CRY-5: tampering with any header byte inside `AAD_w` or `AAD_p`
/// makes unwrap (bytes 0..148: `AAD_w`, wrap nonce, wrapped DEK) or open
/// (148..184) fail, or the parser rejects the header or file length.
#[test]
fn t_cry_5_header_tamper_detected_at_the_right_layer() {
    let (file, _) = make_vault("pw", &vaults::sample_model(), floor_params(), 2);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, b"pw");
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let h = parse_header(&file).unwrap();
    let p = KdfParams {
        m_kib: h.kdf_m_kib,
        t: h.kdf_t,
    };
    crypto::derive_kek(s.pw2.expose(), &h.salt, p, &mut s.kek, false).unwrap();
    let mut f = file.clone();
    let (mut unwrap_fail, mut open_fail, mut parse_fail) = (0, 0, 0);
    for i in 0..HEADER_LEN {
        for mask in [0x01u8, 0x80, 0xFF] {
            f[i] ^= mask;
            if let Ok((th, _, _)) = format::split_file(&f) {
                let uw = crypto::unwrap_dek(
                    s.kek.expose(),
                    &th.wrap_nonce,
                    &th.wrapped_dek,
                    &f[..AAD_W_LEN],
                    &mut s.dek,
                );
                if i < 148 {
                    assert_eq!(uw, Err(crypto::Error::Auth), "byte {i} must break unwrap");
                    unwrap_fail += 1;
                } else {
                    assert_eq!(uw, Ok(()), "byte {i} is outside the wrap");
                    open_fail += 1;
                }
                let r = vault::open_with_kek(&f, s.kek.expose(), &mut s.dek, &mut s.vault_a);
                assert_eq!(r.err(), Some(AUTH), "byte {i}");
            } else {
                parse_fail += 1;
            }
            f[i] ^= mask;
        }
    }
    assert!(unwrap_fail > 0 && open_fail > 0 && parse_fail > 0);
    assert_eq!(unwrap_fail + open_fail + parse_fail, 3 * HEADER_LEN);
}

/// T-CRY-6: created with composed U+00E9, opened with e + U+0301.
#[test]
fn t_cry_6_nfc_composed_vs_decomposed() {
    let m = vaults::sample_model();
    let (file, _) = make_vault("caf\u{e9} \u{c5}ngstr\u{f6}m", &m, floor_params(), 1);
    let decomposed = "cafe\u{301} A\u{30a}ngstro\u{308}m";
    assert_eq!(unlock_model(&file, decomposed.as_bytes()).unwrap().1, m);
    assert_eq!(unlock_model(&file, b"cafe Angstrom").unwrap_err(), AUTH);
    // And the reverse direction.
    let (file2, _) = make_vault(decomposed, &m, floor_params(), 1);
    let composed = "caf\u{e9} \u{c5}ngstr\u{f6}m";
    assert_eq!(unlock_model(&file2, composed.as_bytes()).unwrap().1, m);
}

#[test]
fn unlock_rejects_bad_utf8_password_and_bad_files() {
    let (file, _) = make_vault("pw", &Model::new(), floor_params(), 1);
    assert_eq!(
        unlock_model(&file, b"\xc3").unwrap_err(),
        vault::Error::Crypto(crypto::Error::Password)
    );
    assert_eq!(
        unlock_model(&file[..file.len() - 1], b"pw").unwrap_err(),
        vault::Error::Format(format::Error::FileLength)
    );
    assert_eq!(
        cli::exit_code(vault::Error::Format(format::Error::Magic)),
        3
    );
    assert_eq!(unlock_model(&file, b"pw").unwrap().1, Model::new());
}

// ------------------------------------------------------------- T-COMPAT-1

fn goldens() -> Vec<Golden> {
    let text = std::fs::read_to_string(vaults::vectors_dir().join("MANIFEST")).expect("MANIFEST");
    vaults::parse_manifest(&text)
}

fn read_golden(g: &Golden) -> Vec<u8> {
    let f = std::fs::read(vaults::vectors_dir().join(&g.file)).expect("golden file");
    assert_eq!(
        vaults::hex(&sha256(&f)),
        g.sha256,
        "{}: SHA-256 changed",
        g.file
    );
    f
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// T-COMPAT-1: every golden vault decrypts to its exact recorded model,
/// with its password and every recorded alternative spelling.
#[test]
fn t_compat_1_golden_vaults() {
    let gs = goldens();
    let names: Vec<&str> = gs.iter().map(|g| g.file.as_str()).collect();
    assert_eq!(
        names,
        [
            "v1-small.pwv",
            "v1-empty.pwv",
            "v1-multiblock.pwv",
            "v1-rekeyed.pwv"
        ]
    );
    assert_eq!(
        vaults::parse_manifest(&vaults::render_manifest(&gs)),
        gs,
        "manifest round-trips"
    );
    for g in &gs {
        let f = read_golden(g);
        let h = parse_header(&f);
        #[cfg(feature = "testkdf")]
        {
            let h = h.expect("header");
            assert_eq!(h.generation, g.generation, "{}", g.file);
            for pw in std::iter::once(&g.password).chain(&g.also_opens) {
                let (_, m) = unlock_model(&f, pw).unwrap_or_else(|e| panic!("{}: {e:?}", g.file));
                assert_eq!(m, g.model, "{}", g.file);
            }
            let mut wrong = g.password.clone();
            wrong.push(b'!');
            assert_eq!(unlock_model(&f, &wrong).unwrap_err(), AUTH);
        }
        // Production builds refuse the lowered KDF memory on read.
        #[cfg(not(feature = "testkdf"))]
        assert_eq!(h.err(), Some(format::Error::KdfMemory), "{}", g.file);
    }
}

/// Golden vectors are created once (`PWV_WRITE_GOLDEN=1 cargo test
/// --features testkdf --test crypto golden`), refusing to overwrite an
/// existing manifest. The fuzz_open seeds derive from them deterministically
/// and are checked (or, with `PWV_WRITE_CORPUS=1`, rewritten) here.
#[cfg(feature = "testkdf")]
#[test]
#[allow(clippy::disallowed_methods, reason = "writes test vectors; test-only")]
fn golden_vectors_and_fuzz_open_seeds() {
    let dir = vaults::vectors_dir();
    if std::env::var_os("PWV_WRITE_GOLDEN").is_some() {
        assert!(
            !dir.join("MANIFEST").exists(),
            "golden vectors are never regenerated"
        );
        let gs = make_goldens();
        for (g, bytes) in &gs {
            std::fs::write(dir.join(&g.file), bytes).unwrap();
        }
        let list: Vec<Golden> = gs.into_iter().map(|(g, _)| g).collect();
        std::fs::write(dir.join("MANIFEST"), vaults::render_manifest(&list)).unwrap();
    }
    let g = &goldens()[0];
    let file = read_golden(g);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    write_body(&g.model, &mut s.vault_a);
    let seeds = [
        ("seed-unlock-golden", [&[0u8][..], &file].concat()),
        ("seed-save-body", [&[1u8][..], s.vault_a.expose()].concat()),
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/fuzz_open");
    for (name, bytes) in &seeds {
        if std::env::var_os("PWV_WRITE_CORPUS").is_some() {
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join(name), bytes).unwrap();
        }
        assert_eq!(
            &std::fs::read(root.join(name)).expect("seed"),
            bytes,
            "{name}"
        );
    }
    // The fuzz target's fixed password is this vault's.
    assert_eq!(g.password, "pwv golden \u{e9}t\u{e9}".as_bytes());
}

#[cfg(feature = "testkdf")]
fn make_goldens() -> Vec<(Golden, Vec<u8>)> {
    let p = |m, t| KdfParams::for_write(m, t).unwrap();
    let mk = |file: &str, pw: &str, also: &[&str], m: Model, params, saves| {
        let (bytes, h) = make_vault(pw, &m, params, saves);
        let g = Golden {
            file: file.into(),
            sha256: vaults::hex(&sha256(&bytes)),
            password: pw.as_bytes().to_vec(),
            also_opens: also.iter().map(|a| a.as_bytes().to_vec()).collect(),
            generation: h.generation,
            model: m,
        };
        (g, bytes)
    };
    let small = vaults::sample_model();
    let mut out = vec![
        mk(
            "v1-small.pwv",
            "pwv golden \u{e9}t\u{e9}",
            &["pwv golden e\u{301}te\u{301}"],
            small.clone(),
            p(64, 3),
            1,
        ),
        mk("v1-empty.pwv", "empty", &[], Model::new(), p(8, 3), 1),
        mk(
            "v1-multiblock.pwv",
            "multi-block \u{1f512}",
            &[],
            vaults::big_model(150),
            p(256, 4),
            5,
        ),
    ];
    // Rekeyed: created under one password, passwd to another, saved.
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let (mut h, _) = vault::init(b"before", p(64, 3), &mut s.kek, &mut s.dek, false).unwrap();
    write_body(&small, &mut s.vault_a);
    vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
    let pw = "rekeyed \u{2603}";
    let (mut nh, _) = vault::passwd(
        &h,
        pw.as_bytes(),
        Some(p(32, 5)),
        &mut s.kek,
        &mut s.new_dek,
        false,
    )
    .unwrap();
    let bytes = vault::save(s.new_dek.expose(), &mut nh, s.vault_a.expose_mut()).unwrap();
    out.push((
        Golden {
            file: "v1-rekeyed.pwv".into(),
            sha256: vaults::hex(&sha256(&bytes)),
            password: pw.as_bytes().to_vec(),
            also_opens: vec![],
            generation: nh.generation,
            model: small,
        },
        bytes,
    ));
    out
}
