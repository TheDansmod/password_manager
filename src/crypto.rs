//! Argon2id into arena-owned memory; XChaCha20-Poly1305 seal and open in
//! place; key wrapping (spec Section 6). Pure: no I/O.
//!
//! Byte-level primitives only. `format` is in the same layer, so the
//! file-level lifecycle (init, unlock, save, passwd), which needs header
//! bytes as associated data, lives one layer up in `vault`.
//!
//! APIs verified against the pinned versions: argon2 0.6.0
//! (`Argon2::hash_password_into_with_memory`, `Params::new`,
//! `Params::block_count`); chacha20poly1305 0.11.0 / aead 0.6.1
//! (`KeyInit::new_from_slice`; `AeadInOut::{en,de}crypt_inout_detached` on
//! an `InOutBuf` made from one `&mut [u8]`, i.e. in place: the spec's
//! `{en,de}crypt_in_place_detached` are deprecated forwarders to exactly
//! these in aead 0.6; the cipher zeroizes its key on drop with `zeroize`); getrandom 0.4.3 (`fill`); unicode-normalization
//! 0.1.26 (`UnicodeNormalization::nfc`).

use crate::secmem::{KEY_LEN, KdfRegion, SecretSlot};
use crate::sys;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Argon2id salt length.
pub const SALT_LEN: usize = 32;
/// Length of a wrapped DEK: ciphertext then tag.
pub const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;
/// Smallest `m` (KiB) ever written (Section 6.4). `testkdf` builds lower it
/// to the read floor, 8 KiB, so that test vaults derive quickly.
#[cfg(not(feature = "testkdf"))]
pub const KDF_M_WRITE_MIN: u32 = 65_536;
/// Smallest `m` (KiB) ever written (`testkdf`: the 8 KiB read floor).
#[cfg(feature = "testkdf")]
pub const KDF_M_WRITE_MIN: u32 = 8;
/// Largest `m` (KiB) accepted (4 GiB).
pub const KDF_M_MAX: u32 = 4_194_304;
/// Smallest `t` ever written.
pub const KDF_T_WRITE_MIN: u32 = 3;
/// Largest `t` accepted.
pub const KDF_T_MAX: u32 = 20;

/// A cryptographic failure. Messages are fixed and secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An AEAD tag did not verify, at either layer. One message for both,
    /// so wrong password and damaged vault are indistinguishable (6.3).
    Auth,
    /// The password is not UTF-8, or its NFC form exceeds the slot.
    Password,
    /// KDF parameters outside the write policy of Section 6.4.
    KdfParams,
    /// The KDF memory could not be mapped, or Argon2 failed.
    Kdf,
    /// The KDF memory could not be locked and locking was required.
    KdfUnlocked,
    /// The OS random number generator failed.
    Random,
    /// A key or buffer has the wrong length (a caller bug; fails closed).
    Length,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Auth => "wrong password or damaged vault",
            Error::Password => "password must be valid UTF-8 and at most 1024 bytes",
            Error::KdfParams => "KDF parameters out of range (minimum 64 MiB and 3 passes)",
            Error::Kdf => "cannot allocate memory for the key derivation",
            Error::KdfUnlocked => {
                "cannot lock key-derivation memory (RLIMIT_MEMLOCK) and --require-locked-kdf was given"
            }
            Error::Random => "the operating system random number generator failed",
            Error::Length => "internal error: bad key or buffer length",
        }
    }
}

/// Argon2id cost parameters (p is always 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
}

impl KdfParams {
    /// Default written parameters: 256 MiB, 3 passes (Section 6.1).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 262_144,
        t: 3,
    };

    /// Parameters for a new header, checked against the write floor.
    ///
    /// # Errors
    /// [`Error::KdfParams`] below the floor or above the read maximum.
    pub fn for_write(m_kib: u32, t: u32) -> Result<Self, Error> {
        let ok = (KDF_M_WRITE_MIN..=KDF_M_MAX).contains(&m_kib)
            && (KDF_T_WRITE_MIN..=KDF_T_MAX).contains(&t);
        if ok {
            Ok(KdfParams { m_kib, t })
        } else {
            Err(Error::KdfParams)
        }
    }
}

/// What a key derivation reports to its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfOutcome {
    /// The KDF memory was locked; if not, the caller prints the notice of
    /// Section 5.4 step 3.
    pub locked: bool,
    /// Address range of the (now unmapped) KDF region, for T-MEM-7.
    pub region: (usize, usize),
    /// `memtest`: every byte of the region was zero just before `munmap`.
    #[cfg(feature = "memtest")]
    pub wiped: bool,
}

/// Fills `buf` from `getrandom(2)`. May write directly into an arena slot.
///
/// # Errors
/// [`Error::Random`] if the OS generator fails.
pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Writes UTF8(NFC(`raw`)) into `out` (Section 6.2). Secret contract:
/// reads `raw` (an arena slot) and writes only into `out`.
///
/// # Errors
/// [`Error::Password`] if `raw` is not UTF-8 or the result does not fit;
/// `out` is then empty.
pub fn normalize(raw: &[u8], out: &mut SecretSlot<'_>) -> Result<(), Error> {
    out.clear();
    let s = core::str::from_utf8(raw).map_err(|_| Error::Password)?;
    let mut buf = [0u8; 4];
    let mut res = Ok(());
    for c in s.nfc() {
        let (n, enc) = (out.len(), c.encode_utf8(&mut buf).len());
        let fits = n.checked_add(enc).is_some_and(|m| out.set_len(m).is_ok());
        let copied = fits
            && out
                .expose_mut()
                .get_mut(n..)
                .zip(buf.get(..enc))
                .map(|(dst, src)| dst.copy_from_slice(src))
                .is_some();
        if !copied {
            res = Err(Error::Password);
            break;
        }
    }
    buf.zeroize();
    if res.is_err() {
        out.clear();
    }
    res
}

/// Runs `ctx` (any Argon2 context) with its working memory in a fresh
/// [`KdfRegion`], writing the tag into `out`; the region is zeroized and
/// unmapped before returning (Section 5.4). This is the arena-backed
/// wrapper that T-KAT-1 exercises. Never uses the allocating API.
///
/// # Errors
/// [`Error::Kdf`] if the region cannot be mapped or Argon2 rejects its
/// inputs; [`Error::KdfUnlocked`] if the region is not locked and
/// `require_locked` is set. On error `out` is zeroized.
pub fn argon2_in_region(
    ctx: &Argon2<'_>,
    pwd: &[u8],
    salt: &[u8],
    out: &mut [u8],
    require_locked: bool,
) -> Result<KdfOutcome, Error> {
    let mut region = KdfRegion::new(ctx.params().block_count()).map_err(|_| Error::Kdf)?;
    let locked = region.is_locked();
    let res = if require_locked && !locked {
        Err(Error::KdfUnlocked)
    } else {
        ctx.hash_password_into_with_memory(pwd, salt, &mut *out, region.blocks())
            .map_err(|_| Error::Kdf)
    };
    let range = region.data_range();
    #[cfg(feature = "memtest")]
    let mut wiped = false;
    #[cfg(feature = "memtest")]
    region.close_with_snapshot(&mut |d| wiped = d.iter().all(|&b| b == 0));
    #[cfg(not(feature = "memtest"))]
    drop(region);
    sys::scrub_stack();
    if let Err(e) = res {
        out.zeroize();
        return Err(e);
    }
    Ok(KdfOutcome {
        locked,
        region: range,
        #[cfg(feature = "memtest")]
        wiped,
    })
}

/// Derives the KEK = Argon2id(`pw`, `salt`; m, t, p = 1, 32 bytes) into
/// `kek` (Section 6.2). `pw` must already be NFC-normalised. Secret
/// contract: borrows `pw`, writes only `kek` and the KDF region.
///
/// # Errors
/// As [`argon2_in_region`]; [`Error::KdfParams`] if Argon2 rejects m or t.
/// On error `kek` is empty.
pub fn derive_kek(
    pw: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
    kek: &mut SecretSlot<'_>,
    require_locked: bool,
) -> Result<KdfOutcome, Error> {
    let p = Params::new(params.m_kib, params.t, 1, Some(KEY_LEN)).map_err(|_| Error::KdfParams)?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    kek.set_len(KEY_LEN).map_err(|_| Error::Length)?;
    argon2_in_region(&ctx, pw, salt, kek.expose_mut(), require_locked).inspect_err(|_| kek.clear())
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, Error> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Length)
}

/// Encrypts `buf` in place under `key` and `nonce`, binding `aad`; returns
/// the tag. Secret contract: `buf` is an arena slot; no copy is made.
///
/// # Errors
/// [`Error::Length`] if `key` is not 32 bytes or `buf` is too long.
pub fn seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let tag = cipher(key)?
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .map_err(|_| Error::Length)?;
    Ok(tag.into())
}

/// Verifies `tag` and decrypts `buf` in place. On failure `buf` is zeroized.
///
/// # Errors
/// [`Error::Auth`] if the tag does not verify; [`Error::Length`] for a bad
/// key or tag length.
pub fn open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Length)?;
    cipher(key)?
        .decrypt_inout_detached(nonce.into(), aad, (&mut *buf).into(), tag.into())
        .map_err(|_| {
            buf.zeroize();
            Error::Auth
        })
}

/// Wraps `dek` under `kek` with a fresh nonce: `W = Seal(KEK, n_w, DEK,
/// aad_w)`. Returns (`n_w`, `W`). Only ciphertext leaves the function.
///
/// # Errors
/// [`Error::Random`]; [`Error::Length`] if a key is not 32 bytes.
pub fn wrap_dek(
    kek: &[u8],
    dek: &[u8],
    aad_w: &[u8],
) -> Result<([u8; NONCE_LEN], [u8; WRAPPED_LEN]), Error> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let mut w = [0u8; WRAPPED_LEN];
    let (ct, tag) = w.split_at_mut(KEY_LEN);
    if dek.len() != KEY_LEN {
        return Err(Error::Length);
    }
    ct.copy_from_slice(dek);
    let t = seal(kek, &nonce, aad_w, ct).inspect_err(|_| ct.zeroize())?;
    tag.copy_from_slice(&t);
    Ok((nonce, w))
}

/// Unwraps W into `dek` (decrypted in place inside the slot).
///
/// # Errors
/// [`Error::Auth`] if `W`, `n_w`, `aad_w`, or the KEK is wrong; `dek` is then
/// empty.
pub fn unwrap_dek(
    kek: &[u8],
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_LEN],
    aad_w: &[u8],
    dek: &mut SecretSlot<'_>,
) -> Result<(), Error> {
    let (ct, tag) = wrapped.split_at(KEY_LEN);
    dek.set_len(KEY_LEN).map_err(|_| Error::Length)?;
    dek.expose_mut().copy_from_slice(ct);
    open(kek, nonce, aad_w, dek.expose_mut(), tag).inspect_err(|_| dek.clear())
}

/// Constant-time equality of two secret byte strings (Section 5.2), e.g.
/// the two master-password entries. Lengths are not secret.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    a.len() == b.len() && core::hint::black_box(diff) == 0
}
