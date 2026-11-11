//! In-memory model: an index over the decrypted plaintext held in the
//! arena; all entry operations and their validation (spec Section 9.2;
//! model operations arrive in M5).
//!
//! M3: the file-level key lifecycle of Section 6.3 (init, unlock, save,
//! passwd). It joins `format` (header bytes as associated data) and
//! `crypto`, which share a layer and so may not use each other. Plaintext
//! exists only in arena slots; files are ciphertext in ordinary `Vec`s.

use crate::crypto::{self, KdfOutcome, KdfParams};
use crate::format::{self, AAD_W_LEN, HEADER_LEN, Header};
use crate::secmem::{KEY_LEN, SecretSlot};
use crate::sys;

/// A lifecycle failure. Messages are fixed and secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The file or body violates the format.
    Format(format::Error),
    /// A cryptographic failure (including authentication).
    Crypto(crypto::Error),
    /// The payload does not fit the arena's vault slot.
    Capacity,
    /// The generation counter would overflow.
    Generation,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Format(e) => e.message(),
            Error::Crypto(e) => e.message(),
            Error::Capacity => "vault too large for secure memory; raise --arena-size",
            Error::Generation => "generation counter overflow",
        }
    }
}

impl From<format::Error> for Error {
    fn from(e: format::Error) -> Self {
        Error::Format(e)
    }
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::Crypto(e)
    }
}

/// Creates the key material of a new vault (Section 6.3, init): random
/// vault ID, salt, and DEK (into `dek`); KEK from `pw` (NFC form) into
/// `kek`, used to wrap the DEK, then wiped. The returned header has
/// generation 0 and no payload: the first [`save`] writes generation 1.
///
/// # Errors
/// [`crypto::Error::KdfParams`] below the write floor; any KDF error.
pub fn init(
    pw: &[u8],
    params: KdfParams,
    kek: &mut SecretSlot<'_>,
    dek: &mut SecretSlot<'_>,
    require_locked: bool,
) -> Result<(Header, KdfOutcome), Error> {
    let mut vault_id = [0u8; 16];
    crypto::fill_random(&mut vault_id)?;
    keyslot(vault_id, 0, pw, params, kek, dek, require_locked)
}

/// Rekeys for `passwd` (Section 6.3): fresh salt, fresh DEK (into
/// `new_dek`), fresh wrap nonce, optionally new KDF parameters; the vault
/// ID and generation are kept. Re-encrypt by passing the result and
/// `new_dek` to [`save`], which draws a fresh payload nonce; adopt the new
/// DEK only once that file is safely written.
///
/// # Errors
/// As [`init`].
pub fn passwd(
    old: &Header,
    new_pw: &[u8],
    params: Option<KdfParams>,
    kek: &mut SecretSlot<'_>,
    new_dek: &mut SecretSlot<'_>,
    require_locked: bool,
) -> Result<(Header, KdfOutcome), Error> {
    let p = params.unwrap_or(KdfParams {
        m_kib: old.kdf_m_kib,
        t: old.kdf_t,
    });
    keyslot(
        old.vault_id,
        old.generation,
        new_pw,
        p,
        kek,
        new_dek,
        require_locked,
    )
}

fn keyslot(
    vault_id: [u8; 16],
    generation: u64,
    pw: &[u8],
    params: KdfParams,
    kek: &mut SecretSlot<'_>,
    dek: &mut SecretSlot<'_>,
    require_locked: bool,
) -> Result<(Header, KdfOutcome), Error> {
    let params = KdfParams::for_write(params.m_kib, params.t)?;
    let mut h = Header {
        vault_id,
        kdf_m_kib: params.m_kib,
        kdf_t: params.t,
        salt: [0; 32],
        wrap_nonce: [0; 24],
        wrapped_dek: [0; 48],
        generation,
        payload_nonce: [0; 24],
        payload_len: 0,
    };
    crypto::fill_random(&mut h.salt)?;
    dek.set_len(KEY_LEN).map_err(|_| crypto::Error::Length)?;
    let res = crypto::fill_random(dek.expose_mut())
        .and_then(|()| crypto::derive_kek(pw, &h.salt, params, kek, require_locked))
        .and_then(|out| {
            let aad = h.encode();
            let aad_w = aad.get(..AAD_W_LEN).ok_or(crypto::Error::Length)?;
            (h.wrap_nonce, h.wrapped_dek) = crypto::wrap_dek(kek.expose(), dek.expose(), aad_w)?;
            Ok(out)
        });
    kek.clear();
    match res {
        Ok(out) => Ok((h, out)),
        Err(e) => {
            dek.clear();
            Err(e.into())
        }
    }
}

/// Saves (Section 6.3): validates `body` (a padded canonical body in an
/// arena slot), increments the generation, draws a fresh payload nonce,
/// encrypts `body` in place, copies header, ciphertext, and tag into the
/// returned file, then decrypts `body` back in place (which also verifies
/// the file). `h` is updated only on success. The wrap is unchanged.
///
/// # Errors
/// Any body error; [`Error::Generation`]; a crypto error.
pub fn save(dek: &[u8], h: &mut Header, body: &mut [u8]) -> Result<Vec<u8>, Error> {
    format::parse_body(body)?;
    let mut n = h.clone();
    n.generation = n.generation.checked_add(1).ok_or(Error::Generation)?;
    n.payload_len = u32::try_from(body.len()).map_err(|_| Error::Capacity)?;
    crypto::fill_random(&mut n.payload_nonce)?;
    let aad = n.encode();
    format::parse_header(&aad)?;
    let tag = crypto::seal(dek, &n.payload_nonce, &aad, body)?;
    let mut file = Vec::with_capacity(n.file_len());
    for part in [&aad[..], &*body, &tag] {
        file.extend_from_slice(part);
    }
    let restored = crypto::open(dek, &n.payload_nonce, &aad, body, &tag);
    sys::scrub_stack();
    restored?;
    *h = n;
    Ok(file)
}

/// Unlocks (Section 6.3 and the unlock data flow of Section 4): parses the
/// header, NFC-normalises `pw` into `nfc`, derives the KEK, unwraps the
/// DEK, wipes the KEK and both password slots, then decrypts and validates
/// the body in `body`. Both tag failures are the one [`crypto::Error::Auth`].
///
/// # Errors
/// Any format, crypto, or capacity error. On any error `dek` and `body`
/// are empty; `pw`, `nfc`, and `kek` are always empty on return.
#[allow(clippy::too_many_arguments, reason = "one slot per role, no struct")]
pub fn unlock(
    file: &[u8],
    pw: &mut SecretSlot<'_>,
    nfc: &mut SecretSlot<'_>,
    kek: &mut SecretSlot<'_>,
    dek: &mut SecretSlot<'_>,
    body: &mut SecretSlot<'_>,
    require_locked: bool,
) -> Result<(Header, KdfOutcome), Error> {
    let mut derive = || -> Result<KdfOutcome, Error> {
        let h = format::parse_header(file)?;
        crypto::normalize(pw.expose(), nfc)?;
        pw.clear();
        let p = KdfParams {
            m_kib: h.kdf_m_kib,
            t: h.kdf_t,
        };
        Ok(crypto::derive_kek(
            nfc.expose(),
            &h.salt,
            p,
            kek,
            require_locked,
        )?)
    };
    let derived = derive();
    pw.clear();
    nfc.clear();
    let res = derived.and_then(|out| Ok((open_with_kek(file, kek.expose(), dek, body)?, out)));
    kek.clear();
    sys::scrub_stack();
    res
}

/// The post-KDF half of [`unlock`]: unwraps the DEK with `kek`, copies the
/// ciphertext into `body`, decrypts it in place, and validates it.
///
/// # Errors
/// As [`unlock`]; on any error `dek` and `body` are empty.
pub fn open_with_kek(
    file: &[u8],
    kek: &[u8],
    dek: &mut SecretSlot<'_>,
    body: &mut SecretSlot<'_>,
) -> Result<Header, Error> {
    let res = open_inner(file, kek, dek, body);
    if res.is_err() {
        dek.clear();
        body.clear();
    }
    res
}

fn open_inner(
    file: &[u8],
    kek: &[u8],
    dek: &mut SecretSlot<'_>,
    body: &mut SecretSlot<'_>,
) -> Result<Header, Error> {
    let (h, ct, tag) = format::split_file(file)?;
    let aad = file.get(..HEADER_LEN).ok_or(format::Error::HeaderLength)?;
    let aad_w = aad.get(..AAD_W_LEN).ok_or(format::Error::HeaderLength)?;
    crypto::unwrap_dek(kek, &h.wrap_nonce, &h.wrapped_dek, aad_w, dek)?;
    body.set_len(ct.len()).map_err(|_| Error::Capacity)?;
    body.expose_mut().copy_from_slice(ct);
    crypto::open(dek.expose(), &h.payload_nonce, aad, body.expose_mut(), tag)?;
    format::parse_body(body.expose())?;
    Ok(h)
}

/// Adopts the DEK of a completed `passwd`: copies `new_dek` into `dek` and
/// wipes `new_dek`.
///
/// # Errors
/// [`crypto::Error::Length`] if `new_dek` does not hold a key.
pub fn adopt_dek(dek: &mut SecretSlot<'_>, new_dek: &mut SecretSlot<'_>) -> Result<(), Error> {
    if new_dek.len() != KEY_LEN {
        return Err(crypto::Error::Length.into());
    }
    dek.set_len(KEY_LEN).map_err(|_| crypto::Error::Length)?;
    dek.expose_mut().copy_from_slice(new_dek.expose());
    new_dek.clear();
    Ok(())
}
