//! In-memory model: an index over the decrypted plaintext held in the
//! arena; all entry operations and their validation (spec Sections 4, 9.2,
//! 12.2), and the file-level key lifecycle of Section 6.3 (init, unlock,
//! save, passwd), which joins `format` (header bytes as associated data)
//! and `crypto`, which share a layer and so may not use each other.
//!
//! Plaintext exists only in arena slots; files are ciphertext in ordinary
//! `Vec`s. [`Model`] holds the live and scratch halves of the vault double
//! buffer. Every operation validates, rewrites live into scratch, and swaps,
//! so on any error the live body is byte-identical to before.

use crate::crypto::{self, KdfOutcome, KdfParams};
use crate::format::{self, AAD_W_LEN, BodyWriter, EntryRef, HEADER_LEN, Header};
use crate::secmem::{KEY_LEN, SecretSlot};
use crate::sys;
use core::cmp::Ordering;

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
    /// User input or an imported body violates the format.
    Invalid(format::Error),
    /// The new entry name is taken.
    EntryExists,
    /// The new field key is taken in the entry (ASCII case-insensitive).
    FieldExists,
    /// No entry has that name.
    NoEntry,
    /// The entry has no field with that key.
    NoField,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Format(e) | Error::Invalid(e) => e.message(),
            Error::Crypto(e) => e.message(),
            Error::Capacity => "vault too large for secure memory; raise --arena-size",
            Error::Generation => "generation counter overflow",
            Error::EntryExists => "an entry with that name already exists",
            Error::FieldExists => "the entry already has a field with that key",
            Error::NoEntry => "no such entry",
            Error::NoField => "no such field",
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

/// Appended to a colliding imported name with `--on-conflict suffix`.
pub const IMPORT_SUFFIX: &[u8] = b" (imported)";

/// One entry of a rewrite: its new name (plus suffix) and, unless it is
/// new, its source record. Holds borrowed slices of arena slots only.
struct Item<'b> {
    name: &'b [u8],
    suffix: &'static [u8],
    src: Option<EntryRef<'b>>,
}

impl Item<'_> {
    fn full(&self) -> impl Iterator<Item = &u8> {
        self.name.iter().chain(self.suffix)
    }
}

/// The field change applied to one entry of a rewrite.
enum Edit<'b> {
    None,
    Set(&'b [u8], bool, &'b [u8]),
    Unset(&'b [u8]),
    Rename(&'b [u8], &'b [u8]),
}

fn user(e: format::Error) -> Error {
    match e {
        format::Error::Capacity => Error::Capacity,
        e => Error::Invalid(e),
    }
}

fn items(body: &[u8]) -> Result<Vec<Item<'_>>, Error> {
    let entries = format::parse_body(body)?;
    Ok(entries.map(|e| item(e.name, b"", Some(e))).collect())
}

fn item<'b>(name: &'b [u8], suffix: &'static [u8], src: Option<EntryRef<'b>>) -> Item<'b> {
    Item { name, suffix, src }
}

fn find(items: &[Item<'_>], name: &[u8]) -> Result<usize, usize> {
    items.binary_search_by(|it| it.name.cmp(name))
}

/// The entry `name` and the index of its field `key` (ASCII case-folded).
fn field(items: &[Item<'_>], name: &[u8], key: &[u8]) -> Result<(usize, Option<usize>), Error> {
    let i = find(items, name).map_err(|_| Error::NoEntry)?;
    let e = items.get(i).and_then(|it| it.src.as_ref());
    let f = e.and_then(|e| {
        e.fields
            .clone()
            .position(|f| f.key.eq_ignore_ascii_case(key))
    });
    Ok((i, f))
}

/// The whole scratch slot, for writing.
fn full<'s>(scratch: &'s mut SecretSlot<'_>) -> Result<&'s mut [u8], Error> {
    scratch
        .set_len(scratch.capacity())
        .map_err(|_| Error::Capacity)?;
    Ok(scratch.expose_mut())
}

/// The plan of one operation: edits the item list (from the live body)
/// and names the entry and field change to apply, or refuses.
type Plan<'p, 'b> = &'p mut dyn FnMut(&mut Vec<Item<'b>>) -> Result<(usize, Edit<'b>), Error>;

/// Rewrites `live` into `scratch` according to `plan`.
fn rewrite<'b>(
    live: &'b [u8],
    scratch: &mut SecretSlot<'_>,
    plan: Plan<'_, 'b>,
) -> Result<usize, Error> {
    let out = full(scratch)?;
    let mut it = items(live)?;
    let (at, edit) = plan(&mut it)?;
    emit(out, &it, at, &edit)
}

/// Writes `items` (sorted) as a canonical body into `out`, applying `edit`
/// to entry `at`. Returns the padded length.
fn emit(out: &mut [u8], items: &[Item<'_>], at: usize, edit: &Edit<'_>) -> Result<usize, Error> {
    let mut w = BodyWriter::new(out);
    for (i, it) in items.iter().enumerate() {
        w.entry_suffixed(it.name, it.suffix).map_err(user)?;
        let hit = |k: &[u8]| match edit {
            Edit::Set(key, ..) | Edit::Unset(key) | Edit::Rename(key, _) => {
                i == at && k.eq_ignore_ascii_case(key)
            }
            Edit::None => false,
        };
        let mut done = false;
        for f in it.src.iter().flat_map(|e| e.fields.clone()) {
            let r = match edit {
                _ if !hit(f.key) => w.field(f.key, f.sensitive, f.value),
                Edit::Set(_, s, v) => w.field(f.key, *s, v),
                Edit::Rename(_, new) => w.field(new, f.sensitive, f.value),
                Edit::Unset(_) | Edit::None => Ok(()),
            };
            r.map_err(user)?;
            done |= hit(f.key);
        }
        if let (Edit::Set(k, s, v), true, false) = (edit, i == at, done) {
            w.field(k, *s, v).map_err(user)?;
        }
    }
    w.finish().map_err(user)
}

/// The model: the live canonical body, the scratch half, and an index of
/// entry offsets (not secret) for lookups. Names, keys, and values are
/// only ever borrowed from the slots.
pub struct Model<'a> {
    live: SecretSlot<'a>,
    scratch: SecretSlot<'a>,
    index: Vec<usize>,
}

impl<'a> Model<'a> {
    /// Takes the two vault halves. `live` holds a decrypted body (unlock),
    /// or is empty for a new vault (init).
    ///
    /// # Errors
    /// [`Error::Format`] if `live` is not a valid body.
    pub fn new(live: SecretSlot<'a>, scratch: SecretSlot<'a>) -> Result<Self, Error> {
        let mut m = Model {
            live,
            scratch,
            index: Vec::new(),
        };
        if m.live.is_empty() {
            let r = emit(full(&mut m.scratch)?, &[], 0, &Edit::None);
            m.adopt(r)?;
        } else {
            m.reindex()?;
        }
        Ok(m)
    }

    /// The live canonical body (padded), for saving and comparison.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.live.expose()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the vault has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The entries in name order, borrowed from the live half.
    pub fn entries(&self) -> impl Iterator<Item = EntryRef<'_>> {
        let body = self.live.expose();
        self.index
            .iter()
            .filter_map(move |&o| format::entry_at(body, o))
    }

    /// The entry named exactly `name` (binary search over the index).
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<EntryRef<'_>> {
        let body = self.live.expose();
        let cmp =
            |&o: &usize| format::entry_at(body, o).map_or(Ordering::Less, |e| e.name.cmp(name));
        let i = self.index.binary_search_by(cmp).ok()?;
        format::entry_at(body, *self.index.get(i)?)
    }

    /// The scratch half. `import` reads its input from here (Section 12.2:
    /// stdin is read into the scratch half); every operation overwrites it
    /// and leaves it empty.
    pub fn scratch(&mut self) -> &mut SecretSlot<'a> {
        &mut self.scratch
    }

    /// Makes a body written into scratch the live half; zeroizes the old
    /// one. On error, wipes scratch and keeps live.
    fn adopt(&mut self, written: Result<usize, Error>) -> Result<(), Error> {
        let res = written.and_then(|l| self.scratch.set_len(l).map_err(|_| Error::Capacity));
        if res.is_ok() {
            core::mem::swap(&mut self.live, &mut self.scratch);
        }
        self.scratch.clear();
        res.and_then(|()| self.reindex())
    }

    fn reindex(&mut self) -> Result<(), Error> {
        let entries = format::parse_body(self.live.expose())?;
        self.index = entries.map(|e| e.offset).collect();
        Ok(())
    }

    /// `add`: a new entry without fields.
    ///
    /// # Errors
    /// [`Error::Invalid`] (name rules, 10,000 entries);
    /// [`Error::EntryExists`]; [`Error::Capacity`].
    pub fn add(&mut self, name: &[u8]) -> Result<(), Error> {
        format::check_name(name, 0).map_err(Error::Invalid)?;
        let r = rewrite(self.live.expose(), &mut self.scratch, &mut |it| {
            let pos = find(it, name).err().ok_or(Error::EntryExists)?;
            if it.len() >= format::MAX_ENTRIES as usize {
                return Err(Error::Invalid(format::Error::EntryCount));
            }
            it.insert(pos, item(name, b"", None));
            Ok((usize::MAX, Edit::None))
        });
        self.adopt(r)
    }

    /// `set`: replaces the value and flag of the field matching `key` (ASCII
    /// case-insensitive; its position and spelling are kept), or appends a
    /// new field.
    ///
    /// # Errors
    /// [`Error::Invalid`] (key and value rules, 64 fields);
    /// [`Error::NoEntry`]; [`Error::Capacity`].
    pub fn set(
        &mut self,
        name: &[u8],
        key: &[u8],
        sensitive: bool,
        value: &[u8],
    ) -> Result<(), Error> {
        format::check_key(key, 0).map_err(Error::Invalid)?;
        format::check_value(value, 0).map_err(Error::Invalid)?;
        let r = rewrite(self.live.expose(), &mut self.scratch, &mut |it| {
            let (i, f) = field(it, name, key)?;
            let n = it
                .get(i)
                .and_then(|x| x.src.as_ref())
                .map_or(0, |e| e.fields.clone().count());
            if f.is_none() && n >= usize::from(format::MAX_FIELDS) {
                return Err(Error::Invalid(format::Error::FieldCount(0)));
            }
            Ok((i, Edit::Set(key, sensitive, value)))
        });
        self.adopt(r)
    }

    /// `unset`: removes the field matching `key` (ASCII case-insensitive).
    ///
    /// # Errors
    /// [`Error::NoEntry`]; [`Error::NoField`].
    pub fn unset(&mut self, name: &[u8], key: &[u8]) -> Result<(), Error> {
        let r = rewrite(
            self.live.expose(),
            &mut self.scratch,
            &mut |it| match field(it, name, key)? {
                (i, Some(_)) => Ok((i, Edit::Unset(key))),
                (_, None) => Err(Error::NoField),
            },
        );
        self.adopt(r)
    }

    /// `mv`: renames an entry. Refuses a `new` name held by another entry
    /// (B4); renaming an entry to its own name changes nothing.
    ///
    /// # Errors
    /// [`Error::Invalid`]; [`Error::NoEntry`]; [`Error::EntryExists`];
    /// [`Error::Capacity`].
    pub fn mv(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        format::check_name(new, 0).map_err(Error::Invalid)?;
        let r = rewrite(self.live.expose(), &mut self.scratch, &mut |it| {
            let i = find(it, old).map_err(|_| Error::NoEntry)?;
            let mut item = it.remove(i);
            let pos = find(it, new).err().ok_or(Error::EntryExists)?;
            item.name = new;
            it.insert(pos, item);
            Ok((usize::MAX, Edit::None))
        });
        self.adopt(r)
    }

    /// `mvfield`: renames the field matching `old`. Refuses a `new` key
    /// that matches another field of the entry under ASCII case-folding
    /// (B4); a case-only rename of the field itself is allowed.
    ///
    /// # Errors
    /// [`Error::Invalid`]; [`Error::NoEntry`]; [`Error::NoField`];
    /// [`Error::FieldExists`]; [`Error::Capacity`].
    pub fn mvfield(&mut self, name: &[u8], old: &[u8], new: &[u8]) -> Result<(), Error> {
        format::check_key(new, 0).map_err(Error::Invalid)?;
        let r = rewrite(self.live.expose(), &mut self.scratch, &mut |it| {
            let (i, f) = field(it, name, old)?;
            let f = f.ok_or(Error::NoField)?;
            let (_, g) = field(it, name, new)?;
            if g.is_some_and(|g| g != f) {
                return Err(Error::FieldExists);
            }
            Ok((i, Edit::Rename(old, new)))
        });
        self.adopt(r)
    }

    /// `rm`: deletes an entry.
    ///
    /// # Errors
    /// [`Error::NoEntry`].
    pub fn rm(&mut self, name: &[u8]) -> Result<(), Error> {
        let r = rewrite(self.live.expose(), &mut self.scratch, &mut |it| {
            it.remove(find(it, name).map_err(|_| Error::NoEntry)?);
            Ok((usize::MAX, Edit::None))
        });
        self.adopt(r)
    }

    /// `import` (Section 12.2): merges the body the caller read into the
    /// scratch half. With `suffix`, an imported name equal to an existing
    /// one gets [`IMPORT_SUFFIX`]; any remaining collision (without
    /// `suffix`, or a suffixed name that is taken) is refused. The import
    /// is moved to the top of scratch and merged into the bottom, so the
    /// merged body plus the import must fit the slot. Returns the number
    /// of imported entries. The scratch half is empty afterwards.
    ///
    /// # Errors
    /// [`Error::Invalid`] (the import's exact constraint and entry index;
    /// a suffixed name over 256 bytes; 10,000 entries);
    /// [`Error::EntryExists`]; [`Error::Capacity`].
    pub fn import(&mut self, suffix: bool) -> Result<usize, Error> {
        let mut n = 0;
        let r = self.merge(suffix, &mut n);
        self.adopt(r).map(|()| n)
    }

    fn merge(&mut self, suffix: bool, n: &mut usize) -> Result<usize, Error> {
        let len = self.scratch.len();
        format::parse_body(self.scratch.expose()).map_err(Error::Invalid)?;
        let cap = self.scratch.capacity();
        let buf = full(&mut self.scratch)?;
        buf.copy_within(..len, cap - len);
        let (out, top) = buf.split_at_mut(cap - len);
        out.fill(0);
        let mut it = items(self.live.expose())?;
        let live = it.len();
        for (i, e) in format::parse_body(top)?.enumerate() {
            let clash = it.get(..live).is_some_and(|l| find(l, e.name).is_ok());
            if clash && !suffix {
                return Err(Error::EntryExists);
            }
            let sfx = if clash { IMPORT_SUFFIX } else { b"" };
            if e.name.len() + sfx.len() > format::MAX_NAME {
                let i = u32::try_from(i).map_err(|_| format::Error::EntryCount)?;
                return Err(Error::Invalid(format::Error::NameLength(i)));
            }
            it.push(item(e.name, sfx, Some(e)));
        }
        *n = it.len() - live;
        it.sort_by(|a, b| a.full().cmp(b.full()));
        if it
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.full().eq(b.full())))
        {
            return Err(Error::EntryExists);
        }
        if it.len() > format::MAX_ENTRIES as usize {
            return Err(Error::Invalid(format::Error::EntryCount));
        }
        emit(out, &it, usize::MAX, &Edit::None)
    }

    /// Seals the live body for saving (Section 4, save data flow): copies
    /// it into the scratch half, encrypts it there with [`save`], copies
    /// the ciphertext out, and wipes scratch. The live half is unchanged.
    ///
    /// # Errors
    /// As [`save`].
    pub fn seal(&mut self, dek: &[u8], h: &mut Header) -> Result<Vec<u8>, Error> {
        let r = self
            .scratch
            .set_len(self.live.len())
            .map_err(|_| Error::Capacity);
        let r = r.and_then(|()| {
            self.scratch
                .expose_mut()
                .copy_from_slice(self.live.expose());
            save(dek, h, self.scratch.expose_mut())
        });
        self.scratch.clear();
        r
    }
}
