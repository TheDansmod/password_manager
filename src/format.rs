//! Byte-level encode and decode of the vault header and plaintext body;
//! canonical form; padding (spec Section 7, mirrored in `FORMAT.md`).
//!
//! Pure: no I/O, and the parsers never allocate. Every parse is strict and
//! total: any deviation is an [`Error`] naming the violated constraint (and
//! at most an entry index), never a panic. Body access is zero-copy: the
//! parser and the iterators return slices borrowed from the caller's buffer,
//! which for plaintext is an arena slot.

use core::str;

/// Header length in bytes; also the extent of `AAD_p`.
pub const HEADER_LEN: usize = 184;
/// Extent of `AAD_w`: header bytes `[0, 76)`.
pub const AAD_W_LEN: usize = 76;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Padding block size; `payload_len` is a non-zero multiple of it.
pub const BLOCK: usize = 4096;
/// Largest permitted `payload_len` (16 MiB).
pub const MAX_PAYLOAD: usize = 16 << 20;
/// Largest valid file: header, payload, tag.
pub const MAX_FILE: usize = HEADER_LEN + MAX_PAYLOAD + TAG_LEN;
/// File magic: ASCII `PWVAULT` then 0x00.
pub const MAGIC: [u8; 8] = *b"PWVAULT\0";
/// The only format version this binary reads and writes.
pub const VERSION: u16 = 1;
/// `kdf_id` of Argon2id v0x13.
pub const KDF_ARGON2ID: u8 = 1;
/// Smallest accepted `kdf_m_kib` on read (Section 6.4; 8 KiB under `testkdf`).
#[cfg(not(feature = "testkdf"))]
pub const KDF_M_MIN: u32 = 65_536;
/// Smallest accepted `kdf_m_kib` on read (Section 6.4; 8 KiB under `testkdf`).
#[cfg(feature = "testkdf")]
pub const KDF_M_MIN: u32 = 8;
/// Largest accepted `kdf_m_kib` (4 GiB).
pub const KDF_M_MAX: u32 = 4_194_304;
/// Largest accepted `kdf_t`; the smallest is 1.
pub const KDF_T_MAX: u32 = 20;
/// Body magic: ASCII `PWVB`.
pub const BODY_MAGIC: [u8; 4] = *b"PWVB";
/// Length of the body's fixed prefix (magic, `content_len`, `entry_count`).
pub const BODY_PREFIX: usize = 12;
/// Largest `entry_count`.
pub const MAX_ENTRIES: u32 = 10_000;
/// Largest `name_len`; the smallest is 1.
pub const MAX_NAME: usize = 256;
/// Largest `field_count`.
pub const MAX_FIELDS: u16 = 64;
/// Largest `key_len`; the smallest is 1.
pub const MAX_KEY: usize = 64;
/// Largest `value_len`.
pub const MAX_VALUE: usize = 4096;

#[cfg(not(feature = "testkdf"))]
const KDF_MEMORY_MSG: &str = "KDF memory parameter out of range";
// T-ENG-7 marker: present only in `testkdf` builds.
#[cfg(feature = "testkdf")]
const KDF_MEMORY_MSG: &str = "KDF memory parameter out of range (PWV_TESTKDF build)";

/// A violated format constraint. Variants with a `u32` carry the 0-based
/// index of the offending entry, and nothing else: errors never contain
/// content (spec Section 17, rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Fewer than [`HEADER_LEN`] bytes.
    HeaderLength,
    /// Bad `magic`.
    Magic,
    /// Unsupported `format_version`.
    Version,
    /// Non-zero `flags`.
    Flags,
    /// Unknown `kdf_id`.
    KdfId,
    /// Non-zero reserved bytes.
    Reserved,
    /// `kdf_m_kib` out of range.
    KdfMemory,
    /// `kdf_t` out of range.
    KdfTime,
    /// `kdf_p` is not 1.
    KdfParallelism,
    /// `generation` is 0.
    Generation,
    /// `payload_len` is 0, not a multiple of 4096, or above 16 MiB.
    PayloadLength,
    /// The file length is not exactly 200 + `payload_len`.
    FileLength,
    /// Body length is 0, not a multiple of 4096, or above 16 MiB.
    BodyLength,
    /// Bad `body_magic`.
    BodyMagic,
    /// 12 + `content_len` exceeds the body length.
    ContentLength,
    /// `entry_count` above 10,000.
    EntryCount,
    /// The entries do not consume exactly `content_len` bytes.
    TrailingBytes,
    /// A padding byte is not 0x00.
    Padding,
    /// Padding is not minimal.
    PaddingLength,
    /// An entry record extends past `content_len`.
    EntryTruncated(u32),
    /// `name_len` outside 1–256.
    NameLength(u32),
    /// Name is not UTF-8.
    NameUtf8(u32),
    /// Name contains a control character.
    NameControl(u32),
    /// Name has leading or trailing whitespace.
    NameWhitespace(u32),
    /// Name equals the previous name.
    NameDuplicate(u32),
    /// Name sorts before the previous name.
    NameOrder(u32),
    /// `field_count` above 64.
    FieldCount(u32),
    /// `key_len` outside 1–64.
    KeyLength(u32),
    /// Key is not UTF-8.
    KeyUtf8(u32),
    /// Key contains a control character.
    KeyControl(u32),
    /// Key equals an earlier key of the entry under ASCII case-folding.
    KeyDuplicate(u32),
    /// Field `flags` bits 1–7 are not zero.
    FieldFlags(u32),
    /// `value_len` above 4,096.
    ValueLength(u32),
    /// Value is not UTF-8.
    ValueUtf8(u32),
    /// Value contains a control character other than LF.
    ValueControl(u32),
    /// The output buffer is too small (vault body capacity exceeded).
    Capacity,
}

impl Error {
    /// Fixed, content-free message naming the violated constraint.
    #[must_use]
    pub fn message(self) -> &'static str {
        use Error as E;
        match self {
            E::HeaderLength => "file shorter than the header",
            E::Magic => "not a pwv vault (bad magic)",
            E::Version => "unsupported format version",
            E::Flags => "reserved header flags set",
            E::KdfId => "unknown KDF",
            E::Reserved => "reserved header bytes set",
            E::KdfMemory => KDF_MEMORY_MSG,
            E::KdfTime => "KDF time parameter out of range",
            E::KdfParallelism => "KDF parallelism must be 1",
            E::Generation => "generation must be at least 1",
            E::PayloadLength => "payload length invalid",
            E::FileLength => "file length does not match the header",
            E::BodyLength => "body length invalid",
            E::BodyMagic => "bad body magic",
            E::ContentLength => "content length exceeds the body",
            E::EntryCount => "too many entries",
            E::TrailingBytes => "entries do not fill the content length",
            E::Padding => "non-zero padding",
            E::PaddingLength => "padding is not minimal",
            E::EntryTruncated(_) => "entry truncated",
            E::NameLength(_) => "name length must be 1 to 256 bytes",
            E::NameUtf8(_) => "name is not valid UTF-8",
            E::NameControl(_) => "name contains a control character",
            E::NameWhitespace(_) => "name has leading or trailing whitespace",
            E::NameDuplicate(_) => "duplicate entry name",
            E::NameOrder(_) => "entries not sorted by name",
            E::FieldCount(_) => "more than 64 fields",
            E::KeyLength(_) => "field key length must be 1 to 64 bytes",
            E::KeyUtf8(_) => "field key is not valid UTF-8",
            E::KeyControl(_) => "field key contains a control character",
            E::KeyDuplicate(_) => "duplicate field key (case-insensitive)",
            E::FieldFlags(_) => "reserved field flags set",
            E::ValueLength(_) => "field value longer than 4096 bytes",
            E::ValueUtf8(_) => "field value is not valid UTF-8",
            E::ValueControl(_) => "field value contains a control character",
            E::Capacity => "vault body capacity exceeded",
        }
    }

    /// The 0-based index of the offending entry, if the error has one.
    #[must_use]
    pub fn entry(self) -> Option<u32> {
        use Error as E;
        match self {
            E::EntryTruncated(i)
            | E::NameLength(i)
            | E::NameUtf8(i)
            | E::NameControl(i)
            | E::NameWhitespace(i)
            | E::NameDuplicate(i)
            | E::NameOrder(i)
            | E::FieldCount(i)
            | E::KeyLength(i)
            | E::KeyUtf8(i)
            | E::KeyControl(i)
            | E::KeyDuplicate(i)
            | E::FieldFlags(i)
            | E::ValueLength(i)
            | E::ValueUtf8(i)
            | E::ValueControl(i) => Some(i),
            _ => None,
        }
    }
}

fn ensure(ok: bool, e: Error) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(e) }
}

/// Bounds-checked little-endian cursor. Running out of bytes yields `short`.
#[derive(Clone)]
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    short: Error,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(self.short)?;
        let b = self.buf.get(self.pos..end).ok_or(self.short)?;
        self.pos = end;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        self.bytes(1)?.first().copied().ok_or(self.short)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.bytes(2)?.try_into().map_err(|_| self.short)?;
        Ok(u16::from_le_bytes(b))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?.try_into().map_err(|_| self.short)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.bytes(8)?.try_into().map_err(|_| self.short)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// The 184-byte vault header (spec Section 7.1). Not secret: the DEK is
/// stored wrapped. Fixed fields (`magic`, `format_version`, `flags`,
/// `kdf_id`, reserved, `kdf_p`) are implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Random at init; never changes.
    pub vault_id: [u8; 16],
    /// Argon2id memory in KiB.
    pub kdf_m_kib: u32,
    /// Argon2id passes.
    pub kdf_t: u32,
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Nonce of the DEK wrap.
    pub wrap_nonce: [u8; 24],
    /// Wrapped DEK: 32-byte ciphertext then 16-byte tag.
    pub wrapped_dek: [u8; 48],
    /// Save counter, at least 1.
    pub generation: u64,
    /// Nonce of the payload, fresh per save.
    pub payload_nonce: [u8; 24],
    /// Payload length L.
    pub payload_len: u32,
}

impl Header {
    /// Encodes the header. Does not validate; [`parse_header`] does.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let parts: [&[u8]; 14] = [
            &MAGIC,
            &VERSION.to_le_bytes(),
            &[0, 0],
            &self.vault_id,
            &[KDF_ARGON2ID, 0, 0, 0],
            &self.kdf_m_kib.to_le_bytes(),
            &self.kdf_t.to_le_bytes(),
            &1u32.to_le_bytes(),
            &self.salt,
            &self.wrap_nonce,
            &self.wrapped_dek,
            &self.generation.to_le_bytes(),
            &self.payload_nonce,
            &self.payload_len.to_le_bytes(),
        ];
        parts.concat().try_into().unwrap_or([0; HEADER_LEN])
    }

    /// Exact length of a file with this header: 200 + `payload_len`.
    #[must_use]
    pub fn file_len(&self) -> usize {
        usize::try_from(self.payload_len)
            .unwrap_or(usize::MAX)
            .saturating_add(HEADER_LEN + TAG_LEN)
    }
}

/// Parses and validates the first [`HEADER_LEN`] bytes of `bytes`; later
/// bytes are ignored. Never allocates, so a hostile header is rejected
/// before any buffer is sized from it.
///
/// # Errors
/// The first violated header constraint of spec Sections 6.4 and 7.1.
pub fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    let short = Error::HeaderLength;
    let buf = bytes.get(..HEADER_LEN).ok_or(short)?;
    let mut r = Reader { buf, pos: 0, short };
    ensure(r.bytes(8)? == MAGIC, Error::Magic)?;
    ensure(r.u16()? == VERSION, Error::Version)?;
    ensure(r.u16()? == 0, Error::Flags)?;
    let vault_id = r.bytes(16)?.try_into().map_err(|_| short)?;
    ensure(r.u8()? == KDF_ARGON2ID, Error::KdfId)?;
    ensure(r.bytes(3)? == [0, 0, 0], Error::Reserved)?;
    let kdf_m_kib = r.u32()?;
    ensure(
        (KDF_M_MIN..=KDF_M_MAX).contains(&kdf_m_kib),
        Error::KdfMemory,
    )?;
    let kdf_t = r.u32()?;
    ensure((1..=KDF_T_MAX).contains(&kdf_t), Error::KdfTime)?;
    ensure(r.u32()? == 1, Error::KdfParallelism)?;
    let salt = r.bytes(32)?.try_into().map_err(|_| short)?;
    let wrap_nonce = r.bytes(24)?.try_into().map_err(|_| short)?;
    let wrapped_dek = r.bytes(48)?.try_into().map_err(|_| short)?;
    let generation = r.u64()?;
    ensure(generation >= 1, Error::Generation)?;
    let payload_nonce = r.bytes(24)?.try_into().map_err(|_| short)?;
    let payload_len = r.u32()?;
    let l = usize::try_from(payload_len).map_err(|_| Error::PayloadLength)?;
    ensure(valid_block_len(l), Error::PayloadLength)?;
    Ok(Header {
        vault_id,
        kdf_m_kib,
        kdf_t,
        salt,
        wrap_nonce,
        wrapped_dek,
        generation,
        payload_nonce,
        payload_len,
    })
}

/// Parses a whole vault file into its header, payload ciphertext, and tag.
///
/// # Errors
/// Any header error, or [`Error::FileLength`] if `file.len()` is not
/// exactly 200 + `payload_len`.
pub fn split_file(file: &[u8]) -> Result<(Header, &[u8], &[u8]), Error> {
    let h = parse_header(file)?;
    ensure(file.len() == h.file_len(), Error::FileLength)?;
    let rest = file.get(HEADER_LEN..).ok_or(Error::FileLength)?;
    let (ct, tag) = rest
        .split_at_checked(rest.len().saturating_sub(TAG_LEN))
        .ok_or(Error::FileLength)?;
    Ok((h, ct, tag))
}

fn valid_block_len(l: usize) -> bool {
    l >= BLOCK && l.is_multiple_of(BLOCK) && l <= MAX_PAYLOAD
}

/// Minimal padded body length for `content` bytes of entries:
/// 4096 · ⌈(12 + C) / 4096⌉.
#[must_use]
pub fn padded_len(content: usize) -> Option<usize> {
    content
        .checked_add(BODY_PREFIX)?
        .checked_next_multiple_of(BLOCK)
}

/// Iterator over the entries of a validated body, in canonical (sorted)
/// order. Borrowed; holds no copy. No `Debug`: it reaches content.
#[derive(Clone)]
pub struct Entries<'a> {
    r: Reader<'a>,
    index: u32,
    left: u32,
}

impl<'a> Iterator for Entries<'a> {
    type Item = EntryRef<'a>;
    fn next(&mut self) -> Option<EntryRef<'a>> {
        self.left = self.left.checked_sub(1)?;
        let e = read_entry(&mut self.r, self.index).ok();
        self.index = self.index.saturating_add(1);
        e
    }
}

/// One entry, borrowed from the body. No `Debug`: it holds content.
pub struct EntryRef<'a> {
    /// Byte offset of the entry record within the body.
    pub offset: usize,
    /// The name (validated UTF-8).
    pub name: &'a [u8],
    /// The fields, in insertion order.
    pub fields: Fields<'a>,
}

/// Iterator over the fields of an [`EntryRef`].
#[derive(Clone)]
pub struct Fields<'a> {
    r: Reader<'a>,
    index: u32,
    left: u16,
}

impl<'a> Iterator for Fields<'a> {
    type Item = FieldRef<'a>;
    fn next(&mut self) -> Option<FieldRef<'a>> {
        self.left = self.left.checked_sub(1)?;
        read_field(&mut self.r, self.index).ok()
    }
}

/// One field, borrowed from the body. No `Debug`: it holds content.
pub struct FieldRef<'a> {
    /// The key (validated UTF-8).
    pub key: &'a [u8],
    /// Flag bit 0.
    pub sensitive: bool,
    /// The value (validated UTF-8; LF allowed).
    pub value: &'a [u8],
}

fn text(b: &[u8], lf: bool, utf8: Error, control: Error) -> Result<&str, Error> {
    let s = str::from_utf8(b).map_err(|_| utf8)?;
    ensure(
        !s.chars().any(|c| c.is_control() && !(lf && c == '\n')),
        control,
    )?;
    Ok(s)
}

fn read_field<'a>(r: &mut Reader<'a>, i: u32) -> Result<FieldRef<'a>, Error> {
    let key_len = usize::from(r.u8()?);
    ensure((1..=MAX_KEY).contains(&key_len), Error::KeyLength(i))?;
    let key = r.bytes(key_len)?;
    text(key, false, Error::KeyUtf8(i), Error::KeyControl(i))?;
    let flags = r.u8()?;
    ensure(flags & !1 == 0, Error::FieldFlags(i))?;
    let value_len = usize::from(r.u16()?);
    ensure(value_len <= MAX_VALUE, Error::ValueLength(i))?;
    let value = r.bytes(value_len)?;
    text(value, true, Error::ValueUtf8(i), Error::ValueControl(i))?;
    Ok(FieldRef {
        key,
        sensitive: flags == 1,
        value,
    })
}

fn read_entry<'a>(r: &mut Reader<'a>, i: u32) -> Result<EntryRef<'a>, Error> {
    r.short = Error::EntryTruncated(i);
    let offset = r.pos;
    let name_len = usize::from(r.u16()?);
    ensure((1..=MAX_NAME).contains(&name_len), Error::NameLength(i))?;
    let name = r.bytes(name_len)?;
    let s = text(name, false, Error::NameUtf8(i), Error::NameControl(i))?;
    ensure(s.trim() == s, Error::NameWhitespace(i))?;
    let count = r.u16()?;
    ensure(count <= MAX_FIELDS, Error::FieldCount(i))?;
    let fields = Fields {
        r: r.clone(),
        index: i,
        left: count,
    };
    for k in 0..count {
        let f = read_field(r, i)?;
        let mut earlier = Fields {
            left: k,
            ..fields.clone()
        };
        ensure(
            !earlier.any(|e| e.key.eq_ignore_ascii_case(f.key)),
            Error::KeyDuplicate(i),
        )?;
    }
    Ok(EntryRef {
        offset,
        name,
        fields,
    })
}

/// Validates a whole plaintext body (spec Sections 7.2, 7.3) without
/// copying it, and returns its entries. `body.len()` is L.
///
/// # Errors
/// The first violated body constraint.
pub fn parse_body(body: &[u8]) -> Result<Entries<'_>, Error> {
    ensure(valid_block_len(body.len()), Error::BodyLength)?;
    let mut r = Reader {
        buf: body,
        pos: 0,
        short: Error::BodyLength,
    };
    ensure(r.bytes(4)? == BODY_MAGIC, Error::BodyMagic)?;
    let c = usize::try_from(r.u32()?).map_err(|_| Error::ContentLength)?;
    let count = r.u32()?;
    let end = c
        .checked_add(BODY_PREFIX)
        .filter(|&e| e <= body.len())
        .ok_or(Error::ContentLength)?;
    ensure(count <= MAX_ENTRIES, Error::EntryCount)?;
    let (content, padding) = body.split_at_checked(end).ok_or(Error::ContentLength)?;
    ensure(padding.iter().all(|&b| b == 0), Error::Padding)?;
    ensure(padded_len(c) == Some(body.len()), Error::PaddingLength)?;
    let mut r = Reader {
        buf: content,
        pos: BODY_PREFIX,
        short: Error::TrailingBytes,
    };
    let mut prev: Option<&[u8]> = None;
    for i in 0..count {
        let e = read_entry(&mut r, i)?;
        if let Some(p) = prev {
            ensure(p != e.name, Error::NameDuplicate(i))?;
            ensure(p < e.name, Error::NameOrder(i))?;
        }
        prev = Some(e.name);
    }
    ensure(r.pos == content.len(), Error::TrailingBytes)?;
    r.pos = BODY_PREFIX;
    Ok(Entries {
        r,
        index: 0,
        left: count,
    })
}

/// Serialises a canonical body into a caller-provided buffer (the arena's
/// scratch slot): call [`BodyWriter::entry`] per entry in sorted order, then
/// [`BodyWriter::field`] per field, then [`BodyWriter::finish`]. Copies only
/// into `out`.
pub struct BodyWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    entries: u32,
    count_at: usize,
    fields: u16,
}

impl<'a> BodyWriter<'a> {
    /// Starts a body in `out`.
    #[must_use]
    pub fn new(out: &'a mut [u8]) -> Self {
        BodyWriter {
            out,
            pos: BODY_PREFIX,
            entries: 0,
            count_at: 0,
            fields: 0,
        }
    }

    fn put(&mut self, b: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(b.len()).ok_or(Error::Capacity)?;
        let dst = self.out.get_mut(self.pos..end).ok_or(Error::Capacity)?;
        dst.copy_from_slice(b);
        self.pos = end;
        Ok(())
    }

    /// Appends an entry record with no fields yet.
    ///
    /// # Errors
    /// [`Error::Capacity`]; [`Error::NameLength`] or [`Error::EntryCount`]
    /// if a length does not fit its field.
    pub fn entry(&mut self, name: &[u8]) -> Result<(), Error> {
        let i = self.entries;
        let len = u16::try_from(name.len()).map_err(|_| Error::NameLength(i))?;
        self.put(&len.to_le_bytes())?;
        self.put(name)?;
        self.count_at = self.pos;
        self.fields = 0;
        self.put(&[0, 0])?;
        self.entries = i.checked_add(1).ok_or(Error::EntryCount)?;
        Ok(())
    }

    /// Appends a field record to the current entry. A field before any
    /// entry yields a body that [`BodyWriter::finish`] rejects.
    ///
    /// # Errors
    /// [`Error::Capacity`]; a length error if a length does not fit its
    /// field.
    pub fn field(&mut self, key: &[u8], sensitive: bool, value: &[u8]) -> Result<(), Error> {
        let i = self.entries.saturating_sub(1);
        let key_len = u8::try_from(key.len()).map_err(|_| Error::KeyLength(i))?;
        let value_len = u16::try_from(value.len()).map_err(|_| Error::ValueLength(i))?;
        self.put(&[key_len])?;
        self.put(key)?;
        self.put(&[u8::from(sensitive)])?;
        self.put(&value_len.to_le_bytes())?;
        self.put(value)?;
        self.fields = self.fields.checked_add(1).ok_or(Error::FieldCount(i))?;
        let at = self.count_at;
        let dst = self.out.get_mut(at..at + 2).ok_or(Error::Capacity)?;
        dst.copy_from_slice(&self.fields.to_le_bytes());
        Ok(())
    }

    /// Writes the prefix and minimal zero padding, then validates the result
    /// with [`parse_body`], so a non-canonical body is never produced.
    /// Returns L, the padded length; the body is `out[..L]`.
    ///
    /// # Errors
    /// [`Error::Capacity`] if `out` is shorter than L; any body error.
    pub fn finish(self) -> Result<usize, Error> {
        let c = self.pos.saturating_sub(BODY_PREFIX);
        let c32 = u32::try_from(c).map_err(|_| Error::Capacity)?;
        let l = padded_len(c).ok_or(Error::Capacity)?;
        let body = self.out.get_mut(..l).ok_or(Error::Capacity)?;
        body.get_mut(self.pos..).unwrap_or_default().fill(0);
        let prefix = body.get_mut(..BODY_PREFIX).ok_or(Error::Capacity)?;
        let parts = [BODY_MAGIC, c32.to_le_bytes(), self.entries.to_le_bytes()];
        prefix.copy_from_slice(parts.as_flattened());
        parse_body(body)?;
        Ok(l)
    }
}
