//! `SecureArena` and `SecretSlot`: locked, guarded, non-dumpable memory
//! that holds every secret byte (spec Section 5.2).
//!
//! The arena's data region is partitioned once into fixed, named slots
//! ([`Slots`]); there is no allocator inside the arena. Slot bytes beyond a
//! slot's current length are always zero.

#![allow(unsafe_code)]

use crate::sys::{self, GuardedRegion};
use core::marker::PhantomData;

/// Smallest permitted arena data size (256 KiB, `--arena-size`).
pub const MIN_ARENA: usize = 256 * 1024;
/// Largest permitted arena data size (6 MiB, `--arena-size`).
pub const MAX_ARENA: usize = 6 * 1024 * 1024;
/// Default arena data size (1 MiB).
pub const DEFAULT_ARENA: usize = 1024 * 1024;

/// Size of the `Input` slot (the kernel's canonical line limit).
pub const INPUT_LEN: usize = 4096;
/// Size of each of the `Pw1`, `Pw2`, `Gen`, `Clip` slots.
pub const SMALL_LEN: usize = 1024;
/// Size of each of the `Kek`, `Dek`, `NewDek` slots.
pub const KEY_LEN: usize = 32;

/// Arena and slot errors. Messages are fixed and secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Requested arena size outside [`MIN_ARENA`, `MAX_ARENA`].
    Size,
    /// The protected mapping could not be created.
    Map(sys::Error),
    /// `mlock` failed and `--allow-unlocked-memory` was not given.
    Lock,
    /// A slot length exceeds the slot's capacity.
    Capacity,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Size => "arena size must be between 256 and 6144 KiB",
            Error::Map(e) => e.message(),
            Error::Lock => {
                "cannot lock secure memory (RLIMIT_MEMLOCK); see `pwv doctor` or pass --allow-unlocked-memory"
            }
            Error::Capacity => "value too long",
        }
    }
}

/// The single home of all secrets: one guarded, locked, non-dumpable
/// mapping. Not `Send`, `Sync`, or `Clone`. Dropping it zeroizes the whole
/// data region, then `munlock`s, then `munmap`s.
pub struct SecureArena {
    region: GuardedRegion,
}

impl SecureArena {
    /// Creates the arena with a data region of `size` bytes (rounded up to
    /// whole pages) and locks it.
    ///
    /// # Errors
    /// [`Error::Size`] if `size` is out of range; [`Error::Map`] if mapping
    /// fails; [`Error::Lock`] if `mlock` fails and `allow_unlocked` is false.
    pub fn new(size: usize, allow_unlocked: bool) -> Result<Self, Error> {
        if !(MIN_ARENA..=MAX_ARENA).contains(&size) {
            return Err(Error::Size);
        }
        let mut region = GuardedRegion::new(size).map_err(Error::Map)?;
        if region.lock().is_err() && !allow_unlocked {
            return Err(Error::Lock);
        }
        #[cfg(feature = "memtest")]
        {
            let (start, end) = region.data_range();
            sys::write_stderr(format!("PWV_MEMTEST arena {start:#x}-{end:#x}\n").as_bytes());
        }
        Ok(SecureArena { region })
    }

    /// Whether the data region is locked in RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.region.is_locked()
    }

    /// Data region size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.region.size()
    }

    /// Address range `[start, end)` of the data region.
    #[must_use]
    pub fn data_range(&self) -> (usize, usize) {
        self.region.data_range()
    }

    /// Partitions the data region into its named slots. `VaultB` ends at the
    /// last byte of the data region, directly below the upper guard page.
    ///
    /// # Errors
    /// [`Error::Size`] if the region is too small (impossible for an arena
    /// built by [`SecureArena::new`]).
    pub fn slots(&mut self) -> Result<Slots<'_>, Error> {
        #[allow(
            clippy::mut_mut,
            reason = "standard slice-carving idiom with mem::take"
        )]
        fn take<'a>(rest: &mut &'a mut [u8], n: usize) -> Result<SecretSlot<'a>, Error> {
            let (head, tail) = core::mem::take(rest)
                .split_at_mut_checked(n)
                .ok_or(Error::Size)?;
            *rest = tail;
            Ok(SecretSlot::new(head))
        }
        let mut r = self.region.data_mut();
        let vault_len = r
            .len()
            .saturating_sub(4 * SMALL_LEN + 3 * KEY_LEN + INPUT_LEN)
            / 2;
        Ok(Slots {
            input: take(&mut r, INPUT_LEN)?,
            pw1: take(&mut r, SMALL_LEN)?,
            pw2: take(&mut r, SMALL_LEN)?,
            kek: take(&mut r, KEY_LEN)?,
            dek: take(&mut r, KEY_LEN)?,
            new_dek: take(&mut r, KEY_LEN)?,
            r#gen: take(&mut r, SMALL_LEN)?,
            clip: take(&mut r, SMALL_LEN)?,
            vault_a: take(&mut r, vault_len)?,
            vault_b: SecretSlot::new(r),
        })
    }

    /// `memtest`: the whole data region, for zero checks.
    #[cfg(feature = "memtest")]
    #[must_use]
    pub fn raw_data(&self) -> &[u8] {
        self.region.data()
    }

    /// `memtest` (T-MEM-3): runs the drop sequence, calling `hook` with the
    /// data region after zeroization and just before `munmap`.
    #[cfg(feature = "memtest")]
    pub fn close_with_snapshot(self, hook: &mut dyn FnMut(&[u8])) {
        self.region.close_with_snapshot(hook);
    }

    /// `memtest` (T-MEM-2): writes one byte just past the last slot
    /// (`overflow`) or just before the first slot. Dies with SIGSEGV.
    #[cfg(all(feature = "memtest", not(miri)))]
    pub fn probe_guard(&mut self, overflow: bool) {
        self.region.probe_guard(overflow);
    }
}

impl core::fmt::Debug for SecureArena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureArena([REDACTED; {} bytes])", self.size())
    }
}

/// Argon2 working memory (spec Section 5.4, `KdfRegion`): a dedicated
/// guarded, `MADV_DONTDUMP` mapping viewed as Argon2 blocks. Locking is
/// attempted, never required here; the caller decides (`--require-locked-kdf`).
/// Dropping it zeroizes the data, then `munlock`s, then `munmap`s.
pub struct KdfRegion {
    region: GuardedRegion,
}

// `blocks` views page-aligned memory as `argon2::Block`s (argon2 0.6.0:
// `#[repr(align(64))] struct Block([u64; 128])`).
const _: () = assert!(
    core::mem::size_of::<argon2::Block>() == argon2::Block::SIZE
        && core::mem::align_of::<argon2::Block>() <= 4096
);

impl KdfRegion {
    /// Maps a region of at least `blocks` Argon2 blocks (1 KiB each) and
    /// attempts to lock it.
    ///
    /// # Errors
    /// [`Error::Size`] if the size overflows; [`Error::Map`] if mapping fails.
    pub fn new(blocks: usize) -> Result<Self, Error> {
        let len = blocks.checked_mul(argon2::Block::SIZE).ok_or(Error::Size)?;
        let mut region = GuardedRegion::new(len).map_err(Error::Map)?;
        let _ = region.lock();
        Ok(KdfRegion { region })
    }

    /// Whether the region is locked in RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.region.is_locked()
    }

    /// Address range `[start, end)` of the data part (not secret; T-MEM-7).
    #[must_use]
    pub fn data_range(&self) -> (usize, usize) {
        self.region.data_range()
    }

    /// The region as Argon2 blocks (whole pages, so at least the requested
    /// count).
    #[must_use]
    pub fn blocks(&mut self) -> &mut [argon2::Block] {
        let data = self.region.data_mut();
        if data
            .as_ptr()
            .align_offset(core::mem::align_of::<argon2::Block>())
            != 0
        {
            return &mut []; // unreachable for page-aligned maps; Argon2 then fails
        }
        let n = data.len() / argon2::Block::SIZE;
        // SAFETY: `data` is aligned for `Block` (checked just above; it is
        // page-aligned), initialised, and exclusively borrowed for the returned
        // lifetime; `n * 1024 <= data.len()`. `Block` is plain `[u64; 128]`,
        // so every bit pattern is a valid value.
        #[allow(clippy::cast_ptr_alignment, reason = "alignment checked above")]
        unsafe {
            core::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<argon2::Block>(), n)
        }
    }

    /// `memtest` (T-MEM-7): runs the drop sequence, calling `hook` with the
    /// data after zeroization and just before `munmap`.
    #[cfg(feature = "memtest")]
    pub fn close_with_snapshot(self, hook: &mut dyn FnMut(&[u8])) {
        self.region.close_with_snapshot(hook);
    }
}

/// The fixed slots of the arena (spec Section 5.2 table).
#[derive(Debug)]
pub struct Slots<'a> {
    /// Raw bytes of any line typed by the user (4 KiB).
    pub input: SecretSlot<'a>,
    /// Master password entry; NFC-normalised copy (1 KiB).
    pub pw1: SecretSlot<'a>,
    /// Master password confirmation (1 KiB).
    pub pw2: SecretSlot<'a>,
    /// Key-encryption key (32 B).
    pub kek: SecretSlot<'a>,
    /// Data-encryption key (32 B).
    pub dek: SecretSlot<'a>,
    /// New DEK during `passwd` (32 B).
    pub new_dek: SecretSlot<'a>,
    /// Freshly generated password or passphrase (1 KiB).
    pub r#gen: SecretSlot<'a>,
    /// The value currently on the clipboard (1 KiB).
    pub clip: SecretSlot<'a>,
    /// Vault body, first half of the double buffer.
    pub vault_a: SecretSlot<'a>,
    /// Vault body, second half of the double buffer; ends at the guard page.
    pub vault_b: SecretSlot<'a>,
}

/// A `&mut` view of one arena slot plus its current length.
///
/// Not `Send`, `Sync`, `Clone`, `Copy`, or `Display`, and no `Deref` to
/// `[u8]`: bytes are reachable only through [`SecretSlot::expose`] and
/// [`SecretSlot::expose_mut`]. Bytes beyond the length are always zero.
/// Dropping the slot zeroizes the used prefix.
pub struct SecretSlot<'a> {
    buf: &'a mut [u8],
    len: usize,
    _not_send: PhantomData<*mut u8>,
}

impl<'a> SecretSlot<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        SecretSlot {
            buf,
            len: 0,
            _not_send: PhantomData,
        }
    }

    /// Capacity of the slot in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Current length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the current length is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sets the length. Growing exposes zero bytes; shrinking zeroizes the
    /// bytes cut off, preserving the zero-tail invariant.
    ///
    /// # Errors
    /// [`Error::Capacity`] if `len` exceeds the capacity.
    pub fn set_len(&mut self, len: usize) -> Result<(), Error> {
        if len > self.buf.len() {
            return Err(Error::Capacity);
        }
        if let Some(tail) = self.buf.get_mut(len..self.len) {
            sys::wipe(tail);
        }
        self.len = len;
        Ok(())
    }

    /// The used prefix. Every read of secret bytes goes through here.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// The used prefix, mutably.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.buf.get_mut(..self.len).unwrap_or_default()
    }

    /// Zeroizes the used prefix and sets the length to 0.
    pub fn clear(&mut self) {
        sys::wipe(self.expose_mut());
        self.len = 0;
    }
}

impl Drop for SecretSlot<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl core::fmt::Debug for SecretSlot<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.len)
    }
}
