//! Clipboard copy with expiry, clear-if-unchanged, clear at exit
//! (spec Section 11.3). The deadline itself is kept by `cli`, whose `poll`
//! loop also enforces the idle timeout (same-layer modules may not use
//! each other, so `clip` cannot wait on the terminal).
//!
//! Rule 5 exception (owner sign-off 2026-11-15, `DESIGN_NOTES`): arboard
//! 3.7.0 copies the value to the heap and into its X11 server thread, and
//! `get_text` returns a heap `String`. The zeroizing allocator wipes them
//! when freed; the `Clip` slot holds the comparison copy.

use crate::crypto;
use crate::secmem::SecretSlot;

/// A clipboard failure. Messages are fixed and secret-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Built without the `clipboard` feature.
    Unsupported,
    /// No clipboard is reachable (no display), or the copy failed.
    Unavailable,
    /// The value is not UTF-8 text.
    Utf8,
    /// The value does not fit the `Clip` slot.
    Capacity,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Unsupported => "this build has no clipboard support",
            Error::Unavailable => "the clipboard is not available",
            Error::Utf8 => "the value is not UTF-8 text",
            Error::Capacity => "the value is too long for the clipboard slot",
        }
    }
}

/// The clipboard handle, created lazily on the first copy and reused
/// (Section 11.3 step 1). `CLIPBOARD` selection only, never `PRIMARY`.
#[derive(Default)]
pub struct Clip {
    #[cfg(feature = "clipboard")]
    board: Option<arboard::Clipboard>,
}

impl Clip {
    /// Copies `value` to the clipboard with the history-exclusion hint, and
    /// into `slot` for the later clear-if-unchanged comparison. The caller
    /// sets the deadline.
    ///
    /// # Errors
    /// Any [`Error`]; `slot` is then empty and the clipboard unchanged.
    pub fn copy(&mut self, value: &[u8], slot: &mut SecretSlot<'_>) -> Result<(), Error> {
        slot.clear();
        let text = core::str::from_utf8(value).map_err(|_| Error::Utf8)?;
        slot.set_len(value.len()).map_err(|_| Error::Capacity)?;
        slot.expose_mut().copy_from_slice(value);
        self.set(text, true).inspect_err(|_| slot.clear())
    }

    #[cfg(feature = "clipboard")]
    fn set(&mut self, text: &str, hint: bool) -> Result<(), Error> {
        // arboard 3.7.0: `Set::text`, `SetExtLinux::exclude_from_history`
        // (src/platform/linux/mod.rs:380), default selection CLIPBOARD.
        use arboard::SetExtLinux;
        if self.board.is_none() {
            self.board = Some(arboard::Clipboard::new().map_err(|_| Error::Unavailable)?);
        }
        let set = self.board.as_mut().ok_or(Error::Unavailable)?.set();
        let set = if hint {
            set.exclude_from_history()
        } else {
            set
        };
        set.text(std::borrow::Cow::Borrowed(text))
            .map_err(|_| Error::Unavailable)
    }

    #[cfg(not(feature = "clipboard"))]
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "same signature as the clipboard build"
    )]
    fn set(&mut self, _text: &str, _hint: bool) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The current clipboard text; the returned `String` is wiped by the
    /// allocator when dropped.
    #[cfg(feature = "clipboard")]
    fn get(&mut self) -> Option<String> {
        self.board.as_mut()?.get_text().ok()
    }

    #[cfg(not(feature = "clipboard"))]
    #[allow(clippy::unused_self, reason = "same signature as the clipboard build")]
    fn get(&mut self) -> Option<String> {
        None
    }

    /// Expiry, and every exit path (Section 11.3 step 3): if the clipboard
    /// still holds the value in `slot` (compared in constant time), sets it
    /// to the empty string. `slot` is zeroed in every case, also when the
    /// clipboard cannot be read. Call this before dropping the `Clip`
    /// (step 4), so a hand-over to a clipboard manager carries nothing.
    ///
    /// The clipboard handle is then dropped (the next copy makes a new
    /// one): a value that another client pasted went through the X11
    /// connection's write buffer (x11rb 0.13.2, `WriteBuffer::data_buf`),
    /// which keeps sent bytes until they are overwritten. Dropping the
    /// handle frees that buffer, and the allocator wipes it (T-MEM-4).
    pub fn clear_if_unchanged(&mut self, slot: &mut SecretSlot<'_>) {
        if !slot.is_empty() {
            let ours = self
                .get()
                .is_some_and(|now| crypto::ct_eq(now.as_bytes(), slot.expose()));
            if ours {
                let _ = self.set("", true);
            }
        }
        slot.clear();
        #[cfg(feature = "clipboard")]
        {
            self.board = None;
        }
    }
}
