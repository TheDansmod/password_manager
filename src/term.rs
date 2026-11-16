//! Raw `read(2)`/`write(2)` on `/dev/tty`, echo control, `poll`-based
//! waiting, control-character sanitisation, screen clearing (spec Section
//! 11.1, 11.2). The only module permitted to name std stdio (it names none:
//! all I/O is raw, through `sys`).
//!
//! Secret contract: input is read directly into an arena slot; a secret is
//! written straight from its slot, never through an intermediate buffer.

use crate::secmem::SecretSlot;
use crate::sys::{self, Errno, Signal};
use core::time::Duration;
use std::os::fd::{AsFd, OwnedFd};

/// The fixed mask for a sensitive value: 8 bullets, whatever its length
/// (Section 11.2, S6).
pub const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// A terminal failure or event. Messages are fixed and never echo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `/dev/tty` cannot be opened.
    NoTty,
    /// A terminal syscall failed, or echo could not be disabled.
    Io,
    /// End of input (Ctrl-D on an empty line, or the terminal went away).
    Eof,
    /// The line does not fit the slot; it was drained and discarded.
    TooLong,
    /// The line is not valid UTF-8.
    Utf8,
    /// SIGINT: the current command is cancelled.
    Interrupted,
    /// SIGTERM, SIGHUP, or SIGQUIT: orderly exit.
    Terminated,
    /// `memtest` only: SIGUSR1 ended a `__pause`.
    Resumed,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::NoTty => "cannot open /dev/tty (a controlling terminal is required)",
            Error::Io => "terminal I/O failed",
            Error::Eof => "end of input",
            Error::TooLong => "input too long; nothing was used",
            Error::Utf8 => "input is not valid UTF-8; nothing was used",
            Error::Interrupted => "cancelled",
            Error::Terminated => "terminated by a signal",
            Error::Resumed => "resumed",
        }
    }
}

/// The controlling terminal: every prompt and all output go here, never to
/// fd 0 or fd 1 (Section 9.3). Dropping it restores the saved `termios`.
pub struct Term {
    fd: OwnedFd,
    saved: Option<sys::TtyState>,
    color: bool,
}

/// Hidden input (Section 11.1, `TermiosGuard`): while it lives, `ECHO` is
/// off; dropping it restores the saved `termios` and ends the line.
pub struct EchoGuard<'t>(&'t Term);

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        self.0.restore();
        self.0.write(b"\n");
    }
}

impl Term {
    /// Opens `/dev/tty` once and saves its settings. `color` enables ANSI
    /// styling (the caller applies the `TERM`, `NO_COLOR`, `--no-color`
    /// rules of Section 11.2).
    ///
    /// # Errors
    /// [`Error::NoTty`] if `/dev/tty` cannot be opened.
    pub fn open(color: bool) -> Result<Term, Error> {
        let fd = sys::open_tty().map_err(|_| Error::NoTty)?;
        let saved = sys::tty_state(fd.as_fd()).ok();
        Ok(Term { fd, saved, color })
    }

    /// Writes `bytes` to the terminal by raw `write(2)`, unchanged. Use only
    /// for fixed program text; anything derived from vault content goes
    /// through [`Term::write_sanitized`].
    pub fn write(&self, bytes: &[u8]) {
        sys::write_fd(self.fd.as_fd(), bytes);
    }

    /// Writes `bytes` through [`sanitize`], chunk by chunk from the caller's
    /// slice (which may be an arena slot), without an intermediate copy.
    pub fn write_sanitized(&self, bytes: &[u8]) {
        sanitize(bytes, &mut |chunk| self.write(chunk));
    }

    /// Writes an ANSI style sequence if styling is enabled: `1` bold, `2`
    /// dim, `0` reset.
    pub fn style(&self, code: u8) {
        if self.color {
            self.write(&[0x1b, b'[', b'0' + code % 10, b'm']);
        }
    }

    /// Clears the screen and the scrollback: `ESC[H ESC[2J ESC[3J`.
    pub fn clear_screen(&self) {
        self.write(b"\x1b[H\x1b[2J\x1b[3J");
    }

    /// Restores the terminal settings saved at open.
    pub fn restore(&self) {
        if let Some(saved) = &self.saved {
            let _ = sys::set_tty(self.fd.as_fd(), saved, true);
        }
    }

    /// The pending signal as an error, if any.
    fn signal() -> Result<(), Error> {
        match sys::take_signal() {
            None => Ok(()),
            Some(Signal::Interrupt) => Err(Error::Interrupted),
            Some(Signal::Terminate) => Err(Error::Terminated),
            Some(Signal::Resume) => Err(Error::Resumed),
        }
    }

    /// Waits until input is available (`true`), or until `timeout` has
    /// passed or an unrelated signal arrived (`false`: the caller checks
    /// its deadlines against the clock).
    ///
    /// # Errors
    /// [`Error::Interrupted`], [`Error::Terminated`] for a handled signal;
    /// [`Error::Io`] if `poll` fails.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        Self::signal()?;
        let ms = timeout.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        match sys::wait_readable(self.fd.as_fd(), ms) {
            Ok(ready) => Ok(ready),
            Err(Errno::INTR) => Self::signal().map(|()| false),
            Err(_) => Err(Error::Io),
        }
    }

    /// Clears `ECHO` (keeping `ICANON` and `ISIG`) until the returned
    /// guard is dropped. Call it before writing the prompt: the kernel
    /// echoes input when it is typed, not when it is read.
    ///
    /// # Errors
    /// [`Error::Io`] if echo cannot be turned off (fail closed).
    pub fn hide(&self) -> Result<EchoGuard<'_>, Error> {
        let saved = self.saved.as_ref().ok_or(Error::Io)?;
        sys::set_tty(self.fd.as_fd(), saved, false).map_err(|_| Error::Io)?;
        Ok(EchoGuard(self))
    }

    /// Reads one line in canonical mode by raw `read(2)` directly into
    /// `out` (without the newline). A line that does not fit `out` is
    /// drained to its newline and rejected, never truncated.
    ///
    /// # Errors
    /// Any [`Error`]; `out` is then empty.
    pub fn read_line(&self, out: &mut SecretSlot<'_>) -> Result<(), Error> {
        out.clear();
        let res = self.read_raw(out);
        if res.is_err() {
            out.clear();
        }
        res
    }

    fn read_raw(&self, out: &mut SecretSlot<'_>) -> Result<(), Error> {
        let mut long = false;
        loop {
            Self::signal()?;
            out.set_len(out.capacity()).map_err(|_| Error::Io)?;
            let n = match sys::read_fd(self.fd.as_fd(), out.expose_mut()) {
                Ok(n) => n,
                Err(Errno::INTR) => {
                    out.clear();
                    continue; // the loop head reports a handled signal
                }
                Err(_) => return Err(Error::Io),
            };
            out.set_len(n).map_err(|_| Error::Io)?;
            if n == 0 {
                return Err(Error::Eof);
            }
            let ended = out.expose().last() == Some(&b'\n');
            if ended && long {
                return Err(Error::TooLong);
            }
            if ended {
                out.set_len(n - 1).map_err(|_| Error::Io)?;
                return match core::str::from_utf8(out.expose()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(Error::Utf8),
                };
            }
            // No newline: the line is longer than the slot. Drain it.
            long = true;
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Whether `c` must never reach the terminal raw: C0, DEL, and C1 controls,
/// and the bidirectional overrides U+202A–U+202E and U+2066–U+2069.
#[must_use]
pub fn is_unsafe(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Display sanitisation (Section 9.3): passes `input` to `sink` in chunks,
/// with every unsafe character replaced by a visible escape (`\x1b` for C0
/// and DEL, `\u{202e}` for the others) and every byte that is not valid
/// UTF-8 by `\xNN`. Clean runs are borrowed from `input`; escapes come from
/// a small stack buffer, so a secret is never copied to the heap.
pub fn sanitize(input: &[u8], sink: &mut dyn FnMut(&[u8])) {
    let mut emit = |chunk: &[u8]| {
        if !chunk.is_empty() {
            sink(chunk);
        }
    };
    let mut rest = input;
    while !rest.is_empty() {
        let valid = match core::str::from_utf8(rest) {
            Ok(s) => s,
            Err(e) => rest
                .get(..e.valid_up_to())
                .and_then(|b| core::str::from_utf8(b).ok())
                .unwrap_or_default(),
        };
        let mut start = 0;
        for (i, c) in valid.char_indices().filter(|(_, c)| is_unsafe(*c)) {
            emit(valid.as_bytes().get(start..i).unwrap_or_default());
            escape(u32::from(c), c.is_ascii(), &mut emit);
            start = i + c.len_utf8();
        }
        emit(valid.as_bytes().get(start..).unwrap_or_default());
        if let Some(&bad) = rest.get(valid.len()) {
            escape(u32::from(bad), true, &mut emit);
        }
        rest = rest.get(valid.len() + 1..).unwrap_or_default();
    }
}

/// Emits `\xNN` (`byte`) or `\u{N..}` for `v`.
fn escape(v: u32, byte: bool, emit: &mut dyn FnMut(&[u8])) {
    let mut buf = [0u8; 12];
    let mut n = 0;
    let mut push = |c: u8| {
        if let Some(slot) = buf.get_mut(n) {
            *slot = c;
            n += 1;
        }
    };
    let digits = if byte {
        2
    } else {
        (32 - v.leading_zeros()).div_ceil(4).max(2)
    };
    for c in if byte { &b"\\x"[..] } else { &b"\\u{"[..] } {
        push(*c);
    }
    for d in (0..digits).rev() {
        push(
            b"0123456789abcdef"
                .get((v >> (4 * d)) as usize & 15)
                .copied()
                .unwrap_or(b'?'),
        );
    }
    if !byte {
        push(b'}');
    }
    emit(buf.get(..n).unwrap_or_default());
    sys::wipe(&mut buf);
}
