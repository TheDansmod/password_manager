//! Raw `read(2)`/`write(2)` on the TTY, echo control, `poll`-based idle
//! timeout, control-character sanitisation, screen clearing (spec Section 11).
//! The only module permitted to name std stdio. Implemented in M7.

use crate::sys;

/// M1 placeholder: blocks until a newline or end of file on fd 0, discarding
/// the bytes (no secret is read before M7). Replaced by `/dev/tty` I/O in M7.
///
/// # Errors
/// [`sys::Error::Read`] if `read(2)` fails.
pub fn wait_line() -> Result<(), sys::Error> {
    let mut buf = [0u8; 64];
    loop {
        let n = sys::read_stdin(&mut buf)?;
        if n == 0 || buf.get(..n).is_some_and(|b| b.contains(&b'\n')) {
            return Ok(());
        }
    }
}
