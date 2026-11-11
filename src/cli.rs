//! Command grammar, REPL loop, idle timeout, confirmation prompts, rendering
//! of entries (spec Section 9). Implemented in M7.

use crate::sys::Hardening;
use crate::term;

/// Exit code for an environment refusal (spec Section 9.3).
pub const EXIT_ENV: i32 = 4;
/// Exit code for an internal error (spec Section 9.3).
pub const EXIT_INTERNAL: i32 = 5;

/// Runs the program after [`crate::sys::harden`] and returns the exit code.
///
/// M1 placeholder: no command exists yet. Waits for one line (or end of file)
/// on the terminal, so tests can inspect a hardened live process, then
/// returns [`EXIT_INTERNAL`].
#[must_use]
pub fn run(_hardening: &Hardening) -> i32 {
    match term::wait_line() {
        Ok(()) | Err(_) => EXIT_INTERNAL,
    }
}
