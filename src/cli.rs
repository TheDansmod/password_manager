//! Command grammar, REPL loop, idle timeout, confirmation prompts, rendering
//! of entries (spec Section 9). Implemented in M7.

use crate::sys::Hardening;
use crate::{crypto, term, vault};

/// Exit code for a user error (spec Section 9.3).
pub const EXIT_USER: i32 = 1;
/// Exit code for an authentication failure (spec Section 9.3).
pub const EXIT_AUTH: i32 = 2;
/// Exit code for a vault integrity or rollback refusal (spec Section 9.3).
pub const EXIT_INTEGRITY: i32 = 3;
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

/// Exit code for a vault lifecycle error (Section 9.3). Wrong password and
/// damaged payload are the same [`crypto::Error::Auth`], hence the same
/// code and the same message (T-CRY-2).
#[must_use]
pub fn exit_code(e: vault::Error) -> i32 {
    use crypto::Error as C;
    match e {
        vault::Error::Crypto(C::Auth) => EXIT_AUTH,
        vault::Error::Format(_) | vault::Error::Generation => EXIT_INTEGRITY,
        vault::Error::Crypto(C::Password | C::KdfParams) | vault::Error::Capacity => EXIT_USER,
        vault::Error::Crypto(C::Kdf | C::KdfUnlocked) => EXIT_ENV,
        vault::Error::Crypto(C::Random | C::Length) => EXIT_INTERNAL,
    }
}
