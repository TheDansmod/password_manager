//! Command grammar, REPL loop, idle timeout, confirmation prompts, rendering
//! of entries (spec Section 9). Implemented in M7.

use crate::format::Header;
use crate::store::{self, Freshness};
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
        vault::Error::Crypto(C::Password | C::KdfParams)
        | vault::Error::Capacity
        | vault::Error::Invalid(_)
        | vault::Error::EntryExists
        | vault::Error::FieldExists
        | vault::Error::NoEntry
        | vault::Error::NoField => EXIT_USER,
        vault::Error::Crypto(C::Kdf | C::KdfUnlocked) => EXIT_ENV,
        vault::Error::Crypto(C::Random | C::Length) => EXIT_INTERNAL,
    }
}

/// Exit code for a storage error (Section 9.3): a missing or existing
/// vault is a user error; a damaged file or state file is an integrity
/// error; everything else (permissions, owner, file type, filesystem,
/// lock, I/O) is an environment refusal.
#[must_use]
pub fn store_exit_code(e: &store::Error) -> i32 {
    match e {
        store::Error::NoVault | store::Error::Exists => EXIT_USER,
        store::Error::Format(_) | store::Error::State => EXIT_INTEGRITY,
        _ => EXIT_ENV,
    }
}

/// The rollback warning of Section 8.4 for file generation `file` below
/// the recorded generation `recorded`.
#[must_use]
pub fn rollback_warning(file: u64, recorded: u64) -> String {
    format!(
        "This vault is older than the last version saved on this machine \
         (generation {file} < {recorded}). It may have been rolled back or restored from backup."
    )
}

/// Applies the user's answer to a rollback warning (Section 8.4). Only
/// exactly `yes` continues; the header's generation is then raised to the
/// recorded one, so the next save writes `max(g_f, g_s) + 1`. A fresh vault
/// needs no answer.
///
/// # Errors
/// [`EXIT_INTEGRITY`] for any other answer; `h` is unchanged.
pub fn confirm_rollback(h: &mut Header, f: Freshness, answer: &[u8]) -> Result<(), i32> {
    match f {
        Freshness::Fresh => Ok(()),
        Freshness::RolledBack { recorded, .. } if answer == b"yes" => {
            h.generation = h.generation.max(recorded);
            Ok(())
        }
        Freshness::RolledBack { .. } => Err(EXIT_INTEGRITY),
    }
}
