//! `pwv` binary entry point.
//!
//! Spec Section 4: calls `sys::harden()` before any other code, installs the
//! zeroizing global allocator, parses arguments, and dispatches to `cli`.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(false);

fn main() {
    let code = match pwv::sys::harden() {
        // A panic unwinds through `run`, so every `Drop` (arena wipe,
        // clipboard clear, terminal restore) runs; then exit code 5
        // (Section 9.3). The hook has already written "internal error".
        Ok(hardening) => std::panic::catch_unwind(|| pwv::cli::run(&hardening))
            .unwrap_or(pwv::cli::EXIT_INTERNAL),
        Err(e) => {
            pwv::sys::write_stderr(b"pwv: ");
            pwv::sys::write_stderr(e.message().as_bytes());
            pwv::sys::write_stderr(b"\n");
            pwv::cli::EXIT_ENV
        }
    };
    std::process::exit(code);
}
