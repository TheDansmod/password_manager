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
        Ok(hardening) => pwv::cli::run(&hardening),
        Err(e) => {
            pwv::sys::write_stderr(b"pwv: ");
            pwv::sys::write_stderr(e.message().as_bytes());
            pwv::sys::write_stderr(b"\n");
            pwv::cli::EXIT_ENV
        }
    };
    std::process::exit(code);
}
