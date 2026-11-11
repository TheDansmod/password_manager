//! `pwv`: a single-binary, Linux-first terminal password manager.
//!
//! The library target exists for tests and fuzzing; `main.rs` is a thin
//! wrapper. Module layering (spec Section 4), top to bottom:
//!
//! ```text
//! cli
//! clip  term  store  vault  gen
//! format  crypto
//! secmem
//! sys
//! ```
//!
//! `alloc` is independent. A module may depend only on modules in a lower
//! band; `tests/eng.rs` (T-ENG-3) enforces this.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod alloc;
pub mod cli;
pub mod clip;
pub mod crypto;
pub mod format;
pub mod r#gen;
pub mod secmem;
pub mod store;
pub mod sys;
pub mod term;
pub mod vault;

/// T-MEM-6: unit tests run under the verifying zeroizing allocator.
#[cfg(test)]
#[global_allocator]
static TEST_ALLOC: alloc::ZeroizingAlloc = alloc::ZeroizingAlloc::new(true);
