//! Zeroizing global allocator, defence in depth (spec Section 5.3).
//!
//! Wraps `std::alloc::System`: `dealloc` zeroizes the full block first;
//! `realloc` always moves (allocate, copy, zeroize old, free) so no stale
//! prefix survives; `alloc_zeroed` is delegated unchanged.
//!
//! The verifying mode is the asserting layer of T-MEM-6: after zeroizing it
//! checks that every byte of the block is zero just before
//! `System::dealloc`, and aborts the process otherwise. Every test crate
//! installs the verifying mode; `main.rs` installs the plain one.
//!
//! Independent of every other module (it cannot use `sys`).

#![allow(unsafe_code)]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};
use zeroize::Zeroize;

/// The zeroizing allocator. Construct with [`ZeroizingAlloc::new`] in a
/// `#[global_allocator]` static.
#[derive(Debug)]
pub struct ZeroizingAlloc {
    verify: bool,
    verified: AtomicUsize,
}

impl ZeroizingAlloc {
    /// Zeroize on free; if `verify` (tests only, T-MEM-6), also assert that
    /// each freed block is all-zero and abort otherwise.
    #[must_use]
    pub const fn new(verify: bool) -> Self {
        ZeroizingAlloc {
            verify,
            verified: AtomicUsize::new(0),
        }
    }

    /// Number of blocks verified to be zero at `dealloc` (verifying mode).
    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.verified.load(Ordering::Relaxed)
    }
}

// SAFETY: every method forwards to `System` with the caller's layout, so the
// `GlobalAlloc` contract is inherited from `System`; `dealloc` only adds a
// wipe of the block being freed, and `realloc` returns a fresh `System`
// block of `new_size` bytes with the same alignment.
unsafe impl GlobalAlloc for ZeroizingAlloc {
    // SAFETY: (trait method) forwards the caller's layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: (trait method) forwards the caller's layout to `System`.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc_zeroed`'s contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    // SAFETY: (trait method) `ptr` is a live block of `layout` from `self`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is valid for writes of `layout.size()` bytes until
        // freed below; `MaybeUninit<u8>` accepts any (even uninit) contents.
        let block = unsafe {
            core::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), layout.size())
        };
        block.zeroize();
        if self.verify {
            let ptr = core::hint::black_box(ptr);
            // SAFETY: same block, now fully initialised (zeroed) above.
            let bytes = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.iter().any(|&b| b != 0) {
                std::process::abort();
            }
            self.verified.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: `ptr` was allocated by `System` with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: (trait method) `ptr` is a live block of `layout` from `self`.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return core::ptr::null_mut();
        };
        // SAFETY: `new_size` is non-zero per the `realloc` contract.
        let new = unsafe { System.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: both blocks are valid for `min(old, new)` bytes and
            // distinct live allocations, so they cannot overlap; the old
            // block is then wiped and freed exactly once.
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}
