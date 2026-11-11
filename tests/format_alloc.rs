//! T-FMT-4: hostile headers (extreme `kdf_m_kib`, `payload_len` at or
//! beyond the file size, `payload_len` near `u32::MAX`) are rejected before
//! any allocation larger than 64 KiB.
//!
//! A counting layer around the verifying zeroizing allocator (T-MEM-6)
//! records the largest allocation made while armed. This crate holds a
//! single `#[test]` so no other test thread allocates while armed. The
//! store's read path (M4) is added to this test when it exists.

use pwv::alloc::ZeroizingAlloc;
use pwv::format::{Error, HEADER_LEN, Header, MAX_FILE, parse_header, split_file};
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Counting {
    inner: ZeroizingAlloc,
    armed: AtomicBool,
    largest: AtomicUsize,
}

#[global_allocator]
static GLOBAL: Counting = Counting {
    inner: ZeroizingAlloc::new(true),
    armed: AtomicBool::new(false),
    largest: AtomicUsize::new(0),
};

impl Counting {
    fn note(&self, size: usize) {
        if self.armed.load(Ordering::SeqCst) {
            self.largest.fetch_max(size, Ordering::SeqCst);
        }
    }
}

// SAFETY: forwards every call unchanged to the inner allocator; only
// records sizes.
unsafe impl GlobalAlloc for Counting {
    // SAFETY: (trait method) forwards the caller's contract.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.note(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { self.inner.alloc(layout) }
    }
    // SAFETY: (trait method) forwards the caller's contract.
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.note(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc_zeroed`'s contract.
        unsafe { self.inner.alloc_zeroed(layout) }
    }
    // SAFETY: (trait method) forwards the caller's contract.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract.
        unsafe { self.inner.dealloc(ptr, layout) }
    }
    // SAFETY: (trait method) forwards the caller's contract.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.note(new_size);
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract.
        unsafe { self.inner.realloc(ptr, layout, new_size) }
    }
}

const LIMIT: usize = 64 * 1024;

fn header() -> Header {
    Header {
        vault_id: [1; 16],
        kdf_m_kib: 65_536,
        kdf_t: 3,
        salt: [2; 32],
        wrap_nonce: [3; 24],
        wrapped_dek: [4; 48],
        generation: 1,
        payload_nonce: [5; 24],
        payload_len: 4096,
    }
}

fn patched(off: usize, patch: &[u8]) -> [u8; HEADER_LEN + 16] {
    let mut f = [0u8; HEADER_LEN + 16];
    f[..HEADER_LEN].copy_from_slice(&header().encode());
    f[off..off + patch.len()].copy_from_slice(patch);
    f
}

/// Runs `f` armed and returns its result and the largest allocation.
fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    GLOBAL.largest.store(0, Ordering::SeqCst);
    GLOBAL.armed.store(true, Ordering::SeqCst);
    let r = f();
    GLOBAL.armed.store(false, Ordering::SeqCst);
    (r, GLOBAL.largest.load(Ordering::SeqCst))
}

#[test]
fn t_fmt_4_hostile_headers_rejected_before_large_allocation() {
    // The counter works: a large allocation while armed is seen.
    let (v, big) = measured(|| vec![0u8; 2 * LIMIT]);
    drop(v);
    assert!(big >= 2 * LIMIT, "counting allocator not active");

    // Build the inputs before arming; they live on the stack.
    let cases: [(&str, [u8; HEADER_LEN + 16], Error); 7] = [
        (
            "kdf_m_kib = 0",
            patched(32, &0u32.to_le_bytes()),
            Error::KdfMemory,
        ),
        (
            "kdf_m_kib = 2^32 - 1",
            patched(32, &u32::MAX.to_le_bytes()),
            Error::KdfMemory,
        ),
        (
            "payload_len = u32::MAX",
            patched(180, &u32::MAX.to_le_bytes()),
            Error::PayloadLength,
        ),
        (
            "payload_len = 2^32 - 4096",
            patched(180, &0xFFFF_F000u32.to_le_bytes()),
            Error::PayloadLength,
        ),
        (
            "payload_len = 2^31",
            patched(180, &0x8000_0000u32.to_le_bytes()),
            Error::PayloadLength,
        ),
        // Valid L, but L >= the 200-byte file's size.
        (
            "payload_len >= file size",
            patched(180, &4096u32.to_le_bytes()),
            Error::FileLength,
        ),
        (
            "payload_len = 16 MiB > file size",
            patched(180, &(16u32 << 20).to_le_bytes()),
            Error::FileLength,
        ),
    ];
    for (what, file, want) in &cases {
        let (got, largest) = measured(|| split_file(file).err());
        assert_eq!(got, Some(*want), "{what}");
        assert!(largest <= LIMIT, "{what}: allocated {largest} bytes");
        // The store-style check (parse the header, compare the claimed
        // length with the actual size) also stays allocation-free.
        let (claimed, largest) = measured(|| parse_header(file).map(|h| h.file_len()));
        assert!(largest <= LIMIT, "{what}: allocated {largest} bytes");
        if let Ok(len) = claimed {
            assert!(len <= MAX_FILE && len != file.len(), "{what}");
        }
    }
}
