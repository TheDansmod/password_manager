//! T-FMT-4: hostile headers (extreme `kdf_m_kib`, `payload_len` at or
//! beyond the file size, `payload_len` near `u32::MAX`) are rejected before
//! any allocation larger than 64 KiB.
//!
//! A counting layer around the verifying zeroizing allocator (T-MEM-6)
//! records the largest allocation made while armed. This crate holds a
//! single `#[test]` so no other test thread allocates while armed. M4 adds
//! the store's read path: `Store::open` compares the header's claimed
//! length with the file size before allocating the file buffer.

use pwv::alloc::ZeroizingAlloc;
use pwv::format::{Error, HEADER_LEN, Header, MAX_FILE, parse_header, split_file};
use pwv::store::{self, Paths, Store};
use std::alloc::{GlobalAlloc, Layout};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
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

    // M4: the store's read path, on files planted in a private directory.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("pwv");
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let paths = Paths {
        vault: dir.join("vault.pwv"),
        state: tmp.path().join("state"),
    };
    let plant = |bytes: &[u8], len: u64| {
        let _ = std::fs::remove_file(&paths.vault);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true).mode(0o600);
        let mut f = o.open(&paths.vault).unwrap();
        f.write_all(bytes).unwrap();
        f.set_len(len).unwrap(); // sparse beyond `bytes`
    };
    let gib = 1u64 << 30;
    let store_cases: [(&str, [u8; HEADER_LEN + 16], u64, Error); 5] = [
        // Header claims 4 KiB; the (sparse) file is 1 GiB.
        (
            "1 GiB file",
            patched(180, &4096u32.to_le_bytes()),
            gib,
            Error::FileLength,
        ),
        // Header claims 16 MiB; the file is 200 bytes.
        (
            "16 MiB claimed",
            patched(180, &(16u32 << 20).to_le_bytes()),
            200,
            Error::FileLength,
        ),
        (
            "payload_len = u32::MAX",
            patched(180, &u32::MAX.to_le_bytes()),
            gib,
            Error::PayloadLength,
        ),
        (
            "kdf_m_kib = 2^32 - 1",
            patched(32, &u32::MAX.to_le_bytes()),
            gib,
            Error::KdfMemory,
        ),
        // Shorter than a header.
        ("100-byte file", patched(0, &[]), 100, Error::HeaderLength),
    ];
    for (what, file, len, want) in &store_cases {
        plant(file, *len);
        let (got, largest) = measured(|| Store::open(paths.clone(), false).err());
        assert_eq!(got, Some(store::Error::Format(*want)), "store: {what}");
        assert!(largest <= LIMIT, "store: {what}: allocated {largest} bytes");
    }
}
