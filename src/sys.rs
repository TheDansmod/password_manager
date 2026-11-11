//! Process hardening and thin syscall wrappers (spec Sections 5.1, 5.2, 5.6).
//!
//! The only module that names `rustix` or `libc`. API versions verified
//! against rustix 1.1.6: `process::{setrlimit, getrlimit, umask,
//! set_dumpable_behavior}`, `mm::{mmap_anonymous, mprotect, mlock, munlock,
//! madvise, munmap}`, `mm::Advice::{LinuxDontDump, LinuxWipeOnFork}`,
//! `termios::isatty`, `io::{read, write}`, `stdio::{stdin, stderr}`.

#![allow(unsafe_code)]

use core::ptr::NonNull;
use rustix::fd::BorrowedFd;
use rustix::io::Errno;
use rustix::mm::{Advice, MprotectFlags};
use rustix::process::{Resource, Rlimit};
use zeroize::Zeroize;

/// Failure of a hardening step or a memory syscall. Messages are fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `setrlimit(RLIMIT_CORE)` failed.
    CoreLimit,
    /// `prctl(PR_SET_DUMPABLE, 0)` failed.
    Dumpable,
    /// fd 0 or fd 1 is not a terminal.
    NotATty,
    /// `mmap` or `mprotect` failed, or the size overflowed.
    Map,
    /// `madvise(MADV_DONTDUMP | MADV_WIPEONFORK)` failed.
    Advise,
    /// `mlock` failed (typically `RLIMIT_MEMLOCK`).
    Lock,
    /// `read(2)` failed.
    Read,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::CoreLimit => "cannot disable core dumps (RLIMIT_CORE)",
            Error::Dumpable => "cannot mark the process non-dumpable",
            Error::NotATty => "standard input and output must be a terminal",
            Error::Map => "cannot map protected memory",
            Error::Advise => "cannot exclude protected memory from dumps and forks",
            Error::Lock => "cannot lock memory (RLIMIT_MEMLOCK too low)",
            Error::Read => "cannot read from the terminal",
        }
    }
}

/// Outcome of [`harden`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// Effective soft `RLIMIT_MEMLOCK` in bytes; `None` means unlimited.
    pub memlock_limit: Option<u64>,
}

/// Hardens the process (spec Section 5.1). Must be the first call in `main`.
///
/// Steps, in order: `RLIMIT_CORE` = {0, 0}; `PR_SET_DUMPABLE` = 0 (skipped in
/// `memtest` builds, Section 5.8); `umask(0o077)`; fds 0 and 1 must be TTYs;
/// panic hook; raise the soft `RLIMIT_MEMLOCK` to the hard limit.
///
/// # Errors
/// Any failure of steps 1–4 (step 5 cannot fail; step 6 is best effort).
pub fn harden() -> Result<Hardening, Error> {
    let zero = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(Resource::Core, zero).map_err(|_| Error::CoreLimit)?;
    #[cfg(not(feature = "memtest"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| Error::Dumpable)?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    if !rustix::termios::isatty(rustix::stdio::stdin())
        || !rustix::termios::isatty(rustix::stdio::stdout())
    {
        return Err(Error::NotATty);
    }
    install_panic_hook();
    let mut lim = rustix::process::getrlimit(Resource::Memlock);
    if lim.current != lim.maximum {
        let raised = Rlimit {
            current: lim.maximum,
            maximum: lim.maximum,
        };
        if rustix::process::setrlimit(Resource::Memlock, raised).is_ok() {
            lim = rustix::process::getrlimit(Resource::Memlock);
        }
    }
    Ok(Hardening {
        memlock_limit: lim.current,
    })
}

/// Installs a panic hook that writes the fixed string `internal error` to
/// fd 2 by raw `write(2)` and never formats the panic payload (Section 5.1).
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| write_stderr(b"internal error\n")));
}

/// Writes `buf` to fd 2 by raw `write(2)`, ignoring errors. Never pass
/// secret bytes.
pub fn write_stderr(buf: &[u8]) {
    write_all(rustix::stdio::stderr(), buf);
}

fn write_all(fd: BorrowedFd<'_>, mut buf: &[u8]) {
    while !buf.is_empty() {
        match rustix::io::write(fd, buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf = buf.get(n..).unwrap_or_default(),
        }
    }
}

/// Reads from fd 0 by raw `read(2)` into `buf`, retrying on `EINTR`.
/// Returns the number of bytes read (0 at end of file).
///
/// # Errors
/// [`Error::Read`] if `read(2)` fails.
pub fn read_stdin(buf: &mut [u8]) -> Result<usize, Error> {
    loop {
        match rustix::io::read(rustix::stdio::stdin(), &mut *buf) {
            Ok(n) => return Ok(n),
            Err(Errno::INTR) => {}
            Err(_) => return Err(Error::Read),
        }
    }
}

/// Best-effort erasure of stack residue (Section 5.6): zeroizes a 64 KiB
/// local array and passes it through `black_box`.
#[inline(never)]
#[allow(
    clippy::large_stack_arrays,
    reason = "the stack array is the point (Section 5.6)"
)]
pub fn scrub_stack() {
    let mut buf = [0u8; 65536];
    buf.zeroize();
    core::hint::black_box(&mut buf);
}

/// Callback receiving the zeroized data part just before `munmap`.
type SnapshotHook<'h> = &'h mut dyn FnMut(&[u8]);

/// An anonymous private mapping `[guard | data | guard]`: guards are
/// `PROT_NONE`; data is read-write and `MADV_DONTDUMP | MADV_WIPEONFORK`.
///
/// `Drop` zeroizes the data, then `munlock`s (if locked), then `munmap`s.
/// Not `Send` or `Sync` (holds a raw pointer). Under `cfg(miri)` the data is
/// a heap block without guards (spec T-SAN-2).
pub struct GuardedRegion {
    base: NonNull<u8>,
    data: NonNull<u8>,
    total: usize,
    data_len: usize,
    locked: bool,
    /// Data part is read-write (set once `mprotect` succeeds).
    writable: bool,
}

impl GuardedRegion {
    /// Maps a region whose data part is `min_len` rounded up to whole pages.
    ///
    /// # Errors
    /// [`Error::Map`] on size overflow or `mmap`/`mprotect` failure;
    /// [`Error::Advise`] if `madvise` fails (fail closed).
    pub fn new(min_len: usize) -> Result<Self, Error> {
        let page = if cfg!(miri) {
            4096
        } else {
            rustix::param::page_size()
        };
        let guard = if cfg!(miri) { 0 } else { page };
        let data_len = min_len
            .max(1)
            .checked_next_multiple_of(page)
            .ok_or(Error::Map)?;
        let total = data_len.checked_add(2 * guard).ok_or(Error::Map)?;
        let base = map(total)?;
        let mut region = GuardedRegion {
            base,
            // Cannot be null: base is non-null and the offset stays in the mapping.
            data: NonNull::new(base.as_ptr().wrapping_add(guard)).unwrap_or(base),
            total,
            data_len,
            locked: false,
            writable: false,
        };
        region.protect()?;
        Ok(region)
    }

    fn protect(&mut self) -> Result<(), Error> {
        if cfg!(miri) {
            self.writable = true;
            return Ok(());
        }
        let (ptr, len) = (self.data.as_ptr().cast(), self.data_len);
        // SAFETY: [ptr, ptr + len) is the data part of the mapping owned by
        // `self`; changing its protection affects no other Rust object.
        unsafe { rustix::mm::mprotect(ptr, len, MprotectFlags::READ | MprotectFlags::WRITE) }
            .map_err(|_| Error::Map)?;
        self.writable = true;
        for advice in [Advice::LinuxDontDump, Advice::LinuxWipeOnFork] {
            // SAFETY: as above; these advice values only change dump and fork
            // behaviour and never discard or alias memory.
            unsafe { rustix::mm::madvise(ptr, len, advice) }.map_err(|_| Error::Advise)?;
        }
        Ok(())
    }

    /// Locks the data pages in RAM (`mlock`).
    ///
    /// # Errors
    /// [`Error::Lock`] if `mlock` fails.
    pub fn lock(&mut self) -> Result<(), Error> {
        if !cfg!(miri) {
            // SAFETY: the range is the data part of the mapping owned by `self`.
            unsafe { rustix::mm::mlock(self.data.as_ptr().cast(), self.data_len) }
                .map_err(|_| Error::Lock)?;
        }
        self.locked = true;
        Ok(())
    }

    /// Whether [`GuardedRegion::lock`] succeeded.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Size of the data part in bytes (a whole number of pages).
    #[must_use]
    pub fn size(&self) -> usize {
        self.data_len
    }

    /// Address range `[start, end)` of the data part (for tests and `memtest`).
    #[must_use]
    pub fn data_range(&self) -> (usize, usize) {
        let start = self.data.as_ptr() as usize;
        (start, start.wrapping_add(self.data_len))
    }

    /// The data part.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        // SAFETY: `data` points to `data_len` readable, initialised (zero-
        // filled by the kernel or allocator) bytes owned by `self`, which
        // stay mapped until `self` is dropped; the borrow ties to `&self`.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.data_len) }
    }

    /// The data part, mutably.
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `data`; `&mut self` guarantees exclusive access.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len) }
    }

    /// Zeroizes, then calls `hook` with the data part, then unlocks and
    /// unmaps (the `memtest` snapshot of T-MEM-3, taken just before `munmap`).
    #[cfg(feature = "memtest")]
    pub fn close_with_snapshot(mut self, hook: SnapshotHook<'_>) {
        self.teardown(Some(hook));
        core::mem::forget(self);
    }

    /// `memtest` probe for T-MEM-2: writes one byte at `data + offset`, where
    /// `offset` is `-1` (underflow) or `size()` (overflow). Faults with SIGSEGV.
    #[cfg(all(feature = "memtest", not(miri)))]
    pub fn probe_guard(&mut self, overflow: bool) {
        let target = if overflow {
            self.data.as_ptr().wrapping_add(self.data_len)
        } else {
            self.data.as_ptr().wrapping_sub(1)
        };
        // SAFETY: deliberately not memory-safe. `target` lies in a PROT_NONE
        // guard page of this mapping, so the write faults (SIGSEGV) before it
        // can modify anything. Test-only (`memtest`), never in release builds.
        unsafe { core::ptr::write_volatile(target, 0xA5) };
    }

    /// Zeroize (if the data is accessible), munlock, optional snapshot, munmap.
    fn teardown(&mut self, hook: Option<SnapshotHook<'_>>) {
        if self.writable {
            self.data_mut().zeroize();
        }
        if self.locked && !cfg!(miri) {
            // SAFETY: the range is the data part of our own mapping.
            let _ = unsafe { rustix::mm::munlock(self.data.as_ptr().cast(), self.data_len) };
        }
        if let (Some(hook), true) = (hook, self.writable) {
            hook(self.data());
        }
        unmap(self.base, self.total);
    }
}

impl Drop for GuardedRegion {
    fn drop(&mut self) {
        self.teardown(None);
    }
}

#[cfg(not(miri))]
fn map(total: usize) -> Result<NonNull<u8>, Error> {
    // SAFETY: a fresh anonymous mapping at a kernel-chosen address; it cannot
    // overlap any existing Rust object.
    let p = unsafe {
        rustix::mm::mmap_anonymous(
            core::ptr::null_mut(),
            total,
            rustix::mm::ProtFlags::empty(),
            rustix::mm::MapFlags::PRIVATE,
        )
    }
    .map_err(|_| Error::Map)?;
    NonNull::new(p.cast::<u8>()).ok_or(Error::Map)
}

#[cfg(not(miri))]
fn unmap(base: NonNull<u8>, total: usize) {
    // SAFETY: [base, base + total) is exactly the mapping created by `map`,
    // and no reference into it outlives the owning `GuardedRegion`.
    let _ = unsafe { rustix::mm::munmap(base.as_ptr().cast(), total) };
}

#[cfg(miri)]
fn map(total: usize) -> Result<NonNull<u8>, Error> {
    let layout = std::alloc::Layout::from_size_align(total, 4096).map_err(|_| Error::Map)?;
    // SAFETY: `layout` has non-zero size.
    NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).ok_or(Error::Map)
}

#[cfg(miri)]
fn unmap(base: NonNull<u8>, total: usize) {
    if let Ok(layout) = std::alloc::Layout::from_size_align(total, 4096) {
        // SAFETY: `base` was allocated by `map` with this exact layout.
        unsafe { std::alloc::dealloc(base.as_ptr(), layout) };
    }
}
