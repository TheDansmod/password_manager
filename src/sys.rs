//! Process hardening and thin syscall wrappers (spec Sections 5.1, 5.2, 5.6).
//!
//! The only module that names `rustix` or `libc`. API versions verified
//! against rustix 1.1.6: `process::{setrlimit, getrlimit, umask,
//! set_dumpable_behavior}`, `mm::{mmap_anonymous, mprotect, mlock, munlock,
//! madvise, munmap}`, `mm::Advice::{LinuxDontDump, LinuxWipeOnFork}`,
//! `termios::isatty`, `io::{read, write}`, `stdio::{stdin, stderr}`; M4:
//! `fs::{open, openat, fstat, statat, fstatfs, flock, fsync, renameat,
//! linkat, unlinkat, Dir}`, `process::geteuid`; M7: `termios::{tcgetattr,
//! tcsetattr, OptionalActions::Now, LocalModes::ECHO}`, `event::{poll,
//! PollFd, PollFlags, Timespec}`. libc 0.2.191 (M7): `sigaction`,
//! `sigemptyset` (rustix has no `sigaction`).

#![allow(unsafe_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use rustix::fd::{BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
pub use rustix::io::Errno;
use rustix::mm::{Advice, MprotectFlags};
use rustix::process::{Resource, Rlimit};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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
    /// `sigaction` failed.
    Signal,
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
            Error::Signal => "cannot install signal handlers",
        }
    }
}

/// Outcome of [`harden`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// Effective soft `RLIMIT_MEMLOCK` in bytes; `None` means unlimited.
    pub memlock_limit: Option<u64>,
    /// Whether fd 0 is a terminal. Only `import --from-stdin` may run
    /// without one (Sections 9.3, 12.2); `cli` refuses everything else.
    pub stdin_tty: bool,
}

/// Hardens the process (spec Section 5.1). Must be the first call in `main`.
///
/// Steps, in order: `RLIMIT_CORE` = {0, 0}; `PR_SET_DUMPABLE` = 0 (skipped in
/// `memtest` builds, Section 5.8); `umask(0o077)`; fd 1 must be a TTY, and
/// whether fd 0 is one is recorded for `cli` (a pipe is allowed only for
/// `import --from-stdin`); panic hook; raise the soft `RLIMIT_MEMLOCK` to
/// the hard limit.
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
    if !rustix::termios::isatty(rustix::stdio::stdout()) {
        return Err(Error::NotATty);
    }
    let stdin_tty = rustix::termios::isatty(rustix::stdio::stdin());
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
        stdin_tty,
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
    write_fd(rustix::stdio::stderr(), buf);
}

/// Writes all of `buf` to `fd` by raw `write(2)`, retrying on `EINTR` and
/// giving up on any other error (a vanished terminal cannot be reported
/// to). No intermediate buffer: `buf` may be an arena slot.
pub fn write_fd(fd: BorrowedFd<'_>, mut buf: &[u8]) {
    while !buf.is_empty() {
        match rustix::io::write(fd, buf) {
            Err(Errno::INTR) => {}
            Ok(0) | Err(_) => return,
            Ok(n) => buf = buf.get(n..).unwrap_or_default(),
        }
    }
}

/// One raw `read(2)` from `fd` into `buf` (which may be an arena slot).
/// Returns 0 at end of file.
///
/// # Errors
/// The `read(2)` error; `EINTR` is returned, not retried, so that a signal
/// can cancel a prompt.
pub fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, Errno> {
    rustix::io::read(fd, buf)
}

/// fd 0, for `import --from-stdin`.
#[must_use]
pub fn stdin() -> BorrowedFd<'static> {
    rustix::stdio::stdin()
}

// ---- Terminal and signals (spec Sections 9.3, 11.1).

/// Opens `/dev/tty` with `O_RDWR | O_CLOEXEC` (Section 11.1).
///
/// # Errors
/// The `open(2)` error (`ENXIO` without a controlling terminal).
pub fn open_tty() -> Result<OwnedFd, Errno> {
    rustix::fs::open("/dev/tty", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
}

/// Saved terminal settings (`termios`).
pub struct TtyState(rustix::termios::Termios);

/// Reads the terminal settings of `fd`.
///
/// # Errors
/// The `tcgetattr` error.
pub fn tty_state(fd: BorrowedFd<'_>) -> Result<TtyState, Errno> {
    rustix::termios::tcgetattr(fd).map(TtyState)
}

/// Applies `state` to `fd`, with `ECHO` cleared unless `echo` (hidden
/// input keeps `ICANON` and `ISIG`). `set_tty(fd, saved, true)` restores.
///
/// # Errors
/// The `tcsetattr` error.
pub fn set_tty(fd: BorrowedFd<'_>, state: &TtyState, echo: bool) -> Result<(), Errno> {
    let mut t = state.0.clone();
    if !echo {
        t.local_modes.remove(rustix::termios::LocalModes::ECHO);
    }
    rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &t)
}

/// `poll(2)` for input on `fd`: `true` if it is readable (or hung up),
/// `false` after `timeout_ms` (`None` waits without limit).
///
/// # Errors
/// The `poll(2)` error; `EINTR` when a signal arrived.
pub fn wait_readable(fd: BorrowedFd<'_>, timeout_ms: Option<u64>) -> Result<bool, Errno> {
    let ts = timeout_ms.map(|ms| rustix::event::Timespec {
        tv_sec: i64::try_from(ms / 1000).unwrap_or(i64::MAX),
        tv_nsec: ((ms % 1000) * 1_000_000).try_into().unwrap_or(0),
    });
    let mut fds = [rustix::event::PollFd::from_borrowed_fd(
        fd,
        rustix::event::PollFlags::IN,
    )];
    Ok(rustix::event::poll(&mut fds, ts.as_ref())? > 0)
}

/// A signal recorded by the handler (Section 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// SIGINT: cancel the current command.
    Interrupt,
    /// SIGTERM, SIGHUP, or SIGQUIT: orderly exit.
    Terminate,
    /// `memtest` only: SIGUSR1, which ends `__pause` (Section 5.8).
    Resume,
}

/// The pending signal: 0 none, 1 interrupt, 2 terminate, 3 resume. The
/// only global besides the allocator (T-ENG-3 permits atomics).
static PENDING: AtomicU8 = AtomicU8::new(0);

/// The handler only sets the atomic flag. Terminate is never overwritten.
extern "C" fn on_signal(sig: libc::c_int) {
    let v = match sig {
        libc::SIGINT => 1,
        libc::SIGUSR1 => 3,
        _ => 2,
    };
    if v == 2 {
        PENDING.store(2, Ordering::SeqCst);
    } else {
        let _ = PENDING.compare_exchange(0, v, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Installs the flag-setting handler for SIGINT, SIGTERM, SIGHUP, and
/// SIGQUIT (and SIGUSR1 in `memtest` builds), without `SA_RESTART`, so a
/// blocked `read` or `poll` returns `EINTR`.
///
/// # Errors
/// [`Error::Signal`] if `sigaction` fails.
pub fn install_signal_flag() -> Result<(), Error> {
    let extra: &[libc::c_int] = if cfg!(feature = "memtest") {
        &[libc::SIGUSR1]
    } else {
        &[]
    };
    for &sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT]
        .iter()
        .chain(extra)
    {
        // SAFETY: an all-zero `sigaction` is a valid value (no flags, so no
        // SA_SIGINFO and no SA_RESTART); `on_signal` has the handler ABI and
        // is async-signal-safe (one atomic store); the pointers are valid
        // for the calls.
        let rc = unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&raw mut sa.sa_mask);
            libc::sigaction(sig, &raw const sa, core::ptr::null_mut())
        };
        if rc != 0 {
            return Err(Error::Signal);
        }
    }
    Ok(())
}

/// Takes the pending signal, if any, clearing the flag.
pub fn take_signal() -> Option<Signal> {
    match PENDING.swap(0, Ordering::SeqCst) {
        1 => Some(Signal::Interrupt),
        2 => Some(Signal::Terminate),
        3 => Some(Signal::Resume),
        _ => None,
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
    wipe(&mut buf);
    core::hint::black_box(&mut buf);
}

/// Zeroizes `buf` with volatile stores (`zeroize`), one `u64` at a time
/// over its aligned middle and byte by byte at the ends: the same erasure
/// as `zeroize` on bytes, in an eighth of the stores (Miri pays per store).
pub fn wipe(buf: &mut [u8]) {
    // SAFETY: every bit pattern is a valid `u64`, and `align_to_mut` only
    // reinterprets the aligned middle of this same exclusive borrow.
    let (head, mid, tail) = unsafe { buf.align_to_mut::<u64>() };
    head.zeroize();
    mid.zeroize();
    tail.zeroize();
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
            wipe(self.data_mut());
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

// Under Miri the region comes from `System`, not the global allocator: like
// `mmap`, it bypasses `ZeroizingAlloc`, whose second wipe and scan of an
// already zeroized region would only cost interpretation time.
#[cfg(miri)]
fn map(total: usize) -> Result<NonNull<u8>, Error> {
    use std::alloc::GlobalAlloc;
    let layout = std::alloc::Layout::from_size_align(total, 4096).map_err(|_| Error::Map)?;
    // SAFETY: `layout` has non-zero size.
    NonNull::new(unsafe { std::alloc::System.alloc_zeroed(layout) }).ok_or(Error::Map)
}

#[cfg(miri)]
fn unmap(base: NonNull<u8>, total: usize) {
    use std::alloc::GlobalAlloc;
    if let Ok(layout) = std::alloc::Layout::from_size_align(total, 4096) {
        // SAFETY: `base` was allocated by `map` from `System` with this
        // exact layout.
        unsafe { std::alloc::System.dealloc(base.as_ptr(), layout) };
    }
}

// ---- Files (spec Section 8, for `store`). Every open adds `O_NOFOLLOW |
// O_CLOEXEC`; names are single path components relative to a directory fd.

/// What the open-time checks of Section 8.2 need from `fstat`/`lstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo {
    /// A directory.
    pub is_dir: bool,
    /// A regular file.
    pub is_file: bool,
    /// Owner UID.
    pub uid: u32,
    /// Permission bits, `st_mode & 0o7777`.
    pub perm: u32,
    /// Size in bytes.
    pub size: u64,
}

/// How [`open_at`] opens a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read only, `O_NONBLOCK` (an open of a planted FIFO cannot block).
    Read,
    /// Read only, created with mode 0600 if missing (lock files).
    Lock,
    /// `O_CREAT | O_EXCL | O_WRONLY`, mode 0600 (temporary files).
    CreateNew,
}

/// The effective UID.
#[must_use]
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Opens the directory `path` (`O_DIRECTORY`; the last component must not
/// be a symlink).
///
/// # Errors
/// The `open(2)` error (`ELOOP`/`ENOTDIR` for a symlink or non-directory).
pub fn open_dir(path: &Path) -> Result<OwnedFd, Errno> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, Mode::empty())
}

/// Opens `name` in `dir` as `how` says.
///
/// # Errors
/// The `openat(2)` error (`ELOOP` for a symlink).
pub fn open_at(dir: BorrowedFd<'_>, name: &OsStr, how: OpenMode) -> Result<OwnedFd, Errno> {
    let flags = match how {
        OpenMode::Read => OFlags::RDONLY | OFlags::NONBLOCK,
        OpenMode::Lock => OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CREATE,
        OpenMode::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
    };
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::openat(dir, name, flags, Mode::RUSR | Mode::WUSR)
}

fn file_info(st: &rustix::fs::Stat) -> FileInfo {
    let kind = FileType::from_raw_mode(st.st_mode);
    FileInfo {
        is_dir: kind == FileType::Directory,
        is_file: kind == FileType::RegularFile,
        uid: st.st_uid,
        perm: st.st_mode & 0o7777,
        size: u64::try_from(st.st_size).unwrap_or(u64::MAX),
    }
}

/// `fstat(2)` of `fd`.
///
/// # Errors
/// The `fstat(2)` error.
pub fn info(fd: BorrowedFd<'_>) -> Result<FileInfo, Errno> {
    Ok(file_info(&rustix::fs::fstat(fd)?))
}

/// `fstatat(2)` of `name` in `dir`, not following a symlink (`lstat`).
///
/// # Errors
/// The `fstatat(2)` error (`ENOENT` if missing).
pub fn info_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<FileInfo, Errno> {
    Ok(file_info(&rustix::fs::statat(
        dir,
        name,
        AtFlags::SYMLINK_NOFOLLOW,
    )?))
}

/// The filesystem magic number (`statfs.f_type`) of the filesystem holding
/// `fd`. Magic numbers are 32-bit values.
///
/// # Errors
/// The `fstatfs(2)` error.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "f_type is a signed long holding a 32-bit magic number"
)]
pub fn fs_magic(fd: BorrowedFd<'_>) -> Result<u32, Errno> {
    Ok(rustix::fs::fstatfs(fd)?.f_type as u32)
}

/// `flock(LOCK_EX)`, blocking if `wait`, else `LOCK_NB` (`EWOULDBLOCK` if
/// held). Retries on `EINTR`.
///
/// # Errors
/// The `flock(2)` error.
pub fn lock(fd: BorrowedFd<'_>, wait: bool) -> Result<(), Errno> {
    let op = if wait {
        FlockOperation::LockExclusive
    } else {
        FlockOperation::NonBlockingLockExclusive
    };
    loop {
        match rustix::fs::flock(fd, op) {
            Err(Errno::INTR) => {}
            r => return r,
        }
    }
}

/// `fsync(2)`.
///
/// # Errors
/// The `fsync(2)` error.
pub fn fsync(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    rustix::fs::fsync(fd)
}

/// `renameat(2)` within `dir` (atomic replacement of `to`).
///
/// # Errors
/// The `renameat(2)` error (`ENOENT` if `from` is missing).
pub fn rename_at(dir: BorrowedFd<'_>, from: &OsStr, to: &OsStr) -> Result<(), Errno> {
    rustix::fs::renameat(dir, from, dir, to)
}

/// `linkat(2)` within `dir`, not following a symlink at `from`.
///
/// # Errors
/// The `linkat(2)` error (`EPERM`/`EOPNOTSUPP` where unsupported).
pub fn link_at(dir: BorrowedFd<'_>, from: &OsStr, to: &OsStr) -> Result<(), Errno> {
    rustix::fs::linkat(dir, from, dir, to, AtFlags::empty())
}

/// `unlinkat(2)` of a non-directory `name` in `dir`.
///
/// # Errors
/// The `unlinkat(2)` error.
pub fn unlink_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<(), Errno> {
    rustix::fs::unlinkat(dir, name, AtFlags::empty())
}

/// The names in `dir` (including `.` and `..`).
///
/// # Errors
/// The `getdents(2)` error.
pub fn list_dir(dir: BorrowedFd<'_>) -> Result<Vec<OsString>, Errno> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        names.push(OsStr::from_bytes(entry?.file_name().to_bytes()).to_owned());
    }
    Ok(names)
}
