//! Path resolution, permission checks, `flock`, atomic write, backup
//! rotation, rollback-state file (spec Section 8).
//!
//! Every file is reached through a directory fd with `O_NOFOLLOW`. The
//! store never interprets ciphertext: it reads and writes whole files and
//! looks only at the header (length, vault ID, generation).

use crate::format::{self, HEADER_LEN, Header};
use crate::{crypto, sys};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use sys::{Errno, FileInfo, OpenMode};

/// Number of backups kept, `.1` (newest) to `.5` (Section 8.1).
pub const BACKUPS: u8 = 5;
/// Size cap of the rollback-state file.
const STATE_MAX: u64 = 1 << 20;
/// `statfs` magic numbers of filesystems with synthetic permission bits
/// (Section 8.2 step 3): FUSE (`fuseblk`, i.e. ntfs-3g; `statfs` reports
/// one magic for every FUSE mount, so WSL2 virtiofs too), `ntfs3`, legacy
/// `ntfs`, `vfat`/`msdos`, `exfat`, and `9p` (WSL2 `DrvFs`: bits are
/// synthetic unless mounted with `metadata`; owner decision 2026-11-11).
const FOREIGN_FS: [u32; 6] = [
    0x6573_5546,
    0x7366_746e,
    0x5346_544e,
    0x4d44,
    0x2011_bab0,
    0x0102_1997,
];

/// A storage failure. Messages are fixed, except that [`Error::Mode`]
/// carries the exact `chmod` remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No usable vault or state location (`HOME` unset, empty override).
    Path,
    /// No vault at the location; open never creates one (B1).
    NoVault,
    /// `init`: a vault already exists.
    Exists,
    /// A symlink, or not a directory / regular file where one is required.
    Kind,
    /// Not owned by the effective UID.
    Owner,
    /// Group or other permission bits are set; the message with the remedy.
    Mode(String),
    /// Filesystem without real permission bits (`--allow-foreign-fs`).
    ForeignFs,
    /// The vault's lock is held by another session (R3).
    InUse,
    /// The vault file's header or length is invalid.
    Format(format::Error),
    /// The rollback-state file is malformed.
    State,
    /// Any other I/O failure.
    Io,
}

impl Error {
    /// Secret-free message for this error.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Error::Path => "cannot determine the vault location; set HOME or use --vault",
            Error::NoVault => "no vault found; create one with `pwv init`",
            Error::Exists => "a vault already exists at this location",
            Error::Kind => {
                "vault directory and files must be a real directory and regular files, not symlinks"
            }
            Error::Owner => "vault directory and files must be owned by the current user",
            Error::Mode(m) => m,
            Error::ForeignFs => {
                "vault is on a filesystem without real permissions (NTFS, FAT, exFAT, FUSE); move it or pass --allow-foreign-fs"
            }
            Error::InUse => "vault is in use: it is open in another session",
            Error::Format(e) => e.message(),
            Error::State => "rollback-state file is damaged",
            Error::Io => "cannot read or write the vault files",
        }
    }
}

impl From<format::Error> for Error {
    fn from(e: format::Error) -> Self {
        Error::Format(e)
    }
}

impl From<Errno> for Error {
    fn from(_: Errno) -> Self {
        Error::Io
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Io
    }
}

/// Maps an open or stat error: missing, symlink / wrong type, other.
fn found(e: Errno) -> Error {
    match e {
        Errno::NOENT => Error::NoVault,
        Errno::LOOP | Errno::NOTDIR => Error::Kind,
        _ => Error::Io,
    }
}

/// Whether a `statfs` magic number names a filesystem whose permission
/// bits are synthetic (Section 8.2 step 3).
#[must_use]
pub fn is_foreign_fs(magic: u32) -> bool {
    FOREIGN_FS.contains(&magic)
}

/// Resolved locations (Section 8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The vault file; backups, lock, and temporary files sit beside it.
    pub vault: PathBuf,
    /// The rollback-state file.
    pub state: PathBuf,
}

impl Paths {
    /// Resolves the vault (`flag`, else `PWV_VAULT`, else
    /// `$XDG_DATA_HOME/pwv/vault.pwv`, else `~/.local/share/pwv/vault.pwv`)
    /// and the state file (`$XDG_STATE_HOME/pwv/state`, else
    /// `~/.local/state/pwv/state`). `env` reads an environment variable.
    /// Relative or empty XDG values and `HOME` are ignored.
    ///
    /// # Errors
    /// [`Error::Path`] for an empty override or no usable base directory.
    pub fn resolve(
        flag: Option<&OsStr>,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Paths, Error> {
        let xdg = |var: &str, fallback: &str| -> Result<PathBuf, Error> {
            let abs = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
            let base = abs(env(var)).or_else(|| abs(env("HOME")).map(|h| h.join(fallback)));
            Ok(base.ok_or(Error::Path)?.join("pwv"))
        };
        let vault = match flag.map(OsStr::to_owned).or_else(|| env("PWV_VAULT")) {
            Some(v) if v.is_empty() => return Err(Error::Path),
            Some(v) => PathBuf::from(v),
            None => xdg("XDG_DATA_HOME", ".local/share")?.join("vault.pwv"),
        };
        let state = xdg("XDG_STATE_HOME", ".local/state")?.join("state");
        Ok(Paths { vault, state })
    }
}

/// Result of the rollback check (Section 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Generation at least the recorded one, or an unknown vault.
    Fresh,
    /// The file's generation is below the one recorded on this machine.
    RolledBack {
        /// `g_f`, the file's generation.
        file: u64,
        /// `g_s`, the recorded generation.
        recorded: u64,
    },
}

/// Test-only fault hook (T-STORE-2): called at each step of the save
/// protocol; it may panic to simulate a crash, or return `true` to make
/// the next operation fail as unsupported.
#[cfg(test)]
type Hook = std::cell::RefCell<Box<dyn FnMut(&'static str) -> bool>>;

/// An open vault: the directory fd and the session's `flock` (held until
/// drop). Not `Clone`.
pub struct Store {
    paths: Paths,
    dir: OwnedFd,
    name: OsString,
    euid: u32,
    foreign: bool,
    _lock: OwnedFd,
    #[cfg(test)]
    hook: Option<Hook>,
}

/// Directory and file name of `p`.
fn split(p: &Path) -> Result<(PathBuf, OsString), Error> {
    let name = p.file_name().ok_or(Error::Path)?.to_owned();
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    Ok((dir.unwrap_or(Path::new(".")).to_owned(), name))
}

fn named(parts: &[&[u8]]) -> OsString {
    OsStr::from_bytes(&parts.concat()).to_owned()
}

/// Section 8.2 steps 1–2 for one object: type, owner, no group or other bits.
fn check(
    info: Result<FileInfo, Errno>,
    dir: bool,
    euid: u32,
    path: &Path,
) -> Result<FileInfo, Error> {
    let i = info.map_err(found)?;
    if (dir && !i.is_dir) || (!dir && !i.is_file) {
        return Err(Error::Kind);
    }
    if i.uid != euid {
        return Err(Error::Owner);
    }
    if i.perm & 0o077 != 0 {
        let quoted = path.to_string_lossy().replace('\'', "'\\''");
        let m = if dir { 700 } else { 600 };
        return Err(Error::Mode(format!(
            "permissions too open; run: chmod {m} '{quoted}'"
        )));
    }
    Ok(i)
}

/// Opens and checks the directory of `path`, creating it (mode 0700) first
/// if `create`. The filesystem is checked first: on a foreign filesystem
/// owner and mode are synthetic, so their errors would mislead. Returns
/// the fd, the directory path, and the file name.
fn open_parent(
    path: &Path,
    euid: u32,
    create: bool,
    foreign: bool,
) -> Result<(OwnedFd, PathBuf, OsString), Error> {
    let (dir_path, name) = split(path)?;
    if create {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir_path)?;
    }
    let dir = sys::open_dir(&dir_path).map_err(found)?;
    if !foreign && is_foreign_fs(sys::fs_magic(dir.as_fd())?) {
        return Err(Error::ForeignFs);
    }
    check(sys::info(dir.as_fd()), true, euid, &dir_path)?;
    Ok((dir, dir_path, name))
}

/// Takes the exclusive `flock` on `name` in `dir` (created 0600 if missing).
fn take_lock(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    euid: u32,
    path: &Path,
    wait: bool,
) -> Result<OwnedFd, Error> {
    let lock = sys::open_at(dir, name, OpenMode::Lock).map_err(found)?;
    check(sys::info(lock.as_fd()), false, euid, path)?;
    sys::lock(lock.as_fd(), wait).map_err(|e| {
        if e == Errno::WOULDBLOCK {
            Error::InUse
        } else {
            Error::Io
        }
    })?;
    Ok(lock)
}

/// Removes leftovers `.<name>.tmp.<16 lowercase hex>` of an interrupted
/// write (hygiene only: they hold ciphertext or public state).
fn remove_stale(dir: BorrowedFd<'_>, name: &OsStr) -> Result<(), Error> {
    let prefix = named(&[b".", name.as_bytes(), b".tmp."]);
    for n in sys::list_dir(dir)? {
        let rest = n
            .as_bytes()
            .strip_prefix(prefix.as_bytes())
            .unwrap_or_default();
        if rest.len() == 16 && rest.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            let _ = sys::unlink_at(dir, &n);
        }
    }
    Ok(())
}

/// Fills `buf` from `f`, which must then be at its end.
fn fill_exact(f: &mut File, buf: &mut [u8]) -> Result<(), Error> {
    f.read_exact(buf)?;
    if f.read(&mut [0u8; 1])? != 0 {
        return Err(format::Error::FileLength.into());
    }
    Ok(())
}

/// Parses the state file: lines `<32 lowercase hex> <decimal>\n`, IDs unique.
fn parse_state(text: &[u8]) -> Option<Vec<([u8; 16], u64)>> {
    let mut rows: Vec<([u8; 16], u64)> = Vec::new();
    for line in std::str::from_utf8(text).ok()?.split_inclusive('\n') {
        let (id, g) = line.strip_suffix('\n')?.split_once(' ')?;
        let all = |s: &str, f: fn(&u8) -> bool| !s.is_empty() && s.bytes().all(|c| f(&c));
        if id.len() != 32
            || !all(id, |c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            || !all(g, u8::is_ascii_digit)
        {
            return None;
        }
        let id = u128::from_str_radix(id, 16).ok()?.to_be_bytes();
        if rows.iter().any(|r| r.0 == id) {
            return None;
        }
        rows.push((id, g.parse().ok()?));
    }
    Some(rows)
}

impl Store {
    /// Opens the vault (Section 8.2): checks the directory and the vault
    /// (owner, type, mode, filesystem), takes the session lock, removes
    /// stale temporary files, and reads the file, checking the header's
    /// length against the file size before allocating. Never creates
    /// anything if the vault is missing.
    ///
    /// # Errors
    /// Any [`Error`]; [`Error::InUse`] if another session holds the lock.
    pub fn open(paths: Paths, allow_foreign_fs: bool) -> Result<(Store, Vec<u8>), Error> {
        Self::open_as(paths, allow_foreign_fs, sys::euid())
    }

    fn open_as(paths: Paths, foreign: bool, euid: u32) -> Result<(Store, Vec<u8>), Error> {
        let st = Self::attach(paths, foreign, euid, false)?;
        let fd = sys::open_at(st.dir.as_fd(), &st.name, OpenMode::Read).map_err(found)?;
        let info = check(sys::info(fd.as_fd()), false, euid, &st.paths.vault)?;
        let size = usize::try_from(info.size).map_err(|_| format::Error::FileLength)?;
        if size < HEADER_LEN {
            return Err(format::Error::HeaderLength.into());
        }
        let mut f = File::from(fd);
        let mut head = [0u8; HEADER_LEN];
        f.read_exact(&mut head)?;
        let len = format::parse_header(&head)?.file_len();
        if len != size {
            return Err(format::Error::FileLength.into());
        }
        let mut file = vec![0; len];
        let (h, rest) = file.split_at_mut_checked(HEADER_LEN).ok_or(Error::Io)?;
        h.copy_from_slice(&head);
        fill_exact(&mut f, rest)?;
        Ok((st, file))
    }

    /// Prepares a new vault for `init`: creates the directory (0700) if
    /// needed, checks it, takes the lock, and refuses if a vault exists.
    /// The first [`Store::save`] writes the file.
    ///
    /// # Errors
    /// Any [`Error`]; [`Error::Exists`] if a vault exists.
    pub fn create(paths: Paths, allow_foreign_fs: bool) -> Result<Store, Error> {
        Self::attach(paths, allow_foreign_fs, sys::euid(), true)
    }

    fn attach(paths: Paths, foreign: bool, euid: u32, create: bool) -> Result<Store, Error> {
        let (dir, dir_path, name) = open_parent(&paths.vault, euid, create, foreign)?;
        if !create {
            check(sys::info_at(dir.as_fd(), &name), false, euid, &paths.vault)?;
        }
        let lock_name = named(&[name.as_bytes(), b".lock"]);
        let lock = take_lock(
            dir.as_fd(),
            &lock_name,
            euid,
            &dir_path.join(&lock_name),
            false,
        )?;
        if create && sys::info_at(dir.as_fd(), &name) != Err(Errno::NOENT) {
            return Err(Error::Exists);
        }
        remove_stale(dir.as_fd(), &name)?;
        Ok(Store {
            paths,
            dir,
            name,
            euid,
            foreign,
            _lock: lock,
            #[cfg(test)]
            hook: None,
        })
    }

    /// Fault-injection point (T-STORE-2); `true` means "fail as unsupported".
    #[allow(clippy::unused_self, reason = "uses `self.hook` in test builds")]
    fn step(&self, point: &'static str) -> bool {
        #[cfg(test)]
        if let Some(h) = &self.hook {
            return (h.borrow_mut())(point);
        }
        let _ = point;
        false
    }

    fn backup(&self, i: u8) -> OsString {
        named(&[self.name.as_bytes(), b".", &[b'0' + i]])
    }

    /// Saves `file` (Section 8.3): rotates the backups, links the current
    /// vault to `.1` (copy if hard links are unsupported), writes a
    /// temporary file, `fsync`s, renames it over the vault, `fsync`s the
    /// directory, then records the generation in the state file. Returns
    /// only when all of that is durable. Refuses a malformed file.
    ///
    /// # Errors
    /// [`Error::Format`] (nothing written); otherwise any I/O [`Error`].
    pub fn save(&mut self, file: &[u8]) -> Result<(), Error> {
        let (h, _, _) = format::split_file(file)?;
        let dir = self.dir.as_fd();
        for i in (1..BACKUPS).rev() {
            self.step("rotate");
            // rename(2) does nothing when both names link one inode, which
            // repeated crashes after the link below leave behind; the
            // older name is then a duplicate and must go, or `link` fails.
            match sys::rename_at(dir, &self.backup(i), &self.backup(i + 1))
                .and_then(|()| sys::unlink_at(dir, &self.backup(i)))
            {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let linked = if self.step("link") {
            Err(Errno::PERM)
        } else {
            sys::link_at(dir, &self.name, &self.backup(1))
        };
        match linked {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(Errno::PERM | Errno::OPNOTSUPP | Errno::NOSYS) => {
                let fd = sys::open_at(dir, &self.name, OpenMode::Read).map_err(found)?;
                let size = check(sys::info(fd.as_fd()), false, self.euid, &self.paths.vault)?.size;
                let mut old = vec![
                    0;
                    usize::try_from(size)
                        .unwrap_or(usize::MAX)
                        .min(format::MAX_FILE)
                ];
                fill_exact(&mut File::from(fd), &mut old)?;
                self.write_atomic(dir, &self.name, &self.backup(1), &old)?;
            }
            Err(e) => return Err(e.into()),
        }
        self.write_atomic(dir, &self.name, &self.name, file)?;
        self.record(&h)
    }

    /// Writes `bytes` to `name` in `dir` atomically: temporary file
    /// `.<base>.tmp.<16 hex>` (removed at the next open if left over),
    /// `fsync`, rename, `fsync` of the directory (Section 8.3 steps 3–5).
    fn write_atomic(
        &self,
        dir: BorrowedFd<'_>,
        base: &OsStr,
        name: &OsStr,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let mut rnd = [0u8; 8];
        crypto::fill_random(&mut rnd).map_err(|_| Error::Io)?;
        let suffix = format!(".tmp.{:016x}", u64::from_ne_bytes(rnd));
        let tmp = named(&[b".", base.as_bytes(), suffix.as_bytes()]);
        self.step("create temp");
        let mut f = File::from(sys::open_at(dir, &tmp, OpenMode::CreateNew)?);
        let (a, b) = bytes.split_at(bytes.len() / 2);
        let res = f.write_all(a).and_then(|()| {
            self.step("partial write");
            f.write_all(b)?;
            self.step("fsync temp");
            f.sync_all()
        });
        let res = res.map_err(Error::from).and_then(|()| {
            self.step("rename");
            Ok(sys::rename_at(dir, &tmp, name)?)
        });
        if res.is_err() {
            let _ = sys::unlink_at(dir, &tmp);
        }
        res?;
        self.step("fsync dir");
        sys::fsync(dir)?;
        self.step("done");
        Ok(())
    }

    /// Opens the state directory (created 0700 if `create`), or `None` if
    /// it does not exist.
    fn state_dir(&self, create: bool) -> Result<Option<(OwnedFd, PathBuf, OsString)>, Error> {
        match open_parent(&self.paths.state, self.euid, create, self.foreign) {
            Err(Error::NoVault) => Ok(None),
            r => r.map(Some),
        }
    }

    fn read_state(&self, dir: BorrowedFd<'_>, name: &OsStr) -> Result<Vec<([u8; 16], u64)>, Error> {
        let fd = match sys::open_at(dir, name, OpenMode::Read) {
            Err(Errno::NOENT) => return Ok(Vec::new()),
            r => r.map_err(found)?,
        };
        if check(sys::info(fd.as_fd()), false, self.euid, &self.paths.state)?.size > STATE_MAX {
            return Err(Error::State);
        }
        let mut text = Vec::new();
        File::from(fd).take(STATE_MAX).read_to_end(&mut text)?;
        parse_state(&text).ok_or(Error::State)
    }

    /// Rollback check (Section 8.4) of an authenticated header against the
    /// generation recorded for its vault ID.
    ///
    /// # Errors
    /// [`Error::State`] if the state file is malformed; any check failure
    /// of the state directory or file.
    pub fn freshness(&self, h: &Header) -> Result<Freshness, Error> {
        let Some((dir, _, name)) = self.state_dir(false)? else {
            return Ok(Freshness::Fresh);
        };
        let rows = self.read_state(dir.as_fd(), &name)?;
        Ok(match rows.iter().find(|r| r.0 == h.vault_id) {
            Some(&(_, recorded)) if h.generation < recorded => Freshness::RolledBack {
                file: h.generation,
                recorded,
            },
            _ => Freshness::Fresh,
        })
    }

    /// Records `h`'s generation for its vault (Section 8.3 step 6), never
    /// lowering a recorded value, under the state directory's own lock.
    fn record(&self, h: &Header) -> Result<(), Error> {
        let (dir, dir_path, name) = self.state_dir(true)?.ok_or(Error::Io)?;
        let lock_name = named(&[name.as_bytes(), b".lock"]);
        let _lock = take_lock(
            dir.as_fd(),
            &lock_name,
            self.euid,
            &dir_path.join(&lock_name),
            true,
        )?;
        remove_stale(dir.as_fd(), &name)?;
        let mut rows = self.read_state(dir.as_fd(), &name)?;
        match rows.iter_mut().find(|r| r.0 == h.vault_id) {
            Some(r) => r.1 = r.1.max(h.generation),
            None => rows.push((h.vault_id, h.generation)),
        }
        let text = rows.iter().fold(String::new(), |mut t, (id, g)| {
            let _ = writeln!(t, "{:032x} {g}", u128::from_be_bytes(*id));
            t
        });
        self.write_atomic(dir.as_fd(), &name, &name, text.as_bytes())
    }
}

/// T-STORE-2 (fault injection at every step of Section 8.3), the
/// wrong-owner part of T-STORE-1 (test-only UID override), and the copy
/// fallback for backups. The store never decrypts, so these tests check
/// byte identity of whole files, which implies the same model.
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    const WRITE: [&str; 6] = [
        "create temp",
        "partial write",
        "fsync temp",
        "rename",
        "fsync dir",
        "done",
    ];

    fn paths(tmp: &Path) -> Paths {
        Paths {
            vault: tmp.join("v/vault.pwv"),
            state: tmp.join("s/pwv/state"),
        }
    }

    /// A well-formed file of generation `g` whose payload identifies `g`.
    fn file(g: u64) -> Vec<u8> {
        let h = Header {
            vault_id: [7; 16],
            kdf_m_kib: 65_536,
            kdf_t: 3,
            salt: [1; 32],
            wrap_nonce: [2; 24],
            wrapped_dek: [3; 48],
            generation: g,
            payload_nonce: [4; 24],
            payload_len: 4096,
        };
        let mut f = h.encode().to_vec();
        f.resize(h.file_len(), u8::try_from(g % 251).unwrap());
        f
    }

    fn setup(p: &Paths, n: u64) {
        let mut st = Store::create(p.clone(), false).unwrap();
        for g in 1..=n {
            st.save(&file(g)).unwrap();
        }
    }

    fn hooked(mut st: Store, f: impl FnMut(&'static str) -> bool + 'static) -> Store {
        st.hook = Some(RefCell::new(Box::new(f)));
        st
    }

    fn recorded(p: &Paths) -> u64 {
        let rows = parse_state(&fs::read(&p.state).unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        rows[0].1
    }

    fn names(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    /// The fault points of one save, in order.
    fn expected(fail_link: bool) -> Vec<&'static str> {
        let mut v = vec!["rotate"; 4];
        v.push("link");
        if fail_link {
            v.extend(WRITE); // copy of the vault to `.1`
        }
        v.extend(WRITE); // the vault
        v.extend(WRITE); // the state file
        v
    }

    #[test]
    fn t_store_2_crash_at_every_step() {
        for (prior, fail_link) in [(1, false), (2, false), (7, false), (2, true), (7, true)] {
            // Dry run: record the fault points.
            let tmp = tempfile::tempdir().unwrap();
            let p = paths(tmp.path());
            setup(&p, prior);
            let seen = Rc::new(RefCell::new(Vec::new()));
            let log = Rc::clone(&seen);
            let (st, _) = Store::open(p.clone(), false).unwrap();
            let mut st = hooked(st, move |pt| {
                log.borrow_mut().push(pt);
                fail_link && pt == "link"
            });
            st.save(&file(prior + 1)).unwrap();
            let points = seen.borrow().clone();
            assert_eq!(points, expected(fail_link));
            let base = if fail_link { 5 + WRITE.len() } else { 5 };
            let vault_rename = base + 3;
            let state_rename = base + WRITE.len() + 3;

            for (k, point) in points.iter().enumerate() {
                let ctx = format!("prior {prior}, fail_link {fail_link}, crash at #{k} ({point})");
                let tmp = tempfile::tempdir().unwrap();
                let p = paths(tmp.path());
                setup(&p, prior);
                let vdir = p.vault.parent().unwrap();
                // The same crash repeated more times than there are backups:
                // a crash after step 2's link leaves `.1` linked to the
                // vault, and repeats make every backup a link to it.
                let (mut st, _) = Store::open(p.clone(), false).unwrap();
                for _ in 0..=BACKUPS {
                    let mut n = 0;
                    let mut hk = hooked(st, move |pt| {
                        assert!(n != k, "injected crash at {pt}");
                        n += 1;
                        fail_link && pt == "link"
                    });
                    let crashed = catch_unwind(AssertUnwindSafe(move || hk.save(&file(prior + 1))));
                    assert!(crashed.is_err(), "{ctx}: no crash: {:?}", crashed.ok());

                    // Restart: open never fails and yields exactly old or new.
                    let got;
                    (st, got) =
                        Store::open(p.clone(), false).unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
                    let new = k > vault_rename;
                    assert_eq!(got, file(if new { prior + 1 } else { prior }), "{ctx}");
                    let h = format::parse_header(&got).unwrap();
                    assert_eq!(st.freshness(&h).unwrap(), Freshness::Fresh, "{ctx}");
                    let want = if k > state_rename { prior + 1 } else { prior };
                    assert_eq!(recorded(&p), want, "{ctx}");
                    assert!(
                        names(vdir).iter().all(|n| !n.contains(".tmp.")),
                        "{ctx}: {:?}",
                        names(vdir)
                    );
                    for i in 1..=BACKUPS {
                        if let Ok(b) = fs::read(vdir.join(format!("vault.pwv.{i}"))) {
                            assert!((1..=prior + 1).any(|g| b == file(g)), "{ctx}: backup .{i}");
                        }
                    }
                }
                // Recovery: the next saves complete normally, through a
                // whole cycle of the backups (a crash after step 2's link
                // leaves `.1` linked to the vault; it must not break a
                // later rotation).
                let last = prior + 2 + u64::from(BACKUPS);
                for g in prior + 2..=last {
                    st.save(&file(g))
                        .unwrap_or_else(|e| panic!("{ctx}: recovery save {g}: {e:?}"));
                }
                drop(st);
                let (st, got) = Store::open(p.clone(), false).unwrap();
                assert_eq!(got, file(last), "{ctx}");
                assert_eq!(recorded(&p), last, "{ctx}");
                assert_eq!(fs::metadata(&p.vault).unwrap().nlink(), 1, "{ctx}");
                for i in 1..=BACKUPS {
                    let b = vdir.join(format!("vault.pwv.{i}"));
                    assert_eq!(fs::read(&b).unwrap(), file(last - u64::from(i)), "{ctx}");
                    assert_eq!(fs::metadata(&b).unwrap().nlink(), 1, "{ctx}: .{i}");
                }
                let h = format::parse_header(&got).unwrap();
                assert_eq!(st.freshness(&h).unwrap(), Freshness::Fresh, "{ctx}");
                let sdir = p.state.parent().unwrap();
                assert!(
                    names(sdir).iter().all(|n| !n.contains(".tmp.")),
                    "{ctx}: {:?}",
                    names(sdir)
                );
            }
        }
    }

    #[test]
    fn t_store_7_copy_fallback_without_hard_links() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        setup(&p, 1);
        let (st, _) = Store::open(p.clone(), false).unwrap();
        let mut st = hooked(st, |pt| pt == "link");
        for g in 2..=7 {
            st.save(&file(g)).unwrap();
        }
        drop(st);
        let vdir = p.vault.parent().unwrap();
        assert_eq!(fs::read(&p.vault).unwrap(), file(7));
        assert_eq!(fs::metadata(&p.vault).unwrap().nlink(), 1);
        for i in 1..=BACKUPS {
            let b = vdir.join(format!("vault.pwv.{i}"));
            assert_eq!(fs::read(&b).unwrap(), file(7 - u64::from(i)), ".{i}");
            assert_eq!(
                fs::metadata(&b).unwrap().nlink(),
                1,
                ".{i}: a copy, not a link"
            );
        }
        let mut n = names(vdir);
        n.sort();
        assert_eq!(n.len(), 7, "{n:?}");
    }

    #[test]
    fn t_store_1_wrong_owner_via_uid_override() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(tmp.path());
        setup(&p, 1);
        let me = sys::euid();
        assert!(Store::open_as(p.clone(), false, me).is_ok());
        let e = Store::open_as(p.clone(), false, me.wrapping_add(1)).err();
        assert_eq!(e, Some(Error::Owner));
        // Each object, and the order of the checks: type, owner, mode.
        let path = Path::new("/x/it's");
        for dir in [true, false] {
            let ok = FileInfo {
                is_dir: dir,
                is_file: !dir,
                uid: me,
                perm: if dir { 0o700 } else { 0o600 },
                size: 0,
            };
            assert_eq!(check(Ok(ok), dir, me, path), Ok(ok));
            let other = FileInfo {
                uid: me.wrapping_add(1),
                ..ok
            };
            assert_eq!(check(Ok(other), dir, me, path), Err(Error::Owner));
            let open = FileInfo {
                perm: ok.perm | 0o044,
                ..other
            };
            assert_eq!(check(Ok(open), dir, me, path), Err(Error::Owner));
            let wrong = FileInfo {
                is_dir: !dir,
                is_file: dir,
                ..open
            };
            assert_eq!(check(Ok(wrong), dir, me, path), Err(Error::Kind));
            let m = if dir { "700" } else { "600" };
            let msg = format!("permissions too open; run: chmod {m} '/x/it'\\''s'");
            assert_eq!(
                check(
                    Ok(FileInfo {
                        perm: ok.perm | 0o001,
                        ..ok
                    }),
                    dir,
                    me,
                    path
                ),
                Err(Error::Mode(msg))
            );
        }
        assert_eq!(
            check(Err(Errno::NOENT), true, me, path),
            Err(Error::NoVault)
        );
        assert_eq!(check(Err(Errno::LOOP), false, me, path), Err(Error::Kind));
        assert_eq!(check(Err(Errno::IO), false, me, path), Err(Error::Io));
    }
}
