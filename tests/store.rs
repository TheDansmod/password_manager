//! M4 gate: T-STORE-1, T-STORE-3 – T-STORE-7, T-STORE-9 (spec Sections 8
//! and 14.5), plus path resolution (E2) and "open never creates" (B1).
//! T-STORE-2 needs the `#[cfg(test)]` fault hook, so it is a unit test in
//! `src/store.rs`.
//!
//! Vaults live under the system temporary directory (`tempfile`), never in
//! the source tree, whose filesystem may itself be foreign. The data
//! directory name contains a space and a single quote, so every `chmod`
//! remedy is executed by `sh` to prove its quoting is exact.

mod common;

use common::child_command;
use common::vaults::{self, Model, arena, floor_params, put, read_body, write_body};
use pwv::cli;
use pwv::crypto;
use pwv::format::Header;
use pwv::secmem::SecretSlot;
use pwv::store::{self, Error, Freshness, Paths, Store};
use pwv::vault;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{PoisonError, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

const PW: &str = "correct horse battery staple";

// ------------------------------------------------- fork/flock isolation

/// Serialises child-process spawns (write) against opens and creates whose
/// outcome a test asserts (read). Between `fork` and `exec` a child holds
/// a copy of every fd of this multi-threaded test process, including
/// another test's lock fd, so a just-closed session's `flock` can look held
/// until the child drops its copy. `Command::spawn` does not wait for that:
/// it returns once `exec` has replaced the child's memory, before the
/// kernel runs close-on-exec (DESIGN_NOTES, M5: `open: InUse` in 3 of 12
/// parallel local runs). [`SpawnLocked`] therefore has the child
/// close its copies itself and report back before the write lock is
/// released. The `pwv` binary never forks (Section 5.7), so this is a
/// property of the test harness only.
static FORK: RwLock<()> = RwLock::new(());

fn open(paths: Paths, foreign: bool) -> Result<(Store, Vec<u8>), Error> {
    let _g = FORK.read().unwrap_or_else(PoisonError::into_inner);
    Store::open(paths, foreign)
}

fn create(paths: Paths, foreign: bool) -> Result<Store, Error> {
    let _g = FORK.read().unwrap_or_else(PoisonError::into_inner);
    Store::create(paths, foreign)
}

trait SpawnLocked {
    /// Spawns under the write lock and returns only once the child holds
    /// no copy of this process's file descriptors that name a file (lock
    /// files included).
    fn spawn_locked(&mut self) -> std::io::Result<std::process::Child>;
}

impl SpawnLocked for std::process::Command {
    fn spawn_locked(&mut self) -> std::io::Result<std::process::Child> {
        let _g = FORK.write().unwrap_or_else(PoisonError::into_inner);
        let (mut done, tx) = std::io::pipe()?;
        let signal = tx.as_raw_fd();
        // Every lock fd exists by now: opens wait for the write lock.
        let max = highest_fd();
        // SAFETY: the hook runs in the forked child before `exec` and only
        // makes async-signal-safe calls (`fstat`, `close`, `write`) on plain
        // integers and a stack buffer. It closes the regular files and
        // directories, which `exec` would close anyway (every fd of this
        // process is close-on-exec); pipes (`signal`, those of `Command`)
        // and devices are kept.
        unsafe {
            self.pre_exec(move || {
                for fd in 3..=max {
                    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
                    if libc::fstat(fd, st.as_mut_ptr()) == 0 {
                        let kind = st.assume_init().st_mode & libc::S_IFMT;
                        if kind == libc::S_IFREG || kind == libc::S_IFDIR {
                            libc::close(fd);
                        }
                    }
                }
                // The `close` calls have returned, so the kernel has dropped
                // this child's references (and any `flock` they kept alive).
                match libc::write(signal, [1u8].as_ptr().cast(), 1) {
                    1 => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                }
            });
        }
        let child = self.spawn()?;
        done.read_exact(&mut [0u8])?;
        Ok(child)
    }
}

/// The highest fd number open in this process.
fn highest_fd() -> i32 {
    let names = fs::read_dir("/proc/self/fd").unwrap().map(|e| e.unwrap());
    let fds = names.filter_map(|e| e.file_name().to_str()?.parse().ok());
    fds.max().unwrap_or(2)
}

/// Runs `cmd` to completion with spawns serialised (see [`FORK`]).
fn output(cmd: &mut std::process::Command) -> std::process::Output {
    let _g = FORK.write().unwrap_or_else(PoisonError::into_inner);
    cmd.output().unwrap()
}

// ------------------------------------------------------------- fixtures

/// A vault location in a fresh temporary directory.
struct Fx {
    tmp: tempfile::TempDir,
    paths: Paths,
}

fn fx() -> Fx {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = Paths {
        vault: tmp.path().join("my data's/pwv/vault.pwv"),
        state: tmp.path().join("state/pwv/state"),
    };
    Fx { tmp, paths }
}

impl Fx {
    fn dir(&self) -> &Path {
        self.paths.vault.parent().unwrap()
    }
    fn at(&self, name: &str) -> PathBuf {
        self.dir().join(name)
    }
    fn names(&self) -> Vec<String> {
        list(self.dir())
    }
}

fn list(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

fn chmod(p: &Path, m: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The model saved at generation `g`: the sample model plus an entry that
/// records `g`, so a file's content can be checked against its header.
fn model(g: u64) -> Model {
    let mut m = vaults::sample_model();
    m.push((
        "generation".into(),
        vec![("value".into(), false, g.to_string())],
    ));
    m.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    m
}

/// Writes `model(generation + 1)` into `body`, encrypts, and saves through
/// the store. Returns the file written.
fn save_next(st: &mut Store, h: &mut Header, dek: &[u8], body: &mut SecretSlot<'_>) -> Vec<u8> {
    write_body(&model(h.generation + 1), body);
    let file = vault::save(dek, h, body.expose_mut()).expect("vault save");
    st.save(&file).expect("store save");
    file
}

/// Creates a vault and saves it `saves` times (generation g holds
/// `model(g)`). Returns the KEK, for fast verification, and every file
/// written, in order.
fn create_vault(paths: &Paths, saves: u64) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let params = floor_params();
    let (mut h, _) = vault::init(s.pw2.expose(), params, &mut s.kek, &mut s.dek, false).unwrap();
    crypto::derive_kek(s.pw2.expose(), &h.salt, params, &mut s.kek, false).unwrap();
    let kek = s.kek.expose().to_vec();
    let mut st = create(paths.clone(), false).expect("create");
    let files = (0..saves)
        .map(|_| save_next(&mut st, &mut h, s.dek.expose(), &mut s.vault_a))
        .collect();
    (kek, files)
}

/// Decrypts `file` with the cached KEK.
fn open_model(file: &[u8], kek: &[u8]) -> (Header, Model) {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let h = vault::open_with_kek(file, kek, &mut s.dek, &mut s.vault_a).expect("decrypts");
    (h, read_body(s.vault_a.expose()))
}

/// Opens the vault, decrypts it, and returns the store and header with
/// the DEK and body in a fresh arena handed to `f`.
fn with_session<T>(
    paths: &Paths,
    kek: &[u8],
    f: impl FnOnce(&mut Store, &mut Header, &[u8], &mut SecretSlot<'_>) -> T,
) -> T {
    let (mut st, file) = open(paths.clone(), false).expect("open");
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut h = vault::open_with_kek(&file, kek, &mut s.dek, &mut s.vault_a).expect("unlock");
    f(&mut st, &mut h, s.dek.expose(), &mut s.vault_a)
}

fn refused(paths: &Paths) -> Error {
    open(paths.clone(), false).err().expect("open refused")
}

/// Runs the `chmod` remedy of a mode error through `sh`, exactly as the
/// user would paste it.
fn run_remedy(e: &Error) {
    let msg = e.message();
    let cmd = &msg[msg.find("chmod ").expect("remedy names chmod")..];
    let out = output(&mut common::shell_command(cmd));
    assert!(out.status.success(), "remedy failed: {cmd}");
}

/// Deterministic test RNG (splitmix64).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Writes `\nPWV <msg>\n` to fd 1 (libtest may print on the same line).
fn report(msg: &str) {
    let line = format!("\nPWV {msg}\n");
    let mut b = line.as_bytes();
    while !b.is_empty() {
        let n = rustix::io::write(rustix::stdio::stdout(), b).expect("report");
        b = &b[n..];
    }
}

/// Reads a child's stdout to the end on a thread; the receiver fires once
/// `PWV ready` has been seen. The thread returns everything read.
fn watch(mut out: impl Read + Send + 'static) -> (mpsc::Receiver<()>, thread::JoinHandle<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let h = thread::spawn(move || {
        let (mut all, mut buf, mut sent) = (Vec::new(), [0u8; 4096], false);
        while let Ok(n @ 1..) = out.read(&mut buf) {
            all.extend_from_slice(&buf[..n]);
            if !sent && all.windows(11).any(|w| w == b"\nPWV ready\n") {
                sent = tx.send(()).is_ok();
            }
        }
        all
    });
    (rx, h)
}

/// The generations in complete `PWV gen <n>` lines.
fn reported(out: &[u8]) -> Vec<u64> {
    String::from_utf8_lossy(out)
        .split_inclusive('\n')
        .filter_map(|l| l.strip_prefix("PWV gen ")?.strip_suffix('\n')?.parse().ok())
        .collect()
}

fn child_env(f: &Fx) -> Vec<(String, String)> {
    vec![
        ("PWV_T_VAULT".into(), f.paths.vault.display().to_string()),
        ("PWV_T_STATE".into(), f.paths.state.display().to_string()),
    ]
}

fn child_paths() -> Option<Paths> {
    Some(Paths {
        vault: std::env::var_os("PWV_T_VAULT")?.into(),
        state: std::env::var_os("PWV_T_STATE")?.into(),
    })
}

fn spawn_child(test: &str, env: &[(String, String)]) -> std::process::Command {
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    child_command(test, &env)
}

// ------------------------------------------------------ paths (E2, 8.1)

fn env_of<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
    move |k| {
        vars.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| OsString::from(v))
    }
}

#[test]
fn paths_xdg_defaults_and_overrides() {
    let p = Paths::resolve(None, &env_of(&[("HOME", "/home/u")])).unwrap();
    assert_eq!(p.vault, Path::new("/home/u/.local/share/pwv/vault.pwv"));
    assert_eq!(p.state, Path::new("/home/u/.local/state/pwv/state"));

    let xdg = [
        ("HOME", "/home/u"),
        ("XDG_DATA_HOME", "/d"),
        ("XDG_STATE_HOME", "/s"),
    ];
    let p = Paths::resolve(None, &env_of(&xdg)).unwrap();
    assert_eq!(p.vault, Path::new("/d/pwv/vault.pwv"));
    assert_eq!(p.state, Path::new("/s/pwv/state"));

    // Relative or empty XDG values are invalid and ignored (XDG Base
    // Directory specification).
    let bad = [
        ("HOME", "/home/u"),
        ("XDG_DATA_HOME", "rel/data"),
        ("XDG_STATE_HOME", ""),
    ];
    let p = Paths::resolve(None, &env_of(&bad)).unwrap();
    assert_eq!(p.vault, Path::new("/home/u/.local/share/pwv/vault.pwv"));
    assert_eq!(p.state, Path::new("/home/u/.local/state/pwv/state"));

    // PWV_VAULT overrides the default; --vault overrides both. The state
    // file stays in XDG_STATE_HOME.
    let env = [("HOME", "/home/u"), ("PWV_VAULT", "/v/env.pwv")];
    let p = Paths::resolve(None, &env_of(&env)).unwrap();
    assert_eq!(p.vault, Path::new("/v/env.pwv"));
    let flag = OsString::from("rel/flag.pwv");
    let p = Paths::resolve(Some(&flag), &env_of(&env)).unwrap();
    assert_eq!(p.vault, Path::new("rel/flag.pwv"));
    assert_eq!(p.state, Path::new("/home/u/.local/state/pwv/state"));

    // No usable base directory, or an empty override: refused, never a
    // guessed path.
    for vars in [
        &[][..],
        &[("HOME", "")][..],
        &[("HOME", "relative/home")][..],
    ] {
        let e = Paths::resolve(None, &env_of(vars)).unwrap_err();
        assert_eq!(e, Error::Path);
        assert_eq!(cli::store_exit_code(&e), cli::EXIT_ENV);
    }
    let empty = OsString::new();
    let home = [("HOME", "/home/u")];
    assert_eq!(
        Paths::resolve(Some(&empty), &env_of(&home)),
        Err(Error::Path)
    );
    let env = [("HOME", "/home/u"), ("PWV_VAULT", "")];
    assert_eq!(Paths::resolve(None, &env_of(&env)), Err(Error::Path));
}

// ------------------------------------------------------------ T-STORE-1

#[test]
fn t_store_1_modes() {
    let f = fx();
    create_vault(&f.paths, 1);
    let lock = f.at("vault.pwv.lock");
    assert_eq!(mode(f.dir()), 0o700);
    assert_eq!(mode(&f.paths.vault), 0o600);
    assert_eq!(mode(&lock), 0o600);
    drop(open(f.paths.clone(), false).expect("0700 / 0600 accepted"));

    let cases: [(&Path, u32, &str); 3] = [
        (f.dir(), 0o700, "700"),
        (&f.paths.vault, 0o600, "600"),
        (&lock, 0o600, "600"),
    ];
    for (path, ok, remedy) in cases {
        for bit in [0o040, 0o020, 0o010, 0o004, 0o002, 0o001] {
            chmod(path, ok | bit);
            let e = refused(&f.paths);
            let quoted = path.display().to_string().replace('\'', "'\\''");
            assert!(
                matches!(e, Error::Mode(_)),
                "{}: {bit:o}: {e:?}",
                path.display()
            );
            assert!(
                e.message().ends_with(&format!("chmod {remedy} '{quoted}'")),
                "{}",
                e.message()
            );
            assert_eq!(cli::store_exit_code(&e), cli::EXIT_ENV);
            run_remedy(&e);
            assert_eq!(mode(path), ok);
        }
    }
    drop(open(f.paths.clone(), false).expect("accepted after the remedies"));
}

#[test]
fn t_store_1_wrong_owner_root_directory() {
    // The unit tests in src/store.rs cover a wrong owner for the directory,
    // the vault, and the lock file through the test-only UID override. Here
    // the owner check is exercised against a real root-owned directory.
    assert_ne!(euid(), 0, "T-STORE-1 must run as a non-root user");
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths {
        vault: PathBuf::from("/pwv-t-store-1-no-such-vault.pwv"),
        state: tmp.path().join("state"),
    };
    let e = refused(&paths);
    assert_eq!(e, Error::Owner);
    assert_eq!(cli::store_exit_code(&e), cli::EXIT_ENV);
    let e = create(paths, false).err().expect("create refused");
    assert_eq!(e, Error::Owner);
}

#[test]
fn t_store_1_symlinks_and_file_types() {
    let f = fx();
    create_vault(&f.paths, 1);
    let kind = |paths: &Paths| {
        let e = refused(paths);
        assert_eq!(e, Error::Kind);
        assert_eq!(cli::store_exit_code(&e), cli::EXIT_ENV);
    };

    // Symlinked vault (relative and absolute targets).
    let real = f.at("real.pwv");
    fs::rename(&f.paths.vault, &real).unwrap();
    for target in [Path::new("real.pwv"), real.as_path()] {
        symlink(target, &f.paths.vault).unwrap();
        kind(&f.paths);
        fs::remove_file(&f.paths.vault).unwrap();
    }
    // The target itself is acceptable, so the refusal is about the link.
    let direct = Paths {
        vault: real.clone(),
        state: f.paths.state.clone(),
    };
    drop(open(direct, false).expect("real file opens"));
    fs::rename(&real, &f.paths.vault).unwrap();

    // Symlinked directory.
    let link = f.tmp.path().join("link");
    symlink(f.dir(), &link).unwrap();
    kind(&Paths {
        vault: link.join("vault.pwv"),
        state: f.paths.state.clone(),
    });

    // The vault is a directory; the vault is a FIFO (must not block).
    let other = |name: &str| Paths {
        vault: f.at(name),
        state: f.paths.state.clone(),
    };
    fs::create_dir(f.at("adir")).unwrap();
    chmod(&f.at("adir"), 0o700);
    kind(&other("adir"));
    rustix::fs::mknodat(
        rustix::fs::CWD,
        f.at("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let t0 = Instant::now();
    kind(&other("fifo"));
    assert!(t0.elapsed() < Duration::from_secs(5));

    // The "directory" is a regular file.
    kind(&Paths {
        vault: f.paths.vault.join("vault.pwv"),
        state: f.paths.state.clone(),
    });
    drop(open(f.paths.clone(), false).expect("still opens"));
}

#[test]
fn t_store_1_statfs_classifier() {
    let foreign: [(&str, u32); 6] = [
        (
            "fuseblk (ntfs-3g; all FUSE, so also WSL2 virtiofs)",
            0x6573_5546,
        ),
        ("ntfs3", 0x7366_746e),
        ("ntfs (legacy driver)", 0x5346_544e),
        ("vfat / msdos", 0x4d44),
        ("exfat", 0x2011_bab0),
        (
            "9p (WSL2 DrvFs; synthetic bits without `metadata`)",
            0x0102_1997,
        ),
    ];
    for (name, magic) in foreign {
        assert!(store::is_foreign_fs(magic), "{name} must be refused");
    }
    let native: [(&str, u32); 8] = [
        ("ext2/3/4", 0xEF53),
        ("btrfs", 0x9123_683E),
        ("xfs", 0x5846_5342),
        ("tmpfs", 0x0102_1994),
        ("f2fs", 0xF2F5_2010),
        ("zfs", 0x2FC1_2FC1),
        ("overlayfs", 0x794C_7630),
        ("bcachefs", 0xCA45_1A4E),
    ];
    for (name, magic) in native {
        assert!(!store::is_foreign_fs(magic), "{name} must be accepted");
    }
    assert_eq!(cli::store_exit_code(&Error::ForeignFs), cli::EXIT_ENV);
}

/// A real foreign filesystem, when `PWV_FOREIGN_DIR` names a writable
/// directory on one (CI mounts a vfat image; locally any FUSE mount).
/// Refused without the override; with it, the full save protocol runs,
/// including the copy fallback for backups where hard links are
/// unsupported. Without the variable this test only checks it is unset
/// on purpose (CI sets it in a dedicated step).
#[test]
fn t_store_1_foreign_fs_real_mount() {
    let Some(base) = std::env::var_os("PWV_FOREIGN_DIR") else {
        return;
    };
    let base = tempfile::tempdir_in(base).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths {
        vault: base.path().join("pwv/vault.pwv"),
        state: tmp.path().join("state/pwv/state"),
    };
    let e = create(paths.clone(), false).err().expect("refused");
    assert_eq!(e, Error::ForeignFs);
    assert_eq!(cli::store_exit_code(&e), cli::EXIT_ENV);

    // The override waives only the filesystem check: owner and mode are
    // still enforced, so it needs a mount that reports our UID and private
    // modes (CI: vfat with uid=, umask=077).
    let m = fs::metadata(base.path()).unwrap();
    assert!(
        m.uid() == euid() && m.mode() & 0o077 == 0,
        "PWV_FOREIGN_DIR must report our UID and mode 0700 (vfat: uid=,umask=077)"
    );
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let (mut h, _) = vault::init(
        s.pw2.expose(),
        floor_params(),
        &mut s.kek,
        &mut s.dek,
        false,
    )
    .unwrap();
    crypto::derive_kek(s.pw2.expose(), &h.salt, floor_params(), &mut s.kek, false).unwrap();
    let kek = s.kek.expose().to_vec();
    let mut st = create(paths.clone(), true).expect("override");
    let files: Vec<Vec<u8>> = (0..7)
        .map(|_| save_next(&mut st, &mut h, s.dek.expose(), &mut s.vault_a))
        .collect();
    drop(st);
    assert_eq!(refused(&paths), Error::ForeignFs);
    let (_st, file) = open(paths.clone(), true).expect("override");
    assert_eq!(file, files[6]);
    let dir = paths.vault.parent().unwrap();
    for i in 1..=5 {
        let b = fs::read(dir.join(format!("vault.pwv.{i}"))).unwrap();
        assert_eq!(b, files[6 - i]);
        assert_eq!(open_model(&b, &kek).1, model(7 - i as u64));
    }
}

// ------------------------------------------------------------ T-STORE-3

const KILL_ITERATIONS_MIN: usize = 500;

/// T-STORE-3 child: opens the vault named by the environment, then saves
/// forever, reporting each generation after `Store::save` has returned.
#[test]
fn store_3_child() {
    let (Some(paths), Ok(kek)) = (child_paths(), std::env::var("PWV_T_KEK")) else {
        return;
    };
    let kek = vaults::unhex(&kek);
    let (mut st, file) = open(paths, false).expect("child open");
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut h = vault::open_with_kek(&file, &kek, &mut s.dek, &mut s.vault_a).expect("unlock");
    assert_eq!(st.freshness(&h).unwrap(), Freshness::Fresh);
    report("ready");
    loop {
        save_next(&mut st, &mut h, s.dek.expose(), &mut s.vault_a);
        report(&format!("gen {}", h.generation));
    }
}

/// After a kill: the vault opens, decrypts to the model of its generation,
/// which is the last reported commit or one more (killed between rename
/// and report); it is fresh; every backup decrypts to its own generation's
/// model; no temporary file survives the open.
fn verify_after_kill(f: &Fx, kek: &[u8], committed: u64, ctx: &str) -> u64 {
    let (st, file) = open(f.paths.clone(), false)
        .unwrap_or_else(|e| panic!("{ctx}: open failed: {}", e.message()));
    let (h, m) = open_model(&file, kek);
    let g = h.generation;
    assert!(
        g == committed || g == committed + 1,
        "{ctx}: generation {g}, last commit {committed}"
    );
    assert_eq!(m, model(g), "{ctx}");
    assert_eq!(st.freshness(&h).unwrap(), Freshness::Fresh, "{ctx}");
    for i in 1..=5 {
        if let Ok(b) = fs::read(f.at(&format!("vault.pwv.{i}"))) {
            let (bh, bm) = open_model(&b, kek);
            assert!(bh.generation <= g, "{ctx}: backup .{i}");
            assert_eq!(bm, model(bh.generation), "{ctx}: backup .{i}");
        }
    }
    let names = f.names();
    assert!(
        names.iter().all(|n| !n.contains(".tmp.")),
        "{ctx}: {names:?}"
    );
    g
}

#[test]
fn t_store_3_kill_loop() {
    let iterations = std::env::var("PWV_T_STORE_3_ITERATIONS")
        .map_or(KILL_ITERATIONS_MIN, |v| v.parse().expect("iterations"));
    assert!(iterations >= KILL_ITERATIONS_MIN);
    let seed = std::env::var("PWV_T_STORE_3_SEED").map_or_else(
        |_| {
            let mut b = [0u8; 8];
            crypto::fill_random(&mut b).unwrap();
            u64::from_le_bytes(b)
        },
        |v| u64::from_str_radix(v.trim_start_matches("0x"), 16).expect("seed"),
    );
    let f = fx();
    let (kek, _) = create_vault(&f.paths, 1);
    let mut env = child_env(&f);
    env.push(("PWV_T_KEK".into(), vaults::hex(&kek)));
    let mut rng = Rng(seed);
    let (mut gen_now, mut none, mut some) = (1u64, 0usize, 0usize);
    // Kills between step 2's link and step 4's rename leave `.1` linked to
    // the vault; five in a row once made every later save fail (DESIGN_NOTES,
    // M4 CI round 1). Counted so the log shows that window was exercised.
    let (mut window, mut run, mut longest) = (0usize, 0usize, 0usize);
    for it in 0..iterations {
        let delay = Duration::from_micros(rng.next() % 50_001);
        let ctx = format!("iteration {it}, seed {seed:#x}, delay {delay:?}");
        let mut child = spawn_child("store_3_child", &env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_locked()
            .unwrap();
        let (ready, reader) = watch(child.stdout.take().unwrap());
        let (_, errs) = watch(child.stderr.take().unwrap());
        let stderr = |errs: thread::JoinHandle<Vec<u8>>| {
            String::from_utf8_lossy(&errs.join().unwrap()).into_owned()
        };
        if ready.recv_timeout(Duration::from_secs(120)).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{ctx}: child never became ready; stderr:\n{}", stderr(errs));
        }
        thread::sleep(delay);
        child.kill().unwrap();
        let status = child.wait().unwrap();
        let errs = stderr(errs);
        assert_eq!(
            status.signal(),
            Some(9),
            "{ctx}: child must die by SIGKILL; stderr:\n{errs}"
        );
        let gens = reported(&reader.join().unwrap());
        // Reports are consecutive generations starting after the last state.
        for (i, g) in gens.iter().enumerate() {
            assert_eq!(*g, gen_now + 1 + i as u64, "{ctx}: reports {gens:?}");
        }
        if gens.is_empty() {
            none += 1;
        } else {
            some += 1;
        }
        let committed = gens.last().copied().unwrap_or(gen_now);
        gen_now = verify_after_kill(&f, &kek, committed, &ctx);
        let ino = |n: &str| fs::metadata(f.at(n)).map(|m| m.ino()).ok();
        if ino("vault.pwv.1").is_some() && ino("vault.pwv.1") == ino("vault.pwv") {
            window += 1;
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    pwv::sys::write_stderr(
        format!(
            "T-STORE-3: seed {seed:#x}, {iterations} kills: {none} before the first \
             commit, {some} after commits; {window} between link and rename \
             (longest run {longest}); final generation {gen_now}\n"
        )
        .as_bytes(),
    );
    // Not vacuous: kills landed both before the first commit and after
    // commits (the remaining kills land inside saves).
    assert!(none > 0 && some > 0, "seed {seed:#x}: {none} / {some}");
    assert!(gen_now > iterations as u64 / 2, "seed {seed:#x}: {gen_now}");
}

// ------------------------------------------------------------ T-STORE-4

/// T-STORE-4 children. `hold`: opens the vault and keeps it open until
/// its stdin closes. `second`: tries to open it and exits with the CLI's
/// exit code for the error, writing the message to fd 2.
#[test]
fn store_4_child() {
    let (Some(paths), Ok(role)) = (child_paths(), std::env::var("PWV_T_ROLE")) else {
        return;
    };
    if role == "hold" {
        let opened = open(paths, false).expect("holder opens");
        report("ready");
        let mut b = [0u8; 1];
        while rustix::io::read(rustix::stdio::stdin(), &mut b) == Ok(1) {}
        drop(opened);
    } else {
        match open(paths, false) {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                pwv::sys::write_stderr(e.message().as_bytes());
                std::process::exit(cli::store_exit_code(&e));
            }
        }
    }
}

fn spawn_holder(f: &Fx) -> std::process::Child {
    let mut env = child_env(f);
    env.push(("PWV_T_ROLE".into(), "hold".into()));
    let mut c = spawn_child("store_4_child", &env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn_locked()
        .unwrap();
    let (ready, _reader) = watch(c.stdout.take().unwrap());
    ready
        .recv_timeout(Duration::from_secs(60))
        .expect("holder ready");
    c
}

#[test]
fn t_store_4_second_process_refused() {
    let f = fx();
    create_vault(&f.paths, 1);
    let mut holder = spawn_holder(&f);
    let mut env = child_env(&f);
    env.push(("PWV_T_ROLE".into(), "second".into()));
    for _ in 0..5 {
        let mut second = spawn_child("store_4_child", &env);
        second.stdout(Stdio::null()).stderr(Stdio::piped());
        let t0 = Instant::now();
        let out = output(&mut second);
        let took = t0.elapsed();
        let msg = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(cli::EXIT_ENV), "{msg}");
        assert!(msg.contains("in use"), "{msg}");
        assert!(msg.contains("open in another session"), "{msg}");
        assert!(
            took < Duration::from_millis(100),
            "second exited after {took:?}"
        );
    }
    // A second open in this process is refused too (flock is per open
    // file description), with the same error.
    assert_eq!(refused(&f.paths), Error::InUse);

    // Closing the session releases the lock.
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    drop(open(f.paths.clone(), false).expect("released"));

    // So does SIGKILL.
    let mut holder = spawn_holder(&f);
    assert_eq!(refused(&f.paths), Error::InUse);
    holder.kill().unwrap();
    holder.wait().unwrap();
    drop(open(f.paths.clone(), false).expect("released after kill"));
}

// ------------------------------------------------------------ T-STORE-5

#[test]
fn t_store_5_rollback_detected() {
    let f = fx();
    let (kek, files) = create_vault(&f.paths, 5);
    // `.2` holds generation 3. Restore it over the vault.
    fs::copy(f.at("vault.pwv.2"), &f.paths.vault).unwrap();
    let warned = with_session(&f.paths, &kek, |st, h, dek, body| {
        assert_eq!(h.generation, 3);
        let fr = st.freshness(h).unwrap();
        assert_eq!(
            fr,
            Freshness::RolledBack {
                file: 3,
                recorded: 5
            }
        );
        let msg = cli::rollback_warning(3, 5);
        assert_eq!(
            msg,
            "This vault is older than the last version saved on this machine \
             (generation 3 < 5). It may have been rolled back or restored from backup."
        );
        // Anything but `yes` refuses with exit code 3 and changes nothing.
        for answer in [
            &b"no"[..],
            b"",
            b"y",
            b"YES",
            b"yes please",
            b" yes",
            b"yes\n",
        ] {
            let mut h2 = h.clone();
            assert_eq!(
                cli::confirm_rollback(&mut h2, fr, answer),
                Err(cli::EXIT_INTEGRITY)
            );
            assert_eq!(&h2, h);
        }
        // `yes` continues; the next save writes max(3, 5) + 1 = 6.
        assert_eq!(cli::confirm_rollback(h, fr, b"yes"), Ok(()));
        let file = save_next(st, h, dek, body);
        assert_eq!(h.generation, 6);
        file
    });
    let (st, file) = open(f.paths.clone(), false).unwrap();
    assert_eq!(file, warned);
    let (h, m) = open_model(&file, &kek);
    assert_eq!((h.generation, m), (6, model(6)));
    assert_eq!(st.freshness(&h).unwrap(), Freshness::Fresh);
    drop(st);
    assert_eq!(fs::read(f.at("vault.pwv.1")).unwrap(), files[2]);

    // A fresh vault never asks; `confirm_rollback` is then a no-op.
    let mut h2 = h.clone();
    assert_eq!(
        cli::confirm_rollback(&mut h2, Freshness::Fresh, b"no"),
        Ok(())
    );
    assert_eq!(h2, h);
}

#[test]
fn t_store_5_state_never_regresses_and_tracks_vaults_separately() {
    let f = fx();
    let (kek, _) = create_vault(&f.paths, 5);
    // A second vault sharing the state file.
    let other = Paths {
        vault: f.tmp.path().join("other/vault.pwv"),
        state: f.paths.state.clone(),
    };
    let (kek2, _) = create_vault(&other, 2);
    // Restore generation 3 and save without acknowledging: the file gets
    // generation 4 but the state keeps 5, so the rollback is still seen.
    fs::copy(f.at("vault.pwv.2"), &f.paths.vault).unwrap();
    with_session(&f.paths, &kek, |st, h, dek, body| {
        save_next(st, h, dek, body);
        assert_eq!(h.generation, 4);
        assert_eq!(
            st.freshness(h).unwrap(),
            Freshness::RolledBack {
                file: 4,
                recorded: 5
            }
        );
    });
    // The other vault is unaffected (generation 2 recorded for it).
    with_session(&other, &kek2, |st, h, _, _| {
        assert_eq!(h.generation, 2);
        assert_eq!(st.freshness(h).unwrap(), Freshness::Fresh);
    });
    let state = fs::read_to_string(&f.paths.state).unwrap();
    assert_eq!(state.lines().count(), 2, "{state}");
    let mut gens: Vec<&str> = state
        .lines()
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    gens.sort_unstable();
    assert_eq!(gens, ["2", "5"], "{state}");
    assert_eq!(mode(&f.paths.state), 0o600);
    assert_eq!(mode(f.paths.state.parent().unwrap()), 0o700);
    // A vault saved elsewhere (file newer than the record) is fresh.
    with_session(&other, &kek2, |st, h, _, _| {
        let mut newer = h.clone();
        newer.generation = 9;
        assert_eq!(st.freshness(&newer).unwrap(), Freshness::Fresh);
    });
}

#[test]
fn state_file_damage_and_permissions_refused() {
    let f = fx();
    let (kek, _) = create_vault(&f.paths, 1);
    let good = fs::read(&f.paths.state).unwrap();
    let id = String::from_utf8(good.clone()).unwrap();
    let id = id.split(' ').next().unwrap().to_owned();
    let damaged = [
        "garbage\n".to_owned(),
        format!("{id} 1"),     // no final newline
        format!("{id} +1\n"),  // sign
        format!("{id} 1 \n"),  // trailing space
        format!("{id}  1\n"),  // double space
        format!("{id} \n"),    // empty generation
        format!("{id} 1\r\n"), // CR
        format!("{} 1\n", id.to_uppercase()),
        format!("{} 1\n", &id[..30]),
        format!("{id} 1\n{id} 2\n"),               // duplicate vault
        format!("{id} 99999999999999999999999\n"), // overflow
    ];
    for text in &damaged {
        overwrite(&f.paths.state, text.as_bytes());
        with_session(&f.paths, &kek, |st, h, _, _| {
            let e = st.freshness(h).unwrap_err();
            assert_eq!(e, Error::State, "{text:?}");
            assert_eq!(cli::store_exit_code(&e), cli::EXIT_INTEGRITY);
        });
    }
    overwrite(&f.paths.state, &good);
    // Group or other bits on the state file or its directory: refused with
    // the exact remedy.
    for p in [
        f.paths.state.clone(),
        f.paths.state.parent().unwrap().to_owned(),
    ] {
        let ok = mode(&p);
        chmod(&p, ok | 0o004);
        with_session(&f.paths, &kek, |st, h, _, _| {
            let e = st.freshness(h).unwrap_err();
            assert!(matches!(e, Error::Mode(_)), "{e:?}");
            run_remedy(&e);
            assert_eq!(st.freshness(h).unwrap(), Freshness::Fresh);
        });
        assert_eq!(mode(&p), ok);
    }
}

// ------------------------------------------------------------ T-STORE-6

#[test]
fn t_store_6_stale_temp_files_removed() {
    let f = fx();
    let (_, files) = create_vault(&f.paths, 2);
    let stale = [
        ".vault.pwv.tmp.0123456789abcdef",
        ".vault.pwv.tmp.fedcba9876543210",
    ];
    // Similar names that are not this vault's temporary files survive.
    let keep = [
        ".vault.pwv.tmp.0123456789abcde",
        ".vault.pwv.tmp.0123456789abcdef0",
        ".vault.pwv.tmp.0123456789ABCDEF",
        ".vault.pwv.tmp.xyz",
        ".other.pwv.tmp.0123456789abcdef",
        "vault.pwv.tmp.0123456789abcdef",
        "notes.txt",
    ];
    for n in stale.iter().chain(&keep) {
        new_file(&f.at(n), &files[0][..100]);
    }
    let (_st, file) = open(f.paths.clone(), false).unwrap();
    assert_eq!(file, files[1]);
    for n in stale {
        assert!(!f.at(n).exists(), "{n} not removed");
    }
    for n in keep {
        assert!(f.at(n).exists(), "{n} removed");
    }
}

/// Replaces the contents of the existing file `p` with `b`.
fn overwrite(p: &Path, b: &[u8]) {
    use std::io::Write;
    let mut o = fs::OpenOptions::new();
    o.write(true).truncate(true);
    o.open(p).unwrap().write_all(b).unwrap();
}

/// Creates `p` (mode 0600) holding `b`.
fn new_file(p: &Path, b: &[u8]) {
    use std::io::Write;
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true).mode(0o600);
    o.open(p).unwrap().write_all(b).unwrap();
}

// ------------------------------------------------------------ T-STORE-7

#[test]
fn t_store_7_seven_saves_keep_five_backups() {
    let f = fx();
    let (kek, files) = create_vault(&f.paths, 7);
    let mut want = vec!["vault.pwv".to_owned()];
    want.extend((1..=5).map(|i| format!("vault.pwv.{i}")));
    want.push("vault.pwv.lock".to_owned());
    assert_eq!(f.names(), want);
    assert_eq!(fs::read(&f.paths.vault).unwrap(), files[6]);
    for i in 1..=5usize {
        let p = f.at(&format!("vault.pwv.{i}"));
        let b = fs::read(&p).unwrap();
        assert_eq!(b, files[6 - i], ".{i}");
        let (h, m) = open_model(&b, &kek);
        assert_eq!(h.generation, 7 - i as u64, ".{i}");
        assert_eq!(m, model(7 - i as u64), ".{i}");
        assert_eq!(mode(&p), 0o600);
    }
    // The oldest backup also opens through the full password path.
    let (h, m) = vaults::unlock_model(&fs::read(f.at("vault.pwv.5")).unwrap(), PW.as_bytes())
        .expect("password opens backup");
    assert_eq!((h.generation, m), (2, model(2)));
}

// ------------------------------------------------------------ T-STORE-9

/// Everything a write could change: names, and per file the inode,
/// modification and change times, size, and link count; the same for the
/// two directories.
/// (path, inode, mtime s, mtime ns, ctime s, ctime ns, size, links).
type Snap = Vec<(String, u64, i64, i64, i64, i64, u64, u64)>;

fn snapshot(f: &Fx) -> Snap {
    let mut out = Vec::new();
    let state_dir = f.paths.state.parent().unwrap();
    for dir in [f.dir(), state_dir] {
        let mut paths = vec![dir.to_owned()];
        paths.extend(list(dir).iter().map(|n| dir.join(n)));
        for p in paths {
            let m = fs::symlink_metadata(&p).unwrap();
            out.push((
                p.display().to_string(),
                m.ino(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
                m.size(),
                m.nlink(),
            ));
        }
    }
    out
}

#[test]
fn t_store_9_read_only_sessions_do_not_write() {
    let f = fx();
    let (kek, _) = create_vault(&f.paths, 2);
    let before = snapshot(&f);
    thread::sleep(Duration::from_millis(50));
    // Store-level read-only sessions: open, decrypt, rollback check, read
    // the model, close (M7 adds the read-only commands on top).
    for _ in 0..3 {
        with_session(&f.paths, &kek, |st, h, _, body| {
            assert_eq!(read_body(body.expose()), model(2));
            assert_eq!(st.freshness(h).unwrap(), Freshness::Fresh);
        });
    }
    assert_eq!(snapshot(&f), before);

    // Control: a save is visible in the snapshot (new vault inode).
    with_session(&f.paths, &kek, |st, h, dek, body| {
        save_next(st, h, dek, body);
    });
    let after = snapshot(&f);
    let ino = |s: &Snap| s.iter().find(|e| e.0.ends_with("/vault.pwv")).map(|e| e.1);
    assert_ne!(ino(&after), ino(&before));
}

// ------------------------------------------------- open/create contract

#[test]
fn open_never_creates() {
    let f = fx();
    let e = refused(&f.paths);
    assert_eq!(e, Error::NoVault);
    assert!(e.message().contains("pwv init"), "{}", e.message());
    assert_eq!(cli::store_exit_code(&e), cli::EXIT_USER);
    assert!(list(f.tmp.path()).is_empty(), "open created files");

    fs::create_dir_all(f.dir()).unwrap();
    chmod(f.dir(), 0o700);
    assert_eq!(refused(&f.paths), Error::NoVault);
    assert!(f.names().is_empty(), "open created {:?}", f.names());
}

#[test]
fn create_refuses_an_existing_vault() {
    let f = fx();
    let (_, files) = create_vault(&f.paths, 1);
    let e = create(f.paths.clone(), false).err().expect("refused");
    assert_eq!(e, Error::Exists);
    assert_eq!(cli::store_exit_code(&e), cli::EXIT_USER);
    assert_eq!(fs::read(&f.paths.vault).unwrap(), files[0]);
    // While a session holds the vault, create reports it in use.
    let (_held, _) = open(f.paths.clone(), false).unwrap();
    assert_eq!(create(f.paths.clone(), false).err(), Some(Error::InUse));
}

#[test]
fn create_makes_private_directories() {
    let f = fx();
    let (_, files) = create_vault(&f.paths, 1);
    for d in [
        f.dir(),
        f.dir().parent().unwrap(),
        f.paths.state.parent().unwrap(),
    ] {
        assert_eq!(mode(d), 0o700, "{}", d.display());
    }
    assert_eq!(fs::read(&f.paths.vault).unwrap(), files[0]);
    assert_eq!(f.names(), ["vault.pwv", "vault.pwv.lock"]);
}

/// Child: with `RLIMIT_FSIZE` below the vault size (and `SIGXFSZ`
/// ignored), the temporary file's write fails with `EFBIG`, as on a full
/// disk. The save must report an I/O error.
#[test]
fn store_fsize_child() {
    let (Some(paths), Ok(kek)) = (child_paths(), std::env::var("PWV_T_FSIZE_KEK")) else {
        return;
    };
    // SAFETY: called before any other thread of this child exists; sets
    // the disposition of SIGXFSZ to "ignore", so the write fails instead.
    unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    let limit = rustix::process::Rlimit {
        current: Some(4096),
        maximum: Some(4096),
    };
    rustix::process::setrlimit(rustix::process::Resource::Fsize, limit).unwrap();
    with_session(&paths, &vaults::unhex(&kek), |st, h, dek, body| {
        write_body(&model(h.generation + 1), body);
        let file = vault::save(dek, h, body.expose_mut()).unwrap();
        assert!(file.len() > 4096);
        assert_eq!(st.save(&file), Err(Error::Io));
        assert_eq!(cli::store_exit_code(&Error::Io), cli::EXIT_ENV);
    });
}

#[test]
fn failed_save_leaves_vault_state_and_no_temp_file() {
    let f = fx();
    let (kek, files) = create_vault(&f.paths, 2);
    let state = fs::read(&f.paths.state).unwrap();
    let mut env = child_env(&f);
    env.push(("PWV_T_FSIZE_KEK".into(), vaults::hex(&kek)));
    let out = output(&mut spawn_child("store_fsize_child", &env));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The vault and the state are unchanged; the temporary file is gone.
    // (Backups were already rotated: Section 8.3, steps 1-2 of the table.)
    assert_eq!(fs::read(&f.paths.vault).unwrap(), files[1]);
    assert_eq!(fs::read(&f.paths.state).unwrap(), state);
    let names = f.names();
    assert!(names.iter().all(|n| !n.contains(".tmp.")), "{names:?}");
    with_session(&f.paths, &kek, |st, h, _, body| {
        assert_eq!(read_body(body.expose()), model(2));
        assert_eq!(st.freshness(h).unwrap(), Freshness::Fresh);
    });
}

#[test]
fn save_refuses_malformed_files_and_changes_nothing() {
    let f = fx();
    let (kek, files) = create_vault(&f.paths, 2);
    let before = snapshot(&f);
    with_session(&f.paths, &kek, |st, _, _, _| {
        for bad in [&files[1][..100], &files[1][..files[1].len() - 1], &[][..]] {
            assert!(matches!(st.save(bad), Err(Error::Format(_))));
        }
    });
    assert_eq!(snapshot(&f), before);
}
