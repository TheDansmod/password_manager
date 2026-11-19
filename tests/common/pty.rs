//! PTY harness for the end-to-end tests (T-E2E, T-CLIP).
//!
//! The captured screen holds secrets (test canaries), so nothing here ever
//! prints it: helpers return booleans and positions only (rule 9).
//! expectrl 0.9.0 / ptyprocess 0.5.0, verified against the pinned sources:
//! `Session::spawn(Command)`, `try_read` (non-blocking), `Write`,
//! `get_process().status()`, `get_process_mut().signal()`.

pub use expectrl::process::unix::Signal;
use expectrl::process::unix::WaitStatus;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// How long a single expectation may take.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// The most output one child may produce. The tests print a few kilobytes;
/// a child that writes without end is killed and fails its test here,
/// instead of growing `screen` until the machine runs out of memory
/// (DESIGN_NOTES, M7 CI round 1).
pub const SCREEN_CAP: usize = 4 << 20;

/// The most one `pump` call reads, so that the callers' deadlines are
/// checked however fast the child writes.
const PUMP_MAX: usize = 256 << 10;

/// A `pwv` process on a pseudo-terminal, with everything it wrote so far.
pub struct Pty {
    session: expectrl::session::OsSession,
    screen: Vec<u8>,
    /// Everything before this offset was consumed by `expect`.
    cursor: usize,
}

/// A scratch home for one test: the vault, state, and working directories
/// live under `/tmp` (the repository is on a refused filesystem).
pub struct Home {
    pub dir: tempfile::TempDir,
}

impl Home {
    pub fn new() -> Home {
        let dir = tempfile::Builder::new()
            .prefix("pwv-e2e-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        std::fs::create_dir(dir.path().join("cwd")).expect("cwd");
        Home { dir }
    }

    pub fn vault(&self) -> PathBuf {
        self.dir.path().join("data/pwv/vault.pwv")
    }

    /// `pwv <args>` with this home, not started.
    pub fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut cmd = super::pwv_command();
        self.env(&mut cmd);
        cmd.args(args);
        cmd
    }

    pub fn env(&self, cmd: &mut Command) {
        let d = self.dir.path();
        cmd.env("HOME", d)
            .env("XDG_DATA_HOME", d.join("data"))
            .env("XDG_STATE_HOME", d.join("state"))
            .env_remove("PWV_VAULT")
            .env_remove("NO_COLOR")
            .env("TERM", "dumb")
            .current_dir(d.join("cwd"));
    }

    /// Starts `pwv <args>` on a PTY.
    pub fn spawn<S: AsRef<OsStr>>(&self, args: &[S]) -> Pty {
        Pty::spawn(self.command(args))
    }
}

impl Pty {
    /// Runs `cmd` on a new PTY. ptyprocess starts children with `ECHO`
    /// off, which would make every "not visible" assertion vacuous, so the
    /// child turns echo on (`stty echo`) before it execs the program.
    pub fn spawn(cmd: Command) -> Pty {
        Pty::spawn_shell("exec \"$0\" \"$@\"", cmd)
    }

    /// Runs `script` with `sh -c` on a new PTY, after `stty echo`; in the
    /// script, `"$0" "$@"` is `cmd`. Shared by [`Pty::spawn`] and
    /// [`Pty::spawn_piped`]; tests use it for other redirections.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    pub fn spawn_shell(script: &str, cmd: Command) -> Pty {
        let mut sh = Command::new("sh");
        sh.arg("-c").arg(format!("stty echo && {script}"));
        sh.arg(cmd.get_program()).args(cmd.get_args());
        for (k, v) in cmd.get_envs() {
            match v {
                Some(v) => sh.env(k, v),
                None => sh.env_remove(k),
            };
        }
        if let Some(dir) = cmd.get_current_dir() {
            sh.current_dir(dir);
        }
        let session = expectrl::session::Session::spawn(sh).expect("spawn on a pty");
        Pty {
            session,
            screen: Vec::new(),
            cursor: 0,
        }
    }

    /// Runs `<producer> | cmd` on a new PTY: stdin of `cmd` is a pipe,
    /// its terminal is the PTY.
    pub fn spawn_piped(producer: &str, cmd: Command) -> Pty {
        Pty::spawn_shell(&format!("{producer} | \"$0\" \"$@\""), cmd)
    }

    /// The PTY master, for `tcgetattr`.
    pub fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.session.get_stream().as_fd()
    }

    /// The text between the first `start` and the next `end` on the whole
    /// screen. May be a secret: never print it.
    pub fn between(&mut self, start: &str, end: &str) -> Option<String> {
        self.pump();
        let text = String::from_utf8_lossy(&self.screen).into_owned();
        let from = text.find(start)? + start.len();
        let len = text[from..].find(end)?;
        Some(text[from..from + len].to_owned())
    }

    /// Everything on the screen after the first `needle`. May hold
    /// secrets: compare it, never print it.
    pub fn tail_after(&mut self, needle: &str) -> Vec<u8> {
        self.pump();
        let n = needle.as_bytes();
        let at = self.screen.windows(n.len()).position(|w| w == n);
        at.map_or(Vec::new(), |p| self.screen[p + n.len()..].to_vec())
    }

    pub fn pid(&self) -> i32 {
        self.session.get_process().pid().as_raw()
    }

    /// Reads what is available, at most `PUMP_MAX` bytes per call; false
    /// once the PTY is closed.
    ///
    /// # Panics
    /// If the child has written more than `SCREEN_CAP` bytes; it is
    /// killed first. The message is fixed: the screen is never printed.
    fn pump(&mut self) -> bool {
        let mut buf = [0u8; 4096];
        let mut got = 0;
        while got < PUMP_MAX {
            match self.session.try_read(&mut buf) {
                Ok(0) => return false,
                Ok(n) => {
                    self.screen.extend_from_slice(&buf[..n]);
                    got += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
            if self.screen.len() > SCREEN_CAP {
                let _ = self.session.get_process_mut().signal(Signal::SIGKILL);
                panic!("pty: the child wrote more than SCREEN_CAP bytes; killed");
            }
        }
        true
    }

    fn find(&self, needle: &str) -> Option<usize> {
        let n = needle.as_bytes();
        self.screen[self.cursor..]
            .windows(n.len())
            .position(|w| w == n)
            .map(|p| self.cursor + p)
    }

    /// Waits until `needle` appears after everything consumed so far, and
    /// consumes through it. False on timeout or exit.
    pub fn expect(&mut self, needle: &str) -> bool {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let open = self.pump();
            if let Some(p) = self.find(needle) {
                self.cursor = p + needle.len();
                return true;
            }
            if !open || Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Types `text`.
    pub fn send(&mut self, text: &str) {
        self.session.write_all(text.as_bytes()).expect("write");
        self.session.flush().expect("flush");
    }

    /// `expect(prompt)`, then types `line` and Enter.
    pub fn answer(&mut self, prompt: &str, line: &str) -> bool {
        let seen = self.expect(prompt);
        if seen {
            self.send(line);
            self.send("\n");
        }
        seen
    }

    /// Whether the whole screen so far contains `needle`.
    pub fn saw(&mut self, needle: &str) -> bool {
        self.pump();
        self.count(needle) > 0
    }

    /// How often the whole screen so far contains `needle`.
    pub fn count(&mut self, needle: &str) -> usize {
        self.pump();
        let n = needle.as_bytes();
        self.screen.windows(n.len()).filter(|w| *w == n).count()
    }

    pub fn signal(&mut self, sig: Signal) {
        self.session.get_process_mut().signal(sig).expect("signal");
    }

    /// Waits for the process to end. `Some(code)` for a normal exit.
    pub fn exit_code(&mut self) -> Option<i32> {
        match self.wait_status(PATIENCE) {
            Some(WaitStatus::Exited(_, code)) => Some(code),
            _ => None,
        }
    }

    /// Whether the process is still running after `d`.
    pub fn alive_after(&mut self, d: Duration) -> bool {
        self.wait_status(d).is_none()
    }

    fn wait_status(&mut self, patience: Duration) -> Option<WaitStatus> {
        let deadline = Instant::now() + patience;
        loop {
            self.pump();
            match self.session.get_process().status() {
                Ok(WaitStatus::StillAlive) => {}
                Ok(status) => {
                    self.pump();
                    return Some(status);
                }
                Err(_) => return None,
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Names in `dir`, sorted (to prove that nothing was created or changed).
pub fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| {
                e.expect("dirent")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

/// Replaces a vault file's bytes (a test tampering with the disk, as an
/// attacker with write access would).
#[allow(
    clippy::disallowed_methods,
    reason = "tests tamper with vault files; the ban binds src/"
)]
pub fn overwrite(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("overwrite");
}
