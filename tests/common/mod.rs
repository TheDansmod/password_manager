//! Shared helpers for integration tests.

#![allow(dead_code)]

pub mod vaults;

use std::process::{Command, Output};

/// Re-runs this test binary, executing only `test_name`, with `env` set.
/// The named test is a no-op unless its environment variable is present,
/// which lets one integration test drive a scenario in a child process.
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
pub fn run_child(test_name: &str, env: &[(&str, &str)]) -> Output {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test_name, "--nocapture", "--test-threads=1"]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn child test")
}

/// A `Command` that re-runs this test binary, executing only `test_name`
/// (quietly, single-threaded), with `env` set. Unlike [`run_child`] it is
/// not started, so the caller can pipe its streams and signal it.
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
pub fn child_command(test_name: &str, env: &[(&str, &str)]) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        test_name,
        "--nocapture",
        "--test-threads=1",
        "-q",
    ]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd
}

/// `sh -c <script>`.
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
pub fn shell_command(script: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", script]);
    cmd
}

/// `std::process::Command` for the `pwv` binary built alongside the tests.
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
pub fn pwv_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pwv"))
}

/// Mapping of `/proc/self/smaps` or `/proc/<pid>/smaps`: one VMA.
#[derive(Debug, Clone)]
pub struct Vma {
    pub start: usize,
    pub end: usize,
    pub perms: String,
    pub fields: Vec<(String, String)>,
}

impl Vma {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parses smaps text into VMAs.
pub fn parse_smaps(text: &str) -> Vec<Vma> {
    let mut out: Vec<Vma> = Vec::new();
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        let range = first.split_once('-').and_then(|(a, b)| {
            Some((
                usize::from_str_radix(a, 16).ok()?,
                usize::from_str_radix(b, 16).ok()?,
            ))
        });
        if let Some((start, end)) = range {
            let perms = line.split_whitespace().nth(1).unwrap_or("").to_owned();
            out.push(Vma {
                start,
                end,
                perms,
                fields: Vec::new(),
            });
            continue;
        }
        if let (Some(vma), Some((k, v))) = (out.last_mut(), line.split_once(':')) {
            vma.fields.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    out
}

/// The VMA containing `addr`.
pub fn vma_at(vmas: &[Vma], addr: usize) -> Option<&Vma> {
    vmas.iter().find(|v| v.start <= addr && addr < v.end)
}
