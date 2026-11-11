//! Process hardening: T-MEM-5 (run against a release build:
//! `cargo test --release --test harden`), plus Section 5.1 steps 3–6.

mod common;

use std::process::Stdio;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

const SIBLING_ENV: &str = "PWV_T_MEM_5_TARGET";
const PANIC_ENV: &str = "PWV_PANIC_HOOK_CHILD";

#[test]
fn harden_refuses_non_tty_with_exit_4() {
    let out = common::pwv_command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run pwv");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "pwv: standard input and output must be a terminal\n"
    );
    assert!(out.stdout.is_empty());
}

/// Child half of the panic-hook test; a no-op unless its env var is set.
#[test]
fn panic_hook_child() {
    if std::env::var(PANIC_ENV).is_err() {
        return;
    }
    pwv::sys::install_panic_hook();
    let payload = String::from("PWV-SECRET-CANARY");
    panic!("{payload}");
}

#[test]
fn panic_hook_prints_fixed_string_never_payload() {
    let out = common::run_child("panic_hook_child", &[(PANIC_ENV, "1")]);
    assert!(!out.status.success());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(stderr.contains("internal error\n"), "stderr: {stderr}");
    assert!(!stderr.contains("PWV-SECRET-CANARY") && !stdout.contains("PWV-SECRET-CANARY"));
    assert!(
        !stderr.contains("panicked"),
        "default hook must not run: {stderr}"
    );
}

/// Sibling half of T-MEM-5: a non-parent process tries to read the target's
/// memory and to ptrace-attach to it. Exit code: 42 if both are refused;
/// otherwise 10 + 1 (memory readable) + 2 (attach succeeded).
#[test]
fn t_mem_5_sibling() {
    let Ok(pid) = std::env::var(SIBLING_ENV) else {
        return;
    };
    let pid: i32 = pid.parse().expect("pid");
    let mem_read = match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Err(_) => false,
        Ok(f) => {
            use std::os::unix::fs::FileExt;
            let mut b = [0u8; 1];
            // Any readable address will do; try the start of the first mapping.
            let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
            let addr = maps
                .split('-')
                .next()
                .and_then(|a| u64::from_str_radix(a, 16).ok())
                .unwrap_or(0);
            f.read_at(&mut b, addr).is_ok()
        }
    };
    let null = std::ptr::null_mut::<libc::c_void>();
    // SAFETY: PTRACE_ATTACH/DETACH with null addr and data have no memory-safety
    // preconditions in the calling process.
    let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, null, null) };
    let attached = rc == 0;
    if attached {
        // SAFETY: as above.
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, null, null) };
    }
    // A distinctive code, so a vacuous no-op run (exit 0) cannot pass.
    std::process::exit(if mem_read || attached {
        10 + i32::from(mem_read) + 2 * i32::from(attached)
    } else {
        42
    });
}

#[cfg(not(feature = "memtest"))]
#[test]
fn t_mem_5_core_limit_ptrace_mem_and_sigsegv() {
    use expectrl::process::unix::{Signal, WaitStatus};
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = common::pwv_command();
    cmd.current_dir(tmp.path());
    let mut session = expectrl::session::Session::spawn(cmd).expect("spawn pwv under a pty");
    let pid = session.get_process().pid().as_raw();

    // Wait until harden() has run. The inherited limits cannot be the signal:
    // CI runners start processes with a soft core limit of 0 already (hard
    // unlimited), so "soft == 0" is true before harden() runs. Wait instead
    // for the observable end state of steps 1-3 (core {0, 0}, non-dumpable,
    // umask 0077), then re-read everything for the assertions below.
    let limits_path = format!("/proc/{pid}/limits");
    let status_path = format!("/proc/{pid}/status");
    let core_row = || {
        std::fs::read_to_string(&limits_path)
            .expect("limits")
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .expect("core row")
            .to_owned()
    };
    let me = std::fs::metadata("/proc/self/mem").expect("self mem").uid();
    let mem_owner = || {
        std::fs::metadata(format!("/proc/{pid}/mem"))
            .expect("mem meta")
            .uid()
    };
    let umask_077 = || {
        std::fs::read_to_string(&status_path)
            .expect("status")
            .lines()
            .any(|l| l == "Umask:\t0077")
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let row = core_row();
        let f: Vec<&str> = row.split_whitespace().collect();
        let done = (f[4], f[5]) == ("0", "0") && mem_owner() != me && umask_077();
        if done || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Some time for step 6 (RLIMIT_MEMLOCK), which runs after the umask.
    std::thread::sleep(Duration::from_millis(100));

    // Step 1: soft and hard core limit 0.
    let row = core_row();
    let f: Vec<&str> = row.split_whitespace().collect();
    assert_eq!((f[4], f[5]), ("0", "0"), "core limit: {row}");

    // Step 2: non-dumpable => /proc/<pid> files are no longer owned by us.
    assert_ne!(mem_owner(), me, "process is still dumpable");

    // Step 3: umask 0077.
    assert!(umask_077(), "umask not 0077");

    // Step 6: soft RLIMIT_MEMLOCK raised to the hard limit.
    let limits = std::fs::read_to_string(&limits_path).expect("limits");
    let ml: Vec<&str> = limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .expect("row")
        .split_whitespace()
        .collect();
    assert_eq!(ml[3], ml[4], "memlock soft != hard");

    // A4: a sibling (not our child's parent) cannot read memory or attach.
    let out = common::run_child("t_mem_5_sibling", &[(SIBLING_ENV, &pid.to_string())]);
    assert_eq!(
        out.status.code(),
        Some(42),
        "sibling must report both refused (42); 11/13 = memory read, 12/13 = attached"
    );

    // SIGSEGV: dies by the signal, and the kernel reports no core dump.
    let mut last = WaitStatus::StillAlive;
    for _ in 0..3 {
        session
            .get_process_mut()
            .signal(Signal::SIGSEGV)
            .expect("kill");
        let until = Instant::now() + Duration::from_millis(1000);
        while Instant::now() < until {
            last = session.get_process().status().expect("status");
            if last != WaitStatus::StillAlive {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if last != WaitStatus::StillAlive {
            break;
        }
    }
    match last {
        WaitStatus::Signaled(_, Signal::SIGSEGV, core) => {
            assert!(
                !core,
                "kernel reports a core dump was written (see DESIGN_NOTES.md, suid_dumpable)"
            )
        }
        other => panic!("expected death by SIGSEGV, got {other:?}"),
    }
    let left: Vec<_> = std::fs::read_dir(tmp.path()).expect("tmp").collect();
    assert!(left.is_empty(), "files (core?) left in cwd: {left:?}");
}
