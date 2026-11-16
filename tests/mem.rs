//! T-MEM-4, the canary scan (spec Sections 5.8 and 14.9): the test reads
//! every readable mapping of a running `memtest` build of `pwv` through
//! `/proc/<pid>/mem` and searches it for canary secrets, in UTF-8 and in
//! UTF-16LE. Mid-session, a secret may be found only inside the arena and
//! the master password nowhere; after the wipe, nothing anywhere.
//!
//! The one accepted exception (rule 5, DESIGN_NOTES "Heap copies") is the
//! value that is on the clipboard at the moment of the scan: `arboard`
//! keeps it on the heap. It is asserted narrowly: that value only, only
//! while it is on the clipboard, only in private anonymous memory.
//!
//! The test process is the parent of `pwv` (`exec` keeps the PID of the
//! shell the PTY harness starts), which Yama `ptrace_scope = 1` requires
//! for reading its memory. Canaries and the screen are never printed
//! (rule 9): failures name a canary by its label, with counts and mapping
//! names only.

mod common;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

#[cfg(feature = "memtest")]
mod scan {
    use super::common;
    use common::pty::{Home, Pty, Signal};
    use std::os::unix::fs::FileExt;
    use std::time::Duration;

    /// The master password, canary P. It passes the strength policy.
    const P: &str = "Vk7#CANARY-mem-P-qunmp2!xbrw9Tz";
    /// C1: in the vault before the scanned session starts.
    const C1: &str = "CANARY-mem-C1-vault-8Qz";
    /// C2: typed (hidden, twice) in `set`.
    const C2: &str = "CANARY-mem-C2-typed-5Lw";
    /// Typed with echo in `set` of a plain field.
    const C5: &str = "CANARY-mem-C5-plain-3Hd";
    const PROMPT: &str = "pwv> ";
    const CLIP_TIMEOUT: u64 = 5;

    /// One mapping of the scanned process.
    struct Map {
        start: usize,
        end: usize,
        perms: String,
        /// The path column of `/proc/<pid>/maps`; empty if anonymous.
        path: String,
    }

    /// Where a canary was found.
    struct Hit {
        /// Index into the canary list.
        canary: usize,
        addr: usize,
        /// Index into `Scan::maps`.
        map: usize,
    }

    struct Scan {
        maps: Vec<Map>,
        hits: Vec<Hit>,
        /// Bytes read successfully.
        read: usize,
        /// Readable mappings with unreadable pages that are not guard
        /// pages: perms, name, and page counts.
        unread: Vec<String>,
        /// Guard pages skipped.
        guards: usize,
    }

    /// A canary and its label for messages.
    struct Canary {
        label: String,
        bytes: Vec<u8>,
    }

    /// Each secret twice: UTF-8 and UTF-16LE.
    fn canaries(secrets: &[(&str, &str)]) -> Vec<Canary> {
        let mut out = Vec::new();
        for (label, s) in secrets {
            out.push(Canary {
                label: format!("{label} (UTF-8)"),
                bytes: s.as_bytes().to_vec(),
            });
            out.push(Canary {
                label: format!("{label} (UTF-16LE)"),
                bytes: s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            });
        }
        out
    }

    fn parse_maps(text: &str) -> Vec<Map> {
        text.lines()
            .map(|line| {
                let mut cols = line.split_whitespace();
                let (a, b) = cols
                    .next()
                    .and_then(|r| r.split_once('-'))
                    .expect("maps: range");
                let perms = cols.next().expect("maps: perms").to_owned();
                let path = cols.nth(3).unwrap_or("").to_owned();
                Map {
                    start: usize::from_str_radix(a, 16).expect("maps: start"),
                    end: usize::from_str_radix(b, 16).expect("maps: end"),
                    perms,
                    path,
                }
            })
            .collect()
    }

    /// The kernel's page size: `pagemap` has one entry per page, and guard
    /// regions are whole pages (4 KiB on x86_64; an arm64 kernel may use
    /// 16 or 64 KiB, where a fixed 4096 would index the wrong entries).
    fn page() -> usize {
        rustix::param::page_size()
    }

    /// Whether the page at `addr` is a guard region (`madvise(
    /// MADV_GUARD_INSTALL)`, Linux 6.13): `pagemap` bit 58
    /// (`PM_GUARD_REGION`). Such a page faults on every access, the
    /// process's own included, so it holds no data. glibc 2.42 places
    /// thread-stack guards this way, inside the stack's `rw-p` mapping
    /// (DESIGN_NOTES, M8 CI round 1).
    fn is_guard(pagemap: &std::fs::File, addr: usize) -> bool {
        let mut e = [0u8; 8];
        let at = (addr / page() * 8) as u64;
        pagemap.read_exact_at(&mut e, at).is_ok() && u64::from_le_bytes(e) >> 58 & 1 == 1
    }

    /// Reads every readable mapping of `pid` and searches it for every
    /// canary. One pass per mapping: a table of first bytes selects the
    /// positions worth comparing.
    fn scan(pid: i32, canaries: &[Canary]) -> Scan {
        let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
        let maps = parse_maps(&text);
        let mem = std::fs::File::open(format!("/proc/{pid}/mem")).expect("open mem (parent?)");
        let mut first = [false; 256];
        for c in canaries {
            first[usize::from(c.bytes[0])] = true;
        }
        let pagemap =
            std::fs::File::open(format!("/proc/{pid}/pagemap")).expect("open pagemap (parent?)");
        let mut out = Scan {
            maps: Vec::new(),
            hits: Vec::new(),
            read: 0,
            unread: Vec::new(),
            guards: 0,
        };
        for (i, m) in maps.iter().enumerate() {
            if !m.perms.starts_with('r') {
                continue;
            }
            let mut data = vec![0u8; m.end - m.start];
            if mem.read_exact_at(&mut data, m.start as u64).is_err() {
                // Page by page: only guard pages may fail (see `is_guard`).
                let (mut bad, mut ok) = (0, 0);
                for (k, chunk) in data.chunks_mut(page()).enumerate() {
                    let addr = m.start + k * page();
                    if mem.read_exact_at(chunk, addr as u64).is_ok() {
                        ok += chunk.len();
                    } else if is_guard(&pagemap, addr) {
                        out.guards += 1;
                    } else {
                        bad += 1;
                    }
                }
                out.read += ok;
                if bad > 0 {
                    out.unread.push(format!(
                        "{} {:?}, {} of {} pages unreadable and not guard pages",
                        m.perms,
                        m.path,
                        bad,
                        data.len() / page()
                    ));
                }
            } else {
                out.read += data.len();
            }
            for (at, b) in data.iter().enumerate() {
                if !first[usize::from(*b)] {
                    continue;
                }
                for (k, c) in canaries.iter().enumerate() {
                    if data[at..].starts_with(&c.bytes) {
                        out.hits.push(Hit {
                            canary: k,
                            addr: m.start + at,
                            map: i,
                        });
                    }
                }
            }
        }
        out.maps = maps;
        out
    }

    impl Scan {
        /// Hits of canary `k`, inside (`true`) or outside the arena.
        fn count(&self, k: usize, arena: (usize, usize), inside: bool) -> usize {
            self.hits
                .iter()
                .filter(|h| h.canary == k)
                .filter(|h| (arena.0 <= h.addr && h.addr < arena.1) == inside)
                .count()
        }

        /// The mappings (perms and name, never content) where canary `k`
        /// was found outside the arena, for a failure message.
        fn outside(&self, k: usize, arena: (usize, usize)) -> Vec<String> {
            self.hits
                .iter()
                .filter(|h| h.canary == k && !(arena.0 <= h.addr && h.addr < arena.1))
                .map(|h| {
                    let m = &self.maps[h.map];
                    format!("{} {:?} +{:#x}", m.perms, m.path, h.addr - m.start)
                })
                .collect()
        }

        /// The scan must have read the process: the program image, the
        /// heap, the stack, and megabytes in total. Only the kernel's
        /// special mappings may be unreadable.
        fn assert_complete(&self) {
            assert!(self.read > 1 << 20, "scan read only {} bytes", self.read);
            for name in ["[heap]", "[stack]", "pwv"] {
                assert!(
                    self.maps
                        .iter()
                        .any(|m| m.perms.starts_with('r') && m.path.ends_with(name)),
                    "no readable mapping named {name}"
                );
            }
            for what in &self.unread {
                assert!(
                    what.contains("\"[v"),
                    "a readable mapping could not be read: {what}"
                );
            }
        }
    }

    /// The arena's data range, from the `PWV_MEMTEST arena` line on fd 2
    /// (the PTY).
    fn arena_range(p: &mut Pty) -> (usize, usize) {
        let line = p.between("PWV_MEMTEST arena ", "\r\n").expect("arena line");
        let (a, b) = line.split_once('-').expect("arena range");
        let hex = |s: &str| usize::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex");
        (hex(a), hex(b))
    }

    fn run(p: &mut Pty, line: &str) {
        p.send(line);
        p.send("\n");
        assert!(p.expect(PROMPT), "no prompt after a command");
    }

    /// `__pause`, scan, SIGUSR1, back at the prompt.
    fn paused_scan(p: &mut Pty, canaries: &[Canary]) -> Scan {
        p.send("__pause\n");
        assert!(p.expect("PWV_MEMTEST paused"), "no pause");
        let s = scan(p.pid(), canaries);
        p.signal(Signal::SIGUSR1);
        assert!(p.expect(PROMPT), "no prompt after the pause");
        s
    }

    fn display() -> bool {
        let have =
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
        assert!(
            have || std::env::var_os("PWV_REQUIRE_X11").is_none(),
            "PWV_REQUIRE_X11 is set but there is no display"
        );
        have && cfg!(feature = "clipboard")
    }

    fn x11() -> bool {
        std::env::var_os("DISPLAY").is_some_and(|d| !d.is_empty())
    }

    /// What another X client reads from the CLIPBOARD selection.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn pasted() -> Vec<u8> {
        let out = std::process::Command::new("xclip")
            .args(["-o", "-selection", "clipboard", "-t", "UTF8_STRING"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .expect("run xclip");
        out.stdout
    }

    /// A vault with master password P holding C1, written by earlier
    /// processes, so the scanned process meets C1 only by decryption.
    fn seeded() -> Home {
        let home = Home::new();
        let mut p = home.spawn(&["init", "--kdf-memory", "64"]);
        let ok = p.answer("[Y/n] ", "n")
            && p.answer("New master password: ", P)
            && p.answer("Repeat: ", P)
            && p.expect("Vault created.");
        assert!(ok && p.exit_code() == Some(0), "init");
        let mut p = home.spawn::<&str>(&[]);
        assert!(p.answer("Master password: ", P));
        assert!(p.expect(PROMPT));
        p.send("add site\n");
        assert!(p.answer("Field key (. to finish): ", "password"));
        assert!(p.answer("gen [options]? ", "hidden"));
        assert!(p.answer("Value (hidden): ", C1));
        assert!(p.answer("Repeat: ", C1));
        assert!(p.answer("Field key (. to finish): ", "."));
        assert!(p.expect(PROMPT));
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        home
    }

    /// The session under test: unlocked with P, pausing before exit.
    fn session(home: &Home, idle: &str) -> (Pty, (usize, usize)) {
        let clip = CLIP_TIMEOUT.to_string();
        let mut cmd = home.command(&["--clip-timeout", &clip, "--idle-timeout", idle]);
        cmd.env("PWV_MEMTEST_EXIT_PAUSE", "1");
        let mut p = Pty::spawn(cmd);
        assert!(p.answer("Master password: ", P), "no password prompt");
        assert!(p.expect(PROMPT), "no REPL prompt");
        let arena = arena_range(&mut p);
        assert!(arena.0 < arena.1 && arena.1 - arena.0 == 1 << 20);
        (p, arena)
    }

    /// `show`, `reveal`, `copy`, `set` (hidden, plain, generated), `gen`.
    /// Returns the two generated values: C3 (stored by `set --gen`) and C4
    /// (`gen`, never stored; on the clipboard if there is one).
    fn exercise(p: &mut Pty, clipboard: bool) -> (String, String) {
        run(p, "show site");
        p.send("reveal site password\n");
        assert!(p.answer("Press Enter to clear the screen. ", ""));
        assert!(p.expect(PROMPT));
        assert!(p.count(C1) >= 1, "reveal showed the value");
        run(p, "copy site password");
        assert_eq!(p.saw("Copied. Clearing in"), clipboard, "copy");
        p.send("set site pin\n");
        assert!(p.answer("Value (hidden): ", C2));
        assert!(p.answer("Repeat: ", C2));
        assert!(p.expect(PROMPT));
        p.send("set site note\n");
        assert!(p.answer("Value: ", C5));
        assert!(p.expect(PROMPT));
        run(p, "set site token --gen --len 24");
        p.send("reveal site token\n");
        assert!(p.expect("Press Enter to clear the screen. "));
        let c3 = p
            .between("reveal site token\r\n", "\r\n")
            .expect("generated value");
        p.send("\n");
        assert!(p.expect(PROMPT));
        run(p, "gen --show --len 25");
        let out = p
            .between("gen --show --len 25\r\n", "\r\npwv")
            .expect("gen output");
        let c4 = out.split("\r\n").nth(1).expect("gen value").to_owned();
        assert_eq!((c3.len(), c4.len()), (24, 25), "generated lengths");
        if clipboard && x11() {
            // Another client pastes: the value then also passes through
            // the X11 connection's buffers inside `pwv`.
            assert!(pasted() == c4.as_bytes(), "C4 is on the clipboard");
        }
        (c3, c4)
    }

    /// After the wipe: nothing anywhere, in either encoding.
    fn assert_wiped(p: &mut Pty, all: &[Canary]) {
        assert!(p.expect("PWV_MEMTEST wiped"), "no pause after the wipe");
        let s = scan(p.pid(), all);
        s.assert_complete();
        for (k, c) in all.iter().enumerate() {
            let n = s.hits.iter().filter(|h| h.canary == k).count();
            let at = s.outside(k, (0, 0));
            assert_eq!(n, 0, "after the wipe: {} found at {at:?}", c.label);
        }
        p.signal(Signal::SIGUSR1);
        assert_eq!(p.exit_code(), Some(0), "exit after the wipe");
    }

    #[test]
    fn t_mem_4_canary_scan_mid_session_and_after_lock() {
        let clipboard = display();
        let home = seeded();
        let (mut p, arena) = session(&home, "300");

        // ---- Straight after unlock, before any command reuses a slot:
        // P is already gone, and C1 exists only as decrypted in the arena.
        let early = canaries(&[("P", P), ("C1", C1)]);
        let s = paused_scan(&mut p, &early);
        s.assert_complete();
        for (k, c) in early.iter().enumerate() {
            let (inside, outside) = (s.count(k, arena, true), s.count(k, arena, false));
            let at = s.outside(k, arena);
            assert_eq!(outside, 0, "after unlock: {} outside: {at:?}", c.label);
            assert_eq!(inside, usize::from(k == 2), "after unlock: {}", c.label);
        }

        let (c3, c4) = exercise(&mut p, clipboard);
        // Index k of a secret: 2k is its UTF-8 canary, 2k + 1 UTF-16LE.
        // The vault path is not a secret: it is the positive control that
        // the scan finds heap data outside the arena.
        let path = home.vault();
        let path = path.to_str().expect("path");
        let all = canaries(&[
            ("P", P),
            ("C1", C1),
            ("C2", C2),
            ("C3", &c3),
            ("C4", &c4),
            ("C5", C5),
            ("vault path", path),
        ]);
        let (secrets, control) = all.split_at(12);

        // ---- Mid-session, C4 on the clipboard (if there is one).
        let s = paused_scan(&mut p, &all);
        s.assert_complete();
        assert!(
            s.count(12, arena, false) >= 1,
            "positive control: the vault path is on the heap"
        );
        assert_eq!(control.len(), 2);
        for (k, c) in secrets.iter().enumerate() {
            let (inside, outside) = (s.count(k, arena, true), s.count(k, arena, false));
            let at = s.outside(k, arena);
            match k {
                // P: nowhere, the arena included.
                0 | 1 => assert_eq!(inside + outside, 0, "{} found; outside: {at:?}", c.label),
                // The stored secrets, UTF-8: in the arena and only there.
                2 | 4 | 6 | 10 => {
                    assert!(inside >= 1, "positive control: {} in the arena", c.label);
                    assert_eq!(outside, 0, "{} outside the arena: {at:?}", c.label);
                }
                // C4, UTF-8: in the `Clip` slot while on the clipboard,
                // and then (the accepted exception) in `arboard`'s
                // private anonymous memory; without a clipboard, nowhere.
                8 if clipboard => {
                    assert_eq!(inside, 1, "{} once in the Clip slot", c.label);
                    for h in s.hits.iter().filter(|h| h.canary == k) {
                        let m = &s.maps[h.map];
                        let anon = m.path.is_empty() || m.path == "[heap]";
                        assert!(
                            m.perms == "rw-p" && anon,
                            "{} in {} {:?}",
                            c.label,
                            m.perms,
                            m.path
                        );
                    }
                }
                8 => assert_eq!(inside + outside, 0, "{} found; outside: {at:?}", c.label),
                // No UTF-16LE copy of anything, anywhere.
                _ => assert_eq!(inside + outside, 0, "{} found; outside: {at:?}", c.label),
            }
        }

        // ---- After the clipboard expired: the exception is over.
        std::thread::sleep(Duration::from_secs(CLIP_TIMEOUT + 1));
        run(&mut p, "ls");
        let s = paused_scan(&mut p, &all);
        s.assert_complete();
        for (k, c) in secrets.iter().enumerate() {
            let (inside, outside) = (s.count(k, arena, true), s.count(k, arena, false));
            let at = s.outside(k, arena);
            assert_eq!(outside, 0, "{} outside the arena: {at:?}", c.label);
            let stored = matches!(k, 2 | 4 | 6 | 10);
            assert_eq!(inside >= 1, stored, "{} in the arena: {inside}", c.label);
        }

        // ---- `lock` wipes and pauses before exit.
        p.send("lock\n");
        assert_wiped(&mut p, secrets);
    }

    /// The other exit paths wipe as well: a signal, end of input, and the
    /// idle timeout (30 s, the shortest allowed), each after a secret was
    /// revealed and copied.
    #[test]
    fn t_mem_4_signal_eof_and_idle_exits_are_wiped() {
        let clipboard = display();
        let home = seeded();
        for how in ["SIGTERM", "SIGHUP", "eof", "idle"] {
            let (mut p, _) = session(&home, if how == "idle" { "30" } else { "300" });
            p.send("reveal site password\n");
            assert!(p.answer("Press Enter to clear the screen. ", ""));
            assert!(p.expect(PROMPT));
            run(&mut p, "copy site password");
            assert_eq!(p.saw("Copied. Clearing in"), clipboard, "copy");
            if clipboard && x11() {
                assert!(pasted() == C1.as_bytes(), "C1 is on the clipboard");
            }
            match how {
                "SIGTERM" => p.signal(Signal::SIGTERM),
                "SIGHUP" => p.signal(Signal::SIGHUP),
                "eof" => p.send("\x04"),
                _ => assert!(p.alive_after(Duration::from_secs(25)), "idle too early"),
            }
            assert_wiped(&mut p, &canaries(&[("P", P), ("C1", C1)]));
        }
    }

    /// The scanner skips a guard page inside a readable mapping, and only
    /// that page: a canary on each side of it is still found. The child
    /// is Python (ctypes `mmap` and `madvise`), a child of this process.
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn scan_skips_guard_pages_and_nothing_else() {
        use std::io::{BufRead, Write};
        const CHILD: &str = r#"
import ctypes, mmap, sys
P = mmap.PAGESIZE
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
a = libc.mmap(None, 3 * P, 3, 0x22, -1, 0)
for page in (0, 2):
    ctypes.memmove(a + page * P + 100, b"CANARY-mem-guard-test", 21)
ok = libc.madvise(a + P, P, 102) == 0  # MADV_GUARD_INSTALL
print(f"ready {a}" if ok else "unsupported", flush=True)
sys.stdin.read()
"#;
        let mut child = std::process::Command::new("python3")
            .args(["-I", "-c", CHILD])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("ready line");
        let pid = i32::try_from(child.id()).expect("pid");
        let base: Option<usize> = line
            .trim()
            .strip_prefix("ready ")
            .map(|a| a.parse().expect("addr"));
        let s = base.map(|_| scan(pid, &canaries(&[("guard test", "CANARY-mem-guard-test")])));
        let _ = child.stdin.take().expect("stdin").write_all(b"");
        let _ = child.wait();
        let Some(s) = s else {
            // A kernel before 6.13 has no guard regions: nothing to test.
            assert!(line.trim() == "unsupported", "child failed");
            return;
        };
        assert_eq!(s.guards, 1, "exactly the guard page is skipped");
        let other: Vec<_> = s.unread.iter().filter(|u| !u.contains("\"[v")).collect();
        assert!(other.is_empty(), "unreadable: {other:?}");
        let base = base.expect("base");
        for at in [base + 100, base + 2 * page() + 100] {
            assert!(
                s.hits.iter().any(|h| h.canary == 0 && h.addr == at),
                "a canary next to the guard page was missed"
            );
        }
    }

    /// The exit pause is opt-in: without the variable a `memtest` build
    /// exits at once (the other suites rely on it).
    #[test]
    fn exit_pause_needs_the_environment_variable() {
        let home = seeded();
        let mut p = home.spawn::<&str>(&[]);
        assert!(p.answer("Master password: ", P));
        assert!(p.expect(PROMPT));
        p.send("lock\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(!p.saw("PWV_MEMTEST wiped"));
    }
}
