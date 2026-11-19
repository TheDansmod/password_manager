//! Clipboard tests on X11 (spec Section 14.8): T-CLIP-1 to T-CLIP-4, and
//! the clipboard half of T-E2E-6.
//!
//! They need an X server and `xclip`, which the sandbox lacks, so they run
//! in CI under `xvfb-run` (job `e2e`). Without `DISPLAY` each test returns
//! at once; CI sets `PWV_REQUIRE_X11=1`, which turns a missing display
//! into a failure, so the gate cannot pass vacuously. This is the pattern
//! of `t_store_1_foreign_fs_real_mount` (`PWV_FOREIGN_DIR`).
//!
//! The copied values are test canaries; they are compared, never printed.

mod common;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

/// `copy` refuses a value it cannot serve before it touches the
/// clipboard: text that is not UTF-8, and a value longer than the 1 KiB
/// `Clip` slot (field values may be up to 4 KiB). The slot is left empty,
/// and every error has a fixed, printable message of its own. Runs in every
/// build, with or without a display.
#[test]
fn copy_refuses_values_it_cannot_serve() {
    use pwv::clip::{Clip, Error};
    let mut a = common::vaults::arena();
    let mut s = a.slots().expect("slots");
    let too_long = vec![b'a'; s.clip.capacity() + 1];
    let mut clip = Clip::default();
    for (value, want) in [
        (&b"\xff\xfe"[..], Error::Utf8),
        (&too_long[..], Error::Capacity),
    ] {
        common::vaults::put(&mut s.clip, b"stale");
        assert_eq!(clip.copy(value, &mut s.clip), Err(want));
        assert!(s.clip.is_empty(), "{want:?}: slot not cleared");
    }
    let all = [
        Error::Unsupported,
        Error::Unavailable,
        Error::Utf8,
        Error::Capacity,
    ];
    let mut seen = std::collections::HashSet::new();
    for e in all {
        let m = e.message();
        assert!(
            !m.is_empty() && m.bytes().all(|b| (b' '..=b'~').contains(&b)),
            "{e:?}"
        );
        assert!(seen.insert(m), "{e:?}: message shared with another variant");
    }
}

#[cfg(feature = "clipboard")]
mod x11 {
    use super::common;
    use common::pty::{Home, Pty};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    // x11rb 0.13.2 (the version arboard 3.7.0 uses), verified against the
    // pinned source: `connect`, `ConnectionExt::{create_window,
    // intern_atom, set_selection_owner, convert_selection, get_property,
    // send_event}`, `Event::{SelectionRequest, SelectionNotify}`.
    use x11rb::connection::Connection;
    use x11rb::protocol::Event;
    use x11rb::protocol::xproto::{
        AtomEnum, ConnectionExt, CreateWindowAux, EventMask, SELECTION_NOTIFY_EVENT,
        SelectionNotifyEvent, WindowClass,
    };

    const PW: &str = "Vk7#qunmp2!xbrw9Tz-clip";
    const SECRET: &str = "CANARY-clip-value-1";
    const PROMPT: &str = "pwv> ";

    /// Whether an X display is available. Panics instead of skipping when
    /// `PWV_REQUIRE_X11` is set (CI).
    fn display() -> bool {
        let have = std::env::var_os("DISPLAY").is_some_and(|d| !d.is_empty());
        assert!(
            have || std::env::var_os("PWV_REQUIRE_X11").is_none(),
            "PWV_REQUIRE_X11 is set but DISPLAY is not"
        );
        have
    }

    /// A vault with one entry `site` whose password is [`SECRET`].
    fn seeded() -> Home {
        let home = Home::new();
        let mut p = home.spawn(&["init", "--kdf-memory", "64"]);
        assert!(p.answer("[Y/n] ", "n"));
        assert!(p.answer("New master password: ", PW));
        assert!(p.answer("Repeat: ", PW));
        assert!(p.expect("Vault created."));
        assert_eq!(p.exit_code(), Some(0));
        let mut p = open(&home, &[]);
        p.send("add site\n");
        assert!(p.answer("Field key (. to finish): ", "password"));
        assert!(p.answer("gen [options]? ", "hidden"));
        assert!(p.answer("Value (hidden): ", SECRET));
        assert!(p.answer("Repeat: ", SECRET));
        assert!(p.answer("Field key (. to finish): ", "."));
        assert!(p.expect(PROMPT));
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        home
    }

    fn open(home: &Home, flags: &[&str]) -> Pty {
        let mut p = home.spawn(flags);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect(PROMPT));
        p
    }

    /// `xclip -o` for `target` on the CLIPBOARD selection: the bytes, or
    /// `None` if the selection has no owner or lacks the target.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn xclip_out(target: &str) -> Option<Vec<u8>> {
        let out = Command::new("xclip")
            .args(["-o", "-selection", "clipboard", "-t", target])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("run xclip");
        out.status.success().then_some(out.stdout)
    }

    /// Whether the clipboard holds no text: no owner, or the empty string.
    fn clipboard_empty() -> bool {
        xclip_out("UTF8_STRING").is_none_or(|v| v.is_empty())
    }

    fn clipboard_is(text: &str) -> bool {
        xclip_out("UTF8_STRING").is_some_and(|v| v == text.as_bytes())
    }

    /// Waits up to `d` for `cond`.
    fn eventually(d: Duration, cond: &dyn Fn() -> bool) -> bool {
        let end = Instant::now() + d;
        loop {
            if cond() {
                return true;
            }
            if Instant::now() > end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The X clipboard is one global resource: these tests take turns.
    static X: Mutex<()> = Mutex::new(());

    fn turn() -> std::sync::MutexGuard<'static, ()> {
        X.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn t_clip_1_copy_sets_the_history_exclusion_hint() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "60"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 60 s."));
        assert!(p.expect(PROMPT));
        assert!(clipboard_is(SECRET), "the value is on the clipboard");
        let targets = xclip_out("TARGETS").expect("TARGETS");
        let targets = String::from_utf8_lossy(&targets);
        assert!(
            targets.lines().any(|t| t == "x-kde-passwordManagerHint"),
            "history-exclusion hint missing"
        );
        assert_eq!(
            xclip_out("x-kde-passwordManagerHint"),
            Some(b"secret".to_vec())
        );
        assert!(!p.saw(SECRET), "copy printed the value");
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(clipboard_empty(), "cleared at exit");
    }

    #[test]
    fn t_clip_2_clipboard_is_cleared_after_the_timeout() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        // In the session: the poll loop clears at the deadline.
        let mut p = open(&home, &["--clip-timeout", "5"]);
        p.send("copy site password\n");
        assert!(p.expect("Copied. Clearing in 5 s."));
        assert!(clipboard_is(SECRET));
        std::thread::sleep(Duration::from_secs(3));
        assert!(clipboard_is(SECRET), "cleared too early");
        assert!(
            eventually(Duration::from_secs(5), &clipboard_empty),
            "not cleared"
        );
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        // One-shot: stays alive until the deadline, then clears and exits.
        let mut p = home.spawn(&["--clip-timeout", "5", "copy", "site"]);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect("Copied. Clearing in 5 s (Enter to clear now)."));
        assert!(clipboard_is(SECRET));
        assert!(
            p.alive_after(Duration::from_secs(3)),
            "one-shot copy exited early"
        );
        assert_eq!(p.exit_code(), Some(0));
        assert!(clipboard_empty());
        // One-shot: Enter clears at once.
        let mut p = home.spawn(&["--clip-timeout", "300", "copy", "site"]);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect("(Enter to clear now)."));
        assert!(clipboard_is(SECRET));
        p.send("\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(clipboard_empty());
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn t_clip_3_a_foreign_value_is_not_cleared() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "5"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 5 s."));
        assert!(clipboard_is(SECRET));
        // Another client takes the clipboard before the timeout. `xclip
        // -i` keeps serving the selection in the background.
        let mut other = Command::new("sh")
            .args([
                "-c",
                "printf 'other client' | xclip -i -selection clipboard",
            ])
            .spawn()
            .expect("xclip -i");
        assert!(other.wait().expect("xclip -i").success());
        assert!(clipboard_is("other client"));
        std::thread::sleep(Duration::from_secs(7));
        assert!(clipboard_is("other client"), "a foreign value was cleared");
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(clipboard_is("other client"), "cleared at exit");
    }

    /// Review finding R-09 (Section 11.3 step 3): a clipboard that another
    /// client holds in a format other than text demonstrably does not hold
    /// our value, and is left alone at the deadline and at exit (T-CLIP-3
    /// covers foreign text). The other client is [`image_owner`].
    #[test]
    fn a_foreign_non_text_clipboard_is_not_cleared() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "5"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 5 s."));
        assert!(clipboard_is(SECRET));
        let (stop, ready, lost) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let thread = {
            let (stop, ready, lost) = (stop.clone(), ready.clone(), lost.clone());
            std::thread::spawn(move || image_owner(&stop, &ready, &lost))
        };
        assert!(
            eventually(Duration::from_secs(10), &|| ready.load(Ordering::SeqCst)),
            "the image owner did not take the clipboard"
        );
        let image = || xclip_out("image/png").is_some_and(|v| v == b"not text");
        assert!(image(), "the other client owns the clipboard");
        assert!(xclip_out("UTF8_STRING").is_none(), "no text on offer");
        std::thread::sleep(Duration::from_secs(7));
        assert!(!lost.load(Ordering::SeqCst), "taken at the deadline");
        assert!(image(), "a foreign image was cleared at the deadline");
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(!lost.load(Ordering::SeqCst), "taken at exit");
        assert!(image(), "a foreign image was cleared at exit");
        stop.store(true, Ordering::SeqCst);
        thread.join().expect("image owner");
    }

    /// The fail-closed half of R-09: a clipboard pwv cannot read is set to
    /// the empty string at exit. `xclip -t image/png` answers a request for
    /// text with its data typed `image/png`; arboard 3.7.0 reports that as
    /// `Error::Unknown` ("incorrect type received"), not as a missing
    /// format, so pwv cannot tell what the clipboard holds and clears it.
    /// (The first CI run of `a_foreign_non_text_clipboard_is_not_cleared`,
    /// which used xclip, reached this arm: `clip.rs` line 101 was covered
    /// and line 100 was not.)
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn an_unreadable_clipboard_is_cleared_at_exit() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "300"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 300 s."));
        assert!(clipboard_is(SECRET));
        let mut other = Command::new("sh")
            .args([
                "-c",
                "printf 'not text' | xclip -i -selection clipboard -t image/png",
            ])
            .spawn()
            .expect("xclip -i");
        assert!(other.wait().expect("xclip -i").success());
        assert_eq!(xclip_out("image/png"), Some(b"not text".to_vec()));
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        assert!(
            xclip_out("image/png").is_none(),
            "an unreadable clipboard was left serving"
        );
        assert!(clipboard_empty());
    }

    /// A client that owns CLIPBOARD as `image/png` only and, as ICCCM
    /// requires, refuses every other target (`SelectionNotify` with
    /// property `None`); `TARGETS` lists `TARGETS` and `image/png`. Sets
    /// `lost` if another client takes the selection.
    ///
    /// `xclip -i -t image/png` cannot play this part: xclip answers a
    /// request for any target with its data, typed `image/png`, so
    /// `xclip -o -t UTF8_STRING` printed the image (CI, 2026-11-18), and
    /// arboard 3.7.0 reports the mistyped reply as `Error::Unknown`, which
    /// pwv's `get` maps to "cannot be read" and clears (fail closed).
    fn image_owner(stop: &AtomicBool, ready: &AtomicBool, lost: &AtomicBool) {
        use x11rb::protocol::xproto::PropMode;
        use x11rb::wrapper::ConnectionExt as _;
        let (conn, screen) = x11rb::connect(None).expect("X connection");
        let root = conn.setup().roots[screen].root;
        let win = conn.generate_id().expect("id");
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new(),
        )
        .expect("window");
        let atom = |name: &str| {
            conn.intern_atom(false, name.as_bytes())
                .expect("intern")
                .reply()
                .expect("atom")
                .atom
        };
        let (clipboard, targets, png) = (atom("CLIPBOARD"), atom("TARGETS"), atom("image/png"));
        let none = u32::from(AtomEnum::NONE);
        conn.set_selection_owner(win, clipboard, x11rb::CURRENT_TIME)
            .expect("own");
        let owner = conn
            .get_selection_owner(clipboard)
            .expect("owner")
            .reply()
            .expect("owner")
            .owner;
        assert_eq!(owner, win, "could not take the clipboard");
        ready.store(true, Ordering::SeqCst);
        while !stop.load(Ordering::SeqCst) {
            let Some(event) = conn.poll_for_event().expect("event") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            match event {
                Event::SelectionRequest(req) if req.selection == clipboard => {
                    // ICCCM 2.2: an obsolete requestor names no property.
                    let prop = if req.property == none {
                        req.target
                    } else {
                        req.property
                    };
                    let served = if req.target == targets {
                        conn.change_property32(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            AtomEnum::ATOM,
                            &[targets, png],
                        )
                        .expect("targets");
                        true
                    } else if req.target == png {
                        conn.change_property8(
                            PropMode::REPLACE,
                            req.requestor,
                            prop,
                            png,
                            b"not text",
                        )
                        .expect("image");
                        true
                    } else {
                        false
                    };
                    let reply = SelectionNotifyEvent {
                        response_type: SELECTION_NOTIFY_EVENT,
                        sequence: 0,
                        time: req.time,
                        requestor: req.requestor,
                        selection: req.selection,
                        target: req.target,
                        property: if served { prop } else { none },
                    };
                    conn.send_event(false, req.requestor, EventMask::NO_EVENT, reply)
                        .expect("notify");
                    conn.flush().expect("flush");
                }
                Event::SelectionClear(c) if c.selection == clipboard => {
                    lost.store(true, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    }

    /// What the mock clipboard manager saw.
    #[derive(Default)]
    struct Seen {
        /// `SAVE_TARGETS` requests received.
        requests: usize,
        /// The CLIPBOARD text fetched for each request (`None`: no text).
        saved: Vec<Option<Vec<u8>>>,
    }

    /// A minimal clipboard manager (ICCCM / freedesktop ClipboardManager):
    /// owns `CLIPBOARD_MANAGER`; on a `SAVE_TARGETS` request it fetches the
    /// CLIPBOARD text, records it, and confirms to the requestor.
    fn manager(stop: Arc<AtomicBool>, seen: Arc<Mutex<Seen>>, ready: Arc<AtomicBool>) {
        let (conn, screen) = x11rb::connect(None).expect("X connection");
        let root = conn.setup().roots[screen].root;
        let win = conn.generate_id().expect("id");
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .expect("window");
        let atom = |name: &str| {
            conn.intern_atom(false, name.as_bytes())
                .expect("intern")
                .reply()
                .expect("atom")
                .atom
        };
        let (mgr, save, clipboard, utf8, prop) = (
            atom("CLIPBOARD_MANAGER"),
            atom("SAVE_TARGETS"),
            atom("CLIPBOARD"),
            atom("UTF8_STRING"),
            atom("PWV_TEST_SAVED"),
        );
        conn.set_selection_owner(win, mgr, x11rb::CURRENT_TIME)
            .expect("own");
        conn.flush().expect("flush");
        ready.store(true, Ordering::SeqCst);
        let mut pending: Option<x11rb::protocol::xproto::SelectionRequestEvent> = None;
        let confirm = |req: &x11rb::protocol::xproto::SelectionRequestEvent| {
            let done = SelectionNotifyEvent {
                response_type: SELECTION_NOTIFY_EVENT,
                sequence: 0,
                time: req.time,
                requestor: req.requestor,
                selection: req.selection,
                target: req.target,
                property: req.property,
            };
            conn.send_event(false, req.requestor, EventMask::NO_EVENT, done)
                .expect("notify");
            conn.flush().expect("flush");
        };
        while !stop.load(Ordering::SeqCst) {
            let Some(event) = conn.poll_for_event().expect("event") else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            match event {
                Event::SelectionRequest(req) if req.selection == mgr && req.target == save => {
                    seen.lock().expect("seen").requests += 1;
                    conn.convert_selection(win, clipboard, utf8, prop, x11rb::CURRENT_TIME)
                        .expect("convert");
                    conn.flush().expect("flush");
                    pending = Some(req);
                }
                Event::SelectionNotify(n) if n.requestor == win => {
                    let text = (n.property != u32::from(AtomEnum::NONE)).then(|| {
                        conn.get_property(true, win, prop, AtomEnum::ANY, 0, u32::MAX)
                            .expect("get")
                            .reply()
                            .expect("property")
                            .value
                    });
                    seen.lock().expect("seen").saved.push(text);
                    if let Some(req) = pending.take() {
                        confirm(&req);
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn t_clip_4_the_clipboard_manager_receives_nothing_sensitive_at_exit() {
        if !display() {
            return;
        }
        let _x = turn();
        let (stop, ready) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let seen = Arc::new(Mutex::new(Seen::default()));
        let thread = {
            let (stop, seen, ready) = (stop.clone(), seen.clone(), ready.clone());
            std::thread::spawn(move || manager(stop, seen, ready))
        };
        assert!(eventually(Duration::from_secs(10), &|| ready.load(Ordering::SeqCst)));

        // Positive control: a client that exits while owning an ordinary
        // (not excluded) value hands it to the manager. This proves the
        // mock manager works, so the check below is not vacuous.
        {
            let mut board = arboard::Clipboard::new().expect("clipboard");
            board.set_text("CONTROL-handover").expect("set");
            assert!(clipboard_is("CONTROL-handover"));
        }
        assert!(
            eventually(Duration::from_secs(5), &|| {
                let s = seen.lock().expect("seen");
                s.saved.iter().flatten().any(|v| v == b"CONTROL-handover")
            }),
            "the mock manager did not receive the control value"
        );
        let control_requests = seen.lock().expect("seen").requests;
        assert!(control_requests >= 1);

        // pwv exits while the clipboard still holds the copied value.
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "300"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 300 s."));
        assert!(clipboard_is(SECRET), "the clipboard is ours at exit");
        p.send("quit\n");
        assert_eq!(p.exit_code(), Some(0));
        std::thread::sleep(Duration::from_millis(500));
        assert!(clipboard_empty(), "the clipboard is cleared at exit");
        stop.store(true, Ordering::SeqCst);
        thread.join().expect("manager thread");
        let seen = seen.lock().expect("seen");
        let leaked = seen
            .saved
            .iter()
            .flatten()
            .any(|v| v.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
        assert!(!leaked, "the manager received the copied value");
        // Whatever pwv handed over at exit (possibly nothing) was empty.
        let after: Vec<_> = seen.saved.iter().skip(control_requests).collect();
        assert!(
            after
                .iter()
                .all(|v| v.as_ref().is_none_or(|v| v.is_empty())),
            "the manager received content at exit"
        );
    }

    #[test]
    fn t_e2e_6_idle_exit_clears_the_clipboard() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--idle-timeout", "30", "--clip-timeout", "300"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 300 s."));
        assert!(p.expect(PROMPT));
        assert!(clipboard_is(SECRET));
        assert!(p.alive_after(Duration::from_secs(25)), "exited early");
        assert!(clipboard_is(SECRET), "cleared before the idle timeout");
        assert!(p.expect("Locked after 30 s without input."));
        assert_eq!(p.exit_code(), Some(0));
        assert!(
            clipboard_empty(),
            "idle exit left the value on the clipboard"
        );
    }

    #[test]
    fn signal_exit_clears_the_clipboard() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "300"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 300 s."));
        assert!(clipboard_is(SECRET));
        p.signal(common::pty::Signal::SIGTERM);
        assert_eq!(p.exit_code(), Some(0));
        assert!(clipboard_empty(), "SIGTERM left the value on the clipboard");
    }

    /// Review finding R-08: a panic unwinds through the session, whose
    /// `Drop` clears the clipboard; the exit code is 5.
    #[cfg(feature = "memtest")]
    #[test]
    fn panic_exit_clears_the_clipboard() {
        if !display() {
            return;
        }
        let _x = turn();
        let home = seeded();
        let mut p = open(&home, &["--clip-timeout", "300"]);
        p.send("copy site\n");
        assert!(p.expect("Copied. Clearing in 300 s."));
        assert!(p.expect(PROMPT));
        assert!(clipboard_is(SECRET));
        p.send("__panic\n");
        assert!(p.expect("internal error"));
        assert_eq!(p.exit_code(), Some(5));
        assert!(clipboard_empty(), "a panic left the value on the clipboard");
    }
}
