//! End-to-end tests through a PTY (spec Section 14.7): T-E2E-1 to
//! T-E2E-12, plus the binary-level halves of T-CRY-2, T-STORE-5, and
//! T-STORE-9.
//!
//! The captured screen holds the test's canary secrets, so no assertion
//! prints it: every check is a boolean or a count (rule 9). Each test has
//! its own home under `/tmp`; nothing touches the real home directory.
//! Vaults use the lowest KDF cost this build may write.

mod common;

use common::pty::{Home, Pty, Signal, listing};
use common::vaults::{Model, unlock_model};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

/// A chosen master password that passes the strength policy.
const PW: &str = "Vk7#qunmp2!xbrw9Tz-e2e";
/// Another one, for `passwd`.
const PW2: &str = "Hq4@zzmrt8?pdxk3Wn-e2e";
const PROMPT: &str = "pwv> ";
const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";
const KDF: [&str; 2] = ["--kdf-memory", "64"];

/// `pwv init` with the chosen password `pw`; true if the vault was created.
fn init_with(home: &Home, pw: &str) -> bool {
    let mut p = home.spawn(&["init", KDF[0], KDF[1]]);
    let ok = p.answer("[Y/n] ", "n")
        && p.answer("New master password: ", pw)
        && p.answer("Repeat: ", pw)
        && p.expect("Vault created.");
    ok && p.exit_code() == Some(0)
}

fn init(home: &Home) {
    assert!(init_with(home, PW), "init failed");
}

/// Starts the REPL and unlocks with `pw`.
fn open_with(home: &Home, pw: &str) -> Pty {
    let mut p = home.spawn::<&str>(&[]);
    assert!(p.answer("Master password: ", pw), "no password prompt");
    assert!(p.expect(PROMPT), "no REPL prompt");
    p
}

fn open(home: &Home) -> Pty {
    open_with(home, PW)
}

/// Types one REPL command and waits for the next prompt.
fn run(p: &mut Pty, line: &str) {
    p.send(line);
    p.send("\n");
    assert!(p.expect(PROMPT), "no prompt after a command");
}

fn quit(mut p: Pty) {
    p.send("quit\n");
    assert_eq!(p.exit_code(), Some(0), "quit");
}

/// The vault's content, decrypted independently of the binary under test.
fn model(home: &Home, pw: &str) -> Model {
    let file = std::fs::read(home.vault()).expect("vault file");
    unlock_model(&file, pw.as_bytes()).expect("vault opens").1
}

/// `add <name>` with typed and hidden fields: (key, value, hidden).
fn add(p: &mut Pty, name: &str, fields: &[(&str, &str, bool)]) {
    p.send(&format!("add {name}\n"));
    for (key, value, hidden) in fields {
        assert!(p.answer("Field key (. to finish): ", key));
        if *hidden {
            assert!(p.answer("gen [options]? ", "hidden"));
            assert!(p.answer("Value (hidden): ", value));
            assert!(p.answer("Repeat: ", value));
        } else {
            assert!(p.answer("gen [options]? ", "typed"));
            assert!(p.answer("Value: ", value));
        }
    }
    assert!(p.answer("Field key (. to finish): ", "."));
    assert!(p.expect(PROMPT));
}

/// A home with a vault holding one entry `site` (user, password).
fn seeded() -> Home {
    let home = Home::new();
    init(&home);
    let mut p = open(&home);
    add(
        &mut p,
        "site",
        &[
            ("user", "alice", false),
            ("password", "CANARY-e2e-pw-1", true),
        ],
    );
    quit(p);
    home
}

fn stat(home: &Home) -> (u64, i64, i64, u64) {
    let m = std::fs::metadata(home.vault()).expect("vault metadata");
    (m.ino(), m.mtime(), m.mtime_nsec(), m.size())
}

// ------------------------------------------------------------ T-E2E-1

#[test]
fn t_e2e_1_init_weak_password_refused() {
    for weak in [
        "password1password1",
        "short-Xk7#",
        "qwertyuiopasdfghjkl",
        "1qaz2wsx3edc4rfv",
        "P@ssw0rd2024!!!!",
    ] {
        let home = Home::new();
        let mut p = home.spawn(&["init", KDF[0], KDF[1]]);
        assert!(p.answer("[Y/n] ", "n"));
        assert!(p.answer("New master password: ", weak));
        assert!(p.answer("Repeat: ", weak));
        assert!(p.expect("password refused"));
        assert_eq!(p.exit_code(), Some(1));
        assert!(!home.vault().exists(), "no vault for a refused password");
        // Echo is on (the answer `n` is visible), yet the password is not.
        assert!(p.saw("[Y/n] n"), "positive control: echo is on");
        assert!(!p.saw(weak), "typed password visible");
    }
}

#[test]
fn t_e2e_1_init_mismatch_refused() {
    let home = Home::new();
    let mut p = home.spawn(&["init", KDF[0], KDF[1]]);
    assert!(p.answer("[Y/n] ", "n"));
    assert!(p.answer("New master password: ", PW));
    assert!(p.answer("Repeat: ", PW2));
    assert!(p.expect("the two passwords differ"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(!home.vault().exists());
    assert!(!p.saw(PW) && !p.saw(PW2), "typed password visible");
}

#[test]
fn t_e2e_1_init_weak_password_needs_flag_and_sentence() {
    let weak = "password1password1";
    // With the flag but the wrong sentence: refused.
    let home = Home::new();
    let mut p = home.spawn(&["init", KDF[0], KDF[1], "--accept-weak-password"]);
    assert!(p.answer("[Y/n] ", "n"));
    assert!(p.answer("New master password: ", weak));
    assert!(p.answer("Repeat: ", weak));
    assert!(p.expect("this password is weak"));
    assert!(p.answer("to continue: ", "yes"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(!home.vault().exists());
    // With the flag and the sentence: accepted.
    let mut p = home.spawn(&["init", KDF[0], KDF[1], "--accept-weak-password"]);
    assert!(p.answer("[Y/n] ", "n"));
    assert!(p.answer("New master password: ", weak));
    assert!(p.answer("Repeat: ", weak));
    assert!(p.answer("to continue: ", "I accept a weak master password"));
    assert!(p.expect("Vault created."));
    assert_eq!(p.exit_code(), Some(0));
    assert!(!p.saw(weak), "typed password visible");
    assert!(model(&home, weak).is_empty());
}

#[test]
fn t_e2e_1_init_generated_passphrase_accepted() {
    let other = Home::new();
    // A wrong confirmation is refused.
    let mut wrong = other.spawn(&["init", KDF[0], KDF[1]]);
    assert!(wrong.answer("[Y/n] ", "y"));
    assert!(wrong.answer("Press Enter to clear the screen. ", ""));
    assert!(wrong.answer("Type the passphrase to confirm: ", "not-the-passphrase"));
    assert!(wrong.expect("does not match"));
    assert_eq!(wrong.exit_code(), Some(1));
    assert!(!other.vault().exists());
    let home = Home::new();
    let mut p = home.spawn(&["init", KDF[0], KDF[1]]);
    assert!(p.expect("strongly recommended"));
    assert!(p.answer("[Y/n] ", ""));
    assert!(p.expect("Write it down:"));
    assert!(p.expect("Press Enter to clear the screen. "));
    let phrase = p
        .between("Write it down:\r\n\r\n  ", "\r\n")
        .expect("passphrase");
    assert_eq!(phrase.split('-').count(), 6, "six words");
    p.send("\n");
    assert!(p.expect("\x1b[H\x1b[2J\x1b[3J"), "screen cleared");
    // The right one creates the vault; it was displayed once, never echoed.
    assert!(p.answer("Type the passphrase to confirm: ", &phrase));
    assert!(p.expect("Vault created."));
    assert_eq!(p.exit_code(), Some(0));
    assert_eq!(p.count(&phrase), 1, "shown once, never echoed");
    assert!(model(&home, &phrase).is_empty());
    quit(open_with(&home, &phrase));
}

#[test]
fn t_e2e_1_init_refuses_existing_vault() {
    let home = Home::new();
    init(&home);
    let before = std::fs::read(home.vault()).expect("vault");
    let mut p = home.spawn(&["init", KDF[0], KDF[1]]);
    assert!(p.expect("a vault already exists"));
    assert_eq!(p.exit_code(), Some(1));
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
}

// ------------------------------------------------------------ T-E2E-2

#[test]
fn t_e2e_2_missing_vault_names_init_and_creates_nothing() {
    let home = Home::new();
    let before = listing(home.dir.path());
    let commands: [&[&str]; 9] = [
        &[],
        &["ls"],
        &["show", "x"],
        &["reveal", "x", "y"],
        &["copy", "x"],
        &["add", "x"],
        &["set", "x", "y"],
        &["rm", "x"],
        &["passwd"],
    ];
    for args in commands {
        let mut p = home.spawn(args);
        assert!(p.expect("pwv init"), "error names `pwv init`");
        assert_eq!(p.exit_code(), Some(1));
        assert!(!p.saw("Master password"), "no prompt without a vault");
        assert_eq!(listing(home.dir.path()), before, "nothing created");
    }
}

// ------------------------------------------------------------ T-E2E-3

#[test]
fn t_e2e_3_ls_names_only_and_show_masks() {
    let home = Home::new();
    init(&home);
    let long = "CANARY-e2e-".repeat(30);
    let mut p = open(&home);
    add(
        &mut p,
        "alpha",
        &[("user", "CANARY-e2e-plain", false), ("pin", "7", true)],
    );
    add(&mut p, "\"Beta mail\"", &[("password", &long, true)]);
    let (before, keys) = (p.count("CANARY-e2e-plain"), p.count("user"));
    run(&mut p, "ls");
    assert!(p.saw("ls\r\nBeta mail\r\nalpha\r\n"), "names in byte order");
    run(&mut p, "ls ALP");
    run(&mut p, "ls nothing-matches");
    assert_eq!(p.count("CANARY-e2e-plain"), before, "ls printed a value");
    assert_eq!(p.count("user"), keys, "ls printed a key");
    // show: 8 bullets per sensitive value, whatever its length.
    run(&mut p, "show alpha");
    assert!(p.saw(&format!("  pin: {MASK}\r\n")));
    assert!(p.saw("  user: CANARY-e2e-plain\r\n"));
    run(&mut p, "show \"Beta mail\"");
    assert!(p.saw(&format!("  password: {MASK}\r\n")));
    assert_eq!(p.count("\u{2022}"), 16, "exactly 8 bullets per value");
    assert!(!p.saw(&long), "sensitive value visible");
    run(&mut p, "show missing");
    assert!(p.saw("pwv: no such entry"));
    quit(p);
}

// ------------------------------------------------------------ T-E2E-4

#[test]
fn t_e2e_4_reveal_once_then_clears_screen_and_scrollback() {
    let home = seeded();
    let mut p = open(&home);
    p.send("reveal site password\n");
    assert!(p.expect("CANARY-e2e-pw-1"));
    assert!(p.expect("Press Enter to clear the screen. "));
    assert!(!p.saw("\x1b[2J"), "cleared before Enter");
    p.send("\n");
    assert!(p.expect("\x1b[H\x1b[2J\x1b[3J"));
    assert!(p.expect(PROMPT));
    assert_eq!(p.count("CANARY-e2e-pw-1"), 1, "value appears once");
    run(&mut p, "reveal site nofield");
    assert!(p.saw("pwv: no such field"));
    quit(p);
    // One-shot: the same behaviour.
    let mut p = home.spawn(&["reveal", "site", "password"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.answer("Press Enter to clear the screen. ", ""));
    assert_eq!(p.exit_code(), Some(0));
    assert!(p.saw("\x1b[H\x1b[2J\x1b[3J"));
    assert_eq!(p.count("CANARY-e2e-pw-1"), 1);
}

// ------------------------------------------------------------ T-E2E-5

#[test]
fn t_e2e_5_add_and_set_errors_keep_the_session() {
    let home = seeded();
    let mut p = open(&home);
    // add: existing name refused.
    run(&mut p, "add site");
    assert!(p.saw("an entry with that name already exists"));
    // add: duplicate key (ASCII case-folded), invalid key (control
    // character), over-length key: error, prompt again, session continues.
    p.send("add shop\n");
    assert!(p.answer("Field key (. to finish): ", "user"));
    assert!(p.answer("gen [options]? ", "typed"));
    assert!(p.answer("Value: ", "bob"));
    assert!(p.answer("Field key (. to finish): ", "USER"));
    assert!(p.expect("the entry already has a field with that key"));
    assert!(p.answer("Field key (. to finish): ", "bad\x01key"));
    assert!(p.expect("pwv: "));
    assert!(p.answer("Field key (. to finish): ", &"k".repeat(65)));
    assert!(p.expect("pwv: "));
    assert!(p.answer("Field key (. to finish): ", "pin"));
    assert!(p.answer("gen [options]? ", "nonsense"));
    assert!(p.expect("answer typed, hidden, or gen"));
    assert!(p.answer("Field key (. to finish): ", "pin"));
    assert!(p.answer("gen [options]? ", "hidden"));
    assert!(p.answer("Value (hidden): ", "1111"));
    assert!(p.answer("Repeat: ", "2222"));
    assert!(p.expect("the two entries differ"));
    assert!(p.answer("Field key (. to finish): ", "pin"));
    assert!(p.answer("gen [options]? ", "gen --len 7"));
    assert!(p.expect("--len must be between 8 and 128"));
    assert!(p.answer("Field key (. to finish): ", "pin"));
    assert!(p.answer("gen [options]? ", "gen --len 12 --classes d"));
    assert!(p.expect("Entropy: "));
    assert!(p.answer("Field key (. to finish): ", "."));
    assert!(p.expect(PROMPT));
    // set: unknown entry, invalid key, bad options, mismatch.
    run(&mut p, "set nowhere user");
    assert!(p.saw("pwv: no such entry"));
    run(&mut p, &format!("set shop {}", "k".repeat(65)));
    run(&mut p, "set shop note --len 12");
    assert!(p.saw("generation options need --gen"));
    run(&mut p, "set shop note \\x");
    assert!(p.saw("invalid backslash sequence"));
    run(&mut p, "set shop \"unterminated");
    assert!(p.saw("unterminated quote"));
    p.send("set shop note\n");
    assert!(p.answer("Value: ", "typed note"));
    assert!(p.expect(PROMPT));
    quit(p);
    let m = model(&home, PW);
    let shop = &m.iter().find(|e| e.0 == "shop").expect("shop").1;
    assert_eq!(shop.len(), 3);
    assert_eq!(shop[0], ("user".into(), false, "bob".into()));
    assert_eq!(
        (shop[1].0.as_str(), shop[1].1, shop[1].2.len()),
        ("pin", true, 12)
    );
    assert!(shop[1].2.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(shop[2], ("note".into(), false, "typed note".into()));
}

#[test]
fn t_e2e_5_set_replacing_a_sensitive_value_needs_confirmation() {
    let home = seeded();
    let mut p = open(&home);
    p.send("set site password\n");
    assert!(p.answer("Replace the sensitive value? [y/N] ", ""));
    assert!(p.expect("not confirmed; nothing was changed"));
    assert!(p.expect(PROMPT));
    p.send("set site password\n");
    assert!(p.answer("Replace the sensitive value? [y/N] ", "y"));
    assert!(p.answer("Value (hidden): ", "CANARY-e2e-pw-2"));
    assert!(p.answer("Repeat: ", "CANARY-e2e-pw-2"));
    assert!(p.expect(PROMPT));
    p.send("set site user --sensitive\n");
    assert!(p.answer("Value (hidden): ", "carol"));
    assert!(p.answer("Repeat: ", "carol"));
    assert!(p.expect(PROMPT));
    p.send("unset site user\n");
    assert!(p.answer("Remove the field? [y/N] ", "n"));
    assert!(p.expect(PROMPT));
    run(&mut p, "mvfield site password Passphrase");
    run(&mut p, "mvfield site user Passphrase");
    assert!(p.saw("the entry already has a field with that key"));
    run(&mut p, "mv site site2");
    quit(p);
    assert!(!{
        let mut q = open(&home);
        let seen = q.saw("CANARY-e2e-pw-2");
        quit(q);
        seen
    });
    let m = model(&home, PW);
    assert_eq!(
        m,
        vec![(
            "site2".to_owned(),
            vec![
                ("user".into(), true, "carol".into()),
                ("Passphrase".into(), true, "CANARY-e2e-pw-2".into()),
            ]
        )]
    );
}

#[test]
fn t_e2e_5_overlong_password_line_is_rejected_not_truncated() {
    let home = seeded();
    let mut p = home.spawn(&["ls"]);
    // Longer than the 1 KiB password slot: drained and refused. A
    // truncated line would be a wrong password (exit 2) instead.
    assert!(p.answer("Master password: ", &"x".repeat(1500)));
    assert!(p.expect("input too long"));
    assert_eq!(p.exit_code(), Some(1));
}

// ------------------------------------------------------------ T-E2E-6

#[test]
fn t_e2e_6_idle_timeout_locks_and_exits_0() {
    let home = seeded();
    let mut p = home.spawn(&["--idle-timeout", "30"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect(PROMPT));
    assert!(p.alive_after(Duration::from_secs(25)), "exited early");
    assert!(p.expect("Locked after 30 s without input."));
    assert_eq!(p.exit_code(), Some(0));
    // Out of range values are refused.
    for bad in ["29", "3601", "x"] {
        let mut p = home.spawn(&["--idle-timeout", bad]);
        assert!(p.expect("--idle-timeout needs a number from 30 to 3600"));
        assert_eq!(p.exit_code(), Some(1));
    }
}

// ------------------------------------------------------------ T-E2E-7

/// The terminal's settings, read through the PTY master.
fn termios(p: &Pty) -> (u64, u64, u64, u64) {
    let t = rustix::termios::tcgetattr(p.fd()).expect("tcgetattr");
    (
        u64::from(t.input_modes.bits()),
        u64::from(t.output_modes.bits()),
        u64::from(t.control_modes.bits()),
        u64::from(t.local_modes.bits()),
    )
}

#[test]
fn t_e2e_7_sigint_cancels_the_command() {
    let home = seeded();
    let before = std::fs::read(home.vault()).expect("vault");
    let mut p = open(&home);
    // At the prompt: a new prompt, the session lives.
    p.signal(Signal::SIGINT);
    assert!(p.expect("cancelled"));
    assert!(p.expect(PROMPT));
    // Inside the guided add: the entry is abandoned, nothing is saved.
    p.send("add halfway\n");
    assert!(p.answer("Field key (. to finish): ", "user"));
    assert!(p.answer("gen [options]? ", "typed"));
    assert!(p.answer("Value: ", "x"));
    assert!(p.expect("Field key (. to finish): "));
    p.signal(Signal::SIGINT);
    assert!(p.expect("cancelled"));
    assert!(p.expect(PROMPT));
    // Ctrl-C typed at a hidden prompt: cancelled, echo restored.
    let saved = termios(&p);
    p.send("set site password\n");
    assert!(p.answer("Replace the sensitive value? [y/N] ", "y"));
    assert!(p.expect("Value (hidden): "));
    assert_ne!(termios(&p), saved, "echo is off at a hidden prompt");
    p.send("\x03");
    assert!(p.expect(PROMPT));
    assert_eq!(termios(&p), saved, "termios restored after SIGINT");
    let typed = p.count("halfway");
    run(&mut p, "ls");
    assert_eq!(p.count("halfway"), typed, "cancelled entry listed");
    quit(p);
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
}

#[test]
fn t_e2e_7_sigterm_sighup_sigquit_exit_cleanly_and_restore_termios() {
    let home = seeded();
    for sig in [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGQUIT] {
        let before = std::fs::read(home.vault()).expect("vault");
        let mut p = open(&home);
        let saved = termios(&p);
        // Mid-command, at a hidden prompt, where echo is off.
        p.send("set site password\n");
        assert!(p.answer("Replace the sensitive value? [y/N] ", "y"));
        assert!(p.expect("Value (hidden): "));
        assert_ne!(termios(&p), saved, "echo is off at a hidden prompt");
        p.signal(sig);
        assert_eq!(p.exit_code(), Some(0), "orderly exit");
        assert_eq!(termios(&p), saved, "termios restored");
        assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
        assert!(
            listing(&home.dir.path().join("cwd")).is_empty(),
            "core file"
        );
    }
}

// ------------------------------------------------------------ T-E2E-8

#[test]
fn t_e2e_8_control_and_bidi_characters_are_shown_as_escapes() {
    let home = seeded();
    let evil = "ev\u{202e}il";
    let title = "\x1b]0;PWNED\x07";
    let mut p = open(&home);
    // ESC and BEL can never enter a name, key, or value.
    run(&mut p, &format!("add \"x{title}\""));
    run(&mut p, &format!("mv site \"x{title}\""));
    p.send("set site note\n");
    assert!(p.answer("Value: ", &format!("v{title}")));
    assert!(p.expect(PROMPT));
    // A bidi override is valid content.
    p.send(&format!("add {evil}\n"));
    assert!(p.answer("Field key (. to finish): ", "k\u{2066}"));
    assert!(p.answer("gen [options]? ", "typed"));
    assert!(p.answer("Value: ", "v\u{202a}"));
    assert!(p.answer("Field key (. to finish): ", "."));
    assert!(p.expect(PROMPT));
    assert_eq!(p.count("\x1b"), 0, "raw ESC reached the terminal");
    assert_eq!(p.count("\x07"), 0, "raw BEL reached the terminal");
    quit(p);
    let m = model(&home, PW);
    assert_eq!(m.len(), 2, "no entry with ESC or BEL was created");
    assert_eq!(
        m[0],
        (
            evil.to_owned(),
            vec![("k\u{2066}".into(), false, "v\u{202a}".into())]
        )
    );
    // One-shot, so the name is not echoed by typing: the stored name, key,
    // and value reach the terminal only as visible escapes.
    for args in [&["ls"][..], &["show", evil], &["reveal", evil, "k\u{2066}"]] {
        let mut p = home.spawn(args);
        assert!(p.answer("Master password: ", PW));
        if args[0] == "reveal" {
            assert!(p.answer("Press Enter to clear the screen. ", ""));
        }
        assert_eq!(p.exit_code(), Some(0));
        for raw in ["\u{202e}", "\u{2066}", "\u{202a}", "\x07", "\x1b]"] {
            assert_eq!(p.count(raw), 0, "raw control or bidi character");
        }
        let want = match args[0] {
            "ls" => "ev\\u{202e}il\r\n",
            "show" => "  k\\u{2066}: v\\u{202a}\r\n",
            _ => "v\\u{202a}",
        };
        assert!(p.saw(want), "visible escape missing");
    }
}

// ------------------------------------------------------------ T-E2E-9

#[test]
fn t_e2e_9_rm_needs_the_exact_name_and_there_is_no_export() {
    let home = seeded();
    let before = std::fs::read(home.vault()).expect("vault");
    let mut p = open(&home);
    for wrong in ["", "y", "yes", "Site", "site "] {
        p.send("rm site\n");
        assert!(p.answer("Type the entry name to confirm deletion: ", wrong));
        assert!(p.expect("nothing was deleted"));
        assert!(p.expect(PROMPT));
    }
    run(&mut p, "rm missing");
    assert!(p.saw("pwv: no such entry"));
    for absent in ["export", "dump", "export --all", "save"] {
        let n = p.count("pwv: unknown command");
        run(&mut p, absent);
        assert_eq!(p.count("pwv: unknown command"), n + 1);
    }
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
    p.send("rm site\n");
    assert!(p.answer("Type the entry name to confirm deletion: ", "site"));
    assert!(p.expect(PROMPT));
    quit(p);
    assert!(model(&home, PW).is_empty());
    for absent in ["export", "dump"] {
        let mut p = home.spawn(&[absent]);
        assert!(p.expect("pwv: unknown command"));
        assert_eq!(p.exit_code(), Some(1));
    }
}

// ------------------------------------------------------------ T-E2E-10

/// A canonical body as `printf` octal escapes.
fn body_escapes(m: &Model) -> String {
    let mut a = common::vaults::arena();
    let mut s = a.slots().expect("slots");
    common::vaults::write_body(m, &mut s.vault_a);
    octal(s.vault_a.expose())
}

fn octal(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:03o}")).collect()
}

fn entry(name: &str, value: &str) -> (String, Vec<(String, bool, String)>) {
    (
        name.to_owned(),
        vec![("password".into(), true, value.into())],
    )
}

/// `printf <escapes> | pwv import --from-stdin <args>`, unlocked.
fn import(home: &Home, escapes: &str, args: &[&str]) -> Pty {
    let mut all = vec!["import", "--from-stdin"];
    all.extend_from_slice(args);
    let mut p = Pty::spawn_piped(&format!("printf '{escapes}'"), home.command(&all));
    assert!(p.answer("Master password: ", PW));
    p
}

#[test]
fn t_e2e_10_import_valid_invalid_and_tty() {
    let home = seeded();
    let incoming = vec![
        entry("mail", "CANARY-e2e-imp-1"),
        entry("site", "CANARY-e2e-imp-2"),
    ];
    let valid = body_escapes(&incoming);
    // A name conflict aborts by default; nothing changes.
    let before = std::fs::read(home.vault()).expect("vault");
    let mut p = import(&home, &valid, &[]);
    assert!(p.expect("an entry with that name already exists"));
    assert_eq!(p.exit_code(), Some(1));
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
    // Invalid input: precise refusal naming the constraint and the entry.
    let mut a = common::vaults::arena();
    let mut s = a.slots().expect("slots");
    common::vaults::write_body(&incoming, &mut s.vault_a);
    let mut bytes = s.vault_a.expose().to_vec();
    let at = bytes.windows(4).position(|w| w == b"mail").expect("name");
    bytes[at] = 0x01;
    for (escapes, want) in [
        (octal(&bytes), "import refused: "),
        (octal(&bytes[..100]), "import refused: "),
        (octal(b"not a body"), "import refused: "),
    ] {
        let mut p = import(&home, &escapes, &[]);
        assert!(p.expect(want));
        assert_eq!(p.exit_code(), Some(1));
        assert!(!p.saw("CANARY-e2e-imp"), "refusal printed content");
        assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
    }
    let mut p = import(&home, &octal(&bytes), &[]);
    assert!(p.expect("(entry 0)"), "the refusal names the entry index");
    assert_eq!(p.exit_code(), Some(1));
    // An empty pipe (the producer failed) is refused as before, and since
    // M8 before the master password is asked (DESIGN_NOTES, M8).
    let mut p = Pty::spawn_piped("printf ''", home.command(&["import", "--from-stdin"]));
    assert!(p.expect("import refused: "));
    assert_eq!(p.exit_code(), Some(1));
    assert!(
        !p.saw("Master password"),
        "asked for a password for nothing"
    );
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
    // Valid, with suffix: merged with one save.
    let mut p = import(&home, &valid, &["--on-conflict", "suffix"]);
    assert!(p.expect("Imported 2 entries"));
    assert_eq!(p.exit_code(), Some(0));
    assert!(!p.saw("CANARY-e2e-imp"), "import printed content");
    let m = model(&home, PW);
    let names: Vec<&str> = m.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(names, ["mail", "site", "site (imported)"]);
    assert_eq!(m[2].1[0].2, "CANARY-e2e-imp-2");
    // A terminal as stdin is refused, in one-shot mode and in the REPL;
    // in one-shot mode before the master password is asked (review
    // finding R-03: the refusal used to follow a full key derivation).
    let mut p = home.spawn(&["import", "--from-stdin"]);
    assert!(p.expect("import reads a canonical body from a pipe"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(
        !p.saw("Master password"),
        "asked for a password for nothing"
    );
    let mut p = home.spawn(&["import"]);
    assert!(p.expect("import reads a canonical body from a pipe"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(!p.saw("Master password"));
    // A regular file as stdin is refused too: "stdin must be a pipe"
    // (Section 12.2 step 1), so that plaintext need never be on disk.
    // Positive control: the same bytes through a pipe are imported below.
    let fresh = vec![entry("filed", "CANARY-e2e-imp-3")];
    let file = home.dir.path().join("body.bin");
    let mut a = common::vaults::arena();
    let mut s = a.slots().expect("slots");
    common::vaults::write_body(&fresh, &mut s.vault_a);
    common::pty::overwrite(&file, s.vault_a.expose());
    let cmd = home.command(&["import", "--from-stdin"]);
    let script = format!("exec \"$0\" \"$@\" < '{}'", file.display());
    let mut p = Pty::spawn_shell(&script, cmd);
    assert!(p.expect("import reads a canonical body from a pipe"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(!p.saw("Master password"));
    assert_eq!(model(&home, PW), m, "a regular file was imported");
    let mut p = import(&home, &body_escapes(&fresh), &[]);
    assert!(p.expect("Imported 1 entries"));
    assert_eq!(p.exit_code(), Some(0));
    let m = model(&home, PW);
    assert_eq!(m.len(), 4);
    let mut p = open(&home);
    run(&mut p, "import --from-stdin");
    assert!(p.saw("import reads a canonical body from a pipe"));
    run(&mut p, "import");
    quit(p);
    assert_eq!(model(&home, PW), m);
}

/// Since M8 `import` reads the pipe to its end before it asks for the
/// master password, because the producer of the pipe (the migration
/// script's `gpg`) asks for the legacy passphrase on the same terminal.
#[test]
fn t_e2e_10_import_reads_the_pipe_before_asking_for_the_master_password() {
    let home = seeded();
    let body = body_escapes(&vec![entry("mail", "CANARY-e2e-imp-3")]);
    // A producer that asks a question on the terminal first.
    let producer = format!(
        "{{ stty -echo; printf 'Legacy: ' > /dev/tty; read x < /dev/tty; stty echo; \
         [ \"$x\" = old-secret ] && printf '{body}'; }}"
    );
    let cmd = || home.command(&["import", "--from-stdin"]);
    let mut p = Pty::spawn_piped(&producer, cmd());
    assert!(p.expect("Legacy: "));
    // `pwv` started long ago; it must not have asked yet.
    std::thread::sleep(Duration::from_millis(500));
    assert!(!p.saw("Master password"), "two prompts at once");
    p.send("old-secret\n");
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect("Imported 1 entries"));
    assert_eq!(p.exit_code(), Some(0));
    assert!(!p.saw("old-secret") && !p.saw("CANARY-e2e-imp"));
    // The producer gives up: no master password prompt at all.
    let before = std::fs::read(home.vault()).expect("vault");
    let mut p = Pty::spawn_piped(&producer, cmd());
    assert!(p.answer("Legacy: ", "wrong"));
    assert!(p.expect("import refused: the pipe delivered nothing"));
    assert_eq!(p.exit_code(), Some(1));
    assert!(!p.saw("Master password"));
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
    // A wrong master password after a good pipe: exit 2, nothing merged.
    let mut p = Pty::spawn_piped(&producer, cmd());
    assert!(p.answer("Legacy: ", "old-secret"));
    assert!(p.answer("Master password: ", PW2));
    assert_eq!(p.exit_code(), Some(2));
    assert_eq!(std::fs::read(home.vault()).expect("vault"), before);
}

// ------------------------------------------------------------ T-E2E-11

#[test]
fn t_e2e_11_passwd_then_only_the_new_password_opens() {
    let home = seeded();
    let old_file = std::fs::read(home.vault()).expect("vault");
    let mut p = open(&home);
    // A wrong current password changes nothing.
    p.send("passwd\n");
    assert!(p.answer("Current master password: ", PW2));
    assert!(p.expect("wrong password or damaged vault"));
    assert!(p.expect(PROMPT));
    assert_eq!(std::fs::read(home.vault()).expect("vault"), old_file);
    p.send("passwd\n");
    assert!(p.answer("Current master password: ", PW));
    assert!(p.answer("[Y/n] ", "n"));
    assert!(p.answer("New master password: ", PW2));
    assert!(p.answer("Repeat: ", PW2));
    assert!(p.expect("Master password changed."));
    assert!(p.expect(PROMPT));
    // The session keeps working under the new key.
    p.send("set site note\n");
    assert!(p.answer("Value: ", "after passwd"));
    assert!(p.expect(PROMPT));
    quit(p);
    assert!(!{
        let mut q = open_with(&home, PW2);
        run(&mut q, "show site");
        let leaked = q.saw(PW) || q.saw(PW2);
        quit(q);
        leaked
    });
    let m = model(&home, PW2);
    assert_eq!(m[0].1.len(), 3);
    let mut old = home.spawn(&["ls"]);
    assert!(old.answer("Master password: ", PW));
    assert!(old.expect("wrong password or damaged vault"));
    assert_eq!(old.exit_code(), Some(2));
    // Salt and wrapped key were rotated.
    let new_file = std::fs::read(home.vault()).expect("vault");
    assert_ne!(old_file[44..76], new_file[44..76], "salt");
    assert_ne!(old_file[100..148], new_file[100..148], "wrapped DEK");
    assert_eq!(old_file[12..28], new_file[12..28], "vault ID kept");
}

/// Review finding R-11: after `passwd` the backups still open with the
/// old password. Without the flag a notice says so and they stay; with
/// `--purge-backups` they are deleted once the new vault is saved.
#[test]
fn passwd_notice_and_purge_backups() {
    let home = seeded();
    let dir = home.vault().parent().expect("dir").to_owned();
    let backups = |dir: &std::path::Path| {
        common::pty::listing(dir)
            .into_iter()
            .filter(|n| n.starts_with("vault.pwv."))
            .filter(|n| n.as_bytes().last().is_some_and(u8::is_ascii_digit))
            .count()
    };
    let change = |p: &mut Pty, from: &str, to: &str, flag: &str| {
        p.send(&format!("passwd {flag}\n"));
        assert!(p.answer("Current master password: ", from));
        assert!(p.answer("[Y/n] ", "n"));
        assert!(p.answer("New master password: ", to));
        assert!(p.answer("Repeat: ", to));
        assert!(p.expect("Master password changed."));
    };
    let mut p = open(&home);
    change(&mut p, PW, PW2, "");
    assert!(p.expect("still open with the old password"));
    assert!(p.expect(PROMPT));
    let n = backups(&dir);
    assert!(n >= 1, "backups kept without the flag");
    let old = std::fs::read(dir.join("vault.pwv.1")).expect(".1");
    assert!(
        common::vaults::unlock_model(&old, PW.as_bytes()).is_ok(),
        "control"
    );
    change(&mut p, PW2, PW, "--purge-backups");
    assert!(p.expect("Backups deleted."));
    assert!(p.expect(PROMPT));
    assert_eq!(backups(&dir), 0, "backups left after --purge-backups");
    quit(p);
    assert_eq!(model(&home, PW)[0].0, "site", "the vault itself is intact");
}

/// Review finding R-12: `passwd` checks the KDF parameters before it asks
/// for anything or derives a key; and the Section 5.4 notice that the KDF
/// memory was not locked is printed also when the password proves wrong.
#[test]
fn passwd_checks_parameters_first_and_kdf_notice_on_failure() {
    let home = seeded();
    let mut p = open(&home);
    p.send("passwd --kdf-time 1\n");
    assert!(p.expect("KDF parameters out of range"));
    assert!(p.expect(PROMPT));
    assert!(!p.saw("Current master password"), "asked before checking");
    quit(p);
    // At most 4 MiB lockable (lowered only, never raised): enough for the
    // arena, which the harness already locks, not for the 64 MiB KDF region.
    let notice = "the key-derivation memory could not be locked";
    let sh = "l=$(ulimit -l); { [ \"$l\" = unlimited ] || [ \"$l\" -gt 4096 ]; } && ulimit -l 4096; \
              exec \"$0\" \"$@\"";
    for (pw, code) in [(PW, 0), (PW2, 2)] {
        let mut p = Pty::spawn_shell(sh, home.command(&["ls"]));
        assert!(p.answer("Master password: ", pw));
        assert!(p.expect(notice), "no notice (exit code {code})");
        assert_eq!(p.exit_code(), Some(code));
    }
}

// ------------------------------------------------------------ T-E2E-12

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
fn t_e2e_12_no_terminal_is_exit_4() {
    use std::process::{Command, Stdio};
    let home = seeded();
    // No controlling terminal at all (setsid), stdin and stdout redirected.
    for args in [&["ls"][..], &[], &["doctor"], &["import", "--from-stdin"]] {
        let mut cmd = Command::new("setsid");
        cmd.arg("--wait").arg(env!("CARGO_BIN_EXE_pwv")).args(args);
        home.env(&mut cmd);
        let out = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("setsid");
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty(), "nothing on fd 1");
    }
    // A terminal exists, but stdin is redirected: refused for everything
    // except `import --from-stdin`.
    for args in [&["ls"][..], &[], &["init"], &["import"]] {
        let mut p = Pty::spawn_piped("true", home.command(args));
        assert!(p.expect("standard input must be a terminal"));
        assert_eq!(p.exit_code(), Some(4));
        assert!(!p.saw("Master password"));
    }
}

// ---------------------------------------- T-CRY-2, T-STORE-5, T-STORE-9

#[test]
fn t_cry_2_wrong_password_and_damage_look_the_same() {
    let home = seeded();
    let outcome = |home: &Home, pw: &str| {
        let mut p = home.spawn(&["ls"]);
        assert!(p.answer("Master password: ", pw));
        let code = p.exit_code();
        (code, p.tail_after("Master password: "))
    };
    let wrong = outcome(&home, PW2);
    let mut file = std::fs::read(home.vault()).expect("vault");
    let last = file.len() - 20;
    file[last] ^= 1;
    common::pty::overwrite(&home.vault(), &file);
    let damaged = outcome(&home, PW);
    assert_eq!(wrong.0, Some(2));
    assert_eq!(wrong, damaged, "same exit code and same bytes on screen");
}

#[test]
fn t_store_5_rollback_warning_no_exits_3_yes_continues() {
    let home = seeded();
    let old = std::fs::read(home.vault()).expect("vault");
    let mut p = open(&home);
    for i in 0..3 {
        p.send("set site note\n");
        assert!(p.answer("Value: ", &format!("v{i}")));
        assert!(p.expect(PROMPT));
    }
    quit(p);
    let newest = pwv::format::parse_header(&std::fs::read(home.vault()).expect("vault"))
        .expect("header")
        .generation;
    common::pty::overwrite(&home.vault(), &old);
    for answer in ["no", "", "y", "YES"] {
        let mut p = home.spawn::<&str>(&[]);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect("This vault is older than the last version saved on this machine"));
        assert!(p.answer("Type yes to continue: ", answer));
        assert_eq!(p.exit_code(), Some(3));
        assert_eq!(std::fs::read(home.vault()).expect("vault"), old);
    }
    let mut p = home.spawn::<&str>(&[]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.answer("Type yes to continue: ", "yes"));
    assert!(p.expect(PROMPT));
    p.send("set site note\n");
    assert!(p.answer("Value: ", "after rollback"));
    assert!(p.expect(PROMPT));
    quit(p);
    let h =
        pwv::format::parse_header(&std::fs::read(home.vault()).expect("vault")).expect("header");
    assert_eq!(h.generation, newest + 1, "the counter never regresses");
    // One-shot mode (review finding R-02): the answer must not overwrite
    // the command's arguments, so after `yes` the command still addresses
    // `site` (it read `s`, or nothing, before the fix).
    common::pty::overwrite(&home.vault(), &old);
    let mut p = home.spawn(&["show", "site"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.answer("Type yes to continue: ", "yes"));
    assert!(p.expect("alice"), "the one-shot command lost its argument");
    assert_eq!(p.exit_code(), Some(0));
    assert!(!p.saw("no such entry"));
    let mut p = home.spawn(&["mv", "site", "renamed"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.answer("Type yes to continue: ", "yes"));
    assert_eq!(p.exit_code(), Some(0));
    let m = model(&home, PW);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].0, "renamed", "the rename went to the wrong entry");
    let h =
        pwv::format::parse_header(&std::fs::read(home.vault()).expect("vault")).expect("header");
    assert_eq!(h.generation, newest + 2, "the counter never regresses");
}

/// Review finding R-08: a panic (reached through the `memtest` command
/// `__panic`) unwinds, writes only the fixed message, restores the
/// terminal, and exits with code 5 (internal error), not Rust's 101.
#[cfg(feature = "memtest")]
#[test]
fn panic_exits_with_code_5_and_the_fixed_message() {
    let home = seeded();
    let mut p = home.spawn(&["__panic"]);
    assert!(p.expect("internal error"));
    assert_eq!(p.exit_code(), Some(5));
    assert!(!p.saw("panicked"), "the panic payload was formatted");
    let mut p = open(&home);
    run(&mut p, "show site");
    p.send("__panic\n");
    assert!(p.expect("internal error"));
    assert_eq!(p.exit_code(), Some(5));
    assert!(!p.saw("panicked"));
}

#[test]
fn t_store_9_read_only_commands_never_write() {
    let home = seeded();
    let dir = home.vault().parent().expect("dir").to_owned();
    let (before, names) = (stat(&home), listing(&dir));
    let state = std::fs::read(home.dir.path().join("state/pwv/state")).expect("state");
    let mut p = open(&home);
    for line in [
        "ls",
        "ls si",
        "show site",
        "copy site",
        "gen",
        "gen --words 4",
        "doctor",
        "help",
    ] {
        run(&mut p, line);
    }
    p.send("reveal site password\n");
    assert!(p.answer("Press Enter to clear the screen. ", ""));
    assert!(p.expect(PROMPT));
    quit(p);
    for args in [&["ls"][..], &["show", "site"], &["doctor"]] {
        let mut p = home.spawn(args);
        assert!(p.answer("Master password: ", PW) || args[0] == "doctor");
        assert!(p.exit_code().is_some());
    }
    assert_eq!(stat(&home), before, "inode, mtime, or size changed");
    assert_eq!(listing(&dir), names, "files created or removed");
    assert_eq!(
        std::fs::read(home.dir.path().join("state/pwv/state")).expect("state"),
        state
    );
    // Positive control: a mutating command does change the file.
    let mut p = open(&home);
    p.send("set site note\n");
    assert!(p.answer("Value: ", "x"));
    assert!(p.expect(PROMPT));
    quit(p);
    assert_ne!(stat(&home), before);
}

// ------------------------------------------------------- other commands

#[test]
fn one_shot_commands_and_help() {
    let home = seeded();
    let mut p = home.spawn(&["help"]);
    for c in pwv::cli::COMMANDS.iter().filter(|c| !c.help.is_empty()) {
        assert!(p.expect(c.usage), "help lists every command");
    }
    assert_eq!(p.exit_code(), Some(0));
    assert!(!p.saw("Master password"), "help needs no vault");
    let mut p = home.spawn(&["show", "site"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect(&format!("  password: {MASK}\r\n")));
    assert_eq!(p.exit_code(), Some(0));
    let mut p = home.spawn(&["mv", "site", "new name"]);
    assert!(p.answer("Master password: ", PW));
    assert_eq!(p.exit_code(), Some(0));
    assert_eq!(model(&home, PW)[0].0, "new name");
    // `--` ends the options, so a name starting with `--` is addressable.
    let mut p = home.spawn(&["mv", "--", "new name", "--odd"]);
    assert!(p.answer("Master password: ", PW));
    assert_eq!(p.exit_code(), Some(0));
    assert_eq!(model(&home, PW)[0].0, "--odd");
    for (args, want) in [
        (&["show"][..], "missing argument"),
        (&["show", "a", "b"], "too many arguments"),
        (&["ls", "--nope"], "unknown option for this command"),
        (&["--nope"], "unknown option --nope"),
        (
            &["--arena-size", "5"],
            "--arena-size needs a number from 256 to 6144",
        ),
        (
            &["--clip-timeout", "4"],
            "--clip-timeout needs a number from 5 to 300",
        ),
    ] {
        let mut p = home.spawn(args);
        assert!(p.expect(want));
        assert_eq!(p.exit_code(), Some(1));
    }
}

#[test]
fn gen_reports_entropy_and_shows_the_value_only_on_request() {
    let home = Home::new();
    let clipboard = cfg!(feature = "clipboard")
        && (std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some());
    let refusal = if cfg!(feature = "clipboard") {
        "pwv: the clipboard is not available"
    } else {
        "pwv: this build has no clipboard support"
    };
    let mut p = home.spawn(&[
        "--clip-timeout",
        "5",
        "gen",
        "--len",
        "16",
        "--classes",
        "ld",
    ]);
    assert!(p.expect("Entropy: "));
    if clipboard {
        assert!(p.answer("(Enter to clear now).", ""));
        assert_eq!(p.exit_code(), Some(0));
    } else {
        assert!(p.expect(refusal));
        assert_eq!(p.exit_code(), Some(4));
    }
    assert!(!p.saw("Master password"), "gen needs no vault");
    let mut p = home.spawn(&["gen", "--words", "5", "--sep", ".", "--show"]);
    assert!(p.expect("Entropy: 88."), "5 x 17.65 bits");
    assert!(p.expect(" bits\r\n"));
    // The value is written by a later `write(2)`: wait for its line end
    // before reading it back (`between` reads only what has arrived).
    assert!(p.expect("\r\n"), "value line");
    let phrase = p.between(" bits\r\n", "\r\n").expect("value");
    assert_eq!(phrase.split('.').count(), 5);
    if clipboard {
        p.send("\n");
    }
    assert!(p.exit_code().is_some());
    for (args, want) in [
        (
            &["gen", "--len", "7"][..],
            "--len must be between 8 and 128",
        ),
        (&["gen", "--words", "3"], "--words must be between 4 and 16"),
        (
            &["gen", "--sep", "e"],
            "--sep must be one printable ASCII character",
        ),
        (
            &["gen", "--len", "12", "--words", "4"],
            "cannot be combined",
        ),
        (
            &["gen", "--classes", "lx"],
            "--classes takes each of l, u, d, s",
        ),
        (&["gen", "--len", "x"], "the option needs a number"),
    ] {
        let mut p = home.spawn(args);
        assert!(p.expect(want));
        assert_eq!(p.exit_code(), Some(1));
    }
}

#[test]
fn copy_without_a_clipboard_fails_cleanly() {
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return; // with a display, tests/clip.rs covers `copy`
    }
    let home = seeded();
    let mut p = home.spawn(&["copy", "site"]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect(if cfg!(feature = "clipboard") {
        "pwv: the clipboard is not available"
    } else {
        "pwv: this build has no clipboard support"
    }));
    assert_eq!(p.exit_code(), Some(4));
    assert!(!p.saw("CANARY-e2e-pw-1"));
}

#[test]
fn doctor_reports_every_check_and_exits_0_or_1() {
    let home = Home::new();
    let mut p = home.spawn(&["doctor"]);
    for check in [
        "Arena lockable",
        "KDF memory lockable",
        "Swap",
        "Hibernation",
        "Core dumps",
        "ptrace scope",
        "Vault location",
        "Clipboard history",
    ] {
        assert!(p.expect(check), "doctor lists every check");
    }
    let code = p.exit_code().expect("exit");
    assert_eq!(code, i32::from(p.saw("[FAIL]")), "exit 1 iff a check fails");
    assert!(p.saw("no vault yet"), "doctor creates nothing");
    assert!(!home.vault().exists());
}

// ------------------------------------------------------- PTY harness

/// A child that writes without end is killed and fails its test at
/// `SCREEN_CAP`, with a fixed message; the capture must not grow until
/// the machine is out of memory (DESIGN_NOTES, M7 CI round 1).
#[test]
#[should_panic(expected = "more than SCREEN_CAP bytes")]
fn harness_stops_a_child_that_floods_the_terminal() {
    let mut p = Pty::spawn(common::shell_command("exec yes"));
    // Never appears; `expect` must end by the cap, not by its deadline.
    let _ = p.expect("pwv> ");
}
