//! Legacy migration (spec Sections 12 and 14.12): T-MIG-1 to T-MIG-3, and
//! T-E2E-10's real pipe, `tools/migrate_legacy.py | pwv import
//! --from-stdin`, on a PTY.
//!
//! The legacy vault is JSON encrypted by GnuPG (owner decision
//! 2026-11-16, `DESIGN_NOTES`); the script lets `gpg` decrypt it. Every test
//! runs with a **stand-in** `gpg` first on `PATH`: a small program that
//! checks the exact arguments the script passes, asks for the passphrase
//! on `/dev/tty` like `gpg` in loopback mode, and really decrypts a test
//! cipher, so no plaintext fixture is ever on disk. Where
//! `PWV_LEGACY_PYTHON` names a Python with the legacy program's imports
//! (CI job `e2e`), every test also runs with the **real** `gpg`, on a
//! fixture written by the original `encrypted_pw_mgr.py`
//! (`tests/legacy/make_fixture.py`). `PWV_REQUIRE_GPG` makes that
//! mandatory, so the gate cannot pass on the stand-in alone.
//!
//! Values and passphrases are test canaries; they are compared, never
//! printed (rule 9).

mod common;

use common::pty::{Home, Pty, overwrite};
use common::vaults::{Model, unlock_model};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

/// The pwv master password.
const PW: &str = "Vk7#qunmp2!xbrw9Tz-mig";
/// The legacy vault's passphrase.
const LEGACY: &str = "CANARY-mig-legacy-passphrase";
const ASK: &str = "Enter passphrase: ";
const NOTHING: &str = "import refused: the pipe delivered nothing";
const FAILED: &str = "migrate_legacy: gpg could not decrypt the vault";

/// The stand-in `gpg`. It accepts only the command line the script must
/// use, records that it ran, asks like `gpg --pinentry-mode loopback`,
/// and decrypts `STANDIN1 | SHA-256(pass | plain) | plain XOR stream`.
const STAND_IN: &str = r#"#!/usr/bin/env python3
import hashlib, os, sys, termios
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "called"), "w").close()
a = sys.argv[1:]
want = ["--quiet", "--no-symkey-cache", "--pinentry-mode", "loopback", "--decrypt", "--"]
if a[:6] != want or len(a) != 7:
    sys.stderr.write("stand-in gpg: unexpected arguments\n")
    sys.exit(64)
blob = open(a[6], "rb").read()
if blob[:8] != b"STANDIN1":
    sys.stderr.write("gpg: no valid OpenPGP data found.\n")
    sys.exit(2)
tty = os.open("/dev/tty", os.O_RDWR)
old = termios.tcgetattr(tty)
new = termios.tcgetattr(tty)
new[3] &= ~termios.ECHO
termios.tcsetattr(tty, termios.TCSADRAIN, new)
os.write(tty, b"Enter passphrase: ")
pw = b""
while not pw.endswith(b"\n"):
    c = os.read(tty, 1)
    if not c:
        break
    pw += c
termios.tcsetattr(tty, termios.TCSADRAIN, old)
os.write(tty, b"\n")
pw = pw.rstrip(b"\n")
tag, ct = blob[8:40], blob[40:]
ks = b"".join(hashlib.sha256(pw + i.to_bytes(4, "big")).digest() for i in range(len(ct) // 32 + 1))
plain = bytes(x ^ y for x, y in zip(ct, ks))
if hashlib.sha256(pw + plain).digest() != tag:
    sys.stderr.write("gpg: decryption failed: Bad session key\n")
    sys.exit(2)
sys.stdout.buffer.write(plain)
"#;

/// Which `gpg` the script finds.
#[derive(Clone, Debug)]
enum Gpg {
    StandIn,
    /// The real one; the fixture is written by the legacy program, run
    /// with this Python.
    Real(PathBuf),
}

/// The stand-in always; the real `gpg` where the environment provides it.
fn backends() -> Vec<Gpg> {
    let python = std::env::var_os("PWV_LEGACY_PYTHON").filter(|p| !p.is_empty());
    assert!(
        python.is_some() || std::env::var_os("PWV_REQUIRE_GPG").is_none(),
        "PWV_REQUIRE_GPG is set but PWV_LEGACY_PYTHON is not"
    );
    let mut all = vec![Gpg::StandIn];
    all.extend(python.map(|p| Gpg::Real(PathBuf::from(p))));
    all
}

/// A legacy value.
#[derive(Clone)]
enum V {
    S(String),
    /// What the legacy `add_secure_password` stores for a length below 8:
    /// `None` (audit finding B2).
    B2,
    /// Not text: the script must refuse it.
    Num,
}

fn s(v: &str) -> V {
    V::S(v.to_owned())
}

/// Entries and their fields, in the legacy file's order.
type Legacy = Vec<(String, Vec<(String, V)>)>;

/// A JSON string as the legacy `json.dumps` writes it (`ensure_ascii`).
fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// The legacy JSON. `for_driver`: B2 as the sentinel the fixture driver
/// replaces by the original program's own `None`; else `null`.
fn json(data: &Legacy, for_driver: bool) -> String {
    let entries: Vec<String> = data
        .iter()
        .map(|(name, fields)| {
            let fields: Vec<String> = fields
                .iter()
                .map(|(k, v)| {
                    let v = match v {
                        V::S(v) => json_string(v),
                        V::B2 if for_driver => json_string("@@B2@@"),
                        V::B2 => "null".to_owned(),
                        V::Num => "5".to_owned(),
                    };
                    format!("{}: {v}", json_string(k))
                })
                .collect();
            format!("{}: {{{}}}", json_string(name), fields.join(", "))
        })
        .collect();
    format!("{{{}}}", entries.join(", "))
}

/// The stand-in's cipher.
fn stand_in_encrypt(pass: &str, plain: &[u8]) -> Vec<u8> {
    let mut out = b"STANDIN1".to_vec();
    out.extend(
        Sha256::new()
            .chain_update(pass)
            .chain_update(plain)
            .finalize(),
    );
    for (i, block) in plain.chunks(32).enumerate() {
        let n = u32::try_from(i).expect("blocks");
        let ks = Sha256::new()
            .chain_update(pass)
            .chain_update(n.to_be_bytes())
            .finalize();
        out.extend(block.iter().zip(ks).map(|(p, k)| p ^ k));
    }
    out
}

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// One test's home: a pwv vault, a `gpg` (stand-in on `PATH`, or the real
/// one with its own `GNUPGHOME`), and the legacy vault files.
struct Rig {
    home: Home,
    gpg: Gpg,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.stop_agent();
    }
}

impl Rig {
    #[allow(
        clippy::disallowed_methods,
        reason = "tests write their fixtures; the ban binds src/"
    )]
    fn new(gpg: &Gpg) -> Rig {
        let home = Home::new();
        let mut p = home.spawn(&["init", "--kdf-memory", "64"]);
        let ok = p.answer("[Y/n] ", "n")
            && p.answer("New master password: ", PW)
            && p.answer("Repeat: ", PW)
            && p.expect("Vault created.");
        assert!(ok && p.exit_code() == Some(0), "init");
        for dir in ["bin", "gnupg"] {
            let d = home.dir.path().join(dir);
            std::fs::create_dir(&d).expect("mkdir");
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        if matches!(gpg, Gpg::StandIn) {
            let exe = home.dir.path().join("bin/gpg");
            std::fs::write(&exe, STAND_IN).expect("stand-in");
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Rig {
            home,
            gpg: gpg.clone(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.home.dir.path().join(name)
    }

    /// The environment in which `gpg` means this rig's `gpg`.
    fn env(&self, cmd: &mut Command) {
        self.home.env(cmd);
        cmd.env("LC_ALL", "C")
            .env("GNUPGHOME", self.path("gnupg"))
            .env_remove("GPG_AGENT_INFO");
        if matches!(self.gpg, Gpg::StandIn) {
            let old = std::env::var("PATH").expect("PATH");
            cmd.env("PATH", format!("{}:{old}", self.path("bin").display()));
        }
    }

    /// Whether the stand-in was started at all.
    fn stand_in_called(&self) -> bool {
        self.path("bin/called").exists()
    }

    /// Runs `cmd` with `input` on stdin; true on success.
    fn feed(mut cmd: Command, input: &[u8]) -> bool {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn");
        let wrote = child.stdin.take().expect("stdin").write_all(input);
        child.wait().expect("wait").success() && wrote.is_ok()
    }

    /// A legacy vault holding `data`, encrypted with `LEGACY`. With the
    /// real `gpg` it is written by the original program's `encrypt_data`.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn legacy_vault(&self, name: &str, data: &Legacy) -> PathBuf {
        let out = self.path(name);
        match &self.gpg {
            Gpg::StandIn => overwrite(
                &out,
                &stand_in_encrypt(LEGACY, json(data, false).as_bytes()),
            ),
            Gpg::Real(python) => {
                let mut cmd = Command::new(python);
                cmd.arg(repo("tests/legacy/make_fixture.py")).arg(&out);
                self.env(&mut cmd);
                cmd.env("PWV_LEGACY_PASSPHRASE", LEGACY);
                assert!(
                    Self::feed(cmd, json(data, true).as_bytes()),
                    "the legacy program wrote no fixture"
                );
                let head = std::fs::read(&out).expect("fixture");
                assert!(
                    head.first().is_some_and(|b| b & 0x80 != 0),
                    "the fixture is not an OpenPGP message"
                );
            }
        }
        out
    }

    /// `bytes` (not JSON) encrypted with `LEGACY` as a legacy vault.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn encrypted(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let out = self.path(name);
        match &self.gpg {
            Gpg::StandIn => overwrite(&out, &stand_in_encrypt(LEGACY, bytes)),
            Gpg::Real(_) => {
                // The payload is an exploit, not a secret: it may be a file.
                let plain = self.path("payload.bin");
                overwrite(&plain, bytes);
                let mut cmd = Command::new("gpg");
                cmd.args(["--batch", "--yes", "--quiet", "--no-symkey-cache"])
                    .args(["--pinentry-mode", "loopback"])
                    .args([
                        "--passphrase-fd",
                        "0",
                        "--symmetric",
                        "--cipher-algo",
                        "AES256",
                    ])
                    .arg("-o")
                    .arg(&out)
                    .arg(&plain);
                self.env(&mut cmd);
                assert!(Self::feed(cmd, LEGACY.as_bytes()), "gpg --symmetric");
            }
        }
        out
    }

    /// The script's command line, for `sh`.
    fn script(vault: &Path) -> String {
        format!(
            "python3 -I '{}' --vault '{}'",
            repo("tools/migrate_legacy.py").display(),
            vault.display()
        )
    }

    /// `migrate_legacy.py --vault <vault> | pwv import --from-stdin <args>`.
    fn pipe(&self, vault: &Path, args: &[&str]) -> Pty {
        let mut all = vec!["import", "--from-stdin"];
        all.extend_from_slice(args);
        let mut cmd = self.home.command(&all);
        self.env(&mut cmd);
        Pty::spawn_piped(&Self::script(vault), cmd)
    }

    /// The same, up to and including the legacy passphrase. `pwv` must
    /// not have asked for anything yet: it reads the pipe first.
    fn pipe_with(&self, vault: &Path, passphrase: &str, args: &[&str]) -> Pty {
        let mut p = self.pipe(vault, args);
        assert!(p.expect(ASK), "gpg did not ask for the passphrase");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            p.count("Master password"),
            0,
            "pwv asked before the pipe ended"
        );
        p.send(passphrase);
        p.send("\n");
        p
    }

    /// Stops this rig's `gpg-agent`, so no daemon outlives the test.
    #[allow(
        clippy::disallowed_methods,
        reason = "tests spawn children; Section 5.7 binds the binary only"
    )]
    fn stop_agent(&self) {
        if matches!(self.gpg, Gpg::Real(_)) {
            let mut cmd = Command::new("gpgconf");
            cmd.args(["--kill", "gpg-agent"]);
            self.env(&mut cmd);
            let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }

    fn vault_bytes(&self) -> Vec<u8> {
        std::fs::read(self.home.vault()).expect("vault file")
    }

    fn model(&self) -> Model {
        unlock_model(&self.vault_bytes(), PW.as_bytes())
            .expect("vault opens")
            .1
    }
}

/// The failed-migration ending: the script's message, then `pwv` refuses
/// the empty pipe with exit code 1, without asking for the master password.
fn assert_nothing_imported(p: &mut Pty, rig: &Rig, before: &[u8]) {
    assert!(p.expect(NOTHING), "pwv did not refuse the empty pipe");
    assert_eq!(p.exit_code(), Some(1));
    assert_eq!(
        p.count("Master password"),
        0,
        "pwv asked for the master password"
    );
    assert!(rig.vault_bytes() == before, "the vault changed");
}

fn good() -> Legacy {
    let f = |k: &str, v: V| (k.to_owned(), v);
    vec![
        (
            "github".into(),
            vec![
                f("Username", s("octo")),
                f("Password", s("CANARY-mig-pw-1")),
                f("Email", s("octo@example.org")),
            ],
        ),
        (
            "Bank".into(),
            vec![
                f("PIN", s("CANARY-mig-pin-2")),
                f("note", s("line 1\nline 2")),
            ],
        ),
        (
            "zeta \u{e9}\u{4e2d}\u{1f511}".into(),
            vec![f("Password", V::B2)],
        ),
        ("empty".into(), vec![]),
        (
            "api".into(),
            vec![
                f("API Key", s("CANARY-mig-key-3 \"quoted\" \\ back")),
                f("Recovery Codes", s("CANARY-mig-rc-4\nsecond")),
                f("password hint", s("not sensitive by its key")),
            ],
        ),
    ]
}

/// What `good()` must become: sorted by name bytes, field order kept,
/// sensitivity by the default list, the B2 `None` an empty value.
fn good_model() -> Model {
    let f = |k: &str, sens: bool, v: &str| (k.to_owned(), sens, v.to_owned());
    vec![
        (
            "Bank".into(),
            vec![
                f("PIN", true, "CANARY-mig-pin-2"),
                f("note", false, "line 1\nline 2"),
            ],
        ),
        (
            "api".into(),
            vec![
                f("API Key", true, "CANARY-mig-key-3 \"quoted\" \\ back"),
                f("Recovery Codes", true, "CANARY-mig-rc-4\nsecond"),
                f("password hint", false, "not sensitive by its key"),
            ],
        ),
        ("empty".into(), vec![]),
        (
            "github".into(),
            vec![
                f("Username", false, "octo"),
                f("Password", true, "CANARY-mig-pw-1"),
                f("Email", false, "octo@example.org"),
            ],
        ),
        (
            "zeta \u{e9}\u{4e2d}\u{1f511}".into(),
            vec![f("Password", true, "")],
        ),
    ]
}

// -------------------------------------------------------------- T-MIG-1

#[test]
fn t_mig_1_legacy_fixture_imports_the_expected_model_with_its_warning() {
    for gpg in backends() {
        let rig = Rig::new(&gpg);
        let vault = rig.legacy_vault("legacy.enc", &good());
        let mut p = rig.pipe_with(&vault, LEGACY, &[]);
        // The B2 `None` became an empty value; the warning names the
        // entry, escaped to ASCII.
        assert!(
            p.expect(
                "warning: entry \"zeta \\u00e9\\u4e2d\\ud83d\\udd11\": \
                 an empty value replaces a missing one"
            ),
            "{gpg:?}: no B2 warning"
        );
        assert!(
            p.expect("5 entries, 9 fields, 1 warnings"),
            "{gpg:?}: summary"
        );
        assert!(p.answer("Master password: ", PW), "{gpg:?}: no pwv prompt");
        assert!(p.expect("Imported 5 entries"), "{gpg:?}: not imported");
        assert_eq!(p.exit_code(), Some(0));
        assert!(rig.model() == good_model(), "{gpg:?}: unexpected model");
        // Nothing secret reached the screen: no value, neither password.
        for secret in ["CANARY-mig", "line 1", "octo", PW] {
            assert_eq!(p.count(secret), 0, "{gpg:?}: content on the screen");
        }
        assert_eq!(matches!(gpg, Gpg::StandIn), rig.stand_in_called());

        // A second run meets the same names: refused by default, merged
        // with `--on-conflict suffix`.
        let before = rig.vault_bytes();
        let mut p = rig.pipe_with(&vault, LEGACY, &[]);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect("an entry with that name already exists"));
        assert_eq!(p.exit_code(), Some(1));
        assert!(
            rig.vault_bytes() == before,
            "{gpg:?}: a refused import wrote"
        );
        let mut p = rig.pipe_with(&vault, LEGACY, &["--on-conflict", "suffix"]);
        assert!(p.answer("Master password: ", PW));
        assert!(p.expect("Imported 5 entries"));
        assert_eq!(p.exit_code(), Some(0));
        let m = rig.model();
        assert_eq!(m.len(), 10);
        assert!(m.iter().any(|e| e.0 == "github (imported)"));
    }
}

#[test]
fn t_mig_1_key_case_collision_and_invalid_entries_are_refused() {
    let f = |k: &str, v: V| (k.to_owned(), v);
    for gpg in backends() {
        let rig = Rig::new(&gpg);
        let before = rig.vault_bytes();
        // `Password` and `password` in one entry: the whole migration
        // aborts, naming the entry; valid entries are not imported either.
        let mut data = good();
        data.push((
            "dup".into(),
            vec![
                f("Password", s("CANARY-mig-d1")),
                f("password", s("CANARY-mig-d2")),
            ],
        ));
        let vault = rig.legacy_vault("collision.enc", &data);
        let mut p = rig.pipe_with(&vault, LEGACY, &[]);
        assert!(
            p.expect("refused: entry \"dup\": two keys differ only in letter case"),
            "{gpg:?}: collision not reported"
        );
        assert!(p.expect("migrate_legacy: nothing was written"));
        assert_nothing_imported(&mut p, &rig, &before);
        assert_eq!(p.count("CANARY-mig"), 0, "{gpg:?}: content on the screen");

        // Every other refusal, all listed in one run, names escaped.
        let long = "k".repeat(65);
        let bad: Legacy = vec![
            ("esc\u{1b}]0;title\u{7}".into(), vec![f("user", s("u"))]),
            (" leading".into(), vec![f("user", s("u"))]),
            ("number".into(), vec![f("pin", V::Num)]),
            ("tab".into(), vec![f("note", s("a\tb"))]),
            ("ctl-key".into(), vec![f("a\u{85}b", s("v"))]),
            ("long-key".into(), vec![f(&long, s("v"))]),
            ("bidi \u{202e}".into(), vec![f("", s("v"))]),
            ("fine".into(), vec![f("user", s("CANARY-mig-fine"))]),
        ];
        let vault = rig.legacy_vault("bad.enc", &bad);
        let mut p = rig.pipe_with(&vault, LEGACY, &[]);
        assert!(p.expect("migrate_legacy: nothing was written"));
        assert_nothing_imported(&mut p, &rig, &before);
        for want in [
            "refused: entry \"esc\\u001b]0;title\\u0007\": control character in the name",
            "refused: entry \" leading\": leading or trailing whitespace in the name",
            "refused: entry \"number\": a value is not text",
            "refused: entry \"tab\": control character other than a line feed in a value",
            "refused: entry \"ctl-key\": control character in a key",
            "refused: entry \"long-key\": a key must be 1 to 64 bytes of UTF-8",
            "refused: entry \"bidi \\u202e\": a key must be 1 to 64 bytes of UTF-8",
        ] {
            assert!(p.saw(want), "{gpg:?}: missing refusal: {want}");
        }
        assert_eq!(
            p.count("refused: entry"),
            7,
            "{gpg:?}: the valid entry is not listed"
        );
        assert!(
            !p.saw("\u{1b}]0;"),
            "{gpg:?}: a raw escape reached the terminal"
        );
        assert!(
            !p.saw("\u{202e}"),
            "{gpg:?}: a raw bidi override reached the terminal"
        );
        assert_eq!(p.count("CANARY-mig"), 0, "{gpg:?}: content on the screen");
    }
}

/// Waits for `a` or `b` to appear more often than `seen` counted them.
fn either(p: &mut Pty, a: &str, b: &str, seen: (usize, usize)) -> Option<bool> {
    let end = Instant::now() + common::pty::PATIENCE;
    while Instant::now() < end {
        if p.count(a) > seen.0 {
            return Some(true);
        }
        if p.count(b) > seen.1 {
            return Some(false);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn t_mig_1_wrong_legacy_passphrase_imports_nothing() {
    for gpg in backends() {
        let rig = Rig::new(&gpg);
        let before = rig.vault_bytes();
        let vault = rig.legacy_vault("legacy.enc", &good());
        let mut p = rig.pipe(&vault, &[]);
        // gpg may ask again after a wrong passphrase; answer wrongly each
        // time (at most five) until the script reports the failure.
        let mut asked = 0;
        loop {
            match either(&mut p, ASK, FAILED, (asked, 0)) {
                Some(true) if asked < 5 => {
                    asked += 1;
                    p.send("CANARY-mig-wrong-passphrase\n");
                }
                Some(false) => break,
                _ => panic!("{gpg:?}: no refusal after a wrong passphrase"),
            }
        }
        assert!(asked >= 1, "{gpg:?}: the passphrase was never asked");
        assert_nothing_imported(&mut p, &rig, &before);
        assert_eq!(p.count("CANARY-mig"), 0, "{gpg:?}: content on the screen");
    }
}

/// More than a pipe buffer (64 KiB): the script must deliver all of it,
/// and `pwv` must read to the end before it asks.
#[test]
fn t_mig_1_a_vault_larger_than_the_pipe_buffer_arrives_whole() {
    let rig = Rig::new(&Gpg::StandIn);
    let data: Legacy = (0..800)
        .map(|i| {
            (
                format!("entry-{i:04}"),
                vec![
                    ("Username".to_owned(), s(&format!("user-{i}@example.org"))),
                    (
                        "Password".to_owned(),
                        s(&format!("CANARY-mig-big-{i:05}-{}", "x".repeat(40))),
                    ),
                ],
            )
        })
        .collect();
    assert!(json(&data, false).len() > 80_000);
    let vault = rig.legacy_vault("big.enc", &data);
    let mut p = rig.pipe_with(&vault, LEGACY, &[]);
    assert!(p.expect("800 entries, 1600 fields, 0 warnings"));
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect("Imported 800 entries"));
    assert_eq!(p.exit_code(), Some(0));
    let m = rig.model();
    assert_eq!(m.len(), 800);
    assert!(m[799].0 == "entry-0799" && m[799].1[1].2.starts_with("CANARY-mig-big-00799-"));
}

// -------------------------------------------------------------- T-MIG-2

/// A pickle whose `REDUCE` runs `touch <marker>` when it is unpickled.
fn malicious_pickle(marker: &Path) -> Vec<u8> {
    format!("cos\nsystem\n(S'touch {}'\ntR.", marker.display()).into_bytes()
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
fn t_mig_2_malicious_pickle_aborts_and_creates_no_marker() {
    for gpg in backends() {
        let rig = Rig::new(&gpg);
        let before = rig.vault_bytes();
        let marker = rig.path("marker");
        let pickle = malicious_pickle(&marker);
        // Positive control: this pickle does create the marker when a
        // program unpickles it.
        let raw = rig.path("raw.pickle");
        overwrite(&raw, &pickle);
        let loaded = Command::new("python3")
            .args([
                "-I",
                "-c",
                "import pickle, sys; pickle.load(open(sys.argv[1], 'rb'))",
            ])
            .arg(&raw)
            .status()
            .expect("python3");
        assert!(
            loaded.success() && marker.exists(),
            "{gpg:?}: the pickle is not live"
        );
        std::fs::remove_file(&marker).expect("remove marker");

        // (a) The pickle in place of the vault file: gpg refuses it.
        let mut p = rig.pipe(&raw, &[]);
        assert!(
            p.expect(FAILED),
            "{gpg:?}: no abort for a pickle as the vault"
        );
        assert_nothing_imported(&mut p, &rig, &before);
        assert!(!marker.exists(), "{gpg:?}: the vault file was unpickled");

        // (b) The pickle as the decrypted content of a well-encrypted
        // vault: it is not JSON, so nothing interprets it.
        let vault = rig.encrypted("pickle.enc", &pickle);
        let mut p = rig.pipe_with(&vault, LEGACY, &[]);
        assert!(
            p.expect("migrate_legacy: the decrypted data is not the legacy JSON"),
            "{gpg:?}: no abort for a pickle as the content"
        );
        assert_nothing_imported(&mut p, &rig, &before);
        assert!(
            !marker.exists(),
            "{gpg:?}: the decrypted content was unpickled"
        );
    }
}

/// The script imports nothing that can execute data, and nothing outside
/// the standard library.
#[test]
fn t_mig_2_script_has_no_code_executing_parser() {
    let src = std::fs::read_to_string(repo("tools/migrate_legacy.py")).expect("script");
    let mut imports: Vec<&str> = src
        .lines()
        .filter_map(|l| l.strip_prefix("import "))
        .collect();
    imports.sort_unstable();
    assert_eq!(
        imports,
        [
            "argparse",
            "gc",
            "json",
            "os",
            "stat",
            "struct",
            "subprocess",
            "sys"
        ]
    );
    assert!(
        !src.lines().any(|l| l.trim_start().starts_with("from ")),
        "a from-import"
    );
    for banned in [
        "pickle",
        "marshal",
        "shelve",
        "__import__",
        "importlib",
        "eval(",
        "exec(",
        "compile(",
    ] {
        assert!(!src.contains(banned), "the script mentions {banned}");
    }
    assert_eq!(src.matches("json.loads(").count(), 1, "one parser, JSON");
    assert_eq!(
        src.matches("subprocess.").count(),
        2,
        "one child process: gpg"
    );
}

// -------------------------------------------------------------- T-MIG-3

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
fn t_mig_3_stdout_must_be_a_pipe() {
    const REFUSAL: &str = "migrate_legacy: standard output must be a pipe";
    let rig = Rig::new(&Gpg::StandIn);
    let vault = rig.legacy_vault("legacy.enc", &good());
    let script = Rig::script(&vault);
    // A terminal.
    let mut cmd = common::shell_command(&format!("exec {script}"));
    rig.env(&mut cmd);
    let mut p = Pty::spawn(cmd);
    assert!(p.expect(REFUSAL), "a terminal was not refused");
    assert_eq!(p.exit_code(), Some(1));
    assert_eq!(p.count(ASK), 0, "the passphrase was asked");
    assert_eq!(p.count("CANARY-mig"), 0, "content on the screen");
    // A regular file, and a device.
    let out = rig.path("out.bin");
    for target in [out.to_str().expect("path"), "/dev/null"] {
        let mut cmd = common::shell_command(&format!("{script} > '{target}'"));
        rig.env(&mut cmd);
        let done = cmd.stdin(Stdio::null()).output().expect("run");
        assert_eq!(done.status.code(), Some(1), "{target} was not refused");
        assert!(
            String::from_utf8_lossy(&done.stderr).contains(REFUSAL),
            "no refusal message for {target}"
        );
    }
    assert_eq!(
        std::fs::metadata(&out).expect("out").len(),
        0,
        "bytes reached a file"
    );
    // The refusal comes before anything is decrypted.
    assert!(!rig.stand_in_called(), "gpg was started");
    // Positive control: into a pipe, the same command line does run gpg.
    let mut p = rig.pipe_with(&vault, LEGACY, &[]);
    assert!(p.answer("Master password: ", PW));
    assert!(p.expect("Imported 5 entries"));
    assert!(rig.stand_in_called());
}

/// `--vault` has no default, and the script takes nothing else.
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "tests spawn children; Section 5.7 binds the binary only"
)]
fn migrate_script_requires_the_vault_argument() {
    let rig = Rig::new(&Gpg::StandIn);
    let script = repo("tools/migrate_legacy.py");
    for args in [&[][..], &["--salt", "x"], &["--vault"]] {
        let mut cmd = common::shell_command(&format!(
            "python3 -I '{}' {} | cat",
            script.display(),
            args.join(" ")
        ));
        rig.env(&mut cmd);
        let done = cmd.stdin(Stdio::null()).output().expect("run");
        assert!(done.stdout.is_empty(), "output without a vault argument");
        assert!(String::from_utf8_lossy(&done.stderr).contains("usage:"));
    }
    assert!(!rig.stand_in_called());
}
