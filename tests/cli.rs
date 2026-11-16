//! Pure parts of `cli` and `term` (M7): the tokenizer, the command and
//! option parsers, display sanitisation, default sensitivity, `ls`
//! matching, the master-password strength estimate, `doctor`'s checks, and
//! the exit codes. Also the seed corpora of T-FUZZ-4 and T-FUZZ-5, and the
//! truncation tests the Section 15.5 checklist asks for.
//!
//! Test data here is synthetic, so ordinary `String`/`Vec` are fine.

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence, TestRunner};
use pwv::cli::{
    Args, COMMANDS, Facts, MAX_ARGS, MIN_PASSWORD_BITS, Status, Swap, contains_ci,
    default_sensitive, doctor_report, gen_exit_code, gen_policy, parse_command, strength_bits,
    swap_kind, tokenize, weakness,
};
use pwv::r#gen::{self, Policy};
use pwv::term::{is_unsafe, sanitize};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

fn cases(native: u32, miri: u32) -> Config {
    let mut c = Config::with_cases(if cfg!(miri) { miri } else { native });
    c.source_file = Some(file!());
    c.failure_persistence = if cfg!(miri) {
        None
    } else {
        Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        )))
    };
    c
}

/// Tokenizes `line`; the arguments as owned strings.
fn toks(line: &str) -> Result<Vec<String>, &'static str> {
    let mut buf = line.as_bytes().to_vec();
    let args = tokenize(&mut buf)?;
    Ok(strings(&buf, &args))
}

fn strings(buf: &[u8], args: &Args) -> Vec<String> {
    (0..args.len())
        .map(|i| String::from_utf8_lossy(args.get(buf, i).expect("range")).into_owned())
        .collect()
}

/// Quotes arguments so that the tokenizer returns exactly them.
fn quote(args: &[String]) -> String {
    let one = |a: &String| format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""));
    args.iter().map(one).collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------ tokenizer

#[test]
fn tokenizer_splits_quotes_and_escapes() {
    let ok: &[(&str, &[&str])] = &[
        ("", &[]),
        ("   \t ", &[]),
        ("ls", &["ls"]),
        ("  show   my-entry\t", &["show", "my-entry"]),
        ("show \"my entry\"", &["show", "my entry"]),
        ("show \"\"", &["show", ""]),
        ("a\"b c\"d e", &["ab cd", "e"]),
        ("\"a\"\"b\"", &["ab"]),
        ("say \\\"hi\\\"", &["say", "\"hi\""]),
        ("a\\\\b \"c\\\\d\" \"e\\\"f\"", &["a\\b", "c\\d", "e\"f"]),
        ("tab\"\t\"in", &["tab\tin"]),
        (
            "caf\u{e9} \u{1f600} na\u{a0}me",
            &["caf\u{e9}", "\u{1f600}", "na\u{a0}me"],
        ),
        ("--len 12 -- --name", &["--len", "12", "--", "--name"]),
    ];
    for (line, want) in ok {
        assert_eq!(toks(line).expect(line), *want, "{line:?}");
    }
    let bad = [
        ("a\\nb", "invalid backslash sequence"),
        ("a\\", "invalid backslash sequence"),
        ("\\x41", "invalid backslash sequence"),
        ("\"a\\tb\"", "invalid backslash sequence"),
        ("\\ ", "invalid backslash sequence"),
        ("\"open", "unterminated quote"),
        ("a \"b\" \"", "unterminated quote"),
        ("x\"", "unterminated quote"),
    ];
    for (line, want) in bad {
        let err = toks(line).expect_err(line);
        assert!(err.starts_with(want), "{line:?}: {err}");
    }
}

#[test]
fn tokenizer_argument_limit() {
    let line = |n: usize| vec!["a"; n].join(" ");
    assert_eq!(toks(&line(MAX_ARGS)).expect("at the limit").len(), MAX_ARGS);
    assert_eq!(toks(&line(MAX_ARGS + 1)), Err("too many arguments"));
    assert_eq!(
        toks(&vec!["\"\""; MAX_ARGS + 1].join(" ")),
        Err("too many arguments")
    );
}

#[test]
fn tokenizer_ranges_are_ordered_and_inside_the_buffer() {
    let mut buf = b"  set \"my \\\"site\\\"\" pass\\\\word  --gen ".to_vec();
    let args = tokenize(&mut buf).expect("valid");
    assert_eq!(
        strings(&buf, &args),
        ["set", "my \"site\"", "pass\\word", "--gen"]
    );
    assert!(args.get(&buf, args.len()).is_none());
    assert!(!args.is_empty());
    // A range from one buffer never indexes outside a shorter one.
    assert!(args.get(&buf[..3], 3).is_none());
}

/// Section 15.5: a truncation test for each new parser. Every prefix of
/// each line is an error or a result, never a panic.
#[test]
fn tokenizer_and_parser_on_every_truncation() {
    let lines = [
        "set \"my \\\"site\\\"\" pass\\\\word --gen --len 20 --classes luds --symbols \"!\\\"#\"",
        "gen --words 6 --sep - --show",
        "import --from-stdin --on-conflict suffix",
        "mvfield \"a b\" \"c d\" \"e f\"",
        "init --kdf-memory 256 --kdf-time 3 --accept-weak-password",
    ];
    for line in lines {
        for cut in 0..=line.len() {
            let mut buf = line.as_bytes()[..cut].to_vec();
            if let Ok(args) = tokenize(&mut buf)
                && let Ok(cmd) = parse_command(&buf, &args)
            {
                let _ = gen_policy(&cmd, &buf).map(|p| p.validate());
            }
        }
    }
}

#[test]
fn tokenizer_properties() {
    let mut runner = TestRunner::new(cases(2000, 16));
    // Any bytes: an error or in-range arguments; canonical quoting of the
    // result tokenizes to the same arguments.
    runner
        .run(&proptest::collection::vec(any::<u8>(), 0..200), |bytes| {
            let mut buf = bytes.clone();
            if let Ok(args) = tokenize(&mut buf) {
                prop_assert!(args.len() <= MAX_ARGS);
                let got: Vec<Vec<u8>> = (0..args.len())
                    .map(|i| args.get(&buf, i).expect("range").to_vec())
                    .collect();
                let mut line = Vec::new();
                for t in &got {
                    line.push(b'"');
                    for &b in t {
                        if b == b'"' || b == b'\\' {
                            line.push(b'\\');
                        }
                        line.push(b);
                    }
                    line.extend_from_slice(b"\" ");
                }
                let again = tokenize(&mut line).expect("canonical quoting");
                prop_assert_eq!(again.len(), got.len());
                for (i, t) in got.iter().enumerate() {
                    prop_assert_eq!(again.get(&line, i).expect("range"), &t[..]);
                }
            }
            Ok(())
        })
        .expect("tokenizer on arbitrary bytes");
    // Any list of arguments survives quoting.
    let arg = "[ -~\u{e9}\u{202e}\t]{0,12}";
    runner
        .run(&proptest::collection::vec(arg, 0..MAX_ARGS), |args| {
            prop_assert_eq!(toks(&quote(&args)), Ok(args));
            Ok(())
        })
        .expect("quoted arguments round-trip");
}

// ------------------------------------------------------- command parser

/// A parsed line: command name, positional arguments, buffer, command.
type Parsed = (String, Vec<String>, Vec<u8>, pwv::cli::Cmd);

fn parse(line: &str) -> Result<Parsed, &'static str> {
    let mut buf = line.as_bytes().to_vec();
    let args = tokenize(&mut buf)?;
    let cmd = parse_command(&buf, &args)?;
    let pos = (0..4)
        .map_while(|i| cmd.arg(&buf, i))
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    Ok((cmd.spec.names[0].to_owned(), pos, buf, cmd))
}

#[test]
fn command_table_has_the_seventeen_commands() {
    let listed: Vec<&str> = COMMANDS
        .iter()
        .filter(|c| !c.help.is_empty())
        .map(|c| c.names[0])
        .collect();
    assert_eq!(
        listed,
        [
            "init", "ls", "show", "reveal", "copy", "add", "set", "unset", "mv", "mvfield", "rm",
            "gen", "passwd", "import", "doctor", "help", "quit"
        ]
    );
    let mut names: Vec<&str> = COMMANDS
        .iter()
        .flat_map(|c| c.names.iter().copied())
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "names and aliases are unique");
    for c in COMMANDS {
        assert!(c.arity.0 <= c.arity.1 && c.arity.1 <= 3, "{}", c.names[0]);
        assert!(
            c.flags.len() <= 10,
            "{}: more options than a Cmd holds",
            c.names[0]
        );
        assert!(
            c.usage.starts_with(c.names[0]),
            "usage starts with the name"
        );
        assert!(c.flags.iter().all(|f| f.0.starts_with("--")));
    }
    // S1: no export, dump, or save command exists.
    for absent in ["export", "dump", "save", "backup", "print"] {
        assert_eq!(
            parse(absent).err(),
            Some("unknown command; type `help` for the list")
        );
    }
    for alias in ["quit", "exit", "lock"] {
        assert_eq!(parse(alias).expect(alias).0, "quit");
    }
}

#[test]
fn command_parser_arity_for_every_command() {
    for c in COMMANDS {
        let name = c.names[0];
        for n in 0..=4 {
            let line = format!("{name}{}", " arg".repeat(n));
            let got = parse(&line).map(|p| p.1.len());
            let want = if n < c.arity.0 {
                Err("missing argument")
            } else if n > c.arity.1 {
                Err("too many arguments")
            } else {
                Ok(n)
            };
            assert_eq!(got, want, "{line}");
        }
        // Every option is accepted once, refused twice; a value option
        // needs its value.
        for (flag, takes_value) in c.flags {
            let args = " arg".repeat(c.arity.0);
            let value = if *takes_value { " 1" } else { "" };
            let (.., buf, cmd) = parse(&format!("{name} {flag}{value}{args}")).expect(flag);
            assert!(cmd.has(flag));
            assert_eq!(
                cmd.opt(&buf, flag).map(<[u8]>::len),
                Some(value.len().saturating_sub(1))
            );
            assert_eq!(
                parse(&format!("{name} {flag}{value} {flag}{value}{args}")).err(),
                Some("an option was given twice")
            );
            if *takes_value {
                assert_eq!(
                    parse(&format!("{name}{args} {flag}")).err(),
                    Some("the option needs a value")
                );
            }
        }
        assert_eq!(
            parse(&format!("{name} --no-such-option")).err(),
            Some("unknown option for this command")
        );
    }
    assert_eq!(parse("").err(), Some("no command given"));
    assert_eq!(
        parse("LS").err(),
        Some("unknown command; type `help` for the list")
    );
}

#[test]
fn command_parser_options_anywhere_and_double_dash() {
    let (name, pos, buf, cmd) =
        parse("set --gen site --len 24 password --sensitive").expect("valid");
    assert_eq!(
        (name.as_str(), pos),
        ("set", vec!["site".into(), "password".into()])
    );
    assert!(cmd.has("--gen") && cmd.has("--sensitive") && !cmd.has("--plain"));
    assert_eq!(cmd.opt(&buf, "--len"), Some(&b"24"[..]));
    assert_eq!(
        cmd.opt(&buf, "--gen"),
        Some(&b""[..]),
        "a switch has no value"
    );
    assert_eq!(cmd.opt(&buf, "--words"), None);
    assert!(!cmd.has("--show"), "an option of another command");
    // After `--`, everything is positional.
    let (_, pos, ..) = parse("mv -- --old --new").expect("valid");
    assert_eq!(pos, ["--old", "--new"]);
    let (_, pos, ..) = parse("show -- --").expect("valid");
    assert_eq!(pos, ["--"]);
    assert_eq!(
        parse("show --weird").err(),
        Some("unknown option for this command")
    );
    // An option value may look like an option.
    let (.., buf, cmd) = parse("gen --symbols --!").expect("valid");
    assert_eq!(cmd.opt(&buf, "--symbols"), Some(&b"--!"[..]));
}

/// Buffers that `policy` leaks for a `'static` lifetime, kept reachable so
/// LeakSanitizer (T-SAN-1) does not report them (M9).
static KEPT: std::sync::Mutex<Vec<&'static [u8]>> = std::sync::Mutex::new(Vec::new());

fn policy(line: &str) -> Result<Policy<'static>, &'static str> {
    let (.., buf, cmd) = parse(line)?;
    let buf: &'static [u8] = buf.leak();
    KEPT.lock().expect("lock").push(buf);
    gen_policy(&cmd, buf)
}

#[test]
fn gen_options_map_to_policies() {
    assert_eq!(policy("gen"), Ok(Policy::DEFAULT_CHARS));
    assert_eq!(policy("gen --words 6"), Ok(Policy::DEFAULT_WORDS));
    assert_eq!(policy("gen --sep -"), Ok(Policy::DEFAULT_WORDS));
    assert_eq!(
        policy("gen --len 32 --classes dl --symbols #! --no-ambiguous"),
        Ok(Policy::Chars {
            len: 32,
            classes: [true, false, true, false],
            symbols: b"#!",
            no_ambiguous: true
        })
    );
    assert_eq!(
        policy("gen --words 12 --sep \" \""),
        Ok(Policy::Words {
            count: 12,
            sep: b' '
        })
    );
    assert_eq!(
        policy("set a b --gen --words 4"),
        Ok(Policy::Words {
            count: 4,
            sep: b'-'
        })
    );
    // Ranges are the generator's business (`validate`); the parser keeps
    // the number.
    assert_eq!(
        policy("gen --len 7").map(|p| p.validate()),
        Ok(Err(r#gen::Error::Length))
    );
    assert_eq!(
        policy("gen --words 17").map(|p| p.validate()),
        Ok(Err(r#gen::Error::WordCount))
    );
    assert_eq!(
        policy("gen --classes \"\"").map(|p| p.validate()),
        Ok(Err(r#gen::Error::NoClasses))
    );
    for (line, want) in [
        ("gen --len x", "the option needs a number"),
        ("gen --len -5", "the option needs a number"),
        ("gen --len +5", "the option needs a number"),
        ("gen --len 1234567890", "the option needs a number"),
        ("gen --len \"\"", "the option needs a number"),
        ("gen --words 4.5", "the option needs a number"),
        (
            "gen --classes lul",
            "--classes takes each of l, u, d, s at most once",
        ),
        (
            "gen --classes x",
            "--classes takes each of l, u, d, s at most once",
        ),
        (
            "gen --classes L",
            "--classes takes each of l, u, d, s at most once",
        ),
        ("gen --sep ab", "--sep takes exactly one character"),
        ("gen --sep \"\"", "--sep takes exactly one character"),
        ("gen --sep \u{e9}", "--sep takes exactly one character"),
        (
            "gen --words 5 --len 20",
            "password and passphrase options cannot be combined",
        ),
        (
            "gen --sep . --classes l",
            "password and passphrase options cannot be combined",
        ),
        (
            "gen --words 5 --symbols !",
            "password and passphrase options cannot be combined",
        ),
        (
            "gen --sep . --no-ambiguous",
            "password and passphrase options cannot be combined",
        ),
    ] {
        assert_eq!(policy(line).err(), Some(want), "{line}");
    }
}

#[test]
fn exit_codes_for_generator_errors() {
    use r#gen::Error as G;
    for e in [
        G::Length,
        G::NoClasses,
        G::SymbolChar,
        G::SymbolDuplicate,
        G::SymbolsEmpty,
        G::WordCount,
        G::Separator,
    ] {
        assert_eq!(gen_exit_code(e), pwv::cli::EXIT_USER, "{e:?}");
    }
    for e in [G::Attempts, G::Random, G::Capacity, G::WordList] {
        assert_eq!(gen_exit_code(e), pwv::cli::EXIT_INTERNAL, "{e:?}");
    }
}

// --------------------------------------------- sensitivity and matching

#[test]
fn default_sensitive_keys() {
    for key in [
        "password",
        "passphrase",
        "pin",
        "secret",
        "otp",
        "totp",
        "cvv",
        "token",
        "api key",
        "recovery codes",
        "PASSWORD",
        "Api Key",
        "Recovery Codes",
        "PiN",
    ] {
        assert!(default_sensitive(key.as_bytes()), "{key}");
    }
    for key in [
        "user",
        "url",
        "note",
        "passwords",
        "pass word",
        "apikey",
        "api  key",
        " pin",
        "pin ",
        "",
        "p\u{131}n",
    ] {
        assert!(!default_sensitive(key.as_bytes()), "{key:?}");
    }
}

#[test]
fn ls_matching_is_a_unicode_case_insensitive_substring() {
    let yes = [
        ("GitHub", ""),
        ("GitHub", "git"),
        ("GitHub", "HUB"),
        ("GitHub", "GitHub"),
        ("Caf\u{c9} Mail", "caf\u{e9}"),
        ("stra\u{df}e", "STRA\u{df}E"),
        ("\u{391}\u{3b8}\u{3ae}\u{3bd}\u{3b1}", "\u{3b1}\u{398}"),
        ("a\u{1f600}b", "\u{1f600}B"),
        ("", ""),
    ];
    for (hay, needle) in yes {
        assert!(
            contains_ci(hay.as_bytes(), needle.as_bytes()),
            "{hay:?} {needle:?}"
        );
    }
    let no = [
        ("GitHub", "gitlab"),
        ("GitHub", "hubs"),
        ("", "a"),
        ("ab", "abc"),
        ("cafe", "caf\u{e9}"),
    ];
    for (hay, needle) in no {
        assert!(
            !contains_ci(hay.as_bytes(), needle.as_bytes()),
            "{hay:?} {needle:?}"
        );
    }
    // Text that is not UTF-8 never matches (and never panics).
    assert!(!contains_ci(b"ab\xff", b"a"));
    assert!(!contains_ci(b"ab", b"\xff"));
}

// ------------------------------------------------------------- strength

#[test]
fn weak_master_passwords_are_refused() {
    let weak = [
        "",
        "short",
        "Tr0ub4dor&3",                // strong-looking, but 11 characters
        "aaaaaaaaaaaaaaaaaaaaaaaa",   // one character
        "abababababababababababab",   // one pair
        "abcdefghijklmnopqrstuvwxyz", // alphabet run
        "12345678901234567890",       // digit run
        "qwertyuiopasdfghjklzxcvbnm", // keyboard rows
        "password1password1",         // repeated word
        "passwordpasswordpassword",   // repeated word
        "Password1234567890",         // word and a run
        "letmeinletmeinletmein",      // repeated non-list text
        "iloveyouiloveyou",           // repeated phrase
        "correct horse battery",      // three list words
        "summer-winter-spring",       // three list words
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    for pw in weak {
        assert!(
            weakness(pw.as_bytes()).is_some(),
            "accepted a weak password (index only): {}",
            pw.len()
        );
    }
    assert_eq!(weakness(b"\xff\xfe"), Some("it is not valid UTF-8"));
    assert_eq!(
        weakness(b"Vk7#qunmp2!xbrw"),
        Some("it has fewer than 16 characters")
    );
    assert_eq!(
        weakness(b"aaaaaaaaaaaaaaaa"),
        Some("it is too predictable (estimated below 10^14 guesses)")
    );
}

#[test]
fn strong_master_passwords_are_accepted() {
    let strong = [
        "Vk7#qunmp2!xbrw9Tz",
        "mZ4$tqLp9@wXc2&nRb7!",
        "correct horse battery staple zebra",
        "\u{3b1}\u{3b2}9K#m\u{3b8}zQ7!x\u{3c9}Lp2&r",
    ];
    for pw in strong {
        assert_eq!(
            weakness(pw.as_bytes()),
            None,
            "refused a strong password ({} bytes)",
            pw.len()
        );
    }
    // A generated 6-word passphrase always passes, also when the user
    // types it as a chosen password.
    for line in [
        "able-about-above-absent-absorb-abstract",
        "zebra zesty zinc zone zoom zipper",
    ] {
        let known = line
            .split(['-', ' '])
            .filter(|w| r#gen::WORDS.lines().any(|l| l == *w));
        if known.count() == 6 {
            assert_eq!(weakness(line.as_bytes()), None);
        }
    }
}

#[test]
fn strength_estimate_details() {
    let close = |a: f64, b: f64| (a - b).abs() < 1e-9;
    assert!(close(strength_bits(""), 0.0));
    assert!(close(strength_bits("k"), 26f64.log2()));
    assert!(close(strength_bits("7"), 10f64.log2()));
    assert!(close(strength_bits("#"), 33f64.log2()));
    assert!(close(strength_bits("\u{3b8}"), 6.0));
    // Repeats, neighbours in code-point order, and keyboard neighbours
    // count 1 bit each.
    assert!(close(strength_bits("kk"), 26f64.log2() + 1.0));
    assert!(close(strength_bits("kl"), 26f64.log2() + 1.0));
    assert!(close(strength_bits("lk"), 26f64.log2() + 1.0));
    assert!(close(strength_bits("fg"), 26f64.log2() + 1.0));
    assert!(
        close(strength_bits("p1"), 26f64.log2() + 10f64.log2()),
        "row ends do not join"
    );
    assert!(close(strength_bits("kx"), 2.0 * 26f64.log2()));
    // A pair seen before is predictable the second time.
    assert!(close(
        strength_bits("kxmkx"),
        3.0 * 26f64.log2() + 26f64.log2() + 1.0
    ));
    // A list word counts 11 bits, in any letter case; a repeat counts 1.
    let word = r#gen::WORDS
        .lines()
        .find(|w| w.len() == 8 && !w.contains('-'))
        .expect("word");
    assert!(close(strength_bits(word), 11.0));
    assert!(close(strength_bits(&word.to_uppercase()), 11.0));
    assert!(close(strength_bits(&format!("{word}{word}")), 12.0));
    assert!(close(
        strength_bits(&format!("{word}#{word}")),
        12.0 + 33f64.log2()
    ));
    // The estimate never exceeds the uniform bound for the characters.
    let mut runner = TestRunner::new(cases(300, 4));
    runner
        .run(&"[ -~\u{e9}\u{3b8}]{0,40}", |pw| {
            let bits = strength_bits(&pw);
            prop_assert!(bits >= 0.0);
            prop_assert!(bits <= 6.0 * pw.chars().count() as f64 + 1e-9);
            prop_assert_eq!(weakness(pw.as_bytes()).is_none(), {
                pw.chars().count() >= 16 && bits >= MIN_PASSWORD_BITS
            });
            Ok(())
        })
        .expect("strength bounds");
}

// --------------------------------------------------------------- doctor

fn healthy() -> Facts {
    Facts {
        memlock: None,
        arena: 1024 * 1024,
        kdf_kib: Some(262_144),
        swap: Swap::None,
        hibernation: false,
        suid_dumpable: Some(0),
        ptrace_scope: Some(1),
        vault: Some(String::new()),
        desktop: "KDE".into(),
    }
}

fn statuses(f: &Facts) -> Vec<Status> {
    doctor_report(f).into_iter().map(|r| r.0).collect()
}

#[test]
fn doctor_checks_follow_section_9_4() {
    use Status::{Fail, Pass, Warn};
    let names: Vec<&str> = doctor_report(&healthy()).into_iter().map(|r| r.1).collect();
    assert_eq!(
        names,
        [
            "Arena lockable",
            "KDF memory lockable",
            "Swap",
            "Hibernation",
            "Core dumps",
            "ptrace scope",
            "Vault location",
            "Clipboard history"
        ]
    );
    assert_eq!(statuses(&healthy()), [Pass; 8]);
    let with = |change: &dyn Fn(&mut Facts)| {
        let mut f = healthy();
        change(&mut f);
        statuses(&f)
    };
    let only = |i: usize, s: Status| {
        let mut want = [Pass; 8];
        want[i] = s;
        want.to_vec()
    };
    // Arena: the limit must cover the arena, exactly.
    assert_eq!(with(&|f| f.memlock = Some(1024 * 1024)), only(1, Warn));
    assert_eq!(with(&|f| f.memlock = Some(1024 * 1024 - 1)), {
        let mut w = only(0, Fail);
        w[1] = Warn;
        w
    });
    // KDF memory: a warning, since derivation proceeds unlocked (5.4).
    assert_eq!(with(&|f| f.memlock = Some(262_144 * 1024)), [Pass; 8]);
    assert_eq!(
        with(&|f| f.memlock = Some(262_144 * 1024 - 1)),
        only(1, Warn)
    );
    assert_eq!(
        with(&|f| {
            f.memlock = Some(8 << 20);
            f.kdf_kib = Some(8192);
        }),
        [Pass; 8]
    );
    // Swap and hibernation.
    assert_eq!(with(&|f| f.swap = Swap::Protected), [Pass; 8]);
    assert_eq!(with(&|f| f.swap = Swap::Plain), only(2, Fail));
    assert_eq!(with(&|f| f.hibernation = true), [Pass; 8]);
    assert_eq!(
        with(&|f| {
            f.hibernation = true;
            f.swap = Swap::Protected;
        }),
        [Pass; 8]
    );
    assert_eq!(
        with(&|f| {
            f.hibernation = true;
            f.swap = Swap::Plain;
        }),
        {
            let mut w = only(2, Fail);
            w[3] = Fail;
            w
        }
    );
    // Core dumps: only suid_dumpable = 0 passes (owner decision, M1).
    for bad in [Some(1), Some(2), None] {
        assert_eq!(with(&|f| f.suid_dumpable = bad), only(4, Fail));
    }
    // ptrace scope.
    assert_eq!(with(&|f| f.ptrace_scope = Some(3)), [Pass; 8]);
    for bad in [Some(0), None] {
        assert_eq!(with(&|f| f.ptrace_scope = bad), only(5, Warn));
    }
    // Vault location.
    assert_eq!(with(&|f| f.vault = None), only(6, Warn));
    assert_eq!(
        with(&|f| f.vault = Some("wrong owner".into())),
        only(6, Fail)
    );
    let mut f = healthy();
    f.vault = Some("the reason".into());
    assert_eq!(doctor_report(&f)[6].2, "the reason");
    // Clipboard history is informational.
    for d in ["GNOME", "", "sway"] {
        assert_eq!(with(&|f| f.desktop = d.into()), only(7, Warn));
    }
    assert_eq!(with(&|f| f.desktop = "ubuntu:kde".into()), [Pass; 8]);
}

#[test]
fn swap_classification() {
    let head = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
    let uuid = |name: &str| match name {
        "dm-0" => Some("CRYPT-LUKS2-0123-swap\n".to_owned()),
        "dm-1" => Some("LVM-abcdef\n".to_owned()),
        _ => None,
    };
    let kind = |rows: &str| swap_kind(&format!("{head}{rows}"), &uuid);
    assert_eq!(swap_kind("", &uuid), Swap::None);
    assert_eq!(kind(""), Swap::None);
    assert_eq!(
        kind("/dev/zram0 partition 8388604 0 100\n"),
        Swap::Protected
    );
    assert_eq!(kind("/dev/dm-0 partition 8388604 0 -2\n"), Swap::Protected);
    assert_eq!(
        kind("/dev/dm-1 partition 8388604 0 -2\n"),
        Swap::Plain,
        "LVM, not dm-crypt"
    );
    assert_eq!(
        kind("/dev/dm-7 partition 8388604 0 -2\n"),
        Swap::Plain,
        "unknown uuid"
    );
    assert_eq!(kind("/dev/nvme0n1p3 partition 8388604 0 -2\n"), Swap::Plain);
    assert_eq!(kind("/swapfile file 2097148 0 -2\n"), Swap::Plain);
    assert_eq!(
        kind("/zramfile file 2097148 0 -2\n"),
        Swap::Plain,
        "a file, not a zram device"
    );
    // One plain device is enough, in any order.
    assert_eq!(
        kind("/dev/zram0 partition 1 0 1\n/swapfile file 1 0 -2\n"),
        Swap::Plain
    );
    assert_eq!(
        kind("/swapfile file 1 0 -2\n/dev/zram0 partition 1 0 1\n"),
        Swap::Plain
    );
    assert_eq!(
        kind("/dev/zram0 partition 1 0 1\n/dev/dm-0 partition 1 0 2\n"),
        Swap::Protected
    );
}

// ------------------------------------------------------------- sanitize

fn clean(input: &[u8]) -> String {
    let mut out = Vec::new();
    sanitize(input, &mut |chunk| {
        assert!(!chunk.is_empty(), "empty chunk");
        out.extend_from_slice(chunk);
    });
    String::from_utf8(out).expect("sanitize output is UTF-8")
}

#[test]
fn sanitize_escapes_controls_and_bidi_overrides() {
    let cases: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"plain text", "plain text"),
        ("caf\u{e9} \u{1f600}".as_bytes(), "caf\u{e9} \u{1f600}"),
        (b"\x1b[31mred", "\\x1b[31mred"),
        (b"\x1b]0;title\x07", "\\x1b]0;title\\x07"),
        (b"a\nb\tc\rd", "a\\x0ab\\x09c\\x0dd"),
        (b"\x00\x7f", "\\x00\\x7f"),
        ("a\u{85}b\u{9b}c".as_bytes(), "a\\u{85}b\\u{9b}c"),
        ("ev\u{202e}il".as_bytes(), "ev\\u{202e}il"),
        ("\u{2066}x\u{2069}".as_bytes(), "\\u{2066}x\\u{2069}"),
        (b"ok\xffbad\xc3", "ok\\xffbad\\xc3"),
        (b"\xf0\x9f\x98", "\\xf0\\x9f\\x98"),
        (b"back\\slash \\x1b", "back\\slash \\x1b"),
    ];
    for (input, want) in cases {
        assert_eq!(clean(input), *want);
    }
}

#[test]
fn sanitize_every_unsafe_character() {
    let unsafe_chars = (0u32..0x20)
        .chain(0x7f..0xa0)
        .chain(0x202a..=0x202e)
        .chain(0x2066..=0x2069);
    let mut n = 0;
    for v in unsafe_chars {
        let c = char::from_u32(v).expect("char");
        assert!(is_unsafe(c), "U+{v:04X}");
        let want = if v < 0x80 {
            format!("<\\x{v:02x}>")
        } else {
            format!("<\\u{{{v:x}}}>")
        };
        assert_eq!(clean(format!("<{c}>").as_bytes()), want);
        n += 1;
    }
    assert_eq!(n, 32 + 33 + 5 + 4);
    // Their neighbours, and other formatting characters, are untouched.
    for v in [
        0x20u32, 0x7e, 0xa0, 0x2029, 0x202f, 0x2065, 0x206a, 0x200e, 0x200f, 0x61c,
    ] {
        let c = char::from_u32(v).expect("char");
        assert!(!is_unsafe(c), "U+{v:04X}");
        assert_eq!(clean(c.to_string().as_bytes()), c.to_string());
    }
}

#[test]
fn sanitize_properties_and_truncation() {
    let mut runner = TestRunner::new(cases(3000, 16));
    runner
        .run(&proptest::collection::vec(any::<u8>(), 0..300), |bytes| {
            let out = clean(&bytes);
            prop_assert!(!out.chars().any(is_unsafe));
            prop_assert!(out.len() >= bytes.len());
            Ok(())
        })
        .expect("arbitrary bytes");
    runner
        .run(&"\\PC{0,60}", |text| {
            let out = clean(text.as_bytes());
            prop_assert!(!out.chars().any(is_unsafe));
            if !text.chars().any(is_unsafe) {
                prop_assert_eq!(out, text);
            }
            Ok(())
        })
        .expect("arbitrary text");
    // Every prefix (also one that cuts a character in half).
    let text = "a\u{1f600}\x1b[0m\u{202e}\u{e9}\u{85}z".as_bytes();
    for cut in 0..=text.len() {
        assert!(!clean(&text[..cut]).chars().any(is_unsafe));
    }
}

// ---------------------------------------------------------- fuzz corpus

/// Seed inputs for T-FUZZ-4 and T-FUZZ-5 (Section 14.10: corpus committed).
#[cfg_attr(miri, allow(dead_code))] // its only caller is not(miri)
fn corpus_seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let line = |s: &str| s.as_bytes().to_vec();
    vec![
        ("fuzz_tokenizer", "seed-empty", line("")),
        ("fuzz_tokenizer", "seed-ls", line("ls git")),
        (
            "fuzz_tokenizer",
            "seed-quotes",
            line("show \"my \\\"site\\\"\" a\\\\b \"\""),
        ),
        (
            "fuzz_tokenizer",
            "seed-set-gen",
            line(
                "set site password --gen --len 24 --classes luds --symbols \"!#%\" --no-ambiguous --sensitive",
            ),
        ),
        (
            "fuzz_tokenizer",
            "seed-gen-words",
            line("gen --words 6 --sep - --show"),
        ),
        (
            "fuzz_tokenizer",
            "seed-import",
            line("import --from-stdin --on-conflict suffix"),
        ),
        (
            "fuzz_tokenizer",
            "seed-init",
            line("init --kdf-memory 256 --kdf-time 3 --accept-weak-password"),
        ),
        (
            "fuzz_tokenizer",
            "seed-dashes",
            line("mv -- --old \"--new name\""),
        ),
        (
            "fuzz_tokenizer",
            "seed-password",
            line("correct horse Battery9 staple qwerty 12345"),
        ),
        ("fuzz_tokenizer", "seed-bad", line("reveal \"open \\x")),
        ("fuzz_sanitize", "seed-empty", line("")),
        (
            "fuzz_sanitize",
            "seed-plain",
            line("plain caf\u{e9} \u{1f600}"),
        ),
        (
            "fuzz_sanitize",
            "seed-escape",
            b"\x1b]0;title\x07\x1b[31m\r\n\t\x00\x7f".to_vec(),
        ),
        (
            "fuzz_sanitize",
            "seed-bidi",
            line("ev\u{202e}il \u{2066}x\u{2069} \u{85}\u{9b}"),
        ),
        (
            "fuzz_sanitize",
            "seed-invalid",
            b"ok\xffbad\xc3\xf0\x9f\x98".to_vec(),
        ),
    ]
}

/// The committed seed files equal the generated seeds. To regenerate after
/// a deliberate change: `PWV_WRITE_CORPUS=1 cargo test --test cli corpus`.
#[cfg(not(miri))]
#[test]
#[allow(clippy::disallowed_methods, reason = "writes fuzz seeds; test-only")]
fn fuzz_corpus_seeds_are_committed() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let write = std::env::var_os("PWV_WRITE_CORPUS").is_some();
    for (target, name, bytes) in corpus_seeds() {
        let path = root.join(target).join(name);
        if write {
            std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
            std::fs::write(&path, &bytes).expect("write seed");
        }
        let got = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(got, bytes, "{} is stale", path.display());
    }
}
