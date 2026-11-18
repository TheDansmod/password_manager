//! Command grammar, REPL loop, idle timeout, confirmation prompts, rendering
//! of entries, `doctor` (spec Sections 6.5, 8.4, 8.5, 9, 11, 12.2).
//!
//! Secret contract: every typed line is read into an arena slot and
//! tokenized there in place; command arguments are byte ranges into that
//! slot. Arguments needed after a later prompt are parked in the `Pw1` and
//! `Pw2` slots, a hidden value awaiting its repetition in the vault's
//! scratch half. Names, keys, and values are written to the terminal
//! straight from their slots. Only fixed program text and numbers are
//! formatted on the heap.

use crate::crypto::KdfParams;
use crate::format::{self, EntryRef, FieldRef, Header};
use crate::r#gen::{self, Policy};
use crate::secmem::{self, SecretSlot, SecureArena, Slots};
use crate::store::{self, Freshness, Paths, Store};
use crate::sys::{self, Hardening};
use crate::{clip, crypto, term, vault};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

/// Exit code for a user error (spec Section 9.3).
pub const EXIT_USER: i32 = 1;
/// Exit code for an authentication failure (spec Section 9.3).
pub const EXIT_AUTH: i32 = 2;
/// Exit code for a vault integrity or rollback refusal (spec Section 9.3).
pub const EXIT_INTEGRITY: i32 = 3;
/// Exit code for an environment refusal (spec Section 9.3).
pub const EXIT_ENV: i32 = 4;
/// Exit code for an internal error (spec Section 9.3).
pub const EXIT_INTERNAL: i32 = 5;

/// Exit code for a vault lifecycle error (Section 9.3). Wrong password and
/// damaged payload are the same [`crypto::Error::Auth`], hence the same
/// code and the same message (T-CRY-2).
#[must_use]
pub fn exit_code(e: vault::Error) -> i32 {
    use crypto::Error as C;
    match e {
        vault::Error::Crypto(C::Auth) => EXIT_AUTH,
        vault::Error::Format(_) | vault::Error::Generation => EXIT_INTEGRITY,
        vault::Error::Crypto(C::Password | C::KdfParams)
        | vault::Error::Capacity
        | vault::Error::Invalid(_)
        | vault::Error::EntryExists
        | vault::Error::FieldExists
        | vault::Error::NoEntry
        | vault::Error::NoField => EXIT_USER,
        vault::Error::Crypto(C::Kdf | C::KdfUnlocked) => EXIT_ENV,
        vault::Error::Crypto(C::Random | C::Length) => EXIT_INTERNAL,
    }
}

/// Exit code for a storage error (Section 9.3): a missing or existing
/// vault is a user error; a damaged file or state file is an integrity
/// error; everything else (permissions, owner, file type, filesystem,
/// lock, I/O) is an environment refusal.
#[must_use]
pub fn store_exit_code(e: &store::Error) -> i32 {
    match e {
        store::Error::NoVault | store::Error::Exists => EXIT_USER,
        store::Error::Format(_) | store::Error::State => EXIT_INTEGRITY,
        _ => EXIT_ENV,
    }
}

/// The rollback warning of Section 8.4 for file generation `file` below
/// the recorded generation `recorded`.
#[must_use]
pub fn rollback_warning(file: u64, recorded: u64) -> String {
    format!(
        "This vault is older than the last version saved on this machine \
         (generation {file} < {recorded}). It may have been rolled back or restored from backup."
    )
}

/// Applies the user's answer to a rollback warning (Section 8.4). Only
/// exactly `yes` continues; the header's generation is then raised to the
/// recorded one, so the next save writes `max(g_f, g_s) + 1`. A fresh vault
/// needs no answer.
///
/// # Errors
/// [`EXIT_INTEGRITY`] for any other answer; `h` is unchanged.
pub fn confirm_rollback(h: &mut Header, f: Freshness, answer: &[u8]) -> Result<(), i32> {
    match f {
        Freshness::Fresh => Ok(()),
        Freshness::RolledBack { recorded, .. } if answer == b"yes" => {
            h.generation = h.generation.max(recorded);
            Ok(())
        }
        Freshness::RolledBack { .. } => Err(EXIT_INTEGRITY),
    }
}

/// Exit code for a generator error: a violated policy is a user error; a
/// failed generator, a full slot, or a damaged word list is internal.
#[must_use]
pub fn gen_exit_code(e: r#gen::Error) -> i32 {
    use r#gen::Error as G;
    match e {
        G::Attempts | G::Random | G::Capacity | G::WordList => EXIT_INTERNAL,
        _ => EXIT_USER,
    }
}

// ---- Tokenizer and command parser (Section 9.3; fuzzed by T-FUZZ-4).

/// Most arguments one command line may hold.
pub const MAX_ARGS: usize = 24;

/// A byte range `[start, end)` of the line buffer.
type Span = (usize, usize);

/// The arguments of one command line: byte ranges into the line buffer
/// (the `Input` slot), never owned copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Args {
    n: usize,
    spans: [Span; MAX_ARGS],
}

impl Args {
    /// Number of arguments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.n
    }

    /// Whether the line held no argument.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    fn span(&self, i: usize) -> Option<Span> {
        self.spans.get(i).copied().filter(|_| i < self.n)
    }

    /// Argument `i`, borrowed from `buf` (the buffer that was tokenized).
    #[must_use]
    pub fn get<'b>(&self, buf: &'b [u8], i: usize) -> Option<&'b [u8]> {
        let (a, b) = self.span(i)?;
        buf.get(a..b)
    }

    fn push(&mut self, span: Span) -> Result<(), &'static str> {
        *self.spans.get_mut(self.n).ok_or("too many arguments")? = span;
        self.n += 1;
        Ok(())
    }
}

/// Splits a command line in place: arguments are separated by spaces or
/// tabs; double quotes group (and may be empty); a backslash escapes only
/// `"` and `\\`. Escapes and quotes are removed by compacting the bytes
/// towards the front of `buf`, so the returned ranges index `buf` itself.
///
/// # Errors
/// A fixed message for any other backslash sequence, an unterminated
/// quote, or more than [`MAX_ARGS`] arguments.
pub fn tokenize(buf: &mut [u8]) -> Result<Args, &'static str> {
    let mut args = Args::default();
    let (mut read, mut write, mut quoted) = (0, 0, false);
    let mut start: Option<usize> = None;
    while let Some(&c) = buf.get(read) {
        read += 1;
        let literal = match c {
            b'\\' => match buf.get(read) {
                Some(&e @ (b'"' | b'\\')) => {
                    read += 1;
                    Some(e)
                }
                _ => return Err("invalid backslash sequence: only \\\" and \\\\ are allowed"),
            },
            b'"' => {
                quoted = !quoted;
                start.get_or_insert(write);
                None
            }
            b' ' | b'\t' if !quoted => {
                if let Some(s) = start.take() {
                    args.push((s, write))?;
                }
                None
            }
            c => Some(c),
        };
        if let (Some(l), Some(slot)) = (literal, buf.get_mut(write)) {
            start.get_or_insert(write);
            *slot = l;
            write += 1;
        }
    }
    if quoted {
        return Err("unterminated quote");
    }
    if let Some(s) = start {
        args.push((s, write))?;
    }
    Ok(args)
}

/// A command handler: runs against the session context.
type Handler = fn(&mut Session<'_>, &Cmd) -> Result<(), Fail>;

/// One row of the command table (Section 15.2): the parser and the help
/// text both derive from it.
pub struct CommandSpec {
    /// The command name, then its aliases.
    pub names: &'static [&'static str],
    /// Argument synopsis for the help text.
    pub usage: &'static str,
    /// One-line description.
    pub help: &'static str,
    /// Least and greatest number of positional arguments.
    pub arity: (usize, usize),
    /// The options it accepts, and whether each takes a value.
    pub flags: &'static [(&'static str, bool)],
    /// Whether it needs the unlocked vault.
    pub vault: bool,
    run: Handler,
}

/// Most options one command accepts.
const MAX_FLAGS: usize = 10;

/// A parsed command: its table row, positional arguments, and options, all
/// as ranges into the line buffer.
pub struct Cmd {
    /// The command's table row.
    pub spec: &'static CommandSpec,
    pos: Args,
    opts: [Option<Span>; MAX_FLAGS],
}

impl Cmd {
    /// Positional argument `i`.
    #[must_use]
    pub fn arg<'b>(&self, buf: &'b [u8], i: usize) -> Option<&'b [u8]> {
        self.pos.get(buf, i)
    }

    fn slot(&self, flag: &str) -> Option<Span> {
        let i = self.spec.flags.iter().position(|f| f.0 == flag)?;
        self.opts.get(i).copied().flatten()
    }

    /// Whether option `flag` was given.
    #[must_use]
    pub fn has(&self, flag: &str) -> bool {
        self.slot(flag).is_some()
    }

    /// The value of option `flag`, if given.
    #[must_use]
    pub fn opt<'b>(&self, buf: &'b [u8], flag: &str) -> Option<&'b [u8]> {
        let (a, b) = self.slot(flag)?;
        buf.get(a..b)
    }
}

/// Parses tokenized arguments against the command table: the command name
/// or alias, then options (`--name [value]`) and positional arguments in
/// any order. A bare `--` ends the options, so that a name starting with
/// `--` can be addressed.
///
/// # Errors
/// A fixed message: unknown command or option, a missing option value, an
/// option given twice, or the wrong number of arguments.
pub fn parse_command(buf: &[u8], args: &Args) -> Result<Cmd, &'static str> {
    let name = args.get(buf, 0).ok_or("no command given")?;
    let spec = COMMANDS
        .iter()
        .find(|c| c.names.iter().any(|n| n.as_bytes() == name))
        .ok_or("unknown command; type `help` for the list")?;
    let mut cmd = Cmd {
        spec,
        pos: Args::default(),
        opts: [None; MAX_FLAGS],
    };
    let (mut i, mut options) = (1, true);
    while let (Some(span), Some(a)) = (args.span(i), args.get(buf, i)) {
        i += 1;
        if options && a == b"--" {
            options = false;
        } else if options && a.starts_with(b"--") {
            let k = spec.flags.iter().position(|f| f.0.as_bytes() == a);
            let k = k.ok_or("unknown option for this command")?;
            let takes_value = spec.flags.get(k).is_some_and(|f| f.1);
            let value = if takes_value {
                i += 1;
                args.span(i - 1).ok_or("the option needs a value")?
            } else {
                (0, 0)
            };
            let slot = cmd
                .opts
                .get_mut(k)
                .ok_or("unknown option for this command")?;
            if slot.replace(value).is_some() {
                return Err("an option was given twice");
            }
        } else if cmd.pos.len() < spec.arity.1 {
            cmd.pos.push(span)?;
        } else {
            return Err("too many arguments");
        }
    }
    if cmd.pos.len() < spec.arity.0 {
        return Err("missing argument");
    }
    Ok(cmd)
}

/// A decimal number of at most 9 digits (no sign, no spaces).
fn number(v: &[u8]) -> Option<usize> {
    let ok = (1..=9).contains(&v.len()) && v.iter().all(u8::is_ascii_digit);
    core::str::from_utf8(v).ok().filter(|_| ok)?.parse().ok()
}

/// The generation policy named by a command's `gen` options (Section
/// 10.1). `--words` or `--sep` selects a passphrase; they cannot be mixed
/// with the character options. Ranges are checked later by
/// [`Policy::validate`]. The symbol set is borrowed from `buf`.
///
/// # Errors
/// A fixed message for a malformed option value.
pub fn gen_policy<'b>(cmd: &Cmd, buf: &'b [u8]) -> Result<Policy<'b>, &'static str> {
    let num = |flag: &str| match cmd.opt(buf, flag) {
        None => Ok(None),
        Some(v) => number(v).map(Some).ok_or("the option needs a number"),
    };
    let (len, words, sep) = (num("--len")?, num("--words")?, cmd.opt(buf, "--sep"));
    let chars = len.is_some()
        || ["--classes", "--symbols", "--no-ambiguous"]
            .iter()
            .any(|f| cmd.has(f));
    if words.is_none() && sep.is_none() {
        let mut classes = [true; 4];
        if let Some(list) = cmd.opt(buf, "--classes") {
            classes = [false; 4];
            for c in list {
                let k = b"luds".iter().position(|x| x == c);
                let seen = k.and_then(|k| classes.get_mut(k));
                match seen {
                    Some(seen @ false) => *seen = true,
                    _ => return Err("--classes takes each of l, u, d, s at most once"),
                }
            }
        }
        return Ok(Policy::Chars {
            len: len.unwrap_or(20),
            classes,
            symbols: cmd.opt(buf, "--symbols").unwrap_or(r#gen::SYMBOLS),
            no_ambiguous: cmd.has("--no-ambiguous"),
        });
    }
    if chars {
        return Err("password and passphrase options cannot be combined");
    }
    let sep = match sep {
        None => b'-',
        Some([c]) => *c,
        Some(_) => return Err("--sep takes exactly one character"),
    };
    Ok(Policy::Words {
        count: words.unwrap_or(6),
        sep,
    })
}

// ---- Pure helpers: matching, default sensitivity, password strength.

/// Keys whose fields are sensitive by default (Section 9.3).
const SENSITIVE_KEYS: [&str; 10] = [
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
];

/// Whether a field with this key is sensitive by default.
#[must_use]
pub fn default_sensitive(key: &[u8]) -> bool {
    SENSITIVE_KEYS
        .iter()
        .any(|k| k.as_bytes().eq_ignore_ascii_case(key))
}

/// The characters of `s`, lower-cased (Unicode), without allocating.
fn folded(s: &str) -> impl Iterator<Item = char> + '_ {
    s.chars().flat_map(char::to_lowercase)
}

/// Unicode-aware case-insensitive substring test (`ls`). Compares in
/// place; text that is not UTF-8 never matches.
#[must_use]
pub fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    let (Ok(h), Ok(n)) = (core::str::from_utf8(hay), core::str::from_utf8(needle)) else {
        return false;
    };
    let starts = h.char_indices().map(|(i, _)| i).chain([h.len()]);
    starts.into_iter().any(|i| {
        let mut rest = folded(h.get(i..).unwrap_or_default());
        folded(n).all(|c| rest.next() == Some(c))
    })
}

/// Unicode-aware case-insensitive equality (near-duplicate names).
fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    match (core::str::from_utf8(a), core::str::from_utf8(b)) {
        (Ok(a), Ok(b)) => folded(a).eq(folded(b)),
        _ => false,
    }
}

/// A master password needs at least this many characters.
pub const MIN_PASSWORD_CHARS: usize = 16;
/// ... and at least this estimate: log2(10^14 guesses), as Section 6.5.
pub const MIN_PASSWORD_BITS: f64 = 46.5;
/// Bits credited to a word of the embedded list that the user chose.
const WORD_BITS: f64 = 11.0;
/// Bits credited to a character that follows from what precedes it.
const PREDICTABLE_BITS: f64 = 1.0;
/// Bits credited to a year 1900–2099 (log2 of 200).
const YEAR_BITS: f64 = 7.64;
/// Bits credited to a common separator (space, `-`, `_`, `.`) after a word.
const SEP_BITS: f64 = 2.0;
/// US keyboard rows of 10 keys, each half a key right of the one above;
/// the last is the shifted digit row. For walks along rows, columns, and
/// diagonals.
const KEYS: &[u8; 50] = b"1234567890qwertyuiopasdfghjkl;zxcvbnm,./!@#$%^&*()";
/// Common letter substitutions ("leet"): each byte of the first string
/// stands for the letter below it.
const LEET: [&[u8; 9]; 2] = [b"4@31!05$7", b"aaeiiosst"];
/// Breach-corpus roots that the word list lacks (letters as [`unleet`]).
const COMMON: [&[u8]; 4] = [b"iloveyou", b"loveyou", b"letmein", b"trustnoi"];

/// The letter a [`LEET`] substitute stands for, else `b` lower-cased.
fn unleet(b: u8) -> u8 {
    let at = LEET[0].iter().position(|l| *l == b);
    at.and_then(|i| LEET[1].get(i).copied())
        .unwrap_or(b.to_ascii_lowercase())
}

/// Whether `w` (ASCII, any case) is a word of the embedded list: a binary
/// search over the sorted list's bytes, comparing in place.
fn listed(w: &[u8]) -> bool {
    let list = r#gen::WORDS.as_bytes();
    let (mut lo, mut hi) = (0, list.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let before = list.get(lo..mid).unwrap_or_default();
        let start = before
            .iter()
            .rposition(|&c| c == b'\n')
            .map_or(lo, |p| lo + p + 1);
        let tail = list.get(start..hi).unwrap_or_default();
        let len = tail.iter().position(|&c| c == b'\n').unwrap_or(tail.len());
        let line = tail.get(..len).unwrap_or_default();
        let probe = w.iter().map(|b| unleet(*b));
        match line.iter().copied().cmp(probe) {
            core::cmp::Ordering::Equal => return true,
            core::cmp::Ordering::Less => lo = start + len + 1,
            core::cmp::Ordering::Greater => hi = start,
        }
    }
    false
}

/// Length of the longest list word or [`COMMON`] root (5 to 24 letters,
/// leet substitutions undone) at the start of `s`.
fn word_at(s: &[u8]) -> Option<usize> {
    let common = |w: &[u8]| {
        COMMON
            .iter()
            .any(|c| w.iter().map(|b| unleet(*b)).eq(c.iter().copied()))
    };
    (5..=24usize)
        .rev()
        .filter_map(|n| s.get(..n).map(|w| (n, w)))
        .find(|(_, w)| {
            w.iter()
                .all(|c| unleet(*c).is_ascii_lowercase() || *c == b'-')
                && (listed(w) || common(w))
        })
        .map(|(n, _)| n)
}

/// Row (shifted digits on the digit row) and column of `b` on [`KEYS`].
fn key(b: u8) -> Option<(usize, usize)> {
    let at = KEYS.iter().position(|k| *k == b.to_ascii_lowercase());
    at.map(|i| (i / 10 % 4, i % 10))
}

/// Whether `c` is predictable from the text before it: a repeat of the
/// previous character, its neighbour in code-point order or on the
/// keyboard (same row, or the two touching keys of the next row), or the
/// end of a character pair that occurred earlier.
fn predictable(before: &[u8], prev: char, c: char) -> bool {
    let ascii = (u8::try_from(prev).ok(), u8::try_from(c).ok());
    let below =
        |(r, c): (usize, usize), (s, d): (usize, usize)| s == r + 1 && (d == c || d + 1 == c);
    let neighbours = match (ascii.0.and_then(key), ascii.1.and_then(key)) {
        (Some(a), Some(b)) => (a.0 == b.0 && a.1.abs_diff(b.1) == 1) || below(a, b) || below(b, a),
        _ => false,
    };
    let seen = matches!(ascii, (Some(p), Some(q)) if before.windows(2).any(|w| w == [p, q]));
    u32::from(prev).abs_diff(u32::from(c)) <= 1 || neighbours || seen
}

/// A conservative estimate of a chosen master password's strength in bits
/// (log2 of guesses). Written by hand so that the password never leaves
/// the arena (owner decision 2026-11-15: no `zxcvbn`). It reads `pw` in
/// place and allocates nothing. A run of 3 or more bytes that occurred
/// earlier counts 1 bit; a list word or common root counts [`WORD_BITS`]
/// and a year 1900–2099 [`YEAR_BITS`] (either 1 bit if it occurred before
/// in another letter case); a separator after such a token counts
/// [`SEP_BITS`] if common, 0 if it repeats the previous separator; any
/// other character counts log2 of its class size (26 letters, 10 digits,
/// 33 punctuation, 64 otherwise), or 1 bit if [`predictable`]. A
/// heuristic: it bounds common patterns, not every one.
#[must_use]
pub fn strength_bits(pw: &str) -> f64 {
    let bytes = pw.as_bytes();
    let (mut bits, mut i, mut prev, mut sep) = (0.0, 0, None::<char>, None);
    while let Some(c) = pw.get(i..).and_then(|s| s.chars().next()) {
        let (before, rest) = bytes.split_at_checked(i).unwrap_or_default();
        // A run of 3 or more bytes that occurred before is one more guess.
        let again = (0..before.len())
            .map(|j| {
                let earlier = before.get(j..).unwrap_or_default();
                earlier.iter().zip(rest).take_while(|(a, b)| a == b).count()
            })
            .max()
            .unwrap_or(0);
        let again = (3..=again).rev().find(|n| pw.is_char_boundary(i + n));
        let year = matches!(rest.get(..4), Some([b'1', b'9', a, b] | [b'2', b'0', a, b])
            if a.is_ascii_digit() && b.is_ascii_digit());
        let token = (again.map(|n| (n, PREDICTABLE_BITS)))
            .or_else(|| word_at(rest).map(|n| (n, WORD_BITS)))
            .or_else(|| year.then_some((4, YEAR_BITS)));
        if let Some((n, b)) = token {
            let w = rest.get(..n).unwrap_or_default();
            let repeated = before.windows(n).any(|e| e.eq_ignore_ascii_case(w));
            bits += if repeated { PREDICTABLE_BITS } else { b };
            (i, prev) = (i + n, None);
            continue;
        }
        let pool: f64 = match c {
            'a'..='z' | 'A'..='Z' => 26.0,
            '0'..='9' => 10.0,
            c if c.is_ascii() => 33.0,
            _ => 64.0,
        };
        let known = prev.is_some_and(|p| predictable(before, p, c));
        let joint = i > 0 && prev.is_none() && (c == ' ' || c.is_ascii_punctuation());
        bits += match (joint, known) {
            (true, _) if sep == Some(c) => 0.0,
            (true, _) if " -_.".contains(c) => SEP_BITS,
            (_, true) => PREDICTABLE_BITS,
            _ => pool.log2(),
        };
        sep = if joint { Some(c) } else { sep };
        (i, prev) = (i + c.len_utf8(), Some(c));
    }
    bits
}

/// Why `pw` is too weak for a master password, if it is.
#[must_use]
pub fn weakness(pw: &[u8]) -> Option<&'static str> {
    let Ok(s) = core::str::from_utf8(pw) else {
        return Some("it is not valid UTF-8");
    };
    if s.chars().count() < MIN_PASSWORD_CHARS {
        Some("it has fewer than 16 characters")
    } else if strength_bits(s) < MIN_PASSWORD_BITS {
        Some("it is too predictable (estimated below 10^14 guesses)")
    } else {
        None
    }
}

// ---- doctor (Section 9.4): pure checks over facts read from /proc and /sys.

/// Outcome of one `doctor` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The condition holds.
    Pass,
    /// Informational, or a weakness with a documented fallback.
    Warn,
    /// The condition fails; `doctor` exits 1.
    Fail,
}

/// What kind of swap is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swap {
    /// No swap device.
    None,
    /// Only zram or dm-crypt devices.
    Protected,
    /// At least one plain device or file.
    Plain,
}

/// Classifies `/proc/swaps`. `dm_uuid` returns the content of
/// `/sys/block/<dm-N>/dm/uuid`; a `CRYPT-` prefix means dm-crypt.
#[must_use]
pub fn swap_kind(proc_swaps: &str, dm_uuid: &dyn Fn(&str) -> Option<String>) -> Swap {
    let mut kind = Swap::None;
    for line in proc_swaps.lines().skip(1) {
        let dev = line.split_whitespace().next().unwrap_or_default();
        let name = dev.strip_prefix("/dev/").unwrap_or_default();
        let crypt =
            name.starts_with("dm-") && dm_uuid(name).is_some_and(|u| u.starts_with("CRYPT-"));
        if name.starts_with("zram") || crypt {
            kind = if kind == Swap::Plain {
                kind
            } else {
                Swap::Protected
            };
        } else if !dev.is_empty() {
            kind = Swap::Plain;
        }
    }
    kind
}

/// The facts `doctor` judges. `None` means the source could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// Effective `RLIMIT_MEMLOCK` in bytes (`None`: unlimited).
    pub memlock: Option<u64>,
    /// Arena size in bytes.
    pub arena: u64,
    /// Argon2 memory of the vault header in KiB, if a vault was readable.
    pub kdf_kib: Option<u32>,
    /// Active swap.
    pub swap: Swap,
    /// Whether hibernation is available (`/sys/power/state`, `disk`).
    pub hibernation: bool,
    /// `/proc/sys/fs/suid_dumpable`.
    pub suid_dumpable: Option<u32>,
    /// `/proc/sys/kernel/yama/ptrace_scope`.
    pub ptrace_scope: Option<u32>,
    /// Why the vault location was refused; empty if it passed. `None`: no
    /// vault exists yet.
    pub vault: Option<String>,
    /// `XDG_CURRENT_DESKTOP`.
    pub desktop: String,
}

/// The `doctor` report: one status, check name, and remedy or detail per
/// check of Section 9.4, in table order.
#[must_use]
pub fn doctor_report(f: &Facts) -> Vec<(Status, &'static str, String)> {
    use Status::{Fail, Pass, Warn};
    let fits = |need: u64| f.memlock.is_none_or(|l| l >= need);
    let limit = f
        .memlock
        .map_or("unlimited".to_owned(), |l| format!("{} KiB", l / 1024));
    let st = |ok: bool, bad: Status| if ok { Pass } else { bad };
    let kdf = u64::from(f.kdf_kib.unwrap_or(KdfParams::DEFAULT.m_kib)) * 1024;
    let desktop = f.desktop.to_ascii_lowercase();
    vec![
        (
            st(fits(f.arena), Fail),
            "Arena lockable",
            format!("RLIMIT_MEMLOCK is {limit}; raise it in /etc/security/limits.d/ or pass --allow-unlocked-memory"),
        ),
        (
            st(fits(kdf), Warn),
            "KDF memory lockable",
            format!("RLIMIT_MEMLOCK is {limit}, key derivation uses {} KiB; use encrypted swap or raise the limit (LimitMEMLOCK=)", kdf / 1024),
        ),
        (
            st(f.swap != Swap::Plain, Fail),
            "Swap",
            "unencrypted swap is active; use dm-crypt or zram swap, or `swapoff -a`".to_owned(),
        ),
        (
            st(!f.hibernation || f.swap != Swap::Plain, Fail),
            "Hibernation",
            "hibernation writes locked memory to unencrypted swap; disable it or encrypt swap".to_owned(),
        ),
        (
            st(f.suid_dumpable == Some(0), Fail),
            "Core dumps",
            "set fs.suid_dumpable = 0 (for example in /etc/sysctl.d/)".to_owned(),
        ),
        (
            st(f.ptrace_scope.is_some_and(|s| s >= 1), Warn),
            "ptrace scope",
            "set kernel.yama.ptrace_scope = 1 or higher".to_owned(),
        ),
        match &f.vault {
            None => (Warn, "Vault location", "no vault yet; create one with `pwv init`".to_owned()),
            Some(why) => (st(why.is_empty(), Fail), "Vault location", why.clone()),
        },
        (
            st(desktop.contains("kde"), Warn),
            "Clipboard history",
            "informational: only clipboard managers that honour the KDE password hint skip copied values (GNOME falls back to XWayland)".to_owned(),
        ),
    ]
}

// ---- Session.

/// How a failed command affects the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Report and return to the prompt.
    Error,
    /// The user cancelled (SIGINT); a guided command is abandoned.
    Cancel,
    /// Leave the session: quit, idle expiry, a signal, or a failed save.
    Exit,
}

/// A command's failure: exit code, fixed secret-free message, and effect.
struct Fail {
    code: i32,
    msg: String,
    kind: Kind,
}

fn fail(code: i32, msg: &str) -> Fail {
    let (msg, kind) = (msg.to_owned(), Kind::Error);
    Fail { code, msg, kind }
}

fn user(msg: &str) -> Fail {
    fail(EXIT_USER, msg)
}

fn leave(code: i32, msg: &str) -> Fail {
    Fail {
        kind: Kind::Exit,
        ..fail(code, msg)
    }
}

impl From<vault::Error> for Fail {
    fn from(e: vault::Error) -> Self {
        fail(exit_code(e), e.message())
    }
}

impl From<crypto::Error> for Fail {
    fn from(e: crypto::Error) -> Self {
        vault::Error::Crypto(e).into()
    }
}

impl From<store::Error> for Fail {
    fn from(e: store::Error) -> Self {
        fail(store_exit_code(&e), e.message())
    }
}

impl From<r#gen::Error> for Fail {
    fn from(e: r#gen::Error) -> Self {
        fail(gen_exit_code(e), e.message())
    }
}

impl From<clip::Error> for Fail {
    fn from(e: clip::Error) -> Self {
        fail(EXIT_ENV, e.message())
    }
}

impl From<term::Error> for Fail {
    fn from(e: term::Error) -> Self {
        use term::Error as T;
        match e {
            T::TooLong | T::Utf8 | T::Resumed => user(e.message()),
            T::Interrupted => Fail {
                kind: Kind::Cancel,
                ..user(e.message())
            },
            T::Eof | T::Terminated => leave(0, ""),
            T::NoTty | T::Io => leave(EXIT_ENV, e.message()),
        }
    }
}

/// Global options (Section 9.1).
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent flag per switch of the Section 9.1 table"
)]
struct Options {
    vault: Option<OsString>,
    idle: u64,
    clip: u64,
    arena: usize,
    allow_unlocked: bool,
    require_locked_kdf: bool,
    allow_foreign_fs: bool,
    no_color: bool,
}

/// Default clipboard timeout in seconds. The specification says 20; the
/// owner chose 10 on 2026-11-15, because the copied value also lives on
/// the unlocked heap inside `arboard` for that long (`DESIGN_NOTES`).
pub const DEFAULT_CLIP_TIMEOUT: u64 = 10;

/// Parses the global flags that precede the command. Returns the options
/// and the index of the first command argument.
fn globals(argv: &[OsString]) -> Result<(Options, usize), String> {
    let mut o = Options {
        vault: None,
        idle: 300,
        clip: DEFAULT_CLIP_TIMEOUT,
        arena: secmem::DEFAULT_ARENA / 1024,
        allow_unlocked: false,
        require_locked_kdf: false,
        allow_foreign_fs: false,
        no_color: false,
    };
    let mut i = 0;
    while let Some(flag) = argv
        .get(i)
        .and_then(|a| a.to_str())
        .filter(|a| a.starts_with("--"))
    {
        let value = argv.get(i + 1);
        let ranged = |lo: usize, hi: usize| {
            value
                .and_then(|v| number(v.as_bytes()))
                .filter(|n| (lo..=hi).contains(n))
                .ok_or(format!("{flag} needs a number from {lo} to {hi}"))
        };
        i += 2;
        match flag {
            "--vault" => o.vault = Some(value.ok_or("--vault needs a path")?.clone()),
            "--idle-timeout" => o.idle = ranged(30, 3600)? as u64,
            "--clip-timeout" => o.clip = ranged(5, 300)? as u64,
            "--arena-size" => o.arena = ranged(256, 6144)?,
            _ => {
                i -= 1;
                match flag {
                    "--allow-unlocked-memory" => o.allow_unlocked = true,
                    "--require-locked-kdf" => o.require_locked_kdf = true,
                    "--allow-foreign-fs" => o.allow_foreign_fs = true,
                    "--no-color" => o.no_color = true,
                    _ => return Err(format!("unknown option {flag}; see `pwv help`")),
                }
            }
        }
    }
    Ok((o, i))
}

/// The open vault of a session.
struct Vault<'a> {
    store: Store,
    header: Header,
    model: vault::Model<'a>,
}

/// Which slot a prompt reads into.
#[derive(Clone, Copy)]
enum To {
    Input,
    Pw1,
    Pw2,
}

/// The session context, passed by reference to every command (E1): the
/// terminal, the clipboard, the arena slots, and the open vault.
struct Session<'a> {
    term: term::Term,
    clip: clip::Clip,
    opts: Options,
    hard: Hardening,
    /// Whether the arena is locked in RAM (else the prompt warns).
    locked: bool,
    /// One-shot invocation (`pwv <command> ...`), not the REPL.
    one_shot: bool,
    input: SecretSlot<'a>,
    pw1: SecretSlot<'a>,
    pw2: SecretSlot<'a>,
    kek: SecretSlot<'a>,
    dek: SecretSlot<'a>,
    new_dek: SecretSlot<'a>,
    r#gen: SecretSlot<'a>,
    clip_slot: SecretSlot<'a>,
    /// The two vault halves until a vault is opened or created.
    halves: Option<(SecretSlot<'a>, SecretSlot<'a>)>,
    vault: Option<Vault<'a>>,
    clip_deadline: Option<Instant>,
}

/// Clear-if-unchanged on every exit path, unwinding from a panic included,
/// before the `Clip` field is dropped (Section 11.3 steps 3 and 4).
impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.expire_clip();
    }
}

fn no_vault() -> Fail {
    fail(EXIT_INTERNAL, "internal error: no open vault")
}

/// Copies `v` into `slot` (an arena slot), replacing its content.
fn park(slot: &mut SecretSlot<'_>, v: &[u8]) -> Result<(), Fail> {
    slot.clear();
    slot.set_len(v.len()).map_err(|e| user(e.message()))?;
    slot.expose_mut().copy_from_slice(v);
    Ok(())
}

/// The field of `e` whose key matches `key` (ASCII case-insensitive).
fn field<'e>(e: &EntryRef<'e>, key: &[u8]) -> Option<FieldRef<'e>> {
    e.fields.clone().find(|f| f.key.eq_ignore_ascii_case(key))
}

impl Session<'_> {
    fn say(&self, text: &str) {
        self.term.write(text.as_bytes());
    }

    fn report(&self, f: &Fail) {
        if !f.msg.is_empty() {
            self.say(&format!("pwv: {}\n", f.msg));
        }
    }

    /// Clear-if-unchanged (Section 11.3 step 3), on expiry and on exit.
    fn expire_clip(&mut self) {
        self.clip.clear_if_unchanged(&mut self.clip_slot);
        self.clip_deadline = None;
    }

    /// Writes `text`, then reads one line into slot `to`. The single
    /// `poll` loop: it enforces the idle and clipboard deadlines while
    /// waiting (Section 11.1).
    fn prompt(&mut self, text: &str, to: To, hidden: bool) -> Result<(), Fail> {
        // Echo goes off before the prompt appears, so nothing typed in
        // answer to it is ever echoed.
        let _hidden = if hidden {
            Some(self.term.hide()?)
        } else {
            None
        };
        self.say(text);
        let idle = Instant::now() + Duration::from_secs(self.opts.idle);
        loop {
            let now = Instant::now();
            if self.clip_deadline.is_some_and(|d| d <= now) {
                self.clip.clear_if_unchanged(&mut self.clip_slot);
                self.clip_deadline = None;
            }
            if idle <= now {
                let secs = self.opts.idle;
                return Err(leave(0, &format!("\nLocked after {secs} s without input.")));
            }
            let next = self.clip_deadline.map_or(idle, |d| d.min(idle));
            if self.term.wait(Some(next.saturating_duration_since(now)))? {
                break;
            }
        }
        let out = match to {
            To::Input => &mut self.input,
            To::Pw1 => &mut self.pw1,
            To::Pw2 => &mut self.pw2,
        };
        Ok(self.term.read_line(out)?)
    }

    /// Asks a yes/no question; anything but `y` or `yes` refuses.
    fn confirm(&mut self, question: &str) -> Result<(), Fail> {
        self.prompt(question, To::Input, false)?;
        let a = self.input.expose();
        if a.eq_ignore_ascii_case(b"y") || a.eq_ignore_ascii_case(b"yes") {
            Ok(())
        } else {
            Err(user("not confirmed; nothing was changed"))
        }
    }

    /// Reads a hidden value twice into `Input`. The first entry waits in
    /// the vault's scratch half and is compared in constant time.
    fn hidden_twice(&mut self) -> Result<(), Fail> {
        self.prompt("Value (hidden): ", To::Input, true)?;
        let Some(v) = self.vault.as_mut() else {
            return Err(no_vault());
        };
        park(v.model.scratch(), self.input.expose())?;
        let read = self.prompt("Repeat: ", To::Input, true);
        let Some(v) = self.vault.as_mut() else {
            return Err(no_vault());
        };
        let same = crypto::ct_eq(v.model.scratch().expose(), self.input.expose());
        v.model.scratch().clear();
        read?;
        if same {
            Ok(())
        } else {
            Err(user("the two entries differ; nothing was changed"))
        }
    }

    fn paths(&self) -> Result<Paths, Fail> {
        Ok(Paths::resolve(self.opts.vault.as_deref(), &|k| {
            std::env::var_os(k)
        })?)
    }

    /// The Section 5.4 step 3 notice, once per key derivation.
    fn kdf_notice(&self, out: &crypto::KdfOutcome) {
        if !out.locked {
            let limit = self
                .hard
                .memlock_limit
                .map_or("unlimited".to_owned(), |l| format!("{} KiB", l / 1024));
            self.say(&format!(
                "Note: the key-derivation memory could not be locked (RLIMIT_MEMLOCK is {limit}). \
                 Use encrypted swap, or raise the limit in /etc/security/limits.d/ or with \
                 LimitMEMLOCK= in a systemd user unit.\n"
            ));
        }
    }

    /// Opens and unlocks the vault (Sections 4, 8.2, 8.4).
    fn unlock(&mut self) -> Result<(), Fail> {
        let (store, file) = Store::open(self.paths()?, self.opts.allow_foreign_fs)?;
        let Some((mut live, scratch)) = self.halves.take() else {
            return Err(no_vault());
        };
        self.prompt("Master password: ", To::Pw1, true)?;
        let locked = self.opts.require_locked_kdf;
        let derived = vault::derive(&file, &mut self.pw1, &mut self.pw2, &mut self.kek, locked);
        // The notice also when the password proves wrong (review R-12).
        if let Ok(out) = &derived {
            self.kdf_notice(out);
        }
        let (kek, dek) = (self.kek.expose(), &mut self.dek);
        let opened = derived.and_then(|_| vault::open_with_kek(&file, kek, dek, &mut live));
        self.kek.clear();
        sys::scrub_stack();
        let mut header = opened?;
        let fresh = store.freshness(&header)?;
        if let Freshness::RolledBack { file, recorded } = fresh {
            self.say(&rollback_warning(file, recorded));
            // Into `Pw2` (free after unlock), never `Input`: a one-shot
            // command's argument spans still point into `Input`.
            let read = self.prompt("\nType yes to continue: ", To::Pw2, false);
            let ok = read.map(|()| confirm_rollback(&mut header, fresh, self.pw2.expose()));
            self.pw2.clear();
            ok?.map_err(|code| leave(code, "rollback not acknowledged; vault not opened"))?;
        }
        let model = vault::Model::new(live, scratch)?;
        self.vault = Some(Vault {
            store,
            header,
            model,
        });
        Ok(())
    }

    /// Saves the model (Section 8.3): exactly once per mutating command. A
    /// failure is fatal to the session (Section 8.5).
    fn save(&mut self) -> Result<(), Fail> {
        let Some(v) = self.vault.as_mut() else {
            return Err(no_vault());
        };
        let sealed = v.model.seal(self.dek.expose(), &mut v.header);
        let res = sealed
            .map_err(Fail::from)
            .and_then(|file| Ok(v.store.save(&file)?));
        sys::scrub_stack();
        res.map_err(|f| {
            let msg = format!(
                "save failed ({}); exiting, because memory and disk may no longer agree",
                f.msg
            );
            leave(f.code, &msg)
        })
    }

    /// Starts the clipboard deadline; a one-shot command then stays alive
    /// until it expires or Enter is pressed (Section 11.3 step 5).
    fn copied(&mut self) -> Result<(), Fail> {
        let secs = self.opts.clip;
        self.clip_deadline = Some(Instant::now() + Duration::from_secs(secs));
        if !self.one_shot {
            self.say(&format!("Copied. Clearing in {secs} s.\n"));
            return Ok(());
        }
        self.say(&format!(
            "Copied. Clearing in {secs} s (Enter to clear now).\n"
        ));
        while let Some(d) = self.clip_deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            if self.term.wait(Some(left))? {
                self.term.read_line(&mut self.input)?;
                break;
            }
        }
        self.expire_clip();
        Ok(())
    }

    /// Generates under the policy named by `c`'s options into the `Gen`
    /// slot and prints the entropy.
    fn generate(&mut self, c: &Cmd) -> Result<(), Fail> {
        let policy = gen_policy(c, self.input.expose()).map_err(user)?;
        let h = r#gen::generate(&mut r#gen::OsBytes, &policy, &mut self.r#gen)?;
        self.say(&format!("Entropy: {:.1} bits\n", h.bits));
        Ok(())
    }

    /// Obtains a new master password (Section 6.5) and leaves its NFC form
    /// in `Pw2`. A generated 6-word passphrase is the default and strongly
    /// recommended; a chosen password is entered twice, compared in
    /// constant time, and must pass [`weakness`] unless `accept_weak` and
    /// the confirmation sentence is typed.
    fn new_password(&mut self, accept_weak: bool) -> Result<(), Fail> {
        self.prompt(
            "A generated 6-word passphrase (about 106 bits) is strongly recommended.\n\
             Use a generated passphrase? [Y/n] ",
            To::Input,
            false,
        )?;
        let a = self.input.expose();
        if a.is_empty() || a.eq_ignore_ascii_case(b"y") || a.eq_ignore_ascii_case(b"yes") {
            r#gen::generate(&mut r#gen::OsBytes, &Policy::DEFAULT_WORDS, &mut self.r#gen)?;
            self.say("Your master passphrase is shown once. Write it down:\n\n  ");
            self.term.write_sanitized(self.r#gen.expose());
            let shown = self.prompt("\n\nPress Enter to clear the screen. ", To::Input, false);
            self.term.clear_screen();
            shown?;
            self.prompt("Type the passphrase to confirm: ", To::Pw1, true)?;
            let same = crypto::ct_eq(self.pw1.expose(), self.r#gen.expose());
            self.r#gen.clear();
            if !same {
                return Err(user("the passphrase does not match; nothing was changed"));
            }
        } else if a.eq_ignore_ascii_case(b"n") || a.eq_ignore_ascii_case(b"no") {
            self.say(
                "Warning: a password you choose is usually far weaker than a generated \
                 passphrase, and the master password protects everything in the vault.\n",
            );
            self.prompt("New master password: ", To::Pw1, true)?;
            self.prompt("Repeat: ", To::Pw2, true)?;
            if !crypto::ct_eq(self.pw1.expose(), self.pw2.expose()) {
                return Err(user("the two passwords differ; nothing was changed"));
            }
            if let Some(why) = weakness(self.pw1.expose()) {
                if !accept_weak {
                    return Err(user(&format!(
                        "password refused: {why}. Use the generated passphrase, a stronger \
                         password, or --accept-weak-password"
                    )));
                }
                self.say(&format!("Warning: this password is weak: {why}.\n"));
                self.prompt(
                    "Type \"I accept a weak master password\" to continue: ",
                    To::Input,
                    false,
                )?;
                if self.input.expose() != b"I accept a weak master password" {
                    return Err(user("not confirmed; nothing was changed"));
                }
            }
        } else {
            return Err(user("answer y or n; nothing was changed"));
        }
        let nfc = crypto::normalize(self.pw1.expose(), &mut self.pw2);
        self.pw1.clear();
        Ok(nfc?)
    }

    /// Wipes the per-command slots.
    fn tidy(&mut self) {
        for slot in [
            &mut self.input,
            &mut self.pw1,
            &mut self.pw2,
            &mut self.r#gen,
            &mut self.kek,
            &mut self.new_dek,
        ] {
            slot.clear();
        }
        if let Some(v) = self.vault.as_mut() {
            v.model.scratch().clear();
        }
    }

    /// Parses and runs the command in `Input`, unlocking first if needed.
    fn exec(&mut self, args: &Args) -> Result<(), Fail> {
        let cmd = parse_command(self.input.expose(), args).map_err(user)?;
        if cmd.spec.vault && self.vault.is_none() {
            self.unlock().map_err(|f| leave(f.code, &f.msg))?;
            sys::scrub_stack();
        }
        (cmd.spec.run)(self, &cmd)
    }

    /// One-shot mode: the arguments are copied into `Input` as they are
    /// (no tokenizing, so no quoting rules apply).
    fn one_shot(&mut self, argv: &[OsString]) -> Result<(), Fail> {
        let mut spans = Args::default();
        let total: usize = argv.iter().map(|a| a.len()).sum();
        self.input.set_len(total).map_err(|e| user(e.message()))?;
        let mut at = 0;
        for a in argv {
            let end = at + a.len();
            if let Some(dst) = self.input.expose_mut().get_mut(at..end) {
                dst.copy_from_slice(a.as_bytes());
            }
            spans.push((at, end)).map_err(user)?;
            at = end;
        }
        self.exec(&spans)
    }

    /// The interactive session.
    fn repl(&mut self) -> Result<(), Fail> {
        self.unlock().map_err(|f| leave(f.code, &f.msg))?;
        sys::scrub_stack();
        loop {
            let prompt = if self.locked {
                "pwv> "
            } else {
                "pwv [memory not locked]> "
            };
            let res = self.prompt(prompt, To::Input, false).and_then(|()| {
                let args = tokenize(self.input.expose_mut()).map_err(user)?;
                if args.is_empty() {
                    Ok(())
                } else {
                    self.exec(&args)
                }
            });
            self.tidy();
            if let Err(f) = res {
                if f.kind == Kind::Exit {
                    return Err(f);
                }
                self.report(&f);
            }
        }
    }
}

// ---- Commands (Section 9.2). Each handler is one row of `COMMANDS`.

fn cmd_ls(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let pattern = cmd.arg(ses.input.expose(), 0).unwrap_or_default();
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    for e in v.model.entries().filter(|e| contains_ci(e.name, pattern)) {
        ses.term.style(1);
        ses.term.write_sanitized(e.name);
        ses.term.style(0);
        ses.term.write(b"\n");
    }
    Ok(())
}

fn cmd_show(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let name = cmd.arg(ses.input.expose(), 0).unwrap_or_default();
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v.model.get(name).ok_or(vault::Error::NoEntry)?;
    ses.term.style(1);
    ses.term.write_sanitized(e.name);
    ses.term.style(0);
    ses.term.write(b"\n");
    for f in e.fields {
        ses.term.write(b"  ");
        ses.term.write_sanitized(f.key);
        ses.term.write(b": ");
        if f.sensitive {
            ses.term.style(2);
            ses.term.write(term::MASK.as_bytes());
            ses.term.style(0);
        } else {
            ses.term.write_sanitized(f.value);
        }
        ses.term.write(b"\n");
    }
    Ok(())
}

fn cmd_reveal(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    let (name, key) = (
        cmd.arg(buf, 0).unwrap_or_default(),
        cmd.arg(buf, 1).unwrap_or_default(),
    );
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v.model.get(name).ok_or(vault::Error::NoEntry)?;
    let f = field(&e, key).ok_or(vault::Error::NoField)?;
    ses.term.write_sanitized(f.value);
    let read = ses.prompt("\nPress Enter to clear the screen. ", To::Input, false);
    ses.term.clear_screen();
    read
}

fn cmd_copy(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v
        .model
        .get(cmd.arg(buf, 0).unwrap_or_default())
        .ok_or(vault::Error::NoEntry)?;
    let f = match cmd.arg(buf, 1) {
        Some(key) => field(&e, key),
        None => e.fields.clone().find(|f| f.sensitive),
    };
    let f = f.ok_or(vault::Error::NoField)?;
    ses.clip.copy(f.value, &mut ses.clip_slot)?;
    ses.copied()
}

fn cmd_gen(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    ses.generate(cmd)?;
    if cmd.has("--show") {
        ses.term.write_sanitized(ses.r#gen.expose());
        ses.term.write(b"\n");
    }
    let copied = ses.clip.copy(ses.r#gen.expose(), &mut ses.clip_slot);
    ses.r#gen.clear();
    copied?;
    ses.copied()
}

/// One round of the guided `add`: `Ok(true)` when the user finished.
fn add_field(ses: &mut Session<'_>) -> Result<bool, Fail> {
    ses.prompt("Field key (. to finish): ", To::Input, false)?;
    if ses.input.expose() == b"." {
        return Ok(true);
    }
    format::check_key(ses.input.expose(), 0).map_err(vault::Error::Invalid)?;
    park(&mut ses.pw2, ses.input.expose())?;
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v.model.get(ses.pw1.expose()).ok_or(vault::Error::NoEntry)?;
    if field(&e, ses.pw2.expose()).is_some() {
        return Err(vault::Error::FieldExists.into());
    }
    let secret = default_sensitive(ses.pw2.expose());
    let ask = if secret {
        "Value: typed, hidden, or gen [options]? [hidden] "
    } else {
        "Value: typed, hidden, or gen [options]? [typed] "
    };
    ses.prompt(ask, To::Input, false)?;
    let args = tokenize(ses.input.expose_mut()).map_err(user)?;
    let default: &[u8] = if secret { b"hidden" } else { b"typed" };
    let mode = args.get(ses.input.expose(), 0).unwrap_or(default);
    let (generated, sensitive) = match mode {
        b"gen" => {
            let cmd = parse_command(ses.input.expose(), &args).map_err(user)?;
            ses.generate(&cmd)?;
            (true, true)
        }
        b"hidden" => {
            ses.hidden_twice()?;
            (false, true)
        }
        b"typed" => {
            ses.prompt("Value: ", To::Input, false)?;
            (false, secret)
        }
        _ => return Err(user("answer typed, hidden, or gen [options]")),
    };
    let value = if generated { &ses.r#gen } else { &ses.input };
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.set(
        ses.pw1.expose(),
        ses.pw2.expose(),
        sensitive,
        value.expose(),
    )?;
    Ok(false)
}

fn cmd_add(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    park(
        &mut ses.pw1,
        cmd.arg(ses.input.expose(), 0).unwrap_or_default(),
    )?;
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    let name = ses.pw1.expose();
    let near = v
        .model
        .entries()
        .any(|e| e.name != name && eq_ci(e.name, name));
    v.model.add(name)?;
    if near {
        ses.say("Note: an entry whose name differs only in letter case already exists.\n");
    }
    let done = loop {
        match add_field(ses) {
            Ok(true) => break Ok(()),
            Ok(false) => {}
            Err(f) if f.kind == Kind::Error => ses.report(&f),
            Err(f) => break Err(f),
        }
    };
    if done.is_err() {
        // Cancelled: remove the entry again. Nothing was saved, and the
        // canonical form is unique, so memory equals disk again.
        if let Some(v) = ses.vault.as_mut() {
            v.model.scratch().clear();
            let _ = v.model.rm(ses.pw1.expose());
        }
        return done;
    }
    ses.save()
}

fn cmd_set(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    park(&mut ses.pw1, cmd.arg(buf, 0).unwrap_or_default())?;
    park(&mut ses.pw2, cmd.arg(buf, 1).unwrap_or_default())?;
    let generated = cmd.has("--gen");
    let gen_options = cmd.spec.flags.iter().take(6).any(|f| cmd.has(f.0));
    if (gen_options && !generated) || (cmd.has("--sensitive") && cmd.has("--plain")) {
        return Err(user(
            "generation options need --gen; --sensitive excludes --plain",
        ));
    }
    format::check_key(ses.pw2.expose(), 0).map_err(vault::Error::Invalid)?;
    if generated {
        ses.generate(cmd)?;
    }
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v.model.get(ses.pw1.expose()).ok_or(vault::Error::NoEntry)?;
    let was_sensitive = field(&e, ses.pw2.expose()).is_some_and(|f| f.sensitive);
    let sensitive = !cmd.has("--plain")
        && (cmd.has("--sensitive")
            || generated
            || was_sensitive
            || default_sensitive(ses.pw2.expose()));
    if was_sensitive {
        ses.confirm("Replace the sensitive value? [y/N] ")?;
    }
    if !generated && sensitive {
        ses.hidden_twice()?;
    } else if !generated {
        ses.prompt("Value: ", To::Input, false)?;
    }
    let value = if generated { &ses.r#gen } else { &ses.input };
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.set(
        ses.pw1.expose(),
        ses.pw2.expose(),
        sensitive,
        value.expose(),
    )?;
    ses.save()
}

fn cmd_unset(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    park(&mut ses.pw1, cmd.arg(buf, 0).unwrap_or_default())?;
    park(&mut ses.pw2, cmd.arg(buf, 1).unwrap_or_default())?;
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    let e = v.model.get(ses.pw1.expose()).ok_or(vault::Error::NoEntry)?;
    field(&e, ses.pw2.expose()).ok_or(vault::Error::NoField)?;
    ses.confirm("Remove the field? [y/N] ")?;
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.unset(ses.pw1.expose(), ses.pw2.expose())?;
    ses.save()
}

fn cmd_mv(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.mv(
        cmd.arg(buf, 0).unwrap_or_default(),
        cmd.arg(buf, 1).unwrap_or_default(),
    )?;
    ses.save()
}

fn cmd_mvfield(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let buf = ses.input.expose();
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.mvfield(
        cmd.arg(buf, 0).unwrap_or_default(),
        cmd.arg(buf, 1).unwrap_or_default(),
        cmd.arg(buf, 2).unwrap_or_default(),
    )?;
    ses.save()
}

fn cmd_rm(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    park(
        &mut ses.pw1,
        cmd.arg(ses.input.expose(), 0).unwrap_or_default(),
    )?;
    let v = ses.vault.as_ref().ok_or_else(no_vault)?;
    v.model.get(ses.pw1.expose()).ok_or(vault::Error::NoEntry)?;
    ses.prompt(
        "Type the entry name to confirm deletion: ",
        To::Input,
        false,
    )?;
    if !crypto::ct_eq(ses.input.expose(), ses.pw1.expose()) {
        return Err(user("the name does not match; nothing was deleted"));
    }
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    v.model.rm(ses.pw1.expose())?;
    ses.save()
}

/// `--kdf-memory <MiB>` and `--kdf-time <t>`, where given.
fn kdf_options(cmd: &Cmd, buf: &[u8]) -> Result<(Option<u32>, Option<u32>), Fail> {
    let num = |flag: &str, scale: usize| match cmd.opt(buf, flag) {
        None => Ok(None),
        Some(v) => number(v)
            .and_then(|n| u32::try_from(n.checked_mul(scale)?).ok())
            .map(Some)
            .ok_or_else(|| Fail::from(crypto::Error::KdfParams)),
    };
    Ok((num("--kdf-memory", 1024)?, num("--kdf-time", 1)?))
}

fn cmd_init(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    if ses.vault.is_some() {
        return Err(user("a vault is already open; `init` creates a new one"));
    }
    let (m, t) = kdf_options(cmd, ses.input.expose())?;
    let d = KdfParams::DEFAULT;
    let params = KdfParams::for_write(m.unwrap_or(d.m_kib), t.unwrap_or(d.t))?;
    let weak = cmd.has("--accept-weak-password");
    let store = Store::create(ses.paths()?, ses.opts.allow_foreign_fs)?;
    ses.new_password(weak)?;
    let made = vault::init(
        ses.pw2.expose(),
        params,
        &mut ses.kek,
        &mut ses.dek,
        ses.opts.require_locked_kdf,
    );
    ses.pw2.clear();
    let (header, out) = made?;
    ses.kdf_notice(&out);
    let (live, scratch) = ses.halves.take().ok_or_else(no_vault)?;
    let model = vault::Model::new(live, scratch)?;
    ses.vault = Some(Vault {
        store,
        header,
        model,
    });
    ses.save()?;
    ses.say("Vault created.\n");
    Ok(())
}

fn cmd_passwd(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let (m, t) = kdf_options(cmd, ses.input.expose())?;
    let weak = cmd.has("--accept-weak-password");
    let locked = ses.opts.require_locked_kdf;
    let old = ses.vault.as_ref().ok_or_else(no_vault)?.header.clone();
    let aad = old.encode();
    let current = KdfParams {
        m_kib: old.kdf_m_kib,
        t: old.kdf_t,
    };
    // Checked before any prompt or key derivation (review finding R-12).
    let params = KdfParams::for_write(m.unwrap_or(current.m_kib), t.unwrap_or(current.t))?;
    ses.prompt("Current master password: ", To::Pw1, true)?;
    // Verify the current password: derive its KEK and unwrap the DEK.
    let nfc = crypto::normalize(ses.pw1.expose(), &mut ses.pw2);
    ses.pw1.clear();
    let checked = nfc
        .and_then(|()| {
            crypto::derive_kek(ses.pw2.expose(), &old.salt, current, &mut ses.kek, locked)
        })
        .and_then(|out| {
            let aad_w = aad.get(..format::AAD_W_LEN).unwrap_or_default();
            crypto::unwrap_dek(
                ses.kek.expose(),
                &old.wrap_nonce,
                &old.wrapped_dek,
                aad_w,
                &mut ses.new_dek,
            )?;
            Ok(out)
        });
    for slot in [&mut ses.pw2, &mut ses.kek, &mut ses.new_dek] {
        slot.clear();
    }
    sys::scrub_stack();
    ses.kdf_notice(&checked?);
    ses.new_password(weak)?;
    let rekeyed = vault::passwd(
        &old,
        ses.pw2.expose(),
        Some(params),
        &mut ses.kek,
        &mut ses.new_dek,
        locked,
    );
    ses.pw2.clear();
    let (mut header, _) = rekeyed?;
    // Re-encrypt under the new DEK; adopt it only once the file is saved.
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    let file = v.model.seal(ses.new_dek.expose(), &mut header)?;
    let saved = v.store.save(&file);
    sys::scrub_stack();
    saved.map_err(|e| leave(store_exit_code(&e), e.message()))?;
    vault::adopt_dek(&mut ses.dek, &mut ses.new_dek)?;
    v.header = header;
    // The backups are still encrypted under the old password (R-11).
    let purged = if cmd.has("--purge-backups") {
        v.store.purge_backups().map(|()| "Backups deleted.\n")
    } else {
        Ok(
            "Note: the backups (.1 to .5) still open with the old password until later \
            saves replace them; `passwd --purge-backups` deletes them.\n",
        )
    };
    ses.say("Master password changed.\n");
    ses.say(purged.map_err(|e| fail(store_exit_code(&e), "deleting the backups failed"))?);
    Ok(())
}

/// Raw-reads standard input to its end into `scratch` (Section 12.2); the
/// cap is the slot size. On error `scratch` is empty.
fn read_pipe(scratch: &mut SecretSlot<'_>) -> Result<(), Fail> {
    scratch.clear();
    let cap = scratch.capacity();
    scratch.set_len(cap).map_err(|e| user(e.message()))?;
    let mut n = 0;
    let read = loop {
        let free = scratch.expose_mut().get_mut(n..).unwrap_or_default();
        match sys::read_fd(sys::stdin(), free) {
            _ if free.is_empty() => break Err(vault::Error::Capacity.into()),
            Ok(0) => break Ok(()),
            Ok(k) => n += k,
            Err(sys::Errno::INTR) if sys::take_signal().is_none() => {}
            Err(sys::Errno::INTR) => break Err(term::Error::Terminated.into()),
            Err(_) => break Err(fail(EXIT_ENV, "cannot read standard input")),
        }
    };
    let sized = scratch.set_len(n);
    if read.is_err() || sized.is_err() {
        scratch.clear();
        return read.and(Err(no_vault()));
    }
    Ok(())
}

/// `import` unlocks by itself, after the pipe was read to its end (owner
/// decision 2026-11-16): the producer of the pipe asks for the legacy
/// passphrase on the same terminal, so the master password is asked only
/// once that program has finished. The body waits in the scratch half.
fn cmd_import(ses: &mut Session<'_>, cmd: &Cmd) -> Result<(), Fail> {
    let suffix = match cmd.opt(ses.input.expose(), "--on-conflict") {
        None | Some(b"abort") => false,
        Some(b"suffix") => true,
        Some(_) => return Err(user("--on-conflict takes abort or suffix")),
    };
    // A pipe only, not a terminal or a regular file (Section 12.2 step 1),
    // and refused before any key derivation.
    if !(cmd.has("--from-stdin") && ses.hard.stdin_pipe) {
        return Err(user(
            "import reads a canonical body from a pipe: `... | pwv import --from-stdin`",
        ));
    }
    if ses.vault.is_none() {
        if let Some((_, scratch)) = ses.halves.as_mut() {
            read_pipe(scratch)?;
            // Nothing arrived: the producer failed. Refuse before asking
            // for the master password.
            if scratch.is_empty() {
                return Err(user("import refused: the pipe delivered nothing"));
            }
        }
        ses.unlock().map_err(|f| leave(f.code, &f.msg))?;
        sys::scrub_stack();
    }
    let v = ses.vault.as_mut().ok_or_else(no_vault)?;
    let count = v.model.import(suffix).map_err(|e| match e {
        vault::Error::Invalid(fe) => match fe.entry() {
            Some(i) => user(&format!("import refused: {} (entry {i})", fe.message())),
            None => user(&format!("import refused: {}", fe.message())),
        },
        e => e.into(),
    })?;
    ses.save()?;
    ses.say(&format!("Imported {count} entries\n"));
    Ok(())
}

fn cmd_doctor(ses: &mut Session<'_>, _: &Cmd) -> Result<(), Fail> {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let num = |p: &str| read(p).and_then(|t| t.trim().parse::<u32>().ok());
    let (vault, kdf_kib) = match (&ses.vault, ses.paths()) {
        (Some(v), _) => (Some(String::new()), Some(v.header.kdf_m_kib)),
        (None, Err(e)) => (Some(e.msg), None),
        (None, Ok(p)) => match Store::open(p, ses.opts.allow_foreign_fs) {
            Ok((_, file)) => (
                Some(String::new()),
                format::parse_header(&file).ok().map(|h| h.kdf_m_kib),
            ),
            Err(store::Error::NoVault) => (None, None),
            Err(e) => (Some(e.message().to_owned()), None),
        },
    };
    let state = read("/sys/power/state").unwrap_or_default();
    let disk = read("/sys/power/disk").unwrap_or_default();
    let facts = Facts {
        memlock: ses.hard.memlock_limit,
        arena: ses.opts.arena as u64 * 1024,
        kdf_kib,
        swap: swap_kind(&read("/proc/swaps").unwrap_or_default(), &|dm| {
            read(&format!("/sys/block/{dm}/dm/uuid"))
        }),
        hibernation: state.split_whitespace().any(|w| w == "disk") && !disk.contains("[disabled]"),
        suid_dumpable: num("/proc/sys/fs/suid_dumpable"),
        ptrace_scope: num("/proc/sys/kernel/yama/ptrace_scope"),
        vault,
        desktop: std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default(),
    };
    let mut failed = 0;
    for (status, name, remedy) in doctor_report(&facts) {
        let line = match status {
            Status::Pass => format!("[pass] {name}\n"),
            Status::Warn => format!("[warn] {name}: {remedy}\n"),
            Status::Fail => format!("[FAIL] {name}: {remedy}\n"),
        };
        failed += usize::from(status == Status::Fail);
        ses.say(&line);
    }
    if failed == 0 {
        Ok(())
    } else {
        Err(Fail {
            msg: String::new(),
            ..user("")
        })
    }
}

#[allow(clippy::unnecessary_wraps, reason = "the handler signature")]
fn cmd_help(ses: &mut Session<'_>, _: &Cmd) -> Result<(), Fail> {
    for cmd in COMMANDS.iter().filter(|cmd| !cmd.help.is_empty()) {
        ses.say(&format!("  {}\n      {}\n", cmd.usage, cmd.help));
    }
    ses.say(
        "Global options: --vault <path>, --idle-timeout <s>, --clip-timeout <s>, \
         --arena-size <KiB>, --allow-unlocked-memory, --require-locked-kdf, \
         --allow-foreign-fs, --no-color\n",
    );
    Ok(())
}

fn cmd_quit(_: &mut Session<'_>, _: &Cmd) -> Result<(), Fail> {
    Err(leave(0, ""))
}

/// `memtest` only: panics, so that tests reach the unwinding path (review
/// finding R-08: clipboard cleared, exit code 5).
#[cfg(feature = "memtest")]
#[allow(clippy::panic, reason = "memtest hook for the unwinding path")]
fn cmd_panic(_: &mut Session<'_>, _: &Cmd) -> Result<(), Fail> {
    panic!("__panic");
}

/// `memtest` only (Section 5.8): blocks until the harness sends SIGUSR1.
#[cfg(feature = "memtest")]
fn cmd_pause(ses: &mut Session<'_>, _: &Cmd) -> Result<(), Fail> {
    sys::write_stderr(b"PWV_MEMTEST paused\n");
    loop {
        match ses.term.wait(None) {
            Err(term::Error::Resumed) => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
    }
}

/// The `gen` options (Section 10.1), shared by `gen` and `set --gen`.
/// `set` relies on these being the first six of its list.
const SET_FLAGS: &[(&str, bool)] = &[
    ("--len", true),
    ("--classes", true),
    ("--symbols", true),
    ("--no-ambiguous", false),
    ("--words", true),
    ("--sep", true),
    ("--gen", false),
    ("--sensitive", false),
    ("--plain", false),
];
const GEN_FLAGS: &[(&str, bool)] = &[
    ("--len", true),
    ("--classes", true),
    ("--symbols", true),
    ("--no-ambiguous", false),
    ("--words", true),
    ("--sep", true),
    ("--show", false),
];
/// `init` takes the first three.
const KEY_FLAGS: &[(&str, bool)] = PASSWD_FLAGS.split_at(3).0;
const PASSWD_FLAGS: &[(&str, bool)] = &[
    ("--kdf-memory", true),
    ("--kdf-time", true),
    ("--accept-weak-password", false),
    ("--purge-backups", false),
];

const fn row(
    names: &'static [&'static str],
    usage: &'static str,
    help: &'static str,
    arity: (usize, usize),
    flags: &'static [(&'static str, bool)],
    vault: bool,
    run: Handler,
) -> CommandSpec {
    CommandSpec {
        names,
        usage,
        help,
        arity,
        flags,
        vault,
        run,
    }
}

/// The command table (Section 9.2): the parser and `help` derive from it.
/// One row per command: names, usage, help, arity, options, needs the
/// vault, handler.
#[rustfmt::skip]
pub const COMMANDS: &[CommandSpec] = &[
    row(&["init"], "init [--kdf-memory MiB] [--kdf-time t] [--accept-weak-password]", "create a vault", (0, 0), KEY_FLAGS, false, cmd_init),
    row(&["ls"], "ls [pattern]", "list entry names", (0, 1), &[], true, cmd_ls),
    row(&["show"], "show <name>", "show an entry; sensitive values masked", (1, 1), &[], true, cmd_show),
    row(&["reveal"], "reveal <name> <field>", "print one value, then clear the screen", (2, 2), &[], true, cmd_reveal),
    row(&["copy"], "copy <name> [field]", "copy a value to the clipboard, with expiry", (1, 2), &[], true, cmd_copy),
    row(&["add"], "add <name>", "create an entry, field by field", (1, 1), &[], true, cmd_add),
    row(&["set"], "set <name> <field> [--gen [options]] [--sensitive|--plain]", "create or replace a field", (2, 2), SET_FLAGS, true, cmd_set),
    row(&["unset"], "unset <name> <field>", "remove a field", (2, 2), &[], true, cmd_unset),
    row(&["mv"], "mv <old> <new>", "rename an entry", (2, 2), &[], true, cmd_mv),
    row(&["mvfield"], "mvfield <name> <old> <new>", "rename a field", (3, 3), &[], true, cmd_mvfield),
    row(&["rm"], "rm <name>", "delete an entry", (1, 1), &[], true, cmd_rm),
    row(&["gen"], "gen [--len L] [--classes luds] [--symbols S] [--no-ambiguous] [--words k] [--sep c] [--show]", "generate and copy a password or passphrase", (0, 0), GEN_FLAGS, false, cmd_gen),
    row(&["passwd"], "passwd [--kdf-memory MiB] [--kdf-time t] [--accept-weak-password] [--purge-backups]", "change the master password; --purge-backups deletes the backups, which the old one opens", (0, 0), PASSWD_FLAGS, true, cmd_passwd),
    row(&["import"], "import --from-stdin [--on-conflict abort|suffix]", "merge a canonical body from a pipe", (0, 0), &[("--from-stdin", false), ("--on-conflict", true)], false, cmd_import),
    row(&["doctor"], "doctor", "report the security posture of the environment", (0, 0), &[], false, cmd_doctor),
    row(&["help"], "help", "show this list", (0, 0), &[], false, cmd_help),
    row(&["quit", "exit", "lock"], "quit (exit, lock)", "wipe and exit", (0, 0), &[], false, cmd_quit),
    #[cfg(feature = "memtest")]
    row(&["__pause"], "__pause", "", (0, 0), &[], false, cmd_pause),
    #[cfg(feature = "memtest")]
    row(&["__panic"], "__panic", "", (0, 0), &[], false, cmd_panic),
];

/// Runs the program after [`crate::sys::harden`] and returns the exit code
/// (Section 9.3). Opens `/dev/tty` first; refuses a non-terminal stdin
/// except for `import --from-stdin`. On every path the clipboard is
/// cleared if it is still ours, the terminal settings are restored, and
/// the arena is wiped before this returns.
#[must_use]
pub fn run(hardening: &Hardening) -> i32 {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let env_set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    let parsed = globals(&argv);
    let plain = parsed.as_ref().is_ok_and(|(o, _)| o.no_color)
        || env_set("NO_COLOR")
        || std::env::var_os("TERM").is_none_or(|t| t == "dumb");
    let tty = term::Term::open(!plain);
    let signals = sys::install_signal_flag();
    let term = match (tty, signals) {
        (Ok(t), Ok(())) => t,
        (Err(e), _) => return refuse(e.message()),
        (_, Err(e)) => return refuse(e.message()),
    };
    let (opts, first) = match parsed {
        Ok(p) => p,
        Err(msg) => {
            term.write(format!("pwv: {msg}\n").as_bytes());
            return EXIT_USER;
        }
    };
    let rest = argv.get(first..).unwrap_or_default();
    let import =
        rest.first().is_some_and(|c| c == "import") && rest.iter().any(|a| a == "--from-stdin");
    if !hardening.stdin_tty && !import {
        term.write(
            b"pwv: standard input must be a terminal (only `import --from-stdin` reads a pipe)\n",
        );
        return EXIT_ENV;
    }
    let mut arena = match SecureArena::new(opts.arena * 1024, opts.allow_unlocked) {
        Ok(a) => a,
        Err(e) => {
            term.write(format!("pwv: {}\n", e.message()).as_bytes());
            return EXIT_ENV;
        }
    };
    let locked = arena.is_locked();
    let code = match arena.slots() {
        Ok(slots) => session(term, opts, *hardening, locked, slots, rest),
        Err(_) => EXIT_INTERNAL,
    };
    drop(arena);
    sys::scrub_stack();
    #[cfg(feature = "memtest")]
    wiped_pause();
    code
}

/// `memtest` only (Section 5.8, T-MEM-4): when `PWV_MEMTEST_EXIT_PAUSE` is
/// set, reports that the wipe is done and blocks until the harness sends
/// SIGUSR1, so that it can scan the process once more before it exits.
/// The session and the arena no longer exist here: only the signal flag
/// is used.
#[cfg(feature = "memtest")]
fn wiped_pause() {
    if std::env::var_os("PWV_MEMTEST_EXIT_PAUSE").is_none() {
        return;
    }
    sys::write_stderr(b"PWV_MEMTEST wiped\n");
    while !matches!(
        sys::take_signal(),
        Some(sys::Signal::Resume | sys::Signal::Terminate)
    ) {
        sys::nap(20);
    }
}

/// Reports an environment refusal on fd 2 (there is no terminal to use).
fn refuse(msg: &str) -> i32 {
    sys::write_stderr(format!("pwv: {msg}\n").as_bytes());
    EXIT_ENV
}

fn session(
    term: term::Term,
    opts: Options,
    hard: Hardening,
    locked: bool,
    slots: Slots<'_>,
    rest: &[OsString],
) -> i32 {
    let mut s = Session {
        term,
        clip: clip::Clip::default(),
        opts,
        hard,
        locked,
        one_shot: !rest.is_empty(),
        input: slots.input,
        pw1: slots.pw1,
        pw2: slots.pw2,
        kek: slots.kek,
        dek: slots.dek,
        new_dek: slots.new_dek,
        r#gen: slots.r#gen,
        clip_slot: slots.clip,
        halves: Some((slots.vault_a, slots.vault_b)),
        vault: None,
        clip_deadline: None,
    };
    let res = if rest.is_empty() {
        s.repl()
    } else {
        s.one_shot(rest)
    };
    // Clear-if-unchanged first; the `Clip` is dropped only afterwards.
    s.expire_clip();
    match res {
        Ok(()) => 0,
        Err(f) => {
            s.report(&f);
            f.code
        }
    }
}
