//! Password and passphrase generation, entropy computation, embedded word
//! list (spec Section 10). The RNG is injected through [`ByteSource`].
//!
//! Output is exactly uniform over the policy-valid strings: stage 1 maps
//! random bytes to indices by rejection ([`map_draw`]), stage 2 redraws
//! the whole string until every required class occurs. Characters are
//! written straight into the caller's slot; a rejected candidate is
//! overwritten by the next attempt, and every error leaves the slot empty.
//! Deviations from Section 10 (24-bit word draw, separator rule, the
//! ambiguous set, `&mut dyn` instead of a generic) are in `DESIGN_NOTES.md`.

use crate::crypto;
use crate::secmem::SecretSlot;
use crate::sys;
use zeroize::Zeroize;

/// The embedded word list: one lower-case word per line, LF-terminated
/// (T-GEN-6 pins its SHA-256).
pub const WORDS: &str = include_str!("wordlist.txt");
/// Number of words in [`WORDS`].
pub const WORD_COUNT: u32 = 205_690;
/// Stage-2 attempts before [`Error::Attempts`] (Section 10.2).
pub const MAX_ATTEMPTS: u32 = 10_000;
/// Lower-case letters.
pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
pub const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Digits.
pub const DIGITS: &[u8] = b"0123456789";
/// The default symbol set: all 32 ASCII punctuation characters.
pub const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// Removed by `--no-ambiguous`: both readings of Section 10.1 (backslash
/// and backtick).
pub const AMBIGUOUS: &[u8] = b"Il1O0\\`'\"";

/// Generator errors. Messages name the violated constraint, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `--len` outside 8 to 128.
    Length,
    /// `--classes` is empty.
    NoClasses,
    /// A symbol is not printable ASCII 0x21 to 0x7E, or is alphanumeric.
    SymbolChar,
    /// A symbol is listed twice.
    SymbolDuplicate,
    /// The symbol class is required but has no characters left.
    SymbolsEmpty,
    /// `--words` outside 4 to 16.
    WordCount,
    /// `--sep` is not printable ASCII, or is a lower-case letter.
    Separator,
    /// Stage 2 exceeded [`MAX_ATTEMPTS`].
    Attempts,
    /// The random number generator failed.
    Random,
    /// The output does not fit the slot.
    Capacity,
    /// The embedded word list is shorter than [`WORD_COUNT`].
    WordList,
}

impl Error {
    /// Fixed, secret-free message for this error.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Error::Length => "--len must be between 8 and 128",
            Error::NoClasses => "--classes must list at least one of l, u, d, s",
            Error::SymbolChar => "--symbols may hold only printable ASCII punctuation",
            Error::SymbolDuplicate => "--symbols lists a character twice",
            Error::SymbolsEmpty => "the symbol class has no characters left",
            Error::WordCount => "--words must be between 4 and 16",
            Error::Separator => "--sep must be one printable ASCII character other than a-z",
            Error::Attempts => "generation did not succeed within 10000 attempts",
            Error::Random => "the operating system random number generator failed",
            Error::Capacity => "generated value too long",
            Error::WordList => "internal error: embedded word list damaged",
        }
    }
}

/// A source of random bytes (the one trait of rule 7).
pub trait ByteSource {
    /// Fills `buf` with random bytes.
    ///
    /// # Errors
    /// [`Error::Random`] if no bytes are available.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// The production source: the OS CSPRNG (`crypto::fill_random`).
#[derive(Debug)]
pub struct OsBytes;

impl ByteSource for OsBytes {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        crypto::fill_random(buf).map_err(|_| Error::Random)
    }
}

/// A generation policy (Section 10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy<'a> {
    /// A password over the listed classes.
    Chars {
        /// Length L.
        len: usize,
        /// Required classes, in the order lower, upper, digit, symbol
        /// (`--classes luds`); the alphabet is their union.
        classes: [bool; 4],
        /// The symbol class.
        symbols: &'a [u8],
        /// Remove [`AMBIGUOUS`] from every class.
        no_ambiguous: bool,
    },
    /// A passphrase of list words.
    Words {
        /// Number of words k.
        count: usize,
        /// Separator byte.
        sep: u8,
    },
}

impl Policy<'static> {
    /// `--len 20 --classes luds`, all 32 symbols.
    pub const DEFAULT_CHARS: Self = Policy::Chars {
        len: 20,
        classes: [true; 4],
        symbols: SYMBOLS,
        no_ambiguous: false,
    };
    /// `--words 6 --sep -`.
    pub const DEFAULT_WORDS: Self = Policy::Words {
        count: 6,
        sep: b'-',
    };
}

/// A character alphabet: each character with its class index, and the
/// size of each class.
type Alphabet = ([(u8, u8); 94], usize, [u32; 4], usize);

/// The error of the first violated check, if any.
fn first(checks: &[(bool, Error)]) -> Result<(), Error> {
    checks.iter().find(|c| c.0).map_or(Ok(()), |c| Err(c.1))
}

impl Policy<'_> {
    /// Checks every constraint of Section 10.1.
    ///
    /// # Errors
    /// The first violated constraint.
    pub fn validate(&self) -> Result<(), Error> {
        self.alphabet().map(|_| ())
    }

    /// Validates, and for a character policy builds the alphabet.
    fn alphabet(&self) -> Result<Alphabet, Error> {
        let (mut sigma, mut n, mut sizes, mut k) = ([(0, 0); 94], 0, [0u32; 4], 0);
        let (len, classes, symbols, no_ambiguous) = match *self {
            Policy::Chars {
                len,
                classes,
                symbols,
                no_ambiguous,
            } => (len, classes, symbols, no_ambiguous),
            Policy::Words { count, sep } => {
                let bad_sep = !(0x20..=0x7E).contains(&sep) || sep.is_ascii_lowercase();
                first(&[
                    (!(4..=16).contains(&count), Error::WordCount),
                    (bad_sep, Error::Separator),
                ])?;
                return Ok((sigma, n, sizes, k));
            }
        };
        let dup = |(i, b): (usize, &u8)| symbols.get(..i).is_some_and(|h| h.contains(b));
        first(&[
            (!(8..=128).contains(&len), Error::Length),
            (!classes.contains(&true), Error::NoClasses),
            (
                !symbols.iter().all(u8::is_ascii_punctuation),
                Error::SymbolChar,
            ),
            (symbols.iter().enumerate().any(dup), Error::SymbolDuplicate),
        ])?;
        let sets = classes.iter().zip([LOWER, UPPER, DIGITS, symbols]);
        for (set, class) in sets.filter(|c| *c.0).map(|c| c.1).zip(0u8..) {
            for &b in set
                .iter()
                .filter(|b| !(no_ambiguous && AMBIGUOUS.contains(b)))
            {
                *sigma.get_mut(n).ok_or(Error::Length)? = (b, class);
                *sizes.get_mut(usize::from(class)).ok_or(Error::Length)? += 1;
                n += 1;
            }
            k += 1;
        }
        // Only the symbol class can be empty (after `--no-ambiguous`).
        if sizes.get(..k).is_some_and(|s| s.contains(&0)) {
            return Err(Error::SymbolsEmpty);
        }
        Ok((sigma, n, sizes, k))
    }
}

/// Entropy of the generated value: log2 of the number of equally likely
/// outputs. Not secret.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Entropy {
    /// Bits.
    pub bits: f64,
}

/// Stage 1 (Section 10.2): maps a uniform draw `v` in `0..range` to a
/// uniform index in `0..n`, or `None` (reject and redraw) if `v` is at or
/// above `range - range % n`.
#[must_use]
pub fn map_draw(v: u32, range: u32, n: u32) -> Option<u32> {
    let limit = range.checked_sub(range.checked_rem(n)?)?;
    (v < limit).then(|| v % n)
}

/// One uniform index in `0..n` from `width` big-endian random bytes (1 or
/// 3). The bytes are wiped before returning.
fn draw(rng: &mut dyn ByteSource, n: u32, width: usize) -> Result<usize, Error> {
    loop {
        let mut b = [0u8; 4];
        let r = rng.fill(b.get_mut(4 - width..).unwrap_or_default());
        let v = u32::from_be_bytes(b);
        b.zeroize();
        r?;
        if let Some(i) = map_draw(v, 1 << (8 * width), n) {
            return usize::try_from(i).map_err(|_| Error::Random);
        }
    }
}

/// Two-stage sampling of `len` characters into `out`. `sigma` (1 to 256
/// entries) pairs each character with its class, `0..classes` (at most
/// 32), and every class must occur. Exactly uniform over the valid
/// strings.
///
/// # Errors
/// [`Error::Length`] for a malformed alphabet, [`Error::Capacity`],
/// [`Error::Attempts`], [`Error::Random`]; `out` is then empty.
pub fn sample(
    rng: &mut dyn ByteSource,
    sigma: &[(u8, u8)],
    classes: usize,
    len: usize,
    out: &mut SecretSlot<'_>,
) -> Result<(), Error> {
    out.clear();
    let n = u32::try_from(sigma.len()).map_err(|_| Error::Length)?;
    if !(1..=256).contains(&n) || classes > 32 {
        return Err(Error::Length);
    }
    out.set_len(len).map_err(|_| Error::Capacity)?;
    let r = (|| {
        for _ in 0..MAX_ATTEMPTS {
            let mut seen = 0u64;
            for c in out.expose_mut() {
                let (b, class) = sigma.get(draw(rng, n, 1)?).copied().unwrap_or_default();
                *c = b;
                // A tag of 64 or more never counts, so such a string fails.
                seen |= 1u64.checked_shl(u32::from(class)).unwrap_or(0);
            }
            if seen == (1 << classes) - 1 {
                return Ok(());
            }
        }
        Err(Error::Attempts)
    })();
    if r.is_err() {
        out.clear();
    }
    r
}

/// `count` list words joined by `sep`, appended to `out` one by one.
fn words(
    rng: &mut dyn ByteSource,
    count: usize,
    sep: u8,
    out: &mut SecretSlot<'_>,
) -> Result<(), Error> {
    for _ in 0..count {
        let w = WORDS
            .split_terminator('\n')
            .nth(draw(rng, WORD_COUNT, 3)?)
            .ok_or(Error::WordList)?;
        let p = out.len();
        out.set_len(p + w.len() + 1).map_err(|_| Error::Capacity)?;
        for (d, s) in out
            .expose_mut()
            .iter_mut()
            .skip(p)
            .zip(w.bytes().chain([sep]))
        {
            *d = s;
        }
    }
    // Drop the final separator (`set_len` wipes it).
    out.set_len(out.len().saturating_sub(1))
        .map_err(|_| Error::Capacity)
}

/// Generates a value under `policy` into `out` (Section 10.1; rule 7: a
/// trait object, not a generic) and returns its entropy. Validates the
/// policy before drawing any byte; scrubs the stack once at the end.
///
/// # Errors
/// The violated constraint, or [`Error::Attempts`], [`Error::Random`],
/// [`Error::Capacity`], [`Error::WordList`]; `out` is then empty.
pub fn generate(
    rng: &mut dyn ByteSource,
    policy: &Policy<'_>,
    out: &mut SecretSlot<'_>,
) -> Result<Entropy, Error> {
    out.clear();
    let (sigma, n, sizes, k) = policy.alphabet()?;
    let (sigma, sizes) = (
        sigma.get(..n).unwrap_or_default(),
        sizes.get(..k).unwrap_or_default(),
    );
    let r = match *policy {
        Policy::Chars { len, .. } => {
            sample(rng, sigma, sizes.len(), len, out).map(|()| (sizes, len))
        }
        Policy::Words { count, sep } => {
            words(rng, count, sep, out).map(|()| (&[WORD_COUNT][..], count))
        }
    };
    if r.is_err() {
        out.clear();
    }
    sys::scrub_stack();
    let (sizes, len) = r?;
    let bits = log2_count(sizes, u32::try_from(len).unwrap_or(0)).unwrap_or(f64::NAN);
    Ok(Entropy { bits })
}

/// Calls `f(even, rest)` for every subset S of the classes: `even` is
/// whether |S| is even, `rest` = n minus the sizes in S. Returns n, or
/// `None` for over 16 classes or n > `u32::MAX`.
fn subsets(sizes: &[u32], f: &mut dyn FnMut(bool, u32)) -> Option<u32> {
    let n = sizes.iter().try_fold(0u32, |a, &s| a.checked_add(s))?;
    for mask in 0u32..1 << Some(sizes.len()).filter(|&k| k <= 16)? {
        let picked = sizes.iter().enumerate().filter(|c| mask >> c.0 & 1 == 1);
        f(
            mask.count_ones() % 2 == 0,
            n - picked.map(|c| c.1).sum::<u32>(),
        );
    }
    Some(n)
}

/// Exact number of strings of length `len` over the union of classes of
/// the given `sizes` that contain every class (inclusion-exclusion,
/// Section 10.2); `None` if it does not fit `u128`.
#[must_use]
pub fn valid_count(sizes: &[u32], len: u32) -> Option<u128> {
    let (mut plus, mut minus, mut ok) = (0u128, 0u128, true);
    subsets(sizes, &mut |even, rest| {
        let acc = if even { &mut plus } else { &mut minus };
        match u128::from(rest)
            .checked_pow(len)
            .and_then(|t| acc.checked_add(t))
        {
            Some(v) => *acc = v,
            None => ok = false,
        }
    })?;
    plus.checked_sub(minus).filter(|_| ok)
}

/// log2 of [`valid_count`] in floating point, so that it exists for every
/// length: L log2 n + log2 P(a uniform string contains every class). The
/// ratios (rest / n)^L stay in [0, 1], so no length overflows.
#[must_use]
pub fn log2_count(sizes: &[u32], len: u32) -> Option<f64> {
    let (mut p, l) = (0.0, i32::try_from(len).ok()?);
    let n = f64::from(sizes.iter().try_fold(0u32, |a, &s| a.checked_add(s))?);
    subsets(sizes, &mut |even, rest| {
        let t = (f64::from(rest) / n).powi(l);
        p += if even { t } else { -t };
    })?;
    Some(f64::from(len) * n.log2() + f64::log2(p))
}
