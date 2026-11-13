//! M6 gate (spec Section 14.4): T-GEN-1 .. T-GEN-6, plus the attempt cap,
//! RNG failure, the ambiguous set, the separator rule, and error messages.
//!
//! Test output carries no content (rule 9): generated values stay in the
//! `Gen` slot and are inspected there; assertion messages name only
//! positions, counts, and error variants. Proptest generates policies and
//! RNG seeds, never output, so its reports and regression file hold no
//! generated value.
//!
//! Miri (T-SAN-2) runs a representative subset, selected by `cfg!(miri)`
//! inside the tests and by name in CI: T-GEN-1 over 8 values of n and a
//! sample of 24-bit values, T-GEN-2 with 2 byte values per residue instead
//! of 64, T-GEN-4 with 4 + 4 cases, T-GEN-5 for n, L <= 4, and the unit
//! tests. T-GEN-3 (10^6 characters) and T-GEN-6 (SHA-256 of 2.2 MB) run
//! natively only.

mod common;

use common::vaults::arena;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence, TestRunner};
use pwv::r#gen::{
    AMBIGUOUS, ByteSource, DIGITS, Error, LOWER, MAX_ATTEMPTS, OsBytes, Policy, SYMBOLS, UPPER,
    WORD_COUNT, WORDS, generate, log2_count, map_draw, sample, valid_count,
};
use pwv::secmem::SMALL_LEN;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

/// SHA-256 of `src/wordlist.txt`, as supplied by the owner in
/// `full_wordlist_sha256sum.txt` (DESIGN_NOTES, M6: word list).
const WORDLIST_SHA256: &str = "9b7bb4cc2ede3e5573174339e0547c774b67e769cfda1fbbc93038ec66a93320";

/// `--classes luds`: lower, upper, digit, symbol.
const ALL: [bool; 4] = [true; 4];
type Classes = [bool; 4];

// ------------------------------------------------------------ byte sources

/// `ByteSource` over a seeded `ChaCha20Rng` (rand_chacha 0.10.0: `Rng`
/// and `SeedableRng` from its re-exported rand_core 0.10.1).
struct Chacha(ChaCha20Rng);

impl Chacha {
    fn new(seed: u64) -> Self {
        Chacha(ChaCha20Rng::seed_from_u64(seed))
    }
}

impl ByteSource for Chacha {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.0.fill_bytes(buf);
        Ok(())
    }
}

/// Serves a fixed byte sequence, then fails with `Error::Random`. Counts
/// the bytes requested.
struct Script<'a> {
    bytes: &'a [u8],
    pos: usize,
    asked: usize,
}

impl<'a> Script<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Script {
            bytes,
            pos: 0,
            asked: 0,
        }
    }
}

impl ByteSource for Script<'_> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.asked += buf.len();
        let src = self.bytes.get(self.pos..self.pos + buf.len());
        let src = src.ok_or(Error::Random)?;
        buf.copy_from_slice(src);
        self.pos += buf.len();
        Ok(())
    }
}

/// Always the same byte; counts the bytes requested.
struct Constant {
    byte: u8,
    asked: usize,
}

impl ByteSource for Constant {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.asked += buf.len();
        buf.fill(self.byte);
        Ok(())
    }
}

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

fn word_list() -> Vec<&'static str> {
    WORDS.split_terminator('\n').collect()
}

/// Line `i` of the list (a scan; no allocation, so cheap under Miri).
fn nth_word(i: usize) -> &'static str {
    WORDS.split_terminator('\n').nth(i).unwrap()
}

/// Whether `w` is a list word: binary search over the sorted list's bytes,
/// without building an index (cheap under Miri).
fn is_listed(w: &[u8]) -> bool {
    let b = WORDS.as_bytes();
    // Invariant: `lo` and `hi` are line starts (or the end).
    let (mut lo, mut hi) = (0, b.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let start = b[..mid]
            .iter()
            .rposition(|&c| c == b'\n')
            .map_or(0, |p| p + 1)
            .max(lo);
        let end = start + b[start..].iter().position(|&c| c == b'\n').unwrap();
        match b[start..end].cmp(w) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => lo = end + 1,
            std::cmp::Ordering::Greater => hi = start,
        }
    }
    false
}

/// The alphabet of a character policy, by class, as the test reads
/// Section 10.1 (independently of `gen`'s construction).
fn classes_of(classes: Classes, symbols: &[u8], no_ambiguous: bool) -> Vec<Vec<u8>> {
    let keep = |c: &u8| !(no_ambiguous && b"Il1O0\\`'\"".contains(c));
    [
        (classes[0], &b"abcdefghijklmnopqrstuvwxyz"[..]),
        (classes[1], &b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..]),
        (classes[2], &b"0123456789"[..]),
        (classes[3], symbols),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| set.iter().copied().filter(keep).collect())
    .collect()
}

fn class_sizes(sets: &[Vec<u8>]) -> Vec<u32> {
    sets.iter()
        .map(|s| u32::try_from(s.len()).unwrap())
        .collect()
}

/// Number of ways to read `out` as exactly `count` list words joined by
/// `sep` (1 means the passphrase decodes uniquely).
fn parses(out: &[u8], sep: u8, count: usize) -> u64 {
    let tokens: Vec<&[u8]> = out.split(|&b| b == sep).collect();
    // ways[i][k]: ways to read tokens[..i] as k words.
    let mut ways = vec![vec![0u64; count + 1]; tokens.len() + 1];
    ways[0][0] = 1;
    for i in 0..tokens.len() {
        for j in i + 1..=tokens.len() {
            let word = tokens[i..j].join(&sep);
            if !is_listed(&word) {
                continue;
            }
            for k in 0..count {
                ways[j][k + 1] += ways[i][k];
            }
        }
    }
    ways[tokens.len()][count]
}

// ------------------------------------------------------------ T-GEN-1

/// T-GEN-1: for every n in 2..=256, the 256 byte values through the
/// stage-1 mapping give each residue exactly floor(256 / n) accepted bytes,
/// and exactly the bytes >= 256 - (256 mod n) are rejected.
#[test]
fn t_gen_1_byte_mapping_is_exact_for_every_n() {
    let all: Vec<u32> = (2..=256).collect();
    let ns = if cfg!(miri) {
        vec![2, 3, 7, 94, 128, 129, 255, 256]
    } else {
        all
    };
    for n in ns {
        let mut hits = vec![0u32; n as usize];
        for b in 0..256u32 {
            match map_draw(b, 256, n) {
                Some(r) => {
                    assert!(b < 256 - 256 % n, "n {n}: byte {b} accepted");
                    assert_eq!(r, b % n, "n {n}: byte {b}");
                    hits[r as usize] += 1;
                }
                None => assert!(b >= 256 - 256 % n, "n {n}: byte {b} rejected"),
            }
        }
        assert!(hits.iter().all(|&h| h == 256 / n), "n {n}: residues uneven");
    }
}

/// T-GEN-1 for the word index (Section 10.2 deviation, DESIGN_NOTES M6):
/// 205,690 words need a 24-bit draw. All 2^24 values: each index receives
/// exactly floor(2^24 / n) = 81 values, and exactly the 116,326 values from
/// 16,660,890 up are rejected. Miri checks the boundaries and a stride.
#[test]
fn t_gen_1_word_mapping_is_exact_over_24_bits() {
    const RANGE: u32 = 1 << 24;
    let n = WORD_COUNT;
    assert_eq!(n, 205_690);
    assert_eq!(RANGE % n, 116_326);
    let limit = RANGE - RANGE % n;
    assert_eq!(limit, 16_660_890);
    if cfg!(miri) {
        for v in (0..RANGE)
            .step_by(65_537)
            .chain([limit - 1, limit, RANGE - 1])
        {
            assert_eq!(map_draw(v, RANGE, n), (v < limit).then_some(v % n), "v {v}");
        }
        return;
    }
    let mut hits = vec![0u8; n as usize];
    let mut rejected = 0u32;
    for v in 0..RANGE {
        match map_draw(v, RANGE, n) {
            Some(i) => {
                assert!(v < limit && i == v % n, "v {v}");
                hits[i as usize] += 1;
            }
            None => {
                assert!(v >= limit, "v {v} rejected");
                rejected += 1;
            }
        }
    }
    assert_eq!(rejected, RANGE % n);
    assert!(
        hits.iter().all(|&h| u32::from(h) == RANGE / n),
        "indices uneven"
    );
    // Degenerate inputs are rejected, never a panic.
    assert_eq!(map_draw(0, 256, 0), None);
    assert_eq!(map_draw(256, 256, 2), None);
}

/// The word draw end to end: 3 big-endian bytes per draw, a rejected value
/// is redrawn, and index i yields line i of the list. Sixteen copies of the
/// longest word fill 399 bytes, which fits the 1 KiB `Gen` slot.
#[test]
fn word_draw_maps_three_bytes_to_the_listed_word() {
    let (longest, word) = (0u32..)
        .zip(WORDS.split_terminator('\n'))
        .max_by_key(|(_, w)| w.len())
        .unwrap();
    assert_eq!(word.len(), 24);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let i = longest.to_be_bytes();
    // Each draw: one rejected value (0xFFFFFF), then the index.
    let mut bytes = Vec::new();
    for _ in 0..16 {
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, i[1], i[2], i[3]]);
    }
    let mut rng = Script::new(&bytes);
    let policy = Policy::Words {
        count: 16,
        sep: b' ',
    };
    generate(&mut rng, &policy, &mut s.r#gen).unwrap();
    assert_eq!(rng.asked, bytes.len());
    let want = vec![word; 16].join(" ");
    assert_eq!(s.r#gen.len(), 16 * 25 - 1);
    assert!(s.r#gen.expose() == want.as_bytes(), "passphrase differs");
    // First, middle, and last index (repeated), with separator '-'.
    let last = WORD_COUNT - 1;
    let mut bytes = Vec::new();
    for idx in [0, 102_845, last, last] {
        bytes.extend_from_slice(&idx.to_be_bytes()[1..]);
    }
    let mut rng = Script::new(&bytes);
    let policy = Policy::Words {
        count: 4,
        sep: b'-',
    };
    generate(&mut rng, &policy, &mut s.r#gen).unwrap();
    let l = nth_word(last as usize);
    let want = [nth_word(0), nth_word(102_845), l, l].join("-");
    assert!(s.r#gen.expose() == want.as_bytes(), "passphrase differs");
}

// ------------------------------------------------------------ T-GEN-2

/// T-GEN-2: alphabet {a, b, C, 1}, classes {lower, upper, digit}, L = 4.
/// 256 = 64 x 4, so every byte is accepted at stage 1 and a draw sequence
/// is 4 bytes. The source enumerates every residue sequence (4^4) with 64
/// byte values per residue (every byte value occurs at every position);
/// an attempt that asks for a fifth byte was rejected at stage 2 and is
/// counted as rejected. Every valid string must occur equally often (64
/// times) and no invalid string at all.
#[test]
fn t_gen_2_exhaustive_uniformity() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    // Characters with their class: lower {a, b}, upper {C}, digit {1}.
    let sigma = [(b'a', 0), (b'b', 0), (b'C', 1), (b'1', 2)];
    let mult: Vec<u8> = if cfg!(miri) {
        vec![0, 63]
    } else {
        (0..64).collect()
    };
    let mut seen: BTreeMap<[u8; 4], u32> = BTreeMap::new();
    let mut rejected = 0u32;
    for seq in 0..256u32 {
        for &m in &mult {
            let bytes: Vec<u8> = (0..4u32)
                .map(|j| {
                    let r = u8::try_from((seq >> (2 * j)) & 3).unwrap();
                    let k = (u32::from(m) + 13 * j) % 64;
                    r + 4 * u8::try_from(k).unwrap()
                })
                .collect();
            let mut rng = Script::new(&bytes);
            match sample(&mut rng, &sigma, 3, 4, &mut s.r#gen) {
                Ok(()) => {
                    assert_eq!(rng.asked, 4, "accepted after one attempt");
                    let out: [u8; 4] = s.r#gen.expose().try_into().unwrap();
                    *seen.entry(out).or_default() += 1;
                }
                Err(e) => {
                    assert_eq!(e, Error::Random, "only the scripted end fails");
                    assert_eq!(rng.asked, 5, "a rejected attempt redraws");
                    assert!(s.r#gen.is_empty(), "rejected candidate cleared");
                    rejected += 1;
                }
            }
        }
    }
    let per = u32::try_from(mult.len()).unwrap();
    assert_eq!(valid_count(&[2, 1, 1], 4), Some(96));
    assert_eq!(seen.len(), 96, "every valid string appears");
    for (out, &count) in &seen {
        assert_eq!(count, per, "uneven");
        let has = |set: &[u8]| out.iter().any(|c| set.contains(c));
        assert!(
            has(b"ab") && has(b"C") && has(b"1"),
            "invalid string produced"
        );
        assert!(out.iter().all(|c| b"abC1".contains(c)));
    }
    assert_eq!(rejected, (256 - 96) * per);
}

/// Stage 2 redraws all L characters: an invalid first attempt is discarded
/// whole, and the result is exactly the second attempt.
#[test]
fn stage_2_redraws_the_whole_string() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    // "aaaa" (no upper, no digit), then "C1ba".
    let bytes = [0, 4, 8, 12, 2, 3, 1, 0];
    let mut rng = Script::new(&bytes);
    let abc1 = [(b'a', 0), (b'b', 0), (b'C', 1), (b'1', 2)];
    sample(&mut rng, &abc1, 3, 4, &mut s.r#gen).unwrap();
    assert_eq!(rng.asked, 8);
    assert!(s.r#gen.expose() == b"C1ba", "second attempt");
    // Stage 1 inside stage 2: a rejected byte (n = 3: 255 >= 255) is
    // redrawn without restarting the string.
    let bytes = [0, 255, 1, 2];
    let mut rng = Script::new(&bytes);
    let ab1 = [(b'a', 0), (b'B', 1), (b'1', 2)];
    sample(&mut rng, &ab1, 3, 3, &mut s.r#gen).unwrap();
    assert!(s.r#gen.expose() == b"aB1", "byte redrawn in place");
}

// ------------------------------------------------------------ T-GEN-3

/// Probability that a uniform string of length `len` over the classes
/// `sizes` contains every class (inclusion-exclusion in f64; test-side).
fn p_valid(sizes: &[f64], len: i32) -> f64 {
    let n: f64 = sizes.iter().sum();
    let mut p = 0.0;
    for mask in 0u32..1 << sizes.len() {
        let out: f64 = (0..sizes.len())
            .filter(|i| mask >> i & 1 == 1)
            .map(|i| sizes[i])
            .sum();
        let sign = if mask.count_ones() % 2 == 0 {
            1.0
        } else {
            -1.0
        };
        p += sign * ((n - out) / n).powi(len);
    }
    p
}

/// T-GEN-3: a seeded `ChaCha20Rng`, the default policy (L = 20 over 94
/// characters), 50,000 passwords = 10^6 characters. Chi-square per
/// position (50,000 samples each) and pooled (10^6) against the exact
/// output distribution, at alpha = 1e-6 with 93 degrees of freedom
/// (critical value 172.747, mpmath; DESIGN_NOTES M6). The expected
/// frequencies are not 1/94: stage 2 conditions on class coverage, which
/// favours the smaller classes. For a character c in class i,
/// P(c at a position) = (1/n) * P(the other L - 1 positions cover every
/// class except possibly i) / P(valid). The seed is fixed, so the result
/// is deterministic.
#[test]
fn t_gen_3_chi_square_default_policy() {
    const PASSWORDS: usize = 50_000;
    const L: usize = 20;
    const CRITICAL: f64 = 172.747_337;
    let sets = classes_of(ALL, SYMBOLS, false);
    let sigma: Vec<u8> = sets.concat();
    assert_eq!(sigma.len(), 94);
    let sizes: Vec<f64> = sets.iter().map(|s| s.len() as f64).collect();
    let n = 94.0;
    let pv = p_valid(&sizes, 20);
    let mut prob = [0.0f64; 128];
    for (i, set) in sets.iter().enumerate() {
        // Classes other than i must all appear among the other L - 1.
        let mut rest = sizes.clone();
        let own = rest.remove(i);
        let others: f64 = rest.iter().sum();
        // P(other positions cover every class except possibly i): strings
        // over all n with class i unconstrained = inclusion-exclusion over
        // the remaining classes, with own class always allowed.
        let mut q = 0.0;
        for mask in 0u32..1 << rest.len() {
            let out: f64 = (0..rest.len())
                .filter(|j| mask >> j & 1 == 1)
                .map(|j| rest[j])
                .sum();
            let sign = if mask.count_ones() % 2 == 0 {
                1.0
            } else {
                -1.0
            };
            q += sign * ((own + others - out) / n).powi(19);
        }
        for &c in set {
            prob[c as usize] = q / n / pv;
        }
    }
    let total: f64 = prob.iter().sum();
    assert!((total - 1.0).abs() < 1e-12, "probabilities sum to {total}");

    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut rng = Chacha::new(3);
    let mut by_pos = vec![[0u32; 128]; L];
    for _ in 0..PASSWORDS {
        generate(&mut rng, &Policy::DEFAULT_CHARS, &mut s.r#gen).unwrap();
        assert_eq!(s.r#gen.len(), L);
        for (pos, &c) in s.r#gen.expose().iter().enumerate() {
            by_pos[pos][c as usize] += 1;
        }
    }
    let chi = |counts: &[u32; 128], samples: f64| -> f64 {
        sigma
            .iter()
            .map(|&c| {
                let e = samples * prob[c as usize];
                let d = f64::from(counts[c as usize]) - e;
                d * d / e
            })
            .sum()
    };
    let mut pooled = [0u32; 128];
    for (pos, counts) in by_pos.iter().enumerate() {
        let outside: u32 = (0..128)
            .filter(|c| !sigma.contains(&u8::try_from(*c).unwrap()))
            .map(|c| counts[c])
            .sum();
        assert_eq!(outside, 0, "position {pos}: character outside the alphabet");
        let x = chi(counts, PASSWORDS as f64);
        assert!(x < CRITICAL, "position {pos}: chi-square {x:.1}");
        for c in 0..128 {
            pooled[c] += counts[c];
        }
    }
    let x = chi(&pooled, (PASSWORDS * L) as f64);
    assert!(x < CRITICAL, "pooled chi-square {x:.1}");
    // The conditioning is visible at this sample size: digits are 11.88 %
    // of the characters, not 10/94 = 10.64 % (the test would catch a
    // generator that skipped stage 2's conditioning).
    let digits: u32 = DIGITS.iter().map(|&c| pooled[c as usize]).sum();
    let share = f64::from(digits) / (PASSWORDS * L) as f64;
    let want: f64 = DIGITS.iter().map(|&c| prob[c as usize]).sum();
    assert!(want - 10.0 / 94.0 > 0.01);
    assert!((share - want).abs() < 0.0015, "digit share");
}

// ------------------------------------------------------------ T-GEN-4

#[derive(Clone, Debug)]
enum Gen {
    Chars {
        len: usize,
        classes: Classes,
        symbols: Vec<u8>,
        no_ambiguous: bool,
    },
    Words {
        count: usize,
        sep: u8,
    },
}

impl Gen {
    fn policy(&self) -> Policy<'_> {
        match self {
            Gen::Chars {
                len,
                classes,
                symbols,
                no_ambiguous,
            } => Policy::Chars {
                len: *len,
                classes: *classes,
                symbols,
                no_ambiguous: *no_ambiguous,
            },
            Gen::Words { count, sep } => Policy::Words {
                count: *count,
                sep: *sep,
            },
        }
    }
}

fn classes_from(mask: u8) -> Classes {
    [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0]
}

/// Separators allowed by DESIGN_NOTES M6: printable ASCII 0x20..=0x7E
/// except a-z (a letter separator would make passphrases ambiguous).
fn allowed_sep(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) && !c.is_ascii_lowercase()
}

fn valid_policy() -> impl Strategy<Value = Gen> {
    let chars = (
        8usize..=128,
        1u8..16,
        proptest::sample::subsequence(SYMBOLS.to_vec(), 1..=32).prop_shuffle(),
        any::<bool>(),
    )
        .prop_filter(
            "an ambiguous-only symbol set is invalid",
            |(_, m, s, na)| !(m & 8 != 0 && *na && s.iter().all(|c| AMBIGUOUS.contains(c))),
        )
        .prop_map(|(len, m, symbols, no_ambiguous)| Gen::Chars {
            len,
            classes: classes_from(m),
            symbols,
            no_ambiguous,
        });
    let words = (
        4usize..=16,
        (0x20u8..=0x7E).prop_filter("sep", |c| allowed_sep(*c)),
    )
        .prop_map(|(count, sep)| Gen::Words { count, sep });
    prop_oneof![chars, words]
}

/// T-GEN-4 (valid half): random valid policies produce output of exactly
/// length L containing every required class and only allowed characters;
/// passphrases are exactly k list words that decode uniquely. The reported
/// entropy equals `log2_count` of the policy.
#[test]
fn t_gen_4_valid_policies_produce_valid_output() {
    let mut a = arena();
    let slots = RefCell::new(a.slots().unwrap());
    let mut runner = TestRunner::new(cases(512, 8));
    runner
        .run(&(valid_policy(), any::<u64>()), |(g, seed)| {
            let policy = g.policy();
            assert_eq!(policy.validate(), Ok(()));
            let mut rng = Chacha::new(seed);
            let mut s = slots.borrow_mut();
            let h = generate(&mut rng, &policy, &mut s.r#gen).unwrap();
            let out = s.r#gen.expose();
            match &g {
                Gen::Chars {
                    len,
                    classes,
                    symbols,
                    no_ambiguous,
                } => {
                    let sets = classes_of(*classes, symbols, *no_ambiguous);
                    prop_assert_eq!(out.len(), *len);
                    prop_assert!(out.iter().all(|c| sets.iter().any(|s| s.contains(c))));
                    for (i, set) in sets.iter().enumerate() {
                        prop_assert!(out.iter().any(|c| set.contains(c)), "class {} missing", i);
                    }
                    let want = log2_count(&class_sizes(&sets), u32::try_from(*len).unwrap());
                    prop_assert_eq!(Some(h.bits), want);
                }
                Gen::Words { count, sep } => {
                    prop_assert_eq!(parses(out, *sep, *count), 1);
                    let k = u32::try_from(*count).unwrap();
                    prop_assert_eq!(Some(h.bits), log2_count(&[WORD_COUNT], k));
                }
            }
            Ok(())
        })
        .unwrap();
}

/// Section 10.1 constraints, read independently: the first violated one,
/// in the order length or count, classes, symbols (characters, duplicates,
/// empty after `--no-ambiguous`), separator.
fn expected(g: &Gen) -> Result<(), Error> {
    match g {
        Gen::Chars {
            len,
            classes,
            symbols,
            no_ambiguous,
        } => {
            if !(8..=128).contains(len) {
                return Err(Error::Length);
            }
            if !classes.contains(&true) {
                return Err(Error::NoClasses);
            }
            if symbols
                .iter()
                .any(|c| !(0x21..=0x7E).contains(c) || c.is_ascii_alphanumeric())
            {
                return Err(Error::SymbolChar);
            }
            let unique: BTreeSet<u8> = symbols.iter().copied().collect();
            if unique.len() != symbols.len() {
                return Err(Error::SymbolDuplicate);
            }
            let usable = symbols
                .iter()
                .filter(|c| !(*no_ambiguous && AMBIGUOUS.contains(c)))
                .count();
            if classes[3] && usable == 0 {
                return Err(Error::SymbolsEmpty);
            }
            Ok(())
        }
        Gen::Words { count, sep } => {
            if !(4..=16).contains(count) {
                return Err(Error::WordCount);
            }
            if !allowed_sep(*sep) {
                return Err(Error::Separator);
            }
            Ok(())
        }
    }
}

fn any_policy() -> impl Strategy<Value = Gen> {
    let symbols = prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..40),
        proptest::collection::vec(0x21u8..=0x7E, 0..40),
        proptest::collection::vec(proptest::sample::select(SYMBOLS.to_vec()), 0..40),
        proptest::sample::subsequence(SYMBOLS.to_vec(), 0..=32).prop_shuffle(),
    ];
    let len = prop_oneof![
        0usize..=140,
        Just(7),
        Just(8),
        Just(128),
        Just(129),
        any::<usize>()
    ];
    let chars =
        (len, 0u8..16, symbols, any::<bool>()).prop_map(|(len, m, symbols, na)| Gen::Chars {
            len,
            classes: classes_from(m),
            symbols,
            no_ambiguous: na,
        });
    let count = prop_oneof![
        0usize..=20,
        Just(3),
        Just(4),
        Just(16),
        Just(17),
        any::<usize>()
    ];
    let words = (count, any::<u8>()).prop_map(|(count, sep)| Gen::Words { count, sep });
    prop_oneof![chars, words]
}

/// T-GEN-4 (invalid half): for arbitrary policies, `validate` returns the
/// first violated constraint, and `generate` returns the same error with
/// the slot left empty (it held a previous value) and no byte drawn.
#[test]
fn t_gen_4_invalid_policies_return_err() {
    let mut a = arena();
    let slots = RefCell::new(a.slots().unwrap());
    let mut runner = TestRunner::new(cases(4096, 16));
    let seen = RefCell::new(BTreeSet::new());
    runner
        .run(&any_policy(), |g| {
            let want = expected(&g);
            let policy = g.policy();
            prop_assert_eq!(policy.validate(), want);
            if let Err(e) = want {
                seen.borrow_mut().insert(format!("{e:?}"));
                let mut s = slots.borrow_mut();
                s.r#gen.set_len(5).unwrap();
                s.r#gen.expose_mut().fill(b'x');
                let mut rng = Constant { byte: 0, asked: 0 };
                prop_assert_eq!(generate(&mut rng, &policy, &mut s.r#gen), Err(e));
                prop_assert!(s.r#gen.is_empty());
                prop_assert_eq!(rng.asked, 0);
            }
            Ok(())
        })
        .unwrap();
    if !cfg!(miri) {
        // Non-vacuity: every constraint was violated somewhere.
        assert_eq!(seen.borrow().len(), 7, "error kinds seen");
    }
}

/// T-GEN-4, one targeted case per constraint of Section 10.1, at and just
/// beyond each limit.
#[test]
fn t_gen_4_each_constraint_at_its_limits() {
    let chars = |len, classes, symbols, no_ambiguous| Policy::Chars {
        len,
        classes,
        symbols,
        no_ambiguous,
    };
    let none = classes_from(0);
    let only_sym = classes_from(8);
    let cases: Vec<(Policy<'_>, Result<(), Error>)> = vec![
        (chars(7, ALL, SYMBOLS, false), Err(Error::Length)),
        (chars(8, ALL, SYMBOLS, false), Ok(())),
        (chars(128, ALL, SYMBOLS, false), Ok(())),
        (chars(129, ALL, SYMBOLS, false), Err(Error::Length)),
        (chars(0, ALL, SYMBOLS, false), Err(Error::Length)),
        (chars(20, none, SYMBOLS, false), Err(Error::NoClasses)),
        (chars(20, ALL, b"! ", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!\x7f", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!a", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!Z", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!5", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!\xc3\xa9", false), Err(Error::SymbolChar)),
        (chars(20, ALL, b"!?!", false), Err(Error::SymbolDuplicate)),
        (chars(20, ALL, b"", false), Err(Error::SymbolsEmpty)),
        (chars(20, ALL, b"'\"`\\", true), Err(Error::SymbolsEmpty)),
        (chars(20, ALL, b"'\"`\\", false), Ok(())),
        (chars(20, classes_from(7), b"", false), Ok(())),
        (chars(8, only_sym, b"~", false), Ok(())),
        (
            Policy::Words {
                count: 3,
                sep: b'-',
            },
            Err(Error::WordCount),
        ),
        (
            Policy::Words {
                count: 4,
                sep: b'-',
            },
            Ok(()),
        ),
        (
            Policy::Words {
                count: 16,
                sep: b'-',
            },
            Ok(()),
        ),
        (
            Policy::Words {
                count: 17,
                sep: b'-',
            },
            Err(Error::WordCount),
        ),
        (
            Policy::Words {
                count: 6,
                sep: b' ',
            },
            Ok(()),
        ),
        (
            Policy::Words {
                count: 6,
                sep: b'~',
            },
            Ok(()),
        ),
        (
            Policy::Words {
                count: 6,
                sep: b'A',
            },
            Ok(()),
        ),
        (
            Policy::Words {
                count: 6,
                sep: b'e',
            },
            Err(Error::Separator),
        ),
        (
            Policy::Words {
                count: 6,
                sep: b'\t',
            },
            Err(Error::Separator),
        ),
        (
            Policy::Words {
                count: 6,
                sep: 0x7F,
            },
            Err(Error::Separator),
        ),
        (
            Policy::Words {
                count: 6,
                sep: 0xC3,
            },
            Err(Error::Separator),
        ),
    ];
    for (i, (p, want)) in cases.iter().enumerate() {
        assert_eq!(p.validate(), *want, "case {i}");
    }
    assert_eq!(Policy::DEFAULT_CHARS.validate(), Ok(()));
    assert_eq!(Policy::DEFAULT_WORDS.validate(), Ok(()));
    assert_eq!(
        Policy::DEFAULT_CHARS,
        chars(20, ALL, SYMBOLS, false),
        "Section 10.1 defaults"
    );
    assert_eq!(
        Policy::DEFAULT_WORDS,
        Policy::Words {
            count: 6,
            sep: b'-'
        }
    );
}

// ------------------------------------------------------------ T-GEN-5

/// Every composition of n into class sizes (every alphabet partition up
/// to relabelling).
fn compositions(n: u32) -> Vec<Vec<u32>> {
    if n == 0 {
        return vec![vec![]];
    }
    (1..=n)
        .flat_map(|first| {
            compositions(n - first).into_iter().map(move |mut rest| {
                rest.insert(0, first);
                rest
            })
        })
        .collect()
}

/// T-GEN-5: inclusion-exclusion N(L) equals a brute-force count for every
/// alphabet partition with n <= 6 and every L <= 6; the log2 path agrees
/// with log2 of the exact count.
#[test]
fn t_gen_5_inclusion_exclusion_matches_brute_force() {
    let max = if cfg!(miri) { 4 } else { 6 };
    let mut checked = 0;
    for n in 1..=max {
        for sizes in compositions(n) {
            // Class of each character 0..n.
            let class: Vec<usize> = sizes
                .iter()
                .enumerate()
                .flat_map(|(k, &s)| std::iter::repeat_n(k, s as usize))
                .collect();
            for len in 0..=max {
                let mut count = 0u128;
                for code in 0..n.pow(len) {
                    let mut seen = 0u32;
                    let mut c = code;
                    for _ in 0..len {
                        seen |= 1 << class[(c % n) as usize];
                        c /= n;
                    }
                    if seen.count_ones() as usize == sizes.len() {
                        count += 1;
                    }
                }
                assert_eq!(valid_count(&sizes, len), Some(count), "{sizes:?} L {len}");
                let log = log2_count(&sizes, len).unwrap();
                if count == 0 {
                    assert!(log == f64::NEG_INFINITY || log.is_nan() || log < -40.0);
                } else {
                    let exact = (count as f64).log2();
                    assert!((log - exact).abs() < 1e-9, "{sizes:?} L {len}");
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}

/// Entropy of the policies the spec quotes (Section 10.2), from exact
/// big-integer values (Python, DESIGN_NOTES M6), including lengths whose
/// count overflows u128, where only the log2 path exists; and the exact
/// path against the log2 path wherever the count fits u128.
#[test]
fn entropy_known_values_and_both_paths() {
    let cases: [(&[u32], u32, f64); 7] = [
        (&[26, 26, 10, 32], 8, 51.318_288_320_643_95),
        (&[26, 26, 10, 32], 16, 104.592_514_135_247_6),
        (&[26, 26, 10, 32], 19, 124.348_815_659_161_58),
        (&[26, 26, 10, 32], 20, 130.925_867_010_866_22),
        (&[26, 26, 10, 32], 128, 838.987_372_208_323_7),
        (&[25, 24, 8, 28], 20, 127.968_648_485_142_24),
        (&[WORD_COUNT], 6, 105.900_672_784_291_89),
    ];
    for (sizes, len, want) in cases {
        let got = log2_count(sizes, len).unwrap();
        assert!((got - want).abs() < 1e-9, "{sizes:?} L {len}: {got}");
        match valid_count(sizes, len) {
            Some(c) => assert!(((c as f64).log2() - got).abs() < 1e-9),
            None => assert!(want > 127.9, "only overflowing counts lack an exact value"),
        }
    }
    let lens = if cfg!(miri) { 8..=9 } else { 8..=128 };
    for len in lens {
        if let Some(c) = valid_count(&[26, 26, 10, 32], len) {
            let got = log2_count(&[26, 26, 10, 32], len).unwrap();
            assert!(((c as f64).log2() - got).abs() < 1e-9, "L {len}");
        } else {
            assert!(len >= 20, "u128 holds the count up to L = 19");
        }
    }
    // Too many classes for the subset loop: refused, never a panic.
    assert_eq!(valid_count(&[1; 40], 3), None);
    assert_eq!(log2_count(&[1; 40], 3), None);

    let mut a = arena();
    let mut s = a.slots().unwrap();
    let h = generate(&mut Chacha::new(1), &Policy::DEFAULT_CHARS, &mut s.r#gen).unwrap();
    assert!((h.bits - 130.925_867_010_866_22).abs() < 1e-9);
    let h = generate(&mut Chacha::new(1), &Policy::DEFAULT_WORDS, &mut s.r#gen).unwrap();
    assert!((h.bits - 105.900_672_784_291_89).abs() < 1e-9);
}

// ------------------------------------------------------------ T-GEN-6

/// T-GEN-6 (Section 10.3, with the owner's list; DESIGN_NOTES M6):
/// 205,690 lines, unique (and sorted), every word `[a-z-]+` of lower-case
/// ASCII, LF line ends with a final LF, SHA-256 equal to the pinned digest.
/// Also: the longest passphrase fits the `Gen` slot, and with `-` as the
/// separator a passphrase decodes uniquely (no word ends where a longer
/// word has a hyphen, so the word list is a prefix code over `-`-tokens).
#[test]
fn t_gen_6_word_list_integrity() {
    use sha2::Digest;
    let digest: [u8; 32] = sha2::Sha256::digest(WORDS.as_bytes()).into();
    assert_eq!(common::vaults::hex(&digest), WORDLIST_SHA256);
    assert!(WORDS.ends_with('\n') && !WORDS.contains('\r'));
    let list = word_list();
    assert_eq!(list.len(), 205_690);
    assert_eq!(list.len(), WORD_COUNT as usize);
    assert!(list.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
    let unique: BTreeSet<&str> = list.iter().copied().collect();
    assert_eq!(unique.len(), list.len());
    for (i, w) in list.iter().enumerate() {
        assert!(!w.is_empty(), "line {i} empty");
        assert!(
            w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "line {i} outside [a-z-]"
        );
        for (pos, _) in w.match_indices('-') {
            assert!(!unique.contains(&w[..pos]), "line {i}: prefix is a word");
        }
    }
    let longest = list.iter().map(|w| w.len()).max().unwrap();
    assert_eq!(longest, 24);
    assert!(
        16 * (longest + 1) - 1 <= SMALL_LEN,
        "16 words fit the Gen slot"
    );
}

// ------------------------------------------------------------ unit tests

/// The stage-2 cap: a source that only ever yields 'a' never covers
/// upper, digit, and symbol, so after exactly 10,000 attempts of L bytes
/// `generate` returns `Attempts` with the slot empty.
#[test]
fn attempt_cap_is_10000_and_clears_the_slot() {
    assert_eq!(MAX_ATTEMPTS, 10_000);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut rng = Constant { byte: 0, asked: 0 };
    let p = Policy::Chars {
        len: 8,
        classes: ALL,
        symbols: SYMBOLS,
        no_ambiguous: false,
    };
    assert_eq!(generate(&mut rng, &p, &mut s.r#gen), Err(Error::Attempts));
    assert_eq!(rng.asked, 10_000 * 8);
    assert!(s.r#gen.is_empty());
}

/// An RNG failure at any point of a character or word draw returns
/// `Random` and leaves the slot empty.
#[test]
fn rng_failure_at_every_point_clears_the_slot() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut good = Chacha::new(9);
    let mut bytes = vec![0u8; 64];
    good.fill(&mut bytes).unwrap();
    for policy in [Policy::DEFAULT_CHARS, Policy::DEFAULT_WORDS] {
        // Fewer bytes than one value needs: 20 for the characters, 18 for
        // the six 3-byte word draws (more if a draw is rejected).
        let stop = if cfg!(miri) {
            vec![0, 1, 17]
        } else {
            (0..18).collect()
        };
        for k in stop {
            s.r#gen.set_len(3).unwrap();
            s.r#gen.expose_mut().fill(b'x');
            let mut rng = Script::new(&bytes[..k]);
            assert_eq!(
                generate(&mut rng, &policy, &mut s.r#gen),
                Err(Error::Random),
                "{k}"
            );
            assert!(s.r#gen.is_empty(), "{k}");
        }
    }
}

/// `sample` refuses malformed alphabets and a slot that is too small;
/// a character tagged with a class outside `0..classes` (or 64 and above)
/// never counts, so no string is accepted and the cap ends the search.
#[test]
fn sample_rejects_malformed_input() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut rng = Chacha::new(5);
    let ab = [(b'a', 0), (b'b', 1)];
    let big = [(b'a', 0); 257];
    let r = sample(&mut rng, &[], 0, 4, &mut s.r#gen);
    assert_eq!(r, Err(Error::Length));
    let r = sample(&mut rng, &big, 1, 4, &mut s.r#gen);
    assert_eq!(r, Err(Error::Length));
    assert_eq!(sample(&mut rng, &big[..256], 1, 4, &mut s.r#gen), Ok(()));
    let r = sample(&mut rng, &ab, 33, 4, &mut s.r#gen);
    assert_eq!(r, Err(Error::Length));
    let r = sample(&mut rng, &ab, 2, 2000, &mut s.r#gen);
    assert_eq!(r, Err(Error::Capacity));
    assert!(s.r#gen.is_empty());
    assert_eq!(sample(&mut rng, &ab, 2, 2, &mut s.r#gen), Ok(()));
    if !cfg!(miri) {
        for bad in [[(b'a', 0), (b'b', 2)], [(b'a', 0), (b'b', 200)]] {
            let r = sample(&mut rng, &bad, 2, 4, &mut s.r#gen);
            assert_eq!(r, Err(Error::Attempts));
            assert!(s.r#gen.is_empty());
        }
    }
}

/// `--no-ambiguous` removes exactly I l 1 O 0 \ ` ' " (DESIGN_NOTES M6:
/// the union of both readings of Section 10.1), and nothing else.
#[test]
fn no_ambiguous_removes_exactly_the_nine_characters() {
    let mut want: Vec<u8> = b"Il1O0\\`'\"".to_vec();
    want.sort_unstable();
    let mut got = AMBIGUOUS.to_vec();
    got.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(LOWER, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(UPPER, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    assert_eq!(DIGITS, b"0123456789");
    assert_eq!(SYMBOLS.len(), 32);
    assert!(SYMBOLS.iter().all(|c| c.is_ascii_punctuation()));
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut rng = Chacha::new(11);
    let p = Policy::Chars {
        len: 128,
        classes: ALL,
        symbols: SYMBOLS,
        no_ambiguous: true,
    };
    let mut seen = [false; 128];
    let rounds = if cfg!(miri) { 2 } else { 200 };
    for _ in 0..rounds {
        generate(&mut rng, &p, &mut s.r#gen).unwrap();
        for &c in s.r#gen.expose() {
            assert!(!AMBIGUOUS.contains(&c), "ambiguous character produced");
            seen[c as usize] = true;
        }
    }
    if !cfg!(miri) {
        let used = seen.iter().filter(|&&x| x).count();
        assert_eq!(used, 94 - 9, "every other character occurs");
    }
}

/// Production source: the OS CSPRNG through `crypto::fill_random`.
#[test]
fn os_bytes_generates_both_modes() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let h = generate(&mut OsBytes, &Policy::DEFAULT_CHARS, &mut s.r#gen).unwrap();
    assert_eq!(s.r#gen.len(), 20);
    assert!(h.bits > 130.0);
    let h = generate(&mut OsBytes, &Policy::DEFAULT_WORDS, &mut s.r#gen).unwrap();
    assert!(s.r#gen.expose().iter().filter(|&&c| c == b'-').count() >= 5);
    assert!(h.bits > 105.0);
}

/// Messages are fixed, distinct, and name the constraint.
#[test]
fn error_messages() {
    let all = [
        Error::Length,
        Error::NoClasses,
        Error::SymbolChar,
        Error::SymbolDuplicate,
        Error::SymbolsEmpty,
        Error::WordCount,
        Error::Separator,
        Error::Attempts,
        Error::Random,
        Error::Capacity,
        Error::WordList,
    ];
    let msgs: BTreeSet<&str> = all.iter().map(|e| e.message()).collect();
    assert_eq!(msgs.len(), all.len());
    assert!(Error::Length.message().contains("8"));
    assert!(Error::WordCount.message().contains("16"));
}

/// A slot that is not the 1 KiB `Gen` slot: too small for the passphrase
/// is a clean `Capacity` error.
#[test]
fn passphrase_too_long_for_slot_is_capacity() {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let mut rng = Chacha::new(2);
    let r = generate(&mut rng, &Policy::DEFAULT_WORDS, &mut s.kek);
    assert_eq!(r, Err(Error::Capacity));
    assert!(s.kek.is_empty());
    let r = generate(&mut rng, &Policy::DEFAULT_CHARS, &mut s.kek);
    assert!(r.is_ok(), "20 characters fit 32 bytes");
}
