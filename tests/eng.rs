//! Engineering gates that are checked by reading the source tree.
//!
//! - T-ENG-2: `unsafe` appears only in `sys.rs`, `secmem.rs`, `alloc.rs`, and
//!   every `unsafe` use is immediately preceded by a `// SAFETY:` comment
//!   (or a `# Safety` doc section for `unsafe fn` / `unsafe trait`).
//! - T-ENG-3: the `crate::` dependency graph respects the layering of spec
//!   Section 4; no `static mut`; no global state except the allocator and
//!   atomics (signal flags).
//! - T-ENG-4 (scope part): the clippy bans in `clippy.toml` may be locally
//!   allowed only in `term.rs` (stdio) and `store.rs` (file creation).
//!
//! The checks are deliberately simple line scanners over comment-stripped
//! source. Each checker has negative self-tests at the bottom of this file so
//! that a broken checker cannot pass silently.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

/// Every production source file of spec Section 4, and nothing else.
const SRC_FILES: &[&str] = &[
    "main.rs",
    "lib.rs",
    "cli.rs",
    "term.rs",
    "clip.rs",
    "vault.rs",
    "format.rs",
    "crypto.rs",
    "gen.rs",
    "store.rs",
    "secmem.rs",
    "alloc.rs",
    "sys.rs",
];

/// Modules allowed to contain `unsafe` (spec Section 3, principle 5).
const UNSAFE_MODULES: &[&str] = &["sys", "secmem", "alloc"];

/// Files allowed to locally allow a clippy `disallowed_*` lint (T-ENG-4).
const BAN_EXEMPT: &[&str] = &["term.rs", "store.rs"];

/// Layer of each library module; a module may use only strictly lower
/// layers. `alloc` is independent and handled separately.
fn layer(module: &str) -> Option<u8> {
    match module {
        "sys" => Some(0),
        "secmem" => Some(1),
        "format" | "crypto" => Some(2),
        "clip" | "term" | "store" | "vault" | "gen" => Some(3),
        "cli" => Some(4),
        _ => None,
    }
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read_src(name: &str) -> String {
    fs::read_to_string(src_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn module_of(file: &str) -> &str {
    file.trim_end_matches(".rs")
}

/// Removes `//` comments, `/* */` comments, and the contents of string and
/// char literals, keeping line structure. Doc comments are removed too.
fn strip_code(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = 0usize;
    for line in src.lines() {
        let b: Vec<char> = line.chars().collect();
        let mut s = String::new();
        let mut i = 0;
        let mut in_str = false;
        while i < b.len() {
            let c = b[i];
            let next = b.get(i + 1).copied();
            if in_block > 0 {
                if c == '*' && next == Some('/') {
                    in_block -= 1;
                    i += 2;
                } else if c == '/' && next == Some('*') {
                    in_block += 1;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_str {
                if c == '\\' {
                    i += 2;
                } else {
                    if c == '"' {
                        in_str = false;
                        s.push('"');
                    }
                    i += 1;
                }
                continue;
            }
            if c == '/' && next == Some('/') {
                break;
            }
            if c == '/' && next == Some('*') {
                in_block += 1;
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = true;
                s.push('"');
                i += 1;
                continue;
            }
            // Char literal such as '{' or '\''; lifetimes ('a) are left alone.
            if c == '\'' {
                if next == Some('\\') {
                    if let Some(end) = (i + 2..b.len()).find(|&j| b[j] == '\'') {
                        s.push_str("' '");
                        i = end + 1;
                        continue;
                    }
                } else if b.get(i + 2) == Some(&'\'') {
                    s.push_str("' '");
                    i += 3;
                    continue;
                }
            }
            s.push(c);
            i += 1;
        }
        out.push(s);
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True if `word` occurs in `line` as a whole token.
fn has_word(line: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(word) {
        let at = start + pos;
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        if !before.is_some_and(is_ident_char) && !after.is_some_and(is_ident_char) {
            return true;
        }
        start = at + word.len();
    }
    false
}

/// Returns the first path segment after every occurrence of `prefix`
/// (for example `crate::`), expanding brace groups: `crate::{a, b::c}`
/// yields `a` and `b`. Raw identifiers (`r#gen`) are unprefixed.
fn path_roots(code: &str, prefix: &str) -> BTreeSet<String> {
    let mut roots = BTreeSet::new();
    let mut start = 0;
    while let Some(pos) = code[start..].find(prefix) {
        let at = start + pos;
        start = at + prefix.len();
        if code[..at].chars().next_back().is_some_and(is_ident_char) {
            continue; // e.g. `mycrate::`
        }
        let rest = code[start..].trim_start();
        if let Some(group) = rest.strip_prefix('{') {
            let mut depth = 1usize;
            let mut item = String::new();
            let mut items = Vec::new();
            for c in group.chars() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    ',' if depth == 1 => {
                        items.push(std::mem::take(&mut item));
                        continue;
                    }
                    _ => {}
                }
                if depth == 1 {
                    item.push(c);
                }
            }
            items.push(item);
            for it in items {
                let ident: String = it
                    .trim()
                    .trim_start_matches("r#")
                    .chars()
                    .take_while(|&c| is_ident_char(c))
                    .collect();
                if !ident.is_empty() && ident != "self" {
                    roots.insert(ident);
                }
            }
        } else {
            let ident: String = rest
                .trim_start_matches("r#")
                .chars()
                .take_while(|&c| is_ident_char(c))
                .collect();
            if !ident.is_empty() {
                roots.insert(ident);
            }
        }
    }
    roots
}

/// T-ENG-2 core: returns the 1-based lines of `unsafe` uses that are not
/// preceded by a SAFETY comment. A use is justified if a `SAFETY:` comment
/// (or `# Safety` doc heading) appears on the same line, or in the comment
/// lines directly above the statement containing it.
fn unjustified_unsafe(src: &str) -> Vec<usize> {
    let raw: Vec<&str> = src.lines().collect();
    let code = strip_code(src);
    let mut bad = Vec::new();
    for (i, line) in code.iter().enumerate() {
        if !has_word(line, "unsafe") {
            continue;
        }
        let marker = |l: &str| l.contains("SAFETY:") || l.contains("# Safety");
        if raw.get(i).is_some_and(|l| marker(l)) {
            continue;
        }
        let mut ok = false;
        let mut j = i;
        while j > 0 {
            j -= 1;
            let r = raw[j].trim();
            let c = code[j].trim();
            if r.is_empty() {
                break;
            }
            if c.is_empty() || c.starts_with("#[") {
                // Pure comment or attribute line.
                if marker(r) {
                    ok = true;
                    break;
                }
                continue;
            }
            // Code line: a statement boundary ends the search; otherwise it
            // is a continuation of the statement containing `unsafe`.
            if c.ends_with(';') || c.ends_with('{') || c.ends_with('}') {
                break;
            }
        }
        if !ok {
            bad.push(i + 1);
        }
    }
    bad
}

/// T-ENG-3 core: returns offending lines for forbidden global state.
fn global_state_violations(src: &str) -> Vec<(usize, String)> {
    let code = strip_code(src);
    let mut bad = Vec::new();
    let forbidden = [
        "thread_local",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "LazyCell",
        "lazy_static",
        "once_cell",
    ];
    for (i, line) in code.iter().enumerate() {
        for f in forbidden {
            if has_word(line, f) {
                bad.push((i + 1, format!("forbidden global-state primitive `{f}`")));
            }
        }
        // `static` items (not `'static` lifetimes).
        let mut start = 0;
        while let Some(pos) = line[start..].find("static") {
            let at = start + pos;
            start = at + "static".len();
            let before = line[..at].chars().next_back();
            let after = line[start..].chars().next();
            if before == Some('\'')
                || before.is_some_and(is_ident_char)
                || after.is_some_and(is_ident_char)
            {
                continue;
            }
            let rest = line[start..].trim_start();
            if rest.starts_with("mut ") {
                bad.push((i + 1, "`static mut`".to_owned()));
                continue;
            }
            let ty = rest
                .split_once(':')
                .map(|(_, t)| t.trim_start())
                .unwrap_or("");
            let prev_attr = code[..i].iter().rev().find(|l| !l.trim().is_empty());
            let is_allocator = prev_attr.is_some_and(|l| l.contains("#[global_allocator]"));
            let is_atomic = ty.starts_with("Atomic")
                || ty.starts_with("std::sync::atomic::Atomic")
                || ty.starts_with("core::sync::atomic::Atomic");
            if !is_allocator && !is_atomic {
                bad.push((
                    i + 1,
                    "`static` that is neither the allocator nor an atomic".to_owned(),
                ));
            }
        }
    }
    bad
}

#[test]
fn t_eng_layout_src_files_exact() {
    let mut found: Vec<String> = fs::read_dir(src_dir())
        .expect("read src")
        .map(|e| {
            e.expect("dirent")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".rs"))
        .collect();
    found.sort();
    let mut want: Vec<String> = SRC_FILES.iter().map(|s| (*s).to_owned()).collect();
    want.sort();
    assert_eq!(
        found, want,
        "src/ must contain exactly the modules of Section 4"
    );
}

#[test]
fn t_eng_2_unsafe_confined_and_justified() {
    for file in SRC_FILES {
        let src = read_src(file);
        let code = strip_code(&src);
        let module = module_of(file);
        let uses_unsafe = code.iter().any(|l| has_word(l, "unsafe"));
        let allows = code.iter().any(|l| {
            l.contains("allow(unsafe_code)") || l.contains("allow(unsafe_op_in_unsafe_fn)")
        });
        if UNSAFE_MODULES.contains(&module) {
            assert!(
                code.iter().any(|l| l.trim() == "#![allow(unsafe_code)]"),
                "{file}: must carry #![allow(unsafe_code)]"
            );
        } else {
            assert!(!uses_unsafe, "{file}: `unsafe` outside sys/secmem/alloc");
            assert!(!allows, "{file}: may not allow unsafe lints");
        }
        let bad = unjustified_unsafe(&src);
        assert!(
            bad.is_empty(),
            "{file}: `unsafe` without `// SAFETY:` at lines {bad:?}"
        );
    }
    for root in ["lib.rs", "main.rs"] {
        let code = strip_code(&read_src(root));
        assert!(
            code.iter().any(|l| l.trim() == "#![deny(unsafe_code)]"),
            "{root}: crate root must #![deny(unsafe_code)]"
        );
        assert!(
            code.iter()
                .any(|l| l.trim() == "#![deny(unsafe_op_in_unsafe_fn)]"),
            "{root}: crate root must #![deny(unsafe_op_in_unsafe_fn)]"
        );
    }
}

#[test]
fn t_eng_3_layering() {
    for file in SRC_FILES {
        let module = module_of(file);
        let code = strip_code(&read_src(file)).join("\n");
        let deps = path_roots(&code, "crate::");
        match *file {
            "lib.rs" => assert!(deps.is_empty(), "lib.rs must only declare modules"),
            "main.rs" => {
                assert!(deps.is_empty(), "main.rs is a separate crate; use `pwv::`");
                let used = path_roots(&code, "pwv::");
                for d in &used {
                    assert!(
                        ["cli", "sys", "alloc"].contains(&d.as_str()),
                        "main.rs may use only pwv::{{cli, sys, alloc}}, found `{d}`"
                    );
                }
            }
            "alloc.rs" => assert!(deps.is_empty(), "alloc must be independent, found {deps:?}"),
            _ => {
                let own = layer(module).unwrap_or_else(|| panic!("{file}: no layer"));
                for d in &deps {
                    assert_ne!(d, "alloc", "{file}: only main.rs may use alloc");
                    let theirs = layer(d).unwrap_or_else(|| panic!("{file}: unknown module `{d}`"));
                    assert!(
                        theirs < own,
                        "{file} (layer {own}) may not use `{d}` (layer {theirs})"
                    );
                }
            }
        }
    }
}

#[test]
fn t_eng_3_no_global_state() {
    for file in SRC_FILES {
        let bad = global_state_violations(&read_src(file));
        assert!(bad.is_empty(), "{file}: {bad:?}");
    }
}

#[test]
fn t_eng_4_ban_exemptions_scoped() {
    for file in SRC_FILES {
        let code = strip_code(&read_src(file)).join("\n");
        let exempts = code.contains("disallowed_methods") || code.contains("disallowed_macros");
        if exempts {
            assert!(
                BAN_EXEMPT.contains(file),
                "{file}: may not allow clippy::disallowed_*"
            );
            assert!(
                !code.contains("#![allow(clippy::disallowed"),
                "{file}: exemptions must be item-level, not module-wide"
            );
        }
    }
}

#[test]
fn t_eng_syscalls_only_in_sys() {
    // Section 4: `sys` is the only module that names `rustix` or `libc`.
    for file in SRC_FILES {
        if *file == "sys.rs" {
            continue;
        }
        let code = strip_code(&read_src(file));
        for word in ["rustix", "libc"] {
            assert!(
                !code.iter().any(|l| has_word(l, word)),
                "{file}: names `{word}`"
            );
        }
    }
}

#[test]
fn t_mem_6_every_test_crate_installs_verifying_allocator() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut n = 0;
    for entry in fs::read_dir(&dir).expect("tests dir") {
        let path = entry.expect("dirent").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let code = strip_code(&fs::read_to_string(&path).expect("read")).join("\n");
            assert!(
                code.contains("#[global_allocator]") && code.contains("ZeroizingAlloc::new(true)"),
                "{}: must install the verifying ZeroizingAlloc (T-MEM-6)",
                path.display()
            );
            n += 1;
        }
    }
    assert!(n >= 4);
    let lib = strip_code(&read_src("lib.rs")).join("\n");
    assert!(
        lib.contains("ZeroizingAlloc::new(true)"),
        "lib unit tests (T-MEM-6)"
    );
}

// ---- Self-tests: each checker must reject known-bad input. ----

#[test]
fn selftest_unsafe_checker() {
    assert_eq!(
        unjustified_unsafe("fn f() {\n    unsafe { g() };\n}\n"),
        vec![2]
    );
    assert!(
        unjustified_unsafe("fn f() {\n    // SAFETY: ok.\n    unsafe { g() };\n}\n").is_empty()
    );
    assert!(
        unjustified_unsafe(
            "fn f() {\n    // SAFETY: ok.\n    let x =\n        unsafe { g() };\n}\n"
        )
        .is_empty()
    );
    // A SAFETY comment for a previous statement does not carry over.
    assert_eq!(
        unjustified_unsafe("// SAFETY: a.\nunsafe { a() };\nunsafe { b() };\n"),
        vec![3]
    );
    // Strings and comments do not count as uses.
    assert!(unjustified_unsafe("let s = \"unsafe\"; // unsafe\n").is_empty());
    assert!(unjustified_unsafe("/// # Safety\n/// caller ...\npub unsafe fn f() {}\n").is_empty());
}

#[test]
fn selftest_path_roots() {
    let r = path_roots(
        "use crate::{format, r#gen::X, secmem::{A, B}};\nuse crate::sys;",
        "crate::",
    );
    let want: BTreeSet<String> = ["format", "gen", "secmem", "sys"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(r, want);
    assert!(path_roots("use mycrate::x;", "crate::").is_empty());
    assert_eq!(
        path_roots("let a = crate::vault::f();", "crate::")
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["vault".to_owned()]
    );
}

#[test]
fn selftest_global_state_checker() {
    assert!(!global_state_violations("static mut X: u8 = 0;").is_empty());
    assert!(!global_state_violations("static X: Mutex<u8> = Mutex::new(0);").is_empty());
    assert!(!global_state_violations("static X: OnceLock<u8> = OnceLock::new();").is_empty());
    assert!(!global_state_violations("thread_local! { static X: u8 = 0; }").is_empty());
    assert!(
        global_state_violations("static FLAG: AtomicBool = AtomicBool::new(false);").is_empty()
    );
    assert!(global_state_violations("#[global_allocator]\nstatic A: Z = Z;").is_empty());
    assert!(global_state_violations("fn f(x: &'static str) {}").is_empty());
}

#[test]
fn selftest_strip_code() {
    let s = strip_code("let a = '{'; let b = \"}\\\"\"; // }\nlet c = 1; /* x\n y */ let d;");
    assert_eq!(s[0], "let a = ' '; let b = \"\"; ");
    assert_eq!(s[1], "let c = 1; ");
    assert_eq!(s[2], " let d;");
}
