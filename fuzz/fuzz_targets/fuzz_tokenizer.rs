//! T-FUZZ-4: REPL tokenizer, command parser, and `gen` option parser, plus
//! the master-password strength estimate (which also reads typed input).
//! Invariants: no panic; every argument is a range inside the buffer, in
//! order and without overlap; at most `MAX_ARGS` arguments; re-quoting
//! the arguments and tokenizing again yields the same arguments.

#![no_main]
// `fuzz_target!` expands to a `File::create` (libfuzzer-sys debug output);
// pwv's clippy.toml ban applies to the production crate, not harnesses.
#![allow(clippy::disallowed_methods)]

use libfuzzer_sys::fuzz_target;
use pwv::cli::{MAX_ARGS, contains_ci, gen_policy, parse_command, tokenize, weakness};

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

fuzz_target!(|data: &[u8]| {
    // Passwords come from a 1 KiB slot and lines from a 4 KiB slot.
    let _ = weakness(&data[..data.len().min(1024)]);
    let (hay, needle) = data.split_at(data.len() / 2);
    let _ = contains_ci(&hay[..hay.len().min(256)], &needle[..needle.len().min(256)]);
    let mut buf = data[..data.len().min(4096)].to_vec();
    let Ok(args) = tokenize(&mut buf) else {
        return;
    };
    assert!(args.len() <= MAX_ARGS);
    let tokens: Vec<Vec<u8>> = (0..args.len())
        .map(|i| args.get(&buf, i).expect("range inside the buffer").to_vec())
        .collect();
    assert!(args.get(&buf, args.len()).is_none());
    assert!(tokens.iter().map(Vec::len).sum::<usize>() <= buf.len());
    // Canonical re-quoting round-trips.
    let mut line = Vec::new();
    for t in &tokens {
        line.push(b'"');
        for &b in t {
            if b == b'"' || b == b'\\' {
                line.push(b'\\');
            }
            line.push(b);
        }
        line.extend_from_slice(b"\" ");
    }
    let again = tokenize(&mut line).expect("canonical quoting is valid");
    assert_eq!(again.len(), tokens.len());
    for (i, t) in tokens.iter().enumerate() {
        assert_eq!(again.get(&line, i).expect("range"), &t[..]);
    }
    if let Ok(cmd) = parse_command(&buf, &args) {
        for i in 0..4 {
            let _ = cmd.arg(&buf, i);
        }
        for f in cmd.spec.flags {
            assert_eq!(cmd.has(f.0), cmd.opt(&buf, f.0).is_some());
        }
        if let Ok(policy) = gen_policy(&cmd, &buf) {
            let _ = policy.validate();
        }
    }
});
