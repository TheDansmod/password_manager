//! T-PERF-1 (spec 14.12; M9): unlock at the default parameters <= 3 s; a
//! save of 1,000 entries, excluding `fsync`, <= 50 ms; allocator overhead
//! versus `System` <= 5 %.
//!
//! Owner decisions (2026-11-16, DESIGN_NOTES "M9 decisions" item 4):
//! "excluding fsync" is measured on tmpfs, where `fsync` costs nearly
//! nothing, with no production code added; the allocator overhead is an
//! in-process benchmark of a representative workload run twice, `System`
//! versus `ZeroizingAlloc::new(false)`, median of several runs; nightly, on
//! the CI runner, which the job records.
//!
//! Timings are meaningless next to a parallel test run, so these tests act
//! only with `PWV_PERF=1` (the nightly `perf` job: release build, one test
//! thread) and return at once otherwise. Each prints its measurement to
//! fd 2 (`T-PERF-1 ...` lines: durations only), which the job checks by name.

mod common;

use common::vaults::{arena, big_model, floor_params, put, read_body, write_body};
use pwv::crypto::{self, KdfParams};
use pwv::store::{Paths, Store};
use pwv::vault;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const VERIFY: u8 = 0;
const SYSTEM: u8 = 1;
const PLAIN: u8 = 2;

/// The allocator that frees blocks: the verifying `ZeroizingAlloc`
/// (T-MEM-6) except inside the allocator benchmark.
static MODE: AtomicU8 = AtomicU8::new(VERIFY);
static VERIFYING: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);
static ZEROIZING: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(false);

/// T-MEM-6's verifying allocator, switchable for the benchmark to `System`
/// or to the plain zeroizing allocator that `main.rs` installs. Every mode
/// allocates from and frees to `System` (`ZeroizingAlloc` only wipes before
/// `System::dealloc`), so a block allocated in one mode may be freed in
/// another.
struct Switch;

// SAFETY: every method forwards the caller's arguments unchanged to an
// allocator whose blocks all come from `System` (see `Switch`), so each
// block is freed by the allocator family that allocated it.
unsafe impl GlobalAlloc for Switch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc_zeroed`'s contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live `System` block of `layout` (see `Switch`).
        unsafe {
            match MODE.load(Ordering::Relaxed) {
                SYSTEM => System.dealloc(ptr, layout),
                PLAIN => ZEROIZING.dealloc(ptr, layout),
                _ => VERIFYING.dealloc(ptr, layout),
            }
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: as `dealloc`; the caller upholds `realloc`'s contract.
        unsafe {
            match MODE.load(Ordering::Relaxed) {
                SYSTEM => System.realloc(ptr, layout, new_size),
                PLAIN => ZEROIZING.realloc(ptr, layout, new_size),
                _ => VERIFYING.realloc(ptr, layout, new_size),
            }
        }
    }
}

// T-MEM-6: wraps `ZeroizingAlloc::new(true)`, the default mode.
#[global_allocator]
static GLOBAL: Switch = Switch;

/// The measurements take turns (timings, and the allocator mode).
static TURN: Mutex<()> = Mutex::new(());

fn enabled() -> bool {
    std::env::var_os("PWV_PERF").is_some_and(|v| v == "1")
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn report(line: &str) {
    pwv::sys::write_stderr(format!("{line}\n").as_bytes());
}

const PW: &str = "correct horse battery staple";

/// Unlock (Argon2id at 256 MiB, t = 3, then unwrap and decrypt), median of
/// five, against a vault created at the default parameters.
#[test]
fn t_perf_1_unlock_at_default_parameters() {
    if !enabled() {
        return;
    }
    let _t = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let (mut h, _) = vault::init(
        s.pw2.expose(),
        KdfParams::DEFAULT,
        &mut s.kek,
        &mut s.dek,
        false,
    )
    .unwrap();
    assert_eq!((h.kdf_m_kib, h.kdf_t), (262_144, 3), "default parameters");
    write_body(&big_model(100), &mut s.vault_a);
    let file = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
    let mut times = Vec::new();
    for _ in 0..5 {
        put(&mut s.pw1, PW.as_bytes());
        let t0 = Instant::now();
        vault::unlock(
            &file,
            &mut s.pw1,
            &mut s.pw2,
            &mut s.kek,
            &mut s.dek,
            &mut s.vault_b,
            false,
        )
        .unwrap();
        times.push(t0.elapsed());
    }
    assert_eq!(read_body(s.vault_b.expose()), big_model(100));
    let m = median(times.clone());
    report(&format!(
        "T-PERF-1 unlock at 256 MiB, t = 3: median {:.3} s of {:?} (limit 3 s)",
        m.as_secs_f64(),
        times.iter().map(|t| t.as_millis()).collect::<Vec<_>>()
    ));
    assert!(m <= Duration::from_secs(3), "unlock median {m:?} > 3 s");
}

/// `PWV_PERF_TMPFS`, else the temporary directory; must be tmpfs.
fn tmpfs_dir() -> std::path::PathBuf {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    let dir = std::env::var_os("PWV_PERF_TMPFS").map_or_else(std::env::temp_dir, Into::into);
    let st = rustix::fs::statfs(&dir).expect("statfs");
    #[allow(clippy::cast_sign_loss, reason = "f_type is a magic number")]
    let magic = st.f_type as u64;
    assert_eq!(
        magic,
        TMPFS_MAGIC,
        "{} must be tmpfs (\"excluding fsync\"; PWV_PERF_TMPFS)",
        dir.display()
    );
    dir
}

/// A save of 1,000 entries on tmpfs: serialise the model into the arena,
/// encrypt (`vault::save`), and `Store::save` (temporary file, `fsync`,
/// rename, backup rotation, state file). Median of eleven.
#[test]
fn t_perf_1_save_1000_entries_on_tmpfs() {
    if !enabled() {
        return;
    }
    let _t = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir_in(tmpfs_dir()).unwrap();
    let paths = Paths {
        vault: tmp.path().join("pwv/vault.pwv"),
        state: tmp.path().join("state/pwv/state"),
    };
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let (mut h, _) = vault::init(
        s.pw2.expose(),
        floor_params(),
        &mut s.kek,
        &mut s.dek,
        false,
    )
    .unwrap();
    let mut st = Store::create(paths, false).unwrap();
    let model = big_model(1000);
    let mut times = Vec::new();
    for _ in 0..11 {
        let t0 = Instant::now();
        write_body(&model, &mut s.vault_a);
        let file = vault::save(s.dek.expose(), &mut h, s.vault_a.expose_mut()).unwrap();
        st.save(&file).unwrap();
        times.push(t0.elapsed());
    }
    let m = median(times);
    report(&format!(
        "T-PERF-1 save of 1,000 entries on tmpfs: median {:.2} ms (limit 50 ms)",
        m.as_secs_f64() * 1e3
    ));
    assert!(m <= Duration::from_millis(50), "save median {m:?} > 50 ms");
}

/// The representative workload: what the test suite and a session do to
/// the heap. Build a 1,000-entry model (owned strings), serialise it into
/// the arena, encrypt, decrypt, parse it back into owned strings, compare.
fn workload(dek: &[u8], kek: &[u8], h: &mut pwv::format::Header) {
    let mut a = arena();
    let mut s = a.slots().unwrap();
    let model = big_model(1000);
    write_body(&model, &mut s.vault_a);
    let file = vault::save(dek, h, s.vault_a.expose_mut()).unwrap();
    vault::open_with_kek(&file, kek, &mut s.dek, &mut s.vault_b).unwrap();
    assert_eq!(read_body(s.vault_b.expose()), model);
}

/// Allocator overhead: the workload under `ZeroizingAlloc::new(false)`
/// (what `main.rs` installs) versus `System`, alternating, median of nine
/// runs of each; overhead = median ratio - 1 <= 5 %.
#[test]
fn t_perf_1_allocator_overhead() {
    if !enabled() {
        return;
    }
    let _t = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let mut a = arena();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, PW.as_bytes());
    crypto::normalize(s.pw1.expose(), &mut s.pw2).unwrap();
    let (mut h, _) = vault::init(
        s.pw2.expose(),
        floor_params(),
        &mut s.kek,
        &mut s.dek,
        false,
    )
    .unwrap();
    crypto::derive_kek(s.pw2.expose(), &h.salt, floor_params(), &mut s.kek, false).unwrap();
    let (dek, kek) = (s.dek.expose().to_vec(), s.kek.expose().to_vec());
    let run = |mode: u8, h: &mut pwv::format::Header| {
        MODE.store(mode, Ordering::SeqCst);
        let t0 = Instant::now();
        // About 0.3 s per run in release: short runs measured only noise
        // (+-4 % at 31 ms per run, locally).
        for _ in 0..200 {
            workload(&dek, &kek, h);
        }
        let t = t0.elapsed();
        MODE.store(VERIFY, Ordering::SeqCst);
        t
    };
    run(SYSTEM, &mut h); // warm-up
    let (mut sys, mut zero) = (Vec::new(), Vec::new());
    for _ in 0..9 {
        sys.push(run(SYSTEM, &mut h));
        zero.push(run(PLAIN, &mut h));
    }
    let (ms, mz) = (median(sys), median(zero));
    let overhead = mz.as_secs_f64() / ms.as_secs_f64() - 1.0;
    report(&format!(
        "T-PERF-1 allocator overhead: System median {:.1} ms, ZeroizingAlloc median {:.1} ms, \
         overhead {:+.2} % (limit 5 %)",
        ms.as_secs_f64() * 1e3,
        mz.as_secs_f64() * 1e3,
        overhead * 100.0
    ));
    assert!(overhead <= 0.05, "allocator overhead {overhead:.4} > 5 %");
}
