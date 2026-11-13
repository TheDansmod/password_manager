//! Secure arena tests: T-MEM-1, T-MEM-2, T-MEM-3, T-ENG-5, and slot contract.

mod common;

use pwv::secmem::{DEFAULT_ARENA, Error, MAX_ARENA, MIN_ARENA, SecretSlot, SecureArena};
use static_assertions::assert_not_impl_any;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

// T-ENG-5: no Clone, Copy, Display, Send, Sync, or Deref to bytes.
assert_not_impl_any!(SecureArena: Clone, Copy, std::fmt::Display, Send, Sync);
assert_not_impl_any!(SecretSlot<'static>: Clone, Copy, std::fmt::Display, Send, Sync);
assert_not_impl_any!(SecureArena: std::ops::Deref<Target = [u8]>, std::ops::DerefMut);
assert_not_impl_any!(SecretSlot<'static>: std::ops::Deref<Target = [u8]>, std::ops::DerefMut);
assert_not_impl_any!(pwv::secmem::Slots<'static>: Clone, Send, Sync);

const PAGE: usize = 4096;

fn arena() -> SecureArena {
    SecureArena::new(DEFAULT_ARENA, false).expect("arena (needs RLIMIT_MEMLOCK >= 1 MiB)")
}

#[test]
fn t_mem_1_smaps_locked_dontdump_wipeonfork_guards() {
    let a = arena();
    assert!(a.is_locked());
    let (start, end) = a.data_range();
    assert_eq!(end - start, DEFAULT_ARENA);
    assert_eq!(start % PAGE, 0);
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("smaps");
    let vmas = common::parse_smaps(&smaps);
    let data = common::vma_at(&vmas, start).expect("data vma");
    assert_eq!(
        (data.start, data.end),
        (start, end),
        "data region is exactly one VMA"
    );
    assert_eq!(data.perms, "rw-p");
    assert_eq!(
        data.field("Locked"),
        Some(format!("{} kB", DEFAULT_ARENA / 1024).as_str())
    );
    let flags: Vec<&str> = data
        .field("VmFlags")
        .expect("VmFlags")
        .split_whitespace()
        .collect();
    for f in ["dd", "wf", "lo"] {
        assert!(flags.contains(&f), "VmFlags {flags:?} lacks {f}");
    }
    let below = common::vma_at(&vmas, start - 1).expect("lower guard");
    let above = common::vma_at(&vmas, end).expect("upper guard");
    assert_eq!(below.perms, "---p");
    assert_eq!(above.perms, "---p");
}

#[test]
fn arena_size_bounds_and_rounding() {
    assert_eq!(
        SecureArena::new(MIN_ARENA - 1, false).err(),
        Some(Error::Size)
    );
    assert_eq!(
        SecureArena::new(MAX_ARENA + 1, false).err(),
        Some(Error::Size)
    );
    let a = SecureArena::new(MIN_ARENA + 1, false).expect("arena");
    assert_eq!(a.size(), MIN_ARENA + PAGE, "rounded up to whole pages");
}

#[test]
fn slot_layout_partitions_region_and_last_slot_meets_guard() {
    let mut a = arena();
    let len = a.size();
    let s = a.slots().expect("slots");
    let caps = [
        s.input.capacity(),
        s.pw1.capacity(),
        s.pw2.capacity(),
        s.kek.capacity(),
        s.dek.capacity(),
        s.new_dek.capacity(),
        s.r#gen.capacity(),
        s.clip.capacity(),
    ];
    assert_eq!(caps, [4096, 1024, 1024, 32, 32, 32, 1024, 1024]);
    let fixed: usize = caps.iter().sum();
    assert_eq!(s.vault_a.capacity() + s.vault_b.capacity() + fixed, len);
    assert!(s.vault_b.capacity() - s.vault_a.capacity() <= 1);
}

#[test]
fn slot_contract_zero_tail_clear_and_redaction() {
    let mut a = arena();
    let mut s = a.slots().expect("slots");
    let slot = &mut s.pw1;
    assert!(slot.is_empty());
    assert_eq!(slot.set_len(1025), Err(Error::Capacity));
    slot.set_len(8).expect("len");
    assert_eq!(slot.expose(), &[0u8; 8]);
    slot.expose_mut().copy_from_slice(b"hunter22");
    assert_eq!(format!("{slot:?}"), "[REDACTED; 8 bytes]");
    slot.set_len(3).expect("shrink");
    slot.set_len(8).expect("regrow");
    assert_eq!(
        slot.expose(),
        b"hun\0\0\0\0\0",
        "shrinking zeroizes the cut tail"
    );
    slot.clear();
    assert!(slot.is_empty());
    slot.set_len(8).expect("regrow");
    assert_eq!(slot.expose(), &[0u8; 8]);
    assert_eq!(format!("{:?}", s), format!("{:?}", s));
    assert!(!format!("{s:?}").contains("hun"));
    drop(s);
    assert!(format!("{a:?}").starts_with("SecureArena([REDACTED"));
}

#[test]
fn unlocked_override_is_reported() {
    // With the override the arena is always created; is_locked tells the truth.
    let a = SecureArena::new(MIN_ARENA, true).expect("arena");
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("smaps");
    let vmas = common::parse_smaps(&smaps);
    let data = common::vma_at(&vmas, a.data_range().0).expect("vma");
    let locked = data
        .field("VmFlags")
        .expect("flags")
        .split_whitespace()
        .any(|f| f == "lo");
    assert_eq!(a.is_locked(), locked);
}

#[cfg(feature = "memtest")]
mod memtest {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    const ENV: &str = "PWV_T_MEM_2_PROBE";

    /// Child half of T-MEM-2; a no-op unless run by `t_mem_2_*` below.
    #[test]
    fn t_mem_2_child() {
        let Ok(dir) = std::env::var(ENV) else { return };
        // Hygiene: the deliberate crash must not ship a core to the host's
        // systemd-coredump (this child is the dumpable test binary).
        let zero = rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        rustix::process::setrlimit(rustix::process::Resource::Core, zero).expect("rlimit");
        let mut a = arena();
        let s = a.slots().expect("slots");
        drop(s);
        a.probe_guard(dir == "over");
        // Unreachable if the guard page works.
        std::process::exit(0);
    }

    fn assert_segv(dir: &str) {
        let out = common::run_child("memtest::t_mem_2_child", &[(ENV, dir)]);
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGSEGV),
            "{dir}flow probe must die by SIGSEGV; status {:?}",
            out.status
        );
    }

    #[test]
    fn t_mem_2_write_past_last_slot_faults() {
        assert_segv("over");
    }

    #[test]
    fn t_mem_2_write_before_first_slot_faults() {
        assert_segv("under");
    }

    #[test]
    fn t_mem_3_slot_drop_then_arena_drop_leave_all_zero() {
        let mut a = arena();
        {
            let mut s = a.slots().expect("slots");
            for slot in [&mut s.pw1, &mut s.kek, &mut s.vault_b] {
                let n = slot.capacity().min(64);
                slot.set_len(n).expect("len");
                slot.expose_mut().fill(0xA5);
            }
        } // slots dropped: used prefixes zeroized
        assert!(
            a.raw_data().iter().all(|&b| b == 0),
            "slot drop left residue"
        );
        let mut checked = false;
        a.close_with_snapshot(&mut |data| {
            assert_eq!(data.len(), DEFAULT_ARENA);
            assert!(data.iter().all(|&b| b == 0));
            checked = true;
        });
        assert!(checked, "snapshot hook ran");
    }

    #[test]
    fn t_mem_3_arena_drop_wipes_even_if_slot_drop_was_skipped() {
        let mut a = arena();
        let mut s = a.slots().expect("slots");
        s.input.set_len(4096).expect("len");
        s.input.expose_mut().fill(0x5A);
        std::mem::forget(s); // simulate a slot whose Drop never ran
        assert!(a.raw_data().iter().any(|&b| b != 0));
        let mut all_zero = false;
        a.close_with_snapshot(&mut |data| all_zero = data.iter().all(|&b| b == 0));
        assert!(all_zero, "arena teardown must zeroize the full region");
    }
}

#[test]
fn wipe_zeroes_exactly_the_slice_at_every_alignment() {
    // `sys::wipe` stores a `u64` at a time over the aligned middle and
    // bytes at the ends: every start offset and length up to three words.
    let mut buf = [0u8; 64];
    for start in 0..16 {
        for len in 0..=24 {
            buf.fill(0xA5);
            pwv::sys::wipe(&mut buf[start..start + len]);
            for (i, &b) in buf.iter().enumerate() {
                let inside = (start..start + len).contains(&i);
                assert_eq!(
                    b,
                    if inside { 0 } else { 0xA5 },
                    "start {start} len {len} byte {i}"
                );
            }
        }
    }
}
