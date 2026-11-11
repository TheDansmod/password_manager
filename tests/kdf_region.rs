//! T-MEM-7: after unlock the KDF region is no longer mapped, and (in
//! `memtest`) its bytes were zero just before `munmap` (spec Sections 5.4,
//! 14.9). One test in its own crate, so no other test thread can map
//! memory at the freed address while `/proc/self/maps` is inspected.

mod common;

use common::vaults::{arena, floor_params, make_vault, put, sample_model};
use pwv::vault;

#[global_allocator]
static GLOBAL: pwv::alloc::ZeroizingAlloc = pwv::alloc::ZeroizingAlloc::new(true);

#[test]
fn t_mem_7_kdf_region_unmapped_after_unlock() {
    let (file, h) = make_vault("pw", &sample_model(), floor_params(), 1);
    let mut a = arena();
    let (arena_start, _) = a.data_range();
    let mut s = a.slots().unwrap();
    put(&mut s.pw1, b"pw");
    let (_, out) = vault::unlock(
        &file,
        &mut s.pw1,
        &mut s.pw2,
        &mut s.kek,
        &mut s.dek,
        &mut s.vault_a,
        false,
    )
    .expect("unlock");
    let maps = std::fs::read_to_string("/proc/self/maps").expect("maps");
    let (start, end) = out.region;
    let m = usize::try_from(h.kdf_m_kib).unwrap() * 1024;
    assert!(end - start >= m, "region covers m KiB");
    // The data part and both guard pages are gone.
    let page = 4096;
    let (lo, hi) = (start - page, end + page);
    for v in common::parse_smaps(&maps) {
        assert!(
            v.end <= lo || v.start >= hi,
            "KDF region still mapped: {:#x}-{:#x}",
            v.start,
            v.end
        );
    }
    // The arena itself is still there (the check above is not vacuous).
    assert!(common::vma_at(&common::parse_smaps(&maps), arena_start).is_some());
    #[cfg(feature = "memtest")]
    assert!(out.wiped, "KDF region not zero before munmap");
    // Small (testkdf) regions fit the 8 MiB RLIMIT_MEMLOCK and are locked.
    #[cfg(feature = "testkdf")]
    assert!(out.locked, "KDF region was not locked");
}
