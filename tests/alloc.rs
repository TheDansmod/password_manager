//! T-MEM-6: the zeroizing allocator, in verifying mode, for this test crate.
//! Every block freed anywhere in this binary is checked to be all-zero just
//! before `System::dealloc`; a violation aborts the test process.

use pwv::alloc::ZeroizingAlloc;

#[global_allocator]
static GLOBAL: ZeroizingAlloc = ZeroizingAlloc::new(true);

#[test]
fn t_mem_6_verifying_layer_is_active() {
    let before = GLOBAL.verified_count();
    drop(vec![0xAAu8; 10_000]);
    drop(String::from("canary-value"));
    assert!(GLOBAL.verified_count() >= before + 2);
}

#[test]
fn realloc_moves_and_preserves_contents() {
    let mut v: Vec<u32> = Vec::with_capacity(1);
    for i in 0..100_000u32 {
        v.push(i);
    }
    assert!(v.iter().enumerate().all(|(i, &x)| x as usize == i));
    v.truncate(10);
    v.shrink_to_fit();
    assert_eq!(v, (0..10).collect::<Vec<_>>());
}

#[test]
fn high_alignment_and_zeroed_allocations() {
    #[repr(align(4096))]
    struct Page([u8; 4096]);
    let b = Box::new(Page([7; 4096]));
    assert_eq!((&raw const *b) as usize % 4096, 0);
    assert_eq!(b.0[4095], 7);
    drop(b);
    let z = vec![0u64; 1 << 16];
    assert!(z.iter().all(|&x| x == 0));
}
