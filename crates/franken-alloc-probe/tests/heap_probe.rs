//! The probe's own heap figure (`N02` / `ffw-ugf`, acceptance row 17): `live_bytes`, `measure_heap` and `heap_is_tracked`.
//!
//! `tests/n02_heap_high_water.rs` bounds a channel's heap with this figure, so the figure is checked here first, against
//! allocations whose sizes are known to the byte: a block held across the window is net growth, a block made and dropped
//! inside it is a peak and no growth, a `realloc` that grows is counted at its new size, a window nested in a window leaves
//! the outer peak intact, a block that is retained shows up as growth that a dropped one does not, and a request that the
//! probe's injected failure refuses holds no memory and never reaches the high-water mark, and a nested window that
//! unwinds (its panic caught inside the outer window) leaves the outer window with the peak it had already reached.
//!
//! Host allocation behaviour only. It says nothing about a board's allocator, its size classes or its fragmentation.
use std::hint::black_box;
use std::panic::catch_unwind;

use franken_alloc_probe::{
    CountingAllocator, fail_next_allocation, heap_is_tracked, live_bytes, measure_heap,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

// Sizes for the unwind tests. The block an outer window reaches first is far larger than anything the panic itself allocates
// (its payload, a captured message), so a peak that was lost cannot be hidden by the noise of the unwind.
const EARLIER_BLOCK: usize = 4 * 1024 * 1024;
const SMALL_BLOCK: usize = 1000;
const AFTER_BLOCK: usize = 2000;
const LATER_BLOCK: usize = 5000;

fn planted_panic() {
    panic!("planted: a nested measure_heap window unwinds");
}

/// A measured window that holds `bytes` and then panics. It catches nothing: the test catches the panic from outside, which is the
/// case under test (a caught unwind inside an outer window).
fn a_window_that_holds_a_block_and_then_unwinds(bytes: usize) {
    measure_heap(|| {
        let _held = black_box(vec![0u8; bytes]);
        planted_panic();
    });
}

#[test]
fn the_heap_figure_is_live_in_this_binary() {
    assert!(
        heap_is_tracked(),
        "the counting allocator is not this binary's global allocator, or its live figure did not move"
    );
}

#[test]
fn a_block_held_across_the_window_is_net_growth_and_a_dropped_one_is_only_a_peak() {
    let before = live_bytes();
    // Held: the window ends with the block alive.
    let (held, window) = measure_heap(|| black_box(vec![0u8; 4096]));
    assert_eq!(window.net_bytes, 4096);
    assert_eq!(window.peak_above_start, 4096);
    assert_eq!(live_bytes() - before, 4096);
    drop(held);
    assert_eq!(
        live_bytes(),
        before,
        "dropping the block returns the figure"
    );

    // Dropped inside: the same allocation, no net growth, but the high-water mark still sees it.
    let ((), window) = measure_heap(|| drop(black_box(vec![0u8; 4096])));
    assert_eq!(window.net_bytes, 0);
    assert_eq!(window.peak_above_start, 4096);
    assert_eq!(live_bytes(), before);
}

#[test]
fn a_window_that_only_frees_has_a_peak_of_zero_and_negative_growth() {
    let block = black_box(vec![0u8; 1000]);
    let ((), window) = measure_heap(|| drop(block));
    assert_eq!(window.net_bytes, -1000);
    assert_eq!(window.peak_above_start, 0);
}

#[test]
fn a_realloc_that_grows_is_counted_at_its_new_size() {
    let mut buffer: Vec<u8> = Vec::with_capacity(100);
    buffer.push(1);
    let before = live_bytes();
    // `reserve_exact(1000)` on a one-element vector asks the allocator for exactly 1001 bytes.
    let ((), window) = measure_heap(|| buffer.reserve_exact(1000));
    assert_eq!(buffer.capacity(), 1001);
    assert_eq!(window.net_bytes, 901, "1001 live now, 100 before");
    assert_eq!(
        window.peak_above_start, 1001,
        "the new block counts before the old one stops counting, so a move is never understated: {window:?}"
    );
    assert_eq!(live_bytes() - before, 901);
}

#[test]
fn a_window_inside_a_window_leaves_the_outer_peak_intact() {
    let (kept, outer) = measure_heap(|| {
        let a = black_box(vec![0u8; 1000]);
        let ((), inner) = measure_heap(|| drop(black_box(vec![0u8; 500])));
        assert_eq!(inner.net_bytes, 0);
        assert_eq!(inner.peak_above_start, 500);
        a
    });
    assert_eq!(kept.len(), 1000);
    assert_eq!(outer.net_bytes, 1000);
    assert_eq!(
        outer.peak_above_start, 1500,
        "the outer window held its own 1000 and the inner 500 at once"
    );
}

#[test]
fn a_structure_that_keeps_what_it_is_given_grows_and_one_that_does_not_is_flat() {
    // The leak and its control, as the N02 test uses them: each round hands a 64-byte buffer to the structure.
    let mut kept: Vec<Vec<u8>> = Vec::with_capacity(256);
    let (_, leaking) = measure_heap(|| {
        for round in 0..=255u8 {
            kept.push(black_box(vec![round; 64]));
        }
    });
    assert_eq!(leaking.net_bytes, 256 * 64, "every buffer is still alive");

    let mut flat: Vec<Vec<u8>> = Vec::with_capacity(1);
    let (_, dropping) = measure_heap(|| {
        for round in 0..=255u8 {
            flat.clear();
            flat.push(black_box(vec![round; 64]));
        }
    });
    assert_eq!(dropping.net_bytes, 64, "only the last buffer is alive");
    assert_eq!(dropping.peak_above_start, 64);
    drop(kept);
    drop(flat);
}

#[test]
fn a_window_starts_its_own_high_water_mark_and_does_not_inherit_an_earlier_one() {
    let ((), first) = measure_heap(|| drop(black_box(vec![0u8; 4096])));
    assert_eq!(first.peak_above_start, 4096);
    let ((), second) = measure_heap(|| drop(black_box(vec![0u8; 100])));
    assert_eq!(second.net_bytes, 0);
    assert_eq!(
        second.peak_above_start, 100,
        "an earlier window's peak is not this window's: {second:?}"
    );
}

#[test]
fn an_outer_window_keeps_a_peak_it_reached_before_the_inner_window_opened() {
    let ((), outer) = measure_heap(|| {
        drop(black_box(vec![0u8; 2000]));
        let ((), inner) = measure_heap(|| drop(black_box(vec![0u8; 500])));
        assert_eq!(inner.peak_above_start, 500);
    });
    assert_eq!(outer.net_bytes, 0);
    assert_eq!(
        outer.peak_above_start, 2000,
        "the inner window must not lower what the outer one already saw: {outer:?}"
    );
}

#[test]
fn a_request_the_probe_refuses_holds_no_memory_and_the_next_request_still_counts() {
    let before = live_bytes();
    let ((refused, fired), window) = measure_heap(|| {
        fail_next_allocation(|| {
            let mut buffer: Vec<u8> = Vec::new();
            buffer.try_reserve_exact(4096).is_err()
        })
    });
    assert!(
        fired,
        "the injected failure never reached the allocator, so this proved nothing"
    );
    assert!(refused, "the reservation must report the refusal");
    assert_eq!(
        window.net_bytes, 0,
        "a request the allocator refused holds no memory: {window:?}"
    );
    assert_eq!(
        window.peak_above_start, 0,
        "and it never reaches the high-water mark: {window:?}"
    );
    assert_eq!(live_bytes(), before);

    // The failure is one-shot: the next request is an ordinary one and is counted.
    let (kept, window) = measure_heap(|| black_box(vec![0u8; 100]));
    assert_eq!(window.net_bytes, 100);
    assert_eq!(window.peak_above_start, 100);
    drop(kept);
    assert_eq!(live_bytes(), before);
}

#[test]
fn a_nested_window_that_unwinds_does_not_lose_a_peak_the_enclosing_window_already_reached() {
    let ((), outer) = measure_heap(|| {
        // The outer window's high water: a large block made and dropped before the nested window opens.
        drop(black_box(vec![0u8; EARLIER_BLOCK]));
        // A nested window that holds far less than that and then unwinds; the panic is caught inside the outer window.
        let unwound = catch_unwind(|| a_window_that_holds_a_block_and_then_unwinds(SMALL_BLOCK));
        assert!(
            unwound.is_err(),
            "the planted panic must reach catch_unwind, or this test proved nothing"
        );
    });
    // `>=`: the panic machinery may allocate a little more than the nested window's own block, never less than the earlier one.
    assert!(
        outer.peak_above_start >= EARLIER_BLOCK,
        "an unwound nested window must give back the peak it displaced: {outer:?}"
    );
}

#[test]
fn a_nested_window_that_unwinds_hands_its_own_peak_to_the_enclosing_window() {
    // The other half of the restoration: here the nested window holds the larger block, so the larger of the two peaks is
    // the nested one, and restoring only the enclosing figure would understate the outer window.
    let ((), outer) = measure_heap(|| {
        let unwound = catch_unwind(|| a_window_that_holds_a_block_and_then_unwinds(LATER_BLOCK));
        assert!(
            unwound.is_err(),
            "the planted panic must reach catch_unwind, or this test proved nothing"
        );
    });
    assert!(
        outer.peak_above_start >= LATER_BLOCK,
        "the outer window held the nested window's block too: {outer:?}"
    );
}

#[test]
fn the_same_nested_window_returning_normally_keeps_the_enclosing_peak_and_reports_its_own() {
    // The control for the two tests above, with the same sizes: the only difference is that the nested window returns.
    let ((), outer) = measure_heap(|| {
        drop(black_box(vec![0u8; EARLIER_BLOCK]));
        let ((), inner) = measure_heap(|| drop(black_box(vec![0u8; SMALL_BLOCK])));
        assert_eq!(inner.net_bytes, 0);
        assert_eq!(inner.peak_above_start, SMALL_BLOCK);
    });
    assert_eq!(outer.net_bytes, 0);
    assert_eq!(
        outer.peak_above_start, EARLIER_BLOCK,
        "the outer window kept the block it reached first: {outer:?}"
    );

    let ((), outer) = measure_heap(|| {
        let ((), inner) = measure_heap(|| drop(black_box(vec![0u8; LATER_BLOCK])));
        assert_eq!(inner.peak_above_start, LATER_BLOCK);
    });
    assert_eq!(
        outer.peak_above_start, LATER_BLOCK,
        "the outer window also saw the nested window's block: {outer:?}"
    );
}

#[test]
fn windows_measure_exactly_after_a_nested_window_has_unwound_and_been_caught() {
    let ((), outer) = measure_heap(|| {
        let unwound = catch_unwind(|| a_window_that_holds_a_block_and_then_unwinds(SMALL_BLOCK));
        assert!(
            unwound.is_err(),
            "the planted panic must reach catch_unwind, or this test proved nothing"
        );
        drop(unwound);
        // A window opened after the unwind starts from its own level and reports its own figures exactly.
        let ((), after) = measure_heap(|| drop(black_box(vec![0u8; AFTER_BLOCK])));
        assert_eq!(after.net_bytes, 0);
        assert_eq!(
            after.peak_above_start, AFTER_BLOCK,
            "a window after an unwind must not inherit the unwound window's peak: {after:?}"
        );
        // And the outer window keeps counting: a block made directly in it after the unwind still reaches its peak.
        drop(black_box(vec![0u8; LATER_BLOCK]));
    });
    assert!(
        outer.peak_above_start >= LATER_BLOCK,
        "the outer window kept measuring after the unwind: {outer:?}"
    );

    // A top-level window after all of that is exact.
    let (held, window) = measure_heap(|| black_box(vec![0u8; 4096]));
    assert_eq!(window.net_bytes, 4096);
    assert_eq!(window.peak_above_start, 4096);
    drop(held);
}
