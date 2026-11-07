//! Test-only counting global allocator (`D01` / `ffw-f3b`).
//!
//! Install [`CountingAllocator`] as the `#[global_allocator]` of a **test binary**, run the
//! code under test inside [`measure`], and assert the allocation delta is zero. This is how the
//! workspace proves a render path does not allocate.
//!
//! # Safety policy (the one `unsafe` in the workspace)
//!
//! `GlobalAlloc` is an `unsafe` trait, so this crate cannot inherit the workspace's
//! `unsafe_code = "forbid"`. Instead:
//!
//! * the crate lint level is `deny` (see `Cargo.toml`), and the only `allow` is the single
//!   `unsafe impl GlobalAlloc` below;
//! * calls normally forward their arguments **unchanged** to [`std::alloc::System`]. An explicitly
//!   armed, calling-thread-only failure instead returns null once from `alloc`, `alloc_zeroed` or
//!   `realloc`, as allowed by `GlobalAlloc`. A failed `realloc` leaves the original allocation
//!   owned by the caller; `dealloc` always forwards. The caller's obligations remain unchanged;
//! * the extra work counts every allocator attempt (including injected failures) and manages the
//!   calling thread's one-shot failure flag. These thread-local `Cell` values are const-initialised
//!   and have no destructor, so touching them neither allocates nor registers a TLS destructor
//!   (which would recurse into the allocator), and `try_with` makes access during thread teardown
//!   a no-op rather than a panic;
//! * counters are **per thread**: [`measure`] sees only the calling thread's allocations.
//!
//! No firmware crate may depend on this crate (not even as a dev-dependency); it is a probe, not
//! a library. If the allocator is not installed in the running binary, every counter stays at
//! zero, which would make a "no allocation" assertion vacuous; [`is_active`] exists so tests can
//! assert the counter really counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::thread::LocalKey;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static BYTES_REQUESTED: Cell<usize> = const { Cell::new(0) };
    static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    static FAILURES: Cell<usize> = const { Cell::new(0) };
}

fn bump(counter: &'static LocalKey<Cell<usize>>, by: usize) {
    let _ = counter.try_with(|cell| cell.set(cell.get().wrapping_add(by)));
}

fn read(counter: &'static LocalKey<Cell<usize>>) -> usize {
    counter.try_with(Cell::get).unwrap_or(0)
}

/// True exactly once after [`fail_next_allocation`] armed the calling thread: the allocator call that sees it returns null (the
/// `GlobalAlloc` way to say "out of memory"). Other threads never see it, so unrelated allocations are not failed.
fn fail_now() -> bool {
    FAIL_NEXT
        .try_with(|armed| {
            let fire = armed.replace(false);
            if fire {
                bump(&FAILURES, 1);
            }
            fire
        })
        .unwrap_or(false)
}

/// A global allocator that counts every attempted call (per thread), including injected failures.
/// Normally it forwards to `System`; [`fail_next_allocation`] can instead return null once on the calling thread.
#[derive(Debug, Default)]
pub struct CountingAllocator;

impl CountingAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[allow(unsafe_code)]
// SAFETY: calls normally forward unchanged to `System`. The sole exception is an explicitly
// armed, calling-thread-only failure: returning null from alloc/alloc_zeroed/realloc is permitted
// by GlobalAlloc. A failed realloc does not touch or free the original allocation, and dealloc
// always forwards. Attempt counters and the one-shot flag use const-initialised, destructor-free
// thread-local Cells; this instrumentation cannot allocate or unwind.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(&ALLOCATIONS, 1);
        bump(&BYTES_REQUESTED, layout.size());
        if fail_now() {
            return std::ptr::null_mut();
        }
        // SAFETY: caller upholds `GlobalAlloc::alloc`'s contract; forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(&ALLOCATIONS, 1);
        bump(&BYTES_REQUESTED, layout.size());
        if fail_now() {
            return std::ptr::null_mut();
        }
        // SAFETY: caller upholds `GlobalAlloc::alloc_zeroed`'s contract; forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump(&DEALLOCATIONS, 1);
        // SAFETY: caller upholds `GlobalAlloc::dealloc`'s contract; forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(&REALLOCATIONS, 1);
        bump(&BYTES_REQUESTED, new_size);
        if fail_now() {
            return std::ptr::null_mut();
        }
        // SAFETY: caller upholds `GlobalAlloc::realloc`'s contract; forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Allocator activity on the calling thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocSnapshot {
    /// `alloc` and `alloc_zeroed` calls.
    pub allocations: usize,
    /// `realloc` calls (a growing `Vec` shows up here).
    pub reallocations: usize,
    /// `dealloc` calls (dropping a pre-existing buffer shows up here).
    pub deallocations: usize,
    /// Bytes requested by `alloc`, `alloc_zeroed` and `realloc`.
    pub bytes_requested: usize,
}

impl AllocSnapshot {
    /// True when no allocator call of any kind happened.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.allocations == 0 && self.reallocations == 0 && self.deallocations == 0
    }
}

/// Totals for the calling thread since it started.
#[must_use]
pub fn snapshot() -> AllocSnapshot {
    AllocSnapshot {
        allocations: read(&ALLOCATIONS),
        reallocations: read(&REALLOCATIONS),
        deallocations: read(&DEALLOCATIONS),
        bytes_requested: read(&BYTES_REQUESTED),
    }
}

/// Run `f` and return its result with the calling thread's allocator activity during `f`.
///
/// Allocations made by other threads (including threads `f` spawns) are not counted.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, AllocSnapshot) {
    let before = snapshot();
    let result = f();
    let after = snapshot();
    let delta = AllocSnapshot {
        allocations: after.allocations.wrapping_sub(before.allocations),
        reallocations: after.reallocations.wrapping_sub(before.reallocations),
        deallocations: after.deallocations.wrapping_sub(before.deallocations),
        bytes_requested: after.bytes_requested.wrapping_sub(before.bytes_requested),
    };
    (result, delta)
}

/// Run `f` with the calling thread's NEXT allocator call (`alloc`, `alloc_zeroed` or `realloc`) failing once: it returns null, which
/// `Vec::try_reserve_exact` and the other fallible reservations report as an error. Use it only around code that reserves fallibly (an
/// infallible allocation that fails aborts the process), with the first allocation `f` makes being the one under test. Returns `f`'s
/// result and whether a call really failed (false means `f` never allocated, so the test proved nothing). Other threads are untouched
/// and the failure is disarmed when `f` returns or unwinds. A failed call still counts as an allocator
/// attempt and contributes its requested bytes to [`snapshot`] and [`measure`]; it cannot appear as no allocator activity.
pub fn fail_next_allocation<R>(f: impl FnOnce() -> R) -> (R, bool) {
    struct Disarm;
    impl Drop for Disarm {
        fn drop(&mut self) {
            let _ = FAIL_NEXT.try_with(|armed| armed.set(false));
        }
    }
    let failures_before = read(&FAILURES);
    let _ = FAIL_NEXT.try_with(|armed| armed.set(true));
    let disarm = Disarm;
    let result = f();
    drop(disarm);
    (result, read(&FAILURES) != failures_before)
}

/// True when [`CountingAllocator`] is the running binary's global allocator (it counted a real
/// allocation made here). A "no allocation" assertion is meaningless unless this is true.
#[must_use]
pub fn is_active() -> bool {
    let (boxed, delta) = measure(|| std::hint::black_box(Box::new(0xA5u8)));
    drop(boxed);
    delta.allocations >= 1
}
