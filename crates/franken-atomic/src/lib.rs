//! Semantic 64-bit replacements for targets that have no native 64-bit atomics (`P05` / `ffw-ipz`).
//!
//! The big-endian MIPS32 and PowerPC32 device targets have 32-bit atomics at most, so `AtomicU64` and
//! `AtomicI64` do not exist there. This crate is what shared 64-bit state uses instead. It is
//! `#![forbid(unsafe_code)]`, depends on nothing but `std`, and contains no `AtomicU64`: every shared value
//! sits behind a `Mutex`.
//!
//! # What is guaranteed
//!
//! * **Whole values.** Every operation reads or writes all 64 bits under one lock. There is no pair of
//!   32-bit words that a reader can see half updated, and no `as u32` anywhere on a value path.
//! * **Linearizable per cell.** Each operation (`load`, `store`, `swap`, `compare_exchange`, the
//!   `fetch_*` family) takes effect at one instant between its call and its return, in an order all
//!   threads agree on. A thread that observes an effect also observes what the writer did before it.
//!   Different cells share no order: this is *not* `SeqCst` across cells, and nothing here claims it.
//! * **Typed range errors.** `fetch_add` / `fetch_sub` are checked and return [`ArithError`] without
//!   changing the cell. Wrapping exists only under an explicit `_wrapping` name. [`Sequence`] never reuses
//!   an identifier: at the end it returns [`Exhausted`].
//! * **Bounded critical section.** No caller code runs under the lock (no closure-taking `fetch_update`),
//!   nothing allocates after construction, and an operation cannot be cancelled half way. A panicking
//!   thread cannot corrupt a cell; a poisoned lock is recovered with the stored value intact.
//!
//! # What is not
//!
//! * **Not lock-free, not wait-free, not for a render deadline.** A thread preempted inside the critical
//!   section delays every other user of that cell. Render-path state is owner-local ([`LocalU64`]) or a
//!   native 32-bit atomic; a shared 64-bit value read on the render path is a design error this crate
//!   cannot fix.
//! * **Not async-signal-safe.** A signal handler that interrupts the lock holder and then takes the same
//!   lock would deadlock. Handlers use the `try_*` calls (which answer [`Contended`] at once) or a native
//!   32-bit atomic.
//! * **Not a promise about the host.** Host tests of this crate exercise the same `Mutex` code that a
//!   device build runs, because the implementation is not switched by target; they say nothing about a
//!   device kernel's futex support or scheduling.
//!
//! The map from every 64-bit atomic in the pinned Asupersync revision to one of these types, and the
//! reason for each choice, is `docs/contracts/p05.md`.

#![forbid(unsafe_code)]

mod counter;
mod error;
mod local;
mod shared;

pub use counter::Sequence;
pub use error::{ArithError, Contended, Exhausted};
pub use local::LocalU64;
pub use shared::{SharedI64, SharedU64};

/// Whether the compilation target has native 64-bit atomics. Informational: this crate's types do not
/// change with it, so a host test run is a run of the device code path.
pub const TARGET_HAS_NATIVE_ATOMIC_64: bool = cfg!(target_has_atomic = "64");

#[cfg(test)]
mod model;
#[cfg(test)]
mod planted;
#[cfg(test)]
mod tests;
