//! Runs asupersync's ORIGINAL `runtime_abort_vs_cancel_semantics_audit.rs`, and its `stream_cancellation` helper, unchanged.
//!
//! Both files below are the pinned bytes (build.rs refuses the build otherwise); nothing in them is edited, filtered, ignored or
//! reordered, and all of their `#[test]`s run (46 in the audit, 2 in the helper).
//!
//! There is exactly one interposition, and it is the macro below. In the asupersync package `env!("CARGO_MANIFEST_DIR")` is the
//! asupersync source root, and the audit's structural pins read `src/**` and `tests/*` beneath it. In this package asupersync is a
//! dependency, so that variable would name this harness and every such pin would fail. The macro answers that one question with
//! `ASUP_ROOT`, which build.rs sets only after proving the directory is the pinned asupersync tree. The immutable original files use only
//! this environment query; an unsupported new query fails compilation. A wrong or missing tree fails loudly; it cannot make a pin pass.
//!
//! The consequence for names: the tests live in `mod audit`, so libtest reports `audit::<name>` and
//! `audit::stream_cancellation::<name>` where the original lane reported `<name>` and `stream_cancellation::<name>`.

macro_rules! env {
    ("CARGO_MANIFEST_DIR") => {
        ::core::env!("ASUP_ROOT")
    };
}

#[path = "runtime_abort_vs_cancel_semantics_audit.rs"]
mod audit;
