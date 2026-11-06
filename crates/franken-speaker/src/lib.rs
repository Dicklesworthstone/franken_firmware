//! Speaker Composition Root and Readiness/Recovery UX state (`P01` / `ffw-h3g`, `UX01` / `ffw-389`).
//!
//! The Virtual House harness (`Q01` / `ffw-gmq`) lives in `harness.rs` and is compiled only with the
//! off-by-default `harness` feature (or for unit tests). A default build has no dependency edge onto
//! `franken-test-support`, which is what keeps test-only code out of a device image. The P01 workspace
//! contract (`virtual_house_harness`, `cargo_feature = "harness"`) records and checks that.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// User-observable readiness and recovery state (`UX01` / `ffw-389`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeakerReadinessState {
    BootstrappingMuted,
    VerifyingBoardAndClock,
    ReadySynchronized,
    DegradedStandaloneRecovery { reason: String },
    FaultedSafeMuted { reason: String },
}

pub mod button_adapter;
pub mod clock_view;
pub mod guest_evidence;
pub mod platform_start;
pub mod render;
pub mod render_log;
pub mod services;

#[cfg(any(test, feature = "harness"))]
mod clock_log;

#[cfg(any(test, feature = "harness"))]
mod control_adapter;

#[cfg(any(test, feature = "harness"))]
mod harness;

#[cfg(any(test, feature = "harness"))]
mod playout_adapter;

#[cfg(any(test, feature = "harness"))]
pub use harness::{
    FencingProbeStats, MemberSimulationStats, RefusedBy, StreamAgreement, StreamOutcome,
    StreamRefusal, VirtualHouseReport, VirtualSpeakerNode, run_virtual_house_campaign,
};

#[cfg(any(test, feature = "harness"))]
pub use clock_log::ClockLogSummary;

#[cfg(any(test, feature = "harness"))]
pub use control_adapter::VolumeReport;

#[cfg(any(test, feature = "harness"))]
pub use playout_adapter::PlayoutMemberReport;
