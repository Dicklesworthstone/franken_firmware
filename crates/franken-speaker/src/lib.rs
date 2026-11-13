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
pub mod media_playout;
pub mod net_carrier;
pub mod network_render;
pub mod output_fence;
pub mod platform_start;
pub mod render;
pub mod render_log;
pub mod services;
pub mod settled_http;
pub mod settled_render;
pub mod source_media;
pub mod source_runtime;

#[cfg(any(test, feature = "harness"))]
mod clock_log;

#[cfg(any(test, feature = "harness"))]
mod control_adapter;

// The bounded loopback transport for an actual `fsonos` client (G03, `docs/contracts/g03.md` section 11.1): one listener on 127.0.0.1,
// the real endpoint behind it. Harness and test builds only, like the control plane it drives.
#[cfg(any(test, feature = "harness"))]
pub mod fsonos_loopback;

// A regular-file `Storage` for the harness control plane, and the process-restart driver that runs the durable plane over it
// (`--control-restart`). Harness and test builds on unix only; neither is compiled into a device build.
#[cfg(all(unix, any(test, feature = "harness")))]
pub mod file_medium;

#[cfg(all(unix, feature = "harness"))]
pub mod control_restart;

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
