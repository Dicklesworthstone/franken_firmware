//! Regression cases for the legacy compatibility helper; no provider/physical proof.
use franken_clock::{LatencyLedger, compute_cooperative_video_sync};

fn ledger() -> LatencyLedger {
    LatencyLedger {
        network_ingress_us: 1000,
        jitter_buffer_target_us: 0,
        dsp_block_period_us: 0,
        dma_queue_us: 0,
        calibrated_dac_delay_us: 0,
        calibration_uncertainty_us: 0,
    }
}

#[test]
fn legacy_normal_cooperative_sample_keeps_its_result() {
    let result = compute_cooperative_video_sync("synthetic-video", true, &ledger(), 900).unwrap();
    assert_eq!(result.measured_end_to_end_audio_latency_us, 1000);
    assert_eq!(result.commanded_video_delay_us, 1000);
    assert_eq!(result.residual_av_skew_us, 100);
    assert!(result.within_40ms_p99_gate);
}

#[test]
fn legacy_extreme_applied_delay_cannot_wrap_into_a_passing_residual() {
    assert!(compute_cooperative_video_sync("synthetic-video", true, &ledger(), u64::MAX).is_err());
}

#[test]
fn legacy_component_overflow_cannot_be_silently_saturated_into_a_match() {
    let mut input = ledger();
    input.network_ingress_us = u64::MAX;
    input.jitter_buffer_target_us = 1;
    assert!(compute_cooperative_video_sync("synthetic-video", true, &input, u64::MAX).is_err());
}

#[test]
fn legacy_gate_covers_calibration_uncertainty_instead_of_point_only() {
    let mut input = ledger();
    input.calibration_uncertainty_us = 40_000;
    let result = compute_cooperative_video_sync("synthetic-video", true, &input, 0).unwrap();
    assert!(!result.within_40ms_p99_gate);
    // Permitted boundary: worst-case residual is exactly 40ms.
    input.calibration_uncertainty_us = 39_000;
    let result = compute_cooperative_video_sync("synthetic-video", true, &input, 0).unwrap();
    assert!(result.within_40ms_p99_gate);
}
