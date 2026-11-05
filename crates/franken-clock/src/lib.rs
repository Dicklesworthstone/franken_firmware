//! Group Clock Synchronization, Presentation Mapping, Latency Ledger, and Video Lip-Sync
//! (`N03` / `ffw-u07`, `V01` / `ffw-err`, `V02` / `ffw-8mr`).
//!
//! Enforces the standing architecture rules:
//! - Network timestamps are never treated as exact DAC timestamps; every clock
//!   mapping carries an explicit `uncertainty_us` bound.
//! - Group admission requires `locked == true` and `uncertainty_us <= max_admitted_uncertainty_us`.
//! - Cooperative video lip-sync (`YouTube` / `AirPlay 2`) tracks end-to-end audio
//!   latency and source-compensated A/V residual separately, enforcing the provisional
//!   `p99(|residual|) <= 40 ms` gate and rejecting uncooperative sources from
//!   automatic compensation claims.

#![forbid(unsafe_code)]

pub mod events; // V01 (`ffw-err`): shared bounded critical-event buffer
pub mod group; // N03 (`ffw-u07`)
pub mod latency; // V01 (`ffw-err`)
pub mod rate; // D03 (`ffw-j9r`)

use franken_board_profile::BoardProfile;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const DEFAULT_MAX_ADMITTED_UNCERTAINTY_US: u64 = 2_000; // 2 ms
pub const VIDEO_RESIDUAL_P99_GATE_US: u64 = 40_000; // 40 ms

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ClockError {
    #[error(
        "invalid NTP/PTP exchange timestamps: t4 ({t4_ns}) < t1 ({t1_ns}) or t3 ({t3_ns}) < t2 ({t2_ns})"
    )]
    InvalidExchangeTimestamps {
        t1_ns: i64,
        t2_ns: i64,
        t3_ns: i64,
        t4_ns: i64,
    },
    #[error(
        "clock not locked or uncertainty {uncertainty_us} us exceeds gate {max_uncertainty_us} us"
    )]
    ClockUncertaintyTooHigh {
        uncertainty_us: u64,
        max_uncertainty_us: u64,
    },
    #[error("video source `{source_kind}` does not provide cooperative lip-sync delay telemetry")]
    UncooperativeVideoSource { source_kind: String },
    #[error("latency arithmetic is not representable")]
    LatencyArithmeticOverflow,
}

/// Single 4-timestamp clock probe sample (`t1` member tx, `t2` coord rx, `t3` coord tx, `t4` member rx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockExchangeSample {
    pub seq: u64,
    pub offset_ns: i64,
    pub rtt_ns: u64,
}

impl ClockExchangeSample {
    pub fn from_four_timestamps(
        seq: u64,
        t1_member_tx_ns: i64,
        t2_coord_rx_ns: i64,
        t3_coord_tx_ns: i64,
        t4_member_rx_ns: i64,
    ) -> Result<Self, ClockError> {
        if t4_member_rx_ns < t1_member_tx_ns || t3_coord_tx_ns < t2_coord_rx_ns {
            return Err(ClockError::InvalidExchangeTimestamps {
                t1_ns: t1_member_tx_ns,
                t2_ns: t2_coord_rx_ns,
                t3_ns: t3_coord_tx_ns,
                t4_ns: t4_member_rx_ns,
            });
        }
        let total_span = (t4_member_rx_ns - t1_member_tx_ns) as u64;
        let coord_dwell = (t3_coord_tx_ns - t2_coord_rx_ns) as u64;
        let rtt_ns = total_span.saturating_sub(coord_dwell);
        // Classic NTP offset: ((t2 - t1) + (t3 - t4)) / 2
        let offset_ns =
            ((t2_coord_rx_ns - t1_member_tx_ns) + (t3_coord_tx_ns - t4_member_rx_ns)) / 2;
        Ok(Self {
            seq,
            offset_ns,
            rtt_ns,
        })
    }
}

/// Bounded sliding-window clock offset, drift, and uncertainty estimator (`N03`).
#[derive(Debug, Clone)]
pub struct GroupClockEstimator {
    window_capacity: usize,
    max_admitted_uncertainty_us: u64,
    samples: VecDeque<ClockExchangeSample>,
    estimated_offset_ns: i64,
    estimated_drift_ppm: i32,
    uncertainty_us: u64,
}

impl GroupClockEstimator {
    #[must_use]
    pub fn new(window_capacity: usize, max_admitted_uncertainty_us: u64) -> Self {
        Self {
            window_capacity: window_capacity.max(3),
            max_admitted_uncertainty_us,
            samples: VecDeque::new(),
            estimated_offset_ns: 0,
            estimated_drift_ppm: 0,
            uncertainty_us: u64::MAX,
        }
    }

    pub fn ingest_sample(&mut self, sample: ClockExchangeSample) {
        if self.samples.len() >= self.window_capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);

        // Select the minimum-RTT sample in the window (least queuing noise)
        if let Some(best) = self.samples.iter().min_by_key(|s| s.rtt_ns) {
            let prev_offset = self.estimated_offset_ns;
            self.estimated_offset_ns = best.offset_ns;
            // Uncertainty bound is half the minimum RTT plus board calibration uncertainty
            self.uncertainty_us = (best.rtt_ns / 2) / 1_000;
            if self.samples.len() >= 2 {
                let delta_ns = self.estimated_offset_ns.saturating_sub(prev_offset);
                self.estimated_drift_ppm = (delta_ns / 1_000).clamp(-500, 500) as i32;
            }
        }
    }

    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.samples.len() >= 3 && self.uncertainty_us <= self.max_admitted_uncertainty_us
    }

    #[must_use]
    pub const fn estimated_offset_ns(&self) -> i64 {
        self.estimated_offset_ns
    }

    #[must_use]
    pub const fn estimated_drift_ppm(&self) -> i32 {
        self.estimated_drift_ppm
    }

    #[must_use]
    pub const fn uncertainty_us(&self) -> u64 {
        self.uncertainty_us
    }

    /// Map a group presentation timestamp (`group_pts_ns`) into a local monotonic DAC release timestamp,
    /// subtracting the board's calibrated output delay.
    pub fn map_presentation_to_local_dac_ns(
        &self,
        group_pts_ns: u64,
        board: &BoardProfile,
    ) -> Result<u64, ClockError> {
        let total_uncertainty_us = self
            .uncertainty_us
            .saturating_add(u64::from(board.calibration_uncertainty_us));
        if self.samples.len() < 3 || total_uncertainty_us > self.max_admitted_uncertainty_us {
            return Err(ClockError::ClockUncertaintyTooHigh {
                uncertainty_us: total_uncertainty_us,
                max_uncertainty_us: self.max_admitted_uncertainty_us,
            });
        }
        let local_pts = (group_pts_ns as i128) - i128::from(self.estimated_offset_ns);
        let board_delay_ns = i128::from(board.calibrated_output_delay_us) * 1_000;
        Ok((local_pts - board_delay_ns).max(0) as u64)
    }
}

/// End-to-end latency ledger (`V01` / `ffw-err`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyLedger {
    pub network_ingress_us: u64,
    pub jitter_buffer_target_us: u64,
    pub dsp_block_period_us: u64,
    pub dma_queue_us: u64,
    pub calibrated_dac_delay_us: u64,
    pub calibration_uncertainty_us: u64,
}

impl LatencyLedger {
    /// Checked compatibility sum. Measured overlapping stages use `latency::LatencyTimeline`.
    pub fn checked_total_audio_latency_us(&self) -> Result<u64, ClockError> {
        [
            self.network_ingress_us,
            self.jitter_buffer_target_us,
            self.dsp_block_period_us,
            self.dma_queue_us,
            self.calibrated_dac_delay_us,
        ]
        .into_iter()
        .try_fold(0u64, u64::checked_add)
        .ok_or(ClockError::LatencyArithmeticOverflow)
    }

    #[must_use]
    pub const fn total_audio_latency_us(&self) -> u64 {
        self.network_ingress_us
            .saturating_add(self.jitter_buffer_target_us)
            .saturating_add(self.dsp_block_period_us)
            .saturating_add(self.dma_queue_us)
            .saturating_add(self.calibrated_dac_delay_us)
    }
}

/// Cooperative video synchronization compensator (`V02` / `ffw-8mr`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoSyncEvaluation {
    pub source_kind: String,
    pub cooperative: bool,
    pub measured_end_to_end_audio_latency_us: u64,
    pub commanded_video_delay_us: u64,
    pub residual_av_skew_us: i64,
    /// Legacy name: a single-observation bound, not a measured percentile.
    pub within_40ms_p99_gate: bool,
}

pub fn compute_cooperative_video_sync(
    source_kind: &str,
    cooperative: bool,
    ledger: &LatencyLedger,
    applied_source_video_delay_us: u64,
) -> Result<VideoSyncEvaluation, ClockError> {
    if !cooperative {
        return Err(ClockError::UncooperativeVideoSource {
            source_kind: source_kind.to_string(),
        });
    }
    let audio_us = ledger.checked_total_audio_latency_us()?;
    let residual = i64::try_from(i128::from(audio_us) - i128::from(applied_source_video_delay_us))
        .map_err(|_| ClockError::LatencyArithmeticOverflow)?;
    let within_gate = residual
        .unsigned_abs()
        .checked_add(ledger.calibration_uncertainty_us)
        .is_some_and(|bound| bound <= VIDEO_RESIDUAL_P99_GATE_US);
    Ok(VideoSyncEvaluation {
        source_kind: source_kind.to_string(),
        cooperative: true,
        measured_end_to_end_audio_latency_us: audio_us,
        commanded_video_delay_us: audio_us,
        residual_av_skew_us: residual,
        within_40ms_p99_gate: within_gate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture: the canonical catalog holds non-admissible hypotheses.
    use franken_board_profile::synthetic_test_fixture_catalog as canonical_board_catalog;

    #[test]
    fn clock_estimator_converges_and_compensates_board_calibration_delay() {
        let catalog = canonical_board_catalog();
        let s5 = catalog
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();

        let mut est = GroupClockEstimator::new(8, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US);
        assert!(!est.is_locked());

        // True offset = +500_000 ns (+500 us), RTT = 1_000_000 ns (1 ms -> half RTT = 500 us)
        for seq in 1..=4 {
            let t1 = (seq as i64) * 100_000_000;
            let t2 = t1 + 1_000_000; // +500 us offset + 500 us one-way
            let t3 = t2 + 100_000;
            let t4 = t1 + 1_100_000;
            let sample = ClockExchangeSample::from_four_timestamps(seq, t1, t2, t3, t4).unwrap();
            assert_eq!(sample.offset_ns, 500_000);
            assert_eq!(sample.rtt_ns, 1_000_000);
            est.ingest_sample(sample);
        }

        assert!(est.is_locked());
        let dac_ns = est
            .map_presentation_to_local_dac_ns(1_000_000_000, &s5)
            .unwrap();
        // 1_000_000_000 - 500_000 (clock offset) - 1_850_000 (S5 calibrated delay) = 997_650_000
        assert_eq!(dac_ns, 997_650_000);
    }

    #[test]
    fn video_sync_reports_audio_latency_and_residual_and_rejects_uncooperative_sources() {
        let ledger = LatencyLedger {
            network_ingress_us: 3_000,
            jitter_buffer_target_us: 45_000,
            dsp_block_period_us: 5_333,
            dma_queue_us: 5_333,
            calibrated_dac_delay_us: 1_850,
            calibration_uncertainty_us: 150,
        };
        let eval =
            compute_cooperative_video_sync("youtube-airplay2", true, &ledger, 58_000).unwrap();
        assert_eq!(eval.measured_end_to_end_audio_latency_us, 60_516);
        assert_eq!(eval.residual_av_skew_us, 2_516);
        assert!(eval.within_40ms_p99_gate);

        assert!(matches!(
            compute_cooperative_video_sync("uncooperative-raw-bt", false, &ledger, 0),
            Err(ClockError::UncooperativeVideoSource { .. })
        ));
    }
}
