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
    #[error(
        "clock offset of the exchange t1 ({t1_ns}), t2 ({t2_ns}), t3 ({t3_ns}), t4 ({t4_ns}) does not fit i64 nanoseconds"
    )]
    ExchangeOffsetNotRepresentable {
        t1_ns: i64,
        t2_ns: i64,
        t3_ns: i64,
        t4_ns: i64,
    },
    #[error(
        "presentation time {group_pts_ns} ns mapped with clock offset {offset_ns} ns is past the largest local u64 nanosecond time"
    )]
    LocalDeadlineNotRepresentable { group_pts_ns: u64, offset_ns: i64 },
}

/// Single 4-timestamp clock probe sample (`t1` member tx, `t2` coord rx, `t3` coord tx, `t4` member rx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockExchangeSample {
    pub seq: u64,
    pub offset_ns: i64,
    pub rtt_ns: u64,
}

impl ClockExchangeSample {
    /// Build a sample from one four-timestamp exchange.
    ///
    /// The differences and the offset sum are computed in `i128`, so no `i64` input can overflow them. The round
    /// trip is the whole span less the coordinator's dwell, saturating at zero when the dwell is the longer. The
    /// offset is `((t2 - t1) + (t3 - t4)) / 2`, truncated toward zero.
    ///
    /// # Errors
    /// [`ClockError::InvalidExchangeTimestamps`] when `t4 < t1` or `t3 < t2`, and
    /// [`ClockError::ExchangeOffsetNotRepresentable`] when the offset does not fit `i64`. The round trip always
    /// fits `u64`.
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
        let (t1, t2, t3, t4) = (
            i128::from(t1_member_tx_ns),
            i128::from(t2_coord_rx_ns),
            i128::from(t3_coord_tx_ns),
            i128::from(t4_member_rx_ns),
        );
        // Both differences are non-negative here, so the saturated round trip is in `0..=u64::MAX`.
        let rtt_ns = u64::try_from(((t4 - t1) - (t3 - t2)).max(0)).unwrap_or(u64::MAX);
        // Classic NTP offset: ((t2 - t1) + (t3 - t4)) / 2
        let offset_ns = i64::try_from(((t2 - t1) + (t3 - t4)) / 2).map_err(|_| {
            ClockError::ExchangeOffsetNotRepresentable {
                t1_ns: t1_member_tx_ns,
                t2_ns: t2_coord_rx_ns,
                t3_ns: t3_coord_tx_ns,
                t4_ns: t4_member_rx_ns,
            }
        })?;
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
            // Uncertainty bound is half the minimum RTT, in microseconds and rounded UP (a floor would report a
            // bound below the real half round trip), plus board calibration uncertainty added at the mapping.
            self.uncertainty_us = best.rtt_ns.div_ceil(2_000);
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
    ///
    /// A time before the local epoch maps to `0`. A time past `u64::MAX` is not a timestamp, and wrapping it
    /// would hand back an early deadline, so it is an error.
    ///
    /// # Errors
    /// [`ClockError::ClockUncertaintyTooHigh`] when the estimator is not locked within its gate, and
    /// [`ClockError::LocalDeadlineNotRepresentable`] when the mapped time exceeds `u64::MAX` nanoseconds.
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
        let local_pts = i128::from(group_pts_ns) - i128::from(self.estimated_offset_ns);
        let board_delay_ns = i128::from(board.calibrated_output_delay_us) * 1_000;
        u64::try_from((local_pts - board_delay_ns).max(0)).map_err(|_| {
            ClockError::LocalDeadlineNotRepresentable {
                group_pts_ns,
                offset_ns: self.estimated_offset_ns,
            }
        })
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

    // ---- checked arithmetic at the edges of the i64 / u64 range -------------------------------------------------------------
    //
    // Expected values are worked out by hand from the formulas in the doc comments, never read back from the code.

    fn s5() -> BoardProfile {
        canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
    }

    fn exchange(t1: i64, t2: i64, t3: i64, t4: i64) -> Result<ClockExchangeSample, ClockError> {
        ClockExchangeSample::from_four_timestamps(7, t1, t2, t3, t4)
    }

    /// A locked estimator whose clock offset is exactly `offset_ns` and whose round trip is zero:
    /// `t1 == t4 == 0` and `t2 == t3 == offset_ns` give that offset exactly.
    fn estimator_at_offset(offset_ns: i64) -> GroupClockEstimator {
        let mut est = GroupClockEstimator::new(8, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US);
        for seq in 1..=3 {
            est.ingest_sample(exchange_for(seq, offset_ns));
        }
        assert!(est.is_locked());
        assert_eq!(est.estimated_offset_ns(), offset_ns);
        est
    }

    fn exchange_for(seq: u64, offset_ns: i64) -> ClockExchangeSample {
        ClockExchangeSample::from_four_timestamps(seq, 0, offset_ns, offset_ns, 0).unwrap()
    }

    /// An estimator whose three samples all have round trip `rtt_ns`.
    fn estimator_with_rtt(rtt_ns: u64) -> GroupClockEstimator {
        let mut est = GroupClockEstimator::new(8, DEFAULT_MAX_ADMITTED_UNCERTAINTY_US);
        for seq in 1..=3 {
            est.ingest_sample(ClockExchangeSample {
                seq,
                offset_ns: 0,
                rtt_ns,
            });
        }
        est
    }

    #[test]
    fn an_exchange_spanning_the_whole_i64_range_is_measured_without_overflow() {
        // t4 - t1 is 2^64 - 1 ns: past i64, but a valid u64 round trip. The offset is (2^63 - (2^63 - 1)) / 2 = 0.
        let sample = exchange(i64::MIN, 0, 0, i64::MAX).unwrap();
        assert_eq!(
            (sample.seq, sample.offset_ns, sample.rtt_ns),
            (7, 0, u64::MAX)
        );
        // A coordinator dwell as wide as the whole span leaves no round trip, and the offset is 0.
        let sample = exchange(i64::MIN, i64::MIN, i64::MAX, i64::MAX).unwrap();
        assert_eq!((sample.offset_ns, sample.rtt_ns), (0, 0));
    }

    #[test]
    fn an_exchange_offset_outside_i64_is_a_typed_error_not_a_panic_or_a_wrapped_value() {
        for (t1, t2, t3, t4) in [
            (i64::MIN, i64::MAX, i64::MAX, i64::MIN), // offset 2^64 - 1
            (i64::MIN, 0, 0, i64::MIN),               // offset 2^63, one past i64::MAX
            (i64::MAX, i64::MIN, i64::MIN, i64::MAX), // offset -(2^64 - 1)
            (i64::MAX, -2, -2, i64::MAX),             // offset -2^63 - 1, one past i64::MIN
        ] {
            assert_eq!(
                exchange(t1, t2, t3, t4),
                Err(ClockError::ExchangeOffsetNotRepresentable {
                    t1_ns: t1,
                    t2_ns: t2,
                    t3_ns: t3,
                    t4_ns: t4,
                }),
                "{t1} {t2} {t3} {t4}"
            );
        }
    }

    #[test]
    fn the_widest_exchange_offsets_that_fit_i64_are_taken_exactly() {
        // (2^63 - 1) + (2^63 - 1) = 2^64 - 2, half of it is i64::MAX.
        let widest = exchange(i64::MIN, -1, -1, i64::MIN).unwrap();
        assert_eq!((widest.offset_ns, widest.rtt_ns), (i64::MAX, 0));
        // An odd sum, 2^64 - 1, truncates toward zero to the same i64::MAX; the dwell of 1 ns saturates the round trip.
        let truncated = exchange(i64::MIN, -1, 0, i64::MIN).unwrap();
        assert_eq!((truncated.offset_ns, truncated.rtt_ns), (i64::MAX, 0));
        // (-2^63) + (-2^63) = -2^64, half of it is i64::MIN.
        let lowest = exchange(i64::MAX, -1, -1, i64::MAX).unwrap();
        assert_eq!((lowest.offset_ns, lowest.rtt_ns), (i64::MIN, 0));
    }

    #[test]
    fn ordinary_exchanges_keep_ntp_truncation_the_rtt_saturation_and_the_order_check() {
        // ((0 - 3) + (0 - 4)) / 2 = -7 / 2 truncates toward zero to -3; round trip 4 - 3 less a dwell of 0 is 1.
        let sample = exchange(3, 0, 0, 4).unwrap();
        assert_eq!((sample.offset_ns, sample.rtt_ns), (-3, 1));
        // A dwell of 100 inside a span of 10 saturates the round trip at 0; the offset is (0 + 90) / 2 = 45.
        let sample = exchange(0, 0, 100, 10).unwrap();
        assert_eq!((sample.offset_ns, sample.rtt_ns), (45, 0));
        // Both orderings are still refused, with the four timestamps named.
        assert_eq!(
            exchange(10, 0, 0, 9),
            Err(ClockError::InvalidExchangeTimestamps {
                t1_ns: 10,
                t2_ns: 0,
                t3_ns: 0,
                t4_ns: 9,
            })
        );
        assert_eq!(
            exchange(0, 5, 4, 10),
            Err(ClockError::InvalidExchangeTimestamps {
                t1_ns: 0,
                t2_ns: 5,
                t3_ns: 4,
                t4_ns: 10,
            })
        );
    }

    #[test]
    fn a_local_deadline_past_u64_is_a_typed_error_not_a_wrapped_early_deadline() {
        let board = s5();
        // The S5 output delay is 1_850_000 ns, so offset -1_850_001 puts u64::MAX one nanosecond past u64::MAX.
        // Wrapping used to hand back 0 here, an immediate deadline.
        let est = estimator_at_offset(-1_850_001);
        assert_eq!(
            est.map_presentation_to_local_dac_ns(u64::MAX, &board),
            Err(ClockError::LocalDeadlineNotRepresentable {
                group_pts_ns: u64::MAX,
                offset_ns: -1_850_001,
            })
        );
        // A large negative offset used to wrap to a small, early deadline.
        let est = estimator_at_offset(-(1_i64 << 62));
        assert_eq!(
            est.map_presentation_to_local_dac_ns(u64::MAX, &board),
            Err(ClockError::LocalDeadlineNotRepresentable {
                group_pts_ns: u64::MAX,
                offset_ns: -(1_i64 << 62),
            })
        );
    }

    #[test]
    fn the_latest_representable_local_deadline_is_exact_and_before_zero_still_clamps() {
        let board = s5();
        // offset -1_850_000 cancels the delay exactly: the result is u64::MAX. One nanosecond less offset, one less result.
        let est = estimator_at_offset(-1_850_000);
        assert_eq!(
            est.map_presentation_to_local_dac_ns(u64::MAX, &board),
            Ok(u64::MAX)
        );
        let est = estimator_at_offset(-1_849_999);
        assert_eq!(
            est.map_presentation_to_local_dac_ns(u64::MAX, &board),
            Ok(u64::MAX - 1)
        );
        // Before the local epoch is still a deadline of zero: 100 - 5_000_000 - 1_850_000 is negative.
        let est = estimator_at_offset(5_000_000);
        assert_eq!(est.map_presentation_to_local_dac_ns(100, &board), Ok(0));
    }

    #[test]
    fn half_the_round_trip_is_rounded_up_so_the_uncertainty_bound_is_never_understated() {
        // 4_000_000 ns is exactly 2000 us of half round trip: at the gate, and admitted.
        let at_gate = estimator_with_rtt(4_000_000);
        assert_eq!(at_gate.uncertainty_us(), 2_000);
        assert!(at_gate.is_locked());
        // 4_000_001 ns is 2000.0005 us: a floor reports 2000 and admits it, a bound of 2001 does not.
        let over = estimator_with_rtt(4_000_001);
        assert_eq!(over.uncertainty_us(), 2_001);
        assert!(!over.is_locked());
        assert!(matches!(
            over.map_presentation_to_local_dac_ns(1_000_000_000, &s5()),
            Err(ClockError::ClockUncertaintyTooHigh { .. })
        ));
        // The ceiling cannot overflow at the largest round trip: ceil((2^64 - 1) / 2000) = 9_223_372_036_854_776.
        let widest = estimator_with_rtt(u64::MAX);
        assert_eq!(widest.uncertainty_us(), 9_223_372_036_854_776);
        assert!(!widest.is_locked());
        // An exact multiple is unchanged: a 1 ms round trip is 500 us, as the converging-estimator test shows.
        assert_eq!(estimator_with_rtt(1_000_000).uncertainty_us(), 500);
    }
}
