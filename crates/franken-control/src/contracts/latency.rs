//! Typed latency contract (P01 / `ffw-h3g`, bead "Provisional qualification targets").
//!
//! A budget is a set of [`Duration`]s, and a breach is a [`LatencyViolation`] value, not a log line.
//! Three budgets cover the three shapes of limit the bead names:
//!
//! * [`LatencyBudget`] caps each stage of the existing [`LatencyLedger`] (network ingress, jitter
//!   buffer, DSP block, DMA queue, DAC calibration, calibration uncertainty) and the end-to-end
//!   total. It wraps the ledger; it does not replace it.
//! * [`DeadlineBudget`] is the render-submission deadline: a declared block period, with a share of it
//!   held back as execution reserve (the bead proposes 25%). Finishing after the period is a missed
//!   deadline; finishing inside the period but eating into the reserve is a separate violation.
//! * [`QuantileBudget`] caps the 99th percentile and the maximum of a set of measurements (group
//!   skew, for example) with the nearest-rank method. **No samples is an error, never a pass**: an
//!   absent measurement must not read as a satisfied budget.
//!
//! Every successful check returns a report that carries its [`BudgetBasis`]. The bead's thresholds are
//! proposals, not measurements, so a budget built as [`BudgetBasis::ProvisionalProposal`] yields
//! reports for which [`LatencyReport::is_measured_guarantee`] is false. Only a budget declared
//! [`BudgetBasis::MeasuredOnBoard`] can say otherwise. This module invents no per-stage numbers: those
//! come from the caller, who owns the evidence for them.

use core::fmt;
use core::time::Duration;

use franken_clock::LatencyLedger;

/// The bead's provisional share of the render period held back as execution reserve, in percent.
pub const PROVISIONAL_RESERVE_PERCENT: u8 = 25;

/// Where a budget's numbers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetBasis {
    /// A proposed engineering threshold, not a measurement and not an owner guarantee.
    ProvisionalProposal,
    /// A threshold set from measurements on the board it describes.
    MeasuredOnBoard,
}

/// The stages of the latency ledger, plus the end-to-end total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LatencyStage {
    NetworkIngress,
    JitterBuffer,
    DspBlock,
    DmaQueue,
    DacCalibration,
    CalibrationUncertainty,
    EndToEnd,
}

impl LatencyStage {
    /// Every stage, in the fixed order violations are reported.
    pub const ALL: [Self; 7] = [
        Self::NetworkIngress,
        Self::JitterBuffer,
        Self::DspBlock,
        Self::DmaQueue,
        Self::DacCalibration,
        Self::CalibrationUncertainty,
        Self::EndToEnd,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NetworkIngress => "network ingress",
            Self::JitterBuffer => "jitter buffer",
            Self::DspBlock => "DSP block",
            Self::DmaQueue => "DMA queue",
            Self::DacCalibration => "DAC calibration",
            Self::CalibrationUncertainty => "calibration uncertainty",
            Self::EndToEnd => "end-to-end",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::NetworkIngress => 0,
            Self::JitterBuffer => 1,
            Self::DspBlock => 2,
            Self::DmaQueue => 3,
            Self::DacCalibration => 4,
            Self::CalibrationUncertainty => 5,
            Self::EndToEnd => 6,
        }
    }

    /// What the ledger records for this stage. The end-to-end total is the ledger's own
    /// `total_audio_latency_us`, which by its definition leaves out the calibration uncertainty.
    #[must_use]
    pub fn observed(self, ledger: &LatencyLedger) -> Duration {
        let micros = match self {
            Self::NetworkIngress => ledger.network_ingress_us,
            Self::JitterBuffer => ledger.jitter_buffer_target_us,
            Self::DspBlock => ledger.dsp_block_period_us,
            Self::DmaQueue => ledger.dma_queue_us,
            Self::DacCalibration => ledger.calibrated_dac_delay_us,
            Self::CalibrationUncertainty => ledger.calibration_uncertainty_us,
            Self::EndToEnd => ledger.total_audio_latency_us(),
        };
        Duration::from_micros(micros)
    }
}

impl fmt::Display for LatencyStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Which statistic of a sample set a quantile budget limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantile {
    P99,
    Max,
}

impl fmt::Display for Quantile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P99 => "p99",
            Self::Max => "maximum",
        })
    }
}

/// A budget that cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LatencyConfigError {
    #[error("stage `{stage}` is given more than one limit")]
    DuplicateStage { stage: LatencyStage },
    #[error("stage `{stage}` has no limit")]
    MissingStage { stage: LatencyStage },
    #[error("the {what} limit is zero, which no measurement can satisfy meaningfully")]
    ZeroBudget { what: &'static str },
    #[error("an execution reserve of {percent}% leaves no time to run")]
    ReserveOutOfRange { percent: u8 },
    #[error("the p99 limit {p99:?} is above the maximum limit {max:?}")]
    QuantileOrder { p99: Duration, max: Duration },
}

/// A measured value over its budget. Typed so a caller can match on which limit broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LatencyViolation {
    #[error("{stage} latency {observed:?} is over its budget of {budget:?}")]
    StageOverBudget {
        stage: LatencyStage,
        observed: Duration,
        budget: Duration,
    },
    #[error("a render submission took {observed:?}, past the {period:?} device deadline")]
    DeadlineMissed {
        observed: Duration,
        period: Duration,
    },
    #[error(
        "a render submission took {observed:?}, over the {allowed:?} allowed once the execution reserve of the {period:?} period is kept"
    )]
    ReserveBreached {
        observed: Duration,
        allowed: Duration,
        period: Duration,
    },
    #[error("{quantile} latency {observed:?} is over its budget of {budget:?}")]
    QuantileOverBudget {
        quantile: Quantile,
        observed: Duration,
        budget: Duration,
    },
    #[error("no latency samples: the absence of a measurement is not a pass")]
    NoSamples,
}

/// A satisfied check, with what it was checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyReport {
    pub basis: BudgetBasis,
    pub observed: Duration,
    pub limit: Duration,
}

impl LatencyReport {
    /// How much room was left under the limit.
    #[must_use]
    pub fn headroom(&self) -> Duration {
        self.limit.saturating_sub(self.observed)
    }

    /// True only if the budget behind this report was set from measurements on the board.
    #[must_use]
    pub const fn is_measured_guarantee(&self) -> bool {
        matches!(self.basis, BudgetBasis::MeasuredOnBoard)
    }
}

/// A satisfied quantile check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantileReport {
    pub basis: BudgetBasis,
    pub samples: usize,
    pub p99: Duration,
    pub max: Duration,
}

impl QuantileReport {
    #[must_use]
    pub const fn is_measured_guarantee(&self) -> bool {
        matches!(self.basis, BudgetBasis::MeasuredOnBoard)
    }
}

/// Per-stage and end-to-end limits for a [`LatencyLedger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyBudget {
    basis: BudgetBasis,
    limits: [Duration; 7],
}

impl LatencyBudget {
    /// Build a budget from one limit per stage. Every stage must appear exactly once and no limit may
    /// be zero.
    pub fn from_limits(
        basis: BudgetBasis,
        limits: &[(LatencyStage, Duration)],
    ) -> Result<Self, LatencyConfigError> {
        let mut slots: [Option<Duration>; 7] = [None; 7];
        for &(stage, limit) in limits {
            if limit.is_zero() {
                return Err(LatencyConfigError::ZeroBudget {
                    what: stage.label(),
                });
            }
            let slot = &mut slots[stage.index()];
            if slot.is_some() {
                return Err(LatencyConfigError::DuplicateStage { stage });
            }
            *slot = Some(limit);
        }
        let mut resolved = [Duration::ZERO; 7];
        for stage in LatencyStage::ALL {
            match slots[stage.index()] {
                Some(limit) => resolved[stage.index()] = limit,
                None => return Err(LatencyConfigError::MissingStage { stage }),
            }
        }
        Ok(Self {
            basis,
            limits: resolved,
        })
    }

    #[must_use]
    pub const fn basis(&self) -> BudgetBasis {
        self.basis
    }

    #[must_use]
    pub const fn limit(&self, stage: LatencyStage) -> Duration {
        self.limits[stage.index()]
    }

    /// Every stage over its limit, in [`LatencyStage::ALL`] order. A value equal to its limit is
    /// within budget.
    #[must_use]
    pub fn violations(&self, ledger: &LatencyLedger) -> Vec<LatencyViolation> {
        LatencyStage::ALL
            .iter()
            .filter_map(|&stage| {
                let observed = stage.observed(ledger);
                let budget = self.limit(stage);
                (observed > budget).then_some(LatencyViolation::StageOverBudget {
                    stage,
                    observed,
                    budget,
                })
            })
            .collect()
    }

    /// Check a ledger. The first violation in stage order is the error; the report is for the
    /// end-to-end total.
    pub fn check(&self, ledger: &LatencyLedger) -> Result<LatencyReport, LatencyViolation> {
        if let Some(first) = self.violations(ledger).into_iter().next() {
            return Err(first);
        }
        Ok(LatencyReport {
            basis: self.basis,
            observed: LatencyStage::EndToEnd.observed(ledger),
            limit: self.limit(LatencyStage::EndToEnd),
        })
    }
}

/// The render-submission deadline and the execution reserve kept inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineBudget {
    basis: BudgetBasis,
    period: Duration,
    reserve_percent: u8,
}

impl DeadlineBudget {
    /// `period` is the declared render block period; `reserve_percent` (0 to 99) is the share of it
    /// held back.
    pub fn new(
        basis: BudgetBasis,
        period: Duration,
        reserve_percent: u8,
    ) -> Result<Self, LatencyConfigError> {
        if period.is_zero() {
            return Err(LatencyConfigError::ZeroBudget {
                what: "render period",
            });
        }
        if reserve_percent > 99 {
            return Err(LatencyConfigError::ReserveOutOfRange {
                percent: reserve_percent,
            });
        }
        Ok(Self {
            basis,
            period,
            reserve_percent,
        })
    }

    /// The execution time allowed once the reserve is kept: `period * (100 - reserve) / 100`,
    /// truncated to the nanosecond.
    #[must_use]
    pub fn allowed_execution(&self) -> Duration {
        let keep = u128::from(100 - self.reserve_percent);
        let nanos = self.period.as_nanos() * keep / 100;
        let secs = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
        let sub = u32::try_from(nanos % 1_000_000_000).unwrap_or(0);
        Duration::new(secs, sub)
    }

    /// Check one submission's execution time. Reaching the period is a missed deadline.
    pub fn check_execution(&self, observed: Duration) -> Result<LatencyReport, LatencyViolation> {
        if observed >= self.period {
            return Err(LatencyViolation::DeadlineMissed {
                observed,
                period: self.period,
            });
        }
        let allowed = self.allowed_execution();
        if observed > allowed {
            return Err(LatencyViolation::ReserveBreached {
                observed,
                allowed,
                period: self.period,
            });
        }
        Ok(LatencyReport {
            basis: self.basis,
            observed,
            limit: allowed,
        })
    }
}

/// The 1-based nearest-rank position of the 99th percentile among `n` samples: `ceil(0.99 * n)`.
/// For fewer than 100 samples this is `n`, so the p99 equals the maximum.
#[must_use]
pub fn p99_rank(n: usize) -> usize {
    let scaled = (n as u128) * 99;
    usize::try_from(scaled.div_ceil(100)).unwrap_or(usize::MAX)
}

/// Limits on the 99th percentile and the maximum of a sample set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuantileBudget {
    basis: BudgetBasis,
    p99: Duration,
    max: Duration,
}

impl QuantileBudget {
    /// Both limits must be non-zero and the p99 limit may not exceed the maximum limit.
    pub fn new(
        basis: BudgetBasis,
        p99: Duration,
        max: Duration,
    ) -> Result<Self, LatencyConfigError> {
        if p99.is_zero() {
            return Err(LatencyConfigError::ZeroBudget { what: "p99" });
        }
        if max.is_zero() {
            return Err(LatencyConfigError::ZeroBudget { what: "maximum" });
        }
        if p99 > max {
            return Err(LatencyConfigError::QuantileOrder { p99, max });
        }
        Ok(Self { basis, p99, max })
    }

    /// The bead's proposed group-synchronization limits (p99 of 2 ms, maximum of 5 ms after lock).
    /// A proposal, not a measurement.
    #[must_use]
    pub const fn provisional_group_skew() -> Self {
        Self {
            basis: BudgetBasis::ProvisionalProposal,
            p99: Duration::from_millis(2),
            max: Duration::from_millis(5),
        }
    }

    /// Check a set of measurements. An empty set is [`LatencyViolation::NoSamples`].
    pub fn check_samples(&self, samples: &[Duration]) -> Result<QuantileReport, LatencyViolation> {
        if samples.is_empty() {
            return Err(LatencyViolation::NoSamples);
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let n = sorted.len();
        let p99 = sorted[p99_rank(n).clamp(1, n) - 1];
        let max = sorted[n - 1];
        if p99 > self.p99 {
            return Err(LatencyViolation::QuantileOverBudget {
                quantile: Quantile::P99,
                observed: p99,
                budget: self.p99,
            });
        }
        if max > self.max {
            return Err(LatencyViolation::QuantileOverBudget {
                quantile: Quantile::Max,
                observed: max,
                budget: self.max,
            });
        }
        Ok(QuantileReport {
            basis: self.basis,
            samples: n,
            p99,
            max,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ledger used by `franken-clock`'s own video-sync test: 3 000 + 45 000 + 5 333 + 5 333 +
    /// 1 850 = 60 516 us end to end, with 150 us calibration uncertainty beside it.
    fn ledger() -> LatencyLedger {
        LatencyLedger {
            network_ingress_us: 3_000,
            jitter_buffer_target_us: 45_000,
            dsp_block_period_us: 5_333,
            dma_queue_us: 5_333,
            calibrated_dac_delay_us: 1_850,
            calibration_uncertainty_us: 150,
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Test-only numbers. They are not the product's budget; the bead gives none for the stages.
    fn limits() -> Vec<(LatencyStage, Duration)> {
        vec![
            (LatencyStage::NetworkIngress, ms(5)),
            (LatencyStage::JitterBuffer, ms(50)),
            (LatencyStage::DspBlock, ms(6)),
            (LatencyStage::DmaQueue, ms(6)),
            (LatencyStage::DacCalibration, ms(2)),
            (LatencyStage::CalibrationUncertainty, ms(1)),
            (LatencyStage::EndToEnd, ms(70)),
        ]
    }

    fn budget() -> LatencyBudget {
        LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &limits()).unwrap()
    }

    fn with_limit(stage: LatencyStage, limit: Duration) -> LatencyBudget {
        let edited: Vec<_> = limits()
            .into_iter()
            .map(|(s, l)| if s == stage { (s, limit) } else { (s, l) })
            .collect();
        LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &edited).unwrap()
    }

    #[test]
    fn stage_observations_come_from_the_ledger_and_the_total_is_the_ledgers_own() {
        let l = ledger();
        let observed: Vec<u64> = LatencyStage::ALL
            .iter()
            .map(|s| u64::try_from(s.observed(&l).as_micros()).unwrap())
            .collect();
        assert_eq!(
            observed,
            vec![3_000, 45_000, 5_333, 5_333, 1_850, 150, 60_516]
        );
    }

    #[test]
    fn a_ledger_within_every_limit_passes_and_reports_end_to_end_headroom() {
        let report = budget().check(&ledger()).unwrap();
        assert_eq!(report.observed, Duration::from_micros(60_516));
        assert_eq!(report.limit, ms(70));
        assert_eq!(report.headroom(), Duration::from_micros(9_484));
        assert!(budget().violations(&ledger()).is_empty());
    }

    #[test]
    fn a_value_equal_to_its_limit_is_within_budget_and_one_microsecond_over_is_not() {
        let exact = with_limit(LatencyStage::DmaQueue, Duration::from_micros(5_333));
        assert!(exact.check(&ledger()).is_ok());
        let tight = with_limit(LatencyStage::DmaQueue, Duration::from_micros(5_332));
        assert_eq!(
            tight.check(&ledger()).unwrap_err(),
            LatencyViolation::StageOverBudget {
                stage: LatencyStage::DmaQueue,
                observed: Duration::from_micros(5_333),
                budget: Duration::from_micros(5_332),
            }
        );
    }

    #[test]
    fn each_stage_can_be_the_one_that_breaks() {
        for stage in LatencyStage::ALL {
            let observed = stage.observed(&ledger());
            let one_under = observed - Duration::from_micros(1);
            let breached = with_limit(stage, one_under);
            let err = breached.check(&ledger()).unwrap_err();
            assert_eq!(
                err,
                LatencyViolation::StageOverBudget {
                    stage,
                    observed,
                    budget: one_under,
                },
                "{stage}"
            );
        }
    }

    #[test]
    fn the_end_to_end_limit_can_break_while_every_stage_is_within_its_own() {
        // 60.516 ms total against a 60 ms end-to-end limit; each stage is inside its limit.
        let tight = with_limit(LatencyStage::EndToEnd, ms(60));
        let all = tight.violations(&ledger());
        assert_eq!(
            all,
            vec![LatencyViolation::StageOverBudget {
                stage: LatencyStage::EndToEnd,
                observed: Duration::from_micros(60_516),
                budget: ms(60),
            }]
        );
    }

    #[test]
    fn violations_lists_every_breach_in_stage_order_and_check_returns_the_first() {
        // Ingress 12 ms (limit 5) and DSP 7 ms (limit 6); the total is 12 000 + 45 000 + 7 000 +
        // 5 333 + 1 850 = 71 183 us, over the 70 ms end-to-end limit as well.
        let l = LatencyLedger {
            network_ingress_us: 12_000,
            dsp_block_period_us: 7_000,
            ..ledger()
        };
        let all = budget().violations(&l);
        let stages: Vec<LatencyStage> = all
            .iter()
            .map(|v| match v {
                LatencyViolation::StageOverBudget { stage, .. } => *stage,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            stages,
            vec![
                LatencyStage::NetworkIngress,
                LatencyStage::DspBlock,
                LatencyStage::EndToEnd
            ]
        );
        assert_eq!(budget().check(&l).unwrap_err(), all[0]);
    }

    #[test]
    fn a_violation_is_a_typed_value_with_a_readable_message() {
        let err = LatencyViolation::StageOverBudget {
            stage: LatencyStage::JitterBuffer,
            observed: ms(60),
            budget: ms(50),
        };
        assert_eq!(
            err.to_string(),
            "jitter buffer latency 60ms is over its budget of 50ms"
        );
    }

    #[test]
    fn a_budget_needs_every_stage_once_and_no_zero_limit() {
        let missing: Vec<_> = limits().into_iter().take(6).collect();
        assert_eq!(
            LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &missing).unwrap_err(),
            LatencyConfigError::MissingStage {
                stage: LatencyStage::EndToEnd
            }
        );
        let mut twice = limits();
        twice.push((LatencyStage::DspBlock, ms(7)));
        assert_eq!(
            LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &twice).unwrap_err(),
            LatencyConfigError::DuplicateStage {
                stage: LatencyStage::DspBlock
            }
        );
        let zero: Vec<_> = limits()
            .into_iter()
            .map(|(s, l)| {
                if s == LatencyStage::DmaQueue {
                    (s, Duration::ZERO)
                } else {
                    (s, l)
                }
            })
            .collect();
        assert_eq!(
            LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &zero).unwrap_err(),
            LatencyConfigError::ZeroBudget { what: "DMA queue" }
        );
        assert_eq!(
            LatencyBudget::from_limits(BudgetBasis::ProvisionalProposal, &[]).unwrap_err(),
            LatencyConfigError::MissingStage {
                stage: LatencyStage::NetworkIngress
            }
        );
    }

    #[test]
    fn a_provisional_budget_never_reports_a_measured_guarantee() {
        let provisional = budget().check(&ledger()).unwrap();
        assert_eq!(provisional.basis, BudgetBasis::ProvisionalProposal);
        assert!(!provisional.is_measured_guarantee());

        let measured = LatencyBudget::from_limits(BudgetBasis::MeasuredOnBoard, &limits()).unwrap();
        let report = measured.check(&ledger()).unwrap();
        assert!(report.is_measured_guarantee());
        assert_eq!(measured.basis(), BudgetBasis::MeasuredOnBoard);
    }

    // ----- deadline

    fn render() -> DeadlineBudget {
        // 5.333 ms period (256 frames at 48 kHz), with the bead's provisional 25% reserve.
        DeadlineBudget::new(
            BudgetBasis::ProvisionalProposal,
            Duration::from_nanos(5_333_000),
            PROVISIONAL_RESERVE_PERCENT,
        )
        .unwrap()
    }

    #[test]
    fn the_execution_allowance_is_the_period_less_the_reserve() {
        // 5_333_000 ns * 75 / 100 = 3_999_750 ns.
        assert_eq!(
            render().allowed_execution(),
            Duration::from_nanos(3_999_750)
        );
        let none_held = DeadlineBudget::new(
            BudgetBasis::ProvisionalProposal,
            Duration::from_millis(10),
            0,
        )
        .unwrap();
        assert_eq!(none_held.allowed_execution(), Duration::from_millis(10));
        let nearly_all = DeadlineBudget::new(
            BudgetBasis::ProvisionalProposal,
            Duration::from_millis(10),
            99,
        )
        .unwrap();
        assert_eq!(nearly_all.allowed_execution(), Duration::from_micros(100));
        // A period longer than a second keeps its whole seconds.
        let long = DeadlineBudget::new(
            BudgetBasis::ProvisionalProposal,
            Duration::from_millis(2_500),
            50,
        )
        .unwrap();
        assert_eq!(long.allowed_execution(), Duration::from_millis(1_250));
    }

    #[test]
    fn execution_inside_the_allowance_passes_with_headroom() {
        let report = render()
            .check_execution(Duration::from_nanos(3_000_000))
            .unwrap();
        assert_eq!(report.observed, Duration::from_nanos(3_000_000));
        assert_eq!(report.limit, Duration::from_nanos(3_999_750));
        assert_eq!(report.headroom(), Duration::from_nanos(999_750));
        assert!(!report.is_measured_guarantee());
        // The allowance itself is within budget.
        assert!(
            render()
                .check_execution(Duration::from_nanos(3_999_750))
                .is_ok()
        );
    }

    #[test]
    fn eating_into_the_reserve_and_missing_the_deadline_are_different_violations() {
        let period = Duration::from_nanos(5_333_000);
        let allowed = Duration::from_nanos(3_999_750);

        let one_over = Duration::from_nanos(3_999_751);
        assert_eq!(
            render().check_execution(one_over).unwrap_err(),
            LatencyViolation::ReserveBreached {
                observed: one_over,
                allowed,
                period
            }
        );
        // Just under the period is still the reserve, not a missed deadline.
        let late = Duration::from_nanos(5_332_999);
        assert!(matches!(
            render().check_execution(late).unwrap_err(),
            LatencyViolation::ReserveBreached { .. }
        ));
        // Reaching the period is a miss, and so is going past it.
        for observed in [
            period,
            period + Duration::from_nanos(1),
            Duration::from_secs(1),
        ] {
            assert_eq!(
                render().check_execution(observed).unwrap_err(),
                LatencyViolation::DeadlineMissed { observed, period }
            );
        }
    }

    #[test]
    fn a_deadline_budget_refuses_a_zero_period_and_a_reserve_that_leaves_nothing() {
        assert_eq!(
            DeadlineBudget::new(BudgetBasis::ProvisionalProposal, Duration::ZERO, 25).unwrap_err(),
            LatencyConfigError::ZeroBudget {
                what: "render period"
            }
        );
        for percent in [100, 150, u8::MAX] {
            assert_eq!(
                DeadlineBudget::new(BudgetBasis::ProvisionalProposal, ms(5), percent).unwrap_err(),
                LatencyConfigError::ReserveOutOfRange { percent }
            );
        }
        assert!(DeadlineBudget::new(BudgetBasis::ProvisionalProposal, ms(5), 99).is_ok());
    }

    // ----- quantiles

    #[test]
    fn the_p99_rank_follows_nearest_rank_and_equals_the_maximum_below_a_hundred_samples() {
        // Written by hand from ceil(0.99 * n).
        let table = [
            (1, 1),
            (2, 2),
            (10, 10),
            (50, 50),
            (99, 99),
            (100, 99),
            (101, 100),
            (200, 198),
            (1000, 990),
            (1001, 991),
        ];
        for (n, rank) in table {
            assert_eq!(p99_rank(n), rank, "n = {n}");
        }
    }

    /// 98 samples of 1 ms, one of 2 ms, one of `top`: the p99 is the 99th smallest, the 2 ms one.
    fn hundred(top: Duration) -> Vec<Duration> {
        let mut v = vec![ms(1); 98];
        v.push(ms(2));
        v.push(top);
        v
    }

    #[test]
    fn samples_within_both_limits_pass_and_the_report_says_what_was_seen() {
        let report = QuantileBudget::provisional_group_skew()
            .check_samples(&hundred(ms(4)))
            .unwrap();
        assert_eq!(report.samples, 100);
        assert_eq!(report.p99, ms(2));
        assert_eq!(report.max, ms(4));
        assert!(!report.is_measured_guarantee());
        // The limits themselves are within budget.
        assert!(
            QuantileBudget::provisional_group_skew()
                .check_samples(&hundred(ms(5)))
                .is_ok()
        );
    }

    #[test]
    fn a_p99_over_its_limit_fails_even_when_the_maximum_is_within_its_own() {
        // Two 3 ms samples among 100: the 99th smallest is 3 ms (over 2 ms), the maximum is 3 ms (< 5 ms).
        let mut v = vec![ms(1); 98];
        v.extend([ms(3), ms(3)]);
        assert_eq!(
            QuantileBudget::provisional_group_skew()
                .check_samples(&v)
                .unwrap_err(),
            LatencyViolation::QuantileOverBudget {
                quantile: Quantile::P99,
                observed: ms(3),
                budget: ms(2)
            }
        );
    }

    #[test]
    fn a_single_outlier_breaks_the_maximum_but_not_the_p99() {
        let mut v = vec![ms(1); 99];
        v.push(ms(6));
        assert_eq!(
            QuantileBudget::provisional_group_skew()
                .check_samples(&v)
                .unwrap_err(),
            LatencyViolation::QuantileOverBudget {
                quantile: Quantile::Max,
                observed: ms(6),
                budget: ms(5)
            }
        );
    }

    #[test]
    fn no_samples_is_a_violation_never_a_pass() {
        assert_eq!(
            QuantileBudget::provisional_group_skew()
                .check_samples(&[])
                .unwrap_err(),
            LatencyViolation::NoSamples
        );
    }

    #[test]
    fn with_few_samples_the_p99_is_the_maximum_so_one_bad_sample_fails_both_ways() {
        let budget = QuantileBudget::provisional_group_skew();
        let err = budget.check_samples(&[ms(1), ms(9)]).unwrap_err();
        assert_eq!(
            err,
            LatencyViolation::QuantileOverBudget {
                quantile: Quantile::P99,
                observed: ms(9),
                budget: ms(2)
            }
        );
        assert!(budget.check_samples(&[ms(1)]).is_ok());
    }

    #[test]
    fn sample_order_does_not_matter() {
        let mut v = hundred(ms(4));
        let forward = QuantileBudget::provisional_group_skew().check_samples(&v);
        v.reverse();
        assert_eq!(
            forward,
            QuantileBudget::provisional_group_skew().check_samples(&v)
        );
    }

    #[test]
    fn a_quantile_budget_refuses_zero_limits_and_a_p99_above_the_maximum() {
        let basis = BudgetBasis::MeasuredOnBoard;
        assert_eq!(
            QuantileBudget::new(basis, Duration::ZERO, ms(5)).unwrap_err(),
            LatencyConfigError::ZeroBudget { what: "p99" }
        );
        assert_eq!(
            QuantileBudget::new(basis, ms(2), Duration::ZERO).unwrap_err(),
            LatencyConfigError::ZeroBudget { what: "maximum" }
        );
        assert_eq!(
            QuantileBudget::new(basis, ms(6), ms(5)).unwrap_err(),
            LatencyConfigError::QuantileOrder {
                p99: ms(6),
                max: ms(5)
            }
        );
        let equal = QuantileBudget::new(basis, ms(5), ms(5)).unwrap();
        assert!(
            equal
                .check_samples(&[ms(5)])
                .unwrap()
                .is_measured_guarantee()
        );
    }
}
