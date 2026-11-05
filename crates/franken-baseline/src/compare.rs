//! Comparative claims, and why most of them are refused.
//!
//! An absolute result needs nothing but the capture. A claim that one firmware drops out less than
//! another needs a baseline, and a baseline is only a baseline if it was measured on the device. The
//! type system carries that rule:
//!
//! * [`Baseline`] has a private field and one constructor, [`Baseline::new`], which refuses anything but
//!   a physical-device measurement with adequate coverage and a known dropout rate.
//! * [`compare`] takes `Option<&Baseline>`. With `None`, or with a current run that is not itself a
//!   physical measurement of the same profile, it returns a [`ClaimRefused`]; there is no value of
//!   [`Comparison`] to print.
//!
//! So a synthetic capture can be analyzed, qualified against its own declared thresholds, and compared
//! with nothing. It can never be dressed up as an incumbent baseline or as an improvement.

use crate::capture::Evidence;
use crate::json::Json;

/// A baseline must cover at least this fraction (parts per million) of its declared duration.
pub const MIN_BASELINE_COVERAGE_PPM: u64 = 900_000;

/// The figures of a series report that a comparison may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsoluteSummary {
    pub evidence: Evidence,
    pub profile: String,
    pub coverage_ppm: u64,
    /// Dropout intervals per hour times 1000, over the uncensored time; `None` if dropouts are unknown.
    pub dropout_per_hour_milli: Option<u128>,
    /// Dropout counts that fell in spans the capture could not locate. They make the rate a lower bound.
    pub censored_dropouts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineError {
    NotMeasuredOnDevice(Evidence),
    InsufficientCoverage { have_ppm: u64, need_ppm: u64 },
    DropoutsUnknown,
}

impl BaselineError {
    pub fn as_str(&self) -> &'static str {
        match self {
            BaselineError::NotMeasuredOnDevice(_) => "baseline_not_measured_on_device",
            BaselineError::InsufficientCoverage { .. } => "baseline_insufficient_coverage",
            BaselineError::DropoutsUnknown => "baseline_dropouts_unknown",
        }
    }
}

/// A measured incumbent baseline. Only [`Baseline::new`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    summary: AbsoluteSummary,
    rate_milli: u128,
}

impl Baseline {
    pub fn new(summary: AbsoluteSummary) -> Result<Baseline, BaselineError> {
        if summary.evidence != Evidence::Physical {
            return Err(BaselineError::NotMeasuredOnDevice(summary.evidence));
        }
        if summary.coverage_ppm < MIN_BASELINE_COVERAGE_PPM {
            return Err(BaselineError::InsufficientCoverage {
                have_ppm: summary.coverage_ppm,
                need_ppm: MIN_BASELINE_COVERAGE_PPM,
            });
        }
        let Some(rate_milli) = summary.dropout_per_hour_milli else {
            return Err(BaselineError::DropoutsUnknown);
        };
        Ok(Baseline {
            summary,
            rate_milli,
        })
    }

    pub fn summary(&self) -> &AbsoluteSummary {
        &self.summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRefused {
    NoBaseline,
    CurrentNotMeasuredOnDevice(Evidence),
    ProfileMismatch,
    InsufficientCoverage { have_ppm: u64, need_ppm: u64 },
    CurrentDropoutsUnknown,
    CurrentHasCensoredDropouts,
    BadMargin(u64),
}

impl ClaimRefused {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimRefused::NoBaseline => "no_baseline",
            ClaimRefused::CurrentNotMeasuredOnDevice(_) => "current_not_measured_on_device",
            ClaimRefused::ProfileMismatch => "profile_mismatch",
            ClaimRefused::InsufficientCoverage { .. } => "insufficient_coverage",
            ClaimRefused::CurrentDropoutsUnknown => "current_dropouts_unknown",
            ClaimRefused::CurrentHasCensoredDropouts => "current_has_censored_dropouts",
            ClaimRefused::BadMargin(_) => "bad_margin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Better,
    Equivalent,
    Worse,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Better => "better",
            Verdict::Equivalent => "equivalent",
            Verdict::Worse => "worse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comparison {
    pub baseline_per_hour_milli: u128,
    pub current_per_hour_milli: u128,
    pub margin_pct: u64,
    pub verdict: Verdict,
}

impl Comparison {
    pub fn to_json(&self) -> Json {
        let big = |v: u128| Json::Int(i128::try_from(v).unwrap_or(i128::MAX));
        Json::obj(vec![
            ("baseline_per_hour_milli", big(self.baseline_per_hour_milli)),
            ("current_per_hour_milli", big(self.current_per_hour_milli)),
            ("margin_pct", Json::int(self.margin_pct)),
            ("verdict", Json::str(self.verdict.as_str())),
        ])
    }
}

/// Compare a current run with a baseline. `margin_pct` (0..=99) is how much better or worse the rate has
/// to be before the verdict says so: `Better` means at least `margin_pct` percent fewer dropouts per
/// hour, `Worse` at least `margin_pct` percent more, and anything in between is `Equivalent`.
pub fn compare(
    current: &AbsoluteSummary,
    baseline: Option<&Baseline>,
    margin_pct: u64,
) -> Result<Comparison, ClaimRefused> {
    if margin_pct > 99 {
        return Err(ClaimRefused::BadMargin(margin_pct));
    }
    let Some(baseline) = baseline else {
        return Err(ClaimRefused::NoBaseline);
    };
    if current.evidence != Evidence::Physical {
        return Err(ClaimRefused::CurrentNotMeasuredOnDevice(current.evidence));
    }
    if current.profile != baseline.summary.profile {
        return Err(ClaimRefused::ProfileMismatch);
    }
    if current.coverage_ppm < MIN_BASELINE_COVERAGE_PPM {
        return Err(ClaimRefused::InsufficientCoverage {
            have_ppm: current.coverage_ppm,
            need_ppm: MIN_BASELINE_COVERAGE_PPM,
        });
    }
    let Some(cur) = current.dropout_per_hour_milli else {
        return Err(ClaimRefused::CurrentDropoutsUnknown);
    };
    if current.censored_dropouts > 0 {
        return Err(ClaimRefused::CurrentHasCensoredDropouts);
    }
    let base = baseline.rate_milli;
    let margin = u128::from(margin_pct);
    let verdict = if cur == base {
        Verdict::Equivalent
    } else if cur < base && cur * 100 <= base * (100 - margin) {
        Verdict::Better
    } else if cur > base && cur * 100 >= base * (100 + margin) {
        Verdict::Worse
    } else {
        Verdict::Equivalent
    };
    Ok(Comparison {
        baseline_per_hour_milli: base,
        current_per_hour_milli: cur,
        margin_pct,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(evidence: Evidence, coverage_ppm: u64, rate: Option<u128>) -> AbsoluteSummary {
        AbsoluteSummary {
            evidence,
            profile: "incumbent-music-v1".to_string(),
            coverage_ppm,
            dropout_per_hour_milli: rate,
            censored_dropouts: 0,
        }
    }

    fn baseline(rate: u128) -> Baseline {
        Baseline::new(summary(Evidence::Physical, 1_000_000, Some(rate))).expect("valid baseline")
    }

    #[test]
    fn a_baseline_must_be_a_physical_measurement_with_coverage_and_a_known_rate() {
        for e in [
            Evidence::Synthetic,
            Evidence::HostSimulation,
            Evidence::GuestExecution,
            Evidence::RealService,
        ] {
            assert_eq!(
                Baseline::new(summary(e, 1_000_000, Some(5))),
                Err(BaselineError::NotMeasuredOnDevice(e))
            );
        }
        assert_eq!(
            Baseline::new(summary(Evidence::Physical, 899_999, Some(5))),
            Err(BaselineError::InsufficientCoverage {
                have_ppm: 899_999,
                need_ppm: 900_000
            })
        );
        assert_eq!(
            Baseline::new(summary(Evidence::Physical, 1_000_000, None)),
            Err(BaselineError::DropoutsUnknown)
        );
        let ok = Baseline::new(summary(Evidence::Physical, 900_000, Some(0)));
        assert!(ok.is_ok());
    }

    #[test]
    fn with_no_baseline_every_comparative_claim_is_refused() {
        let current = summary(Evidence::Physical, 1_000_000, Some(100));
        assert_eq!(compare(&current, None, 10), Err(ClaimRefused::NoBaseline));
        // Even a perfect current run, and even one that is not physical, gets the same refusal first.
        let synthetic = summary(Evidence::Synthetic, 1_000_000, Some(0));
        assert_eq!(compare(&synthetic, None, 10), Err(ClaimRefused::NoBaseline));
    }

    #[test]
    fn a_current_run_must_itself_be_a_comparable_physical_measurement() {
        let b = baseline(1000);
        let cases = [
            (
                summary(Evidence::Synthetic, 1_000_000, Some(0)),
                ClaimRefused::CurrentNotMeasuredOnDevice(Evidence::Synthetic),
            ),
            (
                summary(Evidence::Physical, 800_000, Some(0)),
                ClaimRefused::InsufficientCoverage {
                    have_ppm: 800_000,
                    need_ppm: 900_000,
                },
            ),
            (
                summary(Evidence::Physical, 1_000_000, None),
                ClaimRefused::CurrentDropoutsUnknown,
            ),
        ];
        for (current, want) in cases {
            assert_eq!(compare(&current, Some(&b), 10), Err(want));
        }
        let mut other = summary(Evidence::Physical, 1_000_000, Some(0));
        other.profile = "different-profile".to_string();
        assert_eq!(
            compare(&other, Some(&b), 10),
            Err(ClaimRefused::ProfileMismatch)
        );
        let mut hidden = summary(Evidence::Physical, 1_000_000, Some(0));
        hidden.censored_dropouts = 1;
        assert_eq!(
            compare(&hidden, Some(&b), 10),
            Err(ClaimRefused::CurrentHasCensoredDropouts)
        );
        let current = summary(Evidence::Physical, 1_000_000, Some(0));
        assert_eq!(
            compare(&current, Some(&b), 100),
            Err(ClaimRefused::BadMargin(100))
        );
    }

    #[test]
    fn the_margin_decides_better_equivalent_and_worse() {
        let b = baseline(1000);
        let verdict = |rate: u128, margin: u64| {
            compare(
                &summary(Evidence::Physical, 1_000_000, Some(rate)),
                Some(&b),
                margin,
            )
            .expect("comparable")
            .verdict
        };
        // 10% margin on a baseline of 1000: better at or below 900, worse at or above 1100.
        assert_eq!(verdict(900, 10), Verdict::Better);
        assert_eq!(verdict(901, 10), Verdict::Equivalent);
        assert_eq!(verdict(1000, 10), Verdict::Equivalent);
        assert_eq!(verdict(1099, 10), Verdict::Equivalent);
        assert_eq!(verdict(1100, 10), Verdict::Worse);
        // Zero margin: any strict change counts.
        assert_eq!(verdict(999, 0), Verdict::Better);
        assert_eq!(verdict(1001, 0), Verdict::Worse);
        assert_eq!(verdict(1000, 0), Verdict::Equivalent);
        // 99% margin: only a near-total elimination is better.
        assert_eq!(verdict(10, 99), Verdict::Better);
        assert_eq!(verdict(11, 99), Verdict::Equivalent);
    }

    #[test]
    fn a_zero_baseline_can_only_be_matched_or_beaten_downward() {
        let b = baseline(0);
        let verdict = |rate: u128| {
            compare(
                &summary(Evidence::Physical, 1_000_000, Some(rate)),
                Some(&b),
                10,
            )
            .expect("comparable")
            .verdict
        };
        assert_eq!(verdict(0), Verdict::Equivalent);
        assert_eq!(verdict(1), Verdict::Worse);
    }

    #[test]
    fn a_comparison_renders_its_figures() {
        let b = baseline(1000);
        let c = compare(
            &summary(Evidence::Physical, 1_000_000, Some(500)),
            Some(&b),
            10,
        )
        .expect("comparable");
        assert_eq!(
            c.to_json().render(),
            "{\"baseline_per_hour_milli\":1000,\"current_per_hour_milli\":500,\"margin_pct\":10,\"verdict\":\"better\"}"
        );
    }
}
