//! Bounded clock-rate estimator (`D03` / `ffw-j9r`): how fast does a source's frame counter advance
//! against the local monotonic clock, as a correction ratio with an uncertainty.
//!
//! The estimator is control-plane code with a fixed-size window, no I/O and no panics on any input.
//! Contract: `docs/contracts/d03.md` section 2.
//!
//! * **Ratio.** Least-squares slope of unwrapped source position against local microseconds over at
//!   most [`RATE_WINDOW`] observations, in 128-bit integer arithmetic, reported as parts per billion
//!   (`ratio_ppb`, positive when the source runs fast). The correction is that ratio clamped to
//!   `max_correction_ppm`.
//! * **Uncertainty.** The standard error of the slope from the fit residuals, in the same unit,
//!   growing with the age of the newest observation ([`RateEstimator::estimate_at`]).
//! * **Wrap.** The source position is a wrapping `u32` frame counter (at 48 kHz it wraps near 24.86
//!   hours). A step of less than half the range is unwrapped without fuss; a step that cannot be told
//!   from a backward jump is a discontinuity.
//! * **Discontinuity.** A clock jump or ambiguous timeline step rejects the observation and parks
//!   the estimator until an explicit [`RateEstimator::begin_epoch`]. Nothing is reset implicitly:
//!   the source-local history (window, fit, estimate) is cleared only at that transition, and each
//!   transition is recorded with its reason. Configuration and the reset log are never cleared.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Observations kept in the fitting window.
pub const RATE_WINDOW: usize = 64;
/// Resets remembered in the reset log.
pub const RESET_LOG: usize = 8;

/// Why an observation was rejected as a discontinuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscontinuityReason {
    /// The local clock did not advance (it stood still or went backwards).
    LocalClockRegression,
    /// The source position moved backwards, or forwards by half the counter range or more.
    SourceTimelineAmbiguous,
    /// Too long since the previous observation to trust continuity.
    ObservationGap,
    /// The rate implied by the last two observations is outside the plausible band.
    ImplausibleRate,
    /// The position deviates from the fitted line by more than the residual limit.
    PositionJump,
}

impl DiscontinuityReason {
    /// Stable machine-readable name for logs and receipts.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::LocalClockRegression => "LocalClockRegression",
            Self::SourceTimelineAmbiguous => "SourceTimelineAmbiguous",
            Self::ObservationGap => "ObservationGap",
            Self::ImplausibleRate => "ImplausibleRate",
            Self::PositionJump => "PositionJump",
        }
    }
}

/// Why source-local history was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetReason {
    /// A different source began.
    NewSource,
    /// Recovery from a rejected observation.
    Discontinuity(DiscontinuityReason),
    /// A rebuffer/rejoin after an excessive rate.
    Rejoin,
}

/// One explicit epoch transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetRecord {
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub reason: ResetReason,
    pub observations_dropped: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RateError {
    #[error("invalid rate-estimator configuration: {0}")]
    InvalidConfig(String),
    #[error(
        "observation rejected as a discontinuity ({0:?}); an explicit epoch transition is required"
    )]
    Discontinuity(DiscontinuityReason),
    #[error("an epoch transition is required before further observations")]
    EpochTransitionRequired,
    #[error("epoch {requested} does not advance current epoch {current}")]
    EpochNotAdvanced { current: u32, requested: u32 },
    #[error("estimator arithmetic out of range")]
    Overflow,
}

/// Limits and thresholds. [`RateConfig::for_rate`] gives the documented defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateConfig {
    pub nominal_rate_hz: u32,
    /// The correction is clamped to this many ppm either way.
    pub max_correction_ppm: u32,
    /// A measured ratio beyond this many ppm needs a rebuffer/rejoin, not resampling.
    pub rejoin_ppm: u32,
    /// An instantaneous rate beyond this many ppm from nominal is a discontinuity.
    pub max_instant_ppm: u32,
    /// Longest tolerated spacing between observations.
    pub max_gap_us: u64,
    /// A position further than this many frames from the fitted line is a discontinuity.
    pub max_residual_frames: u32,
    /// Observations needed before an estimate is offered.
    pub min_observations: u32,
    /// Time spanned by the window before an estimate is offered.
    pub min_span_us: u64,
    /// Above this the estimate is `Noisy` and the correction is held at zero.
    pub max_uncertainty_ppb: u64,
    /// Uncertainty added per second of observation age.
    pub aging_ppb_per_s: u64,
    /// Beyond this age no estimate is offered.
    pub max_holdover_us: u64,
    /// Window length, at most [`RATE_WINDOW`].
    pub window: u32,
}

impl RateConfig {
    pub const MIN_RATE_HZ: u32 = 8_000;
    pub const MAX_RATE_HZ: u32 = 384_000;
    /// Longest `max_gap_us` the 128-bit arithmetic is sized for.
    pub const MAX_GAP_LIMIT_US: u64 = 30_000_000;

    /// Documented defaults for a nominal frame rate.
    pub fn for_rate(nominal_rate_hz: u32) -> Result<Self, RateError> {
        let cfg = Self {
            nominal_rate_hz,
            max_correction_ppm: 500,
            rejoin_ppm: 2_000,
            max_instant_ppm: 50_000,
            max_gap_us: 10_000_000,
            max_residual_frames: nominal_rate_hz / 100,
            min_observations: 8,
            min_span_us: 4_000_000,
            max_uncertainty_ppb: 50_000,
            aging_ppb_per_s: 100,
            max_holdover_us: 60_000_000,
            window: RATE_WINDOW as u32,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), RateError> {
        let bad = |what: &str| Err(RateError::InvalidConfig(what.to_string()));
        if !(Self::MIN_RATE_HZ..=Self::MAX_RATE_HZ).contains(&self.nominal_rate_hz) {
            return bad("nominal_rate_hz outside 8000..=384000");
        }
        if self.max_correction_ppm == 0 || self.max_correction_ppm > self.rejoin_ppm {
            return bad("need 0 < max_correction_ppm <= rejoin_ppm");
        }
        if self.rejoin_ppm > self.max_instant_ppm || self.max_instant_ppm > 500_000 {
            return bad("need rejoin_ppm <= max_instant_ppm <= 500000");
        }
        if self.max_gap_us == 0 || self.max_gap_us > Self::MAX_GAP_LIMIT_US {
            return bad("max_gap_us outside 1..=30000000");
        }
        if self.window < 3 || self.window as usize > RATE_WINDOW {
            return bad("window outside 3..=64");
        }
        if self.min_observations < 3 || self.min_observations > self.window {
            return bad("need 3 <= min_observations <= window");
        }
        if self.min_span_us == 0 || self.max_holdover_us == 0 || self.max_residual_frames == 0 {
            return bad("min_span_us, max_holdover_us and max_residual_frames must be nonzero");
        }
        Ok(())
    }
}

/// One reading: the source's wrapping frame counter against the local monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub position: u32,
    pub local_us: u64,
}

/// How far the estimate can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EstimateStatus {
    /// Within the correction limit and certain enough to apply.
    Valid,
    /// Beyond the correction limit; the correction is clamped.
    Clamped,
    /// Too uncertain to apply; the correction is held at zero.
    Noisy,
    /// Beyond the rejoin limit: rebuffer or rejoin instead of resampling.
    RejoinRequired,
}

impl EstimateStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Valid => "Valid",
            Self::Clamped => "Clamped",
            Self::Noisy => "Noisy",
            Self::RejoinRequired => "RejoinRequired",
        }
    }
}

/// The estimator's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateEstimate {
    pub epoch: u32,
    pub observations: u32,
    pub span_us: u64,
    /// Measured source-rate error against nominal, in ppb (positive: the source runs fast).
    pub ratio_ppb: i64,
    /// What to apply: the ratio clamped to the correction limit, or zero when `Noisy`.
    pub correction_ppb: i64,
    pub clamped: bool,
    pub uncertainty_ppb: u64,
    pub status: EstimateStatus,
}

/// Counters that survive resets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateStats {
    pub accepted: u64,
    pub discontinuities: u32,
    /// Timeline wraps absorbed by unwrapping (not discontinuities).
    pub wraps: u32,
    pub resets: u32,
}

#[derive(Debug, Clone, Copy)]
struct Point {
    raw: u32,
    unwrapped: i64,
    local_us: i64,
}

#[derive(Debug, Clone, Copy)]
struct Fit {
    x0: i64,
    y0: i64,
    xbar: f64,
    ybar: f64,
    slope: f64,
}

/// Nearest integer, halves away from zero, for `den > 0` (the exact rule the reference uses).
fn div_round_nearest(num: i128, den: i128) -> i128 {
    if num >= 0 {
        (2 * num + den) / (2 * den)
    } else {
        -((-2 * num + den) / (2 * den))
    }
}

#[derive(Debug, Clone)]
pub struct RateEstimator {
    cfg: RateConfig,
    epoch: u32,
    window: VecDeque<Point>,
    awaiting_epoch: bool,
    last_discontinuity: Option<DiscontinuityReason>,
    fit: Option<Fit>,
    estimate: Option<RateEstimate>,
    resets: VecDeque<ResetRecord>,
    stats: RateStats,
}

impl RateEstimator {
    pub fn new(cfg: RateConfig) -> Result<Self, RateError> {
        cfg.validate()?;
        let cap = cfg.window as usize;
        Ok(Self {
            cfg,
            epoch: 0,
            window: VecDeque::with_capacity(cap),
            awaiting_epoch: false,
            last_discontinuity: None,
            fit: None,
            estimate: None,
            resets: VecDeque::with_capacity(RESET_LOG),
            stats: RateStats::default(),
        })
    }

    #[must_use]
    pub const fn config(&self) -> &RateConfig {
        &self.cfg
    }

    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// True after a rejected observation, until [`Self::begin_epoch`].
    #[must_use]
    pub const fn awaiting_epoch(&self) -> bool {
        self.awaiting_epoch
    }

    #[must_use]
    pub const fn last_discontinuity(&self) -> Option<DiscontinuityReason> {
        self.last_discontinuity
    }

    #[must_use]
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    #[must_use]
    pub const fn stats(&self) -> RateStats {
        self.stats
    }

    /// The most recent resets, oldest first (at most [`RESET_LOG`]).
    pub fn reset_log(&self) -> impl Iterator<Item = &ResetRecord> + '_ {
        self.resets.iter()
    }

    /// The estimate as of the newest observation; `None` until enough has been seen. It survives a
    /// rejected observation (holdover) and is cleared only by [`Self::begin_epoch`].
    #[must_use]
    pub const fn estimate(&self) -> Option<RateEstimate> {
        self.estimate
    }

    /// The estimate as of `now_us`, with uncertainty grown by observation age; `None` once the age
    /// exceeds `max_holdover_us`.
    #[must_use]
    pub fn estimate_at(&self, now_us: u64) -> Option<RateEstimate> {
        let est = self.estimate?;
        let newest = self.window.back()?;
        let newest_us = u64::try_from(newest.local_us).unwrap_or(0);
        let age_us = now_us.saturating_sub(newest_us);
        if age_us > self.cfg.max_holdover_us {
            return None;
        }
        let growth = self.cfg.aging_ppb_per_s.saturating_mul(age_us) / 1_000_000;
        let uncertainty_ppb = est.uncertainty_ppb.saturating_add(growth);
        let (status, correction_ppb) = self.classify(est.ratio_ppb, uncertainty_ppb);
        Some(RateEstimate {
            uncertainty_ppb,
            correction_ppb,
            clamped: matches!(
                status,
                EstimateStatus::Clamped | EstimateStatus::RejoinRequired
            ),
            status,
            ..est
        })
    }

    /// Feed one reading. A discontinuity returns an error, leaves the window untouched and parks the
    /// estimator until [`Self::begin_epoch`].
    pub fn observe(&mut self, obs: Observation) -> Result<(), RateError> {
        if self.awaiting_epoch {
            return Err(RateError::EpochTransitionRequired);
        }
        let local = i64::try_from(obs.local_us).map_err(|_| RateError::Overflow)?;
        let mut point = Point {
            raw: obs.position,
            unwrapped: i64::from(obs.position),
            local_us: local,
        };
        let mut wrapped = false;
        if let Some(prev) = self.window.back().copied() {
            if local <= prev.local_us {
                return self.reject(DiscontinuityReason::LocalClockRegression);
            }
            let delta = obs.position.wrapping_sub(prev.raw) as i32;
            if delta < 0 {
                return self.reject(DiscontinuityReason::SourceTimelineAmbiguous);
            }
            let dt_us = local - prev.local_us;
            if dt_us as u64 > self.cfg.max_gap_us {
                return self.reject(DiscontinuityReason::ObservationGap);
            }
            let dpos = i64::from(delta);
            if self.rate_is_implausible(dpos, dt_us) {
                return self.reject(DiscontinuityReason::ImplausibleRate);
            }
            point.unwrapped = prev
                .unwrapped
                .checked_add(dpos)
                .ok_or(RateError::Overflow)?;
            wrapped = obs.position < prev.raw;
            if self.position_jumped(&point) {
                return self.reject(DiscontinuityReason::PositionJump);
            }
        }
        if self.window.len() >= self.cfg.window as usize {
            self.window.pop_front();
        }
        self.window.push_back(point);
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        if wrapped {
            self.stats.wraps = self.stats.wraps.saturating_add(1);
        }
        self.refit()
    }

    /// Begin a new epoch: clear the source-local history (window, fit, estimate) and record why.
    /// Configuration, counters and the reset log are kept. `epoch` must advance the current one.
    pub fn begin_epoch(
        &mut self,
        epoch: u32,
        reason: ResetReason,
    ) -> Result<ResetRecord, RateError> {
        if (epoch.wrapping_sub(self.epoch) as i32) <= 0 {
            return Err(RateError::EpochNotAdvanced {
                current: self.epoch,
                requested: epoch,
            });
        }
        let record = ResetRecord {
            from_epoch: self.epoch,
            to_epoch: epoch,
            reason,
            observations_dropped: u32::try_from(self.window.len()).unwrap_or(u32::MAX),
        };
        self.window.clear();
        self.fit = None;
        self.estimate = None;
        self.awaiting_epoch = false;
        self.epoch = epoch;
        self.stats.resets = self.stats.resets.saturating_add(1);
        if self.resets.len() >= RESET_LOG {
            self.resets.pop_front();
        }
        self.resets.push_back(record);
        Ok(record)
    }

    fn reject(&mut self, reason: DiscontinuityReason) -> Result<(), RateError> {
        self.awaiting_epoch = true;
        self.last_discontinuity = Some(reason);
        self.stats.discontinuities = self.stats.discontinuities.saturating_add(1);
        Err(RateError::Discontinuity(reason))
    }

    /// `|dpos/dt - nominal| / nominal > max_instant_ppm / 1e6`, in exact integers.
    fn rate_is_implausible(&self, dpos: i64, dt_us: i64) -> bool {
        let nominal = i128::from(self.cfg.nominal_rate_hz);
        let dev = (i128::from(dpos) * 1_000_000 - nominal * i128::from(dt_us)).abs() * 1_000_000;
        let limit = i128::from(self.cfg.max_instant_ppm) * nominal * i128::from(dt_us);
        dev > limit
    }

    /// Is `point` further from the current fit than the residual limit? Only once enough is known.
    fn position_jumped(&self, point: &Point) -> bool {
        if self.window.len() < self.cfg.min_observations as usize {
            return false;
        }
        match self.fit {
            Some(fit) => {
                let dx = (point.local_us - fit.x0) as f64;
                let dy = (point.unwrapped - fit.y0) as f64;
                let predicted = fit.ybar + fit.slope * (dx - fit.xbar);
                (dy - predicted).abs() > f64::from(self.cfg.max_residual_frames)
            }
            None => false,
        }
    }

    /// Rejoin > noisy > clamped > valid.
    fn classify(&self, ratio_ppb: i64, uncertainty_ppb: u64) -> (EstimateStatus, i64) {
        let cap = i64::from(self.cfg.max_correction_ppm) * 1_000;
        let rejoin = u64::from(self.cfg.rejoin_ppm) * 1_000;
        let clamped = ratio_ppb.clamp(-cap, cap);
        if ratio_ppb.unsigned_abs() > rejoin {
            (EstimateStatus::RejoinRequired, clamped)
        } else if uncertainty_ppb > self.cfg.max_uncertainty_ppb {
            (EstimateStatus::Noisy, 0)
        } else if ratio_ppb.unsigned_abs() > cap.unsigned_abs() {
            (EstimateStatus::Clamped, clamped)
        } else {
            (EstimateStatus::Valid, ratio_ppb)
        }
    }

    /// Recompute the fit and estimate from the window. Sums are exact 128-bit integers; the window
    /// span is bounded by `window * max_gap_us` (validated), so they cannot overflow.
    fn refit(&mut self) -> Result<(), RateError> {
        self.fit = None;
        self.estimate = None;
        let n = self.window.len();
        if n < 3 {
            return Ok(());
        }
        let (first, last) = match (self.window.front(), self.window.back()) {
            (Some(a), Some(b)) => (*a, *b),
            _ => return Ok(()),
        };
        let (mut sx, mut sy, mut sxx, mut sxy) = (0_i128, 0_i128, 0_i128, 0_i128);
        for p in &self.window {
            let x = i128::from(p.local_us - first.local_us);
            let y = i128::from(p.unwrapped - first.unwrapped);
            sx += x;
            sy += y;
            sxx += x * x;
            sxy += x * y;
        }
        let nn = n as i128;
        let dx = nn * sxx - sx * sx;
        let dxy = nn * sxy - sx * sy;
        if dx <= 0 {
            return Ok(());
        }
        let nominal = i128::from(self.cfg.nominal_rate_hz);
        // ppb = (dxy*1e6 - nominal*dx) * 1e9 / (nominal*dx)
        let scaled = dxy.checked_mul(1_000_000).ok_or(RateError::Overflow)?;
        let base = nominal.checked_mul(dx).ok_or(RateError::Overflow)?;
        let numerator = scaled
            .checked_sub(base)
            .and_then(|v| v.checked_mul(1_000_000_000))
            .ok_or(RateError::Overflow)?;
        let ratio = div_round_nearest(numerator, base);
        let ratio_ppb = ratio.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;

        // Uncertainty (standard error of the slope) from the residuals, in f64.
        let nf = n as f64;
        let xbar = sx as f64 / nf;
        let ybar = sy as f64 / nf;
        let slope = dxy as f64 / dx as f64;
        let mut ssr = 0.0_f64;
        for p in &self.window {
            let x = (p.local_us - first.local_us) as f64;
            let y = (p.unwrapped - first.unwrapped) as f64;
            let r = (y - ybar) - slope * (x - xbar);
            ssr += r * r;
        }
        let sxx_centred = dx as f64 / nf;
        let var = ssr / ((n - 2) as f64) / sxx_centred;
        let unc = var.sqrt() * 1.0e15 / f64::from(self.cfg.nominal_rate_hz);
        // Below a thousandth of a ppb is float noise on an exact line, not uncertainty.
        let uncertainty_ppb = if !unc.is_finite() {
            u64::MAX
        } else if unc < 1.0e-3 {
            0
        } else {
            unc.ceil().min(1.0e18) as u64
        };
        self.fit = Some(Fit {
            x0: first.local_us,
            y0: first.unwrapped,
            xbar,
            ybar,
            slope,
        });

        let span_us = (last.local_us - first.local_us) as u64;
        if n < self.cfg.min_observations as usize || span_us < self.cfg.min_span_us {
            return Ok(());
        }
        let (status, correction_ppb) = self.classify(ratio_ppb, uncertainty_ppb);
        self.estimate = Some(RateEstimate {
            epoch: self.epoch,
            observations: n as u32,
            span_us,
            ratio_ppb,
            correction_ppb,
            clamped: matches!(
                status,
                EstimateStatus::Clamped | EstimateStatus::RejoinRequired
            ),
            uncertainty_ppb,
            status,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../tests/d03/vectors.json"))
            .expect("vectors.json parses")
    }

    fn cfg() -> RateConfig {
        RateConfig::for_rate(48_000).expect("default config")
    }

    fn obs_of(v: &Value) -> Observation {
        Observation {
            position: u32::try_from(v[0].as_u64().expect("position")).expect("u32 position"),
            local_us: v[1].as_u64().expect("local_us"),
        }
    }

    fn feed(est: &mut RateEstimator, list: &Value) {
        for o in list.as_array().expect("observation list") {
            est.observe(obs_of(o)).expect("clean observation accepted");
        }
    }

    /// A perfect source at `ppb` from nominal, one observation per second, no noise.
    fn perfect(n: usize, ppb: i64, pos0: u64) -> Vec<Observation> {
        (0..n as u64)
            .map(|i| {
                let us = i * 1_000_000;
                let frames = (i128::from(us) * 48_000 * i128::from(1_000_000_000 + ppb)
                    / 1_000_000_000_000_000) as u64;
                Observation {
                    position: ((pos0 + frames) & 0xFFFF_FFFF) as u32,
                    local_us: 1_000_000_000 + us,
                }
            })
            .collect()
    }

    #[test]
    fn d03_rate_defaults_match_contract() {
        let v = vectors();
        let d = &v["params"]["rate_defaults"];
        let c = cfg();
        assert_eq!(
            u64::from(c.nominal_rate_hz),
            d["nominal_rate_hz"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(c.max_correction_ppm),
            d["max_correction_ppm"].as_u64().unwrap()
        );
        assert_eq!(u64::from(c.rejoin_ppm), d["rejoin_ppm"].as_u64().unwrap());
        assert_eq!(
            u64::from(c.max_instant_ppm),
            d["max_instant_ppm"].as_u64().unwrap()
        );
        assert_eq!(c.max_gap_us, d["max_gap_us"].as_u64().unwrap());
        assert_eq!(
            u64::from(c.max_residual_frames),
            d["max_residual_frames"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(c.min_observations),
            d["min_observations"].as_u64().unwrap()
        );
        assert_eq!(c.min_span_us, d["min_span_us"].as_u64().unwrap());
        assert_eq!(
            c.max_uncertainty_ppb,
            d["max_uncertainty_ppb"].as_u64().unwrap()
        );
        assert_eq!(c.aging_ppb_per_s, d["aging_ppb_per_s"].as_u64().unwrap());
        assert_eq!(c.max_holdover_us, d["max_holdover_us"].as_u64().unwrap());
        assert_eq!(u64::from(c.window), d["window"].as_u64().unwrap());
        assert_eq!(RATE_WINDOW as u64, d["window"].as_u64().unwrap());
    }

    #[test]
    fn d03_estimator_matches_independent_least_squares() {
        let v = vectors();
        for case in v["estimator"].as_array().expect("estimator cases") {
            let id = case["id"].as_str().expect("id");
            let mut est = RateEstimator::new(cfg()).expect("estimator");
            feed(&mut est, &case["observations"]);
            let e = est
                .estimate()
                .unwrap_or_else(|| panic!("{id}: no estimate"));
            assert_eq!(
                e.ratio_ppb,
                case["expect_ratio_ppb"].as_i64().unwrap(),
                "{id}: ratio_ppb"
            );
            assert_eq!(
                e.status.code(),
                case["status"].as_str().unwrap(),
                "{id}: status"
            );
            assert_eq!(
                e.correction_ppb,
                case["correction_ppb"].as_i64().unwrap(),
                "{id}: correction"
            );
            assert_eq!(
                e.clamped,
                case["clamped"].as_bool().unwrap(),
                "{id}: clamped flag"
            );
            assert_eq!(
                u64::from(e.observations),
                case["window_len"].as_u64().unwrap(),
                "{id}: window"
            );
            assert_eq!(e.span_us, case["span_us"].as_u64().unwrap(), "{id}: span");
            assert_eq!(
                u64::from(est.stats().wraps),
                case["expect_wraps"].as_u64().unwrap(),
                "{id}: wraps"
            );
            let want = case["expect_uncertainty_ppb"].as_f64().unwrap();
            let tol = (want * 1.0e-6).max(1.0) + 1.0;
            assert!(
                (e.uncertainty_ppb as f64 - want.ceil()).abs() <= tol,
                "{id}: uncertainty {} vs reference {want}",
                e.uncertainty_ppb
            );
            assert_eq!(est.stats().discontinuities, 0, "{id}: clean data rejected");
            println!(
                "D03-OBSERVED {}",
                json!({"id": id, "kind": "estimator", "ratio_ppb": e.ratio_ppb,
                       "uncertainty_ppb": e.uncertainty_ppb, "status": e.status.code(),
                       "correction_ppb": e.correction_ppb, "wraps": est.stats().wraps})
            );
        }
    }

    #[test]
    fn d03_estimator_offers_nothing_until_warm() {
        let v = vectors();
        for case in v["estimator_warmup"].as_array().expect("warm-up cases") {
            let id = case["id"].as_str().unwrap();
            let mut est = RateEstimator::new(cfg()).unwrap();
            feed(&mut est, &case["observations"]);
            assert!(
                est.estimate().is_none(),
                "{id}: estimate offered while cold"
            );
            assert!(!est.awaiting_epoch(), "{id}");
        }
    }

    #[test]
    fn d03_perfect_nominal_source_has_zero_drift_and_zero_uncertainty() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        for o in perfect(16, 0, 1234) {
            est.observe(o).unwrap();
        }
        let e = est.estimate().unwrap();
        assert_eq!(
            (e.ratio_ppb, e.uncertainty_ppb, e.status),
            (0, 0, EstimateStatus::Valid)
        );
        assert_eq!((e.correction_ppb, e.clamped), (0, false));
    }

    #[test]
    fn d03_perfect_drifting_sources_are_recovered_in_both_directions() {
        for ppb in [1_000_000_i64, -1_000_000, 250_000, -250_000] {
            let mut est = RateEstimator::new(cfg()).unwrap();
            for o in perfect(20, ppb, 0) {
                est.observe(o).unwrap();
            }
            let e = est.estimate().unwrap();
            // each of these is an exact integer-step line (48000 * (1 + ppb/1e9) is a whole number),
            // so least squares must return the injected ratio exactly
            assert_eq!(e.ratio_ppb, ppb, "ppb {ppb}");
            assert_eq!(
                e.uncertainty_ppb, 0,
                "ppb {ppb}: an exact line has no residual"
            );
        }
    }

    #[test]
    fn d03_correction_is_clamped_and_rejoin_is_flagged() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        for o in perfect(20, 1_200_000, 0) {
            est.observe(o).unwrap();
        }
        let e = est.estimate().unwrap();
        assert_eq!(
            (e.status, e.clamped, e.correction_ppb),
            (EstimateStatus::Clamped, true, 500_000)
        );
        let mut est = RateEstimator::new(cfg()).unwrap();
        for o in perfect(20, -2_500_000, 0) {
            est.observe(o).unwrap();
        }
        let e = est.estimate().unwrap();
        assert_eq!(
            (e.status, e.correction_ppb),
            (EstimateStatus::RejoinRequired, -500_000)
        );
    }

    #[test]
    fn d03_wrap_is_absorbed_and_changes_nothing() {
        let a = perfect(30, 120_000, 100);
        let b = perfect(30, 120_000, (1_u64 << 32) - 10 * 48_000);
        let (mut ea, mut eb) = (
            RateEstimator::new(cfg()).unwrap(),
            RateEstimator::new(cfg()).unwrap(),
        );
        for (x, y) in a.iter().zip(b.iter()) {
            ea.observe(*x).unwrap();
            eb.observe(*y).unwrap();
        }
        assert_eq!(eb.stats().wraps, 1);
        assert_eq!(ea.stats().wraps, 0);
        assert_eq!(
            ea.estimate().unwrap().ratio_ppb,
            eb.estimate().unwrap().ratio_ppb
        );
        assert!(!eb.awaiting_epoch());
    }

    #[test]
    fn d03_discontinuities_reject_and_park_until_an_explicit_epoch() {
        let v = vectors();
        let cases = v["discontinuities"]
            .as_array()
            .expect("discontinuity cases");
        assert!(cases.len() >= 8);
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let mut est = RateEstimator::new(cfg()).unwrap();
            feed(&mut est, &case["prefix"]);
            let before = est
                .estimate()
                .unwrap_or_else(|| panic!("{id}: prefix gave no estimate"));
            let window_before = est.window_len();

            let err = est.observe(obs_of(&case["event"])).unwrap_err();
            let reason = case["reason"].as_str().unwrap();
            match err {
                RateError::Discontinuity(r) => assert_eq!(r.code(), reason, "{id}"),
                other => panic!("{id}: expected a discontinuity, got {other:?}"),
            }
            // nothing was reset by the rejection: the window and the estimate are intact (holdover)
            assert!(est.awaiting_epoch(), "{id}");
            assert_eq!(
                est.window_len(),
                window_before,
                "{id}: window changed by a rejected observation"
            );
            assert_eq!(
                est.estimate(),
                Some(before),
                "{id}: estimate changed by a rejected observation"
            );
            assert_eq!(
                est.stats().resets,
                0,
                "{id}: reset without an epoch transition"
            );
            // further input is refused until the transition
            let ok_next = Observation {
                position: 1,
                local_us: 4_000_000_000,
            };
            assert_eq!(
                est.observe(ok_next),
                Err(RateError::EpochTransitionRequired),
                "{id}"
            );
            assert_eq!(est.window_len(), window_before, "{id}");

            let rec = est.begin_epoch(1, reset_reason_of(reason)).unwrap();
            assert_eq!((rec.from_epoch, rec.to_epoch), (0, 1), "{id}");
            assert_eq!(rec.observations_dropped as usize, window_before, "{id}");
            assert_eq!(
                rec.reason,
                ResetReason::Discontinuity(est.last_discontinuity().unwrap()),
                "{id}"
            );
            assert!(!est.awaiting_epoch(), "{id}");
            assert_eq!(
                (est.window_len(), est.estimate()),
                (0, None),
                "{id}: history survived the reset"
            );
            assert_eq!(
                est.stats().discontinuities,
                1,
                "{id}: counters must survive the reset"
            );
            assert_eq!(
                est.config(),
                &cfg(),
                "{id}: configuration must survive the reset"
            );
            // the new epoch estimates afresh
            for o in perfect(10, 80_000, 7) {
                est.observe(o).unwrap();
            }
            let e = est.estimate().unwrap();
            assert_eq!(e.epoch, 1, "{id}");
            println!(
                "D03-OBSERVED {}",
                json!({"id": id, "kind": "discontinuity", "reason": reason, "dropped": rec.observations_dropped,
                       "to_epoch": rec.to_epoch})
            );
        }
    }

    /// Maps a reason name from the vectors back to the typed reset reason.
    fn reset_reason_of(code: &str) -> ResetReason {
        let r = match code {
            "LocalClockRegression" => DiscontinuityReason::LocalClockRegression,
            "SourceTimelineAmbiguous" => DiscontinuityReason::SourceTimelineAmbiguous,
            "ObservationGap" => DiscontinuityReason::ObservationGap,
            "ImplausibleRate" => DiscontinuityReason::ImplausibleRate,
            "PositionJump" => DiscontinuityReason::PositionJump,
            other => panic!("unknown reason {other}"),
        };
        ResetReason::Discontinuity(r)
    }

    #[test]
    fn d03_reset_touches_only_its_own_estimator() {
        let (mut a, mut b) = (
            RateEstimator::new(cfg()).unwrap(),
            RateEstimator::new(cfg()).unwrap(),
        );
        for o in perfect(12, 50_000, 0) {
            a.observe(o).unwrap();
            b.observe(o).unwrap();
        }
        let b_before = b.estimate();
        a.begin_epoch(1, ResetReason::NewSource).unwrap();
        assert_eq!(a.estimate(), None);
        assert_eq!(b.estimate(), b_before);
        assert_eq!(a.reset_log().count(), 1);
        assert_eq!(b.reset_log().count(), 0);
    }

    #[test]
    fn d03_epochs_must_advance_and_compare_in_wrapping_order() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        assert_eq!(
            est.begin_epoch(0, ResetReason::NewSource),
            Err(RateError::EpochNotAdvanced {
                current: 0,
                requested: 0
            })
        );
        est.begin_epoch(5, ResetReason::NewSource).unwrap();
        assert!(matches!(
            est.begin_epoch(4, ResetReason::Rejoin),
            Err(RateError::EpochNotAdvanced { .. })
        ));
        est.begin_epoch(u32::MAX, ResetReason::Rejoin).unwrap_err(); // u32::MAX is 2^32-5 ahead: not "ahead" in wrapping order
        let mut near = RateEstimator::new(cfg()).unwrap();
        near.begin_epoch(u32::MAX - 1, ResetReason::NewSource)
            .unwrap_err();
        near.begin_epoch(1 << 30, ResetReason::NewSource).unwrap();
        near.begin_epoch((1 << 30) + (1 << 30), ResetReason::NewSource)
            .unwrap();
        near.begin_epoch(u32::MAX, ResetReason::NewSource).unwrap();
        assert_eq!(
            near.begin_epoch(0, ResetReason::NewSource)
                .map(|r| r.to_epoch),
            Ok(0),
            "0 follows u32::MAX"
        );
    }

    #[test]
    fn d03_reset_log_is_bounded_and_ordered() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        for e in 1..=(RESET_LOG as u32 + 4) {
            est.begin_epoch(e, ResetReason::NewSource).unwrap();
        }
        let log: Vec<u32> = est.reset_log().map(|r| r.to_epoch).collect();
        assert_eq!(log.len(), RESET_LOG);
        assert_eq!(log.first(), Some(&5));
        assert_eq!(log.last(), Some(&(RESET_LOG as u32 + 4)));
        assert_eq!(est.stats().resets, RESET_LOG as u32 + 4);
    }

    #[test]
    fn d03_uncertainty_grows_with_age_and_holdover_is_bounded() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        let list = perfect(16, 100_000, 0);
        for o in &list {
            est.observe(*o).unwrap();
        }
        let newest = list.last().unwrap().local_us;
        let fresh = est.estimate_at(newest).unwrap();
        let later = est.estimate_at(newest + 10_000_000).unwrap();
        assert_eq!(later.uncertainty_ppb, fresh.uncertainty_ppb + 1_000); // 100 ppb/s * 10 s
        assert_eq!(later.ratio_ppb, fresh.ratio_ppb);
        assert!(
            est.estimate_at(newest + 60_000_001).is_none(),
            "beyond max_holdover_us"
        );
        assert!(est.estimate_at(newest + 60_000_000).is_some());
        // enough age turns a valid estimate noisy and holds the correction at zero
        let mut cfg2 = cfg();
        cfg2.aging_ppb_per_s = 10_000;
        let mut est2 = RateEstimator::new(cfg2).unwrap();
        for o in &list {
            est2.observe(*o).unwrap();
        }
        let old = est2.estimate_at(newest + 6_000_000).unwrap();
        assert_eq!((old.status, old.correction_ppb), (EstimateStatus::Noisy, 0));
    }

    #[test]
    fn d03_config_is_validated() {
        let mut bad = Vec::new();
        let base = cfg();
        for edit in 0..12 {
            let mut c = base.clone();
            match edit {
                0 => c.nominal_rate_hz = 100,
                1 => c.nominal_rate_hz = 1_000_000,
                2 => c.max_correction_ppm = 0,
                3 => c.max_correction_ppm = c.rejoin_ppm + 1,
                4 => c.max_instant_ppm = c.rejoin_ppm - 1,
                5 => c.max_gap_us = 0,
                6 => c.max_gap_us = RateConfig::MAX_GAP_LIMIT_US + 1,
                7 => c.window = 2,
                8 => c.window = RATE_WINDOW as u32 + 1,
                9 => c.min_observations = c.window + 1,
                10 => c.min_span_us = 0,
                _ => c.max_residual_frames = 0,
            }
            bad.push(c);
        }
        for (i, c) in bad.iter().enumerate() {
            assert!(
                matches!(
                    RateEstimator::new(c.clone()),
                    Err(RateError::InvalidConfig(_))
                ),
                "edit {i}"
            );
        }
        assert!(RateConfig::for_rate(8_000).is_ok() && RateConfig::for_rate(384_000).is_ok());
        assert!(RateConfig::for_rate(7_999).is_err());
    }

    #[test]
    fn d03_window_slides_and_never_exceeds_its_bound() {
        let mut est = RateEstimator::new(cfg()).unwrap();
        for o in perfect(RATE_WINDOW * 2 + 5, 10_000, 0) {
            est.observe(o).unwrap();
            assert!(est.window_len() <= RATE_WINDOW);
        }
        assert_eq!(est.window_len(), RATE_WINDOW);
        assert_eq!(est.estimate().unwrap().observations as usize, RATE_WINDOW);
    }
}
