//! Bounded latency observations for one audio snapshot, route and clock epoch.
//!
//! Component durations can overlap. The timeline reports their union separately
//! from elapsed ingress-to-output time; gaps remain visible, never invented as
//! a component. These are software observations, not analog-output qualification.

use serde::{Deserialize, Serialize};

pub mod events;

pub const STAGE_COUNT: usize = 8;
const SCALE: i128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Stage {
    Ingress,
    Decode,
    Repair,
    Jitter,
    Resample,
    Dsp,
    Dma,
    Output,
}

impl Stage {
    pub const fn bit(self) -> u16 {
        1 << self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub clock_id: u64,
    pub epoch: u64,
    pub route_revision: u64,
    pub snapshot_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelayKind {
    Fixed,
    Variable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    Measured,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub start_ns: u64,
    pub end_ns: u64,
}

impl Interval {
    pub fn new(start_ns: u64, end_ns: u64) -> Result<Self, LatencyError> {
        if end_ns < start_ns {
            return Err(LatencyError::ReversedInterval);
        }
        Ok(Self { start_ns, end_ns })
    }

    pub fn from_signed(start_ns: i64, end_ns: i64) -> Result<Self, LatencyError> {
        Self::new(
            u64::try_from(start_ns).map_err(|_| LatencyError::NegativeTimestamp)?,
            u64::try_from(end_ns).map_err(|_| LatencyError::NegativeTimestamp)?,
        )
    }
}

/// A bounded affine map. The uncertainty applies to each mapped endpoint;
/// observations beyond the admitted local horizon are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockTransform {
    pub source_clock_id: u64,
    pub target_clock_id: u64,
    pub epoch: u64,
    pub local_anchor_ns: u64,
    pub target_anchor_ns: u64,
    pub rate_ppb: i32,
    pub uncertainty_ns: u64,
    pub valid_local: Interval,
}

impl ClockTransform {
    fn map_endpoint(self, timestamp: u64, round_up: bool) -> Result<u64, LatencyError> {
        if self.valid_local.end_ns < self.valid_local.start_ns
            || timestamp < self.valid_local.start_ns
            || timestamp > self.valid_local.end_ns
        {
            return Err(LatencyError::TransformExpired);
        }
        let rate = SCALE + i128::from(self.rate_ppb);
        if rate <= 0 {
            return Err(LatencyError::InvalidRate);
        }
        let scaled = (i128::from(timestamp) - i128::from(self.local_anchor_ns)) * rate;
        let mut delta = scaled.div_euclid(SCALE);
        if round_up && scaled.rem_euclid(SCALE) != 0 {
            delta += 1;
        }
        u64::try_from(i128::from(self.target_anchor_ns) + delta).map_err(|_| LatencyError::Overflow)
    }

    pub fn map_interval(self, interval: Interval) -> Result<Interval, LatencyError> {
        Interval::new(interval.start_ns, interval.end_ns)?;
        Interval::new(
            self.map_endpoint(interval.start_ns, false)?,
            self.map_endpoint(interval.end_ns, true)?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub context: Context,
    pub interval: Interval,
    pub uncertainty_ns: u64,
    pub kind: DelayKind,
    pub provenance: Provenance,
}

impl Observation {
    pub fn transform(self, transform: ClockTransform) -> Result<Self, LatencyError> {
        if self.context.clock_id != transform.source_clock_id
            || self.context.epoch != transform.epoch
        {
            return Err(LatencyError::ContextMismatch);
        }
        let rate = SCALE + i128::from(transform.rate_ppb);
        if rate <= 0 {
            return Err(LatencyError::InvalidRate);
        }
        let scaled_uncertainty = i128::from(self.uncertainty_ns) * rate;
        let mapped_uncertainty =
            u64::try_from(scaled_uncertainty / SCALE + i128::from(scaled_uncertainty % SCALE != 0))
                .map_err(|_| LatencyError::Overflow)?;
        Ok(Self {
            context: Context {
                clock_id: transform.target_clock_id,
                ..self.context
            },
            interval: transform.map_interval(self.interval)?,
            uncertainty_ns: mapped_uncertainty
                .checked_add(transform.uncertainty_ns)
                .ok_or(LatencyError::Overflow)?,
            ..self
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LatencyError {
    #[error("negative monotonic timestamp")]
    NegativeTimestamp,
    #[error("end timestamp precedes start")]
    ReversedInterval,
    #[error("clock, epoch, route or snapshot differs")]
    ContextMismatch,
    #[error("timestamp is outside the admitted clock transform horizon")]
    TransformExpired,
    #[error("clock transform rate is not positive")]
    InvalidRate,
    #[error("latency arithmetic is not representable")]
    Overflow,
    #[error("required stages are unknown: {0:#x}")]
    MissingStages(u16),
    #[error("invalid required-stage mask")]
    InvalidStageMask,
    #[error("latency snapshot is stale or in the future")]
    StaleSnapshot,
    #[error("stage lies outside ingress-to-output timeline")]
    OutsideTimeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyEstimate {
    pub context: Context,
    pub observed_at_ns: u64,
    /// Elapsed time including all gaps, from ingress start to output end.
    pub effective_ns: u64,
    pub minimum_ns: u64,
    pub maximum_ns: u64,
    pub accounted_ns: u64,
    pub unaccounted_ns: u64,
    pub fixed_only_ns: u64,
    pub variable_only_ns: u64,
    pub shared_ns: u64,
    pub inferred_stages: u16,
}

/// Advice for a cooperative source. One observation is never labelled p99;
/// the gate covers both ends of this observation's uncertainty interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoDelayAdvice {
    pub requested_delay_ns: u64,
    pub residual_min_ns: i128,
    pub residual_max_ns: i128,
    pub within_40ms_bound: bool,
}

impl LatencyEstimate {
    pub fn video_delay_advice(&self, applied_video_delay_ns: u64) -> VideoDelayAdvice {
        let residual_min_ns = i128::from(self.minimum_ns) - i128::from(applied_video_delay_ns);
        let residual_max_ns = i128::from(self.maximum_ns) - i128::from(applied_video_delay_ns);
        VideoDelayAdvice {
            requested_delay_ns: self.effective_ns,
            residual_min_ns,
            residual_max_ns,
            within_40ms_bound: residual_min_ns >= -40_000_000 && residual_max_ns <= 40_000_000,
        }
    }
}

/// Constant storage, bounded work (at most eight intervals). Replacing a queue
/// observation updates its stage, rather than accumulating queue depth forever.
#[derive(Debug, Clone)]
pub struct LatencyTimeline {
    context: Context,
    required: u16,
    observed_at_ns: u64,
    max_age_ns: u64,
    stages: [Option<Observation>; STAGE_COUNT],
}

impl LatencyTimeline {
    pub fn new(
        context: Context,
        required: u16,
        observed_at_ns: u64,
        max_age_ns: u64,
    ) -> Result<Self, LatencyError> {
        if required >> STAGE_COUNT != 0 {
            return Err(LatencyError::InvalidStageMask);
        }
        Ok(Self {
            context,
            required: required | Stage::Ingress.bit() | Stage::Output.bit(),
            observed_at_ns,
            max_age_ns,
            stages: [None; STAGE_COUNT],
        })
    }

    pub fn record(&mut self, stage: Stage, observation: Observation) -> Result<(), LatencyError> {
        if observation.context != self.context {
            return Err(LatencyError::ContextMismatch);
        }
        Interval::new(observation.interval.start_ns, observation.interval.end_ns)?;
        // Unknown/unbounded uncertainty must never turn into an exact value.
        observation
            .interval
            .end_ns
            .checked_add(observation.uncertainty_ns)
            .ok_or(LatencyError::Overflow)?;
        self.stages[stage as usize] = Some(observation);
        Ok(())
    }

    pub fn invalidate(&mut self, stage: Stage) {
        self.stages[stage as usize] = None;
    }

    pub fn estimate(&self, current: Context, now_ns: u64) -> Result<LatencyEstimate, LatencyError> {
        if current != self.context {
            return Err(LatencyError::ContextMismatch);
        }
        if now_ns < self.observed_at_ns || now_ns - self.observed_at_ns > self.max_age_ns {
            return Err(LatencyError::StaleSnapshot);
        }
        let present = self.stages.iter().enumerate().fold(0, |mask, (i, item)| {
            mask | if item.is_some() { 1 << i } else { 0 }
        });
        let missing = self.required & !present;
        if missing != 0 {
            return Err(LatencyError::MissingStages(missing));
        }
        let ingress = self.stages[Stage::Ingress as usize]
            .ok_or(LatencyError::MissingStages(Stage::Ingress.bit()))?;
        let output = self.stages[Stage::Output as usize]
            .ok_or(LatencyError::MissingStages(Stage::Output.bit()))?;
        let start = ingress.interval.start_ns;
        let end = output.interval.end_ns;
        if end < start {
            return Err(LatencyError::OutsideTimeline);
        }
        if self
            .stages
            .iter()
            .flatten()
            .any(|item| item.interval.start_ns < start || item.interval.end_ns > end)
        {
            return Err(LatencyError::OutsideTimeline);
        }
        let effective_ns = end - start;
        let uncertainty = ingress
            .uncertainty_ns
            .checked_add(output.uncertainty_ns)
            .ok_or(LatencyError::Overflow)?;
        let accounted_ns = self.union(None);
        let fixed = self.union(Some(DelayKind::Fixed));
        let variable = self.union(Some(DelayKind::Variable));
        let shared_ns =
            u64::try_from(u128::from(fixed) + u128::from(variable) - u128::from(accounted_ns))
                .map_err(|_| LatencyError::Overflow)?;
        let inferred_stages = self.stages.iter().enumerate().fold(0, |mask, (i, item)| {
            mask | if item.is_some_and(|o| o.provenance == Provenance::Inferred) {
                1 << i
            } else {
                0
            }
        });
        Ok(LatencyEstimate {
            context: self.context,
            observed_at_ns: self.observed_at_ns,
            effective_ns,
            minimum_ns: effective_ns.saturating_sub(uncertainty),
            maximum_ns: effective_ns
                .checked_add(uncertainty)
                .ok_or(LatencyError::Overflow)?,
            accounted_ns,
            unaccounted_ns: effective_ns - accounted_ns,
            fixed_only_ns: fixed - shared_ns,
            variable_only_ns: variable - shared_ns,
            shared_ns,
            inferred_stages,
        })
    }

    fn union(&self, kind: Option<DelayKind>) -> u64 {
        let mut intervals = [Interval {
            start_ns: 0,
            end_ns: 0,
        }; STAGE_COUNT];
        let mut count = 0;
        for observation in self.stages.iter().flatten() {
            if kind.is_none_or(|k| k == observation.kind) {
                intervals[count] = observation.interval;
                count += 1;
            }
        }
        intervals[..count].sort_unstable_by_key(|interval| interval.start_ns);
        let mut total = 0;
        let mut cursor = 0;
        for interval in &intervals[..count] {
            let begin = interval.start_ns.max(cursor);
            if interval.end_ns > begin {
                total += interval.end_ns - begin;
            }
            cursor = cursor.max(interval.end_ns);
        }
        total
    }
}
