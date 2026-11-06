//! Group clock and synchronized join, member side (`N03` / `ffw-u07`).
//!
//! A member exchanges authenticated clock probes with the group's coordinator, fits a transform from its own
//! monotonic clock to the group clock, and says how far that transform can be trusted. It is allowed to make
//! sound only after it has locked within an explicit uncertainty, and it falls silent again when the timing it
//! rests on goes stale. Contract: `docs/contracts/n03.md`.
//!
//! What this is, and is not:
//!
//! * **A clock fit, not DAC alignment.** Every result is "the group clock reads X at local time T, give or take
//!   U". Decode, resampler and DSP delay, DMA depth and the DAC pipeline are separate terms the render path adds;
//!   the one board term modelled here is the calibrated output delay and its stated uncertainty
//!   ([`GroupClockConfig::output_delay_ns`], [`GroupClockConfig::calibration_uncertainty_ns`]). A small U here is
//!   not a claim about the speaker cone.
//! * **No promise from an NTP-style offset alone.** The four-timestamp offset is exact only when the two path
//!   delays are equal, which the timestamps cannot show. Its error is bounded by half the exchange delay
//!   (the bias of a path with delays `df` and `dr` is exactly `(df - dr) / 2`), so that half is *in* the
//!   uncertainty, together with twice the timer resolution (the exchange's readings, and the reading the answer is asked
//!   at: a coarse clock shows one value for a whole tick), the board term and growth with age.
//! * **Authenticity is N01's job.** Probes arrive over the authenticated control channel. This module checks what
//!   is left: epoch, leader, request/response pairing (replay), timing sanity and plausibility.
//! * **Standalone.** Plain-typed inputs (`u64` epoch and nanosecond timestamps, as N01 carries them) and no
//!   dependency on the stream or session crates. The D03 rate estimator ([`crate::rate`]) does the frequency
//!   fit; the group timeline is fed to it as a wrapping 48 kHz `u32` frame counter, so counter wrap and
//!   half-range ambiguity are handled by the code that already handles them.

pub use crate::events::EventStats;
use crate::events::{BufferedEvent, EventBuffer};
use crate::rate::{EstimateStatus, Observation, RateConfig, RateError, RateEstimator, ResetReason};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Largest timestamp N01 accepts on the wire (2^62 ns).
pub const MAX_TIMESTAMP_NS: u64 = 1 << 62;
/// The group timeline is fed to the rate estimator as frames at this rate.
pub const FRAME_RATE_HZ: u32 = 48_000;
/// Longest sample window a configuration may ask for.
pub const MAX_WINDOW: u32 = 64;

const NS: i128 = 1_000_000_000;

fn clamp_u64(v: i128) -> u64 {
    u64::try_from(v.max(0)).unwrap_or(u64::MAX)
}

/// Group time as a wrapping `u32` frame counter at 48 kHz (it wraps near 24.86 hours).
#[must_use]
pub fn frame_position(group_ns: u64) -> u32 {
    let frames = u128::from(group_ns) * u128::from(FRAME_RATE_HZ) / 1_000_000_000;
    u32::try_from(frames & 0xFFFF_FFFF).unwrap_or(0)
}

// --------------------------------------------------------------------------------------------- vocabulary

/// Why a probe response was not used. A rejection leaves the fit as it was, with two exceptions that clear it and
/// mute the member: `Discontinuity`, and `LocalClockRegression` between two exchanges (the local clock went back).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeReject {
    /// The response is for an older epoch.
    StaleEpoch,
    /// The response is for a newer epoch than the member has been told about (epochs arrive by control, not by probe).
    FutureEpoch,
    /// The response names a leader the member has not admitted.
    UnadmittedLeader,
    /// No outstanding request has this sequence: unsolicited, already answered (a replay), or long expired.
    UnsolicitedOrReplayed,
    /// The local clock went backwards across the exchange (`t4 < t1`), or stood still for longer than its declared
    /// resolution can hide (equal readings are only a sub-resolution exchange when the dwell the coordinator reports
    /// is below twice the resolution, and never on a clock declared exact); both are sample-level rejects. Or it went
    /// backwards between two exchanges, which clears the fit: nothing measured on the old clock describes the new
    /// readings. Equal readings across two exchanges are not backwards time.
    LocalClockRegression,
    /// The exchange took longer than the request lifetime.
    ExpiredRequest,
    /// Impossible timestamps (out of range, transmit before receive, dwell longer than the round trip).
    Malformed,
    /// The path delay is above the limit; the sample says too little to use.
    ExcessiveDelay,
    /// The sample contradicts the established fit by more than its uncertainty (a clock jump), or the rate
    /// estimator saw one. The fit is cleared and the member is muted until it locks again.
    Discontinuity,
}

impl ProbeReject {
    pub const ALL: [Self; 9] = [
        Self::StaleEpoch,
        Self::FutureEpoch,
        Self::UnadmittedLeader,
        Self::UnsolicitedOrReplayed,
        Self::LocalClockRegression,
        Self::ExpiredRequest,
        Self::Malformed,
        Self::ExcessiveDelay,
        Self::Discontinuity,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StaleEpoch => "StaleEpoch",
            Self::FutureEpoch => "FutureEpoch",
            Self::UnadmittedLeader => "UnadmittedLeader",
            Self::UnsolicitedOrReplayed => "UnsolicitedOrReplayed",
            Self::LocalClockRegression => "LocalClockRegression",
            Self::ExpiredRequest => "ExpiredRequest",
            Self::Malformed => "Malformed",
            Self::ExcessiveDelay => "ExcessiveDelay",
            Self::Discontinuity => "Discontinuity",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::StaleEpoch => 0,
            Self::FutureEpoch => 1,
            Self::UnadmittedLeader => 2,
            Self::UnsolicitedOrReplayed => 3,
            Self::LocalClockRegression => 4,
            Self::ExpiredRequest => 5,
            Self::Malformed => 6,
            Self::ExcessiveDelay => 7,
            Self::Discontinuity => 8,
        }
    }
}

/// Why a scheduled start was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartReject {
    StaleEpoch,
    FutureEpoch,
    NotLocked,
    /// The start is further ahead than the admitted future window.
    TooFarAhead,
    /// The member cannot be ready (muted catch-up needs `catchup_ns`) before the start.
    TooLate,
    /// The clock's uncertainty at the start instant is above the threshold.
    UncertaintyAtStart,
    /// The timing the member would rest on expires before the start.
    ExpiresBeforeStart,
}

impl StartReject {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StaleEpoch => "StaleEpoch",
            Self::FutureEpoch => "FutureEpoch",
            Self::NotLocked => "NotLocked",
            Self::TooFarAhead => "TooFarAhead",
            Self::TooLate => "TooLate",
            Self::UncertaintyAtStart => "UncertaintyAtStart",
            Self::ExpiresBeforeStart => "ExpiresBeforeStart",
        }
    }
}

/// Why the member is muted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MuteReason {
    NotLocked,
    /// Locked, but no start has been admitted (or it was cleared by an expiry or reset).
    NotAdmitted,
    /// Timing went stale: the holdover bound passed or the uncertainty outgrew the threshold.
    ClockExpired,
    AuthorityExpired,
    Discontinuity,
    EpochChange,
    /// The platform clock failed; nothing it says can be trusted.
    ClockFault,
}

impl MuteReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotLocked => "NotLocked",
            Self::NotAdmitted => "NotAdmitted",
            Self::ClockExpired => "ClockExpired",
            Self::AuthorityExpired => "AuthorityExpired",
            Self::Discontinuity => "Discontinuity",
            Self::EpochChange => "EpochChange",
            Self::ClockFault => "ClockFault",
        }
    }
}

/// Which of the three holdover bounds is the smallest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Binding {
    Authority,
    Buffer,
    Uncertainty,
}

impl Binding {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authority => "Authority",
            Self::Buffer => "Buffer",
            Self::Uncertainty => "Uncertainty",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockStatus {
    /// Not enough evidence yet (or none since a reset).
    Unlocked,
    /// Fresh timing, uncertainty within the threshold.
    Locked,
    /// No fresh timing, but still inside the holdover bound.
    Holdover,
    /// Was locked; the holdover bound passed or the uncertainty outgrew the threshold. Needs a rejoin.
    Expired,
}

impl ClockStatus {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unlocked => "Unlocked",
            Self::Locked => "Locked",
            Self::Holdover => "Holdover",
            Self::Expired => "Expired",
        }
    }
}

/// What the member may do with its output right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Muted(MuteReason),
    /// Admitted and catching up silently; sound begins in this many nanoseconds of local time.
    Armed {
        starts_in_ns: u64,
    },
    Audible,
}

impl Output {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Muted(_) => "Muted",
            Self::Armed { .. } => "Armed",
            Self::Audible => "Audible",
        }
    }

    #[must_use]
    pub const fn is_audible(self) -> bool {
        matches!(self, Self::Audible)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupClockError {
    #[error("invalid group clock configuration: {0}")]
    InvalidConfig(String),
    #[error("epoch {requested} does not advance current epoch {current}")]
    EpochNotAdvanced { current: u64, requested: u64 },
    #[error("authority is for epoch {given}, the member is in epoch {current}")]
    WrongEpoch { current: u64, given: u64 },
}

// --------------------------------------------------------------------------------------------- configuration

/// Limits and thresholds. [`GroupClockConfig::standard`] gives the documented defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupClockConfig {
    /// A sample whose path delay is above this is not used.
    pub max_delay_ns: u64,
    /// A request unanswered for this long is dead; its response is `ExpiredRequest`.
    pub request_ttl_ns: u64,
    /// Samples needed before the member can lock.
    pub min_probes_for_lock: u32,
    /// The explicit uncertainty threshold: lock requires the clock's uncertainty at or below this.
    pub lock_uncertainty_ns: u64,
    /// A probe newer than this keeps the status `Locked`; older timing is `Holdover`.
    pub fresh_ns: u64,
    /// Worst-case error of the group-to-local ratio `rho` (group time per unit of local time, `ratio_ppb` is `rho - 1`): the true
    /// `rho` is within this of 1 whatever the rate estimator says. It is the ratio uncertainty used until the estimator has a
    /// usable estimate, and the only rate bound available to a single exchange (see [`Sample::from_exchange`]).
    pub oscillator_bound_ppb: u64,
    /// The rate estimator reports a one-sigma standard error; the ratio uncertainty used here is this many sigmas
    /// plus [`Self::wander_ppb`].
    pub rate_sigma_multiple: u64,
    /// Assumed worst-case change of the oscillator ratio over a whole holdover, added to a usable rate estimate's
    /// own uncertainty. It is an assumption, not a measurement (the default covers the D03 estimator's own aging
    /// allowance, 100 ppb/s over its 60 s holdover).
    pub wander_ppb: u64,
    /// The declared resolution of every reading in an exchange: the member's two local readings and the coordinator's
    /// two group readings are each taken to be the true time rounded down by less than this. A clock coarser than
    /// what is declared here breaks the bounds; declare the coarsest of the member's and the coordinator's. Zero
    /// declares an exact clock, which cannot read the same value before and after a network round trip. It is charged
    /// twice in every uncertainty (the exchange, and the reading the answer is asked at), so a clock whose `2 *
    /// resolution + calibration_uncertainty_ns` is above [`Self::lock_uncertainty_ns`] can never lock.
    pub timer_resolution_ns: u64,
    /// The board's calibration uncertainty (`BoardProfile::calibration_uncertainty_us`).
    pub calibration_uncertainty_ns: u64,
    /// The board's calibrated output delay, subtracted from a scheduled start (`calibrated_output_delay_us`).
    pub output_delay_ns: u64,
    /// How far beyond its uncertainty a new sample may disagree with the fit before it is a clock jump.
    pub prediction_slack_ns: u64,
    /// Only samples whose delay is within this of the best in the window feed the frequency fit.
    pub rate_delay_slack_ns: u64,
    /// Time the member needs, muted, to be ready before a scheduled start.
    pub catchup_ns: u64,
    /// A start further ahead than this is refused.
    pub max_future_ns: u64,
    /// Samples kept (at most [`MAX_WINDOW`]).
    pub window: u32,
    /// Requests that may await a response at once.
    pub max_outstanding: u32,
    /// The D03 rate estimator's configuration (48 kHz).
    pub rate: RateConfig,
}

impl GroupClockConfig {
    /// The documented defaults for a room-group member.
    pub fn standard() -> Result<Self, GroupClockError> {
        let rate = RateConfig::for_rate(FRAME_RATE_HZ)
            .map_err(|e| GroupClockError::InvalidConfig(e.to_string()))?;
        let cfg = Self {
            max_delay_ns: 50_000_000,
            request_ttl_ns: 2_000_000_000,
            min_probes_for_lock: 4,
            lock_uncertainty_ns: 2_000_000,
            fresh_ns: 3_000_000_000,
            oscillator_bound_ppb: 100_000,
            rate_sigma_multiple: 3,
            wander_ppb: 6_000,
            timer_resolution_ns: 1_000,
            calibration_uncertainty_ns: 0,
            output_delay_ns: 0,
            prediction_slack_ns: 500_000,
            rate_delay_slack_ns: 500_000,
            catchup_ns: 100_000_000,
            max_future_ns: 5_000_000_000,
            window: 16,
            max_outstanding: 8,
            rate,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// The defaults with a board's calibrated output delay and calibration uncertainty.
    pub fn for_board(
        profile: &franken_board_profile::BoardProfile,
    ) -> Result<Self, GroupClockError> {
        let mut cfg = Self::standard()?;
        cfg.output_delay_ns = u64::from(profile.calibrated_output_delay_us) * 1_000;
        cfg.calibration_uncertainty_ns = u64::from(profile.calibration_uncertainty_us) * 1_000;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), GroupClockError> {
        let bad = |what: &str| Err(GroupClockError::InvalidConfig(what.to_string()));
        if self.window == 0 || self.window > MAX_WINDOW {
            return bad("window outside 1..=64");
        }
        if self.min_probes_for_lock == 0 || self.min_probes_for_lock > self.window {
            return bad("need 1 <= min_probes_for_lock <= window");
        }
        if self.max_outstanding == 0 || self.max_outstanding > 64 {
            return bad("max_outstanding outside 1..=64");
        }
        if self.lock_uncertainty_ns == 0 || self.fresh_ns == 0 || self.request_ttl_ns == 0 {
            return bad("lock_uncertainty_ns, fresh_ns and request_ttl_ns must be nonzero");
        }
        if self.max_delay_ns > self.request_ttl_ns {
            return bad("max_delay_ns must not exceed request_ttl_ns");
        }
        if self.catchup_ns >= self.max_future_ns {
            return bad("catchup_ns must be below max_future_ns");
        }
        if self.oscillator_bound_ppb > 1_000_000 || self.wander_ppb > 1_000_000 {
            return bad("oscillator_bound_ppb and wander_ppb are limited to 1000 ppm");
        }
        if self.rate_sigma_multiple == 0 || self.rate_sigma_multiple > 10 {
            return bad("rate_sigma_multiple outside 1..=10");
        }
        self.rate
            .validate()
            .map_err(|e| GroupClockError::InvalidConfig(e.to_string()))
    }
}

// --------------------------------------------------------------------------------------------- one exchange

/// A request for the coordinator's time. `t1_local_ns` is the member's monotonic reading when it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub epoch: u64,
    pub seq: u64,
    pub t1_local_ns: u64,
}

/// The coordinator's answer, already authenticated by the control channel. `t2` and `t3` are the coordinator's
/// group-clock readings when it received the request and sent the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub epoch: u64,
    pub leader: u64,
    pub seq: u64,
    /// The request's `t1_local_ns`, echoed back. A response only matches an outstanding request whose sequence
    /// *and* send time it repeats, so a response captured before a restart cannot answer a new request.
    pub t1_echo_ns: u64,
    pub t2_group_ns: u64,
    pub t3_group_ns: u64,
}

/// What one valid exchange tells: its path delay and where its midpoints sit on each clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub delay_ns: u64,
    pub local_mid_ns: u64,
    pub group_mid_ns: u64,
}

impl Sample {
    /// Validate an exchange and reduce it to a sample. `t1` and `t4` are local readings, `t2` and `t3` group
    /// readings. The checks run in this order, which is part of the contract.
    ///
    /// Readings are quantized, so the measured delay `(t4 - t1) - (t3 - t2)` can be negative for an exchange whose
    /// true delay is not: the measured delay differs from the true one by `(e1 + e3) - (e2 + e4)`, each rounding error
    /// `e` in `[0, R)`, so it is above `-2R` whenever the true delay is not negative. A dwell that exceeds the round
    /// trip by **less than** `2R` plus the rate allowance `ceil((rtt + R) * oscillator_bound_ppb / 1e9)` is therefore
    /// consistent with a physical exchange and is admitted with the delay clamped to zero, whether the
    /// readings are equal or differ (an equal-readings exchange is the case of a round trip of zero: a
    /// **sub-resolution exchange**). The rate allowance: the dwell is read on the coordinator's clock and the round trip on the
    /// member's, which run apart by the ratio `rho`, `|rho - 1| <= oscillator_bound_ppb`; the dwell is at most the true round
    /// trip, which in local units is the observed round trip plus up to one hidden tick `R` (the observed one is rounded down by
    /// less than `R`), so the two differ by up to `(rtt + R) * oscillator_bound_ppb`. The tick matters most when the observed
    /// round trip is zero: a local clock 80 ppm slow can read 0 across 4 ms of true time. The resolution in
    /// [`base_uncertainty_ns`] bounds its offset. A dwell that exceeds
    /// the round trip by the bound or more cannot be a rounding: with equal readings the local clock stood still
    /// for longer than its resolution can hide (`LocalClockRegression`), with differing readings the timestamps are
    /// `Malformed`. `t4 < t1` is backwards time on any clock, and a clock declared exact (`timer_resolution_ns == 0`)
    /// cannot read the same value before and after a network round trip: both are `LocalClockRegression`.
    pub fn from_exchange(
        t1: u64,
        t2: u64,
        t3: u64,
        t4: u64,
        cfg: &GroupClockConfig,
    ) -> Result<Self, ProbeReject> {
        let resolution = cfg.timer_resolution_ns;
        if t4 < t1 || (t4 == t1 && resolution == 0) {
            return Err(ProbeReject::LocalClockRegression);
        }
        let rtt = t4 - t1;
        if rtt > cfg.request_ttl_ns {
            return Err(ProbeReject::ExpiredRequest);
        }
        if t3 < t2 || t2 > MAX_TIMESTAMP_NS || t3 > MAX_TIMESTAMP_NS {
            return Err(ProbeReject::Malformed);
        }
        let dwell = t3 - t2;
        let excess = dwell.saturating_sub(rtt);
        let rate_allowance = ((u128::from(rtt) + u128::from(resolution))
            * u128::from(cfg.oscillator_bound_ppb))
        .div_ceil(1_000_000_000);
        let allowed = u128::from(resolution) * 2 + rate_allowance;
        if excess > 0 && u128::from(excess) >= allowed {
            return Err(if rtt == 0 {
                ProbeReject::LocalClockRegression
            } else {
                ProbeReject::Malformed
            });
        }
        let delay = rtt.saturating_sub(dwell);
        if delay > cfg.max_delay_ns {
            return Err(ProbeReject::ExcessiveDelay);
        }
        Ok(Self {
            delay_ns: delay,
            local_mid_ns: t1 + rtt / 2,
            group_mid_ns: t2 + dwell / 2,
        })
    }

    /// Group minus local at the midpoints. Exact only when the two path delays were equal.
    #[must_use]
    pub fn offset_ns(&self) -> i128 {
        i128::from(self.group_mid_ns) - i128::from(self.local_mid_ns)
    }
}

// --------------------------------------------------------------------------------------------- the pure core

/// What a sample cannot know about itself: half its delay (path asymmetry), **twice** the timer resolution, the board term.
///
/// The resolution is charged twice. With the rounding errors `e1..e4` of `t1..t4` in `[0, R)`, the offset the midpoints give
/// is wrong by `(df - dr) / 2` plus `(e1 + e4 - e2 - e3) / 2`, and the measured delay differs from the true one by
/// `(e1 + e3) - (e2 + e4)`; taking the worst path split for either sign of the asymmetry leaves an error strictly below
/// `delay / 2 + R` (below `R` for a measured delay of zero, the sub-resolution case). That is the exchange. The reading the
/// answer is asked at is rounded the same way: a clock that shows `now` shows it for a whole tick, so the true time is up
/// to one more `R` later than `now` says, and the reported group time lags the true one by that much on top (an exact
/// group time at an arbitrary instant of the tick lies in `(-delay/2 - 2R, delay/2 + R)` of the report, a group reading
/// rounded the same way in `(-delay/2 - 2R, delay/2 + 2R)`). So the claim "the true group time at any instant at which the
/// local clock shows `now` is within the uncertainty of the reported group time" needs `2R`, and this is that bound. It is
/// checked by brute force over every phase of small grids in `tests/n03/anchors.py`.
#[must_use]
pub fn base_uncertainty_ns(cfg: &GroupClockConfig, delay_ns: u64) -> u64 {
    delay_ns
        .div_ceil(2)
        .saturating_add(cfg.timer_resolution_ns.saturating_mul(2))
        .saturating_add(cfg.calibration_uncertainty_ns)
}

/// What the second resolution of [`base_uncertainty_ns`], the tick of the reading the answer is asked at, costs more when it
/// is read through the rate. A tick is `R` of local time; the group time that passes during it is `R * rho`, where the group-to-local
/// ratio `rho = 1 + ratio_ppb / 1e9` is the fitted mean rate, true to within `ratio_unc_ppb`. So the lag of a report behind the true
/// time is at most `R * (1 + (ratio_ppb + ratio_unc_ppb) / 1e9)`: the excess over `R` is `ceil(R * (ratio_ppb + ratio_unc_ppb) / 1e9)`,
/// zero if the fastest admitted ratio is not above 1 (the lag is then at most `R`) or for an exact clock. The fitted mean matters
/// as much as its error: at `ratio = +80 ppm` a 100 us tick passes 100 008 ns of group time, which the error alone (6 ppm) does not show.
#[must_use]
pub fn query_tick_rate_excess_ns(
    cfg: &GroupClockConfig,
    ratio_ppb: i64,
    ratio_unc_ppb: u64,
) -> u64 {
    let fastest = i128::from(ratio_ppb) + i128::from(ratio_unc_ppb);
    let Ok(fastest) = u128::try_from(fastest) else {
        return 0;
    };
    let excess = (u128::from(cfg.timer_resolution_ns) * fastest).div_ceil(1_000_000_000);
    u64::try_from(excess).unwrap_or(u64::MAX)
}

/// The sample's uncertainty at local time `at`: its base term, the query tick seen through the fitted ratio `ratio_ppb` and its
/// uncertainty, and growth with age at `ratio_unc_ppb`.
#[must_use]
pub fn uncertainty_at(
    cfg: &GroupClockConfig,
    s: &Sample,
    at: u64,
    ratio_ppb: i64,
    ratio_unc_ppb: u64,
) -> u64 {
    let age = u128::from(at.saturating_sub(s.local_mid_ns));
    let growth = (age * u128::from(ratio_unc_ppb)).div_ceil(1_000_000_000);
    base_uncertainty_ns(cfg, s.delay_ns)
        .saturating_add(query_tick_rate_excess_ns(cfg, ratio_ppb, ratio_unc_ppb))
        .saturating_add(u64::try_from(growth).unwrap_or(u64::MAX))
}

/// What rounding the readings can do to a fitted ratio, in ppb. Each fed observation's offset is off by less than
/// `resolution_ns` from rounding (the exchange's four readings, [`base_uncertainty_ns`]). An ordinary least-squares slope over
/// `observations` points spanning `span_us` has weights `d_i / S` (`d_i` the distance from the mean time, `S` the sum of
/// their squares), so the slope moves by at most `resolution * sum|d_i| / S`. `sum|d_i| <= sqrt(n * S)` (Cauchy-Schwarz)
/// and `S >= span^2 / 2` (the two ends alone), hence at most `resolution * sqrt(2n) / span`, rounded up with the square
/// root rounded up. A constant error (the board term, a steady path asymmetry) cancels in a slope and is not here.
/// Zero for an exact clock; unbounded for a span of zero. It says nothing about the 48 kHz frame position the estimator
/// is fed, which D03 owns.
#[must_use]
pub fn quantization_ratio_ppb(resolution_ns: u64, observations: u32, span_us: u64) -> u64 {
    if resolution_ns == 0 {
        return 0;
    }
    if span_us == 0 {
        return u64::MAX;
    }
    let twice = u64::from(observations) * 2;
    let floor = twice.isqrt();
    let root = if floor * floor < twice {
        floor + 1
    } else {
        floor
    };
    let ppb =
        (u128::from(resolution_ns) * u128::from(root) * 1_000_000).div_ceil(u128::from(span_us));
    u64::try_from(ppb).unwrap_or(u64::MAX)
}

/// A sample chosen as the anchor of the clock transform, with the ratio it is extrapolated by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    pub sample: Sample,
    pub ratio_ppb: i64,
    pub ratio_unc_ppb: u64,
    /// The anchor's uncertainty at the instant it was selected for.
    pub uncertainty_ns: u64,
}

/// The sample with the smallest uncertainty at `now`. Ties go to the newer midpoint, then to the later one.
pub fn select_anchor<'a>(
    cfg: &GroupClockConfig,
    samples: impl IntoIterator<Item = &'a Sample>,
    now: u64,
    ratio_ppb: i64,
    ratio_unc_ppb: u64,
) -> Option<Anchor> {
    let mut best: Option<(u64, u64, Sample)> = None;
    for s in samples {
        let u = uncertainty_at(cfg, s, now, ratio_ppb, ratio_unc_ppb);
        let better = match best {
            None => true,
            Some((bu, bmid, _)) => u < bu || (u == bu && s.local_mid_ns >= bmid),
        };
        if better {
            best = Some((u, s.local_mid_ns, *s));
        }
    }
    best.map(|(u, _, s)| Anchor {
        sample: s,
        ratio_ppb,
        ratio_unc_ppb,
        uncertainty_ns: u,
    })
}

/// The group clock at local time `now`, by the anchor's transform.
#[must_use]
pub fn group_at(a: &Anchor, now: u64) -> u64 {
    let delta = i128::from(now) - i128::from(a.sample.local_mid_ns);
    let scaled = (delta * (NS + i128::from(a.ratio_ppb))).div_euclid(NS);
    clamp_u64(i128::from(a.sample.group_mid_ns) + scaled)
}

/// The local time at which the group clock reads `group_ns`, by the anchor's transform.
#[must_use]
pub fn local_of(a: &Anchor, group_ns: u64) -> u64 {
    let delta = i128::from(group_ns) - i128::from(a.sample.group_mid_ns);
    let denom = (NS + i128::from(a.ratio_ppb)).max(1);
    let scaled = (delta * NS).div_euclid(denom);
    clamp_u64(i128::from(a.sample.local_mid_ns) + scaled)
}

/// How long the member may keep sounding without fresh timing, and what sets the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holdover {
    /// The first local instant at which holdover is NOT allowed.
    pub until_local_ns: u64,
    pub binding: Binding,
}

/// `min(buffer coverage, authority validity, time for the uncertainty to reach the threshold)`. Ties go to
/// Authority, then Buffer, then Uncertainty.
#[must_use]
pub fn holdover_for(
    cfg: &GroupClockConfig,
    a: &Anchor,
    authority_until: Option<u64>,
    buffer_until: Option<u64>,
) -> Holdover {
    let base = base_uncertainty_ns(cfg, a.sample.delay_ns)
        .saturating_add(query_tick_rate_excess_ns(cfg, a.ratio_ppb, a.ratio_unc_ppb));
    let headroom = cfg.lock_uncertainty_ns.saturating_sub(base);
    let unc_until = if a.ratio_unc_ppb == 0 {
        u64::MAX
    } else {
        let span = u128::from(headroom) * 1_000_000_000 / u128::from(a.ratio_unc_ppb);
        u64::try_from(u128::from(a.sample.local_mid_ns) + span + 1).unwrap_or(u64::MAX)
    };
    let mut best = Holdover {
        until_local_ns: unc_until,
        binding: Binding::Uncertainty,
    };
    if let Some(b) = buffer_until
        && b <= best.until_local_ns
    {
        best = Holdover {
            until_local_ns: b,
            binding: Binding::Buffer,
        };
    }
    if let Some(au) = authority_until
        && au <= best.until_local_ns
    {
        best = Holdover {
            until_local_ns: au,
            binding: Binding::Authority,
        };
    }
    best
}

/// A scheduled future start: the group time at which a frame boundary is presented (N01's `presentation_time_ns`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartSchedule {
    pub epoch: u64,
    pub start_group_ns: u64,
}

/// An admitted start: when to begin (local), by when to be ready, and how long the timing behind it is good for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartPlan {
    pub epoch: u64,
    pub start_group_ns: u64,
    pub start_local_ns: u64,
    pub deadline_local_ns: u64,
    pub uncertainty_at_start_ns: u64,
    pub valid_until_local_ns: u64,
    pub binding: Binding,
}

/// Everything [`decide_start`] needs besides the schedule and the configuration.
#[derive(Debug, Clone, Copy)]
pub struct StartContext<'a> {
    pub epoch: u64,
    pub status: ClockStatus,
    pub anchor: &'a Anchor,
    pub now_local_ns: u64,
    pub authority_until: Option<u64>,
    pub buffer_until: Option<u64>,
}

/// The admissible-start decision. The checks run in this order, which is part of the contract.
pub fn decide_start(
    cfg: &GroupClockConfig,
    ctx: &StartContext<'_>,
    sched: StartSchedule,
) -> Result<StartPlan, StartReject> {
    let (a, now) = (ctx.anchor, ctx.now_local_ns);
    if sched.epoch < ctx.epoch {
        return Err(StartReject::StaleEpoch);
    }
    if sched.epoch > ctx.epoch {
        return Err(StartReject::FutureEpoch);
    }
    if ctx.status != ClockStatus::Locked {
        return Err(StartReject::NotLocked);
    }
    let group_now = group_at(a, now);
    if sched.start_group_ns > group_now.saturating_add(cfg.max_future_ns) {
        return Err(StartReject::TooFarAhead);
    }
    let start_local = local_of(a, sched.start_group_ns).saturating_sub(cfg.output_delay_ns);
    let deadline = start_local.saturating_sub(cfg.catchup_ns);
    if now > deadline {
        return Err(StartReject::TooLate);
    }
    let u_start = uncertainty_at(cfg, &a.sample, start_local, a.ratio_ppb, a.ratio_unc_ppb);
    if u_start > cfg.lock_uncertainty_ns {
        return Err(StartReject::UncertaintyAtStart);
    }
    let h = holdover_for(cfg, a, ctx.authority_until, ctx.buffer_until);
    if start_local >= h.until_local_ns {
        return Err(StartReject::ExpiresBeforeStart);
    }
    Ok(StartPlan {
        epoch: ctx.epoch,
        start_group_ns: sched.start_group_ns,
        start_local_ns: start_local,
        deadline_local_ns: deadline,
        uncertainty_at_start_ns: u_start,
        valid_until_local_ns: h.until_local_ns,
        binding: h.binding,
    })
}

// --------------------------------------------------------------------------------------------- the member

/// Counters. `rejected` is indexed by [`ProbeReject`]; read it with [`GroupStats::rejected`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct GroupStats {
    pub probes_sent: u64,
    /// Requests that were pushed out of the outstanding table or expired unanswered.
    pub probes_lost: u64,
    pub accepted: u64,
    pub rejected: [u64; 9],
    /// Full resets of the fit (a clock jump, a local clock regression, a platform clock fault).
    pub resets: u32,
    /// Times the frequency fit alone was restarted because the rate estimator saw a discontinuity.
    pub rate_restarts: u32,
    pub epochs: u32,
}

impl GroupStats {
    #[must_use]
    pub const fn rejected(&self, reason: ProbeReject) -> u64 {
        self.rejected[reason.index()]
    }

    #[must_use]
    pub fn rejected_total(&self) -> u64 {
        self.rejected.iter().sum()
    }
}

/// What an accepted probe changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub delay_ns: u64,
    pub offset_ns: i64,
    pub status: ClockStatus,
}

/// The reading every report carries so nobody mistakes a clock fit for acoustic alignment.
pub const CLAIM: &str = "network-clock-fit-only: not DAC or acoustic alignment";

/// A bounded diagnostic snapshot. `claim` is always [`CLAIM`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClockReport {
    pub epoch: u64,
    pub leader: u64,
    pub status: &'static str,
    pub output: &'static str,
    pub mute_reason: Option<&'static str>,
    pub claim: &'static str,
    pub samples: u32,
    pub accepted: u64,
    pub rejected_total: u64,
    pub uncertainty_ns: Option<u64>,
    pub ratio_ppb: Option<i64>,
    pub ratio_unc_ppb: Option<u64>,
    pub holdover_until_local_ns: Option<u64>,
    pub holdover_binding: Option<&'static str>,
    pub last_accept_age_ns: Option<u64>,
    /// Diagnostic events dropped because the ring was full, and critical ones that could not be stored at all.
    pub events_dropped: u64,
    pub events_critical_lost: u64,
}

/// Events the clock keeps for its owner to pop, in the crate's shared fixed-storage buffer ([`crate::events`]). The
/// buffer never feeds back into any decision: popping it, not popping it, a full buffer or an unavailable one
/// changes nothing the clock decides.
pub const EVENT_RING_CAPACITY: usize = 64;
/// Ordinary events are admitted at most this many per window of the clock's own time; critical events bypass the
/// rate cap but never the storage cap.
pub const EVENT_RATE_PER_WINDOW: u32 = 32;
pub const EVENT_WINDOW_NS: u64 = 1_000_000_000;

/// One thing the clock did or saw, as plain data for a structured log. `kind` and `cause` come from a fixed
/// vocabulary and nothing a peer supplied is copied in; the numbers are this member's own counters, its epoch and
/// nanosecond readings of its own clock. Every event states, in `claim`, that it is a clock-fit claim and not
/// DAC or acoustic alignment. `critical` events (status changes, resets, epochs, truth violations) are the
/// evidence a run cannot be trusted without: a full buffer evicts the oldest ordinary event to keep one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClockEvent {
    pub kind: &'static str,
    pub claim: &'static str,
    /// The member's own monotonic reading when it happened, clamped never to go backwards.
    pub local_ns: u64,
    pub epoch: u64,
    /// Counts events created by this clock, including any later dropped.
    pub revision: u64,
    pub samples: u32,
    /// Exchanges accepted since the last reset, against the `lock_needed` that locks: relock progress "n of 4".
    pub accepted_in_epoch: u32,
    pub lock_needed: u32,
    pub delay_ns: Option<u64>,
    pub uncertainty_ns: Option<u64>,
    /// The estimate minus the known truth, only on `n03.truth.*` events.
    pub error_ns: Option<i64>,
    pub cause: Option<&'static str>,
    pub critical: bool,
}

impl ClockEvent {
    /// A short stable label: the kind, the relock progress for an accepted exchange, and the cause.
    #[must_use]
    pub fn label(&self) -> String {
        let mut label = self.kind.to_string();
        if self.kind == "n03.probe.accepted" {
            label.push_str(&format!("@{}/{}", self.accepted_in_epoch, self.lock_needed));
        }
        if let Some(cause) = self.cause {
            label.push(':');
            label.push_str(cause);
        }
        label
    }
}

#[derive(Debug)]
pub struct GroupClock {
    cfg: GroupClockConfig,
    epoch: u64,
    leader: u64,
    next_seq: u64,
    outstanding: VecDeque<ProbeRequest>,
    samples: VecDeque<Sample>,
    rate: RateEstimator,
    last_fed_us: Option<u64>,
    accepted_in_epoch: u32,
    last_accept_ns: Option<u64>,
    last_t4_ns: Option<u64>,
    lock_seen: bool,
    authority_until: Option<u64>,
    buffer_until: Option<u64>,
    armed: Option<u64>,
    mute: MuteReason,
    stats: GroupStats,
    events: EventBuffer<ClockEvent, EVENT_RING_CAPACITY>,
    revision: u64,
    last_event_ns: u64,
    last_status: ClockStatus,
    last_output: Option<(&'static str, Option<&'static str>)>,
}

fn fresh_rate(cfg: &GroupClockConfig) -> Result<RateEstimator, GroupClockError> {
    RateEstimator::new(cfg.rate.clone()).map_err(|e| GroupClockError::InvalidConfig(e.to_string()))
}

impl GroupClock {
    /// A member in `epoch`, admitting only `leader`. Nothing is carried over from a previous run: a member that
    /// restarts is unlocked and has no outstanding requests, so replayed answers from before are unsolicited.
    /// `seq_base` numbers the first request; take it from the platform entropy source on every boot, so a response
    /// recorded before a restart (it carries a valid MAC) cannot match a request made after it.
    pub fn new(
        cfg: GroupClockConfig,
        epoch: u64,
        leader: u64,
        seq_base: u64,
    ) -> Result<Self, GroupClockError> {
        cfg.validate()?;
        let rate = fresh_rate(&cfg)?;
        Ok(Self {
            cfg,
            epoch,
            leader,
            next_seq: seq_base,
            outstanding: VecDeque::new(),
            samples: VecDeque::new(),
            rate,
            last_fed_us: None,
            accepted_in_epoch: 0,
            last_accept_ns: None,
            last_t4_ns: None,
            lock_seen: false,
            authority_until: None,
            buffer_until: None,
            armed: None,
            mute: MuteReason::NotLocked,
            stats: GroupStats::default(),
            events: EventBuffer::new(EVENT_RATE_PER_WINDOW, EVENT_WINDOW_NS),
            revision: 0,
            last_event_ns: 0,
            last_status: ClockStatus::Unlocked,
            last_output: None,
        })
    }

    #[must_use]
    pub const fn config(&self) -> &GroupClockConfig {
        &self.cfg
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn leader(&self) -> u64 {
        self.leader
    }

    #[must_use]
    pub const fn stats(&self) -> GroupStats {
        self.stats
    }

    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Move to a newer epoch under a (possibly new) leader. The new leader does not inherit the old timestamp
    /// interpretation: every sample, request, the rate fit, the authority and any admitted start are dropped, and
    /// the member is muted until it has locked again and been admitted again.
    pub fn begin_epoch(&mut self, epoch: u64, leader: u64) -> Result<(), GroupClockError> {
        if epoch <= self.epoch {
            return Err(GroupClockError::EpochNotAdvanced {
                current: self.epoch,
                requested: epoch,
            });
        }
        self.epoch = epoch;
        self.leader = leader;
        self.authority_until = None;
        self.clear_timing(MuteReason::EpochChange);
        self.stats.epochs = self.stats.epochs.saturating_add(1);
        let event = self.new_event("n03.epoch.begin", self.last_event_ns, true);
        self.push_event(event);
        self.observe_status(self.last_event_ns);
        Ok(())
    }

    /// The platform clock failed (P02, for example `WentBackwards`). Nothing it said can be trusted: drop the fit and
    /// mute.
    pub fn report_clock_fault(&mut self) {
        self.clear_timing(MuteReason::ClockFault);
        self.stats.resets = self.stats.resets.saturating_add(1);
        let mut event = self.new_event("n03.reset", self.last_event_ns, true);
        event.cause = Some("ClockFault");
        self.push_event(event);
        self.observe_status(self.last_event_ns);
    }

    /// Record the authority's validity for this epoch (`expires_at_local_ns` is a local instant, the way G01's token
    /// check compares it). Holdover never outlasts it, and an admitted start does not survive it.
    pub fn set_authority(
        &mut self,
        epoch: u64,
        expires_at_local_ns: u64,
        now_local_ns: u64,
    ) -> Result<(), GroupClockError> {
        if epoch != self.epoch {
            return Err(GroupClockError::WrongEpoch {
                current: self.epoch,
                given: epoch,
            });
        }
        // An expiry that already passed must clear the admitted start before a renewal can revive it.
        self.settle(now_local_ns);
        self.authority_until = Some(expires_at_local_ns);
        Ok(())
    }

    /// The first local instant at which no audio is queued any more (buffer coverage ends). `None` means the caller
    /// imposes no buffer bound.
    pub fn set_buffer_until(&mut self, until_local_ns: Option<u64>) {
        self.buffer_until = until_local_ns;
    }

    fn clear_timing(&mut self, mute: MuteReason) {
        self.samples.clear();
        self.outstanding.clear();
        self.accepted_in_epoch = 0;
        self.last_accept_ns = None;
        self.last_t4_ns = None;
        self.last_fed_us = None;
        self.lock_seen = false;
        self.armed = None;
        self.mute = mute;
        if let Ok(rate) = fresh_rate(&self.cfg) {
            self.rate = rate;
        }
    }

    fn reject(&mut self, reason: ProbeReject) -> ProbeReject {
        let slot = &mut self.stats.rejected[reason.index()];
        *slot = slot.saturating_add(1);
        reason
    }

    /// Count `reason` and clear the whole fit: the member is muted until it has locked again.
    fn reset_for(&mut self, reason: ProbeReject) -> ProbeReject {
        self.clear_timing(MuteReason::Discontinuity);
        self.stats.resets = self.stats.resets.saturating_add(1);
        self.reject(reason)
    }

    /// Issue the next probe request, sent at local time `now_local_ns`.
    pub fn next_probe(&mut self, now_local_ns: u64) -> ProbeRequest {
        let before = self.outstanding.len();
        let ttl = self.cfg.request_ttl_ns;
        self.outstanding
            .retain(|r| now_local_ns.saturating_sub(r.t1_local_ns) <= ttl);
        let mut lost = before - self.outstanding.len();
        while self.outstanding.len() >= self.cfg.max_outstanding as usize {
            self.outstanding.pop_front();
            lost += 1;
        }
        self.stats.probes_lost = self
            .stats
            .probes_lost
            .saturating_add(u64::try_from(lost).unwrap_or(u64::MAX));
        let request = ProbeRequest {
            epoch: self.epoch,
            seq: self.next_seq,
            t1_local_ns: now_local_ns,
        };
        self.next_seq = self.next_seq.wrapping_add(1);
        self.outstanding.push_back(request);
        self.stats.probes_sent = self.stats.probes_sent.saturating_add(1);
        request
    }

    /// Take one probe response, received at local time `t4_local_ns`. The checks run in this order, which is part
    /// of the contract. A rejection leaves the fit as it was, except `Discontinuity` and a `LocalClockRegression`
    /// between two exchanges, which clear it. Every outcome is also recorded as diagnostic events (see
    /// [`ClockEvent`]); recording never changes the outcome.
    pub fn on_response(
        &mut self,
        resp: ProbeResponse,
        t4_local_ns: u64,
    ) -> Result<Accepted, ProbeReject> {
        let resets_before = self.stats.resets;
        let outcome = self.probe_outcome(resp, t4_local_ns);
        match &outcome {
            Ok(accepted) => {
                let mut event = self.new_event("n03.probe.accepted", t4_local_ns, false);
                event.delay_ns = Some(accepted.delay_ns);
                event.uncertainty_ns = self.anchor_at(t4_local_ns).map(|a| a.uncertainty_ns);
                self.push_event(event);
            }
            Err(reason) => {
                let mut event = self.new_event("n03.probe.rejected", t4_local_ns, false);
                event.cause = Some(reason.code());
                self.push_event(event);
                if self.stats.resets > resets_before {
                    let mut reset = self.new_event("n03.reset", t4_local_ns, true);
                    reset.cause = Some(reason.code());
                    self.push_event(reset);
                }
            }
        }
        self.observe_status(t4_local_ns);
        outcome
    }

    fn probe_outcome(
        &mut self,
        resp: ProbeResponse,
        t4_local_ns: u64,
    ) -> Result<Accepted, ProbeReject> {
        if resp.epoch < self.epoch {
            return Err(self.reject(ProbeReject::StaleEpoch));
        }
        if resp.epoch > self.epoch {
            return Err(self.reject(ProbeReject::FutureEpoch));
        }
        if resp.leader != self.leader {
            return Err(self.reject(ProbeReject::UnadmittedLeader));
        }
        let Some(pos) = self
            .outstanding
            .iter()
            .position(|r| r.seq == resp.seq && r.t1_local_ns == resp.t1_echo_ns)
        else {
            return Err(self.reject(ProbeReject::UnsolicitedOrReplayed));
        };
        let Some(request) = self.outstanding.remove(pos) else {
            return Err(self.reject(ProbeReject::UnsolicitedOrReplayed));
        };
        if self.last_t4_ns.is_some_and(|last| t4_local_ns < last) {
            return Err(self.reset_for(ProbeReject::LocalClockRegression));
        }
        // An expiry that passed before this response must mute before fresh timing can revive the member.
        self.settle(t4_local_ns);
        let sample = Sample::from_exchange(
            request.t1_local_ns,
            resp.t2_group_ns,
            resp.t3_group_ns,
            t4_local_ns,
            &self.cfg,
        )
        .map_err(|reason| self.reject(reason))?;

        // A sample that disagrees with the established fit by more than the fit and the sample can account for is
        // a clock jump (a suspend, a step of the group clock), not noise.
        if let Some(a) = self.anchor_at(t4_local_ns) {
            let predicted = i128::from(group_at(&a, sample.local_mid_ns));
            let diff = (i128::from(sample.group_mid_ns) - predicted).unsigned_abs();
            let allowed = u128::from(uncertainty_at(
                &self.cfg,
                &a.sample,
                sample.local_mid_ns,
                a.ratio_ppb,
                a.ratio_unc_ppb,
            )) + u128::from(sample.delay_ns.div_ceil(2))
                + u128::from(self.cfg.prediction_slack_ns);
            if diff > allowed {
                return Err(self.reset_for(ProbeReject::Discontinuity));
            }
        }

        if self.samples.len() >= self.cfg.window as usize {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        self.accepted_in_epoch = self.accepted_in_epoch.saturating_add(1);
        self.last_accept_ns = Some(t4_local_ns);
        self.last_t4_ns = Some(t4_local_ns);
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        self.feed_rate(&sample);

        let status = self.status(t4_local_ns);
        if status == ClockStatus::Locked {
            self.lock_seen = true;
        }
        Ok(Accepted {
            delay_ns: sample.delay_ns,
            offset_ns: i64::try_from(sample.offset_ns()).unwrap_or(i64::MAX),
            status,
        })
    }

    /// Only good samples feed the frequency fit: a delayed exchange is mostly path asymmetry. A discontinuity the
    /// rate estimator reports restarts the frequency fit alone, never the offset fit (an offset step is judged by the
    /// prediction check above, which is what clears the clock).
    fn feed_rate(&mut self, sample: &Sample) {
        let best_delay = self
            .samples
            .iter()
            .map(|s| s.delay_ns)
            .min()
            .unwrap_or(sample.delay_ns);
        let local_us = sample.local_mid_ns / 1_000;
        let advances = self.last_fed_us.is_none_or(|last| local_us > last);
        if !advances || sample.delay_ns > best_delay.saturating_add(self.cfg.rate_delay_slack_ns) {
            return;
        }
        let obs = Observation {
            position: frame_position(sample.group_mid_ns),
            local_us,
        };
        let reason = match self.rate.observe(obs) {
            Ok(()) => {
                self.last_fed_us = Some(local_us);
                return;
            }
            Err(RateError::Discontinuity(why)) => ResetReason::Discontinuity(why),
            Err(_) => ResetReason::Rejoin,
        };
        let next = self.rate.epoch().wrapping_add(1);
        self.last_fed_us = None;
        if self.rate.begin_epoch(next, reason).is_ok() {
            self.stats.rate_restarts = self.stats.rate_restarts.saturating_add(1);
            if self.rate.observe(obs).is_ok() {
                self.last_fed_us = Some(local_us);
            }
        }
    }

    /// The rate estimator's ratio and its uncertainty, if it has a usable estimate as of its newest observation: `Valid`,
    /// and with a quantization bound ([`quantization_ratio_ppb`]) that does not exceed the oscillator's own worst case.
    /// The uncertainty is the larger of the estimator's statistical one (sigmas plus wander) and the quantization bound,
    /// which are two bounds on one error and are not added. A fit that cannot beat the oscillator's worst case is not in
    /// force.
    fn usable_rate(&self) -> Option<(i64, u64)> {
        let e = self
            .rate
            .estimate()
            .filter(|e| e.status == EstimateStatus::Valid)?;
        let quantization =
            quantization_ratio_ppb(self.cfg.timer_resolution_ns, e.observations, e.span_us);
        if quantization > self.cfg.oscillator_bound_ppb {
            return None;
        }
        let statistical = e
            .uncertainty_ppb
            .saturating_mul(self.cfg.rate_sigma_multiple)
            .saturating_add(self.cfg.wander_ppb);
        Some((e.correction_ppb, statistical.max(quantization)))
    }

    /// The ratio of group time to local time and its uncertainty: the rate estimator's if it is usable, otherwise
    /// zero with the oscillator's worst-case bound. It does not depend on the time asked about: only a new probe
    /// changes it, so holdover and start planning can be computed in closed form.
    fn ratio_state(&self) -> (i64, u64) {
        self.usable_rate()
            .unwrap_or((0, self.cfg.oscillator_bound_ppb))
    }

    fn anchor_at(&self, now_local_ns: u64) -> Option<Anchor> {
        let (ratio_ppb, ratio_unc_ppb) = self.ratio_state();
        select_anchor(
            &self.cfg,
            self.samples.iter(),
            now_local_ns,
            ratio_ppb,
            ratio_unc_ppb,
        )
    }

    /// Where the clock stands at local time `now`.
    #[must_use]
    pub fn status(&self, now_local_ns: u64) -> ClockStatus {
        if self.accepted_in_epoch < self.cfg.min_probes_for_lock {
            return ClockStatus::Unlocked;
        }
        let Some(a) = self.anchor_at(now_local_ns) else {
            return ClockStatus::Unlocked;
        };
        if a.uncertainty_ns > self.cfg.lock_uncertainty_ns {
            return if self.lock_seen {
                ClockStatus::Expired
            } else {
                ClockStatus::Unlocked
            };
        }
        let age = now_local_ns.saturating_sub(self.last_accept_ns.unwrap_or(0));
        if age <= self.cfg.fresh_ns {
            return ClockStatus::Locked;
        }
        if !self.lock_seen {
            return ClockStatus::Unlocked;
        }
        let h = holdover_for(&self.cfg, &a, self.authority_until, self.buffer_until);
        if now_local_ns < h.until_local_ns {
            ClockStatus::Holdover
        } else {
            ClockStatus::Expired
        }
    }

    /// The transform in force at local time `now`: the anchor sample, ratio and uncertainty. `None` until a sample
    /// exists. A reading says nothing about whether the member may sound: ask [`Self::status`].
    #[must_use]
    pub fn reading(&self, now_local_ns: u64) -> Option<Anchor> {
        self.anchor_at(now_local_ns)
    }

    /// The group clock at local time `now`.
    #[must_use]
    pub fn group_ns(&self, now_local_ns: u64) -> Option<u64> {
        self.anchor_at(now_local_ns)
            .map(|a| group_at(&a, now_local_ns))
    }

    /// The local time at which the group clock reads `group_ns`, by the transform chosen at `now`.
    #[must_use]
    pub fn local_for_group(&self, group_ns: u64, now_local_ns: u64) -> Option<u64> {
        self.anchor_at(now_local_ns).map(|a| local_of(&a, group_ns))
    }

    /// How long timing may go stale before the member must mute, and which bound sets it.
    #[must_use]
    pub fn holdover(&self, now_local_ns: u64) -> Option<Holdover> {
        self.anchor_at(now_local_ns)
            .map(|a| holdover_for(&self.cfg, &a, self.authority_until, self.buffer_until))
    }

    /// Whether a scheduled future start could be admitted now (a pure query).
    pub fn plan_start(
        &self,
        sched: StartSchedule,
        now_local_ns: u64,
    ) -> Result<StartPlan, StartReject> {
        let status = self.status(now_local_ns);
        let Some(anchor) = self.anchor_at(now_local_ns) else {
            return Err(StartReject::NotLocked);
        };
        let ctx = StartContext {
            epoch: self.epoch,
            status,
            anchor: &anchor,
            now_local_ns,
            authority_until: self.authority_until,
            buffer_until: self.buffer_until,
        };
        decide_start(&self.cfg, &ctx, sched)
    }

    /// Admit a scheduled start: the member stays muted, catching up, until the group clock reaches it. Refused with
    /// the same reasons as [`Self::plan_start`], and then nothing changes.
    pub fn admit(
        &mut self,
        sched: StartSchedule,
        now_local_ns: u64,
    ) -> Result<StartPlan, StartReject> {
        self.settle(now_local_ns);
        match self.plan_start(sched, now_local_ns) {
            Ok(plan) => {
                self.armed = Some(plan.start_group_ns);
                let mut event = self.new_event("n03.admit.accepted", now_local_ns, false);
                event.uncertainty_ns = Some(plan.uncertainty_at_start_ns);
                self.push_event(event);
                Ok(plan)
            }
            Err(reason) => {
                let mut event = self.new_event("n03.admit.rejected", now_local_ns, false);
                event.cause = Some(reason.code());
                self.push_event(event);
                Err(reason)
            }
        }
    }

    /// Apply to the state what has become true by local time `now`: a stale clock, an expired authority or a reset
    /// clears any admitted start, so sound returns only after a fresh lock and a fresh admission (muted catch-up).
    fn settle(&mut self, now_local_ns: u64) -> ClockStatus {
        let status = self.status(now_local_ns);
        match status {
            ClockStatus::Unlocked => self.armed = None,
            ClockStatus::Expired => {
                self.armed = None;
                self.mute = MuteReason::ClockExpired;
            }
            ClockStatus::Locked | ClockStatus::Holdover => {
                if self
                    .authority_until
                    .is_some_and(|expiry| now_local_ns >= expiry)
                {
                    self.armed = None;
                    self.mute = MuteReason::AuthorityExpired;
                } else if self.armed.is_none() {
                    self.mute = MuteReason::NotAdmitted;
                }
            }
        }
        status
    }

    fn output_at(&self, status: ClockStatus, now_local_ns: u64) -> Output {
        match status {
            ClockStatus::Unlocked => Output::Muted(match self.mute {
                MuteReason::Discontinuity | MuteReason::EpochChange | MuteReason::ClockFault => {
                    self.mute
                }
                _ => MuteReason::NotLocked,
            }),
            ClockStatus::Expired => Output::Muted(MuteReason::ClockExpired),
            ClockStatus::Locked | ClockStatus::Holdover => {
                if self
                    .authority_until
                    .is_some_and(|expiry| now_local_ns >= expiry)
                {
                    return Output::Muted(MuteReason::AuthorityExpired);
                }
                let Some(start_group) = self.armed else {
                    return Output::Muted(MuteReason::NotAdmitted);
                };
                let group_now = self.group_ns(now_local_ns).unwrap_or(0);
                let target = start_group.saturating_sub(self.cfg.output_delay_ns);
                if group_now < target {
                    Output::Armed {
                        starts_in_ns: target - group_now,
                    }
                } else {
                    Output::Audible
                }
            }
        }
    }

    /// Advance to local time `now` and say what the output may do. Sound needs a locked (or in-holdover) clock, a
    /// valid authority and an admitted start that the group clock has reached. Everything else is muted.
    pub fn tick(&mut self, now_local_ns: u64) -> Output {
        let status = self.settle(now_local_ns);
        let output = self.output_at(status, now_local_ns);
        self.observe_status(now_local_ns);
        self.observe_output(output, now_local_ns);
        output
    }

    /// What the output may do at local time `now`, with no side effects (unlike [`Self::tick`], it does not clear an
    /// admitted start that has gone stale; the answer is the same).
    #[must_use]
    pub fn output(&self, now_local_ns: u64) -> Output {
        self.output_at(self.status(now_local_ns), now_local_ns)
    }

    /// Whether the frequency fit currently has a usable estimate (otherwise the oscillator bound is in force).
    #[must_use]
    pub fn rate_in_force(&self) -> bool {
        self.usable_rate().is_some()
    }

    /// A bounded diagnostic snapshot at local time `now`, with no side effects. Never a claim about the DAC.
    #[must_use]
    pub fn report(&self, now_local_ns: u64) -> ClockReport {
        let status = self.status(now_local_ns);
        let output = self.output_at(status, now_local_ns);
        let anchor = self.anchor_at(now_local_ns);
        let hold = anchor
            .as_ref()
            .map(|a| holdover_for(&self.cfg, a, self.authority_until, self.buffer_until));
        ClockReport {
            epoch: self.epoch,
            leader: self.leader,
            status: status.code(),
            output: output.code(),
            mute_reason: match output {
                Output::Muted(reason) => Some(reason.code()),
                _ => None,
            },
            claim: CLAIM,
            samples: u32::try_from(self.samples.len()).unwrap_or(u32::MAX),
            accepted: self.stats.accepted,
            rejected_total: self.stats.rejected_total(),
            uncertainty_ns: anchor.map(|a| a.uncertainty_ns),
            ratio_ppb: anchor.map(|a| a.ratio_ppb),
            ratio_unc_ppb: anchor.map(|a| a.ratio_unc_ppb),
            holdover_until_local_ns: hold.map(|h| h.until_local_ns),
            holdover_binding: hold.map(|h| h.binding.code()),
            last_accept_age_ns: self.last_accept_ns.map(|t| now_local_ns.saturating_sub(t)),
            events_dropped: self.events.stats().dropped,
            events_critical_lost: self.events.stats().critical_lost,
        }
    }
}

// ---- diagnostics: events in the shared fixed-storage buffer ------------------------------------------------

impl GroupClock {
    /// Take the oldest pending event. The buffer holds at most [`EVENT_RING_CAPACITY`] events; an owner that never
    /// pops only increases the dropped count, and no decision changes.
    pub fn pop_event(&mut self) -> Option<BufferedEvent<ClockEvent>> {
        self.events.pop()
    }

    /// Exact accounting of the buffer: `emitted == delivered + pending + dropped`, with `critical_lost` (a subset
    /// of `dropped`) counting evidence that could not be kept.
    #[must_use]
    pub const fn event_stats(&self) -> EventStats {
        self.events.stats()
    }

    #[must_use]
    pub const fn pending_events(&self) -> usize {
        self.events.pending()
    }

    /// Model an unavailable log (the subsystem that carries the events is down): events are then counted as
    /// dropped, critical ones as lost, and no decision changes.
    pub fn set_events_available(&mut self, available: bool) {
        self.events.set_available(available);
    }

    /// Record the estimated error against a truth the owner knows (a test world, a reference clock): the clock's
    /// group time at local time `now` minus `true_group_ns`, against the uncertainty it reported. Returns the
    /// signed error, or `None` while there is no estimate. A true time outside the reported uncertainty is a
    /// critical `n03.truth.violated` event.
    pub fn note_truth(&mut self, now_local_ns: u64, true_group_ns: u64) -> Option<i64> {
        let anchor = self.anchor_at(now_local_ns)?;
        let estimate = group_at(&anchor, now_local_ns);
        let raw = i128::from(estimate) - i128::from(true_group_ns);
        let error = i64::try_from(raw.clamp(i128::from(i64::MIN), i128::from(i64::MAX)))
            .unwrap_or(i64::MAX);
        let within = error.unsigned_abs() <= anchor.uncertainty_ns;
        let kind = if within {
            "n03.truth.within"
        } else {
            "n03.truth.violated"
        };
        let mut event = self.new_event(kind, now_local_ns, !within);
        event.uncertainty_ns = Some(anchor.uncertainty_ns);
        event.error_ns = Some(error);
        self.push_event(event);
        Some(error)
    }

    fn new_event(&mut self, kind: &'static str, now_ns: u64, critical: bool) -> ClockEvent {
        self.revision = self.revision.saturating_add(1);
        let local_ns = now_ns.max(self.last_event_ns);
        self.last_event_ns = local_ns;
        ClockEvent {
            kind,
            claim: CLAIM,
            local_ns,
            epoch: self.epoch,
            revision: self.revision,
            samples: u32::try_from(self.samples.len()).unwrap_or(u32::MAX),
            accepted_in_epoch: self.accepted_in_epoch,
            lock_needed: self.cfg.min_probes_for_lock,
            delay_ns: None,
            uncertainty_ns: None,
            error_ns: None,
            cause: None,
            critical,
        }
    }

    /// Hand an event to the shared buffer, which stores it or counts it; it never blocks. Ordinary events are rate-
    /// and capacity-limited; a critical one bypasses the rate cap and evicts the oldest ordinary event when full,
    /// and is counted lost only when the buffer holds nothing but critical events.
    fn push_event(&mut self, event: ClockEvent) {
        if event.critical {
            self.events.try_emit_critical(event.local_ns, event);
        } else {
            self.events.try_emit(event.local_ns, event);
        }
    }

    /// Record a change of status since the last observation: lock gained, holdover entered (and which limit binds
    /// it), expiry, or back to unlocked.
    fn observe_status(&mut self, now_ns: u64) {
        let status = self.status(now_ns);
        if status == self.last_status {
            return;
        }
        let kind = match status {
            ClockStatus::Unlocked => "n03.status.unlocked",
            ClockStatus::Locked => "n03.status.locked",
            ClockStatus::Holdover => "n03.status.holdover",
            ClockStatus::Expired => "n03.status.expired",
        };
        let mut event = self.new_event(kind, now_ns, true);
        event.uncertainty_ns = self.anchor_at(now_ns).map(|a| a.uncertainty_ns);
        if status == ClockStatus::Holdover {
            event.cause = self.holdover(now_ns).map(|h| h.binding.code());
        }
        self.push_event(event);
        self.last_status = status;
    }

    /// Record a change in what the output may do (muted with a reason, armed, audible).
    fn observe_output(&mut self, output: Output, now_ns: u64) {
        let reason = match output {
            Output::Muted(reason) => Some(reason.code()),
            _ => None,
        };
        let key = (output.code(), reason);
        if self.last_output == Some(key) {
            return;
        }
        let kind = match output {
            Output::Muted(_) => "n03.output.muted",
            Output::Armed { .. } => "n03.output.armed",
            Output::Audible => "n03.output.audible",
        };
        let mut event = self.new_event(kind, now_ns, false);
        event.cause = reason;
        self.push_event(event);
        self.last_output = Some(key);
    }
}

// ---- the production `ffw.log.v1` line ----------------------------------------------------------------------

/// The schema every diagnostic line follows; the same shape as `franken-test-support`'s `DiagnosticEvent`, which
/// only a test links.
pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";
/// No line is longer than this (with its newline); a longer one is refused, never truncated.
pub const MAX_LOG_LINE_BYTES: usize = 1024;
/// Longest label in a [`LogContext`].
pub const MAX_LABEL_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogContextError {
    #[error(
        "`{field}` must be 1 to 64 bytes of a-z, 0-9, '.', '_' and '-', starting with a letter or digit"
    )]
    InvalidLabel { field: &'static str },
}

fn valid_label(raw: &str) -> bool {
    let starts_ok = raw
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    starts_ok
        && raw.len() <= MAX_LABEL_LEN
        && raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// Who is speaking in a log line: labels the owner chooses, never data from a peer. The member and group labels are
/// the owner's pseudonyms (for example `p-` and sixteen hex digits from a keyed hash); `franken-clock` does no
/// hashing and never sees a real identifier. `fault` names the injected fault schedule entry in force, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogContext {
    run_id: String,
    case_id: String,
    member: String,
    group: String,
    fault: Option<String>,
}

impl LogContext {
    pub fn new(
        run_id: &str,
        case_id: &str,
        member: &str,
        group: &str,
        fault: Option<&str>,
    ) -> Result<Self, LogContextError> {
        let checks = [
            ("run_id", run_id),
            ("case_id", case_id),
            ("member", member),
            ("group", group),
        ];
        for (field, value) in checks {
            if !valid_label(value) {
                return Err(LogContextError::InvalidLabel { field });
            }
        }
        if fault.is_some_and(|f| !valid_label(f)) {
            return Err(LogContextError::InvalidLabel { field: "fault" });
        }
        Ok(Self {
            run_id: run_id.to_string(),
            case_id: case_id.to_string(),
            member: member.to_string(),
            group: group.to_string(),
            fault: fault.map(str::to_string),
        })
    }
}

/// Field order is the order of `DiagnosticEvent`, so the bytes are the same as serializing one.
#[derive(Serialize)]
struct LogRecord<'a> {
    schema_version: &'static str,
    timestamp_mono_ns: u64,
    run_id: &'a str,
    case_id: &'a str,
    correlation_id: String,
    member_id: &'a str,
    group_id: &'a str,
    source_epoch: u64,
    state_revision: u64,
    event_kind: &'static str,
    message: String,
    queue_depth: u64,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fault: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'static str>,
}

impl ClockEvent {
    /// One `ffw.log.v1` line (no trailing newline) for this event, or `None` if it would exceed
    /// [`MAX_LOG_LINE_BYTES`] (the caller counts that as a dropped event). The text fields are built only from the
    /// fixed vocabulary, the claim and numbers; nothing a peer supplied can reach them.
    #[must_use]
    pub fn to_log_line(&self, ctx: &LogContext) -> Option<String> {
        let number = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |n| n.to_string());
        let error = self
            .error_ns
            .map_or_else(|| "-".to_string(), |n| n.to_string());
        let message = format!(
            "{}; samples={} accepted={}/{} delay_ns={} unc_ns={} err_ns={}",
            self.claim,
            self.samples,
            self.accepted_in_epoch,
            self.lock_needed,
            number(self.delay_ns),
            number(self.uncertainty_ns),
            error
        );
        let record = LogRecord {
            schema_version: LOG_SCHEMA_VERSION,
            timestamp_mono_ns: self.local_ns,
            run_id: &ctx.run_id,
            case_id: &ctx.case_id,
            correlation_id: format!("{}#{}", ctx.member, self.revision),
            member_id: &ctx.member,
            group_id: &ctx.group,
            source_epoch: self.epoch,
            state_revision: self.revision,
            event_kind: self.kind,
            message,
            queue_depth: u64::from(self.samples),
            latency_us: self.delay_ns.unwrap_or(0) / 1_000,
            fault: ctx.fault.as_deref(),
            cause: self.cause,
        };
        serde_json::to_string(&record)
            .ok()
            .filter(|line| line.len() < MAX_LOG_LINE_BYTES)
    }
}

#[cfg(test)]
mod tests;
