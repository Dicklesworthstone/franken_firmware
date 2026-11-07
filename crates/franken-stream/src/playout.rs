//! Bounded playout engine with a `consume_by` cutoff, exactly-once decisions, bounded concealment and
//! coordinated latency changes (`N04` / `ffw-nx0`).
//!
//! The contract is `docs/contracts/n04.md`; `tests/n04/reference.py` restates it as exact-integer Python and
//! `tests/n04/run_cases.py` holds this module to it. Nothing here reads a clock: every call carries a
//! [`ClockView`] built by the caller from the group clock (N03 `GroupClock::group_ns` and
//! `ClockReport::uncertainty_ns`, usable while the status is Locked or Holdover).
//!
//! One decision per block, taken once, at the cutoff
//! `consume_by = presentation - downstream work - submission lead - clock uncertainty`:
//! a block that arrived strictly before the cutoff is real, one that did not is concealed (a bounded number
//! of times, then muted). A packet or repair that arrives at or after the cutoff is late and is never played,
//! even if the DAC presentation time is still ahead. The sender's own `consume_by_ns` header field is not
//! used: it cannot know this board's costs, and a sender must not be able to extend a receiver's deadline.
//!
//! Memory is fixed at construction (`horizon_blocks` slots of one block each); the consume path allocates
//! nothing and copies at most one block per call. Latency changes are accepted only from the control channel
//! ([`PlayoutEngine::apply_change`]) and are bounded per step and in net.
//!
//! A caller that owns a memory ledger builds the engine with [`PlayoutEngine::new_within`]: the profile's footprint
//! ([`PlayoutEngine::resident_bytes`]) is checked against the budget it offers, and a profile that does not fit is refused with a
//! typed [`CapacityError`] before anything is allocated.

use serde::Serialize;

mod log;

pub use log::{
    DrainReport, DrainStop, LOG_SCHEMA, LogConfig, LogConfigError, LogSink, LogStats,
    MAX_LABEL_LEN, MAX_LINE_BYTES, SinkReply,
};

/// Frames in a full block (N01 `start_frame` granularity).
pub const BLOCK_FRAMES: u64 = 256;
/// Bytes of a full block of 16-bit big-endian stereo PCM.
pub const BLOCK_PAYLOAD_BYTES: usize = 1024;
/// Upper bound of any timestamp (N01).
pub const MAX_TIMESTAMP_NS: u64 = 1 << 62;
/// `floor(256 * 1e9 / 48000)`: the unit latency advice counts in.
pub const BLOCK_NS: u64 = 5_333_333;
/// Decided blocks remembered, to tell a duplicate of a played block from a late arrival.
pub const HISTORY_BLOCKS: usize = 128;
/// Arrival margins kept for latency advice.
pub const MARGIN_WINDOW: usize = 64;
const ADVICE_MIN_EVENTS: usize = 16;
const ADVICE_LATE_TRIGGER: usize = 2;
const ADVICE_KEEP_BLOCKS: i64 = 3;
/// `round(0.7^n * 32768)` for n = 1..=8: the Q15 attenuation of the n-th concealed block.
pub const CONCEAL_GAIN_Q15: [i32; 8] = [22938, 16056, 11239, 7868, 5507, 3855, 2699, 1889];
/// Version of the frozen profile table below.
pub const PROFILE_VERSION: &str = "n04.profiles.v1";

const H_NONE: u8 = 0;
const H_REAL: u8 = 1;
const H_CONCEALED: u8 = 2;
const H_MUTED: u8 = 3;
const H_SKIPPED: u8 = 4;

/// `floor(frames * 1e9 / 48000)`: the exact frame-to-time mapping (62500 / 3 ns per frame).
#[must_use]
pub fn frames_to_ns(frames: u64) -> u64 {
    clamp_u64(u128::from(frames) * 62_500 / 3)
}

/// `presentation - (work + lead + uncertainty)`, clamped at zero.
#[must_use]
pub fn consume_by(presentation_ns: u64, work_ns: u64, lead_ns: u64, uncertainty_ns: u64) -> u64 {
    presentation_ns.saturating_sub(
        work_ns
            .saturating_add(lead_ns)
            .saturating_add(uncertainty_ns),
    )
}

fn clamp_u64(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

fn clamp_i64(v: i128) -> i64 {
    i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX })
}

/// The `run`-th (1-based, at most 8) concealed block: every 16-bit sample of `last` scaled by the Q15 gain for
/// `run`, rounding half up (floor shift). `last` is a whole block (a shorter final block is zero padded).
pub fn conceal_block(
    last: &[u8; BLOCK_PAYLOAD_BYTES],
    run: u8,
    out: &mut [u8; BLOCK_PAYLOAD_BYTES],
) {
    let gain = CONCEAL_GAIN_Q15[usize::from(run.clamp(1, 8)) - 1];
    // Both buffers are exactly 1024 bytes, an even count: the remainder of each split is always empty, so every
    // byte is a sample byte, as with the `chunks_exact` this replaced.
    let (src_samples, _) = last.as_chunks::<2>();
    let (dst_samples, _) = out.as_chunks_mut::<2>();
    for (src, dst) in src_samples.iter().zip(dst_samples.iter_mut()) {
        let s = i32::from(i16::from_be_bytes(*src));
        let v = (s * gain + 16384) >> 15;
        *dst = i16::try_from(v).unwrap_or(0).to_be_bytes();
    }
}

/// Fixed caps of a playout policy. Provisional engineering parameters, not measurements; changing one is a new
/// [`PROFILE_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlayoutProfile {
    pub name: &'static str,
    /// Blocks admissible ahead of the cursor (and the number of slots).
    pub horizon_blocks: u16,
    /// Consecutive blocks concealed before the output is muted.
    pub max_conceal_blocks: u8,
    /// A coordinated latency change must take effect at least this many blocks ahead.
    pub notice_blocks: u16,
    /// Largest single latency step, in blocks.
    pub max_step_blocks: u16,
    /// Largest net latency shift from the stream's start, either direction, in blocks.
    pub max_net_blocks: u16,
}

impl PlayoutProfile {
    /// 500 ms playout horizon (94 blocks).
    pub const MUSIC: Self = Self {
        name: "music",
        horizon_blocks: 94,
        max_conceal_blocks: 8,
        notice_blocks: 8,
        max_step_blocks: 38,
        max_net_blocks: 94,
    };
    /// 45 ms-class low-latency horizon (9 blocks), for video-synchronised sources.
    pub const REALTIME: Self = Self {
        name: "realtime",
        horizon_blocks: 9,
        max_conceal_blocks: 3,
        notice_blocks: 2,
        max_step_blocks: 4,
        max_net_blocks: 9,
    };

    fn net_cap_ns(&self) -> i128 {
        i128::from(frames_to_ns(u64::from(self.max_net_blocks) * BLOCK_FRAMES))
    }

    fn step_cap_ns(&self) -> i128 {
        i128::from(frames_to_ns(u64::from(self.max_step_blocks) * BLOCK_FRAMES))
    }
}

/// The receiver's admitted downstream costs and tolerances. All times are group-clock nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlayoutConfig {
    /// Admitted DSP and conversion work between the cutoff and the device submission. Must be positive.
    pub work_ns: u64,
    /// Device submission lead before the presentation time. Must be positive.
    pub lead_ns: u64,
    /// How far a packet's header presentation time may differ from the agreed timeline (below half a block).
    pub tolerance_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    WorkNotPositive,
    LeadNotPositive,
    ToleranceTooLarge,
}

impl ConfigError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WorkNotPositive => "work_ns",
            Self::LeadNotPositive => "lead_ns",
            Self::ToleranceTooLarge => "tolerance_ns",
        }
    }
}

impl PlayoutConfig {
    /// # Errors
    /// Names the first invalid field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.work_ns < 1 {
            Err(ConfigError::WorkNotPositive)
        } else if self.lead_ns < 1 {
            Err(ConfigError::LeadNotPositive)
        } else if self.tolerance_ns >= BLOCK_NS / 2 {
            Err(ConfigError::ToleranceTooLarge)
        } else {
            Ok(())
        }
    }
}

/// A profile that does not fit the memory the caller offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityError {
    /// Bytes the engine would occupy: [`PlayoutEngine::resident_bytes`] of the profile.
    pub needed_bytes: usize,
    /// Bytes the caller offered.
    pub budget_bytes: usize,
}

/// The allocator could not give memory the budget had admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationError {
    /// Bytes that were asked for.
    pub requested_bytes: usize,
}

/// Why [`PlayoutEngine::new_within`] built nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    /// The configuration is invalid. It is judged first, whatever the budget.
    Config(ConfigError),
    /// The profile does not fit the budget.
    Capacity(CapacityError),
    /// The profile fits the budget but the allocator could not give the memory.
    Allocation(AllocationError),
}

impl AdmitError {
    /// A stable name: the invalid configuration field, or `capacity`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Config(error) => error.code(),
            Self::Capacity(_) => "capacity",
            Self::Allocation(_) => "allocation",
        }
    }
}

/// What the group clock says at the moment of a call (built by the caller from N03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockView {
    /// The group clock now.
    pub group_ns: u64,
    /// The clock's uncertainty now (`ClockReport::uncertainty_ns`); the cutoff moves earlier by exactly this.
    pub uncertainty_ns: u64,
    /// False unless the clock may be used (N03 status Locked or Holdover).
    pub usable: bool,
}

/// A media block as the engine sees it (from an authenticated N01 packet).
#[derive(Debug, Clone, Copy)]
pub struct MediaPacket<'a> {
    pub epoch: u64,
    pub start_frame: u64,
    pub presentation_ns: u64,
    pub frames: u32,
    pub payload: &'a [u8],
}

impl<'a> MediaPacket<'a> {
    /// The engine's view of an N01 packet, or `None` for a repair packet. The caller must have obtained the
    /// packet from `StreamReceiver::accept`; the sender's `consume_by_ns` is deliberately dropped.
    #[must_use]
    pub fn from_authenticated(pkt: &'a crate::AuthenticatedStreamPacket) -> Option<Self> {
        (pkt.kind == crate::PacketKind::Media).then(|| Self {
            epoch: pkt.session_epoch,
            start_frame: pkt.start_frame,
            presentation_ns: pkt.presentation_time_ns,
            frames: u32::try_from(pkt.payload.len() / 4).unwrap_or(u32::MAX),
            payload: &pkt.payload,
        })
    }
}

/// A block recovered by repair (N05/N06). It has no header of its own, so no timeline check; the same cutoff.
#[derive(Debug, Clone, Copy)]
pub struct RepairBlock<'a> {
    pub epoch: u64,
    pub start_frame: u64,
    pub frames: u32,
    pub payload: &'a [u8],
}

/// What happened to an arriving packet or repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    NotBound,
    StaleEpoch,
    FutureEpoch,
    ClockUnusable,
    ClockRegression,
    BadInput,
    Duplicate,
    Late,
    TooFarAhead,
    TimelineMismatch,
}

impl Admission {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::NotBound => "not_bound",
            Self::StaleEpoch => "stale_epoch",
            Self::FutureEpoch => "future_epoch",
            Self::ClockUnusable => "clock_unusable",
            Self::ClockRegression => "clock_regression",
            Self::BadInput => "bad_input",
            Self::Duplicate => "duplicate",
            Self::Late => "late",
            Self::TooFarAhead => "too_far_ahead",
            Self::TimelineMismatch => "timeline_mismatch",
        }
    }
}

/// The one decision taken for a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The block that arrived in time; its bytes are in the caller's buffer.
    Real,
    /// The last played block, attenuated by the gain for this run (1-based); bytes in the buffer.
    Concealed { run: u8 },
    /// More consecutive blocks missing than the profile conceals: silence, never extrapolation.
    MutedGap,
    /// Nothing has been played yet, so there is nothing to conceal with.
    MutedNoHistory,
    /// Decided after the block's presentation time: it can no longer be presented.
    MutedOverdue,
    /// Dropped by a coordinated latency decrease.
    Skipped,
}

impl Outcome {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Concealed { .. } => "concealed",
            Self::MutedGap => "muted_gap",
            Self::MutedNoHistory => "muted_nohistory",
            Self::MutedOverdue => "muted_overdue",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub block: u64,
    pub outcome: Outcome,
    /// Group time at which the block is to be presented, by the timeline in force for it.
    pub presentation_ns: u64,
    /// Frames to take from the buffer (0 unless real or concealed).
    pub frames: u16,
    /// Silence the consumer must insert before this block (nonzero only at a latency transition).
    pub gap_before_ns: u64,
    /// Latest time the block may still be accepted downstream (`presentation - lead`; 0 if nothing to deliver).
    pub submit_deadline_ns: u64,
    /// How long after its cutoff the decision was taken (the render loop's lateness).
    pub late_by_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// The cutoff of the next block is still ahead.
    Pending,
    Decision(Decision),
    ClockUnusable,
    ClockRegression,
    NotBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartReject {
    StaleEpoch,
    Misaligned,
    BadAnchor,
}

impl StartReject {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StaleEpoch => "stale_epoch",
            Self::Misaligned => "misaligned",
            Self::BadAnchor => "bad_anchor",
        }
    }
}

/// A coordinated latency change from the control channel (N02/G01). From `effective_frame` on, the frame whose
/// presentation was `origin + ft(f)` is presented at `new_anchor_ns + ft(f - effective_frame)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyChange {
    pub epoch: u64,
    /// Strictly increasing within a stream; a repeat is a replay.
    pub change_id: u64,
    pub effective_frame: u64,
    pub new_anchor_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeReject {
    NotBound,
    StaleEpoch,
    FutureEpoch,
    ReplayedChange,
    ChangePending,
    Misaligned,
    TooSoon,
    TooFarAhead,
    BadAnchor,
    NoChange,
    TransitionTooLarge,
    LatencyCapExceeded,
}

impl ChangeReject {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotBound => "not_bound",
            Self::StaleEpoch => "stale_epoch",
            Self::FutureEpoch => "future_epoch",
            Self::ReplayedChange => "replayed_change",
            Self::ChangePending => "change_pending",
            Self::Misaligned => "misaligned",
            Self::TooSoon => "too_soon",
            Self::TooFarAhead => "too_far_ahead",
            Self::BadAnchor => "bad_anchor",
            Self::NoChange => "no_change",
            Self::TransitionTooLarge => "transition_too_large",
            Self::LatencyCapExceeded => "latency_cap_exceeded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdviceAction {
    Hold,
    Increase,
    Decrease,
    Unhealthy,
}

impl AdviceAction {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Increase => "increase",
            Self::Decrease => "decrease",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Latency advice. Never applied by the engine: a change needs group coordination ([`PlayoutEngine::apply_change`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advice {
    pub action: AdviceAction,
    pub blocks: u32,
    pub reason: &'static str,
}

/// Latency advice from arrival margins (`cutoff - arrival` in ns; at most 0 means late).
///
/// Increase when at least two late arrivals are in the window, by enough whole blocks to have made the worst one
/// on time, at most `max_step_blocks` and never past the net cap (then unhealthy: the engine will not keep adding
/// latency to hide a member that cannot keep up). Decrease when the window is full, nothing is late and the slack
/// beyond three blocks covers at least one block.
#[must_use]
pub fn latency_advice(margins: &[i64], net_shift_ns: i64, profile: &PlayoutProfile) -> Advice {
    let hold = |reason| Advice {
        action: AdviceAction::Hold,
        blocks: 0,
        reason,
    };
    if margins.len() < ADVICE_MIN_EVENTS {
        return hold("insufficient_data");
    }
    let late = margins.iter().filter(|&&m| m <= 0).count();
    let worst = margins.iter().copied().min().unwrap_or(0);
    let block = i128::from(BLOCK_NS);
    if late >= ADVICE_LATE_TRIGGER {
        let need = (1 - i128::from(worst) + block - 1).div_euclid(block);
        let n = need.min(i128::from(profile.max_step_blocks));
        let shifted = i128::from(net_shift_ns)
            + i128::from(frames_to_ns(clamp_u64(n.unsigned_abs()) * BLOCK_FRAMES));
        if shifted > profile.net_cap_ns() {
            return Advice {
                action: AdviceAction::Unhealthy,
                blocks: 0,
                reason: "latency_cap",
            };
        }
        return Advice {
            action: AdviceAction::Increase,
            blocks: u32::try_from(n).unwrap_or(0),
            reason: "late_arrivals",
        };
    }
    if late == 0 && margins.len() >= MARGIN_WINDOW {
        let spare = i128::from(worst) - i128::from(ADVICE_KEEP_BLOCKS) * block;
        let n = if spare > 0 {
            (spare / block).min(i128::from(profile.max_step_blocks))
        } else {
            0
        };
        let after = i128::from(net_shift_ns)
            - i128::from(frames_to_ns(clamp_u64(n.unsigned_abs()) * BLOCK_FRAMES));
        if n >= 1 && after.abs() <= profile.net_cap_ns() {
            return Advice {
                action: AdviceAction::Decrease,
                blocks: u32::try_from(n).unwrap_or(0),
                reason: "spare_slack",
            };
        }
        return hold("stable");
    }
    hold(if late > 0 {
        "isolated_late"
    } else {
        "window_filling"
    })
}

/// Counters, cumulative since the engine was created. Field names are the keys of the reference's `STAT_KEYS`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PlayoutStats {
    pub packets_seen: u64,
    pub repairs_seen: u64,
    pub admitted: u64,
    pub admitted_repair: u64,
    pub duplicate: u64,
    pub duplicate_conflict: u64,
    pub duplicate_repair: u64,
    pub late: u64,
    pub late_repair: u64,
    pub not_bound: u64,
    pub stale_epoch: u64,
    pub future_epoch: u64,
    pub clock_unusable: u64,
    pub clock_regressions: u64,
    pub bad_input: u64,
    pub too_far_ahead: u64,
    pub timeline_mismatch: u64,
    pub decided_real: u64,
    pub decided_concealed: u64,
    pub decided_muted_gap: u64,
    pub decided_muted_nohistory: u64,
    pub decided_muted_overdue: u64,
    pub decided_skipped: u64,
    pub clock_unusable_polls: u64,
    pub delivered: u64,
    pub abandoned: u64,
    pub changes_applied: u64,
    pub changes_rejected: u64,
}

/// A bounded diagnostic snapshot (no payload bytes, no identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EngineSnapshot {
    pub epoch: Option<u64>,
    pub cursor: u64,
    pub queued: u32,
    pub gap_run: u32,
    pub net_shift_ns: i64,
    pub pending: bool,
    pub stats: PlayoutStats,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    used: bool,
    frames: u16,
    payload: [u8; BLOCK_PAYLOAD_BYTES],
}

impl Slot {
    const EMPTY: Self = Self {
        used: false,
        frames: 0,
        payload: [0; BLOCK_PAYLOAD_BYTES],
    };
}

/// Bytes of one slot of the decoded playout queue, as the compiler lays it out for the target being built: the 1024-byte payload, a
/// `u16` frame count and a use flag (1027 bytes of fields) rounded up to the slot's alignment, which is 1028 wherever a `u16` is
/// 2-byte aligned (the host and the big-endian MIPS and PowerPC targets). The rule, not the number, is what is asserted at compile time
/// below. Allocator metadata is not counted.
pub const SLOT_BYTES: usize = core::mem::size_of::<Slot>();

/// `slots` slots of `slot_bytes` plus `inline_bytes`, or `None` when that does not fit a `usize`: every step is a checked operation, so
/// an admission decision can never rest on a wrapped number.
const fn footprint(slots: usize, slot_bytes: usize, inline_bytes: usize) -> Option<usize> {
    match slots.checked_mul(slot_bytes) {
        Some(queue) => queue.checked_add(inline_bytes),
        None => None,
    }
}

// Checked for every target this crate is built for, so a layout that differs on a target fails that target's build instead of
// being assumed: (1) the slot is its fields rounded up to its alignment; (2) the widest profile a `u16` horizon can name, with the
// engine struct, still fits a `usize` (this matters on the 32-bit big-endian targets).
const _: () = {
    let fields = BLOCK_PAYLOAD_BYTES + 2 + 1;
    let align = core::mem::align_of::<Slot>();
    assert!(SLOT_BYTES == fields.div_ceil(align) * align);
    assert!(
        footprint(
            u16::MAX as usize,
            SLOT_BYTES,
            core::mem::size_of::<PlayoutEngine>()
        )
        .is_some()
    );
};

impl PlayoutProfile {
    /// Slots [`PlayoutEngine::new`] builds: `horizon_blocks`, and at least one (the queue is never empty).
    const fn queue_slots(&self) -> usize {
        if self.horizon_blocks == 0 {
            1
        } else {
            self.horizon_blocks as usize
        }
    }

    /// Heap bytes [`PlayoutEngine::new`] requests for this profile's decoded playout queue (`usize::MAX` if that is not representable,
    /// which no `u16` horizon reaches: checked at compile time). It is the engine's only allocation besides the optional diagnostics
    /// ring, which the caller counts with its own `capacity` (section 15 of the contract).
    #[must_use]
    pub const fn playout_queue_bytes(&self) -> usize {
        match footprint(self.queue_slots(), SLOT_BYTES, 0) {
            Some(bytes) => bytes,
            None => usize::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingChange {
    effective_frame: u64,
    new_origin: u64,
    delta: i128,
}

/// The shape of one arrival, shared by media and repair.
struct Arrival<'a> {
    epoch: u64,
    start_frame: u64,
    frames: u32,
    payload: &'a [u8],
    /// `Some` for media (checked against the timeline), `None` for a repair.
    presentation_ns: Option<u64>,
}

#[derive(Debug)]
pub struct PlayoutEngine {
    profile: PlayoutProfile,
    cfg: PlayoutConfig,
    epoch: Option<u64>,
    origin: u64,
    first_block: u64,
    cursor: u64,
    /// The `Vec` the (fallible) reservation produced, kept as it is: no conversion to a boxed slice, which may shrink and reallocate.
    slots: Vec<Slot>,
    hist: [u8; HISTORY_BLOCKS],
    last_real: [u8; BLOCK_PAYLOAD_BYTES],
    have_last_real: bool,
    gap_run: u32,
    pending: Option<PendingChange>,
    skip_until: u64,
    gap_next: u64,
    last_change_id: u64,
    net_shift: i128,
    margins: [i64; MARGIN_WINDOW],
    margin_len: usize,
    margin_head: usize,
    last_now: Option<u64>,
    stats: PlayoutStats,
    diag: Option<log::DiagLog>,
}

impl PlayoutEngine {
    /// Allocates the slots (the only allocation this type ever makes).
    ///
    /// # Errors
    /// `cfg` is invalid, or the profile has no slots.
    pub fn new(profile: PlayoutProfile, cfg: PlayoutConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self::with_slots(
            profile,
            cfg,
            vec![Slot::EMPTY; usize::from(profile.horizon_blocks.max(1))],
        ))
    }

    /// The engine over already-allocated `slots`: the one place its fields are listed.
    fn with_slots(profile: PlayoutProfile, cfg: PlayoutConfig, slots: Vec<Slot>) -> Self {
        Self {
            profile,
            cfg,
            epoch: None,
            origin: 0,
            first_block: 0,
            cursor: 0,
            slots,
            hist: [H_NONE; HISTORY_BLOCKS],
            last_real: [0; BLOCK_PAYLOAD_BYTES],
            have_last_real: false,
            gap_run: 0,
            pending: None,
            skip_until: 0,
            gap_next: 0,
            last_change_id: 0,
            net_shift: 0,
            margins: [0; MARGIN_WINDOW],
            margin_len: 0,
            margin_head: 0,
            last_now: None,
            stats: PlayoutStats::default(),
            diag: None,
        }
    }

    /// Bytes an engine for `profile` occupies, wherever the caller puts the struct: the struct itself and its decoded playout queue.
    /// The diagnostics ring ([`PlayoutEngine::enable_log`]) and allocator metadata are not included.
    /// The struct holds every other piece of the engine inline (the pending latency change, the history, the arrival margins, the last
    /// real block, the counters and the diagnostics handle); `usize::MAX` if the sum is not representable.
    #[must_use]
    pub const fn resident_bytes(profile: &PlayoutProfile) -> usize {
        match Self::checked_resident_bytes(profile) {
            Some(bytes) => bytes,
            None => usize::MAX,
        }
    }

    /// Heap bytes this engine holds now: the slot queue as the allocator actually gave it (`Vec::capacity`, which may exceed the count
    /// that was asked for) and the diagnostics heap (the ring and the configuration's strings). The struct itself is
    /// `size_of::<Self>()`; the two together are what a ledger charges for a built engine.
    #[must_use]
    pub fn owned_heap_bytes(&self) -> usize {
        self.slots
            .capacity()
            .saturating_mul(SLOT_BYTES)
            .saturating_add(self.log_heap_bytes())
    }

    const fn checked_resident_bytes(profile: &PlayoutProfile) -> Option<usize> {
        footprint(
            profile.queue_slots(),
            SLOT_BYTES,
            core::mem::size_of::<Self>(),
        )
    }

    /// Build an engine only if it fits `budget_bytes`, the caller's line of its memory ledger for this stream. The configuration is
    /// judged first; then [`PlayoutEngine::resident_bytes`] against the budget. A profile that does not fit is refused with a typed
    /// [`CapacityError`] **before anything is allocated**: no smaller profile is substituted and no existing engine is touched, so a
    /// stream that is playing is never evicted to make room.
    ///
    /// # Errors
    /// An invalid configuration, or a profile that does not fit the budget.
    pub fn new_within(
        profile: PlayoutProfile,
        cfg: PlayoutConfig,
        budget_bytes: usize,
    ) -> Result<Self, AdmitError> {
        cfg.validate().map_err(AdmitError::Config)?;
        let checked = Self::checked_resident_bytes(&profile);
        if !matches!(checked, Some(needed) if needed <= budget_bytes) {
            return Err(AdmitError::Capacity(CapacityError {
                needed_bytes: checked.unwrap_or(usize::MAX),
                budget_bytes,
            }));
        }
        // Only now, with the configuration valid and the footprint admitted, is memory asked for, and it is asked for fallibly: an allocator
        // that cannot give the slots is a typed refusal, not an abort. The `Vec` the reservation produced is the one the engine keeps.
        let count = profile.queue_slots();
        let mut slots: Vec<Slot> = Vec::new();
        if slots.try_reserve_exact(count).is_err() {
            return Err(AdmitError::Allocation(AllocationError {
                requested_bytes: profile.playout_queue_bytes(),
            }));
        }
        // The allocator may give more than was asked for (`try_reserve_exact` only promises at least): what is kept is what is charged,
        // and it must still fit before the engine is published.
        let kept = slots
            .capacity()
            .checked_mul(SLOT_BYTES)
            .and_then(|queue| queue.checked_add(core::mem::size_of::<Self>()));
        if !matches!(kept, Some(bytes) if bytes <= budget_bytes) {
            return Err(AdmitError::Capacity(CapacityError {
                needed_bytes: kept.unwrap_or(usize::MAX),
                budget_bytes,
            }));
        }
        slots.resize(count, Slot::EMPTY);
        Ok(Self::with_slots(profile, cfg, slots))
    }

    #[must_use]
    pub const fn profile(&self) -> &PlayoutProfile {
        &self.profile
    }

    #[must_use]
    pub const fn stats(&self) -> &PlayoutStats {
        &self.stats
    }

    fn horizon(&self) -> u64 {
        self.slots.len() as u64
    }

    fn slot_index(&self, block: u64) -> usize {
        usize::try_from(block % self.horizon()).unwrap_or(0)
    }

    fn reset(&mut self, origin: u64, first_block: u64) {
        self.origin = origin;
        self.first_block = first_block;
        self.cursor = first_block;
        for s in self.slots.iter_mut() {
            s.used = false;
        }
        self.hist = [H_NONE; HISTORY_BLOCKS];
        self.have_last_real = false;
        self.gap_run = 0;
        self.pending = None;
        self.skip_until = first_block;
        self.gap_next = 0;
        self.last_change_id = 0;
        self.net_shift = 0;
        self.margin_len = 0;
        self.margin_head = 0;
        self.last_now = None;
    }

    /// Bind a stream: its epoch and the group time at which `anchor_frame` is presented. The same epoch may be
    /// bound again (N03 re-admits a start within its epoch after a relock); an older one may not.
    ///
    /// # Errors
    /// A stale epoch, a misaligned anchor frame, or an anchor earlier than its own frame offset.
    pub fn begin_stream(
        &mut self,
        epoch: u64,
        anchor_frame: u64,
        anchor_ns: u64,
    ) -> Result<(), StartReject> {
        let result = self.bind(epoch, anchor_frame, anchor_ns);
        self.log_start(epoch, anchor_frame, anchor_ns, result);
        result
    }

    fn bind(&mut self, epoch: u64, anchor_frame: u64, anchor_ns: u64) -> Result<(), StartReject> {
        if self.epoch.is_some_and(|e| epoch < e) {
            return Err(StartReject::StaleEpoch);
        }
        if !anchor_frame.is_multiple_of(BLOCK_FRAMES) {
            return Err(StartReject::Misaligned);
        }
        let offset = frames_to_ns(anchor_frame);
        if anchor_ns > MAX_TIMESTAMP_NS || anchor_ns < offset {
            return Err(StartReject::BadAnchor);
        }
        self.epoch = Some(epoch);
        self.reset(anchor_ns - offset, anchor_frame / BLOCK_FRAMES);
        Ok(())
    }

    fn pres_of(&self, frame: u64) -> u64 {
        let origin = match self.pending {
            Some(p) if frame >= p.effective_frame => p.new_origin,
            _ => self.origin,
        };
        origin.saturating_add(frames_to_ns(frame))
    }

    fn cutoff_of(&self, block: u64, uncertainty_ns: u64) -> u64 {
        consume_by(
            self.pres_of(block.saturating_mul(BLOCK_FRAMES)),
            self.cfg.work_ns,
            self.cfg.lead_ns,
            uncertainty_ns,
        )
    }

    /// Accept a coordinated latency change (see [`LatencyChange`]). Returns the shift in nanoseconds
    /// (positive: later presentation, more latency).
    ///
    /// # Errors
    /// The first failed check, in the order of [`ChangeReject`]'s documentation in the contract.
    pub fn apply_change(&mut self, ch: LatencyChange) -> Result<i64, ChangeReject> {
        let result = self.check_change(ch);
        match result {
            Ok(_) => self.stats.changes_applied += 1,
            Err(_) => self.stats.changes_rejected += 1,
        }
        self.log_change(&ch, result);
        result
    }

    fn check_change(&mut self, ch: LatencyChange) -> Result<i64, ChangeReject> {
        let Some(epoch) = self.epoch else {
            return Err(ChangeReject::NotBound);
        };
        if ch.epoch < epoch {
            return Err(ChangeReject::StaleEpoch);
        }
        if ch.epoch > epoch {
            return Err(ChangeReject::FutureEpoch);
        }
        if ch.change_id <= self.last_change_id {
            return Err(ChangeReject::ReplayedChange);
        }
        if self.pending.is_some() {
            return Err(ChangeReject::ChangePending);
        }
        if !ch.effective_frame.is_multiple_of(BLOCK_FRAMES) {
            return Err(ChangeReject::Misaligned);
        }
        let eb = ch.effective_frame / BLOCK_FRAMES;
        if eb
            < self
                .cursor
                .saturating_add(u64::from(self.profile.notice_blocks))
        {
            return Err(ChangeReject::TooSoon);
        }
        if eb > self.cursor.saturating_add(self.horizon()) {
            return Err(ChangeReject::TooFarAhead);
        }
        let offset = frames_to_ns(ch.effective_frame);
        let old_p = i128::from(self.origin) + i128::from(offset);
        if ch.new_anchor_ns > MAX_TIMESTAMP_NS || ch.new_anchor_ns < offset {
            return Err(ChangeReject::BadAnchor);
        }
        let delta = i128::from(ch.new_anchor_ns) - old_p;
        if delta == 0 {
            return Err(ChangeReject::NoChange);
        }
        if delta.abs() > self.profile.step_cap_ns() {
            return Err(ChangeReject::TransitionTooLarge);
        }
        if (self.net_shift + delta).abs() > self.profile.net_cap_ns() {
            return Err(ChangeReject::LatencyCapExceeded);
        }
        self.last_change_id = ch.change_id;
        self.pending = Some(PendingChange {
            effective_frame: ch.effective_frame,
            new_origin: ch.new_anchor_ns - offset,
            delta,
        });
        Ok(clamp_i64(delta))
    }

    fn check_view(&mut self, view: ClockView) -> Option<Admission> {
        if !view.usable {
            return Some(Admission::ClockUnusable);
        }
        if self.last_now.is_some_and(|last| view.group_ns < last) {
            return Some(Admission::ClockRegression);
        }
        self.last_now = Some(view.group_ns);
        None
    }

    fn note_margin(&mut self, margin: i128) {
        let at = (self.margin_head + self.margin_len) % MARGIN_WINDOW;
        self.margins[at] = clamp_i64(margin);
        if self.margin_len < MARGIN_WINDOW {
            self.margin_len += 1;
        } else {
            self.margin_head = (self.margin_head + 1) % MARGIN_WINDOW;
        }
    }

    fn margins_in_order(&self) -> [i64; MARGIN_WINDOW] {
        let mut out = [0; MARGIN_WINDOW];
        for (i, slot) in out.iter_mut().enumerate().take(self.margin_len) {
            *slot = self.margins[(self.margin_head + i) % MARGIN_WINDOW];
        }
        out
    }

    /// Admit an authenticated media packet. See the contract for the order of checks.
    pub fn on_packet(&mut self, view: ClockView, pkt: &MediaPacket<'_>) -> Admission {
        self.stats.packets_seen += 1;
        let result = self.admit(
            view,
            &Arrival {
                epoch: pkt.epoch,
                start_frame: pkt.start_frame,
                frames: pkt.frames,
                payload: pkt.payload,
                presentation_ns: Some(pkt.presentation_ns),
            },
        );
        self.log_arrival(
            view,
            false,
            (pkt.epoch, pkt.start_frame, pkt.frames),
            result,
        );
        result
    }

    /// Admit a recovered block. Judged by the same cutoff as media: after it, a repair is discarded even when the
    /// DAC presentation time is still ahead.
    pub fn on_repair(&mut self, view: ClockView, block: &RepairBlock<'_>) -> Admission {
        self.stats.repairs_seen += 1;
        let result = self.admit(
            view,
            &Arrival {
                epoch: block.epoch,
                start_frame: block.start_frame,
                frames: block.frames,
                payload: block.payload,
                presentation_ns: None,
            },
        );
        self.log_arrival(
            view,
            true,
            (block.epoch, block.start_frame, block.frames),
            result,
        );
        result
    }

    fn admit(&mut self, view: ClockView, a: &Arrival<'_>) -> Admission {
        let repair = a.presentation_ns.is_none();
        let Some(epoch) = self.epoch else {
            self.stats.not_bound += 1;
            return Admission::NotBound;
        };
        if a.epoch < epoch {
            self.stats.stale_epoch += 1;
            return Admission::StaleEpoch;
        }
        if a.epoch > epoch {
            self.stats.future_epoch += 1;
            return Admission::FutureEpoch;
        }
        if let Some(why) = self.check_view(view) {
            match why {
                Admission::ClockUnusable => self.stats.clock_unusable += 1,
                _ => self.stats.clock_regressions += 1,
            }
            return why;
        }
        let bytes = (a.frames as usize).saturating_mul(4);
        if !a.start_frame.is_multiple_of(BLOCK_FRAMES)
            || !(1..=BLOCK_FRAMES as u32).contains(&a.frames)
            || a.payload.len() != bytes
        {
            self.stats.bad_input += 1;
            return Admission::BadInput;
        }
        let b = a.start_frame / BLOCK_FRAMES;
        if b < self.cursor {
            let remembered = b >= self.first_block
                && self.cursor - b <= HISTORY_BLOCKS as u64
                && self.hist[(b % HISTORY_BLOCKS as u64) as usize] == H_REAL;
            if remembered {
                if repair {
                    self.stats.duplicate_repair += 1
                } else {
                    self.stats.duplicate += 1
                }
                return Admission::Duplicate;
            }
            if b >= self.first_block {
                self.note_margin(
                    i128::from(self.cutoff_of(b, view.uncertainty_ns)) - i128::from(view.group_ns),
                );
            }
            if repair {
                self.stats.late_repair += 1
            } else {
                self.stats.late += 1
            }
            return Admission::Late;
        }
        if b >= self.cursor.saturating_add(self.horizon()) {
            self.stats.too_far_ahead += 1;
            return Admission::TooFarAhead;
        }
        let idx = self.slot_index(b);
        if self.slots[idx].used {
            if repair {
                self.stats.duplicate_repair += 1
            } else {
                self.stats.duplicate += 1
            }
            let held = &self.slots[idx];
            if held.frames as u32 != a.frames || held.payload[..bytes] != *a.payload {
                self.stats.duplicate_conflict += 1;
            }
            return Admission::Duplicate;
        }
        if let Some(presentation) = a.presentation_ns {
            let expected = self.pres_of(a.start_frame);
            if presentation.abs_diff(expected) > self.cfg.tolerance_ns {
                self.stats.timeline_mismatch += 1;
                return Admission::TimelineMismatch;
            }
        }
        let margin = i128::from(self.cutoff_of(b, view.uncertainty_ns)) - i128::from(view.group_ns);
        self.note_margin(margin);
        if margin <= 0 {
            if repair {
                self.stats.late_repair += 1
            } else {
                self.stats.late += 1
            }
            return Admission::Late;
        }
        let slot = &mut self.slots[idx];
        slot.used = true;
        slot.frames = a.frames as u16;
        slot.payload[..bytes].copy_from_slice(a.payload);
        if repair {
            self.stats.admitted_repair += 1
        } else {
            self.stats.admitted += 1
        }
        Admission::Admitted
    }

    /// Take the decision for the next block if its cutoff has been reached. Call repeatedly until it is
    /// [`Poll::Pending`]: each call decides at most one block, exactly once, and a block is never decided twice.
    /// `out` receives the bytes of a real or concealed block (the first `frames * 4` bytes).
    pub fn decide(&mut self, view: ClockView, out: &mut [u8; BLOCK_PAYLOAD_BYTES]) -> Poll {
        let poll = self.take_decision(view, out);
        self.log_poll(view, &poll);
        poll
    }

    fn take_decision(&mut self, view: ClockView, out: &mut [u8; BLOCK_PAYLOAD_BYTES]) -> Poll {
        if let Some(why) = self.check_view(view) {
            return if why == Admission::ClockUnusable {
                self.stats.clock_unusable_polls += 1;
                Poll::ClockUnusable
            } else {
                self.stats.clock_regressions += 1;
                Poll::ClockRegression
            };
        }
        if self.epoch.is_none() {
            return Poll::NotBound;
        }
        let b = self.cursor;
        if self
            .pending
            .is_some_and(|p| p.effective_frame / BLOCK_FRAMES == b)
        {
            self.commit_change();
        }
        let idx = self.slot_index(b);
        if b < self.skip_until {
            self.slots[idx].used = false;
            return Poll::Decision(self.finish(b, Outcome::Skipped, 0, 0, H_SKIPPED));
        }
        let pres = self.pres_of(b.saturating_mul(BLOCK_FRAMES));
        let cutoff = self.cutoff_of(b, view.uncertainty_ns);
        if view.group_ns < cutoff {
            return Poll::Pending;
        }
        let late_by = view.group_ns - cutoff;
        let slot = self.slots[idx];
        self.slots[idx].used = false;
        if view.group_ns >= pres {
            self.gap_run = (self.gap_run + 1).min(255);
            return Poll::Decision(self.finish(b, Outcome::MutedOverdue, 0, late_by, H_MUTED));
        }
        if slot.used {
            let n = usize::from(slot.frames) * 4;
            out[..n].copy_from_slice(&slot.payload[..n]);
            self.last_real = [0; BLOCK_PAYLOAD_BYTES];
            self.last_real[..n].copy_from_slice(&slot.payload[..n]);
            self.have_last_real = true;
            self.gap_run = 0;
            return Poll::Decision(self.finish(b, Outcome::Real, slot.frames, late_by, H_REAL));
        }
        if !self.have_last_real {
            self.gap_run = (self.gap_run + 1).min(255);
            return Poll::Decision(self.finish(b, Outcome::MutedNoHistory, 0, late_by, H_MUTED));
        }
        if self.gap_run >= u32::from(self.profile.max_conceal_blocks) {
            self.gap_run = (self.gap_run + 1).min(255);
            return Poll::Decision(self.finish(b, Outcome::MutedGap, 0, late_by, H_MUTED));
        }
        self.gap_run += 1;
        let run = u8::try_from(self.gap_run).unwrap_or(8);
        conceal_block(&self.last_real, run, out);
        Poll::Decision(self.finish(
            b,
            Outcome::Concealed { run },
            BLOCK_FRAMES as u16,
            late_by,
            H_CONCEALED,
        ))
    }

    fn commit_change(&mut self) {
        let Some(ch) = self.pending.take() else {
            return;
        };
        let fe = ch.effective_frame;
        let old_end = i128::from(self.origin) + i128::from(frames_to_ns(fe));
        let new_at =
            |n: u64| i128::from(ch.new_origin) + i128::from(frames_to_ns(fe + n * BLOCK_FRAMES));
        let mut n = 0;
        if ch.delta < 0 {
            n = 1;
            while new_at(n) < old_end && n < 4096 {
                n += 1;
            }
        }
        self.gap_next = u64::try_from(new_at(n) - old_end).unwrap_or(0);
        self.skip_until = fe / BLOCK_FRAMES + n;
        self.origin = ch.new_origin;
        self.net_shift += ch.delta;
    }

    fn finish(
        &mut self,
        block: u64,
        outcome: Outcome,
        frames: u16,
        late_by: u64,
        code: u8,
    ) -> Decision {
        self.hist[(block % HISTORY_BLOCKS as u64) as usize] = code;
        self.cursor = block + 1;
        match outcome {
            Outcome::Real => self.stats.decided_real += 1,
            Outcome::Concealed { .. } => self.stats.decided_concealed += 1,
            Outcome::MutedGap => self.stats.decided_muted_gap += 1,
            Outcome::MutedNoHistory => self.stats.decided_muted_nohistory += 1,
            Outcome::MutedOverdue => self.stats.decided_muted_overdue += 1,
            Outcome::Skipped => self.stats.decided_skipped += 1,
        }
        let presentation_ns = self.pres_of(block.saturating_mul(BLOCK_FRAMES));
        let gap_before_ns = if outcome == Outcome::Skipped {
            0
        } else {
            std::mem::take(&mut self.gap_next)
        };
        let deliverable = matches!(outcome, Outcome::Real | Outcome::Concealed { .. });
        Decision {
            block,
            outcome,
            presentation_ns,
            frames,
            gap_before_ns,
            submit_deadline_ns: if deliverable {
                presentation_ns.saturating_sub(self.cfg.lead_ns)
            } else {
                0
            },
            late_by_ns: late_by,
        }
    }

    /// The downstream ring took the block at `accepted_at_ns` (`None`: it never had room). On time (not after the
    /// decision's `submit_deadline_ns`) it is delivered; otherwise it is abandoned and nothing is queued for it.
    pub fn settle_delivery(
        &mut self,
        submit_deadline_ns: u64,
        accepted_at_ns: Option<u64>,
    ) -> Delivery {
        let result = if accepted_at_ns.is_some_and(|t| t <= submit_deadline_ns) {
            self.stats.delivered += 1;
            Delivery::Delivered
        } else {
            self.stats.abandoned += 1;
            Delivery::Abandoned
        };
        self.log_delivery(submit_deadline_ns, accepted_at_ns, result);
        result
    }

    /// Latency advice from the arrival margins seen so far (see [`latency_advice`]).
    #[must_use]
    pub fn advice(&self) -> Advice {
        let margins = self.margins_in_order();
        latency_advice(
            &margins[..self.margin_len],
            clamp_i64(self.net_shift),
            &self.profile,
        )
    }

    #[must_use]
    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            epoch: self.epoch,
            cursor: self.cursor,
            queued: u32::try_from(self.slots.iter().filter(|s| s.used).count()).unwrap_or(u32::MAX),
            gap_run: self.gap_run,
            net_shift_ns: clamp_i64(self.net_shift),
            pending: self.pending.is_some(),
            stats: self.stats,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod group_clock_tests;
