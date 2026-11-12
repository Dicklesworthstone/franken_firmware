//! The protected render loop (`D04` / `ffw-5h5`). Contract: `docs/contracts/d04.md`.
//!
//! A [`RenderLoop`] turns the HAL into playback. Every block goes source -> D03 drift resampler ->
//! D02 board protection -> interleaved bytes -> [`HalSession::submit`], on a timeline fixed by the
//! device's own tick:
//!
//! * block `k` is **released** at `base + 1 + k * period`, must be **submitted** by
//!   `release + window` (its deadline), and is presented `min_submission_lead` ticks after that;
//! * a block that completes after its deadline is **dropped**, never submitted late: audio that
//!   plays late is out of sync, and old audio must not accumulate;
//! * a source that has nothing yields silence for the rest of the block, so the device never sees a
//!   gap it was not told about.
//!
//! # What this is, and is not
//!
//! Time here is the device tick, and render cost is injected through [`TimingModel`]. Against the
//! fake device this is a **host simulation**: it shows the scheduling, accounting and ownership
//! logic and says nothing about a board's CPU, a driver or the sound. Real CPU measurement, the
//! amplifier and process-death muting stay external qualification.
//!
//! # Four causes, kept apart
//!
//! Every started block ends in exactly one [`BlockOutcome`]:
//!
//! 1. **ingress loss** - the source had no data because packets did not arrive;
//! 2. **decode delay** - packets arrived but decoding was not done in time;
//! 3. **CPU miss** - the loop itself finished after the deadline with the source healthy (a late
//!    wake-up is a CPU miss with a cause, [`RenderCounters::late_wakes`]);
//! 4. **driver underrun** - the device reported it ran dry although every block was supplied on
//!    time. It is a device-side observation, counted apart from the block outcomes.
//!
//! Logical capacity rejection (the ordinary ring share is full) and a short write are separate
//! outcomes, and are not process or kernel out-of-memory.
//!
//! # Ownership
//!
//! A buffer the device may still read is never released because a timer ran out. The loop only
//! ever lets the session free storage on a device acknowledgment (a completion, a flush or a
//! reset). A drain that is not acknowledged faults and quarantines. The cleanup reserve keeps
//! `reserve_slots` ring slots out of ordinary submission, so the stop path always has room.
//!
//! # The driver's counter going backwards
//!
//! The HAL treats a consumed-position report that moves backwards as a fault (muted, quarantined,
//! nothing credited) and marks it apart from a counter that ran ahead. The loop gives it its own
//! [`FaultReason::CounterRegress`] and **invalidates the presentation mapping**: nothing derived from
//! the old counter is used again. The loop stays `Faulted` (muted, every buffer held) until the owner
//! recovers it through an acknowledged HAL reset, which takes a new baseline; after that it returns
//! to `Ready`, and refuses to start until the owner says it has re-derived its mapping from the
//! device's new counter ([`RenderLoop::reinstall_presentation_mapping`]). A timeout alone frees
//! nothing. This is the fake device's counter; the real driver's semantics are not known.

use franken_dsp::format::Endian;
use franken_dsp::protection::{BoardStatus, ProtectedBoardDsp, ProtectedOutput, SourceEvent};
use franken_dsp::resample::{DriftResampler, FrameSource, ResetReason};
use franken_dsp::{FRAMES_PER_BLOCK, MAX_HARDWARE_CHANNELS, StereoAudioBlock};
use franken_hal::backend::{DeviceBackend, DriverError};
use franken_hal::emit::{Critical, CriticalQueue, PushOutcome, SessionEventKind};
use franken_hal::session::{
    DrainOutcome, FaultCode, HalSession, PositionClass, SessionError, SessionPhase,
    StartPreconditions, StorageFootprint,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, TryReserveError, VecDeque};
use std::sync::{Arc, Mutex, TryLockError};

/// Most bytes one block can hold: every hardware channel, a whole DSP block, 16-bit samples.
const OUT_BYTES_MAX: usize = MAX_HARDWARE_CHANNELS * FRAMES_PER_BLOCK * 2;
/// Control commands the port will queue; more are rejected and counted.
pub const CONTROL_QUEUE_CAP: usize = 16;
/// Control commands the loop will apply in one tick, so a storm cannot take the render budget.
pub const MAX_CONTROL_PER_TICK: usize = 4;
/// Render events the loop will keep for its owner.
pub const RENDER_EVENT_CAP: usize = 64;

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

// ------------------------------------------------------------------------------------ source

/// Why a source has nothing to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Starvation {
    /// Packets did not arrive. The content is gone; recovery is a discontinuity.
    IngressLoss,
    /// Packets arrived but decoding was not finished. The content is intact, only late.
    DecodeDelay,
}

/// Decoded PCM for the render loop, and the reason when there is none.
pub trait RenderSource: FrameSource {
    /// `Some(why)` while the next `pull` would return `None`; `None` while frames are available.
    fn starvation(&self) -> Option<Starvation>;

    /// A trusted finite source has exhausted its content and admitted lookahead.
    /// Temporary absence is never EOF. The default preserves streaming behavior.
    fn end_of_stream(&self) -> bool {
        false
    }
}

// ------------------------------------------------------------------------------------ timing

/// What the loop cannot know in a simulation: how late it woke and how long rendering took.
pub trait TimingModel {
    /// Ticks between block `index`'s scheduled release and the loop actually starting on it.
    fn wake_delay(&mut self, index: u64) -> u64;
    /// Ticks the render of block `index` takes.
    fn render_cost(&mut self, index: u64) -> u64;
}

/// A scripted [`TimingModel`]: per-block overrides on top of a default cost and no delay.
#[derive(Debug, Clone, Default)]
pub struct ScriptedTiming {
    pub default_cost: u64,
    pub costs: BTreeMap<u64, u64>,
    pub delays: BTreeMap<u64, u64>,
}

impl TimingModel for ScriptedTiming {
    fn wake_delay(&mut self, index: u64) -> u64 {
        self.delays.get(&index).copied().unwrap_or(0)
    }

    fn render_cost(&mut self, index: u64) -> u64 {
        self.costs.get(&index).copied().unwrap_or(self.default_cost)
    }
}

// ------------------------------------------------------------------------------------ config

/// The loop's fixed parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderConfig {
    /// Frames per block: at most one DSP block and at most one HAL block.
    pub block_frames: usize,
    /// Device ticks between block releases.
    pub period_ticks: u64,
    /// Ticks between a block's release and its submission deadline.
    pub window_ticks: u64,
    /// Execution-time reserve, in percent of the window: a render slower than
    /// `(100 - reserve_percent)%` of the window is a reserve breach, whether or not it was late.
    pub reserve_percent: u8,
    /// Ring slots ordinary submission may not use; the stop path may.
    pub reserve_slots: usize,
    /// Most blocks a graceful stop renders while the output ramps to silence.
    pub max_ramp_blocks: u32,
    /// Consecutive CPU misses that trip the watchdog and mute.
    pub watchdog_misses: u32,
    /// Attempts at handing one block to the device before the unaccepted rest is discarded.
    pub max_submit_attempts: u8,
    /// Byte order of the 16-bit samples handed to the device (a harness model until E04 maps it).
    pub output_endian: Endian,
}

impl RenderConfig {
    #[must_use]
    pub const fn standard(block_frames: usize) -> Self {
        Self {
            block_frames,
            period_ticks: 4,
            window_ticks: 3,
            reserve_percent: 25,
            reserve_slots: 1,
            max_ramp_blocks: 12,
            watchdog_misses: 3,
            max_submit_attempts: 2,
            output_endian: Endian::Big,
        }
    }
}

/// A read-only projection of the next block's existing device-tick schedule.
/// These ticks have no group-time meaning until the caller admits a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderSlot {
    pub now: u64,
    pub index: u64,
    pub block_frames: usize,
    pub release_tick: u64,
    pub deadline_tick: u64,
    pub presentation_tick: u64,
    /// Exact next pull demand from a cloned D03 state, including its phase,
    /// priming and current drift/slew. Querying never advances the real state.
    pub required_source_frames: u64,
    /// Pull demand for the next single output, to distinguish a finite tail
    /// from a completely empty extra device block.
    pub first_output_source_frames: u64,
    /// D03 phase at the next output, including any projected epoch reset.
    pub source_phase: franken_dsp::resample::PhaseState,
    /// An earlier block has already pulled input and is still rendering.
    pub in_progress: bool,
}

// ------------------------------------------------------------------------------------ errors

/// Where an admission failure is injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmitPoint {
    Start,
    Cancel,
    Drain,
    Reconnect,
}

/// Injected **logical** capacity failures. These model admission control saying no, which is not
/// the same as the allocator aborting or the kernel killing the process; neither of those can be
/// reasoned about here.
///
/// * `start` and `reconnect` are refused with a typed error and change nothing;
/// * `cancel` and `drain` find ordinary capacity gone, and must still finish on the reserve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmitFaults {
    pub start: bool,
    pub cancel: bool,
    pub drain: bool,
    pub reconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    #[error("bad render configuration: {0}")]
    BadConfig(&'static str),
    #[error("the session is in phase {0:?}, not Prepared")]
    SessionNotPrepared(SessionPhase),
    #[error("device geometry does not fit the render path: {0}")]
    Geometry(&'static str),
    #[error("the minimum submission lead is unknown, so deadlines cannot be computed")]
    LeadUnknown,
    #[error("the stop deadline is unknown, so a stop cannot be bounded")]
    StopDeadlineUnknown,
    #[error("the protection DSP is not active, so audible output is refused")]
    ProtectionNotActive,
    #[error(
        "silent start requires an acknowledged empty reset, silence-only priming and zero applied gain"
    )]
    SilentStartUnproven,
    #[error("no ordinary render capacity is left after the cleanup reserve")]
    NoOrdinaryCapacity,
    #[error("admission failed at {0:?}")]
    AdmissionFailed(AdmitPoint),
    /// Storage the loop appends to while it runs could not be reserved at admission. Nothing was started.
    /// This is the allocator (or the size) saying no at admission: it is neither `NoOrdinaryCapacity` (the
    /// ring has no ordinary slot), nor an injected `AdmissionFailed`, nor a rejected block.
    #[error("the {what} storage could not be reserved at admission; nothing was started")]
    StorageNotAdmitted { what: &'static str },
    #[error(
        "the driver's counter went backwards, so the presentation mapping is invalid until it is reinstalled"
    )]
    PresentationMappingInvalidated,
    #[error("not allowed in state {0:?}")]
    WrongState(RenderState),
    #[error("session: {0}")]
    Session(SessionError),
}

// ------------------------------------------------------------------------------------ states

/// Where the loop is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderState {
    /// Admitted and prepared; nothing is rendering. Hardware stays muted.
    Ready,
    /// Rendering and submitting.
    Running,
    /// Software-muted: the output has ramped to silence but the timeline keeps running, so unmuting
    /// needs no restart. The amplifier stays unmuted; the admitted safe device state is reached on
    /// a stop or a fault.
    Muted,
    /// Stopping: ramping to silence, then waiting for the device to acknowledge the flush.
    Draining,
    /// The device acknowledged the stop. Hardware is muted and every buffer is accounted for.
    Stopped,
    /// A fault is latched. Hardware mute was requested; whether it was acknowledged is recorded.
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultReason {
    /// The HAL session faulted (a driver error, a bad completion, an unacknowledged mute, ...).
    SessionFaulted,
    /// The device is gone. Persistent: a reset cannot recover it.
    DeviceLost,
    /// A stop was not acknowledged in time. What is in flight stays quarantined.
    DrainTimedOut,
    /// Too many consecutive CPU misses.
    WatchdogTripped,
    /// The protection DSP latched a fault or is no longer active.
    ProtectionFault,
    /// The resampler refused a block (an internal contract violation).
    RenderInternal,
    /// The driver's consumed counter went backwards. The presentation mapping is invalid until the
    /// owner reinstalls it after an acknowledged reset; see [`RenderLoop::recover`].
    CounterRegress,
}

// ------------------------------------------------------------------------------------ control

/// What another task may ask of the loop.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Control {
    SetGain(f32),
    Mute,
    Unmute,
    /// Graceful stop: ramp to silence, then drain.
    Stop,
    /// A source discontinuity: new resampler epoch and a protection fade-in.
    Reconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlRejected {
    #[error("the control queue is full")]
    QueueFull,
}

#[derive(Debug, Default)]
struct ControlInner {
    queue: VecDeque<Control>,
    /// `Mute` and `Stop` are never queued behind anything: they latch, and are applied first.
    mute_latched: bool,
    stop_latched: bool,
    accepted: u64,
    rejected: u64,
}

/// Counts for the control port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlStats {
    pub accepted: u64,
    pub rejected: u64,
}

/// The way other tasks reach the loop. Sending takes the lock for a push and nothing else; the loop
/// only ever `try_lock`s it, so a sender that is slow, or blocked while holding the lock, cannot
/// delay a render: the loop skips servicing that tick and counts it.
#[derive(Debug, Clone, Default)]
pub struct ControlPort {
    inner: Arc<Mutex<ControlInner>>,
}

impl ControlPort {
    /// A port whose queue storage is reserved now, with the fallible allocation API. `send` is called from
    /// other tasks, which would otherwise grow the queue (and so allocate) while holding the lock.
    ///
    /// # Errors
    /// The reservation was refused (the size, or the allocator).
    pub fn reserved() -> Result<Self, TryReserveError> {
        let mut queue = VecDeque::new();
        queue.try_reserve_exact(CONTROL_QUEUE_CAP)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ControlInner {
                queue,
                ..ControlInner::default()
            })),
        })
    }

    /// Commands the queue can hold without allocating. A diagnostic for the owner and for tests: it takes the lock,
    /// which the render path never does (it only `try_lock`s).
    #[must_use]
    pub fn reserved_capacity(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .capacity()
    }

    /// Ask the loop to do something. `Mute` and `Stop` are always accepted; the rest are bounded.
    /// A mute supersedes older queued unmute requests, while a newer unmute remains permitted.
    pub fn send(&self, control: Control) -> Result<(), ControlRejected> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match control {
            Control::Mute => {
                // The loop applies the urgent latch before its bounded command batch. Keeping an
                // older Unmute here would undo this mute, possibly several ticks later. Remove only
                // those superseded requests; a subsequently sent Unmute keeps its normal FIFO place.
                // This walks at most CONTROL_QUEUE_CAP entries on the sending task, never the render.
                inner
                    .queue
                    .retain(|queued| !matches!(*queued, Control::Unmute));
                inner.mute_latched = true;
            }
            Control::Stop => inner.stop_latched = true,
            other => {
                if inner.queue.len() >= CONTROL_QUEUE_CAP {
                    inner.rejected += 1;
                    return Err(ControlRejected::QueueFull);
                }
                inner.queue.push_back(other);
            }
        }
        inner.accepted += 1;
        Ok(())
    }

    #[must_use]
    pub fn stats(&self) -> ControlStats {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ControlStats {
            accepted: inner.accepted,
            rejected: inner.rejected,
        }
    }
}

// ------------------------------------------------------------------------------------ accounting

/// How one started block ended. Exactly one per block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BlockOutcome {
    /// Submitted by its deadline with all of its programme.
    OnTime,
    /// Submitted by its deadline, but the source ran short; the rest of the block is silence.
    Starved {
        cause: Starvation,
        silence_frames: usize,
    },
    /// Finished after its deadline and was dropped, not submitted.
    CpuMiss { late_by: u64 },
    /// The ordinary share of the ring was full: logical capacity rejection, not memory exhaustion.
    CapacityRejected,
    /// The device took only part of the block; the rest was discarded, not carried.
    ShortWrite { discarded_frames: usize },
}

/// Counters that never reset. For every started block exactly one of the first six moves, so
/// `blocks_started` is their sum; frames obey `generated = submitted + dropped + discarded`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderCounters {
    pub blocks_started: u64,
    pub blocks_on_time: u64,
    pub ingress_loss_blocks: u64,
    pub decode_delay_blocks: u64,
    pub cpu_miss_blocks: u64,
    pub capacity_rejected_blocks: u64,
    pub short_write_blocks: u64,
    /// Blocks whose start was delayed past their release. Informational: a late wake that still met
    /// the deadline is on time; one that did not is also a CPU miss.
    pub late_wakes: u64,
    /// Renders that used more than the window minus the reserve, late or not.
    pub reserve_breaches: u64,
    /// The device ran dry although every block had been supplied on time.
    pub driver_underruns: u64,
    /// The device ran dry after the loop had itself dropped a block, so the loop already explains it.
    pub underruns_explained: u64,
    pub frames_generated: u64,
    pub frames_submitted: u64,
    pub frames_dropped_late: u64,
    pub frames_dropped_capacity: u64,
    pub frames_discarded_short: u64,
    pub silence_frames_ingress: u64,
    pub silence_frames_decode: u64,
    pub max_cost_ticks: u64,
    pub max_late_ticks: u64,
    /// Ticks on which the control lock was busy and servicing was skipped.
    pub control_skipped: u64,
    pub epoch_resets: u64,
    pub events_dropped: u64,
    pub events_evicted: u64,
    pub events_lost_critical: u64,
}

/// What the loop reports to its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RenderEventKind {
    State { from: RenderState, to: RenderState },
    Block { index: u64, outcome: BlockOutcome },
    DriverUnderrun,
    ControlRejected,
    Fault { reason: FaultReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderEvent {
    /// The loop's tick when it happened.
    pub tick: u64,
    pub kind: RenderEventKind,
}

impl Critical for RenderEvent {
    fn critical(&self) -> bool {
        matches!(
            self.kind,
            RenderEventKind::Fault { .. }
                | RenderEventKind::State {
                    to: RenderState::Faulted,
                    ..
                }
        )
    }
}

/// What one [`RenderLoop::tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    /// The loop's tick after this call.
    pub now: u64,
    pub state: RenderState,
    /// The block that began rendering this tick.
    pub started: Option<u64>,
    /// The block that finished this tick, and how.
    pub finished: Option<(u64, BlockOutcome)>,
}

/// What a stop did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReport {
    /// Whether the device acknowledged the stop. Anything else leaves buffers quarantined.
    pub acknowledged: bool,
    /// Ticks from the stop request to the end of the stop.
    pub ticks: u64,
    /// Frames the device had accepted and not yet consumed when the stop began: they are
    /// irrevocable, and the stop could only flush them.
    pub irrevocable_tail_frames: u64,
    /// False once the driver's counter went backwards: `irrevocable_tail_frames` was read from a
    /// counter that has since been shown untrustworthy, and must not be used.
    pub tail_trusted: bool,
}

#[derive(Debug, Clone, Copy)]
struct Busy {
    index: u64,
    complete_tick: u64,
    deadline: u64,
    bytes_len: usize,
    frames: usize,
    starved: Option<(Starvation, usize)>,
}

/// What a loop reserved at admission, as capacities. Every figure is fixed by admission: start, reconnect,
/// cancel, a drain (acknowledged or not), a fault, a recovery and a restart never change one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderFootprint {
    pub session: StorageFootprint,
    /// Render events that fit without allocating.
    pub events: usize,
    /// Control commands that fit without allocating.
    pub control: usize,
}

/// What `new` reserves for the loop itself; `session` and the fixed-size buffers are the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopStorage {
    Events,
    Control,
}

// ------------------------------------------------------------------------------------ the loop

/// The protected render loop over one HAL session.
pub struct RenderLoop<B: DeviceBackend> {
    session: HalSession<B>,
    dsp: ProtectedBoardDsp,
    resampler: DriftResampler,
    cfg: RenderConfig,
    channels: usize,
    ring_depth: usize,
    lead_ticks: u64,
    stop_deadline_ticks: u64,

    state: RenderState,
    fault: Option<FaultReason>,
    /// The loop's own tick count: one per device tick it has stepped.
    now: u64,
    base: u64,
    next_index: u64,
    /// Whether `next_start` and `next_delay` are known for `next_index`.
    scheduled: bool,
    next_start: u64,
    next_delay: u64,
    busy: Option<Busy>,
    in_flight: usize,
    ordinary_exhausted: bool,

    // Everything the render path touches is allocated here, once.
    block: StereoAudioBlock,
    out: ProtectedOutput,
    bytes: [u8; OUT_BYTES_MAX],
    frames_rendered: u64,
    last_applied_gain: f32,

    epoch: u32,
    started_before: bool,
    resync_pending: bool,
    dropped_since_submit: u32,
    consecutive_misses: u32,
    dry_latched: bool,
    ramp_blocks: u32,
    cancel_mode: bool,
    stop_began: u64,
    stop_tail_frames: u64,
    stop_tail_trusted: bool,
    /// False after the driver's counter went backwards, until the owner reinstalls its mapping.
    mapping_valid: bool,
    last_mute_ack: Option<bool>,

    control: ControlPort,
    /// A start could not take the control lock to clear stale commands; the next tick that can will.
    clear_control_pending: bool,
    admit_faults: AdmitFaults,
    counters: RenderCounters,
    events: CriticalQueue<RenderEvent>,
}

impl<B: DeviceBackend> RenderLoop<B> {
    /// Admit a loop. Nothing audible happens: the session stays prepared and muted. Everything the
    /// render path needs is allocated here, before `Running`.
    pub fn new(
        session: HalSession<B>,
        dsp: ProtectedBoardDsp,
        resampler: DriftResampler,
        cfg: RenderConfig,
    ) -> Result<Self, RenderError> {
        Self::new_reserving(session, dsp, resampler, cfg, &mut |_| false)
    }

    /// `new` with each reservation made visible: `refuse` is asked before each one and a `true` refuses it, so
    /// a test can show that the refusal is typed and nothing was started. Production never refuses; the real
    /// reservation can still fail, and fails the same way.
    fn new_reserving(
        mut session: HalSession<B>,
        dsp: ProtectedBoardDsp,
        resampler: DriftResampler,
        cfg: RenderConfig,
        refuse: &mut dyn FnMut(LoopStorage) -> bool,
    ) -> Result<Self, RenderError> {
        if session.phase() != SessionPhase::Prepared {
            return Err(RenderError::SessionNotPrepared(session.phase()));
        }
        let Some(geometry) = session.geometry() else {
            return Err(RenderError::Geometry("the session has no geometry"));
        };
        if cfg.block_frames == 0
            || cfg.block_frames > FRAMES_PER_BLOCK
            || cfg.block_frames > geometry.frames_per_block
        {
            return Err(RenderError::BadConfig(
                "block_frames must be 1..=min(DSP block, HAL block)",
            ));
        }
        if cfg.period_ticks == 0 || cfg.window_ticks == 0 {
            return Err(RenderError::BadConfig(
                "period and window must be at least 1",
            ));
        }
        if cfg.reserve_percent > 99
            || cfg.max_submit_attempts == 0
            || cfg.watchdog_misses == 0
            || cfg.max_ramp_blocks == 0
        {
            return Err(RenderError::BadConfig(
                "reserve below 100%, and attempts, watchdog and ramp each at least 1",
            ));
        }
        if geometry.bytes_per_sample != 2 {
            return Err(RenderError::Geometry("only 16-bit samples are admitted"));
        }
        let channels = dsp.channel_count();
        if channels == 0 || channels > MAX_HARDWARE_CHANNELS || geometry.channels != channels {
            return Err(RenderError::Geometry(
                "the device and the protection DSP disagree on the channel count",
            ));
        }
        if cfg.reserve_slots >= geometry.ring_depth {
            return Err(RenderError::NoOrdinaryCapacity);
        }
        let Some(lead_ticks) = session.min_submission_lead_ticks() else {
            return Err(RenderError::LeadUnknown);
        };
        let Some(stop_deadline_ticks) = session.stop_deadline_ticks() else {
            return Err(RenderError::StopDeadlineUnknown);
        };
        // The session announced its own preparation; that is not news for this loop.
        while session.take_event().is_some() {}
        // Everything the loop, and the tasks that send to it, append to while it runs is reserved now with the
        // fallible API, so a start, a cancel, a drain or a reconnect never allocates and a refusal is an error here.
        let events = if refuse(LoopStorage::Events) {
            None
        } else {
            CriticalQueue::reserved(RENDER_EVENT_CAP).ok()
        };
        let Some(events) = events else {
            return Err(RenderError::StorageNotAdmitted {
                what: "event queue",
            });
        };
        let control = if refuse(LoopStorage::Control) {
            None
        } else {
            ControlPort::reserved().ok()
        };
        let Some(control) = control else {
            return Err(RenderError::StorageNotAdmitted {
                what: "control queue",
            });
        };
        Ok(Self {
            ring_depth: geometry.ring_depth,
            session,
            dsp,
            resampler,
            cfg,
            channels,
            lead_ticks,
            stop_deadline_ticks,
            state: RenderState::Ready,
            fault: None,
            now: 0,
            base: 0,
            next_index: 0,
            scheduled: false,
            next_start: 0,
            next_delay: 0,
            busy: None,
            in_flight: 0,
            ordinary_exhausted: false,
            block: StereoAudioBlock::silence(0),
            out: ProtectedOutput::new(),
            bytes: [0; OUT_BYTES_MAX],
            frames_rendered: 0,
            last_applied_gain: 0.0,
            epoch: 0,
            started_before: false,
            resync_pending: false,
            dropped_since_submit: 0,
            consecutive_misses: 0,
            dry_latched: false,
            ramp_blocks: 0,
            cancel_mode: false,
            stop_began: 0,
            stop_tail_frames: 0,
            stop_tail_trusted: true,
            mapping_valid: true,
            last_mute_ack: None,
            control,
            clear_control_pending: false,
            admit_faults: AdmitFaults::default(),
            counters: RenderCounters::default(),
            events,
        })
    }

    // ---- read-only views

    #[must_use]
    pub const fn state(&self) -> RenderState {
        self.state
    }

    #[must_use]
    pub const fn fault(&self) -> Option<FaultReason> {
        self.fault
    }

    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }

    #[must_use]
    pub const fn config(&self) -> RenderConfig {
        self.cfg
    }

    /// Whether no external control handle can mutate this loop's queue.
    /// A serialized enclosing owner can require this before taking the loop;
    /// it must then keep the loop and its control port private.
    /// This says nothing about commands queued before the other handles left.
    #[must_use]
    pub fn control_is_exclusive(&self) -> bool {
        Arc::strong_count(&self.control.inner) == 1
    }

    /// Project the next block without polling, allocating, pulling input or
    /// changing the device. Ready/Stopped project the next successful start,
    /// including its resampler epoch reset; Running/Muted use the active run.
    /// Drain/fault and unrepresentable tick arithmetic return `None`.
    /// The owner must still recheck control, authority and time before a tick.
    #[must_use]
    pub fn next_slot(&self) -> Option<RenderSlot> {
        self.now.checked_add(1)?;
        let restarting = matches!(self.state, RenderState::Ready | RenderState::Stopped);
        if !restarting && !matches!(self.state, RenderState::Running | RenderState::Muted) {
            return None;
        }
        let (base, index) = if restarting {
            (self.now, 0)
        } else {
            (self.base, self.next_index)
        };
        let release_tick = base
            .checked_add(1)?
            .checked_add(index.checked_mul(self.cfg.period_ticks)?)?;
        let deadline_tick = release_tick.checked_add(self.cfg.window_ticks)?;
        let presentation_tick = deadline_tick.checked_add(self.lead_ticks)?;
        let mut planned = self.resampler.clone();
        if restarting && self.started_before {
            planned
                .begin_epoch(self.epoch.wrapping_add(1), ResetReason::NewSource)
                .ok()?;
        } else if !restarting && self.resync_pending {
            // The caller will tick only with available source data; render_block
            // then resets the lost stream before its next pull. Model that same
            // reset, rather than undercounting its new priming requirement.
            planned
                .begin_epoch(self.epoch.wrapping_add(1), ResetReason::Discontinuity)
                .ok()?;
        }
        let source_phase = planned.phase_state();
        let first_output_source_frames = planned.clone().plan(1);
        Some(RenderSlot {
            now: self.now,
            index,
            block_frames: self.cfg.block_frames,
            release_tick,
            deadline_tick,
            presentation_tick,
            required_source_frames: planned.plan(u64::try_from(self.cfg.block_frames).ok()?),
            first_output_source_frames,
            source_phase,
            in_progress: self.busy.is_some(),
        })
    }

    #[must_use]
    pub const fn counters(&self) -> RenderCounters {
        self.counters
    }

    /// Whether the last hardware-mute request was acknowledged: `None` before any was made.
    #[must_use]
    pub const fn last_mute_acknowledged(&self) -> Option<bool> {
        self.last_mute_ack
    }

    /// Whether the presentation mapping can be used. It is invalid from a driver counter regress until
    /// [`reinstall_presentation_mapping`](Self::reinstall_presentation_mapping).
    #[must_use]
    pub const fn presentation_mapping_valid(&self) -> bool {
        self.mapping_valid
    }

    /// Blocks handed to the device and not yet reported complete.
    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Whether a block has started rendering and has not ended: audio it carries has been pulled from the
    /// source and is not yet in the device. A cancel, a fault or a recovery drops such a block WITHOUT an
    /// outcome, so the cumulative block counters never balance again afterwards; this is the loop's own
    /// state, not a counter equality.
    #[must_use]
    pub const fn block_in_progress(&self) -> bool {
        self.busy.is_some()
    }

    /// Read-only view of the HAL session.
    #[must_use]
    pub const fn session(&self) -> &HalSession<B> {
        &self.session
    }

    #[must_use]
    pub const fn dsp(&self) -> &ProtectedBoardDsp {
        &self.dsp
    }

    /// Give the session back (for example to close it). The loop's state is lost.
    #[must_use]
    pub fn into_session(self) -> HalSession<B> {
        self.session
    }

    /// The protection DSP, for the control plane (a profile switch, a fault clear). It is the D02
    /// owner's API; the loop only reads its status.
    pub fn dsp_mut(&mut self) -> &mut ProtectedBoardDsp {
        &mut self.dsp
    }

    /// A handle other tasks use to send commands. Clones share one queue.
    #[must_use]
    pub fn control_port(&self) -> ControlPort {
        self.control.clone()
    }

    #[must_use]
    pub fn control_stats(&self) -> ControlStats {
        self.control.stats()
    }

    pub fn set_admit_faults(&mut self, faults: AdmitFaults) {
        self.admit_faults = faults;
    }

    /// A read-only report of the capacities reserved at admission (see [`RenderFootprint`]). It is not a
    /// memory measurement: it says what was asked for and kept, not what the process uses.
    #[must_use]
    pub fn storage_footprint(&self) -> RenderFootprint {
        RenderFootprint {
            session: self.session.storage_footprint(),
            events: self.events.reserved_capacity(),
            control: self.control.reserved_capacity(),
        }
    }

    /// The next render event, oldest first. The queue is bounded: see the counters for what it lost.
    pub fn take_event(&mut self) -> Option<RenderEvent> {
        self.events.pop()
    }

    // ---- timeline

    const fn release(&self, index: u64) -> u64 {
        self.base + 1 + index * self.cfg.period_ticks
    }

    const fn deadline(&self, index: u64) -> u64 {
        self.release(index) + self.cfg.window_ticks
    }

    /// The tick at which block `index` is presented: its deadline plus the device's minimum lead.
    #[must_use]
    pub const fn presentation_tick(&self, index: u64) -> u64 {
        self.deadline(index) + self.lead_ticks
    }

    const fn ordinary_cap(&self) -> usize {
        if self.ordinary_exhausted {
            0
        } else {
            self.ring_depth - self.cfg.reserve_slots
        }
    }

    // ---- events and state

    fn emit(&mut self, kind: RenderEventKind) {
        let event = RenderEvent {
            tick: self.now,
            kind,
        };
        match self.events.push(event) {
            PushOutcome::Queued => {}
            PushOutcome::DroppedOrdinary => self.counters.events_dropped += 1,
            PushOutcome::EvictedOrdinary => self.counters.events_evicted += 1,
            PushOutcome::LostCritical => self.counters.events_lost_critical += 1,
        }
    }

    fn set_state(&mut self, to: RenderState) {
        if self.state != to {
            let from = self.state;
            self.state = to;
            self.emit(RenderEventKind::State { from, to });
        }
    }

    /// Latch a fault: ask for a hardware mute, record whether it was acknowledged, stop rendering.
    /// Whatever the device may still read stays where it is; the session quarantines it.
    fn fail(&mut self, reason: FaultReason) {
        if self.state == RenderState::Faulted {
            return;
        }
        // The session reports a backwards counter as one of its own faults. Wherever the loop first
        // learns of that fault (a tick, a submit or a drain), it is this loop's own reason, and the
        // mapping built on the old counter goes with it.
        let reason = if reason == FaultReason::SessionFaulted && self.session.counter_regressed() {
            FaultReason::CounterRegress
        } else {
            reason
        };
        if reason == FaultReason::CounterRegress {
            self.invalidate_presentation_mapping();
        }
        self.last_mute_ack = match self.session.abort_mute() {
            Ok(report) => Some(report.mute_acknowledged),
            Err(_) => Some(false),
        };
        let _ = self.dsp.set_muted(true);
        self.busy = None;
        self.fault = Some(reason);
        self.emit(RenderEventKind::Fault { reason });
        self.set_state(RenderState::Faulted);
    }

    /// The driver's counter went backwards: every figure derived from it is dropped. The dry latch and
    /// the stop's tail were read from the old counter, and the owner's mapping was anchored on it.
    /// Buffers are not touched: they stay held until a reset is acknowledged.
    fn invalidate_presentation_mapping(&mut self) {
        self.mapping_valid = false;
        self.dry_latched = false;
        self.stop_tail_trusted = false;
    }

    // ---- lifecycle

    /// `Ready` or `Stopped` -> `Running`. Refused, with nothing touched, unless the protection DSP is
    /// active and admission succeeds; an injected start failure is such a refusal.
    pub fn start(&mut self, pre: StartPreconditions) -> Result<(), RenderError> {
        self.start_with_mute(pre, false)
    }

    /// Whether the owned prepared HAL declares bounded stop/flush support.
    /// This is a capability, not an acknowledgement of a stop.
    #[must_use]
    pub fn stop_flush_supported(&self) -> bool {
        self.state == RenderState::Ready && self.session.stop_flush_supported()
    }

    /// Current local join readiness after actual format, protected DSP, prime
    /// and bounded stop/flush capability admission. It is not a stop ACK.
    #[must_use]
    pub fn prepared_join_ready(&self) -> bool {
        self.silent_start_admissible()
            && self.stop_flush_supported()
            && self.presentation_mapping_valid()
            && matches!(self.dsp.status(), BoardStatus::Active)
            && self.session.primed_silence_blocks() >= self.session.required_silence_blocks()
    }

    /// Admission predicate for the software-silent start path. It does not
    /// prove that the HAL amplifier remains muted after the backend starts.
    #[must_use]
    pub fn silent_start_admissible(&self) -> bool {
        matches!(self.state, RenderState::Ready | RenderState::Stopped)
            && self.session.silent_prepared_after_reset()
            && self.dsp.applied_gain() == 0.0
    }

    /// Software-silent start: the HAL still calls its normal backend unmute. The
    /// owned prepared queue must have been reset and contain only silence, and
    /// the protection ramp must already be at zero. No source is pulled here.
    pub fn start_silent(&mut self, pre: StartPreconditions) -> Result<(), RenderError> {
        self.start_with_mute(pre, true)
    }

    fn start_with_mute(
        &mut self,
        pre: StartPreconditions,
        silent: bool,
    ) -> Result<(), RenderError> {
        if silent && (!self.session.silent_prepared_after_reset() || self.dsp.applied_gain() != 0.0)
        {
            return Err(RenderError::SilentStartUnproven);
        }
        if !matches!(self.state, RenderState::Ready | RenderState::Stopped) {
            return Err(RenderError::WrongState(self.state));
        }
        if !self.mapping_valid {
            return Err(RenderError::PresentationMappingInvalidated);
        }
        if self.admit_faults.start {
            return Err(RenderError::AdmissionFailed(AdmitPoint::Start));
        }
        if !matches!(self.dsp.status(), BoardStatus::Active) {
            return Err(RenderError::ProtectionNotActive);
        }
        self.dsp
            .set_muted(silent)
            .map_err(|_| RenderError::ProtectionNotActive)?;
        // Events from an earlier run are not news: a fault left over from one would otherwise fault
        // this run on its first tick.
        while self.session.take_event().is_some() {}
        if let Err(error) = self.session.start(pre) {
            let _ = self.dsp.set_muted(true);
            // A backend failure may already have faulted the HAL and
            // quarantined retained buffers. Mirror that real state; an
            // ordinary precondition refusal while Prepared remains retryable.
            if self.session.phase() == SessionPhase::Faulted {
                self.fail(FaultReason::SessionFaulted);
            }
            return Err(RenderError::Session(error));
        }
        if self.started_before {
            self.begin_epoch(ResetReason::NewSource);
        }
        self.started_before = true;
        // A command queued before this start belongs to an earlier run. Never wait for the lock.
        self.clear_control_pending = true;
        self.drop_stale_control();
        self.base = self.now;
        self.next_index = 0;
        self.scheduled = false;
        self.busy = None;
        self.in_flight = 0;
        self.ordinary_exhausted = false;
        self.dropped_since_submit = 0;
        self.consecutive_misses = 0;
        self.dry_latched = false;
        self.cancel_mode = false;
        self.fault = None;
        self.set_state(if silent {
            RenderState::Muted
        } else {
            RenderState::Running
        });
        Ok(())
    }

    /// Ramp to silence and keep the timeline. The device stays unmuted until a stop or a fault.
    pub fn mute(&mut self) -> Result<(), RenderError> {
        match self.state {
            RenderState::Running => {
                let _ = self.dsp.set_muted(true);
                self.set_state(RenderState::Muted);
                Ok(())
            }
            RenderState::Muted => Ok(()),
            other => Err(RenderError::WrongState(other)),
        }
    }

    /// `Muted` -> `Running`. Refused unless the protection DSP is active.
    pub fn unmute(&mut self) -> Result<(), RenderError> {
        match self.state {
            RenderState::Muted => {
                self.dsp
                    .set_muted(false)
                    .map_err(|_| RenderError::ProtectionNotActive)?;
                self.set_state(RenderState::Running);
                Ok(())
            }
            RenderState::Running => Ok(()),
            other => Err(RenderError::WrongState(other)),
        }
    }

    /// The user's volume, `0.0..=1.0`; the applied gain follows by a bounded slew.
    pub fn set_gain(&mut self, gain: f32) -> f32 {
        self.dsp.set_user_gain(gain)
    }

    /// A source discontinuity: a new resampler epoch and a protection fade-in. Refused, with the
    /// playing stream untouched, if admission for the new stream fails.
    pub fn reconnect(&mut self) -> Result<(), RenderError> {
        if !matches!(self.state, RenderState::Running | RenderState::Muted) {
            return Err(RenderError::WrongState(self.state));
        }
        if self.admit_faults.reconnect {
            return Err(RenderError::AdmissionFailed(AdmitPoint::Reconnect));
        }
        self.begin_epoch(ResetReason::Rejoin);
        Ok(())
    }

    fn begin_epoch(&mut self, reason: ResetReason) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.resampler.begin_epoch(self.epoch, reason).is_ok() {
            self.counters.epoch_resets += 1;
        }
        self.dsp.on_source_event(SourceEvent::Reconnect);
        self.resync_pending = false;
    }

    /// Graceful stop: ramp to silence while the timeline runs, then ask the device to flush and wait
    /// for its acknowledgment. Driven by [`tick`](Self::tick).
    pub fn stop(&mut self) -> Result<(), RenderError> {
        if !matches!(self.state, RenderState::Running | RenderState::Muted) {
            return Err(RenderError::WrongState(self.state));
        }
        if self.admit_faults.drain {
            // Ordinary admission is gone; the ramp-out must finish on the reserve.
            self.ordinary_exhausted = true;
        }
        let _ = self.dsp.set_muted(true);
        self.ramp_blocks = 0;
        self.cancel_mode = false;
        self.begin_stop();
        Ok(())
    }

    /// Cancel: mute the device now and wait, bounded by the stop deadline, for its acknowledgment.
    /// The ramp is skipped; the device mute is not.
    pub fn cancel(&mut self) -> Result<(), RenderError> {
        if !matches!(self.state, RenderState::Running | RenderState::Muted) {
            return Err(RenderError::WrongState(self.state));
        }
        if self.admit_faults.cancel {
            self.ordinary_exhausted = true;
        }
        let _ = self.dsp.set_muted(true);
        self.cancel_mode = true;
        self.begin_stop();
        match self.session.abort_mute() {
            Ok(report) => self.last_mute_ack = Some(report.mute_acknowledged),
            Err(_) => self.last_mute_ack = Some(false),
        }
        self.busy = None;
        Ok(())
    }

    /// Cancel a prepared loop without ever starting the backend or pulling a
    /// source. Prepared silence priming can still be in HAL custody; use the
    /// same acknowledged flush and bounded timeout path as an active cancel.
    pub fn cancel_prepared(&mut self) -> Result<(), RenderError> {
        if self.state != RenderState::Ready || self.session.phase() != SessionPhase::Prepared {
            return Err(RenderError::WrongState(self.state));
        }
        let _ = self.dsp.set_muted(true);
        self.cancel_mode = true;
        self.begin_stop();
        match self.session.abort_mute() {
            Ok(report) => self.last_mute_ack = Some(report.mute_acknowledged),
            Err(_) => self.last_mute_ack = Some(false),
        }
        self.busy = None;
        Ok(())
    }

    fn begin_stop(&mut self) {
        self.stop_began = self.now;
        self.stop_tail_trusted = true;
        self.stop_tail_frames = self
            .session
            .irrevocable_until_frames()
            .saturating_sub(self.session.position().consumed_frames);
        self.set_state(RenderState::Draining);
    }

    /// Leave `Faulted` by asking the device for a reset. A lost device cannot be recovered.
    pub fn recover(&mut self) -> Result<(), RenderError> {
        if self.state != RenderState::Faulted {
            return Err(RenderError::WrongState(self.state));
        }
        match self.session.reset_device() {
            Ok(()) => {
                self.in_flight = 0;
                self.busy = None;
                self.fault = None;
                // The faults that put the loop here have been dealt with.
                while self.session.take_event().is_some() {}
                self.set_state(RenderState::Ready);
                Ok(())
            }
            Err(error) => Err(RenderError::Session(error)),
        }
    }

    /// The owner has re-derived its presentation mapping from the device's new counter, so the loop
    /// may start again. Allowed only in `Ready`, which is where an acknowledged reset leaves a loop
    /// that was `Faulted`: a mapping cannot be reinstalled while the old counter is still the only one
    /// there is. The loop cannot do this itself, because the mapping lives with its owner.
    pub fn reinstall_presentation_mapping(&mut self) -> Result<(), RenderError> {
        if self.state != RenderState::Ready {
            return Err(RenderError::WrongState(self.state));
        }
        self.mapping_valid = true;
        Ok(())
    }

    // ---- the tick

    /// One device tick. The device advances, control is serviced, the block in progress is finished,
    /// and the next one is started if it is due. At most one block finishes and one starts.
    pub fn tick<S: RenderSource, T: TimingModel>(
        &mut self,
        source: &mut S,
        timing: &mut T,
    ) -> TickReport {
        self.tick_with_start_permission(source, timing, true)
    }

    /// Advance the device and finish already-started work, optionally permitting
    /// a new source block. `false` never pulls new source or moves the fixed
    /// timeline; a later admitted start still faces its original deadline.
    /// Cancel/flush acknowledgement continues normally. A graceful ramp requires
    /// future permitted rendering; immediate invalidation must use `cancel`.
    pub fn tick_with_start_permission<S: RenderSource, T: TimingModel>(
        &mut self,
        source: &mut S,
        timing: &mut T,
        start_permitted: bool,
    ) -> TickReport {
        let mut report = TickReport {
            now: self.now,
            state: self.state,
            started: None,
            finished: None,
        };
        if !matches!(
            self.state,
            RenderState::Running | RenderState::Muted | RenderState::Draining
        ) {
            return report;
        }
        let poll = self.session.step();
        self.now += 1;
        self.in_flight = self.in_flight.saturating_sub(poll.completions);
        self.observe_session();
        if self.state != RenderState::Faulted {
            self.service_control();
        }
        if self.state != RenderState::Faulted {
            self.observe_dry();
        }
        if self.state == RenderState::Draining && self.cancel_mode {
            self.wait_for_cancel_ack();
        } else if self.state != RenderState::Faulted && self.state != RenderState::Stopped {
            self.run_block(source, timing, &mut report, start_permitted);
        }
        report.now = self.now;
        report.state = self.state;
        report
    }

    /// Fold the session's own events into the loop: a fault there is a fault here, and a lost device
    /// is told apart from any other fault.
    fn observe_session(&mut self) {
        let mut lost = false;
        let mut faulted = false;
        while let Some(event) = self.session.take_event() {
            match event.kind {
                SessionEventKind::Fault { code } => {
                    faulted = true;
                    lost |= matches!(
                        code,
                        FaultCode::DeviceLost
                            | FaultCode::DriverError {
                                error: DriverError::Gone,
                                ..
                            }
                    );
                }
                SessionEventKind::DeviceLostWhileFaulted => lost = true,
                _ => {}
            }
        }
        if lost {
            self.fail(FaultReason::DeviceLost);
        } else if faulted || self.session.phase() == SessionPhase::Faulted {
            self.fail(FaultReason::SessionFaulted);
        }
    }

    /// Clear commands left over from before a start, if the control lock is free; otherwise leave the
    /// flag set and let a later tick do it.
    fn drop_stale_control(&mut self) {
        if !self.clear_control_pending {
            return;
        }
        let mut inner = match self.control.inner.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        inner.queue.clear();
        inner.mute_latched = false;
        inner.stop_latched = false;
        self.clear_control_pending = false;
    }

    fn service_control(&mut self) {
        self.drop_stale_control();
        if self.clear_control_pending {
            self.counters.control_skipped += 1;
            return;
        }
        let mut taken: [Option<Control>; MAX_CONTROL_PER_TICK] = [None; MAX_CONTROL_PER_TICK];
        let (mute, stop) = {
            let mut inner = match self.control.inner.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    self.counters.control_skipped += 1;
                    return;
                }
            };
            let latched = (
                std::mem::take(&mut inner.mute_latched),
                std::mem::take(&mut inner.stop_latched),
            );
            for slot in &mut taken {
                *slot = inner.queue.pop_front();
            }
            latched
        };
        // Urgent first: a mute or a stop is never behind a queue of gain changes.
        if mute {
            let _ = self.mute();
        }
        if stop {
            let _ = self.stop();
        }
        for control in taken.into_iter().flatten() {
            match control {
                Control::SetGain(gain) => {
                    self.set_gain(gain);
                }
                Control::Unmute => {
                    let _ = self.unmute();
                }
                Control::Reconnect => {
                    let _ = self.reconnect();
                }
                Control::Mute => {
                    let _ = self.mute();
                }
                Control::Stop => {
                    let _ = self.stop();
                }
            }
        }
    }

    /// The device ran out of audio. If the loop had dropped a block since its last good submit, the
    /// loop already explains it; if not, the device did it on its own, and that is a driver underrun.
    fn observe_dry(&mut self) {
        if !matches!(self.state, RenderState::Running | RenderState::Muted) {
            self.dry_latched = false;
            return;
        }
        let position = self.session.position();
        let accepted = self.session.irrevocable_until_frames();
        let observable = !matches!(position.class, PositionClass::Unknown);
        let dry = observable && accepted > 0 && position.consumed_frames >= accepted;
        if !dry {
            self.dry_latched = false;
        } else if !self.dry_latched {
            self.dry_latched = true;
            if self.dropped_since_submit > 0 {
                self.counters.underruns_explained += 1;
            } else {
                self.counters.driver_underruns += 1;
                self.emit(RenderEventKind::DriverUnderrun);
            }
        }
    }

    fn wait_for_cancel_ack(&mut self) {
        if self.session.phase() == SessionPhase::Prepared {
            self.in_flight = 0;
            self.finish_stop();
        } else if self.now.saturating_sub(self.stop_began) > self.stop_deadline_ticks {
            // No acknowledgment in time. What is in flight is quarantined, never freed: the device has
            // not said it stopped reading.
            let _ = self.session.cancel_drain();
            self.fail(FaultReason::DrainTimedOut);
        }
    }

    fn finish_stop(&mut self) {
        self.busy = None;
        self.set_state(RenderState::Stopped);
    }

    // ---- one block

    fn run_block<S: RenderSource, T: TimingModel>(
        &mut self,
        source: &mut S,
        timing: &mut T,
        report: &mut TickReport,
        start_permitted: bool,
    ) {
        if let Some(busy) = self.busy
            && self.now >= busy.complete_tick
        {
            self.busy = None;
            let outcome = self.finish_block(busy);
            report.finished = Some((busy.index, outcome));
            if self.state == RenderState::Draining && !self.cancel_mode {
                self.ramp_blocks += 1;
                if self.last_applied_gain == 0.0 || self.ramp_blocks >= self.cfg.max_ramp_blocks {
                    self.drain_now();
                }
            }
            if self.state == RenderState::Faulted || self.state == RenderState::Stopped {
                return;
            }
        }
        if self.busy.is_none() && start_permitted {
            if !self.scheduled {
                self.schedule_next(timing);
            }
            if self.now >= self.next_start {
                self.start_block(source, timing, report);
            }
        }
    }

    fn schedule_next<T: TimingModel>(&mut self, timing: &mut T) {
        let delay = timing.wake_delay(self.next_index);
        self.next_delay = delay;
        // Scheduled only once the previous block has finished, so the one CPU is already free.
        self.next_start = self.release(self.next_index) + delay;
        self.scheduled = true;
    }

    fn start_block<S: RenderSource, T: TimingModel>(
        &mut self,
        source: &mut S,
        timing: &mut T,
        report: &mut TickReport,
    ) {
        let index = self.next_index;
        let delay = self.next_delay;
        let (frames, starved) = self.render_block(source);
        if self.state == RenderState::Faulted {
            return;
        }
        let bytes_len = self.interleave(frames);
        let cost = timing.render_cost(index);
        let busy = Busy {
            index,
            complete_tick: self.now + cost,
            deadline: self.deadline(index),
            bytes_len,
            frames,
            starved,
        };
        self.counters.blocks_started += 1;
        self.counters.frames_generated += to_u64(frames);
        self.counters.max_cost_ticks = self.counters.max_cost_ticks.max(cost);
        if delay > 0 {
            self.counters.late_wakes += 1;
        }
        if cost * 100 > self.cfg.window_ticks * u64::from(100 - self.cfg.reserve_percent) {
            self.counters.reserve_breaches += 1;
        }
        self.next_index += 1;
        self.scheduled = false;
        report.started = Some(index);
        self.busy = Some(busy);
        if cost == 0 {
            self.busy = None;
            let outcome = self.finish_block(busy);
            report.finished = Some((index, outcome));
            if self.state == RenderState::Draining && !self.cancel_mode {
                self.ramp_blocks += 1;
                if self.last_applied_gain == 0.0 || self.ramp_blocks >= self.cfg.max_ramp_blocks {
                    self.drain_now();
                }
            }
        }
    }

    /// Source -> resampler -> protection into the preallocated buffers. Returns the frames made and
    /// whether the source ran short.
    fn render_block<S: RenderSource>(
        &mut self,
        source: &mut S,
    ) -> (usize, Option<(Starvation, usize)>) {
        let n = self.cfg.block_frames;
        if self.resync_pending && source.starvation().is_none() {
            // The content that was lost is gone: the stream resumes as a new epoch, faded in.
            self.begin_epoch(ResetReason::Discontinuity);
        }
        let rendered = self.resampler.render(
            source,
            &mut self.block.left[..n],
            &mut self.block.right[..n],
        );
        let produced = match rendered {
            Ok(report) => report.produced.min(n),
            Err(_) => {
                self.fail(FaultReason::RenderInternal);
                return (0, None);
            }
        };
        let mut starved = None;
        if produced < n {
            self.block.left[produced..n].fill(0.0);
            self.block.right[produced..n].fill(0.0);
            if !source.end_of_stream() {
                let cause = source.starvation().unwrap_or(Starvation::DecodeDelay);
                if cause == Starvation::IngressLoss {
                    self.resync_pending = true;
                }
                starved = Some((cause, n - produced));
            }
        }
        self.block.frames = n;
        self.block.start_frame = self.frames_rendered;
        self.frames_rendered += to_u64(n);
        let block_report = self.dsp.render_into(&self.block, &mut self.out);
        self.last_applied_gain = block_report.applied_gain;
        if !matches!(block_report.status, BoardStatus::Active)
            && matches!(self.state, RenderState::Running | RenderState::Muted)
        {
            self.fail(FaultReason::ProtectionFault);
        }
        (n, starved)
    }

    /// The protected output as interleaved 16-bit samples in the configured byte order.
    fn interleave(&mut self, frames: usize) -> usize {
        let mut at = 0_usize;
        for f in 0..frames {
            for lane in self.out.samples.iter().take(self.channels) {
                let sample = lane.get(f).copied().unwrap_or(0);
                let pair = match self.cfg.output_endian {
                    Endian::Big => sample.to_be_bytes(),
                    Endian::Little => sample.to_le_bytes(),
                };
                if let Some(dst) = self.bytes.get_mut(at..at + 2) {
                    dst.copy_from_slice(&pair);
                }
                at += 2;
            }
        }
        at
    }

    /// A block's render is finished. Late: drop it. In time: hand it to the device.
    fn finish_block(&mut self, busy: Busy) -> BlockOutcome {
        let frames = to_u64(busy.frames);
        let late_by = self.now.saturating_sub(busy.deadline);
        let outcome = if late_by > 0 {
            self.counters.cpu_miss_blocks += 1;
            self.counters.frames_dropped_late += frames;
            self.counters.max_late_ticks = self.counters.max_late_ticks.max(late_by);
            self.dropped_since_submit += 1;
            self.consecutive_misses += 1;
            BlockOutcome::CpuMiss { late_by }
        } else {
            self.consecutive_misses = 0;
            self.submit_block(&busy)
        };
        if !matches!(outcome, BlockOutcome::OnTime) {
            self.emit(RenderEventKind::Block {
                index: busy.index,
                outcome,
            });
        }
        if self.consecutive_misses >= self.cfg.watchdog_misses {
            self.fail(FaultReason::WatchdogTripped);
        }
        outcome
    }

    fn submit_block(&mut self, busy: &Busy) -> BlockOutcome {
        let frames = to_u64(busy.frames);
        let cap = if self.state == RenderState::Draining {
            self.ring_depth
        } else {
            self.ordinary_cap()
        };
        if self.in_flight >= cap {
            self.counters.capacity_rejected_blocks += 1;
            self.counters.frames_dropped_capacity += frames;
            return BlockOutcome::CapacityRejected;
        }
        let frame_bytes = self.channels * 2;
        let mut offset = 0_usize;
        let mut attempts = 0_u8;
        let mut faulted = false;
        while offset < busy.bytes_len && attempts < self.cfg.max_submit_attempts {
            attempts += 1;
            let Some(rest) = self.bytes.get(offset..busy.bytes_len) else {
                break;
            };
            match self.session.submit(rest) {
                Ok(receipt) => {
                    if receipt.accepted_bytes > 0 {
                        self.in_flight += 1;
                        offset += receipt.accepted_bytes;
                        self.dropped_since_submit = 0;
                    }
                    // The token is deliberately left in the receipt and goes out of scope with it. It is a
                    // claim check that owns nothing and has no `Drop`; the session frees the slot on the
                    // device's acknowledgment, whatever becomes of it.
                }
                Err(SessionError::NoFreeSlot) => {
                    if offset == 0 {
                        self.counters.capacity_rejected_blocks += 1;
                        self.counters.frames_dropped_capacity += frames;
                        return BlockOutcome::CapacityRejected;
                    }
                    // Part of the block is in; the ring is full for the rest.
                    break;
                }
                Err(_) => {
                    faulted = true;
                    break;
                }
            }
        }
        let submitted = offset / frame_bytes;
        self.counters.frames_submitted += to_u64(submitted);
        if offset < busy.bytes_len {
            let discarded = busy.frames - submitted;
            self.counters.short_write_blocks += 1;
            self.counters.frames_discarded_short += to_u64(discarded);
            if faulted {
                // The session faulted; the frames never reached the device.
                self.fail(FaultReason::SessionFaulted);
            }
            return BlockOutcome::ShortWrite {
                discarded_frames: discarded,
            };
        }
        match busy.starved {
            Some((cause, silence_frames)) => {
                match cause {
                    Starvation::IngressLoss => {
                        self.counters.ingress_loss_blocks += 1;
                        self.counters.silence_frames_ingress += to_u64(silence_frames);
                    }
                    Starvation::DecodeDelay => {
                        self.counters.decode_delay_blocks += 1;
                        self.counters.silence_frames_decode += to_u64(silence_frames);
                    }
                }
                BlockOutcome::Starved {
                    cause,
                    silence_frames,
                }
            }
            None => {
                self.counters.blocks_on_time += 1;
                BlockOutcome::OnTime
            }
        }
    }

    /// Everything the ramp-out had to say is submitted: ask the device to flush and wait, bounded by
    /// its stated stop deadline. Only an acknowledgment lets the session free what is in flight.
    fn drain_now(&mut self) {
        match self.session.drain(self.stop_deadline_ticks) {
            Ok(DrainOutcome::Acknowledged { waited_ticks }) => {
                self.now += waited_ticks;
                self.in_flight = 0;
                self.finish_stop();
            }
            Ok(DrainOutcome::TimedOut { waited_ticks }) => {
                self.now += waited_ticks;
                self.fail(FaultReason::DrainTimedOut);
            }
            Err(_) => self.fail(FaultReason::SessionFaulted),
        }
    }

    /// How a stop that has finished went. Meaningful in `Stopped` or `Faulted`.
    #[must_use]
    pub fn stop_report(&self) -> StopReport {
        StopReport {
            acknowledged: self.state == RenderState::Stopped,
            ticks: self.now.saturating_sub(self.stop_began),
            irrevocable_tail_frames: self.stop_tail_frames,
            tail_trusted: self.stop_tail_trusted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_dsp::protection::{Admission, synthetic_calibration_for};
    use franken_dsp::resample::ResamplerConfig;
    use franken_hal::abi::{DeviceEvent, RawGeometry};
    use franken_hal::backend::{FakeBackend, FakeCall, FakeConfig, FakeProbe};
    use franken_hal::session::SessionConfig;
    use franken_hal::slots::{LeakLedger, SlotState};

    const READY: StartPreconditions = StartPreconditions {
        presentation_mapping_installed: true,
        safe_gain_installed: true,
    };
    const BLOCK: usize = 64;
    type Fixture = (RenderLoop<FakeBackend>, FakeProbe, Arc<LeakLedger>);

    fn profile() -> franken_board_profile::BoardProfile {
        franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S1")
            .unwrap()
    }

    /// Four 64-frame slots, two channels, a completion two ticks after a submit, a minimum lead of
    /// one tick, a stop deadline of eight, and a flush acknowledged one tick after it is asked.
    fn fake_config() -> FakeConfig {
        let mut cfg = FakeConfig::retained();
        cfg.geometry = RawGeometry {
            ring_depth: 4,
            frames_per_block: 64,
            channels: 2,
            bytes_per_sample: 2,
        };
        cfg.completion_delay_ticks = 2;
        cfg
    }

    fn dsp() -> ProtectedBoardDsp {
        let profile = profile();
        let calibration = synthetic_calibration_for(&profile);
        ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
    }

    fn build(cfg: FakeConfig, render: RenderConfig) -> Fixture {
        let (backend, probe) = FakeBackend::new(cfg);
        let ledger = Arc::new(LeakLedger::new(64));
        let config = SessionConfig::with_ledger(Arc::clone(&ledger), 2);
        let mut session = HalSession::open(profile(), backend, config).unwrap();
        session.prepare().unwrap();
        let resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
        (
            RenderLoop::new(session, dsp(), resampler, render).unwrap(),
            probe,
            ledger,
        )
    }

    fn standard() -> Fixture {
        build(fake_config(), RenderConfig::standard(BLOCK))
    }

    /// `standard()`, already started.
    fn started() -> Fixture {
        let (mut l, probe, ledger) = standard();
        l.start(READY).unwrap();
        (l, probe, ledger)
    }

    #[test]
    fn silent_start_refuses_reset_without_playback_discard_evidence() {
        for copying in [false, true] {
            let mut cfg = fake_config();
            if copying {
                cfg.abi = FakeConfig::copying().abi;
            }
            let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
            assert!(l.session.abort_mute().unwrap().mute_acknowledged);
            l.session.reset_device().unwrap();
            l.session.prime_silence().unwrap();
            let before = probe.calls().len();
            assert_eq!(l.start_silent(READY), Err(RenderError::SilentStartUnproven));
            assert_eq!(l.state(), RenderState::Ready);
            assert_eq!(probe.calls().len(), before);
        }
    }

    #[test]
    fn failed_hal_start_or_unmute_faults_loop_and_preserves_retained_silence() {
        use franken_hal::backend::{DriverError, Op};
        for fail_start in [true, false] {
            let mut cfg = fake_config();
            cfg.completion_delay_ticks = 100;
            cfg.unmute_ack = fail_start;
            let (mut render, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
            probe.capture_submissions(4);
            render.session.prime_silence().unwrap();
            let held = probe.pending_slots();
            let captured = probe.captured_submissions();
            assert_eq!(held.len(), 1);
            assert_eq!(captured, vec![vec![0; BLOCK * 4]]);
            if fail_start {
                probe.fail_next(Op::Start, DriverError::Errno(5));
            }
            assert!(matches!(render.start(READY), Err(RenderError::Session(_))));
            assert_eq!(render.session.phase(), SessionPhase::Faulted);
            assert_eq!(render.state(), RenderState::Faulted);
            assert_eq!(render.fault(), Some(FaultReason::SessionFaulted));
            assert!(!render.stop_report().acknowledged);
            assert!(
                render
                    .session
                    .slot_states()
                    .contains(&SlotState::Quarantined)
            );
            assert_eq!(probe.pending_slots(), held);
            assert_eq!(probe.kernel_touch_pending(), (1, 0));
            assert_eq!(probe.captured_submissions(), captured);
            assert_eq!(
                probe
                    .calls()
                    .iter()
                    .filter(|call| **call == FakeCall::Start)
                    .count(),
                1
            );
            let mut source = ToneSource::new();
            let mut timing = ScriptedTiming::default();
            let tick = render.tick(&mut source, &mut timing);
            assert_eq!(tick.started, None);
            assert_eq!(source.pos, 0);
            assert_eq!(probe.captured_submissions(), captured);
            assert_eq!(probe.use_after_free(), 0);
            assert_eq!(probe.modified_while_owned(), 0);
        }
    }

    #[test]
    fn start_precondition_refusal_stays_prepared_and_valid_retry_starts() {
        let (mut render, probe, _) = standard();
        let refusal = StartPreconditions {
            presentation_mapping_installed: true,
            safe_gain_installed: false,
        };
        assert!(matches!(
            render.start(refusal),
            Err(RenderError::Session(_))
        ));
        assert_eq!(render.session.phase(), SessionPhase::Prepared);
        assert_eq!(render.state(), RenderState::Ready);
        assert!(!probe.calls().contains(&FakeCall::Start));
        render.start(READY).unwrap();
        assert_eq!(render.state(), RenderState::Running);
        assert!(probe.calls().contains(&FakeCall::Start));
    }

    #[test]
    fn next_slot_projects_the_schedule_without_advancing_source_or_device() {
        let (mut l, probe, _) = standard();
        let phase = l.resampler.phase_state();
        let initial_tick = probe.tick();
        let slot = l.next_slot().unwrap();
        assert_eq!((slot.index, slot.now, slot.block_frames), (0, 0, BLOCK));
        assert_eq!(
            (
                slot.release_tick,
                slot.deadline_tick,
                slot.presentation_tick
            ),
            (1, 4, 5)
        );
        assert_eq!(slot.required_source_frames, 66);
        assert_eq!(slot.first_output_source_frames, 3);
        assert_eq!(slot.source_phase, phase);
        assert!(!slot.in_progress);
        assert_eq!(l.resampler.phase_state(), phase);
        assert_eq!(probe.tick(), initial_tick);
        assert_eq!(l.config().period_ticks, 4);
        l.start(READY).unwrap();
        assert_eq!(l.next_slot().unwrap(), slot);
        let mut source = ToneSource::new();
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..Default::default()
        };
        l.tick(&mut source, &mut timing);
        let next = l.next_slot().unwrap();
        assert_eq!((next.index, next.now), (1, 1));
        assert_eq!(
            (
                next.release_tick,
                next.deadline_tick,
                next.presentation_tick
            ),
            (5, 8, 9)
        );
        assert!(next.in_progress);
        assert_eq!(next.required_source_frames, 64);
        assert_eq!(next.first_output_source_frames, 1);
        let after = l.resampler.phase_state();
        assert_eq!(l.next_slot().unwrap(), next);
        assert_eq!(l.resampler.phase_state(), after);
    }

    #[test]
    fn next_slot_source_demand_matches_real_drift_and_resync_pulls() {
        for ppb in [-500_000, 0, 500_000] {
            for initial_ppb in [0, ppb] {
                let (mut l, _, _) = started();
                l.resampler =
                    DriftResampler::with_initial_ppb(ResamplerConfig::default(), initial_ppb)
                        .unwrap();
                l.resampler.set_target_ppb(i64::from(ppb));
                let mut source = ToneSource::new();
                for _ in 0..16 {
                    let predicted = l.next_slot().unwrap().required_source_frames;
                    let before = l.resampler.phase_state();
                    let mut actual = l.resampler.clone();
                    let report = actual
                        .render(&mut source, &mut [0.0; BLOCK], &mut [0.0; BLOCK])
                        .unwrap();
                    assert_eq!(predicted, u64::try_from(report.pulled).unwrap());
                    assert_eq!(report.produced, BLOCK);
                    assert_eq!(l.resampler.phase_state(), before);
                    l.resampler = actual;
                }
                l.resync_pending = true;
                let old_phase = l.resampler.phase_state();
                let predicted = l.next_slot().unwrap().required_source_frames;
                let mut actual = l.resampler.clone();
                actual
                    .begin_epoch(l.epoch.wrapping_add(1), ResetReason::Discontinuity)
                    .unwrap();
                let report = actual
                    .render(&mut source, &mut [0.0; BLOCK], &mut [0.0; BLOCK])
                    .unwrap();
                assert_eq!(predicted, u64::try_from(report.pulled).unwrap());
                assert_eq!(report.produced, BLOCK);
                assert_eq!(l.resampler.phase_state(), old_phase);
                // A stopped owner next starts at its current tick with fresh source
                // history, not at the old run's next block index or old phase.
                l.resync_pending = false;
                l.state = RenderState::Stopped;
                l.now = 37;
                l.base = 4;
                l.next_index = 9;
                let restarted = l.next_slot().unwrap();
                assert_eq!((restarted.index, restarted.release_tick), (0, 38));
                assert_eq!(restarted.required_source_frames, predicted);
            }
        }
    }

    #[test]
    fn next_slot_refuses_overflow_and_inactive_states_without_mutation() {
        for state in [RenderState::Draining, RenderState::Faulted] {
            let (mut l, probe, _) = standard();
            l.state = state;
            let tick = probe.tick();
            assert!(l.next_slot().is_none());
            assert_eq!(probe.tick(), tick);
        }
        for fault in 0..4 {
            let (mut l, _, _) = started();
            match fault {
                0 => l.now = u64::MAX,
                1 => l.base = u64::MAX,
                2 => l.next_index = u64::MAX,
                _ => l.cfg.window_ticks = u64::MAX,
            }
            let phase = l.resampler.phase_state();
            assert!(l.next_slot().is_none(), "overflow case {fault}");
            assert_eq!(l.resampler.phase_state(), phase);
        }
        assert!(standard().0.next_slot().is_some());
    }

    #[test]
    fn exclusive_control_observation_detects_and_recovers_from_a_retained_handle() {
        let (l, probe, _) = standard();
        let tick = probe.tick();
        assert!(l.control_is_exclusive());
        let control = l.control_port();
        assert!(!l.control_is_exclusive());
        drop(control);
        assert!(l.control_is_exclusive());
        assert_eq!(probe.tick(), tick);
    }

    #[test]
    fn a_finish_only_tick_submits_busy_work_without_starting_or_pulling_another_block() {
        let mut cfg = RenderConfig::standard(BLOCK);
        cfg.period_ticks = 1;
        let (mut l, probe, _) = build(fake_config(), cfg);
        probe.capture_submissions(4);
        l.start(READY).unwrap();
        let mut source = ToneSource::new();
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..Default::default()
        };
        assert_eq!(l.tick(&mut source, &mut timing).started, Some(0));
        let pulled = source.pos;
        assert!(l.block_in_progress());
        let finished = l.tick_with_start_permission(&mut source, &mut timing, false);
        assert!(finished.finished.is_some());
        assert_eq!(finished.started, None);
        assert_eq!(source.pos, pulled);
        assert_eq!(probe.captured_submissions().len(), 1);
        assert!(!l.block_in_progress());
        let idle = l.tick_with_start_permission(&mut source, &mut timing, false);
        assert_eq!(idle.started, None);
        assert_eq!(source.pos, pulled);
        // Permission resumes the existing block index/deadline, not a new run.
        assert_eq!(l.tick(&mut source, &mut timing).started, Some(1));
        assert!(source.pos > pulled);
        let finished = l.tick_with_start_permission(&mut source, &mut timing, false);
        assert!(finished.finished.is_some());
        assert_eq!(finished.started, None);
        assert_eq!(probe.captured_submissions().len(), 2);
        assert_eq!(l.counters().cpu_miss_blocks, 0);
    }

    #[test]
    fn prepared_cancel_waits_for_flush_ack_without_start_or_source_pull() {
        let mut cfg = fake_config();
        cfg.flush_ack_delay_ticks = Some(3);
        cfg.completion_delay_ticks = 100;
        let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        probe.capture_submissions(4);
        assert_eq!(l.session.prime_silence().unwrap().accepted_bytes, BLOCK * 4);
        assert_eq!(probe.pending(), 1);
        let before = probe.calls().len();
        l.cancel_prepared().unwrap();
        assert_eq!(l.state(), RenderState::Draining);
        assert_eq!(
            &probe.calls()[before..],
            &[FakeCall::SetMute(true), FakeCall::RequestFlush]
        );
        let mut source = ToneSource::new();
        let mut timing = ScriptedTiming::default();
        for _ in 0..16 {
            if l.state() != RenderState::Draining {
                break;
            }
            let tick = l.tick(&mut source, &mut timing);
            assert_eq!(tick.started, None);
            assert_eq!(source.pos, 0);
        }
        assert_eq!(l.state(), RenderState::Stopped);
        assert!(l.stop_report().acknowledged);
        assert_eq!(probe.pending(), 0);
        assert_eq!(probe.captured_submissions(), vec![vec![0; BLOCK * 4]]);
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
        assert!(!probe.calls().contains(&FakeCall::Start));
        assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
    }

    #[test]
    fn prepared_copying_cancel_reports_ack_and_timeout_without_start() {
        for ack in [true, false] {
            let mut cfg = fake_config();
            cfg.abi = FakeConfig::copying().abi;
            cfg.flush_ack_delay_ticks = if ack { Some(2) } else { None };
            let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
            assert_eq!(l.session.prime_silence().unwrap().accepted_bytes, BLOCK * 4);
            assert_eq!(probe.written_bytes(), BLOCK * 4);
            l.cancel_prepared().unwrap();
            let mut source = ToneSource::new();
            let mut timing = ScriptedTiming::default();
            for _ in 0..16 {
                if l.state() != RenderState::Draining {
                    break;
                }
                l.tick(&mut source, &mut timing);
            }
            assert_eq!(l.stop_report().acknowledged, ack);
            assert_eq!(
                l.state(),
                if ack {
                    RenderState::Stopped
                } else {
                    RenderState::Faulted
                }
            );
            assert_eq!(source.pos, 0);
            assert!(!probe.calls().contains(&FakeCall::Start));
            assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
        }
    }

    #[test]
    fn prepared_cancel_timeout_keeps_priming_custody_without_ack() {
        let mut cfg = fake_config();
        cfg.flush_ack_delay_ticks = None;
        cfg.completion_delay_ticks = 100;
        let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        l.session.prime_silence().unwrap();
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        l.cancel_prepared().unwrap();
        let mut source = ToneSource::new();
        let mut timing = ScriptedTiming::default();
        for _ in 0..16 {
            if l.state() != RenderState::Draining {
                break;
            }
            l.tick(&mut source, &mut timing);
        }
        assert_eq!(l.state(), RenderState::Faulted);
        assert!(!l.stop_report().acknowledged);
        assert_eq!(source.pos, 0);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
        assert!(!probe.calls().contains(&FakeCall::Start));
        assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
    }

    #[test]
    fn a_finish_only_tick_keeps_cancel_acknowledgement_progressing_without_new_source() {
        let (mut l, probe, _) = started();
        probe.capture_submissions(4);
        let mut source = ToneSource::new();
        let mut timing = ScriptedTiming::default();
        l.tick(&mut source, &mut timing);
        assert_eq!(probe.captured_submissions().len(), 1);
        let pulled = source.pos;
        l.cancel().unwrap();
        assert_eq!(l.state(), RenderState::Draining);
        for _ in 0..16 {
            if l.state() != RenderState::Draining {
                break;
            }
            let tick = l.tick_with_start_permission(&mut source, &mut timing, false);
            assert_eq!(tick.started, None);
            assert_eq!(source.pos, pulled);
        }
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(probe.captured_submissions().len(), 1);
        assert_eq!(probe.pending(), 0);
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
    }

    #[test]
    fn an_explicit_finite_end_pads_the_device_tail_but_temporary_absence_still_starves() {
        struct FiniteSource {
            pulled: usize,
            declared_end: bool,
        }
        impl FrameSource for FiniteSource {
            fn pull(&mut self) -> Option<[f32; 2]> {
                if self.pulled == 39 {
                    return None;
                }
                let sample = if self.pulled < 37 {
                    [0.25, 0.125]
                } else {
                    [0.0; 2]
                };
                self.pulled += 1;
                Some(sample)
            }
        }
        impl RenderSource for FiniteSource {
            fn starvation(&self) -> Option<Starvation> {
                Some(Starvation::DecodeDelay)
            }
            fn end_of_stream(&self) -> bool {
                self.declared_end && self.pulled == 39
            }
        }
        for declared_end in [false, true] {
            let (mut l, probe, _) = started();
            probe.capture_submissions(2);
            let mut source = FiniteSource {
                pulled: 0,
                declared_end,
            };
            let mut timing = ScriptedTiming::default();
            let tick = l.tick(&mut source, &mut timing);
            let outcome = tick.finished.unwrap().1;
            assert_eq!(source.pulled, 39);
            assert_eq!(probe.captured_submissions().len(), 1);
            assert_eq!(probe.captured_submissions()[0].len(), BLOCK * 4);
            if declared_end {
                assert_eq!(outcome, BlockOutcome::OnTime);
                assert_eq!(l.counters().silence_frames_decode, 0);
                assert_eq!(l.counters().decode_delay_blocks, 0);
            } else {
                assert_eq!(
                    outcome,
                    BlockOutcome::Starved {
                        cause: Starvation::DecodeDelay,
                        silence_frames: 27
                    }
                );
                assert_eq!(l.counters().silence_frames_decode, 27);
                assert_eq!(l.counters().decode_delay_blocks, 1);
            }
            assert!(!l.resync_pending);
        }
    }

    /// A steady tone, so the source never runs out unless the test makes it.
    struct ToneSource {
        pos: u64,
        starved: Option<Starvation>,
    }

    impl ToneSource {
        fn new() -> Self {
            Self {
                pos: 0,
                starved: None,
            }
        }
    }

    impl FrameSource for ToneSource {
        fn pull(&mut self) -> Option<[f32; 2]> {
            if self.starved.is_some() {
                return None;
            }
            let phase = (self.pos % 48) as f32 / 48.0;
            self.pos += 1;
            let v = 0.25 * (2.0 * std::f32::consts::PI * phase).sin();
            // In phase, with the right channel at half the left. NOT `[v, -v]`: this profile's two
            // drivers (`WooferMono`, `TweeterMono`) are both fed from `mid = 0.5 * (l + r)`
            // (`RouteSource::Mid` in D02's synthetic calibration), and an antiphase pair sums to exactly
            // 0.0, so every output byte is zero. The loop and the stages then agree trivially on silence
            // and the sample tests prove nothing (b26 showed exactly that).
            Some([v, 0.5 * v])
        }
    }

    impl RenderSource for ToneSource {
        fn starvation(&self) -> Option<Starvation> {
            self.starved
        }
    }

    fn timing(default_cost: u64, costs: &[(u64, u64)], delays: &[(u64, u64)]) -> ScriptedTiming {
        ScriptedTiming {
            default_cost,
            costs: costs.iter().copied().collect(),
            delays: delays.iter().copied().collect(),
        }
    }

    fn run(
        l: &mut RenderLoop<FakeBackend>,
        src: &mut ToneSource,
        t: &mut ScriptedTiming,
        ticks: u64,
    ) -> Vec<TickReport> {
        (0..ticks).map(|_| l.tick(src, t)).collect()
    }

    /// Every block that finished, as (index, tick, outcome).
    fn finished(reports: &[TickReport]) -> Vec<(u64, u64, BlockOutcome)> {
        reports
            .iter()
            .filter_map(|r| r.finished.map(|(k, o)| (k, r.now, o)))
            .collect()
    }

    fn count_slots(l: &RenderLoop<FakeBackend>, want: SlotState) -> usize {
        l.session()
            .slot_states()
            .into_iter()
            .filter(|s| *s == want)
            .count()
    }

    /// With no block in progress, every started block has exactly one outcome and every frame
    /// generated is accounted for.
    fn assert_identities(l: &RenderLoop<FakeBackend>) {
        assert!(l.busy.is_none(), "a block is still in progress");
        let c = l.counters();
        assert_eq!(
            c.blocks_started,
            c.blocks_on_time
                + c.ingress_loss_blocks
                + c.decode_delay_blocks
                + c.cpu_miss_blocks
                + c.capacity_rejected_blocks
                + c.short_write_blocks
        );
        assert_eq!(
            c.frames_generated,
            c.frames_submitted
                + c.frames_dropped_late
                + c.frames_dropped_capacity
                + c.frames_discarded_short
        );
    }

    /// Run until the loop leaves `Draining`, to a bound, returning the most blocks it had in flight.
    fn run_until_stopped(
        l: &mut RenderLoop<FakeBackend>,
        src: &mut ToneSource,
        t: &mut ScriptedTiming,
    ) -> usize {
        let mut most = l.in_flight();
        for _ in 0..300 {
            if l.state() != RenderState::Draining {
                break;
            }
            l.tick(src, t);
            most = most.max(l.in_flight());
        }
        most
    }

    // ------------------------------------------------------------------------ construction

    #[test]
    fn a_new_loop_is_ready_and_silent_and_touches_the_device_only_to_prepare() {
        let (l, probe, _) = standard();
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(l.counters(), RenderCounters::default());
        assert_eq!(l.in_flight(), 0);
        let calls = probe.calls();
        assert!(calls.contains(&FakeCall::Capabilities));
        assert!(!calls.iter().any(|c| matches!(
            c,
            FakeCall::Start | FakeCall::SubmitRetained { .. } | FakeCall::SetMute(false)
        )));
    }

    #[test]
    fn a_block_is_in_progress_from_its_start_to_its_end_and_a_cancel_drops_it_without_an_outcome() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        assert!(!l.block_in_progress());
        run(&mut l, &mut src, &mut t, 1); // block 0 starts and ends one tick later
        assert!(l.block_in_progress());
        run(&mut l, &mut src, &mut t, 1);
        assert!(!l.block_in_progress());
        run(&mut l, &mut src, &mut t, 3); // block 1 starts on tick 5
        assert!(l.block_in_progress());
        // A cancel drops the block in flight with no outcome: the cumulative counters never balance again,
        // which is why the loop's own state is the accessor and not a counter equality.
        l.cancel().unwrap();
        assert!(!l.block_in_progress());
        let c = l.counters();
        assert_eq!((c.blocks_started, c.blocks_on_time), (2, 1));
    }

    #[test]
    fn a_refused_reservation_admits_no_loop_names_which_storage_and_never_reads_as_capacity() {
        let make = || {
            let (backend, probe) = FakeBackend::new(fake_config());
            let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
            let mut session = HalSession::open(profile(), backend, config).unwrap();
            session.prepare().unwrap();
            (session, probe)
        };
        let resampler = || DriftResampler::new(ResamplerConfig::default()).unwrap();
        let ok = RenderConfig::standard(BLOCK);
        for (which, what) in [
            (LoopStorage::Events, "event queue"),
            (LoopStorage::Control, "control queue"),
        ] {
            let (session, probe) = make();
            let refused =
                RenderLoop::new_reserving(session, dsp(), resampler(), ok, &mut |asked| {
                    asked == which
                })
                .err();
            assert_eq!(refused, Some(RenderError::StorageNotAdmitted { what }));
            assert!(
                !probe.calls().iter().any(|c| matches!(
                    c,
                    FakeCall::Start | FakeCall::SubmitRetained { .. } | FakeCall::SetMute(false)
                )),
                "a refused admission starts nothing"
            );
        }
        // Its own name: not the ring, not an injected admission failure, and not a rejected block.
        let error = RenderError::StorageNotAdmitted {
            what: "event queue",
        };
        assert_ne!(error, RenderError::NoOrdinaryCapacity);
        assert_ne!(error, RenderError::AdmissionFailed(AdmitPoint::Start));
        let text = error.to_string();
        assert!(text.contains("reserved") && text.contains("nothing was started"));
        assert!(
            !text.contains("ordinary") && !text.contains("ring") && !text.contains("capacity"),
            "{text}"
        );
        // A rejected block is an outcome of a started block, in its own vocabulary.
        assert_eq!(
            serde_json::to_string(&BlockOutcome::CapacityRejected).unwrap(),
            r#"{"outcome":"capacity_rejected"}"#
        );
        // Permitted positive: with nothing refused the loop is admitted, and its footprint is that of a
        // loop that never saw a refusal.
        let (session, _probe) = make();
        let admitted =
            RenderLoop::new_reserving(session, dsp(), resampler(), ok, &mut |_| false).unwrap();
        let (clean, _probe, _) = standard();
        assert_eq!(admitted.storage_footprint(), clean.storage_footprint());
    }

    #[test]
    fn the_storage_a_loop_reserved_at_admission_does_not_move_through_start_reconnect_cancel_stop_a_fault_and_a_restart()
     {
        let (mut l, _probe, _) = standard();
        let admitted = l.storage_footprint();
        assert!(admitted.events >= RENDER_EVENT_CAP);
        assert!(admitted.control >= CONTROL_QUEUE_CAP);
        assert!(admitted.session.fault_records >= franken_hal::session::MAX_FAULT_RECORDS);
        assert_eq!(admitted.session.slots, 4);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let port = l.control_port();
        // Start, run past the ring depth so every slot has been used, flood the control port past its cap,
        // reconnect, mute and unmute.
        l.start(READY).unwrap();
        run(&mut l, &mut src, &mut t, 24);
        for _ in 0..(2 * CONTROL_QUEUE_CAP) {
            let _ = port.send(Control::SetGain(0.5));
        }
        run(&mut l, &mut src, &mut t, 4);
        l.reconnect().unwrap();
        l.mute().unwrap();
        l.unmute().unwrap();
        run(&mut l, &mut src, &mut t, 8);
        assert_eq!(l.storage_footprint(), admitted);
        // Cancel, then stop-and-start cycles, with the render events well past their cap.
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(l.storage_footprint(), admitted);
        for _ in 0..40 {
            l.start(READY).unwrap();
            run(&mut l, &mut src, &mut t, 6);
            l.stop().unwrap();
            run_until_stopped(&mut l, &mut src, &mut t);
            assert_eq!(l.state(), RenderState::Stopped);
            assert_eq!(l.storage_footprint(), admitted);
        }
        let counters = l.counters();
        assert!(
            counters.events_dropped + counters.events_evicted + counters.events_lost_critical > 0,
            "the render events overflowed their cap without growing it"
        );

        // A stop the device never acknowledges faults and quarantines; the loop recovers and starts again.
        let mut cfg = fake_config();
        cfg.flush_ack_delay_ticks = None;
        let (mut l, _probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        let admitted = l.storage_footprint();
        l.start(READY).unwrap();
        run(&mut l, &mut src, &mut t, 8);
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.fault(), Some(FaultReason::DrainTimedOut));
        assert_eq!(l.storage_footprint(), admitted);
        l.recover().unwrap();
        l.start(READY).unwrap();
        run(&mut l, &mut src, &mut t, 8);
        assert_eq!(l.storage_footprint(), admitted);
    }

    #[test]
    fn a_cancel_with_device_events_pending_and_a_failing_poll_faults_the_loop_muted_and_grows_nothing()
     {
        let (mut l, probe, _) = started();
        let admitted = l.storage_footprint();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 8);
        // Events the device has not yet reported (a flush acknowledgment outside a drain is an anomaly, never a
        // fault), and a poll that fails once while the cancel settles them.
        probe.queue_event(DeviceEvent::FlushAck);
        probe.queue_event(DeviceEvent::FlushAck);
        probe.fail_next(franken_hal::backend::Op::PollEvent, DriverError::Errno(5));
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::SessionFaulted));
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        assert_eq!(l.storage_footprint(), admitted);
        // Permitted positive: the same cancel with the same events and no failing poll stops cleanly.
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 8);
        probe.queue_event(DeviceEvent::FlushAck);
        probe.queue_event(DeviceEvent::FlushAck);
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(l.storage_footprint(), admitted);
    }

    #[test]
    fn construction_refuses_what_the_render_path_cannot_carry() {
        let make = |cfg: FakeConfig| {
            let (backend, _probe) = FakeBackend::new(cfg);
            let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
            let mut session = HalSession::open(profile(), backend, config).unwrap();
            session.prepare().unwrap();
            session
        };
        let resampler = || DriftResampler::new(ResamplerConfig::default()).unwrap();
        let ok = RenderConfig::standard(BLOCK);
        let new = |cfg: FakeConfig, render: RenderConfig| {
            RenderLoop::new(make(cfg), dsp(), resampler(), render).err()
        };
        // A block bigger than the device block, and a block of nothing.
        assert!(matches!(
            new(fake_config(), RenderConfig::standard(65)),
            Some(RenderError::BadConfig(_))
        ));
        assert!(matches!(
            new(fake_config(), RenderConfig::standard(0)),
            Some(RenderError::BadConfig(_))
        ));
        // A timeline with no period or no window.
        for bad in [
            RenderConfig {
                period_ticks: 0,
                ..ok
            },
            RenderConfig {
                window_ticks: 0,
                ..ok
            },
        ] {
            assert!(matches!(
                new(fake_config(), bad),
                Some(RenderError::BadConfig(_))
            ));
        }
        // No ring slot left for ordinary submission after the cleanup reserve.
        assert_eq!(
            new(
                fake_config(),
                RenderConfig {
                    reserve_slots: 4,
                    ..ok
                }
            ),
            Some(RenderError::NoOrdinaryCapacity)
        );
        // Without a stated lead or stop deadline no deadline can be computed or bounded.
        let mut cfg = fake_config();
        cfg.min_submission_lead_ticks = None;
        assert_eq!(new(cfg, ok), Some(RenderError::LeadUnknown));
        let mut cfg = fake_config();
        cfg.stop_deadline_ticks = None;
        assert_eq!(new(cfg, ok), Some(RenderError::StopDeadlineUnknown));
        // A session that is not prepared.
        let (backend, _probe) = FakeBackend::new(fake_config());
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        let unprepared = HalSession::open(profile(), backend, config).unwrap();
        let refused = RenderLoop::new(unprepared, dsp(), resampler(), ok).err();
        assert_eq!(
            refused,
            Some(RenderError::SessionNotPrepared(SessionPhase::Closed))
        );
        // Permitted positive: the same inputs, valid, are admitted.
        assert!(new(fake_config(), ok).is_none());
    }

    #[test]
    fn start_is_refused_for_a_board_that_is_not_active_and_leaves_the_device_alone() {
        let profile = profile();
        let (backend, probe) = FakeBackend::new(fake_config());
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        let mut session = HalSession::open(profile.clone(), backend, config).unwrap();
        session.prepare().unwrap();
        // No calibration: the DSP comes up fail-muted and refuses to unmute.
        let blank = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
        let resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
        let mut l =
            RenderLoop::new(session, blank, resampler, RenderConfig::standard(BLOCK)).unwrap();
        assert_eq!(l.start(READY), Err(RenderError::ProtectionNotActive));
        assert_eq!(l.state(), RenderState::Ready);
        assert!(!probe.calls().contains(&FakeCall::Start));
    }

    // ------------------------------------------------------------------------ lifecycle

    #[test]
    fn every_lifecycle_transition_is_taken_and_every_illegal_one_is_refused() {
        let (mut l, _probe, _) = standard();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        // Ready: nothing but start is allowed.
        assert_eq!(l.mute(), Err(RenderError::WrongState(RenderState::Ready)));
        assert_eq!(l.unmute(), Err(RenderError::WrongState(RenderState::Ready)));
        assert_eq!(l.stop(), Err(RenderError::WrongState(RenderState::Ready)));
        assert_eq!(l.cancel(), Err(RenderError::WrongState(RenderState::Ready)));
        assert_eq!(
            l.reconnect(),
            Err(RenderError::WrongState(RenderState::Ready))
        );
        assert_eq!(
            l.recover(),
            Err(RenderError::WrongState(RenderState::Ready))
        );
        // A tick in a state that does not render does nothing, and does not touch the device.
        assert_eq!(l.tick(&mut src, &mut t).now, 0);
        // Ready -> Running.
        l.start(READY).unwrap();
        assert_eq!(l.state(), RenderState::Running);
        assert_eq!(
            l.start(READY),
            Err(RenderError::WrongState(RenderState::Running))
        );
        // Running -> Muted -> Running.
        l.mute().unwrap();
        assert_eq!(l.state(), RenderState::Muted);
        assert_eq!(l.mute(), Ok(()), "muting twice is idempotent");
        l.unmute().unwrap();
        assert_eq!(l.state(), RenderState::Running);
        // Running -> Draining -> Stopped.
        l.stop().unwrap();
        assert_eq!(l.state(), RenderState::Draining);
        assert_eq!(
            l.stop(),
            Err(RenderError::WrongState(RenderState::Draining))
        );
        assert_eq!(
            l.mute(),
            Err(RenderError::WrongState(RenderState::Draining))
        );
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert!(l.stop_report().acknowledged);
        // Stopped: only a restart is allowed.
        assert_eq!(l.mute(), Err(RenderError::WrongState(RenderState::Stopped)));
        // Stopped -> Running again, and a restart is a new resampler epoch.
        l.start(READY).unwrap();
        assert_eq!(l.state(), RenderState::Running);
        assert_eq!(l.counters().epoch_resets, 1);
        // Running -> Draining (cancel) -> Stopped.
        l.cancel().unwrap();
        assert_eq!(l.state(), RenderState::Draining);
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        // The state changes were reported, in order, to whoever reads them.
        let states: Vec<(RenderState, RenderState)> = std::iter::from_fn(|| l.take_event())
            .filter_map(|e| match e.kind {
                RenderEventKind::State { from, to } => Some((from, to)),
                _ => None,
            })
            .collect();
        let want = vec![
            (RenderState::Ready, RenderState::Running),
            (RenderState::Running, RenderState::Muted),
            (RenderState::Muted, RenderState::Running),
            (RenderState::Running, RenderState::Draining),
            (RenderState::Draining, RenderState::Stopped),
            (RenderState::Stopped, RenderState::Running),
            (RenderState::Running, RenderState::Draining),
            (RenderState::Draining, RenderState::Stopped),
        ];
        assert_eq!(states, want);
    }

    // ------------------------------------------------------------------------ the timeline

    #[test]
    fn steady_state_blocks_are_released_on_the_period_and_submitted_before_their_deadline() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let reports = run(&mut l, &mut src, &mut t, 24);
        // Block k is released on tick 1 + 4k and, costing one tick, finishes on tick 2 + 4k.
        let starts: Vec<(u64, u64)> = reports
            .iter()
            .filter_map(|r| r.started.map(|k| (k, r.now)))
            .collect();
        assert_eq!(
            starts,
            vec![(0, 1), (1, 5), (2, 9), (3, 13), (4, 17), (5, 21)]
        );
        let want: Vec<(u64, u64, BlockOutcome)> = (0..6)
            .map(|k| (k, 2 + 4 * k, BlockOutcome::OnTime))
            .collect();
        assert_eq!(finished(&reports), want);
        // Each was submitted by its deadline, and its presentation is a minimum lead later.
        for (k, at, _) in finished(&reports) {
            assert!(at <= l.deadline(k), "block {k} was late");
            assert_eq!(l.presentation_tick(k), l.deadline(k) + 1);
        }
        assert_eq!(l.deadline(0), 4);
        assert_eq!(l.presentation_tick(0), 5);
        let c = l.counters();
        assert_eq!((c.blocks_started, c.blocks_on_time), (6, 6));
        assert_eq!((c.frames_generated, c.frames_submitted), (384, 384));
        // The device's irrevocable cursor is exactly what was handed over.
        assert_eq!(l.session().irrevocable_until_frames(), 384);
        // Each completion came two ticks after its submit, so nothing is left in flight.
        assert_eq!(l.in_flight(), 0);
        assert_identities(&l);
    }

    #[test]
    fn a_block_finishing_on_its_deadline_is_on_time_and_one_tick_later_is_dropped() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[(0, 3), (1, 4)], &[]));
        let reports = run(&mut l, &mut src, &mut t, 10);
        // Block 0 starts on tick 1, costs 3 and finishes on tick 4, which is its deadline.
        // Block 1 starts on tick 5, costs 4 and finishes on tick 9, one tick after its deadline of 8.
        // Block 2 is released on tick 9, when the loop is free again, and costs 1.
        let want = vec![
            (0, 4, BlockOutcome::OnTime),
            (1, 9, BlockOutcome::CpuMiss { late_by: 1 }),
            (2, 10, BlockOutcome::OnTime),
        ];
        assert_eq!(finished(&reports), want);
        let c = l.counters();
        assert_eq!((c.cpu_miss_blocks, c.blocks_on_time), (1, 2));
        assert_eq!((c.max_cost_ticks, c.max_late_ticks), (4, 1));
        // The late block was dropped, not submitted: only the other two reached the device.
        assert_eq!(c.frames_dropped_late, 64);
        assert_eq!(c.frames_submitted, 128);
        assert_eq!(l.session().irrevocable_until_frames(), 128);
        // A render over three quarters of the window breaches the 25% reserve, late or not:
        // 3 and 4 do, 1 does not.
        assert_eq!(c.reserve_breaches, 2);
        assert_identities(&l);
    }

    #[test]
    fn a_late_wakeup_that_still_meets_the_deadline_is_on_time_and_one_that_does_not_is_a_cpu_miss()
    {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[(0, 2), (1, 3)]));
        let reports = run(&mut l, &mut src, &mut t, 10);
        // Block 0 is released on tick 1 but only starts on tick 3, and finishes on tick 4: its deadline.
        // Block 1 is released on tick 5, starts on tick 8 and finishes on tick 9: one late.
        let want = vec![
            (0, 4, BlockOutcome::OnTime),
            (1, 9, BlockOutcome::CpuMiss { late_by: 1 }),
            (2, 10, BlockOutcome::OnTime),
        ];
        assert_eq!(finished(&reports), want);
        let starts: Vec<(u64, u64)> = reports
            .iter()
            .filter_map(|r| r.started.map(|k| (k, r.now)))
            .collect();
        assert_eq!(starts, vec![(0, 3), (1, 8), (2, 9)]);
        assert_eq!(l.counters().late_wakes, 2);
        assert_identities(&l);
    }

    #[test]
    fn a_render_longer_than_the_period_delays_the_next_block_instead_of_overlapping_it() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[(0, 6)], &[]));
        let reports = run(&mut l, &mut src, &mut t, 10);
        // Block 0 finishes on tick 7, three late. Block 1 was released on tick 5 but the one CPU was
        // busy until tick 7; it starts then and finishes on tick 8, its deadline.
        let want = vec![
            (0, 7, BlockOutcome::CpuMiss { late_by: 3 }),
            (1, 8, BlockOutcome::OnTime),
            (2, 10, BlockOutcome::OnTime),
        ];
        assert_eq!(finished(&reports), want);
        // One miss then a good block: the run of misses is broken, so the watchdog stays quiet.
        assert_eq!(l.state(), RenderState::Running);
    }

    #[test]
    fn consecutive_cpu_misses_trip_the_watchdog_which_mutes_and_stops_rendering() {
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[(0, 6), (1, 6), (2, 6)], &[]));
        let reports = run(&mut l, &mut src, &mut t, 19);
        // Blocks 0, 1 and 2 finish on ticks 7, 13 and 19, late by 3, 5 and 7: the third trips it.
        let want = vec![
            (0, 7, BlockOutcome::CpuMiss { late_by: 3 }),
            (1, 13, BlockOutcome::CpuMiss { late_by: 5 }),
            (2, 19, BlockOutcome::CpuMiss { late_by: 7 }),
        ];
        assert_eq!(finished(&reports), want);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::WatchdogTripped));
        // The trip asked the device to mute, got an acknowledgment, and nothing was ever submitted.
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        let calls = probe.calls();
        assert!(calls.contains(&FakeCall::SetMute(true)));
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, FakeCall::SubmitRetained { .. }))
        );
        assert_eq!(l.counters().frames_submitted, 0);
        // A faulted loop renders nothing more and does not advance the device.
        let before = l.now();
        assert_eq!(l.tick(&mut src, &mut t).now, before);
        let events: Vec<RenderEventKind> = std::iter::from_fn(|| l.take_event())
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            events.last(),
            Some(&RenderEventKind::State {
                from: RenderState::Running,
                to: RenderState::Faulted
            })
        );
        assert!(events.contains(&RenderEventKind::Fault {
            reason: FaultReason::WatchdogTripped
        }));
    }

    // ------------------------------------------------------------------------ the four causes

    #[test]
    fn ingress_loss_and_decode_delay_are_counted_apart_and_only_ingress_loss_resets_the_stream() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let mut reports = run(&mut l, &mut src, &mut t, 4); // block 0
        src.starved = Some(Starvation::IngressLoss);
        reports.extend(run(&mut l, &mut src, &mut t, 8)); // blocks 1 and 2: nothing arrived
        src.starved = None;
        reports.extend(run(&mut l, &mut src, &mut t, 4)); // block 3: the stream is back
        src.starved = Some(Starvation::DecodeDelay);
        reports.extend(run(&mut l, &mut src, &mut t, 4)); // block 4: decoding is behind
        src.starved = None;
        reports.extend(run(&mut l, &mut src, &mut t, 4)); // block 5: caught up
        let loss = BlockOutcome::Starved {
            cause: Starvation::IngressLoss,
            silence_frames: 64,
        };
        let delay = BlockOutcome::Starved {
            cause: Starvation::DecodeDelay,
            silence_frames: 64,
        };
        let want = vec![
            (0, 2, BlockOutcome::OnTime),
            (1, 6, loss),
            (2, 10, loss),
            (3, 14, BlockOutcome::OnTime),
            (4, 18, delay),
            (5, 22, BlockOutcome::OnTime),
        ];
        assert_eq!(finished(&reports), want);
        let c = l.counters();
        assert_eq!((c.ingress_loss_blocks, c.decode_delay_blocks), (2, 1));
        assert_eq!(
            (c.silence_frames_ingress, c.silence_frames_decode),
            (128, 64)
        );
        // A starved block is still submitted, as silence: the device never sees a gap it was not told
        // about. Neither cause is a CPU miss or a driver underrun.
        assert_eq!(c.frames_submitted, 384);
        assert_eq!((c.cpu_miss_blocks, c.driver_underruns), (0, 0));
        // Content lost on the way in is a discontinuity: one new epoch, when the stream came back.
        // A late decode loses nothing and starts no epoch.
        assert_eq!(c.epoch_resets, 1);
        assert_identities(&l);
    }

    #[test]
    fn a_device_that_runs_dry_with_nothing_dropped_is_a_driver_underrun() {
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let mut reports = run(&mut l, &mut src, &mut t, 2); // block 0 is submitted: 64 frames accepted
        probe.queue_event(DeviceEvent::Position { counter: 1000 }); // the first report is a baseline
        reports.extend(run(&mut l, &mut src, &mut t, 1));
        assert_eq!(l.counters().driver_underruns, 0);
        // The device reports it consumed all 64 frames: it is dry, and the loop dropped nothing.
        probe.queue_event(DeviceEvent::Position { counter: 1064 });
        reports.extend(run(&mut l, &mut src, &mut t, 1));
        let c = l.counters();
        assert_eq!((c.driver_underruns, c.underruns_explained), (1, 0));
        let events: Vec<RenderEventKind> = std::iter::from_fn(|| l.take_event())
            .map(|e| e.kind)
            .collect();
        assert!(events.contains(&RenderEventKind::DriverUnderrun));
        // Once the next block is accepted the device is no longer dry, so the same dryness is not
        // counted again.
        reports.extend(run(&mut l, &mut src, &mut t, 6));
        assert_eq!(l.counters().driver_underruns, 1);
    }

    #[test]
    fn a_device_that_runs_dry_after_the_loop_dropped_a_block_is_explained_not_blamed_on_the_driver()
    {
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[(1, 6)], &[]));
        run(&mut l, &mut src, &mut t, 2); // block 0 is submitted
        probe.queue_event(DeviceEvent::Position { counter: 1000 });
        run(&mut l, &mut src, &mut t, 9); // ticks 3..11: block 1 finishes on tick 11, late, and is dropped
        assert_eq!(l.counters().cpu_miss_blocks, 1);
        // Now the device reports it has consumed everything it was given.
        probe.queue_event(DeviceEvent::Position { counter: 1064 });
        run(&mut l, &mut src, &mut t, 1); // tick 12
        let c = l.counters();
        assert_eq!((c.driver_underruns, c.underruns_explained), (0, 1));
    }

    // ------------------------------------------------------------------------ the HAL boundary

    #[test]
    fn a_short_write_is_retried_within_the_tick_and_the_rest_is_discarded_not_carried() {
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        // The device takes 64 bytes (16 frames) per call; two attempts get 32 of the 64 frames.
        probe.set_accept_limit(Some(64));
        let reports = run(&mut l, &mut src, &mut t, 2);
        assert_eq!(
            finished(&reports),
            vec![(
                0,
                2,
                BlockOutcome::ShortWrite {
                    discarded_frames: 32
                }
            )]
        );
        let c = l.counters();
        assert_eq!((c.short_write_blocks, c.frames_submitted), (1, 32));
        assert_eq!(c.frames_discarded_short, 32);
        // Both accepted pieces hold a slot until the device completes them.
        assert_eq!(l.in_flight(), 2);
        assert_identities(&l);
        // Permitted positive: a device that takes half a block per call takes all of it in two.
        let (mut l, probe, _) = started();
        probe.set_accept_limit(Some(128));
        let reports = run(&mut l, &mut src, &mut t, 2);
        assert_eq!(finished(&reports), vec![(0, 2, BlockOutcome::OnTime)]);
        assert_eq!(l.counters().frames_submitted, 64);
        assert_eq!(l.in_flight(), 2);
    }

    #[test]
    fn the_cleanup_reserve_keeps_a_slot_that_ordinary_blocks_cannot_take_and_the_stop_path_can() {
        let mut cfg = fake_config();
        cfg.completion_delay_ticks = 20; // blocks stay in flight
        let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        l.start(READY).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let reports = run(&mut l, &mut src, &mut t, 14);
        // Three blocks fill the ordinary share of the four-slot ring; the fourth is turned away.
        assert_eq!(
            finished(&reports).last(),
            Some(&(3, 14, BlockOutcome::CapacityRejected))
        );
        let c = l.counters();
        assert_eq!(
            (c.capacity_rejected_blocks, c.frames_dropped_capacity),
            (1, 64)
        );
        assert_eq!(count_slots(&l, SlotState::KernelOwned), 3);
        assert_eq!(
            count_slots(&l, SlotState::Free),
            1,
            "the reserve was not spent by ordinary submission"
        );
        assert_identities(&l);
        // The stop path may use it.
        l.stop().unwrap();
        let most = run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(most, 4, "the ramp-out used the reserved slot");
        // Everything is accounted for: the flush acknowledgment freed what was in flight.
        assert_eq!(count_slots(&l, SlotState::Free), 4);
        assert_eq!(
            (probe.use_after_free(), probe.modified_while_owned()),
            (0, 0)
        );
    }

    #[test]
    fn a_held_buffer_is_never_released_because_a_timer_ran_out_only_on_an_acknowledgment() {
        let (mut l, probe, _) = started();
        probe.set_lose_completions(true);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        for tick in 1..=60 {
            l.tick(&mut src, &mut t);
            if tick >= 10 {
                assert_eq!(
                    count_slots(&l, SlotState::KernelOwned),
                    3,
                    "tick {tick}: a slot was released without the device's say-so"
                );
            }
        }
        assert_eq!(l.in_flight(), 3);
        // The blocks that found the ordinary share full were turned away, 12 of them.
        assert_eq!(l.counters().capacity_rejected_blocks, 12);
        assert_eq!(probe.use_after_free(), 0);
        // A cancel is acknowledged one tick later, and that is what frees them.
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(count_slots(&l, SlotState::Free), 4);
    }

    #[test]
    fn a_stop_the_device_never_acknowledges_faults_and_quarantines_it_does_not_free() {
        let mut cfg = fake_config();
        cfg.flush_ack_delay_ticks = None;
        let (mut l, probe, ledger) = build(cfg, RenderConfig::standard(BLOCK));
        l.start(READY).unwrap();
        probe.set_lose_completions(true);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 12);
        assert_eq!(count_slots(&l, SlotState::KernelOwned), 3);
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        // Bounded by the stop deadline, then faulted: never "stopped" without the acknowledgment.
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::DrainTimedOut));
        assert!(!l.stop_report().acknowledged);
        assert!(l.stop_report().ticks <= 9);
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        assert_eq!(count_slots(&l, SlotState::Free), 1);
        // Destroying the owner keeps what the kernel may still read alive.
        drop(l);
        assert_eq!(ledger.leaked_slots(), 3);
        assert_eq!(probe.kernel_touch_pending(), (3, 0));
        assert_eq!(probe.use_after_free(), 0);
    }

    // ------------------------------------------------------------------------ device loss and process death

    #[test]
    fn device_loss_is_a_persistent_fault_that_cannot_be_acknowledged_or_recovered() {
        let (mut l, probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 6);
        probe.lose_device();
        l.tick(&mut src, &mut t);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::DeviceLost));
        // The mute was requested, but a device that is gone cannot acknowledge it.
        assert_eq!(l.last_mute_acknowledged(), Some(false));
        // A reset cannot bring it back.
        assert_eq!(
            l.recover(),
            Err(RenderError::Session(SessionError::DevicePersistentlyLost))
        );
        assert_eq!(l.state(), RenderState::Faulted);
    }

    #[test]
    fn process_death_leaves_the_kernels_buffers_alive_and_claims_no_acknowledgment() {
        let mut cfg = fake_config();
        cfg.completion_delay_ticks = 20;
        let (mut l, probe, ledger) = build(cfg, RenderConfig::standard(BLOCK));
        l.start(READY).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 11);
        assert_eq!(l.in_flight(), 3);
        // The process dies while the kernel holds three buffers. Nothing in this process can observe
        // what the amplifier did next: the loop is gone. What can be shown is what it left behind.
        drop(l);
        assert_eq!(probe.calls().last(), Some(&FakeCall::SetMute(true)));
        assert_eq!(ledger.leaked_slots(), 3);
        assert_eq!(probe.kernel_touch_pending(), (3, 0));
        assert_eq!(
            (probe.use_after_free(), probe.modified_while_owned()),
            (0, 0)
        );
        // Whether the amplifier really muted is external qualification, not something this proves.
    }

    // ------------------------------------------------------------------------ control

    #[test]
    fn a_later_mute_supersedes_unmutes_even_beyond_the_first_control_batch() {
        for backlog in [0, MAX_CONTROL_PER_TICK, CONTROL_QUEUE_CAP - 1] {
            let (mut l, _probe, _) = started();
            let port = l.control_port();
            for _ in 0..backlog {
                port.send(Control::SetGain(0.25)).unwrap();
            }
            port.send(Control::Unmute).unwrap();
            port.send(Control::Mute).unwrap();
            let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
            for tick in 0..(CONTROL_QUEUE_CAP / MAX_CONTROL_PER_TICK + 2) {
                l.tick(&mut src, &mut t);
                assert_eq!(
                    l.state(),
                    RenderState::Muted,
                    "an older Unmute undid a later Mute: backlog={backlog} tick={tick} stats={:?}",
                    port.stats()
                );
            }
            let expected_gain = if backlog == 0 { 1.0 } else { 0.25 };
            assert!(
                (l.dsp().user_gain() - expected_gain).abs() < f32::EPSILON,
                "superseding Unmute must preserve queued gain commands"
            );
            eprintln!(
                "D04_CONTROL_ORDER scenario=older_unmute backlog={backlog} state={:?} stats={:?}",
                l.state(),
                port.stats()
            );
        }
    }

    #[test]
    fn an_unmute_after_the_latest_mute_is_preserved() {
        for older_unmute in [false, true] {
            let (mut l, _probe, _) = started();
            let port = l.control_port();
            if older_unmute {
                port.send(Control::Unmute).unwrap();
            }
            port.send(Control::Mute).unwrap();
            // This is a new request, after the mute, not the stale request it superseded.
            port.send(Control::Unmute).unwrap();
            let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
            l.tick(&mut src, &mut t);
            assert_eq!(
                l.state(),
                RenderState::Running,
                "older_unmute={older_unmute}"
            );
            let states: Vec<_> = std::iter::from_fn(|| l.take_event())
                .filter_map(|event| match event.kind {
                    RenderEventKind::State { from, to } => Some((from, to)),
                    _ => None,
                })
                .collect();
            assert!(states.contains(&(RenderState::Running, RenderState::Muted)));
            assert!(states.contains(&(RenderState::Muted, RenderState::Running)));
            eprintln!(
                "D04_CONTROL_ORDER scenario=fresh_unmute older_unmute={older_unmute} states={states:?} stats={:?}",
                port.stats()
            );
        }
    }

    #[test]
    fn a_repeated_mute_supersedes_an_intervening_unmute_without_widening_the_queue() {
        let (mut l, _probe, _) = started();
        let port = l.control_port();
        for _ in 0..CONTROL_QUEUE_CAP {
            port.send(Control::Unmute).unwrap();
        }
        port.send(Control::Mute).unwrap();
        // Superseded requests no longer occupy the bounded queue; a genuinely newer Unmute fits.
        port.send(Control::Unmute).unwrap();
        port.send(Control::Mute).unwrap();
        for _ in 0..CONTROL_QUEUE_CAP {
            port.send(Control::SetGain(0.5)).unwrap();
        }
        assert_eq!(port.send(Control::Unmute), Err(ControlRejected::QueueFull));
        assert_eq!(
            port.send(Control::Mute),
            Ok(()),
            "a full queue never refuses Mute"
        );
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        for tick in 0..(CONTROL_QUEUE_CAP / MAX_CONTROL_PER_TICK + 2) {
            l.tick(&mut src, &mut t);
            assert_eq!(
                l.state(),
                RenderState::Muted,
                "tick={tick} stats={:?}",
                port.stats()
            );
        }
        assert!((l.dsp().user_gain() - 0.5).abs() < f32::EPSILON);
        assert_eq!(port.stats().accepted, (2 * CONTROL_QUEUE_CAP + 4) as u64);
        assert_eq!(port.stats().rejected, 1);
        eprintln!(
            "D04_CONTROL_ORDER scenario=repeated_mute capacity={CONTROL_QUEUE_CAP} state={:?} stats={:?}",
            l.state(),
            port.stats()
        );
    }

    #[test]
    fn a_control_storm_is_bounded_and_does_not_make_a_render_late() {
        let (mut l, _probe, _) = started();
        let port = l.control_port();
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..100 {
            match port.send(Control::SetGain(0.5)) {
                Ok(()) => accepted += 1,
                Err(ControlRejected::QueueFull) => rejected += 1,
            }
        }
        assert_eq!(
            (accepted, rejected),
            (CONTROL_QUEUE_CAP, 100 - CONTROL_QUEUE_CAP)
        );
        assert_eq!(
            port.stats(),
            ControlStats {
                accepted: 16,
                rejected: 84
            }
        );
        // A mute is never refused, however full the queue is.
        assert_eq!(port.send(Control::Mute), Ok(()));
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let reports = run(&mut l, &mut src, &mut t, 8);
        assert_eq!(l.state(), RenderState::Muted);
        assert!((l.dsp().user_gain() - 0.5).abs() < f32::EPSILON);
        let want = vec![(0, 2, BlockOutcome::OnTime), (1, 6, BlockOutcome::OnTime)];
        assert_eq!(finished(&reports), want);
        assert_eq!(l.counters().control_skipped, 0);
    }

    #[test]
    fn a_blocked_management_request_cannot_hold_the_render_owners_lock() {
        let (mut l, _probe, _) = started();
        let port = l.control_port();
        port.send(Control::SetGain(0.25)).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        // Something holds the control lock and does not let go.
        let held = port.inner.lock().unwrap();
        let reports = run(&mut l, &mut src, &mut t, 8);
        // Every render still met its deadline; the loop skipped control on each tick and counted it.
        let want = vec![(0, 2, BlockOutcome::OnTime), (1, 6, BlockOutcome::OnTime)];
        assert_eq!(finished(&reports), want);
        assert_eq!(l.counters().control_skipped, 8);
        assert!(
            (l.dsp().user_gain() - 1.0).abs() < f32::EPSILON,
            "nothing was applied yet"
        );
        // Permitted positive: when the lock is free again the queued command is applied.
        drop(held);
        run(&mut l, &mut src, &mut t, 1);
        assert!((l.dsp().user_gain() - 0.25).abs() < f32::EPSILON);
        assert_eq!(l.counters().control_skipped, 8);
    }

    #[test]
    fn mute_and_stop_from_the_port_take_effect_and_a_stale_command_does_not_outlive_a_stop() {
        let (mut l, _probe, _) = started();
        let port = l.control_port();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        port.send(Control::Mute).unwrap();
        run(&mut l, &mut src, &mut t, 1);
        assert_eq!(l.state(), RenderState::Muted);
        port.send(Control::Unmute).unwrap();
        run(&mut l, &mut src, &mut t, 1);
        assert_eq!(l.state(), RenderState::Running);
        port.send(Control::Stop).unwrap();
        run(&mut l, &mut src, &mut t, 1);
        assert_eq!(l.state(), RenderState::Draining);
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        // A command left over from before a restart is not applied to the new run.
        port.send(Control::Stop).unwrap();
        l.start(READY).unwrap();
        run(&mut l, &mut src, &mut t, 3);
        assert_eq!(l.state(), RenderState::Running);
    }

    // ------------------------------------------------------------------------ admission

    #[test]
    fn injected_admission_failures_fail_closed_at_start_and_reconnect_and_the_stop_path_still_finishes()
     {
        // Start: refused, typed, and the device is not touched.
        let (mut l, probe, _) = standard();
        l.set_admit_faults(AdmitFaults {
            start: true,
            ..AdmitFaults::default()
        });
        assert_eq!(
            l.start(READY),
            Err(RenderError::AdmissionFailed(AdmitPoint::Start))
        );
        assert_eq!(l.state(), RenderState::Ready);
        assert!(!probe.calls().contains(&FakeCall::Start));
        // Permitted positive: without the fault it starts.
        l.set_admit_faults(AdmitFaults::default());
        l.start(READY).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 6);

        // Reconnect: refused, and the playing stream is untouched.
        l.set_admit_faults(AdmitFaults {
            reconnect: true,
            ..AdmitFaults::default()
        });
        assert_eq!(
            l.reconnect(),
            Err(RenderError::AdmissionFailed(AdmitPoint::Reconnect))
        );
        assert_eq!(l.counters().epoch_resets, 0);
        let reports = run(&mut l, &mut src, &mut t, 4);
        assert_eq!(
            finished(&reports),
            vec![(2, 10, BlockOutcome::OnTime)],
            "the stream played on"
        );
        l.set_admit_faults(AdmitFaults::default());
        l.reconnect().unwrap();
        assert_eq!(l.counters().epoch_resets, 1);

        // Stop and cancel with ordinary capacity gone: they finish on the reserve.
        l.set_admit_faults(AdmitFaults {
            drain: true,
            ..AdmitFaults::default()
        });
        l.stop().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(l.counters().capacity_rejected_blocks, 0);
        l.set_admit_faults(AdmitFaults::default());
        l.start(READY).unwrap();
        run(&mut l, &mut src, &mut t, 6);
        l.set_admit_faults(AdmitFaults {
            cancel: true,
            ..AdmitFaults::default()
        });
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        assert_eq!(l.last_mute_acknowledged(), Some(true));
    }

    #[test]
    fn a_protection_dsp_that_stops_being_active_faults_the_loop_and_mutes() {
        let (mut l, _probe, _) = started();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 6);
        // Switch to a calibration the DSP refuses: it goes fail-muted.
        let profile = profile();
        let mut bad = synthetic_calibration_for(&profile);
        bad.sample_rate_hz = 44_100;
        assert!(
            l.dsp_mut()
                .request_profile_switch(&profile, &bad, Admission::HostSimulation)
                .is_err()
        );
        // The next block it renders shows the board is no longer active.
        run(&mut l, &mut src, &mut t, 4);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::ProtectionFault));
        assert_eq!(l.last_mute_acknowledged(), Some(true));
    }

    #[test]
    fn a_loop_that_recovered_from_a_fault_starts_clean_and_is_not_faulted_by_the_old_events() {
        // A cancel the device never acknowledges faults the session twice over (cancelled, then
        // possibly saturated); those events are still queued when the loop is recovered.
        let mut cfg = fake_config();
        cfg.flush_ack_delay_ticks = None;
        let (mut l, _probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        l.start(READY).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 6);
        l.cancel().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.fault(), Some(FaultReason::DrainTimedOut));
        // Recover through an acknowledged reset, and start again.
        l.recover().unwrap();
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(l.fault(), None);
        l.start(READY).unwrap();
        let reports = run(&mut l, &mut src, &mut t, 8);
        assert_eq!(
            l.state(),
            RenderState::Running,
            "the old faults were not read again"
        );
        let done = finished(&reports);
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(|(_, _, o)| *o == BlockOutcome::OnTime));
    }

    // ------------------------------------------------------------------------ the driver's counter regresses

    /// A started loop whose device never completes anything, so three blocks stay held (the ordinary
    /// share of the four-slot ring) and 192 frames are in flight for the counter to be judged against.
    fn holding_three_blocks() -> (
        RenderLoop<FakeBackend>,
        FakeProbe,
        ToneSource,
        ScriptedTiming,
    ) {
        let (mut l, probe, _) = started();
        probe.set_lose_completions(true);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 12);
        assert_eq!(count_slots(&l, SlotState::KernelOwned), 3);
        assert_eq!(l.session().irrevocable_until_frames(), 192);
        (l, probe, src, t)
    }

    /// The device reports the consumed counter at each of these values, in order, and the loop gets one tick.
    fn report_counter(
        l: &mut RenderLoop<FakeBackend>,
        probe: &FakeProbe,
        src: &mut ToneSource,
        t: &mut ScriptedTiming,
        counters: &[u32],
    ) {
        for counter in counters {
            probe.queue_event(DeviceEvent::Position { counter: *counter });
        }
        l.tick(src, t);
    }

    #[test]
    fn a_counter_that_goes_back_by_one_faults_the_loop_with_its_own_reason_and_holds_every_buffer()
    {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        // A baseline, then 64 of the 192 frames consumed: a clean step, which the loop accepts.
        report_counter(&mut l, &probe, &mut src, &mut t, &[1000, 1064]);
        assert_eq!(l.state(), RenderState::Running);
        assert_eq!(l.session().position().consumed_frames, 64);
        assert!(l.presentation_mapping_valid());
        // One behind 1064.
        report_counter(&mut l, &probe, &mut src, &mut t, &[1063]);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        assert!(!l.presentation_mapping_valid());
        assert!(l.session().counter_regressed());
        assert_eq!(
            l.session().position().consumed_frames,
            64,
            "a regress credits nothing"
        );
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        // Held, not freed: the three blocks the device may still read are quarantined.
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        assert_eq!(count_slots(&l, SlotState::KernelOwned), 0);
        assert_eq!(count_slots(&l, SlotState::Free), 1);
        // Waiting frees nothing: forty ticks are five stop deadlines.
        for _ in 0..40 {
            l.tick(&mut src, &mut t);
        }
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        assert_eq!(count_slots(&l, SlotState::Free), 1);
        assert_eq!(probe.use_after_free(), 0);
        // Only an acknowledged reset frees them, and the mapping is still invalid afterwards.
        l.recover().unwrap();
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(count_slots(&l, SlotState::Free), 4);
        assert_eq!(count_slots(&l, SlotState::Quarantined), 0);
        assert!(!l.presentation_mapping_valid());
    }

    #[test]
    fn a_counter_that_goes_back_across_its_wrap_is_a_regress_and_the_wrap_itself_is_not() {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        // Forward over the wrap: 0xFFFF_FFE0 to 0x20 is 64 frames, a clean step.
        report_counter(&mut l, &probe, &mut src, &mut t, &[0xFFFF_FFE0, 0x20]);
        assert_eq!(l.state(), RenderState::Running);
        assert_eq!(l.fault(), None);
        assert_eq!(l.session().position().consumed_frames, 64);
        assert!(l.presentation_mapping_valid());
        // Back over it: 0xFFFF_FFFF is 33 behind 0x20, not four billion ahead.
        report_counter(&mut l, &probe, &mut src, &mut t, &[0xFFFF_FFFF]);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        assert!(!l.presentation_mapping_valid());
        assert_eq!(l.session().position().consumed_frames, 64);
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
    }

    #[test]
    fn a_forward_overclaim_faults_the_loop_as_a_session_fault_and_leaves_the_mapping_valid() {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        report_counter(&mut l, &probe, &mut src, &mut t, &[1000, 1064]);
        // 4096 frames ahead of 1064 when only 128 are in flight: impossible, but not backwards.
        report_counter(&mut l, &probe, &mut src, &mut t, &[1064 + 4096]);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::SessionFaulted));
        assert!(!l.session().counter_regressed());
        assert!(l.presentation_mapping_valid());
        assert_eq!(l.session().position().consumed_frames, 64);
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        // The mapping was never in doubt, so the loop restarts as soon as the device is reset.
        l.recover().unwrap();
        assert_eq!(l.state(), RenderState::Ready);
        l.start(READY).unwrap();
        assert_eq!(l.state(), RenderState::Running);
    }

    #[test]
    fn a_regress_during_a_drain_faults_it_instead_of_timing_out_and_the_stop_tail_is_not_trusted() {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        report_counter(&mut l, &probe, &mut src, &mut t, &[1000, 1064]);
        l.stop().unwrap();
        assert_eq!(l.state(), RenderState::Draining);
        // Read from a counter that was still believed: 192 accepted, 64 consumed.
        assert!(l.stop_report().tail_trusted);
        assert_eq!(l.stop_report().irrevocable_tail_frames, 128);
        report_counter(&mut l, &probe, &mut src, &mut t, &[1063]);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        let report = l.stop_report();
        assert!(!report.acknowledged);
        assert!(!report.tail_trusted);
        assert!(!l.presentation_mapping_valid());
        // Long past the stop deadline the drain has not "timed out" into anything else, and nothing is freed.
        for _ in 0..40 {
            l.tick(&mut src, &mut t);
        }
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        assert_eq!(count_slots(&l, SlotState::Free), 1);
    }

    #[test]
    fn a_regress_while_muted_faults_the_same_way_and_leaves_the_muted_state_for_faulted() {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        l.mute().unwrap();
        assert_eq!(l.state(), RenderState::Muted);
        report_counter(&mut l, &probe, &mut src, &mut t, &[1000, 1064]);
        assert_eq!(l.state(), RenderState::Muted);
        report_counter(&mut l, &probe, &mut src, &mut t, &[1063]);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        assert!(!l.presentation_mapping_valid());
        assert_eq!(l.last_mute_acknowledged(), Some(true));
        assert_eq!(count_slots(&l, SlotState::Quarantined), 3);
        let events: Vec<RenderEventKind> = std::iter::from_fn(|| l.take_event())
            .map(|e| e.kind)
            .collect();
        assert!(events.contains(&RenderEventKind::Fault {
            reason: FaultReason::CounterRegress
        }));
        assert!(events.contains(&RenderEventKind::State {
            from: RenderState::Muted,
            to: RenderState::Faulted
        }));
        // Exactly one fault event: the reaction is reported once.
        let faults = events
            .iter()
            .filter(|k| matches!(k, RenderEventKind::Fault { .. }))
            .count();
        assert_eq!(faults, 1);
    }

    #[test]
    fn after_a_regress_the_loop_refuses_the_old_mapping_until_it_is_reinstalled_and_then_takes_a_new_baseline()
     {
        let (mut l, probe, mut src, mut t) = holding_three_blocks();
        report_counter(&mut l, &probe, &mut src, &mut t, &[1000, 1064]);
        report_counter(&mut l, &probe, &mut src, &mut t, &[1063]);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        // Nothing can be reinstalled or restarted while the old counter is the only one there is.
        assert_eq!(
            l.reinstall_presentation_mapping(),
            Err(RenderError::WrongState(RenderState::Faulted))
        );
        assert_eq!(
            l.start(READY),
            Err(RenderError::WrongState(RenderState::Faulted))
        );
        // The acknowledged reset returns the loop to a safe Ready, still without a mapping.
        l.recover().unwrap();
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(l.fault(), None);
        assert!(!l.presentation_mapping_valid());
        // The caller says its mapping is installed; the loop knows that mapping was built on the old counter.
        let calls = probe.calls();
        assert_eq!(
            l.start(READY),
            Err(RenderError::PresentationMappingInvalidated)
        );
        assert_eq!(l.state(), RenderState::Ready);
        assert_eq!(probe.calls(), calls, "a refused start touches nothing");
        // Reinstalled, it starts.
        l.reinstall_presentation_mapping().unwrap();
        assert!(l.presentation_mapping_valid());
        l.start(READY).unwrap();
        assert_eq!(l.state(), RenderState::Running);
        run(&mut l, &mut src, &mut t, 12); // three new blocks held: 192 frames in flight
        assert_eq!(l.state(), RenderState::Running);
        // The device now counts from somewhere else entirely. The old baseline (1064) is not used: the
        // first report only sets the new one, and a step of 64 from it is credited.
        let consumed_before = l.session().position().consumed_frames;
        report_counter(&mut l, &probe, &mut src, &mut t, &[5, 69]);
        assert_eq!(
            l.state(),
            RenderState::Running,
            "a stale baseline faults here"
        );
        assert_eq!(l.fault(), None);
        assert_eq!(l.session().position().consumed_frames, consumed_before + 64);
        // A stop that meets no regress reports a tail it can stand behind.
        l.stop().unwrap();
        assert!(l.stop_report().tail_trusted);
    }

    // ------------------------------------------------------------------------ samples

    /// The same stages, run with no loop around them: the blocks the loop must have produced.
    fn offline_blocks(blocks: usize, endian: Endian) -> Vec<Vec<u8>> {
        let mut src = ToneSource::new();
        let mut dsp = dsp();
        dsp.set_muted(false).unwrap();
        let mut resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
        let mut block = StereoAudioBlock::silence(0);
        let mut out = ProtectedOutput::new();
        let mut all = Vec::new();
        for k in 0..blocks {
            resampler
                .render(
                    &mut src,
                    &mut block.left[..BLOCK],
                    &mut block.right[..BLOCK],
                )
                .unwrap();
            block.frames = BLOCK;
            block.start_frame = (k * BLOCK) as u64;
            dsp.render_into(&block, &mut out);
            let mut bytes = Vec::new();
            for f in 0..BLOCK {
                for lane in out.samples.iter().take(2) {
                    bytes.extend_from_slice(&match endian {
                        Endian::Big => lane[f].to_be_bytes(),
                        Endian::Little => lane[f].to_le_bytes(),
                    });
                }
            }
            all.push(bytes);
        }
        all
    }

    #[test]
    fn what_reaches_the_device_is_exactly_what_the_stages_produce_in_order_without_loss_or_repeat()
    {
        let (mut l, probe, _) = started();
        probe.capture_submissions(64);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 24);
        let seen = probe.captured_submissions();
        assert_eq!(seen.len(), 6);
        assert_eq!(seen, offline_blocks(6, Endian::Big));
        // The tone arrives (the fade-in ramp has begun) and is not silence.
        assert!(seen[5].iter().any(|b| *b != 0));
        assert!(seen.iter().all(|b| b.len() == BLOCK * 4));
        // Permitted positive and the explicit byte order: the same run in little-endian is the same
        // samples with each pair of bytes swapped.
        let little_cfg = RenderConfig {
            output_endian: Endian::Little,
            ..RenderConfig::standard(BLOCK)
        };
        let (mut ll, lp, _) = build(fake_config(), little_cfg);
        ll.start(READY).unwrap();
        lp.capture_submissions(64);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut ll, &mut src, &mut t, 24);
        let little = lp.captured_submissions();
        assert_eq!(little, offline_blocks(6, Endian::Little));
        for (b, le) in seen.iter().zip(&little) {
            let swapped: Vec<u8> = b.chunks(2).flat_map(|p| [p[1], p[0]]).collect();
            assert_eq!(&swapped, le);
        }
    }

    #[test]
    fn a_graceful_stop_ramps_to_silence_and_ends_within_the_ramp_plus_the_stop_deadline() {
        let (mut l, probe, _) = started();
        probe.capture_submissions(200);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        run(&mut l, &mut src, &mut t, 48); // twelve blocks: full gain is reached
        let before = probe.captured_submissions().len();
        l.stop().unwrap();
        run_until_stopped(&mut l, &mut src, &mut t);
        assert_eq!(l.state(), RenderState::Stopped);
        let report = l.stop_report();
        assert!(report.acknowledged);
        // Bounded: at most the ramp blocks at four ticks each, plus the stop deadline, plus a period.
        let bound = u64::from(l.cfg.max_ramp_blocks) * 4 + 8 + 4;
        assert!(
            report.ticks <= bound,
            "{} ticks exceeds {bound}",
            report.ticks
        );
        // The ramp is audible in the samples: the first channel's peak never rises across the
        // blocks submitted after the stop began, and falls.
        let seen = probe.captured_submissions();
        let peaks: Vec<i32> = seen[before..]
            .iter()
            .map(|b| {
                b.chunks(4)
                    .map(|f| i32::from(i16::from_be_bytes([f[0], f[1]])).abs())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        assert!(peaks.len() >= 2, "{peaks:?}");
        assert!(peaks.windows(2).all(|w| w[1] <= w[0]), "{peaks:?}");
        assert!(peaks.last() < peaks.first(), "{peaks:?}");
    }

    #[test]
    fn a_one_frame_block_is_rendered_and_submitted_without_indexing_errors() {
        let (mut l, probe, _) = build(fake_config(), RenderConfig::standard(1));
        l.start(READY).unwrap();
        probe.capture_submissions(16);
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let reports = run(&mut l, &mut src, &mut t, 10);
        assert_eq!(finished(&reports).len(), 3);
        assert!(probe.captured_submissions().iter().all(|b| b.len() == 4));
        assert_identities(&l);
    }

    // ------------------------------------------------------------------------ the sink

    /// A scenario that produces many events: after three blocks every block is turned away.
    fn flood(read_every_tick: bool) -> (RenderCounters, Vec<(u64, BlockOutcome)>, Vec<FakeCall>) {
        let mut cfg = fake_config();
        cfg.completion_delay_ticks = 1000;
        let (mut l, probe, _) = build(cfg, RenderConfig::standard(BLOCK));
        l.start(READY).unwrap();
        let (mut src, mut t) = (ToneSource::new(), timing(1, &[], &[]));
        let mut outcomes = Vec::new();
        for _ in 0..400 {
            let r = l.tick(&mut src, &mut t);
            outcomes.extend(r.finished);
            if read_every_tick {
                while l.take_event().is_some() {}
            }
        }
        (l.counters(), outcomes, probe.calls())
    }

    #[test]
    fn a_full_or_unread_event_sink_changes_no_deadline_and_no_outcome() {
        let (unread, unread_outcomes, unread_calls) = flood(false);
        let (read, read_outcomes, read_calls) = flood(true);
        // 98 events were emitted (the start, and the 97 blocks turned away from block 3 on) into a
        // queue of 64: the rest were dropped, and counted.
        assert_eq!(unread.events_dropped, 98 - RENDER_EVENT_CAP as u64);
        assert_eq!(read.events_dropped, 0);
        // Nothing else differs: the same outcomes in the same order, the same device calls.
        assert_eq!(unread_outcomes, read_outcomes);
        assert_eq!(unread_calls, read_calls);
        let strip = |mut c: RenderCounters| {
            c.events_dropped = 0;
            c
        };
        assert_eq!(strip(unread), strip(read));
        assert_eq!(unread.capacity_rejected_blocks, 97);
    }

    // ------------------------------------------------------------------------ the independent model

    const SCENARIOS_JSON: &str = include_str!("../../../tests/d04/scenarios.json");

    /// The encoding `tests/d04/scenarios.json` uses for a block outcome.
    fn outcome_name(outcome: BlockOutcome) -> String {
        match outcome {
            BlockOutcome::OnTime => "on_time".to_string(),
            BlockOutcome::CpuMiss { late_by } => format!("cpu_miss:{late_by}"),
            BlockOutcome::CapacityRejected => "capacity_rejected".to_string(),
            BlockOutcome::ShortWrite { discarded_frames } => {
                format!("short_write:{discarded_frames}")
            }
            BlockOutcome::Starved {
                cause,
                silence_frames,
            } => {
                let cause = match cause {
                    Starvation::IngressLoss => "ingress_loss",
                    Starvation::DecodeDelay => "decode_delay",
                };
                format!("starved:{cause}:{silence_frames}")
            }
        }
    }

    fn numbers(map: &serde_json::Value) -> Vec<(u64, u64)> {
        map.as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.parse().unwrap(), v.as_u64().unwrap()))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn the_committed_scenarios_replay_through_the_real_loop_exactly_as_the_independent_model_says()
    {
        let doc: serde_json::Value = serde_json::from_str(SCENARIOS_JSON).unwrap();
        assert_eq!(doc["schema"], "ffw.d04.scenarios.v1");
        let scenarios = doc["scenarios"].as_array().unwrap();
        assert_eq!(scenarios.len(), 12, "a scenario was added or dropped");
        let cfg = &doc["config"];
        for sc in scenarios {
            let id = sc["id"].as_str().unwrap();
            let mut device = fake_config();
            device.completion_delay_ticks = sc["completion_delay"].as_u64().unwrap_or(2);
            let render = RenderConfig {
                block_frames: usize::try_from(cfg["block_frames"].as_u64().unwrap()).unwrap(),
                period_ticks: cfg["period"].as_u64().unwrap(),
                window_ticks: cfg["window"].as_u64().unwrap(),
                reserve_percent: u8::try_from(cfg["reserve_percent"].as_u64().unwrap()).unwrap(),
                reserve_slots: usize::try_from(cfg["reserve_slots"].as_u64().unwrap()).unwrap(),
                watchdog_misses: u32::try_from(cfg["watchdog_misses"].as_u64().unwrap()).unwrap(),
                max_submit_attempts: u8::try_from(cfg["attempts"].as_u64().unwrap()).unwrap(),
                ..RenderConfig::standard(BLOCK)
            };
            let (mut l, probe, _) = build(device, render);
            if let Some(limit) = sc["accept_limit"].as_u64() {
                probe.set_accept_limit(Some(usize::try_from(limit).unwrap()));
            }
            l.start(READY).unwrap();
            let costs = numbers(&sc["costs"]);
            let delays = numbers(&sc["delays"]);
            let mut t = timing(sc["default_cost"].as_u64().unwrap_or(1), &costs, &delays);
            let starve: BTreeMap<u64, Starvation> = sc["starve"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| {
                            let cause = match v.as_str().unwrap() {
                                "ingress_loss" => Starvation::IngressLoss,
                                "decode_delay" => Starvation::DecodeDelay,
                                other => panic!("{id}: unknown cause {other}"),
                            };
                            (k.parse().unwrap(), cause)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut src = ToneSource::new();
            let mut seen: Vec<(u64, u64, String)> = Vec::new();
            for _ in 0..sc["ticks"].as_u64().unwrap() {
                // A block meets the source's state at the moment it starts, which is when it is next.
                src.starved = starve.get(&l.next_index).copied();
                let r = l.tick(&mut src, &mut t);
                if let Some((k, o)) = r.finished {
                    seen.push((k, r.now, outcome_name(o)));
                }
            }
            let expect = &sc["expect"];
            let want: Vec<(u64, u64, String)> = expect["finished"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    (
                        f[0].as_u64().unwrap(),
                        f[1].as_u64().unwrap(),
                        f[2].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            assert_eq!(seen, want, "{id}: which blocks finished, when, and how");
            let counters = serde_json::to_value(l.counters()).unwrap();
            for (key, value) in expect["counters"].as_object().unwrap() {
                assert_eq!(&counters[key], value, "{id}: counter {key}");
            }
            let state = serde_json::to_value(l.state()).unwrap();
            assert_eq!(state, expect["state"], "{id}: final state");
            assert_eq!(l.now(), expect["now"].as_u64().unwrap(), "{id}: final tick");
        }
    }
}
