//! The HAL session: one owner driving one device through its lifecycle (`P04` / `ffw-0bh`).
//!
//! `Closed -> Prepared -> Running -> Draining -> Prepared -> Closed`, with `Faulted` reachable from
//! anywhere. The rules this layer enforces, each with a test:
//!
//! * **Fail muted.** A driver error, a malformed or forged response, a completion for a slot that
//!   is not in flight, or a counter that claims more than was submitted moves the session to
//!   `Faulted`, asks the device to mute, and records the fault. Nothing the device says is believed
//!   until it has been checked.
//! * **Tokens are inert.** A [`SubmitToken`] is a slot number and a generation. It owns nothing and
//!   has no `Drop`, so forgetting it, dropping it, or never polling for it cannot return storage.
//! * **The owner holds the storage.** A slot becomes `Free` only when the device acknowledges it (a
//!   matching completion, a flush acknowledgment, or a reset acknowledgment). Storage the kernel may
//!   still read is never reused, and destroying the session keeps it alive (see
//!   [`crate::slots`]).
//! * **Stop requested is not stopped.** `Draining` ends on a flush acknowledgment. If none arrives
//!   in time the drain reports `TimedOut`, quarantines what is in flight and faults; it never
//!   reports success it did not observe.
//! * **No audible transition without a stop deadline.** If the device cannot state how long a stop
//!   takes, [`HalSession::start`] is refused.
//! * **Optional silence priming.** [`SessionConfig::with_required_silence_blocks`] asks for `n` whole
//!   all-zero blocks to be taken by the device, while muted, before the first unmute; until it has them
//!   [`HalSession::start`] is refused with `UnmuteBeforeSilencePrime` before the backend is touched.
//!   The default is 0, which changes nothing.
//!
//! * **Transitions are emitted.** Prepare, start, an acknowledged stop or reset, every recorded
//!   fault and a device lost while faulted go into a bounded, critical-first queue the owner reads
//!   with [`HalSession::take_event`]. A full queue never changes what the session does, and what it
//!   could not keep is counted (see [`crate::emit`]).
//!
//! This is a host model. Run against the fake device it shows the adapter logic and nothing about
//! any board; the receipt says so.

use crate::abi::{AbiError, DeviceEvent, EVENT_LEN, RawGeometry, decode_event, decode_geometry};
use crate::backend::{AbiKind, DeviceBackend, DriverError, LocalEventCapability, Op, Provenance};
use crate::contract::ContractMatrix;
use crate::emit::{DEFAULT_EVENT_QUEUE_CAP, EmitStats, EventQueue, SessionEvent, SessionEventKind};
use crate::slots::{
    CompletionProblem, LeakLedger, MAX_BLOCK_BYTES, MAX_SLOTS, SlotError, SlotState, SlotTable,
    TokenState,
};
use franken_board_profile::{AmplifierPolicy, BoardProfile, UnsupportedReasonCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Schema string of a [`SessionReceipt`].
pub const RECEIPT_SCHEMA: &str = "ffw.p04.session_receipt.v1";
/// Most device events handled by one [`HalSession::poll`].
pub const MAX_EVENTS_PER_POLL: usize = 64;
/// Most fault records kept; further ones are counted, not stored.
pub const MAX_FAULT_RECORDS: usize = 16;
/// Slots that may be quarantined before the session records saturation.
pub const DEFAULT_QUARANTINE_CAP: usize = 4;
const MAX_CHANNELS: usize = 8;
/// The furthest a consumed-position report may move ahead of the last one and still be read as a
/// claim about the future. The driver's counter is 32 bits and wraps, so a report cannot say which way
/// it moved: it is read as ahead when the wrapping step is at most half the range, and as **behind**
/// when it is more. A step of exactly this value is ambiguous and is read as ahead (the forward
/// overclaim), never as a regress.
pub const COUNTER_FORWARD_LIMIT: u32 = 0x8000_0000;

/// Session ids come from a 32-bit counter because big-endian MIPS32 and PowerPC32 have no 64-bit
/// atomics. The counter never wraps: a wrapped id could let a token from an old session match a new
/// one and return storage the kernel may still hold. Once it is exhausted no session is created.
static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);

/// The next session id, or `None` once the counter is exhausted. Ids run from 1 to `u32::MAX - 1`:
/// the update that would carry the counter past `u32::MAX` is refused, so it stays put and every
/// later call also answers `None`.
///
/// An explicit compare-and-swap loop rather than `fetch_update`, which newer toolchains deprecate
/// in favour of `try_update`; the loop is valid on every toolchain. A concurrent taker makes the
/// swap fail with the value it saw, and the loop retries from there, so two takers never get the
/// same id.
fn take_session_id(counter: &AtomicU32) -> Option<u32> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(current),
            Err(seen) => current = seen,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Closed,
    Prepared,
    Running,
    Draining,
    Faulted,
}

/// What the session knows about the amplifier. `Unknown` means a mute was not acknowledged or the
/// device is gone, so the physical state cannot be assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Amp {
    Muted,
    Unmuted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedKind {
    Geometry,
    Event,
    WriteCount,
    SubmitCount,
}

/// Why the session faulted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaultCode {
    DriverError {
        op: Op,
        error: DriverError,
    },
    Malformed {
        what: MalformedKind,
        abi: Option<AbiError>,
    },
    BadCompletion {
        problem: CompletionProblem,
    },
    /// A completion arrived on an ABI that has no completions.
    UnexpectedCompletion,
    /// A consumed-position report claimed more than the session had in flight. Any such report is
    /// recorded as this, forward or backward, first, so a reader that only knows this code still sees
    /// every impossible counter.
    CounterOverclaim,
    /// The consumed counter went **backwards** (see [`COUNTER_FORWARD_LIMIT`]). It is recorded right
    /// after the [`FaultCode::CounterOverclaim`] it qualifies, and never after a forward overclaim, so
    /// its presence is what tells a regress (a driver whose counter was reset or rewound) from a
    /// counter that merely ran ahead. The safety response is the same for both: mute, quarantine,
    /// credit nothing.
    CounterRegress,
    DeviceLost,
    DrainTimedOut,
    DrainCancelled,
    MuteNotAcknowledged,
    UnmuteNotAcknowledged,
    QuarantineSaturated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRecord {
    pub code: FaultCode,
    /// Frames accepted by the device when the fault was recorded.
    pub accepted_frames: u64,
}

/// What `open` reserves for the cleanup path before any block can be submitted (the slot storage is
/// reserved by `prepare`, which asks slot by slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reserved {
    FaultRecords,
    EventQueue,
}

/// The storage a session reserved at admission, as capacities. Every figure is fixed by admission:
/// start, submit, drain, cancel, a fault, a reset or a restart never changes one, which is what makes
/// the cleanup path free of allocation. (The leak ledger is atomics, and the device is the backend's.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFootprint {
    /// Fault records that fit without allocating.
    pub fault_records: usize,
    /// Session events that fit without allocating.
    pub events: usize,
    /// Slots in the table (0 before `prepare`, and for a copying ABI).
    pub slots: usize,
    /// Bytes reserved for the slots, summed.
    pub slot_bytes: usize,
}

/// A device geometry that passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geometry {
    pub ring_depth: usize,
    pub frames_per_block: usize,
    pub channels: usize,
    pub bytes_per_sample: usize,
    pub frame_bytes: usize,
    pub block_bytes: usize,
}

fn validate_geometry(raw: &RawGeometry) -> Option<Geometry> {
    let ring_depth = usize::try_from(raw.ring_depth).ok()?;
    let frames_per_block = usize::try_from(raw.frames_per_block).ok()?;
    let channels = usize::try_from(raw.channels).ok()?;
    let bytes_per_sample = usize::try_from(raw.bytes_per_sample).ok()?;
    if ring_depth == 0
        || ring_depth > MAX_SLOTS
        || frames_per_block == 0
        || channels == 0
        || channels > MAX_CHANNELS
        || !(1..=4).contains(&bytes_per_sample)
    {
        return None;
    }
    let frame_bytes = channels.checked_mul(bytes_per_sample)?;
    let block_bytes = frames_per_block.checked_mul(frame_bytes)?;
    if block_bytes > MAX_BLOCK_BYTES {
        return None;
    }
    Some(Geometry {
        ring_depth,
        frames_per_block,
        channels,
        bytes_per_sample,
        frame_bytes,
        block_bytes,
    })
}

fn whole_frames(len: usize, frame_bytes: usize) -> bool {
    len / frame_bytes * frame_bytes == len
}

/// How well the consumed-frame count can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PositionClass {
    Exact,
    Bounded { max_error_frames: u32 },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub consumed_frames: u64,
    pub class: PositionClass,
}

/// What a [`HalSession::poll`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollReport {
    pub events: usize,
    pub completions: usize,
    /// Reports that contradicted the contract.
    pub anomalies: usize,
    /// Reports drained while already faulted, which change nothing.
    pub ignored_in_fault: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartPreconditions {
    pub presentation_mapping_installed: bool,
    pub safe_gain_installed: bool,
}

/// A claim check for a retained-buffer submit. It owns nothing.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct SubmitToken {
    session_id: u64,
    slot: u16,
    generation: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SubmitReceipt {
    pub accepted_bytes: usize,
    pub accepted_frames: u64,
    /// Bytes the device did not take. They stay with the caller.
    pub remainder_bytes: usize,
    /// Present only for a retained-buffer submit the device accepted.
    pub token: Option<SubmitToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The device acknowledged the stop.
    Acknowledged { waited_ticks: u64 },
    /// No acknowledgment within the bound. What was in flight is quarantined and the session faulted.
    TimedOut { waited_ticks: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbortReport {
    pub mute_acknowledged: bool,
}

/// A record of what the session did and what that does and does not show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReceipt {
    pub schema: String,
    pub provenance: Provenance,
    /// `model` for a fake device, `driver` for a real one.
    pub evidence: String,
    /// `host_simulation` or `device`.
    pub scope: String,
    pub abi: String,
    /// For a copying ABI: the stated evidence that the copy is synchronous.
    pub copy_evidence: Option<String>,
    pub phase: SessionPhase,
    pub amp: Amp,
    pub stop_deadline_known: bool,
    pub audible_transition_admitted: bool,
    pub admission_blocker: Option<String>,
    /// A stop was asked for. This is NOT the same as the device having stopped: that needs a flush
    /// or reset acknowledgment, after which this is false again.
    pub stop_requested: bool,
    pub accepted_frames: u64,
    pub consumed_frames: u64,
    /// Frames accepted and then thrown away by a flush or reset instead of played.
    pub discarded_frames: u64,
    pub position_class: PositionClass,
    pub slots_free: usize,
    pub slots_in_flight: usize,
    pub slots_quarantined: usize,
    /// Slots whose storage was kept alive because the kernel might still read it.
    pub leaked_slots: usize,
    pub faults: Vec<FaultRecord>,
    pub dropped_fault_records: u32,
    pub anomalies: u32,
    pub local_events: LocalEventCapability,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub ledger: Arc<LeakLedger>,
    pub quarantine_cap: usize,
    /// Capacity of the session's event queue (at least 1).
    pub event_queue_cap: usize,
    /// Whole all-zero blocks the device must have taken, while muted, before `start` may unmute.
    /// 0 (the default) demands none, which is how every session behaved before this field existed.
    pub required_silence_blocks: u32,
}

impl SessionConfig {
    /// The process-wide leak ledger and the default quarantine cap.
    #[must_use]
    pub fn process_default() -> Self {
        Self {
            ledger: LeakLedger::process(),
            quarantine_cap: DEFAULT_QUARANTINE_CAP,
            event_queue_cap: DEFAULT_EVENT_QUEUE_CAP,
            required_silence_blocks: 0,
        }
    }

    #[must_use]
    pub const fn with_ledger(ledger: Arc<LeakLedger>, quarantine_cap: usize) -> Self {
        Self {
            ledger,
            quarantine_cap,
            event_queue_cap: DEFAULT_EVENT_QUEUE_CAP,
            required_silence_blocks: 0,
        }
    }

    /// The same configuration with a different event queue capacity.
    #[must_use]
    pub const fn with_event_queue_cap(mut self, event_queue_cap: usize) -> Self {
        self.event_queue_cap = event_queue_cap;
        self
    }

    /// The same configuration requiring `blocks` whole blocks of silence before the first unmute.
    #[must_use]
    pub const fn with_required_silence_blocks(mut self, blocks: u32) -> Self {
        self.required_silence_blocks = blocks;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("board profile rejected for audio output: {0:?}")]
    ProfileRejected(UnsupportedReasonCode),
    #[error("amplifier policy forbids hardware audio output")]
    AmplifierForbidden,
    #[error("a real device needs a hardware-eligible contract matrix")]
    HardwareNeedsContract,
    #[error("the contract matrix is not hardware-eligible ({missing} missing)")]
    ContractIncomplete { missing: usize },
    #[error("a copying-write ABI needs stated evidence that the copy is synchronous")]
    CopyEvidenceMissing,
    #[error("quarantine cap and event queue capacity must each be at least 1")]
    BadConfig,
    #[error("the session id space is exhausted, so no new session can be created")]
    SessionIdsExhausted,
    #[error("not allowed in phase {phase:?}")]
    WrongPhase { phase: SessionPhase },
    #[error("the mute was not acknowledged")]
    MuteNotAcknowledged,
    #[error("no presentation mapping is installed")]
    PresentationMappingMissing,
    #[error("no safe gain is installed")]
    SafeGainMissing,
    #[error("the device cannot state a stop deadline, so no audible transition is admitted")]
    StopDeadlineUnknown,
    #[error(
        "silence priming incomplete: {primed} of {required} whole block(s) taken, so the amplifier stays muted"
    )]
    UnmuteBeforeSilencePrime { primed: u32, required: u32 },
    #[error("a submit must carry at least one frame")]
    EmptySubmit,
    #[error("{len} byte(s) is not a whole number of {frame_bytes}-byte frames")]
    PartialFrame { len: usize, frame_bytes: usize },
    #[error("{len} byte(s) exceed the {block_bytes}-byte block")]
    TooLarge { len: usize, block_bytes: usize },
    #[error("no free slot")]
    NoFreeSlot,
    #[error("slot table: {0}")]
    Slots(SlotError),
    /// Something the cleanup path needs could not be reserved at admission. Nothing was started and the
    /// device was not touched. This is the allocator (or the size) saying no; it is not a full ring.
    #[error("the {what} storage could not be reserved at admission; nothing was started")]
    StorageNotAdmitted { what: &'static str },
    #[error("the session faulted and is muted: {0:?}")]
    Faulted(FaultCode),
    #[error("the session faulted while draining")]
    FaultedDuringDrain,
    #[error("the device did not acknowledge the reset")]
    ResetNotAcknowledged,
    #[error("the device is gone; a reset cannot recover it")]
    DevicePersistentlyLost,
    #[error("that token belongs to another session")]
    ForeignToken,
    #[error(
        "cannot close: phase {phase:?}, {in_flight} in flight, {quarantined} quarantined, muted {amp_muted}"
    )]
    CloseBlocked {
        phase: SessionPhase,
        in_flight: usize,
        quarantined: usize,
        amp_muted: bool,
    },
}

/// A refused close hands the session back, intact.
#[derive(Debug)]
pub struct CloseRefused<B: DeviceBackend> {
    pub session: HalSession<B>,
    pub reason: SessionError,
}

/// One owner driving one device.
#[derive(Debug)]
pub struct HalSession<B: DeviceBackend> {
    // Declared first, so after `Drop::drop` has asked for a mute, the table's own drop (which keeps
    // in-flight storage alive) runs before the backend goes away.
    slots: Option<SlotTable>,
    backend: B,
    session_id: u64,
    /// How many flushes and resets the device has acknowledged since this session opened.
    generation: u64,
    phase: SessionPhase,
    amp: Amp,
    abi: AbiKind,
    provenance: Provenance,
    geometry: Option<Geometry>,
    stop_deadline_ticks: Option<u64>,
    min_lead_ticks: Option<u64>,
    position_error_frames: Option<u32>,
    local_events: LocalEventCapability,
    accepted_frames: u64,
    consumed_frames: u64,
    discarded_frames: u64,
    last_counter: u32,
    rebaseline: bool,
    /// Set when the consumed counter went backwards; cleared only by an acknowledged reset, which also
    /// takes a new baseline. While it is set the counter's old baseline is not trusted for anything.
    counter_regressed: bool,
    stop_requested: bool,
    device_lost: bool,
    saturated_reported: bool,
    faults: Vec<FaultRecord>,
    dropped_fault_records: u32,
    anomalies: u32,
    ledger: Arc<LeakLedger>,
    quarantine_cap: usize,
    events: EventQueue,
    required_silence_blocks: u32,
    primed_silence_blocks: u32,
    // True only after an acknowledged reset and while every later Prepared submit was silent.
    silent_prepared_after_reset: bool,
}

impl<B: DeviceBackend> HalSession<B> {
    /// Acquire a device that is not real hardware. A real backend is refused here: it must come
    /// through [`Self::open_hardware`] with a hardware-eligible contract matrix.
    pub fn open(
        profile: BoardProfile,
        backend: B,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        if backend.provenance() == Provenance::Real {
            return Err(SessionError::HardwareNeedsContract);
        }
        Self::open_checked(profile, backend, config)
    }

    /// Acquire a device with the retained-driver contract matrix checked first.
    pub fn open_hardware(
        profile: BoardProfile,
        backend: B,
        config: SessionConfig,
        matrix: &ContractMatrix,
    ) -> Result<Self, SessionError> {
        let report = matrix.evaluate_for_profile(&profile);
        if !report.hardware_eligible {
            return Err(SessionError::ContractIncomplete {
                missing: report.missing.len(),
            });
        }
        Self::open_checked(profile, backend, config)
    }

    fn open_checked(
        profile: BoardProfile,
        backend: B,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        Self::open_with_ids(profile, backend, config, &NEXT_SESSION_ID)
    }

    /// `open_checked` with the id counter passed in, so a test can start it near its limit.
    fn open_with_ids(
        profile: BoardProfile,
        backend: B,
        config: SessionConfig,
        ids: &AtomicU32,
    ) -> Result<Self, SessionError> {
        Self::open_admitting(profile, backend, config, ids, &mut |_| false)
    }

    /// `open_with_ids` with each reservation for the cleanup path made visible: `refuse` is asked before
    /// each one and a `true` refuses it, so a test can show a refusal is clean (typed, the device untouched,
    /// no id used). Production never refuses; the real reservation can still fail, and fails the same way.
    fn open_admitting(
        profile: BoardProfile,
        backend: B,
        config: SessionConfig,
        ids: &AtomicU32,
        refuse: &mut dyn FnMut(Reserved) -> bool,
    ) -> Result<Self, SessionError> {
        profile
            .verify_integrity()
            .map_err(SessionError::ProfileRejected)?;
        if profile.amplifier_policy != AmplifierPolicy::AdmittedSafeStartupOrder {
            return Err(SessionError::AmplifierForbidden);
        }
        let abi = backend.abi();
        if let AbiKind::CopyingWrite { evidence } = &abi
            && evidence.trim().is_empty()
        {
            return Err(SessionError::CopyEvidenceMissing);
        }
        if config.quarantine_cap == 0 || config.event_queue_cap == 0 {
            return Err(SessionError::BadConfig);
        }
        // The cleanup path appends to these (a fault is recorded, an event emitted) on a stop, a drain
        // timeout or a failed start: reserved now, they are never grown there. Before the id is taken,
        // so a refused open uses none, and before the device is touched.
        let mut faults = Vec::new();
        if refuse(Reserved::FaultRecords) || faults.try_reserve_exact(MAX_FAULT_RECORDS).is_err() {
            return Err(SessionError::StorageNotAdmitted {
                what: "fault records",
            });
        }
        let events = if refuse(Reserved::EventQueue) {
            None
        } else {
            EventQueue::reserved(config.event_queue_cap).ok()
        };
        let Some(events) = events else {
            return Err(SessionError::StorageNotAdmitted {
                what: "event queue",
            });
        };
        // Last, so a refused open does not use up an id. Nothing has touched the device yet.
        let session_id = take_session_id(ids).ok_or(SessionError::SessionIdsExhausted)?;
        let provenance = backend.provenance();
        Ok(Self {
            slots: None,
            backend,
            session_id: u64::from(session_id),
            generation: 0,
            phase: SessionPhase::Closed,
            // The session has not touched the device, so it has not unmuted it.
            amp: Amp::Muted,
            abi,
            provenance,
            geometry: None,
            stop_deadline_ticks: None,
            min_lead_ticks: None,
            position_error_frames: None,
            local_events: LocalEventCapability::Unsupported {
                reason: "not queried yet".to_string(),
            },
            accepted_frames: 0,
            consumed_frames: 0,
            discarded_frames: 0,
            last_counter: 0,
            rebaseline: true,
            counter_regressed: false,
            stop_requested: false,
            device_lost: false,
            saturated_reported: false,
            faults,
            dropped_fault_records: 0,
            anomalies: 0,
            ledger: config.ledger,
            quarantine_cap: config.quarantine_cap,
            events,
            required_silence_blocks: config.required_silence_blocks,
            primed_silence_blocks: 0,
            silent_prepared_after_reset: false,
        })
    }

    // ---- events

    /// The next session event, oldest first. The queue is bounded: see [`Self::event_stats`] for
    /// exactly what it could not keep. Events are never audio.
    pub fn take_event(&mut self) -> Option<SessionEvent> {
        self.events.take()
    }

    /// Events waiting to be taken.
    #[must_use]
    pub fn events_pending(&self) -> usize {
        self.events.pending()
    }

    /// Exact accounting of every event the session emitted.
    #[must_use]
    pub const fn event_stats(&self) -> EmitStats {
        self.events.stats()
    }

    /// False once a critical event (a fault, or a device lost while faulted) could not be kept.
    #[must_use]
    pub const fn event_evidence_complete(&self) -> bool {
        self.events.stats().lost_critical == 0
    }

    // ---- read-only views

    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    #[must_use]
    pub const fn amp(&self) -> Amp {
        self.amp
    }

    /// Whole all-zero blocks the device has taken while the session was `Prepared`. It returns to 0 on
    /// a stop, a reset, a fault, a lost device and on the unmute that spends it.
    #[must_use]
    pub const fn primed_silence_blocks(&self) -> u32 {
        self.primed_silence_blocks
    }

    /// How many such blocks `start` demands (0: none).
    #[must_use]
    pub const fn required_silence_blocks(&self) -> u32 {
        self.required_silence_blocks
    }

    #[must_use]
    pub const fn geometry(&self) -> Option<Geometry> {
        self.geometry
    }

    #[must_use]
    pub fn slot_states(&self) -> Vec<SlotState> {
        self.slots.as_ref().map_or_else(Vec::new, SlotTable::states)
    }

    /// A read-only report of the capacities reserved at admission (see [`StorageFootprint`]). It is not a
    /// memory measurement: it says what was asked for and kept, not what the process uses.
    #[must_use]
    pub fn storage_footprint(&self) -> StorageFootprint {
        StorageFootprint {
            fault_records: self.faults.capacity(),
            events: self.events.reserved_capacity(),
            slots: self.slots.as_ref().map_or(0, SlotTable::depth),
            slot_bytes: self.slots.as_ref().map_or(0, SlotTable::reserved_bytes),
        }
    }

    /// Fewest ticks ahead of the output cursor a block must be submitted, if the device says.
    #[must_use]
    pub const fn min_submission_lead_ticks(&self) -> Option<u64> {
        self.min_lead_ticks
    }

    #[must_use]
    pub const fn stop_deadline_ticks(&self) -> Option<u64> {
        self.stop_deadline_ticks
    }

    /// Everything handed to the device so far is irrevocable: the output cursor cannot move back
    /// past it. This is the count of frames the device accepted.
    #[must_use]
    pub const fn irrevocable_until_frames(&self) -> u64 {
        self.accepted_frames
    }

    /// This session's identity: unique in the process and never reused, because the ids that name sessions
    /// never wrap (a session that cannot get one is refused at open). A frame count means nothing without
    /// the session that counted it.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// How many flushes and resets the device has acknowledged since this session opened. Frames the
    /// session accepted before an acknowledgment were flushed by it, not played: the frame counters keep
    /// counting across it, so this number is what separates the audio before the flush from the audio
    /// after it. It advances only on an acknowledgment, never on a request, a fault or a timeout.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn position(&self) -> Position {
        let class = match self.position_error_frames {
            Some(0) => PositionClass::Exact,
            Some(n) => PositionClass::Bounded {
                max_error_frames: n,
            },
            None => PositionClass::Unknown,
        };
        Position {
            consumed_frames: self.consumed_frames,
            class,
        }
    }

    /// Whether the session is faulted because the device's consumed counter went backwards. It holds
    /// from that fault until an acknowledged [`Self::reset_device`], which takes a new baseline.
    #[must_use]
    pub const fn counter_regressed(&self) -> bool {
        self.counter_regressed
    }

    fn in_flight_frames(&self) -> u64 {
        self.accepted_frames
            .saturating_sub(self.consumed_frames)
            .saturating_sub(self.discarded_frames)
    }

    /// Where the use of a slot named by a token stands.
    pub fn token_state(&self, token: &SubmitToken) -> Result<TokenState, SessionError> {
        if token.session_id != self.session_id {
            return Err(SessionError::ForeignToken);
        }
        Ok(self.inspect_slot(token.slot, token.generation))
    }

    /// Diagnostic: where the use of `slot` at `generation` stands, without needing a token.
    #[must_use]
    pub fn inspect_slot(&self, slot: u16, generation: u32) -> TokenState {
        self.slots
            .as_ref()
            .map_or(TokenState::Settled, |t| t.token_state(slot, generation))
    }

    #[must_use]
    pub fn receipt(&self) -> SessionReceipt {
        let (slots_free, slots_in_flight, slots_quarantined) =
            self.slots.as_ref().map_or((0, 0, 0), |t| {
                (
                    t.count(SlotState::Free),
                    t.count(SlotState::KernelOwned),
                    t.count(SlotState::Quarantined),
                )
            });
        let admitted = self.stop_deadline_ticks.is_some();
        let (evidence, scope) = match self.provenance {
            Provenance::Fake => ("model", "host_simulation"),
            Provenance::Real => ("driver", "device"),
        };
        let (abi, copy_evidence) = match &self.abi {
            AbiKind::CopyingWrite { evidence } => ("copying_write", Some(evidence.clone())),
            AbiKind::RetainedBuffer => ("retained_buffer", None),
        };
        SessionReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            provenance: self.provenance,
            evidence: evidence.to_string(),
            scope: scope.to_string(),
            abi: abi.to_string(),
            copy_evidence,
            phase: self.phase,
            amp: self.amp,
            stop_deadline_known: admitted,
            audible_transition_admitted: admitted,
            admission_blocker: if admitted {
                None
            } else {
                Some("stop deadline unknown".to_string())
            },
            stop_requested: self.stop_requested,
            accepted_frames: self.accepted_frames,
            consumed_frames: self.consumed_frames,
            discarded_frames: self.discarded_frames,
            position_class: self.position().class,
            slots_free,
            slots_in_flight,
            slots_quarantined,
            leaked_slots: self.ledger.leaked_slots(),
            faults: self.faults.clone(),
            dropped_fault_records: self.dropped_fault_records,
            anomalies: self.anomalies,
            local_events: self.local_events.clone(),
        }
    }

    // ---- fault handling

    fn require_phase(&self, allowed: &[SessionPhase]) -> Result<(), SessionError> {
        if allowed.contains(&self.phase) {
            Ok(())
        } else {
            Err(SessionError::WrongPhase { phase: self.phase })
        }
    }

    /// Emit a transition. This never changes what the session does: a full queue only counts.
    fn emit(&mut self, kind: SessionEventKind) {
        self.events.emit(kind, self.accepted_frames);
    }

    /// The device is gone and the session was already faulted, so no new fault is recorded. The
    /// first time that happens it is emitted, because the amplifier is now `Unknown`.
    fn note_loss_while_faulted(&mut self) {
        if !self.device_lost {
            self.emit(SessionEventKind::DeviceLostWhileFaulted);
        }
        self.device_lost = true;
    }

    fn record_fault(&mut self, code: FaultCode) {
        self.emit(SessionEventKind::Fault { code: code.clone() });
        if self.faults.len() < MAX_FAULT_RECORDS {
            self.faults.push(FaultRecord {
                code,
                accepted_frames: self.accepted_frames,
            });
        } else {
            self.dropped_fault_records = self.dropped_fault_records.saturating_add(1);
        }
    }

    /// Ask the device to mute. Returns whether it acknowledged, and records what the session now
    /// knows about the amplifier.
    fn try_mute(&mut self) -> bool {
        match self.backend.set_mute(true) {
            Ok(true) => {
                self.amp = Amp::Muted;
                true
            }
            Ok(false) => {
                self.amp = Amp::Unknown;
                false
            }
            Err(error) => {
                if error == DriverError::Gone {
                    self.device_lost = true;
                }
                self.amp = Amp::Unknown;
                false
            }
        }
    }

    /// The one failure path: record, quarantine what the kernel may hold, fault, mute.
    fn fail_muted(&mut self, code: FaultCode) -> SessionError {
        self.fail_muted_qualified(code, None)
    }

    /// [`Self::fail_muted`] with a second code recorded straight after the first, before anything the
    /// failure itself causes (saturation, an unacknowledged mute), so the pair reads as one cause.
    fn fail_muted_qualified(
        &mut self,
        code: FaultCode,
        qualifier: Option<FaultCode>,
    ) -> SessionError {
        self.record_fault(code.clone());
        if let Some(qualifier) = qualifier {
            self.record_fault(qualifier);
        }
        let mut saturated = false;
        if let Some(table) = self.slots.as_mut() {
            table.quarantine_all_in_flight();
            saturated = table.quarantine_over_cap();
        }
        if saturated && !self.saturated_reported {
            self.saturated_reported = true;
            self.record_fault(FaultCode::QuarantineSaturated);
        }
        self.primed_silence_blocks = 0;
        self.phase = SessionPhase::Faulted;
        self.stop_requested = true;
        let acknowledged = self.try_mute();
        if !acknowledged && !matches!(code, FaultCode::MuteNotAcknowledged) {
            self.record_fault(FaultCode::MuteNotAcknowledged);
        }
        SessionError::Faulted(code)
    }

    fn driver_failed(&mut self, op: Op, error: DriverError) -> SessionError {
        if error == DriverError::Gone {
            self.device_lost = true;
        }
        self.fail_muted(FaultCode::DriverError { op, error })
    }

    // ---- lifecycle

    /// `Closed -> Prepared`. Queries the device (no state change), validates what it says, reserves the
    /// buffers (a refusal here has touched the device with nothing but that query), mutes, and commits.
    pub fn prepare(&mut self) -> Result<(), SessionError> {
        self.prepare_reserving(&mut |_| false)
    }

    /// `prepare` with each slot's reservation made visible: `refuse(slot)` is asked before slot `slot`'s
    /// storage is reserved. A refusal leaves the session `Closed` and muted, with no table and no fault
    /// recorded, so the same session can prepare again.
    fn prepare_reserving(
        &mut self,
        refuse: &mut dyn FnMut(usize) -> bool,
    ) -> Result<(), SessionError> {
        self.require_phase(&[SessionPhase::Closed])?;
        let caps = match self.backend.capabilities() {
            Ok(caps) => caps,
            Err(error) => return Err(self.driver_failed(Op::Capabilities, error)),
        };
        let raw = match decode_geometry(&caps.geometry) {
            Ok(raw) => raw,
            Err(error) => {
                return Err(self.fail_muted(FaultCode::Malformed {
                    what: MalformedKind::Geometry,
                    abi: Some(error),
                }));
            }
        };
        let Some(geometry) = validate_geometry(&raw) else {
            return Err(self.fail_muted(FaultCode::Malformed {
                what: MalformedKind::Geometry,
                abi: None,
            }));
        };
        // The buffers are reserved before the device is asked to do anything but answer the query above, so a
        // refusal touches nothing; until the session commits below, the table is only a local.
        let table = if self.abi == AbiKind::RetainedBuffer {
            let cap = self.quarantine_cap.min(geometry.ring_depth);
            let table = SlotTable::new_reserving(
                geometry.ring_depth,
                geometry.block_bytes,
                cap,
                Arc::clone(&self.ledger),
                refuse,
            )
            .map_err(SessionError::Slots)?;
            Some(table)
        } else {
            None
        };
        match self.backend.set_mute(true) {
            Ok(true) => self.amp = Amp::Muted,
            Ok(false) => return Err(self.fail_muted(FaultCode::MuteNotAcknowledged)),
            Err(error) => return Err(self.driver_failed(Op::SetMute, error)),
        }
        self.slots = table;
        self.geometry = Some(geometry);
        self.stop_deadline_ticks = caps.stop_deadline_ticks;
        self.min_lead_ticks = caps.min_submission_lead_ticks;
        self.position_error_frames = caps.position_error_frames;
        self.local_events = caps.local_events;
        self.phase = SessionPhase::Prepared;
        self.emit(SessionEventKind::Prepared);
        Ok(())
    }

    /// `Prepared -> Running`. Refused unless the amplifier is known muted, a presentation mapping and
    /// a safe gain are installed, and the device can state how long a stop takes. If the session was
    /// configured to require silence priming it is also refused, with `UnmuteBeforeSilencePrime`, until
    /// that many whole blocks of silence have been taken; that refusal makes no call on the backend.
    pub fn start(&mut self, pre: StartPreconditions) -> Result<(), SessionError> {
        self.require_phase(&[SessionPhase::Prepared])?;
        if self.amp != Amp::Muted {
            return Err(SessionError::MuteNotAcknowledged);
        }
        if !pre.presentation_mapping_installed {
            return Err(SessionError::PresentationMappingMissing);
        }
        if !pre.safe_gain_installed {
            return Err(SessionError::SafeGainMissing);
        }
        if self.stop_deadline_ticks.is_none() {
            return Err(SessionError::StopDeadlineUnknown);
        }
        // Last of the checks and before the backend is touched: a refusal here leaves the device
        // exactly as it was, muted and not started, and is a caller error rather than a fault.
        if self.primed_silence_blocks < self.required_silence_blocks {
            return Err(SessionError::UnmuteBeforeSilencePrime {
                primed: self.primed_silence_blocks,
                required: self.required_silence_blocks,
            });
        }
        if let Err(error) = self.backend.start() {
            return Err(self.driver_failed(Op::Start, error));
        }
        match self.backend.set_mute(false) {
            Ok(true) => {
                self.amp = Amp::Unmuted;
                self.phase = SessionPhase::Running;
                self.silent_prepared_after_reset = false;
                // The priming is spent by this unmute.
                self.primed_silence_blocks = 0;
                self.emit(SessionEventKind::Started);
                Ok(())
            }
            Ok(false) => Err(self.fail_muted(FaultCode::UnmuteNotAcknowledged)),
            Err(error) => Err(self.driver_failed(Op::SetMute, error)),
        }
    }

    /// Whether an acknowledged reset with an explicit playback-discard guarantee
    /// cleared unknown inherited custody and all later Prepared submissions were
    /// silence. This is a software admission condition, not evidence that a
    /// physical amplifier stays muted after start.
    #[must_use]
    pub const fn silent_prepared_after_reset(&self) -> bool {
        matches!(self.phase, SessionPhase::Prepared)
            && matches!(self.amp, Amp::Muted)
            && self.silent_prepared_after_reset
    }

    /// Hand a block to the device. `bytes` must be a whole number of frames and fit one block.
    /// A short write leaves the remainder with the caller.
    pub fn submit(&mut self, bytes: &[u8]) -> Result<SubmitReceipt, SessionError> {
        self.require_phase(&[SessionPhase::Prepared, SessionPhase::Running])?;
        let Some(geometry) = self.geometry else {
            return Err(SessionError::WrongPhase { phase: self.phase });
        };
        if bytes.is_empty() {
            return Err(SessionError::EmptySubmit);
        }
        if !whole_frames(bytes.len(), geometry.frame_bytes) {
            return Err(SessionError::PartialFrame {
                len: bytes.len(),
                frame_bytes: geometry.frame_bytes,
            });
        }
        if bytes.len() > geometry.block_bytes {
            return Err(SessionError::TooLarge {
                len: bytes.len(),
                block_bytes: geometry.block_bytes,
            });
        }
        // Only a prepared session is priming. `Prepared` is never unmuted (the one place the amplifier
        // becomes `Unmuted` also makes the phase `Running`), so the amplifier needs no check of its own.
        // This is a comparison, so a running session's submit pays nothing for it.
        let priming = self.phase == SessionPhase::Prepared;
        // Conservatively invalidate even on an error or short write: the backend may have
        // accepted bytes before reporting an ambiguous failure.
        if priming && bytes.iter().any(|&byte| byte != 0) {
            self.silent_prepared_after_reset = false;
        }
        let result = if self.abi == AbiKind::RetainedBuffer {
            self.submit_retained(bytes, geometry)
        } else {
            self.submit_copying(bytes, geometry)
        };
        // A block counts only if the device took all of it (a longer submit was refused above, so that
        // makes it a whole block) and every byte is zero. All-zero bytes are silence for signed PCM; the
        // geometry record carries no sample format, so that is an assumption of this layer.
        if priming
            && result
                .as_ref()
                .is_ok_and(|receipt| receipt.accepted_bytes == geometry.block_bytes)
            && bytes.iter().all(|&byte| byte == 0)
        {
            self.primed_silence_blocks = self.primed_silence_blocks.saturating_add(1);
        }
        result
    }

    /// Submit one whole block of silence, as the priming that
    /// [`SessionConfig::with_required_silence_blocks`] asks for. It is a convenience over
    /// [`Self::submit`]: whether the block counted is [`Self::primed_silence_blocks`] going up, which
    /// happens only if the device took all of it. Allowed only while `Prepared`.
    pub fn prime_silence(&mut self) -> Result<SubmitReceipt, SessionError> {
        self.require_phase(&[SessionPhase::Prepared])?;
        let Some(geometry) = self.geometry else {
            return Err(SessionError::WrongPhase { phase: self.phase });
        };
        let block = vec![0u8; geometry.block_bytes];
        self.submit(&block)
    }

    fn credit(&mut self, accepted_bytes: usize, geometry: Geometry) -> u64 {
        let frames = u64::try_from(accepted_bytes / geometry.frame_bytes).unwrap_or(u64::MAX);
        self.accepted_frames = self.accepted_frames.saturating_add(frames);
        frames
    }

    fn submit_copying(
        &mut self,
        bytes: &[u8],
        geometry: Geometry,
    ) -> Result<SubmitReceipt, SessionError> {
        match self.backend.write(bytes) {
            Err(error) => Err(self.driver_failed(Op::Write, error)),
            Ok(n) if n > bytes.len() || !whole_frames(n, geometry.frame_bytes) => Err(self
                .fail_muted(FaultCode::Malformed {
                    what: MalformedKind::WriteCount,
                    abi: None,
                })),
            Ok(n) => {
                let accepted_frames = self.credit(n, geometry);
                Ok(SubmitReceipt {
                    accepted_bytes: n,
                    accepted_frames,
                    remainder_bytes: bytes.len() - n,
                    token: None,
                })
            }
        }
    }

    fn submit_retained(
        &mut self,
        bytes: &[u8],
        geometry: Geometry,
    ) -> Result<SubmitReceipt, SessionError> {
        let acquired = match self.slots.as_mut() {
            Some(table) => table.acquire_free(bytes),
            None => return Err(SessionError::WrongPhase { phase: self.phase }),
        };
        let (slot, generation, view) = match acquired {
            Ok(parts) => parts,
            Err(SlotError::NoFreeSlot) => return Err(SessionError::NoFreeSlot),
            Err(other) => return Err(SessionError::Slots(other)),
        };
        match self
            .backend
            .submit_retained(slot, generation, view, bytes.len())
        {
            Err(error) => {
                // The call failed, so we cannot tell whether the kernel kept the buffer.
                if let Some(table) = self.slots.as_mut() {
                    table.quarantine_slot(slot);
                }
                Err(self.driver_failed(Op::SubmitRetained, error))
            }
            Ok(n) if n > bytes.len() || !whole_frames(n, geometry.frame_bytes) => {
                if let Some(table) = self.slots.as_mut() {
                    table.quarantine_slot(slot);
                }
                Err(self.fail_muted(FaultCode::Malformed {
                    what: MalformedKind::SubmitCount,
                    abi: None,
                }))
            }
            Ok(0) => {
                // The device took none of it, so it holds nothing and the slot is ours again.
                if let Some(table) = self.slots.as_mut() {
                    table.release_unaccepted(slot, generation);
                }
                Ok(SubmitReceipt {
                    accepted_bytes: 0,
                    accepted_frames: 0,
                    remainder_bytes: bytes.len(),
                    token: None,
                })
            }
            Ok(n) => {
                let accepted_frames = self.credit(n, geometry);
                Ok(SubmitReceipt {
                    accepted_bytes: n,
                    accepted_frames,
                    remainder_bytes: bytes.len() - n,
                    token: Some(SubmitToken {
                        session_id: self.session_id,
                        slot,
                        generation,
                    }),
                })
            }
        }
    }

    // ---- device events

    fn note_anomaly(&mut self, report: &mut PollReport) {
        self.anomalies = self.anomalies.saturating_add(1);
        report.anomalies += 1;
    }

    fn apply_event(&mut self, event: DeviceEvent, report: &mut PollReport) {
        if self.phase == SessionPhase::Faulted {
            // Already muted and quarantined. Draining what the device says changes nothing.
            if event == DeviceEvent::DeviceLost {
                self.note_loss_while_faulted();
                self.amp = Amp::Unknown;
            }
            report.ignored_in_fault += 1;
            return;
        }
        match event {
            DeviceEvent::Completed { slot, generation } => {
                let result = self
                    .slots
                    .as_mut()
                    .map(|table| table.complete(slot, generation));
                match result {
                    Some(Ok(())) => report.completions += 1,
                    Some(Err(problem)) => {
                        self.note_anomaly(report);
                        let _ = self.fail_muted(FaultCode::BadCompletion { problem });
                    }
                    None => {
                        self.note_anomaly(report);
                        let _ = self.fail_muted(FaultCode::UnexpectedCompletion);
                    }
                }
            }
            DeviceEvent::Position { counter } => {
                if self.rebaseline {
                    // The first report after open or reset only sets the baseline.
                    self.last_counter = counter;
                    self.rebaseline = false;
                    return;
                }
                let step = counter.wrapping_sub(self.last_counter);
                let delta = u64::from(step);
                if delta > self.in_flight_frames() {
                    self.note_anomaly(report);
                    // More than half the range is a step back: the counter was reset or rewound.
                    // Either way nothing is credited and the old baseline is no longer used.
                    if step > COUNTER_FORWARD_LIMIT {
                        self.counter_regressed = true;
                        let _ = self.fail_muted_qualified(
                            FaultCode::CounterOverclaim,
                            Some(FaultCode::CounterRegress),
                        );
                    } else {
                        let _ = self.fail_muted(FaultCode::CounterOverclaim);
                    }
                } else {
                    self.consumed_frames += delta;
                    self.last_counter = counter;
                }
            }
            DeviceEvent::FlushAck => {
                if self.phase == SessionPhase::Draining {
                    if let Some(table) = self.slots.as_mut() {
                        table.free_in_flight_after_flush_ack();
                    }
                    self.discarded_frames = self
                        .discarded_frames
                        .saturating_add(self.in_flight_frames());
                    self.phase = SessionPhase::Prepared;
                    self.stop_requested = false;
                    self.primed_silence_blocks = 0;
                    self.generation = self.generation.saturating_add(1);
                    self.emit(SessionEventKind::StopAcknowledged);
                } else {
                    self.note_anomaly(report);
                }
            }
            DeviceEvent::DeviceLost => {
                self.device_lost = true;
                self.record_fault(FaultCode::DeviceLost);
                if let Some(table) = self.slots.as_mut() {
                    table.quarantine_all_in_flight();
                }
                self.amp = Amp::Unknown;
                self.primed_silence_blocks = 0;
                self.phase = SessionPhase::Faulted;
                self.stop_requested = true;
            }
        }
    }

    /// Drain pending device events (at most [`MAX_EVENTS_PER_POLL`]). Every record is decoded and
    /// checked before it changes anything.
    pub fn poll(&mut self) -> PollReport {
        let mut report = PollReport::default();
        for _ in 0..MAX_EVENTS_PER_POLL {
            // One fixed record on the stack, fresh for each event: the device writes into it and nothing is
            // allocated. A backend that reports a record it did not write hands back zeroes, which read as an
            // unknown kind and fault, and never as a repeat of the previous event.
            let mut record = [0u8; EVENT_LEN];
            let len = match self.backend.poll_event(&mut record) {
                Ok(Some(len)) => len,
                Ok(None) => break,
                Err(error) => {
                    if self.phase == SessionPhase::Faulted {
                        if error == DriverError::Gone {
                            self.note_loss_while_faulted();
                        }
                    } else {
                        let _ = self.driver_failed(Op::PollEvent, error);
                    }
                    break;
                }
            };
            report.events += 1;
            // A record of any other length is refused by the length the device reported; it is never cut to
            // fit and then decoded.
            let decoded = if len == EVENT_LEN {
                decode_event(&record)
            } else {
                Err(AbiError::Length {
                    expected: EVENT_LEN,
                    actual: len,
                })
            };
            match decoded {
                Ok(event) => self.apply_event(event, &mut report),
                Err(error) => {
                    if self.phase == SessionPhase::Faulted {
                        report.ignored_in_fault += 1;
                    } else {
                        self.note_anomaly(&mut report);
                        let _ = self.fail_muted(FaultCode::Malformed {
                            what: MalformedKind::Event,
                            abi: Some(error),
                        });
                    }
                }
            }
        }
        report
    }

    /// Let the device make one tick of progress, then handle what it reported.
    pub fn step(&mut self) -> PollReport {
        self.backend.wait_tick();
        self.poll()
    }

    /// Handle everything the device has already queued. Called before a new flush request, so an
    /// acknowledgment seen afterwards cannot be one that answered an earlier request (an
    /// acknowledgment carries no id).
    fn settle_events(&mut self) {
        for _ in 0..8 {
            if self.poll().events == 0 {
                break;
            }
        }
    }

    // ---- stopping

    /// Mute, ask the device to flush, and wait up to `max_wait_ticks` for it to acknowledge. Success
    /// is reported only when the acknowledgment was observed.
    pub fn drain(&mut self, max_wait_ticks: u64) -> Result<DrainOutcome, SessionError> {
        self.require_phase(&[SessionPhase::Running, SessionPhase::Prepared])?;
        match self.backend.set_mute(true) {
            Ok(true) => self.amp = Amp::Muted,
            Ok(false) => return Err(self.fail_muted(FaultCode::MuteNotAcknowledged)),
            Err(error) => return Err(self.driver_failed(Op::SetMute, error)),
        }
        self.settle_events();
        if self.phase == SessionPhase::Faulted {
            return Err(SessionError::FaultedDuringDrain);
        }
        if let Err(error) = self.backend.request_flush() {
            return Err(self.driver_failed(Op::RequestFlush, error));
        }
        self.phase = SessionPhase::Draining;
        self.stop_requested = true;
        let mut waited = 0u64;
        loop {
            self.poll();
            match self.phase {
                SessionPhase::Prepared => {
                    return Ok(DrainOutcome::Acknowledged {
                        waited_ticks: waited,
                    });
                }
                SessionPhase::Faulted => return Err(SessionError::FaultedDuringDrain),
                _ => {}
            }
            if waited >= max_wait_ticks {
                break;
            }
            self.backend.wait_tick();
            waited += 1;
        }
        let _ = self.fail_muted(FaultCode::DrainTimedOut);
        Ok(DrainOutcome::TimedOut {
            waited_ticks: waited,
        })
    }

    /// Give up on a drain. What is in flight is quarantined, never freed: the device has not said it
    /// stopped.
    pub fn cancel_drain(&mut self) -> Result<(), SessionError> {
        self.require_phase(&[SessionPhase::Draining])?;
        let _ = self.fail_muted(FaultCode::DrainCancelled);
        Ok(())
    }

    /// Abort into mute and report whether the device acknowledged it.
    pub fn abort_mute(&mut self) -> Result<AbortReport, SessionError> {
        self.require_phase(&[
            SessionPhase::Prepared,
            SessionPhase::Running,
            SessionPhase::Draining,
            SessionPhase::Faulted,
        ])?;
        self.stop_requested = true;
        match self.backend.set_mute(true) {
            Ok(true) => {
                self.amp = Amp::Muted;
                if self.phase != SessionPhase::Faulted {
                    self.settle_events();
                    if self.phase != SessionPhase::Faulted {
                        self.phase = SessionPhase::Draining;
                        if let Err(error) = self.backend.request_flush() {
                            return Err(self.driver_failed(Op::RequestFlush, error));
                        }
                    }
                }
                Ok(AbortReport {
                    mute_acknowledged: true,
                })
            }
            Ok(false) => {
                let _ = self.fail_muted(FaultCode::MuteNotAcknowledged);
                Ok(AbortReport {
                    mute_acknowledged: false,
                })
            }
            Err(error) => {
                let _ = self.driver_failed(Op::SetMute, error);
                Ok(AbortReport {
                    mute_acknowledged: false,
                })
            }
        }
    }

    /// Ask for a full device reset. Only an acknowledged reset frees what was in flight or
    /// quarantined. A device that is gone cannot be recovered this way.
    pub fn reset_device(&mut self) -> Result<(), SessionError> {
        self.require_phase(&[SessionPhase::Draining, SessionPhase::Faulted])?;
        if self.device_lost {
            return Err(SessionError::DevicePersistentlyLost);
        }
        match self.backend.reset() {
            Ok(true) => {
                if let Some(table) = self.slots.as_mut() {
                    table.release_all_after_reset_ack();
                }
                self.discarded_frames = self
                    .discarded_frames
                    .saturating_add(self.in_flight_frames());
                self.rebaseline = true;
                self.counter_regressed = false;
                self.stop_requested = false;
                self.saturated_reported = false;
                self.primed_silence_blocks = 0;
                self.silent_prepared_after_reset = self.backend.reset_ack_discards_playback();
                self.phase = SessionPhase::Prepared;
                self.generation = self.generation.saturating_add(1);
                self.emit(SessionEventKind::ResetAcknowledged);
                Ok(())
            }
            Ok(false) => Err(SessionError::ResetNotAcknowledged),
            Err(error) => Err(self.driver_failed(Op::Reset, error)),
        }
    }

    /// Release the device. Allowed only when every slot is accounted for and the amplifier is known
    /// muted; otherwise the session comes back intact with the reason.
    pub fn close(mut self) -> Result<SessionReceipt, Box<CloseRefused<B>>> {
        let (in_flight, quarantined) = self.slots.as_ref().map_or((0, 0), |t| {
            (
                t.count(SlotState::KernelOwned),
                t.count(SlotState::Quarantined),
            )
        });
        let phase_ok = matches!(self.phase, SessionPhase::Prepared | SessionPhase::Closed);
        if !phase_ok || in_flight > 0 || quarantined > 0 || self.amp != Amp::Muted {
            let reason = SessionError::CloseBlocked {
                phase: self.phase,
                in_flight,
                quarantined,
                amp_muted: self.amp == Amp::Muted,
            };
            return Err(Box::new(CloseRefused {
                session: self,
                reason,
            }));
        }
        self.phase = SessionPhase::Closed;
        self.slots = None;
        Ok(self.receipt())
    }
}

impl<B: DeviceBackend> Drop for HalSession<B> {
    /// Destroying the owner asks for a mute. The slot table's own drop then keeps alive any storage
    /// the kernel may still be reading.
    fn drop(&mut self) {
        if self.phase != SessionPhase::Closed || self.amp != Amp::Muted {
            let _ = self.backend.set_mute(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{FakeBackend, FakeCall, FakeConfig, FakeProbe};
    use franken_board_profile::synthetic_test_fixture_catalog;

    const READY: StartPreconditions = StartPreconditions {
        presentation_mapping_installed: true,
        safe_gain_installed: true,
    };
    /// One block: 4 frames of 2 channels of 2 bytes.
    const BLOCK: [u8; 16] = [0xAA; 16];

    fn profile() -> BoardProfile {
        synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
    }

    fn session_with(
        cfg: FakeConfig,
        ledger: Arc<LeakLedger>,
        cap: usize,
    ) -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(ledger, cap);
        (HalSession::open(profile(), backend, config).unwrap(), probe)
    }

    fn session(cfg: FakeConfig) -> (HalSession<FakeBackend>, FakeProbe, Arc<LeakLedger>) {
        let ledger = Arc::new(LeakLedger::new(64));
        let (s, p) = session_with(cfg, Arc::clone(&ledger), 2);
        (s, p, ledger)
    }

    fn running(cfg: FakeConfig) -> (HalSession<FakeBackend>, FakeProbe, Arc<LeakLedger>) {
        let (mut s, p, l) = session(cfg);
        s.prepare().unwrap();
        s.start(READY).unwrap();
        (s, p, l)
    }

    fn token(s: &mut HalSession<FakeBackend>) -> SubmitToken {
        s.submit(&BLOCK).unwrap().token.unwrap()
    }

    fn first_fault(s: &HalSession<FakeBackend>) -> FaultCode {
        s.receipt().faults[0].code.clone()
    }

    /// One block of silence: 4 frames of 2 channels of 2 bytes, all zero.
    const SILENCE: [u8; 16] = [0; 16];

    /// A prepared, muted session that wants `required` blocks of silence before its first unmute.
    fn priming_session(cfg: FakeConfig, required: u32) -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2)
            .with_required_silence_blocks(required);
        let mut s = HalSession::open(profile(), backend, config).unwrap();
        s.prepare().unwrap();
        (s, probe)
    }

    /// How many times the device was told to unmute.
    fn unmute_calls(probe: &FakeProbe) -> usize {
        probe
            .calls()
            .iter()
            .filter(|call| **call == FakeCall::SetMute(false))
            .count()
    }

    /// How many times the device was told to start.
    fn start_calls(probe: &FakeProbe) -> usize {
        probe
            .calls()
            .iter()
            .filter(|call| **call == FakeCall::Start)
            .count()
    }

    fn refused(primed: u32, required: u32) -> Result<(), SessionError> {
        Err(SessionError::UnmuteBeforeSilencePrime { primed, required })
    }

    #[test]
    fn silence_priming_is_off_by_default_so_start_is_unchanged() {
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        assert_eq!(config.required_silence_blocks, 0);
        let (mut s, probe, _) = session(FakeConfig::retained());
        s.prepare().unwrap();
        assert_eq!(s.required_silence_blocks(), 0);
        assert_eq!(s.start(READY), Ok(()));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Running, Amp::Unmuted));
        assert_eq!(s.primed_silence_blocks(), 0);
        // Exactly the calls a session made before the gate existed: nothing was submitted first.
        assert_eq!(
            probe.calls(),
            vec![
                FakeCall::Capabilities,
                FakeCall::SetMute(true),
                FakeCall::Start,
                FakeCall::SetMute(false)
            ]
        );
    }

    #[test]
    fn start_refuses_an_unprimed_unmute_by_name_and_the_backend_never_sees_an_unmute() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 2);
        assert_eq!(s.required_silence_blocks(), 2);
        assert_eq!(s.start(READY), refused(0, 2));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Prepared, Amp::Muted));
        // A refusal is a caller error, not a device fault, and it touched nothing.
        assert!(s.receipt().faults.is_empty());
        assert_eq!(
            probe.calls(),
            vec![FakeCall::Capabilities, FakeCall::SetMute(true)]
        );
    }

    #[test]
    fn only_a_whole_all_zero_block_counts_as_priming() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 2);
        // Not silence: a tone.
        s.submit(&BLOCK).unwrap();
        assert_eq!(s.primed_silence_blocks(), 0);
        // Silence, but half a block.
        s.submit(&SILENCE[..8]).unwrap();
        assert_eq!(s.primed_silence_blocks(), 0);
        // Silence except for the low byte of the last sample.
        let mut almost = SILENCE;
        almost[15] = 1;
        s.submit(&almost).unwrap();
        assert_eq!(s.primed_silence_blocks(), 0);
        assert_eq!(s.start(READY), refused(0, 2));
        assert_eq!((start_calls(&probe), unmute_calls(&probe)), (0, 0));
    }

    #[test]
    fn a_block_the_device_took_only_part_of_or_none_of_does_not_count_as_priming() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 2);
        probe.set_accept_limit(Some(8));
        let receipt = s.submit(&SILENCE).unwrap();
        assert_eq!((receipt.accepted_bytes, receipt.remainder_bytes), (8, 8));
        assert_eq!(s.primed_silence_blocks(), 0);
        probe.set_accept_limit(Some(0));
        let receipt = s.submit(&SILENCE).unwrap();
        assert_eq!((receipt.accepted_bytes, receipt.remainder_bytes), (0, 16));
        assert_eq!(s.primed_silence_blocks(), 0);
        assert_eq!(s.start(READY), refused(0, 2));
        assert_eq!((start_calls(&probe), unmute_calls(&probe)), (0, 0));
    }

    #[test]
    fn enough_whole_silent_blocks_open_the_gate_and_the_amp_unmutes_once() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 2);
        probe.capture_submissions(4);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        assert_eq!(s.start(READY), refused(1, 2));
        assert_eq!((start_calls(&probe), unmute_calls(&probe)), (0, 0));
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 2);
        assert_eq!(s.start(READY), Ok(()));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Running, Amp::Unmuted));
        assert_eq!((start_calls(&probe), unmute_calls(&probe)), (1, 1));
        // The priming is spent by the unmute.
        assert_eq!(s.primed_silence_blocks(), 0);
        // The unmute came after the last priming block was handed over...
        let calls = probe.calls();
        let unmute_at = calls
            .iter()
            .position(|call| *call == FakeCall::SetMute(false))
            .unwrap();
        let last_submit_at = calls
            .iter()
            .rposition(|call| matches!(call, FakeCall::SubmitRetained { .. }))
            .unwrap();
        assert!(last_submit_at < unmute_at);
        // ...and what the device was handed was silence, two whole blocks of it.
        let seen = probe.captured_submissions();
        assert_eq!(seen.len(), 2);
        assert!(
            seen.iter()
                .all(|block| block.len() == 16 && block.iter().all(|&byte| byte == 0))
        );
    }

    #[test]
    fn silence_submitted_while_unmuted_is_not_priming() {
        let (mut s, _probe) = priming_session(FakeConfig::retained(), 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.start(READY), Ok(()));
        assert_eq!(s.primed_silence_blocks(), 0);
        s.submit(&SILENCE).unwrap();
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Running, Amp::Unmuted));
        assert_eq!(s.primed_silence_blocks(), 0);
    }

    #[test]
    fn a_flush_acknowledgment_discards_the_priming() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        assert!(matches!(s.drain(10), Ok(DrainOutcome::Acknowledged { .. })));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Prepared, Amp::Muted));
        assert_eq!(s.primed_silence_blocks(), 0);
        assert_eq!(s.start(READY), refused(0, 1));
        assert_eq!(unmute_calls(&probe), 0);
    }

    #[test]
    fn a_fault_discards_the_priming_and_a_reset_does_not_bring_it_back() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        // A completion for a slot nothing was handed to: the session faults muted.
        probe.queue_event(DeviceEvent::Completed {
            slot: 3,
            generation: 1,
        });
        s.poll();
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(s.primed_silence_blocks(), 0);
        s.reset_device().unwrap();
        assert_eq!(s.phase(), SessionPhase::Prepared);
        assert_eq!(s.primed_silence_blocks(), 0);
        assert_eq!(s.start(READY), refused(0, 1));
        assert_eq!(unmute_calls(&probe), 0);
    }

    #[test]
    fn reset_ack_without_playback_discard_evidence_is_not_silent_admission() {
        for cfg in [FakeConfig::retained(), FakeConfig::copying()] {
            let (mut s, _probe, _ledger) = session(cfg);
            s.prepare().unwrap();
            assert!(!s.silent_prepared_after_reset());
            s.submit(&BLOCK).unwrap();
            assert!(s.abort_mute().unwrap().mute_acknowledged);
            s.reset_device().unwrap();
            assert!(!s.silent_prepared_after_reset());
            s.submit(&SILENCE).unwrap();
            assert!(!s.silent_prepared_after_reset());
        }
    }

    #[test]
    fn refused_reset_is_not_silent_admission() {
        let mut cfg = FakeConfig::retained();
        cfg.reset_ack = false;
        let (mut s, _probe, _ledger) = session(cfg);
        s.prepare().unwrap();
        s.submit(&BLOCK).unwrap();
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        assert!(matches!(
            s.reset_device(),
            Err(SessionError::ResetNotAcknowledged)
        ));
        assert!(!s.silent_prepared_after_reset());
    }

    #[test]
    fn a_reset_acknowledgment_discards_the_priming() {
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None; // the flush is never acknowledged, so only a reset ends it
        let (mut s, probe) = priming_session(cfg, 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        assert_eq!(s.phase(), SessionPhase::Draining);
        s.reset_device().unwrap();
        assert_eq!(s.phase(), SessionPhase::Prepared);
        assert_eq!(s.primed_silence_blocks(), 0);
        assert_eq!(s.start(READY), refused(0, 1));
        assert_eq!(unmute_calls(&probe), 0);
    }

    #[test]
    fn a_lost_device_discards_the_priming() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        probe.lose_device();
        s.poll();
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(s.primed_silence_blocks(), 0);
    }

    #[test]
    fn a_copying_abi_counts_priming_the_same_way() {
        let (mut s, probe) = priming_session(FakeConfig::copying(), 2);
        s.submit(&BLOCK).unwrap();
        assert_eq!(s.primed_silence_blocks(), 0);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 1);
        s.submit(&SILENCE).unwrap();
        assert_eq!(s.primed_silence_blocks(), 2);
        assert_eq!(s.start(READY), Ok(()));
        assert_eq!((start_calls(&probe), unmute_calls(&probe)), (1, 1));
    }

    #[test]
    fn prime_silence_submits_one_whole_silent_block_and_only_while_prepared() {
        let (mut s, probe) = priming_session(FakeConfig::retained(), 2);
        probe.capture_submissions(4);
        let receipt = s.prime_silence().unwrap();
        assert_eq!((receipt.accepted_bytes, receipt.remainder_bytes), (16, 0));
        assert_eq!(s.primed_silence_blocks(), 1);
        s.prime_silence().unwrap();
        assert_eq!(s.start(READY), Ok(()));
        assert_eq!(
            s.prime_silence().err(),
            Some(SessionError::WrongPhase {
                phase: SessionPhase::Running
            })
        );
        let seen = probe.captured_submissions();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|block| block.iter().all(|&byte| byte == 0)));
    }

    #[test]
    fn a_clean_prepare_run_drain_close_cycle() {
        let (mut s, probe, ledger) = session(FakeConfig::retained());
        assert_eq!(s.phase(), SessionPhase::Closed);
        s.prepare().unwrap();
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Prepared, Amp::Muted));
        // The capability query comes first and changes nothing; the mute follows it.
        assert_eq!(
            probe.calls(),
            vec![FakeCall::Capabilities, FakeCall::SetMute(true)]
        );
        s.start(READY).unwrap();
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Running, Amp::Unmuted));
        let receipt = s.submit(&BLOCK).unwrap();
        assert_eq!(
            (
                receipt.accepted_bytes,
                receipt.accepted_frames,
                receipt.remainder_bytes
            ),
            (16, 4, 0)
        );
        let t = receipt.token.unwrap();
        assert_eq!(s.token_state(&t), Ok(TokenState::InFlight));
        assert_eq!(
            s.slot_states(),
            vec![
                SlotState::KernelOwned,
                SlotState::Free,
                SlotState::Free,
                SlotState::Free
            ]
        );
        assert_eq!(s.irrevocable_until_frames(), 4);
        // The flush is requested at tick 0 and acknowledged at tick 1.
        assert_eq!(
            s.drain(10),
            Ok(DrainOutcome::Acknowledged { waited_ticks: 1 })
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Prepared, Amp::Muted));
        assert_eq!(s.slot_states(), vec![SlotState::Free; 4]);
        assert_eq!(s.token_state(&t), Ok(TokenState::Settled));
        let closed = s.close().unwrap();
        assert_eq!(closed.phase, SessionPhase::Closed);
        assert_eq!((closed.accepted_frames, closed.discarded_frames), (4, 4));
        assert!(closed.faults.is_empty());
        assert_eq!(
            probe.calls(),
            vec![
                FakeCall::Capabilities,
                FakeCall::SetMute(true),
                FakeCall::Start,
                FakeCall::SetMute(false),
                FakeCall::SubmitRetained {
                    slot: 0,
                    generation: 1,
                    len: 16
                },
                FakeCall::SetMute(true),
                FakeCall::RequestFlush,
            ]
        );
        assert_eq!(
            (probe.use_after_free(), probe.modified_while_owned()),
            (0, 0)
        );
        assert_eq!(ledger.leaked_slots(), 0, "a clean cycle leaks nothing");
    }

    #[test]
    fn a_copying_write_abi_needs_no_slots_and_reports_a_short_write() {
        let (mut s, probe, _) = running(FakeConfig::copying());
        assert!(s.slot_states().is_empty());
        probe.set_accept_limit(Some(8));
        let r = s.submit(&BLOCK).unwrap();
        assert_eq!(
            (r.accepted_bytes, r.accepted_frames, r.remainder_bytes),
            (8, 2, 8)
        );
        assert!(r.token.is_none(), "a copying write leaves nothing to track");
        assert_eq!(s.irrevocable_until_frames(), 2);
        assert_eq!(probe.written_bytes(), 8);
        // A count that is not a whole number of frames is a malformed response: fail muted.
        probe.set_accept_limit(Some(6));
        let err = s.submit(&BLOCK).err().unwrap();
        assert_eq!(
            err,
            SessionError::Faulted(FaultCode::Malformed {
                what: MalformedKind::WriteCount,
                abi: None
            })
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(probe.calls().last(), Some(&FakeCall::SetMute(true)));
    }

    #[test]
    fn a_copying_abi_without_stated_evidence_is_refused() {
        let mut cfg = FakeConfig::copying();
        cfg.abi = AbiKind::CopyingWrite {
            evidence: "   ".to_string(),
        };
        let (backend, _probe) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        let err = HalSession::open(profile(), backend, config).err().unwrap();
        assert_eq!(err, SessionError::CopyEvidenceMissing);
        // Permitted positive: the same device with evidence opens.
        let (backend, _probe) = FakeBackend::new(FakeConfig::copying());
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        assert!(HalSession::open(profile(), backend, config).is_ok());
        let (s, _, _) = session(FakeConfig::copying());
        assert!(s.receipt().copy_evidence.is_some());
    }

    #[test]
    fn malformed_geometry_fails_muted() {
        let wrong_length = |bytes: Vec<u8>| {
            let mut cfg = FakeConfig::retained();
            cfg.geometry_override = Some(bytes);
            cfg
        };
        let (mut s, probe, _) = session(wrong_length(vec![0; 15]));
        assert_eq!(
            s.prepare().err().unwrap(),
            SessionError::Faulted(FaultCode::Malformed {
                what: MalformedKind::Geometry,
                abi: Some(AbiError::Length {
                    expected: 16,
                    actual: 15
                })
            })
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(probe.calls().last(), Some(&FakeCall::SetMute(true)));
        // Well-formed bytes that describe an impossible device are malformed too.
        let impossible = [
            (0, 4, 2, 2),
            (65, 4, 2, 2),
            (4, 0, 2, 2),
            (4, 4, 0, 2),
            (4, 4, 9, 2),
            (4, 4, 2, 0),
            (4, 4, 2, 5),
            (4, 1 << 30, 2, 2),
        ];
        for (depth, frames, channels, bytes) in impossible {
            let raw = RawGeometry {
                ring_depth: depth,
                frames_per_block: frames,
                channels,
                bytes_per_sample: bytes,
            };
            let (mut s, _, _) = session(wrong_length(crate::abi::encode_geometry(&raw).to_vec()));
            let err = s.prepare().err().unwrap();
            assert_eq!(
                err,
                SessionError::Faulted(FaultCode::Malformed {
                    what: MalformedKind::Geometry,
                    abi: None
                }),
                "{raw:?}"
            );
            assert_eq!(s.phase(), SessionPhase::Faulted, "{raw:?}");
        }
        // Permitted positive: the standard geometry is accepted and reported.
        let (mut s, _, _) = session(FakeConfig::retained());
        s.prepare().unwrap();
        let g = s.geometry().unwrap();
        assert_eq!((g.frame_bytes, g.block_bytes), (4, 16));
    }

    #[test]
    fn an_ioctl_error_fails_muted_and_a_failed_submit_quarantines_its_slot() {
        let (mut s, probe, _) = session(FakeConfig::retained());
        s.prepare().unwrap();
        probe.fail_next(Op::Start, DriverError::Errno(5));
        let err = s.start(READY).err().unwrap();
        assert_eq!(
            err,
            SessionError::Faulted(FaultCode::DriverError {
                op: Op::Start,
                error: DriverError::Errno(5)
            })
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        // A submit that fails: we cannot tell whether the kernel kept the buffer, so the slot is
        // quarantined, not freed.
        let (mut s, probe, _) = running(FakeConfig::retained());
        probe.fail_next(Op::SubmitRetained, DriverError::Errno(22));
        assert!(s.submit(&BLOCK).is_err());
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(s.receipt().slots_quarantined, 1);
    }

    #[test]
    fn forgotten_and_dropped_tokens_cannot_return_storage() {
        // A token has no `Drop`, so forgetting one is the same as dropping it (clippy says so). The
        // two cases worth separating are a token that is dropped and one that is never given back to
        // anything, which is kept alive here until the end of the iteration.
        for hold in [true, false] {
            let (mut s, probe, _) = running(FakeConfig::retained());
            let t = token(&mut s);
            let held = if hold {
                Some(t)
            } else {
                drop(t);
                None
            };
            assert_eq!(s.slot_states()[0], SlotState::KernelOwned);
            // Tick 1: nothing is due yet, and the slot is still the kernel's.
            assert_eq!(s.step().completions, 0);
            assert_eq!(s.slot_states()[0], SlotState::KernelOwned);
            // Tick 2: the device completes it, and the owner frees it, token or no token.
            assert_eq!(s.step().completions, 1);
            assert_eq!(s.slot_states()[0], SlotState::Free);
            assert_eq!(probe.use_after_free(), 0);
            assert!(s.receipt().faults.is_empty());
            // The held token was still held throughout, and the dropped one was not.
            assert_eq!(held.is_some(), hold);
        }
    }

    #[test]
    fn a_stale_completion_never_frees_the_new_occupant_and_slot_reuse_is_refused() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let first = token(&mut s);
        s.step();
        s.step();
        assert_eq!(s.token_state(&first), Ok(TokenState::Settled));
        let _second = token(&mut s); // the lowest free slot again, one generation later
        assert_eq!(s.slot_states()[0], SlotState::KernelOwned);
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 1,
        });
        let report = s.poll();
        assert_eq!(report.anomalies, 1);
        assert_eq!(
            first_fault(&s),
            FaultCode::BadCompletion {
                problem: CompletionProblem::StaleGeneration {
                    expected: 2,
                    got: 1
                }
            }
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        // The new occupant is quarantined, not freed, and it cannot be handed out again.
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(
            s.submit(&BLOCK).err().unwrap(),
            SessionError::WrongPhase {
                phase: SessionPhase::Faulted
            }
        );
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(probe.use_after_free(), 0);
    }

    #[test]
    fn duplicate_and_unknown_completions_fault_muted() {
        // A duplicate: the slot was already completed.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        s.step();
        s.step();
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 1,
        });
        s.poll();
        assert_eq!(
            first_fault(&s),
            FaultCode::BadCompletion {
                problem: CompletionProblem::NotKernelOwned(SlotState::Free)
            }
        );
        // A slot that does not exist.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        probe.queue_event(DeviceEvent::Completed {
            slot: 9,
            generation: 1,
        });
        s.poll();
        assert_eq!(
            first_fault(&s),
            FaultCode::BadCompletion {
                problem: CompletionProblem::OutOfRange
            }
        );
        // The in-flight slot it did not name was quarantined, not freed.
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        // A completion on an ABI that has none.
        let (mut s, probe, _) = running(FakeConfig::copying());
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 1,
        });
        s.poll();
        assert_eq!(first_fault(&s), FaultCode::UnexpectedCompletion);
    }

    #[test]
    fn a_malformed_event_record_fails_muted() {
        for bytes in [
            vec![1u8, 2, 3],
            vec![0; 12],
            vec![0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0],
        ] {
            let (mut s, probe, _) = running(FakeConfig::retained());
            let _t = token(&mut s);
            probe.queue_raw_event(bytes.clone());
            let report = s.poll();
            assert_eq!(report.anomalies, 1, "{bytes:?}");
            assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
            assert_eq!(s.slot_states()[0], SlotState::Quarantined, "{bytes:?}");
            assert!(matches!(
                first_fault(&s),
                FaultCode::Malformed {
                    what: MalformedKind::Event,
                    abi: Some(_)
                }
            ));
        }
    }

    #[test]
    fn destroying_the_owner_keeps_storage_the_kernel_may_still_read() {
        let (mut s, probe, ledger) = running(FakeConfig::retained());
        let a = token(&mut s);
        // One token is dropped and one is never given back; the token is inert either way, so this
        // one is simply kept alive past the owner's destruction.
        let _b = token(&mut s);
        drop(a);
        assert_eq!(probe.pending(), 2);
        drop(s);
        // The owner and its table are gone, and the kernel can still read both buffers.
        assert_eq!(probe.kernel_touch_pending(), (2, 0));
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(ledger.leaked_slots(), 2);
        assert_eq!(ledger.leaked_bytes(), 32);
        // Destroying the owner asked for a mute on the way out.
        assert_eq!(probe.calls().last(), Some(&FakeCall::SetMute(true)));
    }

    #[test]
    fn the_leak_budget_bounds_how_many_devices_are_admitted_after_leaks() {
        let ledger = Arc::new(LeakLedger::new(2));
        let (mut s, _probe) = session_with(FakeConfig::retained(), Arc::clone(&ledger), 2);
        s.prepare().unwrap();
        s.start(READY).unwrap();
        let _a = token(&mut s);
        let _b = token(&mut s);
        drop(s);
        assert!(ledger.exhausted());
        // The next device cannot build a slot table until the budget is dealt with.
        let (mut next, _probe) = session_with(FakeConfig::retained(), Arc::clone(&ledger), 2);
        assert_eq!(
            next.prepare().err().unwrap(),
            SessionError::Slots(SlotError::LeakBudgetExhausted)
        );
        assert_eq!(next.phase(), SessionPhase::Closed);
    }

    #[test]
    fn a_session_names_itself_and_counts_the_flushes_the_device_acknowledged() {
        let (mut s, _probe, _) = running(FakeConfig::retained());
        let (other, _other_probe, _) = session(FakeConfig::retained());
        assert_ne!(
            s.session_id(),
            other.session_id(),
            "two sessions never share an id"
        );
        assert_eq!(s.generation(), 0);
        let _t = token(&mut s);
        assert_eq!(s.irrevocable_until_frames(), 4);
        assert_eq!(
            s.drain(10),
            Ok(DrainOutcome::Acknowledged { waited_ticks: 1 })
        );
        // The acknowledgment starts a new generation; the frame counters carry on across it.
        assert_eq!(s.generation(), 1);
        assert_eq!(s.irrevocable_until_frames(), 4);
        assert_eq!(s.receipt().discarded_frames, 4);
    }

    #[test]
    fn a_drain_that_times_out_does_not_advance_the_generation_but_an_acknowledged_reset_does() {
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (mut s, probe, _) = running(cfg);
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        assert_eq!(s.drain(3), Ok(DrainOutcome::TimedOut { waited_ticks: 3 }));
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(s.generation(), 0, "no acknowledgment, no new generation");
        // The permitted counterpart: the device acknowledges the reset.
        s.reset_device().unwrap();
        assert_eq!(s.generation(), 1);
    }

    #[test]
    fn a_reset_the_device_does_not_acknowledge_leaves_the_generation_alone() {
        let mut cfg = FakeConfig::retained();
        cfg.reset_ack = false;
        cfg.flush_ack_delay_ticks = None;
        let (mut s, probe, _) = running(cfg);
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        assert_eq!(s.drain(1), Ok(DrainOutcome::TimedOut { waited_ticks: 1 }));
        assert_eq!(
            s.reset_device().err().unwrap(),
            SessionError::ResetNotAcknowledged
        );
        assert_eq!(s.generation(), 0);
    }

    #[test]
    fn a_drain_that_is_not_acknowledged_quarantines_and_never_claims_success() {
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (mut s, probe, ledger) = running(cfg);
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        assert_eq!(s.drain(3), Ok(DrainOutcome::TimedOut { waited_ticks: 3 }));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(probe.pending(), 1, "the kernel still holds it");
        assert_eq!(first_fault(&s), FaultCode::DrainTimedOut);
        // Closing is refused, and the session comes back intact.
        let refused = s.close().err().unwrap();
        let CloseRefused { session, reason } = *refused;
        assert_eq!(
            reason,
            SessionError::CloseBlocked {
                phase: SessionPhase::Faulted,
                in_flight: 0,
                quarantined: 1,
                amp_muted: true
            }
        );
        // Only an acknowledged reset frees it. Then the cycle completes cleanly.
        let mut s = session;
        s.reset_device().unwrap();
        assert_eq!(
            (s.phase(), s.slot_states()[0]),
            (SessionPhase::Prepared, SlotState::Free)
        );
        assert_eq!(probe.pending(), 0);
        assert!(s.close().is_ok());
        assert_eq!(ledger.leaked_slots(), 0);
    }

    /// Why this test exists, as a deduction (the pre-fix code was never run; there is no local cargo):
    /// * Old path: `drain` requested the flush and set `Draining` with no settle step, so its first
    ///   `poll` consumed the acknowledgment queued earlier, freed the in-flight slot, and returned.
    /// * Reasoned result on the old path: `Acknowledged { waited_ticks: 0 }` with the slot freed, while
    ///   the kernel (the fake) still held the buffer.
    /// * Expected result now: `TimedOut { waited_ticks: 2 }`, the slot quarantined, the early
    ///   acknowledgment counted as one anomaly and not believed.
    #[test]
    fn an_acknowledgment_queued_before_a_drain_cannot_answer_it() {
        // A flush acknowledgment carries no id. One queued while running is not the answer to a
        // drain that starts afterwards; if it were believed, the drain would report success while
        // the kernel still held the buffer.
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None; // the device never really acknowledges
        let (mut s, probe, _) = running(cfg);
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        probe.queue_event(DeviceEvent::FlushAck);
        assert_eq!(s.drain(2), Ok(DrainOutcome::TimedOut { waited_ticks: 2 }));
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(probe.pending(), 1, "the kernel still holds it");
        let receipt = s.receipt();
        assert_eq!(
            receipt.anomalies, 1,
            "the early acknowledgment was counted, not believed"
        );
        assert_eq!(receipt.faults[0].code, FaultCode::DrainTimedOut);
        // A stop was asked for and never acknowledged, and the receipt says so. (The paired positive,
        // a real acknowledgment being accepted, is the clean cycle in the first test of this module.)
        assert!(receipt.stop_requested);
    }

    #[test]
    fn a_cancelled_drain_quarantines_instead_of_freeing() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        let report = s.abort_mute().unwrap();
        assert!(report.mute_acknowledged);
        assert_eq!(s.phase(), SessionPhase::Draining);
        s.cancel_drain().unwrap();
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(first_fault(&s), FaultCode::DrainCancelled);
        // The earlier flush request may still be acknowledged. That acknowledgment arrives after the
        // cancel, so it is ignored and the slot stays quarantined until a reset is acknowledged.
        s.step();
        s.step();
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(
            s.cancel_drain().err().unwrap(),
            SessionError::WrongPhase {
                phase: SessionPhase::Faulted
            }
        );
    }

    #[test]
    fn quarantine_saturation_is_recorded_and_bounded() {
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let ledger = Arc::new(LeakLedger::new(64));
        let (mut s, probe) = session_with(cfg, Arc::clone(&ledger), 1);
        s.prepare().unwrap();
        s.start(READY).unwrap();
        probe.set_lose_completions(true);
        let _a = token(&mut s);
        let _b = token(&mut s);
        assert_eq!(s.drain(1), Ok(DrainOutcome::TimedOut { waited_ticks: 1 }));
        let codes: Vec<FaultCode> = s.receipt().faults.into_iter().map(|f| f.code).collect();
        assert_eq!(
            codes,
            vec![FaultCode::DrainTimedOut, FaultCode::QuarantineSaturated]
        );
        assert_eq!(s.receipt().slots_quarantined, 2);
        // Dropping the faulted owner leaks exactly what is quarantined, no more.
        drop(s);
        assert_eq!(ledger.leaked_slots(), 2);
        assert_eq!(probe.kernel_touch_pending(), (2, 0));
    }

    #[test]
    fn an_unacknowledged_mute_blocks_everything_until_it_is_acknowledged() {
        let mut cfg = FakeConfig::retained();
        cfg.mute_ack = false;
        let (mut s, _probe, _) = session(cfg);
        assert_eq!(
            s.prepare().err().unwrap(),
            SessionError::Faulted(FaultCode::MuteNotAcknowledged)
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Unknown));
        assert_eq!(
            s.receipt().faults.len(),
            1,
            "one fault, not one per attempt"
        );
        assert_eq!(
            s.start(READY).err().unwrap(),
            SessionError::WrongPhase {
                phase: SessionPhase::Faulted
            }
        );
        // A reset is acknowledged, but it does not make the amplifier known muted.
        s.reset_device().unwrap();
        assert_eq!(s.phase(), SessionPhase::Prepared);
        assert_eq!(
            s.start(READY).err().unwrap(),
            SessionError::MuteNotAcknowledged
        );
        assert_eq!(
            s.abort_mute(),
            Ok(AbortReport {
                mute_acknowledged: false
            })
        );
        assert_eq!(s.amp(), Amp::Unknown);
    }

    #[test]
    fn an_unacknowledged_unmute_falls_back_to_muted() {
        let mut cfg = FakeConfig::retained();
        cfg.unmute_ack = false;
        let (mut s, probe, _) = session(cfg);
        s.prepare().unwrap();
        assert_eq!(
            s.start(READY).err().unwrap(),
            SessionError::Faulted(FaultCode::UnmuteNotAcknowledged)
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(
            probe.calls(),
            vec![
                FakeCall::Capabilities,
                FakeCall::SetMute(true),
                FakeCall::Start,
                FakeCall::SetMute(false),
                FakeCall::SetMute(true),
            ]
        );
    }

    #[test]
    fn an_unknown_stop_deadline_refuses_the_audible_transition() {
        let mut cfg = FakeConfig::retained();
        cfg.stop_deadline_ticks = None;
        let (mut s, probe, _) = session(cfg);
        s.prepare().unwrap();
        let r = s.receipt();
        assert!(!r.stop_deadline_known && !r.audible_transition_admitted);
        assert_eq!(
            r.admission_blocker.as_deref(),
            Some("stop deadline unknown")
        );
        assert_eq!(
            s.start(READY).err().unwrap(),
            SessionError::StopDeadlineUnknown
        );
        // Nothing was started or unmuted on the device, and the session did not fault.
        assert_eq!(
            probe.calls(),
            vec![FakeCall::Capabilities, FakeCall::SetMute(true)]
        );
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Prepared, Amp::Muted));
        // Permitted positive: a known deadline is admitted.
        let (mut s, _, _) = session(FakeConfig::retained());
        s.prepare().unwrap();
        assert!(s.receipt().audible_transition_admitted);
    }

    #[test]
    fn start_preconditions_are_checked_before_the_device_is_touched() {
        let (mut s, probe, _) = session(FakeConfig::retained());
        s.prepare().unwrap();
        let before = probe.calls();
        let no_map = StartPreconditions {
            presentation_mapping_installed: false,
            safe_gain_installed: true,
        };
        let no_gain = StartPreconditions {
            presentation_mapping_installed: true,
            safe_gain_installed: false,
        };
        assert_eq!(
            s.start(no_map).err().unwrap(),
            SessionError::PresentationMappingMissing
        );
        assert_eq!(
            s.start(no_gain).err().unwrap(),
            SessionError::SafeGainMissing
        );
        assert_eq!(probe.calls(), before);
        assert!(s.start(READY).is_ok());
    }

    #[test]
    fn the_consumed_counter_wraps_but_never_claims_more_than_is_in_flight() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s); // 8 frames in flight
        let report = |s: &mut HalSession<FakeBackend>, counter| {
            probe.queue_event(DeviceEvent::Position { counter });
            s.poll()
        };
        report(&mut s, 0xFFFF_FFFC); // the first report only sets the baseline
        assert_eq!(s.position().consumed_frames, 0);
        report(&mut s, 2); // wraps: 2 - 0xFFFFFFFC = 6
        assert_eq!(s.position().consumed_frames, 6);
        assert_eq!(s.phase(), SessionPhase::Running);
        // 7 more would leave 13 consumed of 8 submitted.
        let r = report(&mut s, 9);
        assert_eq!(r.anomalies, 1);
        assert_eq!(first_fault(&s), FaultCode::CounterOverclaim);
        assert_eq!(
            s.position().consumed_frames,
            6,
            "an overclaim credits nothing"
        );
        // An enormous jump is not an enormous index: it is just an overclaim.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        probe.queue_event(DeviceEvent::Position { counter: 0 });
        probe.queue_event(DeviceEvent::Position {
            counter: 0x8000_0000,
        });
        s.poll();
        assert_eq!(first_fault(&s), FaultCode::CounterOverclaim);
        assert_eq!(s.position().consumed_frames, 0);
    }

    #[test]
    fn a_consumed_counter_that_goes_backwards_by_one_faults_muted_and_credits_nothing() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s); // 8 frames in flight
        let report = |s: &mut HalSession<FakeBackend>, counter| {
            probe.queue_event(DeviceEvent::Position { counter });
            s.poll()
        };
        report(&mut s, 100); // the first report only sets the baseline
        let r = report(&mut s, 104);
        assert_eq!(r.anomalies, 0);
        assert_eq!(s.position().consumed_frames, 4);
        assert_eq!(s.phase(), SessionPhase::Running);
        // 103 is one behind 104. The wrapping delta reads that as 0xFFFF_FFFF frames, far more than
        // the 4 still in flight, so it is an overclaim and not a quiet step back.
        let r = report(&mut s, 103);
        assert_eq!(r.anomalies, 1);
        assert_eq!(first_fault(&s), FaultCode::CounterOverclaim);
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(s.position().consumed_frames, 4, "a regress credits nothing");
    }

    fn fault_codes(s: &HalSession<FakeBackend>) -> Vec<FaultCode> {
        s.receipt().faults.into_iter().map(|f| f.code).collect()
    }

    fn slots_in(s: &HalSession<FakeBackend>, want: SlotState) -> usize {
        s.slot_states().into_iter().filter(|st| *st == want).count()
    }

    #[test]
    fn a_backwards_counter_records_the_regress_code_after_the_overclaim_and_changes_nothing_else() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s); // 8 frames in flight
        let report = |s: &mut HalSession<FakeBackend>, counter| {
            probe.queue_event(DeviceEvent::Position { counter });
            s.poll()
        };
        report(&mut s, 100); // the first report only sets the baseline
        report(&mut s, 104);
        assert!(!s.counter_regressed(), "a clean step is not a regress");
        assert!(fault_codes(&s).is_empty());
        let r = report(&mut s, 103); // one behind
        assert_eq!(r.anomalies, 1);
        // The overclaim stays first, so a reader that only knows it still sees the fault; the regress
        // code follows it and nothing else is recorded: the mute was acknowledged, two slots fit the cap.
        assert_eq!(
            fault_codes(&s),
            vec![FaultCode::CounterOverclaim, FaultCode::CounterRegress]
        );
        assert!(s.counter_regressed());
        // The safety response is exactly what a forward overclaim gets.
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(s.position().consumed_frames, 4, "a regress credits nothing");
        assert_eq!(slots_in(&s, SlotState::Quarantined), 2);
        assert_eq!(slots_in(&s, SlotState::Free), 2);
        // Later reports are drained and change nothing.
        let r = report(&mut s, 50);
        assert_eq!((r.anomalies, r.ignored_in_fault), (0, 1));
        assert_eq!(fault_codes(&s).len(), 2);
    }

    #[test]
    fn a_forward_overclaim_never_records_the_regress_code() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s); // 8 frames in flight
        let report = |s: &mut HalSession<FakeBackend>, counter| {
            probe.queue_event(DeviceEvent::Position { counter });
            s.poll()
        };
        report(&mut s, 100);
        report(&mut s, 104); // 4 consumed, 4 still in flight
        let r = report(&mut s, 113); // 9 ahead: more than the 4 in flight
        assert_eq!(r.anomalies, 1);
        assert_eq!(fault_codes(&s), vec![FaultCode::CounterOverclaim]);
        assert!(!s.counter_regressed());
        // The same safety response as a regress.
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(
            s.position().consumed_frames,
            4,
            "an overclaim credits nothing"
        );
        assert_eq!(slots_in(&s, SlotState::Quarantined), 2);
    }

    #[test]
    fn the_regress_boundary_is_half_the_counter_range_and_a_regress_across_the_wrap_is_still_one() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Want {
            Clean,
            Overclaim,
            Regress,
        }
        // One block of 4 frames is in flight in every case. After the baseline report, `first` and then
        // `second` (if any) are reported.
        let cases = [
            (
                "exactly half ahead is the forward claim",
                0_u32,
                0x8000_0000_u32,
                None,
                Want::Overclaim,
            ),
            (
                "one past half is a step back",
                0,
                0x8000_0001,
                None,
                Want::Regress,
            ),
            (
                "zero back to the top of the range",
                0,
                u32::MAX,
                None,
                Want::Regress,
            ),
            (
                "a legitimate wrap forward is no fault",
                0xFFFF_FFFE,
                2,
                None,
                Want::Clean,
            ),
            (
                "a step back across the wrap after a legitimate wrap",
                0xFFFF_FFFE,
                2,
                Some(u32::MAX),
                Want::Regress,
            ),
            ("a stalled counter is no fault", 7, 7, Some(7), Want::Clean),
        ];
        for (name, baseline, first, second, want) in cases {
            let (mut s, probe, _) = running(FakeConfig::retained());
            let _held = token(&mut s);
            probe.queue_event(DeviceEvent::Position { counter: baseline });
            probe.queue_event(DeviceEvent::Position { counter: first });
            if let Some(counter) = second {
                probe.queue_event(DeviceEvent::Position { counter });
            }
            s.poll();
            let codes = fault_codes(&s);
            let got = match codes.as_slice() {
                [] => Want::Clean,
                [FaultCode::CounterOverclaim] => Want::Overclaim,
                [FaultCode::CounterOverclaim, FaultCode::CounterRegress] => Want::Regress,
                other => panic!("{name}: unexpected fault records {other:?}"),
            };
            assert_eq!(got, want, "{name}");
            assert_eq!(s.counter_regressed(), want == Want::Regress, "{name}");
            assert_eq!(
                s.phase() == SessionPhase::Faulted,
                want != Want::Clean,
                "{name}"
            );
        }
    }

    #[test]
    fn an_acknowledged_reset_clears_the_regress_mark_and_the_next_report_is_only_a_baseline() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s);
        for counter in [100, 104, 103] {
            probe.queue_event(DeviceEvent::Position { counter });
        }
        s.poll();
        assert!(s.counter_regressed());
        assert_eq!(s.position().consumed_frames, 4);
        // Nothing frees the quarantined slots or clears the mark until the device acknowledges a reset.
        assert_eq!(slots_in(&s, SlotState::Quarantined), 2);
        s.reset_device().unwrap();
        assert!(!s.counter_regressed());
        assert_eq!(s.phase(), SessionPhase::Prepared);
        assert_eq!(slots_in(&s, SlotState::Free), 4);
        // The device now counts from somewhere else entirely. The old baseline (104) is not used: the
        // first report only sets the new one, and the next is judged against it.
        s.start(READY).unwrap();
        let _c = token(&mut s); // 4 frames in flight; 4 were discarded by the reset
        let anomalies_before = s.receipt().anomalies;
        probe.queue_event(DeviceEvent::Position { counter: 5 });
        let r = s.poll();
        assert_eq!((r.anomalies, s.position().consumed_frames), (0, 4));
        probe.queue_event(DeviceEvent::Position { counter: 9 });
        let r = s.poll();
        assert_eq!(r.anomalies, 0);
        assert_eq!(s.position().consumed_frames, 8);
        assert_eq!(s.phase(), SessionPhase::Running);
        assert_eq!(s.receipt().anomalies, anomalies_before);
    }

    #[test]
    fn a_flush_acknowledgment_outside_a_drain_is_an_anomaly_not_a_free() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        probe.queue_event(DeviceEvent::FlushAck);
        let report = s.poll();
        assert_eq!(report.anomalies, 1);
        assert_eq!(s.slot_states()[0], SlotState::KernelOwned);
        assert_eq!(s.phase(), SessionPhase::Running);
        assert!(s.receipt().faults.is_empty());
        assert_eq!(s.receipt().anomalies, 1);
    }

    #[test]
    fn a_vanished_device_is_a_persistent_fault() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        probe.lose_device();
        s.poll();
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(
            s.amp(),
            Amp::Unknown,
            "a device that is gone cannot be known muted"
        );
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(first_fault(&s), FaultCode::DeviceLost);
        assert_eq!(
            s.reset_device().err().unwrap(),
            SessionError::DevicePersistentlyLost
        );
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        // The kernel may still be reading, so dropping the owner keeps the storage.
        let (alive, freed) = probe.kernel_touch_pending();
        assert_eq!((alive, freed), (1, 0));
        drop(s);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
    }

    #[test]
    fn a_reset_must_be_acknowledged_to_free_anything() {
        let mut cfg = FakeConfig::retained();
        cfg.reset_ack = false;
        cfg.flush_ack_delay_ticks = None;
        let (mut s, probe, _) = running(cfg);
        probe.set_lose_completions(true);
        let _t = token(&mut s);
        assert_eq!(s.drain(1), Ok(DrainOutcome::TimedOut { waited_ticks: 1 }));
        assert_eq!(
            s.reset_device().err().unwrap(),
            SessionError::ResetNotAcknowledged
        );
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(s.phase(), SessionPhase::Faulted);
    }

    #[test]
    fn a_real_backend_cannot_be_opened_without_an_eligible_contract() {
        struct Real;
        impl DeviceBackend for Real {
            fn provenance(&self) -> Provenance {
                Provenance::Real
            }
            fn abi(&self) -> AbiKind {
                AbiKind::RetainedBuffer
            }
            fn capabilities(&mut self) -> Result<crate::backend::RawCapabilities, DriverError> {
                Err(DriverError::Gone)
            }
            fn set_mute(&mut self, _: bool) -> Result<bool, DriverError> {
                Err(DriverError::Gone)
            }
            fn start(&mut self) -> Result<(), DriverError> {
                Err(DriverError::Gone)
            }
            fn write(&mut self, _: &[u8]) -> Result<usize, DriverError> {
                Err(DriverError::Gone)
            }
            fn submit_retained(
                &mut self,
                _: u16,
                _: u32,
                _: crate::slots::KernelView,
                _: usize,
            ) -> Result<usize, DriverError> {
                Err(DriverError::Gone)
            }
            fn poll_event(
                &mut self,
                _: &mut [u8; EVENT_LEN],
            ) -> Result<Option<usize>, DriverError> {
                Err(DriverError::Gone)
            }
            fn request_flush(&mut self) -> Result<(), DriverError> {
                Err(DriverError::Gone)
            }
            fn reset(&mut self) -> Result<bool, DriverError> {
                Err(DriverError::Gone)
            }
            fn wait_tick(&mut self) {}
        }
        let config = || SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        assert_eq!(
            HalSession::open(profile(), Real, config()).err().unwrap(),
            SessionError::HardwareNeedsContract
        );
        // The committed matrix is all unknown, so it does not make a real device eligible.
        let matrix: ContractMatrix =
            serde_json::from_str(include_str!("../../../tests/e04/matrix_audiodev_m16.json"))
                .unwrap();
        assert_eq!(
            HalSession::open_hardware(profile(), Real, config(), &matrix)
                .err()
                .unwrap(),
            SessionError::ContractIncomplete { missing: 111 }
        );
    }

    #[test]
    fn submit_is_validated_before_anything_changes() {
        let (mut s, probe, _) = session(FakeConfig::retained());
        assert_eq!(
            s.submit(&BLOCK).err().unwrap(),
            SessionError::WrongPhase {
                phase: SessionPhase::Closed
            }
        );
        s.prepare().unwrap();
        let before = probe.calls();
        assert_eq!(s.submit(&[]).err().unwrap(), SessionError::EmptySubmit);
        assert_eq!(
            s.submit(&[0; 5]).err().unwrap(),
            SessionError::PartialFrame {
                len: 5,
                frame_bytes: 4
            }
        );
        assert_eq!(
            s.submit(&[0; 20]).err().unwrap(),
            SessionError::TooLarge {
                len: 20,
                block_bytes: 16
            }
        );
        assert_eq!(probe.calls(), before, "nothing reached the device");
        assert_eq!(s.slot_states(), vec![SlotState::Free; 4]);
        assert_eq!(s.irrevocable_until_frames(), 0);
    }

    #[test]
    fn a_full_ring_is_a_typed_busy_error_with_no_side_effects() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        let tokens: Vec<SubmitToken> = (0..4).map(|_| token(&mut s)).collect();
        assert_eq!(tokens.len(), 4);
        let submits = |p: &FakeProbe| {
            p.calls()
                .iter()
                .filter(|c| matches!(c, FakeCall::SubmitRetained { .. }))
                .count()
        };
        assert_eq!(submits(&probe), 4);
        assert_eq!(s.submit(&BLOCK).err().unwrap(), SessionError::NoFreeSlot);
        assert_eq!(submits(&probe), 4);
        assert_eq!(s.phase(), SessionPhase::Running);
    }

    #[test]
    fn a_zero_accept_returns_the_slot_because_the_device_holds_nothing() {
        let (mut s, probe, _) = running(FakeConfig::retained());
        probe.set_accept_limit(Some(0));
        let r = s.submit(&BLOCK).unwrap();
        assert_eq!(
            (r.accepted_bytes, r.accepted_frames, r.remainder_bytes),
            (0, 0, 16)
        );
        assert!(r.token.is_none());
        assert_eq!(s.slot_states()[0], SlotState::Free);
        assert_eq!(probe.pending(), 0);
        assert_eq!(s.irrevocable_until_frames(), 0);
        // A partial accept keeps the whole slot: the device may read all of it.
        probe.set_accept_limit(Some(8));
        let r = s.submit(&BLOCK).unwrap();
        assert_eq!((r.accepted_frames, r.remainder_bytes), (2, 8));
        assert_eq!(s.slot_states()[0], SlotState::KernelOwned);
    }

    #[test]
    fn session_ids_never_wrap_and_the_counter_refuses_once_it_runs_out() {
        // Ordinary use: ids come out in order, each once.
        let counter = AtomicU32::new(1);
        assert_eq!(take_session_id(&counter), Some(1));
        assert_eq!(take_session_id(&counter), Some(2));
        // Near the top: the last two ids go out, then the counter refuses and stays refused.
        let counter = AtomicU32::new(u32::MAX - 2);
        assert_eq!(take_session_id(&counter), Some(u32::MAX - 2));
        assert_eq!(take_session_id(&counter), Some(u32::MAX - 1));
        assert_eq!(take_session_id(&counter), None);
        assert_eq!(
            take_session_id(&counter),
            None,
            "it must not wrap to an id that was already used"
        );
        assert_eq!(counter.load(Ordering::Relaxed), u32::MAX);
    }

    #[test]
    fn opening_is_refused_with_the_device_untouched_once_the_id_space_is_exhausted() {
        let config = || SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        // The last available id still opens a working session.
        let counter = AtomicU32::new(u32::MAX - 1);
        let (backend, _probe) = FakeBackend::new(FakeConfig::retained());
        let mut last = HalSession::open_with_ids(profile(), backend, config(), &counter).unwrap();
        assert_eq!(last.session_id, u64::from(u32::MAX - 1));
        last.prepare().unwrap();
        assert_eq!(last.phase(), SessionPhase::Prepared);
        // The counter is now exhausted: the next open is refused, and its device was never touched.
        let (backend, probe) = FakeBackend::new(FakeConfig::retained());
        let refused = HalSession::open_with_ids(profile(), backend, config(), &counter);
        assert_eq!(refused.err().unwrap(), SessionError::SessionIdsExhausted);
        assert!(probe.calls().is_empty());
        // A refused open for another reason does not use up an id.
        let fresh = AtomicU32::new(5);
        let (backend, _probe) = FakeBackend::new(FakeConfig::retained());
        let bad = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 0);
        assert_eq!(
            HalSession::open_with_ids(profile(), backend, bad, &fresh)
                .err()
                .unwrap(),
            SessionError::BadConfig
        );
        assert_eq!(fresh.load(Ordering::Relaxed), 5);
        // The process-wide counter is unaffected: an ordinary open still succeeds.
        let (ordinary, _probe, _ledger) = session(FakeConfig::retained());
        assert_eq!(ordinary.phase(), SessionPhase::Closed);
    }

    #[test]
    fn concurrent_takers_never_get_the_same_session_id_and_the_counter_never_wraps() {
        use std::collections::BTreeSet;
        // Uncontended first: the baseline the contended run must agree with.
        let solo = AtomicU32::new(1);
        let ids: Vec<u32> = (0..8).map(|_| take_session_id(&solo).unwrap()).collect();
        assert_eq!(ids, (1..=8u32).collect::<Vec<u32>>());

        // Contended: 8 threads race for the last 1000 ids, each asking far more often than there
        // are ids left, so the counter is certain to run out.
        const LEFT: u32 = 1000;
        let left = usize::try_from(LEFT).unwrap();
        let counter = AtomicU32::new(u32::MAX - LEFT);
        let mut all: Vec<u32> = Vec::new();
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..8 {
                handles.push(scope.spawn(|| {
                    let mut mine = Vec::new();
                    for _ in 0..left {
                        if let Some(id) = take_session_id(&counter) {
                            mine.push(id);
                        }
                    }
                    mine
                }));
            }
            for handle in handles {
                all.extend(handle.join().unwrap());
            }
        });
        assert_eq!(
            all.len(),
            left,
            "the total handed out equals the space left"
        );
        let unique: BTreeSet<u32> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len(), "no id was handed out twice");
        assert_eq!(unique.first().copied(), Some(u32::MAX - LEFT));
        assert_eq!(unique.last().copied(), Some(u32::MAX - 1));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            u32::MAX,
            "it never wrapped"
        );
        assert_eq!(take_session_id(&counter), None, "every later call refuses");
    }

    fn session_events(
        cfg: FakeConfig,
        quarantine_cap: usize,
        event_cap: usize,
    ) -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), quarantine_cap)
            .with_event_queue_cap(event_cap);
        (HalSession::open(profile(), backend, config).unwrap(), probe)
    }

    /// Everything waiting, oldest first, as (seq, accepted_frames, kind).
    fn events_so_far(s: &mut HalSession<FakeBackend>) -> Vec<(u64, u64, SessionEventKind)> {
        std::iter::from_fn(|| s.take_event())
            .map(|e| (e.seq, e.accepted_frames, e.kind))
            .collect()
    }

    #[test]
    fn a_clean_cycle_emits_exactly_the_expected_events_in_order() {
        let (mut s, _probe) = session_events(FakeConfig::retained(), 2, 8);
        s.prepare().unwrap();
        s.start(READY).unwrap();
        let _t = token(&mut s);
        s.step();
        s.step();
        assert_eq!(
            s.drain(5),
            Ok(DrainOutcome::Acknowledged { waited_ticks: 1 })
        );
        // Traced by hand: prepare and start happen before any frame is accepted; the block is four
        // frames; the drain's flush is acknowledged one tick later, with those four frames accepted.
        let want: Vec<(u64, u64, SessionEventKind)> = vec![
            (1, 0, SessionEventKind::Prepared),
            (2, 0, SessionEventKind::Started),
            (3, 4, SessionEventKind::StopAcknowledged),
        ];
        assert_eq!(events_so_far(&mut s), want);
        assert_eq!(
            s.event_stats(),
            EmitStats {
                emitted: 3,
                delivered: 3,
                dropped_ordinary: 0,
                evicted_ordinary: 0,
                lost_critical: 0
            }
        );
        assert!(s.event_evidence_complete());
        assert_eq!(s.events_pending(), 0);
    }

    #[test]
    fn a_lost_completion_emits_the_timeout_and_the_quarantine_saturation() {
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (mut s, probe) = session_events(cfg, 1, 8);
        s.prepare().unwrap();
        s.start(READY).unwrap();
        probe.set_lose_completions(true);
        let _a = token(&mut s);
        let _b = token(&mut s);
        assert_eq!(s.drain(1), Ok(DrainOutcome::TimedOut { waited_ticks: 1 }));
        // Two blocks of four frames were accepted. With a quarantine cap of 1 the drain timeout
        // quarantines both, which is over the cap: two faults, in that order.
        let want: Vec<(u64, u64, SessionEventKind)> = vec![
            (1, 0, SessionEventKind::Prepared),
            (2, 0, SessionEventKind::Started),
            (
                3,
                8,
                SessionEventKind::Fault {
                    code: FaultCode::DrainTimedOut,
                },
            ),
            (
                4,
                8,
                SessionEventKind::Fault {
                    code: FaultCode::QuarantineSaturated,
                },
            ),
        ];
        assert_eq!(events_so_far(&mut s), want);
        assert!(s.event_evidence_complete());
    }

    #[test]
    fn an_unacknowledged_mute_and_a_lost_device_are_each_emitted_once() {
        // A mute that is not acknowledged is one fault, however often the caller retries.
        let mut cfg = FakeConfig::retained();
        cfg.mute_ack = false;
        let (mut s, _probe) = session_events(cfg, 2, 8);
        assert!(s.prepare().is_err());
        assert!(s.prepare().is_err());
        let want: Vec<(u64, u64, SessionEventKind)> = vec![(
            1,
            0,
            SessionEventKind::Fault {
                code: FaultCode::MuteNotAcknowledged,
            },
        )];
        assert_eq!(events_so_far(&mut s), want);

        // A device lost while running is a fault, and losing it again adds nothing.
        let (mut s, probe, _) = running(FakeConfig::retained());
        probe.queue_event(DeviceEvent::DeviceLost);
        s.poll();
        probe.queue_event(DeviceEvent::DeviceLost);
        s.poll();
        let want: Vec<(u64, u64, SessionEventKind)> = vec![
            (1, 0, SessionEventKind::Prepared),
            (2, 0, SessionEventKind::Started),
            (
                3,
                0,
                SessionEventKind::Fault {
                    code: FaultCode::DeviceLost,
                },
            ),
        ];
        assert_eq!(events_so_far(&mut s), want);

        // A device lost after the session had already faulted records no fault, but it is emitted
        // once, because the amplifier is now unknown.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 99,
        });
        s.poll();
        assert_eq!(s.amp(), Amp::Muted);
        probe.queue_event(DeviceEvent::DeviceLost);
        s.poll();
        probe.queue_event(DeviceEvent::DeviceLost);
        s.poll();
        assert_eq!(s.amp(), Amp::Unknown);
        let want: Vec<(u64, u64, SessionEventKind)> = vec![
            (1, 0, SessionEventKind::Prepared),
            (2, 0, SessionEventKind::Started),
            (
                3,
                4,
                SessionEventKind::Fault {
                    code: FaultCode::BadCompletion {
                        problem: CompletionProblem::StaleGeneration {
                            expected: 1,
                            got: 99,
                        },
                    },
                },
            ),
            (4, 4, SessionEventKind::DeviceLostWhileFaulted),
        ];
        assert_eq!(events_so_far(&mut s), want);
    }

    /// One fault and reset: start, submit a block, report a completion for a generation the slot was
    /// never at, then reset. Each cycle emits `Started`, a `Fault` and `ResetAcknowledged`.
    fn fault_and_reset(s: &mut HalSession<FakeBackend>, probe: &FakeProbe) {
        s.start(READY).unwrap();
        let _t = token(s);
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 9999,
        });
        s.poll();
        assert_eq!(s.phase(), SessionPhase::Faulted);
        s.reset_device().unwrap();
    }

    #[test]
    fn an_event_flood_is_bounded_and_every_event_is_accounted_for() {
        // 40 fault-and-reset cycles into a 4-event queue that nobody reads. Traced by hand:
        // * cycle 1 fills it: [Prepared, Started, Fault, ResetAck];
        // * cycles 2 to 4 each drop their Started and ResetAck, and the Fault evicts the oldest
        //   ordinary event (Prepared, then Started, then ResetAck), leaving [F3, F6, F9, F12];
        // * from cycle 5 the queue holds only faults, so each Fault is lost and counted.
        let (mut s, probe) = session_events(FakeConfig::retained(), 2, 4);
        s.prepare().unwrap();
        for _ in 0..40 {
            fault_and_reset(&mut s, &probe);
            assert!(s.events_pending() <= 4, "the queue is never over its cap");
        }
        assert_eq!(
            s.event_stats(),
            EmitStats {
                emitted: 121,
                delivered: 0,
                dropped_ordinary: 78,
                evicted_ordinary: 3,
                lost_critical: 36
            }
        );
        let stats = s.event_stats();
        let pending = u64::try_from(s.events_pending()).unwrap();
        assert_eq!(pending, 4);
        assert_eq!(
            stats.emitted,
            stats.delivered
                + pending
                + stats.dropped_ordinary
                + stats.evicted_ordinary
                + stats.lost_critical,
            "every emitted event is delivered, queued, dropped, evicted or lost"
        );
        assert!(!s.event_evidence_complete());
        let kept = events_so_far(&mut s);
        let seqs: Vec<u64> = kept.iter().map(|(seq, _, _)| *seq).collect();
        assert_eq!(seqs, vec![3, 6, 9, 12], "the gaps show what was lost");
        assert!(kept.iter().all(|(_, _, kind)| kind.is_critical()));

        // Permitted positive: a consumer that keeps up loses nothing, and sees every event once and
        // in order.
        let (mut s, probe) = session_events(FakeConfig::retained(), 2, 4);
        s.prepare().unwrap();
        let mut seen = events_so_far(&mut s);
        for _ in 0..40 {
            fault_and_reset(&mut s, &probe);
            seen.extend(events_so_far(&mut s));
        }
        let seqs: Vec<u64> = seen.iter().map(|(seq, _, _)| *seq).collect();
        assert_eq!(seqs, (1..=121u64).collect::<Vec<u64>>());
        assert!(s.event_evidence_complete());
        assert_eq!(s.event_stats().delivered, 121);
        assert_eq!(s.event_stats().lost_critical, 0);
    }

    #[test]
    fn an_unread_or_tiny_event_queue_never_changes_what_the_session_does() {
        fn run(event_cap: usize, read: bool) -> (Vec<String>, SessionReceipt) {
            let (mut s, probe) = session_events(FakeConfig::retained(), 2, event_cap);
            let mut out = vec![
                format!("{:?}", s.prepare()),
                format!("{:?}", s.start(READY)),
            ];
            let _t = token(&mut s);
            probe.queue_event(DeviceEvent::Completed {
                slot: 0,
                generation: 99,
            });
            out.push(s.poll().anomalies.to_string());
            out.push(format!("{:?}", s.reset_device()));
            out.push(format!("{:?}", s.start(READY)));
            out.push(format!("{:?}", s.drain(5)));
            if read {
                events_so_far(&mut s);
            }
            (out, s.receipt())
        }
        let healthy = run(32, true);
        assert_eq!(run(1, false), healthy);
        assert_eq!(run(2, false), healthy);
        // A queue that could hold nothing at all is a bad configuration, not a silent no-op.
        let (backend, _probe) = FakeBackend::new(FakeConfig::retained());
        let zero =
            SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2).with_event_queue_cap(0);
        assert_eq!(
            HalSession::open(profile(), backend, zero).err().unwrap(),
            SessionError::BadConfig
        );
    }

    // ---- the storage the cleanup path needs is reserved at admission, and a refusal is clean

    fn refuse_only(what: Reserved) -> impl FnMut(Reserved) -> bool {
        move |asked| asked == what
    }

    #[test]
    fn a_refused_reservation_at_open_is_a_typed_refusal_that_leaves_the_device_and_the_id_alone() {
        let config = || SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        for (what, name) in [
            (Reserved::FaultRecords, "fault records"),
            (Reserved::EventQueue, "event queue"),
        ] {
            let ids = AtomicU32::new(5);
            let (backend, probe) = FakeBackend::new(FakeConfig::retained());
            let refused = HalSession::open_admitting(
                profile(),
                backend,
                config(),
                &ids,
                &mut refuse_only(what),
            );
            assert_eq!(
                refused.err().unwrap(),
                SessionError::StorageNotAdmitted { what: name }
            );
            assert!(probe.calls().is_empty(), "nothing touched the device");
            assert_eq!(ids.load(Ordering::Relaxed), 5, "no id was used");
        }
        // The allocator's own refusal, not the seam's: a queue nothing could hold is refused the same way.
        let (backend, probe) = FakeBackend::new(FakeConfig::retained());
        let huge = config().with_event_queue_cap(usize::MAX);
        assert_eq!(
            HalSession::open(profile(), backend, huge).err().unwrap(),
            SessionError::StorageNotAdmitted {
                what: "event queue"
            }
        );
        assert!(probe.calls().is_empty());
        // Permitted positive: with nothing refused it opens, and uses one id.
        let ids = AtomicU32::new(5);
        let (backend, _probe) = FakeBackend::new(FakeConfig::retained());
        let opened =
            HalSession::open_admitting(profile(), backend, config(), &ids, &mut |_| false).unwrap();
        assert_eq!(opened.phase(), SessionPhase::Closed);
        assert_eq!(ids.load(Ordering::Relaxed), 6);
        // A refusal leaves nothing a later admission trusts: the session that opens after one has exactly the
        // footprint of one that never saw a refusal.
        let (clean, _p, _l) = session(FakeConfig::retained());
        assert_eq!(opened.storage_footprint(), clean.storage_footprint());
    }

    #[test]
    fn a_refused_slot_reservation_at_prepare_admits_no_slots_starts_nothing_and_a_retry_succeeds() {
        let (mut s, probe, ledger) = session(FakeConfig::retained());
        let before = s.storage_footprint();
        let refused = s.prepare_reserving(&mut |slot| slot == 2);
        // The device was asked one question and given no instruction: no mute, no start.
        assert_eq!(probe.calls(), vec![FakeCall::Capabilities]);
        assert_eq!(
            refused,
            Err(SessionError::Slots(SlotError::StorageNotAdmitted {
                reserved: 2,
                depth: 4
            }))
        );
        assert_eq!(s.phase(), SessionPhase::Closed);
        assert_eq!(s.amp(), Amp::Muted);
        assert!(s.slot_states().is_empty(), "no table was admitted");
        assert!(
            s.receipt().faults.is_empty(),
            "a refused reservation is not a device fault"
        );
        assert_eq!(ledger.leaked_slots(), 0);
        assert_eq!(s.storage_footprint(), before);
        // Permitted positive: the same session prepares when nothing is refused, and ends up exactly where a
        // session that was never refused does.
        s.prepare().unwrap();
        assert_eq!(s.phase(), SessionPhase::Prepared);
        assert_eq!(s.slot_states().len(), 4);
        let (mut clean, _p, _l) = session(FakeConfig::retained());
        clean.prepare().unwrap();
        assert_eq!(s.storage_footprint(), clean.storage_footprint());
    }

    #[test]
    fn the_storage_footprint_is_fixed_at_admission_and_a_fault_flood_and_a_full_cycle_never_grow_it()
     {
        let (mut s, probe) = session_events(FakeConfig::retained(), 2, 4);
        let opened = s.storage_footprint();
        assert!(opened.fault_records >= MAX_FAULT_RECORDS);
        assert!(opened.events >= 4);
        assert_eq!((opened.slots, opened.slot_bytes), (0, 0));
        s.prepare().unwrap();
        let admitted = s.storage_footprint();
        assert_eq!(
            (admitted.fault_records, admitted.events),
            (opened.fault_records, opened.events)
        );
        assert_eq!(admitted.slots, 4);
        assert!(
            admitted.slot_bytes >= 4 * BLOCK.len(),
            "a whole block per slot"
        );
        // A fault flood, well past MAX_FAULT_RECORDS and the 4-event queue, with every slot used.
        for _ in 0..40 {
            fault_and_reset(&mut s, &probe);
            assert_eq!(s.storage_footprint(), admitted);
        }
        assert_eq!(s.receipt().faults.len(), MAX_FAULT_RECORDS);
        assert!(s.receipt().dropped_fault_records > 0);
        // A clean cycle that fills every slot and drains.
        s.start(READY).unwrap();
        let tokens: Vec<SubmitToken> = (0..4).map(|_| token(&mut s)).collect();
        assert_eq!(tokens.len(), 4);
        assert_eq!(s.storage_footprint(), admitted);
        assert!(matches!(s.drain(8), Ok(DrainOutcome::Acknowledged { .. })));
        assert_eq!(s.storage_footprint(), admitted);
        // A drain the device never acknowledges faults and quarantines, and still allocates nothing.
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (mut s, _probe) = session_events(cfg, 2, 4);
        s.prepare().unwrap();
        let admitted = s.storage_footprint();
        s.start(READY).unwrap();
        let _t = token(&mut s);
        assert!(matches!(s.drain(3), Ok(DrainOutcome::TimedOut { .. })));
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(s.storage_footprint(), admitted);
        s.reset_device().unwrap();
        s.start(READY).unwrap();
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        assert_eq!(s.storage_footprint(), admitted);
    }

    // ---- the event record is the caller's buffer, so the cancel and drain paths read events without allocating

    #[test]
    fn a_device_record_is_read_into_the_callers_buffer_and_a_wrong_sized_one_is_refused_by_its_true_length()
     {
        // The fake hands a record over by value, and reports the length the device had.
        let (mut backend, probe) = FakeBackend::new(FakeConfig::retained());
        let mut record = [0xEE; EVENT_LEN];
        assert_eq!(backend.poll_event(&mut record), Ok(None));
        probe.queue_event(DeviceEvent::Position { counter: 7 });
        assert_eq!(backend.poll_event(&mut record), Ok(Some(EVENT_LEN)));
        assert_eq!(
            decode_event(&record),
            Ok(DeviceEvent::Position { counter: 7 })
        );
        probe.queue_raw_event(vec![1, 2, 3]);
        assert_eq!(backend.poll_event(&mut record), Ok(Some(3)));
        assert_eq!(record[..3], [1, 2, 3]);
        probe.queue_raw_event((0..40u8).collect::<Vec<u8>>());
        assert_eq!(
            backend.poll_event(&mut record),
            Ok(Some(40)),
            "the length the device had, not the length that fitted"
        );
        assert_eq!(record, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

        // The session refuses each by the length reported, including a long record whose first 12 bytes are a
        // valid event: it is not cut to fit and applied.
        let mut long_valid = crate::abi::encode_event(&DeviceEvent::FlushAck).to_vec();
        long_valid.extend_from_slice(&[0, 0, 0, 0]);
        let cases: [(Vec<u8>, usize); 6] = [
            (vec![], 0),
            (vec![1, 2, 3], 3),
            (vec![0; 11], 11),
            (vec![0; 13], 13),
            (long_valid, 16),
            ((0..40u8).collect::<Vec<u8>>(), 40),
        ];
        for (bytes, actual) in cases {
            let (mut s, probe, _) = running(FakeConfig::retained());
            let _t = token(&mut s);
            probe.queue_raw_event(bytes);
            let report = s.poll();
            assert_eq!(report.anomalies, 1, "{actual}");
            assert_eq!(s.phase(), SessionPhase::Faulted, "{actual}");
            assert_eq!(
                first_fault(&s),
                FaultCode::Malformed {
                    what: MalformedKind::Event,
                    abi: Some(AbiError::Length {
                        expected: EVENT_LEN,
                        actual
                    })
                },
                "{actual}"
            );
        }
        // Permitted positive: a well-formed record of the right length is applied.
        let (mut s, probe, _) = running(FakeConfig::retained());
        probe.queue_event(DeviceEvent::Position { counter: 0 });
        let report = s.poll();
        assert_eq!((report.events, report.anomalies), (1, 0));
        assert_eq!(s.phase(), SessionPhase::Running);
    }

    #[test]
    fn an_abort_and_a_drain_with_events_pending_read_them_into_the_callers_buffer_and_never_grow_the_reservation()
     {
        // Abort with events waiting: both completions are read and applied while the abort settles, a malformed
        // record behind them faults the session muted, and nothing grew.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let admitted = s.storage_footprint();
        let _a = token(&mut s);
        let _b = token(&mut s);
        for (slot, generation) in probe.pending_slots() {
            probe.queue_event(DeviceEvent::Completed { slot, generation });
        }
        probe.queue_raw_event(vec![9; 5]);
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        assert_eq!(s.phase(), SessionPhase::Faulted);
        assert_eq!(
            first_fault(&s),
            FaultCode::Malformed {
                what: MalformedKind::Event,
                abi: Some(AbiError::Length {
                    expected: EVENT_LEN,
                    actual: 5
                })
            }
        );
        assert_eq!(s.storage_footprint(), admitted);
        // Permitted positive: the same events without the malformed record are applied and free both slots.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let _a = token(&mut s);
        let _b = token(&mut s);
        for (slot, generation) in probe.pending_slots() {
            probe.queue_event(DeviceEvent::Completed { slot, generation });
        }
        assert!(s.abort_mute().unwrap().mute_acknowledged);
        assert_eq!(s.phase(), SessionPhase::Draining);
        assert!(s.slot_states().iter().all(|st| *st == SlotState::Free));

        // A drain with an event waiting and a poll that fails once while it settles: refused muted, the slot
        // quarantined, and the reservation as it was.
        let (mut s, probe, _) = running(FakeConfig::retained());
        let admitted = s.storage_footprint();
        let _t = token(&mut s);
        probe.queue_event(DeviceEvent::FlushAck);
        probe.fail_next(Op::PollEvent, DriverError::Errno(5));
        assert_eq!(s.drain(5).err(), Some(SessionError::FaultedDuringDrain));
        assert_eq!((s.phase(), s.amp()), (SessionPhase::Faulted, Amp::Muted));
        assert_eq!(
            first_fault(&s),
            FaultCode::DriverError {
                op: Op::PollEvent,
                error: DriverError::Errno(5)
            }
        );
        assert_eq!(s.slot_states()[0], SlotState::Quarantined);
        assert_eq!(s.storage_footprint(), admitted);
    }

    #[test]
    fn a_token_from_another_session_is_refused() {
        let (mut a, _, _) = running(FakeConfig::retained());
        let (b, _, _) = running(FakeConfig::retained());
        let t = token(&mut a);
        assert_eq!(b.token_state(&t), Err(SessionError::ForeignToken));
        assert_eq!(a.token_state(&t), Ok(TokenState::InFlight));
    }

    #[test]
    fn position_class_lead_and_deadline_are_exposed() {
        for (err, class) in [
            (Some(0), PositionClass::Exact),
            (
                Some(5),
                PositionClass::Bounded {
                    max_error_frames: 5,
                },
            ),
            (None, PositionClass::Unknown),
        ] {
            let mut cfg = FakeConfig::retained();
            cfg.position_error_frames = err;
            let (mut s, _, _) = session(cfg);
            s.prepare().unwrap();
            assert_eq!(s.position().class, class);
            assert_eq!(s.min_submission_lead_ticks(), Some(1));
            assert_eq!(s.stop_deadline_ticks(), Some(8));
        }
    }

    #[test]
    fn the_receipt_names_model_evidence_and_serializes() {
        let (mut s, _, _) = running(FakeConfig::retained());
        let _t = token(&mut s);
        let r = s.receipt();
        assert_eq!(r.schema, RECEIPT_SCHEMA);
        assert_eq!(r.provenance, Provenance::Fake);
        assert_eq!(
            (r.evidence.as_str(), r.scope.as_str(), r.abi.as_str()),
            ("model", "host_simulation", "retained_buffer")
        );
        assert!(matches!(
            r.local_events,
            LocalEventCapability::Unsupported { .. }
        ));
        assert_eq!((r.slots_in_flight, r.slots_free), (1, 3));
        let back: SessionReceipt =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn a_profile_that_does_not_verify_never_reaches_the_device() {
        let hypothesis = franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let (backend, probe) = FakeBackend::new(FakeConfig::retained());
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(8)), 2);
        assert!(matches!(
            HalSession::open(hypothesis, backend, config).err().unwrap(),
            SessionError::ProfileRejected(UnsupportedReasonCode::UnattestedProfile { .. })
        ));
        assert!(probe.calls().is_empty());
    }

    /// Small deterministic generator so the sweep below needs no dependency and replays exactly.
    struct Xorshift(u64);

    impl Xorshift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    fn assert_storage_invariant(s: &HalSession<FakeBackend>, probe: &FakeProbe, seed: u64) {
        assert_eq!(
            probe.use_after_free(),
            0,
            "seed {seed}: the kernel read freed storage"
        );
        assert_eq!(
            probe.modified_while_owned(),
            0,
            "seed {seed}: storage changed under the kernel"
        );
        for (slot, generation) in probe.pending_slots() {
            assert_ne!(
                s.inspect_slot(slot, generation),
                TokenState::Settled,
                "seed {seed}: the kernel holds slot {slot} generation {generation} but the table says it is settled"
            );
        }
    }

    #[test]
    fn storage_the_kernel_may_hold_is_never_released_under_chaos() {
        let mut completions = 0usize;
        let mut quarantined_runs = 0usize;
        let mut leaked_total = 0usize;
        let mut closed_runs = 0usize;
        for seed in 1..=300u64 {
            let mut rng = Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut cfg = FakeConfig::retained();
            cfg.completion_delay_ticks = rng.below(4);
            cfg.flush_ack_delay_ticks = if rng.below(4) == 0 {
                None
            } else {
                Some(rng.below(3))
            };
            cfg.reset_ack = rng.below(5) != 0;
            let ledger = Arc::new(LeakLedger::new(100_000));
            let (backend, probe) = FakeBackend::new(cfg);
            let config = SessionConfig::with_ledger(Arc::clone(&ledger), 2);
            let mut session = Some(HalSession::open(profile(), backend, config).unwrap());
            session.as_mut().unwrap().prepare().unwrap();
            let mut ever_quarantined = false;
            for _ in 0..60 {
                let Some(s) = session.as_mut() else { break };
                match rng.below(15) {
                    0 => {
                        let _ = s.start(READY);
                    }
                    1..=3 => {
                        let lens = [0usize, 4, 8, 16, 16, 20];
                        let len = lens[usize::try_from(rng.below(6)).unwrap()];
                        let _ = s.submit(&vec![0x5A; len]);
                    }
                    4 => completions += s.step().completions,
                    5 => completions += s.poll().completions,
                    6 => {
                        let _ = s.drain(rng.below(4));
                    }
                    7 => {
                        let _ = s.abort_mute();
                    }
                    8 => {
                        let _ = s.cancel_drain();
                    }
                    9 => {
                        let _ = s.reset_device();
                    }
                    10 => match rng.below(5) {
                        // Generation 0 is never valid, so these are always stale or unknown.
                        0 => probe.queue_event(DeviceEvent::Completed {
                            slot: u16::try_from(rng.below(8)).unwrap(),
                            generation: 0,
                        }),
                        1 => probe.queue_event(DeviceEvent::Completed {
                            slot: 200,
                            generation: 1,
                        }),
                        2 => probe.queue_raw_event(vec![1, 2, 3]),
                        3 => probe.queue_event(DeviceEvent::Position {
                            counter: u32::try_from(rng.below(1 << 20)).unwrap(),
                        }),
                        _ => {
                            // A flush acknowledgment while draining would be a device that lies about
                            // having stopped. The session is entitled to believe an acknowledgment, so
                            // the sweep does not forge one.
                            if s.phase() != SessionPhase::Draining {
                                probe.queue_event(DeviceEvent::FlushAck);
                            }
                        }
                    },
                    11 => {
                        probe.set_lose_completions(rng.below(2) == 0);
                        let limits = [None, Some(0), Some(4), Some(7), Some(8)];
                        probe.set_accept_limit(limits[usize::try_from(rng.below(5)).unwrap()]);
                    }
                    12 => {
                        let ops = [
                            Op::Start,
                            Op::SubmitRetained,
                            Op::SetMute,
                            Op::RequestFlush,
                            Op::Reset,
                        ];
                        probe.fail_next(
                            ops[usize::try_from(rng.below(5)).unwrap()],
                            DriverError::Errno(5),
                        );
                    }
                    13 => {
                        if rng.below(6) == 0 {
                            probe.lose_device();
                        }
                    }
                    _ => {
                        if let Some(taken) = session.take() {
                            match taken.close() {
                                Ok(_) => {
                                    assert_eq!(
                                        probe.pending(),
                                        0,
                                        "seed {seed}: closed with the kernel holding storage"
                                    );
                                    closed_runs += 1;
                                    break;
                                }
                                Err(refused) => session = Some(refused.session),
                            }
                        }
                    }
                }
                if let Some(s) = session.as_ref() {
                    assert_storage_invariant(s, &probe, seed);
                    if s.receipt().slots_quarantined > 0 {
                        ever_quarantined = true;
                    }
                }
            }
            // Destroying the owner, in whatever state the chaos left it, must not free what the
            // kernel may still read.
            drop(session);
            assert_eq!(
                probe.use_after_free(),
                0,
                "seed {seed}: owner destruction freed kernel storage"
            );
            assert_eq!(probe.kernel_touch_pending().1, 0, "seed {seed}");
            quarantined_runs += usize::from(ever_quarantined);
            leaked_total += ledger.leaked_slots();
        }
        // The sweep must reach the interesting states, or it proves nothing.
        assert!(completions > 0, "no completion was ever processed");
        assert!(quarantined_runs > 0, "no slot was ever quarantined");
        assert!(
            leaked_total > 0,
            "no owner was ever destroyed with the kernel holding storage"
        );
        assert!(closed_runs > 0, "no session ever closed cleanly");
    }
}
