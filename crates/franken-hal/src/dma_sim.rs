//! DMA ownership simulator and trace replay (`E04` / `ffw-25l`).
//!
//! An offline model of the *contract* between the HAL and a retained audio driver, not of any real
//! board: it cannot show amplifier sequencing, electrical behavior or timing, and a pass here is a
//! host simulation result and nothing more.
//!
//! The simulator takes a stream of [`SimEvent`]s: host actions (acquire, prepare, submit, drain,
//! release) interleaved with what the driver reports (short writes, delayed completions, flush and
//! mute acknowledgments, device loss, a wrapping consumed-frame counter). Each step yields a
//! [`StepOutcome`]. The model refuses a host action that would break an invariant and records a
//! driver report that contradicts the contract as an anomaly without changing state, so a lying or
//! confused driver can never move the model into an unsafe state.
//!
//! Invariants it enforces:
//! * one owner at a time; a second acquire is refused as busy;
//! * a slot the driver may still be reading (`DmaOwned`, or `Quarantined` after a drain timeout or
//!   device loss) is never released or reused;
//! * a stop request is not an acknowledged flush: draining ends only on a flush acknowledgment or a
//!   timeout, and the device is released only after one of them;
//! * an unacknowledged mute is a fault: it blocks start, power-save and release;
//! * driver counters are untrusted: a consumed-frame counter may wrap but may never claim more than
//!   is in flight, and is never used as an index;
//! * radio duties owned by the stock daemon are orphaned when the daemon is replaced, never assumed
//!   to carry on;
//! * with a [`SimModel`] (a channel map, rates and an amplifier startup sequence), a startup step is
//!   accepted only in the contract's order and after its minimum delay, `start` waits for the rate and
//!   the whole sequence, a byte count must be a whole number of frames, and the clocks are cut only
//!   while the amplifier is muted.
//!
//! The hand-written trace cases live in `tests/e04/sim_cases.json` and are replayed here and by the
//! independent Python reference model in `tests/e04/`.

use crate::contract::{AmpAction, DutyOwner, RadioDutyKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema string of the committed trace-case file.
pub const SIM_CASES_SCHEMA: &str = "ffw.e04.sim_cases.v1";

/// Most buffer slots a device can be prepared with.
pub const SLOT_CAP: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Closed,
    Prepared,
    Running,
    Draining,
    Faulted,
    PowerSave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmpState {
    /// Mute asserted and, where it was requested, acknowledged.
    Muted,
    Unmuted,
    /// A mute request was not acknowledged, or the device is gone. The amplifier state is unknown.
    MuteFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    Free,
    /// The driver may be reading this buffer.
    DmaOwned,
    /// A drain timed out or the device was lost with this slot in flight. Not reusable until a
    /// full device reset is acknowledged.
    Quarantined,
    /// The host gave the buffer memory back.
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyState {
    HeldKernelDriver,
    HeldChipFirmware,
    HeldDaemon,
    /// The stock daemon was replaced and nothing has taken the duty over.
    Orphaned,
    /// The replacement took the duty over.
    Adopted,
    /// The owner was never established. Stays explicit; never promoted to held.
    OwnerUnknown,
}

/// Why the model refused a host action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    Busy,
    NotOwner,
    WrongPhase,
    BadSlot,
    BadSlotCount,
    SlotNotFree,
    EmptySubmit,
    ReleaseWhileDmaOwned,
    SlotQuarantined,
    AlreadyReleased,
    MuteNotAcknowledged,
    DmaOwnedSlots,
    QuarantinedSlots,
    PowerSaveNeedsMute,
    PowerSaveNeedsIdle,
    NotInPowerSave,
    DutyNotDeclared,
    NotDaemonOwned,
    DaemonNotReplaced,
    /// The event needs a [`SimModel`] and the trace has none.
    NoModel,
    RateNotSupported,
    RateNotSet,
    AmpStepOutOfOrder,
    AmpStepTooEarly,
    AmpSequenceIncomplete,
    ClocksOffWhileUnmuted,
    PartialFrame,
}

/// How a driver report contradicted the contract. The model state is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    AcceptedMoreThanOffered,
    SpuriousCompletion,
    CompletionForQuarantinedSlot,
    CounterExceedsInFlight,
    ResetUnacknowledged,
    FlushAckOutsideDrain,
    /// The driver reported accepting a byte count that is not a whole number of frames.
    AcceptedPartialFrame,
}

/// What one step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum StepOutcome {
    #[serde(rename = "ok")]
    Applied,
    /// A short write: the driver took fewer frames than offered. `remainder` stays with the host.
    Partial {
        remainder: u32,
    },
    Refused {
        reason: Refusal,
    },
    Anomaly {
        kind: AnomalyKind,
    },
    /// A drain's wait bound passed without a flush acknowledgment.
    DrainTimedOut,
    /// A mute request was not acknowledged.
    MuteFailed,
}

/// One event: a host action or a driver report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SimEvent {
    Acquire {
        owner: String,
    },
    Prepare {
        slots: u16,
    },
    Start,
    /// The host offers `frames`; the driver reports it `accepted` that many.
    Submit {
        slot: u16,
        frames: u32,
        accepted: u32,
    },
    /// The driver reports a slot's transfer finished.
    Completion {
        slot: u16,
    },
    ReleaseSlot {
        slot: u16,
    },
    Drain {
        max_wait_ticks: u64,
    },
    Tick {
        ticks: u64,
    },
    /// The driver acknowledges that it stopped and flushed.
    FlushAck,
    /// The host aborts into mute; `ack` is whether the driver acknowledged the mute.
    AbortMute {
        ack: bool,
    },
    /// The driver reports a full device reset; `ack` is whether it completed.
    DeviceReset {
        ack: bool,
    },
    DeviceLoss,
    PowerSave {
        enter: bool,
    },
    /// The driver reports its wrapping 32-bit consumed-frame counter.
    ConsumedCounter {
        value: u32,
    },
    ReleaseDevice {
        owner: String,
    },
    /// Declare who performs a radio duty. `None` means the owner is not established.
    DeclareDuty {
        duty: RadioDutyKind,
        owner: Option<DutyOwner>,
    },
    DaemonReplaced,
    AdoptDuty {
        duty: RadioDutyKind,
    },
    /// Choose the sample rate. Only while prepared, and only a rate the model lists.
    SetRate {
        hz: u32,
    },
    /// Perform one amplifier step. `disable_clocks` is a stop step; the others advance the startup.
    AmpStep {
        action: AmpAction,
    },
    /// Like `Submit`, in bytes: the host offers `bytes` and the driver reports it `accepted_bytes`.
    SubmitBytes {
        slot: u16,
        bytes: u32,
        accepted_bytes: u32,
    },
}

/// One step of a model's startup sequence: the action, and the least sim time after the previous
/// step. In a trace with a model, one sim tick is one microsecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStep {
    pub action: AmpAction,
    pub min_delay_ticks: u64,
}

/// The contract a trace runs against: the channel map, the rates and the startup sequence. The last
/// startup step is `deassert_mute`, which `start` performs; the steps before it are `amp_step`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimModel {
    pub channels: u8,
    pub bytes_per_sample: u8,
    pub rates_hz: Vec<u32>,
    pub startup: Vec<ModelStep>,
}

/// The externally visible state of the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimSnapshot {
    pub phase: Phase,
    pub amp: AmpState,
    pub owner: Option<String>,
    pub slots: Vec<SlotState>,
    /// Frames the driver accepted since the device was acquired.
    pub submitted: u64,
    /// Frames the driver reported consumed, after validation.
    pub consumed: u64,
    #[serde(default)]
    pub radio: BTreeMap<RadioDutyKind, DutyState>,
    /// The sample rate chosen, if any.
    #[serde(default)]
    pub rate_hz: Option<u32>,
    /// Startup steps done so far, not counting the final unmute that `start` performs.
    #[serde(default)]
    pub amp_progress: usize,
    #[serde(default)]
    pub clocks_on: bool,
}

#[derive(Debug, Clone, Copy)]
struct DutyRecord {
    owner: Option<DutyOwner>,
    state: DutyState,
}

const fn refused(reason: Refusal) -> StepOutcome {
    StepOutcome::Refused { reason }
}

const fn anomaly(kind: AnomalyKind) -> StepOutcome {
    StepOutcome::Anomaly { kind }
}

/// The ownership model.
#[derive(Debug)]
pub struct DmaSim {
    owner: Option<String>,
    phase: Phase,
    amp: AmpState,
    slots: Vec<SlotState>,
    now: u64,
    drain_deadline: Option<u64>,
    submitted_total: u64,
    consumed_total: u64,
    last_counter: u32,
    start_counter: u32,
    daemon_replaced: bool,
    duties: BTreeMap<RadioDutyKind, DutyRecord>,
    model: Option<SimModel>,
    rate_hz: Option<u32>,
    amp_progress: usize,
    last_amp_at: u64,
    clocks_on: bool,
}

impl DmaSim {
    /// A closed, unowned device. `start_counter` is the driver's consumed-frame counter at
    /// acquisition; a nonzero value lets a trace exercise wraparound.
    #[must_use]
    pub fn new(start_counter: u32) -> Self {
        Self {
            owner: None,
            phase: Phase::Closed,
            amp: AmpState::Muted,
            slots: Vec::new(),
            now: 0,
            drain_deadline: None,
            submitted_total: 0,
            consumed_total: 0,
            last_counter: start_counter,
            start_counter,
            daemon_replaced: false,
            duties: BTreeMap::new(),
            model: None,
            rate_hz: None,
            amp_progress: 0,
            last_amp_at: 0,
            clocks_on: false,
        }
    }

    /// As [`new`](Self::new), running against a channel map, rates and startup sequence.
    #[must_use]
    pub fn with_model(start_counter: u32, model: SimModel) -> Self {
        let mut sim = Self::new(start_counter);
        sim.model = Some(model);
        sim
    }

    #[must_use]
    pub fn snapshot(&self) -> SimSnapshot {
        SimSnapshot {
            phase: self.phase,
            amp: self.amp,
            owner: self.owner.clone(),
            slots: self.slots.clone(),
            submitted: self.submitted_total,
            consumed: self.consumed_total,
            radio: self
                .duties
                .iter()
                .map(|(duty, record)| (*duty, record.state))
                .collect(),
            rate_hz: self.rate_hz,
            amp_progress: self.amp_progress,
            clocks_on: self.clocks_on,
        }
    }

    /// Apply one event.
    pub fn apply(&mut self, event: &SimEvent) -> StepOutcome {
        match event {
            SimEvent::Acquire { owner } => self.acquire(owner),
            SimEvent::Prepare { slots } => self.prepare(*slots),
            SimEvent::Start => self.start(),
            SimEvent::Submit {
                slot,
                frames,
                accepted,
            } => self.submit(*slot, *frames, *accepted),
            SimEvent::Completion { slot } => self.completion(*slot),
            SimEvent::ReleaseSlot { slot } => self.release_slot(*slot),
            SimEvent::Drain { max_wait_ticks } => self.drain(*max_wait_ticks),
            SimEvent::Tick { ticks } => self.tick(*ticks),
            SimEvent::FlushAck => self.flush_ack(),
            SimEvent::AbortMute { ack } => self.abort_mute(*ack),
            SimEvent::DeviceReset { ack } => self.device_reset(*ack),
            SimEvent::DeviceLoss => self.device_loss(),
            SimEvent::PowerSave { enter } => self.power_save(*enter),
            SimEvent::ConsumedCounter { value } => self.consumed_counter(*value),
            SimEvent::ReleaseDevice { owner } => self.release_device(owner),
            SimEvent::DeclareDuty { duty, owner } => self.declare_duty(*duty, *owner),
            SimEvent::DaemonReplaced => self.daemon_replaced(),
            SimEvent::AdoptDuty { duty } => self.adopt_duty(*duty),
            SimEvent::SetRate { hz } => self.set_rate(*hz),
            SimEvent::AmpStep { action } => self.amp_step(*action),
            SimEvent::SubmitBytes {
                slot,
                bytes,
                accepted_bytes,
            } => self.submit_bytes(*slot, *bytes, *accepted_bytes),
        }
    }

    fn any_slot(&self, wanted: SlotState) -> bool {
        self.slots.contains(&wanted)
    }

    fn acquire(&mut self, owner: &str) -> StepOutcome {
        if self.owner.is_some() {
            return refused(Refusal::Busy);
        }
        self.owner = Some(owner.to_string());
        StepOutcome::Applied
    }

    fn prepare(&mut self, slots: u16) -> StepOutcome {
        if self.owner.is_none() {
            return refused(Refusal::NotOwner);
        }
        if self.phase != Phase::Closed {
            return refused(Refusal::WrongPhase);
        }
        if slots == 0 || slots > SLOT_CAP {
            return refused(Refusal::BadSlotCount);
        }
        self.slots = vec![SlotState::Free; usize::from(slots)];
        self.phase = Phase::Prepared;
        self.amp = AmpState::Muted;
        self.drain_deadline = None;
        self.rate_hz = None;
        self.amp_progress = 0;
        self.clocks_on = false;
        StepOutcome::Applied
    }

    fn start(&mut self) -> StepOutcome {
        if self.phase != Phase::Prepared {
            return refused(Refusal::WrongPhase);
        }
        if self.amp == AmpState::MuteFailed {
            return refused(Refusal::MuteNotAcknowledged);
        }
        if let Some(model) = &self.model {
            if self.rate_hz.is_none() {
                return refused(Refusal::RateNotSet);
            }
            let last = model.startup.len().saturating_sub(1);
            if self.amp_progress < last {
                return refused(Refusal::AmpSequenceIncomplete);
            }
            if self.amp_progress > 0
                && let Some(step) = model.startup.get(last)
                && self.now.saturating_sub(self.last_amp_at) < step.min_delay_ticks
            {
                return refused(Refusal::AmpStepTooEarly);
            }
        }
        self.amp = AmpState::Unmuted;
        self.phase = Phase::Running;
        self.amp_progress = 0;
        StepOutcome::Applied
    }

    /// The checks every submit shares: the phase, and a slot that exists and is free.
    fn submit_preflight(&self, slot: u16) -> Option<StepOutcome> {
        if !matches!(self.phase, Phase::Prepared | Phase::Running) {
            return Some(refused(Refusal::WrongPhase));
        }
        match self.slots.get(usize::from(slot)).copied() {
            None => Some(refused(Refusal::BadSlot)),
            Some(state) if state != SlotState::Free => Some(refused(Refusal::SlotNotFree)),
            Some(_) => None,
        }
    }

    fn submit(&mut self, slot: u16, frames: u32, accepted: u32) -> StepOutcome {
        if let Some(early) = self.submit_preflight(slot) {
            return early;
        }
        self.submit_frames(slot, frames, accepted)
    }

    /// A byte-level submit: the model's channel map says how many bytes make a frame.
    fn submit_bytes(&mut self, slot: u16, bytes: u32, accepted_bytes: u32) -> StepOutcome {
        let Some(model) = &self.model else {
            return refused(Refusal::NoModel);
        };
        let frame_bytes = (u32::from(model.channels) * u32::from(model.bytes_per_sample)).max(1);
        if let Some(early) = self.submit_preflight(slot) {
            return early;
        }
        if bytes == 0 {
            return refused(Refusal::EmptySubmit);
        }
        if !bytes.is_multiple_of(frame_bytes) {
            return refused(Refusal::PartialFrame);
        }
        if accepted_bytes > bytes {
            return anomaly(AnomalyKind::AcceptedMoreThanOffered);
        }
        if !accepted_bytes.is_multiple_of(frame_bytes) {
            return anomaly(AnomalyKind::AcceptedPartialFrame);
        }
        self.submit_frames(slot, bytes / frame_bytes, accepted_bytes / frame_bytes)
    }

    fn set_rate(&mut self, hz: u32) -> StepOutcome {
        let Some(model) = &self.model else {
            return refused(Refusal::NoModel);
        };
        if self.owner.is_none() {
            return refused(Refusal::NotOwner);
        }
        if self.phase != Phase::Prepared {
            return refused(Refusal::WrongPhase);
        }
        if !model.rates_hz.contains(&hz) {
            return refused(Refusal::RateNotSupported);
        }
        self.rate_hz = Some(hz);
        StepOutcome::Applied
    }

    fn amp_step(&mut self, action: AmpAction) -> StepOutcome {
        let Some(model) = &self.model else {
            return refused(Refusal::NoModel);
        };
        if self.owner.is_none() {
            return refused(Refusal::NotOwner);
        }
        if action == AmpAction::DisableClocks {
            // Cutting the clocks is a stop step: only once the amplifier is known muted.
            if self.amp != AmpState::Muted {
                return refused(Refusal::ClocksOffWhileUnmuted);
            }
            self.clocks_on = false;
            self.amp_progress = 0;
            return StepOutcome::Applied;
        }
        if self.phase != Phase::Prepared {
            return refused(Refusal::WrongPhase);
        }
        let last = model.startup.len().saturating_sub(1);
        if self.amp_progress >= last {
            return refused(Refusal::AmpStepOutOfOrder);
        }
        let Some(expected) = model.startup.get(self.amp_progress) else {
            return refused(Refusal::AmpStepOutOfOrder);
        };
        if action != expected.action {
            return refused(Refusal::AmpStepOutOfOrder);
        }
        if self.amp_progress > 0
            && self.now.saturating_sub(self.last_amp_at) < expected.min_delay_ticks
        {
            return refused(Refusal::AmpStepTooEarly);
        }
        self.amp_progress += 1;
        self.last_amp_at = self.now;
        if action == AmpAction::EnableClocks {
            self.clocks_on = true;
        }
        StepOutcome::Applied
    }

    fn submit_frames(&mut self, slot: u16, frames: u32, accepted: u32) -> StepOutcome {
        let idx = usize::from(slot);
        if frames == 0 {
            return refused(Refusal::EmptySubmit);
        }
        if accepted > frames {
            return anomaly(AnomalyKind::AcceptedMoreThanOffered);
        }
        if accepted == 0 {
            return StepOutcome::Partial { remainder: frames };
        }
        self.slots[idx] = SlotState::DmaOwned;
        self.submitted_total = self.submitted_total.saturating_add(u64::from(accepted));
        if accepted < frames {
            StepOutcome::Partial {
                remainder: frames - accepted,
            }
        } else {
            StepOutcome::Applied
        }
    }

    fn completion(&mut self, slot: u16) -> StepOutcome {
        let idx = usize::from(slot);
        match self.slots.get(idx).copied() {
            Some(SlotState::DmaOwned) => {
                self.slots[idx] = SlotState::Free;
                StepOutcome::Applied
            }
            Some(SlotState::Quarantined) => anomaly(AnomalyKind::CompletionForQuarantinedSlot),
            _ => anomaly(AnomalyKind::SpuriousCompletion),
        }
    }

    fn release_slot(&mut self, slot: u16) -> StepOutcome {
        let idx = usize::from(slot);
        match self.slots.get(idx).copied() {
            None => refused(Refusal::BadSlot),
            Some(SlotState::DmaOwned) => refused(Refusal::ReleaseWhileDmaOwned),
            Some(SlotState::Quarantined) => refused(Refusal::SlotQuarantined),
            Some(SlotState::Released) => refused(Refusal::AlreadyReleased),
            Some(SlotState::Free) => {
                self.slots[idx] = SlotState::Released;
                StepOutcome::Applied
            }
        }
    }

    fn drain(&mut self, max_wait_ticks: u64) -> StepOutcome {
        if !matches!(self.phase, Phase::Running | Phase::Prepared) {
            return refused(Refusal::WrongPhase);
        }
        self.phase = Phase::Draining;
        self.amp = AmpState::Muted;
        self.drain_deadline = Some(self.now.saturating_add(max_wait_ticks));
        self.amp_progress = 0;
        StepOutcome::Applied
    }

    fn tick(&mut self, ticks: u64) -> StepOutcome {
        self.now = self.now.saturating_add(ticks);
        if self.phase == Phase::Draining
            && let Some(deadline) = self.drain_deadline
            && self.now >= deadline
        {
            for slot in &mut self.slots {
                if *slot == SlotState::DmaOwned {
                    *slot = SlotState::Quarantined;
                }
            }
            self.phase = Phase::Faulted;
            self.drain_deadline = None;
            return StepOutcome::DrainTimedOut;
        }
        StepOutcome::Applied
    }

    fn flush_ack(&mut self) -> StepOutcome {
        if self.phase != Phase::Draining {
            return anomaly(AnomalyKind::FlushAckOutsideDrain);
        }
        for slot in &mut self.slots {
            if *slot == SlotState::DmaOwned {
                *slot = SlotState::Free;
            }
        }
        self.phase = Phase::Prepared;
        self.drain_deadline = None;
        StepOutcome::Applied
    }

    fn abort_mute(&mut self, ack: bool) -> StepOutcome {
        if self.phase == Phase::Closed {
            return refused(Refusal::WrongPhase);
        }
        self.amp_progress = 0;
        if ack {
            self.amp = AmpState::Muted;
            if self.phase != Phase::Faulted {
                self.phase = Phase::Draining;
            }
            StepOutcome::Applied
        } else {
            self.amp = AmpState::MuteFailed;
            self.phase = Phase::Faulted;
            self.drain_deadline = None;
            StepOutcome::MuteFailed
        }
    }

    fn device_reset(&mut self, ack: bool) -> StepOutcome {
        if self.owner.is_none() {
            return refused(Refusal::NotOwner);
        }
        if !ack {
            return anomaly(AnomalyKind::ResetUnacknowledged);
        }
        for slot in &mut self.slots {
            if matches!(*slot, SlotState::DmaOwned | SlotState::Quarantined) {
                *slot = SlotState::Free;
            }
        }
        if matches!(self.phase, Phase::Faulted | Phase::Draining) {
            self.phase = Phase::Prepared;
        }
        self.drain_deadline = None;
        self.amp_progress = 0;
        StepOutcome::Applied
    }

    fn device_loss(&mut self) -> StepOutcome {
        for slot in &mut self.slots {
            if *slot == SlotState::DmaOwned {
                *slot = SlotState::Quarantined;
            }
        }
        self.amp = AmpState::MuteFailed;
        self.phase = Phase::Faulted;
        self.drain_deadline = None;
        self.amp_progress = 0;
        StepOutcome::Applied
    }

    fn power_save(&mut self, enter: bool) -> StepOutcome {
        if enter {
            if self.owner.is_none() {
                return refused(Refusal::NotOwner);
            }
            if self.phase != Phase::Prepared {
                return refused(Refusal::WrongPhase);
            }
            if self.amp != AmpState::Muted {
                return refused(Refusal::PowerSaveNeedsMute);
            }
            if self.any_slot(SlotState::DmaOwned) || self.any_slot(SlotState::Quarantined) {
                return refused(Refusal::PowerSaveNeedsIdle);
            }
            self.phase = Phase::PowerSave;
        } else {
            if self.phase != Phase::PowerSave {
                return refused(Refusal::NotInPowerSave);
            }
            self.phase = Phase::Prepared;
        }
        StepOutcome::Applied
    }

    fn consumed_counter(&mut self, value: u32) -> StepOutcome {
        let delta = u64::from(value.wrapping_sub(self.last_counter));
        let in_flight = self.submitted_total.saturating_sub(self.consumed_total);
        if delta > in_flight {
            return anomaly(AnomalyKind::CounterExceedsInFlight);
        }
        self.consumed_total += delta;
        self.last_counter = value;
        StepOutcome::Applied
    }

    fn release_device(&mut self, owner: &str) -> StepOutcome {
        if self.owner.as_deref() != Some(owner) {
            return refused(Refusal::NotOwner);
        }
        if self.amp == AmpState::MuteFailed {
            return refused(Refusal::MuteNotAcknowledged);
        }
        if self.any_slot(SlotState::DmaOwned) {
            return refused(Refusal::DmaOwnedSlots);
        }
        if self.any_slot(SlotState::Quarantined) {
            return refused(Refusal::QuarantinedSlots);
        }
        if !matches!(self.phase, Phase::Closed | Phase::Prepared) {
            return refused(Refusal::WrongPhase);
        }
        self.owner = None;
        self.phase = Phase::Closed;
        self.amp = AmpState::Muted;
        self.slots.clear();
        self.drain_deadline = None;
        self.rate_hz = None;
        self.amp_progress = 0;
        self.clocks_on = false;
        self.submitted_total = 0;
        self.consumed_total = 0;
        self.last_counter = self.start_counter;
        StepOutcome::Applied
    }

    fn declare_duty(&mut self, duty: RadioDutyKind, owner: Option<DutyOwner>) -> StepOutcome {
        let state = match owner {
            Some(DutyOwner::KernelDriver) => DutyState::HeldKernelDriver,
            Some(DutyOwner::ChipFirmware) => DutyState::HeldChipFirmware,
            Some(DutyOwner::Daemon) => {
                if self.daemon_replaced {
                    DutyState::Orphaned
                } else {
                    DutyState::HeldDaemon
                }
            }
            None => DutyState::OwnerUnknown,
        };
        self.duties.insert(duty, DutyRecord { owner, state });
        StepOutcome::Applied
    }

    fn daemon_replaced(&mut self) -> StepOutcome {
        self.daemon_replaced = true;
        for record in self.duties.values_mut() {
            if record.state == DutyState::HeldDaemon {
                record.state = DutyState::Orphaned;
            }
        }
        StepOutcome::Applied
    }

    fn adopt_duty(&mut self, duty: RadioDutyKind) -> StepOutcome {
        let Some(record) = self.duties.get_mut(&duty) else {
            return refused(Refusal::DutyNotDeclared);
        };
        if record.owner != Some(DutyOwner::Daemon) {
            return refused(Refusal::NotDaemonOwned);
        }
        if !self.daemon_replaced {
            return refused(Refusal::DaemonNotReplaced);
        }
        record.state = DutyState::Adopted;
        StepOutcome::Applied
    }
}

/// One step of a trace: an event and the hand-written outcome it must produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    #[serde(rename = "ev")]
    pub event: SimEvent,
    pub expect: StepOutcome,
}

/// One trace case with its hand-written final state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCase {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub start_counter: u32,
    /// The channel map, rates and startup sequence the trace runs against, if it uses any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<SimModel>,
    pub steps: Vec<TraceStep>,
    #[serde(rename = "final")]
    pub expect_final: SimSnapshot,
}

impl TraceCase {
    /// A fresh simulator for this trace: with its model if it has one.
    #[must_use]
    pub fn sim(&self) -> DmaSim {
        match &self.model {
            Some(model) => DmaSim::with_model(self.start_counter, model.clone()),
            None => DmaSim::new(self.start_counter),
        }
    }
}

/// The committed case file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimCases {
    pub schema: String,
    pub cases: Vec<TraceCase>,
}

/// Where a replay first disagreed with the hand-written expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub case: String,
    /// The step index, or `None` for the final state.
    pub step: Option<usize>,
    pub expected: String,
    pub observed: String,
}

/// Replay a case and compare every step and the final state with the hand-written expectation.
pub fn replay(case: &TraceCase) -> Result<(), Mismatch> {
    let mut sim = case.sim();
    for (index, step) in case.steps.iter().enumerate() {
        let observed = sim.apply(&step.event);
        if observed != step.expect {
            return Err(Mismatch {
                case: case.id.clone(),
                step: Some(index),
                expected: format!("{:?}", step.expect),
                observed: format!("{observed:?}"),
            });
        }
    }
    let snapshot = sim.snapshot();
    if snapshot == case.expect_final {
        Ok(())
    } else {
        Err(Mismatch {
            case: case.id.clone(),
            step: None,
            expected: format!("{:?}", case.expect_final),
            observed: format!("{snapshot:?}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const CASES_JSON: &str = include_str!("../../../tests/e04/sim_cases.json");

    fn cases() -> SimCases {
        serde_json::from_str(CASES_JSON).unwrap()
    }

    fn label(outcome: &StepOutcome) -> String {
        match outcome {
            StepOutcome::Applied => "ok".to_string(),
            StepOutcome::Partial { .. } => "partial".to_string(),
            StepOutcome::Refused { reason } => format!("refused:{reason:?}"),
            StepOutcome::Anomaly { kind } => format!("anomaly:{kind:?}"),
            StepOutcome::DrainTimedOut => "drain_timed_out".to_string(),
            StepOutcome::MuteFailed => "mute_failed".to_string(),
        }
    }

    #[test]
    fn every_committed_case_replays_to_its_hand_written_outcomes() {
        let file = cases();
        assert_eq!(file.schema, SIM_CASES_SCHEMA);
        assert_eq!(file.cases.len(), 20, "a case was added or dropped");
        let ids: BTreeSet<&str> = file.cases.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids.len(), 20, "case ids must be unique");
        for case in &file.cases {
            if let Err(mismatch) = replay(case) {
                panic!("{mismatch:?}");
            }
        }
    }

    #[test]
    fn the_cases_exercise_every_refusal_anomaly_and_effect() {
        let mut seen = BTreeSet::new();
        for case in &cases().cases {
            for step in &case.steps {
                seen.insert(label(&step.expect));
            }
        }
        let expected: BTreeSet<String> = [
            "ok",
            "partial",
            "drain_timed_out",
            "mute_failed",
            "refused:Busy",
            "refused:NotOwner",
            "refused:WrongPhase",
            "refused:BadSlot",
            "refused:BadSlotCount",
            "refused:SlotNotFree",
            "refused:EmptySubmit",
            "refused:ReleaseWhileDmaOwned",
            "refused:SlotQuarantined",
            "refused:AlreadyReleased",
            "refused:MuteNotAcknowledged",
            "refused:DmaOwnedSlots",
            "refused:QuarantinedSlots",
            "refused:PowerSaveNeedsMute",
            "refused:PowerSaveNeedsIdle",
            "refused:NotInPowerSave",
            "refused:DutyNotDeclared",
            "refused:NotDaemonOwned",
            "refused:DaemonNotReplaced",
            "refused:NoModel",
            "refused:RateNotSupported",
            "refused:RateNotSet",
            "refused:AmpStepOutOfOrder",
            "refused:AmpStepTooEarly",
            "refused:AmpSequenceIncomplete",
            "refused:ClocksOffWhileUnmuted",
            "refused:PartialFrame",
            "anomaly:AcceptedPartialFrame",
            "anomaly:AcceptedMoreThanOffered",
            "anomaly:SpuriousCompletion",
            "anomaly:CompletionForQuarantinedSlot",
            "anomaly:CounterExceedsInFlight",
            "anomaly:ResetUnacknowledged",
            "anomaly:FlushAckOutsideDrain",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn replay_detects_a_changed_expectation_at_the_exact_step() {
        let file = cases();
        let mut case = file
            .cases
            .iter()
            .find(|c| c.id == "E04-SIM-002")
            .unwrap()
            .clone();
        // Pretend the model allowed the release while the driver owned the buffer.
        case.steps[4].expect = StepOutcome::Applied;
        let mismatch = replay(&case).unwrap_err();
        assert_eq!(mismatch.step, Some(4));
        assert_eq!(mismatch.case, "E04-SIM-002");
        // A wrong final state is caught as well.
        let mut case = file.cases[0].clone();
        case.expect_final.submitted += 1;
        assert_eq!(replay(&case).unwrap_err().step, None);
    }

    #[test]
    fn an_event_round_trips_through_json_in_the_documented_shape() {
        let event = SimEvent::Submit {
            slot: 2,
            frames: 48,
            accepted: 30,
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"type": "submit", "slot": 2, "frames": 48, "accepted": 30})
        );
        assert_eq!(serde_json::from_value::<SimEvent>(value).unwrap(), event);
        assert_eq!(
            serde_json::to_value(SimEvent::FlushAck).unwrap(),
            serde_json::json!({"type": "flush_ack"})
        );
        assert_eq!(
            serde_json::to_value(StepOutcome::Applied).unwrap(),
            serde_json::json!({"result": "ok"})
        );
        assert_eq!(
            serde_json::to_value(StepOutcome::Refused {
                reason: Refusal::ReleaseWhileDmaOwned
            })
            .unwrap(),
            serde_json::json!({"result": "refused", "reason": "release_while_dma_owned"})
        );
    }

    /// Small deterministic generator, so the sweep below needs no dependency and replays exactly.
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

    fn random_event(rng: &mut Xorshift) -> SimEvent {
        let slot = u16::try_from(rng.below(5)).unwrap();
        let owner = if rng.below(2) == 0 { "a" } else { "b" }.to_string();
        let duty = [
            RadioDutyKind::PowerSave,
            RadioDutyKind::Roam,
            RadioDutyKind::Congestion,
        ][usize::try_from(rng.below(3)).unwrap()];
        match rng.below(21) {
            0 | 1 => SimEvent::Acquire { owner },
            2 | 3 => SimEvent::Prepare {
                slots: u16::try_from(rng.below(5)).unwrap(),
            },
            4 | 5 => SimEvent::Start,
            6..=9 => {
                let frames = u32::try_from(rng.below(5)).unwrap();
                SimEvent::Submit {
                    slot,
                    frames,
                    accepted: u32::try_from(rng.below(6)).unwrap(),
                }
            }
            10 => SimEvent::Completion { slot },
            11 => SimEvent::ReleaseSlot { slot },
            12 => SimEvent::Drain {
                max_wait_ticks: rng.below(4),
            },
            13 => SimEvent::Tick {
                ticks: rng.below(4),
            },
            14 => SimEvent::FlushAck,
            15 => SimEvent::AbortMute {
                ack: rng.below(2) == 0,
            },
            16 => SimEvent::DeviceReset {
                ack: rng.below(3) != 0,
            },
            17 => {
                if rng.below(8) == 0 {
                    SimEvent::DeviceLoss
                } else {
                    SimEvent::PowerSave {
                        enter: rng.below(2) == 0,
                    }
                }
            }
            18 => SimEvent::ConsumedCounter {
                value: u32::try_from(rng.below(12)).unwrap().wrapping_sub(6),
            },
            19 => SimEvent::ReleaseDevice { owner },
            _ => match rng.below(3) {
                0 => SimEvent::DeclareDuty {
                    duty,
                    owner: Some(DutyOwner::Daemon),
                },
                1 => SimEvent::DaemonReplaced,
                _ => SimEvent::AdoptDuty { duty },
            },
        }
    }

    #[test]
    fn invariants_hold_over_a_deterministic_random_sweep() {
        let mut applied_release_device = 0usize;
        let mut quarantined_seen = 0usize;
        for seed in 1..=400u64 {
            let mut rng = Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut sim = DmaSim::new(u32::try_from(seed % 7).unwrap().wrapping_sub(3));
            for _ in 0..80 {
                let event = random_event(&mut rng);
                let before = sim.snapshot();
                let outcome = sim.apply(&event);
                let after = sim.snapshot();

                // Exclusive ownership: the owner changes only by acquire (from none) or release.
                if before.owner != after.owner {
                    let acquired = before.owner.is_none()
                        && matches!(event, SimEvent::Acquire { .. })
                        && outcome == StepOutcome::Applied;
                    let released = after.owner.is_none()
                        && matches!(event, SimEvent::ReleaseDevice { .. })
                        && outcome == StepOutcome::Applied;
                    assert!(
                        acquired || released,
                        "seed {seed}: owner changed by {event:?}"
                    );
                }

                // A slot the driver owns is never released, and leaves DMA ownership only through a
                // completion, a flush acknowledgment, an acknowledged reset, or by being quarantined.
                for (index, state) in before.slots.iter().enumerate() {
                    let next = after.slots.get(index).copied();
                    match state {
                        SlotState::DmaOwned => {
                            let next = next.unwrap_or_else(|| {
                                panic!("seed {seed}: DMA-owned slot vanished on {event:?}")
                            });
                            let allowed = match next {
                                SlotState::DmaOwned => true,
                                SlotState::Free => matches!(
                                    event,
                                    SimEvent::Completion { .. }
                                        | SimEvent::FlushAck
                                        | SimEvent::DeviceReset { ack: true }
                                ),
                                SlotState::Quarantined => {
                                    matches!(event, SimEvent::Tick { .. } | SimEvent::DeviceLoss)
                                }
                                SlotState::Released => false,
                            };
                            assert!(allowed, "seed {seed}: DmaOwned -> {next:?} on {event:?}");
                        }
                        SlotState::Quarantined => {
                            quarantined_seen += 1;
                            let next = next.unwrap_or_else(|| {
                                panic!("seed {seed}: quarantined slot vanished on {event:?}")
                            });
                            let allowed = match next {
                                SlotState::Quarantined => true,
                                SlotState::Free => {
                                    matches!(event, SimEvent::DeviceReset { ack: true })
                                }
                                _ => false,
                            };
                            assert!(allowed, "seed {seed}: Quarantined -> {next:?} on {event:?}");
                        }
                        _ => {}
                    }
                }

                // Releasing the device needs every slot accounted for.
                if matches!(event, SimEvent::ReleaseDevice { .. })
                    && outcome == StepOutcome::Applied
                {
                    applied_release_device += 1;
                    assert!(
                        before
                            .slots
                            .iter()
                            .all(|s| !matches!(s, SlotState::DmaOwned | SlotState::Quarantined)),
                        "seed {seed}: device released with slots outstanding"
                    );
                    assert_ne!(before.amp, AmpState::MuteFailed, "seed {seed}");
                }

                // Counters: consumed never exceeds what the driver accepted.
                assert!(after.consumed <= after.submitted, "seed {seed}: {after:?}");

                // An unmuted amplifier means a running device.
                if after.amp == AmpState::Unmuted {
                    assert_eq!(after.phase, Phase::Running, "seed {seed}: {event:?}");
                }
            }
        }
        // The sweep must reach the interesting states, or it proves nothing.
        assert!(
            applied_release_device > 0,
            "no device release was ever applied"
        );
        assert!(quarantined_seen > 0, "no slot was ever quarantined");
    }
}
