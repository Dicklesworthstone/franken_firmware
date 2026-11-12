//! The driver boundary and a deterministic fake device (`P04` / `ffw-0bh`).
//!
//! [`DeviceBackend`] is everything the session may ask of a driver. Every answer is untrusted: the
//! session validates lengths, counts, slot numbers and generations before it believes any of them.
//!
//! [`FakeBackend`] is a **model**, not a driver. It is deterministic (a virtual clock, scripted
//! faults, no randomness inside it) and it is kept apart from any real-device qualification: its
//! [`Provenance`] is `Fake`, so the session labels every receipt as model evidence, and a real
//! device ledger is a separate artifact owned by the human lane. Passing against it shows the
//! adapter logic, not that any board behaves this way.
//!
//! The fake plays the kernel honestly. A retained submit gives it a [`KernelView`], a non-owning
//! reference that does not keep storage alive. When it "reads" the buffer (to complete it, or when a
//! flush or reset settles everything) it records a violation if the storage was freed
//! (`use_after_free`) or changed while the kernel owned it (`modified_while_owned`). A test that
//! ends with both at zero has shown the HAL never gave the kernel's storage back early.

use crate::abi::{DeviceEvent, EVENT_LEN, RawGeometry, encode_event, encode_geometry};
use crate::slots::{KernelRead, KernelView};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// What is behind the trait. Only `Fake` can be opened without a hardware-eligible contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Fake,
    Real,
}

/// How audio reaches the driver, and therefore who owns the buffer afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbiKind {
    /// The driver copies the caller's bytes before the call returns, so the caller's buffer is free
    /// at once and no lease is needed. **Only with explicit evidence** that the copy is synchronous;
    /// a blank `evidence` is refused when the session opens.
    CopyingWrite { evidence: String },
    /// The driver keeps a reference to the buffer until it reports completion. The buffer stays
    /// owned by the session's slot table, and the kernel only ever holds a [`KernelView`].
    RetainedBuffer,
}

/// A driver operation, named for fault records and injected failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Capabilities,
    SetMute,
    Start,
    Write,
    SubmitRetained,
    PollEvent,
    RequestFlush,
    Reset,
}

/// A failed driver call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DriverError {
    #[error("driver returned errno {0}")]
    Errno(i32),
    /// The device node is gone. Whatever it was reading may still be in flight.
    #[error("device is gone")]
    Gone,
}

/// Whether the board has local buttons, LEDs or fault events the adapter can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalEventCapability {
    /// Explicit absence. Nothing is inferred from strings in a driver (see `docs/contracts/e04.md`).
    Unsupported {
        reason: String,
    },
    Declared {
        abi_evidence: String,
    },
}

/// The answer to the capability query. Only `geometry` is wire bytes; the rest is declared by the
/// adapter that knows its driver, and `None` means the adapter cannot promise it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapabilities {
    pub geometry: Vec<u8>,
    /// Worst-case ticks from a stop request to an acknowledged stop. `None` is unknown.
    pub stop_deadline_ticks: Option<u64>,
    /// Fewest ticks ahead of the output cursor a block must be submitted. `None` is unknown.
    pub min_submission_lead_ticks: Option<u64>,
    /// Worst-case error of the consumed-frame count. `None` is unknown.
    pub position_error_frames: Option<u32>,
    pub local_events: LocalEventCapability,
}

/// Everything the session asks of a driver.
pub trait DeviceBackend {
    fn provenance(&self) -> Provenance;
    fn abi(&self) -> AbiKind;
    /// Query only. Must not change audio state.
    fn capabilities(&mut self) -> Result<RawCapabilities, DriverError>;
    /// Returns whether the device acknowledged the request.
    fn set_mute(&mut self, muted: bool) -> Result<bool, DriverError>;
    fn start(&mut self) -> Result<(), DriverError>;
    /// Copying ABI: how many bytes the device took. The caller's buffer is free afterwards.
    fn write(&mut self, bytes: &[u8]) -> Result<usize, DriverError>;
    /// Retained ABI: how many bytes the device accepted. If it accepted any, the device keeps
    /// reading `view` until it reports the slot complete.
    fn submit_retained(
        &mut self,
        slot: u16,
        generation: u32,
        view: KernelView,
        len: usize,
    ) -> Result<usize, DriverError>;
    /// One raw event record, if any. Untrusted bytes; the session decodes and validates them.
    ///
    /// The device writes the record into `record`, a buffer the caller owns and reuses, so a backend allocates
    /// nothing per event. The value returned is the length of the record the device **had**: `Some(EVENT_LEN)` for
    /// a well-formed one. A longer record is reported with its full length and `record` holds its first
    /// `EVENT_LEN` bytes; a shorter one is reported with its length and the rest of `record` is not meaningful.
    /// Either way the session refuses a record whose length is not `EVENT_LEN`, by that length: a record is never
    /// cut to fit and then read.
    fn poll_event(&mut self, record: &mut [u8; EVENT_LEN]) -> Result<Option<usize>, DriverError>;
    fn request_flush(&mut self) -> Result<(), DriverError>;
    /// Whether an acknowledged reset also discards every previously accepted
    /// playback byte, including copied device FIFO data. This is stronger than
    /// releasing retained buffer custody. Adapters may return true only when
    /// that property is established and the session has exclusive playback
    /// submission authority until start: no other handle or autonomous source
    /// may enqueue audio after reset. Unknown defaults false.
    fn reset_ack_discards_playback(&self) -> bool {
        false
    }
    /// Returns whether the device acknowledged a full reset. An ACK alone
    /// does not imply the stronger playback-discard property above.
    fn reset(&mut self) -> Result<bool, DriverError>;
    /// Let one tick pass: block for it on a real device, advance the virtual clock on the fake.
    fn wait_tick(&mut self);
}

/// Configuration of the fake. `retained()` and `copying()` give small, working defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeConfig {
    pub abi: AbiKind,
    pub geometry: RawGeometry,
    /// Replaces the geometry bytes, to model a malformed answer.
    pub geometry_override: Option<Vec<u8>>,
    pub stop_deadline_ticks: Option<u64>,
    pub min_submission_lead_ticks: Option<u64>,
    pub position_error_frames: Option<u32>,
    /// Ticks from a retained submit to its completion.
    pub completion_delay_ticks: u64,
    /// Ticks from a flush request to its acknowledgment. `None` means it never acknowledges.
    pub flush_ack_delay_ticks: Option<u64>,
    pub mute_ack: bool,
    pub unmute_ack: bool,
    pub reset_ack: bool,
}

impl FakeConfig {
    /// A retained-buffer device: 4 slots of 4 frames, 2 channels of 2 bytes (16-byte blocks).
    #[must_use]
    pub fn retained() -> Self {
        Self {
            abi: AbiKind::RetainedBuffer,
            geometry: RawGeometry {
                ring_depth: 4,
                frames_per_block: 4,
                channels: 2,
                bytes_per_sample: 2,
            },
            geometry_override: None,
            stop_deadline_ticks: Some(8),
            min_submission_lead_ticks: Some(1),
            position_error_frames: Some(0),
            completion_delay_ticks: 2,
            flush_ack_delay_ticks: Some(1),
            mute_ack: true,
            unmute_ack: true,
            reset_ack: true,
        }
    }

    /// The same device with a copying-write ABI. The evidence names the fake's own construction,
    /// which is model evidence only.
    #[must_use]
    pub fn copying() -> Self {
        Self {
            abi: AbiKind::CopyingWrite {
                evidence: "model: the fake copies synchronously by construction".to_string(),
            },
            ..Self::retained()
        }
    }
}

/// One call the fake received, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCall {
    Capabilities,
    SetMute(bool),
    Start,
    Write(usize),
    SubmitRetained {
        slot: u16,
        generation: u32,
        len: usize,
    },
    RequestFlush,
    Reset,
}

const CALL_LOG_CAP: usize = 1024;

#[derive(Debug)]
struct Pending {
    slot: u16,
    generation: u32,
    view: KernelView,
    snapshot: Vec<u8>,
    due: u64,
}

/// One event record as the fake device holds it: the length the device "had" and the first [`EVENT_LEN`] bytes of
/// it. It is a small value, so queuing it, handing it over and dropping it allocate nothing per event.
#[derive(Debug, Clone, Copy)]
struct RawRecord {
    len: usize,
    head: [u8; EVENT_LEN],
}

impl RawRecord {
    fn of(event: &DeviceEvent) -> Self {
        Self {
            len: EVENT_LEN,
            head: encode_event(event),
        }
    }

    /// Whatever bytes a test says the device sent: a short or a long record keeps its true length, and its first
    /// `EVENT_LEN` bytes (zero-filled if there are fewer).
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut head = [0u8; EVENT_LEN];
        let kept = bytes.len().min(EVENT_LEN);
        head[..kept].copy_from_slice(&bytes[..kept]);
        Self {
            len: bytes.len(),
            head,
        }
    }
}

#[derive(Debug)]
struct FakeState {
    cfg: FakeConfig,
    tick: u64,
    pending: Vec<Pending>,
    events: VecDeque<RawRecord>,
    flush_due: Option<u64>,
    accept_limit: Option<usize>,
    lose_completions: bool,
    fail_next: VecDeque<(Op, DriverError)>,
    gone: bool,
    calls: Vec<FakeCall>,
    use_after_free: u32,
    modified_while_owned: u32,
    written_bytes: usize,
    /// How many submissions to keep a copy of (0 keeps none).
    capture_limit: usize,
    /// What the device accepted from each submission, oldest first.
    captured: Vec<Vec<u8>>,
}

impl FakeState {
    fn record(&mut self, call: FakeCall) {
        if self.calls.len() < CALL_LOG_CAP {
            self.calls.push(call);
        }
    }

    /// An injected failure for `op` fires once.
    fn injected(&mut self, op: Op) -> Result<(), DriverError> {
        let index = self.fail_next.iter().position(|(o, _)| *o == op);
        if let Some(index) = index
            && let Some((_, error)) = self.fail_next.remove(index)
        {
            return Err(error);
        }
        Ok(())
    }

    /// A vanished device refuses everything; an injected failure fires once.
    fn gate(&mut self, op: Op) -> Result<(), DriverError> {
        if self.gone {
            return Err(DriverError::Gone);
        }
        self.injected(op)
    }

    /// The kernel reads a buffer it was handed. Freed or changed storage is a violation.
    fn kernel_read_check(&mut self, p: &Pending) {
        match p.view.read() {
            KernelRead::Freed => self.use_after_free += 1,
            KernelRead::Alive(bytes) => {
                if bytes != p.snapshot {
                    self.modified_while_owned += 1;
                }
            }
        }
    }

    /// The kernel lets go of everything it held (after a flush or a reset).
    fn settle_all(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for p in &pending {
            self.kernel_read_check(p);
        }
    }

    fn step(&mut self) {
        let now = self.tick;
        if !self.lose_completions {
            let mut i = 0;
            while i < self.pending.len() {
                if self.pending[i].due <= now {
                    let p = self.pending.remove(i);
                    self.kernel_read_check(&p);
                    let event = DeviceEvent::Completed {
                        slot: p.slot,
                        generation: p.generation,
                    };
                    self.events.push_back(RawRecord::of(&event));
                } else {
                    i += 1;
                }
            }
        }
        if let Some(due) = self.flush_due
            && due <= now
        {
            self.settle_all();
            self.events.push_back(RawRecord::of(&DeviceEvent::FlushAck));
            self.flush_due = None;
        }
    }
}

/// The deterministic fake device. Move it into a session; keep the [`FakeProbe`] to script it and
/// to read what the "kernel" saw.
#[derive(Debug)]
pub struct FakeBackend {
    state: Arc<Mutex<FakeState>>,
}

/// A handle to the same fake, kept by the test after the backend moves into a session.
#[derive(Debug, Clone)]
pub struct FakeProbe {
    state: Arc<Mutex<FakeState>>,
}

impl FakeBackend {
    #[must_use]
    pub fn new(cfg: FakeConfig) -> (Self, FakeProbe) {
        let state = Arc::new(Mutex::new(FakeState {
            cfg,
            tick: 0,
            pending: Vec::new(),
            events: VecDeque::new(),
            flush_due: None,
            accept_limit: None,
            lose_completions: false,
            fail_next: VecDeque::new(),
            gone: false,
            calls: Vec::new(),
            use_after_free: 0,
            modified_while_owned: 0,
            written_bytes: 0,
            capture_limit: 0,
            captured: Vec::new(),
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            FakeProbe { state },
        )
    }

    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl DeviceBackend for FakeBackend {
    fn provenance(&self) -> Provenance {
        Provenance::Fake
    }

    fn abi(&self) -> AbiKind {
        self.lock().cfg.abi.clone()
    }

    fn capabilities(&mut self) -> Result<RawCapabilities, DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::Capabilities);
        s.gate(Op::Capabilities)?;
        let geometry = match &s.cfg.geometry_override {
            Some(bytes) => bytes.clone(),
            None => encode_geometry(&s.cfg.geometry).to_vec(),
        };
        Ok(RawCapabilities {
            geometry,
            stop_deadline_ticks: s.cfg.stop_deadline_ticks,
            min_submission_lead_ticks: s.cfg.min_submission_lead_ticks,
            position_error_frames: s.cfg.position_error_frames,
            local_events: LocalEventCapability::Unsupported {
                reason: "the fake declares no local event channel".to_string(),
            },
        })
    }

    fn set_mute(&mut self, muted: bool) -> Result<bool, DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::SetMute(muted));
        s.gate(Op::SetMute)?;
        Ok(if muted {
            s.cfg.mute_ack
        } else {
            s.cfg.unmute_ack
        })
    }

    fn start(&mut self) -> Result<(), DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::Start);
        s.gate(Op::Start)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::Write(bytes.len()));
        s.gate(Op::Write)?;
        let accepted = s.accept_limit.map_or(bytes.len(), |l| l.min(bytes.len()));
        s.written_bytes += accepted;
        Ok(accepted)
    }

    fn submit_retained(
        &mut self,
        slot: u16,
        generation: u32,
        view: KernelView,
        len: usize,
    ) -> Result<usize, DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::SubmitRetained {
            slot,
            generation,
            len,
        });
        s.gate(Op::SubmitRetained)?;
        let accepted = s.accept_limit.map_or(len, |l| l.min(len));
        if accepted > 0 {
            let snapshot = match view.read() {
                KernelRead::Alive(bytes) => bytes,
                KernelRead::Freed => {
                    s.use_after_free += 1;
                    Vec::new()
                }
            };
            if s.captured.len() < s.capture_limit {
                let kept = snapshot.get(..accepted).unwrap_or(&snapshot).to_vec();
                s.captured.push(kept);
            }
            let due = s.tick + s.cfg.completion_delay_ticks;
            s.pending.push(Pending {
                slot,
                generation,
                view,
                snapshot,
                due,
            });
        }
        Ok(accepted)
    }

    fn poll_event(&mut self, record: &mut [u8; EVENT_LEN]) -> Result<Option<usize>, DriverError> {
        let mut s = self.lock();
        s.injected(Op::PollEvent)?;
        // Events the device queued before it vanished (its own loss announcement) still drain.
        if let Some(queued) = s.events.pop_front() {
            *record = queued.head;
            return Ok(Some(queued.len));
        }
        if s.gone {
            return Err(DriverError::Gone);
        }
        Ok(None)
    }

    fn request_flush(&mut self) -> Result<(), DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::RequestFlush);
        s.gate(Op::RequestFlush)?;
        let tick = s.tick;
        let due = s.cfg.flush_ack_delay_ticks.map(|d| tick + d);
        s.flush_due = due;
        Ok(())
    }

    fn reset(&mut self) -> Result<bool, DriverError> {
        let mut s = self.lock();
        s.record(FakeCall::Reset);
        s.gate(Op::Reset)?;
        if s.cfg.reset_ack {
            s.settle_all();
            s.flush_due = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn wait_tick(&mut self) {
        let mut s = self.lock();
        s.tick += 1;
        s.step();
    }
}

impl FakeProbe {
    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue raw event bytes exactly as given, to model a malformed or forged record.
    pub fn queue_raw_event(&self, bytes: Vec<u8>) {
        self.lock().events.push_back(RawRecord::from_bytes(&bytes));
    }

    pub fn queue_event(&self, event: DeviceEvent) {
        self.lock().events.push_back(RawRecord::of(&event));
    }

    /// Cap how many bytes a write or retained submit accepts (a short write).
    pub fn set_accept_limit(&self, limit: Option<usize>) {
        self.lock().accept_limit = limit;
    }

    /// Keep a copy of what the device accepts from the next `limit` retained submissions, so a test
    /// can compare the bytes the device was given with what should have been produced.
    pub fn capture_submissions(&self, limit: usize) {
        self.lock().capture_limit = limit;
    }

    /// The accepted part of each captured submission, oldest first.
    #[must_use]
    pub fn captured_submissions(&self) -> Vec<Vec<u8>> {
        self.lock().captured.clone()
    }

    /// While set, retained completions are never delivered (lost completions).
    pub fn set_lose_completions(&self, lose: bool) {
        self.lock().lose_completions = lose;
    }

    /// Make the next call of `op` fail once with `error`.
    pub fn fail_next(&self, op: Op, error: DriverError) {
        self.lock().fail_next.push_back((op, error));
    }

    /// The device disappears. It announces it, then refuses every call. What it held stays in
    /// flight: nothing says the kernel stopped reading.
    pub fn lose_device(&self) {
        let mut s = self.lock();
        s.gone = true;
        s.events.push_back(RawRecord::of(&DeviceEvent::DeviceLost));
    }

    #[must_use]
    pub fn use_after_free(&self) -> u32 {
        self.lock().use_after_free
    }

    #[must_use]
    pub fn modified_while_owned(&self) -> u32 {
        self.lock().modified_while_owned
    }

    /// Buffers the kernel still holds.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.lock().pending.len()
    }

    /// The (slot, generation) of every buffer the kernel still holds.
    #[must_use]
    pub fn pending_slots(&self) -> Vec<(u16, u32)> {
        self.lock()
            .pending
            .iter()
            .map(|p| (p.slot, p.generation))
            .collect()
    }

    /// Let the kernel touch every buffer it still holds, without completing any. Returns how many
    /// are still readable and how many were freed under it.
    #[must_use]
    pub fn kernel_touch_pending(&self) -> (usize, usize) {
        let s = self.lock();
        let mut alive = 0;
        let mut freed = 0;
        for p in &s.pending {
            match p.view.read() {
                KernelRead::Alive(_) => alive += 1,
                KernelRead::Freed => freed += 1,
            }
        }
        (alive, freed)
    }

    #[must_use]
    pub fn calls(&self) -> Vec<FakeCall> {
        self.lock().calls.clone()
    }

    #[must_use]
    pub fn tick(&self) -> u64 {
        self.lock().tick
    }

    #[must_use]
    pub fn written_bytes(&self) -> usize {
        self.lock().written_bytes
    }
}
