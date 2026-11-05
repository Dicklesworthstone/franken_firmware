//! Local button, LED and fault events (`P04` / `ffw-0bh`, the fresh-eyes clause).
//!
//! What this is and is not. It is the adapter LOGIC for a device that reports local events as a
//! stream of fixed-size records: reassembling partial reads, resynchronising after garbage, refusing
//! malformed records, debouncing buttons, bounding what it holds, and degrading honestly when the
//! device goes away. The record layout here is a **harness model**. No retained driver is known to
//! emit it, and E04 has not decoded the audio-control device, so nothing is inferred from strings in
//! the driver. A pass against the fake source shows this logic and says nothing about any board.
//!
//! * **Capability is explicit.** [`LocalEventChannel::open`] takes the declared
//!   [`LocalEventCapability`]. `Unsupported` is refused with its reason (no event is ever invented),
//!   and `Declared` needs non-blank evidence for the ABI, as a copying write does.
//! * **Bounded.** One queue of at most `queue_cap` events, at most 7 buffered bytes of a torn
//!   record, and at most [`MAX_CHUNKS_PER_PUMP`] reads of at most [`MAX_CHUNK_BYTES`] per pump.
//!   Button events are dropped (counted) before a fault ever is; a fault is lost only when the queue
//!   holds nothing but faults, and that marks the evidence incomplete.
//! * **Untrusted device clock.** Debounce runs on the channel's own tick, never on the device's
//!   timestamp, which is carried as information only.
//! * **Device loss is not "released".** When the device is gone every button becomes `Unknown`, one
//!   `Lost` event is queued, and nothing more is read.
//!
//! G02 owns what a press means and UX01 owns how status is shown; this layer only delivers events.

use crate::backend::{DriverError, LocalEventCapability};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Length of one event record.
pub const RECORD_LEN: usize = 8;
/// First byte of every record. It lets the decoder find the next record after garbage.
pub const SYNC: u8 = 0xA5;
/// Largest chunk accepted from one read.
pub const MAX_CHUNK_BYTES: usize = 256;
/// Most reads handled by one [`LocalEventChannel::pump`].
pub const MAX_CHUNKS_PER_PUMP: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEventKind {
    ButtonDown,
    ButtonUp,
    LedFault,
    DeviceFault,
}

impl LocalEventKind {
    const fn code(self) -> u8 {
        match self {
            Self::ButtonDown => 1,
            Self::ButtonUp => 2,
            Self::LedFault => 3,
            Self::DeviceFault => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ButtonDown),
            2 => Some(Self::ButtonUp),
            3 => Some(Self::LedFault),
            4 => Some(Self::DeviceFault),
            _ => None,
        }
    }
}

/// One decoded record. `device_ticks` is the device's own clock: information, never trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEvent {
    pub kind: LocalEventKind,
    pub id: u8,
    pub device_ticks: u32,
}

/// Why one record was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum RecordError {
    #[error("record is {actual} byte(s), expected 8")]
    Length { actual: usize },
    #[error("bad sync byte {0:#04x}")]
    BadSync(u8),
    #[error("unknown event kind {0}")]
    UnknownKind(u8),
    #[error("nonzero flags {0:#04x}")]
    FlagsNonZero(u8),
}

/// Decode one record: `[SYNC, kind, id, flags(0), ticks as 4 big-endian bytes]`.
pub fn decode_record(rec: &[u8]) -> Result<LocalEvent, RecordError> {
    if rec.len() != RECORD_LEN {
        return Err(RecordError::Length { actual: rec.len() });
    }
    if rec[0] != SYNC {
        return Err(RecordError::BadSync(rec[0]));
    }
    let Some(kind) = LocalEventKind::from_code(rec[1]) else {
        return Err(RecordError::UnknownKind(rec[1]));
    };
    if rec[3] != 0 {
        return Err(RecordError::FlagsNonZero(rec[3]));
    }
    Ok(LocalEvent {
        kind,
        id: rec[2],
        device_ticks: u32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]]),
    })
}

#[must_use]
pub fn encode_record(event: &LocalEvent) -> [u8; RECORD_LEN] {
    let t = event.device_ticks.to_be_bytes();
    [SYNC, event.kind.code(), event.id, 0, t[0], t[1], t[2], t[3]]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonState {
    Up,
    Down,
    /// Never seen, or the channel was lost or faulted. Not the same as `Up`.
    Unknown,
}

/// What the channel delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelEvent {
    /// A button's debounced state changed. `at` is the channel tick at which it settled.
    ButtonChanged {
        id: u8,
        state: ButtonState,
        at: u64,
    },
    LedFault {
        id: u8,
        at: u64,
    },
    DeviceFault {
        id: u8,
        at: u64,
    },
    /// The device is gone. Delivered once.
    Lost {
        at: u64,
    },
    /// Too many bad records in a row: the channel is no longer trusted. Delivered once per fault.
    Faulted {
        at: u64,
    },
}

impl ChannelEvent {
    /// Everything except a button change must not be lost silently.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        !matches!(self, Self::ButtonChanged { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    Open,
    /// Reset-able: too many consecutive bad records.
    Faulted,
    /// Not recoverable here: the device is gone.
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("local events are not supported: {reason}")]
    Unsupported { reason: String },
    #[error("a declared event ABI needs stated evidence")]
    EvidenceMissing,
    #[error("bad channel configuration")]
    BadConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventChannelConfig {
    pub queue_cap: usize,
    /// Ticks a button edge must stay unchanged before it is reported.
    pub debounce_ticks: u64,
    pub max_buttons: u8,
    pub max_leds: u8,
    /// Consecutive bad records or reads that fault the channel.
    pub malformed_limit: u32,
    /// Ticks a half-received record may wait before it is discarded.
    pub torn_timeout_ticks: u64,
}

impl EventChannelConfig {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            queue_cap: 4,
            debounce_ticks: 3,
            max_buttons: 4,
            max_leds: 2,
            malformed_limit: 3,
            torn_timeout_ticks: 4,
        }
    }

    const fn valid(&self) -> bool {
        self.queue_cap > 0 && self.max_buttons > 0 && self.malformed_limit > 0
    }
}

/// Exact accounting. Nothing is dropped without being counted here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventStats {
    /// Records that decoded.
    pub parsed: u64,
    /// Parsed records that were in range and accepted.
    pub accepted: u64,
    /// Bad records, garbage runs and out-of-range ids.
    pub malformed: u64,
    pub resync_skipped_bytes: u64,
    /// Half-received records discarded after the torn timeout.
    pub torn: u64,
    pub oversize_chunks: u64,
    pub source_errors: u64,
    /// Button edges that restarted a pending change.
    pub bounce_suppressed: u64,
    /// Button edges that repeated the state already pending.
    pub duplicate_edges: u64,
    pub dropped_button_events: u64,
    pub evicted_button_events: u64,
    pub lost_critical: u64,
    pub delivered: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PumpReport {
    pub chunks: usize,
}

/// Where raw event bytes come from.
pub trait LocalEventSource {
    /// One read: a chunk of bytes (possibly a partial record, several records, or garbage), or
    /// nothing right now.
    fn read_raw(&mut self) -> Result<Option<Vec<u8>>, DriverError>;
}

#[derive(Debug, Clone, Copy)]
struct Button {
    reported: ButtonState,
    raw: ButtonState,
    raw_since: u64,
}

impl Button {
    const fn unknown() -> Self {
        Self {
            reported: ButtonState::Unknown,
            raw: ButtonState::Unknown,
            raw_since: 0,
        }
    }
}

/// Adapter state for one device's local events.
#[derive(Debug)]
pub struct LocalEventChannel<S: LocalEventSource> {
    source: S,
    cfg: EventChannelConfig,
    state: ChannelState,
    partial: Vec<u8>,
    partial_since: Option<u64>,
    consecutive_bad: u32,
    buttons: Vec<Button>,
    queue: VecDeque<ChannelEvent>,
    stats: EventStats,
}

impl<S: LocalEventSource> LocalEventChannel<S> {
    /// Open the channel. `Unsupported` is refused with its reason, and a declared ABI needs stated
    /// evidence. The source is not read before this succeeds.
    pub fn open(
        capability: &LocalEventCapability,
        source: S,
        cfg: EventChannelConfig,
    ) -> Result<Self, OpenError> {
        match capability {
            LocalEventCapability::Unsupported { reason } => {
                return Err(OpenError::Unsupported {
                    reason: reason.clone(),
                });
            }
            LocalEventCapability::Declared { abi_evidence } => {
                if abi_evidence.trim().is_empty() {
                    return Err(OpenError::EvidenceMissing);
                }
            }
        }
        if !cfg.valid() {
            return Err(OpenError::BadConfig);
        }
        Ok(Self {
            source,
            cfg,
            state: ChannelState::Open,
            partial: Vec::new(),
            partial_since: None,
            consecutive_bad: 0,
            buttons: vec![Button::unknown(); usize::from(cfg.max_buttons)],
            queue: VecDeque::new(),
            stats: EventStats::default(),
        })
    }

    #[must_use]
    pub const fn channel_state(&self) -> ChannelState {
        self.state
    }

    #[must_use]
    pub const fn stats(&self) -> EventStats {
        self.stats
    }

    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Bytes of a half-received record being held (always fewer than a whole record).
    #[must_use]
    pub fn partial_len(&self) -> usize {
        self.partial.len()
    }

    /// False once a critical event had to be dropped.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.stats.lost_critical == 0
    }

    #[must_use]
    pub fn button_state(&self, id: u8) -> ButtonState {
        self.buttons
            .get(usize::from(id))
            .map_or(ButtonState::Unknown, |b| b.reported)
    }

    /// The next delivered event, oldest first.
    pub fn take(&mut self) -> Option<ChannelEvent> {
        let event = self.queue.pop_front();
        if event.is_some() {
            self.stats.delivered += 1;
        }
        event
    }

    /// Recover from `Faulted`. A lost device cannot be recovered here. Button states stay `Unknown`
    /// until a fresh edge settles.
    pub fn reset(&mut self) -> bool {
        if self.state != ChannelState::Faulted {
            return false;
        }
        self.state = ChannelState::Open;
        self.consecutive_bad = 0;
        self.partial.clear();
        self.partial_since = None;
        true
    }

    /// Read what the device has, decode it, debounce it. `now` is the channel's own tick.
    pub fn pump(&mut self, now: u64) -> PumpReport {
        let mut report = PumpReport::default();
        if self.state != ChannelState::Open {
            return report;
        }
        self.discard_torn(now);
        for _ in 0..MAX_CHUNKS_PER_PUMP {
            match self.source.read_raw() {
                Ok(Some(chunk)) => {
                    report.chunks += 1;
                    if chunk.len() > MAX_CHUNK_BYTES {
                        self.stats.oversize_chunks += 1;
                        self.bump_bad(now);
                    } else {
                        self.feed(&chunk, now);
                    }
                    if self.state != ChannelState::Open {
                        break;
                    }
                }
                Ok(None) => break,
                Err(DriverError::Gone) => {
                    self.lose(now);
                    break;
                }
                Err(DriverError::Errno(_)) => {
                    self.stats.source_errors += 1;
                    self.bump_bad(now);
                    break;
                }
            }
        }
        if self.state == ChannelState::Open {
            self.settle(now);
        }
        report
    }

    fn discard_torn(&mut self, now: u64) {
        if let Some(since) = self.partial_since
            && !self.partial.is_empty()
            && now.saturating_sub(since) >= self.cfg.torn_timeout_ticks
        {
            self.partial.clear();
            self.partial_since = None;
            self.stats.torn += 1;
        }
    }

    fn feed(&mut self, chunk: &[u8], now: u64) {
        self.partial.extend_from_slice(chunk);
        let mut consumed = false;
        loop {
            if self.state != ChannelState::Open {
                self.partial.clear();
                break;
            }
            // Drop garbage up to the next sync byte. A whole garbage run counts as one bad event.
            let skip = self
                .partial
                .iter()
                .position(|&b| b == SYNC)
                .unwrap_or(self.partial.len());
            if skip > 0 {
                self.partial.drain(..skip);
                self.stats.resync_skipped_bytes = self
                    .stats
                    .resync_skipped_bytes
                    .saturating_add(u64::try_from(skip).unwrap_or(u64::MAX));
                self.stats.malformed += 1;
                self.bump_bad(now);
                continue;
            }
            if self.partial.len() < RECORD_LEN {
                break;
            }
            let record: Vec<u8> = self.partial.drain(..RECORD_LEN).collect();
            consumed = true;
            match decode_record(&record) {
                Ok(event) => self.accept(event, now),
                Err(_) => {
                    self.stats.malformed += 1;
                    self.bump_bad(now);
                }
            }
        }
        if self.partial.is_empty() {
            self.partial_since = None;
        } else if consumed || self.partial_since.is_none() {
            self.partial_since = Some(now);
        }
    }

    fn accept(&mut self, event: LocalEvent, now: u64) {
        self.stats.parsed += 1;
        let in_range = match event.kind {
            LocalEventKind::ButtonDown | LocalEventKind::ButtonUp => {
                event.id < self.cfg.max_buttons
            }
            LocalEventKind::LedFault => event.id < self.cfg.max_leds,
            LocalEventKind::DeviceFault => true,
        };
        if !in_range {
            self.stats.malformed += 1;
            self.bump_bad(now);
            return;
        }
        self.stats.accepted += 1;
        self.consecutive_bad = 0;
        match event.kind {
            LocalEventKind::ButtonDown => self.edge(event.id, ButtonState::Down, now),
            LocalEventKind::ButtonUp => self.edge(event.id, ButtonState::Up, now),
            LocalEventKind::LedFault => self.push(ChannelEvent::LedFault {
                id: event.id,
                at: now,
            }),
            LocalEventKind::DeviceFault => {
                self.push(ChannelEvent::DeviceFault {
                    id: event.id,
                    at: now,
                });
            }
        }
    }

    /// A raw button edge. A change in the middle of a pending change restarts the wait.
    fn edge(&mut self, id: u8, new: ButtonState, now: u64) {
        let Some(button) = self.buttons.get_mut(usize::from(id)) else {
            return;
        };
        if button.raw == new {
            self.stats.duplicate_edges += 1;
            return;
        }
        if button.raw != button.reported {
            self.stats.bounce_suppressed += 1;
        }
        button.raw = new;
        button.raw_since = now;
    }

    /// Report every button whose raw state has been steady for the debounce window.
    fn settle(&mut self, now: u64) {
        let window = self.cfg.debounce_ticks;
        let mut changed = Vec::new();
        for (index, button) in self.buttons.iter_mut().enumerate() {
            if button.raw != ButtonState::Unknown
                && button.raw != button.reported
                && now.saturating_sub(button.raw_since) >= window
            {
                button.reported = button.raw;
                changed.push((index, button.raw));
            }
        }
        for (index, state) in changed {
            let id = u8::try_from(index).unwrap_or(u8::MAX);
            self.push(ChannelEvent::ButtonChanged { id, state, at: now });
        }
    }

    fn bump_bad(&mut self, now: u64) {
        self.consecutive_bad = self.consecutive_bad.saturating_add(1);
        if self.consecutive_bad >= self.cfg.malformed_limit && self.state == ChannelState::Open {
            self.state = ChannelState::Faulted;
            self.forget_buttons();
            self.push(ChannelEvent::Faulted { at: now });
        }
    }

    fn lose(&mut self, now: u64) {
        self.state = ChannelState::Lost;
        self.forget_buttons();
        self.push(ChannelEvent::Lost { at: now });
    }

    /// After a fault or a loss nothing is known about the buttons. They are not "up".
    fn forget_buttons(&mut self) {
        self.partial.clear();
        self.partial_since = None;
        for button in &mut self.buttons {
            *button = Button::unknown();
        }
    }

    fn push(&mut self, event: ChannelEvent) {
        if self.queue.len() < self.cfg.queue_cap {
            self.queue.push_back(event);
            return;
        }
        if !event.is_critical() {
            self.stats.dropped_button_events += 1;
            return;
        }
        // A critical event makes room by evicting the oldest button change, and is lost only if the
        // queue holds nothing but critical events.
        if let Some(index) = self.queue.iter().position(|e| !e.is_critical()) {
            let _evicted = self.queue.remove(index);
            self.stats.evicted_button_events += 1;
            self.queue.push_back(event);
        } else {
            self.stats.lost_critical += 1;
        }
    }
}

#[derive(Debug)]
struct FakeEventState {
    chunks: VecDeque<Vec<u8>>,
    gone: bool,
    fail_next: VecDeque<DriverError>,
    reads: u64,
}

/// A scripted source. Move it into a channel; keep the probe to feed and inspect it.
#[derive(Debug)]
pub struct FakeEventSource {
    state: Arc<Mutex<FakeEventState>>,
}

#[derive(Debug, Clone)]
pub struct FakeEventProbe {
    state: Arc<Mutex<FakeEventState>>,
}

impl FakeEventSource {
    #[must_use]
    pub fn new() -> (Self, FakeEventProbe) {
        let state = Arc::new(Mutex::new(FakeEventState {
            chunks: VecDeque::new(),
            gone: false,
            fail_next: VecDeque::new(),
            reads: 0,
        }));
        (
            Self {
                state: Arc::clone(&state),
            },
            FakeEventProbe { state },
        )
    }
}

impl LocalEventSource for FakeEventSource {
    fn read_raw(&mut self) -> Result<Option<Vec<u8>>, DriverError> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.reads += 1;
        if s.gone {
            return Err(DriverError::Gone);
        }
        if let Some(error) = s.fail_next.pop_front() {
            return Err(error);
        }
        Ok(s.chunks.pop_front())
    }
}

impl FakeEventProbe {
    fn lock(&self) -> MutexGuard<'_, FakeEventState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn push_chunk(&self, bytes: Vec<u8>) {
        self.lock().chunks.push_back(bytes);
    }

    pub fn push_event(&self, kind: LocalEventKind, id: u8, device_ticks: u32) {
        let record = encode_record(&LocalEvent {
            kind,
            id,
            device_ticks,
        });
        self.push_chunk(record.to_vec());
    }

    pub fn lose_device(&self) {
        self.lock().gone = true;
    }

    pub fn fail_next(&self, error: DriverError) {
        self.lock().fail_next.push_back(error);
    }

    /// How many times the channel asked the source for bytes.
    #[must_use]
    pub fn reads(&self) -> u64 {
        self.lock().reads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS_JSON: &str = include_str!("../../../tests/p04/event_vectors.json");

    fn declared() -> LocalEventCapability {
        LocalEventCapability::Declared {
            abi_evidence: "model: harness event record v1".to_string(),
        }
    }

    fn channel(cfg: EventChannelConfig) -> (LocalEventChannel<FakeEventSource>, FakeEventProbe) {
        let (source, probe) = FakeEventSource::new();
        (
            LocalEventChannel::open(&declared(), source, cfg).unwrap(),
            probe,
        )
    }

    fn std_channel() -> (LocalEventChannel<FakeEventSource>, FakeEventProbe) {
        channel(EventChannelConfig::standard())
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn drain(c: &mut LocalEventChannel<FakeEventSource>) -> Vec<ChannelEvent> {
        std::iter::from_fn(|| c.take()).collect()
    }

    #[test]
    fn the_committed_record_vectors_decode_and_encode_as_written() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        assert_eq!(doc["schema"], "ffw.p04.event_vectors.v1");
        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 8, "a vector was added or dropped");
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let bytes = unhex(v["hex"].as_str().unwrap());
            let expect = &v["expect"];
            match expect.get("error") {
                None => {
                    let event = decode_record(&bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
                    let kind = match expect["kind"].as_str().unwrap() {
                        "button_down" => LocalEventKind::ButtonDown,
                        "button_up" => LocalEventKind::ButtonUp,
                        "led_fault" => LocalEventKind::LedFault,
                        "device_fault" => LocalEventKind::DeviceFault,
                        other => panic!("{id}: unknown kind {other}"),
                    };
                    assert_eq!(event.kind, kind, "{id}");
                    assert_eq!(u64::from(event.id), expect["id"].as_u64().unwrap(), "{id}");
                    assert_eq!(
                        u64::from(event.device_ticks),
                        expect["device_ticks"].as_u64().unwrap(),
                        "{id}"
                    );
                    assert_eq!(encode_record(&event).to_vec(), bytes, "{id}: re-encode");
                }
                Some(error) => {
                    let name = match decode_record(&bytes).unwrap_err() {
                        RecordError::Length { .. } => "length",
                        RecordError::BadSync(_) => "bad_sync",
                        RecordError::UnknownKind(_) => "unknown_kind",
                        RecordError::FlagsNonZero(_) => "flags_non_zero",
                    };
                    assert_eq!(error.as_str().unwrap(), name, "{id}");
                }
            }
        }
    }

    fn state_name(state: ButtonState) -> &'static str {
        match state {
            ButtonState::Up => "up",
            ButtonState::Down => "down",
            ButtonState::Unknown => "unknown",
        }
    }

    #[test]
    fn the_committed_debounce_traces_replay_through_the_channel() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        let traces = doc["debounce_traces"].as_array().unwrap();
        assert_eq!(traces.len(), 5, "a trace was added or dropped");
        for t in traces {
            let id = t["id"].as_str().unwrap();
            let cfg = EventChannelConfig {
                debounce_ticks: t["window"].as_u64().unwrap(),
                ..EventChannelConfig::standard()
            };
            let (mut c, probe) = channel(cfg);
            let mut reported: Vec<(u64, String)> = Vec::new();
            for step in t["steps"].as_array().unwrap() {
                let tick = step[0].as_u64().unwrap();
                match step[1].as_str() {
                    Some("down") => probe.push_event(LocalEventKind::ButtonDown, 0, 0),
                    Some("up") => probe.push_event(LocalEventKind::ButtonUp, 0, 0),
                    Some(other) => panic!("{id}: unknown edge {other}"),
                    None => {}
                }
                c.pump(tick);
                for event in drain(&mut c) {
                    match event {
                        ChannelEvent::ButtonChanged { id: 0, state, at } => {
                            reported.push((at, state_name(state).to_string()));
                        }
                        other => panic!("{id}: unexpected event {other:?}"),
                    }
                }
            }
            let expect = &t["expect"];
            let want: Vec<(u64, String)> = expect["reported"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r[0].as_u64().unwrap(), r[1].as_str().unwrap().to_string()))
                .collect();
            assert_eq!(reported, want, "{id}: what was reported, and when");
            assert_eq!(
                c.stats().bounce_suppressed,
                expect["bounces"].as_u64().unwrap(),
                "{id}: bounces"
            );
            assert_eq!(
                c.stats().duplicate_edges,
                expect["duplicates"].as_u64().unwrap(),
                "{id}: duplicates"
            );
            assert_eq!(
                state_name(c.button_state(0)),
                expect["final"].as_str().unwrap(),
                "{id}: final state"
            );
        }
    }

    #[test]
    fn unsupported_or_unevidenced_capability_is_refused_before_any_read() {
        let (source, probe) = FakeEventSource::new();
        let unsupported = LocalEventCapability::Unsupported {
            reason: "the audio-control device is not decoded".to_string(),
        };
        let err = LocalEventChannel::open(&unsupported, source, EventChannelConfig::standard())
            .err()
            .unwrap();
        assert_eq!(
            err,
            OpenError::Unsupported {
                reason: "the audio-control device is not decoded".to_string()
            }
        );
        assert_eq!(probe.reads(), 0, "an unsupported capability is never read");
        let (source, _) = FakeEventSource::new();
        let blank = LocalEventCapability::Declared {
            abi_evidence: "  ".to_string(),
        };
        assert_eq!(
            LocalEventChannel::open(&blank, source, EventChannelConfig::standard())
                .err()
                .unwrap(),
            OpenError::EvidenceMissing
        );
        let (source, _) = FakeEventSource::new();
        let bad = EventChannelConfig {
            queue_cap: 0,
            ..EventChannelConfig::standard()
        };
        assert_eq!(
            LocalEventChannel::open(&declared(), source, bad)
                .err()
                .unwrap(),
            OpenError::BadConfig
        );
        // Permitted positive: a declared, evidenced capability opens.
        assert!(
            LocalEventChannel::open(
                &declared(),
                FakeEventSource::new().0,
                EventChannelConfig::standard()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_button_press_is_reported_only_after_it_stays_put_for_the_debounce_window() {
        let (mut c, probe) = std_channel();
        probe.push_event(LocalEventKind::ButtonDown, 1, 9_999);
        c.pump(10);
        c.pump(12);
        assert_eq!(c.take(), None, "2 ticks is inside the 3-tick window");
        assert_eq!(c.button_state(1), ButtonState::Unknown);
        c.pump(13);
        assert_eq!(
            c.take(),
            Some(ChannelEvent::ButtonChanged {
                id: 1,
                state: ButtonState::Down,
                at: 13
            })
        );
        assert_eq!(c.button_state(1), ButtonState::Down);
        assert_eq!(
            c.button_state(0),
            ButtonState::Unknown,
            "other buttons were never seen"
        );
        // The release is debounced the same way.
        probe.push_event(LocalEventKind::ButtonUp, 1, 0);
        c.pump(20);
        c.pump(23);
        assert_eq!(
            c.take(),
            Some(ChannelEvent::ButtonChanged {
                id: 1,
                state: ButtonState::Up,
                at: 23
            })
        );
    }

    #[test]
    fn bounce_is_absorbed_and_counted() {
        let (mut c, probe) = std_channel();
        // Down at 10, up at 11, down at 12: one press that settles at 15.
        probe.push_event(LocalEventKind::ButtonDown, 0, 0);
        c.pump(10);
        probe.push_event(LocalEventKind::ButtonUp, 0, 0);
        c.pump(11);
        probe.push_event(LocalEventKind::ButtonDown, 0, 0);
        c.pump(12);
        assert_eq!(c.stats().bounce_suppressed, 2);
        c.pump(14);
        assert_eq!(c.take(), None);
        c.pump(15);
        assert_eq!(
            drain(&mut c),
            vec![ChannelEvent::ButtonChanged {
                id: 0,
                state: ButtonState::Down,
                at: 15
            }]
        );
        // A glitch that returns to the reported state produces no event at all.
        probe.push_event(LocalEventKind::ButtonUp, 0, 0);
        c.pump(30);
        probe.push_event(LocalEventKind::ButtonDown, 0, 0);
        c.pump(31);
        c.pump(40);
        assert!(
            drain(&mut c).is_empty(),
            "a glitch that returns to the reported state is silent"
        );
        assert_eq!(c.button_state(0), ButtonState::Down);
        assert_eq!(c.stats().bounce_suppressed, 3);
        // A repeat of the state already pending is counted, not treated as a new edge.
        probe.push_event(LocalEventKind::ButtonDown, 0, 0);
        c.pump(41);
        assert_eq!(c.stats().duplicate_edges, 1);
    }

    #[test]
    fn a_record_split_across_reads_is_reassembled_and_a_stalled_one_is_discarded() {
        let (mut c, probe) = std_channel();
        let record = encode_record(&LocalEvent {
            kind: LocalEventKind::ButtonDown,
            id: 2,
            device_ticks: 1,
        });
        probe.push_chunk(record[..3].to_vec());
        c.pump(10);
        assert_eq!(c.partial_len(), 3);
        probe.push_chunk(record[3..].to_vec());
        c.pump(11);
        assert_eq!(c.partial_len(), 0);
        assert_eq!(c.stats().accepted, 1);
        c.pump(14);
        assert_eq!(c.button_state(2), ButtonState::Down);
        // A record that never completes is discarded after the torn timeout (4 ticks), and the next
        // whole record is still understood.
        probe.push_chunk(record[..3].to_vec());
        c.pump(20);
        c.pump(23);
        assert_eq!(c.partial_len(), 3, "3 ticks is inside the 4-tick timeout");
        c.pump(24);
        assert_eq!(c.partial_len(), 0);
        assert_eq!(c.stats().torn, 1);
        probe.push_chunk(record.to_vec());
        c.pump(25);
        assert_eq!(c.stats().accepted, 2);
    }

    #[test]
    fn garbage_is_skipped_to_the_next_record_and_counted() {
        let (mut c, probe) = std_channel();
        let mut chunk = vec![0x00, 0x11, 0x22];
        chunk.extend_from_slice(&encode_record(&LocalEvent {
            kind: LocalEventKind::LedFault,
            id: 1,
            device_ticks: 7,
        }));
        probe.push_chunk(chunk);
        c.pump(10);
        let s = c.stats();
        assert_eq!((s.resync_skipped_bytes, s.malformed, s.accepted), (3, 1, 1));
        assert_eq!(c.take(), Some(ChannelEvent::LedFault { id: 1, at: 10 }));
        assert_eq!(
            c.channel_state(),
            ChannelState::Open,
            "a good record resets the run of bad ones"
        );
    }

    #[test]
    fn repeated_malformed_records_fault_the_channel_and_a_reset_recovers_it() {
        let (mut c, probe) = std_channel();
        let bad_kind = vec![SYNC, 9, 0, 0, 0, 0, 0, 0];
        let bad_flags = vec![SYNC, 1, 0, 1, 0, 0, 0, 0];
        let out_of_range = encode_record(&LocalEvent {
            kind: LocalEventKind::ButtonDown,
            id: 7, // the limit is 4 buttons
            device_ticks: 0,
        })
        .to_vec();
        let mut chunk = bad_kind;
        chunk.extend(bad_flags);
        chunk.extend(out_of_range);
        probe.push_chunk(chunk);
        c.pump(10);
        assert_eq!(c.channel_state(), ChannelState::Faulted);
        let s = c.stats();
        assert_eq!((s.malformed, s.parsed, s.accepted), (3, 1, 0));
        assert_eq!(c.take(), Some(ChannelEvent::Faulted { at: 10 }));
        // A faulted channel reads nothing.
        let reads = probe.reads();
        c.pump(11);
        assert_eq!(probe.reads(), reads);
        assert!(c.reset(), "a faulted channel can be reset");
        assert_eq!(c.channel_state(), ChannelState::Open);
        // Permitted positive: after the reset a good record is accepted again.
        probe.push_event(LocalEventKind::ButtonUp, 3, 0);
        c.pump(20);
        assert_eq!(c.stats().accepted, 1);
        assert_eq!(
            c.button_state(3),
            ButtonState::Unknown,
            "not reported until it settles"
        );
        c.pump(23);
        assert_eq!(c.button_state(3), ButtonState::Up);
    }

    #[test]
    fn an_oversize_read_and_a_failing_read_count_toward_a_fault() {
        let (mut c, probe) = std_channel();
        probe.push_chunk(vec![SYNC; MAX_CHUNK_BYTES + 1]);
        c.pump(10);
        assert_eq!(c.stats().oversize_chunks, 1);
        assert_eq!(c.partial_len(), 0, "an oversize chunk is never buffered");
        probe.fail_next(DriverError::Errno(5));
        c.pump(11);
        assert_eq!(c.stats().source_errors, 1);
        probe.fail_next(DriverError::Errno(5));
        c.pump(12);
        assert_eq!(
            c.channel_state(),
            ChannelState::Faulted,
            "three bad reads in a row"
        );
    }

    #[test]
    fn the_queue_is_bounded_and_a_fault_is_lost_only_when_nothing_else_can_make_room() {
        let cfg = EventChannelConfig {
            queue_cap: 2,
            ..EventChannelConfig::standard()
        };
        let (mut c, probe) = channel(cfg);
        // Three buttons settle together; only two fit, and the newest is dropped, counted.
        for id in 0..3 {
            probe.push_event(LocalEventKind::ButtonDown, id, 0);
        }
        c.pump(10);
        c.pump(13);
        assert_eq!(c.queue_len(), 2);
        assert_eq!(c.stats().dropped_button_events, 1);
        // A fault makes room by evicting the oldest button change.
        probe.push_event(LocalEventKind::LedFault, 0, 0);
        c.pump(14);
        assert_eq!(c.stats().evicted_button_events, 1);
        probe.push_event(LocalEventKind::DeviceFault, 5, 0);
        c.pump(15);
        assert_eq!(c.stats().evicted_button_events, 2);
        assert!(c.evidence_complete());
        assert_eq!(
            drain(&mut c),
            vec![
                ChannelEvent::LedFault { id: 0, at: 14 },
                ChannelEvent::DeviceFault { id: 5, at: 15 }
            ]
        );
        // With the queue full of faults, another fault has nowhere to go: counted, and the evidence
        // is marked incomplete.
        for id in 1..=3 {
            probe.push_event(LocalEventKind::DeviceFault, id, 0);
        }
        c.pump(20);
        assert_eq!(c.stats().lost_critical, 1);
        assert!(!c.evidence_complete());
        assert_eq!(c.queue_len(), 2);
    }

    #[test]
    fn device_loss_leaves_buttons_unknown_and_is_not_recoverable() {
        let (mut c, probe) = std_channel();
        probe.push_event(LocalEventKind::ButtonDown, 1, 0);
        c.pump(10);
        c.pump(13);
        assert_eq!(c.button_state(1), ButtonState::Down);
        // Half a record is in flight when the device goes.
        probe.push_chunk(vec![SYNC, 1]);
        c.pump(14);
        assert_eq!(c.partial_len(), 2);
        probe.lose_device();
        c.pump(15);
        assert_eq!(c.channel_state(), ChannelState::Lost);
        assert_eq!(
            c.button_state(1),
            ButtonState::Unknown,
            "a held button is not a released button"
        );
        assert_eq!(c.partial_len(), 0);
        assert_eq!(
            drain(&mut c),
            vec![
                ChannelEvent::ButtonChanged {
                    id: 1,
                    state: ButtonState::Down,
                    at: 13
                },
                ChannelEvent::Lost { at: 15 }
            ]
        );
        let reads = probe.reads();
        c.pump(16);
        assert_eq!(probe.reads(), reads, "a lost channel reads nothing");
        assert!(!c.reset(), "a vanished device cannot be reset");
        assert_eq!(c.channel_state(), ChannelState::Lost);
    }

    /// Small deterministic generator so the sweeps below need no dependency and replay exactly.
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

    fn valid_stream(rng: &mut Xorshift, records: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..records {
            let kind = [
                LocalEventKind::ButtonDown,
                LocalEventKind::ButtonUp,
                LocalEventKind::LedFault,
                LocalEventKind::DeviceFault,
            ][usize::try_from(rng.below(4)).unwrap()];
            let id = u8::try_from(match kind {
                LocalEventKind::ButtonDown | LocalEventKind::ButtonUp => rng.below(4),
                LocalEventKind::LedFault => rng.below(2),
                LocalEventKind::DeviceFault => rng.below(256),
            })
            .unwrap();
            let ticks = u32::try_from(rng.below(1 << 31)).unwrap();
            out.extend_from_slice(&encode_record(&LocalEvent {
                kind,
                id,
                device_ticks: ticks,
            }));
        }
        out
    }

    fn run_stream(chunks: Vec<Vec<u8>>) -> (Vec<ChannelEvent>, EventStats) {
        let cfg = EventChannelConfig {
            queue_cap: 64,
            ..EventChannelConfig::standard()
        };
        let (mut c, probe) = channel(cfg);
        for chunk in chunks {
            probe.push_chunk(chunk);
        }
        // Every read happens at one tick, so only the data can differ between splits.
        for _ in 0..40 {
            c.pump(100);
        }
        c.pump(103);
        let events = drain(&mut c);
        (events, c.stats())
    }

    #[test]
    fn how_a_valid_stream_is_split_into_reads_never_changes_what_is_delivered() {
        for seed in 1..=200u64 {
            let mut rng = Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let stream = valid_stream(&mut rng, 12);
            let (whole_events, whole_stats) = run_stream(vec![stream.clone()]);
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < stream.len() {
                let len = usize::try_from(1 + rng.below(9))
                    .unwrap()
                    .min(stream.len() - at);
                chunks.push(stream[at..at + len].to_vec());
                at += len;
            }
            let (split_events, split_stats) = run_stream(chunks);
            assert_eq!(split_events, whole_events, "seed {seed}");
            assert_eq!(split_stats.parsed, 12, "seed {seed}");
            assert_eq!(split_stats.parsed, whole_stats.parsed, "seed {seed}");
            assert_eq!(split_stats.malformed, 0, "seed {seed}");
        }
    }

    #[test]
    fn arbitrary_bytes_never_break_the_bounds() {
        let mut faulted = 0usize;
        let mut accepted = 0u64;
        for seed in 1..=300u64 {
            let mut rng = Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let cfg = EventChannelConfig {
                queue_cap: 3,
                ..EventChannelConfig::standard()
            };
            let (mut c, probe) = channel(cfg);
            let mut now = 0u64;
            for _ in 0..40 {
                now += rng.below(3);
                let len = usize::try_from(rng.below(20)).unwrap();
                let mut chunk: Vec<u8> = (0..len)
                    .map(|_| u8::try_from(rng.below(256)).unwrap())
                    .collect();
                if rng.below(3) == 0 {
                    // Splice a valid record in so the sweep reaches the accept path.
                    chunk.extend_from_slice(&valid_stream(&mut rng, 1));
                }
                probe.push_chunk(chunk);
                c.pump(now);
                assert!(c.queue_len() <= 3, "seed {seed}: queue over its cap");
                assert!(
                    c.partial_len() < RECORD_LEN,
                    "seed {seed}: a whole record left unparsed"
                );
                if rng.below(5) == 0 {
                    let _ = c.take();
                }
                if c.channel_state() == ChannelState::Faulted {
                    faulted += 1;
                    assert_eq!(c.button_state(0), ButtonState::Unknown, "seed {seed}");
                    c.reset();
                }
            }
            let s = c.stats();
            assert!(s.accepted <= s.parsed, "seed {seed}");
            accepted += s.accepted;
        }
        assert!(faulted > 0, "the sweep never faulted a channel");
        assert!(accepted > 0, "the sweep never accepted a record");
    }
}
