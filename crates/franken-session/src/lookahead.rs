//! Bounded compressed lookahead for a source (`S03` / `ffw-mxt`, contract `docs/contracts/s03.md`).
//!
//! A source that may fetch future media (Spotify, a file) keeps a queue of COMPRESSED chunks ahead of
//! the decoder. That queue has a different purpose and different accounting from the decoded playout
//! buffer, so it is its own type here: [`LookaheadQueue`] holds opaque compressed bytes and the facts
//! the caller already knows about them (which stream, which track, where in the track, how many decoded
//! frames at what declared rate). It decodes nothing, opens no connection, reads no credential and
//! performs no I/O of any kind, so an eviction cannot write a secret anywhere: it drops memory and
//! reports counts.
//!
//! * **Bytes and time are different things, and time is exact.** Three caps are enforced separately
//!   (bytes, media time, chunks), each reported by name when it binds. A chunk's duration is its exact
//!   decoded frame count at its declared rate; positions, contiguity and seek targets are exact frame
//!   numbers, so nothing accumulates a rounded millisecond. Only the time CAP and the derived media time
//!   use nanoseconds, rounded UP per chunk (the same value is added and later removed, so there is no
//!   drift, and a cap is never under-counted). No bit-rate window is invented: variable-bit-rate
//!   streams, a burst, a header or codec-configuration chunk of ZERO frames, and a preroll are valid
//!   negotiated content and are judged only by the byte, time and chunk caps. [`required_link_bps`]
//!   states the arithmetic bound for a fetch (3 minutes at 320 kbit/s is 7.2 MB and needs at least
//!   28.8 Mbit/s to arrive in 2 seconds); it is arithmetic, not a measurement and not a promise.
//!   Readiness is a measured minimum of media time, never a full fill.
//! * **Identity.** Every chunk names the source epoch ([`SourceEpoch`], minted by the
//!   [`SourceArbiter`](crate::SourceArbiter)) and the track ([`TrackSerial`], an opaque number the
//!   adapter assigns; a track URI never enters the queue). A chunk from an older epoch is refused and
//!   counted ([`LookaheadError::LateOldEpoch`]); one from a future epoch is refused; chunks must be
//!   contiguous in the track at one declared rate, and the fetch track advances only after a chunk
//!   marked `last_of_track`.
//! * **Fetch position and playback head are different.** [`LookaheadQueue::fetch_position`] is where the
//!   NEXT chunk must be admitted; [`LookaheadQueue::head_track`] and [`LookaheadQueue::playback_track`]
//!   say what is at the front of the queue and what was last handed out. A gapless queue holds the tail
//!   of one track and the head of the next at once; admitting the last chunk of a track moves only the
//!   fetch position and never touches what is already queued.
//! * **Eviction is explicit and furthest-first.** A full queue refuses a push with a typed
//!   [`LookaheadError::Full`] (back-pressure, nothing dropped). When the memory ledger shrinks the
//!   allowance, [`LookaheadQueue::shrink_to`] drops the chunks furthest in the future first and the fetch
//!   position moves back, so the fetcher refetches contiguously. Decoded playout is not in this module.
//! * **A chunk handed out is outstanding work until it retires.** [`LookaheadQueue::pop`] returns a
//!   [`Handoff`]: the chunk and a [`HandoffTicket`]. The chunk is then being decoded, and the device
//!   cannot see it yet, so an empty device proves nothing about it. The adapter retires every ticket with
//!   [`LookaheadQueue::retire`]: `Submitted` (with the OUTPUT position where its decoded audio ends, in an
//!   explicit [`OutputDomain`] of session, generation and rate) or `Cancelled` (decoding cancelled and
//!   joined). Outstanding tickets are bounded, and a retired, unknown or foreign ticket may not submit
//!   ([`LookaheadQueue::may_submit`]), so a late submission cannot slip past a fence. A ticket belongs to
//!   the queue that issued it: it carries that queue's identity, so a ticket of another queue retires,
//!   authorizes and reduces nothing here, even with the same epoch and sequence number.
//! * **A seek or skip is not acknowledged until the old output is fenced.**
//!   [`LookaheadQueue::begin_transition`] takes the next epoch, drops every buffered chunk of the old
//!   timeline at once and opens ingress for the new one, but it hands the caller a [`FenceRequest`]
//!   instead of an acknowledgment, and [`LookaheadQueue::pop`] stays gated.
//!   [`LookaheadQueue::ack_transition`] does not take a verdict from its caller. First every outstanding
//!   ticket must have retired (the barrier; the renderer is not even asked before that). Then it ASKS an
//!   [`OutputFenceSource`] (the renderer side) for evidence about the request, and accepts only a report
//!   that carries the request's token, speaks for the epoch whose output was handed out, is in the SAME
//!   output domain as the submissions, covers their recorded tail (`tail >= the last submitted end`), and
//!   shows the output drained (`played >= tail`) or a flush the device acknowledged. The evidence has the
//!   shape of `franken-hal`'s `irrevocable_until_frames()` and `DrainOutcome`, and of the group readiness
//!   report's `old_output_tail_complete_frame` / `can_stop_flush`: positions in a named domain, never a
//!   bare count or boolean. Refusing the old epoch's ingress alone never acknowledges anything. A flush
//!   that times out fails the transition for good; a later transition supersedes it and is fenced against
//!   the SAME original output.
//! * **The HAL adapter is not part of this slice.** The type that implements [`OutputFenceSource`] over a
//!   real `franken-hal` session belongs at the integration boundary (a crate that depends on both) and is
//!   UNQUALIFIED until it lands. [`UnqualifiedFence`] is the explicit stand-in: it fails closed, so no seek
//!   is ever acknowledged without a real source.
//!
//! Out of scope: fetching, decoding, the renderer, any provider or device behavior. A refused call
//! changes nothing except its refusal counter.

use crate::SourceEpoch;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

/// Largest byte allowance a configuration may ask for (a sanity ceiling, not a recommendation).
pub const MAX_LOOKAHEAD_BYTES: usize = 64 * 1024 * 1024;
/// Largest media-time allowance a configuration may ask for, in milliseconds (one hour).
pub const MAX_LOOKAHEAD_MEDIA_MS: u64 = 3_600_000;
/// Largest chunk-count allowance a configuration may ask for.
pub const MAX_LOOKAHEAD_CHUNKS: usize = 65_536;
/// Largest number of handed-out chunks that may be outstanding at once.
pub const MAX_LOOKAHEAD_OUTSTANDING: usize = 1024;

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_S: u128 = 1_000_000_000;

/// An opaque number the adapter assigns to each track of a session. Never a track URI or an account
/// identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrackSerial(u64);

impl TrackSerial {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A nonce that binds an [`OutputFence`] to the transition that asked for it, so a report measured
/// before the transition, or for a superseded one, cannot answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FenceToken(u64);

impl FenceToken {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The three separate allowances. There is deliberately no bit-rate window: a variable-bit-rate stream,
/// a burst, a header or a preroll is judged by these caps and nothing invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookaheadLimits {
    /// Compressed payload bytes held at once.
    pub max_bytes: usize,
    /// Milliseconds of media held at once (the exact frame durations, rounded up per chunk).
    pub max_media_ms: u64,
    /// Chunks held at once.
    pub max_chunks: usize,
    /// Largest single payload accepted.
    pub max_chunk_bytes: usize,
    /// Handed-out chunks that may be outstanding (decoding, not yet retired) at once.
    pub max_outstanding: usize,
    /// Media milliseconds that make the queue ready to start: a measured minimum, not a full fill.
    pub ready_min_media_ms: u64,
}

impl LookaheadLimits {
    /// Every allowance non-zero and within the module ceilings, one chunk able to fit, and the readiness
    /// threshold reachable.
    pub fn validate(&self) -> Result<(), LookaheadError> {
        if self.max_bytes == 0 || self.max_bytes > MAX_LOOKAHEAD_BYTES {
            return Err(invalid("max_bytes"));
        }
        if self.max_media_ms == 0 || self.max_media_ms > MAX_LOOKAHEAD_MEDIA_MS {
            return Err(invalid("max_media_ms"));
        }
        if self.max_chunks == 0 || self.max_chunks > MAX_LOOKAHEAD_CHUNKS {
            return Err(invalid("max_chunks"));
        }
        if self.max_chunk_bytes == 0 || self.max_chunk_bytes > self.max_bytes {
            return Err(invalid("max_chunk_bytes"));
        }
        if self.max_outstanding == 0 || self.max_outstanding > MAX_LOOKAHEAD_OUTSTANDING {
            return Err(invalid("max_outstanding"));
        }
        if self.ready_min_media_ms > self.max_media_ms {
            return Err(invalid("ready_min_media_ms"));
        }
        Ok(())
    }
}

fn invalid(field: &'static str) -> LookaheadError {
    LookaheadError::InvalidLimits { field }
}

/// One compressed chunk. The payload is opaque and is never formatted: `Debug` prints its length.
#[derive(Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The source epoch this chunk belongs to.
    pub epoch: SourceEpoch,
    /// The track this chunk belongs to.
    pub track: TrackSerial,
    /// The first decoded frame this chunk yields, counted from the start of its track at `rate_hz`.
    pub start_frame: u64,
    /// The exact number of decoded frames this chunk yields. Zero is valid: a header or codec
    /// configuration chunk carries bytes and no time and does not move the position.
    pub frames: u32,
    /// The declared decode rate of the track, in Hz. Every chunk of a track declares the same rate.
    pub rate_hz: u32,
    /// Whether this is the last chunk of its track (the next chunk is the next track, at frame 0).
    pub last_of_track: bool,
    /// The compressed bytes.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("epoch", &self.epoch.get())
            .field("track", &self.track.get())
            .field("start_frame", &self.start_frame)
            .field("frames", &self.frames)
            .field("rate_hz", &self.rate_hz)
            .field("last_of_track", &self.last_of_track)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Which allowance bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    Bytes,
    MediaMs,
    Chunks,
}

/// Every refusal carries identifiers and numbers only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookaheadError {
    #[error("invalid lookahead limit: {field}")]
    InvalidLimits { field: &'static str },
    #[error("invalid chunk: {reason}")]
    InvalidChunk { reason: &'static str },
    #[error("chunk epoch {chunk} is behind the current epoch {current}")]
    LateOldEpoch { chunk: u64, current: u64 },
    #[error("chunk epoch {chunk} is ahead of the current epoch {current}")]
    EpochAhead { chunk: u64, current: u64 },
    #[error("chunk track {chunk} is not the expected track {expected}")]
    TrackMismatch { chunk: u64, expected: u64 },
    #[error("chunk declares {chunk} Hz but its track is at {expected} Hz")]
    RateMismatch { chunk: u32, expected: u32 },
    #[error(
        "chunk starts at frame {start_frame} but the next contiguous frame is {expected_frame}"
    )]
    NotContiguous {
        start_frame: u64,
        expected_frame: u64,
    },
    #[error("chunk of {bytes} bytes exceeds the {max} byte chunk limit")]
    ChunkTooLarge { bytes: usize, max: usize },
    #[error("the lookahead is full: the {cap:?} allowance binds")]
    Full { cap: CapKind },
    #[error("a position or counter would overflow: {what}")]
    Overflow { what: &'static str },
    #[error("transition epoch {requested} must be ahead of the current epoch {current}")]
    TransitionEpochNotAhead { requested: u64, current: u64 },
    #[error("a transition is pending: the old output is not fenced yet")]
    TransitionPending,
    #[error("the transition failed: start a new one")]
    TransitionFailed,
    #[error("no transition is pending")]
    NoTransition,
    #[error("fence token {got} does not answer the pending request {expected}")]
    FenceTokenStale { got: u64, expected: u64 },
    #[error("fence speaks for epoch {fence}, the output was handed out for epoch {expected}")]
    FenceEpochMismatch { fence: u64, expected: u64 },
    #[error("old output is not drained: played {played_frame} of {tail_frame} frames")]
    OutputNotDrained { tail_frame: u64, played_frame: u64 },
    #[error("the flush was not acknowledged in time: the transition failed")]
    FlushTimedOut,
    #[error("{outstanding} handed-out chunks have not retired: decoder work is still outstanding")]
    OutstandingDecoderWork { outstanding: usize },
    #[error("{max} handed-out chunks are already outstanding")]
    OutstandingLimit { max: usize },
    #[error("handoff {seq} is not outstanding: retired, cancelled, superseded or never issued")]
    UnknownHandoff { seq: u64 },
    #[error("handoff {seq} was issued by another queue")]
    ForeignHandoff { seq: u64 },
    #[error("invalid output domain: {reason}")]
    InvalidOutputDomain { reason: &'static str },
    #[error("the output session, generation or rate changed within one epoch's output")]
    OutputDomainChanged,
    #[error("the fence evidence is for another output session, generation or rate")]
    FenceDomainMismatch,
    #[error("the fence covers output up to {reported} but submissions ended at {required}")]
    FenceTailBehindSubmissions { required: u64, reported: u64 },
}

impl LookaheadError {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits { .. } => "LOOKAHEAD_INVALID_LIMITS",
            Self::InvalidChunk { .. } => "LOOKAHEAD_INVALID_CHUNK",
            Self::LateOldEpoch { .. } => "LOOKAHEAD_LATE_OLD_EPOCH",
            Self::EpochAhead { .. } => "LOOKAHEAD_EPOCH_AHEAD",
            Self::TrackMismatch { .. } => "LOOKAHEAD_TRACK_MISMATCH",
            Self::RateMismatch { .. } => "LOOKAHEAD_RATE_MISMATCH",
            Self::NotContiguous { .. } => "LOOKAHEAD_NOT_CONTIGUOUS",
            Self::ChunkTooLarge { .. } => "LOOKAHEAD_CHUNK_TOO_LARGE",
            Self::Full { .. } => "LOOKAHEAD_FULL",
            Self::Overflow { .. } => "LOOKAHEAD_OVERFLOW",
            Self::TransitionEpochNotAhead { .. } => "LOOKAHEAD_TRANSITION_EPOCH_NOT_AHEAD",
            Self::TransitionPending => "LOOKAHEAD_TRANSITION_PENDING",
            Self::TransitionFailed => "LOOKAHEAD_TRANSITION_FAILED",
            Self::NoTransition => "LOOKAHEAD_NO_TRANSITION",
            Self::FenceTokenStale { .. } => "LOOKAHEAD_FENCE_TOKEN_STALE",
            Self::FenceEpochMismatch { .. } => "LOOKAHEAD_FENCE_EPOCH_MISMATCH",
            Self::OutputNotDrained { .. } => "LOOKAHEAD_OUTPUT_NOT_DRAINED",
            Self::FlushTimedOut => "LOOKAHEAD_FLUSH_TIMED_OUT",
            Self::OutstandingDecoderWork { .. } => "LOOKAHEAD_OUTSTANDING_DECODER_WORK",
            Self::OutstandingLimit { .. } => "LOOKAHEAD_OUTSTANDING_LIMIT",
            Self::UnknownHandoff { .. } => "LOOKAHEAD_UNKNOWN_HANDOFF",
            Self::ForeignHandoff { .. } => "LOOKAHEAD_FOREIGN_HANDOFF",
            Self::InvalidOutputDomain { .. } => "LOOKAHEAD_INVALID_OUTPUT_DOMAIN",
            Self::OutputDomainChanged => "LOOKAHEAD_OUTPUT_DOMAIN_CHANGED",
            Self::FenceDomainMismatch => "LOOKAHEAD_FENCE_DOMAIN_MISMATCH",
            Self::FenceTailBehindSubmissions { .. } => "LOOKAHEAD_FENCE_TAIL_BEHIND_SUBMISSIONS",
        }
    }
}

/// What the renderer reports about the old output of a transition. It is produced by an
/// [`OutputFenceSource`] after the request, echoes the request's token, and names the epoch whose output
/// it speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFence {
    pub token: FenceToken,
    pub epoch: SourceEpoch,
    pub outcome: FenceOutcome,
}

/// The output domain a frame count is measured in: the device session, its generation (a reset or a
/// flush starts a new one) and its sample rate. A bare frame count means nothing without it, and counts
/// from two domains never compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutputDomain {
    pub session: u64,
    pub generation: u64,
    pub rate_hz: u32,
}

/// A frame position in an [`OutputDomain`] (output frames, not decoded source frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPosition {
    pub domain: OutputDomain,
    pub frame: u64,
}

/// How the old output ended. Evidence, not a verdict: each variant carries the device's numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceOutcome {
    /// Everything handed to the device is irrevocable up to `tail`; the output cursor is at `played`.
    /// Drained only when both are in one domain and `played >= tail`.
    Drained {
        tail: OutputPosition,
        played: OutputPosition,
    },
    /// The renderer muted and the device acknowledged a flush of `domain` after `waited_ticks`.
    FlushAcknowledged {
        domain: OutputDomain,
        waited_ticks: u64,
    },
    /// No flush acknowledgment arrived within `waited_ticks`. The transition fails; nothing is
    /// acknowledged.
    FlushTimedOut { waited_ticks: u64 },
}

/// Proof that one chunk was handed to the decoder. Opaque: only [`LookaheadQueue::pop`] issues one, and it
/// belongs to that queue alone. It carries a clone of the issuing queue's identity (an `Arc` compared by
/// pointer; no counter, no 64-bit atomic, no randomness), so another queue, even in the same epoch with the
/// same sequence number, neither recognises it nor lets it retire or authorize anything. Holding the clone
/// keeps the identity's allocation alive, so a dropped queue's address is never reused under a live ticket.
#[derive(Clone)]
pub struct HandoffTicket {
    seq: u64,
    epoch: SourceEpoch,
    queue: Arc<()>,
}

impl HandoffTicket {
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[must_use]
    pub const fn epoch(&self) -> SourceEpoch {
        self.epoch
    }
}

impl PartialEq for HandoffTicket {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.epoch == other.epoch && Arc::ptr_eq(&self.queue, &other.queue)
    }
}

impl Eq for HandoffTicket {}

impl fmt::Debug for HandoffTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffTicket")
            .field("seq", &self.seq)
            .field("epoch", &self.epoch.get())
            .finish()
    }
}

/// A chunk handed to the decoder, with the ticket that must be retired when its decode ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    pub chunk: Chunk,
    pub ticket: HandoffTicket,
}

/// How a handoff ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retirement {
    /// The decoded audio was accepted by the output session and its irrevocable output now ends at `end`.
    Submitted { end: OutputPosition },
    /// Decoding was cancelled and joined: nothing of this handoff is or will ever be in the output.
    Cancelled,
}

/// What the renderer must report to acknowledge a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceRequest {
    pub token: FenceToken,
    /// The epoch whose already-handed-out output must be drained or flushed.
    pub epoch: SourceEpoch,
}

/// The renderer side of the fence. The integration boundary implements it over the real device session
/// (map `irrevocable_until_frames()` to `tail_frame`, the output cursor to `played_frame`, and a drain's
/// acknowledged or timed-out result to the other two outcomes), measuring AFTER the request. The queue
/// calls it from the control path, at most once per acknowledgment attempt, and only while a transition
/// is pending; it never calls it from the render path.
pub trait OutputFenceSource {
    fn fence(&mut self, request: FenceRequest) -> OutputFence;
}

/// The explicit stand-in until a real device adapter exists. It echoes the request and reports a flush
/// that was never acknowledged, so it fails closed: a transition fenced by it fails and no seek or skip
/// is ever acknowledged. Using it is a statement that the output boundary is UNQUALIFIED.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnqualifiedFence;

impl OutputFenceSource for UnqualifiedFence {
    fn fence(&mut self, request: FenceRequest) -> OutputFence {
        OutputFence {
            token: request.token,
            epoch: request.epoch,
            outcome: FenceOutcome::FlushTimedOut { waited_ticks: 0 },
        }
    }
}

/// The result of [`LookaheadQueue::begin_transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionStart {
    /// The epoch the queue now accepts.
    pub epoch: SourceEpoch,
    /// `None` only when no output had been handed out since the last fence, so there is nothing to
    /// drain and the seek or skip is complete. `Some` means NOT acknowledged yet.
    pub fence: Option<FenceRequest>,
    /// Whether this replaced a transition that was still pending or had failed.
    pub superseded: bool,
    /// Chunks of the old timeline dropped, and their payload bytes.
    pub dropped_chunks: usize,
    pub dropped_bytes: usize,
}

impl TransitionStart {
    /// Whether the seek or skip is already complete.
    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        self.fence.is_none()
    }
}

/// How a transition was fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceKind {
    Drained,
    Flushed,
}

/// The acknowledgment of a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionAck {
    pub epoch: SourceEpoch,
    pub via: FenceKind,
}

/// Where a transition stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionStatus {
    Idle,
    AwaitingFence,
    Failed,
}

/// What a shrink dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Evicted {
    pub chunks: usize,
    pub bytes: usize,
    pub media_ns: u64,
}

/// Whether the queue holds enough to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readiness {
    pub ready: bool,
    pub bytes: usize,
    pub media_ns: u64,
}

/// Bytes, time and chunks reported separately, with the lifetime counters. `media_ns` is derived from
/// the exact frame counts and rates, rounded up per chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LookaheadStats {
    pub bytes: usize,
    pub media_ns: u64,
    pub chunks: usize,
    pub accepted_chunks: u64,
    pub accepted_bytes: u64,
    pub refused_late_epoch: u64,
    pub refused_full: u64,
    pub refused_invalid: u64,
    pub evicted_chunks: u64,
    pub evicted_bytes: u64,
    pub invalidated_chunks: u64,
    pub invalidated_bytes: u64,
    pub transitions_acked: u64,
    pub transitions_superseded: u64,
    pub transitions_failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitingFence,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Transition {
    token: FenceToken,
    to_epoch: SourceEpoch,
    fence_epoch: SourceEpoch,
    phase: Phase,
}

/// What an accepted chunk leaves behind: the next fetch position and the time it costs.
#[derive(Debug, Clone, Copy)]
struct Admit {
    track: TrackSerial,
    frame: u64,
    rate_hz: Option<u32>,
    cost_ns: u64,
}

/// The duration of `frames` decoded frames at `rate_hz`, in nanoseconds, rounded up. `None` for a zero
/// rate or an overflow.
#[must_use]
pub fn duration_ns_ceil(frames: u64, rate_hz: u32) -> Option<u64> {
    if rate_hz == 0 {
        return None;
    }
    let ns = (u128::from(frames) * NS_PER_S).div_ceil(u128::from(rate_hz));
    u64::try_from(ns).ok()
}

/// The least payload rate, in bit/s, that moves `bytes` within `window_ms`, rounded up. This is
/// arithmetic only: it says what a deadline would need, not what any provider or link delivers.
/// `None` for a zero window or an overflow.
#[must_use]
pub fn required_link_bps(bytes: u64, window_ms: u64) -> Option<u64> {
    if window_ms == 0 {
        return None;
    }
    let bits_ms = bytes.checked_mul(8)?.checked_mul(1_000)?;
    Some(bits_ms.div_ceil(window_ms))
}

/// The nanoseconds a stored chunk was charged. The rate was validated non-zero when it was admitted, so
/// the zero fallback is unreachable.
fn charge_ns(chunk: &Chunk) -> u64 {
    duration_ns_ceil(u64::from(chunk.frames), chunk.rate_hz).unwrap_or(0)
}

/// A bounded, contiguous queue of compressed chunks for one source session.
#[derive(Debug)]
pub struct LookaheadQueue {
    limits: LookaheadLimits,
    epoch: SourceEpoch,
    fetch_track: TrackSerial,
    fetch_frame: u64,
    /// The rate the fetch track has declared so far; `None` before its first chunk.
    fetch_rate_hz: Option<u32>,
    chunks: VecDeque<Chunk>,
    bytes: usize,
    media_ns: u64,
    /// The track of the newest chunk handed to the decoder.
    playback_track: Option<TrackSerial>,
    /// The epoch of the newest chunk handed to the decoder and not yet fenced.
    output_epoch: Option<SourceEpoch>,
    /// Handed-out chunks whose decode has not retired. Every one belongs to `output_epoch`.
    outstanding: Vec<HandoffTicket>,
    next_seq: u64,
    /// This queue's identity: every ticket it issues carries a clone, compared by pointer.
    identity: Arc<()>,
    /// Where the submissions of `output_epoch` end in the output domain (the largest end seen).
    submitted: Option<OutputPosition>,
    transition: Option<Transition>,
    next_token: u64,
    stats: LookaheadStats,
}

impl LookaheadQueue {
    /// An empty queue that accepts `epoch` and expects the first chunk to be `track` at `start_frame`.
    pub fn new(
        limits: LookaheadLimits,
        epoch: SourceEpoch,
        track: TrackSerial,
        start_frame: u64,
    ) -> Result<Self, LookaheadError> {
        limits.validate()?;
        Ok(Self {
            limits,
            epoch,
            fetch_track: track,
            fetch_frame: start_frame,
            fetch_rate_hz: None,
            chunks: VecDeque::new(),
            bytes: 0,
            media_ns: 0,
            playback_track: None,
            output_epoch: None,
            outstanding: Vec::new(),
            next_seq: 1,
            identity: Arc::new(()),
            submitted: None,
            transition: None,
            next_token: 1,
            stats: LookaheadStats::default(),
        })
    }

    /// How many handed-out chunks have not retired.
    #[must_use]
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Whether `ticket` may still submit output through this queue: this queue issued it and it is
    /// outstanding. A retired, cancelled, unknown or FOREIGN ticket may not (a ticket of another queue
    /// authorizes nothing here), so a decoder that ignored a cancellation must drop what it produced.
    #[must_use]
    pub fn may_submit(&self, ticket: &HandoffTicket) -> bool {
        self.owns(ticket) && self.outstanding.contains(ticket)
    }

    /// Whether this queue issued `ticket`, by the identity the ticket carries.
    fn owns(&self, ticket: &HandoffTicket) -> bool {
        Arc::ptr_eq(&ticket.queue, &self.identity)
    }

    /// The epoch the queue accepts.
    #[must_use]
    pub const fn epoch(&self) -> SourceEpoch {
        self.epoch
    }

    /// The allowances in force.
    #[must_use]
    pub const fn limits(&self) -> LookaheadLimits {
        self.limits
    }

    /// Where the NEXT chunk must be admitted: the fetch track and the frame it must start at. This is the
    /// admission position, not the playback head.
    #[must_use]
    pub const fn fetch_position(&self) -> (TrackSerial, u64) {
        (self.fetch_track, self.fetch_frame)
    }

    /// The track of the chunk at the front of the queue, if any.
    #[must_use]
    pub fn head_track(&self) -> Option<TrackSerial> {
        self.chunks.front().map(|chunk| chunk.track)
    }

    /// The track of the newest chunk handed out by [`Self::pop`], if any.
    #[must_use]
    pub const fn playback_track(&self) -> Option<TrackSerial> {
        self.playback_track
    }

    /// Where a transition stands.
    #[must_use]
    pub fn transition_status(&self) -> TransitionStatus {
        match self.transition {
            None => TransitionStatus::Idle,
            Some(Transition {
                phase: Phase::AwaitingFence,
                ..
            }) => TransitionStatus::AwaitingFence,
            Some(Transition {
                phase: Phase::Failed,
                ..
            }) => TransitionStatus::Failed,
        }
    }

    /// Bytes, time and chunks held now, and the lifetime counters.
    #[must_use]
    pub fn stats(&self) -> LookaheadStats {
        LookaheadStats {
            bytes: self.bytes,
            media_ns: self.media_ns,
            chunks: self.chunks.len(),
            ..self.stats
        }
    }

    /// Whether the queue holds the configured minimum of media time. It is not ready while a transition
    /// is unfenced, because nothing may be handed out until then.
    #[must_use]
    pub fn readiness(&self) -> Readiness {
        let needed = self.limits.ready_min_media_ms.saturating_mul(NS_PER_MS);
        Readiness {
            ready: self.transition.is_none() && self.media_ns >= needed,
            bytes: self.bytes,
            media_ns: self.media_ns,
        }
    }

    /// Append a chunk. Every check happens before anything changes, so a refusal leaves the queue as it
    /// was (the refusal counters aside). An accepted chunk's payload is stored with exactly the capacity of
    /// its length, so the bytes charged are the bytes held.
    pub fn push(&mut self, mut chunk: Chunk) -> Result<(), LookaheadError> {
        match self.check_push(&chunk) {
            Ok(admit) => {
                // Own exactly the bytes that are charged: a Vec with spare capacity would otherwise keep its
                // whole reservation while costing only its length against `max_bytes`.
                if chunk.payload.capacity() != chunk.payload.len() {
                    chunk.payload = std::mem::take(&mut chunk.payload)
                        .into_boxed_slice()
                        .into_vec();
                }
                let len = chunk.payload.len();
                self.bytes += len;
                self.media_ns += admit.cost_ns;
                self.fetch_track = admit.track;
                self.fetch_frame = admit.frame;
                self.fetch_rate_hz = admit.rate_hz;
                self.stats.accepted_chunks = self.stats.accepted_chunks.saturating_add(1);
                self.stats.accepted_bytes = self
                    .stats
                    .accepted_bytes
                    .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
                self.chunks.push_back(chunk);
                Ok(())
            }
            Err(err) => {
                let counter = match err {
                    LookaheadError::LateOldEpoch { .. } => &mut self.stats.refused_late_epoch,
                    LookaheadError::Full { .. } => &mut self.stats.refused_full,
                    _ => &mut self.stats.refused_invalid,
                };
                *counter = counter.saturating_add(1);
                Err(err)
            }
        }
    }

    /// The checks of [`Self::push`], returning what an accepted chunk leaves behind.
    fn check_push(&self, chunk: &Chunk) -> Result<Admit, LookaheadError> {
        let len = chunk.payload.len();
        if len == 0 {
            return Err(LookaheadError::InvalidChunk {
                reason: "empty payload",
            });
        }
        if chunk.rate_hz == 0 {
            return Err(LookaheadError::InvalidChunk {
                reason: "zero rate",
            });
        }
        match chunk.epoch.cmp(&self.epoch) {
            Ordering::Less => {
                return Err(LookaheadError::LateOldEpoch {
                    chunk: chunk.epoch.get(),
                    current: self.epoch.get(),
                });
            }
            Ordering::Greater => {
                return Err(LookaheadError::EpochAhead {
                    chunk: chunk.epoch.get(),
                    current: self.epoch.get(),
                });
            }
            Ordering::Equal => {}
        }
        if chunk.track != self.fetch_track {
            return Err(LookaheadError::TrackMismatch {
                chunk: chunk.track.get(),
                expected: self.fetch_track.get(),
            });
        }
        if let Some(expected) = self.fetch_rate_hz.filter(|rate| chunk.rate_hz != *rate) {
            return Err(LookaheadError::RateMismatch {
                chunk: chunk.rate_hz,
                expected,
            });
        }
        if chunk.start_frame != self.fetch_frame {
            return Err(LookaheadError::NotContiguous {
                start_frame: chunk.start_frame,
                expected_frame: self.fetch_frame,
            });
        }
        if len > self.limits.max_chunk_bytes {
            return Err(LookaheadError::ChunkTooLarge {
                bytes: len,
                max: self.limits.max_chunk_bytes,
            });
        }
        let cost_ns = duration_ns_ceil(u64::from(chunk.frames), chunk.rate_hz).ok_or(
            LookaheadError::Overflow {
                what: "chunk duration",
            },
        )?;
        // The end of the chunk must fit even when it is the last of its track.
        let end = chunk
            .start_frame
            .checked_add(u64::from(chunk.frames))
            .ok_or(LookaheadError::Overflow {
                what: "frame position",
            })?;
        let (track, frame, rate_hz) = if chunk.last_of_track {
            let serial = chunk
                .track
                .get()
                .checked_add(1)
                .ok_or(LookaheadError::Overflow {
                    what: "track serial",
                })?;
            (TrackSerial::new(serial), 0, None)
        } else {
            (chunk.track, end, Some(chunk.rate_hz))
        };
        if self.bytes.saturating_add(len) > self.limits.max_bytes {
            return Err(LookaheadError::Full {
                cap: CapKind::Bytes,
            });
        }
        let cap_ns = self.limits.max_media_ms.saturating_mul(NS_PER_MS);
        if self.media_ns.saturating_add(cost_ns) > cap_ns {
            return Err(LookaheadError::Full {
                cap: CapKind::MediaMs,
            });
        }
        if self.chunks.len() >= self.limits.max_chunks {
            return Err(LookaheadError::Full {
                cap: CapKind::Chunks,
            });
        }
        Ok(Admit {
            track,
            frame,
            rate_hz,
            cost_ns,
        })
    }

    /// Hand the oldest chunk to the decoder, with a ticket that stays outstanding until
    /// [`Self::retire`]d. Refused while a transition is unfenced or failed: nothing of the new timeline may
    /// reach the renderer before the old output is accounted for. Refused when `max_outstanding` chunks are
    /// already being decoded. Handing a chunk out marks its epoch as having output that a later
    /// transition must fence.
    pub fn pop(&mut self) -> Result<Option<Handoff>, LookaheadError> {
        match self.transition {
            Some(Transition {
                phase: Phase::AwaitingFence,
                ..
            }) => return Err(LookaheadError::TransitionPending),
            Some(Transition {
                phase: Phase::Failed,
                ..
            }) => return Err(LookaheadError::TransitionFailed),
            None => {}
        }
        if self.chunks.is_empty() {
            return Ok(None);
        }
        if self.outstanding.len() >= self.limits.max_outstanding {
            return Err(LookaheadError::OutstandingLimit {
                max: self.limits.max_outstanding,
            });
        }
        let seq = self.next_seq;
        let next = seq.checked_add(1).ok_or(LookaheadError::Overflow {
            what: "handoff sequence",
        })?;
        let Some(chunk) = self.chunks.pop_front() else {
            return Ok(None);
        };
        self.next_seq = next;
        self.bytes -= chunk.payload.len();
        self.media_ns -= charge_ns(&chunk);
        self.output_epoch = Some(chunk.epoch);
        self.playback_track = Some(chunk.track);
        let ticket = HandoffTicket {
            seq,
            epoch: chunk.epoch,
            queue: Arc::clone(&self.identity),
        };
        self.outstanding.push(ticket.clone());
        Ok(Some(Handoff { chunk, ticket }))
    }

    /// End a handoff: its decoded audio was submitted to the output (with the OUTPUT position where it
    /// ends) or its decode was cancelled and joined. Refused, with nothing changed, for a ticket another
    /// queue issued (`ForeignHandoff`: it retires nothing here, whatever its epoch and sequence), for a
    /// ticket that is not outstanding (already retired, never issued, or from a fenced epoch), for an
    /// output domain with a zero rate, and for a submission in a different output domain than the epoch's
    /// earlier submissions: one epoch's output lives in one session, generation and rate. A submission that
    /// retires after a transition began is still counted, so a fence measured before it cannot cover it.
    pub fn retire(
        &mut self,
        ticket: &HandoffTicket,
        how: Retirement,
    ) -> Result<(), LookaheadError> {
        if !self.owns(ticket) {
            return Err(LookaheadError::ForeignHandoff { seq: ticket.seq });
        }
        let Some(index) = self.outstanding.iter().position(|t| t == ticket) else {
            return Err(LookaheadError::UnknownHandoff { seq: ticket.seq });
        };
        let submitted = match how {
            Retirement::Cancelled => self.submitted,
            Retirement::Submitted { end } => {
                if end.domain.rate_hz == 0 {
                    return Err(LookaheadError::InvalidOutputDomain {
                        reason: "zero rate",
                    });
                }
                match self.submitted {
                    Some(have) if have.domain != end.domain => {
                        return Err(LookaheadError::OutputDomainChanged);
                    }
                    Some(have) => Some(OutputPosition {
                        domain: have.domain,
                        frame: have.frame.max(end.frame),
                    }),
                    None => Some(end),
                }
            }
        };
        self.submitted = submitted;
        self.outstanding.swap_remove(index);
        Ok(())
    }

    /// The memory ledger changed the allowance. Adopt `limits` and drop the chunks furthest in the future
    /// until the queue fits, which may empty it. The fetch position moves back to the first dropped
    /// chunk, so the fetcher refetches contiguously. Only counts come back.
    pub fn shrink_to(&mut self, limits: LookaheadLimits) -> Result<Evicted, LookaheadError> {
        limits.validate()?;
        self.limits = limits;
        let cap_ns = limits.max_media_ms.saturating_mul(NS_PER_MS);
        // A queued chunk larger than the new per-chunk limit cannot stay, and neither can anything admitted
        // after it (the queue is contiguous), so eviction runs from the tail down to the first such chunk.
        let oversize_at = self
            .chunks
            .iter()
            .position(|c| c.payload.len() > limits.max_chunk_bytes);
        let mut evicted = Evicted::default();
        while self.bytes > limits.max_bytes
            || self.media_ns > cap_ns
            || self.chunks.len() > limits.max_chunks
            || oversize_at.is_some_and(|keep| self.chunks.len() > keep)
        {
            let Some(chunk) = self.chunks.pop_back() else {
                break;
            };
            let charge = charge_ns(&chunk);
            self.bytes -= chunk.payload.len();
            self.media_ns -= charge;
            self.fetch_track = chunk.track;
            self.fetch_frame = chunk.start_frame;
            self.fetch_rate_hz = Some(chunk.rate_hz);
            evicted.chunks += 1;
            evicted.bytes += chunk.payload.len();
            evicted.media_ns += charge;
        }
        self.stats.evicted_chunks = self
            .stats
            .evicted_chunks
            .saturating_add(u64::try_from(evicted.chunks).unwrap_or(u64::MAX));
        self.stats.evicted_bytes = self
            .stats
            .evicted_bytes
            .saturating_add(u64::try_from(evicted.bytes).unwrap_or(u64::MAX));
        Ok(evicted)
    }

    /// Begin a seek or skip. `epoch` is the next source epoch from the arbiter and must be ahead of the
    /// current one; `track` and `target_frame` say where the new timeline starts. Every buffered chunk of
    /// the old timeline is dropped at once and the queue accepts the new epoch, but the seek is NOT
    /// acknowledged unless [`TransitionStart::fence`] is `None`: otherwise the caller must present the
    /// request to an [`OutputFenceSource`] through [`Self::ack_transition`].
    pub fn begin_transition(
        &mut self,
        epoch: SourceEpoch,
        track: TrackSerial,
        target_frame: u64,
    ) -> Result<TransitionStart, LookaheadError> {
        if epoch <= self.epoch {
            return Err(LookaheadError::TransitionEpochNotAhead {
                requested: epoch.get(),
                current: self.epoch.get(),
            });
        }
        let fence = match self.output_epoch {
            Some(fence_epoch) => {
                let token = FenceToken::new(self.next_token);
                let next = self
                    .next_token
                    .checked_add(1)
                    .ok_or(LookaheadError::Overflow {
                        what: "fence token",
                    })?;
                self.next_token = next;
                Some((token, fence_epoch))
            }
            None => None,
        };
        let superseded = self.transition.is_some();
        let dropped_chunks = self.chunks.len();
        let dropped_bytes = self.bytes;
        self.chunks.clear();
        self.bytes = 0;
        self.media_ns = 0;
        self.epoch = epoch;
        self.fetch_track = track;
        self.fetch_frame = target_frame;
        self.fetch_rate_hz = None;
        self.stats.invalidated_chunks = self
            .stats
            .invalidated_chunks
            .saturating_add(u64::try_from(dropped_chunks).unwrap_or(u64::MAX));
        self.stats.invalidated_bytes = self
            .stats
            .invalidated_bytes
            .saturating_add(u64::try_from(dropped_bytes).unwrap_or(u64::MAX));
        if superseded {
            self.stats.transitions_superseded = self.stats.transitions_superseded.saturating_add(1);
        }
        self.transition = fence.map(|(token, fence_epoch)| Transition {
            token,
            to_epoch: epoch,
            fence_epoch,
            phase: Phase::AwaitingFence,
        });
        Ok(TransitionStart {
            epoch,
            fence: fence.map(|(token, fence_epoch)| FenceRequest {
                token,
                epoch: fence_epoch,
            }),
            superseded,
            dropped_chunks,
            dropped_bytes,
        })
    }

    /// Acknowledge the pending transition. The verdict is not an argument: the queue asks `renderer` for
    /// evidence about the pending request, once, and judges it. Refused, with `renderer` not consulted, if
    /// no transition is pending, it already failed, or any handed-out chunk is still outstanding (decoder
    /// work the device cannot see yet). Refused, with nothing changed, if the report's token is not the
    /// pending request's, it speaks for another epoch or another output domain, it covers less than the
    /// submissions recorded by [`Self::retire`], or the old output has not drained. A report of a flush
    /// that timed out fails the transition for good: no later report acknowledges it, and only a new
    /// transition replaces it.
    pub fn ack_transition<F: OutputFenceSource + ?Sized>(
        &mut self,
        renderer: &mut F,
    ) -> Result<TransitionAck, LookaheadError> {
        let Some(transition) = self.transition else {
            return Err(LookaheadError::NoTransition);
        };
        if transition.phase == Phase::Failed {
            return Err(LookaheadError::TransitionFailed);
        }
        if !self.outstanding.is_empty() {
            return Err(LookaheadError::OutstandingDecoderWork {
                outstanding: self.outstanding.len(),
            });
        }
        let report = renderer.fence(FenceRequest {
            token: transition.token,
            epoch: transition.fence_epoch,
        });
        if report.token != transition.token {
            return Err(LookaheadError::FenceTokenStale {
                got: report.token.get(),
                expected: transition.token.get(),
            });
        }
        if report.epoch != transition.fence_epoch {
            return Err(LookaheadError::FenceEpochMismatch {
                fence: report.epoch.get(),
                expected: transition.fence_epoch.get(),
            });
        }
        let via = match report.outcome {
            FenceOutcome::Drained { tail, played } => {
                if tail.domain != played.domain {
                    return Err(LookaheadError::FenceDomainMismatch);
                }
                if let Some(have) = self.submitted {
                    if have.domain != tail.domain {
                        return Err(LookaheadError::FenceDomainMismatch);
                    }
                    if tail.frame < have.frame {
                        return Err(LookaheadError::FenceTailBehindSubmissions {
                            required: have.frame,
                            reported: tail.frame,
                        });
                    }
                }
                if played.frame < tail.frame {
                    return Err(LookaheadError::OutputNotDrained {
                        tail_frame: tail.frame,
                        played_frame: played.frame,
                    });
                }
                FenceKind::Drained
            }
            FenceOutcome::FlushAcknowledged { domain, .. } => {
                if self.submitted.is_some_and(|have| have.domain != domain) {
                    return Err(LookaheadError::FenceDomainMismatch);
                }
                FenceKind::Flushed
            }
            FenceOutcome::FlushTimedOut { .. } => {
                self.transition = Some(Transition {
                    phase: Phase::Failed,
                    ..transition
                });
                self.stats.transitions_failed = self.stats.transitions_failed.saturating_add(1);
                return Err(LookaheadError::FlushTimedOut);
            }
        };
        self.transition = None;
        self.output_epoch = None;
        self.submitted = None;
        self.stats.transitions_acked = self.stats.transitions_acked.saturating_add(1);
        Ok(TransitionAck {
            epoch: transition.to_epoch,
            via,
        })
    }
}

#[cfg(test)]
mod tests;
