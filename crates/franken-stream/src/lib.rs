//! Authenticated Audio Stream Framing, Replay Window, Bounded Jitter Buffer, and FEC
//! (`N01` / `ffw-ey5`, `N04` / `ffw-nx0`, `N05` / `ffw-8cy`, `N06` / `ffw-re8`).
//!
//! The N01 wire contract is `docs/contracts/n01.md`; `tests/n01/reference_frames.py` is an
//! independent (stdlib `hmac` + `struct`) implementation of it that produces the golden vectors
//! this crate's tests replay.
//!
//! Receive order is fixed and is the point of the design: cheap structural bounds, then the MAC,
//! then field validation, then stream/epoch/sequence state, and only then is any state recorded.
//! A packet that fails any earlier step changes nothing, so forged or mutated traffic can never
//! consume a sequence number, move an epoch, or reach the jitter buffer.

#![forbid(unsafe_code)]

use franken_dsp::{FRAMES_PER_BLOCK, StereoAudioBlock};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

pub const WIRE_MAGIC: [u8; 4] = *b"FFWS";
pub const WIRE_VERSION: u8 = 1;
/// Fixed 64-byte big-endian header (every integer is big-endian; nothing is a serialized struct):
/// - `0..4`: magic `FFWS`
/// - `4`: version (`1`)
/// - `5`: packet kind (`1` media, `2` repair)
/// - `6`: flags (`0xF0` critical bits, `0x0F` ignorable bits)
/// - `7`: format (`1` = signed 16-bit big-endian stereo PCM, 48 kHz)
/// - `8..16`: `stream_id` (`u64`, nonzero, random per stream start)
/// - `16..24`: `session_epoch` (`u64`)
/// - `24..32`: `seq` (`u64`, starts at 0 in every epoch)
/// - `32..40`: `start_frame` (`u64`, multiple of 256)
/// - `40..48`: `presentation_time_ns` (`u64`, at most 2^62)
/// - `48..56`: `consume_by_ns` (`u64`, at most `presentation_time_ns`)
/// - `56..58`: `fec_group_id` (`u16`)
/// - `58`: `fec_index`
/// - `59`: `fec_group_size`
/// - `60..62`: `frame_count` (`u16`, 1..=256, equals `payload_len / 4`)
/// - `62..64`: `payload_len` (`u16`, at most 1024)
///
/// The datagram is `header || payload || tag`. The tag is the first 16 bytes of
/// `HMAC-SHA256(key, AUTH_CONTEXT || header || payload)`, so routing, timing, epoch and format
/// fields are all authenticated together with the payload.
pub const HEADER_LEN_BYTES: usize = 64;
pub const AUTH_TAG_LEN_BYTES: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = FRAMES_PER_BLOCK * 4; // 1024 bytes for 256 stereo i16 frames
pub const MIN_DATAGRAM_BYTES: usize = HEADER_LEN_BYTES + AUTH_TAG_LEN_BYTES;
pub const MAX_DATAGRAM_BYTES: usize = HEADER_LEN_BYTES + MAX_PAYLOAD_BYTES + AUTH_TAG_LEN_BYTES;
/// Domain-separation prefix hashed ahead of every authenticated header.
pub const AUTH_CONTEXT: &[u8] = b"FFWS-v1-auth";
/// Flag bits a receiver must understand to process the packet; an unknown one is a hard reject.
pub const CRITICAL_FLAGS_MASK: u8 = 0xF0;
/// Largest timestamp the wire accepts (2^62 ns, about 146 years).
pub const MAX_TIMESTAMP_NS: u64 = 1 << 62;
pub const MAX_FEC_GROUP_SIZE: u8 = 16;
/// Sequence numbers this far behind the highest accepted one are still reorder-tolerant.
pub const REPLAY_WINDOW_PACKETS: u64 = 64;
/// Provisional bound (about 5.4 s of 5.333 ms blocks) on how far ahead of the highest accepted
/// sequence a packet may be before it is discarded and counted. Without it one authenticated
/// packet with a huge `seq` would turn every genuine packet into a "replay".
pub const MAX_FORWARD_SEQ_GAP: u64 = 1024;

const BYTES_PER_FRAME: usize = 4;
const OFF_VERSION: usize = 4;
const OFF_KIND: usize = 5;
const OFF_FLAGS: usize = 6;
const OFF_FORMAT: usize = 7;
const OFF_STREAM_ID: usize = 8;
const OFF_EPOCH: usize = 16;
const OFF_SEQ: usize = 24;
const OFF_START_FRAME: usize = 32;
const OFF_PRESENTATION: usize = 40;
const OFF_CONSUME_BY: usize = 48;
const OFF_FEC_GROUP: usize = 56;
const OFF_FEC_INDEX: usize = 58;
const OFF_FEC_SIZE: usize = 59;
const OFF_FRAME_COUNT: usize = 60;
const OFF_PAYLOAD_LEN: usize = 62;

/// Every rejection carries only numbers: never a key, a tag, or any payload byte.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum StreamError {
    #[error("datagram length {0} is shorter than the minimum header+tag size")]
    PacketTooShort(usize),
    #[error("datagram length {len} exceeds the maximum {MAX_DATAGRAM_BYTES}")]
    DatagramTooLong { len: usize },
    #[error("wire magic does not match")]
    BadMagic,
    #[error("unsupported wire version {version} (this receiver speaks {WIRE_VERSION})")]
    UnsupportedWireVersion { version: u8 },
    #[error("declared payload length {len} exceeds maximum {MAX_PAYLOAD_BYTES}")]
    PayloadTooLarge { len: usize },
    #[error("datagram truncated: {actual} bytes, header declares {expected}")]
    Truncated { expected: usize, actual: usize },
    #[error("datagram has trailing bytes: {actual} bytes, header declares {expected}")]
    TrailingBytes { expected: usize, actual: usize },
    #[error("HMAC authentication tag verification failed")]
    AuthenticationFailed,
    #[error("unknown packet kind {kind}")]
    UnknownPacketKind { kind: u8 },
    #[error("unknown critical flag bits set in {flags:#04x}")]
    UnknownCriticalFlags { flags: u8 },
    #[error("unknown stream format {format}")]
    UnknownFormat { format: u8 },
    #[error("frame count {frames} is outside 1..={FRAMES_PER_BLOCK}")]
    FrameCountOutOfRange { frames: usize },
    #[error("frame count {declared} does not match payload length {payload_len}")]
    FrameCountMismatch { declared: u16, payload_len: usize },
    #[error("start frame {start_frame} is not on a {FRAMES_PER_BLOCK}-frame boundary")]
    MisalignedStartFrame { start_frame: u64 },
    #[error(
        "invalid timestamps: presentation {presentation_time_ns} ns, consume-by {consume_by_ns} ns"
    )]
    InvalidTimestamps {
        presentation_time_ns: u64,
        consume_by_ns: u64,
    },
    #[error("invalid FEC fields: group size {fec_group_size}, index {fec_index}")]
    InvalidFecFields { fec_group_size: u8, fec_index: u8 },
    #[error("stream identity must be nonzero")]
    InvalidStreamId,
    #[error("packet belongs to stream {packet_stream}, not the bound stream")]
    WrongStream { packet_stream: u64 },
    #[error("stale session epoch: packet epoch {packet_epoch} < active epoch {active_epoch}")]
    StaleSessionEpoch {
        packet_epoch: u64,
        active_epoch: u64,
    },
    #[error(
        "future session epoch: packet epoch {packet_epoch} > active epoch {active_epoch}; epochs advance only through the control channel"
    )]
    FutureSessionEpoch {
        packet_epoch: u64,
        active_epoch: u64,
    },
    #[error("packet seq {seq} is outside or already seen in replay window")]
    ReplayOrDuplicatePacket { seq: u64 },
    #[error("packet seq {seq} is beyond the admissible future window (limit {limit})")]
    SequenceBeyondFutureWindow { seq: u64, limit: u64 },
    #[error("sender sequence space exhausted; advance the epoch")]
    SequenceExhausted,
    #[error("epoch {requested} does not advance past {current}")]
    EpochNotAdvancing { requested: u64, current: u64 },
    #[error("packet arrived after its consume_by deadline ({now_ns} > {consume_by_ns})")]
    ExpiredConsumeByDeadline { now_ns: u64, consume_by_ns: u64 },
    #[error("only media packets are admitted to the jitter buffer")]
    NotMediaPacket,
    #[error("payload of {len} bytes is not valid stereo PCM for the jitter buffer")]
    PayloadFormatMismatch { len: usize },
}

impl StreamError {
    /// Stable machine-readable name, shared with the golden vectors and the Python reference.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PacketTooShort(_) => "PACKET_TOO_SHORT",
            Self::DatagramTooLong { .. } => "DATAGRAM_TOO_LONG",
            Self::BadMagic => "BAD_MAGIC",
            Self::UnsupportedWireVersion { .. } => "UNSUPPORTED_VERSION",
            Self::PayloadTooLarge { .. } => "PAYLOAD_TOO_LARGE",
            Self::Truncated { .. } => "TRUNCATED",
            Self::TrailingBytes { .. } => "TRAILING_BYTES",
            Self::AuthenticationFailed => "AUTH_FAILED",
            Self::UnknownPacketKind { .. } => "UNKNOWN_PACKET_KIND",
            Self::UnknownCriticalFlags { .. } => "UNKNOWN_CRITICAL_FLAGS",
            Self::UnknownFormat { .. } => "UNKNOWN_FORMAT",
            Self::FrameCountOutOfRange { .. } => "FRAME_COUNT_OUT_OF_RANGE",
            Self::FrameCountMismatch { .. } => "FRAME_COUNT_MISMATCH",
            Self::MisalignedStartFrame { .. } => "MISALIGNED_START_FRAME",
            Self::InvalidTimestamps { .. } => "INVALID_TIMESTAMPS",
            Self::InvalidFecFields { .. } => "INVALID_FEC_FIELDS",
            Self::InvalidStreamId => "INVALID_STREAM_ID",
            Self::WrongStream { .. } => "WRONG_STREAM",
            Self::StaleSessionEpoch { .. } => "STALE_EPOCH",
            Self::FutureSessionEpoch { .. } => "FUTURE_EPOCH",
            Self::ReplayOrDuplicatePacket { .. } => "REPLAY_OR_DUPLICATE",
            Self::SequenceBeyondFutureWindow { .. } => "FUTURE_SEQUENCE",
            Self::SequenceExhausted => "SEQUENCE_EXHAUSTED",
            Self::EpochNotAdvancing { .. } => "EPOCH_NOT_ADVANCING",
            Self::ExpiredConsumeByDeadline { .. } => "EXPIRED_CONSUME_BY",
            Self::NotMediaPacket => "NOT_MEDIA_PACKET",
            Self::PayloadFormatMismatch { .. } => "PAYLOAD_FORMAT_MISMATCH",
        }
    }
}

/// Shared 32-byte stream authentication key. `Debug` never prints the bytes, and the type has no
/// `Serialize`, `Display` or equality, so a key cannot reach a log or be compared in variable time
/// by accident. (Bytes are not zeroized on drop: no zeroize dependency is admitted yet.)
#[derive(Clone)]
pub struct StreamKey([u8; 32]);

impl StreamKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamKey([REDACTED])")
    }
}

/// Random per-stream-start identity, drawn by the sender from admitted entropy. A restarted or
/// rekeyed sender must use a fresh one, which is what makes pre-restart packets inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId(u64);

impl StreamId {
    /// Zero is reserved as "unset", so an uninitialised sender cannot transmit.
    pub fn new(raw: u64) -> Result<Self, StreamError> {
        if raw == 0 {
            Err(StreamError::InvalidStreamId)
        } else {
            Ok(Self(raw))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketKind {
    Media,
    Repair,
}

impl PacketKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Media => 1,
            Self::Repair => 2,
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Media),
            2 => Some(Self::Repair),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamFormat {
    /// Signed 16-bit big-endian interleaved stereo PCM at 48 kHz.
    Pcm16BeStereo48k,
}

impl StreamFormat {
    const fn wire(self) -> u8 {
        match self {
            Self::Pcm16BeStereo48k => 1,
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Pcm16BeStereo48k),
            _ => None,
        }
    }

    const fn bytes_per_frame(self) -> usize {
        match self {
            Self::Pcm16BeStereo48k => BYTES_PER_FRAME,
        }
    }
}

/// Authenticated big-endian audio stream packet (`N01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedStreamPacket {
    pub stream_id: StreamId,
    pub session_epoch: u64,
    pub seq: u64,
    pub kind: PacketKind,
    pub format: StreamFormat,
    /// Only the ignorable low nibble may be nonzero on the wire in v1.
    pub flags: u8,
    pub start_frame: u64,
    pub presentation_time_ns: u64,
    pub consume_by_ns: u64,
    pub fec_group_id: u16,
    pub fec_index: u8,
    pub fec_group_size: u8,
    pub payload: Vec<u8>,
}

/// Fields of a validated header, read straight from the big-endian bytes.
struct ParsedHeader {
    kind: PacketKind,
    format: StreamFormat,
    flags: u8,
    stream_id: u64,
    session_epoch: u64,
    seq: u64,
    start_frame: u64,
    presentation_time_ns: u64,
    consume_by_ns: u64,
    fec_group_id: u16,
    fec_index: u8,
    fec_group_size: u8,
}

fn be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn be_u64(buf: &[u8], off: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(raw)
}

/// Field validation shared by the encoder and the decoder, so a sender can never emit a frame its
/// own receiver would reject. Runs only after the MAC has passed on the receive side.
fn parse_header(h: &[u8]) -> Result<ParsedHeader, StreamError> {
    let Some(kind) = PacketKind::from_wire(h[OFF_KIND]) else {
        return Err(StreamError::UnknownPacketKind { kind: h[OFF_KIND] });
    };
    let flags = h[OFF_FLAGS];
    if flags & CRITICAL_FLAGS_MASK != 0 {
        return Err(StreamError::UnknownCriticalFlags { flags });
    }
    let Some(format) = StreamFormat::from_wire(h[OFF_FORMAT]) else {
        return Err(StreamError::UnknownFormat {
            format: h[OFF_FORMAT],
        });
    };
    let frame_count = be_u16(h, OFF_FRAME_COUNT);
    let payload_len = usize::from(be_u16(h, OFF_PAYLOAD_LEN));
    if frame_count == 0 || usize::from(frame_count) > FRAMES_PER_BLOCK {
        return Err(StreamError::FrameCountOutOfRange {
            frames: usize::from(frame_count),
        });
    }
    if payload_len != usize::from(frame_count) * format.bytes_per_frame() {
        return Err(StreamError::FrameCountMismatch {
            declared: frame_count,
            payload_len,
        });
    }
    let start_frame = be_u64(h, OFF_START_FRAME);
    if !start_frame.is_multiple_of(FRAMES_PER_BLOCK as u64) {
        return Err(StreamError::MisalignedStartFrame { start_frame });
    }
    let presentation_time_ns = be_u64(h, OFF_PRESENTATION);
    let consume_by_ns = be_u64(h, OFF_CONSUME_BY);
    if presentation_time_ns > MAX_TIMESTAMP_NS || consume_by_ns > presentation_time_ns {
        return Err(StreamError::InvalidTimestamps {
            presentation_time_ns,
            consume_by_ns,
        });
    }
    let fec_index = h[OFF_FEC_INDEX];
    let fec_group_size = h[OFF_FEC_SIZE];
    let fec_ok = match kind {
        PacketKind::Media => {
            if fec_group_size == 0 {
                fec_index == 0
            } else {
                fec_group_size <= MAX_FEC_GROUP_SIZE && fec_index < fec_group_size
            }
        }
        PacketKind::Repair => {
            (1..=MAX_FEC_GROUP_SIZE).contains(&fec_group_size) && fec_index < MAX_FEC_GROUP_SIZE
        }
    };
    if !fec_ok {
        return Err(StreamError::InvalidFecFields {
            fec_group_size,
            fec_index,
        });
    }
    if be_u64(h, OFF_STREAM_ID) == 0 {
        return Err(StreamError::InvalidStreamId);
    }
    Ok(ParsedHeader {
        kind,
        format,
        flags,
        stream_id: be_u64(h, OFF_STREAM_ID),
        session_epoch: be_u64(h, OFF_EPOCH),
        seq: be_u64(h, OFF_SEQ),
        start_frame,
        presentation_time_ns,
        consume_by_ns,
        fec_group_id: be_u16(h, OFF_FEC_GROUP),
        fec_index,
        fec_group_size,
    })
}

/// Cheap, unauthenticated bounds. Everything here is O(1) in the datagram size, so a flood of
/// garbage is rejected before any MAC work. Returns the declared payload length.
fn check_frame_structure(wire: &[u8]) -> Result<usize, StreamError> {
    if wire.len() < MIN_DATAGRAM_BYTES {
        return Err(StreamError::PacketTooShort(wire.len()));
    }
    if wire.len() > MAX_DATAGRAM_BYTES {
        return Err(StreamError::DatagramTooLong { len: wire.len() });
    }
    if wire[0..4] != WIRE_MAGIC {
        return Err(StreamError::BadMagic);
    }
    let version = wire[OFF_VERSION];
    if version != WIRE_VERSION {
        return Err(StreamError::UnsupportedWireVersion { version });
    }
    let payload_len = usize::from(be_u16(wire, OFF_PAYLOAD_LEN));
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(StreamError::PayloadTooLarge { len: payload_len });
    }
    let expected = HEADER_LEN_BYTES + payload_len + AUTH_TAG_LEN_BYTES;
    if wire.len() < expected {
        return Err(StreamError::Truncated {
            expected,
            actual: wire.len(),
        });
    }
    if wire.len() > expected {
        return Err(StreamError::TrailingBytes {
            expected,
            actual: wire.len(),
        });
    }
    Ok(payload_len)
}

fn compute_tag_16(key: &StreamKey, header: &[u8], payload: &[u8]) -> [u8; AUTH_TAG_LEN_BYTES] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("32-byte HMAC key is valid");
    mac.update(AUTH_CONTEXT);
    mac.update(header);
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN_BYTES];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN_BYTES]);
    tag
}

fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl AuthenticatedStreamPacket {
    /// Encode header + payload + 16-byte truncated HMAC-SHA256 tag in network big-endian byte order.
    /// Refuses anything a conforming receiver would reject (oversize payload, unknown critical
    /// flags, bad frame count, misaligned start frame, inverted timestamps, bad FEC fields).
    pub fn encode_signed(&self, key: &StreamKey) -> Result<Vec<u8>, StreamError> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(StreamError::PayloadTooLarge {
                len: self.payload.len(),
            });
        }
        let mut header = [0u8; HEADER_LEN_BYTES];
        header[0..4].copy_from_slice(&WIRE_MAGIC);
        header[OFF_VERSION] = WIRE_VERSION;
        header[OFF_KIND] = self.kind.wire();
        header[OFF_FLAGS] = self.flags;
        header[OFF_FORMAT] = self.format.wire();
        header[OFF_STREAM_ID..OFF_STREAM_ID + 8]
            .copy_from_slice(&self.stream_id.get().to_be_bytes());
        header[OFF_EPOCH..OFF_EPOCH + 8].copy_from_slice(&self.session_epoch.to_be_bytes());
        header[OFF_SEQ..OFF_SEQ + 8].copy_from_slice(&self.seq.to_be_bytes());
        header[OFF_START_FRAME..OFF_START_FRAME + 8]
            .copy_from_slice(&self.start_frame.to_be_bytes());
        header[OFF_PRESENTATION..OFF_PRESENTATION + 8]
            .copy_from_slice(&self.presentation_time_ns.to_be_bytes());
        header[OFF_CONSUME_BY..OFF_CONSUME_BY + 8]
            .copy_from_slice(&self.consume_by_ns.to_be_bytes());
        header[OFF_FEC_GROUP..OFF_FEC_GROUP + 2].copy_from_slice(&self.fec_group_id.to_be_bytes());
        header[OFF_FEC_INDEX] = self.fec_index;
        header[OFF_FEC_SIZE] = self.fec_group_size;
        let frames = (self.payload.len() / self.format.bytes_per_frame()) as u16;
        header[OFF_FRAME_COUNT..OFF_FRAME_COUNT + 2].copy_from_slice(&frames.to_be_bytes());
        header[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
            .copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        parse_header(&header)?;

        let tag = compute_tag_16(key, &header, &self.payload);
        let mut buf =
            Vec::with_capacity(HEADER_LEN_BYTES + self.payload.len() + AUTH_TAG_LEN_BYTES);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    /// Verify HMAC-SHA256 tag and decode big-endian packet fields. Stateless: epoch, stream and
    /// replay checks belong to [`StreamReceiver`].
    pub fn decode_and_verify(wire: &[u8], key: &StreamKey) -> Result<Self, StreamError> {
        let payload_len = check_frame_structure(wire)?;
        Self::verify_and_parse(wire, payload_len, key)
    }

    fn verify_and_parse(
        wire: &[u8],
        payload_len: usize,
        key: &StreamKey,
    ) -> Result<Self, StreamError> {
        let body_end = HEADER_LEN_BYTES + payload_len;
        let header = &wire[..HEADER_LEN_BYTES];
        let payload = &wire[HEADER_LEN_BYTES..body_end];
        let computed = compute_tag_16(key, header, payload);
        if !tags_equal(&wire[body_end..], &computed) {
            return Err(StreamError::AuthenticationFailed);
        }
        let parsed = parse_header(header)?;
        Ok(Self {
            stream_id: StreamId(parsed.stream_id),
            session_epoch: parsed.session_epoch,
            seq: parsed.seq,
            kind: parsed.kind,
            format: parsed.format,
            flags: parsed.flags,
            start_frame: parsed.start_frame,
            presentation_time_ns: parsed.presentation_time_ns,
            consume_by_ns: parsed.consume_by_ns,
            fec_group_id: parsed.fec_group_id,
            fec_index: parsed.fec_index,
            fec_group_size: parsed.fec_group_size,
            payload: payload.to_vec(),
        })
    }
}

/// Sliding anti-replay, epoch, and future-window state (`N01`).
///
/// Newer epochs are never adopted from packets: they arrive through [`ReplayWindow::advance_epoch`]
/// (the authenticated control channel). Sequence numbers are per epoch and start at the seeded
/// origin (0 unless joined mid-stream).
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    active_epoch: u64,
    origin_seq: u64,
    highest_seq: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    #[must_use]
    pub const fn new(active_epoch: u64) -> Self {
        Self::join_at(active_epoch, 0)
    }

    /// Start at `first_expected_seq`, for a receiver joining a stream already in progress.
    #[must_use]
    pub const fn join_at(active_epoch: u64, first_expected_seq: u64) -> Self {
        Self {
            active_epoch,
            origin_seq: first_expected_seq,
            highest_seq: None,
            bitmap: 0,
        }
    }

    #[must_use]
    pub const fn active_epoch(&self) -> u64 {
        self.active_epoch
    }

    #[must_use]
    pub const fn highest_seq(&self) -> Option<u64> {
        self.highest_seq
    }

    /// Adopt a newer epoch announced by the control channel. Older or equal epochs are ignored.
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        if new_epoch > self.active_epoch {
            self.active_epoch = new_epoch;
            self.origin_seq = 0;
            self.highest_seq = None;
            self.bitmap = 0;
        }
    }

    /// Check `(epoch, seq)` and, only if it is admissible, record it. Every error leaves the
    /// window exactly as it was.
    pub fn check_and_record(&mut self, epoch: u64, seq: u64) -> Result<(), StreamError> {
        if epoch < self.active_epoch {
            return Err(StreamError::StaleSessionEpoch {
                packet_epoch: epoch,
                active_epoch: self.active_epoch,
            });
        }
        if epoch > self.active_epoch {
            return Err(StreamError::FutureSessionEpoch {
                packet_epoch: epoch,
                active_epoch: self.active_epoch,
            });
        }
        match self.highest_seq {
            None => {
                if seq < self.origin_seq {
                    return Err(StreamError::ReplayOrDuplicatePacket { seq });
                }
                if seq - self.origin_seq > MAX_FORWARD_SEQ_GAP {
                    return Err(StreamError::SequenceBeyondFutureWindow {
                        seq,
                        limit: self.origin_seq.saturating_add(MAX_FORWARD_SEQ_GAP),
                    });
                }
                self.highest_seq = Some(seq);
                self.bitmap = 1;
                Ok(())
            }
            Some(high) if seq > high => {
                let shift = seq - high;
                if shift > MAX_FORWARD_SEQ_GAP {
                    return Err(StreamError::SequenceBeyondFutureWindow {
                        seq,
                        limit: high.saturating_add(MAX_FORWARD_SEQ_GAP),
                    });
                }
                self.bitmap = if shift >= REPLAY_WINDOW_PACKETS {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest_seq = Some(seq);
                Ok(())
            }
            Some(high) => {
                let delta = high - seq;
                if delta >= REPLAY_WINDOW_PACKETS {
                    return Err(StreamError::ReplayOrDuplicatePacket { seq });
                }
                let mask = 1u64 << delta;
                if (self.bitmap & mask) != 0 {
                    return Err(StreamError::ReplayOrDuplicatePacket { seq });
                }
                self.bitmap |= mask;
                Ok(())
            }
        }
    }
}

/// Bounded per-reason counters. Every datagram fed to [`StreamReceiver::accept`] lands in exactly
/// one of `accepted` or a `rejected_*` field, so `datagrams_seen` equals their sum.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverCounters {
    pub datagrams_seen: u64,
    pub accepted: u64,
    /// MACs actually computed; structural rejects never reach one (the unauthenticated-work cap).
    pub mac_verifications: u64,
    pub rejected_structure: u64,
    pub rejected_unsupported_version: u64,
    pub rejected_authentication: u64,
    pub rejected_malformed_fields: u64,
    pub rejected_wrong_stream: u64,
    pub rejected_stale_epoch: u64,
    pub rejected_future_epoch: u64,
    pub rejected_replay: u64,
    pub rejected_future_sequence: u64,
}

impl ReceiverCounters {
    fn record_rejection(&mut self, err: &StreamError) {
        let slot = match err {
            StreamError::PacketTooShort(_)
            | StreamError::DatagramTooLong { .. }
            | StreamError::BadMagic
            | StreamError::PayloadTooLarge { .. }
            | StreamError::Truncated { .. }
            | StreamError::TrailingBytes { .. } => &mut self.rejected_structure,
            StreamError::UnsupportedWireVersion { .. } => &mut self.rejected_unsupported_version,
            StreamError::AuthenticationFailed => &mut self.rejected_authentication,
            StreamError::UnknownPacketKind { .. }
            | StreamError::UnknownCriticalFlags { .. }
            | StreamError::UnknownFormat { .. }
            | StreamError::FrameCountOutOfRange { .. }
            | StreamError::FrameCountMismatch { .. }
            | StreamError::MisalignedStartFrame { .. }
            | StreamError::InvalidTimestamps { .. }
            | StreamError::InvalidFecFields { .. }
            | StreamError::InvalidStreamId => &mut self.rejected_malformed_fields,
            StreamError::WrongStream { .. } => &mut self.rejected_wrong_stream,
            StreamError::StaleSessionEpoch { .. } => &mut self.rejected_stale_epoch,
            StreamError::FutureSessionEpoch { .. } => &mut self.rejected_future_epoch,
            StreamError::ReplayOrDuplicatePacket { .. } => &mut self.rejected_replay,
            StreamError::SequenceBeyondFutureWindow { .. } => &mut self.rejected_future_sequence,
            // Sender-side and jitter-buffer errors cannot come out of `accept`.
            _ => return,
        };
        *slot = slot.saturating_add(1);
    }
}

/// Receiving endpoint: the only path from raw datagram bytes to an admitted packet.
#[derive(Debug, Clone)]
pub struct StreamReceiver {
    key: StreamKey,
    stream_id: StreamId,
    window: ReplayWindow,
    counters: ReceiverCounters,
}

impl StreamReceiver {
    #[must_use]
    pub fn new(key: StreamKey, stream_id: StreamId, epoch: u64) -> Self {
        Self {
            key,
            stream_id,
            window: ReplayWindow::new(epoch),
            counters: ReceiverCounters::default(),
        }
    }

    /// Bind to a restarted or rekeyed stream (announced over the control channel). Resets the
    /// replay window; packets of the previous stream are rejected as [`StreamError::WrongStream`].
    pub fn bind_stream(&mut self, stream_id: StreamId, epoch: u64) {
        self.stream_id = stream_id;
        self.window = ReplayWindow::new(epoch);
    }

    /// Adopt an epoch announced by the control channel.
    pub fn advance_epoch(&mut self, epoch: u64) {
        self.window.advance_epoch(epoch);
    }

    #[must_use]
    pub const fn active_epoch(&self) -> u64 {
        self.window.active_epoch()
    }

    #[must_use]
    pub const fn counters(&self) -> &ReceiverCounters {
        &self.counters
    }

    /// Admit one datagram. Order: structural bounds, MAC, field validation, stream identity,
    /// epoch, sequence window, and only then is the window updated. A rejection changes nothing
    /// except the counters.
    pub fn accept(&mut self, datagram: &[u8]) -> Result<AuthenticatedStreamPacket, StreamError> {
        self.counters.datagrams_seen = self.counters.datagrams_seen.saturating_add(1);
        match self.admit(datagram) {
            Ok(packet) => {
                self.counters.accepted = self.counters.accepted.saturating_add(1);
                Ok(packet)
            }
            Err(err) => {
                self.counters.record_rejection(&err);
                Err(err)
            }
        }
    }

    fn admit(&mut self, datagram: &[u8]) -> Result<AuthenticatedStreamPacket, StreamError> {
        let payload_len = check_frame_structure(datagram)?;
        self.counters.mac_verifications = self.counters.mac_verifications.saturating_add(1);
        let packet = AuthenticatedStreamPacket::verify_and_parse(datagram, payload_len, &self.key)?;
        if packet.stream_id != self.stream_id {
            return Err(StreamError::WrongStream {
                packet_stream: packet.stream_id.get(),
            });
        }
        self.window
            .check_and_record(packet.session_epoch, packet.seq)?;
        Ok(packet)
    }
}

/// Caller-supplied fields of one outbound frame; the sender owns stream, epoch and sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFrame {
    pub kind: PacketKind,
    pub format: StreamFormat,
    pub flags: u8,
    pub start_frame: u64,
    pub presentation_time_ns: u64,
    pub consume_by_ns: u64,
    pub fec_group_id: u16,
    pub fec_index: u8,
    pub fec_group_size: u8,
    pub payload: Vec<u8>,
}

impl OutboundFrame {
    /// A media block with no FEC coding.
    #[must_use]
    pub fn media(
        start_frame: u64,
        presentation_time_ns: u64,
        consume_by_ns: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            kind: PacketKind::Media,
            format: StreamFormat::Pcm16BeStereo48k,
            flags: 0,
            start_frame,
            presentation_time_ns,
            consume_by_ns,
            fec_group_id: 0,
            fec_index: 0,
            fec_group_size: 0,
            payload,
        }
    }
}

/// Sending endpoint. Sequence numbers start at 0 in every epoch, advance only after a frame was
/// encoded, and never wrap: when the space is exhausted the sender stops until the epoch advances.
#[derive(Debug, Clone)]
pub struct StreamSender {
    key: StreamKey,
    stream_id: StreamId,
    epoch: u64,
    next_seq: u64,
}

impl StreamSender {
    #[must_use]
    pub fn new(key: StreamKey, stream_id: StreamId, epoch: u64) -> Self {
        Self {
            key,
            stream_id,
            epoch,
            next_seq: 0,
        }
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Move to a strictly newer epoch and restart the sequence at 0.
    pub fn advance_epoch(&mut self, epoch: u64) -> Result<(), StreamError> {
        if epoch <= self.epoch {
            return Err(StreamError::EpochNotAdvancing {
                requested: epoch,
                current: self.epoch,
            });
        }
        self.epoch = epoch;
        self.next_seq = 0;
        Ok(())
    }

    pub fn send(&mut self, frame: OutboundFrame) -> Result<Vec<u8>, StreamError> {
        if self.next_seq == u64::MAX {
            return Err(StreamError::SequenceExhausted);
        }
        let packet = AuthenticatedStreamPacket {
            stream_id: self.stream_id,
            session_epoch: self.epoch,
            seq: self.next_seq,
            kind: frame.kind,
            format: frame.format,
            flags: frame.flags,
            start_frame: frame.start_frame,
            presentation_time_ns: frame.presentation_time_ns,
            consume_by_ns: frame.consume_by_ns,
            fec_group_id: frame.fec_group_id,
            fec_index: frame.fec_index,
            fec_group_size: frame.fec_group_size,
            payload: frame.payload,
        };
        let wire = packet.encode_signed(&self.key)?;
        self.next_seq += 1;
        Ok(wire)
    }
}

/// Playout mode controlling target buffering depth (`N04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayoutMode {
    /// 500 ms target playout horizon (94 blocks of 5.333 ms).
    Music500ms,
    /// 45 ms low-latency video playout horizon (9 blocks of 5.333 ms).
    VideoLowLatency,
}

/// Decision returned when pulling the next due block from [`BoundedJitterBuffer`].
#[derive(Debug, Clone, PartialEq)]
pub enum PlayoutPullDecision {
    /// Exact block arrived in time.
    AuthenticBlock(StereoAudioBlock),
    /// Missing block recovered via bounded XOR parity FEC before its `consume_by_ns` deadline.
    FecRecoveredBlock(StereoAudioBlock),
    /// Block missing at deadline; emitted smooth attenuated PLC concealment block.
    PlcConcealedBlock {
        start_frame: u64,
        consecutive_missing: u32,
        block: StereoAudioBlock,
    },
}

/// Bounded adaptive jitter buffer with `consume_by` cutoff, PLC fade, and 4-packet XOR parity FEC (`N04` / `N06`).
///
/// Feed it only packets returned by [`StreamReceiver::accept`]: that is the authentication and
/// replay gate (`N01`), and this buffer assumes it has already happened.
#[derive(Debug, Clone)]
pub struct BoundedJitterBuffer {
    mode: PlayoutMode,
    max_blocks: usize,
    queue: BTreeMap<u64, StereoAudioBlock>,
    last_good_block: Option<StereoAudioBlock>,
    consecutive_missing: u32,
    late_dropped_count: u64,
    plc_concealed_count: u64,
    fec_recovered_count: u64,
}

impl BoundedJitterBuffer {
    #[must_use]
    pub const fn new(mode: PlayoutMode, max_blocks: usize) -> Self {
        Self {
            mode,
            max_blocks: if max_blocks < 4 { 4 } else { max_blocks },
            queue: BTreeMap::new(),
            last_good_block: None,
            consecutive_missing: 0,
            late_dropped_count: 0,
            plc_concealed_count: 0,
            fec_recovered_count: 0,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> PlayoutMode {
        self.mode
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub const fn late_dropped_count(&self) -> u64 {
        self.late_dropped_count
    }

    #[must_use]
    pub const fn plc_concealed_count(&self) -> u64 {
        self.plc_concealed_count
    }

    #[must_use]
    pub const fn fec_recovered_count(&self) -> u64 {
        self.fec_recovered_count
    }

    /// Admit an FEC-recovered block into the jitter buffer.
    pub fn record_fec_recovered_block(&mut self, block: StereoAudioBlock) {
        self.fec_recovered_count = self.fec_recovered_count.saturating_add(1);
        self.queue.insert(block.start_frame, block);
        while self.queue.len() > self.max_blocks {
            let _ = self.queue.pop_first();
        }
    }

    /// Admit an authenticated media packet into the jitter buffer if it arrives before `consume_by_ns`.
    pub fn push_packet(
        &mut self,
        pkt: &AuthenticatedStreamPacket,
        now_ns: u64,
    ) -> Result<(), StreamError> {
        if pkt.kind != PacketKind::Media {
            return Err(StreamError::NotMediaPacket);
        }
        if now_ns > pkt.consume_by_ns {
            self.late_dropped_count = self.late_dropped_count.saturating_add(1);
            return Err(StreamError::ExpiredConsumeByDeadline {
                now_ns,
                consume_by_ns: pkt.consume_by_ns,
            });
        }
        let Ok(block) = StereoAudioBlock::from_be_i16_bytes(pkt.start_frame, &pkt.payload) else {
            return Err(StreamError::PayloadFormatMismatch {
                len: pkt.payload.len(),
            });
        };
        if self.queue.len() >= self.max_blocks
            && !self.queue.contains_key(&pkt.start_frame)
            && let Some(&oldest_frame) = self.queue.keys().next()
        {
            self.queue.remove(&oldest_frame);
        }
        self.queue.insert(pkt.start_frame, block);
        Ok(())
    }

    /// Pull the block for `expected_start_frame`. If absent, synthesize a smooth attenuated PLC block.
    pub fn pull_for_frame(&mut self, expected_start_frame: u64) -> PlayoutPullDecision {
        // Evict any stale blocks older than expected_start_frame
        while let Some(&first_key) = self.queue.keys().next() {
            if first_key < expected_start_frame {
                self.queue.remove(&first_key);
                self.late_dropped_count = self.late_dropped_count.saturating_add(1);
            } else {
                break;
            }
        }

        if let Some(block) = self.queue.remove(&expected_start_frame) {
            self.consecutive_missing = 0;
            self.last_good_block = Some(block.clone());
            return PlayoutPullDecision::AuthenticBlock(block);
        }

        self.consecutive_missing = self.consecutive_missing.saturating_add(1);
        self.plc_concealed_count = self.plc_concealed_count.saturating_add(1);

        let mut concealed = StereoAudioBlock::silence(expected_start_frame);
        // Attenuate previous block exponentially across up to 8 missing blocks (~42 ms), then mute to silence
        if self.consecutive_missing <= 8
            && let Some(prev) = &self.last_good_block
        {
            let decay = 0.7_f32.powi(self.consecutive_missing as i32);
            for i in 0..FRAMES_PER_BLOCK {
                concealed.left[i] = prev.left[i] * decay;
                concealed.right[i] = prev.right[i] * decay;
            }
        }

        PlayoutPullDecision::PlcConcealedBlock {
            start_frame: expected_start_frame,
            consecutive_missing: self.consecutive_missing,
            block: concealed,
        }
    }
}

/// Bounded XOR parity FEC helper (`N05` / `N06`) recovering 1 missing payload in a K-packet group.
#[must_use]
pub fn compute_xor_parity_payload(payloads: &[&[u8]]) -> Vec<u8> {
    let max_len = payloads.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; max_len];
    for p in payloads {
        for (i, &b) in p.iter().enumerate() {
            parity[i] ^= b;
        }
    }
    parity
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    const VECTORS_JSON: &str = include_str!("../tests/vectors/n01_wire_vectors.json");

    fn key() -> StreamKey {
        StreamKey::from_bytes([0x42u8; 32])
    }

    fn sid(raw: u64) -> StreamId {
        StreamId::new(raw).expect("nonzero stream id")
    }

    fn pcm(frames: usize, salt: u8) -> Vec<u8> {
        (0..frames * 4)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    }

    fn media_packet(seq: u64, start_frame: u64, payload: Vec<u8>) -> AuthenticatedStreamPacket {
        AuthenticatedStreamPacket {
            stream_id: sid(0xA11C_E000_0000_0001),
            session_epoch: 1,
            seq,
            kind: PacketKind::Media,
            format: StreamFormat::Pcm16BeStereo48k,
            flags: 0,
            start_frame,
            presentation_time_ns: 100_000_000,
            consume_by_ns: 95_000_000,
            fec_group_id: 0,
            fec_index: 0,
            fec_group_size: 0,
            payload,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(out, "{b:02x}").expect("writing to a String cannot fail");
        }
        out
    }

    fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd-length hex");
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit pair"))
            .collect()
    }

    /// Recompute the tag after a deliberate header edit, to test field validation behind the MAC.
    fn remac(wire: &mut [u8], key: &StreamKey) {
        let body_end = wire.len() - AUTH_TAG_LEN_BYTES;
        let tag = compute_tag_16(
            key,
            &wire[..HEADER_LEN_BYTES],
            &wire[HEADER_LEN_BYTES..body_end],
        );
        wire[body_end..].copy_from_slice(&tag);
    }

    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next_u64() % bound
        }
    }

    fn random_packet(rng: &mut SplitMix64) -> AuthenticatedStreamPacket {
        let frames = 1 + rng.below(FRAMES_PER_BLOCK as u64) as usize;
        let presentation = rng.below(MAX_TIMESTAMP_NS + 1);
        let consume_by = rng.below(presentation + 1);
        let repair = rng.below(2) == 1;
        let (fec_group_size, fec_index) = if repair {
            (
                1 + rng.below(u64::from(MAX_FEC_GROUP_SIZE)) as u8,
                rng.below(u64::from(MAX_FEC_GROUP_SIZE)) as u8,
            )
        } else if rng.below(2) == 0 {
            (0, 0)
        } else {
            let size = 1 + rng.below(u64::from(MAX_FEC_GROUP_SIZE)) as u8;
            (size, rng.below(u64::from(size)) as u8)
        };
        AuthenticatedStreamPacket {
            stream_id: sid(1 + rng.below(u64::MAX - 1)),
            session_epoch: rng.next_u64(),
            seq: rng.below(u64::MAX),
            kind: if repair {
                PacketKind::Repair
            } else {
                PacketKind::Media
            },
            format: StreamFormat::Pcm16BeStereo48k,
            flags: (rng.next_u64() as u8) & !CRITICAL_FLAGS_MASK,
            start_frame: (rng.next_u64() >> 8) * FRAMES_PER_BLOCK as u64,
            presentation_time_ns: presentation,
            consume_by_ns: consume_by,
            fec_group_id: rng.next_u64() as u16,
            fec_index,
            fec_group_size,
            payload: pcm(frames, rng.next_u64() as u8),
        }
    }

    #[test]
    fn authenticated_packet_roundtrip_and_tamper_rejection() {
        let pkt = media_packet(100, 25_600, pcm(FRAMES_PER_BLOCK, 7));
        let mut wire = pkt.encode_signed(&key()).unwrap();
        assert_eq!(wire.len(), MAX_DATAGRAM_BYTES);
        let decoded = AuthenticatedStreamPacket::decode_and_verify(&wire, &key()).unwrap();
        assert_eq!(decoded, pkt);

        // Flip 1 bit in payload -> must fail HMAC verification
        wire[HEADER_LEN_BYTES + 10] ^= 0x01;
        assert_eq!(
            AuthenticatedStreamPacket::decode_and_verify(&wire, &key()),
            Err(StreamError::AuthenticationFailed)
        );
    }

    #[test]
    fn header_is_the_documented_big_endian_layout() {
        let pkt = AuthenticatedStreamPacket {
            stream_id: sid(0x0102_0304_0506_0708),
            session_epoch: 0x1112_1314_1516_1718,
            seq: 0x2122_2324_2526_2728,
            kind: PacketKind::Repair,
            format: StreamFormat::Pcm16BeStereo48k,
            flags: 0x05,
            start_frame: 0x3132_3334_3536_3700,
            presentation_time_ns: 0x0102_0304_0506_0708,
            consume_by_ns: 0x0102_0304_0506_0707,
            fec_group_id: 0xABCD,
            fec_index: 3,
            fec_group_size: 4,
            payload: vec![9, 8, 7, 6],
        };
        let wire = pkt.encode_signed(&key()).unwrap();
        let expected_header: [u8; HEADER_LEN_BYTES] = [
            b'F', b'F', b'W', b'S', 1, 2, 0x05, 1, // magic, version, kind, flags, format
            1, 2, 3, 4, 5, 6, 7, 8, // stream_id
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // epoch
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // seq
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x00, // start_frame
            1, 2, 3, 4, 5, 6, 7, 8, // presentation_time_ns
            1, 2, 3, 4, 5, 6, 7, 7, // consume_by_ns
            0xAB, 0xCD, 3, 4, // fec_group_id, fec_index, fec_group_size
            0, 1, 0, 4, // frame_count = 1, payload_len = 4
        ];
        assert_eq!(&wire[..HEADER_LEN_BYTES], &expected_header[..]);
        assert_eq!(&wire[HEADER_LEN_BYTES..HEADER_LEN_BYTES + 4], &[9, 8, 7, 6]);
        assert_eq!(wire.len(), HEADER_LEN_BYTES + 4 + AUTH_TAG_LEN_BYTES);
    }

    #[test]
    fn golden_vectors_from_the_independent_python_reference_match_byte_for_byte() {
        let doc: serde_json::Value =
            serde_json::from_str(VECTORS_JSON).expect("vector file parses");
        let vkey_bytes = unhex(doc["key_hex"].as_str().unwrap());
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&vkey_bytes);
        let vkey = StreamKey::from_bytes(raw);

        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(
            vectors.len() >= 20,
            "vector file shrank to {}",
            vectors.len()
        );
        let mut accepted = 0;
        let mut rejected = 0;
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let wire = unhex(v["wire_hex"].as_str().unwrap());
            let expect = v["expect"].as_str().unwrap();
            let got = AuthenticatedStreamPacket::decode_and_verify(&wire, &vkey);
            if expect == "ACCEPT" {
                accepted += 1;
                let f = &v["fields"];
                let packet = got.unwrap_or_else(|e| panic!("{id}: expected accept, got {e}"));
                let want = AuthenticatedStreamPacket {
                    stream_id: sid(f["stream_id"].as_u64().unwrap()),
                    session_epoch: f["epoch"].as_u64().unwrap(),
                    seq: f["seq"].as_u64().unwrap(),
                    kind: match f["kind"].as_str().unwrap() {
                        "media" => PacketKind::Media,
                        "repair" => PacketKind::Repair,
                        other => panic!("{id}: unknown kind {other}"),
                    },
                    format: StreamFormat::Pcm16BeStereo48k,
                    flags: f["flags"].as_u64().unwrap() as u8,
                    start_frame: f["start_frame"].as_u64().unwrap(),
                    presentation_time_ns: f["presentation_time_ns"].as_u64().unwrap(),
                    consume_by_ns: f["consume_by_ns"].as_u64().unwrap(),
                    fec_group_id: f["fec_group_id"].as_u64().unwrap() as u16,
                    fec_index: f["fec_index"].as_u64().unwrap() as u8,
                    fec_group_size: f["fec_group_size"].as_u64().unwrap() as u8,
                    payload: unhex(f["payload_hex"].as_str().unwrap()),
                };
                assert_eq!(
                    packet, want,
                    "{id}: decoded fields differ from the reference"
                );
                // The Rust encoder must reproduce the Python bytes exactly, MAC included.
                let reencoded = want.encode_signed(&vkey).unwrap();
                assert_eq!(hex(&reencoded), hex(&wire), "{id}: encoder bytes differ");
            } else {
                rejected += 1;
                match got {
                    Ok(p) => {
                        panic!("{id}: expected {expect}, but the datagram was accepted: {p:?}")
                    }
                    Err(e) => assert_eq!(e.code(), expect, "{id}: wrong rejection ({e})"),
                }
            }
        }
        assert!(
            accepted >= 5 && rejected >= 15,
            "accepted={accepted} rejected={rejected}"
        );
    }

    #[test]
    fn golden_scenarios_replay_through_the_receiver_exactly_as_the_reference_model_predicts() {
        let doc: serde_json::Value =
            serde_json::from_str(VECTORS_JSON).expect("vector file parses");
        let vkey_bytes = unhex(doc["key_hex"].as_str().unwrap());
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&vkey_bytes);
        let scenarios = doc["scenarios"].as_array().expect("scenarios array");
        assert!(scenarios.len() >= 2);
        let mut total_steps = 0;
        for sc in scenarios {
            let id = sc["id"].as_str().unwrap();
            let mut rx = StreamReceiver::new(
                StreamKey::from_bytes(raw),
                sid(sc["stream_id"].as_u64().unwrap()),
                sc["epoch"].as_u64().unwrap(),
            );
            for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
                total_steps += 1;
                match step["op"].as_str().unwrap() {
                    "advance_epoch" => rx.advance_epoch(step["epoch"].as_u64().unwrap()),
                    "bind" => rx.bind_stream(
                        sid(step["stream_id"].as_u64().unwrap()),
                        step["epoch"].as_u64().unwrap(),
                    ),
                    "datagram" => {
                        let wire = unhex(step["wire_hex"].as_str().unwrap());
                        let expect = step["expect"].as_str().unwrap();
                        let outcome = match rx.accept(&wire) {
                            Ok(_) => "OK",
                            Err(ref e) => e.code(),
                        };
                        assert_eq!(outcome, expect, "{id} step {n}");
                    }
                    other => panic!("{id} step {n}: unknown op {other}"),
                }
            }
            let c = rx.counters();
            let rejected = c.rejected_structure
                + c.rejected_unsupported_version
                + c.rejected_authentication
                + c.rejected_malformed_fields
                + c.rejected_wrong_stream
                + c.rejected_stale_epoch
                + c.rejected_future_epoch
                + c.rejected_replay
                + c.rejected_future_sequence;
            assert_eq!(
                c.datagrams_seen,
                c.accepted + rejected,
                "{id}: counter conservation"
            );
            assert_eq!(c.accepted, sc["expect_accepted"].as_u64().unwrap(), "{id}");
        }
        assert!(
            total_steps >= 100,
            "scenario coverage shrank to {total_steps} steps"
        );
    }

    #[test]
    fn seeded_random_packets_roundtrip_and_any_single_bit_flip_is_rejected() {
        let mut rng = SplitMix64(0x4E30_3100);
        for _ in 0..300 {
            let pkt = random_packet(&mut rng);
            let wire = pkt.encode_signed(&key()).unwrap();
            assert_eq!(
                AuthenticatedStreamPacket::decode_and_verify(&wire, &key()).unwrap(),
                pkt
            );
        }
        // Exhaustive single-bit mutation, on short packets so debug-build HMAC cost stays small:
        // every flipped bit of header, payload and tag must be rejected.
        for _ in 0..6 {
            let mut pkt = random_packet(&mut rng);
            pkt.payload.truncate(16 * BYTES_PER_FRAME);
            let wire = pkt.encode_signed(&key()).unwrap();
            for byte in 0..wire.len() {
                for bit in 0..8 {
                    let mut bad = wire.clone();
                    bad[byte] ^= 1 << bit;
                    assert!(
                        AuthenticatedStreamPacket::decode_and_verify(&bad, &key()).is_err(),
                        "flip of byte {byte} bit {bit} was accepted"
                    );
                }
            }
        }
    }

    #[test]
    fn every_truncation_and_extension_is_rejected_without_panicking() {
        let mut rng = SplitMix64(0x7472_756E);
        for _ in 0..20 {
            let wire = random_packet(&mut rng).encode_signed(&key()).unwrap();
            for cut in 0..wire.len() {
                let err = AuthenticatedStreamPacket::decode_and_verify(&wire[..cut], &key())
                    .expect_err("a strict prefix must not decode");
                if cut < MIN_DATAGRAM_BYTES {
                    assert_eq!(err, StreamError::PacketTooShort(cut));
                } else {
                    assert!(matches!(err, StreamError::Truncated { .. }), "{err}");
                }
            }
            for extra in 1..=8 {
                let mut longer = wire.clone();
                longer.extend(std::iter::repeat_n(0xEE, extra));
                assert!(matches!(
                    AuthenticatedStreamPacket::decode_and_verify(&longer, &key()),
                    Err(StreamError::TrailingBytes { .. } | StreamError::DatagramTooLong { .. })
                ));
            }
        }
    }

    #[test]
    fn arbitrary_garbage_never_panics_and_never_authenticates() {
        let mut rng = SplitMix64(0x6761_7262);
        for _ in 0..20_000 {
            let len = rng.below((MAX_DATAGRAM_BYTES + 64) as u64) as usize;
            let mut junk: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            // Half the time give the junk a plausible prefix so deeper checks are exercised.
            if len >= HEADER_LEN_BYTES && rng.below(2) == 0 {
                junk[0..4].copy_from_slice(&WIRE_MAGIC);
                junk[OFF_VERSION] = WIRE_VERSION;
            }
            assert!(AuthenticatedStreamPacket::decode_and_verify(&junk, &key()).is_err());
        }
    }

    #[test]
    fn length_version_and_magic_rejections_happen_before_any_mac_work() {
        let good = media_packet(0, 0, pcm(8, 1)).encode_signed(&key()).unwrap();
        let mut rx = StreamReceiver::new(key(), sid(0xA11C_E000_0000_0001), 1);

        let mut oversize_declared = good.clone();
        oversize_declared[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
            .copy_from_slice(&((MAX_PAYLOAD_BYTES + 4) as u16).to_be_bytes());
        assert!(matches!(
            rx.accept(&oversize_declared),
            Err(StreamError::PayloadTooLarge { len }) if len == MAX_PAYLOAD_BYTES + 4
        ));

        let consistent_oversize = vec![0u8; MAX_DATAGRAM_BYTES + 4];
        assert_eq!(
            rx.accept(&consistent_oversize),
            Err(StreamError::DatagramTooLong {
                len: MAX_DATAGRAM_BYTES + 4
            })
        );

        let mut wrong_version = good.clone();
        wrong_version[OFF_VERSION] = 2;
        assert_eq!(
            rx.accept(&wrong_version),
            Err(StreamError::UnsupportedWireVersion { version: 2 })
        );
        // Even re-authenticated, a future version is not interpreted.
        remac(&mut wrong_version, &key());
        assert_eq!(
            rx.accept(&wrong_version),
            Err(StreamError::UnsupportedWireVersion { version: 2 })
        );

        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(rx.accept(&bad_magic), Err(StreamError::BadMagic));
        assert_eq!(
            rx.accept(&good[..good.len() - 1]),
            Err(StreamError::Truncated {
                expected: good.len(),
                actual: good.len() - 1,
            })
        );
        assert_eq!(rx.accept(&good[..10]), Err(StreamError::PacketTooShort(10)));

        let c = rx.counters();
        assert_eq!(
            c.mac_verifications, 0,
            "structural rejects must not cost a MAC"
        );
        assert_eq!(c.rejected_unsupported_version, 2);
        assert_eq!(c.rejected_structure, 5);
        assert_eq!(c.accepted, 0);

        // Paired positive: the same stream still works afterwards, and now a MAC is spent.
        assert!(rx.accept(&good).is_ok());
        assert_eq!(rx.counters().mac_verifications, 1);
    }

    #[test]
    fn field_validation_rejects_authenticated_but_unacceptable_headers() {
        let good = media_packet(0, 256, pcm(4, 3))
            .encode_signed(&key())
            .unwrap();
        let mut rx = StreamReceiver::new(key(), sid(0xA11C_E000_0000_0001), 1);

        let edit = |offset: usize, bytes: &[u8]| {
            let mut wire = good.clone();
            wire[offset..offset + bytes.len()].copy_from_slice(bytes);
            remac(&mut wire, &key());
            wire
        };

        assert_eq!(
            rx.accept(&edit(OFF_KIND, &[9])),
            Err(StreamError::UnknownPacketKind { kind: 9 })
        );
        assert_eq!(
            rx.accept(&edit(OFF_FLAGS, &[0x80])),
            Err(StreamError::UnknownCriticalFlags { flags: 0x80 })
        );
        assert_eq!(
            rx.accept(&edit(OFF_FORMAT, &[2])),
            Err(StreamError::UnknownFormat { format: 2 })
        );
        assert_eq!(
            rx.accept(&edit(OFF_FRAME_COUNT, &[0, 3])),
            Err(StreamError::FrameCountMismatch {
                declared: 3,
                payload_len: 16
            })
        );
        assert_eq!(
            rx.accept(&edit(OFF_FRAME_COUNT, &[1, 1])),
            Err(StreamError::FrameCountOutOfRange { frames: 257 })
        );
        assert_eq!(
            rx.accept(&edit(OFF_START_FRAME, &257u64.to_be_bytes())),
            Err(StreamError::MisalignedStartFrame { start_frame: 257 })
        );
        assert_eq!(
            rx.accept(&edit(OFF_CONSUME_BY, &100_000_001u64.to_be_bytes())),
            Err(StreamError::InvalidTimestamps {
                presentation_time_ns: 100_000_000,
                consume_by_ns: 100_000_001
            })
        );
        assert_eq!(
            rx.accept(&edit(
                OFF_PRESENTATION,
                &(MAX_TIMESTAMP_NS + 1).to_be_bytes()
            )),
            Err(StreamError::InvalidTimestamps {
                presentation_time_ns: MAX_TIMESTAMP_NS + 1,
                consume_by_ns: 95_000_000
            })
        );
        // A media packet with no FEC group must carry index 0.
        assert_eq!(
            rx.accept(&edit(OFF_FEC_INDEX, &[4])),
            Err(StreamError::InvalidFecFields {
                fec_group_size: 0,
                fec_index: 4
            })
        );
        // A repair packet must name a nonempty coding group.
        assert_eq!(
            rx.accept(&edit(OFF_KIND, &[2])),
            Err(StreamError::InvalidFecFields {
                fec_group_size: 0,
                fec_index: 0
            })
        );
        assert_eq!(
            rx.accept(&edit(OFF_STREAM_ID, &0u64.to_be_bytes())),
            Err(StreamError::InvalidStreamId)
        );
        // Paired positive: a valid FEC group (index inside the group) is accepted.
        assert!(rx.accept(&edit(OFF_FEC_SIZE, &[4])).is_ok());
        let c = rx.counters();
        assert_eq!((c.accepted, c.rejected_malformed_fields), (1, 11));
    }

    #[test]
    fn an_ignorable_flag_bit_is_authenticated_preserved_and_accepted() {
        let mut pkt = media_packet(0, 0, pcm(4, 5));
        pkt.flags = 0x0F;
        let wire = pkt.encode_signed(&key()).unwrap();
        let decoded = AuthenticatedStreamPacket::decode_and_verify(&wire, &key()).unwrap();
        assert_eq!(decoded.flags, 0x0F);
        // But it is covered by the MAC: flipping it without re-signing fails.
        let mut tampered = wire;
        tampered[OFF_FLAGS] = 0x0E;
        assert_eq!(
            AuthenticatedStreamPacket::decode_and_verify(&tampered, &key()),
            Err(StreamError::AuthenticationFailed)
        );
    }

    #[test]
    fn the_encoder_refuses_every_frame_the_decoder_would_reject() {
        let mut p = media_packet(0, 0, pcm(4, 1));
        p.flags = 0x10;
        assert_eq!(
            p.encode_signed(&key()),
            Err(StreamError::UnknownCriticalFlags { flags: 0x10 })
        );
        let p = media_packet(0, 1, pcm(4, 1));
        assert!(matches!(
            p.encode_signed(&key()),
            Err(StreamError::MisalignedStartFrame { .. })
        ));
        let p = media_packet(0, 0, Vec::new());
        assert_eq!(
            p.encode_signed(&key()),
            Err(StreamError::FrameCountOutOfRange { frames: 0 })
        );
        let p = media_packet(0, 0, vec![0u8; 6]);
        assert!(matches!(
            p.encode_signed(&key()),
            Err(StreamError::FrameCountMismatch { .. })
        ));
        let p = media_packet(0, 0, vec![0u8; MAX_PAYLOAD_BYTES + 4]);
        assert_eq!(
            p.encode_signed(&key()),
            Err(StreamError::PayloadTooLarge {
                len: MAX_PAYLOAD_BYTES + 4
            })
        );
        let mut p = media_packet(0, 0, pcm(4, 1));
        p.consume_by_ns = p.presentation_time_ns + 1;
        assert!(matches!(
            p.encode_signed(&key()),
            Err(StreamError::InvalidTimestamps { .. })
        ));
        let mut p = media_packet(0, 0, pcm(4, 1));
        p.kind = PacketKind::Repair;
        assert!(matches!(
            p.encode_signed(&key()),
            Err(StreamError::InvalidFecFields { .. })
        ));
        // Paired positive at the boundary: the largest legal payload encodes.
        assert!(
            media_packet(0, 0, pcm(FRAMES_PER_BLOCK, 1))
                .encode_signed(&key())
                .is_ok()
        );
        assert_eq!(StreamId::new(0), Err(StreamError::InvalidStreamId));
    }

    #[test]
    fn replay_window_rejects_stale_epochs_and_duplicate_sequences() {
        let mut win = ReplayWindow::new(3);
        assert_eq!(
            win.check_and_record(2, 1),
            Err(StreamError::StaleSessionEpoch {
                packet_epoch: 2,
                active_epoch: 3
            })
        );
        assert!(win.check_and_record(3, 10).is_ok());
        assert!(win.check_and_record(3, 8).is_ok());
        assert_eq!(
            win.check_and_record(3, 10),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 10 })
        );
        assert_eq!(
            win.check_and_record(3, 8),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 8 })
        );
    }

    #[test]
    fn replay_window_edges_reorder_depth_and_the_future_bound() {
        let mut win = ReplayWindow::new(1);
        assert!(win.check_and_record(1, 100).is_ok());
        // Exactly 63 behind is still inside the 64-packet window; 64 behind is outside it.
        assert!(win.check_and_record(1, 37).is_ok());
        assert_eq!(
            win.check_and_record(1, 36),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 36 })
        );
        // A forged huge sequence is refused and must not fence out the genuine stream.
        let before = (win.active_epoch(), win.highest_seq());
        assert_eq!(
            win.check_and_record(1, u64::MAX - 1),
            Err(StreamError::SequenceBeyondFutureWindow {
                seq: u64::MAX - 1,
                limit: 100 + MAX_FORWARD_SEQ_GAP
            })
        );
        assert_eq!((win.active_epoch(), win.highest_seq()), before);
        assert!(
            win.check_and_record(1, 101).is_ok(),
            "genuine traffic must still flow"
        );
        // The furthest admissible jump is accepted; one more is not.
        assert!(win.check_and_record(1, 101 + MAX_FORWARD_SEQ_GAP).is_ok());
        let high = win.highest_seq().unwrap();
        assert!(matches!(
            win.check_and_record(1, high + MAX_FORWARD_SEQ_GAP + 1),
            Err(StreamError::SequenceBeyondFutureWindow { .. })
        ));
        assert!(win.check_and_record(1, high + MAX_FORWARD_SEQ_GAP).is_ok());
    }

    #[test]
    fn replay_window_first_packet_is_bounded_by_the_origin_and_never_adopts_epochs() {
        let mut win = ReplayWindow::new(5);
        assert!(matches!(
            win.check_and_record(5, MAX_FORWARD_SEQ_GAP + 1),
            Err(StreamError::SequenceBeyondFutureWindow { .. })
        ));
        assert_eq!(win.highest_seq(), None);
        // A newer epoch in a packet is refused, never adopted.
        assert_eq!(
            win.check_and_record(6, 0),
            Err(StreamError::FutureSessionEpoch {
                packet_epoch: 6,
                active_epoch: 5
            })
        );
        assert_eq!(win.active_epoch(), 5);
        win.advance_epoch(6);
        assert!(win.check_and_record(6, 0).is_ok());
        // Control cannot move the epoch backwards.
        win.advance_epoch(2);
        assert_eq!(win.active_epoch(), 6);
        // A mid-stream join seeds the origin; earlier sequences are then out of bounds.
        let mut joined = ReplayWindow::join_at(9, 5_000);
        assert!(matches!(
            joined.check_and_record(9, 4_999),
            Err(StreamError::ReplayOrDuplicatePacket { .. })
        ));
        assert!(joined.check_and_record(9, 5_000).is_ok());
    }

    #[test]
    fn the_window_matches_a_set_based_model_on_a_long_random_walk() {
        let mut rng = SplitMix64(0x7769_6E64);
        let mut win = ReplayWindow::new(1);
        let mut seen = std::collections::BTreeSet::new();
        let mut high: Option<u64> = None;
        for _ in 0..50_000 {
            let seq = match (high, rng.below(6)) {
                (Some(h), 0) => h.saturating_sub(rng.below(80)),
                (Some(h), 1) => h + rng.below(MAX_FORWARD_SEQ_GAP + 8),
                (Some(h), _) => h + rng.below(3),
                (None, _) => rng.below(MAX_FORWARD_SEQ_GAP + 8),
            };
            let expected = match high {
                None => seq <= MAX_FORWARD_SEQ_GAP,
                Some(h) if seq > h => seq - h <= MAX_FORWARD_SEQ_GAP,
                Some(h) => h - seq < REPLAY_WINDOW_PACKETS && !seen.contains(&seq),
            };
            let got = win.check_and_record(1, seq).is_ok();
            assert_eq!(got, expected, "seq {seq} with highest {high:?}");
            if expected {
                seen.insert(seq);
                high = Some(high.map_or(seq, |h| h.max(seq)));
            }
        }
    }

    fn receiver_and_sender() -> (StreamReceiver, StreamSender) {
        let id = sid(0xFEED_0000_0000_0042);
        (
            StreamReceiver::new(key(), id, 7),
            StreamSender::new(key(), id, 7),
        )
    }

    fn frame(n: u64) -> OutboundFrame {
        OutboundFrame::media(
            n * 256,
            1_000_000_000 + n * 5_333_333,
            995_000_000 + n * 5_333_333,
            pcm(FRAMES_PER_BLOCK, n as u8),
        )
    }

    #[test]
    fn a_tampered_datagram_never_consumes_a_sequence_number() {
        let (mut rx, mut tx) = receiver_and_sender();
        let genuine = tx.send(frame(0)).unwrap();
        let mut tampered = genuine.clone();
        tampered[HEADER_LEN_BYTES + 3] ^= 0x40;
        assert_eq!(rx.accept(&tampered), Err(StreamError::AuthenticationFailed));
        // The genuine copy with the very same sequence number is still admitted afterwards.
        assert!(rx.accept(&genuine).is_ok());
        // And only now is it a replay.
        assert_eq!(
            rx.accept(&genuine),
            Err(StreamError::ReplayOrDuplicatePacket { seq: 0 })
        );
        assert_eq!(rx.counters().rejected_authentication, 1);
        assert_eq!(rx.counters().rejected_replay, 1);
        assert_eq!(rx.counters().accepted, 1);
    }

    #[test]
    fn tampered_epoch_format_and_stream_fields_fail_authentication() {
        let (mut rx, mut tx) = receiver_and_sender();
        let genuine = tx.send(frame(0)).unwrap();
        for (offset, new_value) in [
            (OFF_EPOCH + 7, 8u8),
            (OFF_FORMAT, 2),
            (OFF_STREAM_ID + 7, 0x43),
            (OFF_SEQ + 7, 9),
            (OFF_PRESENTATION + 7, 1),
        ] {
            let mut tampered = genuine.clone();
            tampered[offset] = new_value;
            assert_eq!(
                rx.accept(&tampered),
                Err(StreamError::AuthenticationFailed),
                "offset {offset}"
            );
        }
        assert!(rx.accept(&genuine).is_ok());
    }

    #[test]
    fn stale_future_and_foreign_traffic_is_ignored_without_touching_the_stream() {
        let (mut rx, mut tx) = receiver_and_sender();
        let mut stale_tx = StreamSender::new(key(), sid(0xFEED_0000_0000_0042), 6);
        let mut future_tx = StreamSender::new(key(), sid(0xFEED_0000_0000_0042), 8);
        let mut foreign_tx = StreamSender::new(key(), sid(0xBEEF_0000_0000_0001), 7);

        assert!(rx.accept(&tx.send(frame(0)).unwrap()).is_ok());
        assert_eq!(
            rx.accept(&stale_tx.send(frame(1)).unwrap()),
            Err(StreamError::StaleSessionEpoch {
                packet_epoch: 6,
                active_epoch: 7
            })
        );
        assert_eq!(
            rx.accept(&future_tx.send(frame(1)).unwrap()),
            Err(StreamError::FutureSessionEpoch {
                packet_epoch: 8,
                active_epoch: 7
            })
        );
        assert_eq!(
            rx.accept(&foreign_tx.send(frame(1)).unwrap()),
            Err(StreamError::WrongStream {
                packet_stream: 0xBEEF_0000_0000_0001
            })
        );
        assert_eq!(rx.active_epoch(), 7, "no media packet may move the epoch");
        // The genuine stream continues at the next sequence number, unaffected.
        assert!(rx.accept(&tx.send(frame(1)).unwrap()).is_ok());
        // After the control channel announces epoch 8, the epoch-8 sender is admitted.
        rx.advance_epoch(8);
        assert!(rx.accept(&future_tx.send(frame(2)).unwrap()).is_ok());
        // ...and the old epoch-7 sender is now stale.
        assert!(matches!(
            rx.accept(&tx.send(frame(2)).unwrap()),
            Err(StreamError::StaleSessionEpoch { .. })
        ));
        let c = rx.counters();
        assert_eq!(
            (
                c.rejected_stale_epoch,
                c.rejected_future_epoch,
                c.rejected_wrong_stream
            ),
            (2, 1, 1)
        );
    }

    #[test]
    fn reorder_inside_the_window_is_admitted_and_duplicates_are_not() {
        let (mut rx, mut tx) = receiver_and_sender();
        let wires: Vec<Vec<u8>> = (0..6).map(|n| tx.send(frame(n)).unwrap()).collect();
        for n in [0usize, 1, 3, 2, 5, 4] {
            assert!(rx.accept(&wires[n]).is_ok(), "datagram {n}");
        }
        for n in 0..6 {
            assert_eq!(
                rx.accept(&wires[n]),
                Err(StreamError::ReplayOrDuplicatePacket { seq: n as u64 })
            );
        }
        assert_eq!(rx.counters().accepted, 6);
        assert_eq!(rx.counters().rejected_replay, 6);
    }

    #[test]
    fn a_forged_far_future_sequence_cannot_fence_out_the_real_sender() {
        let (mut rx, mut tx) = receiver_and_sender();
        assert!(rx.accept(&tx.send(frame(0)).unwrap()).is_ok());
        // An insider holding the key forges a sequence far beyond the future window.
        let mut forger = StreamSender::new(key(), sid(0xFEED_0000_0000_0042), 7);
        forger.next_seq = u64::MAX - 5;
        let forged = forger.send(frame(1)).unwrap();
        assert!(matches!(
            rx.accept(&forged),
            Err(StreamError::SequenceBeyondFutureWindow { .. })
        ));
        assert_eq!(rx.counters().rejected_future_sequence, 1);
        for n in 1..40 {
            assert!(
                rx.accept(&tx.send(frame(n)).unwrap()).is_ok(),
                "genuine packet {n}"
            );
        }
    }

    #[test]
    fn restart_and_rekey_make_the_previous_stream_inert() {
        let (mut rx, mut tx) = receiver_and_sender();
        let old: Vec<Vec<u8>> = (0..3).map(|n| tx.send(frame(n)).unwrap()).collect();
        for w in &old {
            assert!(rx.accept(w).is_ok());
        }
        // The sender restarts with a fresh random identity and the same epoch and key.
        let fresh_id = sid(0xFEED_0000_0000_0099);
        rx.bind_stream(fresh_id, 7);
        let mut restarted = StreamSender::new(key(), fresh_id, 7);
        // Sequence 0 is reused by the new stream and is NOT mistaken for a replay...
        assert!(rx.accept(&restarted.send(frame(0)).unwrap()).is_ok());
        // ...while every pre-restart datagram, replayed by an attacker, is refused.
        for w in &old {
            assert!(matches!(rx.accept(w), Err(StreamError::WrongStream { .. })));
        }
        // A different key never authenticates, whatever the identity.
        let mut wrong_key = StreamSender::new(StreamKey::from_bytes([0x43; 32]), fresh_id, 7);
        assert_eq!(
            rx.accept(&wrong_key.send(frame(1)).unwrap()),
            Err(StreamError::AuthenticationFailed)
        );
    }

    #[test]
    fn sender_sequence_epoch_and_identity_rules() {
        let (_, mut tx) = receiver_and_sender();
        assert_eq!(tx.next_seq(), 0);
        tx.send(frame(0)).unwrap();
        tx.send(frame(1)).unwrap();
        assert_eq!(tx.next_seq(), 2);
        // A frame the encoder refuses does not burn a sequence number.
        let mut bad = frame(2);
        bad.start_frame = 1;
        assert!(tx.send(bad).is_err());
        assert_eq!(tx.next_seq(), 2);
        assert_eq!(
            tx.advance_epoch(7),
            Err(StreamError::EpochNotAdvancing {
                requested: 7,
                current: 7
            })
        );
        assert_eq!(
            tx.advance_epoch(3),
            Err(StreamError::EpochNotAdvancing {
                requested: 3,
                current: 7
            })
        );
        tx.advance_epoch(8).unwrap();
        assert_eq!((tx.epoch(), tx.next_seq()), (8, 0));
        tx.next_seq = u64::MAX;
        assert_eq!(tx.send(frame(3)), Err(StreamError::SequenceExhausted));
        tx.advance_epoch(9).unwrap();
        assert!(tx.send(frame(3)).is_ok());
    }

    #[test]
    fn keys_and_payloads_never_appear_in_diagnostics() {
        let secret = StreamKey::from_bytes([0x5A; 32]);
        let shown = format!("{secret:?}");
        assert!(
            shown.contains("REDACTED") && !shown.contains("90"),
            "{shown}"
        );
        let id = sid(1);
        let rx = StreamReceiver::new(secret.clone(), id, 1);
        let tx = StreamSender::new(secret, id, 1);
        for text in [format!("{rx:?}"), format!("{tx:?}")] {
            assert!(text.contains("REDACTED"), "{text}");
            assert!(!text.contains("90, 90"), "{text}");
        }
    }

    #[test]
    fn counters_account_for_every_datagram_exactly_once() {
        let (mut rx, mut tx) = receiver_and_sender();
        let good: Vec<Vec<u8>> = (0..4).map(|n| tx.send(frame(n)).unwrap()).collect();
        let mut fed = 0u64;
        let mut feed = |rx: &mut StreamReceiver, bytes: &[u8]| {
            fed += 1;
            let _ = rx.accept(bytes);
        };
        feed(&mut rx, &good[0]);
        feed(&mut rx, &good[0]);
        feed(&mut rx, &good[1][..40]);
        feed(&mut rx, &[0u8; 2000]);
        let mut flipped = good[2].clone();
        flipped[HEADER_LEN_BYTES] ^= 1;
        feed(&mut rx, &flipped);
        feed(&mut rx, &good[3]);
        let c = rx.counters();
        let rejected = c.rejected_structure
            + c.rejected_unsupported_version
            + c.rejected_authentication
            + c.rejected_malformed_fields
            + c.rejected_wrong_stream
            + c.rejected_stale_epoch
            + c.rejected_future_epoch
            + c.rejected_replay
            + c.rejected_future_sequence;
        assert_eq!(c.datagrams_seen, fed);
        assert_eq!(c.datagrams_seen, c.accepted + rejected);
        assert_eq!(
            (
                c.accepted,
                c.rejected_replay,
                c.rejected_structure,
                c.rejected_authentication
            ),
            (2, 1, 2, 1)
        );
    }

    #[test]
    fn accepted_traffic_feeds_the_jitter_buffer_and_rejected_traffic_never_reaches_it() {
        let (mut rx, mut tx) = receiver_and_sender();
        let mut jb = BoundedJitterBuffer::new(PlayoutMode::Music500ms, 16);
        let wires: Vec<Vec<u8>> = (0..4).map(|n| tx.send(frame(n)).unwrap()).collect();
        let mut tampered = wires[1].clone();
        tampered[HEADER_LEN_BYTES + 1] ^= 0xFF;
        for datagram in [
            &wires[0], &wires[0], &tampered, &wires[2], &wires[1], &wires[3],
        ] {
            if let Ok(pkt) = rx.accept(datagram) {
                jb.push_packet(&pkt, 0).unwrap();
            }
        }
        assert_eq!(
            jb.depth(),
            4,
            "one block per genuine packet, none from duplicates or tampering"
        );
        for n in 0..4u64 {
            match jb.pull_for_frame(n * 256) {
                PlayoutPullDecision::AuthenticBlock(block) => {
                    assert_eq!(block.start_frame, n * 256)
                }
                other => panic!("block {n}: {other:?}"),
            }
        }
        assert_eq!(jb.plc_concealed_count(), 0);
    }

    #[test]
    fn jitter_buffer_rejects_repair_packets_and_reports_pcm_decode_failures_truthfully() {
        let mut jb = BoundedJitterBuffer::new(PlayoutMode::Music500ms, 16);
        let mut repair = media_packet(0, 0, pcm(4, 1));
        repair.kind = PacketKind::Repair;
        assert_eq!(jb.push_packet(&repair, 0), Err(StreamError::NotMediaPacket));
        let ragged = media_packet(0, 0, vec![0u8; 6]);
        assert_eq!(
            jb.push_packet(&ragged, 0),
            Err(StreamError::PayloadFormatMismatch { len: 6 })
        );
        assert_eq!(jb.depth(), 0);
        assert!(jb.push_packet(&media_packet(0, 0, pcm(4, 1)), 0).is_ok());
    }

    #[test]
    fn jitter_buffer_enforces_consume_by_deadline_and_plc_fade() {
        let mut jb = BoundedJitterBuffer::new(PlayoutMode::Music500ms, 16);
        let mut blk = StereoAudioBlock::silence(0);
        blk.left = [0.5; FRAMES_PER_BLOCK];
        blk.right = [0.5; FRAMES_PER_BLOCK];

        let pkt0 = media_packet(0, 0, blk.to_be_i16_bytes());
        assert!(jb.push_packet(&pkt0, 90_000_000).is_ok());
        // Late packet arriving at 96 ms (> 95 ms consume_by) is rejected
        let mut pkt1_late = pkt0.clone();
        pkt1_late.seq = 1;
        pkt1_late.start_frame = 256;
        assert_eq!(
            jb.push_packet(&pkt1_late, 96_000_000),
            Err(StreamError::ExpiredConsumeByDeadline {
                now_ns: 96_000_000,
                consume_by_ns: 95_000_000
            })
        );

        assert!(matches!(
            jb.pull_for_frame(0),
            PlayoutPullDecision::AuthenticBlock(_)
        ));
        match jb.pull_for_frame(256) {
            PlayoutPullDecision::PlcConcealedBlock {
                start_frame,
                consecutive_missing,
                block,
            } => {
                assert_eq!(start_frame, 256);
                assert_eq!(consecutive_missing, 1);
                assert!(block.left[0] > 0.3 && block.left[0] < 0.4);
            }
            other => panic!("expected PLC concealment, got {other:?}"),
        }
    }
}
