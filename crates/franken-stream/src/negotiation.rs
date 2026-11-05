//! Compatibility negotiation for mixed firmware revisions (`N01` / `ffw-ey5`).
//!
//! Before any media datagram is admitted, a sender and a receiver exchange two fixed-size,
//! authenticated messages: an **Offer** (sender) and an **Answer** (receiver). Each carries the
//! sender's capabilities: the wire-protocol range it speaks, mandatory and optional features,
//! sample formats and the largest payload it accepts. The outcome is a pure function of the two
//! capability sets ([`select`]), so both ends can compute it and a peer cannot choose for them.
//!
//! What is authenticated, and why a downgrade fails:
//! - Every message is `HMAC-SHA256`-tagged under the group key with its own context string, and
//!   binds peer identity, stream identity, epoch, a fresh nonce and the full capability lists. A
//!   party without the key can neither strip a higher version or a feature nor replay a message.
//! - The Answer carries the SHA-256 of the exact Offer bytes and the selection. The initiator
//!   recomputes the selection from its own capabilities and the answered ones and refuses any
//!   difference, reporting a lower version than was jointly available as a downgrade.
//! - The media key is derived from the whole transcript, so a negotiation that did not end with
//!   both sides holding byte-identical messages cannot authenticate a single media datagram.
//!
//! Capability differences between firmware revisions (or hardware generations) are expressed only
//! as features and limits inside one wire format: there is no per-generation framing.
//!
//! This layer sends no refusal datagram: an unauthenticated reply is an amplification vector, and
//! timeouts belong to the control channel (N02). The group key is shared, so a party that holds it
//! can still negotiate as a peer; per-peer keys or signatures are out of scope.

use crate::{
    CRITICAL_FLAGS_MASK, HmacSha256, MAX_PAYLOAD_BYTES, StreamId, StreamKey, WIRE_VERSION, be_u16,
    be_u64, tags_equal,
};
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HELLO_MAGIC: [u8; 4] = *b"FFWN";
/// Version of the negotiation message format itself, distinct from the media wire version.
pub const HELLO_VERSION: u8 = 1;
pub const HELLO_BODY_BYTES: usize = 100;
pub const HELLO_TAG_BYTES: usize = 16;
pub const HELLO_DATAGRAM_BYTES: usize = HELLO_BODY_BYTES + HELLO_TAG_BYTES;
const HELLO_AUTH_CONTEXT: &[u8] = b"FFWS-v1-hello";
const TRANSCRIPT_CONTEXT: &[u8] = b"FFWS-v1-transcript";
const SESSION_KEY_CONTEXT: &[u8] = b"FFWS-v1-session-key";

/// Feature bit 0: repair packets (`kind` 2) carrying XOR parity.
pub const FEATURE_XOR_PARITY_FEC: u32 = 0b01;
/// Feature bit 1: media packets shorter than one full block (the final block of a stream).
pub const FEATURE_PARTIAL_FINAL_BLOCK: u32 = 0b10;
pub const KNOWN_FEATURES: u32 = FEATURE_XOR_PARITY_FEC | FEATURE_PARTIAL_FINAL_BLOCK;
/// Format bit 0: signed 16-bit big-endian stereo PCM at 48 kHz.
pub const FORMAT_PCM16_BE_STEREO_48K: u8 = 0b01;
pub const KNOWN_FORMATS: u8 = FORMAT_PCM16_BE_STEREO_48K;

// Message layout, all integers big-endian:
//   0..4 magic "FFWN" | 4 message version | 5 kind (1 offer, 2 answer) | 6 flags (0xF0 critical)
//   7 wire_min | 8 wire_max | 9 formats | 10..12 max_payload | 12..16 mandatory | 16..20 optional
//   20..28 peer_id | 28..36 stream_id | 36..44 epoch | 44..60 nonce
//   60 selected wire version | 61 selected format | 62..64 selected max payload | 64..68 selected features
//   68..100 SHA-256 of the offer datagram (all selection fields and the digest are zero in an offer)
// The datagram is the 100-byte body followed by a 16-byte tag.
const OFF_KIND: usize = 5;
const OFF_FLAGS: usize = 6;
const OFF_WIRE_MIN: usize = 7;
const OFF_WIRE_MAX: usize = 8;
const OFF_FORMATS: usize = 9;
const OFF_MAX_PAYLOAD: usize = 10;
const OFF_MANDATORY: usize = 12;
const OFF_OPTIONAL: usize = 16;
const OFF_PEER: usize = 20;
const OFF_STREAM: usize = 28;
const OFF_EPOCH: usize = 36;
const OFF_NONCE: usize = 44;
const OFF_SEL_VERSION: usize = 60;
const OFF_SEL_FORMAT: usize = 61;
const OFF_SEL_MAX_PAYLOAD: usize = 62;
const OFF_SEL_FEATURES: usize = 64;
const OFF_DIGEST: usize = 68;

/// Every rejection carries only numbers: never a key, tag, nonce or digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum NegotiationError {
    #[error("negotiation message is {actual} bytes, expected {HELLO_DATAGRAM_BYTES}")]
    HelloLength { actual: usize },
    #[error("negotiation magic does not match")]
    HelloBadMagic,
    #[error(
        "unsupported negotiation message version {version} (this build speaks {HELLO_VERSION})"
    )]
    HelloUnsupportedVersion { version: u8 },
    #[error("negotiation message authentication failed")]
    HelloAuthenticationFailed,
    #[error("unknown negotiation message kind {kind}")]
    UnknownHelloKind { kind: u8 },
    #[error("unknown critical flag bits set in {flags:#04x}")]
    UnknownCriticalHelloFlags { flags: u8 },
    #[error("capabilities are malformed or claim more than this build implements")]
    InvalidCapabilities,
    #[error("peer and stream identities must be nonzero")]
    InvalidPeerIdentity,
    #[error("negotiation nonce must be nonzero")]
    InvalidNonce,
    #[error("negotiation message fields are inconsistent with its kind")]
    MalformedHello,
    #[error(
        "no common wire version: local {local_min}..={local_max}, peer {peer_min}..={peer_max}"
    )]
    NoCommonVersion {
        local_min: u8,
        local_max: u8,
        peer_min: u8,
        peer_max: u8,
    },
    #[error("mandatory features {missing:#010x} are not supported by the other side")]
    MandatoryFeatureMissing { missing: u32 },
    #[error("no common sample format")]
    NoCommonFormat,
    #[error(
        "common payload limit {common_max_payload} is below one full block ({MAX_PAYLOAD_BYTES})"
    )]
    LimitsIncompatible { common_max_payload: u16 },
    #[error("offer epoch {offer_epoch} is older than the current epoch {min_epoch}")]
    StaleOfferEpoch { offer_epoch: u64, min_epoch: u64 },
    #[error("negotiation message has the wrong kind for this step")]
    WrongHelloKind,
    #[error("answer is for a different stream")]
    StreamMismatch,
    #[error("answer is for a different epoch")]
    EpochMismatch,
    #[error("answer repeats the offer's peer identity or nonce")]
    ReflectedHello,
    #[error("answer does not answer this offer")]
    OfferDigestMismatch,
    #[error(
        "downgrade detected: answer selects wire version {answered_wire_version}, but {expected_wire_version} is jointly supported"
    )]
    DowngradeDetected {
        expected_wire_version: u8,
        answered_wire_version: u8,
    },
    #[error("answer's selection is not what the capabilities determine")]
    SelectionMismatch,
}

impl NegotiationError {
    /// Stable machine-readable name, shared with the golden vectors and the Python reference.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::HelloLength { .. } => "HELLO_LENGTH",
            Self::HelloBadMagic => "HELLO_BAD_MAGIC",
            Self::HelloUnsupportedVersion { .. } => "HELLO_UNSUPPORTED_VERSION",
            Self::HelloAuthenticationFailed => "HELLO_AUTH_FAILED",
            Self::UnknownHelloKind { .. } => "UNKNOWN_HELLO_KIND",
            Self::UnknownCriticalHelloFlags { .. } => "UNKNOWN_CRITICAL_HELLO_FLAGS",
            Self::InvalidCapabilities => "INVALID_CAPABILITIES",
            Self::InvalidPeerIdentity => "INVALID_PEER_IDENTITY",
            Self::InvalidNonce => "INVALID_NONCE",
            Self::MalformedHello => "MALFORMED_HELLO",
            Self::NoCommonVersion { .. } => "NO_COMMON_VERSION",
            Self::MandatoryFeatureMissing { .. } => "MANDATORY_FEATURE_MISSING",
            Self::NoCommonFormat => "NO_COMMON_FORMAT",
            Self::LimitsIncompatible { .. } => "LIMITS_INCOMPATIBLE",
            Self::StaleOfferEpoch { .. } => "STALE_OFFER_EPOCH",
            Self::WrongHelloKind => "WRONG_HELLO_KIND",
            Self::StreamMismatch => "STREAM_MISMATCH",
            Self::EpochMismatch => "EPOCH_MISMATCH",
            Self::ReflectedHello => "REFLECTED_HELLO",
            Self::OfferDigestMismatch => "OFFER_DIGEST_MISMATCH",
            Self::DowngradeDetected { .. } => "DOWNGRADE_DETECTED",
            Self::SelectionMismatch => "SELECTION_MISMATCH",
        }
    }
}

/// What one endpoint can do. Differences between firmware revisions live here and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Lowest and highest media wire version this endpoint speaks.
    pub wire_min: u8,
    pub wire_max: u8,
    /// Bit set of sample formats (`FORMAT_*`).
    pub formats: u8,
    /// Largest media payload it accepts, in bytes.
    pub max_payload_bytes: u16,
    /// Features the *other* side must also support, or there is no session. An unknown bit here is
    /// therefore a refusal to interoperate, never ignored.
    pub mandatory_features: u32,
    /// Features used only when both sides support them; unknown bits are carried and ignored.
    pub optional_features: u32,
}

impl Capabilities {
    /// Everything this build implements: wire version 1, PCM, every known feature optional.
    #[must_use]
    pub const fn baseline() -> Self {
        Self {
            wire_min: WIRE_VERSION,
            wire_max: WIRE_VERSION,
            formats: FORMAT_PCM16_BE_STEREO_48K,
            max_payload_bytes: MAX_PAYLOAD_BYTES as u16,
            mandatory_features: 0,
            optional_features: KNOWN_FEATURES,
        }
    }

    const fn supported_features(&self) -> u32 {
        self.mandatory_features | self.optional_features
    }

    /// Well-formedness of any endpoint's claim, local or received.
    fn validate(&self) -> Result<(), NegotiationError> {
        let ok = self.wire_min >= 1
            && self.wire_min <= self.wire_max
            && self.formats != 0
            && self.max_payload_bytes >= 4
            && self.max_payload_bytes.is_multiple_of(4)
            && self.mandatory_features & self.optional_features == 0;
        if ok {
            Ok(())
        } else {
            Err(NegotiationError::InvalidCapabilities)
        }
    }

    /// An endpoint of this build may not claim a version, feature, format or size it does not
    /// implement.
    fn validate_local(&self) -> Result<(), NegotiationError> {
        self.validate()?;
        let ok = self.wire_max <= WIRE_VERSION
            && self.supported_features() & !KNOWN_FEATURES == 0
            && self.formats & !KNOWN_FORMATS == 0
            && usize::from(self.max_payload_bytes) <= MAX_PAYLOAD_BYTES;
        if ok {
            Ok(())
        } else {
            Err(NegotiationError::InvalidCapabilities)
        }
    }
}

/// The agreed parameters of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    pub wire_version: u8,
    /// A single `FORMAT_*` bit.
    pub format: u8,
    pub max_payload_bytes: u16,
    /// Features both sides support (mandatory and optional together).
    pub features: u32,
}

impl Selection {
    const ZERO: Self = Self {
        wire_version: 0,
        format: 0,
        max_payload_bytes: 0,
        features: 0,
    };

    fn is_well_formed(&self) -> bool {
        self.wire_version >= 1
            && self.format.count_ones() == 1
            && self.max_payload_bytes >= 4
            && self.max_payload_bytes.is_multiple_of(4)
    }
}

/// The outcome of two capability sets. Symmetric: `select(a, b) == select(b, a)`.
///
/// Highest jointly supported wire version; every feature both sides support; the lowest common
/// format bit; the smaller payload limit, which must still hold a full block of the v1 format. Each
/// side's mandatory features must be supported by the other, or there is no session.
pub fn select(a: &Capabilities, b: &Capabilities) -> Result<Selection, NegotiationError> {
    a.validate()?;
    b.validate()?;
    let low = a.wire_min.max(b.wire_min);
    let high = a.wire_max.min(b.wire_max);
    if low > high {
        return Err(NegotiationError::NoCommonVersion {
            local_min: a.wire_min,
            local_max: a.wire_max,
            peer_min: b.wire_min,
            peer_max: b.wire_max,
        });
    }
    let missing = (a.mandatory_features & !b.supported_features())
        | (b.mandatory_features & !a.supported_features());
    if missing != 0 {
        return Err(NegotiationError::MandatoryFeatureMissing { missing });
    }
    let common_formats = a.formats & b.formats;
    if common_formats == 0 {
        return Err(NegotiationError::NoCommonFormat);
    }
    let common_max_payload = a.max_payload_bytes.min(b.max_payload_bytes);
    if usize::from(common_max_payload) < MAX_PAYLOAD_BYTES {
        return Err(NegotiationError::LimitsIncompatible { common_max_payload });
    }
    Ok(Selection {
        wire_version: high,
        format: common_formats.isolate_lowest_one(),
        max_payload_bytes: MAX_PAYLOAD_BYTES as u16,
        features: a.supported_features() & b.supported_features(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelloKind {
    Offer,
    Answer,
}

impl HelloKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Offer => 1,
            Self::Answer => 2,
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Offer),
            2 => Some(Self::Answer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnswerBody {
    selection: Selection,
    offer_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hello {
    kind: HelloKind,
    flags: u8,
    caps: Capabilities,
    peer_id: u64,
    stream_id: StreamId,
    epoch: u64,
    nonce: [u8; 16],
    answer: Option<AnswerBody>,
}

fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn hello_tag(psk: &StreamKey, body: &[u8]) -> [u8; HELLO_TAG_BYTES] {
    let mut mac = HmacSha256::new_from_slice(&psk.0).expect("32-byte HMAC key is valid");
    mac.update(HELLO_AUTH_CONTEXT);
    mac.update(body);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; HELLO_TAG_BYTES];
    tag.copy_from_slice(&full[..HELLO_TAG_BYTES]);
    tag
}

impl Hello {
    fn encode(&self, psk: &StreamKey) -> Vec<u8> {
        let (selection, digest) = match &self.answer {
            Some(body) => (body.selection, body.offer_digest),
            None => (Selection::ZERO, [0u8; 32]),
        };
        let mut b = Vec::with_capacity(HELLO_DATAGRAM_BYTES);
        b.extend_from_slice(&HELLO_MAGIC);
        b.push(HELLO_VERSION);
        b.push(self.kind.wire());
        b.push(self.flags);
        b.push(self.caps.wire_min);
        b.push(self.caps.wire_max);
        b.push(self.caps.formats);
        b.extend_from_slice(&self.caps.max_payload_bytes.to_be_bytes());
        b.extend_from_slice(&self.caps.mandatory_features.to_be_bytes());
        b.extend_from_slice(&self.caps.optional_features.to_be_bytes());
        b.extend_from_slice(&self.peer_id.to_be_bytes());
        b.extend_from_slice(&self.stream_id.get().to_be_bytes());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.nonce);
        b.push(selection.wire_version);
        b.push(selection.format);
        b.extend_from_slice(&selection.max_payload_bytes.to_be_bytes());
        b.extend_from_slice(&selection.features.to_be_bytes());
        b.extend_from_slice(&digest);
        debug_assert_eq!(b.len(), HELLO_BODY_BYTES);
        let tag = hello_tag(psk, &b);
        b.extend_from_slice(&tag);
        b
    }

    /// Fixed-size and magic/version checks first (O(1), no hashing), then the tag, and only then
    /// any field is interpreted.
    fn decode_and_verify(wire: &[u8], psk: &StreamKey) -> Result<Self, NegotiationError> {
        if wire.len() != HELLO_DATAGRAM_BYTES {
            return Err(NegotiationError::HelloLength { actual: wire.len() });
        }
        if wire[0..4] != HELLO_MAGIC {
            return Err(NegotiationError::HelloBadMagic);
        }
        if wire[4] != HELLO_VERSION {
            return Err(NegotiationError::HelloUnsupportedVersion { version: wire[4] });
        }
        let expected = hello_tag(psk, &wire[..HELLO_BODY_BYTES]);
        if !tags_equal(&wire[HELLO_BODY_BYTES..], &expected) {
            return Err(NegotiationError::HelloAuthenticationFailed);
        }
        let Some(kind) = HelloKind::from_wire(wire[OFF_KIND]) else {
            return Err(NegotiationError::UnknownHelloKind {
                kind: wire[OFF_KIND],
            });
        };
        let flags = wire[OFF_FLAGS];
        if flags & CRITICAL_FLAGS_MASK != 0 {
            return Err(NegotiationError::UnknownCriticalHelloFlags { flags });
        }
        let caps = Capabilities {
            wire_min: wire[OFF_WIRE_MIN],
            wire_max: wire[OFF_WIRE_MAX],
            formats: wire[OFF_FORMATS],
            max_payload_bytes: be_u16(wire, OFF_MAX_PAYLOAD),
            mandatory_features: be_u32(wire, OFF_MANDATORY),
            optional_features: be_u32(wire, OFF_OPTIONAL),
        };
        caps.validate()?;
        let peer_id = be_u64(wire, OFF_PEER);
        let stream_id = StreamId::new(be_u64(wire, OFF_STREAM))
            .map_err(|_| NegotiationError::InvalidPeerIdentity)?;
        if peer_id == 0 {
            return Err(NegotiationError::InvalidPeerIdentity);
        }
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&wire[OFF_NONCE..OFF_NONCE + 16]);
        if nonce == [0u8; 16] {
            return Err(NegotiationError::InvalidNonce);
        }
        let selection = Selection {
            wire_version: wire[OFF_SEL_VERSION],
            format: wire[OFF_SEL_FORMAT],
            max_payload_bytes: be_u16(wire, OFF_SEL_MAX_PAYLOAD),
            features: be_u32(wire, OFF_SEL_FEATURES),
        };
        let mut offer_digest = [0u8; 32];
        offer_digest.copy_from_slice(&wire[OFF_DIGEST..OFF_DIGEST + 32]);
        let answer = match kind {
            HelloKind::Offer => {
                if selection != Selection::ZERO || offer_digest != [0u8; 32] {
                    return Err(NegotiationError::MalformedHello);
                }
                None
            }
            HelloKind::Answer => {
                if !selection.is_well_formed() {
                    return Err(NegotiationError::MalformedHello);
                }
                Some(AnswerBody {
                    selection,
                    offer_digest,
                })
            }
        };
        Ok(Self {
            kind,
            flags,
            caps,
            peer_id,
            stream_id,
            epoch: be_u64(wire, OFF_EPOCH),
            nonce,
            answer,
        })
    }
}

/// A completed negotiation: the agreed parameters and the media key bound to the transcript.
///
/// The key is `HMAC(group key, context || SHA-256(context || offer || answer))`. The transcript
/// contains both peer identities, the stream, the epoch, both nonces and both capability lists, so
/// two sides that did not exchange byte-identical messages derive different keys and every media
/// datagram between them fails authentication.
#[derive(Debug, Clone)]
pub struct NegotiatedSession {
    local_peer_id: u64,
    remote_peer_id: u64,
    stream_id: StreamId,
    epoch: u64,
    selection: Selection,
    transcript: [u8; 32],
    media_key: StreamKey,
}

impl NegotiatedSession {
    fn establish(
        psk: &StreamKey,
        local_peer_id: u64,
        remote_peer_id: u64,
        offer: &Hello,
        selection: Selection,
        offer_wire: &[u8],
        answer_wire: &[u8],
    ) -> Self {
        let mut transcript_input =
            Vec::with_capacity(TRANSCRIPT_CONTEXT.len() + offer_wire.len() + answer_wire.len());
        transcript_input.extend_from_slice(TRANSCRIPT_CONTEXT);
        transcript_input.extend_from_slice(offer_wire);
        transcript_input.extend_from_slice(answer_wire);
        let transcript = sha256(&transcript_input);

        let mut mac = HmacSha256::new_from_slice(&psk.0).expect("32-byte HMAC key is valid");
        mac.update(SESSION_KEY_CONTEXT);
        mac.update(&transcript);
        let full = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&full[..32]);

        Self {
            local_peer_id,
            remote_peer_id,
            stream_id: offer.stream_id,
            epoch: offer.epoch,
            selection,
            transcript,
            media_key: StreamKey::from_bytes(key),
        }
    }

    #[must_use]
    pub const fn local_peer_id(&self) -> u64 {
        self.local_peer_id
    }

    #[must_use]
    pub const fn remote_peer_id(&self) -> u64 {
        self.remote_peer_id
    }

    #[must_use]
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    #[must_use]
    pub const fn transcript_digest(&self) -> &[u8; 32] {
        &self.transcript
    }

    /// The key the media endpoints of this session must use; it is bound to this transcript.
    #[must_use]
    pub const fn media_key(&self) -> &StreamKey {
        &self.media_key
    }
}

/// The sender's half of a pending negotiation. [`Initiator::finish`] consumes it, so one offer can
/// complete at most once.
#[derive(Debug)]
pub struct Initiator {
    psk: StreamKey,
    offer: Hello,
    offer_wire: Vec<u8>,
}

impl Initiator {
    /// Build the Offer. `nonce` must come from admitted entropy and be fresh for every offer.
    pub fn offer(
        psk: &StreamKey,
        local: Capabilities,
        peer_id: u64,
        stream_id: StreamId,
        epoch: u64,
        nonce: [u8; 16],
    ) -> Result<(Self, Vec<u8>), NegotiationError> {
        local.validate_local()?;
        Self::offer_unchecked(psk, local, peer_id, stream_id, epoch, nonce)
    }

    /// As [`Initiator::offer`] but without the "claims only what this build implements" check, so
    /// tests can stand in for firmware that speaks versions or features this build does not.
    fn offer_unchecked(
        psk: &StreamKey,
        local: Capabilities,
        peer_id: u64,
        stream_id: StreamId,
        epoch: u64,
        nonce: [u8; 16],
    ) -> Result<(Self, Vec<u8>), NegotiationError> {
        local.validate()?;
        if peer_id == 0 {
            return Err(NegotiationError::InvalidPeerIdentity);
        }
        if nonce == [0u8; 16] {
            return Err(NegotiationError::InvalidNonce);
        }
        let offer = Hello {
            kind: HelloKind::Offer,
            flags: 0,
            caps: local,
            peer_id,
            stream_id,
            epoch,
            nonce,
            answer: None,
        };
        let offer_wire = offer.encode(psk);
        let sent = offer_wire.clone();
        Ok((
            Self {
                psk: psk.clone(),
                offer,
                offer_wire,
            },
            sent,
        ))
    }

    /// Verify the Answer and complete the session. Everything the Answer asserts is checked
    /// against this side's own offer and capabilities: the responder is trusted with nothing.
    pub fn finish(self, answer_wire: &[u8]) -> Result<NegotiatedSession, NegotiationError> {
        let answer = Hello::decode_and_verify(answer_wire, &self.psk)?;
        // Only an Answer carries a selection and a digest, so this is also the kind check.
        let Some(body) = &answer.answer else {
            return Err(NegotiationError::WrongHelloKind);
        };
        if answer.stream_id != self.offer.stream_id {
            return Err(NegotiationError::StreamMismatch);
        }
        if answer.epoch != self.offer.epoch {
            return Err(NegotiationError::EpochMismatch);
        }
        if answer.peer_id == self.offer.peer_id || answer.nonce == self.offer.nonce {
            return Err(NegotiationError::ReflectedHello);
        }
        if body.offer_digest != sha256(&self.offer_wire) {
            return Err(NegotiationError::OfferDigestMismatch);
        }
        let expected = select(&self.offer.caps, &answer.caps)?;
        if body.selection != expected {
            if body.selection.wire_version < expected.wire_version {
                return Err(NegotiationError::DowngradeDetected {
                    expected_wire_version: expected.wire_version,
                    answered_wire_version: body.selection.wire_version,
                });
            }
            return Err(NegotiationError::SelectionMismatch);
        }
        Ok(NegotiatedSession::establish(
            &self.psk,
            self.offer.peer_id,
            answer.peer_id,
            &self.offer,
            expected,
            &self.offer_wire,
            answer_wire,
        ))
    }
}

/// The receiver's half: verify the Offer, select, and answer. `min_epoch` is the receiver's
/// current epoch; an Offer for an older one is a replay and is refused. On any error no session
/// exists and nothing was sent, so an incompatible join changes nothing for the existing group.
pub fn respond(
    psk: &StreamKey,
    local: Capabilities,
    peer_id: u64,
    min_epoch: u64,
    nonce: [u8; 16],
    offer_wire: &[u8],
) -> Result<(NegotiatedSession, Vec<u8>), NegotiationError> {
    local.validate_local()?;
    respond_unchecked(psk, local, peer_id, min_epoch, nonce, offer_wire)
}

/// As [`respond`] without the local-claims check; see [`Initiator::offer_unchecked`].
fn respond_unchecked(
    psk: &StreamKey,
    local: Capabilities,
    peer_id: u64,
    min_epoch: u64,
    nonce: [u8; 16],
    offer_wire: &[u8],
) -> Result<(NegotiatedSession, Vec<u8>), NegotiationError> {
    local.validate()?;
    if peer_id == 0 {
        return Err(NegotiationError::InvalidPeerIdentity);
    }
    if nonce == [0u8; 16] {
        return Err(NegotiationError::InvalidNonce);
    }
    let offer = Hello::decode_and_verify(offer_wire, psk)?;
    if offer.kind != HelloKind::Offer {
        return Err(NegotiationError::WrongHelloKind);
    }
    if offer.epoch < min_epoch {
        return Err(NegotiationError::StaleOfferEpoch {
            offer_epoch: offer.epoch,
            min_epoch,
        });
    }
    if offer.peer_id == peer_id || offer.nonce == nonce {
        return Err(NegotiationError::ReflectedHello);
    }
    let selection = select(&offer.caps, &local)?;
    let answer = Hello {
        kind: HelloKind::Answer,
        flags: 0,
        caps: local,
        peer_id,
        stream_id: offer.stream_id,
        epoch: offer.epoch,
        nonce,
        answer: Some(AnswerBody {
            selection,
            offer_digest: sha256(offer_wire),
        }),
    };
    let answer_wire = answer.encode(psk);
    let session = NegotiatedSession::establish(
        psk,
        peer_id,
        offer.peer_id,
        &offer,
        selection,
        offer_wire,
        &answer_wire,
    );
    Ok((session, answer_wire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AUTH_TAG_LEN_BYTES, HEADER_LEN_BYTES, OutboundFrame, PacketKind, ReceiverCounters,
        StreamError, StreamReceiver, StreamSender,
    };
    use std::fmt::Write as _;

    const VECTORS_JSON: &str = include_str!("../tests/vectors/n01_negotiation_vectors.json");
    const FRAMES_PER_BLOCK_U64: u64 = 256;
    const SENDER: u64 = 0xAA00_0000_0000_0001;
    const RECEIVER: u64 = 0xBB00_0000_0000_0002;

    fn psk() -> StreamKey {
        StreamKey::from_bytes([0x33; 32])
    }

    fn sid() -> StreamId {
        StreamId::new(0x00C0_FFEE_0000_0001).expect("nonzero")
    }

    fn nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    /// Firmware that predates every optional feature.
    fn old_fw() -> Capabilities {
        Capabilities {
            wire_min: 1,
            wire_max: 1,
            formats: FORMAT_PCM16_BE_STEREO_48K,
            max_payload_bytes: 1024,
            mandatory_features: 0,
            optional_features: 0,
        }
    }

    /// Stand-in for a future revision: speaks versions 1 to 3, knows a feature and a format this
    /// build does not.
    fn future_fw() -> Capabilities {
        Capabilities {
            wire_min: 1,
            wire_max: 3,
            formats: 0b11,
            max_payload_bytes: 1024,
            mandatory_features: 0,
            optional_features: KNOWN_FEATURES | (1 << 20),
        }
    }

    fn pcm(frames: usize, salt: u8) -> Vec<u8> {
        (0..frames * 4)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(salt))
            .collect()
    }

    fn frame(n: u64) -> OutboundFrame {
        OutboundFrame::media(
            n * FRAMES_PER_BLOCK_U64,
            2_000_000_000 + n * 5_333_333,
            1_995_000_000 + n * 5_333_333,
            pcm(256, n as u8),
        )
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

    fn remac(wire: &mut [u8]) {
        let tag = hello_tag(&psk(), &wire[..HELLO_BODY_BYTES]);
        wire[HELLO_BODY_BYTES..].copy_from_slice(&tag);
    }

    fn edited(wire: &[u8], offset: usize, bytes: &[u8]) -> Vec<u8> {
        let mut out = wire.to_vec();
        out[offset..offset + bytes.len()].copy_from_slice(bytes);
        remac(&mut out);
        out
    }

    /// Both ends through the public API.
    fn establish_with(
        sender_caps: Capabilities,
        receiver_caps: Capabilities,
        receiver_peer: u64,
        epoch: u64,
        offer_nonce: u8,
        answer_nonce: u8,
    ) -> (NegotiatedSession, NegotiatedSession) {
        let (initiator, offer) = Initiator::offer(
            &psk(),
            sender_caps,
            SENDER,
            sid(),
            epoch,
            nonce(offer_nonce),
        )
        .expect("offer");
        let (receiver_session, answer) = respond(
            &psk(),
            receiver_caps,
            receiver_peer,
            0,
            nonce(answer_nonce),
            &offer,
        )
        .expect("respond");
        let sender_session = initiator.finish(&answer).expect("finish");
        (sender_session, receiver_session)
    }

    fn establish(
        sender_caps: Capabilities,
        receiver_caps: Capabilities,
    ) -> (NegotiatedSession, NegotiatedSession) {
        establish_with(sender_caps, receiver_caps, RECEIVER, 7, 0x11, 0x22)
    }

    #[test]
    fn old_and_new_firmware_settle_on_the_highest_common_version_and_the_common_features() {
        // The new firmware speaks 1..=3; the old one only 1, with no optional features.
        let expected = Selection {
            wire_version: 1,
            format: 1,
            max_payload_bytes: 1024,
            features: 0,
        };
        assert_eq!(select(&future_fw(), &old_fw()), Ok(expected));
        assert_eq!(select(&old_fw(), &future_fw()), Ok(expected));

        // Against a current-build peer the two known features are common; the unknown bit is not.
        let expected = Selection {
            wire_version: 1,
            format: 1,
            max_payload_bytes: 1024,
            features: FEATURE_XOR_PARITY_FEC | FEATURE_PARTIAL_FINAL_BLOCK,
        };
        assert_eq!(
            select(&future_fw(), &Capabilities::baseline()),
            Ok(expected)
        );

        // Two new peers use the highest version and every feature both know, unknown bit included.
        assert_eq!(
            select(&future_fw(), &future_fw()),
            Ok(Selection {
                wire_version: 3,
                format: 1,
                max_payload_bytes: 1024,
                features: 0x0010_0003,
            })
        );
        // Adjacent ranges meet at their shared version.
        let a = Capabilities {
            wire_min: 1,
            wire_max: 2,
            ..old_fw()
        };
        let b = Capabilities {
            wire_min: 2,
            wire_max: 3,
            ..old_fw()
        };
        assert_eq!(select(&a, &b).map(|s| s.wire_version), Ok(2));
    }

    #[test]
    fn disjoint_version_ranges_have_no_session() {
        let future_only = Capabilities {
            wire_min: 2,
            wire_max: 3,
            ..old_fw()
        };
        assert_eq!(
            select(&old_fw(), &future_only),
            Err(NegotiationError::NoCommonVersion {
                local_min: 1,
                local_max: 1,
                peer_min: 2,
                peer_max: 3
            })
        );
    }

    #[test]
    fn a_mandatory_feature_the_other_side_lacks_is_fatal_in_either_direction() {
        let needs_xor = Capabilities {
            mandatory_features: FEATURE_XOR_PARITY_FEC,
            optional_features: FEATURE_PARTIAL_FINAL_BLOCK,
            ..old_fw()
        };
        assert_eq!(
            select(&needs_xor, &old_fw()),
            Err(NegotiationError::MandatoryFeatureMissing { missing: 1 })
        );
        assert_eq!(
            select(&old_fw(), &needs_xor),
            Err(NegotiationError::MandatoryFeatureMissing { missing: 1 })
        );
        // A mandatory bit this build has never heard of is a refusal to interoperate, not ignored.
        let needs_unknown = Capabilities {
            mandatory_features: 1 << 20,
            ..old_fw()
        };
        assert_eq!(
            select(&needs_unknown, &Capabilities::baseline()),
            Err(NegotiationError::MandatoryFeatureMissing {
                missing: 0x0010_0000
            })
        );
        // Each side missing the other's requirement: both bits are reported.
        let a = Capabilities {
            mandatory_features: 0b01,
            ..old_fw()
        };
        let b = Capabilities {
            mandatory_features: 0b10,
            ..old_fw()
        };
        assert_eq!(
            select(&a, &b),
            Err(NegotiationError::MandatoryFeatureMissing { missing: 0b11 })
        );
        // Paired positive: a mandatory feature the other side lists as optional is satisfied and
        // becomes part of the session.
        let optional_xor = Capabilities {
            optional_features: FEATURE_XOR_PARITY_FEC,
            ..old_fw()
        };
        assert_eq!(
            select(&needs_xor, &optional_xor).map(|s| s.features),
            Ok(FEATURE_XOR_PARITY_FEC)
        );
    }

    #[test]
    fn formats_and_limits_are_negotiated_and_a_limit_below_one_block_is_incompatible() {
        let only_second = Capabilities {
            formats: 0b10,
            ..old_fw()
        };
        assert_eq!(
            select(&only_second, &old_fw()),
            Err(NegotiationError::NoCommonFormat)
        );
        let both = Capabilities {
            formats: 0b11,
            ..old_fw()
        };
        assert_eq!(select(&both, &only_second).map(|s| s.format), Ok(0b10));
        assert_eq!(select(&both, &both).map(|s| s.format), Ok(0b01));

        let small = Capabilities {
            max_payload_bytes: 512,
            ..old_fw()
        };
        assert_eq!(
            select(&small, &old_fw()),
            Err(NegotiationError::LimitsIncompatible {
                common_max_payload: 512
            })
        );
        // A larger claim is capped at what this wire version can carry.
        let big = Capabilities {
            max_payload_bytes: 4096,
            ..old_fw()
        };
        assert_eq!(select(&big, &big).map(|s| s.max_payload_bytes), Ok(1024));
    }

    #[test]
    fn malformed_capability_claims_are_rejected() {
        let bad = [
            Capabilities {
                wire_min: 0,
                ..old_fw()
            },
            Capabilities {
                wire_min: 2,
                wire_max: 1,
                ..old_fw()
            },
            Capabilities {
                formats: 0,
                ..old_fw()
            },
            Capabilities {
                max_payload_bytes: 6,
                ..old_fw()
            },
            Capabilities {
                max_payload_bytes: 0,
                ..old_fw()
            },
            Capabilities {
                mandatory_features: 1,
                optional_features: 1,
                ..old_fw()
            },
        ];
        for caps in bad {
            assert_eq!(
                select(&caps, &old_fw()),
                Err(NegotiationError::InvalidCapabilities),
                "{caps:?}"
            );
        }
        // This build refuses to claim what it does not implement, even though the claim is
        // well-formed.
        for caps in [
            future_fw(),
            Capabilities {
                wire_max: 2,
                ..old_fw()
            },
        ] {
            assert_eq!(
                Initiator::offer(&psk(), caps, SENDER, sid(), 1, nonce(1)).err(),
                Some(NegotiationError::InvalidCapabilities)
            );
        }
    }

    #[test]
    fn a_full_exchange_gives_both_sides_the_same_session_and_a_working_bound_key() {
        let (tx, rx) = establish(Capabilities::baseline(), Capabilities::baseline());
        let expected = Selection {
            wire_version: 1,
            format: 1,
            max_payload_bytes: 1024,
            features: 3,
        };
        assert_eq!(tx.selection(), &expected);
        assert_eq!(rx.selection(), &expected);
        assert_eq!(tx.transcript_digest(), rx.transcript_digest());
        assert_eq!(tx.media_key().0, rx.media_key().0);
        assert_ne!(
            tx.media_key().0,
            psk().0,
            "the media key is derived, not the group key"
        );
        assert_eq!(
            (tx.local_peer_id(), tx.remote_peer_id()),
            (SENDER, RECEIVER)
        );
        assert_eq!(
            (rx.local_peer_id(), rx.remote_peer_id()),
            (RECEIVER, SENDER)
        );
        assert_eq!((tx.stream_id(), tx.epoch()), (sid(), 7));
        assert_eq!((rx.stream_id(), rx.epoch()), (sid(), 7));

        let mut sender = StreamSender::from_negotiated(&tx).unwrap();
        let mut receiver = StreamReceiver::from_negotiated(&rx).unwrap();
        for n in 0..3 {
            assert!(receiver.accept(&sender.send(frame(n)).unwrap()).is_ok());
        }
        assert_eq!(receiver.counters().accepted, 3);

        let shown = format!("{tx:?}");
        assert!(
            shown.contains("REDACTED") && !shown.contains("51, 51, 51, 51"),
            "{shown}"
        );
    }

    #[test]
    fn media_from_a_different_negotiation_does_not_authenticate() {
        let (tx_a, _) = establish_with(
            Capabilities::baseline(),
            Capabilities::baseline(),
            RECEIVER,
            7,
            0x11,
            0x22,
        );
        let (_, rx_b) = establish_with(
            Capabilities::baseline(),
            Capabilities::baseline(),
            RECEIVER,
            7,
            0x33,
            0x44,
        );
        let (_, rx_a) = establish_with(
            Capabilities::baseline(),
            Capabilities::baseline(),
            RECEIVER,
            7,
            0x11,
            0x22,
        );
        let mut sender = StreamSender::from_negotiated(&tx_a).unwrap();
        let wire = sender.send(frame(0)).unwrap();
        // Same peers, stream, epoch and capabilities, but a different transcript: fail closed.
        let mut other = StreamReceiver::from_negotiated(&rx_b).unwrap();
        assert_eq!(other.accept(&wire), Err(StreamError::AuthenticationFailed));
        // Paired positive: the receiver of the same negotiation admits it.
        let mut same = StreamReceiver::from_negotiated(&rx_a).unwrap();
        assert!(same.accept(&wire).is_ok());
        // A different epoch is a different transcript too.
        let (_, rx_e8) = establish_with(
            Capabilities::baseline(),
            Capabilities::baseline(),
            RECEIVER,
            8,
            0x11,
            0x22,
        );
        assert_ne!(rx_e8.media_key().0, rx_a.media_key().0);
        // And a different peer answering is a different transcript.
        let (_, rx_peer) = establish_with(
            Capabilities::baseline(),
            Capabilities::baseline(),
            RECEIVER + 1,
            7,
            0x11,
            0x22,
        );
        assert_ne!(rx_peer.media_key().0, rx_a.media_key().0);
    }

    fn future_pair(
        a: Capabilities,
        b: Capabilities,
    ) -> (Initiator, Vec<u8>, NegotiatedSession, Vec<u8>) {
        let (initiator, offer) =
            Initiator::offer_unchecked(&psk(), a, SENDER, sid(), 7, nonce(0x11)).unwrap();
        let (session, answer) =
            respond_unchecked(&psk(), b, RECEIVER, 0, nonce(0x22), &offer).unwrap();
        (initiator, offer, session, answer)
    }

    #[test]
    fn stripping_a_higher_version_from_an_offer_without_the_key_fails_authentication() {
        let (_, offer) =
            Initiator::offer_unchecked(&psk(), future_fw(), SENDER, sid(), 7, nonce(0x11)).unwrap();
        // The attacker lowers wire_max from 3 to 1 in flight, to force version 1.
        let mut stripped = offer.clone();
        stripped[OFF_WIRE_MAX] = 1;
        assert_eq!(
            respond_unchecked(&psk(), future_fw(), RECEIVER, 0, nonce(0x22), &stripped).err(),
            Some(NegotiationError::HelloAuthenticationFailed)
        );
        // Paired positive: the untouched offer is answered, and selects the highest version.
        let (session, _) =
            respond_unchecked(&psk(), future_fw(), RECEIVER, 0, nonce(0x22), &offer).unwrap();
        assert_eq!(session.selection().wire_version, 3);
    }

    #[test]
    fn even_a_re_authenticated_modified_offer_is_detected_by_the_initiator() {
        let (initiator, offer) =
            Initiator::offer_unchecked(&psk(), future_fw(), SENDER, sid(), 7, nonce(0x11)).unwrap();
        // A party holding the group key re-signs an offer whose wire_max was lowered.
        let modified = edited(&offer, OFF_WIRE_MAX, &[1]);
        let (_, answer) =
            respond_unchecked(&psk(), future_fw(), RECEIVER, 0, nonce(0x22), &modified).unwrap();
        // The responder answered what it was shown; the answer binds the digest of that offer, which
        // is not the offer the initiator sent.
        assert_eq!(
            initiator.finish(&answer).err(),
            Some(NegotiationError::OfferDigestMismatch)
        );
    }

    #[test]
    fn an_answer_selecting_a_lower_version_than_is_jointly_supported_is_a_downgrade() {
        let v2 = Capabilities {
            wire_max: 2,
            ..old_fw()
        };
        let (initiator, _, _, honest) = future_pair(v2, v2);
        let mut forged = Hello::decode_and_verify(&honest, &psk()).unwrap();
        assert_eq!(forged.answer.as_ref().unwrap().selection.wire_version, 2);
        forged.answer.as_mut().unwrap().selection.wire_version = 1;
        assert_eq!(
            initiator.finish(&forged.encode(&psk())).err(),
            Some(NegotiationError::DowngradeDetected {
                expected_wire_version: 2,
                answered_wire_version: 1
            })
        );
        // Paired positive: the honest answer completes at version 2.
        let (initiator, _, _, honest) = future_pair(v2, v2);
        assert_eq!(
            initiator.finish(&honest).unwrap().selection().wire_version,
            2
        );
    }

    #[test]
    fn an_answer_that_strips_or_adds_selection_content_is_a_mismatch_not_a_session() {
        let caps = Capabilities::baseline();
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut stripped = Hello::decode_and_verify(&honest, &psk()).unwrap();
        stripped.answer.as_mut().unwrap().selection.features &= !FEATURE_XOR_PARITY_FEC;
        assert_eq!(
            initiator.finish(&stripped.encode(&psk())).err(),
            Some(NegotiationError::SelectionMismatch)
        );
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut upgraded = Hello::decode_and_verify(&honest, &psk()).unwrap();
        upgraded.answer.as_mut().unwrap().selection.wire_version = 3;
        assert_eq!(
            initiator.finish(&upgraded.encode(&psk())).err(),
            Some(NegotiationError::SelectionMismatch),
            "claiming a higher version than the capabilities allow is not a downgrade"
        );
    }

    #[test]
    fn an_answer_from_an_earlier_negotiation_does_not_answer_a_new_offer() {
        let caps = Capabilities::baseline();
        let (_, _, _, old_answer) = future_pair(caps, caps);
        let (second, _) =
            Initiator::offer_unchecked(&psk(), caps, SENDER, sid(), 7, nonce(0x33)).unwrap();
        assert_eq!(
            second.finish(&old_answer).err(),
            Some(NegotiationError::OfferDigestMismatch)
        );
    }

    #[test]
    fn reflections_and_cross_stream_answers_are_refused() {
        let caps = Capabilities::baseline();
        // The offer fed back as the answer.
        let (initiator, offer) =
            Initiator::offer_unchecked(&psk(), caps, SENDER, sid(), 7, nonce(0x11)).unwrap();
        assert_eq!(
            initiator.finish(&offer).err(),
            Some(NegotiationError::WrongHelloKind)
        );
        // An answer under the offer's own peer identity, and one reusing the offer's nonce.
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut same_peer = Hello::decode_and_verify(&honest, &psk()).unwrap();
        same_peer.peer_id = SENDER;
        assert_eq!(
            initiator.finish(&same_peer.encode(&psk())).err(),
            Some(NegotiationError::ReflectedHello)
        );
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut same_nonce = Hello::decode_and_verify(&honest, &psk()).unwrap();
        same_nonce.nonce = nonce(0x11);
        assert_eq!(
            initiator.finish(&same_nonce.encode(&psk())).err(),
            Some(NegotiationError::ReflectedHello)
        );
        // An answer for another stream, and for another epoch.
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut other_stream = Hello::decode_and_verify(&honest, &psk()).unwrap();
        other_stream.stream_id = StreamId::new(5).unwrap();
        assert_eq!(
            initiator.finish(&other_stream.encode(&psk())).err(),
            Some(NegotiationError::StreamMismatch)
        );
        let (initiator, _, _, honest) = future_pair(caps, caps);
        let mut other_epoch = Hello::decode_and_verify(&honest, &psk()).unwrap();
        other_epoch.epoch = 8;
        assert_eq!(
            initiator.finish(&other_epoch.encode(&psk())).err(),
            Some(NegotiationError::EpochMismatch)
        );
        // An answer where an offer belongs.
        let (_, _, _, answer) = future_pair(caps, caps);
        assert_eq!(
            respond_unchecked(&psk(), caps, RECEIVER, 0, nonce(0x44), &answer).err(),
            Some(NegotiationError::WrongHelloKind)
        );
    }

    #[test]
    fn an_offer_for_an_epoch_older_than_the_receivers_is_refused() {
        let (_, offer) = Initiator::offer(
            &psk(),
            Capabilities::baseline(),
            SENDER,
            sid(),
            7,
            nonce(0x11),
        )
        .unwrap();
        assert_eq!(
            respond(
                &psk(),
                Capabilities::baseline(),
                RECEIVER,
                8,
                nonce(0x22),
                &offer
            )
            .err(),
            Some(NegotiationError::StaleOfferEpoch {
                offer_epoch: 7,
                min_epoch: 8
            })
        );
        assert!(
            respond(
                &psk(),
                Capabilities::baseline(),
                RECEIVER,
                7,
                nonce(0x22),
                &offer
            )
            .is_ok()
        );
    }

    #[test]
    fn identities_and_nonces_must_be_nonzero_and_distinct() {
        let base = Capabilities::baseline();
        assert_eq!(
            Initiator::offer(&psk(), base, 0, sid(), 7, nonce(1)).err(),
            Some(NegotiationError::InvalidPeerIdentity)
        );
        assert_eq!(
            Initiator::offer(&psk(), base, SENDER, sid(), 7, [0u8; 16]).err(),
            Some(NegotiationError::InvalidNonce)
        );
        let (_, offer) = Initiator::offer(&psk(), base, SENDER, sid(), 7, nonce(1)).unwrap();
        assert_eq!(
            respond(&psk(), base, 0, 0, nonce(2), &offer).err(),
            Some(NegotiationError::InvalidPeerIdentity)
        );
        assert_eq!(
            respond(&psk(), base, RECEIVER, 0, [0u8; 16], &offer).err(),
            Some(NegotiationError::InvalidNonce)
        );
        assert_eq!(
            respond(&psk(), base, SENDER, 0, nonce(2), &offer).err(),
            Some(NegotiationError::ReflectedHello)
        );
        assert_eq!(
            respond(&psk(), base, RECEIVER, 0, nonce(1), &offer).err(),
            Some(NegotiationError::ReflectedHello)
        );
    }

    #[test]
    fn authenticated_but_unacceptable_messages_are_refused_field_by_field() {
        let (_, offer) =
            Initiator::offer(&psk(), Capabilities::baseline(), SENDER, sid(), 7, nonce(1)).unwrap();
        let try_offer = |wire: &[u8]| {
            respond(
                &psk(),
                Capabilities::baseline(),
                RECEIVER,
                0,
                nonce(2),
                wire,
            )
            .err()
        };
        assert_eq!(
            try_offer(&edited(&offer, OFF_KIND, &[9])),
            Some(NegotiationError::UnknownHelloKind { kind: 9 })
        );
        assert_eq!(
            try_offer(&edited(&offer, OFF_FLAGS, &[0x10])),
            Some(NegotiationError::UnknownCriticalHelloFlags { flags: 0x10 })
        );
        assert_eq!(
            try_offer(&edited(&offer, 4, &[2])),
            Some(NegotiationError::HelloUnsupportedVersion { version: 2 }),
            "the version byte is checked before the tag, so re-signing cannot get it interpreted"
        );
        assert_eq!(
            try_offer(&edited(&offer, OFF_WIRE_MIN, &[0])),
            Some(NegotiationError::InvalidCapabilities)
        );
        assert_eq!(
            try_offer(&edited(&offer, OFF_PEER, &0u64.to_be_bytes())),
            Some(NegotiationError::InvalidPeerIdentity)
        );
        assert_eq!(
            try_offer(&edited(&offer, OFF_STREAM, &0u64.to_be_bytes())),
            Some(NegotiationError::InvalidPeerIdentity)
        );
        assert_eq!(
            try_offer(&edited(&offer, OFF_NONCE, &[0u8; 16])),
            Some(NegotiationError::InvalidNonce)
        );
        // An offer carrying selection content, and an answer with a malformed selection.
        assert_eq!(
            try_offer(&edited(&offer, OFF_SEL_VERSION, &[1])),
            Some(NegotiationError::MalformedHello)
        );
        let (initiator, _, _, answer) =
            future_pair(Capabilities::baseline(), Capabilities::baseline());
        let malformed = edited(&answer, OFF_SEL_FORMAT, &[0b11]);
        assert_eq!(
            initiator.finish(&malformed).err(),
            Some(NegotiationError::MalformedHello)
        );
        // Paired positive: an ignorable flag bit is authenticated and accepted.
        assert!(try_offer(&edited(&offer, OFF_FLAGS, &[0x01])).is_none());
    }

    #[test]
    fn negotiation_messages_reject_every_truncation_extension_and_single_bit_flip() {
        let (initiator, offer) =
            Initiator::offer(&psk(), Capabilities::baseline(), SENDER, sid(), 7, nonce(1)).unwrap();
        let (_, answer) = respond(
            &psk(),
            Capabilities::baseline(),
            RECEIVER,
            0,
            nonce(2),
            &offer,
        )
        .unwrap();
        assert_eq!(offer.len(), HELLO_DATAGRAM_BYTES);
        assert_eq!(answer.len(), HELLO_DATAGRAM_BYTES);
        for wire in [&offer, &answer] {
            for cut in 0..wire.len() {
                assert_eq!(
                    Hello::decode_and_verify(&wire[..cut], &psk()).err(),
                    Some(NegotiationError::HelloLength { actual: cut })
                );
            }
            for extra in 1..=8 {
                let mut longer = wire.clone();
                longer.extend(std::iter::repeat_n(0xEE, extra));
                assert_eq!(
                    Hello::decode_and_verify(&longer, &psk()).err(),
                    Some(NegotiationError::HelloLength {
                        actual: HELLO_DATAGRAM_BYTES + extra
                    })
                );
            }
            for byte in 0..wire.len() {
                for bit in 0..8 {
                    let mut bad = wire.clone();
                    bad[byte] ^= 1 << bit;
                    assert!(
                        Hello::decode_and_verify(&bad, &psk()).is_err(),
                        "flip of byte {byte} bit {bit} was accepted"
                    );
                }
            }
        }
        // The untouched pair still completes (the loops above only read it).
        assert!(initiator.finish(&answer).is_ok());
    }

    #[test]
    fn arbitrary_garbage_is_never_a_negotiation_message() {
        let mut state = 0x6E65_676F_u64;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for _ in 0..5_000 {
            let len = (next() % 200) as usize;
            let mut junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len == HELLO_DATAGRAM_BYTES && next() % 2 == 0 {
                junk[0..4].copy_from_slice(&HELLO_MAGIC);
                junk[4] = HELLO_VERSION;
            }
            assert!(Hello::decode_and_verify(&junk, &psk()).is_err());
        }
    }

    #[test]
    fn negotiated_features_are_enforced_by_both_endpoints() {
        // The receiver is old firmware: no optional feature is in the session.
        let (tx, rx) = establish(Capabilities::baseline(), old_fw());
        assert_eq!(tx.selection().features, 0);
        let mut sender = StreamSender::from_negotiated(&tx).unwrap();
        let mut receiver = StreamReceiver::from_negotiated(&rx).unwrap();

        // The sender refuses to send what was not negotiated, and a refusal burns no sequence number.
        let repair = OutboundFrame {
            kind: PacketKind::Repair,
            fec_group_size: 4,
            ..frame(0)
        };
        assert_eq!(
            sender.send(repair),
            Err(StreamError::FeatureNotNegotiated {
                feature: FEATURE_XOR_PARITY_FEC
            })
        );
        let partial = OutboundFrame::media(0, 2_000_000_000, 1_995_000_000, pcm(3, 1));
        assert_eq!(
            sender.send(partial),
            Err(StreamError::FeatureNotNegotiated {
                feature: FEATURE_PARTIAL_FINAL_BLOCK
            })
        );
        assert_eq!(sender.next_seq(), 0);

        // The receiver refuses them too, even when a peer holding the session key signs them.
        let mut unrestricted = StreamSender::new(tx.media_key().clone(), sid(), 7);
        let forged_repair = unrestricted
            .send(OutboundFrame {
                kind: PacketKind::Repair,
                fec_group_size: 4,
                ..frame(0)
            })
            .unwrap();
        let forged_partial = unrestricted
            .send(OutboundFrame::media(
                256,
                2_000_000_000,
                1_995_000_000,
                pcm(3, 2),
            ))
            .unwrap();
        assert_eq!(
            receiver.accept(&forged_repair),
            Err(StreamError::FeatureNotNegotiated {
                feature: FEATURE_XOR_PARITY_FEC
            })
        );
        assert_eq!(
            receiver.accept(&forged_partial),
            Err(StreamError::FeatureNotNegotiated {
                feature: FEATURE_PARTIAL_FINAL_BLOCK
            })
        );
        assert_eq!(receiver.counters().rejected_not_negotiated, 2);
        // Paired positive: an ordinary full media block still flows.
        assert!(receiver.accept(&sender.send(frame(0)).unwrap()).is_ok());
        assert_eq!(sender.next_seq(), 1);

        // With both features negotiated, the same frames are legal on both ends.
        let (tx, rx) = establish(Capabilities::baseline(), Capabilities::baseline());
        let mut sender = StreamSender::from_negotiated(&tx).unwrap();
        let mut receiver = StreamReceiver::from_negotiated(&rx).unwrap();
        let repair = OutboundFrame {
            kind: PacketKind::Repair,
            fec_group_size: 4,
            ..frame(0)
        };
        assert!(receiver.accept(&sender.send(repair).unwrap()).is_ok());
        let partial = OutboundFrame::media(256, 2_000_000_000, 1_995_000_000, pcm(3, 1));
        assert!(receiver.accept(&sender.send(partial).unwrap()).is_ok());
    }

    #[test]
    fn a_session_this_build_cannot_speak_is_not_turned_into_media_endpoints() {
        // Both peers stand in for firmware speaking up to version 3: the negotiation is sound...
        let v3 = Capabilities {
            wire_max: 3,
            ..old_fw()
        };
        let (_, _, session, _) = future_pair(v3, v3);
        assert_eq!(session.selection().wire_version, 3);
        // ...but this build only implements wire version 1, so it refuses to start media.
        assert_eq!(
            StreamSender::from_negotiated(&session).err(),
            Some(StreamError::UnsupportedWireVersion { version: 3 })
        );
        assert_eq!(
            StreamReceiver::from_negotiated(&session).err(),
            Some(StreamError::UnsupportedWireVersion { version: 3 })
        );
        // Likewise for a format this build cannot decode.
        let second_format = Capabilities {
            formats: 0b10,
            ..old_fw()
        };
        let (_, _, session, _) = future_pair(second_format, second_format);
        assert_eq!(session.selection().format, 0b10);
        assert_eq!(
            StreamSender::from_negotiated(&session).err(),
            Some(StreamError::UnknownFormat { format: 0b10 })
        );
    }

    #[test]
    fn an_incompatible_join_leaves_the_existing_group_playing_unchanged() {
        // The group requires XOR parity FEC from every member.
        let group = Capabilities {
            mandatory_features: FEATURE_XOR_PARITY_FEC,
            optional_features: FEATURE_PARTIAL_FINAL_BLOCK,
            ..Capabilities::baseline()
        };
        let mut members: Vec<(StreamSender, StreamReceiver)> = Vec::new();
        for (peer, seed) in [
            (0xB100_0000_0000_0001_u64, 0x21_u8),
            (0xB200_0000_0000_0002, 0x31),
        ] {
            let (tx, rx) = establish_with(group, Capabilities::baseline(), peer, 7, seed, seed + 1);
            members.push((
                StreamSender::from_negotiated(&tx).unwrap(),
                StreamReceiver::from_negotiated(&rx).unwrap(),
            ));
        }
        for n in 0..5 {
            for (sender, receiver) in &mut members {
                receiver.accept(&sender.send(frame(n)).unwrap()).unwrap();
            }
        }
        let snapshot = |members: &Vec<(StreamSender, StreamReceiver)>| {
            members
                .iter()
                .map(|(s, r)| {
                    (
                        s.next_seq(),
                        s.epoch(),
                        r.counters().clone(),
                        r.active_epoch(),
                    )
                })
                .collect::<Vec<(u64, u64, ReceiverCounters, u64)>>()
        };
        let before = snapshot(&members);
        assert_eq!(before[0].0, 5);

        // A speaker that lacks the mandatory feature tries to join, twice.
        for attempt in 0..2_u8 {
            let (initiator, offer) =
                Initiator::offer(&psk(), group, SENDER, sid(), 7, nonce(0x41 + attempt)).unwrap();
            assert_eq!(
                respond(
                    &psk(),
                    old_fw(),
                    0xB300_0000_0000_0003,
                    0,
                    nonce(0x51 + attempt),
                    &offer
                )
                .err(),
                Some(NegotiationError::MandatoryFeatureMissing {
                    missing: FEATURE_XOR_PARITY_FEC
                })
            );
            drop(initiator);
        }
        assert_eq!(
            snapshot(&members),
            before,
            "a failed join must touch nothing"
        );

        // Playback continues with no gap and no rejection.
        for n in 5..10 {
            for (sender, receiver) in &mut members {
                receiver.accept(&sender.send(frame(n)).unwrap()).unwrap();
            }
        }
        for (sender, receiver) in &members {
            assert_eq!(sender.next_seq(), 10);
            assert_eq!(receiver.counters().accepted, 10);
            assert_eq!(receiver.counters().datagrams_seen, 10);
        }
    }

    #[test]
    fn endpoints_with_different_capability_sets_share_one_wire_format() {
        // An endpoint without any optional feature and one with all of them negotiate different
        // feature sets over the same framing: the header layout and values are identical.
        let (tx_old, _) = establish(Capabilities::baseline(), old_fw());
        let (tx_new, _) = establish(Capabilities::baseline(), Capabilities::baseline());
        assert_ne!(tx_old.selection().features, tx_new.selection().features);
        let a = StreamSender::from_negotiated(&tx_old)
            .unwrap()
            .send(frame(0))
            .unwrap();
        let b = StreamSender::from_negotiated(&tx_new)
            .unwrap()
            .send(frame(0))
            .unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(&a[..HEADER_LEN_BYTES], &b[..HEADER_LEN_BYTES]);
        assert_eq!(
            &a[HEADER_LEN_BYTES..a.len() - AUTH_TAG_LEN_BYTES],
            &b[HEADER_LEN_BYTES..b.len() - AUTH_TAG_LEN_BYTES]
        );
        // Only the tags differ, because each session has its own key.
        assert_ne!(
            &a[a.len() - AUTH_TAG_LEN_BYTES..],
            &b[b.len() - AUTH_TAG_LEN_BYTES..]
        );
    }

    fn caps_from_json(v: &serde_json::Value) -> Capabilities {
        Capabilities {
            wire_min: v["wire_min"].as_u64().unwrap() as u8,
            wire_max: v["wire_max"].as_u64().unwrap() as u8,
            formats: v["formats"].as_u64().unwrap() as u8,
            max_payload_bytes: v["max_payload_bytes"].as_u64().unwrap() as u16,
            mandatory_features: v["mandatory_features"].as_u64().unwrap() as u32,
            optional_features: v["optional_features"].as_u64().unwrap() as u32,
        }
    }

    fn nonce_from_hex(text: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&unhex(text));
        out
    }

    fn key_from_hex(text: &str) -> StreamKey {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&unhex(text));
        StreamKey::from_bytes(raw)
    }

    #[test]
    fn golden_negotiations_from_the_independent_python_reference_match_byte_for_byte() {
        let doc: serde_json::Value =
            serde_json::from_str(VECTORS_JSON).expect("vector file parses");
        let key = key_from_hex(doc["key_hex"].as_str().unwrap());
        let cases = doc["negotiations"].as_array().expect("negotiations");
        assert!(cases.len() >= 2);
        for c in cases {
            let id = c["id"].as_str().unwrap();
            let stream = StreamId::new(c["stream_id"].as_u64().unwrap()).unwrap();
            let epoch = c["epoch"].as_u64().unwrap();
            let (initiator, offer) = Initiator::offer(
                &key,
                caps_from_json(&c["sender_caps"]),
                c["sender_peer"].as_u64().unwrap(),
                stream,
                epoch,
                nonce_from_hex(c["offer_nonce_hex"].as_str().unwrap()),
            )
            .unwrap_or_else(|e| panic!("{id}: offer refused: {e}"));
            assert_eq!(
                hex(&offer),
                c["offer_hex"].as_str().unwrap(),
                "{id}: offer bytes"
            );
            let (rx, answer) = respond(
                &key,
                caps_from_json(&c["receiver_caps"]),
                c["receiver_peer"].as_u64().unwrap(),
                c["min_epoch"].as_u64().unwrap(),
                nonce_from_hex(c["answer_nonce_hex"].as_str().unwrap()),
                &offer,
            )
            .unwrap_or_else(|e| panic!("{id}: respond refused: {e}"));
            assert_eq!(
                hex(&answer),
                c["answer_hex"].as_str().unwrap(),
                "{id}: answer bytes"
            );
            let tx = initiator
                .finish(&answer)
                .unwrap_or_else(|e| panic!("{id}: finish refused: {e}"));
            let want = &c["selection"];
            let selection = Selection {
                wire_version: want["wire_version"].as_u64().unwrap() as u8,
                format: want["format"].as_u64().unwrap() as u8,
                max_payload_bytes: want["max_payload_bytes"].as_u64().unwrap() as u16,
                features: want["features"].as_u64().unwrap() as u32,
            };
            for session in [&tx, &rx] {
                assert_eq!(session.selection(), &selection, "{id}");
                assert_eq!(
                    hex(session.transcript_digest()),
                    c["transcript_hex"].as_str().unwrap(),
                    "{id}: transcript"
                );
                assert_eq!(
                    hex(&session.media_key().0),
                    c["session_key_hex"].as_str().unwrap(),
                    "{id}: media key"
                );
            }
        }
    }

    #[test]
    fn golden_negotiation_rejections_from_the_reference_carry_the_same_codes() {
        let doc: serde_json::Value =
            serde_json::from_str(VECTORS_JSON).expect("vector file parses");
        let key = key_from_hex(doc["key_hex"].as_str().unwrap());
        let cases = doc["rejections"].as_array().expect("rejections");
        assert!(
            cases.len() >= 15,
            "rejection vectors shrank to {}",
            cases.len()
        );
        for c in cases {
            let id = c["id"].as_str().unwrap();
            let expect = c["expect"].as_str().unwrap();
            let got = match c["op"].as_str().unwrap() {
                "respond" => respond(
                    &key,
                    caps_from_json(&c["local_caps"]),
                    c["local_peer"].as_u64().unwrap(),
                    c["min_epoch"].as_u64().unwrap(),
                    nonce_from_hex(c["nonce_hex"].as_str().unwrap()),
                    &unhex(c["offer_hex"].as_str().unwrap()),
                )
                .err(),
                "finish" => {
                    let (initiator, _) = Initiator::offer(
                        &key,
                        caps_from_json(&c["sender_caps"]),
                        c["sender_peer"].as_u64().unwrap(),
                        StreamId::new(c["stream_id"].as_u64().unwrap()).unwrap(),
                        c["epoch"].as_u64().unwrap(),
                        nonce_from_hex(c["offer_nonce_hex"].as_str().unwrap()),
                    )
                    .unwrap();
                    initiator
                        .finish(&unhex(c["answer_hex"].as_str().unwrap()))
                        .err()
                }
                other => panic!("{id}: unknown op {other}"),
            };
            match got {
                None => panic!("{id}: expected {expect}, but the negotiation succeeded"),
                Some(err) => assert_eq!(err.code(), expect, "{id}: {err}"),
            }
        }
    }
}
