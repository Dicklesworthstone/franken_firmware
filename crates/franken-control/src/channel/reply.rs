//! Authenticated replies (N02 / `ffw-ugf`, section 9.1): what a client can check about the answer it gets.
//!
//! Until now the channel answered with values (`SubmitResult`, `Settlement`) and said nothing about how
//! they travel. A client that trusts an unauthenticated "committed" is exposed to anyone who can reach
//! its connection: a forged answer, a genuine answer to some other command, or an old answer replayed
//! after the state moved on. This module is the answer on the wire, and the check a client makes of it.
//!
//! # The reply
//!
//! A [`ReplyBody`] names **who** it answers (`peer`, `seq`: the command id), **which request** (the
//! SHA-256 of that request's signed bytes, so a reused number with other content is not the same
//! command), **when** (the session's `epoch` and state `revision` at the moment it was made), and **what**
//! happened (a [`ReplyStatus`]). The tag is `HMAC-SHA256(peer key, "FFCR-v1-reply" || signed bytes)`: the
//! same key as the request's proof, under a different label and a different magic, so a request's proof is
//! never a reply's tag. The wire is the signed bytes followed by the 32-byte tag, explicit and big-endian;
//! every status has one encoding and a decoder refuses any other, so there is nothing to be lenient about.
//!
//! # What a client checks, in this order
//!
//! [`verify_reply`] returns a [`VerifiedReply`] only if
//! 1. the **tag** is right (`BadTag`): the reply was made by a holder of this peer's key. Checked first and
//!    in constant time, so a forger learns nothing from which later check would have failed;
//! 2. it answers **this command** (`WrongCommand`): same peer, same `seq`;
//! 3. it answers **this request** (`WrongRequest`): the same bytes, not another request under the same number;
//! 4. it is **not older** than what the client has already seen (`Stale`): its `(epoch, revision)` is not
//!    below the client's [`Freshness`].
//!
//! # What this does and does not protect
//!
//! * A genuine reply is only ever the channel's own answer, so the **one transition** of a command stays
//!   visible to a retrying client: it asks again, and the ledger answers with the same outcome and applies
//!   nothing twice. A forged "not applied" is refused, and the client asks again.
//! * An **unauthenticated request gets no reply**, and a peer that has been revoked cannot be signed for, so
//!   the channel is not an oracle for anyone without a key.
//! * The tag is a **symmetric** MAC: it proves that a holder of the peer's key made the reply, which is the
//!   channel or the client itself. It is not a signature, and it protects against third parties and replays,
//!   not against a peer forging its own answers. It gives no confidentiality.
//! * It does not decide how a client obtains its key, where it keeps it, or how it is rotated (P03, U01, N01).
//! * A client that has been told of a restart or a new epoch must reset its [`Freshness`]: a rebuilt session
//!   starts at a lower revision, and a fresh reply would otherwise look stale to it.

use franken_session::UnifiedGroupSession;
use sha2::{Digest, Sha256};

use super::peer::{
    AuthProof, MAX_PEER_ID_LEN, PROOF_LEN, PeerAuthority, PeerError, PeerId, ReplySigner,
    reply_tag_matches,
};
use super::pipeline::{ControlChannel, Outcome, Refusal, Rejection, SubmitResult};
use super::request::{ControlRequest, Lane, RequestBody};

/// Magic that opens every signed reply body. It differs from the request and acknowledgement magics.
pub const REPLY_MAGIC: [u8; 4] = *b"FFCR";
/// Version of the reply encoding. The additive AlreadySilent status uses tag 10,
/// and SequenceExhausted uses refusal code 17. Status 9 and refusal 16 remain
/// reserved: the original malformed-wire contract requires rejecting them.
/// Older decoders reject the new codes rather than misclassify their outcomes.
pub const REPLY_VERSION: u8 = 1;
/// Length of the request digest a reply is bound to.
pub const DIGEST_LEN: usize = 32;
/// The longest reply on the wire: the longest peer id, the widest status and a full tag.
pub const MAX_REPLY_LEN: usize =
    4 + 1 + 1 + MAX_PEER_ID_LEN + 8 + 8 + 8 + DIGEST_LEN + 18 + PROOF_LEN;

// ---------------------------------------------------------------------------------------------- codes

/// Which of a status code's two numbers a kind uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Not carried: it is zero on the wire.
    Unused,
    Number,
    /// A lane code, 0 (ordinary) or 1 (priority).
    Lane,
}

fn check_fields(fields: (Field, Field), a: u64, b: u64) -> Result<(), ReplyError> {
    for (value, field) in [(a, fields.0), (b, fields.1)] {
        if field == Field::Lane && value > 1 {
            return Err(ReplyError::BadLane { code: value });
        }
    }
    for (value, field) in [(a, fields.0), (b, fields.1)] {
        if field == Field::Unused && value != 0 {
            return Err(ReplyError::NonCanonical);
        }
    }
    Ok(())
}

const fn lane_code(lane: Lane) -> u8 {
    match lane {
        Lane::Ordinary => 0,
        Lane::Priority => 1,
    }
}

const fn lane_from_code(code: u64) -> Option<Lane> {
    match code {
        0 => Some(Lane::Ordinary),
        1 => Some(Lane::Priority),
        _ => None,
    }
}

/// Why an accepted command had no effect, as a reply says it. The numbers `a` and `b` of a
/// [`ReplyStatus::Refused`] are those named in [`RefusalKind::fields_doc`]; the rest are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    SequenceExhausted,
    StaleEpoch,
    EpochAhead,
    RevisionMismatch,
    StaleRevision,
    UnknownMember,
    Session,
    InternalFault,
    NoLease,
    Lease,
    AuthorityExpired,
    Expired,
    TooLateToCancel,
    NothingToCancel,
    TargetOutOfWindow,
    NotCancellable,
}

impl RefusalKind {
    pub(crate) const ALL: [Self; 16] = [
        Self::StaleEpoch,
        Self::EpochAhead,
        Self::RevisionMismatch,
        Self::StaleRevision,
        Self::UnknownMember,
        Self::Session,
        Self::InternalFault,
        Self::NoLease,
        Self::Lease,
        Self::AuthorityExpired,
        Self::Expired,
        Self::TooLateToCancel,
        Self::NothingToCancel,
        Self::TargetOutOfWindow,
        Self::NotCancellable,
        Self::SequenceExhausted,
    ];

    /// The code on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::StaleEpoch => 1,
            Self::EpochAhead => 2,
            Self::RevisionMismatch => 3,
            Self::StaleRevision => 4,
            Self::UnknownMember => 5,
            Self::Session => 6,
            Self::InternalFault => 7,
            Self::NoLease => 8,
            Self::Lease => 9,
            Self::AuthorityExpired => 10,
            Self::Expired => 11,
            Self::TooLateToCancel => 12,
            Self::NothingToCancel => 13,
            Self::TargetOutOfWindow => 14,
            Self::NotCancellable => 15,
            Self::SequenceExhausted => 17,
        }
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// The word for it: the same vocabulary as the diagnostic log's refusal kinds.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StaleEpoch => "stale_epoch",
            Self::EpochAhead => "epoch_ahead",
            Self::RevisionMismatch => "revision_mismatch",
            Self::StaleRevision => "stale_revision",
            Self::UnknownMember => "unknown_member",
            Self::Session => "session",
            Self::InternalFault => "internal_fault",
            Self::NoLease => "no_lease",
            Self::Lease => "lease",
            Self::AuthorityExpired => "authority_expired",
            Self::Expired => "expired",
            Self::TooLateToCancel => "too_late_to_cancel",
            Self::NothingToCancel => "nothing_to_cancel",
            Self::TargetOutOfWindow => "target_out_of_window",
            Self::NotCancellable => "not_cancellable",
            Self::SequenceExhausted => "sequence_exhausted",
        }
    }

    const fn fields(self) -> (Field, Field) {
        match self {
            Self::StaleEpoch | Self::EpochAhead | Self::RevisionMismatch | Self::StaleRevision => {
                (Field::Number, Field::Number)
            }
            Self::TargetOutOfWindow => (Field::Number, Field::Unused),
            Self::UnknownMember
            | Self::SequenceExhausted
            | Self::Session
            | Self::InternalFault
            | Self::NoLease
            | Self::Lease
            | Self::AuthorityExpired
            | Self::Expired
            | Self::TooLateToCancel
            | Self::NothingToCancel
            | Self::NotCancellable => (Field::Unused, Field::Unused),
        }
    }

    /// What the two numbers mean for this kind, for a person reading a reply.
    #[must_use]
    pub const fn fields_doc(self) -> &'static str {
        match self {
            Self::StaleEpoch | Self::EpochAhead => {
                "a: the epoch the request named, b: the session's epoch"
            }
            Self::RevisionMismatch => {
                "a: the revision the request named, b: the session's revision"
            }
            Self::StaleRevision => {
                "a: the revision the request named, b: the revision floor of this incarnation"
            }
            Self::TargetOutOfWindow => "a: the ledger floor",
            _ => "none",
        }
    }
}

/// Why a request was turned away after it authenticated and before it was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionKind {
    /// `a`: the epoch the key is bound to, `b`: the epoch the request named.
    EpochNotBound,
    RevisionRequired,
    /// `a`: the lane code (0 ordinary, 1 priority), `b`: nanoseconds to wait.
    RateLimited,
    /// `a`: the lane code.
    QueueFull,
    IdReuse,
}

impl RejectionKind {
    pub(crate) const ALL: [Self; 5] = [
        Self::EpochNotBound,
        Self::RevisionRequired,
        Self::RateLimited,
        Self::QueueFull,
        Self::IdReuse,
    ];

    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::EpochNotBound => 1,
            Self::RevisionRequired => 2,
            Self::RateLimited => 3,
            Self::QueueFull => 4,
            Self::IdReuse => 5,
        }
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EpochNotBound => "epoch_not_bound",
            Self::RevisionRequired => "revision_required",
            Self::RateLimited => "rate_limited",
            Self::QueueFull => "queue_full",
            Self::IdReuse => "id_reuse",
        }
    }

    const fn fields(self) -> (Field, Field) {
        match self {
            Self::EpochNotBound => (Field::Number, Field::Number),
            Self::RateLimited => (Field::Lane, Field::Number),
            Self::QueueFull => (Field::Lane, Field::Unused),
            Self::RevisionRequired | Self::IdReuse => (Field::Unused, Field::Unused),
        }
    }
}

/// What a reply says happened. There is no variant for an unauthenticated request: nothing is signed for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyStatus {
    /// Received and queued. **Not** committed.
    Queued { lane: Lane },
    /// A copy of this request is already waiting.
    AlreadyQueued { lane: Lane },
    /// Applied; `revision` is the session's state revision after it.
    Committed { revision: u64 },
    /// The requested local silence was already in effect; no new effect or fence was made.
    /// Older decoders reject this new status rather than treating it as committed.
    AlreadySilent { revision: u64 },
    /// Removed by a cancel before it was applied.
    Withdrawn,
    /// This command was a cancel, and it withdrew `target_seq`.
    CancelApplied { target_seq: u64 },
    /// Accepted, then refused with no effect.
    Refused { kind: RefusalKind, a: u64, b: u64 },
    /// The ledger no longer remembers this number: whether it was applied is unknown and it will not be now.
    OutOfWindow { floor: u64 },
    /// Turned away before it was accepted; its number is not consumed.
    Rejected { kind: RejectionKind, a: u64, b: u64 },
}

impl ReplyStatus {
    /// What a terminal outcome says. The match has no wildcard: a new outcome or refusal does not compile until
    /// it is given a status. `InternalFault` carries no detail, as the outcome does not show one to the sender.
    #[must_use]
    pub fn from_outcome(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::AlreadySilent { revision } => Self::AlreadySilent {
                revision: *revision,
            },
            Outcome::Committed { revision } => Self::Committed {
                revision: *revision,
            },
            Outcome::Withdrawn => Self::Withdrawn,
            Outcome::CancelApplied { target_seq } => Self::CancelApplied {
                target_seq: *target_seq,
            },
            Outcome::Refused(refusal) => Self::from_refusal(refusal),
        }
    }

    fn from_refusal(refusal: &Refusal) -> Self {
        let (kind, a, b) = match refusal {
            Refusal::SequenceExhausted => (RefusalKind::SequenceExhausted, 0, 0),
            Refusal::StaleEpoch { request, current } => {
                (RefusalKind::StaleEpoch, *request, *current)
            }
            Refusal::EpochAhead { request, current } => {
                (RefusalKind::EpochAhead, *request, *current)
            }
            Refusal::RevisionMismatch { expected, actual } => {
                (RefusalKind::RevisionMismatch, *expected, *actual)
            }
            Refusal::StaleRevision { observed, floor } => {
                (RefusalKind::StaleRevision, *observed, *floor)
            }
            Refusal::UnknownMember { .. } => (RefusalKind::UnknownMember, 0, 0),
            Refusal::Session(_) => (RefusalKind::Session, 0, 0),
            Refusal::InternalFault => (RefusalKind::InternalFault, 0, 0),
            Refusal::NoLease => (RefusalKind::NoLease, 0, 0),
            Refusal::Lease(_) => (RefusalKind::Lease, 0, 0),
            Refusal::AuthorityExpired => (RefusalKind::AuthorityExpired, 0, 0),
            Refusal::Expired => (RefusalKind::Expired, 0, 0),
            Refusal::TooLateToCancel => (RefusalKind::TooLateToCancel, 0, 0),
            Refusal::NothingToCancel => (RefusalKind::NothingToCancel, 0, 0),
            Refusal::TargetOutOfWindow { floor } => (RefusalKind::TargetOutOfWindow, *floor, 0),
            Refusal::NotCancellable => (RefusalKind::NotCancellable, 0, 0),
        };
        Self::Refused { kind, a, b }
    }

    /// What `submit` told the sender, as a status; `None` for a request that did not authenticate, which gets no reply.
    #[must_use]
    pub fn from_submit(result: &SubmitResult) -> Option<Self> {
        match result {
            SubmitResult::Queued { lane } => Some(Self::Queued { lane: *lane }),
            SubmitResult::AlreadyQueued { lane } => Some(Self::AlreadyQueued { lane: *lane }),
            SubmitResult::Settled(outcome) => Some(Self::from_outcome(outcome)),
            SubmitResult::OutOfWindow { floor } => Some(Self::OutOfWindow { floor: *floor }),
            SubmitResult::Rejected(rejection) => Self::from_rejection(rejection),
        }
    }

    fn from_rejection(rejection: &Rejection) -> Option<Self> {
        let (kind, a, b) = match rejection {
            Rejection::Unauthenticated(_) => return None,
            Rejection::EpochNotBound { bound, request } => {
                (RejectionKind::EpochNotBound, *bound, *request)
            }
            Rejection::RevisionRequired { .. } => (RejectionKind::RevisionRequired, 0, 0),
            Rejection::RateLimited {
                lane,
                retry_after_ns,
            } => (
                RejectionKind::RateLimited,
                u64::from(lane_code(*lane)),
                *retry_after_ns,
            ),
            Rejection::QueueFull { lane } => {
                (RejectionKind::QueueFull, u64::from(lane_code(*lane)), 0)
            }
            Rejection::IdReuse => (RejectionKind::IdReuse, 0, 0),
        };
        Some(Self::Rejected { kind, a, b })
    }

    /// Applied. Every other status is a statement that it was not, or not yet.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    fn validate(&self) -> Result<(), ReplyError> {
        match self {
            Self::Refused { kind, a, b } => check_fields(kind.fields(), *a, *b),
            Self::Rejected { kind, a, b } => check_fields(kind.fields(), *a, *b),
            _ => Ok(()),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::AlreadySilent { revision } => {
                out.push(10);
                out.extend_from_slice(&revision.to_be_bytes());
            }
            Self::Queued { lane } => {
                out.push(1);
                out.push(lane_code(*lane));
            }
            Self::AlreadyQueued { lane } => {
                out.push(2);
                out.push(lane_code(*lane));
            }
            Self::Committed { revision } => {
                out.push(3);
                out.extend_from_slice(&revision.to_be_bytes());
            }
            Self::Withdrawn => out.push(4),
            Self::CancelApplied { target_seq } => {
                out.push(5);
                out.extend_from_slice(&target_seq.to_be_bytes());
            }
            Self::Refused { kind, a, b } => {
                out.push(6);
                out.push(kind.code());
                out.extend_from_slice(&a.to_be_bytes());
                out.extend_from_slice(&b.to_be_bytes());
            }
            Self::OutOfWindow { floor } => {
                out.push(7);
                out.extend_from_slice(&floor.to_be_bytes());
            }
            Self::Rejected { kind, a, b } => {
                out.push(8);
                out.push(kind.code());
                out.extend_from_slice(&a.to_be_bytes());
                out.extend_from_slice(&b.to_be_bytes());
            }
        }
    }
}

// ------------------------------------------------------------------------------------------ errors

/// Why bytes are not a reply, or a reply could not be built. The stable name is [`ReplyError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    #[error("the reply ends before its fields do")]
    Truncated,
    #[error("bytes follow the tag")]
    TrailingBytes,
    #[error("not a reply: the magic is wrong")]
    BadMagic,
    #[error("reply version {version} is not understood")]
    BadVersion { version: u8 },
    #[error("invalid peer id: {0}")]
    InvalidPeer(PeerError),
    #[error("a command number must be at least 1")]
    ZeroSequence,
    #[error("unknown status tag {tag}")]
    UnknownStatus { tag: u8 },
    #[error("unknown code {code} for status tag {tag}")]
    UnknownKind { tag: u8, code: u8 },
    #[error("lane code {code} is neither 0 nor 1")]
    BadLane { code: u64 },
    #[error("a number the kind does not carry is not zero")]
    NonCanonical,
}

impl ReplyError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::TrailingBytes => "trailing_bytes",
            Self::BadMagic => "bad_magic",
            Self::BadVersion { .. } => "bad_version",
            Self::InvalidPeer(_) => "invalid_peer",
            Self::ZeroSequence => "zero_sequence",
            Self::UnknownStatus { .. } => "unknown_status",
            Self::UnknownKind { .. } => "unknown_kind",
            Self::BadLane { .. } => "bad_lane",
            Self::NonCanonical => "non_canonical",
        }
    }
}

// ------------------------------------------------------------------------------------ the reply

/// The SHA-256 of a request's signed bytes: what binds a reply to that request and no other.
#[must_use]
pub fn request_digest(request: &RequestBody) -> [u8; DIGEST_LEN] {
    let full = Sha256::digest(request.signing_bytes());
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&full[..DIGEST_LEN]);
    out
}

/// A reply without its tag: everything the tag covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyBody {
    peer: PeerId,
    seq: u64,
    epoch: u64,
    revision: u64,
    request: [u8; DIGEST_LEN],
    status: ReplyStatus,
}

impl ReplyBody {
    /// A command number of at least 1, and a status whose unused numbers are zero and whose lanes are 0 or 1.
    pub fn new(
        peer: PeerId,
        seq: u64,
        epoch: u64,
        revision: u64,
        request: [u8; DIGEST_LEN],
        status: ReplyStatus,
    ) -> Result<Self, ReplyError> {
        if seq == 0 {
            return Err(ReplyError::ZeroSequence);
        }
        status.validate()?;
        Ok(Self {
            peer,
            seq,
            epoch,
            revision,
            request,
            status,
        })
    }

    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }

    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The session's epoch when the reply was made.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The session's state revision when the reply was made.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn request(&self) -> &[u8; DIGEST_LEN] {
        &self.request
    }

    #[must_use]
    pub const fn status(&self) -> ReplyStatus {
        self.status
    }

    /// The bytes the tag covers: magic, version, peer (a length byte, then the id), `seq`, `epoch`, `revision`,
    /// the request digest and the status (a tag byte and its fields). All integers are big-endian.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_REPLY_LEN);
        out.extend_from_slice(&REPLY_MAGIC);
        out.push(REPLY_VERSION);
        out.push(u8::try_from(self.peer.as_str().len()).unwrap_or(u8::MAX));
        out.extend_from_slice(self.peer.as_str().as_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.request);
        self.status.encode(&mut out);
        out
    }
}

/// A reply as it travels: a body and the tag over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    body: ReplyBody,
    tag: AuthProof,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReplyError> {
        let end = self.pos.checked_add(n).ok_or(ReplyError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(ReplyError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ReplyError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, ReplyError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(raw))
    }
}

impl Reply {
    #[must_use]
    pub const fn new(body: ReplyBody, tag: AuthProof) -> Self {
        Self { body, tag }
    }

    #[must_use]
    pub const fn body(&self) -> &ReplyBody {
        &self.body
    }

    #[must_use]
    pub const fn tag(&self) -> &AuthProof {
        &self.tag
    }

    /// The wire form: the signed bytes, then the tag.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body.signing_bytes();
        out.extend_from_slice(self.tag.as_bytes());
        out
    }

    /// Parse the wire form. A reply that does not parse is refused before any tag is looked at; one that parses
    /// is still **not trusted**: only [`verify_reply`] says that.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplyError> {
        let mut cursor = Cursor { bytes, pos: 0 };
        if cursor.take(4)? != REPLY_MAGIC.as_slice() {
            return Err(ReplyError::BadMagic);
        }
        let version = cursor.u8()?;
        if version != REPLY_VERSION {
            return Err(ReplyError::BadVersion { version });
        }
        let len = usize::from(cursor.u8()?);
        let raw = cursor.take(len)?;
        let peer = std::str::from_utf8(raw)
            .map_err(|_| ReplyError::InvalidPeer(PeerError::InvalidPeerId { reason: "not text" }))
            .and_then(|text| PeerId::parse(text).map_err(ReplyError::InvalidPeer))?;
        let seq = cursor.u64()?;
        let epoch = cursor.u64()?;
        let revision = cursor.u64()?;
        if seq == 0 {
            return Err(ReplyError::ZeroSequence);
        }
        let mut request = [0u8; DIGEST_LEN];
        request.copy_from_slice(cursor.take(DIGEST_LEN)?);
        let status_tag = cursor.u8()?;
        let status = match status_tag {
            1 | 2 => {
                let code = u64::from(cursor.u8()?);
                let lane = lane_from_code(code).ok_or(ReplyError::BadLane { code })?;
                if status_tag == 1 {
                    ReplyStatus::Queued { lane }
                } else {
                    ReplyStatus::AlreadyQueued { lane }
                }
            }
            3 => ReplyStatus::Committed {
                revision: cursor.u64()?,
            },
            4 => ReplyStatus::Withdrawn,
            5 => ReplyStatus::CancelApplied {
                target_seq: cursor.u64()?,
            },
            6 => {
                let code = cursor.u8()?;
                let kind = RefusalKind::from_code(code).ok_or(ReplyError::UnknownKind {
                    tag: status_tag,
                    code,
                })?;
                let (a, b) = (cursor.u64()?, cursor.u64()?);
                check_fields(kind.fields(), a, b)?;
                ReplyStatus::Refused { kind, a, b }
            }
            7 => ReplyStatus::OutOfWindow {
                floor: cursor.u64()?,
            },
            8 => {
                let code = cursor.u8()?;
                let kind = RejectionKind::from_code(code).ok_or(ReplyError::UnknownKind {
                    tag: status_tag,
                    code,
                })?;
                let (a, b) = (cursor.u64()?, cursor.u64()?);
                check_fields(kind.fields(), a, b)?;
                ReplyStatus::Rejected { kind, a, b }
            }
            10 => ReplyStatus::AlreadySilent {
                revision: cursor.u64()?,
            },
            tag => return Err(ReplyError::UnknownStatus { tag }),
        };
        let raw_tag = cursor.take(PROOF_LEN)?;
        if cursor.pos != bytes.len() {
            return Err(ReplyError::TrailingBytes);
        }
        // A tag of exactly PROOF_LEN bytes is always a valid proof length.
        let tag = AuthProof::new(raw_tag.to_vec()).map_err(|_| ReplyError::Truncated)?;
        Ok(Self {
            body: ReplyBody {
                peer,
                seq,
                epoch,
                revision,
                request,
                status,
            },
            tag,
        })
    }
}

// ----------------------------------------------------------------------------- the channel side

impl<A: PeerAuthority + ReplySigner> ControlChannel<A> {
    /// The reply to `request` saying `status`, made under the session's epoch and revision now and signed for the
    /// request's peer. `None` if that peer cannot be signed for: it is not admitted now (revoked, or unknown).
    #[must_use]
    pub fn reply(
        &self,
        request: &RequestBody,
        session: &UnifiedGroupSession,
        status: ReplyStatus,
    ) -> Option<Reply> {
        let body = ReplyBody::new(
            request.peer().clone(),
            request.seq(),
            session.current_epoch,
            session.state_revision,
            request_digest(request),
            status,
        )
        .ok()?;
        let tag = self
            .authority()
            .sign_reply(body.peer(), &body.signing_bytes())?;
        Some(Reply { body, tag })
    }

    /// The reply to what `submit` returned for `request`. **No reply for a request that did not authenticate**: it
    /// has no key to sign under, and a signed refusal would be an oracle for anyone.
    #[must_use]
    pub fn reply_to_submit(
        &self,
        request: &ControlRequest,
        result: &SubmitResult,
        session: &UnifiedGroupSession,
    ) -> Option<Reply> {
        let status = ReplyStatus::from_submit(result)?;
        self.reply(request.body(), session, status)
    }

    /// The reply to a terminal outcome `step` settled for `request`.
    #[must_use]
    pub fn reply_to_outcome(
        &self,
        request: &RequestBody,
        outcome: &Outcome,
        session: &UnifiedGroupSession,
    ) -> Option<Reply> {
        self.reply(request, session, ReplyStatus::from_outcome(outcome))
    }
}

// ----------------------------------------------------------------------------- the client side

/// The newest state a client has seen, from the replies it has verified. A reply made at an earlier
/// `(epoch, revision)` is a replay of something older.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Freshness {
    pub epoch: u64,
    pub revision: u64,
}

/// What a client expects of the reply to the request it sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyExpectation {
    peer: PeerId,
    seq: u64,
    request: [u8; DIGEST_LEN],
    seen: Freshness,
}

impl ReplyExpectation {
    #[must_use]
    pub const fn new(peer: PeerId, seq: u64, request: [u8; DIGEST_LEN], seen: Freshness) -> Self {
        Self {
            peer,
            seq,
            request,
            seen,
        }
    }

    /// The expectation for the reply to `body`, given what the client has already seen.
    #[must_use]
    pub fn for_request(body: &RequestBody, seen: Freshness) -> Self {
        Self::new(body.peer().clone(), body.seq(), request_digest(body), seen)
    }
}

/// Why a reply that parses is not accepted. The stable name is [`ReplyRejection::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyRejection {
    #[error("the tag does not match: this reply was not made by a holder of the peer's key")]
    BadTag,
    #[error("the reply answers another command")]
    WrongCommand,
    #[error("the reply answers a different request under the same number")]
    WrongRequest,
    #[error("the reply is older than one the client has already seen")]
    Stale,
}

impl ReplyRejection {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadTag => "bad_tag",
            Self::WrongCommand => "wrong_command",
            Self::WrongRequest => "wrong_request",
            Self::Stale => "stale",
        }
    }
}

/// Why wire bytes are not an accepted reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(ReplyError),
    Rejected(ReplyRejection),
}

/// A reply that passed every check. It can only be made by [`verify_reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReply {
    body: ReplyBody,
}

impl VerifiedReply {
    #[must_use]
    pub const fn status(&self) -> ReplyStatus {
        self.body.status
    }

    #[must_use]
    pub const fn body(&self) -> &ReplyBody {
        &self.body
    }

    /// What the client has now seen: carry it into the next [`ReplyExpectation`].
    #[must_use]
    pub const fn freshness(&self) -> Freshness {
        Freshness {
            epoch: self.body.epoch,
            revision: self.body.revision,
        }
    }
}

/// The client's check of a reply, with the key it holds. Authenticity first, then the command, then the
/// request, then freshness; see the module documentation.
pub fn verify_reply(
    key: &[u8],
    expected: &ReplyExpectation,
    reply: &Reply,
) -> Result<VerifiedReply, ReplyRejection> {
    let body = reply.body();
    if !reply_tag_matches(key, &body.signing_bytes(), reply.tag().as_bytes()) {
        return Err(ReplyRejection::BadTag);
    }
    if body.peer != expected.peer || body.seq != expected.seq {
        return Err(ReplyRejection::WrongCommand);
    }
    if body.request != expected.request {
        return Err(ReplyRejection::WrongRequest);
    }
    if (body.epoch, body.revision) < (expected.seen.epoch, expected.seen.revision) {
        return Err(ReplyRejection::Stale);
    }
    Ok(VerifiedReply { body: body.clone() })
}

/// [`verify_reply`] on the bytes as they arrived.
pub fn verify_wire(
    key: &[u8],
    expected: &ReplyExpectation,
    bytes: &[u8],
) -> Result<VerifiedReply, VerifyError> {
    let reply = Reply::from_bytes(bytes).map_err(VerifyError::Malformed)?;
    verify_reply(key, expected, &reply).map_err(VerifyError::Rejected)
}

#[cfg(test)]
mod tests {
    use franken_session::{AuthorityToken, MembershipError, SessionError};
    use serde_json::Value;

    use super::*;
    use crate::channel::diag::refusal_kind;
    use crate::channel::limiter::RateLimit;
    use crate::channel::peer::ephemeral::{EphemeralPeers, test_key};
    use crate::channel::peer::{AuthFailure, PeerRole, compute_proof, compute_reply_tag};
    use crate::channel::pipeline::{ChannelConfig, Rejection};
    use crate::channel::request::{ControlCommand, RequestBody};
    use crate::channel::testkit::fixture_session;

    const VECTORS_JSON: &str = include_str!("../../tests/vectors/n02_reply_vectors.json");
    const EPOCH: u64 = 10;
    const MS: u64 = 1_000_000;

    fn vectors() -> Value {
        serde_json::from_str(VECTORS_JSON).expect("the reply vectors are valid JSON")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    fn digest(text: &str) -> [u8; DIGEST_LEN] {
        let mut out = [0u8; DIGEST_LEN];
        out.copy_from_slice(&unhex(text));
        out
    }

    fn lane_of(name: &Value) -> Lane {
        match name.as_str() {
            Some("ordinary") => Lane::Ordinary,
            Some("priority") => Lane::Priority,
            other => panic!("lane {other:?}"),
        }
    }

    fn status_from(v: &Value) -> ReplyStatus {
        let num = |key: &str| v[key].as_u64().expect("a number");
        let name = || v["code"].as_str().expect("a code name");
        match v["kind"].as_str().expect("a status kind") {
            "queued" => ReplyStatus::Queued {
                lane: lane_of(&v["lane"]),
            },
            "already_queued" => ReplyStatus::AlreadyQueued {
                lane: lane_of(&v["lane"]),
            },
            "committed" => ReplyStatus::Committed {
                revision: num("revision"),
            },
            "withdrawn" => ReplyStatus::Withdrawn,
            "cancel_applied" => ReplyStatus::CancelApplied {
                target_seq: num("target_seq"),
            },
            "out_of_window" => ReplyStatus::OutOfWindow {
                floor: num("floor"),
            },
            "refused" => ReplyStatus::Refused {
                kind: RefusalKind::ALL
                    .into_iter()
                    .find(|k| k.name() == name())
                    .expect("a known refusal code"),
                a: num("a"),
                b: num("b"),
            },
            "rejected" => ReplyStatus::Rejected {
                kind: RejectionKind::ALL
                    .into_iter()
                    .find(|k| k.name() == name())
                    .expect("a known rejection code"),
                a: num("a"),
                b: num("b"),
            },
            other => panic!("status kind {other}"),
        }
    }

    fn body_of(v: &Value) -> ReplyBody {
        ReplyBody::new(
            id(v["peer"].as_str().unwrap()),
            v["seq"].as_u64().unwrap(),
            v["epoch"].as_u64().unwrap(),
            v["revision"].as_u64().unwrap(),
            digest(v["request_digest_hex"].as_str().unwrap()),
            status_from(&v["status"]),
        )
        .expect("a vector reply is well formed")
    }

    fn expectation_of(v: &Value) -> ReplyExpectation {
        let e = &v["expect"];
        ReplyExpectation::new(
            id(e["peer"].as_str().unwrap()),
            e["seq"].as_u64().unwrap(),
            digest(e["request_digest_hex"].as_str().unwrap()),
            Freshness {
                epoch: e["seen_epoch"].as_u64().unwrap(),
                revision: e["seen_revision"].as_u64().unwrap(),
            },
        )
    }

    fn reply_vector(id: &str) -> Value {
        vectors()["replies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no reply vector {id}"))
            .clone()
    }

    // ------------------------------------------------------------------ the independent vectors

    #[test]
    fn the_encoding_and_the_tag_equal_the_independent_vectors() {
        let doc = vectors();
        let mut longest = 0;
        for v in doc["replies"].as_array().unwrap() {
            let body = body_of(v);
            let signing = body.signing_bytes();
            assert_eq!(hex(&signing), v["signing_hex"], "{} signed bytes", v["id"]);
            let key = v["key"].as_str().unwrap().as_bytes();
            let tag = compute_reply_tag(key, &signing);
            assert_eq!(hex(tag.as_bytes()), v["tag_hex"], "{} tag", v["id"]);
            let reply = Reply::new(body, tag);
            let wire = reply.to_bytes();
            assert_eq!(hex(&wire), v["wire_hex"], "{} wire", v["id"]);
            assert_eq!(
                Reply::from_bytes(&wire),
                Ok(reply.clone()),
                "{} decodes",
                v["id"]
            );
            let expect = ReplyExpectation::new(
                reply.body().peer().clone(),
                reply.body().seq(),
                *reply.body().request(),
                Freshness::default(),
            );
            let verified =
                verify_wire(key, &expect, &wire).unwrap_or_else(|e| panic!("{}: {e:?}", v["id"]));
            assert_eq!(verified.status(), reply.body().status(), "{}", v["id"]);
            longest = longest.max(wire.len());
        }
        assert_eq!(
            longest, MAX_REPLY_LEN,
            "the longest vector is the stated bound"
        );
        assert_eq!(
            doc["max_reply_len"].as_u64().unwrap(),
            u64::try_from(MAX_REPLY_LEN).unwrap()
        );
    }

    #[test]
    fn a_reply_assembled_by_hand_has_the_bytes_a_person_wrote() {
        // R001, written out from the layout: magic, version, peer, seq 7, epoch 3, revision 13, the literal
        // digest 00..1f, status tag 3 (committed) and revision 13.
        let by_hand = "4646435201\
                       0563746c2d61\
                       0000000000000007\
                       0000000000000003\
                       000000000000000d\
                       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                       03\
                       000000000000000d";
        let body = ReplyBody::new(
            id("ctl-a"),
            7,
            3,
            13,
            digest("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            ReplyStatus::Committed { revision: 13 },
        )
        .unwrap();
        assert_eq!(hex(&body.signing_bytes()), by_hand);
    }

    #[test]
    fn every_tampered_reply_is_refused_as_a_bad_tag_under_the_original_tag() {
        let doc = vectors();
        for t in doc["tampers"].as_array().unwrap() {
            let base = reply_vector(t["reply"].as_str().unwrap());
            let key = base["key"].as_str().unwrap().as_bytes();
            let expect = ReplyExpectation::new(
                id(base["peer"].as_str().unwrap()),
                base["seq"].as_u64().unwrap(),
                digest(base["request_digest_hex"].as_str().unwrap()),
                Freshness::default(),
            );
            // The green baseline: the base reply is accepted, so a refusal below is the tamper and not the setup.
            assert!(
                verify_wire(key, &expect, &unhex(base["wire_hex"].as_str().unwrap())).is_ok(),
                "{} base",
                t["id"]
            );
            let verdict = verify_wire(key, &expect, &unhex(t["wire_hex"].as_str().unwrap()));
            assert_eq!(
                verdict,
                Err(VerifyError::Rejected(ReplyRejection::BadTag)),
                "{} ({}) was not refused as a bad tag",
                t["id"],
                t["field"]
            );
        }
    }

    #[test]
    fn silence_extensions_use_fresh_wire_codes_and_preserve_reserved_rejections() {
        let mut encoded = Vec::new();
        ReplyStatus::AlreadySilent { revision: 13 }.encode(&mut encoded);
        assert_eq!(encoded, vec![10, 0, 0, 0, 0, 0, 0, 0, 13]);
        assert_eq!(RefusalKind::SequenceExhausted.code(), 17);
        assert!(RefusalKind::from_code(16).is_none());
        // Preserve the original corpus, rather than relabeling formerly
        // malformed messages as successful silence or exhaustion outcomes.
        let doc = vectors();
        for (id, expected) in [("M016", "unknown_status"), ("M019", "unknown_kind")] {
            let case = doc["malformed"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["id"] == id)
                .unwrap();
            let wire = unhex(case["wire_hex"].as_str().unwrap());
            let error = Reply::from_bytes(&wire).expect_err("reserved wire code decoded");
            assert_eq!(error.code(), expected, "{id}");
        }
    }

    #[test]
    fn malformed_input_fails_to_decode_with_the_named_error() {
        let doc = vectors();
        for v in doc["replies"].as_array().unwrap() {
            assert!(
                Reply::from_bytes(&unhex(v["wire_hex"].as_str().unwrap())).is_ok(),
                "{}",
                v["id"]
            );
        }
        for m in doc["malformed"].as_array().unwrap() {
            let wire = unhex(m["wire_hex"].as_str().unwrap());
            let got = Reply::from_bytes(&wire).expect_err(&format!("{} decoded", m["id"]));
            assert_eq!(got.code(), m["error"], "{} ({})", m["id"], m["what"]);
        }
    }

    #[test]
    fn the_verification_cases_are_judged_as_written() {
        let doc = vectors();
        for v in doc["verify"].as_array().unwrap() {
            let key = v["key"].as_str().unwrap().as_bytes();
            let got = match verify_wire(
                key,
                &expectation_of(v),
                &unhex(v["wire_hex"].as_str().unwrap()),
            ) {
                Ok(_) => "accepted",
                Err(VerifyError::Rejected(r)) => r.code(),
                Err(VerifyError::Malformed(e)) => panic!("{} did not decode: {e}", v["id"]),
            };
            assert_eq!(got, v["result"], "{} ({})", v["id"], v["what"]);
        }
    }

    // ------------------------------------------------------------------ the codes and the mapping

    #[test]
    fn the_context_of_a_reply_is_not_the_context_of_a_request() {
        let key = test_key("ctl-a");
        let message = b"the same signed bytes";
        assert_ne!(
            compute_reply_tag(&key, message).as_bytes(),
            compute_proof(&key, message).as_bytes()
        );
        assert!(reply_tag_matches(
            &key,
            message,
            compute_reply_tag(&key, message).as_bytes()
        ));
        assert!(!reply_tag_matches(
            &key,
            message,
            compute_proof(&key, message).as_bytes()
        ));
        assert!(!reply_tag_matches(&key, message, &[0u8; 32]));
        assert!(!reply_tag_matches(
            &key,
            message,
            &compute_reply_tag(&key, message).as_bytes()[..31]
        ));
    }

    fn every_refusal() -> Vec<(Refusal, ReplyStatus)> {
        let refused = |kind, a, b| ReplyStatus::Refused { kind, a, b };
        vec![
            (
                Refusal::SequenceExhausted,
                refused(RefusalKind::SequenceExhausted, 0, 0),
            ),
            (
                Refusal::StaleEpoch {
                    request: 3,
                    current: 4,
                },
                refused(RefusalKind::StaleEpoch, 3, 4),
            ),
            (
                Refusal::EpochAhead {
                    request: 6,
                    current: 5,
                },
                refused(RefusalKind::EpochAhead, 6, 5),
            ),
            (
                Refusal::RevisionMismatch {
                    expected: 5,
                    actual: 9,
                },
                refused(RefusalKind::RevisionMismatch, 5, 9),
            ),
            (
                Refusal::StaleRevision {
                    observed: 4,
                    floor: 7,
                },
                refused(RefusalKind::StaleRevision, 4, 7),
            ),
            (
                Refusal::UnknownMember {
                    member_id: "kitchen".to_string(),
                },
                refused(RefusalKind::UnknownMember, 0, 0),
            ),
            (
                Refusal::Session(SessionError::UnknownMember {
                    member_id: "den".to_string(),
                }),
                refused(RefusalKind::Session, 0, 0),
            ),
            (
                Refusal::InternalFault,
                refused(RefusalKind::InternalFault, 0, 0),
            ),
            (Refusal::NoLease, refused(RefusalKind::NoLease, 0, 0)),
            (
                Refusal::Lease(MembershipError::WrongGroup),
                refused(RefusalKind::Lease, 0, 0),
            ),
            (
                Refusal::AuthorityExpired,
                refused(RefusalKind::AuthorityExpired, 0, 0),
            ),
            (Refusal::Expired, refused(RefusalKind::Expired, 0, 0)),
            (
                Refusal::TooLateToCancel,
                refused(RefusalKind::TooLateToCancel, 0, 0),
            ),
            (
                Refusal::NothingToCancel,
                refused(RefusalKind::NothingToCancel, 0, 0),
            ),
            (
                Refusal::TargetOutOfWindow { floor: 12 },
                refused(RefusalKind::TargetOutOfWindow, 12, 0),
            ),
            (
                Refusal::NotCancellable,
                refused(RefusalKind::NotCancellable, 0, 0),
            ),
        ]
    }

    #[test]
    fn every_outcome_refusal_rejection_and_submit_result_has_one_status() {
        let refusals = every_refusal();
        assert_eq!(
            refusals.len(),
            RefusalKind::ALL.len(),
            "a refusal kind per refusal"
        );
        for (refusal, want) in &refusals {
            assert_eq!(
                ReplyStatus::from_outcome(&Outcome::Refused(refusal.clone())),
                *want
            );
            // One vocabulary with the diagnostic log.
            let ReplyStatus::Refused { kind, .. } = want else {
                panic!("not a refusal")
            };
            assert_eq!(kind.name(), refusal_kind(refusal));
        }
        let codes: Vec<u8> = RefusalKind::ALL.iter().map(|k| k.code()).collect();
        assert_eq!(
            codes,
            (1..=15).chain(std::iter::once(17)).collect::<Vec<u8>>(),
            "original codes 1 to 15 stay stable; 16 stays reserved; exhaustion uses 17"
        );
        assert!(RefusalKind::from_code(0).is_none() && RefusalKind::from_code(16).is_none());
        assert!(RefusalKind::from_code(18).is_none());
        assert!(RejectionKind::from_code(0).is_none() && RejectionKind::from_code(6).is_none());

        assert_eq!(
            ReplyStatus::from_outcome(&Outcome::AlreadySilent { revision: 9 }),
            ReplyStatus::AlreadySilent { revision: 9 }
        );
        assert!(!ReplyStatus::AlreadySilent { revision: 9 }.is_committed());
        assert_eq!(
            ReplyStatus::from_outcome(&Outcome::Committed { revision: 9 }),
            ReplyStatus::Committed { revision: 9 }
        );
        assert_eq!(
            ReplyStatus::from_outcome(&Outcome::Withdrawn),
            ReplyStatus::Withdrawn
        );
        assert_eq!(
            ReplyStatus::from_outcome(&Outcome::CancelApplied { target_seq: 4 }),
            ReplyStatus::CancelApplied { target_seq: 4 }
        );

        let rejected = |kind, a, b| Some(ReplyStatus::Rejected { kind, a, b });
        for (result, want) in [
            (
                SubmitResult::Queued {
                    lane: Lane::Ordinary,
                },
                Some(ReplyStatus::Queued {
                    lane: Lane::Ordinary,
                }),
            ),
            (
                SubmitResult::AlreadyQueued {
                    lane: Lane::Priority,
                },
                Some(ReplyStatus::AlreadyQueued {
                    lane: Lane::Priority,
                }),
            ),
            (
                SubmitResult::Settled(Outcome::Committed { revision: 3 }),
                Some(ReplyStatus::Committed { revision: 3 }),
            ),
            (
                SubmitResult::OutOfWindow { floor: 250 },
                Some(ReplyStatus::OutOfWindow { floor: 250 }),
            ),
            (
                SubmitResult::Rejected(Rejection::EpochNotBound {
                    bound: 10,
                    request: 9,
                }),
                rejected(RejectionKind::EpochNotBound, 10, 9),
            ),
            (
                SubmitResult::Rejected(Rejection::RevisionRequired {
                    command: "set_group_volume",
                }),
                rejected(RejectionKind::RevisionRequired, 0, 0),
            ),
            (
                SubmitResult::Rejected(Rejection::RateLimited {
                    lane: Lane::Priority,
                    retry_after_ns: 1_500_000,
                }),
                rejected(RejectionKind::RateLimited, 1, 1_500_000),
            ),
            (
                SubmitResult::Rejected(Rejection::QueueFull {
                    lane: Lane::Ordinary,
                }),
                rejected(RejectionKind::QueueFull, 0, 0),
            ),
            (
                SubmitResult::Rejected(Rejection::IdReuse),
                rejected(RejectionKind::IdReuse, 0, 0),
            ),
            // A request that did not authenticate gets no status at all.
            (
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof)),
                None,
            ),
            (
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer)),
                None,
            ),
            (
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked)),
                None,
            ),
        ] {
            assert_eq!(ReplyStatus::from_submit(&result), want, "{result:?}");
        }
    }

    #[test]
    fn every_status_survives_an_encode_decode_round_trip() {
        let mut statuses: Vec<ReplyStatus> = every_refusal().into_iter().map(|(_, s)| s).collect();
        statuses.extend([
            ReplyStatus::Queued {
                lane: Lane::Ordinary,
            },
            ReplyStatus::AlreadyQueued {
                lane: Lane::Priority,
            },
            ReplyStatus::Committed { revision: u64::MAX },
            ReplyStatus::AlreadySilent { revision: u64::MAX },
            ReplyStatus::Withdrawn,
            ReplyStatus::CancelApplied { target_seq: 298 },
            ReplyStatus::OutOfWindow { floor: 250 },
        ]);
        for kind in RejectionKind::ALL {
            let (a, b) = match kind {
                RejectionKind::EpochNotBound => (10, 9),
                RejectionKind::RateLimited => (1, 1_500_000),
                RejectionKind::QueueFull => (1, 0),
                RejectionKind::RevisionRequired | RejectionKind::IdReuse => (0, 0),
            };
            statuses.push(ReplyStatus::Rejected { kind, a, b });
        }
        for status in statuses {
            let body = ReplyBody::new(id("ctl-a"), 7, EPOCH, 13, [9; DIGEST_LEN], status).unwrap();
            let reply = Reply::new(
                body.clone(),
                compute_reply_tag(&test_key("ctl-a"), &body.signing_bytes()),
            );
            assert_eq!(
                Reply::from_bytes(&reply.to_bytes()),
                Ok(reply),
                "{status:?}"
            );
        }
    }

    #[test]
    fn a_status_a_decoder_would_refuse_cannot_be_built() {
        let build =
            |seq, status| ReplyBody::new(id("ctl-a"), seq, EPOCH, 1, [0; DIGEST_LEN], status);
        assert_eq!(
            build(0, ReplyStatus::Withdrawn),
            Err(ReplyError::ZeroSequence)
        );
        assert_eq!(
            build(
                1,
                ReplyStatus::Refused {
                    kind: RefusalKind::NoLease,
                    a: 1,
                    b: 0
                }
            ),
            Err(ReplyError::NonCanonical)
        );
        assert_eq!(
            build(
                1,
                ReplyStatus::Rejected {
                    kind: RejectionKind::QueueFull,
                    a: 0,
                    b: 5
                }
            ),
            Err(ReplyError::NonCanonical)
        );
        assert_eq!(
            build(
                1,
                ReplyStatus::Rejected {
                    kind: RejectionKind::RateLimited,
                    a: 2,
                    b: 5
                }
            ),
            Err(ReplyError::BadLane { code: 2 })
        );
        assert!(
            build(
                1,
                ReplyStatus::Rejected {
                    kind: RejectionKind::RateLimited,
                    a: 1,
                    b: 5
                }
            )
            .is_ok()
        );
    }

    // ------------------------------------------------------------------ the channel and a client

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
    }

    fn rig() -> Rig {
        let mut peers = EphemeralPeers::new();
        for (name, role, bound) in [
            ("ctl-a", PeerRole::Controller, Some(EPOCH)),
            ("panel", PeerRole::LocalUser, None),
        ] {
            peers
                .admit(&id(name), role, &test_key(name), bound, 1)
                .unwrap();
        }
        let session = fixture_session(EPOCH);
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        config.priority_rate = RateLimit::new(100_000, MS).unwrap();
        config.session_seq_base = 1_000;
        let mut channel = ControlChannel::new(peers, config).unwrap();
        let token = AuthorityToken::issue(&session, 100_000 * MS);
        channel.install_lease(&session, token, 0).unwrap();
        Rig { channel, session }
    }

    fn request(
        peer: &str,
        seq: u64,
        revision: Option<u64>,
        command: ControlCommand,
    ) -> ControlRequest {
        let body = RequestBody::new(id(peer), seq, EPOCH, revision, command).unwrap();
        let proof = compute_proof(&test_key(peer), &body.signing_bytes());
        ControlRequest::new(body, proof)
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    #[test]
    fn a_retrying_client_sees_one_transition_and_every_forgery_and_replay_is_refused_by_name() {
        let mut rig = rig();
        let key = test_key("ctl-a");
        let req = request("ctl-a", 1, Some(rig.session.state_revision), set_group(70));
        let fresh = |seen| ReplyExpectation::for_request(req.body(), seen);

        // 1. Queued: a genuine reply is accepted, and it says accepted, not committed.
        let queued = rig.channel.submit(0, req.clone());
        let r_queued = rig
            .channel
            .reply_to_submit(&req, &queued, &rig.session)
            .expect("an authenticated request is answered");
        let v_queued = verify_reply(&key, &fresh(Freshness::default()), &r_queued).unwrap();
        assert_eq!(
            v_queued.status(),
            ReplyStatus::Queued {
                lane: Lane::Ordinary
            }
        );
        assert!(!v_queued.status().is_committed());
        assert_eq!(
            v_queued.freshness(),
            Freshness {
                epoch: EPOCH,
                revision: 2
            }
        );

        // 2. Three forgeries of "refused: expired" by someone without the key. A reply that merely parses is not trusted.
        let lie = ReplyBody::new(
            id("ctl-a"),
            1,
            EPOCH,
            2,
            request_digest(req.body()),
            ReplyStatus::Refused {
                kind: RefusalKind::Expired,
                a: 0,
                b: 0,
            },
        )
        .unwrap();
        let signing = lie.signing_bytes();
        let forged = [
            ("an all-zero tag", AuthProof::new(vec![0u8; 32]).unwrap()),
            (
                "a tag made under the request context",
                compute_proof(&key, &signing),
            ),
            (
                "the request's own proof, which was on the wire",
                req.proof().clone(),
            ),
        ];
        for (how, tag) in forged {
            let reply = Reply::new(lie.clone(), tag);
            assert!(
                Reply::from_bytes(&reply.to_bytes())
                    .is_ok_and(|r| !r.body().status().is_committed()),
                "{how} parses, so decoding alone proves nothing"
            );
            assert_eq!(
                verify_reply(&key, &fresh(Freshness::default()), &reply),
                Err(ReplyRejection::BadTag),
                "{how}"
            );
        }

        // 3. The step commits. The genuine committed reply never reaches the client.
        let settled = rig.channel.step(0, &mut rig.session);
        assert_eq!(settled.len(), 1);
        let dropped = rig
            .channel
            .reply_to_outcome(req.body(), &settled[0].outcome, &rig.session)
            .unwrap();

        // 4. The client asks again. The ledger answers with the recorded outcome and applies nothing twice.
        let again = rig.channel.submit(0, req.clone());
        assert_eq!(
            again,
            SubmitResult::Settled(Outcome::Committed { revision: 3 })
        );
        let r_again = rig
            .channel
            .reply_to_submit(&req, &again, &rig.session)
            .unwrap();
        let v_again = verify_reply(&key, &fresh(v_queued.freshness()), &r_again).unwrap();
        assert_eq!(v_again.status(), ReplyStatus::Committed { revision: 3 });
        assert_eq!(rig.session.state_revision, 3, "exactly one transition");
        assert_eq!(rig.session.group_master_volume, 70);
        // The reply that was dropped said the same thing.
        assert_eq!(
            verify_reply(&key, &fresh(Freshness::default()), &dropped)
                .unwrap()
                .status(),
            v_again.status()
        );

        // 5. Replays and misdirection, now that the client has seen revision 3.
        let seen = v_again.freshness();
        assert_eq!(
            verify_reply(&key, &fresh(seen), &r_queued),
            Err(ReplyRejection::Stale)
        );
        let next = request("ctl-a", 2, Some(3), set_group(71));
        assert_eq!(
            verify_reply(
                &key,
                &ReplyExpectation::for_request(next.body(), seen),
                &r_again
            ),
            Err(ReplyRejection::WrongCommand)
        );
        let reused = request("ctl-a", 1, Some(3), set_group(80));
        assert_eq!(
            verify_reply(
                &key,
                &ReplyExpectation::for_request(reused.body(), seen),
                &r_again
            ),
            Err(ReplyRejection::WrongRequest)
        );
    }

    #[test]
    fn an_unauthenticated_request_gets_no_reply_and_a_revoked_peer_cannot_be_signed_for() {
        let mut rig = rig();
        // A request with a proof made under another key does not authenticate: no reply, no oracle.
        let body = RequestBody::new(id("ctl-a"), 1, EPOCH, Some(2), set_group(70)).unwrap();
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(&test_key("panel"), &body.signing_bytes()),
        );
        let result = rig.channel.submit(0, forged.clone());
        assert!(matches!(
            result,
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        ));
        assert!(
            rig.channel
                .reply_to_submit(&forged, &result, &rig.session)
                .is_none()
        );
        let stranger = request("stranger", 1, Some(2), set_group(70));
        let result = rig.channel.submit(0, stranger.clone());
        assert!(matches!(
            result,
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer))
        ));
        assert!(
            rig.channel
                .reply_to_submit(&stranger, &result, &rig.session)
                .is_none()
        );

        // The paired positive: the genuine request is answered, and the peer can be signed for.
        let req = request("ctl-a", 1, Some(2), set_group(70));
        let queued = rig.channel.submit(0, req.clone());
        assert!(
            rig.channel
                .reply_to_submit(&req, &queued, &rig.session)
                .is_some()
        );
        assert!(
            rig.channel
                .authority()
                .sign_reply(&id("ctl-a"), b"x")
                .is_some()
        );

        // Revoked after the command was accepted: the step refuses it, and no reply can be signed for it.
        assert!(rig.channel.authority_mut().revoke(&id("ctl-a")));
        let settled = rig.channel.step(0, &mut rig.session);
        assert_eq!(
            settled[0].outcome,
            Outcome::Refused(Refusal::AuthorityExpired)
        );
        assert!(
            rig.channel
                .reply_to_outcome(req.body(), &settled[0].outcome, &rig.session)
                .is_none()
        );
        assert!(
            rig.channel
                .authority()
                .sign_reply(&id("ctl-a"), b"x")
                .is_none()
        );
    }

    #[test]
    fn a_reply_to_another_peer_does_not_verify_under_this_peers_key() {
        let mut rig = rig();
        let for_panel = request(
            "panel",
            1,
            None,
            ControlCommand::SetMemberMute {
                member_id: "kitchen".to_string(),
                muted: true,
            },
        );
        let queued = rig.channel.submit(0, for_panel.clone());
        let reply = rig
            .channel
            .reply_to_submit(&for_panel, &queued, &rig.session)
            .unwrap();
        let panel_expect = ReplyExpectation::for_request(for_panel.body(), Freshness::default());
        assert!(
            verify_reply(&test_key("panel"), &panel_expect, &reply).is_ok(),
            "the genuine reply verifies for its peer"
        );
        assert_eq!(
            verify_reply(&test_key("ctl-a"), &panel_expect, &reply),
            Err(ReplyRejection::BadTag),
            "a reply for the panel handed to a controller holding its own key"
        );
    }
}
