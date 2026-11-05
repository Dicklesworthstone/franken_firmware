//! Typed source-session contract (P01 / `ffw-h3g`, bead section 2, "Integration boundary").
//!
//! A source session says what is playing, from where, to which group, under whose lease. It carries
//! identities and a stream description and nothing that authenticates anyone: no token, no account
//! identifier. The only credential link is a [`SecretHandle`] naming a slot in the secret store.
//!
//! Identities are separate types so they cannot be swapped by accident: [`SessionId`] (ours),
//! [`EndpointId`] (the stable logical endpoint), [`GroupId`], [`TransportIdentity`] (what the wire
//! calls the peer), [`StreamEpoch`] (which stream generation) and [`LeaseTerm`] (which coordinator
//! term holds the group). The three label types accept only `a-z`, `0-9`, `.`, `_`, `-` and `:`, which
//! rules out e-mail addresses and pasted tokens by construction; that is a guard against slips, not a
//! proof that a label is not sensitive.
//!
//! Source failures fall into four categories that stay visible to the end: authentication, unsupported
//! media, network starvation and renderer failure. Each has its own small retry budget in a
//! [`RecoveryLedger`], and a category that has spent its budget is surfaced as such
//! ([`RecoveryDecision::Surface`]) instead of restarting every component forever. The budgets are
//! provisional policy, not measured values.
//!
//! A stale coordinator cannot act: every state change carries a [`LeaseTerm`], and a term older than
//! the group's current lease is refused with [`SourceSessionError::StaleLease`].
//!
//! [`EphemeralSourceSessions`] is an in-memory port for tests only.

#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;

use super::secret_store::{SecretHandle, SecretKind};

/// Longest label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;
/// Most sessions a port keeps at once.
pub const MAX_SESSIONS: usize = 8;
/// Sample rates a source may deliver, in hertz.
pub const SUPPORTED_RATES_HZ: [u32; 4] = [44_100, 48_000, 88_200, 96_000];

/// A session identifier minted by the port that owns the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Which generation of a stream a command or block belongs to. A newer epoch supersedes an older one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamEpoch(u64);

impl StreamEpoch {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The coordinator's term for a group. A larger term has acquired ownership from a smaller one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseTerm(u64);

impl LeaseTerm {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

fn validate_label(raw: &str, what: &'static str) -> Result<String, SourceSessionError> {
    if raw.is_empty() {
        return Err(SourceSessionError::InvalidLabel {
            what,
            reason: "empty",
        });
    }
    if raw.len() > MAX_LABEL_LEN {
        return Err(SourceSessionError::InvalidLabel {
            what,
            reason: "longer than the label limit",
        });
    }
    let alphabet_ok = raw.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b':')
    });
    if !alphabet_ok {
        return Err(SourceSessionError::InvalidLabel {
            what,
            reason: "only a-z, 0-9, '.', '_', '-' and ':' are allowed",
        });
    }
    Ok(raw.to_owned())
}

macro_rules! label_type {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap a label.
            pub fn parse(raw: &str) -> Result<Self, SourceSessionError> {
                validate_label(raw, $what).map(Self)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

label_type!(
    /// The stable logical endpoint a source plays to (a room, not a network address).
    EndpointId,
    "endpoint id"
);
label_type!(
    /// The group a session belongs to.
    GroupId,
    "group id"
);
label_type!(
    /// What the wire protocol calls the peer. Distinct from every service token and account id.
    TransportIdentity,
    "transport identity"
);

/// Kinds of audio source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    Spotify,
    AirPlay2,
    LineIn,
}

impl SourceKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Spotify => "spotify",
            Self::AirPlay2 => "airplay2",
            Self::LineIn => "line-in",
        }
    }

    /// The kind of secret this source authenticates with, or `None` for a source with no credential.
    #[must_use]
    pub const fn credential_kind(self) -> Option<SecretKind> {
        match self {
            Self::Spotify => Some(SecretKind::SpotifyRefreshToken),
            Self::AirPlay2 => Some(SecretKind::AirPlayPairingKey),
            Self::LineIn => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    S16Be,
    S24Be,
    F32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLayout {
    Mono,
    Stereo,
}

/// Where the samples came from, so a later stage cannot mistake a transcode for a bit-exact stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleOrigin {
    SourceDecoded,
    HostTranscoded,
    Passthrough,
}

/// How source media time maps to a presentation time. An unanchored stream makes no sync claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationMapping {
    Unanchored,
    Anchored {
        media_time_ns: u64,
        presentation_ns: u64,
    },
}

/// What a source delivers: format, rate, channel layout, sample origin and presentation mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDescriptor {
    pub format: SampleFormat,
    pub rate_hz: u32,
    pub channels: ChannelLayout,
    pub origin: SampleOrigin,
    pub presentation: PresentationMapping,
}

impl StreamDescriptor {
    /// Build a descriptor, refusing a rate outside [`SUPPORTED_RATES_HZ`].
    pub fn new(
        format: SampleFormat,
        rate_hz: u32,
        channels: ChannelLayout,
        origin: SampleOrigin,
        presentation: PresentationMapping,
    ) -> Result<Self, SourceSessionError> {
        if !SUPPORTED_RATES_HZ.contains(&rate_hz) {
            return Err(SourceSessionError::UnsupportedRate { rate_hz });
        }
        Ok(Self {
            format,
            rate_hz,
            channels,
            origin,
            presentation,
        })
    }
}

/// The four failure categories a source reports. They are never merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceErrorKind {
    Authentication,
    UnsupportedMedia,
    NetworkStarvation,
    RendererFailure,
}

impl SourceErrorKind {
    pub const ALL: [Self; 4] = [
        Self::Authentication,
        Self::UnsupportedMedia,
        Self::NetworkStarvation,
        Self::RendererFailure,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::UnsupportedMedia => "unsupported-media",
            Self::NetworkStarvation => "network-starvation",
            Self::RendererFailure => "renderer-failure",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Authentication => 0,
            Self::UnsupportedMedia => 1,
            Self::NetworkStarvation => 2,
            Self::RendererFailure => 3,
        }
    }

    /// Provisional policy: how many recovery attempts this category gets before it is surfaced.
    /// Authentication gets one (a bad credential does not improve by retrying), unsupported media none
    /// (the same media fails the same way), network starvation a few, and a renderer failure none
    /// (the source cannot repair the renderer; restarting the source would hide it).
    #[must_use]
    pub const fn default_retry_limit(self) -> u8 {
        match self {
            Self::Authentication => 1,
            Self::UnsupportedMedia | Self::RendererFailure => 0,
            Self::NetworkStarvation => 3,
        }
    }
}

/// What to do about one failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Try again; this is attempt `attempt` of `limit` for this category.
    Retry {
        kind: SourceErrorKind,
        attempt: u8,
        limit: u8,
    },
    /// The category's budget is spent: stop recovering and report it, with its category intact.
    Surface {
        kind: SourceErrorKind,
        attempts_used: u8,
    },
}

/// Per-category retry accounting. Each category is independent: spending one budget leaves the
/// others untouched, and a recovery resets only its own category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLedger {
    limits: [u8; 4],
    used: [u8; 4],
}

impl RecoveryLedger {
    /// A ledger with each category's [`SourceErrorKind::default_retry_limit`].
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits([
            SourceErrorKind::Authentication.default_retry_limit(),
            SourceErrorKind::UnsupportedMedia.default_retry_limit(),
            SourceErrorKind::NetworkStarvation.default_retry_limit(),
            SourceErrorKind::RendererFailure.default_retry_limit(),
        ])
    }

    /// A ledger with explicit limits, indexed in [`SourceErrorKind::ALL`] order.
    #[must_use]
    pub const fn with_limits(limits: [u8; 4]) -> Self {
        Self {
            limits,
            used: [0; 4],
        }
    }

    /// Record one failure of `kind` and decide what to do.
    pub fn record_failure(&mut self, kind: SourceErrorKind) -> RecoveryDecision {
        let i = kind.index();
        if self.used[i] < self.limits[i] {
            self.used[i] += 1;
            RecoveryDecision::Retry {
                kind,
                attempt: self.used[i],
                limit: self.limits[i],
            }
        } else {
            RecoveryDecision::Surface {
                kind,
                attempts_used: self.used[i],
            }
        }
    }

    /// The source recovered from `kind`: that category's budget is restored. Others are untouched.
    pub fn record_recovered(&mut self, kind: SourceErrorKind) {
        self.used[kind.index()] = 0;
    }

    #[must_use]
    pub const fn attempts_used(&self, kind: SourceErrorKind) -> u8 {
        self.used[kind.index()]
    }
}

impl Default for RecoveryLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle of a source session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Opening,
    Ready,
    Playing,
    Paused,
    /// Stopping or seeking: submitted output is draining or being flushed.
    Draining,
    Closed,
    /// A surfaced failure, with its category kept.
    Failed(SourceErrorKind),
}

impl SessionState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Ready => "ready",
            Self::Playing => "playing",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Failed(_) => "failed",
        }
    }
}

/// Whether a session may move from `from` to `to`. `Closed` is terminal, any other state may fail,
/// and a failed session can only close.
#[must_use]
pub fn transition_allowed(from: SessionState, to: SessionState) -> bool {
    use SessionState as S;
    match (from, to) {
        (S::Closed, _) | (S::Failed(_), S::Failed(_)) => false,
        (_, S::Failed(_)) => true,
        (S::Failed(_), S::Closed)
        | (S::Opening, S::Ready)
        | (S::Ready, S::Playing | S::Closed)
        | (S::Playing, S::Paused | S::Draining)
        | (S::Paused, S::Playing | S::Draining | S::Closed)
        | (S::Draining, S::Ready | S::Closed) => true,
        _ => false,
    }
}

/// Everything needed to open a session. The credential is a handle, never a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub kind: SourceKind,
    pub endpoint: EndpointId,
    pub group: GroupId,
    pub epoch: StreamEpoch,
    pub term: LeaseTerm,
    pub transport: TransportIdentity,
    pub descriptor: StreamDescriptor,
    pub credential: Option<SecretHandle>,
}

/// An open source session. It holds identities, a stream description and a credential *handle*; it
/// has no field that could hold a token or an account identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSession {
    id: SessionId,
    kind: SourceKind,
    endpoint: EndpointId,
    group: GroupId,
    epoch: StreamEpoch,
    term: LeaseTerm,
    transport: TransportIdentity,
    descriptor: StreamDescriptor,
    credential: Option<SecretHandle>,
    state: SessionState,
}

impl SourceSession {
    /// Validate `request` and build the session in [`SessionState::Opening`]. The credential must be
    /// present exactly when the source kind has one, and it must be of that kind.
    pub fn new(id: SessionId, request: OpenRequest) -> Result<Self, SourceSessionError> {
        match (request.kind.credential_kind(), &request.credential) {
            (Some(_), None) => {
                return Err(SourceSessionError::CredentialRequired {
                    kind: request.kind.label(),
                });
            }
            (None, Some(_)) => {
                return Err(SourceSessionError::UnexpectedCredential {
                    kind: request.kind.label(),
                });
            }
            (Some(expected), Some(handle)) if handle.kind() != expected => {
                return Err(SourceSessionError::CredentialKindMismatch {
                    kind: request.kind.label(),
                    expected: expected.label(),
                    actual: handle.kind().label(),
                });
            }
            _ => {}
        }
        Ok(Self {
            id,
            kind: request.kind,
            endpoint: request.endpoint,
            group: request.group,
            epoch: request.epoch,
            term: request.term,
            transport: request.transport,
            descriptor: request.descriptor,
            credential: request.credential,
            state: SessionState::Opening,
        })
    }

    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    #[must_use]
    pub const fn kind(&self) -> SourceKind {
        self.kind
    }

    #[must_use]
    pub const fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    #[must_use]
    pub const fn group(&self) -> &GroupId {
        &self.group
    }

    #[must_use]
    pub const fn epoch(&self) -> StreamEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn term(&self) -> LeaseTerm {
        self.term
    }

    #[must_use]
    pub const fn transport(&self) -> &TransportIdentity {
        &self.transport
    }

    #[must_use]
    pub const fn descriptor(&self) -> &StreamDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub const fn credential(&self) -> Option<&SecretHandle> {
        self.credential.as_ref()
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }
}

/// Why a source-session operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceSessionError {
    #[error("invalid {what}: {reason}")]
    InvalidLabel {
        what: &'static str,
        reason: &'static str,
    },
    #[error("sample rate {rate_hz} Hz is not supported")]
    UnsupportedRate { rate_hz: u32 },
    #[error("a `{kind}` source needs a credential handle and none was given")]
    CredentialRequired { kind: &'static str },
    #[error("a `{kind}` source has no credential, but one was given")]
    UnexpectedCredential { kind: &'static str },
    #[error("a `{kind}` source needs a `{expected}` credential, not `{actual}`")]
    CredentialKindMismatch {
        kind: &'static str,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("too many sessions open (limit {max})")]
    TooManySessions { max: usize },
    #[error("endpoint `{endpoint}` already has an open session in this group")]
    EndpointInUse { endpoint: EndpointId },
    #[error("no such session {id}")]
    UnknownSession { id: u64 },
    #[error("a session cannot go from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("stale lease term {term}: the group is at term {current}")]
    StaleLease { term: u64, current: u64 },
    #[error("lease term {term} has not been acquired: the group is at term {current}")]
    LeaseNotAcquired { term: u64, current: u64 },
    #[error("lease term {term} does not advance the group's current term {current}")]
    LeaseNotAdvancing { term: u64, current: u64 },
}

/// The port an adapter uses to manage its sessions.
pub trait SourceSessionPort {
    /// Validate and open a session. Opening claims the group's lease at the request's term if no
    /// newer term holds it; an older term is refused.
    fn open(&mut self, request: OpenRequest) -> Result<SessionId, SourceSessionError>;

    fn session(&self, id: SessionId) -> Result<&SourceSession, SourceSessionError>;

    /// Take over a group with a strictly newer term.
    fn acquire_lease(&mut self, group: &GroupId, term: LeaseTerm)
    -> Result<(), SourceSessionError>;

    /// Move a session to `to` under `term`. The term must be the group's current one; the session
    /// adopts it, which is how ownership passes to a newer coordinator.
    fn transition(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        to: SessionState,
    ) -> Result<(), SourceSessionError>;

    /// Record a source failure. When the category's budget is spent the session becomes
    /// [`SessionState::Failed`] with that category.
    fn report_error(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        kind: SourceErrorKind,
    ) -> Result<RecoveryDecision, SourceSessionError>;

    /// Record that a category recovered, restoring only that category's budget.
    fn report_recovered(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        kind: SourceErrorKind,
    ) -> Result<(), SourceSessionError>;
}

#[cfg(test)]
struct Tracked {
    session: SourceSession,
    ledger: RecoveryLedger,
}

/// In-memory port for tests. Closed sessions are removed, which frees their slot and endpoint.
#[cfg(test)]
pub struct EphemeralSourceSessions {
    sessions: BTreeMap<SessionId, Tracked>,
    leases: BTreeMap<GroupId, LeaseTerm>,
    next_id: u64,
    max_sessions: usize,
}

#[cfg(test)]
impl EphemeralSourceSessions {
    #[must_use]
    pub fn with_capacity(max_sessions: usize) -> Self {
        Self {
            sessions: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_id: 1,
            max_sessions: max_sessions.min(MAX_SESSIONS),
        }
    }

    fn check_term(&self, group: &GroupId, term: LeaseTerm) -> Result<(), SourceSessionError> {
        match self.leases.get(group).copied() {
            Some(current) if term < current => Err(SourceSessionError::StaleLease {
                term: term.get(),
                current: current.get(),
            }),
            Some(current) if term > current => Err(SourceSessionError::LeaseNotAcquired {
                term: term.get(),
                current: current.get(),
            }),
            Some(_) => Ok(()),
            None => Err(SourceSessionError::LeaseNotAcquired {
                term: term.get(),
                current: 0,
            }),
        }
    }

    fn group_of(&self, id: SessionId) -> Result<GroupId, SourceSessionError> {
        self.sessions
            .get(&id)
            .map(|tracked| tracked.session.group.clone())
            .ok_or(SourceSessionError::UnknownSession { id: id.get() })
    }
}

#[cfg(test)]
impl SourceSessionPort for EphemeralSourceSessions {
    fn open(&mut self, request: OpenRequest) -> Result<SessionId, SourceSessionError> {
        let id = SessionId::new(self.next_id);
        let group = request.group.clone();
        let term = request.term;
        let endpoint = request.endpoint.clone();
        let session = SourceSession::new(id, request)?;
        if self.sessions.len() >= self.max_sessions {
            return Err(SourceSessionError::TooManySessions {
                max: self.max_sessions,
            });
        }
        if let Some(current) = self.leases.get(&group).copied()
            && term < current
        {
            return Err(SourceSessionError::StaleLease {
                term: term.get(),
                current: current.get(),
            });
        }
        let endpoint_taken = self
            .sessions
            .values()
            .any(|t| t.session.group == group && t.session.endpoint == endpoint);
        if endpoint_taken {
            return Err(SourceSessionError::EndpointInUse { endpoint });
        }
        let held = self.leases.get(&group).copied().unwrap_or(term).max(term);
        self.leases.insert(group, held);
        self.sessions.insert(
            id,
            Tracked {
                session,
                ledger: RecoveryLedger::new(),
            },
        );
        self.next_id += 1;
        Ok(id)
    }

    fn session(&self, id: SessionId) -> Result<&SourceSession, SourceSessionError> {
        self.sessions
            .get(&id)
            .map(|tracked| &tracked.session)
            .ok_or(SourceSessionError::UnknownSession { id: id.get() })
    }

    fn acquire_lease(
        &mut self,
        group: &GroupId,
        term: LeaseTerm,
    ) -> Result<(), SourceSessionError> {
        if let Some(current) = self.leases.get(group).copied()
            && term <= current
        {
            return Err(SourceSessionError::LeaseNotAdvancing {
                term: term.get(),
                current: current.get(),
            });
        }
        self.leases.insert(group.clone(), term);
        Ok(())
    }

    fn transition(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        to: SessionState,
    ) -> Result<(), SourceSessionError> {
        let group = self.group_of(id)?;
        self.check_term(&group, term)?;
        let tracked = self
            .sessions
            .get_mut(&id)
            .ok_or(SourceSessionError::UnknownSession { id: id.get() })?;
        let from = tracked.session.state;
        if !transition_allowed(from, to) {
            return Err(SourceSessionError::InvalidTransition {
                from: from.label(),
                to: to.label(),
            });
        }
        tracked.session.state = to;
        tracked.session.term = term;
        if to == SessionState::Closed {
            self.sessions.remove(&id);
        }
        Ok(())
    }

    fn report_error(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        kind: SourceErrorKind,
    ) -> Result<RecoveryDecision, SourceSessionError> {
        let group = self.group_of(id)?;
        self.check_term(&group, term)?;
        let tracked = self
            .sessions
            .get_mut(&id)
            .ok_or(SourceSessionError::UnknownSession { id: id.get() })?;
        let decision = tracked.ledger.record_failure(kind);
        if matches!(decision, RecoveryDecision::Surface { .. })
            && transition_allowed(tracked.session.state, SessionState::Failed(kind))
        {
            tracked.session.state = SessionState::Failed(kind);
        }
        Ok(decision)
    }

    fn report_recovered(
        &mut self,
        id: SessionId,
        term: LeaseTerm,
        kind: SourceErrorKind,
    ) -> Result<(), SourceSessionError> {
        let group = self.group_of(id)?;
        self.check_term(&group, term)?;
        let tracked = self
            .sessions
            .get_mut(&id)
            .ok_or(SourceSessionError::UnknownSession { id: id.get() })?;
        tracked.ledger.record_recovered(kind);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> StreamDescriptor {
        StreamDescriptor::new(
            SampleFormat::S16Be,
            48_000,
            ChannelLayout::Stereo,
            SampleOrigin::SourceDecoded,
            PresentationMapping::Unanchored,
        )
        .unwrap()
    }

    fn spotify_credential() -> SecretHandle {
        SecretHandle::new(SecretKind::SpotifyRefreshToken, "main").unwrap()
    }

    fn request(endpoint: &str, term: u64) -> OpenRequest {
        OpenRequest {
            kind: SourceKind::Spotify,
            endpoint: EndpointId::parse(endpoint).unwrap(),
            group: GroupId::parse("living-room").unwrap(),
            epoch: StreamEpoch::new(1),
            term: LeaseTerm::new(term),
            transport: TransportIdentity::parse("spotify-connect:dev-1").unwrap(),
            descriptor: descriptor(),
            credential: Some(spotify_credential()),
        }
    }

    fn term(n: u64) -> LeaseTerm {
        LeaseTerm::new(n)
    }

    fn ready_playing(ports: &mut EphemeralSourceSessions, id: SessionId, t: u64) {
        ports.transition(id, term(t), SessionState::Ready).unwrap();
        ports
            .transition(id, term(t), SessionState::Playing)
            .unwrap();
    }

    #[test]
    fn labels_reject_emails_tokens_uppercase_spaces_and_oversize() {
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        for raw in [
            "",
            "user@example.com",
            "tok-SECRET-9f3a",
            "Living-Room",
            "two words",
            "slash/inside",
            "caf\u{e9}",
            long.as_str(),
        ] {
            assert!(
                matches!(
                    EndpointId::parse(raw),
                    Err(SourceSessionError::InvalidLabel { .. })
                ),
                "{raw:?} must be refused as an endpoint id"
            );
            assert!(GroupId::parse(raw).is_err(), "{raw:?}");
            assert!(TransportIdentity::parse(raw).is_err(), "{raw:?}");
        }
        for raw in ["living-room", "spotify-connect:dev-1", "a.b_c", "0"] {
            assert_eq!(EndpointId::parse(raw).unwrap().as_str(), raw);
        }
        assert!(EndpointId::parse(&"x".repeat(MAX_LABEL_LEN)).is_ok());
    }

    #[test]
    fn a_label_error_names_the_kind_of_label_but_not_its_content() {
        let err = GroupId::parse("tok-SECRET-9f3a").unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(text.contains("group id"));
        assert!(!text.contains("SECRET"));
    }

    #[test]
    fn descriptors_accept_the_supported_rates_and_refuse_others() {
        for rate in SUPPORTED_RATES_HZ {
            assert!(
                StreamDescriptor::new(
                    SampleFormat::F32,
                    rate,
                    ChannelLayout::Mono,
                    SampleOrigin::Passthrough,
                    PresentationMapping::Anchored {
                        media_time_ns: 0,
                        presentation_ns: 5
                    },
                )
                .is_ok()
            );
        }
        for rate in [0, 8_000, 44_101, 47_999, 192_000] {
            assert_eq!(
                StreamDescriptor::new(
                    SampleFormat::S16Be,
                    rate,
                    ChannelLayout::Stereo,
                    SampleOrigin::SourceDecoded,
                    PresentationMapping::Unanchored,
                )
                .unwrap_err(),
                SourceSessionError::UnsupportedRate { rate_hz: rate }
            );
        }
    }

    #[test]
    fn a_credential_is_required_exactly_when_the_source_has_one_and_must_be_the_right_kind() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);

        let mut missing = request("kitchen", 1);
        missing.credential = None;
        assert_eq!(
            ports.open(missing).unwrap_err(),
            SourceSessionError::CredentialRequired { kind: "spotify" }
        );

        let mut line_in = request("kitchen", 1);
        line_in.kind = SourceKind::LineIn;
        assert_eq!(
            ports.open(line_in.clone()).unwrap_err(),
            SourceSessionError::UnexpectedCredential { kind: "line-in" }
        );
        line_in.credential = None;
        assert!(ports.open(line_in).is_ok());

        let mut wrong = request("den", 1);
        wrong.credential = Some(SecretHandle::new(SecretKind::TailnetAuthKey, "main").unwrap());
        assert_eq!(
            ports.open(wrong).unwrap_err(),
            SourceSessionError::CredentialKindMismatch {
                kind: "spotify",
                expected: "spotify-refresh-token",
                actual: "tailnet-auth-key"
            }
        );
    }

    #[test]
    fn a_session_shows_its_credential_handle_but_has_nowhere_to_hold_a_secret() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 1)).unwrap();
        let session = ports.session(id).unwrap();
        assert_eq!(session.kind(), SourceKind::Spotify);
        assert_eq!(session.state(), SessionState::Opening);
        assert_eq!(session.credential(), Some(&spotify_credential()));
        assert_eq!(session.epoch(), StreamEpoch::new(1));
        let printed = format!("{session:?}");
        assert!(printed.contains("SpotifyRefreshToken"), "{printed}");
        assert!(!printed.contains("tok-"));
    }

    /// Written separately from `transition_allowed`: the allowed moves, by label, and nothing else.
    const ALLOWED: &[(&str, &str)] = &[
        ("opening", "ready"),
        ("ready", "playing"),
        ("ready", "closed"),
        ("playing", "paused"),
        ("playing", "draining"),
        ("paused", "playing"),
        ("paused", "draining"),
        ("paused", "closed"),
        ("draining", "ready"),
        ("draining", "closed"),
        ("opening", "failed"),
        ("ready", "failed"),
        ("playing", "failed"),
        ("paused", "failed"),
        ("draining", "failed"),
        ("failed", "closed"),
    ];

    #[test]
    fn the_transition_table_matches_an_independently_written_matrix() {
        let mut states = vec![
            SessionState::Opening,
            SessionState::Ready,
            SessionState::Playing,
            SessionState::Paused,
            SessionState::Draining,
            SessionState::Closed,
        ];
        states.extend(SourceErrorKind::ALL.map(SessionState::Failed));
        assert_eq!(states.len(), 10);
        for &from in &states {
            for &to in &states {
                let expected = ALLOWED.contains(&(from.label(), to.label()));
                assert_eq!(transition_allowed(from, to), expected, "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn a_session_walks_its_lifecycle_and_a_closed_session_is_gone() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 1)).unwrap();
        ready_playing(&mut ports, id, 1);
        ports.transition(id, term(1), SessionState::Paused).unwrap();
        ports
            .transition(id, term(1), SessionState::Playing)
            .unwrap();
        ports
            .transition(id, term(1), SessionState::Draining)
            .unwrap();
        ports.transition(id, term(1), SessionState::Closed).unwrap();
        assert_eq!(
            ports.session(id).unwrap_err(),
            SourceSessionError::UnknownSession { id: id.get() }
        );
        assert_eq!(
            ports
                .transition(id, term(1), SessionState::Playing)
                .unwrap_err(),
            SourceSessionError::UnknownSession { id: id.get() }
        );
    }

    #[test]
    fn an_illegal_transition_is_refused_and_leaves_the_state_alone() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 1)).unwrap();
        assert_eq!(
            ports
                .transition(id, term(1), SessionState::Playing)
                .unwrap_err(),
            SourceSessionError::InvalidTransition {
                from: "opening",
                to: "playing"
            }
        );
        assert_eq!(ports.session(id).unwrap().state(), SessionState::Opening);
    }

    #[test]
    fn a_stale_coordinator_cannot_resume_after_a_newer_term_acquires_the_group() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 2)).unwrap();
        ready_playing(&mut ports, id, 2);
        ports.transition(id, term(2), SessionState::Paused).unwrap();

        // A newer coordinator takes the group.
        let group = GroupId::parse("living-room").unwrap();
        ports.acquire_lease(&group, term(3)).unwrap();

        // The old coordinator tries to resume playback: refused, and nothing changed.
        assert_eq!(
            ports
                .transition(id, term(2), SessionState::Playing)
                .unwrap_err(),
            SourceSessionError::StaleLease {
                term: 2,
                current: 3
            }
        );
        assert_eq!(ports.session(id).unwrap().state(), SessionState::Paused);
        assert_eq!(
            ports
                .report_error(id, term(2), SourceErrorKind::NetworkStarvation)
                .unwrap_err(),
            SourceSessionError::StaleLease {
                term: 2,
                current: 3
            }
        );

        // The new coordinator can, and the session adopts its term.
        ports
            .transition(id, term(3), SessionState::Playing)
            .unwrap();
        assert_eq!(ports.session(id).unwrap().term(), term(3));
        assert_eq!(
            ports
                .transition(id, term(2), SessionState::Paused)
                .unwrap_err(),
            SourceSessionError::StaleLease {
                term: 2,
                current: 3
            }
        );
    }

    #[test]
    fn a_term_that_was_never_acquired_cannot_act_and_leases_only_move_forward() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 2)).unwrap();
        assert_eq!(
            ports
                .transition(id, term(5), SessionState::Ready)
                .unwrap_err(),
            SourceSessionError::LeaseNotAcquired {
                term: 5,
                current: 2
            }
        );
        let group = GroupId::parse("living-room").unwrap();
        for not_newer in [1, 2] {
            assert_eq!(
                ports.acquire_lease(&group, term(not_newer)).unwrap_err(),
                SourceSessionError::LeaseNotAdvancing {
                    term: not_newer,
                    current: 2
                }
            );
        }
        assert!(ports.acquire_lease(&group, term(3)).is_ok());
    }

    #[test]
    fn opening_with_an_older_term_than_the_group_holds_is_refused() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        ports.open(request("kitchen", 4)).unwrap();
        assert_eq!(
            ports.open(request("den", 3)).unwrap_err(),
            SourceSessionError::StaleLease {
                term: 3,
                current: 4
            }
        );
        assert!(ports.open(request("den", 4)).is_ok());
    }

    #[test]
    fn sessions_and_endpoints_are_bounded_and_closing_frees_them() {
        let mut ports = EphemeralSourceSessions::with_capacity(2);
        let a = ports.open(request("kitchen", 1)).unwrap();
        assert_eq!(
            ports.open(request("kitchen", 1)).unwrap_err(),
            SourceSessionError::EndpointInUse {
                endpoint: EndpointId::parse("kitchen").unwrap()
            }
        );
        ports.open(request("den", 1)).unwrap();
        assert_eq!(
            ports.open(request("patio", 1)).unwrap_err(),
            SourceSessionError::TooManySessions { max: 2 }
        );
        // Close the first: its slot and its endpoint come back.
        ports.transition(a, term(1), SessionState::Ready).unwrap();
        ports.transition(a, term(1), SessionState::Closed).unwrap();
        assert!(ports.open(request("patio", 1)).is_ok());
        assert!(
            ports.open(request("kitchen", 1)).is_err(),
            "still full at 2"
        );
    }

    #[test]
    fn a_refused_open_does_not_burn_an_id_or_a_slot() {
        let mut ports = EphemeralSourceSessions::with_capacity(2);
        let mut bad = request("kitchen", 1);
        bad.credential = None;
        assert!(ports.open(bad).is_err());
        let id = ports.open(request("kitchen", 1)).unwrap();
        assert_eq!(id.get(), 1, "the refused open must not consume id 1");
    }

    #[test]
    fn recovery_budgets_are_per_category_and_a_spent_budget_is_surfaced_with_its_category() {
        let mut ledger = RecoveryLedger::new();
        // Authentication: one retry, then surfaced.
        assert_eq!(
            ledger.record_failure(SourceErrorKind::Authentication),
            RecoveryDecision::Retry {
                kind: SourceErrorKind::Authentication,
                attempt: 1,
                limit: 1
            }
        );
        assert_eq!(
            ledger.record_failure(SourceErrorKind::Authentication),
            RecoveryDecision::Surface {
                kind: SourceErrorKind::Authentication,
                attempts_used: 1
            }
        );
        // Unsupported media and renderer failure: surfaced at once.
        for kind in [
            SourceErrorKind::UnsupportedMedia,
            SourceErrorKind::RendererFailure,
        ] {
            assert_eq!(
                ledger.record_failure(kind),
                RecoveryDecision::Surface {
                    kind,
                    attempts_used: 0
                }
            );
        }
        // Network starvation still has its whole budget: the others did not spend it.
        for attempt in 1..=3 {
            assert_eq!(
                ledger.record_failure(SourceErrorKind::NetworkStarvation),
                RecoveryDecision::Retry {
                    kind: SourceErrorKind::NetworkStarvation,
                    attempt,
                    limit: 3
                }
            );
        }
        assert!(matches!(
            ledger.record_failure(SourceErrorKind::NetworkStarvation),
            RecoveryDecision::Surface {
                attempts_used: 3,
                ..
            }
        ));
    }

    #[test]
    fn a_recovery_restores_only_its_own_category() {
        let mut ledger = RecoveryLedger::new();
        ledger.record_failure(SourceErrorKind::Authentication);
        ledger.record_failure(SourceErrorKind::NetworkStarvation);
        ledger.record_failure(SourceErrorKind::NetworkStarvation);
        ledger.record_recovered(SourceErrorKind::NetworkStarvation);
        assert_eq!(ledger.attempts_used(SourceErrorKind::NetworkStarvation), 0);
        assert_eq!(ledger.attempts_used(SourceErrorKind::Authentication), 1);
    }

    #[test]
    fn explicit_limits_replace_the_defaults() {
        let mut ledger = RecoveryLedger::with_limits([0, 0, 1, 0]);
        assert!(matches!(
            ledger.record_failure(SourceErrorKind::Authentication),
            RecoveryDecision::Surface { .. }
        ));
        assert!(matches!(
            ledger.record_failure(SourceErrorKind::NetworkStarvation),
            RecoveryDecision::Retry { limit: 1, .. }
        ));
        assert_eq!(RecoveryLedger::default(), RecoveryLedger::new());
    }

    #[test]
    fn a_surfaced_failure_makes_the_session_failed_with_the_category_and_it_can_still_close() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 1)).unwrap();
        ready_playing(&mut ports, id, 1);

        // Network starvation: three retries leave the session playing, the fourth surfaces it.
        for _ in 0..3 {
            let decision = ports
                .report_error(id, term(1), SourceErrorKind::NetworkStarvation)
                .unwrap();
            assert!(matches!(decision, RecoveryDecision::Retry { .. }));
            assert_eq!(ports.session(id).unwrap().state(), SessionState::Playing);
        }
        let decision = ports
            .report_error(id, term(1), SourceErrorKind::NetworkStarvation)
            .unwrap();
        assert!(matches!(decision, RecoveryDecision::Surface { .. }));
        assert_eq!(
            ports.session(id).unwrap().state(),
            SessionState::Failed(SourceErrorKind::NetworkStarvation)
        );

        // A second, different surfaced failure does not overwrite the first category.
        ports
            .report_error(id, term(1), SourceErrorKind::RendererFailure)
            .unwrap();
        assert_eq!(
            ports.session(id).unwrap().state(),
            SessionState::Failed(SourceErrorKind::NetworkStarvation)
        );

        ports.transition(id, term(1), SessionState::Closed).unwrap();
    }

    #[test]
    fn a_report_recovered_through_the_port_restores_the_budget() {
        let mut ports = EphemeralSourceSessions::with_capacity(4);
        let id = ports.open(request("kitchen", 1)).unwrap();
        ready_playing(&mut ports, id, 1);
        for _ in 0..3 {
            ports
                .report_error(id, term(1), SourceErrorKind::NetworkStarvation)
                .unwrap();
        }
        ports
            .report_recovered(id, term(1), SourceErrorKind::NetworkStarvation)
            .unwrap();
        let decision = ports
            .report_error(id, term(1), SourceErrorKind::NetworkStarvation)
            .unwrap();
        assert!(matches!(
            decision,
            RecoveryDecision::Retry { attempt: 1, .. }
        ));
        assert_eq!(ports.session(id).unwrap().state(), SessionState::Playing);
    }

    #[test]
    fn credential_kinds_map_to_the_source_kinds_that_use_them() {
        assert_eq!(
            SourceKind::Spotify.credential_kind(),
            Some(SecretKind::SpotifyRefreshToken)
        );
        assert_eq!(
            SourceKind::AirPlay2.credential_kind(),
            Some(SecretKind::AirPlayPairingKey)
        );
        assert_eq!(SourceKind::LineIn.credential_kind(), None);
    }
}
