//! Group membership cutover (`G01` / `ffw-kh0`, section 12 of the bead).
//!
//! A membership change (a member joins or leaves) is **proposed**, **acknowledged**, **committed**
//! and then **activated at a future frame**. Until that frame nothing audible changes: `propose`,
//! `ack` and `commit` leave the session's members, their lifecycle states and its `state_revision`
//! exactly as they were. Activation is the only step that touches the session, and it bumps
//! `state_revision` once.
//!
//! The engine is additive: it never calls or changes `UnifiedGroupSession::apply_command` and has
//! its own error type, so command traffic (the N02 channel) and membership changes are independent.
//!
//! Authority. The first admitted profile has one configured issuer per group incarnation: the
//! session's `coordinator_id`. Every mutation presents an [`AuthorityToken`] naming the group, that
//! issuer and the epoch, with a lease expiry; a stale, future, foreign or expired token is refused
//! and changes nothing. Followers never mint a valid epoch: only [`GroupMembership::advance_epoch`],
//! behind the issuer's current token, does, and it aborts any proposal in flight. The token's
//! *authenticity* is the transport's job (N01/N02); this layer decides whether it is *current*.
//!
//! Leases and partitions. A lease is only as safe as the rule for replacing it, so replacement is a
//! quorum protocol over a configured electorate of [`LeaseVoter`]s (crash and partition faults; the
//! shared group key puts Byzantine peers out of scope). A holder extends its lease only with
//! acknowledgements from a strict majority of voters: a renewal it could grant itself would let a
//! partitioned holder renew forever while the majority took over. A voter acknowledges a renewal by
//! extending its view of the lease. It grants a takeover only if the lease has expired by *its own*
//! conservative bound, only for the next epoch, and to one candidate per epoch, and having granted
//! one it refuses every older epoch. Any renewal quorum and any takeover quorum therefore share a
//! voter that orders them, and because the holder stops `u` (the clock-uncertainty bound) before its
//! lease expires while a taker waits `u` after it, two valid leaders never overlap. Two partitioned
//! candidates cannot both reach a majority, and a split vote is a refusal, never a tie. A stale
//! holder's mutation is fenced by epoch. When a lease lapses, buffered output continues only to the
//! frame already granted and then mutes; no new output grant is issued without a live lease.
//!
//! The one authority-safety state that must survive a restart is each voter's
//! [`DurableVoterRecord`] (voter id, highest granted epoch, lease view expiry). A voter that restarts
//! without it refuses to grant or acknowledge anything. That is a deliberate exception to "persist
//! only stable intent": it is a fencing record, not a convenience.
//!
//! Missing acknowledgements never hold the group: at the ack deadline the configured
//! [`MissingAckPolicy`] either aborts the proposal or excludes the unreachable existing members. An
//! unreachable *joiner* always aborts. An excluded member is **not** evidence of silence: it is
//! recorded as an unresolved output grant, and [`GroupMembership::conflicting_start_gate`] refuses a
//! conflicting program until the member acknowledges a stop or a conservative expiry bound has
//! passed; an unknown bound refuses.
//!
//! Only stable membership intent is persisted ([`MembershipIntent`]). After a restart the engine
//! refuses every mutation until the current authority has been rediscovered, and a restored intent
//! is a list of members to re-admit, not a live session.

use crate::{ChannelRole, GroupMemberState, MemberLifecycleState, UnifiedGroupSession};
use franken_board_profile::BoardProfile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Largest group a membership change may produce (provisional; not a measured figure).
pub const MAX_GROUP_MEMBERS: usize = 32;
/// How many settled proposals are remembered so clients can reconcile a timed-out request.
pub const MAX_TERMINAL_HISTORY: usize = 64;

/// Every refusal carries only identifiers and numbers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MembershipError {
    #[error("authority token is for a different group")]
    WrongGroup,
    #[error("authority token was not issued by the group's configured issuer")]
    NotConfiguredIssuer,
    #[error("stale authority: token epoch {token_epoch} < group epoch {current_epoch}")]
    StaleAuthority {
        token_epoch: u64,
        current_epoch: u64,
    },
    #[error(
        "authority token epoch {token_epoch} is ahead of the group's epoch {current_epoch}; only the issuer's advance_epoch mints a newer one"
    )]
    FutureAuthority {
        token_epoch: u64,
        current_epoch: u64,
    },
    #[error("authority lease expired at {expires_at_ns} ns (now {now_ns} ns)")]
    AuthorityExpired { expires_at_ns: u64, now_ns: u64 },
    #[error("authority has not been rediscovered since the restart; mutation refused")]
    AuthorityNotDiscovered,
    #[error("proposal {pending} is still in progress; one membership change at a time")]
    ProposalPending { pending: u64 },
    #[error("no proposal {id} is known")]
    UnknownProposal { id: u64 },
    #[error("proposal {id} is {phase:?}, not pending")]
    NotPending { id: u64, phase: ProposalPhase },
    #[error("member `{member_id}` is already in the group")]
    MemberAlreadyPresent { member_id: String },
    #[error("member `{member_id}` is not in the group")]
    UnknownMember { member_id: String },
    #[error("the group already has {max} members")]
    GroupFull { max: usize },
    #[error("board profile `{profile_id}` is not eligible for audio group admission")]
    IneligibleBoard { profile_id: String },
    #[error("member `{member_id}` was excluded earlier and its output is not yet resolved")]
    OutputUnresolved { member_id: String },
    #[error(
        "cutover frame {cutover_frame} is earlier than the first admissible frame {earliest_frame}"
    )]
    CutoverTooSoon {
        cutover_frame: u64,
        earliest_frame: u64,
    },
    #[error("ack deadline {ack_deadline_ns} ns is not after now ({now_ns} ns)")]
    AckDeadlineNotInFuture { ack_deadline_ns: u64, now_ns: u64 },
    #[error("member `{member_id}` is not a participant of this proposal")]
    NotAParticipant { member_id: String },
    #[error("member `{member_id}` already acknowledged with different content")]
    AckConflict { member_id: String },
    #[error("ack deadline {ack_deadline_ns} ns has passed (now {now_ns} ns)")]
    AckAfterDeadline { ack_deadline_ns: u64, now_ns: u64 },
    #[error("acknowledgements are still missing from {members:?}")]
    MissingAcks { members: Vec<String> },
    #[error("members {members:?} reported that they are not ready")]
    MemberNotReady { members: Vec<String> },
    #[error("cutover frame {cutover_frame} has already been reached (now frame {now_frame})")]
    CutoverPassed { cutover_frame: u64, now_frame: u64 },
    #[error(
        "cutover frame {cutover_frame} is before a member's irrevocable output tail ends at frame {tail_complete_frame}"
    )]
    CutoverBeforeOutputTail {
        cutover_frame: u64,
        tail_complete_frame: u64,
    },
    #[error("epoch {requested} does not advance past {current}")]
    EpochNotAdvancing { requested: u64, current: u64 },
    #[error("member `{member_id}` has no unresolved output grant")]
    NoUnresolvedOutput { member_id: String },
    #[error("the electorate must name at least one voter")]
    EmptyElectorate,
    #[error("`{member_id}` is not a voter of this group")]
    NotAVoter { member_id: String },
    #[error(
        "this voter's durable record is unavailable (restart); it refuses until it is restored"
    )]
    VoterRecordUnavailable,
    #[error("this voter has observed no lease, so it cannot judge expiry")]
    NoLeaseView,
    #[error("takeover asked for epoch {requested}, but the next epoch is {expected}")]
    NotNextEpoch { requested: u64, expected: u64 },
    #[error(
        "the lease is not expired by this voter's conservative bound ({conservative_expiry_ns} ns; now {now_ns} ns)"
    )]
    LeaseNotExpired {
        conservative_expiry_ns: u64,
        now_ns: u64,
    },
    #[error("epoch {epoch} is held by `{holder}`, not by the requester")]
    NotLeaseHolder { epoch: u64, holder: String },
    #[error("the acknowledgement does not match the open request")]
    AttemptMismatch,
    #[error("the lease would be over by now ({now_ns} ns; usable until {deadline_ns} ns)")]
    AttemptExpired { now_ns: u64, deadline_ns: u64 },
    #[error("no quorum: {have} of {need} acknowledgements")]
    NoQuorum { have: usize, need: usize },
    #[error("lease expiry {expires_at_ns} ns is beyond the maximum {max_ns} ns")]
    LeaseTooLong { expires_at_ns: u64, max_ns: u64 },
    #[error("lease expiry {expires_at_ns} ns does not extend the current {current_ns} ns")]
    LeaseNotExtended { expires_at_ns: u64, current_ns: u64 },
    #[error("epoch {epoch} is held by `{held_by}`; `{announced_by}` also claims it")]
    ConflictingLeaders {
        epoch: u64,
        held_by: String,
        announced_by: String,
    },
    #[error("this quorum result does not apply to the presented token or session")]
    WinNotApplicable,
    #[error("output through frame {requested_frame} is beyond the grant horizon {max_frame}")]
    OutputHorizonExceeded {
        requested_frame: u64,
        max_frame: u64,
    },
    #[error("this group mints epochs only by voter quorum; the issuer cannot advance it alone")]
    QuorumRequired,
    #[error("this group has no voter electorate; its epochs come only from the configured issuer")]
    NotAQuorumGroup,
}

impl MembershipError {
    /// Stable machine-readable name, shared with the golden scenarios and the Python reference.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::WrongGroup => "WRONG_GROUP",
            Self::NotConfiguredIssuer => "NOT_CONFIGURED_ISSUER",
            Self::StaleAuthority { .. } => "STALE_AUTHORITY",
            Self::FutureAuthority { .. } => "FUTURE_AUTHORITY",
            Self::AuthorityExpired { .. } => "AUTHORITY_EXPIRED",
            Self::AuthorityNotDiscovered => "AUTHORITY_NOT_DISCOVERED",
            Self::ProposalPending { .. } => "PROPOSAL_PENDING",
            Self::UnknownProposal { .. } => "UNKNOWN_PROPOSAL",
            Self::NotPending { .. } => "NOT_PENDING",
            Self::MemberAlreadyPresent { .. } => "MEMBER_ALREADY_PRESENT",
            Self::UnknownMember { .. } => "UNKNOWN_MEMBER",
            Self::GroupFull { .. } => "GROUP_FULL",
            Self::IneligibleBoard { .. } => "INELIGIBLE_BOARD",
            Self::OutputUnresolved { .. } => "OUTPUT_UNRESOLVED",
            Self::CutoverTooSoon { .. } => "CUTOVER_TOO_SOON",
            Self::AckDeadlineNotInFuture { .. } => "ACK_DEADLINE_NOT_IN_FUTURE",
            Self::NotAParticipant { .. } => "NOT_A_PARTICIPANT",
            Self::AckConflict { .. } => "ACK_CONFLICT",
            Self::AckAfterDeadline { .. } => "ACK_AFTER_DEADLINE",
            Self::MissingAcks { .. } => "MISSING_ACKS",
            Self::MemberNotReady { .. } => "MEMBER_NOT_READY",
            Self::CutoverPassed { .. } => "CUTOVER_PASSED",
            Self::CutoverBeforeOutputTail { .. } => "CUTOVER_BEFORE_OUTPUT_TAIL",
            Self::EpochNotAdvancing { .. } => "EPOCH_NOT_ADVANCING",
            Self::NoUnresolvedOutput { .. } => "NO_UNRESOLVED_OUTPUT",
            Self::EmptyElectorate => "EMPTY_ELECTORATE",
            Self::NotAVoter { .. } => "NOT_A_VOTER",
            Self::VoterRecordUnavailable => "VOTER_RECORD_UNAVAILABLE",
            Self::NoLeaseView => "NO_LEASE_VIEW",
            Self::NotNextEpoch { .. } => "NOT_NEXT_EPOCH",
            Self::LeaseNotExpired { .. } => "LEASE_NOT_EXPIRED",
            Self::NotLeaseHolder { .. } => "NOT_LEASE_HOLDER",
            Self::AttemptMismatch => "ATTEMPT_MISMATCH",
            Self::AttemptExpired { .. } => "ATTEMPT_EXPIRED",
            Self::NoQuorum { .. } => "NO_QUORUM",
            Self::LeaseTooLong { .. } => "LEASE_TOO_LONG",
            Self::LeaseNotExtended { .. } => "LEASE_NOT_EXTENDED",
            Self::ConflictingLeaders { .. } => "CONFLICTING_LEADERS",
            Self::WinNotApplicable => "WIN_NOT_APPLICABLE",
            Self::OutputHorizonExceeded { .. } => "OUTPUT_HORIZON_EXCEEDED",
            Self::QuorumRequired => "QUORUM_REQUIRED",
            Self::NotAQuorumGroup => "NOT_A_QUORUM_GROUP",
        }
    }
}

/// Lease naming who may make group-affecting mutations, scoped to one group and one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityToken {
    pub group_id: String,
    pub issuer_id: String,
    pub epoch: u64,
    pub expires_at_ns: u64,
}

impl AuthorityToken {
    /// The configured issuer's own token for the session's current epoch.
    #[must_use]
    pub fn issue(session: &UnifiedGroupSession, expires_at_ns: u64) -> Self {
        Self {
            group_id: session.group_id.clone(),
            issuer_id: session.coordinator_id.clone(),
            epoch: session.current_epoch,
            expires_at_ns,
        }
    }

    /// Whether `session` accepts this token as current at `now_ns`. Pure: nothing changes.
    pub fn check(&self, session: &UnifiedGroupSession, now_ns: u64) -> Result<(), MembershipError> {
        self.check_with_margin(session, now_ns, 0)
    }

    /// As [`AuthorityToken::check`], but the holder treats its lease as over `margin_ns` early (the
    /// clock-uncertainty bound), so it has stopped acting before any taker may start. The epoch is
    /// judged before the issuer: a stale coordinator names the old issuer *and* the old epoch, and
    /// is fenced by epoch.
    pub fn check_with_margin(
        &self,
        session: &UnifiedGroupSession,
        now_ns: u64,
        margin_ns: u64,
    ) -> Result<(), MembershipError> {
        if self.group_id != session.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if self.epoch < session.current_epoch {
            return Err(MembershipError::StaleAuthority {
                token_epoch: self.epoch,
                current_epoch: session.current_epoch,
            });
        }
        if self.epoch > session.current_epoch {
            return Err(MembershipError::FutureAuthority {
                token_epoch: self.epoch,
                current_epoch: session.current_epoch,
            });
        }
        if self.issuer_id != session.coordinator_id {
            return Err(MembershipError::NotConfiguredIssuer);
        }
        if now_ns.saturating_add(margin_ns) >= self.expires_at_ns {
            return Err(MembershipError::AuthorityExpired {
                expires_at_ns: self.expires_at_ns,
                now_ns,
            });
        }
        Ok(())
    }

    /// What this lease looks like to a follower or voter that is told about it.
    #[must_use]
    pub fn lease_view(&self) -> LeaseView {
        LeaseView {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            holder: self.issuer_id.clone(),
            expires_at_ns: self.expires_at_ns,
        }
    }
}

/// A point on the group timeline: monotonic nanoseconds for deadlines, sample frames for cutovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupTime {
    pub ns: u64,
    pub frame: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipChange {
    Join {
        member_id: String,
        board: Box<BoardProfile>,
        role: ChannelRole,
    },
    Leave {
        member_id: String,
    },
}

/// What the authority wants: the change, the frame it takes effect, and how long to wait for acks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalSpec {
    pub change: MembershipChange,
    pub cutover_frame: u64,
    pub ack_deadline_ns: u64,
}

/// One participant's readiness for a cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessReport {
    /// The sample format is one this member can render (a joiner validates it first).
    pub format_ok: bool,
    /// Buffer resources are available (a joiner validates them first).
    pub buffer_ok: bool,
    /// Clock confidence is sufficient for the group's current timeline.
    pub clock_confident: bool,
    /// The member can acknowledge a stop or flush. A joiner has nothing to flush and reports true.
    pub can_stop_flush: bool,
    /// The frame at which this member's irrevocable already-submitted output ends; 0 if none.
    pub old_output_tail_complete_frame: u64,
}

impl ReadinessReport {
    const fn is_ready(&self) -> bool {
        self.format_ok && self.buffer_ok && self.clock_confident && self.can_stop_flush
    }
}

/// What to do when an existing member has not acknowledged by the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingAckPolicy {
    /// Abort the proposal; the group is unchanged.
    Abort,
    /// Continue without the unreachable existing members and record each as an unresolved output.
    ExcludeUnreachable,
}

/// Timing bounds for leases (provisional placeholders until N03 supplies real clock bounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTerms {
    /// No lease may be proposed or extended further ahead than this.
    pub max_lease_ns: u64,
    /// How far apart two nodes' readings of one instant may be. A holder stops this long *before*
    /// its lease expires and a taker waits this long *after*. The default of 0 assumes perfectly
    /// agreeing clocks, which no real deployment has: it keeps behaviour exact until a bound exists.
    pub clock_uncertainty_ns: u64,
    /// How long after its lease a holder's already-granted output may still sound.
    pub max_output_horizon_ns: u64,
}

impl Default for LeaseTerms {
    fn default() -> Self {
        Self {
            max_lease_ns: 5_000_000_000,
            clock_uncertainty_ns: 0,
            max_output_horizon_ns: 10_000_000_000,
        }
    }
}

/// Who may mint a new epoch. The two must never be mixed in one group: an issuer that bumps the
/// epoch alone while a quorum elects someone else at the same epoch would make two leaders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochMint {
    /// The first admitted profile: the configured issuer alone, through
    /// [`GroupMembership::advance_epoch`]. No electorate exists.
    ConfiguredIssuer,
    /// A group with a voter electorate: only a quorum win ([`GroupMembership::assume_authority`])
    /// mints an epoch, and `advance_epoch` refuses.
    Quorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConfig {
    /// A cutover must be at least this many frames ahead, so acknowledgements can arrive.
    pub min_cutover_lead_frames: u64,
    pub max_members: usize,
    pub missing_ack_policy: MissingAckPolicy,
    pub lease: LeaseTerms,
    /// How far ahead of now an output grant may reach, in frames (10 s at 48 kHz; provisional).
    pub max_output_horizon_frames: u64,
    pub epoch_mint: EpochMint,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            min_cutover_lead_frames: 4_800,
            max_members: MAX_GROUP_MEMBERS,
            missing_ack_policy: MissingAckPolicy::Abort,
            lease: LeaseTerms::default(),
            max_output_horizon_frames: 480_000,
            epoch_mint: EpochMint::ConfiguredIssuer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalPhase {
    Pending,
    Committed,
    Activated,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// The authority cancelled it.
    ByAuthority,
    /// The ack deadline passed with acknowledgements missing and the policy (or a missing joiner)
    /// required an abort.
    AckDeadlineMissed { missing: Vec<String> },
    /// The authority moved the group to a newer epoch.
    EpochAdvanced,
    /// The cutover frame was reached before the authority committed.
    CutoverMissed,
    /// The group changed in a way that made the committed change inapplicable at its frame.
    PreconditionFailed,
}

/// The explicit pending / committed / activated / aborted state clients reconcile against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Pending {
        acked: Vec<String>,
        missing: Vec<String>,
        excluded: Vec<String>,
    },
    Committed {
        activate_at_frame: u64,
        excluded: Vec<String>,
    },
    Activated {
        revision: u64,
        excluded: Vec<String>,
    },
    Aborted {
        reason: AbortReason,
    },
}

impl ProposalStatus {
    #[must_use]
    pub const fn phase(&self) -> ProposalPhase {
        match self {
            Self::Pending { .. } => ProposalPhase::Pending,
            Self::Committed { .. } => ProposalPhase::Committed,
            Self::Activated { .. } => ProposalPhase::Activated,
            Self::Aborted { .. } => ProposalPhase::Aborted,
        }
    }
}

/// How an excluded member's earlier output grant is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputBound {
    /// Nothing is known; a conflicting start is refused.
    Unknown,
    /// A conservative bound (output expiry plus irrevocable tail, clock uncertainty and the
    /// stop/drain lead) after which the member can no longer sound.
    ExpiresAtFrame(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputResolution {
    StopAcknowledged,
    ExpiresAtFrame(u64),
}

/// The only membership state that is persisted. No lease, queue, acknowledgement, lifecycle or
/// volume: a restored intent is a list of members to re-admit, not a live session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipIntent {
    pub group_id: String,
    pub issuer_id: String,
    pub members: Vec<IntendedMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntendedMember {
    pub member_id: String,
    pub profile_id: String,
    pub role: ChannelRole,
}

impl MembershipIntent {
    /// Members the intent wants that a (freshly built) live session does not have.
    #[must_use]
    pub fn members_missing_from(&self, session: &UnifiedGroupSession) -> Vec<String> {
        self.members
            .iter()
            .filter(|m| !session.members.contains_key(&m.member_id))
            .map(|m| m.member_id.clone())
            .collect()
    }
}

#[derive(Debug)]
struct Proposal {
    id: u64,
    change: MembershipChange,
    cutover_frame: u64,
    ack_deadline_ns: u64,
    participants: BTreeSet<String>,
    acks: BTreeMap<String, ReadinessReport>,
    excluded: BTreeSet<String>,
    committed: bool,
}

impl Proposal {
    fn required(&self) -> impl Iterator<Item = &String> {
        self.participants
            .iter()
            .filter(|m| !self.excluded.contains(*m))
    }

    fn missing(&self) -> Vec<String> {
        self.required()
            .filter(|m| !self.acks.contains_key(m.as_str()))
            .cloned()
            .collect()
    }

    fn status(&self) -> ProposalStatus {
        let excluded: Vec<String> = self.excluded.iter().cloned().collect();
        if self.committed {
            ProposalStatus::Committed {
                activate_at_frame: self.cutover_frame,
                excluded,
            }
        } else {
            ProposalStatus::Pending {
                acked: self.acks.keys().cloned().collect(),
                missing: self.missing(),
                excluded,
            }
        }
    }
}

/// What a node last learned about the live lease: who holds it, for which epoch, until when (in the
/// holder's clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseView {
    pub group_id: String,
    pub epoch: u64,
    pub holder: String,
    pub expires_at_ns: u64,
}

/// The configured electorate of one group incarnation. A quorum is a strict majority, so an even
/// electorate can split with nobody winning: that is a refusal, never a tie. Use an odd number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumConfig {
    group_id: String,
    voters: BTreeSet<String>,
}

impl QuorumConfig {
    pub fn new(group_id: &str, voters: &[&str]) -> Result<Self, MembershipError> {
        if voters.is_empty() {
            return Err(MembershipError::EmptyElectorate);
        }
        Ok(Self {
            group_id: group_id.to_string(),
            voters: voters.iter().map(|v| (*v).to_string()).collect(),
        })
    }

    /// Acknowledgements needed: a strict majority of the electorate.
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    #[must_use]
    pub const fn voters(&self) -> &BTreeSet<String> {
        &self.voters
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRequestKind {
    /// The holder extends its own epoch's lease.
    Renew,
    /// A candidate asks for the next epoch.
    Takeover,
}

/// A request to the voters. `expires_at_ns` is the lease the requester proposes, in its own clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub kind: LeaseRequestKind,
    pub group_id: String,
    pub requester: String,
    pub epoch: u64,
    pub expires_at_ns: u64,
}

/// A voter's answer. `prior_expires_at_ns` is the latest expiry of any earlier lease the voter
/// knew of (0 for a renewal), so a winner learns how long the previous term could still sound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseAck {
    pub kind: LeaseRequestKind,
    pub group_id: String,
    pub voter: String,
    pub requester: String,
    pub epoch: u64,
    pub expires_at_ns: u64,
    pub prior_expires_at_ns: u64,
}

/// A takeover this voter granted: it will grant no other candidate this epoch or any earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    pub epoch: u64,
    pub candidate: String,
    pub expires_at_ns: u64,
    pub prior_expires_at_ns: u64,
}

/// The authority-safety state a voter must not lose: its id, the lease it last knew, and the
/// highest takeover it granted. Losing it could let a voter grant the same epoch twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableVoterRecord {
    pub voter_id: String,
    pub view: Option<LeaseView>,
    pub grant: Option<GrantRecord>,
}

/// One voter's side of the lease protocol (see the module documentation).
#[derive(Debug, Clone)]
pub struct LeaseVoter {
    id: String,
    quorum: QuorumConfig,
    terms: LeaseTerms,
    view: Option<LeaseView>,
    grant: Option<GrantRecord>,
    record_trusted: bool,
}

impl LeaseVoter {
    /// A voter of a newly formed group: there is no earlier record to lose.
    pub fn new(id: &str, quorum: QuorumConfig, terms: LeaseTerms) -> Result<Self, MembershipError> {
        if !quorum.voters.contains(id) {
            return Err(MembershipError::NotAVoter {
                member_id: id.to_string(),
            });
        }
        Ok(Self {
            id: id.to_string(),
            quorum,
            terms,
            view: None,
            grant: None,
            record_trusted: true,
        })
    }

    /// A voter after a restart: it refuses to grant or acknowledge until
    /// [`LeaseVoter::restore`] gives it the record that was persisted.
    pub fn after_restart(
        id: &str,
        quorum: QuorumConfig,
        terms: LeaseTerms,
    ) -> Result<Self, MembershipError> {
        Ok(Self {
            record_trusted: false,
            ..Self::new(id, quorum, terms)?
        })
    }

    /// Reinstate the persisted record (what U01 stores).
    pub fn restore(&mut self, record: DurableVoterRecord) -> Result<(), MembershipError> {
        if record.voter_id != self.id {
            return Err(MembershipError::VoterRecordUnavailable);
        }
        self.view = record.view;
        self.grant = record.grant;
        self.record_trusted = true;
        Ok(())
    }

    /// What must be persisted after every change.
    #[must_use]
    pub fn durable_record(&self) -> DurableVoterRecord {
        DurableVoterRecord {
            voter_id: self.id.clone(),
            view: self.view.clone(),
            grant: self.grant.clone(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn view(&self) -> Option<&LeaseView> {
        self.view.as_ref()
    }

    /// The highest epoch this voter has seen a lease for or granted.
    fn high_epoch(&self) -> Option<u64> {
        match (&self.view, &self.grant) {
            (Some(v), Some(g)) => Some(v.epoch.max(g.epoch)),
            (Some(v), None) => Some(v.epoch),
            (None, Some(g)) => Some(g.epoch),
            (None, None) => None,
        }
    }

    /// Adopt `view` as the confirmed lease and drop a grant it supersedes.
    fn confirm(&mut self, view: LeaseView) {
        if self.grant.as_ref().is_some_and(|g| g.epoch <= view.epoch) {
            self.grant = None;
        }
        self.view = Some(view);
    }

    /// Learn a lease announced by its holder (or told by a peer). Older epochs are stale; a second
    /// holder for an epoch already confirmed is a conflict (which a correct protocol never produces).
    pub fn observe(&mut self, view: &LeaseView) -> Result<(), MembershipError> {
        if view.group_id != self.quorum.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if !self.quorum.voters.contains(&view.holder) {
            return Err(MembershipError::NotAVoter {
                member_id: view.holder.clone(),
            });
        }
        if let Some(high) = self.high_epoch()
            && view.epoch < high
        {
            return Err(MembershipError::StaleAuthority {
                token_epoch: view.epoch,
                current_epoch: high,
            });
        }
        let mut expires_at_ns = view.expires_at_ns;
        if let Some(current) = &self.view
            && current.epoch == view.epoch
        {
            if current.holder != view.holder {
                return Err(MembershipError::ConflictingLeaders {
                    epoch: view.epoch,
                    held_by: current.holder.clone(),
                    announced_by: view.holder.clone(),
                });
            }
            expires_at_ns = expires_at_ns.max(current.expires_at_ns);
        }
        self.confirm(LeaseView {
            expires_at_ns,
            ..view.clone()
        });
        Ok(())
    }

    /// The request this voter, as the lease holder, sends to extend its lease to `now + lease_ns`.
    pub fn renew_request(
        &self,
        now_ns: u64,
        lease_ns: u64,
    ) -> Result<LeaseRequest, MembershipError> {
        let Some(view) = &self.view else {
            return Err(MembershipError::NoLeaseView);
        };
        if view.holder != self.id {
            return Err(MembershipError::NotLeaseHolder {
                epoch: view.epoch,
                holder: view.holder.clone(),
            });
        }
        self.request(LeaseRequestKind::Renew, view.epoch, now_ns, lease_ns)
    }

    /// The request this voter, as a candidate, sends to take over. A candidate that already holds
    /// its own unfinished grant asks for that same epoch again; otherwise for the next one.
    pub fn takeover_request(
        &self,
        now_ns: u64,
        lease_ns: u64,
    ) -> Result<LeaseRequest, MembershipError> {
        let Some(high) = self.high_epoch() else {
            return Err(MembershipError::NoLeaseView);
        };
        let epoch = match &self.grant {
            Some(g) if g.candidate == self.id => g.epoch,
            _ => high.saturating_add(1),
        };
        self.request(LeaseRequestKind::Takeover, epoch, now_ns, lease_ns)
    }

    fn request(
        &self,
        kind: LeaseRequestKind,
        epoch: u64,
        now_ns: u64,
        lease_ns: u64,
    ) -> Result<LeaseRequest, MembershipError> {
        if lease_ns > self.terms.max_lease_ns {
            return Err(MembershipError::LeaseTooLong {
                expires_at_ns: now_ns.saturating_add(lease_ns),
                max_ns: now_ns.saturating_add(self.terms.max_lease_ns),
            });
        }
        Ok(LeaseRequest {
            kind,
            group_id: self.quorum.group_id.clone(),
            requester: self.id.clone(),
            epoch,
            expires_at_ns: now_ns.saturating_add(lease_ns),
        })
    }

    /// Answer a renewal or takeover request, judged by this voter's own clock reading `now_ns`.
    pub fn respond(
        &mut self,
        request: &LeaseRequest,
        now_ns: u64,
    ) -> Result<LeaseAck, MembershipError> {
        if !self.record_trusted {
            return Err(MembershipError::VoterRecordUnavailable);
        }
        if request.group_id != self.quorum.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if !self.quorum.voters.contains(&request.requester) {
            return Err(MembershipError::NotAVoter {
                member_id: request.requester.clone(),
            });
        }
        let prior_expires_at_ns = match request.kind {
            LeaseRequestKind::Renew => self.acknowledge_renewal(request)?,
            LeaseRequestKind::Takeover => self.grant_takeover(request, now_ns)?,
        };
        Ok(LeaseAck {
            kind: request.kind,
            group_id: request.group_id.clone(),
            voter: self.id.clone(),
            requester: request.requester.clone(),
            epoch: request.epoch,
            expires_at_ns: request.expires_at_ns,
            prior_expires_at_ns,
        })
    }

    fn acknowledge_renewal(&mut self, request: &LeaseRequest) -> Result<u64, MembershipError> {
        let Some(high) = self.high_epoch() else {
            return Err(MembershipError::NoLeaseView);
        };
        // A voter that granted epoch e+1 refuses every renewal of an older epoch: this is the
        // ordering that keeps a renewal quorum and a takeover quorum from both succeeding.
        if request.epoch < high {
            return Err(MembershipError::StaleAuthority {
                token_epoch: request.epoch,
                current_epoch: high,
            });
        }
        // A renewal extends a lease this voter knows to be the requester's: the confirmed lease,
        // or the takeover it granted to the requester. An epoch it has never heard of cannot be
        // minted by renewing it.
        let expires_at_ns = match (&self.view, &self.grant) {
            (Some(view), _) if view.epoch == request.epoch => {
                if view.holder != request.requester {
                    return Err(MembershipError::NotLeaseHolder {
                        epoch: view.epoch,
                        holder: view.holder.clone(),
                    });
                }
                request.expires_at_ns.max(view.expires_at_ns)
            }
            (_, Some(grant)) if grant.epoch == request.epoch => {
                if grant.candidate != request.requester {
                    return Err(MembershipError::NotLeaseHolder {
                        epoch: grant.epoch,
                        holder: grant.candidate.clone(),
                    });
                }
                request.expires_at_ns.max(grant.expires_at_ns)
            }
            _ => {
                return Err(MembershipError::FutureAuthority {
                    token_epoch: request.epoch,
                    current_epoch: high,
                });
            }
        };
        self.confirm(LeaseView {
            group_id: request.group_id.clone(),
            epoch: request.epoch,
            holder: request.requester.clone(),
            expires_at_ns,
        });
        Ok(0)
    }

    fn grant_takeover(
        &mut self,
        request: &LeaseRequest,
        now_ns: u64,
    ) -> Result<u64, MembershipError> {
        let Some(high) = self.high_epoch() else {
            return Err(MembershipError::NoLeaseView);
        };
        // The same candidate asking again for the epoch it was already granted: idempotent.
        if let Some(grant) = &mut self.grant
            && grant.epoch == request.epoch
            && grant.candidate == request.requester
        {
            grant.expires_at_ns = grant.expires_at_ns.max(request.expires_at_ns);
            return Ok(grant.prior_expires_at_ns);
        }
        // One candidate per epoch: a rival for an epoch already granted is refused, never tied.
        if let Some(grant) = &self.grant
            && grant.epoch == request.epoch
        {
            return Err(MembershipError::ConflictingLeaders {
                epoch: grant.epoch,
                held_by: grant.candidate.clone(),
                announced_by: request.requester.clone(),
            });
        }
        if request.epoch != high.saturating_add(1) {
            return Err(MembershipError::NotNextEpoch {
                requested: request.epoch,
                expected: high.saturating_add(1),
            });
        }
        // The previous term may last until the latest expiry this voter knows of, in the holder's
        // clock; wait out the clock uncertainty on top, by this voter's own reading.
        let latest = self
            .view
            .iter()
            .map(|v| v.expires_at_ns)
            .chain(self.grant.iter().map(|g| g.expires_at_ns))
            .max()
            .unwrap_or(0);
        let conservative_expiry_ns = latest.saturating_add(self.terms.clock_uncertainty_ns);
        if now_ns < conservative_expiry_ns {
            return Err(MembershipError::LeaseNotExpired {
                conservative_expiry_ns,
                now_ns,
            });
        }
        self.grant = Some(GrantRecord {
            epoch: request.epoch,
            candidate: request.requester.clone(),
            expires_at_ns: request.expires_at_ns,
            prior_expires_at_ns: latest,
        });
        Ok(latest)
    }
}

/// What a requester gathers acknowledgements into. Everything it concludes is judged against the
/// lease it proposed: once that lease could no longer be relied on, the round is over.
#[derive(Debug, Clone)]
pub struct QuorumRound {
    request: LeaseRequest,
    quorum: usize,
    voters: BTreeSet<String>,
    uncertainty_ns: u64,
    acks: BTreeMap<String, u64>,
}

/// A request that gathered a quorum. It is evidence that the protocol agreed, not itself authority:
/// the engine applies it ([`GroupMembership::renew_lease`], [`GroupMembership::assume_authority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseWin {
    kind: LeaseRequestKind,
    group_id: String,
    requester: String,
    epoch: u64,
    expires_at_ns: u64,
    prior_expires_at_ns: u64,
    acks: usize,
}

impl LeaseWin {
    #[must_use]
    pub const fn kind(&self) -> LeaseRequestKind {
        self.kind
    }

    #[must_use]
    pub fn requester(&self) -> &str {
        &self.requester
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }

    /// The latest expiry of the previous term among the acknowledging voters.
    #[must_use]
    pub const fn prior_expires_at_ns(&self) -> u64 {
        self.prior_expires_at_ns
    }

    #[must_use]
    pub const fn acks(&self) -> usize {
        self.acks
    }
}

impl QuorumRound {
    pub fn start(
        quorum: &QuorumConfig,
        terms: LeaseTerms,
        request: LeaseRequest,
        now_ns: u64,
    ) -> Result<Self, MembershipError> {
        if request.group_id != quorum.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if !quorum.voters.contains(&request.requester) {
            return Err(MembershipError::NotAVoter {
                member_id: request.requester.clone(),
            });
        }
        let max_ns = now_ns.saturating_add(terms.max_lease_ns);
        if request.expires_at_ns > max_ns {
            return Err(MembershipError::LeaseTooLong {
                expires_at_ns: request.expires_at_ns,
                max_ns,
            });
        }
        let round = Self {
            quorum: quorum.quorum(),
            voters: quorum.voters.clone(),
            uncertainty_ns: terms.clock_uncertainty_ns,
            acks: BTreeMap::new(),
            request,
        };
        round.check_live(now_ns)?;
        Ok(round)
    }

    #[must_use]
    pub const fn request(&self) -> &LeaseRequest {
        &self.request
    }

    /// The proposed lease has to be usable with the margin to spare, or the round is over.
    fn check_live(&self, now_ns: u64) -> Result<(), MembershipError> {
        let deadline_ns = self
            .request
            .expires_at_ns
            .saturating_sub(self.uncertainty_ns);
        if now_ns >= deadline_ns {
            return Err(MembershipError::AttemptExpired {
                now_ns,
                deadline_ns,
            });
        }
        Ok(())
    }

    /// Record one voter's acknowledgement. A repeat counts once.
    pub fn record(&mut self, ack: &LeaseAck, now_ns: u64) -> Result<(), MembershipError> {
        let r = &self.request;
        if ack.kind != r.kind
            || ack.group_id != r.group_id
            || ack.requester != r.requester
            || ack.epoch != r.epoch
            || ack.expires_at_ns != r.expires_at_ns
        {
            return Err(MembershipError::AttemptMismatch);
        }
        if !self.voters.contains(&ack.voter) {
            return Err(MembershipError::NotAVoter {
                member_id: ack.voter.clone(),
            });
        }
        self.check_live(now_ns)?;
        self.acks.insert(ack.voter.clone(), ack.prior_expires_at_ns);
        Ok(())
    }

    /// The result so far: a win once a strict majority has acknowledged; otherwise a refusal
    /// (`NO_QUORUM`) that says how far short it is.
    pub fn outcome(&self, now_ns: u64) -> Result<LeaseWin, MembershipError> {
        self.check_live(now_ns)?;
        if self.acks.len() < self.quorum {
            return Err(MembershipError::NoQuorum {
                have: self.acks.len(),
                need: self.quorum,
            });
        }
        Ok(LeaseWin {
            kind: self.request.kind,
            group_id: self.request.group_id.clone(),
            requester: self.request.requester.clone(),
            epoch: self.request.epoch,
            expires_at_ns: self.request.expires_at_ns,
            prior_expires_at_ns: self.acks.values().copied().max().unwrap_or(0),
            acks: self.acks.len(),
        })
    }
}

/// The membership cutover engine for one group. Methods that read the group take the session;
/// only activation (in [`GroupMembership::tick`]) and [`GroupMembership::advance_epoch`] change it.
#[derive(Debug)]
pub struct GroupMembership {
    config: MembershipConfig,
    authority_discovered: bool,
    next_proposal_id: u64,
    current: Option<Proposal>,
    history: VecDeque<(u64, ProposalStatus)>,
    unresolved_output: BTreeMap<String, OutputBound>,
    /// Output this holder has granted, per member: sounding is permitted only below this frame.
    output_grants: BTreeMap<String, u64>,
    /// After a takeover: the earliest instant (this node's clock) a conflicting program may start.
    takeover_gate_until_ns: Option<u64>,
}

impl GroupMembership {
    /// An engine for a group whose authority is known (a newly formed group).
    #[must_use]
    pub fn new(config: MembershipConfig) -> Self {
        Self {
            config,
            authority_discovered: true,
            next_proposal_id: 1,
            current: None,
            history: VecDeque::new(),
            unresolved_output: BTreeMap::new(),
            output_grants: BTreeMap::new(),
            takeover_gate_until_ns: None,
        }
    }

    /// The one authority rule every mutation applies: the token is current for this group and the
    /// holder is still `clock_uncertainty_ns` short of its lease expiry.
    fn authorize(
        &self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
    ) -> Result<(), MembershipError> {
        token.check_with_margin(session, now_ns, self.config.lease.clock_uncertainty_ns)
    }

    /// Whether `token` still lets its holder act, by this engine's conservative reading.
    #[must_use]
    pub fn lease_is_live(
        &self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
    ) -> bool {
        self.authorize(session, token, now_ns).is_ok()
    }

    /// An engine after a restart: every mutation is refused until
    /// [`GroupMembership::discover_authority`] succeeds.
    #[must_use]
    pub fn after_restart(config: MembershipConfig) -> Self {
        Self {
            authority_discovered: false,
            ..Self::new(config)
        }
    }

    /// Accept the current authority, as discovered from the live group.
    pub fn discover_authority(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
    ) -> Result<(), MembershipError> {
        self.authorize(session, token, now_ns)?;
        self.authority_discovered = true;
        Ok(())
    }

    /// The only persisted membership state: who is meant to be in the group.
    #[must_use]
    pub fn stable_intent(session: &UnifiedGroupSession) -> MembershipIntent {
        MembershipIntent {
            group_id: session.group_id.clone(),
            issuer_id: session.coordinator_id.clone(),
            members: session
                .members
                .values()
                .map(|m| IntendedMember {
                    member_id: m.member_id.clone(),
                    profile_id: m.profile_id.clone(),
                    role: m.role,
                })
                .collect(),
        }
    }

    fn require_discovered(&self) -> Result<(), MembershipError> {
        if self.authority_discovered {
            Ok(())
        } else {
            Err(MembershipError::AuthorityNotDiscovered)
        }
    }

    /// Lease renewal, takeover and adoption exist only for a group that elects by voter quorum.
    fn require_quorum_group(&self) -> Result<(), MembershipError> {
        if self.config.epoch_mint == EpochMint::Quorum {
            Ok(())
        } else {
            Err(MembershipError::NotAQuorumGroup)
        }
    }

    #[must_use]
    pub fn pending_proposal(&self) -> Option<u64> {
        self.current.as_ref().map(|p| p.id)
    }

    /// The state of a proposal: live, or settled within the last [`MAX_TERMINAL_HISTORY`].
    pub fn status(&self, id: u64) -> Result<ProposalStatus, MembershipError> {
        if let Some(p) = &self.current
            && p.id == id
        {
            return Ok(p.status());
        }
        self.history
            .iter()
            .find(|(h, _)| *h == id)
            .map(|(_, s)| s.clone())
            .ok_or(MembershipError::UnknownProposal { id })
    }

    fn ensure_live(&self, id: u64) -> Result<(), MembershipError> {
        if self.current.as_ref().is_some_and(|p| p.id == id) {
            return Ok(());
        }
        match self.history.iter().find(|(h, _)| *h == id) {
            Some((_, status)) => Err(MembershipError::NotPending {
                id,
                phase: status.phase(),
            }),
            None => Err(MembershipError::UnknownProposal { id }),
        }
    }

    fn finish(&mut self, id: u64, status: ProposalStatus) {
        if self.current.as_ref().is_some_and(|p| p.id == id) {
            self.current = None;
        }
        self.history.push_back((id, status));
        while self.history.len() > MAX_TERMINAL_HISTORY {
            self.history.pop_front();
        }
    }

    /// Propose a change. Nothing audible changes; the proposal is only recorded.
    pub fn propose(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        spec: ProposalSpec,
        now: GroupTime,
    ) -> Result<u64, MembershipError> {
        self.require_discovered()?;
        self.authorize(session, token, now.ns)?;
        if let Some(current) = &self.current {
            return Err(MembershipError::ProposalPending {
                pending: current.id,
            });
        }
        let mut participants: BTreeSet<String> = session.members.keys().cloned().collect();
        match &spec.change {
            MembershipChange::Join {
                member_id, board, ..
            } => {
                if session.members.contains_key(member_id) {
                    return Err(MembershipError::MemberAlreadyPresent {
                        member_id: member_id.clone(),
                    });
                }
                if self.unresolved_output.contains_key(member_id) {
                    return Err(MembershipError::OutputUnresolved {
                        member_id: member_id.clone(),
                    });
                }
                if board.verify_integrity().is_err() {
                    return Err(MembershipError::IneligibleBoard {
                        profile_id: board.profile_id.clone(),
                    });
                }
                if session.members.len() >= self.config.max_members {
                    return Err(MembershipError::GroupFull {
                        max: self.config.max_members,
                    });
                }
                participants.insert(member_id.clone());
            }
            MembershipChange::Leave { member_id } => {
                if !session.members.contains_key(member_id) {
                    return Err(MembershipError::UnknownMember {
                        member_id: member_id.clone(),
                    });
                }
            }
        }
        let earliest_frame = now
            .frame
            .saturating_add(self.config.min_cutover_lead_frames);
        if spec.cutover_frame < earliest_frame {
            return Err(MembershipError::CutoverTooSoon {
                cutover_frame: spec.cutover_frame,
                earliest_frame,
            });
        }
        if spec.ack_deadline_ns <= now.ns {
            return Err(MembershipError::AckDeadlineNotInFuture {
                ack_deadline_ns: spec.ack_deadline_ns,
                now_ns: now.ns,
            });
        }
        let id = self.next_proposal_id;
        self.next_proposal_id = self.next_proposal_id.saturating_add(1);
        self.current = Some(Proposal {
            id,
            change: spec.change,
            cutover_frame: spec.cutover_frame,
            ack_deadline_ns: spec.ack_deadline_ns,
            participants,
            acks: BTreeMap::new(),
            excluded: BTreeSet::new(),
            committed: false,
        });
        Ok(id)
    }

    /// Record one participant's readiness. A repeat of the same report is accepted; a different
    /// one is a conflict. After the deadline no new acknowledgement is accepted.
    pub fn ack(
        &mut self,
        proposal_id: u64,
        member_id: &str,
        report: ReadinessReport,
        now: GroupTime,
    ) -> Result<(), MembershipError> {
        self.ensure_live(proposal_id)?;
        let Some(p) = self.current.as_mut() else {
            return Err(MembershipError::UnknownProposal { id: proposal_id });
        };
        if p.committed {
            return Err(MembershipError::NotPending {
                id: proposal_id,
                phase: ProposalPhase::Committed,
            });
        }
        if !p.participants.contains(member_id) || p.excluded.contains(member_id) {
            return Err(MembershipError::NotAParticipant {
                member_id: member_id.to_string(),
            });
        }
        if let Some(previous) = p.acks.get(member_id) {
            return if *previous == report {
                Ok(())
            } else {
                Err(MembershipError::AckConflict {
                    member_id: member_id.to_string(),
                })
            };
        }
        if now.ns >= p.ack_deadline_ns {
            return Err(MembershipError::AckAfterDeadline {
                ack_deadline_ns: p.ack_deadline_ns,
                now_ns: now.ns,
            });
        }
        p.acks.insert(member_id.to_string(), report);
        Ok(())
    }

    /// Commit a proposal: every non-excluded participant has acknowledged and is ready, the cutover
    /// frame is still ahead, and it is not before any member's irrevocable output tail. The change
    /// still takes effect only at the cutover frame.
    pub fn commit(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        proposal_id: u64,
        now: GroupTime,
    ) -> Result<ProposalStatus, MembershipError> {
        self.require_discovered()?;
        self.authorize(session, token, now.ns)?;
        self.ensure_live(proposal_id)?;
        let Some(p) = self.current.as_mut() else {
            return Err(MembershipError::UnknownProposal { id: proposal_id });
        };
        if p.committed {
            return Err(MembershipError::NotPending {
                id: proposal_id,
                phase: ProposalPhase::Committed,
            });
        }
        let missing = p.missing();
        if !missing.is_empty() {
            return Err(MembershipError::MissingAcks { members: missing });
        }
        let not_ready: Vec<String> = p
            .required()
            .filter(|m| matches!(p.acks.get(m.as_str()), Some(r) if !r.is_ready()))
            .cloned()
            .collect();
        if !not_ready.is_empty() {
            return Err(MembershipError::MemberNotReady { members: not_ready });
        }
        if now.frame >= p.cutover_frame {
            return Err(MembershipError::CutoverPassed {
                cutover_frame: p.cutover_frame,
                now_frame: now.frame,
            });
        }
        let tail_complete_frame = p
            .required()
            .filter_map(|m| p.acks.get(m.as_str()))
            .map(|r| r.old_output_tail_complete_frame)
            .max()
            .unwrap_or(0);
        if p.cutover_frame < tail_complete_frame {
            return Err(MembershipError::CutoverBeforeOutputTail {
                cutover_frame: p.cutover_frame,
                tail_complete_frame,
            });
        }
        p.committed = true;
        Ok(p.status())
    }

    /// Cancel a proposal that has not activated. The session is untouched, so a cancelled join
    /// leaves existing playback exactly as it was.
    pub fn abort(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        proposal_id: u64,
        now: GroupTime,
    ) -> Result<ProposalStatus, MembershipError> {
        self.require_discovered()?;
        self.authorize(session, token, now.ns)?;
        self.ensure_live(proposal_id)?;
        let status = ProposalStatus::Aborted {
            reason: AbortReason::ByAuthority,
        };
        self.finish(proposal_id, status.clone());
        Ok(status)
    }

    /// Advance time: enforce the ack deadline, abort a proposal whose cutover frame arrived
    /// uncommitted, and activate a committed proposal whose cutover frame has been reached.
    /// Returns the proposals that settled during this call.
    pub fn tick(
        &mut self,
        session: &mut UnifiedGroupSession,
        now: GroupTime,
    ) -> Vec<(u64, ProposalStatus)> {
        let mut settled = Vec::new();
        let Some(mut p) = self.current.take() else {
            return settled;
        };
        let id = p.id;
        if p.committed {
            if now.frame < p.cutover_frame {
                self.current = Some(p);
                return settled;
            }
            let status = self.activate(session, &p);
            self.finish(id, status.clone());
            settled.push((id, status));
            return settled;
        }
        if now.frame >= p.cutover_frame {
            let status = ProposalStatus::Aborted {
                reason: AbortReason::CutoverMissed,
            };
            self.finish(id, status.clone());
            settled.push((id, status));
            return settled;
        }
        if now.ns >= p.ack_deadline_ns {
            let missing = p.missing();
            if !missing.is_empty() {
                let joiner_missing = matches!(
                    &p.change,
                    MembershipChange::Join { member_id, .. } if missing.contains(member_id)
                );
                if joiner_missing || self.config.missing_ack_policy == MissingAckPolicy::Abort {
                    let status = ProposalStatus::Aborted {
                        reason: AbortReason::AckDeadlineMissed { missing },
                    };
                    self.finish(id, status.clone());
                    settled.push((id, status));
                    return settled;
                }
                p.excluded.extend(missing);
            }
        }
        self.current = Some(p);
        settled
    }

    fn activate(&mut self, session: &mut UnifiedGroupSession, p: &Proposal) -> ProposalStatus {
        let remaining = session
            .members
            .keys()
            .filter(|m| !p.excluded.contains(*m))
            .count();
        let applicable = match &p.change {
            MembershipChange::Join { member_id, .. } => {
                !session.members.contains_key(member_id) && remaining < self.config.max_members
            }
            MembershipChange::Leave { member_id } => session.members.contains_key(member_id),
        };
        if !applicable {
            return ProposalStatus::Aborted {
                reason: AbortReason::PreconditionFailed,
            };
        }
        let mut remove: Vec<String> = p
            .excluded
            .iter()
            .filter(|m| session.members.contains_key(*m))
            .cloned()
            .collect();
        let join = match &p.change {
            MembershipChange::Join {
                member_id,
                board,
                role,
            } => Some((member_id.clone(), (**board).clone(), *role)),
            MembershipChange::Leave { member_id } => {
                if !p.excluded.contains(member_id) {
                    remove.push(member_id.clone());
                }
                None
            }
        };
        let revision = session.apply_membership_cutover(join, &remove);
        for member in &p.excluded {
            self.unresolved_output
                .insert(member.clone(), OutputBound::Unknown);
        }
        ProposalStatus::Activated {
            revision,
            excluded: p.excluded.iter().cloned().collect(),
        }
    }

    /// Move the group to a newer epoch. Only the configured issuer, presenting its current token,
    /// can do this; any proposal in flight is aborted, because its authority is superseded.
    pub fn advance_epoch(
        &mut self,
        session: &mut UnifiedGroupSession,
        token: &AuthorityToken,
        new_epoch: u64,
        now: GroupTime,
    ) -> Result<AuthorityToken, MembershipError> {
        self.require_discovered()?;
        if self.config.epoch_mint == EpochMint::Quorum {
            return Err(MembershipError::QuorumRequired);
        }
        self.authorize(session, token, now.ns)?;
        if new_epoch <= session.current_epoch {
            return Err(MembershipError::EpochNotAdvancing {
                requested: new_epoch,
                current: session.current_epoch,
            });
        }
        if let Some(p) = self.current.take() {
            self.finish(
                p.id,
                ProposalStatus::Aborted {
                    reason: AbortReason::EpochAdvanced,
                },
            );
        }
        session.begin_epoch(new_epoch);
        Ok(AuthorityToken::issue(session, token.expires_at_ns))
    }

    /// Extend the holder's own lease to what a voter quorum acknowledged. The holder must still be
    /// live: once its lease has lapsed (by its conservative reading) it cannot be renewed, because
    /// the majority may already be taking over; it has to win a new epoch instead.
    pub fn renew_lease(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        win: &LeaseWin,
        now: GroupTime,
    ) -> Result<AuthorityToken, MembershipError> {
        self.require_quorum_group()?;
        self.require_discovered()?;
        self.authorize(session, token, now.ns)?;
        if win.kind != LeaseRequestKind::Renew
            || win.group_id != token.group_id
            || win.requester != token.issuer_id
            || win.epoch != token.epoch
        {
            return Err(MembershipError::WinNotApplicable);
        }
        if win.expires_at_ns <= token.expires_at_ns {
            return Err(MembershipError::LeaseNotExtended {
                expires_at_ns: win.expires_at_ns,
                current_ns: token.expires_at_ns,
            });
        }
        let max_ns = now.ns.saturating_add(self.config.lease.max_lease_ns);
        if win.expires_at_ns > max_ns {
            return Err(MembershipError::LeaseTooLong {
                expires_at_ns: win.expires_at_ns,
                max_ns,
            });
        }
        Ok(AuthorityToken {
            expires_at_ns: win.expires_at_ns,
            ..token.clone()
        })
    }

    /// Become the group's issuer for the epoch a voter quorum granted. The previous holder's
    /// session state is not touched here; it is fenced by epoch wherever the new epoch is known.
    /// Any proposal in flight under the old authority is aborted, and conflicting programs stay
    /// gated until the previous term's already-granted output can no longer sound.
    pub fn assume_authority(
        &mut self,
        session: &mut UnifiedGroupSession,
        win: &LeaseWin,
        now: GroupTime,
    ) -> Result<AuthorityToken, MembershipError> {
        self.require_quorum_group()?;
        self.require_discovered()?;
        if win.kind != LeaseRequestKind::Takeover || win.group_id != session.group_id {
            return Err(MembershipError::WinNotApplicable);
        }
        if win.epoch <= session.current_epoch {
            return Err(MembershipError::StaleAuthority {
                token_epoch: win.epoch,
                current_epoch: session.current_epoch,
            });
        }
        let margin = self.config.lease.clock_uncertainty_ns;
        if now.ns.saturating_add(margin) >= win.expires_at_ns {
            return Err(MembershipError::AuthorityExpired {
                expires_at_ns: win.expires_at_ns,
                now_ns: now.ns,
            });
        }
        if let Some(p) = self.current.take() {
            self.finish(
                p.id,
                ProposalStatus::Aborted {
                    reason: AbortReason::EpochAdvanced,
                },
            );
        }
        session.coordinator_id.clone_from(&win.requester);
        session.begin_epoch(win.epoch);
        // Output the previous holder granted can sound for its horizon after its last lease expired.
        self.takeover_gate_until_ns = Some(
            win.prior_expires_at_ns
                .saturating_add(self.config.lease.max_output_horizon_ns)
                .saturating_add(margin),
        );
        Ok(AuthorityToken {
            group_id: session.group_id.clone(),
            issuer_id: win.requester.clone(),
            epoch: win.epoch,
            expires_at_ns: win.expires_at_ns,
        })
    }

    /// Learn that a newer epoch has a holder (an announcement, or the first message of the new term).
    /// A node that was the old holder stops being able to act the moment it adopts. Two different
    /// holders for one epoch can only come from a protocol violation and is reported as a conflict.
    pub fn adopt_authority(
        &mut self,
        session: &mut UnifiedGroupSession,
        view: &LeaseView,
    ) -> Result<(), MembershipError> {
        self.require_quorum_group()?;
        if view.group_id != session.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if view.epoch < session.current_epoch {
            return Err(MembershipError::StaleAuthority {
                token_epoch: view.epoch,
                current_epoch: session.current_epoch,
            });
        }
        if view.epoch == session.current_epoch {
            return if view.holder == session.coordinator_id {
                // Learning who holds the epoch is how a restarted follower rediscovers authority.
                self.authority_discovered = true;
                Ok(())
            } else {
                Err(MembershipError::ConflictingLeaders {
                    epoch: view.epoch,
                    held_by: session.coordinator_id.clone(),
                    announced_by: view.holder.clone(),
                })
            };
        }
        if let Some(p) = self.current.take() {
            self.finish(
                p.id,
                ProposalStatus::Aborted {
                    reason: AbortReason::EpochAdvanced,
                },
            );
        }
        session.coordinator_id.clone_from(&view.holder);
        session.begin_epoch(view.epoch);
        self.authority_discovered = true;
        Ok(())
    }

    /// Authorise `member_id` to sound output through (not including) `through_frame`. Needs a live
    /// lease. Grants are bounded by a horizon and only ever extend, so when a lease lapses the
    /// member plays out exactly what it was already granted and then mutes; nothing new is issued
    /// without a live lease.
    pub fn grant_output(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        member_id: &str,
        through_frame: u64,
        now: GroupTime,
    ) -> Result<u64, MembershipError> {
        self.require_discovered()?;
        self.authorize(session, token, now.ns)?;
        if !session.members.contains_key(member_id) {
            return Err(MembershipError::UnknownMember {
                member_id: member_id.to_string(),
            });
        }
        let max_frame = now
            .frame
            .saturating_add(self.config.max_output_horizon_frames);
        if through_frame > max_frame {
            return Err(MembershipError::OutputHorizonExceeded {
                requested_frame: through_frame,
                max_frame,
            });
        }
        let granted = self.output_grants.entry(member_id.to_string()).or_insert(0);
        *granted = (*granted).max(through_frame);
        Ok(*granted)
    }

    /// May `member_id` sound the sample at `frame`? Only below a frame it was granted.
    #[must_use]
    pub fn output_permitted(&self, member_id: &str, frame: u64) -> bool {
        self.output_grants
            .get(member_id)
            .is_some_and(|through| frame < *through)
    }

    /// After a takeover, may a program that conflicts with the previous term's output start at
    /// `now_ns` (this node's clock)? `Err` carries the instant it may. A node that never took over
    /// has no gate.
    pub fn takeover_start_gate(&self, now_ns: u64) -> Result<(), u64> {
        match self.takeover_gate_until_ns {
            Some(until) if now_ns < until => Err(until),
            _ => Ok(()),
        }
    }

    /// Members excluded from a cutover whose earlier output is not yet shown to have ended.
    #[must_use]
    pub fn unresolved_output(&self) -> Vec<String> {
        self.unresolved_output.keys().cloned().collect()
    }

    /// Record evidence about an excluded member's earlier output: a stop acknowledgement, or a
    /// conservative bound after which it cannot sound. A later bound replaces an earlier one only
    /// if it is later, so evidence can never shorten what was already required.
    pub fn resolve_output(
        &mut self,
        member_id: &str,
        resolution: OutputResolution,
    ) -> Result<(), MembershipError> {
        let Some(existing) = self.unresolved_output.get(member_id).copied() else {
            return Err(MembershipError::NoUnresolvedOutput {
                member_id: member_id.to_string(),
            });
        };
        match resolution {
            OutputResolution::StopAcknowledged => {
                self.unresolved_output.remove(member_id);
            }
            OutputResolution::ExpiresAtFrame(frame) => {
                let bound = match existing {
                    OutputBound::ExpiresAtFrame(previous) => previous.max(frame),
                    OutputBound::Unknown => frame,
                };
                self.unresolved_output
                    .insert(member_id.to_string(), OutputBound::ExpiresAtFrame(bound));
            }
        }
        Ok(())
    }

    /// May a program that conflicts with earlier output under this group identity start at
    /// `now_frame`? Not while any excluded member's output is unbounded or its bound lies ahead.
    /// Exclusion or removal from the group is never evidence that a member has stopped sounding.
    pub fn conflicting_start_gate(&self, now_frame: u64) -> Result<(), Vec<String>> {
        let blocked: Vec<String> = self
            .unresolved_output
            .iter()
            .filter(|(_, bound)| match bound {
                OutputBound::Unknown => true,
                OutputBound::ExpiresAtFrame(frame) => now_frame < *frame,
            })
            .map(|(member, _)| member.clone())
            .collect();
        if blocked.is_empty() {
            Ok(())
        } else {
            Err(blocked)
        }
    }
}

impl UnifiedGroupSession {
    /// Apply an activated membership change in one step and bump `state_revision` once.
    pub(crate) fn apply_membership_cutover(
        &mut self,
        join: Option<(String, BoardProfile, ChannelRole)>,
        remove: &[String],
    ) -> u64 {
        for member_id in remove {
            self.members.remove(member_id);
        }
        if let Some((member_id, board, role)) = join {
            self.members.insert(
                member_id.clone(),
                GroupMemberState {
                    member_id,
                    profile_id: board.profile_id,
                    legacy_sw_gen_hint: board.legacy_sw_gen_hint,
                    role,
                    volume_0_to_100: 50,
                    muted: false,
                    // The joiner validated clock confidence in its readiness report before commit.
                    lifecycle: MemberLifecycleState::SynchronizedReady,
                },
            );
        }
        self.state_revision = self.state_revision.saturating_add(1);
        self.state_revision
    }

    /// Adopt a newer epoch minted by the issuer. The command record belongs to the old epoch.
    pub(crate) fn begin_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
        self.applied_commands = crate::AppliedCommands::default();
        self.state_revision = self.state_revision.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FencedControlCommand, GroupCommandPayload, SessionError};

    fn fixture(model: &str) -> BoardProfile {
        franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == model)
            .expect("fixture model present")
    }

    fn hypothesis() -> BoardProfile {
        franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .expect("hypothesis model present")
    }

    /// Epoch 1, issuer `coord`, members `a` (S5) and `b` (S12), state revision 2.
    fn session() -> UnifiedGroupSession {
        session_for("coord")
    }

    /// As [`session`], with `issuer` as the configured issuer.
    fn session_for(issuer: &str) -> UnifiedGroupSession {
        let mut s = UnifiedGroupSession::new("grp", issuer, 1);
        for (seq, (id, model)) in [("a", "S5"), ("b", "S12")].into_iter().enumerate() {
            s.apply_command(FencedControlCommand {
                epoch: 1,
                command_seq: seq as u64 + 1,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: id.to_string(),
                    board: fixture(model),
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();
        }
        s
    }

    fn t(ns: u64, frame: u64) -> GroupTime {
        GroupTime { ns, frame }
    }

    fn token(s: &UnifiedGroupSession) -> AuthorityToken {
        AuthorityToken::issue(s, 1_000_000_000)
    }

    fn ready(tail: u64) -> ReadinessReport {
        ReadinessReport {
            format_ok: true,
            buffer_ok: true,
            clock_confident: true,
            can_stop_flush: true,
            old_output_tail_complete_frame: tail,
        }
    }

    fn join(id: &str, model: &str, cutover_frame: u64, ack_deadline_ns: u64) -> ProposalSpec {
        ProposalSpec {
            change: MembershipChange::Join {
                member_id: id.to_string(),
                board: Box::new(fixture(model)),
                role: ChannelRole::Stereo,
            },
            cutover_frame,
            ack_deadline_ns,
        }
    }

    fn leave(id: &str, cutover_frame: u64, ack_deadline_ns: u64) -> ProposalSpec {
        ProposalSpec {
            change: MembershipChange::Leave {
                member_id: id.to_string(),
            },
            cutover_frame,
            ack_deadline_ns,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn fingerprint(m: &GroupMembership, s: &UnifiedGroupSession) -> String {
        format!("{m:?}|{s:?}")
    }

    fn keys(s: &UnifiedGroupSession) -> Vec<String> {
        s.members.keys().cloned().collect()
    }

    /// Everyone acknowledges the join of `c` (`a` and `b` with the given tails).
    fn ack_join(m: &mut GroupMembership, id: u64, tail_a: u64, tail_b: u64) {
        m.ack(id, "a", ready(tail_a), t(1_100, 10_100)).unwrap();
        m.ack(id, "b", ready(tail_b), t(1_100, 10_100)).unwrap();
        m.ack(id, "c", ready(0), t(1_100, 10_100)).unwrap();
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

    #[test]
    fn a_join_changes_nothing_audible_until_its_cutover_frame_and_then_exactly_once() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let members_before = s.members.clone();
        assert_eq!(s.state_revision, 2);

        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Pending {
                acked: vec![],
                missing: strings(&["a", "b", "c"]),
                excluded: vec![]
            })
        );
        m.ack(id, "a", ready(99_000), t(1_100, 10_100)).unwrap();
        m.ack(id, "b", ready(98_000), t(1_100, 10_100)).unwrap();
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Pending {
                acked: strings(&["a", "b"]),
                missing: strings(&["c"]),
                excluded: vec![]
            })
        );
        m.ack(id, "c", ready(0), t(1_200, 10_200)).unwrap();
        assert_eq!(
            m.commit(&s, &tok, id, t(1_300, 10_300)),
            Ok(ProposalStatus::Committed {
                activate_at_frame: 100_000,
                excluded: vec![]
            })
        );

        // Proposing, acknowledging and committing left the audible state exactly as it was.
        assert_eq!(s.members, members_before);
        assert_eq!(s.state_revision, 2);
        assert!(m.tick(&mut s, t(1_400, 99_999)).is_empty());
        assert_eq!(s.members, members_before);

        // At the cutover frame it activates, once.
        assert_eq!(
            m.tick(&mut s, t(1_500, 100_000)),
            vec![(
                1,
                ProposalStatus::Activated {
                    revision: 3,
                    excluded: vec![]
                }
            )]
        );
        assert_eq!(keys(&s), strings(&["a", "b", "c"]));
        assert_eq!(
            s.members["c"].lifecycle,
            MemberLifecycleState::SynchronizedReady
        );
        assert_eq!(s.members["a"], members_before["a"]);
        assert_eq!(s.state_revision, 3);
        assert!(m.tick(&mut s, t(1_600, 200_000)).is_empty());
        assert_eq!(s.state_revision, 3, "no second activation");
        assert_eq!(m.pending_proposal(), None);
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Activated {
                revision: 3,
                excluded: vec![]
            })
        );
    }

    #[test]
    fn a_leave_removes_the_member_only_at_its_cutover_frame() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, leave("b", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(id, "a", ready(0), t(1_100, 10_100)).unwrap();
        m.ack(id, "b", ready(99_500), t(1_100, 10_100)).unwrap();
        m.commit(&s, &tok, id, t(1_200, 10_200)).unwrap();
        assert_eq!(
            s.members, before,
            "the leaver keeps sounding until the cutover"
        );
        assert!(m.tick(&mut s, t(1_300, 99_999)).is_empty());
        let settled = m.tick(&mut s, t(1_400, 100_000));
        assert_eq!(
            settled,
            vec![(
                1,
                ProposalStatus::Activated {
                    revision: 3,
                    excluded: vec![]
                }
            )]
        );
        assert_eq!(keys(&s), strings(&["a"]));
        assert_eq!(s.members["a"], before["a"]);
        assert!(
            m.unresolved_output().is_empty(),
            "a leaver that acknowledged its tail leaves no unresolved output"
        );
    }

    #[test]
    fn every_mutation_refuses_a_token_that_is_not_current_and_changes_nothing() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let good = token(&s);
        let now = t(1_000, 10_000);
        let bad = [
            (
                AuthorityToken {
                    group_id: "other".to_string(),
                    ..good.clone()
                },
                MembershipError::WrongGroup,
            ),
            (
                AuthorityToken {
                    issuer_id: "intruder".to_string(),
                    ..good.clone()
                },
                MembershipError::NotConfiguredIssuer,
            ),
            (
                AuthorityToken {
                    epoch: 9,
                    ..good.clone()
                },
                MembershipError::FutureAuthority {
                    token_epoch: 9,
                    current_epoch: 1,
                },
            ),
            (
                AuthorityToken {
                    expires_at_ns: 1_000,
                    ..good.clone()
                },
                MembershipError::AuthorityExpired {
                    expires_at_ns: 1_000,
                    now_ns: 1_000,
                },
            ),
        ];
        for (token, expected) in bad {
            let before = fingerprint(&m, &s);
            assert_eq!(
                m.propose(&s, &token, join("c", "S1", 100_000, 2_000), now),
                Err(expected.clone())
            );
            assert_eq!(
                m.advance_epoch(&mut s, &token, 2, now).err(),
                Some(expected)
            );
            assert_eq!(fingerprint(&m, &s), before, "a refusal must change nothing");
        }
        // After a legitimate epoch advance, the old token is stale and the new one is current.
        let fresh = m.advance_epoch(&mut s, &good, 2, now).unwrap();
        assert_eq!(fresh.epoch, 2);
        assert_eq!(
            m.propose(&s, &good, join("c", "S1", 100_000, 2_000), now),
            Err(MembershipError::StaleAuthority {
                token_epoch: 1,
                current_epoch: 2
            })
        );
        assert!(
            m.propose(&s, &fresh, join("c", "S1", 100_000, 2_000), now)
                .is_ok()
        );
    }

    #[test]
    fn a_commit_under_a_stale_epoch_is_refused_and_the_epoch_advance_aborted_the_proposal() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok1 = token(&s);
        let id = m
            .propose(&s, &tok1, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        ack_join(&mut m, id, 0, 0);

        let tok2 = m.advance_epoch(&mut s, &tok1, 2, t(1_300, 10_300)).unwrap();
        assert_eq!((s.current_epoch, s.state_revision), (2, 3));
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::EpochAdvanced
            })
        );
        assert_eq!(
            m.commit(&s, &tok1, id, t(1_400, 10_400)),
            Err(MembershipError::StaleAuthority {
                token_epoch: 1,
                current_epoch: 2
            })
        );
        assert_eq!(
            m.commit(&s, &tok2, id, t(1_400, 10_400)),
            Err(MembershipError::NotPending {
                id,
                phase: ProposalPhase::Aborted
            })
        );
        assert_eq!(keys(&s), strings(&["a", "b"]), "c never joined");

        assert_eq!(
            m.advance_epoch(&mut s, &tok2, 2, t(1_500, 10_500)).err(),
            Some(MembershipError::EpochNotAdvancing {
                requested: 2,
                current: 2
            })
        );
        // A token that claims a newer epoch than the group's cannot mint one: followers never do.
        let forged = AuthorityToken {
            epoch: 5,
            ..tok2.clone()
        };
        assert_eq!(
            m.advance_epoch(&mut s, &forged, 6, t(1_500, 10_500)).err(),
            Some(MembershipError::FutureAuthority {
                token_epoch: 5,
                current_epoch: 2
            })
        );
        assert_eq!(s.current_epoch, 2);

        // The session fences the old epoch's commands too, and its command record was reset:
        // epoch 2 sequence 1 is fresh even though epoch 1 already used sequence 1.
        let old = FencedControlCommand {
            epoch: 1,
            command_seq: 99,
            payload: GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: 10,
            },
        };
        assert_eq!(
            s.apply_command(old),
            Err(SessionError::StaleEpoch {
                command_epoch: 1,
                current_epoch: 2
            })
        );
        let fresh = FencedControlCommand {
            epoch: 2,
            command_seq: 1,
            payload: GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: 10,
            },
        };
        assert_eq!(s.apply_command(fresh.clone()), Ok(4));
        assert_eq!(
            s.apply_command(fresh),
            Err(SessionError::DuplicateCommand {
                epoch: 2,
                command_seq: 1
            })
        );
    }

    #[test]
    fn a_missing_ack_blocks_the_commit_then_the_deadline_aborts_without_holding_the_group() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(id, "a", ready(0), t(1_100, 10_100)).unwrap();
        m.ack(id, "c", ready(0), t(1_100, 10_100)).unwrap();

        assert_eq!(
            m.commit(&s, &tok, id, t(1_500, 10_500)),
            Err(MembershipError::MissingAcks {
                members: strings(&["b"])
            })
        );
        assert!(m.tick(&mut s, t(1_999, 10_600)).is_empty());
        assert_eq!(
            m.ack(id, "b", ready(0), t(2_000, 10_700)),
            Err(MembershipError::AckAfterDeadline {
                ack_deadline_ns: 2_000,
                now_ns: 2_000
            })
        );
        assert_eq!(
            m.tick(&mut s, t(2_000, 10_700)),
            vec![(
                1,
                ProposalStatus::Aborted {
                    reason: AbortReason::AckDeadlineMissed {
                        missing: strings(&["b"])
                    }
                }
            )]
        );
        assert_eq!(s.members, before);
        assert_eq!(s.state_revision, 2);
        // The group is free to try again immediately.
        assert_eq!(m.pending_proposal(), None);
        assert!(
            m.propose(&s, &tok, join("c", "S1", 100_000, 4_000), t(2_100, 10_800))
                .is_ok()
        );
    }

    #[test]
    fn excluding_an_unreachable_member_continues_the_cutover_but_leaves_its_output_unresolved() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig {
            missing_ack_policy: MissingAckPolicy::ExcludeUnreachable,
            ..MembershipConfig::default()
        });
        let tok = token(&s);
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(id, "a", ready(99_000), t(1_100, 10_100)).unwrap();
        m.ack(id, "c", ready(0), t(1_100, 10_100)).unwrap();
        assert!(m.tick(&mut s, t(2_000, 10_700)).is_empty());
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Pending {
                acked: strings(&["a", "c"]),
                missing: vec![],
                excluded: strings(&["b"])
            })
        );
        // The excluded member is no longer a participant: its late ack is refused.
        assert_eq!(
            m.ack(id, "b", ready(0), t(2_100, 10_800)),
            Err(MembershipError::NotAParticipant {
                member_id: "b".to_string()
            })
        );
        assert_eq!(
            m.commit(&s, &tok, id, t(2_200, 10_900)),
            Ok(ProposalStatus::Committed {
                activate_at_frame: 100_000,
                excluded: strings(&["b"])
            })
        );
        assert_eq!(
            keys(&s),
            strings(&["a", "b"]),
            "b is removed only at the cutover"
        );
        assert_eq!(
            m.tick(&mut s, t(2_300, 100_000)),
            vec![(
                1,
                ProposalStatus::Activated {
                    revision: 3,
                    excluded: strings(&["b"])
                }
            )]
        );
        assert_eq!(keys(&s), strings(&["a", "c"]));

        // Removal is not evidence that b stopped sounding: a conflicting start is refused.
        assert_eq!(m.unresolved_output(), strings(&["b"]));
        assert_eq!(m.conflicting_start_gate(u64::MAX), Err(strings(&["b"])));
        // b cannot be re-admitted while its earlier output is unresolved.
        assert_eq!(
            m.propose(
                &s,
                &tok,
                join("b", "S12", 300_000, 5_000),
                t(2_400, 100_100)
            ),
            Err(MembershipError::OutputUnresolved {
                member_id: "b".to_string()
            })
        );
        // A conservative expiry bound lifts the gate only once it has passed...
        m.resolve_output("b", OutputResolution::ExpiresAtFrame(120_000))
            .unwrap();
        assert_eq!(m.conflicting_start_gate(119_999), Err(strings(&["b"])));
        assert_eq!(m.conflicting_start_gate(120_000), Ok(()));
        // ...and later evidence can never shorten a bound that was already required.
        m.resolve_output("b", OutputResolution::ExpiresAtFrame(110_000))
            .unwrap();
        assert_eq!(m.conflicting_start_gate(119_999), Err(strings(&["b"])));
        // A stop acknowledgement resolves it at once.
        m.resolve_output("b", OutputResolution::StopAcknowledged)
            .unwrap();
        assert_eq!(m.conflicting_start_gate(0), Ok(()));
        assert!(m.unresolved_output().is_empty());
        assert_eq!(
            m.resolve_output("b", OutputResolution::StopAcknowledged),
            Err(MembershipError::NoUnresolvedOutput {
                member_id: "b".to_string()
            })
        );
    }

    #[test]
    fn a_missing_joiner_always_aborts_even_when_unreachable_members_are_excluded() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig {
            missing_ack_policy: MissingAckPolicy::ExcludeUnreachable,
            ..MembershipConfig::default()
        });
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(id, "a", ready(0), t(1_100, 10_100)).unwrap();
        m.ack(id, "b", ready(0), t(1_100, 10_100)).unwrap();
        assert_eq!(
            m.tick(&mut s, t(2_000, 10_700)),
            vec![(
                1,
                ProposalStatus::Aborted {
                    reason: AbortReason::AckDeadlineMissed {
                        missing: strings(&["c"])
                    }
                }
            )]
        );
        assert_eq!(s.members, before);
        assert!(m.unresolved_output().is_empty());
    }

    #[test]
    fn duplicate_commits_conflicting_acks_and_strangers_are_refused() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(id, "a", ready(5), t(1_100, 10_100)).unwrap();
        // The identical acknowledgement again is idempotent; a different one is a conflict.
        assert_eq!(m.ack(id, "a", ready(5), t(1_150, 10_150)), Ok(()));
        assert_eq!(
            m.ack(id, "a", ready(6), t(1_150, 10_150)),
            Err(MembershipError::AckConflict {
                member_id: "a".to_string()
            })
        );
        assert_eq!(
            m.ack(id, "zed", ready(0), t(1_150, 10_150)),
            Err(MembershipError::NotAParticipant {
                member_id: "zed".to_string()
            })
        );
        assert_eq!(
            m.ack(9, "a", ready(0), t(1_150, 10_150)),
            Err(MembershipError::UnknownProposal { id: 9 })
        );
        m.ack(id, "b", ready(0), t(1_200, 10_200)).unwrap();
        m.ack(id, "c", ready(0), t(1_200, 10_200)).unwrap();

        assert!(m.commit(&s, &tok, id, t(1_300, 10_300)).is_ok());
        let after_first = fingerprint(&m, &s);
        assert_eq!(
            m.commit(&s, &tok, id, t(1_301, 10_301)),
            Err(MembershipError::NotPending {
                id,
                phase: ProposalPhase::Committed
            })
        );
        assert_eq!(
            m.ack(id, "a", ready(5), t(1_302, 10_302)),
            Err(MembershipError::NotPending {
                id,
                phase: ProposalPhase::Committed
            })
        );
        assert_eq!(
            fingerprint(&m, &s),
            after_first,
            "duplicates change nothing"
        );

        m.tick(&mut s, t(1_400, 100_000));
        assert_eq!(
            m.commit(&s, &tok, id, t(1_401, 100_001)),
            Err(MembershipError::NotPending {
                id,
                phase: ProposalPhase::Activated
            })
        );
        assert_eq!(
            m.abort(&s, &tok, id, t(1_402, 100_002)),
            Err(MembershipError::NotPending {
                id,
                phase: ProposalPhase::Activated
            })
        );
        assert_eq!(s.state_revision, 3, "activation happened exactly once");
    }

    #[test]
    fn the_cutover_may_not_precede_any_members_irrevocable_output_tail() {
        let s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        ack_join(&mut m, id, 120_000, 0);
        assert_eq!(
            m.commit(&s, &tok, id, t(1_300, 10_300)),
            Err(MembershipError::CutoverBeforeOutputTail {
                cutover_frame: 100_000,
                tail_complete_frame: 120_000
            })
        );
        assert!(matches!(m.status(id), Ok(ProposalStatus::Pending { .. })));
        m.abort(&s, &tok, id, t(1_400, 10_400)).unwrap();

        // The tail is exactly the frame the cutover may use: a boundary, paired with the refusal.
        let id = m
            .propose(&s, &tok, join("c", "S1", 120_000, 4_000), t(1_500, 10_500))
            .unwrap();
        ack_join(&mut m, id, 120_000, 0);
        assert!(m.commit(&s, &tok, id, t(1_600, 10_600)).is_ok());
    }

    #[test]
    fn a_commit_at_or_after_the_cutover_frame_is_refused_and_an_uncommitted_proposal_lapses() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        ack_join(&mut m, id, 0, 0);
        assert_eq!(
            m.commit(&s, &tok, id, t(1_500, 100_000)),
            Err(MembershipError::CutoverPassed {
                cutover_frame: 100_000,
                now_frame: 100_000
            })
        );
        // Nobody is held waiting for an authority that never commits.
        assert_eq!(
            m.tick(&mut s, t(1_500, 100_000)),
            vec![(
                1,
                ProposalStatus::Aborted {
                    reason: AbortReason::CutoverMissed
                }
            )]
        );
        assert_eq!(s.members, before);
        assert_eq!(s.state_revision, 2);
    }

    #[test]
    fn a_member_that_is_not_ready_blocks_the_commit_and_cancelling_leaves_playback_intact() {
        let s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        m.ack(
            id,
            "a",
            ReadinessReport {
                can_stop_flush: false,
                ..ready(0)
            },
            t(1_100, 10_100),
        )
        .unwrap();
        m.ack(id, "b", ready(0), t(1_100, 10_100)).unwrap();
        m.ack(
            id,
            "c",
            ReadinessReport {
                clock_confident: false,
                ..ready(0)
            },
            t(1_100, 10_100),
        )
        .unwrap();
        assert_eq!(
            m.commit(&s, &tok, id, t(1_200, 10_200)),
            Err(MembershipError::MemberNotReady {
                members: strings(&["a", "c"])
            })
        );
        assert_eq!(
            m.abort(&s, &tok, id, t(1_300, 10_300)),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::ByAuthority
            })
        );
        assert_eq!(s.members, before);
        assert_eq!(s.state_revision, 2);
    }

    #[test]
    fn cancelling_a_committed_join_before_its_frame_leaves_the_group_untouched() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let before = s.members.clone();
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        ack_join(&mut m, id, 0, 0);
        m.commit(&s, &tok, id, t(1_200, 10_200)).unwrap();
        assert_eq!(
            m.abort(&s, &tok, id, t(1_300, 50_000)),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::ByAuthority
            })
        );
        assert!(m.tick(&mut s, t(1_400, 100_000)).is_empty());
        assert_eq!(s.members, before);
        assert_eq!(s.state_revision, 2);
    }

    #[test]
    fn one_change_at_a_time_and_every_precondition_is_checked_before_anything_is_recorded() {
        let s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let now = t(1_000, 10_000);

        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), now)
            .unwrap();
        assert_eq!(
            m.propose(&s, &tok, leave("a", 100_000, 2_000), now),
            Err(MembershipError::ProposalPending { pending: id })
        );
        m.abort(&s, &tok, id, now).unwrap();

        let refusals = [
            (
                join("a", "S1", 100_000, 2_000),
                MembershipError::MemberAlreadyPresent {
                    member_id: "a".to_string(),
                },
            ),
            (
                ProposalSpec {
                    change: MembershipChange::Join {
                        member_id: "c".to_string(),
                        board: Box::new(hypothesis()),
                        role: ChannelRole::Stereo,
                    },
                    cutover_frame: 100_000,
                    ack_deadline_ns: 2_000,
                },
                MembershipError::IneligibleBoard {
                    profile_id: hypothesis().profile_id,
                },
            ),
            (
                leave("zed", 100_000, 2_000),
                MembershipError::UnknownMember {
                    member_id: "zed".to_string(),
                },
            ),
            (
                join("c", "S1", 14_799, 2_000),
                MembershipError::CutoverTooSoon {
                    cutover_frame: 14_799,
                    earliest_frame: 14_800,
                },
            ),
            (
                join("c", "S1", 100_000, 1_000),
                MembershipError::AckDeadlineNotInFuture {
                    ack_deadline_ns: 1_000,
                    now_ns: 1_000,
                },
            ),
        ];
        for (spec, expected) in refusals {
            let before = fingerprint(&m, &s);
            assert_eq!(m.propose(&s, &tok, spec, now), Err(expected));
            assert_eq!(fingerprint(&m, &s), before);
        }
        // The boundary just inside is accepted.
        assert!(
            m.propose(&s, &tok, join("c", "S1", 14_800, 2_000), now)
                .is_ok()
        );

        // A full group refuses a join.
        let mut small = GroupMembership::new(MembershipConfig {
            max_members: 2,
            ..MembershipConfig::default()
        });
        assert_eq!(
            small.propose(&s, &tok, join("c", "S1", 100_000, 2_000), now),
            Err(MembershipError::GroupFull { max: 2 })
        );
    }

    #[test]
    fn only_stable_intent_is_persisted_and_a_restart_must_rediscover_authority() {
        let mut s = session();
        let mut live = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        // Volatile state exists: an in-flight proposal, a volume and a lease.
        let _ = live
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        s.apply_command(FencedControlCommand {
            epoch: 1,
            command_seq: 3,
            payload: GroupCommandPayload::SetMemberVolume {
                member_id: "a".to_string(),
                volume_0_to_100: 7,
            },
        })
        .unwrap();

        let intent = GroupMembership::stable_intent(&s);
        let json = serde_json::to_value(&intent).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            ["group_id", "issuer_id", "members"]
        );
        let member = json["members"][0].as_object().unwrap();
        assert_eq!(
            member.keys().map(String::as_str).collect::<Vec<_>>(),
            ["member_id", "profile_id", "role"]
        );
        let text = json.to_string();
        for volatile in [
            "epoch",
            "lease",
            "expires",
            "proposal",
            "lifecycle",
            "volume",
            "revision",
        ] {
            assert!(
                !text.contains(volatile),
                "persisted intent mentions `{volatile}`: {text}"
            );
        }
        let back: MembershipIntent = serde_json::from_value(json).unwrap();
        assert_eq!(back, intent);

        // A restored intent is a list of members to re-admit, not a live session.
        let fresh = UnifiedGroupSession::new("grp", "coord", 1);
        assert!(fresh.members.is_empty());
        assert_eq!(back.members_missing_from(&fresh), strings(&["a", "b"]));

        // After a restart nothing may be mutated until the authority has been rediscovered.
        let mut restarted = GroupMembership::after_restart(MembershipConfig::default());
        let mut fresh = session();
        let now = t(5_000, 20_000);
        let tok = token(&fresh);
        let refused = MembershipError::AuthorityNotDiscovered;
        assert_eq!(
            restarted.propose(&fresh, &tok, join("c", "S1", 100_000, 6_000), now),
            Err(refused.clone())
        );
        assert_eq!(restarted.commit(&fresh, &tok, 1, now), Err(refused.clone()));
        assert_eq!(restarted.abort(&fresh, &tok, 1, now), Err(refused.clone()));
        assert_eq!(
            restarted.advance_epoch(&mut fresh, &tok, 2, now).err(),
            Some(refused)
        );
        // A stale token cannot rediscover authority; the current one can.
        let stale = AuthorityToken {
            epoch: 0,
            ..tok.clone()
        };
        assert_eq!(
            restarted.discover_authority(&fresh, &stale, now.ns),
            Err(MembershipError::StaleAuthority {
                token_epoch: 0,
                current_epoch: 1
            })
        );
        restarted.discover_authority(&fresh, &tok, now.ns).unwrap();
        assert!(
            restarted
                .propose(&fresh, &tok, join("c", "S1", 100_000, 6_000), now)
                .is_ok()
        );
    }

    #[test]
    fn terminal_results_are_kept_for_reconciliation_but_the_history_is_bounded() {
        let s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let now = t(1_000, 10_000);
        for _ in 0..80 {
            let id = m
                .propose(&s, &tok, join("c", "S1", 100_000, 2_000), now)
                .unwrap();
            m.abort(&s, &tok, id, now).unwrap();
        }
        assert_eq!(m.history.len(), MAX_TERMINAL_HISTORY);
        assert_eq!(
            m.status(1),
            Err(MembershipError::UnknownProposal { id: 1 }),
            "the oldest results are forgotten, explicitly"
        );
        assert_eq!(
            m.status(80),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::ByAuthority
            })
        );
        assert_eq!(
            m.status(17),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::ByAuthority
            }),
            "80 - 64 + 1 = 17 is the oldest one still kept"
        );
        assert_eq!(
            m.status(16),
            Err(MembershipError::UnknownProposal { id: 16 })
        );
    }

    #[test]
    fn membership_activation_is_independent_of_the_command_record_and_bumps_the_revision() {
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig::default());
        let tok = token(&s);
        let id = m
            .propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(1_000, 10_000))
            .unwrap();
        ack_join(&mut m, id, 0, 0);
        m.commit(&s, &tok, id, t(1_200, 10_200)).unwrap();
        m.tick(&mut s, t(1_300, 100_000));
        assert_eq!(s.state_revision, 3);

        // Commands keep their own numbering: sequence 3 is next and is unaffected by the cutover.
        let command = FencedControlCommand {
            epoch: 1,
            command_seq: 3,
            payload: GroupCommandPayload::SetMemberVolume {
                member_id: "c".to_string(),
                volume_0_to_100: 80,
            },
        };
        assert_eq!(s.apply_command(command), Ok(4));
        assert_eq!(s.members["c"].volume_0_to_100, 80);
    }

    #[test]
    fn seeded_schedules_keep_every_membership_invariant() {
        let mut activated = 0;
        let mut aborted = 0;
        let mut excluded_total = 0;
        let mut exclusion_seeds = 0;
        for seed in 0..8_u64 {
            let counts = run_schedule(seed, 600);
            activated += counts.0;
            aborted += counts.1;
            excluded_total += counts.2;
            if !seed.is_multiple_of(2) {
                exclusion_seeds += 1;
                assert!(
                    counts.2 >= 1,
                    "seed {seed} uses the exclusion policy but never activated an exclusion"
                );
            }
        }
        assert!(
            activated >= 5,
            "schedules activated only {activated} changes"
        );
        assert!(aborted >= 5, "schedules aborted only {aborted} changes");
        // Each exclusion-policy schedule opens with a scripted exclusion, so there is at least one
        // per such seed by construction; the random part adds more.
        assert!(
            excluded_total >= exclusion_seeds && exclusion_seeds >= 4,
            "schedules activated only {excluded_total} exclusions over {exclusion_seeds} seeds"
        );
    }

    /// A short, fixed sequence the generator queues so that a path the random choice almost never
    /// reaches is reached on purpose: a proposal that survives to its ack deadline with one existing
    /// member unreachable, is committed without it, and activates at its frame. (Left to chance, the
    /// cutover frame and the random abort step end nearly every proposal long before its deadline.)
    enum Scripted {
        ProposeJoin(&'static str),
        AckAllExcept(String),
        JumpToDeadline,
        Tick,
        Commit,
        JumpToCutover,
    }

    /// An existing participant of the pending, uncommitted proposal that has not acknowledged yet,
    /// provided there is still room (in nanoseconds and in frames) to run a script to its end.
    fn scriptable_victim(
        m: &GroupMembership,
        s: &UnifiedGroupSession,
        now: GroupTime,
    ) -> Option<String> {
        let p = m.current.as_ref()?;
        if p.committed || p.ack_deadline_ns <= now.ns + 80 || p.cutover_frame <= now.frame + 12_000
        {
            return None;
        }
        p.participants
            .iter()
            .find(|x| {
                s.members.contains_key(*x)
                    && !p.acks.contains_key(x.as_str())
                    && !p.excluded.contains(*x)
            })
            .cloned()
    }

    /// Returns (activations, aborts, exclusions activated). Asserts, after every step: a refused
    /// call changed nothing; a pending or committed proposal never altered members or revision;
    /// activation only at or after its frame and once; revisions never fall; settled results never
    /// change; and, against an independent model, the set of members whose earlier output is
    /// unresolved and the conflicting-start gate are exactly what the exclusions and the evidence
    /// recorded so far imply, an excluded member can neither acknowledge nor rejoin.
    fn run_schedule(seed: u64, steps: usize) -> (u32, u32, u32) {
        let mut rng = SplitMix64(seed ^ 0x4730_3100);
        let policy = if seed.is_multiple_of(2) {
            MissingAckPolicy::Abort
        } else {
            MissingAckPolicy::ExcludeUnreachable
        };
        let mut s = session();
        let mut m = GroupMembership::new(MembershipConfig {
            missing_ack_policy: policy,
            ..MembershipConfig::default()
        });
        let mut tok = AuthorityToken::issue(&s, u64::MAX);
        let mut now = t(1_000, 10_000);
        let pool = ["n0", "n1", "n2", "n3"];
        let mut snapshot: Option<(u64, BTreeMap<String, GroupMemberState>, u64)> = None;
        let mut cutovers: BTreeMap<u64, u64> = BTreeMap::new();
        let mut settled_status: BTreeMap<u64, ProposalStatus> = BTreeMap::new();
        // Independent model of unresolved output: member -> conservative bound (None = unknown).
        let mut model_unresolved: BTreeMap<String, Option<u64>> = BTreeMap::new();
        let mut counts = (0, 0, 0);
        let mut last_revision = s.state_revision;
        let mut script: VecDeque<Scripted> = VecDeque::new();
        if policy == MissingAckPolicy::ExcludeUnreachable {
            script.extend([
                Scripted::ProposeJoin("n0"),
                Scripted::AckAllExcept("a".to_string()),
                Scripted::JumpToDeadline,
                Scripted::Tick,
                Scripted::Commit,
                Scripted::JumpToCutover,
                Scripted::Tick,
            ]);
        }

        for _ in 0..steps {
            now.ns += rng.below(10);
            now.frame += rng.below(1_500);
            let before = fingerprint(&m, &s);
            let revision_before = s.state_revision;
            let mut refused = false;
            let mut ticked = Vec::new();

            if let Some(op) = script.pop_front() {
                match op {
                    Scripted::ProposeJoin(name) => {
                        let cutover = now.frame + 30_000;
                        let deadline = now.ns + 400;
                        match m.propose(&s, &tok, join(name, "S1", cutover, deadline), now) {
                            Ok(id) => {
                                cutovers.insert(id, cutover);
                                snapshot = Some((id, s.members.clone(), s.state_revision));
                            }
                            Err(_) => {
                                refused = true;
                                script.clear();
                            }
                        }
                    }
                    Scripted::AckAllExcept(victim) => match m.pending_proposal() {
                        Some(id) => {
                            let required: Vec<String> = m
                                .current
                                .as_ref()
                                .map(|p| p.required().cloned().collect())
                                .unwrap_or_default();
                            for who in required {
                                if who != victim {
                                    let _ = m.ack(id, &who, ready(now.frame), now);
                                }
                            }
                        }
                        None => script.clear(),
                    },
                    Scripted::JumpToDeadline => {
                        match m.current.as_ref().map(|p| p.ack_deadline_ns) {
                            Some(deadline) => now.ns = now.ns.max(deadline),
                            None => script.clear(),
                        }
                    }
                    Scripted::Tick => ticked = m.tick(&mut s, now),
                    Scripted::Commit => match m.pending_proposal() {
                        Some(id) => refused = m.commit(&s, &tok, id, now).is_err(),
                        None => script.clear(),
                    },
                    Scripted::JumpToCutover => match m.current.as_ref().map(|p| p.cutover_frame) {
                        Some(cutover) => now.frame = now.frame.max(cutover),
                        None => script.clear(),
                    },
                }
            } else {
                match rng.below(12) {
                    0 | 1 => {
                        let cutover = now.frame + 4_800 + rng.below(40_000);
                        let deadline = now.ns + 100 + rng.below(300);
                        let mut join_target = None;
                        let spec = if rng.below(3) == 0 && !s.members.is_empty() {
                            let ids = keys(&s);
                            leave(
                                &ids[rng.below(ids.len() as u64) as usize],
                                cutover,
                                deadline,
                            )
                        } else {
                            let name = pool[rng.below(pool.len() as u64) as usize];
                            join_target = Some(name);
                            join(name, "S1", cutover, deadline)
                        };
                        match m.propose(&s, &tok, spec, now) {
                            Ok(id) => {
                                if let Some(name) = join_target {
                                    assert!(
                                        !model_unresolved.contains_key(name),
                                        "`{name}` was admitted again while its output was unresolved"
                                    );
                                }
                                cutovers.insert(id, cutover);
                                snapshot = Some((id, s.members.clone(), s.state_revision));
                            }
                            Err(_) => refused = true,
                        }
                    }
                    2..=4 => {
                        let participants: Vec<String> = m
                            .current
                            .as_ref()
                            .map(|p| p.participants.iter().cloned().collect())
                            .unwrap_or_default();
                        let id = m.pending_proposal().unwrap_or(rng.below(5) + 1);
                        let who = if participants.is_empty() || rng.below(10) == 0 {
                            pool[rng.below(pool.len() as u64) as usize].to_string()
                        } else {
                            participants[rng.below(participants.len() as u64) as usize].clone()
                        };
                        let report = ReadinessReport {
                            clock_confident: rng.below(12) != 0,
                            old_output_tail_complete_frame: if rng.below(10) == 0 {
                                now.frame + 100_000
                            } else {
                                now.frame.saturating_sub(rng.below(100))
                            },
                            ..ready(0)
                        };
                        if m.ack(id, &who, report, now).is_err() {
                            refused = true;
                        }
                    }
                    5 => {
                        let id = m.pending_proposal().unwrap_or(rng.below(5) + 1);
                        if m.commit(&s, &tok, id, now).is_err() {
                            refused = true;
                        }
                    }
                    6 => {
                        let id = m.pending_proposal().unwrap_or(rng.below(5) + 1);
                        match m.abort(&s, &tok, id, now) {
                            Ok(_) => snapshot = None,
                            Err(_) => refused = true,
                        }
                    }
                    7 | 8 => ticked = m.tick(&mut s, now),
                    9 => {
                        if policy == MissingAckPolicy::ExcludeUnreachable
                            && rng.below(2) == 0
                            && let Some(victim) = scriptable_victim(&m, &s, now)
                        {
                            // One existing member goes unreachable: carry the proposal through its
                            // deadline, exclusion, commit and activation.
                            script.extend([
                                Scripted::AckAllExcept(victim),
                                Scripted::JumpToDeadline,
                                Scripted::Tick,
                                Scripted::Commit,
                                Scripted::JumpToCutover,
                                Scripted::Tick,
                            ]);
                        } else if let Some(id) = m.pending_proposal() {
                            // Drive the current proposal forward: acknowledge everyone, commit.
                            let participants: Vec<String> = m
                                .current
                                .as_ref()
                                .map(|p| p.required().cloned().collect())
                                .unwrap_or_default();
                            for who in participants {
                                let _ = m.ack(id, &who, ready(now.frame), now);
                            }
                            let _ = m.commit(&s, &tok, id, now);
                        }
                    }
                    10 => {
                        if rng.below(5) == 0 {
                            let next_epoch = s.current_epoch + 1;
                            match m.advance_epoch(&mut s, &tok, next_epoch, now) {
                                Ok(next) => {
                                    tok = next;
                                    snapshot = None;
                                }
                                Err(_) => refused = true,
                            }
                        } else {
                            // A stale token can never do anything.
                            let stale = AuthorityToken {
                                epoch: s.current_epoch.saturating_sub(1),
                                ..tok.clone()
                            };
                            if s.current_epoch > 1 {
                                assert!(
                                    m.propose(
                                        &s,
                                        &stale,
                                        join("n0", "S1", now.frame + 9_000, now.ns + 9),
                                        now
                                    )
                                    .is_err()
                                );
                            }
                        }
                    }
                    _ => {
                        // Evidence about an excluded member's earlier output (or, with none
                        // excluded, about someone who was never excluded).
                        let target = match model_unresolved.keys().next() {
                            Some(first) if rng.below(3) != 0 => first.clone(),
                            _ => "nobody".to_string(),
                        };
                        let resolution = if rng.below(2) == 0 {
                            OutputResolution::StopAcknowledged
                        } else {
                            OutputResolution::ExpiresAtFrame(now.frame + rng.below(5_000))
                        };
                        match m.resolve_output(&target, resolution) {
                            Ok(()) => match resolution {
                                OutputResolution::StopAcknowledged => {
                                    model_unresolved.remove(&target);
                                }
                                OutputResolution::ExpiresAtFrame(frame) => {
                                    let bound = model_unresolved.entry(target).or_insert(None);
                                    *bound = Some((*bound).map_or(frame, |prev| prev.max(frame)));
                                }
                            },
                            Err(_) => refused = true,
                        }
                    }
                }
            }

            if refused {
                assert_eq!(before, fingerprint(&m, &s), "a refused call changed state");
            }
            for (id, status) in &ticked {
                match status {
                    ProposalStatus::Activated { revision, excluded } => {
                        counts.0 += 1;
                        counts.2 += u32::try_from(excluded.len()).unwrap();
                        assert!(
                            now.frame >= cutovers[id],
                            "activated before its cutover frame"
                        );
                        assert_eq!(*revision, revision_before + 1);
                        assert_eq!(
                            s.state_revision,
                            revision_before + 1,
                            "activation bumps once"
                        );
                        snapshot = None;
                        for member in excluded {
                            model_unresolved.insert(member.clone(), None);
                            assert!(
                                !s.members.contains_key(member),
                                "an excluded member is still in the group"
                            );
                            // Rejoining while its earlier output is unresolved must be refused,
                            // and refusing changes nothing.
                            let fp = fingerprint(&m, &s);
                            let rejoin = m.propose(
                                &s,
                                &tok,
                                join(member, "S12", now.frame + 30_000, now.ns + 400),
                                now,
                            );
                            assert!(
                                matches!(rejoin, Err(MembershipError::OutputUnresolved { .. })),
                                "an excluded member could rejoin: {rejoin:?}"
                            );
                            assert_eq!(fp, fingerprint(&m, &s));
                        }
                    }
                    ProposalStatus::Aborted { .. } => {
                        counts.1 += 1;
                        snapshot = None;
                    }
                    other => panic!("tick returned a non-terminal status {other:?}"),
                }
                assert!(
                    settled_status.insert(*id, status.clone()).is_none(),
                    "settled twice"
                );
            }
            if ticked.is_empty() {
                // Only activation and an epoch advance may touch the session.
                let epoch_moved = s.state_revision != revision_before;
                if epoch_moved {
                    assert_eq!(s.state_revision, revision_before + 1);
                }
            }
            if let (Some((id, members, revision)), Some(pending)) =
                (&snapshot, m.pending_proposal())
                && *id == pending
            {
                assert_eq!(
                    &s.members, members,
                    "a pending proposal altered audible state"
                );
                assert_eq!(s.state_revision, *revision);
            }
            // An excluded participant of a pending proposal can no longer acknowledge.
            let pending_excluded: Option<(u64, Vec<String>)> = m
                .current
                .as_ref()
                .map(|p| (p.id, p.excluded.iter().cloned().collect()));
            if let Some((id, excluded)) = pending_excluded {
                for member in excluded {
                    let fp = fingerprint(&m, &s);
                    assert!(
                        m.ack(id, &member, ready(now.frame), now).is_err(),
                        "an excluded member could still acknowledge"
                    );
                    assert_eq!(fp, fingerprint(&m, &s));
                }
            }
            assert_eq!(
                m.unresolved_output(),
                model_unresolved.keys().cloned().collect::<Vec<_>>(),
                "the unresolved-output set diverged from the model"
            );
            let blocked: Vec<String> = model_unresolved
                .iter()
                .filter(|(_, bound)| bound.is_none_or(|frame| now.frame < frame))
                .map(|(member, _)| member.clone())
                .collect();
            match m.conflicting_start_gate(now.frame) {
                Ok(()) => assert!(
                    blocked.is_empty(),
                    "the gate opened while {blocked:?} may still be sounding"
                ),
                Err(list) => assert_eq!(list, blocked, "the gate blocked the wrong members"),
            }
            assert!(s.members.len() <= MAX_GROUP_MEMBERS);
            assert!(s.state_revision >= last_revision, "revision went backwards");
            last_revision = s.state_revision;
            for (id, status) in &settled_status {
                if let Ok(now_status) = m.status(*id) {
                    assert_eq!(&now_status, status, "a settled result changed");
                }
            }
        }
        counts
    }

    // ---------------------------------------------------------------------------------------
    // Leases, quorum renewal, takeover and partitions (slice 2). Every number below is derived
    // by hand from the protocol rules, not read back from the code under test.
    // ---------------------------------------------------------------------------------------

    fn lease_terms(uncertainty_ns: u64) -> LeaseTerms {
        LeaseTerms {
            max_lease_ns: 1_000,
            clock_uncertainty_ns: uncertainty_ns,
            max_output_horizon_ns: 500,
        }
    }

    fn quorum_membership_config(terms: LeaseTerms) -> MembershipConfig {
        MembershipConfig {
            epoch_mint: EpochMint::Quorum,
            lease: terms,
            max_output_horizon_frames: 1_000,
            ..MembershipConfig::default()
        }
    }

    fn quorum_engine(terms: LeaseTerms) -> GroupMembership {
        GroupMembership::new(quorum_membership_config(terms))
    }

    /// Voters `v1..vN` of group `grp`.
    fn quorum_config(n: usize) -> QuorumConfig {
        let ids: Vec<String> = (1..=n).map(|i| format!("v{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        QuorumConfig::new("grp", &refs).unwrap()
    }

    /// One voter per electorate member, in id order (`v1` is index 0).
    fn voters_of(q: &QuorumConfig, terms: LeaseTerms) -> Vec<LeaseVoter> {
        q.voters()
            .iter()
            .map(|id| LeaseVoter::new(id, q.clone(), terms).unwrap())
            .collect()
    }

    fn lease_view(epoch: u64, holder: &str, expires_at_ns: u64) -> LeaseView {
        LeaseView {
            group_id: "grp".to_string(),
            epoch,
            holder: holder.to_string(),
            expires_at_ns,
        }
    }

    /// Group formation: every voter learns the founding lease (epoch 1).
    fn found(voters: &mut [LeaseVoter], holder: &str, expires_at_ns: u64) {
        let view = lease_view(1, holder, expires_at_ns);
        for voter in voters {
            voter.observe(&view).unwrap();
        }
    }

    /// The requester (clock reading `now_ns`) sends `request` to the voters at `reach`; voter `i`
    /// judges it by `clocks[i]`. A refusing voter simply does not acknowledge.
    fn gather(
        q: &QuorumConfig,
        terms: LeaseTerms,
        voters: &mut [LeaseVoter],
        request: &LeaseRequest,
        reach: &[usize],
        clocks: &[u64],
        now_ns: u64,
    ) -> Result<LeaseWin, MembershipError> {
        let mut round = QuorumRound::start(q, terms, request.clone(), now_ns)?;
        for &i in reach {
            if let Ok(ack) = voters[i].respond(request, clocks[i]) {
                round.record(&ack, now_ns)?;
            }
        }
        round.outcome(now_ns)
    }

    #[test]
    fn a_quorum_is_a_strict_majority_and_only_voters_may_take_part() {
        assert_eq!(
            QuorumConfig::new("grp", &[]),
            Err(MembershipError::EmptyElectorate)
        );
        for (n, need) in [(1, 1), (2, 2), (3, 2), (4, 3), (5, 3), (7, 4)] {
            assert_eq!(quorum_config(n).quorum(), need, "{n} voters");
        }
        // A repeated name is one voter.
        assert_eq!(
            QuorumConfig::new("grp", &["a", "a", "b"]).unwrap().quorum(),
            2
        );
        let q = quorum_config(3);
        assert_eq!(
            LeaseVoter::new("zz", q.clone(), lease_terms(0)).err(),
            Some(MembershipError::NotAVoter {
                member_id: "zz".to_string()
            })
        );
        let mut voters = voters_of(&q, lease_terms(0));
        let stranger = LeaseRequest {
            kind: LeaseRequestKind::Takeover,
            group_id: "grp".to_string(),
            requester: "zz".to_string(),
            epoch: 2,
            expires_at_ns: 2_000,
        };
        assert_eq!(
            voters[0].respond(&stranger, 5_000).err(),
            Some(MembershipError::NotAVoter {
                member_id: "zz".to_string()
            })
        );
    }

    #[test]
    fn a_renewal_needs_a_majority_so_a_minority_cannot_extend_a_lease() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let s = session_for("v1");
        let mut m = quorum_engine(terms);
        let tok = AuthorityToken::issue(&s, 1_000);
        let clocks = [500; 3];

        // Alone, the holder has one acknowledgement of the two it needs.
        let request = voters[0].renew_request(500, 900).unwrap();
        assert_eq!(request.expires_at_ns, 1_400);
        assert_eq!(
            gather(&q, terms, &mut voters, &request, &[0], &clocks, 500).err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 })
        );
        // With a second voter it extends.
        let win = gather(&q, terms, &mut voters, &request, &[0, 1], &clocks, 500).unwrap();
        assert_eq!(
            (
                win.kind(),
                win.requester(),
                win.epoch(),
                win.expires_at_ns(),
                win.prior_expires_at_ns(),
                win.acks()
            ),
            (LeaseRequestKind::Renew, "v1", 1, 1_400, 0, 2)
        );
        let renewed = m.renew_lease(&s, &tok, &win, t(500, 10_000)).unwrap();
        assert_eq!(
            (
                renewed.epoch,
                renewed.expires_at_ns,
                renewed.issuer_id.as_str()
            ),
            (1, 1_400, "v1")
        );
        // The same result extends nothing the second time.
        assert_eq!(
            m.renew_lease(&s, &renewed, &win, t(510, 10_100)).err(),
            Some(MembershipError::LeaseNotExtended {
                expires_at_ns: 1_400,
                current_ns: 1_400
            })
        );
        // A lease cannot be asked for beyond the maximum (500 + 1_000 = 1_500).
        assert_eq!(
            voters[0].renew_request(500, 1_001).err(),
            Some(MembershipError::LeaseTooLong {
                expires_at_ns: 1_501,
                max_ns: 1_500
            })
        );
        // Once the holder's own margin has passed (1_360 + 50 >= 1_400) it cannot renew at all:
        // the majority may already be taking over, and a new epoch has to be won instead.
        assert_eq!(
            m.renew_lease(&s, &renewed, &win, t(1_360, 10_000)).err(),
            Some(MembershipError::AuthorityExpired {
                expires_at_ns: 1_400,
                now_ns: 1_360
            })
        );
    }

    #[test]
    fn acknowledgements_must_match_the_open_request_and_a_repeat_counts_once() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let request = voters[0].renew_request(500, 900).unwrap();
        let mut round = QuorumRound::start(&q, terms, request.clone(), 500).unwrap();
        let ack = voters[1].respond(&request, 500).unwrap();
        for (label, bad) in [
            (
                "epoch",
                LeaseAck {
                    epoch: 2,
                    ..ack.clone()
                },
            ),
            (
                "expiry",
                LeaseAck {
                    expires_at_ns: 1_300,
                    ..ack.clone()
                },
            ),
            (
                "kind",
                LeaseAck {
                    kind: LeaseRequestKind::Takeover,
                    ..ack.clone()
                },
            ),
            (
                "requester",
                LeaseAck {
                    requester: "v3".to_string(),
                    ..ack.clone()
                },
            ),
            (
                "group",
                LeaseAck {
                    group_id: "other".to_string(),
                    ..ack.clone()
                },
            ),
        ] {
            assert_eq!(
                round.record(&bad, 500),
                Err(MembershipError::AttemptMismatch),
                "{label}"
            );
        }
        assert_eq!(
            round.record(
                &LeaseAck {
                    voter: "zz".to_string(),
                    ..ack.clone()
                },
                500
            ),
            Err(MembershipError::NotAVoter {
                member_id: "zz".to_string()
            })
        );
        round.record(&ack, 500).unwrap();
        round.record(&ack, 500).unwrap();
        assert_eq!(
            round.outcome(500).err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 }),
            "one voter acknowledging twice is still one voter"
        );
        // Requests from outside the electorate, or for another group, never start a round.
        let outsider = LeaseRequest {
            requester: "zz".to_string(),
            ..request.clone()
        };
        assert_eq!(
            QuorumRound::start(&q, terms, outsider, 500).err(),
            Some(MembershipError::NotAVoter {
                member_id: "zz".to_string()
            })
        );
        let foreign = LeaseRequest {
            group_id: "other".to_string(),
            ..request.clone()
        };
        assert_eq!(
            QuorumRound::start(&q, terms, foreign, 500).err(),
            Some(MembershipError::WrongGroup)
        );
        // The round is over once the lease it proposed could no longer be relied on:
        // 1_400 - 50 = 1_350. A late quorum is no quorum.
        let second = voters[2].respond(&request, 500).unwrap();
        round.record(&second, 1_349).unwrap();
        assert!(round.outcome(1_349).is_ok());
        let over = MembershipError::AttemptExpired {
            now_ns: 1_350,
            deadline_ns: 1_350,
        };
        assert_eq!(round.outcome(1_350).err(), Some(over.clone()));
        assert_eq!(round.record(&ack, 1_350), Err(over.clone()));
        assert_eq!(
            QuorumRound::start(&q, terms, request, 1_350).err(),
            Some(over)
        );
    }

    #[test]
    fn a_takeover_waits_for_the_conservative_expiry_and_is_granted_to_one_candidate() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let request = voters[1].takeover_request(1_050, 500).unwrap();
        assert_eq!(
            (
                request.epoch,
                request.expires_at_ns,
                request.requester.as_str()
            ),
            (2, 1_550, "v2")
        );
        // The lease ends at 1_000 by the holder's clock; this voter waits the 50 ns of clock
        // uncertainty on top, by its own reading.
        assert_eq!(
            voters[2].respond(&request, 1_049).err(),
            Some(MembershipError::LeaseNotExpired {
                conservative_expiry_ns: 1_050,
                now_ns: 1_049
            })
        );
        assert_eq!(
            voters[2].durable_record().grant,
            None,
            "a refusal records nothing"
        );
        let ack = voters[2].respond(&request, 1_050).unwrap();
        assert_eq!(
            (ack.voter.as_str(), ack.epoch, ack.prior_expires_at_ns),
            ("v3", 2, 1_000)
        );
        assert_eq!(
            voters[2].respond(&request, 1_060).unwrap(),
            ack,
            "the same candidate asking again is answered the same"
        );
        assert_eq!(
            voters[2].durable_record().grant,
            Some(GrantRecord {
                epoch: 2,
                candidate: "v2".to_string(),
                expires_at_ns: 1_550,
                prior_expires_at_ns: 1_000
            })
        );
        // One candidate per epoch.
        let rival = LeaseRequest {
            requester: "v1".to_string(),
            ..request.clone()
        };
        assert_eq!(
            voters[2].respond(&rival, 1_100).err(),
            Some(MembershipError::ConflictingLeaders {
                epoch: 2,
                held_by: "v2".to_string(),
                announced_by: "v1".to_string()
            })
        );
        // Only the next epoch.
        let skip = LeaseRequest {
            epoch: 5,
            ..request.clone()
        };
        assert_eq!(
            voters[2].respond(&skip, 1_100).err(),
            Some(MembershipError::NotNextEpoch {
                requested: 5,
                expected: 3
            })
        );
        // A voter that has seen no lease cannot judge expiry, so it grants nothing.
        let mut blank = LeaseVoter::new("v3", q.clone(), terms).unwrap();
        assert_eq!(
            blank.respond(&request, 9_999).err(),
            Some(MembershipError::NoLeaseView)
        );
        assert_eq!(
            blank.takeover_request(9_999, 500).err(),
            Some(MembershipError::NoLeaseView)
        );
        assert_eq!(
            blank.renew_request(9_999, 500).err(),
            Some(MembershipError::NoLeaseView)
        );
    }

    #[test]
    fn a_holder_stops_u_before_its_lease_ends_and_a_taker_starts_u_after_so_they_never_overlap() {
        let u = 50;
        let terms = lease_terms(u);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let s = session_for("v1");
        let mut m = quorum_engine(terms);
        let tok = AuthorityToken::issue(&s, 1_000);

        // The holder: live through 949, over from 950 (= 1_000 - u), and then refuses to act.
        assert!(m.lease_is_live(&s, &tok, 949));
        assert!(!m.lease_is_live(&s, &tok, 950));
        let before = fingerprint(&m, &s);
        assert_eq!(
            m.propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(950, 10_000))
                .err(),
            Some(MembershipError::AuthorityExpired {
                expires_at_ns: 1_000,
                now_ns: 950
            })
        );
        assert_eq!(fingerprint(&m, &s), before);
        assert!(
            m.propose(&s, &tok, join("c", "S1", 100_000, 2_000), t(949, 10_000))
                .is_ok()
        );

        // The taker: no voter grants before 1_050 (= 1_000 + u), so the interval 950..1_050 has no
        // leader at all. That gap of 2u is the price of safety under clock uncertainty.
        let request = voters[1].takeover_request(1_050, 500).unwrap();
        for now in 950..1_050 {
            assert!(
                voters[2].respond(&request, now).is_err(),
                "a voter granted at {now}"
            );
        }
        assert!(voters[2].respond(&request, 1_050).is_ok());
    }

    #[test]
    fn a_voter_in_both_quorums_orders_a_renewal_and_a_takeover_so_only_one_wins() {
        let terms = lease_terms(50);
        let q = quorum_config(3);

        // Order one: the takeover is granted first. The majority then refuses the late renewal of
        // the older epoch, so the holder is left with its own acknowledgement alone.
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let take = voters[1].takeover_request(1_050, 500).unwrap();
        let win = gather(&q, terms, &mut voters, &take, &[1, 2], &[1_050; 3], 1_050).unwrap();
        assert_eq!(win.epoch(), 2);
        let renew = voters[0].renew_request(900, 500).unwrap();
        assert_eq!(
            gather(&q, terms, &mut voters, &renew, &[0, 1, 2], &[1_100; 3], 900).err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 })
        );
        let stale = MembershipError::StaleAuthority {
            token_epoch: 1,
            current_epoch: 2,
        };
        assert_eq!(voters[1].respond(&renew, 1_100).err(), Some(stale.clone()));
        assert_eq!(voters[2].respond(&renew, 1_100).err(), Some(stale));

        // Order two: the renewal is acknowledged first. The voter that acknowledged it now holds
        // the longer lease and refuses a takeover until it has passed (1_400 + 50 = 1_450).
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let renew = voters[0].renew_request(900, 500).unwrap();
        let won = gather(&q, terms, &mut voters, &renew, &[0, 1], &[900; 3], 900).unwrap();
        assert_eq!(won.expires_at_ns(), 1_400);
        // v3 never heard of the renewal, so it alone would grant at 1_050.
        let take = voters[2].takeover_request(1_050, 500).unwrap();
        assert_eq!(
            gather(
                &q,
                terms,
                &mut voters,
                &take,
                &[0, 1, 2],
                &[1_050; 3],
                1_050
            )
            .err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 })
        );
        let too_early = MembershipError::LeaseNotExpired {
            conservative_expiry_ns: 1_450,
            now_ns: 1_050,
        };
        assert_eq!(
            voters[0].respond(&take, 1_050).err(),
            Some(too_early.clone())
        );
        assert_eq!(voters[1].respond(&take, 1_050).err(), Some(too_early));
    }

    #[test]
    fn two_candidates_cannot_both_win_an_epoch_and_a_split_vote_is_a_refusal_not_a_tie() {
        let terms = lease_terms(50);

        // Three voters: the first candidate wins; the second finds the epoch taken.
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let clocks = [1_100; 3];
        let first = voters[1].takeover_request(1_100, 500).unwrap();
        let second = voters[2].takeover_request(1_100, 500).unwrap();
        assert_eq!((first.epoch, second.epoch), (2, 2));
        let win = gather(&q, terms, &mut voters, &first, &[1, 0], &clocks, 1_100).unwrap();
        assert_eq!(win.requester(), "v2");
        assert_eq!(
            gather(&q, terms, &mut voters, &second, &[2, 0, 1], &clocks, 1_100).err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 })
        );
        assert_eq!(
            voters[0].respond(&second, 1_100).err(),
            Some(MembershipError::ConflictingLeaders {
                epoch: 2,
                held_by: "v2".to_string(),
                announced_by: "v3".to_string()
            })
        );

        // Four voters (even): two candidates each reach two voters and neither has the three it
        // needs. Nobody wins; nobody ties.
        let q = quorum_config(4);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let a = voters[2].takeover_request(1_100, 500).unwrap();
        let b = voters[3].takeover_request(1_100, 500).unwrap();
        let split = Some(MembershipError::NoQuorum { have: 2, need: 3 });
        assert_eq!(
            gather(&q, terms, &mut voters, &a, &[2, 0], &[1_100; 4], 1_100).err(),
            split
        );
        assert_eq!(
            gather(&q, terms, &mut voters, &b, &[3, 1], &[1_100; 4], 1_100).err(),
            split
        );
        // A voter that voted for one candidate cannot be completed for the other afterwards.
        assert_eq!(
            voters[0].respond(&b, 1_200).err(),
            Some(MembershipError::ConflictingLeaders {
                epoch: 2,
                held_by: "v3".to_string(),
                announced_by: "v4".to_string()
            })
        );
    }

    #[test]
    fn a_voter_only_extends_a_lease_it_knows_to_be_the_requesters_and_learns_only_forward() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut v = LeaseVoter::new("v3", q.clone(), terms).unwrap();
        v.observe(&lease_view(1, "v1", 1_000)).unwrap();
        let renewal = |who: &str, epoch: u64| LeaseRequest {
            kind: LeaseRequestKind::Renew,
            group_id: "grp".to_string(),
            requester: who.to_string(),
            epoch,
            expires_at_ns: 1_300,
        };
        assert_eq!(
            v.respond(&renewal("v2", 1), 500).err(),
            Some(MembershipError::NotLeaseHolder {
                epoch: 1,
                holder: "v1".to_string()
            })
        );
        assert_eq!(
            v.respond(&renewal("v2", 7), 500).err(),
            Some(MembershipError::FutureAuthority {
                token_epoch: 7,
                current_epoch: 1
            }),
            "an epoch nobody was granted cannot be minted by renewing it"
        );
        // What a voter is told only moves forward, and never names a second holder for an epoch.
        assert_eq!(
            v.observe(&lease_view(0, "v1", 900)).err(),
            Some(MembershipError::StaleAuthority {
                token_epoch: 0,
                current_epoch: 1
            })
        );
        assert_eq!(
            v.observe(&lease_view(1, "v2", 1_000)).err(),
            Some(MembershipError::ConflictingLeaders {
                epoch: 1,
                held_by: "v1".to_string(),
                announced_by: "v2".to_string()
            })
        );
        assert_eq!(
            v.observe(&lease_view(1, "zz", 1_000)).err(),
            Some(MembershipError::NotAVoter {
                member_id: "zz".to_string()
            })
        );
        let foreign = LeaseView {
            group_id: "other".to_string(),
            ..lease_view(1, "v1", 1_000)
        };
        assert_eq!(v.observe(&foreign).err(), Some(MembershipError::WrongGroup));
        // Hearing the held lease again can only extend it.
        v.observe(&lease_view(1, "v1", 900)).unwrap();
        assert_eq!(v.view().map(|x| x.expires_at_ns), Some(1_000));
        v.observe(&lease_view(1, "v1", 1_200)).unwrap();
        assert_eq!(v.view().map(|x| x.expires_at_ns), Some(1_200));

        // A voter that granted epoch 2 to v2 acknowledges v2's renewal of it, and nobody else's;
        // doing so turns the grant into the confirmed lease.
        let mut v = LeaseVoter::new("v3", q, terms).unwrap();
        v.observe(&lease_view(1, "v1", 1_000)).unwrap();
        let take = LeaseRequest {
            kind: LeaseRequestKind::Takeover,
            expires_at_ns: 1_550,
            epoch: 2,
            ..renewal("v2", 2)
        };
        v.respond(&take, 1_050).unwrap();
        let renew_two = |who: &str| LeaseRequest {
            expires_at_ns: 1_700,
            ..renewal(who, 2)
        };
        assert_eq!(
            v.respond(&renew_two("v1"), 1_100).err(),
            Some(MembershipError::NotLeaseHolder {
                epoch: 2,
                holder: "v2".to_string()
            })
        );
        v.respond(&renew_two("v2"), 1_100).unwrap();
        let record = v.durable_record();
        assert_eq!(record.grant, None);
        assert_eq!(record.view, Some(lease_view(2, "v2", 1_700)));
    }

    #[test]
    fn a_partitioned_holder_cannot_renew_the_majority_takes_over_and_the_old_holder_is_fenced() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let mut sessions: Vec<UnifiedGroupSession> = (0..3).map(|_| session_for("v1")).collect();
        let mut engines: Vec<GroupMembership> = (0..3).map(|_| quorum_engine(terms)).collect();
        let old = AuthorityToken::issue(&sessions[0], 1_000);

        // v1 is cut off from v2 and v3. Its renewal reaches itself: one acknowledgement of two.
        let renew = voters[0].renew_request(600, 900).unwrap();
        assert_eq!(
            gather(&q, terms, &mut voters, &renew, &[0], &[600; 3], 600).err(),
            Some(MembershipError::NoQuorum { have: 1, need: 2 })
        );
        assert!(engines[0].lease_is_live(&sessions[0], &old, 949));
        assert!(!engines[0].lease_is_live(&sessions[0], &old, 950));

        // The majority side: too early at 1_049 (nobody grants), possible at 1_050.
        let take = voters[1].takeover_request(1_050, 500).unwrap();
        assert_eq!(
            gather(&q, terms, &mut voters, &take, &[1, 2], &[1_049; 3], 1_050).err(),
            Some(MembershipError::NoQuorum { have: 0, need: 2 })
        );
        let win = gather(&q, terms, &mut voters, &take, &[1, 2], &[1_050; 3], 1_050).unwrap();
        assert_eq!(
            (win.epoch(), win.prior_expires_at_ns(), win.acks()),
            (2, 1_000, 2)
        );
        let new_token = engines[1]
            .assume_authority(&mut sessions[1], &win, t(1_050, 20_000))
            .unwrap();
        assert_eq!(
            (
                new_token.epoch,
                new_token.issuer_id.as_str(),
                new_token.expires_at_ns
            ),
            (2, "v2", 1_550)
        );
        assert_eq!(
            (
                sessions[1].current_epoch,
                sessions[1].coordinator_id.as_str()
            ),
            (2, "v2")
        );
        // Until the previous term's already-granted output cannot sound (1_000 + 500 + 50 = 1_550)
        // a conflicting program may not start.
        assert_eq!(engines[1].takeover_start_gate(1_549), Err(1_550));
        assert_eq!(engines[1].takeover_start_gate(1_550), Ok(()));
        assert_eq!(
            quorum_engine(terms).takeover_start_gate(0),
            Ok(()),
            "a node that never took over has no gate"
        );

        // Still partitioned: at no instant do both hold a live lease.
        for now in 900..1_700 {
            let live_old = engines[0].lease_is_live(&sessions[0], &old, now);
            let live_new = now >= 1_050 && engines[1].lease_is_live(&sessions[1], &new_token, now);
            assert!(!(live_old && live_new), "two live leaders at {now}");
        }

        // The partition heals and v1 hears of the new term. Its old token is fenced by epoch no
        // matter what its clock says, and it can no longer renew the old epoch.
        let view = new_token.lease_view();
        voters[0].observe(&view).unwrap();
        engines[0].adopt_authority(&mut sessions[0], &view).unwrap();
        assert_eq!(
            (
                sessions[0].current_epoch,
                sessions[0].coordinator_id.as_str()
            ),
            (2, "v2")
        );
        let before = fingerprint(&engines[0], &sessions[0]);
        assert_eq!(
            engines[0]
                .propose(
                    &sessions[0],
                    &old,
                    join("c", "S1", 100_000, 2_000),
                    t(600, 10_000)
                )
                .err(),
            Some(MembershipError::StaleAuthority {
                token_epoch: 1,
                current_epoch: 2
            })
        );
        assert_eq!(fingerprint(&engines[0], &sessions[0]), before);
        assert_eq!(
            voters[0].renew_request(1_600, 400).err(),
            Some(MembershipError::NotLeaseHolder {
                epoch: 2,
                holder: "v2".to_string()
            })
        );
    }

    #[test]
    fn adopting_a_newer_epoch_aborts_the_proposal_in_flight_and_fences_an_unexpired_stale_token() {
        let terms = lease_terms(50);
        let mut s = session_for("v1");
        let mut m = quorum_engine(terms);
        // A token that is nowhere near its own expiry: only the epoch can stop it.
        let stale = AuthorityToken::issue(&s, 100_000);
        let id = m
            .propose(&s, &stale, join("c", "S1", 100_000, 2_000), t(100, 10_000))
            .unwrap();
        let view = lease_view(2, "v2", 5_000);
        let revision = s.state_revision;
        m.adopt_authority(&mut s, &view).unwrap();
        assert_eq!(
            m.status(id),
            Ok(ProposalStatus::Aborted {
                reason: AbortReason::EpochAdvanced
            })
        );
        assert_eq!(m.pending_proposal(), None);
        assert_eq!(
            (s.current_epoch, s.coordinator_id.as_str(), s.state_revision),
            (2, "v2", revision + 1)
        );

        // The old issuer is also no longer the configured one; epoch is judged first, so the
        // refusal names the real problem.
        let expected = Some(MembershipError::StaleAuthority {
            token_epoch: 1,
            current_epoch: 2,
        });
        let before = fingerprint(&m, &s);
        assert_eq!(
            m.propose(&s, &stale, join("d", "S1", 100_000, 2_000), t(200, 10_100))
                .err(),
            expected
        );
        assert_eq!(m.abort(&s, &stale, id, t(200, 10_100)).err(), expected);
        assert_eq!(
            m.grant_output(&s, &stale, "a", 10_200, t(200, 10_100))
                .err(),
            expected
        );
        assert_eq!(m.discover_authority(&s, &stale, 200).err(), expected);
        assert_eq!(fingerprint(&m, &s), before, "a refusal changes nothing");

        // Adoption is forward-only and names one holder per epoch.
        assert_eq!(m.adopt_authority(&mut s, &view), Ok(()));
        assert_eq!(
            s.state_revision,
            revision + 1,
            "re-adopting changes nothing"
        );
        assert_eq!(
            m.adopt_authority(&mut s, &lease_view(2, "v3", 5_000)),
            Err(MembershipError::ConflictingLeaders {
                epoch: 2,
                held_by: "v2".to_string(),
                announced_by: "v3".to_string()
            })
        );
        assert_eq!(
            m.adopt_authority(&mut s, &lease_view(1, "v2", 5_000)),
            Err(MembershipError::StaleAuthority {
                token_epoch: 1,
                current_epoch: 2
            })
        );
        let foreign = LeaseView {
            group_id: "other".to_string(),
            ..view
        };
        assert_eq!(
            m.adopt_authority(&mut s, &foreign),
            Err(MembershipError::WrongGroup)
        );
    }

    #[test]
    fn when_a_lease_lapses_granted_output_plays_out_and_nothing_new_is_issued() {
        let terms = lease_terms(50);
        let s = session_for("v1");
        // Output grants reach at most 1_000 frames ahead in this configuration.
        let mut m = quorum_engine(terms);
        let tok = AuthorityToken::issue(&s, 1_000);
        let now = t(100, 10_000);
        assert_eq!(m.grant_output(&s, &tok, "a", 10_500, now), Ok(10_500));
        assert_eq!(
            m.grant_output(&s, &tok, "a", 10_200, now),
            Ok(10_500),
            "a grant only ever extends"
        );
        assert_eq!(
            m.grant_output(&s, &tok, "a", 11_001, now).err(),
            Some(MembershipError::OutputHorizonExceeded {
                requested_frame: 11_001,
                max_frame: 11_000
            })
        );
        assert_eq!(
            m.grant_output(&s, &tok, "zz", 10_100, now).err(),
            Some(MembershipError::UnknownMember {
                member_id: "zz".to_string()
            })
        );
        assert!(m.output_permitted("a", 10_499));
        assert!(!m.output_permitted("a", 10_500));
        assert!(!m.output_permitted("b", 0), "no grant, no output");

        // The lease lapses by the holder's margin at 950. Nothing new is granted; what was granted
        // plays out to its frame and then mutes.
        let lapsed = t(950, 20_000);
        let expired = Some(MembershipError::AuthorityExpired {
            expires_at_ns: 1_000,
            now_ns: 950,
        });
        assert_eq!(m.grant_output(&s, &tok, "a", 20_100, lapsed).err(), expired);
        assert_eq!(m.grant_output(&s, &tok, "b", 20_100, lapsed).err(), expired);
        assert!(m.output_permitted("a", 10_499), "granted output plays out");
        assert!(!m.output_permitted("a", 10_500), "and then mutes");
        assert!(!m.output_permitted("b", 20_050), "nothing new was issued");
        // The frame horizon (what a grant may reach) and the nanosecond horizon (how long after
        // its lease a previous term's output may still sound) are two numbers for one duration.
        // The test configuration above uses small independent values; the defaults must agree:
        // 10 s as 48 kHz frames and as nanoseconds.
        let defaults = MembershipConfig::default();
        assert_eq!(
            defaults.max_output_horizon_frames * 1_000_000_000 / 48_000,
            defaults.lease.max_output_horizon_ns
        );
    }

    #[test]
    fn a_voter_without_its_durable_record_refuses_everything_until_it_is_restored() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let take = voters[1].takeover_request(1_050, 500).unwrap();
        let ack = voters[2].respond(&take, 1_050).unwrap(); // v3 grants epoch 2 to v2
        let record = voters[2].durable_record();
        assert_eq!(record.voter_id, "v3");
        assert_eq!(
            record
                .grant
                .as_ref()
                .map(|g| (g.epoch, g.candidate.as_str())),
            Some((2, "v2"))
        );
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            serde_json::from_str::<DurableVoterRecord>(&json).unwrap(),
            record,
            "the record survives its own serialisation"
        );

        let rival = LeaseRequest {
            requester: "v1".to_string(),
            ..take.clone()
        };
        let stale_renewal = voters[0].renew_request(900, 400).unwrap();
        let mut restarted = LeaseVoter::after_restart("v3", q.clone(), terms).unwrap();
        let unavailable = Some(MembershipError::VoterRecordUnavailable);
        assert_eq!(restarted.respond(&rival, 1_100).err(), unavailable);
        assert_eq!(restarted.respond(&stale_renewal, 1_100).err(), unavailable);
        // Another voter's record does not unlock it.
        assert_eq!(
            restarted.restore(voters[1].durable_record()),
            Err(MembershipError::VoterRecordUnavailable)
        );
        assert_eq!(restarted.respond(&rival, 1_100).err(), unavailable);

        // With its own record back it remembers: one candidate per epoch, and no renewal of the
        // older epoch.
        restarted.restore(record).unwrap();
        assert_eq!(
            restarted.respond(&rival, 1_100).err(),
            Some(MembershipError::ConflictingLeaders {
                epoch: 2,
                held_by: "v2".to_string(),
                announced_by: "v1".to_string()
            })
        );
        assert_eq!(
            restarted.respond(&stale_renewal, 1_100).err(),
            Some(MembershipError::StaleAuthority {
                token_epoch: 1,
                current_epoch: 2
            })
        );
        assert_eq!(restarted.respond(&take, 1_100).unwrap(), ack);

        // The control: a voter that forgot (restarted as if new, re-learning only the founding
        // lease) grants the rival the very epoch it already granted. That is what the record is for.
        let mut forgetful = LeaseVoter::new("v3", q, terms).unwrap();
        found(std::slice::from_mut(&mut forgetful), "v1", 1_000);
        assert!(forgetful.respond(&rival, 1_100).is_ok());
    }

    #[test]
    fn a_group_mints_epochs_by_one_rule_only_and_a_restarted_node_must_learn_the_holder_first() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let renew = voters[0].renew_request(500, 900).unwrap();
        let renewal = gather(&q, terms, &mut voters, &renew, &[0, 1], &[500; 3], 500).unwrap();
        // Both views now read 1_400, so the takeover has to wait for 1_450.
        let take = voters[1].takeover_request(1_450, 500).unwrap();
        let win = gather(&q, terms, &mut voters, &take, &[1, 2], &[1_450; 3], 1_450).unwrap();
        assert_eq!((win.epoch(), win.prior_expires_at_ns()), (2, 1_400));

        // A quorum group: the issuer alone cannot advance the epoch.
        let mut s = session_for("v1");
        let mut m = quorum_engine(terms);
        let tok = AuthorityToken::issue(&s, 1_000);
        let before = fingerprint(&m, &s);
        assert_eq!(
            m.advance_epoch(&mut s, &tok, 2, t(100, 10_000)).err(),
            Some(MembershipError::QuorumRequired)
        );
        assert_eq!(fingerprint(&m, &s), before);

        // A configured-issuer group has no electorate: the quorum entry points refuse.
        let mut plain_s = session_for("coord");
        let mut plain = GroupMembership::new(MembershipConfig::default());
        let plain_tok = token(&plain_s);
        let view = lease_view(2, "v2", 5_000);
        let not_quorum = Some(MembershipError::NotAQuorumGroup);
        assert_eq!(plain.adopt_authority(&mut plain_s, &view).err(), not_quorum);
        assert_eq!(
            plain
                .assume_authority(&mut plain_s, &win, t(1_450, 20_000))
                .err(),
            not_quorum
        );
        assert_eq!(
            plain
                .renew_lease(&plain_s, &plain_tok, &renewal, t(500, 10_000))
                .err(),
            not_quorum
        );
        assert!(
            plain
                .advance_epoch(&mut plain_s, &plain_tok, 2, t(100, 10_000))
                .is_ok()
        );

        // A restarted node must first learn who holds the epoch.
        let mut rs = session_for("v1");
        let mut restarted = GroupMembership::after_restart(quorum_membership_config(terms));
        let undiscovered = Some(MembershipError::AuthorityNotDiscovered);
        assert_eq!(
            restarted
                .assume_authority(&mut rs, &win, t(1_450, 20_000))
                .err(),
            undiscovered
        );
        assert_eq!(
            restarted
                .renew_lease(&rs, &tok, &renewal, t(500, 10_000))
                .err(),
            undiscovered
        );
        restarted
            .adopt_authority(&mut rs, &tok.lease_view())
            .unwrap();
        assert!(
            restarted
                .assume_authority(&mut rs, &win, t(1_450, 20_000))
                .is_ok()
        );
    }

    #[test]
    fn a_quorum_result_applies_only_to_what_it_was_gathered_for() {
        let terms = lease_terms(50);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let renew = voters[0].renew_request(500, 900).unwrap();
        let renewal = gather(&q, terms, &mut voters, &renew, &[0, 1], &[500; 3], 500).unwrap();
        let take = voters[1].takeover_request(1_450, 500).unwrap();
        let takeover = gather(&q, terms, &mut voters, &take, &[1, 2], &[1_450; 3], 1_450).unwrap();
        assert_eq!(takeover.expires_at_ns(), 1_950);

        let s = session_for("v1");
        let mut m = quorum_engine(terms);
        let tok = AuthorityToken::issue(&s, 1_000);
        let not_applicable = Some(MembershipError::WinNotApplicable);
        // A takeover result cannot renew; a renewal result cannot take over.
        assert_eq!(
            m.renew_lease(&s, &tok, &takeover, t(500, 10_000)).err(),
            not_applicable
        );
        let mut s_taking = session_for("v1");
        assert_eq!(
            m.assume_authority(&mut s_taking, &renewal, t(500, 10_000))
                .err(),
            not_applicable
        );
        // A renewal won by v1 cannot extend the token of a session whose issuer is v2.
        let s_v2 = session_for("v2");
        let tok_v2 = AuthorityToken::issue(&s_v2, 1_000);
        assert_eq!(
            m.renew_lease(&s_v2, &tok_v2, &renewal, t(500, 10_000))
                .err(),
            not_applicable
        );
        // A takeover result for an epoch the session already has is stale.
        let mut s_there = session_for("v1");
        s_there.begin_epoch(2);
        assert_eq!(
            m.assume_authority(&mut s_there, &takeover, t(1_450, 20_000))
                .err(),
            Some(MembershipError::StaleAuthority {
                token_epoch: 2,
                current_epoch: 2
            })
        );
        // And a result gathered long ago is useless once its lease is nearly over:
        // 1_900 + 50 >= 1_950.
        let mut s_late = session_for("v1");
        assert_eq!(
            m.assume_authority(&mut s_late, &takeover, t(1_900, 20_000))
                .err(),
            Some(MembershipError::AuthorityExpired {
                expires_at_ns: 1_950,
                now_ns: 1_900
            })
        );
        let mut s_ok = session_for("v1");
        assert!(
            m.assume_authority(&mut s_ok, &takeover, t(1_899, 20_000))
                .is_ok()
        );
    }

    /// Instants (true time) at which the old holder and the new leader both consider their lease
    /// live, when the holder's clock reads 40 ns behind everyone else's.
    fn overlap_times(uncertainty_ns: u64) -> Vec<u64> {
        const HOLDER_BEHIND: u64 = 40;
        let terms = lease_terms(uncertainty_ns);
        let q = quorum_config(3);
        let mut voters = voters_of(&q, terms);
        found(&mut voters, "v1", 1_000);
        let holder_session = session_for("v1");
        let holder_engine = quorum_engine(terms);
        let holder_token = AuthorityToken::issue(&holder_session, 1_000);

        // The earliest instant the others will grant, by their own clocks.
        let grant_at = 1_000 + uncertainty_ns;
        let request = voters[1].takeover_request(grant_at, 500).unwrap();
        let win = gather(
            &q,
            terms,
            &mut voters,
            &request,
            &[1, 2],
            &[grant_at; 3],
            grant_at,
        )
        .unwrap();
        let mut taker_session = session_for("v1");
        let mut taker_engine = quorum_engine(terms);
        let taker_token = taker_engine
            .assume_authority(&mut taker_session, &win, t(grant_at, 20_000))
            .unwrap();
        (900..1_700)
            .filter(|&true_ns| {
                let holder_live = holder_engine.lease_is_live(
                    &holder_session,
                    &holder_token,
                    true_ns - HOLDER_BEHIND,
                );
                let taker_live = true_ns >= grant_at
                    && taker_engine.lease_is_live(&taker_session, &taker_token, true_ns);
                holder_live && taker_live
            })
            .collect()
    }

    #[test]
    fn without_the_uncertainty_margin_clock_skew_gives_two_live_leaders_and_with_it_it_does_not() {
        // The planted failure: assume perfectly agreeing clocks (u = 0) while the holder's clock
        // actually runs 40 ns behind. The majority grants at its 1_000, which is the holder's 960,
        // and for 40 ns both believe they lead.
        let broken = overlap_times(0);
        assert_eq!(broken, (1_000..1_040).collect::<Vec<u64>>());
        // With a margin at least as large as the skew the same schedule has no overlap.
        assert_eq!(overlap_times(50), Vec::<u64>::new());
        assert_eq!(overlap_times(40), Vec::<u64>::new());
        // Both sides take the margin (the holder stops u early, the taker waits u late), so the
        // overlap window is [1_000 + u, 1_040 - u): it closes at u = 20 and has exactly two
        // instants at u = 19. The contract still requires u to bound the pairwise skew; the extra
        // slack here is not something to rely on.
        assert_eq!(overlap_times(20), Vec::<u64>::new());
        assert_eq!(overlap_times(19), vec![1_019, 1_020]);
    }

    // ---- the seeded partition schedule --------------------------------------------------------

    struct Node {
        voter: LeaseVoter,
        engine: GroupMembership,
        session: UnifiedGroupSession,
        token: Option<AuthorityToken>,
        /// This node's clock reads true time plus this offset.
        offset: i64,
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct PartitionCounts {
        renewals: u32,
        minority_refused: u32,
        takeovers: u32,
        takeovers_refused: u32,
        fenced: u32,
        mutations_accepted: u32,
        led_steps: u32,
        leaderless_steps: u32,
        /// Steps at which two or more nodes considered their lease live at once.
        overlaps: u32,
        /// Two different holders announced for one epoch.
        conflicts: u32,
    }

    /// Nodes that renew, take over, mutate and hear announcements, on a network that partitions at
    /// random and clocks that disagree by up to a bounded offset.
    struct Cluster {
        q: QuorumConfig,
        terms: LeaseTerms,
        nodes: Vec<Node>,
        /// Which side of the current partition each node is on; nodes talk only within a side.
        side: Vec<u8>,
        true_ns: u64,
        winners: BTreeMap<u64, usize>,
        counts: PartitionCounts,
        rng: SplitMix64,
        /// After the prologue, an announcement to a random third of the reachable nodes is lost, so
        /// a voter's own memory of what it granted is what stands between two candidates.
        lossy: bool,
        /// Every announcement is lost (a scripted stretch of the prologue).
        mute: bool,
    }

    impl Cluster {
        fn new(
            seed: u64,
            voters: usize,
            uncertainty_ns: u64,
            max_offset: i64,
            skew_holder: bool,
        ) -> Self {
            let terms = LeaseTerms {
                max_lease_ns: 2_000,
                clock_uncertainty_ns: uncertainty_ns,
                max_output_horizon_ns: 1_000,
            };
            let q = quorum_config(voters);
            let mut rng = SplitMix64(seed);
            let span = u64::try_from(2 * max_offset + 1).unwrap();
            let founding = 11_500;
            let mut nodes: Vec<Node> = Vec::new();
            for mut voter in voters_of(&q, terms) {
                voter.observe(&lease_view(1, "v1", founding)).unwrap();
                let mut offset = i64::try_from(rng.below(span)).unwrap() - max_offset;
                if skew_holder {
                    // The worst case: the holder's clock is the slowest, everyone else's the fastest.
                    offset = if nodes.is_empty() {
                        -max_offset
                    } else {
                        max_offset
                    };
                }
                let session = session_for("v1");
                let token = if nodes.is_empty() {
                    Some(AuthorityToken::issue(&session, founding))
                } else {
                    None
                };
                nodes.push(Node {
                    voter,
                    engine: quorum_engine(terms),
                    session,
                    token,
                    offset,
                });
            }
            Self {
                q,
                terms,
                nodes,
                side: vec![0; voters],
                true_ns: 10_000,
                winners: BTreeMap::new(),
                counts: PartitionCounts::default(),
                rng,
                lossy: false,
                mute: false,
            }
        }

        fn clock(&self, i: usize) -> u64 {
            self.true_ns
                .checked_add_signed(self.nodes[i].offset)
                .expect("clocks stay positive")
        }

        fn time(&self, i: usize) -> GroupTime {
            let ns = self.clock(i);
            GroupTime { ns, frame: ns }
        }

        /// Nodes on the same side of the partition as `i`, `i` included.
        fn reach(&self, i: usize) -> Vec<usize> {
            (0..self.nodes.len())
                .filter(|&j| self.side[j] == self.side[i])
                .collect()
        }

        /// The node holding the highest-epoch token (the lowest index on a tie), if any.
        fn newest_holder(&self) -> Option<usize> {
            (0..self.nodes.len())
                .filter_map(|i| {
                    self.nodes[i]
                        .token
                        .as_ref()
                        .map(|t| (t.epoch, std::cmp::Reverse(i)))
                })
                .max()
                .map(|(_, std::cmp::Reverse(i))| i)
        }

        fn pick_node(&mut self) -> usize {
            let n = u64::try_from(self.nodes.len()).unwrap();
            usize::try_from(self.rng.below(n)).unwrap()
        }

        /// Node `i` sends `request` to its side and gathers the acknowledgements that come back,
        /// each voter judging it by its own clock. `None` if no round could even start.
        fn collect(
            &mut self,
            i: usize,
            request: &LeaseRequest,
        ) -> Option<Result<LeaseWin, MembershipError>> {
            let now = self.clock(i);
            let mut round = QuorumRound::start(&self.q, self.terms, request.clone(), now).ok()?;
            for j in self.reach(i) {
                let at = self.clock(j);
                if let Ok(ack) = self.nodes[j].voter.respond(request, at) {
                    let _ = round.record(&ack, now);
                }
            }
            Some(round.outcome(now))
        }

        fn try_renew(&mut self, i: usize, len: u64) {
            let Some(token) = self.nodes[i].token.clone() else {
                return;
            };
            let now = self.clock(i);
            let Ok(request) = self.nodes[i].voter.renew_request(now, len) else {
                return;
            };
            match self.collect(i, &request) {
                Some(Ok(win)) => {
                    let time = self.time(i);
                    let node = &mut self.nodes[i];
                    if let Ok(renewed) = node.engine.renew_lease(&node.session, &token, &win, time)
                    {
                        node.token = Some(renewed);
                        self.counts.renewals += 1;
                    }
                }
                Some(Err(MembershipError::NoQuorum { .. })) => self.counts.minority_refused += 1,
                Some(Err(_)) | None => {}
            }
        }

        fn try_takeover(&mut self, i: usize, len: u64) {
            let now = self.clock(i);
            let Ok(request) = self.nodes[i].voter.takeover_request(now, len) else {
                return;
            };
            match self.collect(i, &request) {
                Some(Ok(win)) => {
                    let time = self.time(i);
                    let node = &mut self.nodes[i];
                    match node.engine.assume_authority(&mut node.session, &win, time) {
                        Ok(token) => {
                            node.token = Some(token.clone());
                            // The winner learns its own lease like every other voter; without
                            // this its voter keeps the grant and could not renew or retake.
                            node.voter
                                .observe(&token.lease_view())
                                .expect("the winner can observe its own lease");
                            let first = *self.winners.entry(win.epoch()).or_insert(i);
                            assert_eq!(first, i, "two nodes won epoch {}", win.epoch());
                            self.counts.takeovers += 1;
                            self.announce(i, &token.lease_view());
                        }
                        Err(_) => self.counts.takeovers_refused += 1,
                    }
                }
                Some(Err(_)) => self.counts.takeovers_refused += 1,
                None => {}
            }
        }

        /// `from` tells every node on its side which lease is current.
        fn announce(&mut self, from: usize, view: &LeaseView) {
            if self.mute {
                return;
            }
            for j in self.reach(from) {
                if j == from {
                    continue;
                }
                if self.lossy && self.rng.below(3) == 0 {
                    continue;
                }
                let node = &mut self.nodes[j];
                if matches!(
                    node.voter.observe(view),
                    Err(MembershipError::ConflictingLeaders { .. })
                ) {
                    self.counts.conflicts += 1;
                }
                if matches!(
                    node.engine.adopt_authority(&mut node.session, view),
                    Err(MembershipError::ConflictingLeaders { .. })
                ) {
                    self.counts.conflicts += 1;
                }
            }
        }

        /// The newest holder tells everyone it can reach.
        fn gossip(&mut self) {
            let Some(holder) = self.newest_holder() else {
                return;
            };
            let Some(view) = self.nodes[holder]
                .token
                .as_ref()
                .map(AuthorityToken::lease_view)
            else {
                return;
            };
            self.announce(holder, &view);
        }

        /// Node `i` tries to start a membership change under whatever token it holds.
        fn try_mutation(&mut self, i: usize) {
            let Some(token) = self.nodes[i].token.clone() else {
                return;
            };
            let time = self.time(i);
            let node = &mut self.nodes[i];
            let live = node.engine.lease_is_live(&node.session, &token, time.ns);
            let spec = join("c", "S1", time.frame + 100_000, time.ns + 10_000);
            match node.engine.propose(&node.session, &token, spec, time) {
                Ok(id) => {
                    assert!(live, "node {i} proposed on a lease it should consider over");
                    let _ = node.engine.abort(&node.session, &token, id, time);
                    self.counts.mutations_accepted += 1;
                }
                Err(error) => {
                    let fenced = matches!(error, MembershipError::StaleAuthority { .. });
                    if fenced {
                        self.counts.fenced += 1;
                    }
                    if !live {
                        assert!(
                            fenced || matches!(error, MembershipError::AuthorityExpired { .. }),
                            "node {i} was refused for the wrong reason: {error:?}"
                        );
                    }
                }
            }
        }

        fn repartition(&mut self) {
            let together = self.rng.below(4) == 0;
            let sides: Vec<u8> = (0..self.nodes.len())
                .map(|_| {
                    if together {
                        0
                    } else {
                        u8::try_from(self.rng.below(2)).unwrap()
                    }
                })
                .collect();
            self.side = sides;
            self.gossip();
        }

        /// Checked after every step: how many nodes consider their own lease live right now.
        fn check(&mut self) {
            let live = (0..self.nodes.len())
                .filter(|&i| {
                    let node = &self.nodes[i];
                    node.token.as_ref().is_some_and(|token| {
                        node.engine
                            .lease_is_live(&node.session, token, self.clock(i))
                    })
                })
                .count();
            match live {
                0 => self.counts.leaderless_steps += 1,
                1 => self.counts.led_steps += 1,
                _ => self.counts.overlaps += 1,
            }
        }

        /// The paths random choice reaches only occasionally, taken on purpose: a renewal with
        /// everyone connected, a holder cut off from the majority that cannot renew, a takeover by
        /// the majority at the earliest instant every one of its voters will grant (the boundary
        /// probe), the heal, the old holder's fenced mutation, and then the duel for one epoch.
        fn prologue(&mut self) {
            self.true_ns += 200;
            self.try_renew(0, 1_500);
            assert_eq!(self.counts.renewals, 1, "a connected holder renews");
            self.side[0] = 1;
            self.true_ns += 100;
            self.try_renew(0, 1_500);
            assert_eq!(
                self.counts.minority_refused, 1,
                "an isolated holder gets one acknowledgement and no more"
            );
            // The earliest true time at which every other node's clock has reached the holder's
            // expiry plus u. With u = 0 and the holder's clock slowest, the holder still reads a
            // live lease at that instant; with u at least the skew it does not.
            let expiry = self.nodes[0]
                .token
                .as_ref()
                .expect("the holder renewed")
                .expires_at_ns;
            let slowest = self.nodes[1..]
                .iter()
                .map(|n| n.offset)
                .min()
                .expect("there are other nodes");
            let boundary = (expiry + self.terms.clock_uncertainty_ns)
                .checked_add_signed(-slowest)
                .expect("clocks stay positive");
            self.true_ns = self.true_ns.max(boundary);
            self.check();
            self.try_takeover(1, 1_500);
            assert_eq!(self.counts.takeovers, 1, "the majority side takes over");
            self.check();
            self.side = vec![0; self.nodes.len()];
            self.gossip();
            self.try_mutation(0);
            assert_eq!(self.counts.fenced, 1, "the old holder is fenced by epoch");
            self.check();
            self.duel();
        }

        /// Two candidates for one epoch, the first announcement lost. Node 2 wins epoch 3 with
        /// {0, 2, 3}; nodes 1 (and 4) are on the other side and never hear of it, and the
        /// announcement is lost anyway, so node 0 still holds only its grant. Later node 1,
        /// unaware, asks node 0 for the same epoch. Node 0's memory of its grant is all that
        /// stands in the way; a voter that let a rival overwrite it would hand out epoch 3 twice.
        fn duel(&mut self) {
            let n = self.nodes.len();
            let late: Vec<usize> = if n == 5 { vec![1, 4] } else { vec![1] };
            self.true_ns += 4_000;
            self.side = (0..n).map(|j| u8::from(late.contains(&j))).collect();
            self.mute = true;
            let before = self.counts.takeovers;
            self.try_takeover(2, 1_500);
            self.mute = false;
            assert_eq!(
                self.counts.takeovers,
                before + 1,
                "the first candidate wins"
            );
            self.true_ns += 3_000;
            let together: Vec<usize> = if n == 5 { vec![0, 1, 4] } else { vec![0, 1] };
            self.side = (0..n).map(|j| u8::from(!together.contains(&j))).collect();
            self.try_takeover(1, 1_500);
            assert_eq!(
                self.counts.takeovers,
                before + 1,
                "a rival for a granted epoch must not win"
            );
            self.side = vec![0; n];
            self.gossip();
            self.check();
        }

        fn step(&mut self) {
            self.true_ns += 1 + self.rng.below(300);
            let len = 500 + self.rng.below(1_500);
            let actor = self.pick_node();
            match self.rng.below(100) {
                0..30 => {
                    // The newest holder usually renews; sometimes any node, possibly a stale one.
                    let i = if self.rng.below(4) == 0 {
                        actor
                    } else {
                        self.newest_holder().unwrap_or(actor)
                    };
                    self.try_renew(i, len);
                }
                30..65 => self.try_takeover(actor, len),
                65..85 => self.try_mutation(actor),
                _ => self.repartition(),
            }
            self.check();
        }
    }

    fn run_partition_schedule(
        seed: u64,
        uncertainty_ns: u64,
        max_offset: i64,
        skew_holder: bool,
        steps: usize,
    ) -> PartitionCounts {
        let voters = 3 + 2 * usize::try_from(seed % 2).unwrap();
        let mut cluster = Cluster::new(seed, voters, uncertainty_ns, max_offset, skew_holder);
        cluster.prologue();
        cluster.lossy = true;
        for _ in 0..steps {
            cluster.step();
        }
        cluster.counts
    }

    #[test]
    fn seeded_partitions_never_produce_two_live_leaders_or_two_winners_of_an_epoch() {
        let mut total = PartitionCounts::default();
        // Random clock offsets, and the worst case (the holder 50 ns slow, the rest 50 ns fast).
        // Any two clocks differ by at most 100 ns, which is the uncertainty declared.
        for skew_holder in [false, true] {
            for seed in 0..8_u64 {
                let c = run_partition_schedule(seed, 100, 50, skew_holder, 400);
                assert_eq!(
                    c.overlaps, 0,
                    "seed {seed} (worst-case skew {skew_holder}): two nodes held a live lease at once"
                );
                assert_eq!(
                    c.conflicts, 0,
                    "seed {seed}: two holders were announced for one epoch"
                );
                assert!(
                    c.renewals >= 1 && c.minority_refused >= 1 && c.takeovers >= 1 && c.fenced >= 1,
                    "seed {seed} skipped a path: {c:?}"
                );
                total.renewals += c.renewals;
                total.minority_refused += c.minority_refused;
                total.takeovers += c.takeovers;
                total.takeovers_refused += c.takeovers_refused;
                total.fenced += c.fenced;
                total.mutations_accepted += c.mutations_accepted;
                total.led_steps += c.led_steps;
                total.leaderless_steps += c.leaderless_steps;
            }
        }
        // The prologue gives every run one of each path; the random part has to add real traffic
        // on top, with and without a leader. The floors are about a third of what the 16 runs
        // produce, so they trip on a generator that stopped reaching these paths (a winner that
        // never learned of its own lease cannot renew, and its renewals fall far below the floor).
        assert!(total.renewals >= 70, "renewals: {total:?}");
        assert!(total.takeovers >= 45, "takeovers: {total:?}");
        assert!(
            total.takeovers_refused >= 700,
            "refused takeovers: {total:?}"
        );
        assert!(
            total.minority_refused >= 300,
            "minority renewals: {total:?}"
        );
        assert!(total.fenced >= 230, "fenced mutations: {total:?}");
        assert!(
            total.mutations_accepted >= 25,
            "accepted mutations: {total:?}"
        );
        assert!(total.led_steps >= 550, "steps with a leader: {total:?}");
        assert!(
            total.leaderless_steps >= 550,
            "steps without one: {total:?}"
        );
    }

    #[test]
    fn the_same_schedules_without_the_margin_do_produce_two_live_leaders() {
        // The plant: the configuration assumes the clocks agree (u = 0) while the holder's runs
        // 100 ns behind the others. The prologue's boundary probe then finds two live leaders in
        // every seed, so the clean result above is attributable to the margin.
        for seed in 0..8_u64 {
            let c = run_partition_schedule(seed, 0, 50, true, 400);
            assert!(
                c.overlaps >= 1,
                "seed {seed}: no overlap without the margin, so the schedule cannot tell the \
                 difference"
            );
        }
        // Clocks that really do agree need no margin: the default configuration is exact.
        for seed in 0..8_u64 {
            let c = run_partition_schedule(seed, 0, 0, false, 400);
            assert_eq!(c.overlaps, 0, "seed {seed} with agreeing clocks");
            assert_eq!(c.conflicts, 0, "seed {seed} with agreeing clocks");
        }
    }
}
