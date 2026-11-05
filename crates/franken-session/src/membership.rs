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
        if self.group_id != session.group_id {
            return Err(MembershipError::WrongGroup);
        }
        if self.issuer_id != session.coordinator_id {
            return Err(MembershipError::NotConfiguredIssuer);
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
        if now_ns >= self.expires_at_ns {
            return Err(MembershipError::AuthorityExpired {
                expires_at_ns: self.expires_at_ns,
                now_ns,
            });
        }
        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConfig {
    /// A cutover must be at least this many frames ahead, so acknowledgements can arrive.
    pub min_cutover_lead_frames: u64,
    pub max_members: usize,
    pub missing_ack_policy: MissingAckPolicy,
}

impl Default for MembershipConfig {
    fn default() -> Self {
        Self {
            min_cutover_lead_frames: 4_800,
            max_members: MAX_GROUP_MEMBERS,
            missing_ack_policy: MissingAckPolicy::Abort,
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
        }
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
        token.check(session, now_ns)?;
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
        token.check(session, now.ns)?;
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
        token.check(session, now.ns)?;
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
        token.check(session, now.ns)?;
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
        token.check(session, now.ns)?;
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
        let mut s = UnifiedGroupSession::new("grp", "coord", 1);
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
}
