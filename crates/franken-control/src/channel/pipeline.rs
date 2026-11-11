//! The reliable bounded control channel (N02 / `ffw-ugf`).
//!
//! [`ControlChannel`] sits between peers and one [`UnifiedGroupSession`]. A peer
//! [`submit`](ControlChannel::submit)s a signed request; the owner of the session calls
//! [`step`](ControlChannel::step) to apply what has been accepted. The two are separate on purpose:
//! **accepted is not committed**, and the channel never reports one as the other.
//!
//! # Submit: nothing changes until the caller is who it says it is
//!
//! In this order, each stage refusing without having changed the stages after it:
//!
//! 1. **Authenticate** the proof over the request's canonical bytes. A failure changes no state at
//!    all, so a forger cannot spend a real peer's allowance.
//! 2. **Epoch binding**: a peer whose key is bound to epoch *e* cannot issue under any other epoch.
//! 3. **Rate limit**, per authenticated peer and per lane.
//! 4. **Duplicates.** A request already waiting is acknowledged as queued, once. A request that has a
//!    recorded outcome is answered with *that outcome* and is never applied again. The same number
//!    with different content is refused. A number the ledger has forgotten is answered
//!    [`SubmitResult::OutOfWindow`]: unknown, and not applied.
//!    4c. **A relative command at or below its identity's durable floor** ([`seqfloor`](super::seqfloor)) is answered
//!    [`SubmitResult::OutOfWindow`] too: the channel began to apply a relative command with that number, possibly in
//!    an earlier run, and cannot say how it ended. Only relative commands use this table.
//! 5. **Bounded enqueue** into the ordinary or the priority lane. A full lane refuses.
//!
//! # Step: apply, with the authority re-checked
//!
//! Priority first (stop, mute, cancel), at most [`ChannelConfig::max_per_step`] commands per call.
//! Before anything is applied the peer's authority is checked again, so a peer revoked after its
//! command was accepted changes nothing. A remote controller is then held to the **epoch** (stale and
//! ahead are both refused, and the channel never advances the epoch itself) and to its **expected
//! revision**. The local user is never refused for epoch or revision reasons: it acts on what is
//! audible in front of it. Relative volume is resolved against the live state and sent to the session
//! as an absolute. Each outcome is recorded by `(peer, seq)`.
//!
//! # The group lease (G01)
//!
//! A command that changes the group is applied only under a live lease: an `AuthorityToken` the
//! owner installed with [`ControlChannel::install_lease`] and that the session still accepts at the
//! time of the `step`. A deposed leader (a newer epoch), an expired lease, or no lease at all (a
//! channel that has not been given one, or has restarted) refuses before the session is touched.
//! These refusals are **transient**: they are reported in the `step` result but not recorded, so a
//! request sent again after the lease is renewed is judged afresh. A local stop and a local mute-on
//! only silence and need no lease; a cancel only withdraws its own sender's waiting work and needs
//! none either.
//!
//! # What this is not
//!
//! It does not promise exactly-once delivery forever. It promises *at most one application*, an
//! answer for as long as the outcome is remembered, and an explicit "unknown" afterwards. Commands
//! that wait too long expire. Sustained authenticated priority traffic can delay ordinary work; that
//! is bounded by the per-peer priority rate limit and the pending TTL, not eliminated.
//!
//! The channel calls [`UnifiedGroupSession::apply_command`] with its own strictly increasing command
//! numbers, each at least [`ChannelConfig::session_seq_base`] plus the session's revision. Client
//! numbers never reach the session, because two peers' numbers would collide in its single per-epoch
//! sequence space. Tying the number to the revision means a channel that restarts against a session
//! that kept running starts above every number its predecessor used.
//!
//! **Known limit.** That space is shared with every other caller in the same epoch (membership
//! changes), and the session remembers only the newest `COMMAND_DEDUP_WINDOW` numbers of it. Once
//! the channel has committed more than that in one epoch, the session's floor has risen past the small
//! numbers a membership caller would use, and the session refuses them as below its window. Until
//! the session gives the channel a sequence space of its own, a membership change needs a new epoch
//! after that many channel commits. `docs/contracts/n02.md` states this as an open dependency.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use franken_session::{
    AuthorityToken, FencedControlCommand, GroupCommandPayload, GroupMembership, GroupTime,
    LeaseTerms, LeaseWin, MembershipError, SessionError, UnifiedGroupSession,
};

use super::diag::{ChannelLog, Fact, RejectFact, session_error_kind};
use super::ledger::{LedgerError, Lookup, OutcomeLedger};
use super::limiter::{RateLimit, TokenBucket};
use super::peer::{AuthFailure, Authenticated, PeerAuthority, PeerId, PeerRole};
use super::request::{ControlCommand, ControlRequest, Lane, RequestBody};
use super::seqfloor::SeqFloors;

mod ack;
mod boot;
mod persist;
#[cfg(test)]
mod profile;
mod restart;
mod submit_log;

pub use ack::AckOutcome;
pub use boot::{Booted, DurableBoot, Limits, Storage, StorageFault, boot_durable, reopen_durable};
pub use persist::{
    Cause, DevelopmentVolatile, Durable, FloorCause, HIGH_WATER_KEY, LatchedStepper,
    MemoryJournalStepper, OwnedDurable, REFUSING_FLOOR, RamMedium, Reopened, Restored,
    RestoredFloors, SEQ_FLOORS_KEY, Stepper, StoreFailed, reopen_from_open, restore_from_open,
    restore_seq_floors_from_open, step_then_store, store_high_water,
};
pub use restart::HighWaterError;
pub use submit_log::MAX_PENDING_REJECTS;

/// How a command ended, as remembered in the ledger and returned on a retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Applied; `revision` is the session's state revision after it.
    Committed { revision: u64 },
    /// Removed by a cancel before it was applied.
    Withdrawn,
    /// This command was a cancel, and it withdrew `target_seq`.
    CancelApplied { target_seq: u64 },
    /// Accepted, then refused with no effect.
    Refused(Refusal),
}

/// Why an accepted command had no effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    StaleEpoch {
        request: u64,
        current: u64,
    },
    EpochAhead {
        request: u64,
        current: u64,
    },
    /// A relative command's revision is not the current one, or a command names a revision that does
    /// not exist yet.
    RevisionMismatch {
        expected: u64,
        actual: u64,
    },
    /// A volume or mute command was composed against a revision older than this incarnation's start,
    /// which is how a copy delayed across a restart looks. Nothing was changed; read the group state
    /// and send a fresh command.
    StaleRevision {
        observed: u64,
        floor: u64,
    },
    UnknownMember {
        member_id: String,
    },
    /// The session refused the command for a reason about its content, such as an unknown member.
    Session(SessionError),
    /// The session refused the command for a reason that cannot be the sender's doing: a repeated or
    /// out-of-window command number, or a stale epoch. The channel's own bookkeeping disagrees with the
    /// session. It is counted (`ChannelStats::internal_faults`) and the detail is kept for the operator
    /// (`ControlChannel::last_internal_fault`), but it is never shown to the sender. The sender should
    /// read the group state and send a new command under a new number.
    InternalFault,
    /// The peer was revoked, or its binding changed, after the command was accepted. (This is the
    /// peer's key authority, not the group lease below.)
    AuthorityExpired,
    /// The channel holds no group lease: none was installed, or the channel restarted since. Nothing
    /// was changed. **Transient:** not recorded, so the same request can be sent again once a lease is
    /// installed.
    NoLease,
    /// The group lease the channel holds is no longer live for this group (superseded by a newer
    /// epoch, or expired), as the session's own `AuthorityToken::check` judges it. Nothing was
    /// changed. **Transient:** not recorded; renew the lease and send the request again.
    Lease(MembershipError),
    /// Waited in the queue longer than the pending TTL.
    Expired,
    /// A cancel found its target already settled.
    TooLateToCancel,
    /// A cancel found no such command of the same peer.
    NothingToCancel,
    /// A cancel's target is older than the ledger remembers.
    TargetOutOfWindow {
        floor: u64,
    },
    /// A cancel's target is a stop or a mute, which are not withdrawn.
    NotCancellable,
}

/// Why a request was turned away before it was accepted. Nothing was recorded and its number is not
/// consumed, so it can be sent again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    Unauthenticated(AuthFailure),
    EpochNotBound {
        bound: u64,
        request: u64,
    },
    /// A remote controller sent a volume or mute command without the revision it last read.
    RevisionRequired {
        command: &'static str,
    },
    RateLimited {
        lane: Lane,
        retry_after_ns: u64,
    },
    QueueFull {
        lane: Lane,
    },
    /// The same peer and number as an earlier request, with different content.
    IdReuse,
}

/// What `submit` tells the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitResult {
    /// Received and queued. **Not** committed.
    Queued {
        lane: Lane,
    },
    /// A copy of this request is already waiting.
    AlreadyQueued {
        lane: Lane,
    },
    /// A retry of a command whose outcome is on record: here is that outcome.
    Settled(Outcome),
    /// The ledger no longer remembers this number. Whether it was applied is unknown; it will not be
    /// applied now. Read the group state to reconcile.
    OutOfWindow {
        floor: u64,
    },
    Rejected(Rejection),
}

/// One command that reached its terminal outcome during a `step`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub peer: PeerId,
    pub seq: u64,
    pub outcome: Outcome,
}

/// Why a lease could not be renewed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenewError {
    #[error("the channel holds no lease to renew")]
    NoLease,
    /// The engine (or the session's check of the renewed token) refused. The held lease is unchanged.
    #[error("the renewal was refused: {0}")]
    Refused(#[from] MembershipError),
}

/// A configuration the channel cannot run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("`{field}` must be at least 1")]
    Zero { field: &'static str },
    #[error("invalid ledger: {0}")]
    Ledger(#[from] LedgerError),
}

/// Sizes, windows and limits. Every one is a bound; none is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelConfig {
    /// Most ordinary commands waiting at once.
    pub ordinary_capacity: usize,
    /// Priority slots any authenticated peer may use.
    pub priority_shared_capacity: usize,
    /// Priority slots only the local user may use, so a flood of remote stops cannot take them.
    pub priority_local_reserved: usize,
    /// Most outcomes remembered.
    pub ledger_capacity: usize,
    /// How long an outcome is remembered.
    pub retention_ns: u64,
    /// How long an accepted command may wait before it expires unapplied.
    pub pending_ttl_ns: u64,
    /// Most commands applied per `step`.
    pub max_per_step: usize,
    pub ordinary_rate: RateLimit,
    pub priority_rate: RateLimit,
    /// How far short of its expiry the held lease stops being usable, in nanoseconds: G01's clock
    /// uncertainty `u` (`MembershipConfig::lease.clock_uncertainty_ns`). The holder stops `u` before its
    /// lease ends and a taker waits `u` after, which is what keeps two leaders from sounding at once when
    /// clocks disagree by up to `u`. Zero (the default) assumes perfectly agreeing clocks and makes the
    /// gate identical to the plain expiry check. Set it from the engine's terms with
    /// [`ChannelConfig::with_lease_terms`] so the channel and the engine refuse at the same instant.
    pub lease_margin_ns: u64,
    /// How long after its outcome was recorded an acknowledgement is still on time. A later one, while
    /// the outcome is still remembered, is recorded as `Late`. It has no other effect: nothing waits for
    /// an acknowledgement. Provisional, and unrelated to `retention_ns` except that a budget at or above
    /// the retention can never be exceeded while the outcome is remembered.
    pub ack_budget_ns: u64,
    /// The lowest command number the channel passes to the session. Each number is the larger of the
    /// previous one plus one and this base plus the session's `state_revision`, so a channel that
    /// restarts against a session that kept running is carried above every number it used before
    /// without remembering any of them. Other callers of the session in the same epoch keep to numbers
    /// below the base.
    pub session_seq_base: u64,
}

impl ChannelConfig {
    /// A starting point, **provisional and unmeasured**: the bead names no numbers for these, and
    /// they have not been tuned against a board. Callers that need different bounds set the fields.
    #[must_use]
    pub fn provisional() -> Self {
        Self {
            ordinary_capacity: 16,
            priority_shared_capacity: 4,
            priority_local_reserved: 2,
            ledger_capacity: 64,
            retention_ns: 30_000 * MS,
            pending_ttl_ns: 5_000 * MS,
            max_per_step: 4,
            ordinary_rate: PROVISIONAL_ORDINARY_RATE,
            priority_rate: PROVISIONAL_PRIORITY_RATE,
            lease_margin_ns: 0,
            ack_budget_ns: 2_000 * MS,
            session_seq_base: 1 << 32,
        }
    }

    /// Take the lease margin from G01's lease terms (the owner's `MembershipConfig::lease`).
    #[must_use]
    pub fn with_lease_terms(mut self, terms: &LeaseTerms) -> Self {
        self.lease_margin_ns = terms.clock_uncertainty_ns;
        self
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let fields = [
            ("ordinary_capacity", self.ordinary_capacity),
            ("priority_shared_capacity", self.priority_shared_capacity),
            ("priority_local_reserved", self.priority_local_reserved),
            ("max_per_step", self.max_per_step),
        ];
        for (field, value) in fields {
            if value == 0 {
                return Err(ConfigError::Zero { field });
            }
        }
        if self.pending_ttl_ns == 0 {
            return Err(ConfigError::Zero {
                field: "pending_ttl_ns",
            });
        }
        if self.ack_budget_ns == 0 {
            return Err(ConfigError::Zero {
                field: "ack_budget_ns",
            });
        }
        // The ledger checks its own capacity and retention when it is built.
        Ok(())
    }
}

const MS: u64 = 1_000_000;

/// A rate limit from constants. A zero parameter is a compile-time error here, not a runtime one.
const fn const_rate(burst: u32, interval_ns: u64) -> RateLimit {
    match RateLimit::new(burst, interval_ns) {
        Ok(limit) => limit,
        Err(_) => panic!("a provisional rate limit must have a non-zero burst and interval"),
    }
}

const PROVISIONAL_ORDINARY_RATE: RateLimit = const_rate(8, 100 * MS);
const PROVISIONAL_PRIORITY_RATE: RateLimit = const_rate(4, 250 * MS);

/// Counters. Every call to `submit` lands in exactly one of the buckets after `received`,
/// so `accounted() == received` always; `committed` and the rest count what `step` did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelStats {
    pub received: u64,
    pub rejected_unauthenticated: u64,
    pub rejected_epoch_not_bound: u64,
    pub rejected_revision_required: u64,
    pub rejected_rate_limited: u64,
    pub rejected_queue_full: u64,
    pub rejected_id_reuse: u64,
    pub answered_from_ledger: u64,
    pub answered_already_queued: u64,
    pub out_of_window: u64,
    pub accepted: u64,
    pub committed: u64,
    pub cancels_applied: u64,
    pub withdrawn: u64,
    pub refused: u64,
    pub expired_pending: u64,
    /// Commands the session refused for a reason that was not the sender's. Zero in correct operation.
    pub internal_faults: u64,
    /// Commands refused because the channel held no live group lease (`NoLease` or `Lease`). These are
    /// also counted in `refused`; they are not recorded in the ledger.
    pub refused_for_lease: u64,
    /// An outcome that could not be recorded. Zero in correct operation.
    pub ledger_record_failures: u64,
    /// Every acknowledgement received, and then exactly one of the buckets below
    /// (`acks_accounted() == acks_received`).
    pub acks_received: u64,
    pub acks_rejected_unauthenticated: u64,
    pub acks_on_time: u64,
    pub acks_late: u64,
    pub acks_superseded: u64,
    pub acks_duplicate: u64,
    pub acks_not_settled: u64,
    pub acks_unknown: u64,
    pub acks_out_of_window: u64,
    pub acks_mismatch: u64,
}

impl ChannelStats {
    /// Everything `acknowledge` did with the acknowledgements it received.
    #[must_use]
    pub const fn acks_accounted(&self) -> u64 {
        self.acks_rejected_unauthenticated
            + self.acks_on_time
            + self.acks_late
            + self.acks_superseded
            + self.acks_duplicate
            + self.acks_not_settled
            + self.acks_unknown
            + self.acks_out_of_window
            + self.acks_mismatch
    }

    /// Everything `submit` did with the requests it received.
    #[must_use]
    pub const fn accounted(&self) -> u64 {
        self.rejected_unauthenticated
            + self.rejected_epoch_not_bound
            + self.rejected_revision_required
            + self.rejected_rate_limited
            + self.rejected_queue_full
            + self.rejected_id_reuse
            + self.answered_from_ledger
            + self.answered_already_queued
            + self.out_of_window
            + self.accepted
    }
}

/// A snapshot for diagnostics. `received` and `committed_revision` are reported side by side so a
/// request that arrived is never presented as one that took effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostics {
    pub stats: ChannelStats,
    pub ordinary_pending: usize,
    pub priority_pending: usize,
    pub ledger_len: usize,
    pub tracked_peers: usize,
    pub committed_revision: u64,
}

#[derive(Clone)]
struct Queued {
    auth: Authenticated,
    request: ControlRequest,
    accepted_ns: u64,
}

/// When a command settled, when it was accepted, and the session's revision at that moment.
#[derive(Clone, Copy)]
struct Settled {
    now_ns: u64,
    accepted_ns: u64,
    revision: u64,
}

/// The member a command names, if it names one. Used only to pseudonymize it for the log.
fn member_named(command: &ControlCommand) -> Option<String> {
    match command {
        ControlCommand::SetMemberVolume { member_id, .. }
        | ControlCommand::AdjustMemberVolume { member_id, .. }
        | ControlCommand::SetMemberMute { member_id, .. } => Some(member_id.clone()),
        ControlCommand::SetGroupVolume { .. }
        | ControlCommand::AdjustGroupVolume { .. }
        | ControlCommand::StopGroupPlayback { .. }
        | ControlCommand::Cancel { .. } => None,
    }
}

enum Looked {
    Settled { same: bool, outcome: Outcome },
    OutOfWindow(u64),
    Unseen,
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Where a relative command's duplicate-suppression record is made durable **before** the command takes effect
/// ([`ControlChannel::step_reserving`]).
pub trait FloorStore {
    /// Make `packed` durable: an encoded [`SeqFloors`] that already covers the command about to run. On `Err` the
    /// store must not rely on anything it wrote, and the command is not run.
    fn store(&mut self, packed: &[u8]) -> Result<(), FloorNotStored>;
}

/// A [`FloorStore`] could not make its record durable. The code is the store's own stable word for why (the journal's
/// error code), bounded, and kept for the operator's log; it is never shown to the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorNotStored {
    pub code: &'static str,
}

/// Whether the channel can still make its steps durable ([`ControlChannel::durability`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    Healthy,
    /// A store failed, or the journal is poisoned: what the medium holds is no longer known. Latched until the owner
    /// reopens the journal and says so ([`reopen_from_open`]). While latched no step is staged or written; the local
    /// user's stop and mute-on are applied to the live session, a cancel still withdraws, and every other command is
    /// refused (`Refusal::InternalFault`, cause `durability_failed`, not recorded, so it can be sent again after the
    /// reopen).
    Failed {
        code: &'static str,
    },
}

/// Why the refusal being settled is a store matter. Read, and cleared, by `settle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreCause {
    /// The command's floor could not be made durable (the code says why). Recorded: send under a new number.
    Reservation(&'static str),
    /// The durable path is latched failed. Not recorded.
    Degraded,
}

/// What plain [`ControlChannel::step`] passes: a store that is never asked, because it is never given.
struct NoFloorStore;

impl FloorStore for NoFloorStore {
    fn store(&mut self, _packed: &[u8]) -> Result<(), FloorNotStored> {
        Ok(())
    }
}

/// The channel. Generic over the [`PeerAuthority`] that decides who may speak.
pub struct ControlChannel<A: PeerAuthority> {
    authority: A,
    config: ChannelConfig,
    ordinary: VecDeque<Queued>,
    priority: VecDeque<Queued>,
    ledger: OutcomeLedger<RequestBody, Outcome>,
    /// The highest relative-command number the channel has begun to apply for each identity, restored at boot and
    /// made durable before each relative effect when the owner steps with a [`FloorStore`].
    seq_floors: SeqFloors,
    /// Identities whose retries carry no stable number (the legacy SOAP bridge composes a fresh number for every
    /// request, so a floor could never match a retry). They are never given a floor: no write, and no promise.
    /// Bounded by the number of identities the table can hold.
    unstable_retry: BTreeSet<PeerId>,
    durability: Durability,
    /// Set where a refusal is made for a store reason, taken by `settle`.
    store_cause: Option<StoreCause>,
    /// While a durable step is open the facts it gathers wait here instead of going to the log.
    defer_facts: bool,
    /// The local user's stop and mute-on that the open durable step applied (to its copy of the session). If the step
    /// cannot be made durable they are applied again, to the live session: see `apply_silencing_live`.
    silenced: Vec<Queued>,
    buckets: BTreeMap<(PeerId, Lane), TokenBucket>,
    next_session_seq: u64,
    /// The session's `state_revision` at this incarnation's first `step`. A volume or mute command
    /// composed against anything older predates the incarnation and is refused as stale. After a full
    /// process restart it is at least the restored high-water mark (see `restart`).
    revision_floor: Option<u64>,
    /// The stored high-water mark the owner restored before the first `step`; zero if none.
    restored_high_water: u64,
    /// The group lease (G01 `AuthorityToken`) under which this channel may mutate the group. `None`
    /// until the owner installs one, and again after a restart: the channel fails closed.
    lease: Option<AuthorityToken>,
    last_internal_fault: Option<SessionError>,
    /// The JSONL diagnostics log, if the owner enabled one, and the settled commands waiting to be
    /// written to it at the end of the current `step`.
    log: Option<ChannelLog>,
    facts: Vec<Fact>,
    /// The requests turned away at `submit` that are waiting for the session to be at hand so their records can
    /// be written (see `submit_log`). Bounded by [`MAX_PENDING_REJECTS`]; empty unless a log is enabled.
    reject_facts: Vec<RejectFact>,
    stats: ChannelStats,
}

impl<A: PeerAuthority> ControlChannel<A> {
    /// Build a channel, refusing a configuration with a zero bound.
    pub fn new(authority: A, config: ChannelConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let ledger = OutcomeLedger::new(config.ledger_capacity, config.retention_ns)?;
        let profile = authority.control_profile();
        Ok(Self {
            authority,
            next_session_seq: config.session_seq_base,
            revision_floor: None,
            restored_high_water: 0,
            lease: None,
            config,
            ordinary: VecDeque::new(),
            priority: VecDeque::new(),
            ledger,
            seq_floors: SeqFloors::with_profile(profile),
            unstable_retry: BTreeSet::new(),
            durability: Durability::Healthy,
            store_cause: None,
            defer_facts: false,
            silenced: Vec::new(),
            buckets: BTreeMap::new(),
            last_internal_fault: None,
            log: None,
            facts: Vec::new(),
            reject_facts: Vec::new(),
            stats: ChannelStats::default(),
        })
    }

    #[must_use]
    pub fn authority(&self) -> &A {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }

    #[must_use]
    pub fn config(&self) -> &ChannelConfig {
        &self.config
    }

    #[must_use]
    pub fn stats(&self) -> &ChannelStats {
        &self.stats
    }

    /// Install the group lease this channel acts under, if `session` accepts it at `now_ns`. This is
    /// the same gate G01's `discover_authority` applies: a token for another group or issuer, for a
    /// stale or future epoch, or already expired is refused with the session's own error, and the
    /// lease already held is left alone. `now_ns` must be on the timebase of the token's
    /// `expires_at_ns` (the group's monotonic nanoseconds), the same one `step` is given.
    ///
    /// The token is not a credential: it names no secret and anyone could write one. Installing it is
    /// the owner's act, after it has obtained the lease from the group's authority; what the channel
    /// adds is that it keeps checking the lease against the session on every group-affecting command.
    pub fn install_lease(
        &mut self,
        session: &UnifiedGroupSession,
        token: AuthorityToken,
        now_ns: u64,
    ) -> Result<(), MembershipError> {
        token.check_with_margin(session, now_ns, self.config.lease_margin_ns)?;
        self.lease = Some(token);
        Ok(())
    }

    /// Extend the lease this channel holds to what a voter quorum acknowledged (G01 `renew_lease`), and
    /// install the result. The renewal is judged by the engine under its own rule: the group must be in
    /// quorum mode, the held lease must still be live at `now` (by the margin), the win must be a renewal
    /// by this lease's holder for this lease's epoch, and it must extend the lease, and not past the
    /// maximum. Any refusal is the engine's own error and leaves the held lease as it was.
    ///
    /// A holder whose lease has lapsed cannot be renewed (`AUTHORITY_EXPIRED`): the majority may already
    /// be taking over. It has to win a new epoch instead, and the owner installs the token that
    /// `GroupMembership::assume_authority` returns with [`ControlChannel::install_lease`]. A holder
    /// that has learned of a newer holder (`adopt_authority`) is fenced with no extra code: its old lease
    /// is a stale epoch to the session, so the gate refuses it.
    pub fn renew_lease(
        &mut self,
        membership: &mut GroupMembership,
        session: &UnifiedGroupSession,
        win: &LeaseWin,
        now: GroupTime,
    ) -> Result<(), RenewError> {
        let Some(held) = self.lease.clone() else {
            return Err(RenewError::NoLease);
        };
        let renewed = membership.renew_lease(session, &held, win, now)?;
        self.install_lease(session, renewed, now.ns)?;
        Ok(())
    }

    /// The lease currently held, if any.
    #[must_use]
    pub fn lease(&self) -> Option<&AuthorityToken> {
        self.lease.as_ref()
    }

    /// Start writing one JSONL record per settled command to `log` (see [`super::diag`]), and one per request
    /// turned away at `submit`. Records are written at the end of each `step` (and, for a request turned away, when
    /// the owner calls `flush_log`); the owner drains the log with [`ChannelLog::drain`].
    pub fn enable_log(&mut self, log: ChannelLog) {
        self.log = Some(log);
    }

    #[must_use]
    pub fn log(&self) -> Option<&ChannelLog> {
        self.log.as_ref()
    }

    pub fn log_mut(&mut self) -> Option<&mut ChannelLog> {
        self.log.as_mut()
    }

    /// The session revision this incarnation started from (or the restored high-water mark, if that is
    /// higher), known once the first `step` has run.
    #[must_use]
    pub fn revision_floor(&self) -> Option<u64> {
        self.revision_floor
    }

    /// The session error behind the most recent `Refusal::InternalFault`, for the operator. Holds a
    /// member id or numbers at most; never a key or a proof.
    #[must_use]
    pub fn last_internal_fault(&self) -> Option<&SessionError> {
        self.last_internal_fault.as_ref()
    }

    /// Whether the durable path is intact. `Failed` is latched by `step_then_store` on the first store that fails, and
    /// cleared only by [`reopen_from_open`]. The owner should raise an alarm: the group is controllable at the device
    /// (stop, mute) and nowhere else.
    #[must_use]
    pub fn durability(&self) -> Durability {
        self.durability
    }

    /// Declare that `peer` sends requests whose retries carry no stable number, so no floor can mean anything for it.
    /// The channel then reserves nothing for its relative commands (no journal write, no `OutOfWindow` after a
    /// restart), and does not pretend to deduplicate them. This is the owner's configuration of the channel, made
    /// from the identity it admitted; no request can ask for it. Returns `false` if the table of such identities is
    /// full.
    pub fn declare_unstable_retry_ids(&mut self, peer: &PeerId) -> bool {
        if self.unstable_retry.contains(peer) {
            return true;
        }
        if self.unstable_retry.len() >= super::seqfloor::MAX_ENTRIES {
            return false;
        }
        self.unstable_retry.insert(peer.clone())
    }

    /// The highest relative-command number the channel has begun to apply for `peer`, if it has one on record. `None`
    /// if there is none, or if the floors could not be read (then every relative command is refused anyway).
    #[must_use]
    pub fn seq_floor(&self, peer: &PeerId) -> Option<u64> {
        if self.seq_floors.is_refusing() {
            return None;
        }
        self.seq_floors.floor_of(peer)
    }

    #[must_use]
    pub fn pending(&self, lane: Lane) -> usize {
        match lane {
            Lane::Ordinary => self.ordinary.len(),
            Lane::Priority => self.priority.len(),
        }
    }

    #[must_use]
    pub fn diagnostics(&self, session: &UnifiedGroupSession) -> Diagnostics {
        Diagnostics {
            stats: self.stats,
            ordinary_pending: self.ordinary.len(),
            priority_pending: self.priority.len(),
            ledger_len: self.ledger.len(),
            tracked_peers: self.ledger.tracked_peers(),
            committed_revision: session.state_revision,
        }
    }

    fn take_token(&mut self, peer: &PeerId, lane: Lane, now_ns: u64) -> Result<(), u64> {
        let limit = match lane {
            Lane::Ordinary => self.config.ordinary_rate,
            Lane::Priority => self.config.priority_rate,
        };
        self.buckets
            .entry((peer.clone(), lane))
            .or_insert_with(|| TokenBucket::new(limit, now_ns))
            .try_take(now_ns)
    }

    fn find_pending(&self, peer: &PeerId, seq: u64) -> Option<(Lane, &Queued)> {
        let matches =
            |q: &&Queued| q.request.body().peer() == peer && q.request.body().seq() == seq;
        if let Some(q) = self.priority.iter().find(matches) {
            return Some((Lane::Priority, q));
        }
        self.ordinary
            .iter()
            .find(matches)
            .map(|q| (Lane::Ordinary, q))
    }

    fn has_room(&self, lane: Lane, role: PeerRole) -> bool {
        match lane {
            Lane::Ordinary => self.ordinary.len() < self.config.ordinary_capacity,
            Lane::Priority => {
                let reserved = self.config.priority_local_reserved;
                let shared = self.config.priority_shared_capacity;
                let local = self
                    .priority
                    .iter()
                    .filter(|q| q.auth.role == PeerRole::LocalUser)
                    .count();
                let others = self.priority.len() - local;
                // Local entries beyond the reserved slots spill into the shared pool.
                let shared_used = others + local.saturating_sub(reserved);
                match role {
                    PeerRole::LocalUser => local < reserved || shared_used < shared,
                    PeerRole::Controller => shared_used < shared,
                }
            }
        }
    }

    /// Receive a request. See the module documentation for the order of the stages.
    pub fn submit(&mut self, now_ns: u64, request: ControlRequest) -> SubmitResult {
        // What the sender claimed, kept only if a log will want it: the decision below consumes the request.
        let claimed = self
            .log
            .is_some()
            .then(|| (request.body().peer().clone(), request.body().seq()));
        let result = self.decide_submit(now_ns, request);
        self.note_submit(now_ns, claimed, &result);
        result
    }

    /// The decision `submit` returns, made before any log is told of it.
    fn decide_submit(&mut self, now_ns: u64, request: ControlRequest) -> SubmitResult {
        bump(&mut self.stats.received);
        let body = request.body();

        // 1. Authenticate, before anything else is touched.
        let auth =
            match self
                .authority
                .authenticate(body.peer(), &body.signing_bytes(), request.proof())
            {
                Ok(auth) => auth,
                Err(failure) => {
                    bump(&mut self.stats.rejected_unauthenticated);
                    return SubmitResult::Rejected(Rejection::Unauthenticated(failure));
                }
            };

        // 2. A key bound to one epoch is not valid under another.
        if let Some(bound) = auth.bound_epoch
            && bound != body.epoch()
        {
            bump(&mut self.stats.rejected_epoch_not_bound);
            return SubmitResult::Rejected(Rejection::EpochNotBound {
                bound,
                request: body.epoch(),
            });
        }

        // 3. Rate limit, per peer and lane.
        let lane = body.command().lane();
        if let Err(retry_after_ns) = self.take_token(&auth.peer, lane, now_ns) {
            bump(&mut self.stats.rejected_rate_limited);
            return SubmitResult::Rejected(Rejection::RateLimited {
                lane,
                retry_after_ns,
            });
        }

        // 3b. A remote controller's volume or mute command names the revision it last read.
        if auth.role == PeerRole::Controller
            && body.command().needs_observed_revision()
            && body.expected_revision().is_none()
        {
            bump(&mut self.stats.rejected_revision_required);
            return SubmitResult::Rejected(Rejection::RevisionRequired {
                command: body.command().label(),
            });
        }

        // 4a. A copy already waiting.
        let waiting = self
            .find_pending(body.peer(), body.seq())
            .map(|(found_lane, queued)| (found_lane, queued.request.body() == body));
        match waiting {
            Some((found_lane, true)) => {
                bump(&mut self.stats.answered_already_queued);
                return SubmitResult::AlreadyQueued { lane: found_lane };
            }
            Some((_, false)) => {
                bump(&mut self.stats.rejected_id_reuse);
                return SubmitResult::Rejected(Rejection::IdReuse);
            }
            None => {}
        }

        // 4b. An outcome on record, or a number the ledger has forgotten.
        self.ledger.expire(now_ns);
        let looked = match self.ledger.lookup(body.peer(), body.seq()) {
            Lookup::Settled {
                body: recorded,
                outcome,
            } => Looked::Settled {
                same: recorded == body,
                outcome: outcome.clone(),
            },
            Lookup::OutOfWindow { floor } => Looked::OutOfWindow(floor),
            Lookup::Unseen => Looked::Unseen,
        };
        match looked {
            Looked::Settled {
                same: true,
                outcome,
            } => {
                bump(&mut self.stats.answered_from_ledger);
                return SubmitResult::Settled(outcome);
            }
            Looked::Settled { same: false, .. } => {
                bump(&mut self.stats.rejected_id_reuse);
                return SubmitResult::Rejected(Rejection::IdReuse);
            }
            Looked::OutOfWindow(floor) => {
                bump(&mut self.stats.out_of_window);
                return SubmitResult::OutOfWindow { floor };
            }
            Looked::Unseen => {}
        }

        // 4c. A relative command at or below its identity's durable floor: the channel began to apply a relative
        // command with that number (this run or an earlier one) and cannot say how it ended. Unknown, never again.
        if body.command().is_relative()
            && let Some(floor) = self.seq_floors.floor_of(body.peer())
            && body.seq() <= floor
        {
            bump(&mut self.stats.out_of_window);
            return SubmitResult::OutOfWindow { floor };
        }

        // 5. Bounded enqueue.
        if !self.has_room(lane, auth.role) {
            bump(&mut self.stats.rejected_queue_full);
            return SubmitResult::Rejected(Rejection::QueueFull { lane });
        }
        let queued = Queued {
            auth,
            request,
            accepted_ns: now_ns,
        };
        match lane {
            Lane::Ordinary => self.ordinary.push_back(queued),
            Lane::Priority => self.priority.push_back(queued),
        }
        bump(&mut self.stats.accepted);
        SubmitResult::Queued { lane }
    }

    fn settle(
        &mut self,
        body: RequestBody,
        outcome: Outcome,
        times: Settled,
        out: &mut Vec<Settlement>,
    ) {
        let Settled {
            now_ns,
            accepted_ns,
            revision,
        } = times;
        match &outcome {
            Outcome::Committed { .. } => bump(&mut self.stats.committed),
            Outcome::Withdrawn => bump(&mut self.stats.withdrawn),
            Outcome::CancelApplied { .. } => bump(&mut self.stats.cancels_applied),
            Outcome::Refused(refusal) => {
                bump(&mut self.stats.refused);
                if matches!(refusal, Refusal::Expired) {
                    bump(&mut self.stats.expired_pending);
                }
                if matches!(refusal, Refusal::InternalFault) {
                    bump(&mut self.stats.internal_faults);
                }
                if matches!(refusal, Refusal::NoLease | Refusal::Lease(_)) {
                    bump(&mut self.stats.refused_for_lease);
                }
            }
        }
        let peer = body.peer().clone();
        let seq = body.seq();
        let store_cause = self.store_cause.take();
        let degraded = store_cause == Some(StoreCause::Degraded);
        // A refusal for want of a live lease says nothing about the command, only about the moment:
        // it took no effect, so recording it would make a resend after renewal come back refused. The same is true
        // of a refusal because the durable path is latched failed.
        let transient = degraded
            || matches!(
                outcome,
                Outcome::Refused(Refusal::NoLease | Refusal::Lease(_))
            );
        let member = member_named(body.command());
        // A latched path refuses everything it does not silence; that is one critical event (the latch), not one
        // per refusal, so a flood of refusals cannot fill the log's critical room.
        let mut critical = matches!(outcome, Outcome::Refused(Refusal::InternalFault)) && !degraded;
        if !transient
            && !self
                .ledger
                .record(peer.clone(), seq, body, outcome.clone(), now_ns)
        {
            bump(&mut self.stats.ledger_record_failures);
            critical = true;
        }
        if self.log.is_some() {
            let cause = match store_cause {
                Some(StoreCause::Reservation(code)) => Some(format!("store_{code}")),
                Some(StoreCause::Degraded) => Some("durability_failed".to_string()),
                None => self.cause_of(&outcome),
            };
            let queue_depth = self.ordinary.len() + self.priority.len();
            self.facts.push(Fact {
                peer: peer.clone(),
                seq,
                member,
                cause,
                outcome: outcome.clone(),
                revision,
                queue_depth,
                waited_ns: now_ns.saturating_sub(accepted_ns),
                critical,
            });
        }
        out.push(Settlement { peer, seq, outcome });
    }

    /// The vocabulary word behind a refusal, for the log. Never a session error's text.
    fn cause_of(&self, outcome: &Outcome) -> Option<String> {
        match outcome {
            Outcome::Refused(Refusal::Lease(error)) => Some(error.code().to_lowercase()),
            Outcome::Refused(Refusal::Session(error)) => {
                Some(session_error_kind(error).to_string())
            }
            Outcome::Refused(Refusal::InternalFault) => self
                .last_internal_fault
                .as_ref()
                .map(|error| session_error_kind(error).to_string()),
            _ => None,
        }
    }

    fn expire_pending(&mut self, now_ns: u64, revision: u64, out: &mut Vec<Settlement>) {
        let ttl = self.config.pending_ttl_ns;
        let stale = |q: &Queued| now_ns.saturating_sub(q.accepted_ns) >= ttl;
        let mut expired = Vec::new();
        for queue in [&mut self.priority, &mut self.ordinary] {
            while let Some(pos) = queue.iter().position(stale) {
                if let Some(item) = queue.remove(pos) {
                    expired.push(item);
                }
            }
        }
        for item in expired {
            self.settle(
                item.request.body().clone(),
                Outcome::Refused(Refusal::Expired),
                Settled {
                    now_ns,
                    accepted_ns: item.accepted_ns,
                    revision,
                },
                out,
            );
        }
    }

    /// The next priority command: the local user's first, otherwise the oldest. A remote peer, however
    /// many shared slots it fills, therefore cannot put anything ahead of the person at the device.
    fn pop_priority(&mut self) -> Option<Queued> {
        let position = self
            .priority
            .iter()
            .position(|q| q.auth.role == PeerRole::LocalUser)
            .unwrap_or(0);
        self.priority.remove(position)
    }

    /// Apply what has been accepted: expire stale entries, then at most `max_per_step` commands,
    /// priority first (the local user's before any remote peer's). Returns what reached a terminal
    /// outcome.
    ///
    /// This persists nothing: a relative command takes effect with no durable record that it did. An owner that
    /// keeps a journal steps with [`ControlChannel::step_reserving`] (or, better, `step_then_store`).
    pub fn step(&mut self, now_ns: u64, session: &mut UnifiedGroupSession) -> Vec<Settlement> {
        self.step_inner::<NoFloorStore>(now_ns, session, None)
    }

    /// Whether any command is waiting to be applied (or to expire). A step with none has nothing to stage.
    fn has_work(&self) -> bool {
        !self.ordinary.is_empty() || !self.priority.is_empty()
    }

    /// [`ControlChannel::step`], with each **relative** command's duplicate-suppression record made durable first.
    ///
    /// Immediately before a relative command is applied to the session, after every check that could refuse it for
    /// a reason that leaves it free to be sent again, `store` is asked to make the identity's raised floor durable.
    /// If it cannot, the command is **not applied** and settles `Refused(InternalFault)` (recorded; the sender uses
    /// a new number). If it can, whatever happens next (a crash before the effect, after it, or before the owner
    /// delivers the outcome), the command is at or below a durable floor, so a retry is answered
    /// `OutOfWindow` and never applied a second time. Absolute and stop commands use no store.
    pub fn step_reserving<S: FloorStore>(
        &mut self,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
        store: &mut S,
    ) -> Vec<Settlement> {
        self.step_inner(now_ns, session, Some(store))
    }

    fn step_inner<S: FloorStore>(
        &mut self,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
        mut store: Option<&mut S>,
    ) -> Vec<Settlement> {
        self.ledger.expire(now_ns);
        let floor = *self
            .revision_floor
            .get_or_insert(session.state_revision.max(self.restored_high_water));
        let mut settled = Vec::new();
        self.expire_pending(now_ns, session.state_revision, &mut settled);
        for _ in 0..self.config.max_per_step {
            let Some(item) = self.pop_priority().or_else(|| self.ordinary.pop_front()) else {
                break;
            };
            let outcome = if matches!(self.durability, Durability::Failed { .. }) {
                self.execute_degraded(&item, now_ns, floor, session, &mut settled)
            } else {
                self.execute(
                    &item,
                    now_ns,
                    floor,
                    session,
                    store.as_deref_mut(),
                    &mut settled,
                )
            };
            if self.defer_facts
                && matches!(outcome, Outcome::Committed { .. })
                && Self::silences_locally(&item)
            {
                self.silenced.push(item.clone());
            }
            let times = Settled {
                now_ns,
                accepted_ns: item.accepted_ns,
                revision: session.state_revision,
            };
            self.settle(item.request.body().clone(), outcome, times, &mut settled);
        }
        // Outside a durable step: the requests turned away since the last step were turned away first. Inside one they
        // were written before it began (`begin_step`), against the session as it stood, and `session` here is a copy
        // that may never be made real.
        if !self.defer_facts {
            self.flush_log(session);
            self.emit_facts(now_ns, session);
        }
        settled
    }

    /// Whether `item` is the local user's stop or mute-on: the commands that only silence.
    fn silences_locally(item: &Queued) -> bool {
        item.auth.role == PeerRole::LocalUser
            && matches!(
                item.request.body().command(),
                ControlCommand::StopGroupPlayback { .. }
                    | ControlCommand::SetMemberMute { muted: true, .. }
            )
    }

    fn emit_facts(&mut self, now_ns: u64, session: &UnifiedGroupSession) {
        if let Some(log) = self.log.as_mut() {
            for fact in self.facts.drain(..) {
                log.emit(&fact, now_ns, session.current_epoch, &session.group_id);
            }
        }
    }

    /// Open a durable step: expire what is due (that is not part of the step), then keep everything the step does to
    /// the ledger, the counters and the log facts so that [`ControlChannel::rollback_step`] can take it back. Returns
    /// the counters as they are now.
    ///
    /// The requests turned away at `submit` since the last step are written first, against `session`, the live
    /// session as it stands before the step: they are real evidence and a failed step must neither lose them nor stamp
    /// them with a revision the session never reached.
    fn begin_step(&mut self, now_ns: u64, session: &UnifiedGroupSession) -> ChannelStats {
        self.flush_log(session);
        self.ledger.expire(now_ns);
        self.ledger.begin();
        self.defer_facts = true;
        self.silenced.clear();
        self.stats
    }

    /// The open step is durable and stands: its log facts are written.
    fn commit_step(&mut self, now_ns: u64, session: &UnifiedGroupSession) {
        self.ledger.commit();
        self.defer_facts = false;
        self.silenced.clear();
        self.emit_facts(now_ns, session);
    }

    /// The open step could not be made durable and its effect was dropped. Take back what it did to the ledger
    /// (its outcomes are `Unseen` again, and what it evicted is back, with the floors it had raised undone), the
    /// counters, and its log facts, so nothing says "committed" about an effect that never happened. One critical
    /// record says that a store failed and names the first command it took back. Floors made durable during the step
    /// stay: they are on the medium and only ever refuse more.
    fn rollback_step(
        &mut self,
        before: ChannelStats,
        now_ns: u64,
        session: &UnifiedGroupSession,
        withheld: &[Settlement],
        code: &'static str,
    ) {
        self.ledger.rollback();
        self.stats = before;
        self.defer_facts = false;
        self.facts.clear();
        let queue_depth = self.ordinary.len() + self.priority.len();
        // Name the first command that stays withheld. A local stop or mute-on the step held is about to be applied to the live
        // session (`apply_silencing_live`) and will be logged as applied, so it must not also be named here as refused. If only
        // such commands were in the step the record still exists (the fault is never invisible) and names the first peer with
        // number 0, which no command has.
        let silenced = |s: &Settlement| {
            self.silenced
                .iter()
                .any(|q| q.request.body().peer() == &s.peer && q.request.body().seq() == s.seq)
        };
        let named = withheld
            .iter()
            .find(|s| !silenced(s))
            .map(|s| (s.peer.clone(), s.seq))
            .or_else(|| withheld.first().map(|s| (s.peer.clone(), 0)));
        if let (Some((peer, seq)), Some(log)) = (named, self.log.as_mut()) {
            let fact = Fact {
                peer,
                seq,
                member: None,
                outcome: Outcome::Refused(Refusal::InternalFault),
                cause: Some(format!("store_failed_{code}")),
                revision: session.state_revision,
                queue_depth,
                waited_ns: 0,
                critical: true,
            };
            log.emit(&fact, now_ns, session.current_epoch, &session.group_id);
        }
    }

    /// Latch the durable path failed. Nothing is staged or written until the owner reopens the journal.
    pub(super) fn latch_durability(&mut self, code: &'static str) {
        self.durability = Durability::Failed { code };
    }

    /// The one exception to "nothing a step did is visible until its mark is durable": the local user's stop and mute-on
    /// that the rolled-back step applied are applied again, now to the live session, in the order they ran. Silence is
    /// never withdrawn for want of a disk, and it is the first accepted command that discovers the fault, not the
    /// second. They are judged afresh (the peer must still be current, the command must still apply), recorded and
    /// logged like any applied command, and returned to be delivered: they took effect. Their mark is not stored. Nothing
    /// else the step did is applied: a volume increase, a relative step or an unmute that came with them stays
    /// withheld. Call after `rollback_step` and `latch_durability`.
    fn apply_silencing_live(
        &mut self,
        now_ns: u64,
        session: &mut UnifiedGroupSession,
    ) -> Vec<Settlement> {
        let items = std::mem::take(&mut self.silenced);
        let floor = self.revision_floor.unwrap_or(session.state_revision);
        let mut applied = Vec::new();
        for item in items {
            let outcome =
                self.execute::<NoFloorStore>(&item, now_ns, floor, session, None, &mut applied);
            let times = Settled {
                now_ns,
                accepted_ns: item.accepted_ns,
                revision: session.state_revision,
            };
            self.settle(item.request.body().clone(), outcome, times, &mut applied);
        }
        self.emit_facts(now_ns, session);
        applied
    }

    /// What a step does while the durable path is latched: no command is staged and nothing is written. The local
    /// user's stop and mute-on apply to the live session (silencing is never withdrawn for want of a disk), a cancel
    /// still withdraws, and every other command is refused without being recorded. Louder is not allowed: no
    /// command that raises volume, relative or absolute, gets through.
    ///
    /// The legacy bridge is a controller, so its stop is refused here like any other controller's.
    fn execute_degraded(
        &mut self,
        item: &Queued,
        now_ns: u64,
        floor: u64,
        session: &mut UnifiedGroupSession,
        out: &mut Vec<Settlement>,
    ) -> Outcome {
        let command = item.request.body().command();
        if Self::silences_locally(item) || matches!(command, ControlCommand::Cancel { .. }) {
            return self.execute::<NoFloorStore>(item, now_ns, floor, session, None, out);
        }
        self.store_cause = Some(StoreCause::Degraded);
        Outcome::Refused(Refusal::InternalFault)
    }

    /// Make `peer`'s floor at least `seq` durable through `store`, then in memory. On `Err`, with nothing changed in
    /// memory, the code says why: the table cannot take it, or the store could not make it durable.
    fn reserve_floor<S: FloorStore>(
        &mut self,
        peer: &PeerId,
        seq: u64,
        store: &mut S,
    ) -> Result<(), &'static str> {
        let Some(next) = self.seq_floors.raised(peer, seq) else {
            return Err(if self.seq_floors.is_refusing() {
                "floors_unreadable"
            } else {
                "floors_full"
            });
        };
        store
            .store(&next.encode())
            .map_err(|refused| refused.code)?;
        self.seq_floors = next;
        Ok(())
    }

    fn execute<S: FloorStore>(
        &mut self,
        item: &Queued,
        now_ns: u64,
        floor: u64,
        session: &mut UnifiedGroupSession,
        store: Option<&mut S>,
        out: &mut Vec<Settlement>,
    ) -> Outcome {
        // The authority behind this command must still stand.
        if !self.authority.is_current(&item.auth) {
            return Outcome::Refused(Refusal::AuthorityExpired);
        }
        let body = item.request.body();
        if let ControlCommand::Cancel { target_seq } = body.command() {
            return self.execute_cancel(
                body.peer(),
                *target_seq,
                Settled {
                    now_ns,
                    accepted_ns: item.accepted_ns,
                    revision: session.state_revision,
                },
                out,
            );
        }

        // G01: a group-affecting command is applied only under a live lease for this group, judged by
        // the session's own `AuthorityToken::check`. Refused here, nothing has been touched.
        if let Some(refusal) = self.lease_refusal(body.command(), item.auth.role, session, now_ns) {
            return Outcome::Refused(refusal);
        }

        // A remote controller is held to the epoch and to the revision it last saw.
        if item.auth.role == PeerRole::Controller {
            let current = session.current_epoch;
            if body.epoch() < current {
                return Outcome::Refused(Refusal::StaleEpoch {
                    request: body.epoch(),
                    current,
                });
            }
            if body.epoch() > current {
                return Outcome::Refused(Refusal::EpochAhead {
                    request: body.epoch(),
                    current,
                });
            }
            if let Some(observed) = body.expected_revision() {
                let revision = session.state_revision;
                // A relative command is held to the exact revision its delta was computed against.
                // Any command naming a revision the session has not reached is refused: it was
                // composed against some other state than this one.
                if observed > revision || (body.command().is_relative() && observed != revision) {
                    return Outcome::Refused(Refusal::RevisionMismatch {
                        expected: observed,
                        actual: revision,
                    });
                }
                // An absolute command stays valid however far the group has moved since, as long as it
                // was composed after this incarnation began: absolute volume is naturally repeatable,
                // so a client may pipeline updates and two controllers may interleave. What it may not
                // be is older than the start of this incarnation: that is a copy that outlived a restart.
                if observed < floor {
                    return Outcome::Refused(Refusal::StaleRevision { observed, floor });
                }
            }
        }

        let payload = match body.command() {
            ControlCommand::SetMemberVolume { member_id, volume } => {
                GroupCommandPayload::SetMemberVolume {
                    member_id: member_id.clone(),
                    volume_0_to_100: *volume,
                }
            }
            ControlCommand::SetGroupVolume { volume } => GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: *volume,
            },
            ControlCommand::AdjustMemberVolume { member_id, delta } => {
                let Some(member) = session.members.get(member_id) else {
                    return Outcome::Refused(Refusal::UnknownMember {
                        member_id: member_id.clone(),
                    });
                };
                GroupCommandPayload::SetMemberVolume {
                    member_id: member_id.clone(),
                    volume_0_to_100: stepped(member.volume_0_to_100, *delta),
                }
            }
            ControlCommand::AdjustGroupVolume { delta } => GroupCommandPayload::SetGroupVolume {
                volume_0_to_100: stepped(session.group_master_volume, *delta),
            },
            ControlCommand::SetMemberMute { member_id, muted } => {
                GroupCommandPayload::SetMemberMute {
                    member_id: member_id.clone(),
                    muted: *muted,
                }
            }
            ControlCommand::StopGroupPlayback {
                now_ns,
                irrevocable_dma_tail_ns,
            } => GroupCommandPayload::StopGroupPlayback {
                now_ns: *now_ns,
                irrevocable_dma_tail_ns: *irrevocable_dma_tail_ns,
            },
            // Handled above; present so the match is total without a panic.
            ControlCommand::Cancel { .. } => return Outcome::Refused(Refusal::NotCancellable),
        };

        // A relative command is the one kind that must never be applied twice, so its duplicate-suppression record is
        // made durable BEFORE the effect, here and not earlier (a refusal above leaves the command free to be sent
        // again) and not after (a crash between the effect and a later store would leave an effect nobody remembers).
        // If it cannot be made durable the command is not applied: this is nothing the sender did, so it is told to
        // read the state and use a new number, and no session error is reported as the cause.
        if body.command().is_relative()
            && !self.unstable_retry.contains(body.peer())
            && let Some(store) = store
            && let Err(code) = self.reserve_floor(body.peer(), body.seq(), store)
        {
            self.last_internal_fault = None;
            self.store_cause = Some(StoreCause::Reservation(code));
            return Outcome::Refused(Refusal::InternalFault);
        }

        // The larger of the next counter value and base + revision. The revision only ever grows, so a
        // restarted channel lands above everything its predecessor used; the counter keeps a refused
        // number (which the revision does not move on) from being tried twice.
        let command_seq = self.next_session_seq.max(
            self.config
                .session_seq_base
                .saturating_add(session.state_revision),
        );
        self.next_session_seq = command_seq.saturating_add(1);
        match session.apply_command(FencedControlCommand {
            epoch: session.current_epoch,
            command_seq,
            payload,
        }) {
            Ok(revision) => Outcome::Committed { revision },
            Err(error @ SessionError::UnknownMember { .. }) => {
                Outcome::Refused(Refusal::Session(error))
            }
            // Every other session error is about the command number or the epoch, both of which the
            // channel chose itself. The next command gets a fresh number, so a collision heals.
            Err(error) => {
                self.last_internal_fault = Some(error);
                Outcome::Refused(Refusal::InternalFault)
            }
        }
    }

    /// Why the lease does not cover this command, or `None` if it does. A local stop and a local mute
    /// are exempt because they only silence; a cancel never reaches here.
    fn lease_refusal(
        &self,
        command: &ControlCommand,
        role: PeerRole,
        session: &UnifiedGroupSession,
        now_ns: u64,
    ) -> Option<Refusal> {
        let silences = matches!(
            command,
            ControlCommand::StopGroupPlayback { .. }
                | ControlCommand::SetMemberMute { muted: true, .. }
        );
        if role == PeerRole::LocalUser && silences {
            return None;
        }
        match &self.lease {
            None => Some(Refusal::NoLease),
            Some(token) => token
                .check_with_margin(session, now_ns, self.config.lease_margin_ns)
                .err()
                .map(Refusal::Lease),
        }
    }

    fn execute_cancel(
        &mut self,
        peer: &PeerId,
        target_seq: u64,
        times: Settled,
        out: &mut Vec<Settlement>,
    ) -> Outcome {
        let is_target =
            |q: &Queued| q.request.body().peer() == peer && q.request.body().seq() == target_seq;
        if let Some(pos) = self.ordinary.iter().position(is_target)
            && let Some(target) = self.ordinary.remove(pos)
        {
            self.settle(
                target.request.body().clone(),
                Outcome::Withdrawn,
                Settled {
                    accepted_ns: target.accepted_ns,
                    ..times
                },
                out,
            );
            return Outcome::CancelApplied { target_seq };
        }
        if self.priority.iter().any(is_target) {
            return Outcome::Refused(Refusal::NotCancellable);
        }
        match self.ledger.lookup(peer, target_seq) {
            Lookup::Settled { .. } => Outcome::Refused(Refusal::TooLateToCancel),
            Lookup::OutOfWindow { floor } => Outcome::Refused(Refusal::TargetOutOfWindow { floor }),
            Lookup::Unseen => Outcome::Refused(Refusal::NothingToCancel),
        }
    }
}

/// `current + delta`, clamped to 0..=100.
fn stepped(current: u8, delta: i8) -> u8 {
    let moved = i16::from(current) + i16::from(delta);
    u8::try_from(moved.clamp(0, 100)).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use franken_session::{
        EpochMint, LeaseRequest, LeaseView, LeaseVoter, MembershipConfig, QuorumConfig, QuorumRound,
    };
    use franken_test_support::{
        CommandObservation, DiagnosticEvent, FencedCommandOracle, redact_sensitive_text,
    };

    use super::super::diag::{LogConfig, LogKey, MAX_LINE_BYTES};

    use super::super::peer::compute_proof;
    use super::super::peer::ephemeral::{EphemeralPeers, test_key};
    use super::super::testkit::fixture_session;
    use super::*;

    const EPOCH: u64 = 10;
    /// A lease that outlasts every test clock.
    const LEASE_EXPIRY_NS: u64 = 1_000_000 * MS;

    fn id(raw: &str) -> PeerId {
        PeerId::parse(raw).unwrap()
    }

    /// Epoch 10, members `kitchen` and `den` at volume 50 and a group master at 50; revision 2.
    fn session() -> UnifiedGroupSession {
        fixture_session(EPOCH)
    }

    fn peers() -> EphemeralPeers {
        let mut p = EphemeralPeers::new();
        p.admit(
            &id("ctl-a"),
            PeerRole::Controller,
            test_key("ctl-a").as_slice(),
            Some(EPOCH),
            1,
        )
        .unwrap();
        p.admit(
            &id("ctl-b"),
            PeerRole::Controller,
            test_key("ctl-b").as_slice(),
            Some(EPOCH),
            1,
        )
        .unwrap();
        p.admit(
            &id("panel"),
            PeerRole::LocalUser,
            test_key("panel").as_slice(),
            None,
            1,
        )
        .unwrap();
        p
    }

    /// Generous rate limits and room, so a test exercises one mechanism at a time.
    fn roomy() -> ChannelConfig {
        let mut c = ChannelConfig::provisional();
        c.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        c.priority_rate = RateLimit::new(100_000, MS).unwrap();
        c.ordinary_capacity = 64;
        c.ledger_capacity = 128;
        c.session_seq_base = 1_000;
        c
    }

    struct Rig {
        channel: ControlChannel<EphemeralPeers>,
        session: UnifiedGroupSession,
        now: u64,
    }

    impl Rig {
        fn new(config: ChannelConfig) -> Self {
            let mut rig = Self::without_lease(config);
            rig.grant();
            rig
        }

        /// A channel that has been given no lease, as a fresh or restarted one is.
        fn without_lease(config: ChannelConfig) -> Self {
            Self {
                channel: ControlChannel::new(peers(), config).unwrap(),
                session: session(),
                now: 0,
            }
        }

        /// Turn the JSONL log on, with the run and case labels and key the log tests expect.
        fn log_on(&mut self, max_records: usize, max_bytes: usize) {
            let config = LogConfig::new("run-1", "case-1", max_records, max_bytes).unwrap();
            self.channel
                .enable_log(ChannelLog::new(config, LogKey::new([7; 32])));
        }

        fn records(&self) -> Vec<DiagnosticEvent> {
            self.channel
                .log()
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).expect("a shared-schema event"))
                .collect()
        }

        fn pseudonym(&self, id: &str) -> String {
            self.channel.log().unwrap().pseudonym_of(id)
        }

        /// A fresh group-volume command from `ctl-a` at `ns`, stepped at once: how it settled.
        fn volume_at(&mut self, seq: u64, epoch: u64, ns: u64) -> Outcome {
            self.at(ns);
            let r = self.req("ctl-a", seq, epoch, None, set_group(60 + (seq % 30) as u8));
            self.submit(r);
            self.step().remove(0).outcome
        }

        /// The owner installs a fresh lease for the session's current epoch.
        fn grant(&mut self) {
            self.grant_until(LEASE_EXPIRY_NS);
        }

        fn grant_until(&mut self, expires_at_ns: u64) {
            let token = AuthorityToken::issue(&self.session, expires_at_ns);
            self.channel
                .install_lease(&self.session, token, self.now)
                .unwrap();
        }

        fn roomy() -> Self {
            Self::new(roomy())
        }

        fn body(
            peer: &str,
            seq: u64,
            epoch: u64,
            rev: Option<u64>,
            command: ControlCommand,
        ) -> RequestBody {
            RequestBody::new(id(peer), seq, epoch, rev, command).unwrap()
        }

        fn sign(&self, body: RequestBody) -> ControlRequest {
            let proof = compute_proof(&test_key(body.peer().as_str()), &body.signing_bytes());
            ControlRequest::new(body, proof)
        }

        /// A request from a client that has just read the group state: when a remote controller sends
        /// a volume or mute change and names no revision, the session's current one is supplied. The
        /// local user needs none. Tests about the missing-revision rule use `req_raw`.
        fn req(
            &self,
            peer: &str,
            seq: u64,
            epoch: u64,
            rev: Option<u64>,
            command: ControlCommand,
        ) -> ControlRequest {
            let rev = rev.or_else(|| {
                (peer != "panel" && command.needs_observed_revision())
                    .then_some(self.session.state_revision)
            });
            self.req_raw(peer, seq, epoch, rev, command)
        }

        /// Exactly the fields given, signed.
        fn req_raw(
            &self,
            peer: &str,
            seq: u64,
            epoch: u64,
            rev: Option<u64>,
            command: ControlCommand,
        ) -> ControlRequest {
            self.sign(Self::body(peer, seq, epoch, rev, command))
        }

        fn submit(&mut self, request: ControlRequest) -> SubmitResult {
            self.channel.submit(self.now, request)
        }

        fn step(&mut self) -> Vec<Settlement> {
            self.channel.step(self.now, &mut self.session)
        }

        fn at(&mut self, ns: u64) {
            self.now = ns;
        }

        fn volume(&self, member: &str) -> u8 {
            self.session.members[member].volume_0_to_100
        }
    }

    fn set_group(volume: u8) -> ControlCommand {
        ControlCommand::SetGroupVolume { volume }
    }

    fn adjust(member: &str, delta: i8) -> ControlCommand {
        ControlCommand::AdjustMemberVolume {
            member_id: member.to_string(),
            delta,
        }
    }

    fn mute(member: &str, on: bool) -> ControlCommand {
        ControlCommand::SetMemberMute {
            member_id: member.to_string(),
            muted: on,
        }
    }

    fn stop() -> ControlCommand {
        ControlCommand::StopGroupPlayback {
            now_ns: 1_000,
            irrevocable_dma_tail_ns: 500,
        }
    }

    fn committed(revision: u64) -> Outcome {
        Outcome::Committed { revision }
    }

    // ----------------------------------------------------------------- the basic path

    #[test]
    fn a_request_is_queued_then_committed_and_those_are_different_things() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(70));
        assert_eq!(
            rig.submit(r),
            SubmitResult::Queued {
                lane: Lane::Ordinary
            }
        );
        // Received, not applied.
        assert_eq!(rig.session.group_master_volume, 50);
        assert_eq!(rig.session.state_revision, 2);
        assert_eq!(rig.channel.diagnostics(&rig.session).stats.committed, 0);

        let settled = rig.step();
        assert_eq!(
            settled,
            vec![Settlement {
                peer: id("ctl-a"),
                seq: 1,
                outcome: committed(3)
            }]
        );
        assert_eq!(rig.session.group_master_volume, 70);
        let d = rig.channel.diagnostics(&rig.session);
        assert_eq!(
            (d.stats.received, d.stats.committed, d.committed_revision),
            (1, 1, 3)
        );
    }

    #[test]
    fn every_command_kind_reaches_the_session() {
        let mut rig = Rig::roomy();
        let cases = [
            (
                1,
                ControlCommand::SetMemberVolume {
                    member_id: "kitchen".into(),
                    volume: 20,
                },
            ),
            (2, set_group(60)),
            (3, mute("den", true)),
            (4, stop()),
        ];
        for (seq, command) in cases {
            let r = rig.req("ctl-a", seq, EPOCH, None, command);
            assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        }
        let settled = rig.step();
        assert_eq!(settled.len(), 4);
        assert!(
            settled
                .iter()
                .all(|s| matches!(s.outcome, Outcome::Committed { .. }))
        );
        assert_eq!(rig.volume("kitchen"), 20);
        assert_eq!(rig.session.group_master_volume, 60);
        assert!(rig.session.members["den"].muted);
        assert!(matches!(
            rig.session.members["den"].lifecycle,
            franken_session::MemberLifecycleState::StoppingDmaTail { .. }
        ));
    }

    // ----------------------------------------------------------------- duplicates and exactly one effect

    #[test]
    fn a_lost_acknowledgement_after_commit_is_answered_with_the_same_outcome_and_no_second_effect()
    {
        let mut rig = Rig::roomy();
        let mut oracle = FencedCommandOracle::new(EPOCH);
        oracle.record_issued(1, EPOCH, 1).unwrap();

        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        let before = rig.session.state_revision;
        assert!(matches!(rig.submit(r.clone()), SubmitResult::Queued { .. }));
        rig.step();
        assert_eq!(rig.volume("kitchen"), 60);
        // Delivery 1 is judged by the harness from the session itself, not from the channel's report.
        oracle
            .observe_outcome(CommandObservation {
                command_id: 1,
                applied: rig.session.state_revision > before,
                system_epoch_after: rig.session.current_epoch,
            })
            .unwrap();

        // The acknowledgement is lost; the client sends the identical request again.
        let before_retry = rig.session.state_revision;
        assert_eq!(rig.submit(r), SubmitResult::Settled(committed(3)));
        rig.step();
        assert_eq!(
            rig.volume("kitchen"),
            60,
            "the delta was applied once, not twice"
        );
        assert_eq!(rig.session.state_revision, 3);
        oracle
            .observe_outcome(CommandObservation {
                command_id: 1,
                applied: rig.session.state_revision > before_retry,
                system_epoch_after: rig.session.current_epoch,
            })
            .unwrap();
    }

    #[test]
    fn a_duplicate_relative_volume_has_exactly_one_logical_effect_whenever_the_copy_arrives() {
        // Before the first copy is applied.
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        assert!(matches!(rig.submit(r.clone()), SubmitResult::Queued { .. }));
        assert_eq!(
            rig.submit(r.clone()),
            SubmitResult::AlreadyQueued {
                lane: Lane::Ordinary
            }
        );
        assert_eq!(rig.channel.pending(Lane::Ordinary), 1);
        rig.step();
        // After it.
        assert_eq!(rig.submit(r.clone()), SubmitResult::Settled(committed(3)));
        assert_eq!(rig.submit(r), SubmitResult::Settled(committed(3)));
        assert_eq!(rig.step(), vec![]);
        assert_eq!(rig.volume("kitchen"), 60);
        assert_eq!(rig.session.state_revision, 3);
    }

    #[test]
    fn without_the_ledger_the_copy_would_have_been_refused_as_a_stale_revision() {
        // Why the cached outcome must be consulted before the revision check: the retry still names
        // revision 2, which the first delivery has already moved past.
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        rig.submit(r);
        rig.step();
        assert_eq!(rig.session.state_revision, 3);
        let fresh = rig.req("ctl-a", 2, EPOCH, Some(2), adjust("kitchen", 10));
        rig.submit(fresh);
        let settled = rig.step();
        assert_eq!(
            settled[0].outcome,
            Outcome::Refused(Refusal::RevisionMismatch {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(rig.volume("kitchen"), 60);
    }

    #[test]
    fn a_retry_storm_leaves_the_queue_and_the_ledger_bounded() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 5));
        assert!(matches!(rig.submit(r.clone()), SubmitResult::Queued { .. }));
        for _ in 0..1_000 {
            assert_eq!(
                rig.submit(r.clone()),
                SubmitResult::AlreadyQueued {
                    lane: Lane::Ordinary
                }
            );
        }
        assert_eq!(rig.channel.pending(Lane::Ordinary), 1);
        rig.step();
        for _ in 0..1_000 {
            assert_eq!(rig.submit(r.clone()), SubmitResult::Settled(committed(3)));
        }
        let d = rig.channel.diagnostics(&rig.session);
        assert_eq!((d.ordinary_pending, d.ledger_len), (0, 1));
        assert_eq!(
            rig.volume("kitchen"),
            55,
            "one delta, after two thousand deliveries"
        );
        assert_eq!(rig.session.state_revision, 3);
    }

    #[test]
    fn the_same_number_with_different_content_is_refused_everywhere() {
        let mut rig = Rig::roomy();
        let first = rig.req("ctl-a", 1, EPOCH, None, set_group(70));
        let other = rig.req("ctl-a", 1, EPOCH, None, set_group(90));
        assert!(matches!(rig.submit(first), SubmitResult::Queued { .. }));
        // While the first is waiting.
        assert_eq!(
            rig.submit(other.clone()),
            SubmitResult::Rejected(Rejection::IdReuse)
        );
        rig.step();
        // And after it settled.
        assert_eq!(
            rig.submit(other),
            SubmitResult::Rejected(Rejection::IdReuse)
        );
        assert_eq!(rig.session.group_master_volume, 70);
        // A different number is a different command.
        let next = rig.req("ctl-a", 2, EPOCH, None, set_group(90));
        assert!(matches!(rig.submit(next), SubmitResult::Queued { .. }));
    }

    #[test]
    fn the_same_number_from_two_peers_is_two_commands() {
        let mut rig = Rig::roomy();
        let a = rig.req("ctl-a", 1, EPOCH, None, set_group(70));
        let b = rig.req("ctl-b", 1, EPOCH, None, set_group(30));
        assert!(matches!(rig.submit(a), SubmitResult::Queued { .. }));
        assert!(matches!(rig.submit(b), SubmitResult::Queued { .. }));
        let settled = rig.step();
        assert_eq!(settled.len(), 2);
        assert_eq!(
            rig.session.group_master_volume, 30,
            "applied in arrival order"
        );
    }

    // ----------------------------------------------------------------- the window: expiry, eviction, unknown

    #[test]
    fn after_retention_a_retry_is_unknown_and_is_not_applied_again() {
        let mut config = roomy();
        config.retention_ns = 1_000 * MS;
        let mut rig = Rig::new(config);
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        rig.submit(r.clone());
        rig.step();
        assert_eq!(rig.volume("kitchen"), 60);

        rig.at(999 * MS);
        assert_eq!(rig.submit(r.clone()), SubmitResult::Settled(committed(3)));
        rig.at(1_000 * MS);
        assert_eq!(
            rig.submit(r.clone()),
            SubmitResult::OutOfWindow { floor: 1 }
        );
        assert_eq!(rig.step(), vec![], "nothing was queued");
        assert_eq!(
            rig.volume("kitchen"),
            60,
            "unknown, and not applied a second time"
        );
        assert_eq!(rig.session.state_revision, 3);
        // It stays unknown; the sender must reconcile from the group state.
        assert_eq!(rig.submit(r), SubmitResult::OutOfWindow { floor: 1 });
        assert_eq!(rig.channel.stats().out_of_window, 2);
    }

    #[test]
    fn a_full_ledger_forgets_the_oldest_and_says_so() {
        let mut config = roomy();
        config.ledger_capacity = 2;
        let mut rig = Rig::new(config);
        let mut requests = Vec::new();
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(60 + seq as u8));
            rig.submit(r.clone());
            requests.push(r);
        }
        rig.step();
        assert_eq!(rig.channel.diagnostics(&rig.session).ledger_len, 2);
        assert_eq!(
            rig.submit(requests[0].clone()),
            SubmitResult::OutOfWindow { floor: 1 }
        );
        assert!(matches!(
            rig.submit(requests[2].clone()),
            SubmitResult::Settled(_)
        ));
    }

    // ----------------------------------------------------------------- authentication comes first

    #[test]
    fn a_forged_or_unknown_or_revoked_peer_changes_nothing() {
        let mut rig = Rig::roomy();
        let body = Rig::body("ctl-a", 1, EPOCH, None, set_group(99));
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(b"attacker", &body.signing_bytes()),
        );
        assert_eq!(
            rig.submit(forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        );
        let ghost_body = Rig::body("ghost", 1, EPOCH, None, set_group(99));
        let ghost = ControlRequest::new(
            ghost_body.clone(),
            compute_proof(b"k", &ghost_body.signing_bytes()),
        );
        assert_eq!(
            rig.submit(ghost),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::UnknownPeer))
        );
        let genuine = rig.req("ctl-b", 1, EPOCH, None, set_group(99));
        rig.channel.authority_mut().revoke(&id("ctl-b"));
        assert_eq!(
            rig.submit(genuine),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked))
        );
        let d = rig.channel.diagnostics(&rig.session);
        assert_eq!(
            (d.ordinary_pending, d.priority_pending, d.ledger_len),
            (0, 0, 0)
        );
        assert_eq!(d.stats.rejected_unauthenticated, 3);
        assert_eq!(rig.session.group_master_volume, 50);
    }

    #[test]
    fn a_flood_of_forgeries_cannot_spend_the_real_peers_allowance() {
        // The default limits are tight enough for the flood to matter: a burst of 8.
        let mut rig = Rig::new(ChannelConfig::provisional());
        for seq in 1..=500u64 {
            let body = Rig::body("ctl-a", seq, EPOCH, None, set_group(1));
            let forged = ControlRequest::new(
                body.clone(),
                compute_proof(b"attacker", &body.signing_bytes()),
            );
            assert!(matches!(
                rig.submit(forged),
                SubmitResult::Rejected(Rejection::Unauthenticated(_))
            ));
        }
        // The real ctl-a, in the same instant, still has its whole burst.
        for seq in 1..=8u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(40));
            assert!(
                matches!(rig.submit(r), SubmitResult::Queued { .. }),
                "genuine request {seq} was refused"
            );
        }
    }

    #[test]
    fn changing_any_single_signed_field_voids_the_proof() {
        let mut rig = Rig::roomy();
        let base = Rig::body("ctl-a", 5, EPOCH, Some(2), adjust("kitchen", 10));
        let proof = compute_proof(&test_key(base.peer().as_str()), &base.signing_bytes());
        // The unmodified request is accepted, so the refusals below are due to the change alone.
        assert!(matches!(
            rig.submit(ControlRequest::new(base.clone(), proof.clone())),
            SubmitResult::Queued { .. }
        ));
        let changed = [
            (
                "seq",
                Rig::body("ctl-a", 6, EPOCH, Some(2), adjust("kitchen", 10)),
            ),
            (
                "epoch",
                Rig::body("ctl-a", 5, EPOCH + 1, Some(2), adjust("kitchen", 10)),
            ),
            (
                "expected revision",
                Rig::body("ctl-a", 5, EPOCH, Some(3), adjust("kitchen", 10)),
            ),
            (
                "member",
                Rig::body("ctl-a", 5, EPOCH, Some(2), adjust("den", 10)),
            ),
            (
                "delta",
                Rig::body("ctl-a", 5, EPOCH, Some(2), adjust("kitchen", 11)),
            ),
            (
                "command kind",
                Rig::body(
                    "ctl-a",
                    5,
                    EPOCH,
                    Some(2),
                    ControlCommand::AdjustGroupVolume { delta: 10 },
                ),
            ),
        ];
        for (field, body) in changed {
            let replayed = ControlRequest::new(body, proof.clone());
            assert_eq!(
                rig.submit(replayed),
                SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof)),
                "changing the {field} did not void the proof"
            );
        }
        // A proof for one peer does not carry over to another peer.
        let other_peer = Rig::body("ctl-b", 5, EPOCH, Some(2), adjust("kitchen", 10));
        assert_eq!(
            rig.submit(ControlRequest::new(other_peer, proof)),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        );
    }

    #[test]
    fn a_peer_revoked_after_acceptance_has_no_effect_when_the_step_runs() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(95));
        assert!(matches!(rig.submit(r.clone()), SubmitResult::Queued { .. }));
        rig.channel.authority_mut().revoke(&id("ctl-a"));
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::AuthorityExpired)
        );
        assert_eq!(rig.session.group_master_volume, 50);
        assert_eq!(rig.session.state_revision, 2);
        // The terminal outcome is on record, but only a peer that authenticates can read it.
        assert_eq!(
            rig.submit(r),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::Revoked))
        );
    }

    #[test]
    fn rebinding_a_key_after_acceptance_also_expires_the_commands_accepted_under_the_old_binding() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(95));
        rig.submit(r);
        rig.channel
            .authority_mut()
            .rebind(&id("ctl-a"), Some(EPOCH + 1));
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::AuthorityExpired)
        );
        assert_eq!(rig.session.group_master_volume, 50);
    }

    // ----------------------------------------------------------------- stale leaders and revisions

    #[test]
    fn a_stale_leader_cannot_alter_the_group_after_the_epoch_moves_on() {
        let mut rig = Rig::roomy();
        let mut oracle = FencedCommandOracle::new(EPOCH);
        // The group moves to epoch 11 (a new coordinator, outside this channel).
        rig.session
            .apply_command(FencedControlCommand {
                epoch: 11,
                command_seq: 3,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .unwrap();
        oracle.declare_authority(11).unwrap();
        // The owner has renewed the group lease for the new epoch, so what is judged below is the
        // controller's own epoch; a channel left on the old lease is the next test.
        rig.grant();
        let revision = rig.session.state_revision;

        // The old leader, still holding a key bound to epoch 10, tries to act.
        oracle.record_issued(7, EPOCH, 1).unwrap();
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(5));
        assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::StaleEpoch {
                request: EPOCH,
                current: 11
            })
        );
        assert_eq!(rig.session.group_master_volume, 50);
        assert_eq!(rig.session.state_revision, revision);
        oracle
            .observe_outcome(CommandObservation {
                command_id: 7,
                applied: rig.session.state_revision > revision,
                system_epoch_after: rig.session.current_epoch,
            })
            .unwrap();

        // Rebound to the new epoch, the same peer works again.
        rig.channel.authority_mut().rebind(&id("ctl-a"), Some(11));
        let again = rig.req("ctl-a", 2, 11, None, set_group(5));
        assert!(matches!(rig.submit(again), SubmitResult::Queued { .. }));
        assert!(matches!(rig.step()[0].outcome, Outcome::Committed { .. }));
        assert_eq!(rig.session.group_master_volume, 5);
    }

    #[test]
    fn a_key_bound_to_one_epoch_is_rejected_at_the_door_under_another() {
        let mut rig = Rig::roomy();
        for epoch in [EPOCH - 1, EPOCH + 1, 0] {
            let r = rig.req("ctl-a", 1, epoch, None, set_group(5));
            assert_eq!(
                rig.submit(r),
                SubmitResult::Rejected(Rejection::EpochNotBound {
                    bound: EPOCH,
                    request: epoch
                })
            );
        }
        assert_eq!(rig.channel.pending(Lane::Ordinary), 0);
    }

    #[test]
    fn an_epoch_jump_from_a_peer_whose_key_allows_it_still_cannot_fence_out_the_group() {
        // A controller whose key is (wrongly or maliciously) bound to a far-future epoch: the channel
        // refuses to apply it, so the session's epoch never moves.
        let mut rig = Rig::roomy();
        rig.channel
            .authority_mut()
            .admit(
                &id("rogue"),
                PeerRole::Controller,
                test_key("rogue").as_slice(),
                Some(900),
                1,
            )
            .unwrap();
        let r = rig.req("rogue", 1, 900, None, set_group(1));
        assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::EpochAhead {
                request: 900,
                current: EPOCH
            })
        );
        assert_eq!(rig.session.current_epoch, EPOCH);
        assert_eq!(rig.session.group_master_volume, 50);
    }

    #[test]
    fn a_wrong_expected_revision_is_refused_without_effect() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, Some(99), set_group(5));
        rig.submit(r.clone());
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::RevisionMismatch {
                expected: 99,
                actual: 2
            })
        );
        assert_eq!(rig.session.group_master_volume, 50);
        // The refusal is the terminal outcome for that number; a retry is told the same.
        assert_eq!(
            rig.submit(r),
            SubmitResult::Settled(Outcome::Refused(Refusal::RevisionMismatch {
                expected: 99,
                actual: 2
            }))
        );
    }

    #[test]
    fn a_relative_command_computed_against_an_old_revision_is_not_applied() {
        let mut rig = Rig::roomy();
        // ctl-a and ctl-b both read revision 2; ctl-b's change lands first.
        let b = rig.req("ctl-b", 1, EPOCH, Some(2), adjust("kitchen", 20));
        let a = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        rig.submit(b);
        rig.submit(a);
        let settled = rig.step();
        assert_eq!(settled[0].outcome, committed(3));
        assert_eq!(
            settled[1].outcome,
            Outcome::Refused(Refusal::RevisionMismatch {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(rig.volume("kitchen"), 70, "only the first delta applied");
    }

    #[test]
    fn relative_volume_clamps_and_an_unknown_member_is_a_recorded_refusal() {
        let mut rig = Rig::roomy();
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 100));
        rig.submit(r);
        rig.step();
        assert_eq!(rig.volume("kitchen"), 100);
        let down = rig.req("ctl-a", 2, EPOCH, Some(3), adjust("kitchen", -100));
        rig.submit(down);
        rig.step();
        assert_eq!(rig.volume("kitchen"), 0);

        let missing = rig.req("ctl-a", 3, EPOCH, Some(4), adjust("nowhere", 5));
        rig.submit(missing.clone());
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::UnknownMember {
                member_id: "nowhere".to_string()
            })
        );
        assert_eq!(rig.session.state_revision, 4);
        assert!(matches!(
            rig.submit(missing),
            SubmitResult::Settled(Outcome::Refused(Refusal::UnknownMember { .. }))
        ));
    }

    // ----------------------------------------------------------------- bounds, lanes, flood

    #[test]
    fn the_ordinary_lane_is_bounded_and_a_duplicate_of_a_waiting_command_is_still_answered() {
        let mut config = roomy();
        config.ordinary_capacity = 3;
        let mut rig = Rig::new(config);
        let mut waiting = Vec::new();
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(10 + seq as u8));
            assert!(matches!(rig.submit(r.clone()), SubmitResult::Queued { .. }));
            waiting.push(r);
        }
        let fourth = rig.req("ctl-a", 4, EPOCH, None, set_group(99));
        assert_eq!(
            rig.submit(fourth.clone()),
            SubmitResult::Rejected(Rejection::QueueFull {
                lane: Lane::Ordinary
            })
        );
        // A copy of one that is already waiting needs no room.
        assert_eq!(
            rig.submit(waiting[0].clone()),
            SubmitResult::AlreadyQueued {
                lane: Lane::Ordinary
            }
        );
        // Refused for want of room: its number is not consumed, so it is accepted once room appears.
        rig.step();
        assert!(matches!(rig.submit(fourth), SubmitResult::Queued { .. }));
    }

    #[test]
    fn rate_limits_are_per_peer_and_per_lane_and_report_the_wait() {
        let mut config = roomy();
        config.ordinary_rate = RateLimit::new(2, 100 * MS).unwrap();
        config.priority_rate = RateLimit::new(1, 100 * MS).unwrap();
        let mut rig = Rig::new(config);
        for seq in 1..=2u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(20));
            assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        }
        let third = rig.req("ctl-a", 3, EPOCH, None, set_group(20));
        assert_eq!(
            rig.submit(third.clone()),
            SubmitResult::Rejected(Rejection::RateLimited {
                lane: Lane::Ordinary,
                retry_after_ns: 100 * MS
            })
        );
        // ctl-b has its own allowance; ctl-a's priority lane has its own too.
        let b = rig.req("ctl-b", 1, EPOCH, None, set_group(20));
        assert!(matches!(rig.submit(b), SubmitResult::Queued { .. }));
        let m = rig.req("ctl-a", 4, EPOCH, None, mute("den", true));
        assert!(matches!(
            rig.submit(m),
            SubmitResult::Queued {
                lane: Lane::Priority
            }
        ));
        let m2 = rig.req("ctl-a", 5, EPOCH, None, mute("den", false));
        assert!(matches!(
            rig.submit(m2),
            SubmitResult::Rejected(Rejection::RateLimited {
                lane: Lane::Priority,
                ..
            })
        ));
        // After the wait, the refused request goes through.
        rig.at(100 * MS);
        assert!(matches!(rig.submit(third), SubmitResult::Queued { .. }));
    }

    #[test]
    fn a_step_applies_at_most_its_budget_priority_first() {
        let mut config = roomy();
        config.max_per_step = 2;
        let mut rig = Rig::new(config);
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(10 + seq as u8));
            rig.submit(r);
        }
        let s = rig.req("ctl-a", 4, EPOCH, None, stop());
        rig.submit(s);
        // The stop was queued last but is applied first.
        let first = rig.step();
        assert_eq!(first.len(), 2);
        assert_eq!((first[0].seq, first[1].seq), (4, 1));
        assert_eq!(rig.step().len(), 2);
        assert_eq!(rig.step().len(), 0);
    }

    #[test]
    fn a_local_stop_runs_in_its_first_step_through_a_full_queue_a_retry_storm_and_a_remote_flood() {
        let mut config = ChannelConfig::provisional();
        config.ordinary_rate = RateLimit::new(100_000, MS).unwrap();
        config.priority_rate = RateLimit::new(100_000, MS).unwrap();
        config.session_seq_base = 1_000;
        let mut rig = Rig::new(config);

        // Fill the ordinary lane, then storm it with retries and with refused new work.
        for seq in 1..=16u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(10 + seq as u8));
            assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        }
        let waiting = rig.req("ctl-a", 1, EPOCH, None, set_group(11));
        for _ in 0..500 {
            assert!(matches!(
                rig.submit(waiting.clone()),
                SubmitResult::AlreadyQueued { .. }
            ));
            let extra = rig.req("ctl-b", 9_000, EPOCH, None, set_group(1));
            assert!(matches!(
                rig.submit(extra),
                SubmitResult::Rejected(Rejection::QueueFull {
                    lane: Lane::Ordinary
                })
            ));
        }
        // A compromised but authenticated remote controller floods the shared priority slots.
        let mut remote_accepted = 0;
        for seq in 1..=50u64 {
            let r = rig.req("ctl-b", seq, EPOCH, None, mute("den", seq % 2 == 0));
            if matches!(rig.submit(r), SubmitResult::Queued { .. }) {
                remote_accepted += 1;
            }
        }
        assert_eq!(
            remote_accepted, 4,
            "the remote peer is held to the shared priority slots"
        );

        // The person at the device presses stop. It is accepted despite everything above...
        let local = rig.req("panel", 1, 0, None, stop());
        assert_eq!(
            rig.submit(local),
            SubmitResult::Queued {
                lane: Lane::Priority
            }
        );
        // ...and it is applied first in the very next step, ahead of the four remote priority
        // commands queued before it and of all the ordinary work, with epoch 0 and no revision: the
        // local user is not refused for epoch reasons.
        let settled = rig.step();
        assert_eq!(settled.len(), 4, "the step budget is four");
        assert_eq!(
            settled[0].peer,
            id("panel"),
            "the local stop must run first"
        );
        assert!(matches!(settled[0].outcome, Outcome::Committed { .. }));
        assert!(matches!(
            rig.session.members["kitchen"].lifecycle,
            franken_session::MemberLifecycleState::StoppingDmaTail { .. }
        ));
    }

    #[test]
    fn the_local_user_keeps_reserved_priority_slots_and_a_remote_flood_cannot_take_them() {
        let mut config = roomy();
        config.priority_shared_capacity = 2;
        config.priority_local_reserved = 1;
        let mut rig = Rig::new(config);
        for seq in 1..=2u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, mute("den", true));
            assert!(matches!(
                rig.submit(r),
                SubmitResult::Queued {
                    lane: Lane::Priority
                }
            ));
        }
        let third = rig.req("ctl-b", 1, EPOCH, None, mute("den", true));
        assert_eq!(
            rig.submit(third),
            SubmitResult::Rejected(Rejection::QueueFull {
                lane: Lane::Priority
            })
        );
        // The reserved slot is the local user's.
        let local = rig.req("panel", 1, 0, None, mute("kitchen", true));
        assert!(matches!(
            rig.submit(local),
            SubmitResult::Queued {
                lane: Lane::Priority
            }
        ));
        // Once the reserved slot is used and the shared pool is full, even the local user waits.
        let local2 = rig.req("panel", 2, 0, None, mute("kitchen", false));
        assert_eq!(
            rig.submit(local2),
            SubmitResult::Rejected(Rejection::QueueFull {
                lane: Lane::Priority
            })
        );
        assert_eq!(rig.channel.pending(Lane::Priority), 3);
    }

    #[test]
    fn priority_is_not_an_authentication_bypass() {
        let mut rig = Rig::roomy();
        let body = Rig::body("panel", 1, 0, None, stop());
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(b"not-the-panel-key", &body.signing_bytes()),
        );
        assert_eq!(
            rig.submit(forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        );
        assert_eq!(rig.channel.pending(Lane::Priority), 0);
        assert_eq!(rig.step(), vec![]);
    }

    #[test]
    fn the_local_user_is_never_refused_for_epoch_or_revision_but_a_controller_is() {
        let mut rig = Rig::roomy();
        // Stale epoch and a wrong revision for a volume change: the panel is applied...
        let local = rig.req("panel", 1, 3, Some(999), adjust("kitchen", 10));
        rig.submit(local);
        // ...and a controller in the same position is not.
        let remote = rig.req("ctl-a", 1, EPOCH, Some(999), adjust("kitchen", 10));
        rig.submit(remote);
        let settled = rig.step();
        assert_eq!(settled[0].peer, id("panel"));
        assert!(matches!(settled[0].outcome, Outcome::Committed { .. }));
        assert_eq!(
            settled[1].outcome,
            Outcome::Refused(Refusal::RevisionMismatch {
                expected: 999,
                actual: 3
            })
        );
        assert_eq!(rig.volume("kitchen"), 60);
    }

    // ----------------------------------------------------------------- expiry and cancellation

    #[test]
    fn a_command_that_waits_past_the_ttl_expires_unapplied_and_that_is_its_recorded_outcome() {
        let mut config = roomy();
        config.pending_ttl_ns = 5_000 * MS;
        let mut rig = Rig::new(config);
        let r = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 10));
        rig.submit(r.clone());
        rig.at(4_999 * MS);
        assert_eq!(rig.channel.pending(Lane::Ordinary), 1);
        rig.at(5_000 * MS);
        let settled = rig.step();
        assert_eq!(settled[0].outcome, Outcome::Refused(Refusal::Expired));
        assert_eq!(rig.volume("kitchen"), 50);
        assert_eq!(rig.channel.pending(Lane::Ordinary), 0);
        assert_eq!(rig.channel.stats().expired_pending, 1);
        assert_eq!(
            rig.submit(r),
            SubmitResult::Settled(Outcome::Refused(Refusal::Expired))
        );
    }

    #[test]
    fn a_cancel_withdraws_a_waiting_command_and_the_retry_is_told_so() {
        let mut rig = Rig::roomy();
        let target = rig.req("ctl-a", 1, EPOCH, Some(2), adjust("kitchen", 30));
        rig.submit(target.clone());
        let cancel = rig.req(
            "ctl-a",
            2,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 1 },
        );
        assert_eq!(
            rig.submit(cancel),
            SubmitResult::Queued {
                lane: Lane::Priority
            }
        );
        let settled = rig.step();
        assert_eq!(settled.len(), 2);
        assert_eq!(settled[0].outcome, Outcome::Withdrawn);
        assert_eq!(settled[1].outcome, Outcome::CancelApplied { target_seq: 1 });
        assert_eq!(rig.volume("kitchen"), 50, "the withdrawn command never ran");
        assert_eq!(rig.session.state_revision, 2);
        assert_eq!(
            rig.submit(target),
            SubmitResult::Settled(Outcome::Withdrawn)
        );
    }

    #[test]
    fn a_cancel_that_arrives_too_late_or_too_wrong_changes_nothing() {
        let mut rig = Rig::roomy();
        let done = rig.req("ctl-a", 1, EPOCH, None, set_group(70));
        rig.submit(done);
        rig.step();

        let cancels = [
            (
                2,
                ControlCommand::Cancel { target_seq: 1 },
                Refusal::TooLateToCancel,
            ),
            (
                3,
                ControlCommand::Cancel { target_seq: 77 },
                Refusal::NothingToCancel,
            ),
        ];
        for (seq, command, expected) in cancels {
            let r = rig.req("ctl-a", seq, EPOCH, None, command);
            rig.submit(r);
            assert_eq!(rig.step()[0].outcome, Outcome::Refused(expected));
        }
        assert_eq!(rig.session.group_master_volume, 70);

        // A stop that is still waiting is not withdrawn by a cancel. The cancel is submitted first, so
        // it is processed while its target is still in the priority queue.
        let cancel_stop = rig.req(
            "ctl-a",
            5,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 6 },
        );
        rig.submit(cancel_stop);
        let stopping = rig.req("ctl-a", 6, EPOCH, None, stop());
        rig.submit(stopping);
        let settled = rig.step();
        assert_eq!(
            settled[0].outcome,
            Outcome::Refused(Refusal::NotCancellable)
        );
        assert!(
            matches!(settled[1].outcome, Outcome::Committed { .. }),
            "the stop was not withdrawn and ran"
        );
    }

    #[test]
    fn one_peer_cannot_cancel_another_peers_command() {
        let mut rig = Rig::roomy();
        let victim = rig.req("ctl-a", 1, EPOCH, None, set_group(80));
        rig.submit(victim);
        let attack = rig.req(
            "ctl-b",
            2,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 1 },
        );
        rig.submit(attack);
        let settled = rig.step();
        assert_eq!(settled[0].peer, id("ctl-b"));
        assert_eq!(
            settled[0].outcome,
            Outcome::Refused(Refusal::NothingToCancel)
        );
        assert_eq!(
            settled[1].outcome,
            committed(3),
            "the victim's command still ran"
        );
        assert_eq!(rig.session.group_master_volume, 80);
    }

    #[test]
    fn a_cancel_of_a_number_the_ledger_forgot_says_so() {
        let mut config = roomy();
        config.ledger_capacity = 1;
        let mut rig = Rig::new(config);
        for seq in 1..=2u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(40 + seq as u8));
            rig.submit(r);
        }
        rig.step();
        let cancel = rig.req(
            "ctl-a",
            3,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 1 },
        );
        rig.submit(cancel);
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::TargetOutOfWindow { floor: 1 })
        );
    }

    // ----------------------------------------------------------------- the session boundary and accounting

    #[test]
    fn the_channels_own_command_numbers_never_collide_with_the_session_even_past_its_window() {
        let mut config = roomy();
        config.ledger_capacity = 4;
        let mut rig = Rig::new(config);
        // More commits in one epoch than the session remembers (its window is 1024).
        for seq in 1..=1_100u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group((seq % 100) as u8));
            assert!(
                matches!(rig.submit(r), SubmitResult::Queued { .. }),
                "seq {seq}"
            );
            let settled = rig.step();
            assert!(
                matches!(settled[0].outcome, Outcome::Committed { .. }),
                "seq {seq}: {:?}",
                settled[0].outcome
            );
        }
        assert_eq!(rig.session.state_revision, 2 + 1_100);
        assert_eq!(rig.channel.stats().ledger_record_failures, 0);
    }

    #[test]
    fn every_submit_lands_in_exactly_one_bucket() {
        let mut rig = Rig::new({
            let mut c = roomy();
            c.ordinary_capacity = 2;
            c.ordinary_rate = RateLimit::new(6, 100 * MS).unwrap();
            c
        });
        let good = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        let body = Rig::body("ctl-a", 2, EPOCH, None, set_group(61));
        let forged = ControlRequest::new(body.clone(), compute_proof(b"x", &body.signing_bytes()));
        let reuse = rig.req("ctl-a", 1, EPOCH, None, set_group(99));
        let wrong_epoch = rig.req("ctl-a", 3, EPOCH + 5, None, set_group(1));
        let second = rig.req("ctl-a", 4, EPOCH, None, set_group(62));
        let overflow = rig.req("ctl-a", 5, EPOCH, None, set_group(63));
        let sequence = [
            good.clone(),
            good.clone(),
            forged,
            reuse,
            wrong_epoch,
            second,
            overflow,
        ];
        for r in sequence {
            rig.submit(r);
        }
        rig.step();
        rig.submit(good);
        rig.at(10_000 * MS);
        rig.submit(rig.req("ctl-a", 9, EPOCH, None, set_group(1)));
        let s = *rig.channel.stats();
        assert_eq!(s.accounted(), s.received, "{s:?}");
        assert!(s.received >= 9);
    }

    #[test]
    fn diagnostics_show_received_beside_committed() {
        let mut rig = Rig::roomy();
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(60 + seq as u8));
            rig.submit(r);
        }
        let queued = rig.channel.diagnostics(&rig.session);
        assert_eq!((queued.stats.received, queued.stats.accepted), (3, 3));
        assert_eq!((queued.stats.committed, queued.committed_revision), (0, 2));
        rig.step();
        let done = rig.channel.diagnostics(&rig.session);
        assert_eq!((done.stats.committed, done.committed_revision), (3, 5));
        assert_eq!(done.tracked_peers, 0, "nothing has been forgotten yet");
    }

    #[test]
    fn a_configuration_with_a_zero_bound_is_refused() {
        let zero = |edit: fn(&mut ChannelConfig)| {
            let mut c = ChannelConfig::provisional();
            edit(&mut c);
            ControlChannel::new(peers(), c).err()
        };
        assert_eq!(
            zero(|c| c.ordinary_capacity = 0),
            Some(ConfigError::Zero {
                field: "ordinary_capacity"
            })
        );
        assert_eq!(
            zero(|c| c.priority_shared_capacity = 0),
            Some(ConfigError::Zero {
                field: "priority_shared_capacity"
            })
        );
        assert_eq!(
            zero(|c| c.priority_local_reserved = 0),
            Some(ConfigError::Zero {
                field: "priority_local_reserved"
            })
        );
        assert_eq!(
            zero(|c| c.max_per_step = 0),
            Some(ConfigError::Zero {
                field: "max_per_step"
            })
        );
        assert_eq!(
            zero(|c| c.pending_ttl_ns = 0),
            Some(ConfigError::Zero {
                field: "pending_ttl_ns"
            })
        );
        assert_eq!(
            zero(|c| c.ledger_capacity = 0),
            Some(ConfigError::Ledger(LedgerError::ZeroCapacity))
        );
        assert_eq!(
            zero(|c| c.retention_ns = 0),
            Some(ConfigError::Ledger(LedgerError::ZeroRetention))
        );
        assert!(ControlChannel::new(peers(), ChannelConfig::provisional()).is_ok());
    }

    #[test]
    fn stepping_an_idle_channel_does_nothing() {
        let mut rig = Rig::roomy();
        assert_eq!(rig.step(), vec![]);
        assert_eq!(
            rig.channel.diagnostics(&rig.session).stats,
            ChannelStats::default()
        );
    }

    // ----------------------------------------------------------------- revisions and restarts

    #[test]
    fn a_controller_must_name_the_revision_it_read_for_volume_and_mute() {
        let mut rig = Rig::roomy();
        let no_revision = [
            ("set-group-volume", set_group(60)),
            (
                "set-member-volume",
                ControlCommand::SetMemberVolume {
                    member_id: "kitchen".to_string(),
                    volume: 20,
                },
            ),
            ("set-member-mute", mute("den", true)),
        ];
        for (n, (label, command)) in no_revision.into_iter().enumerate() {
            let r = rig.req_raw("ctl-a", n as u64 + 1, EPOCH, None, command);
            assert_eq!(
                rig.submit(r),
                SubmitResult::Rejected(Rejection::RevisionRequired { command: label }),
                "{label}"
            );
        }
        assert_eq!(rig.channel.stats().rejected_revision_required, 3);
        assert_eq!(rig.channel.pending(Lane::Ordinary), 0);
        assert_eq!(rig.channel.pending(Lane::Priority), 0);

        // Turned away at the door, the number is free: the same number with the revision is accepted.
        let fixed = rig.req_raw("ctl-a", 1, EPOCH, Some(2), set_group(60));
        assert!(matches!(rig.submit(fixed), SubmitResult::Queued { .. }));
        // A stop and a cancel need none, and neither does the local user.
        let stop_no_rev = rig.req_raw("ctl-a", 7, EPOCH, None, stop());
        assert!(matches!(
            rig.submit(stop_no_rev),
            SubmitResult::Queued { .. }
        ));
        let cancel = rig.req_raw(
            "ctl-a",
            8,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 1 },
        );
        assert!(matches!(rig.submit(cancel), SubmitResult::Queued { .. }));
        let local = rig.req_raw("panel", 1, 0, None, set_group(20));
        assert!(matches!(rig.submit(local), SubmitResult::Queued { .. }));
        let s = *rig.channel.stats();
        assert_eq!(s.accounted(), s.received);
    }

    #[test]
    fn a_volume_composed_against_an_older_revision_still_applies_within_an_incarnation() {
        // Absolute volume is naturally repeatable: two controllers read the same revision, or one client
        // pipelines updates before the first acknowledgement, and none of them is stale.
        let mut rig = Rig::roomy();
        let a = rig.req_raw("ctl-a", 1, EPOCH, Some(2), set_group(60));
        let b = rig.req_raw("ctl-b", 1, EPOCH, Some(2), set_group(30));
        let a2 = rig.req_raw("ctl-a", 2, EPOCH, Some(2), set_group(35));
        for r in [a, b, a2] {
            assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        }
        let outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        assert_eq!(outcomes, vec![committed(3), committed(4), committed(5)]);
        assert_eq!(rig.session.group_master_volume, 35);
    }

    #[test]
    fn a_revision_the_session_has_not_reached_is_refused() {
        let mut rig = Rig::roomy();
        for (seq, command) in [(1, set_group(60)), (2, mute("den", true))] {
            let r = rig.req_raw("ctl-a", seq, EPOCH, Some(99), command);
            rig.submit(r);
        }
        let outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        let refused = Outcome::Refused(Refusal::RevisionMismatch {
            expected: 99,
            actual: 2,
        });
        assert_eq!(outcomes, vec![refused.clone(), refused]);
        assert_eq!(rig.session.state_revision, 2);
    }

    #[test]
    fn the_revision_floor_is_the_session_revision_at_the_first_step() {
        let mut rig = Rig::roomy();
        assert_eq!(rig.channel.revision_floor(), None);
        rig.step();
        assert_eq!(rig.channel.revision_floor(), Some(2));
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        rig.submit(r);
        rig.step();
        assert_eq!(rig.session.state_revision, 3);
        assert_eq!(
            rig.channel.revision_floor(),
            Some(2),
            "fixed for the incarnation"
        );
    }

    /// The fix for the restart finding: a copy composed before a restart is refused, whatever its
    /// kind, and a fresh command is applied.
    #[test]
    fn after_a_restart_late_absolute_and_relative_copies_are_refused_and_a_fresh_command_applies() {
        let mut rig = Rig::roomy();
        let absolute = rig.req("ctl-a", 1, EPOCH, None, set_group(70));
        rig.submit(absolute.clone());
        rig.step();
        let newer = rig.req("ctl-b", 1, EPOCH, None, set_group(40));
        rig.submit(newer);
        rig.step();
        let relative = rig.req("ctl-a", 2, EPOCH, Some(4), adjust("kitchen", 10));
        rig.submit(relative.clone());
        rig.step();
        assert_eq!(
            (rig.session.group_master_volume, rig.volume("kitchen")),
            (40, 60)
        );
        assert_eq!(rig.session.state_revision, 5);
        // Without a restart the late copies are answered from memory and change nothing.
        assert_eq!(
            rig.submit(absolute.clone()),
            SubmitResult::Settled(committed(3))
        );
        assert_eq!(rig.step(), vec![]);

        // The channel restarts; the group state is kept. Nothing remembers the copies.
        rig.channel = ControlChannel::new(peers(), roomy()).unwrap();
        rig.grant();
        assert!(matches!(rig.submit(absolute), SubmitResult::Queued { .. }));
        assert!(matches!(rig.submit(relative), SubmitResult::Queued { .. }));
        let outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        assert_eq!(
            outcomes,
            vec![
                // Composed against revision 2; this incarnation began at revision 5.
                Outcome::Refused(Refusal::StaleRevision {
                    observed: 2,
                    floor: 5
                }),
                // A relative copy is held to the exact revision, as before.
                Outcome::Refused(Refusal::RevisionMismatch {
                    expected: 4,
                    actual: 5
                }),
            ]
        );
        assert_eq!(
            rig.session.group_master_volume, 40,
            "the newer change was not reverted"
        );
        assert_eq!(rig.volume("kitchen"), 60, "one delta, not two");
        assert_eq!(rig.session.state_revision, 5);

        // The positive path: a client that read the state after the restart is applied.
        let fresh = rig.req("ctl-a", 3, EPOCH, Some(5), set_group(55));
        rig.submit(fresh);
        assert_eq!(rig.step()[0].outcome, committed(6));
        assert_eq!(rig.session.group_master_volume, 55);
        assert_eq!(rig.channel.stats().internal_faults, 0);
    }

    #[test]
    fn a_restarted_channel_starts_its_numbers_above_everything_the_session_remembers() {
        // Three commands under the old incarnation take numbers 1002..1004 (base 1000 plus the
        // revision). A new incarnation counting from the same base must not meet them.
        let mut rig = Rig::roomy();
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(50 + seq as u8));
            rig.submit(r);
        }
        assert!(
            rig.step()
                .iter()
                .all(|s| matches!(s.outcome, Outcome::Committed { .. }))
        );
        rig.channel = ControlChannel::new(peers(), roomy()).unwrap();
        rig.grant();
        for seq in 4..=9u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(50 + seq as u8));
            rig.submit(r);
        }
        // The step budget is four, so the six take two steps.
        let mut outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        outcomes.extend(rig.step().into_iter().map(|s| s.outcome));
        assert_eq!(outcomes.len(), 6);
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, Outcome::Committed { .. })),
            "{outcomes:?}"
        );
        assert_eq!(rig.channel.stats().internal_faults, 0);
        assert_eq!(rig.channel.last_internal_fault(), None);
        assert_eq!(rig.session.state_revision, 2 + 3 + 6);
    }

    #[test]
    fn a_number_taken_by_another_caller_is_an_internal_fault_that_clears() {
        // Another caller of the session uses exactly the number the channel would mint next: base +
        // the revision the session will have after that caller's own change.
        let mut rig = Rig::roomy();
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: 1_003,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .unwrap();
        assert_eq!(rig.session.state_revision, 3);
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(60 + seq as u8));
            rig.submit(r);
        }
        let missing = rig.req(
            "ctl-a",
            4,
            EPOCH,
            None,
            ControlCommand::SetMemberVolume {
                member_id: "nowhere".to_string(),
                volume: 10,
            },
        );
        rig.submit(missing);
        let outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        assert_eq!(outcomes[0], Outcome::Refused(Refusal::InternalFault));
        assert_eq!(outcomes[1], committed(4));
        assert_eq!(outcomes[2], committed(5));
        assert!(
            matches!(
                outcomes[3],
                Outcome::Refused(Refusal::Session(SessionError::UnknownMember { .. }))
            ),
            "an unknown member is still the sender's: {:?}",
            outcomes[3]
        );
        assert_eq!(
            rig.session.group_master_volume, 63,
            "the first took no effect"
        );
        assert_eq!(rig.channel.stats().internal_faults, 1);
        assert_eq!(
            rig.channel.last_internal_fault(),
            Some(&SessionError::DuplicateCommand {
                epoch: EPOCH,
                command_seq: 1_003
            })
        );
        // A retry is told the recorded outcome, which carries no session detail.
        let again = rig.req("ctl-a", 1, EPOCH, Some(3), set_group(61));
        assert_eq!(
            rig.submit(again),
            SubmitResult::Settled(Outcome::Refused(Refusal::InternalFault))
        );
    }

    // ----------------------------------------------------------------- the group lease (G01)

    fn outcome_of(settled: &[Settlement], peer: &str, seq: u64) -> Outcome {
        settled
            .iter()
            .find(|s| s.peer == id(peer) && s.seq == seq)
            .unwrap_or_else(|| panic!("{peer}#{seq} was not settled in {settled:?}"))
            .outcome
            .clone()
    }

    #[test]
    fn a_deposed_leaders_late_command_is_refused_and_the_same_command_under_the_new_lease_applies()
    {
        let mut rig = Rig::roomy();
        // The group's authority moves to epoch 11 through G01's only epoch mint. The channel still
        // holds the lease it was given for epoch 10.
        let issuer = AuthorityToken::issue(&rig.session, LEASE_EXPIRY_NS);
        let mut membership = GroupMembership::new(MembershipConfig::default());
        let renewed = membership
            .advance_epoch(&mut rig.session, &issuer, 11, GroupTime { ns: 0, frame: 0 })
            .unwrap();
        assert_eq!(
            (rig.session.current_epoch, rig.session.state_revision),
            (11, 3)
        );
        rig.channel.authority_mut().rebind(&id("ctl-a"), Some(11));

        let late = rig.req("ctl-a", 1, 11, None, set_group(70));
        assert!(matches!(
            rig.submit(late.clone()),
            SubmitResult::Queued { .. }
        ));
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::Lease(MembershipError::StaleAuthority {
                token_epoch: 10,
                current_epoch: 11
            }))
        );
        assert_eq!(rig.session.group_master_volume, 50, "nothing was touched");
        assert_eq!(rig.session.state_revision, 3);
        assert_eq!(rig.channel.stats().refused_for_lease, 1);

        // The refusal was not recorded, so the same request is judged afresh under the new lease.
        rig.channel
            .install_lease(&rig.session, renewed, rig.now)
            .unwrap();
        assert!(matches!(rig.submit(late), SubmitResult::Queued { .. }));
        assert_eq!(rig.step()[0].outcome, committed(4));
        assert_eq!(rig.session.group_master_volume, 70);
    }

    #[test]
    fn an_expired_lease_is_refused_and_renewal_plus_resubmit_applies() {
        let mut rig = Rig::roomy();
        rig.grant_until(1_000 * MS);
        let first = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        rig.submit(first);
        rig.at(999 * MS);
        assert_eq!(
            rig.step()[0].outcome,
            committed(3),
            "still live just before the expiry"
        );

        let second = rig.req("ctl-a", 2, EPOCH, None, set_group(61));
        rig.at(1_000 * MS);
        rig.submit(second.clone());
        assert_eq!(
            rig.step()[0].outcome,
            Outcome::Refused(Refusal::Lease(MembershipError::AuthorityExpired {
                expires_at_ns: 1_000 * MS,
                now_ns: 1_000 * MS
            }))
        );
        assert_eq!(rig.session.group_master_volume, 60);

        rig.grant_until(5_000 * MS);
        assert!(
            matches!(rig.submit(second), SubmitResult::Queued { .. }),
            "not answered from memory"
        );
        assert_eq!(rig.step()[0].outcome, committed(4));
        assert_eq!(rig.session.group_master_volume, 61);
    }

    #[test]
    fn a_lease_the_session_does_not_accept_cannot_be_installed_and_leaves_the_held_one_alone() {
        let mut rig = Rig::roomy();
        let good = AuthorityToken::issue(&rig.session, LEASE_EXPIRY_NS);
        let flawed = [
            (
                AuthorityToken {
                    issuer_id: "intruder".to_string(),
                    ..good.clone()
                },
                MembershipError::NotConfiguredIssuer,
            ),
            (
                AuthorityToken {
                    group_id: "elsewhere".to_string(),
                    ..good.clone()
                },
                MembershipError::WrongGroup,
            ),
            (
                AuthorityToken {
                    epoch: EPOCH - 1,
                    ..good.clone()
                },
                MembershipError::StaleAuthority {
                    token_epoch: EPOCH - 1,
                    current_epoch: EPOCH,
                },
            ),
            (
                AuthorityToken {
                    epoch: EPOCH + 1,
                    ..good.clone()
                },
                MembershipError::FutureAuthority {
                    token_epoch: EPOCH + 1,
                    current_epoch: EPOCH,
                },
            ),
            (
                AuthorityToken {
                    expires_at_ns: 5,
                    ..good.clone()
                },
                MembershipError::AuthorityExpired {
                    expires_at_ns: 5,
                    now_ns: 5,
                },
            ),
        ];
        for (token, expected) in flawed {
            assert_eq!(
                rig.channel.install_lease(&rig.session, token, 5),
                Err(expected.clone()),
                "{expected:?}"
            );
            assert_eq!(
                rig.channel.lease(),
                Some(&good),
                "the held lease was replaced"
            );
        }
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        rig.submit(r);
        assert_eq!(rig.step()[0].outcome, committed(3));
    }

    #[test]
    fn without_a_lease_group_changes_are_refused_but_a_local_stop_and_mute_on_are_not() {
        // A fresh channel, or one that restarted, holds no lease.
        let mut rig = Rig::without_lease(roomy());
        assert_eq!(rig.channel.lease(), None);
        let remote_volume = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        let remote_stop = rig.req("ctl-a", 2, EPOCH, None, stop());
        let local_stop = rig.req("panel", 1, 0, None, stop());
        let local_mute_on = rig.req("panel", 2, 0, None, mute("den", true));
        let local_mute_off = rig.req("panel", 3, 0, None, mute("den", false));
        let local_volume = rig.req("panel", 4, 0, None, set_group(20));
        for r in [
            remote_volume.clone(),
            remote_stop,
            local_stop,
            local_mute_on,
            local_mute_off,
            local_volume,
        ] {
            assert!(matches!(rig.submit(r), SubmitResult::Queued { .. }));
        }
        let mut settled = rig.step();
        settled.extend(rig.step());
        assert_eq!(settled.len(), 6);
        let refused = Outcome::Refused(Refusal::NoLease);
        // Only silencing is allowed to the person at the device.
        assert!(matches!(
            outcome_of(&settled, "panel", 1),
            Outcome::Committed { .. }
        ));
        assert!(matches!(
            outcome_of(&settled, "panel", 2),
            Outcome::Committed { .. }
        ));
        assert_eq!(
            outcome_of(&settled, "panel", 3),
            refused,
            "an unmute is not silencing"
        );
        assert_eq!(outcome_of(&settled, "panel", 4), refused);
        assert_eq!(outcome_of(&settled, "ctl-a", 1), refused);
        assert_eq!(
            outcome_of(&settled, "ctl-a", 2),
            refused,
            "a remote stop needs the lease"
        );
        assert!(rig.session.members["den"].muted);
        assert_eq!(rig.session.group_master_volume, 50);
        assert_eq!(rig.channel.stats().refused_for_lease, 4);

        // Not recorded: once a lease is installed, the same request is queued, not answered "refused".
        rig.grant();
        assert!(matches!(
            rig.submit(remote_volume),
            SubmitResult::Queued { .. }
        ));
        assert!(matches!(rig.step()[0].outcome, Outcome::Committed { .. }));
        assert_eq!(rig.session.group_master_volume, 60);
    }

    #[test]
    fn a_forged_request_fails_authentication_before_the_lease_is_consulted() {
        let mut rig = Rig::without_lease(roomy());
        let body = Rig::body("ctl-a", 1, EPOCH, Some(2), set_group(99));
        let forged = ControlRequest::new(
            body.clone(),
            compute_proof(b"an-attackers-key-0123456789", &body.signing_bytes()),
        );
        assert_eq!(
            rig.submit(forged),
            SubmitResult::Rejected(Rejection::Unauthenticated(AuthFailure::BadProof))
        );
        assert_eq!(rig.channel.pending(Lane::Ordinary), 0);
        assert_eq!(rig.step(), vec![], "nothing reached the lease check");
        assert_eq!(rig.channel.stats().refused_for_lease, 0);
    }

    #[test]
    fn a_cancel_needs_no_lease() {
        let mut rig = Rig::without_lease(roomy());
        let waiting = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        let cancel = rig.req(
            "ctl-a",
            2,
            EPOCH,
            None,
            ControlCommand::Cancel { target_seq: 1 },
        );
        rig.submit(waiting);
        rig.submit(cancel);
        let outcomes: Vec<Outcome> = rig.step().into_iter().map(|s| s.outcome).collect();
        assert_eq!(
            outcomes,
            vec![Outcome::Withdrawn, Outcome::CancelApplied { target_seq: 1 }]
        );
        assert_eq!(rig.channel.stats().refused_for_lease, 0);
    }

    // ----------------------------------------------------------------- JSONL diagnostics

    #[test]
    fn every_settled_command_is_logged_once_in_the_shared_schema_with_its_correlation_and_revision()
    {
        let mut rig = Rig::roomy();
        rig.log_on(64, 65_536);
        let script = [
            rig.req("ctl-a", 1, EPOCH, None, set_group(60)),
            rig.req("ctl-a", 2, EPOCH, Some(3), adjust("kitchen", 10)),
            rig.req("ctl-b", 1, EPOCH, Some(3), adjust("kitchen", 5)),
            rig.req(
                "ctl-a",
                3,
                EPOCH,
                None,
                ControlCommand::SetMemberVolume {
                    member_id: "nowhere".to_string(),
                    volume: 10,
                },
            ),
        ];
        for r in script {
            rig.submit(r);
        }
        rig.at(2 * MS);
        let settled = rig.step();
        assert_eq!(settled.len(), 4);

        let records = rig.records();
        assert_eq!(
            records.len(),
            settled.len(),
            "one record per settled command"
        );
        let group = rig.pseudonym("grp");
        let a = rig.pseudonym("ctl-a");
        let b = rig.pseudonym("ctl-b");
        let expected = [
            (
                format!("{a}#1"),
                String::new(),
                "n02.step.committed",
                "committed at revision 3",
                3,
                3,
                None,
            ),
            (
                format!("{a}#2"),
                rig.pseudonym("kitchen"),
                "n02.step.committed",
                "committed at revision 4",
                4,
                2,
                None,
            ),
            (
                format!("{b}#1"),
                rig.pseudonym("kitchen"),
                "n02.step.refused.revision_mismatch",
                "revision 3 named, current is 4",
                4,
                1,
                None,
            ),
            (
                format!("{a}#3"),
                rig.pseudonym("nowhere"),
                "n02.step.refused.session",
                "the session refused the command",
                4,
                0,
                Some("unknown_member".to_string()),
            ),
        ];
        for (record, (correlation, member, kind, message, revision, depth, cause)) in
            records.iter().zip(expected)
        {
            assert_eq!(record.schema_version, "ffw.log.v1");
            assert_eq!(
                (record.run_id.as_str(), record.case_id.as_str()),
                ("run-1", "case-1")
            );
            assert_eq!(record.correlation_id, correlation);
            assert_eq!(record.member_id, member);
            assert_eq!(record.group_id, group);
            assert_eq!(record.event_kind, kind);
            assert_eq!(record.message, message);
            assert_eq!(
                (record.source_epoch, record.state_revision),
                (EPOCH, revision),
                "{kind}"
            );
            assert_eq!(record.queue_depth, depth, "{kind}");
            assert_eq!(record.timestamp_mono_ns, 2 * MS);
            assert_eq!(record.latency_us, 2_000, "queued for 2 ms");
            assert_eq!(record.cause, cause, "{kind}");
        }
        for line in rig.channel.log().unwrap().lines() {
            assert!(line.len() <= MAX_LINE_BYTES);
            assert_eq!(redact_sensitive_text(line), line);
        }
        let stats = rig.channel.log().unwrap().stats();
        assert_eq!((stats.emitted, stats.stored, stats.dropped), (4, 4, 0));
    }

    #[test]
    fn a_refusal_carrying_a_key_shaped_input_never_echoes_it() {
        let mut rig = Rig::roomy();
        rig.log_on(64, 65_536);
        // A peer id and a member id that look like credentials: legal labels, but not to be logged.
        let peer_name = "tok-9f3a1c77e0b2";
        let member_name = "sk-live-4e7d9a1c5b22";
        rig.channel
            .authority_mut()
            .admit(
                &id(peer_name),
                PeerRole::Controller,
                &test_key(peer_name),
                Some(EPOCH),
                1,
            )
            .unwrap();
        let set = rig.req(
            peer_name,
            1,
            EPOCH,
            None,
            ControlCommand::SetMemberVolume {
                member_id: member_name.to_string(),
                volume: 10,
            },
        );
        let relative = rig.req(peer_name, 2, EPOCH, Some(2), adjust(member_name, 5));
        let proofs = [set.proof().clone(), relative.proof().clone()];
        rig.submit(set);
        rig.submit(relative);
        let settled = rig.step();

        // The refusals themselves do carry the input back to the sender: that is the positive control.
        assert_eq!(
            outcome_of(&settled, peer_name, 2),
            Outcome::Refused(Refusal::UnknownMember {
                member_id: member_name.to_string()
            })
        );
        assert!(matches!(
            outcome_of(&settled, peer_name, 1),
            Outcome::Refused(Refusal::Session(SessionError::UnknownMember { .. }))
        ));

        // The log does not. Not the peer, not the member, not any recognisable piece of either, not the
        // peer's key, and not the proofs.
        let log = rig.channel.log().unwrap();
        let everything: String = log.lines().collect::<Vec<_>>().join("\n");
        let mut secrets = vec![
            peer_name.to_string(),
            member_name.to_string(),
            "9f3a1c77e0b2".to_string(),
            "4e7d9a1c5b22".to_string(),
            "sk-live".to_string(),
            "0123456789abcdef".to_string(),
        ];
        for proof in &proofs {
            secrets.push(
                proof
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            );
        }
        for secret in &secrets {
            assert!(
                !everything.contains(secret.as_str()),
                "the log echoes {secret:?}"
            );
        }
        // What it holds instead is the keyed pseudonyms, which the owner can compute.
        assert!(everything.contains(&log.pseudonym_of(peer_name)));
        assert!(everything.contains(&log.pseudonym_of(member_name)));
        for line in log.lines() {
            assert_eq!(redact_sensitive_text(line), line, "{line}");
        }
        assert_eq!(log.stats().stored, 2);
    }

    #[test]
    fn the_record_count_is_bounded_and_a_full_log_does_not_slow_or_change_the_channel() {
        let mut rig = Rig::roomy();
        rig.log_on(5, 65_536);
        let mut seq = 0;
        for _ in 0..10 {
            for _ in 0..4 {
                seq += 1;
                let r = rig.req("ctl-a", seq, EPOCH, None, set_group(50 + (seq % 40) as u8));
                rig.submit(r);
            }
            rig.step();
        }
        let stats = rig.channel.log().unwrap().stats();
        assert_eq!(stats.stored, 5, "no more records than the bound");
        assert_eq!((stats.emitted, stats.dropped), (40, 35));
        assert_eq!(stats.emitted, stats.stored as u64 + stats.dropped);
        assert!(stats.bytes <= 65_536);
        assert!(rig.channel.log().unwrap().is_evidence_complete());
        // The channel carried on regardless: every one of the 40 commands was applied.
        assert_eq!(rig.channel.stats().committed, 40);
        assert_eq!(rig.session.state_revision, 2 + 40);
        // The facts waiting for the end of a step never pile up.
        assert!(rig.channel.facts.is_empty());
    }

    #[test]
    fn lease_refusals_and_internal_faults_are_logged_with_their_cause() {
        let mut rig = Rig::without_lease(roomy());
        rig.log_on(16, 65_536);

        // No lease at all.
        let r = rig.req("ctl-a", 1, EPOCH, None, set_group(60));
        rig.submit(r);
        rig.step();
        // A lease that has expired.
        rig.grant_until(1_000 * MS);
        rig.at(1_000 * MS);
        let r = rig.req("ctl-a", 2, EPOCH, None, set_group(60));
        rig.submit(r);
        rig.step();
        // Another caller of the session takes the number the channel would mint next.
        rig.grant();
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: 1_003,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .unwrap();
        let r = rig.req("ctl-a", 3, EPOCH, None, set_group(60));
        rig.submit(r);
        rig.step();

        let records = rig.records();
        let summary: Vec<(&str, Option<&str>)> = records
            .iter()
            .map(|r| (r.event_kind.as_str(), r.cause.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("n02.step.refused.no_lease", None),
                ("n02.step.refused.lease", Some("authority_expired")),
                ("n02.step.refused.internal_fault", Some("duplicate_command")),
            ]
        );
        assert_eq!(records[0].message, "no group lease is held");
        assert_eq!(records[2].state_revision, 3);
        assert!(rig.channel.log().unwrap().is_evidence_complete());
    }

    #[test]
    fn an_internal_fault_record_survives_a_log_full_of_ordinary_records() {
        let mut rig = Rig::roomy();
        rig.log_on(3, 65_536);
        for seq in 1..=3u64 {
            let r = rig.req("ctl-a", seq, EPOCH, None, set_group(60 + seq as u8));
            rig.submit(r);
        }
        rig.step();
        assert_eq!(rig.channel.log().unwrap().stats().stored, 3);
        // Another caller takes the number the channel would mint next, so the next command faults.
        let next = 1_000 + rig.session.state_revision + 1;
        rig.session
            .apply_command(FencedControlCommand {
                epoch: EPOCH,
                command_seq: next,
                payload: GroupCommandPayload::MarkMemberClockLocked {
                    member_id: "kitchen".to_string(),
                },
            })
            .unwrap();
        let r = rig.req("ctl-a", 4, EPOCH, None, set_group(70));
        rig.submit(r);
        rig.step();
        let kinds: Vec<String> = rig.records().into_iter().map(|r| r.event_kind).collect();
        assert_eq!(kinds.len(), 3);
        assert_eq!(
            kinds[2], "n02.step.refused.internal_fault",
            "the fault evicted the oldest ordinary record"
        );
        assert!(rig.channel.log().unwrap().is_evidence_complete());
    }

    #[test]
    fn turning_the_log_on_changes_nothing_the_channel_does() {
        let run = |with_log: bool| {
            let mut rig = Rig::roomy();
            if with_log {
                rig.log_on(8, 65_536);
            }
            let mut seen = Vec::new();
            for seq in 1..=9u64 {
                let r = rig.req("ctl-a", seq, EPOCH, None, set_group(50 + seq as u8));
                rig.submit(r);
            }
            let cancel = rig.req(
                "ctl-a",
                10,
                EPOCH,
                None,
                ControlCommand::Cancel { target_seq: 9 },
            );
            rig.submit(cancel);
            while rig.channel.pending(Lane::Ordinary) + rig.channel.pending(Lane::Priority) > 0 {
                seen.extend(rig.step());
            }
            (seen, *rig.channel.stats(), rig.session.state_revision)
        };
        assert_eq!(run(false), run(true));
    }

    // ----------------------------------------------------------------- lease renewal and the margin (G01 slice 2)

    /// A three-voter quorum group (`coord` holds epoch 10) and the engine that applies its wins.
    struct Quorum {
        config: QuorumConfig,
        terms: LeaseTerms,
        voters: Vec<LeaseVoter>,
        membership: GroupMembership,
    }

    impl Quorum {
        /// Every voter has seen `coord`'s lease for epoch 10 running to `first_lease_ends_ns`.
        fn new(uncertainty_ns: u64, first_lease_ends_ns: u64) -> Self {
            let config = QuorumConfig::new("grp", &["coord", "v2", "v3"]).unwrap();
            let terms = LeaseTerms {
                clock_uncertainty_ns: uncertainty_ns,
                ..LeaseTerms::default()
            };
            let view = LeaseView {
                group_id: "grp".to_string(),
                epoch: EPOCH,
                holder: "coord".to_string(),
                expires_at_ns: first_lease_ends_ns,
            };
            let voters = ["coord", "v2", "v3"]
                .iter()
                .map(|id| {
                    let mut voter = LeaseVoter::new(id, config.clone(), terms).unwrap();
                    voter.observe(&view).unwrap();
                    voter
                })
                .collect();
            let membership = GroupMembership::new(MembershipConfig {
                lease: terms,
                epoch_mint: EpochMint::Quorum,
                ..MembershipConfig::default()
            });
            Self {
                config,
                terms,
                voters,
                membership,
            }
        }

        /// The round for `request`, answered by every voter at `now_ns`, and its outcome.
        fn win(&mut self, request: &LeaseRequest, now_ns: u64) -> LeaseWin {
            let mut round =
                QuorumRound::start(&self.config, self.terms, request.clone(), now_ns).unwrap();
            for voter in &mut self.voters {
                let ack = voter.respond(request, now_ns).unwrap();
                round.record(&ack, now_ns).unwrap();
            }
            round.outcome(now_ns).unwrap()
        }

        /// `coord` extends its own lease to `now_ns + lease_ns`.
        fn renewal(&mut self, now_ns: u64, lease_ns: u64) -> LeaseWin {
            let request = self.voters[0].renew_request(now_ns, lease_ns).unwrap();
            self.win(&request, now_ns)
        }

        /// `coord` asks for the next epoch.
        fn takeover(&mut self, now_ns: u64, lease_ns: u64) -> LeaseWin {
            let request = self.voters[0].takeover_request(now_ns, lease_ns).unwrap();
            self.win(&request, now_ns)
        }
    }

    fn at_ns(ns: u64) -> GroupTime {
        GroupTime { ns, frame: 0 }
    }

    #[test]
    fn a_holder_that_renews_through_a_quorum_win_keeps_applying_commands_with_no_gap() {
        let u = 10 * MS;
        let mut config = roomy();
        config.lease_margin_ns = u;

        // Without a renewal the lease is usable up to the margin and refused from it: the control.
        let mut control = Rig::new(config);
        control.grant_until(1_000 * MS);
        assert!(matches!(
            control.volume_at(1, EPOCH, 990 * MS - 1),
            Outcome::Committed { .. }
        ));
        assert_eq!(
            control.volume_at(2, EPOCH, 990 * MS),
            Outcome::Refused(Refusal::Lease(MembershipError::AuthorityExpired {
                expires_at_ns: 1_000 * MS,
                now_ns: 990 * MS
            }))
        );

        // With a renewal won at 800 ms, the same instants are served, with no gap, and the new lease
        // ends where the quorum said.
        let mut quorum = Quorum::new(u, 1_000 * MS);
        let mut rig = Rig::new(config);
        rig.grant_until(1_000 * MS);
        let win = quorum.renewal(800 * MS, 1_000 * MS);
        rig.at(800 * MS);
        rig.channel
            .renew_lease(&mut quorum.membership, &rig.session, &win, at_ns(800 * MS))
            .unwrap();
        assert_eq!(rig.channel.lease().unwrap().expires_at_ns, 1_800 * MS);
        assert!(matches!(
            rig.volume_at(1, EPOCH, 990 * MS - 1),
            Outcome::Committed { .. }
        ));
        assert!(
            matches!(rig.volume_at(2, EPOCH, 990 * MS), Outcome::Committed { .. }),
            "no gap at the old margin"
        );
        assert!(matches!(
            rig.volume_at(3, EPOCH, 1_500 * MS),
            Outcome::Committed { .. }
        ));
        assert_eq!(
            rig.volume_at(4, EPOCH, 1_790 * MS),
            Outcome::Refused(Refusal::Lease(MembershipError::AuthorityExpired {
                expires_at_ns: 1_800 * MS,
                now_ns: 1_790 * MS
            })),
            "the renewed lease also stops a margin early"
        );
        assert_eq!(rig.channel.stats().refused_for_lease, 1);

        // The same win cannot be applied again to stretch the lease: it extends nothing.
        assert_eq!(
            rig.channel.renew_lease(
                &mut quorum.membership,
                &rig.session,
                &win,
                at_ns(1_000 * MS)
            ),
            Err(RenewError::Refused(MembershipError::LeaseNotExtended {
                expires_at_ns: 1_800 * MS,
                current_ns: 1_800 * MS
            }))
        );
    }

    #[test]
    fn a_lapsed_holders_renewal_is_refused_and_its_commands_stay_refused_until_it_wins_a_new_epoch()
    {
        let u = 10 * MS;
        let mut config = roomy();
        config.lease_margin_ns = u;
        let mut quorum = Quorum::new(u, 1_000 * MS);
        let mut rig = Rig::new(config);
        rig.grant_until(1_000 * MS);

        // A renewal the holder won at 500 ms but sat on: the voters now believe the lease runs to 1500.
        let stalled = quorum.renewal(500 * MS, 1_000 * MS);

        // At 995 ms the holder is lapsed by its own conservative reading, so the engine refuses it.
        rig.at(995 * MS);
        let expired = MembershipError::AuthorityExpired {
            expires_at_ns: 1_000 * MS,
            now_ns: 995 * MS,
        };
        assert_eq!(
            rig.channel.renew_lease(
                &mut quorum.membership,
                &rig.session,
                &stalled,
                at_ns(995 * MS)
            ),
            Err(RenewError::Refused(expired.clone()))
        );
        assert_eq!(
            rig.channel.lease().unwrap().expires_at_ns,
            1_000 * MS,
            "the lease is as it was"
        );
        assert_eq!(
            rig.volume_at(1, EPOCH, 995 * MS),
            Outcome::Refused(Refusal::Lease(expired))
        );

        // The voters will not grant a takeover before the previous term has surely ended (their
        // latest view is 1500 ms, plus the uncertainty).
        let early = quorum.voters[0]
            .takeover_request(1_000 * MS, 1_000 * MS)
            .unwrap();
        assert_eq!(
            quorum.voters[1].respond(&early, 1_000 * MS),
            Err(MembershipError::LeaseNotExpired {
                conservative_expiry_ns: 1_510 * MS,
                now_ns: 1_000 * MS
            })
        );

        // At 1510 ms it wins epoch 11. Until the owner has the new token the channel stays refused.
        let win = quorum.takeover(1_510 * MS, 1_000 * MS);
        assert_eq!(win.epoch(), 11);
        rig.channel.authority_mut().rebind(&id("ctl-a"), Some(11));
        assert_eq!(
            rig.volume_at(2, 11, 1_510 * MS),
            Outcome::Refused(Refusal::Lease(MembershipError::AuthorityExpired {
                expires_at_ns: 1_000 * MS,
                now_ns: 1_510 * MS
            }))
        );

        let token = quorum
            .membership
            .assume_authority(&mut rig.session, &win, at_ns(1_510 * MS))
            .unwrap();
        assert_eq!((token.epoch, rig.session.current_epoch), (11, 11));
        rig.channel
            .install_lease(&rig.session, token, 1_510 * MS)
            .unwrap();
        assert!(matches!(
            rig.volume_at(3, 11, 1_510 * MS),
            Outcome::Committed { .. }
        ));
    }

    #[test]
    fn adopting_a_newer_holders_lease_fences_a_channel_that_still_holds_the_old_one() {
        let mut quorum = Quorum::new(0, 1_000 * MS);
        let mut rig = Rig::roomy();
        assert!(matches!(
            rig.volume_at(1, EPOCH, 0),
            Outcome::Committed { .. }
        ));

        // The group learns that `v2` holds epoch 11. No call on the channel is needed.
        quorum
            .membership
            .adopt_authority(
                &mut rig.session,
                &LeaseView {
                    group_id: "grp".to_string(),
                    epoch: 11,
                    holder: "v2".to_string(),
                    expires_at_ns: 5_000 * MS,
                },
            )
            .unwrap();
        assert_eq!(
            (
                rig.session.current_epoch,
                rig.session.coordinator_id.as_str()
            ),
            (11, "v2")
        );
        rig.channel.authority_mut().rebind(&id("ctl-a"), Some(11));
        assert_eq!(
            rig.volume_at(2, 11, 0),
            Outcome::Refused(Refusal::Lease(MembershipError::StaleAuthority {
                token_epoch: 10,
                current_epoch: 11
            }))
        );
        // Nor can the old token be put back.
        let old = rig.channel.lease().unwrap().clone();
        assert!(matches!(
            rig.channel.install_lease(&rig.session, old, 0),
            Err(MembershipError::StaleAuthority { .. })
        ));
    }

    #[test]
    fn a_renewal_needs_a_lease_to_renew_and_a_quorum_group_to_renew_in() {
        let mut quorum = Quorum::new(0, 1_000 * MS);
        let win = quorum.renewal(100 * MS, 1_000 * MS);

        // No lease held: nothing to extend.
        let mut bare = Rig::without_lease(roomy());
        assert_eq!(
            bare.channel
                .renew_lease(&mut quorum.membership, &bare.session, &win, at_ns(100 * MS)),
            Err(RenewError::NoLease)
        );

        // A group whose epochs are minted by its configured issuer has no quorum to renew through.
        let mut issuer_mode = GroupMembership::new(MembershipConfig::default());
        let mut rig = Rig::roomy();
        rig.grant_until(1_000 * MS);
        assert_eq!(
            rig.channel
                .renew_lease(&mut issuer_mode, &rig.session, &win, at_ns(100 * MS)),
            Err(RenewError::Refused(MembershipError::NotAQuorumGroup))
        );
        assert_eq!(rig.channel.lease().unwrap().expires_at_ns, 1_000 * MS);
    }

    #[test]
    fn the_channels_gate_and_install_agree_with_g1s_own_liveness_rule_at_every_boundary() {
        let u = 10 * MS;
        let quorum = Quorum::new(u, 1_000 * MS);
        let mut config = roomy();
        config.lease_margin_ns = u;
        let mut rig = Rig::new(config);
        let token = AuthorityToken::issue(&rig.session, 1_000 * MS);
        let instants = [
            0,
            500 * MS,
            990 * MS - 1,
            990 * MS,
            990 * MS + 1,
            999 * MS,
            1_000 * MS,
            1_001 * MS,
        ];
        for ns in instants {
            let live = quorum.membership.lease_is_live(&rig.session, &token, ns);
            assert_eq!(
                rig.channel
                    .install_lease(&rig.session, token.clone(), ns)
                    .is_ok(),
                live,
                "install at {ns} ns"
            );
        }
        // The gate: install at the start, then judge a command at each instant.
        rig.channel
            .install_lease(&rig.session, token.clone(), 0)
            .unwrap();
        for (n, ns) in instants.into_iter().enumerate() {
            let live = quorum.membership.lease_is_live(&rig.session, &token, ns);
            let outcome = rig.volume_at(n as u64 + 1, EPOCH, ns);
            assert_eq!(
                matches!(outcome, Outcome::Committed { .. }),
                live,
                "gate at {ns} ns: {outcome:?}"
            );
        }
    }

    #[test]
    fn the_margin_is_taken_from_g1s_lease_terms() {
        let terms = LeaseTerms {
            clock_uncertainty_ns: 7,
            ..LeaseTerms::default()
        };
        assert_eq!(ChannelConfig::provisional().lease_margin_ns, 0);
        assert_eq!(
            ChannelConfig::provisional()
                .with_lease_terms(&terms)
                .lease_margin_ns,
            7
        );
    }
}
