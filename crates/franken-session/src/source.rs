//! Source ownership arbitration for a group (`G01` / `ffw-kh0`, contract section 10).
//!
//! Several sources (Spotify, AirPlay 2, line-in) can ask to play on one group at the same time. The
//! group has one program, so something has to decide who owns it. [`SourceArbiter`] is that decision,
//! and nothing else: it holds identities and epochs, never audio, a transport or a credential.
//!
//! * **One source epoch per observed epoch.** Every command carries the source epoch its sender last
//!   saw. A command is judged against the current epoch first, and a command that saw an older one is
//!   refused, so of any set of commands that raced from the same view at most one can mint the next
//!   epoch. The losers are told the current epoch and retry deliberately.
//! * **Replace or reject, per kind and class.** When a source that does not own the group sends a
//!   command at the current epoch, [`SourcePolicyTable`] says whether it displaces the owner or is
//!   refused. An owner is never judged by the table.
//! * **A replaced source cannot publish.** [`SourceArbiter::check_publish`] is the gate every block
//!   passes. A block from a source that was replaced is refused with a typed cause
//!   ([`SourceError::SourceReplaced`]) and must not reach output.
//! * **The group epoch fences everything.** The arbiter is bound to the group epoch it last admitted a
//!   command under. When the group's epoch has advanced, the old program is void: no block passes and
//!   a command sees no owner, until a source starts again.
//!
//! Every mutation presents the group's [`AuthorityToken`] (judged first, exactly as in the membership
//! engine), and a refused call changes nothing. The arbiter takes the session by shared reference, so
//! it cannot alter members, volumes or protection state; a source epoch never resets any of them.
//!
//! Out of scope: real Spotify, AirPlay or line-in transports. Here a source is an identity.

use crate::{AuthorityToken, MembershipError, UnifiedGroupSession};
use std::fmt;

/// Longest source label, in bytes.
pub const MAX_SOURCE_LABEL_BYTES: usize = 64;

/// The kinds of source the group arbitrates. Names match `franken-control`'s `SourceKind`; this crate
/// cannot depend on that one, because `franken-control` depends on this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    Spotify,
    AirPlay2,
    LineIn,
}

impl SourceKind {
    pub const ALL: [Self; 3] = [Self::Spotify, Self::AirPlay2, Self::LineIn];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Spotify => "spotify",
            Self::AirPlay2 => "airplay2",
            Self::LineIn => "line-in",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Spotify => 0,
            Self::AirPlay2 => 1,
            Self::LineIn => 2,
        }
    }
}

/// What a source can ask of the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommandClass {
    /// Begin a stream (a new track, a new session). Always a new stream identity.
    Start,
    /// Move within the stream the sender owns.
    Seek,
    /// Re-target the group (which members play).
    GroupChange,
    /// End the stream.
    Stop,
}

impl CommandClass {
    pub const ALL: [Self; 4] = [Self::Start, Self::Seek, Self::GroupChange, Self::Stop];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Seek => "seek",
            Self::GroupChange => "group-change",
            Self::Stop => "stop",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Start => 0,
            Self::Seek => 1,
            Self::GroupChange => 2,
            Self::Stop => 3,
        }
    }
}

impl fmt::Display for CommandClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What happens to a command from a source that does not own the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePolicy {
    /// The sender displaces the owner: a new source epoch is minted.
    Replace,
    /// The command is refused and the owner is untouched.
    Reject,
}

/// The replace-or-reject policy: one cell for each (kind of the **sending** source, command class).
/// It applies only when the sender does not already own the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicyTable {
    cells: [[SourcePolicy; 4]; 3],
}

impl SourcePolicyTable {
    /// The table of contract section 10.1. These are engineering placeholders, not owner-approved policy.
    pub const STANDARD: Self = Self {
        cells: [
            // start, seek, group change, stop
            [
                SourcePolicy::Replace,
                SourcePolicy::Reject,
                SourcePolicy::Reject,
                SourcePolicy::Reject,
            ], // Spotify
            [
                SourcePolicy::Replace,
                SourcePolicy::Reject,
                SourcePolicy::Replace,
                SourcePolicy::Reject,
            ], // AirPlay 2
            [
                SourcePolicy::Reject,
                SourcePolicy::Reject,
                SourcePolicy::Reject,
                SourcePolicy::Reject,
            ], // line-in
        ],
    };

    #[must_use]
    pub const fn get(&self, kind: SourceKind, class: CommandClass) -> SourcePolicy {
        self.cells[kind.index()][class.index()]
    }

    /// The same table with one cell changed.
    #[must_use]
    pub const fn with(
        mut self,
        kind: SourceKind,
        class: CommandClass,
        policy: SourcePolicy,
    ) -> Self {
        self.cells[kind.index()][class.index()] = policy;
        self
    }
}

impl Default for SourcePolicyTable {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Which stream generation a command or block belongs to. Every new stream, replacement, stop and
/// group-epoch transition takes the next number; a number is never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceEpoch(u64);

impl SourceEpoch {
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    const fn successor(self) -> Option<Self> {
        if self.0 == u64::MAX {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }

    const fn successor_saturating(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// A source's identity: its kind and a short label. The label is restricted to `a-z`, `0-9`, `.`, `_`,
/// `:` and `-`, so a pasted token or an address cannot be one; a refusal reports its length only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId {
    kind: SourceKind,
    label: String,
}

impl SourceId {
    pub fn new(kind: SourceKind, label: &str) -> Result<Self, SourceError> {
        let len = label.len();
        let well_formed = (1..=MAX_SOURCE_LABEL_BYTES).contains(&len)
            && label
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'));
        if well_formed {
            Ok(Self {
                kind,
                label: label.to_string(),
            })
        } else {
            Err(SourceError::InvalidSourceLabel { len })
        }
    }

    #[must_use]
    pub const fn kind(&self) -> SourceKind {
        self.kind
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.label(), self.label)
    }
}

/// A source's request, stamped with the source epoch its sender last saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCommand {
    pub source: SourceId,
    pub class: CommandClass,
    pub expected_epoch: SourceEpoch,
}

/// A command that was admitted. The sender's adapter may act on it only now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub class: CommandClass,
    /// The source epoch in force after the command.
    pub epoch: SourceEpoch,
    /// Who owns the group after the command.
    pub owner: Option<SourceId>,
    /// The owner this command displaced. Its adapter must stop publishing; nothing here tells it.
    pub replaced: Option<SourceId>,
    /// Whether this command began a new stream (took the next epoch number).
    pub minted: bool,
}

/// What a command presented now would see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceView {
    pub group_epoch: u64,
    pub epoch: SourceEpoch,
    pub owner: Option<SourceId>,
}

/// Every refusal carries identifiers and numbers only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The group's authority token is not current (see [`MembershipError`]).
    #[error(transparent)]
    Authority(MembershipError),
    #[error(
        "a source label must be 1 to 64 bytes of a-z, 0-9, '.', '_', ':' and '-' (got {len} bytes)"
    )]
    InvalidSourceLabel { len: usize },
    #[error("source epoch {expected} is behind the current source epoch {current}")]
    SourceEpochStale { expected: u64, current: u64 },
    #[error(
        "source epoch {expected} is ahead of the current source epoch {current}; a source never mints one"
    )]
    SourceEpochFuture { expected: u64, current: u64 },
    #[error("the source epoch counter is exhausted")]
    SourceEpochExhausted,
    #[error("{requester} may not {class} while {owner} owns the group")]
    SourceRejected {
        class: CommandClass,
        requester: SourceId,
        owner: SourceId,
    },
    #[error("no source owns the group")]
    NoActiveSource,
    #[error("{sender} was replaced: its epoch {epoch} is behind the current {current}")]
    SourceReplaced {
        sender: SourceId,
        epoch: u64,
        current: u64,
    },
    #[error("{sender} does not own the group; {owner} does")]
    NotSourceOwner { sender: SourceId, owner: SourceId },
    #[error(
        "the group epoch advanced from {arbiter_group_epoch} to {group_epoch}; the old program is void until a source starts again"
    )]
    GroupEpochAdvanced {
        arbiter_group_epoch: u64,
        group_epoch: u64,
    },
}

impl SourceError {
    /// Stable machine-readable name, shared with the Python reference and the contract.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Authority(inner) => inner.code(),
            Self::InvalidSourceLabel { .. } => "INVALID_SOURCE_LABEL",
            Self::SourceEpochStale { .. } => "SOURCE_EPOCH_STALE",
            Self::SourceEpochFuture { .. } => "SOURCE_EPOCH_FUTURE",
            Self::SourceEpochExhausted => "SOURCE_EPOCH_EXHAUSTED",
            Self::SourceRejected { .. } => "SOURCE_REJECTED",
            Self::NoActiveSource => "NO_ACTIVE_SOURCE",
            Self::SourceReplaced { .. } => "SOURCE_REPLACED",
            Self::NotSourceOwner { .. } => "NOT_SOURCE_OWNER",
            Self::GroupEpochAdvanced { .. } => "GROUP_EPOCH_ADVANCED",
        }
    }
}

/// Settings of an arbiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceConfig {
    pub policy: SourcePolicyTable,
    /// The clock-uncertainty margin applied to the authority token, as for the membership engine.
    pub clock_uncertainty_ns: u64,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            policy: SourcePolicyTable::STANDARD,
            clock_uncertainty_ns: 0,
        }
    }
}

/// The outcome of deciding a command, before it is applied.
struct Plan {
    mints: bool,
    owner: Option<SourceId>,
    replaced: Option<SourceId>,
}

/// Arbitrates which source owns one group. See the module documentation.
#[derive(Debug, Clone)]
pub struct SourceArbiter {
    config: SourceConfig,
    /// The group epoch of the last admitted command; `None` until one has been admitted.
    bound: Option<u64>,
    epoch: SourceEpoch,
    owner: Option<SourceId>,
}

impl SourceArbiter {
    /// An arbiter for a group nobody has started yet.
    #[must_use]
    pub fn new(config: SourceConfig) -> Self {
        Self {
            config,
            bound: None,
            epoch: SourceEpoch::new(0),
            owner: None,
        }
    }

    /// An arbiter after a restart. `durable_floor` is the highest source epoch known to have been in
    /// force (kept by a store this crate does not have); the arbiter starts idle above it, so a block
    /// of a stream that existed before the restart can never match a new one.
    #[must_use]
    pub fn resume_after(config: SourceConfig, durable_floor: SourceEpoch) -> Self {
        Self {
            config,
            bound: None,
            epoch: durable_floor.successor_saturating(),
            owner: None,
        }
    }

    /// What a command presented now would see: after a group epoch advance the old owner is gone and
    /// one epoch number has been spent on the transition. Nothing is stored.
    fn effective(&self, group_epoch: u64) -> (Option<&SourceId>, SourceEpoch) {
        match self.bound {
            Some(bound) if bound != group_epoch => (None, self.epoch.successor_saturating()),
            _ => (self.owner.as_ref(), self.epoch),
        }
    }

    #[must_use]
    pub fn view(&self, session: &UnifiedGroupSession) -> SourceView {
        let (owner, epoch) = self.effective(session.current_epoch);
        SourceView {
            group_epoch: session.current_epoch,
            epoch,
            owner: owner.cloned(),
        }
    }

    fn decide(
        &self,
        owner: Option<&SourceId>,
        command: &SourceCommand,
    ) -> Result<Plan, SourceError> {
        let class = command.class;
        let source = &command.source;
        let Some(held) = owner else {
            return if class == CommandClass::Start {
                Ok(Plan {
                    mints: true,
                    owner: Some(source.clone()),
                    replaced: None,
                })
            } else {
                Err(SourceError::NoActiveSource)
            };
        };
        if held == source {
            // The owner is never judged by the table.
            return Ok(match class {
                CommandClass::Start => Plan {
                    mints: true,
                    owner: Some(source.clone()),
                    replaced: None,
                },
                CommandClass::Stop => Plan {
                    mints: true,
                    owner: None,
                    replaced: None,
                },
                CommandClass::Seek | CommandClass::GroupChange => Plan {
                    mints: false,
                    owner: Some(source.clone()),
                    replaced: None,
                },
            });
        }
        match self.config.policy.get(source.kind(), class) {
            SourcePolicy::Reject => Err(SourceError::SourceRejected {
                class,
                requester: source.clone(),
                owner: held.clone(),
            }),
            SourcePolicy::Replace => Ok(Plan {
                mints: true,
                owner: if class == CommandClass::Stop {
                    None
                } else {
                    Some(source.clone())
                },
                replaced: Some(held.clone()),
            }),
        }
    }

    /// Judge a command. Checks, in this order: the group's authority token; the source epoch the
    /// sender presented (older: `SOURCE_EPOCH_STALE`, newer: `SOURCE_EPOCH_FUTURE`); then ownership and
    /// the policy table; then the epoch counter. A refusal changes nothing.
    pub fn submit(
        &mut self,
        session: &UnifiedGroupSession,
        token: &AuthorityToken,
        now_ns: u64,
        command: &SourceCommand,
    ) -> Result<Admitted, SourceError> {
        token
            .check_with_margin(session, now_ns, self.config.clock_uncertainty_ns)
            .map_err(SourceError::Authority)?;
        let (owner, current) = self.effective(session.current_epoch);
        if command.expected_epoch < current {
            return Err(SourceError::SourceEpochStale {
                expected: command.expected_epoch.get(),
                current: current.get(),
            });
        }
        if command.expected_epoch > current {
            return Err(SourceError::SourceEpochFuture {
                expected: command.expected_epoch.get(),
                current: current.get(),
            });
        }
        let plan = self.decide(owner, command)?;
        let epoch_after = if plan.mints {
            current
                .successor()
                .ok_or(SourceError::SourceEpochExhausted)?
        } else {
            current
        };
        self.bound = Some(session.current_epoch);
        self.epoch = epoch_after;
        self.owner.clone_from(&plan.owner);
        Ok(Admitted {
            class: command.class,
            epoch: epoch_after,
            owner: plan.owner,
            replaced: plan.replaced,
            minted: plan.mints,
        })
    }

    /// The gate every block passes before it may reach output: only the owner, under the current
    /// source epoch, in the current group epoch. A source that was replaced is refused as
    /// `SOURCE_REPLACED`, not merely as stale.
    pub fn check_publish(
        &self,
        session: &UnifiedGroupSession,
        source: &SourceId,
        epoch: SourceEpoch,
    ) -> Result<(), SourceError> {
        let Some(bound) = self.bound else {
            return Err(SourceError::NoActiveSource);
        };
        if bound != session.current_epoch {
            return Err(SourceError::GroupEpochAdvanced {
                arbiter_group_epoch: bound,
                group_epoch: session.current_epoch,
            });
        }
        let Some(owner) = self.owner.as_ref() else {
            return Err(SourceError::NoActiveSource);
        };
        if epoch < self.epoch {
            return Err(if owner == source {
                SourceError::SourceEpochStale {
                    expected: epoch.get(),
                    current: self.epoch.get(),
                }
            } else {
                SourceError::SourceReplaced {
                    sender: source.clone(),
                    epoch: epoch.get(),
                    current: self.epoch.get(),
                }
            });
        }
        if epoch > self.epoch {
            return Err(SourceError::SourceEpochFuture {
                expected: epoch.get(),
                current: self.epoch.get(),
            });
        }
        if owner != source {
            return Err(SourceError::NotSourceOwner {
                sender: source.clone(),
                owner: owner.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
