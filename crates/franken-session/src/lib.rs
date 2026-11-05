//! Unified Cross-Generation Group Membership, Epoch Fencing, and Volume/Channel Roles
//! (`G01` / `ffw-kh0`, `G02` / `ffw-ld0`, `N02` / `ffw-ugf`).
//!
//! Eliminates the artificial S1 (`swGen=1`) vs. S2 (`swGen=2`) group segregation while
//! enforcing monotonic coordinator epochs, command idempotency, and irrevocable
//! hardware DMA tail accounting on stop/leave transitions.

#![forbid(unsafe_code)]

use franken_board_profile::BoardProfile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole {
    Stereo,
    LeftMono,
    RightMono,
    MonoSum,
    SubLfe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberLifecycleState {
    JoiningClockSync,
    SynchronizedReady,
    StoppingDmaTail { tail_complete_ns: u64 },
    DegradedStandalone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMemberState {
    pub member_id: String,
    pub profile_id: String,
    pub legacy_sw_gen_hint: u8,
    pub role: ChannelRole,
    pub volume_0_to_100: u8,
    pub muted: bool,
    pub lifecycle: MemberLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum GroupCommandPayload {
    AdmitMember {
        member_id: String,
        board: BoardProfile,
        role: ChannelRole,
    },
    MarkMemberClockLocked {
        member_id: String,
    },
    SetGroupVolume {
        volume_0_to_100: u8,
    },
    SetMemberVolume {
        member_id: String,
        volume_0_to_100: u8,
    },
    SetMemberMute {
        member_id: String,
        muted: bool,
    },
    StopGroupPlayback {
        now_ns: u64,
        irrevocable_dma_tail_ns: u64,
    },
    RemoveMember {
        member_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedControlCommand {
    pub epoch: u64,
    pub command_seq: u64,
    pub payload: GroupCommandPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum SessionError {
    #[error("stale coordinator epoch {command_epoch} < current epoch {current_epoch}")]
    StaleEpoch {
        command_epoch: u64,
        current_epoch: u64,
    },
    #[error("duplicate command (epoch={epoch}, seq={command_seq}) rejected")]
    DuplicateCommand { epoch: u64, command_seq: u64 },
    #[error("board profile `{profile_id}` is not eligible for audio group admission")]
    IneligibleAudioBoard { profile_id: String },
    #[error("unknown group member `{member_id}`")]
    UnknownMember { member_id: String },
    #[error(
        "command (epoch={epoch}, seq={command_seq}) is at or below the idempotency floor {window_floor}: whether it was applied can no longer be known, so it is refused rather than risk applying it twice"
    )]
    CommandBelowWindow {
        epoch: u64,
        command_seq: u64,
        window_floor: u64,
    },
}

/// How many applied command sequence numbers of the current epoch the session remembers.
pub const COMMAND_DEDUP_WINDOW: usize = 1024;

/// Bounded memory of which command sequence numbers of the current epoch have been applied.
///
/// Only commands that were actually applied are recorded, so a rejected command never burns its
/// sequence number and a corrected retry under the same number gets its real outcome. At most
/// [`COMMAND_DEDUP_WINDOW`] numbers are kept: when more arrive the smallest is evicted and the
/// eviction floor rises to it. Anything at or below the floor can no longer be proven unapplied,
/// so it is refused (`CommandBelowWindow`) instead of being applied again. A large jump in
/// sequence number costs one slot and cannot lock out the numbers below it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AppliedCommands {
    seqs: BTreeSet<u64>,
    evicted_through: Option<u64>,
}

impl AppliedCommands {
    fn check(&self, epoch: u64, seq: u64) -> Result<(), SessionError> {
        if self.seqs.contains(&seq) {
            return Err(SessionError::DuplicateCommand {
                epoch,
                command_seq: seq,
            });
        }
        if let Some(floor) = self.evicted_through
            && seq <= floor
        {
            return Err(SessionError::CommandBelowWindow {
                epoch,
                command_seq: seq,
                window_floor: floor,
            });
        }
        Ok(())
    }

    fn record(&mut self, seq: u64) {
        self.seqs.insert(seq);
        while self.seqs.len() > COMMAND_DEDUP_WINDOW {
            let Some(oldest) = self.seqs.pop_first() else {
                break;
            };
            self.evicted_through = Some(
                self.evicted_through
                    .map_or(oldest, |floor| floor.max(oldest)),
            );
        }
    }
}

/// Unified group state machine supporting mixed S1 (`swGen=1`) and S2 (`swGen=2`) speakers (`G01`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedGroupSession {
    pub group_id: String,
    pub coordinator_id: String,
    pub current_epoch: u64,
    pub state_revision: u64,
    pub group_master_volume: u8,
    pub members: BTreeMap<String, GroupMemberState>,
    applied_commands: AppliedCommands,
}

impl UnifiedGroupSession {
    #[must_use]
    pub fn new(group_id: &str, coordinator_id: &str, initial_epoch: u64) -> Self {
        Self {
            group_id: group_id.to_string(),
            coordinator_id: coordinator_id.to_string(),
            current_epoch: initial_epoch.max(1),
            state_revision: 0,
            group_master_volume: 50,
            members: BTreeMap::new(),
            applied_commands: AppliedCommands::default(),
        }
    }

    /// Apply a fenced control command, enforcing epoch monotonicity and idempotency.
    ///
    /// A command is judged against the record of its own epoch and recorded only once it has been
    /// applied: a rejected command leaves the epoch, the record and the state untouched, so it can
    /// be retried (corrected) under the same sequence number, while a duplicate of an applied one
    /// is `DuplicateCommand`. A command from a newer epoch has no record yet; adopting that epoch
    /// drops the older epoch's record.
    pub fn apply_command(&mut self, cmd: FencedControlCommand) -> Result<u64, SessionError> {
        if cmd.epoch < self.current_epoch {
            return Err(SessionError::StaleEpoch {
                command_epoch: cmd.epoch,
                current_epoch: self.current_epoch,
            });
        }
        if cmd.epoch == self.current_epoch {
            self.applied_commands.check(cmd.epoch, cmd.command_seq)?;
        }

        match cmd.payload {
            GroupCommandPayload::AdmitMember {
                member_id,
                board,
                role,
            } => {
                if board.verify_integrity().is_err() {
                    return Err(SessionError::IneligibleAudioBoard {
                        profile_id: board.profile_id,
                    });
                }
                self.members.insert(
                    member_id.clone(),
                    GroupMemberState {
                        member_id,
                        profile_id: board.profile_id,
                        legacy_sw_gen_hint: board.legacy_sw_gen_hint,
                        role,
                        volume_0_to_100: 50,
                        muted: false,
                        lifecycle: MemberLifecycleState::JoiningClockSync,
                    },
                );
            }
            GroupCommandPayload::MarkMemberClockLocked { member_id } => {
                let m = self
                    .members
                    .get_mut(&member_id)
                    .ok_or(SessionError::UnknownMember { member_id })?;
                m.lifecycle = MemberLifecycleState::SynchronizedReady;
            }
            GroupCommandPayload::SetGroupVolume { volume_0_to_100 } => {
                self.group_master_volume = volume_0_to_100.min(100);
            }
            GroupCommandPayload::SetMemberVolume {
                member_id,
                volume_0_to_100,
            } => {
                let m = self
                    .members
                    .get_mut(&member_id)
                    .ok_or(SessionError::UnknownMember { member_id })?;
                m.volume_0_to_100 = volume_0_to_100.min(100);
            }
            GroupCommandPayload::SetMemberMute { member_id, muted } => {
                let m = self
                    .members
                    .get_mut(&member_id)
                    .ok_or(SessionError::UnknownMember { member_id })?;
                m.muted = muted;
            }
            GroupCommandPayload::StopGroupPlayback {
                now_ns,
                irrevocable_dma_tail_ns,
            } => {
                let tail_complete_ns = now_ns.saturating_add(irrevocable_dma_tail_ns);
                for m in self.members.values_mut() {
                    m.lifecycle = MemberLifecycleState::StoppingDmaTail { tail_complete_ns };
                }
            }
            GroupCommandPayload::RemoveMember { member_id } => {
                if self.members.remove(&member_id).is_none() {
                    return Err(SessionError::UnknownMember { member_id });
                }
            }
        }

        // Adopt a newer epoch only now that the command has been applied. Every rejection above
        // returns before this point, so a malformed, unauthorised or ineligible command at a
        // far-future epoch can no longer fence out the legitimate coordinator.
        if cmd.epoch > self.current_epoch {
            self.current_epoch = cmd.epoch;
            self.applied_commands = AppliedCommands::default();
        }
        self.applied_commands.record(cmd.command_seq);
        self.state_revision = self.state_revision.saturating_add(1);
        Ok(self.state_revision)
    }

    /// Compute normalized linear amplitude gain (`0.0..=1.0`) for a member combining group master and member trim.
    pub fn effective_member_gain(&self, member_id: &str) -> Result<f32, SessionError> {
        let m = self
            .members
            .get(member_id)
            .ok_or_else(|| SessionError::UnknownMember {
                member_id: member_id.to_string(),
            })?;
        if m.muted || self.group_master_volume == 0 || m.volume_0_to_100 == 0 {
            return Ok(0.0);
        }
        let g =
            (f32::from(self.group_master_volume) / 100.0) * (f32::from(m.volume_0_to_100) / 100.0);
        Ok(g.clamp(0.0, 1.0))
    }

    /// Returns `true` when the group includes both legacy S1 (`swGen=1`) and S2 (`swGen=2`) hardware in one group.
    #[must_use]
    pub fn is_unified_mixed_generation_group(&self) -> bool {
        let has_s1 = self.members.values().any(|m| m.legacy_sw_gen_hint == 1);
        let has_s2 = self.members.values().any(|m| m.legacy_sw_gen_hint == 2);
        has_s1 && has_s2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture: the canonical catalog holds non-admissible hypotheses.
    use franken_board_profile::synthetic_test_fixture_catalog as canonical_board_catalog;

    #[test]
    fn unified_group_combines_s1_ppc_and_s2_mips_and_enforces_epoch_and_dma_tail() {
        let catalog = canonical_board_catalog();
        let s5_s1 = catalog
            .iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
            .clone();
        let s12_s2 = catalog
            .iter()
            .find(|p| p.model_number == "S12")
            .unwrap()
            .clone();

        let mut session = UnifiedGroupSession::new("grp-unified", "spk-s12", 10);
        session
            .apply_command(FencedControlCommand {
                epoch: 10,
                command_seq: 1,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-s5-office".to_string(),
                    board: s5_s1,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();
        session
            .apply_command(FencedControlCommand {
                epoch: 10,
                command_seq: 2,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-s12-kitchen".to_string(),
                    board: s12_s2,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();

        assert!(session.is_unified_mixed_generation_group());

        // Duplicate command (10, 2) must be rejected
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 10,
                command_seq: 2,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 80
                },
            }),
            Err(SessionError::DuplicateCommand {
                epoch: 10,
                command_seq: 2
            })
        );

        // Stale epoch 9 must be rejected
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 9,
                command_seq: 3,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 80
                },
            }),
            Err(SessionError::StaleEpoch {
                command_epoch: 9,
                current_epoch: 10
            })
        );

        // Stop command records irrevocable DMA tail
        session
            .apply_command(FencedControlCommand {
                epoch: 11,
                command_seq: 1,
                payload: GroupCommandPayload::StopGroupPlayback {
                    now_ns: 1_000_000_000,
                    irrevocable_dma_tail_ns: 10_666_666,
                },
            })
            .unwrap();
        assert_eq!(
            session.members["spk-s5-office"].lifecycle,
            MemberLifecycleState::StoppingDmaTail {
                tail_complete_ns: 1_010_666_666
            }
        );
    }

    #[test]
    fn hypothesis_catalog_boards_are_not_admitted_but_the_labelled_fixture_is() {
        let hypothesis = franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let hypothesis_id = hypothesis.profile_id.clone();
        let fixture = canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();

        let mut session = UnifiedGroupSession::new("grp-gate", "spk-coordinator", 10);
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 10,
                command_seq: 1,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-hypothesis".to_string(),
                    board: hypothesis,
                    role: ChannelRole::Stereo,
                },
            }),
            Err(SessionError::IneligibleAudioBoard {
                profile_id: hypothesis_id
            })
        );
        assert!(session.members.is_empty());

        // Permitted positive: the labelled synthetic fixture is admitted offline.
        session
            .apply_command(FencedControlCommand {
                epoch: 10,
                command_seq: 2,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-fixture".to_string(),
                    board: fixture,
                    role: ChannelRole::Stereo,
                },
            })
            .unwrap();
        assert_eq!(session.members.len(), 1);
    }

    #[test]
    fn a_rejected_command_does_not_move_the_epoch_fence() {
        let hypothesis = franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let hypothesis_id = hypothesis.profile_id.clone();
        let mut session = UnifiedGroupSession::new("grp-fence", "spk-coordinator", 1);

        // Unknown member at a far-future epoch: rejected, and the fence stays put.
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 999,
                command_seq: 1,
                payload: GroupCommandPayload::RemoveMember {
                    member_id: "ghost".to_string()
                },
            }),
            Err(SessionError::UnknownMember {
                member_id: "ghost".to_string()
            })
        );
        assert_eq!(session.current_epoch, 1);

        // Ineligible (hypothesis) board at another future epoch: same.
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 50,
                command_seq: 1,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: "spk-hypothesis".to_string(),
                    board: hypothesis,
                    role: ChannelRole::Stereo,
                },
            }),
            Err(SessionError::IneligibleAudioBoard {
                profile_id: hypothesis_id
            })
        );
        assert_eq!(session.current_epoch, 1);

        // The legitimate coordinator, still at epoch 1, is accepted.
        assert!(
            session
                .apply_command(FencedControlCommand {
                    epoch: 1,
                    command_seq: 2,
                    payload: GroupCommandPayload::SetGroupVolume {
                        volume_0_to_100: 30
                    },
                })
                .is_ok()
        );

        // Permitted positive: a successful command at a newer epoch is adopted and fences epoch 1.
        assert!(
            session
                .apply_command(FencedControlCommand {
                    epoch: 5,
                    command_seq: 1,
                    payload: GroupCommandPayload::SetGroupVolume {
                        volume_0_to_100: 40
                    },
                })
                .is_ok()
        );
        assert_eq!(session.current_epoch, 5);
        assert_eq!(
            session.apply_command(FencedControlCommand {
                epoch: 1,
                command_seq: 3,
                payload: GroupCommandPayload::SetGroupVolume {
                    volume_0_to_100: 50
                },
            }),
            Err(SessionError::StaleEpoch {
                command_epoch: 1,
                current_epoch: 5
            })
        );
    }
}
