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
    applied_commands: BTreeSet<(u64, u64)>,
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
            applied_commands: BTreeSet::new(),
        }
    }

    /// Apply a fenced control command, enforcing epoch monotonicity and idempotency.
    pub fn apply_command(&mut self, cmd: FencedControlCommand) -> Result<u64, SessionError> {
        if cmd.epoch < self.current_epoch {
            return Err(SessionError::StaleEpoch {
                command_epoch: cmd.epoch,
                current_epoch: self.current_epoch,
            });
        }
        if !self.applied_commands.insert((cmd.epoch, cmd.command_seq)) {
            return Err(SessionError::DuplicateCommand {
                epoch: cmd.epoch,
                command_seq: cmd.command_seq,
            });
        }
        if cmd.epoch > self.current_epoch {
            self.current_epoch = cmd.epoch;
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
    use franken_board_profile::canonical_board_catalog;

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
}
