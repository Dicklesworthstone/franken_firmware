//! Unified Cross-Generation Group Membership, Epoch Fencing, and Volume/Channel Roles
//! (`G01` / `ffw-kh0`, `G02` / `ffw-ld0`, `N02` / `ffw-ugf`).
//!
//! Eliminates the artificial S1 (`swGen=1`) vs. S2 (`swGen=2`) group segregation while
//! enforcing monotonic coordinator epochs, command idempotency, and irrevocable
//! hardware DMA tail accounting on stop/leave transitions.
//!
//! Membership changes (join, leave, exclusion) go through the cutover protocol in
//! [`membership`]: propose a future frame, gather readiness acknowledgements, commit, and
//! activate at that frame. It is additive and has its own error type; `apply_command` is unchanged.
//!
//! Which source owns the group's program (Spotify, AirPlay 2, line-in) is decided by
//! [`SourceArbiter`] in [`source`]: replace or reject by kind and command class, one source epoch per
//! observed epoch, and a publish gate that refuses a replaced source.

#![forbid(unsafe_code)]

use franken_board_profile::BoardProfile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod membership;
mod source;
pub use membership::{
    AbortReason, AuthorityToken, DurableVoterRecord, EpochMint, GrantRecord, GroupMembership,
    GroupTime, IntendedMember, LeaseAck, LeaseRequest, LeaseRequestKind, LeaseTerms, LeaseView,
    LeaseVoter, LeaseWin, MAX_GROUP_MEMBERS, MAX_TERMINAL_HISTORY, MembershipChange,
    MembershipConfig, MembershipError, MembershipIntent, MissingAckPolicy, OutputBound,
    OutputResolution, ProposalPhase, ProposalSpec, ProposalStatus, QuorumConfig, QuorumRound,
    ReadinessReport,
};
pub use source::{
    Admitted, CommandClass, MAX_SOURCE_LABEL_BYTES, SourceArbiter, SourceCommand, SourceConfig,
    SourceEpoch, SourceError, SourceId, SourceKind, SourcePolicy, SourcePolicyTable, SourceView,
};

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

    fn set_volume(epoch: u64, command_seq: u64, volume_0_to_100: u8) -> FencedControlCommand {
        FencedControlCommand {
            epoch,
            command_seq,
            payload: GroupCommandPayload::SetGroupVolume { volume_0_to_100 },
        }
    }

    fn admit(
        epoch: u64,
        command_seq: u64,
        member_id: &str,
        board: BoardProfile,
    ) -> FencedControlCommand {
        FencedControlCommand {
            epoch,
            command_seq,
            payload: GroupCommandPayload::AdmitMember {
                member_id: member_id.to_string(),
                board,
                role: ChannelRole::Stereo,
            },
        }
    }

    fn remove(epoch: u64, command_seq: u64, member_id: &str) -> FencedControlCommand {
        FencedControlCommand {
            epoch,
            command_seq,
            payload: GroupCommandPayload::RemoveMember {
                member_id: member_id.to_string(),
            },
        }
    }

    fn fixture_s5() -> BoardProfile {
        canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
    }

    fn hypothesis_s5() -> BoardProfile {
        franken_board_profile::canonical_board_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap()
    }

    #[test]
    fn a_rejected_command_does_not_burn_its_sequence_number_and_a_corrected_retry_is_applied() {
        let hypothesis = hypothesis_s5();
        let hypothesis_id = hypothesis.profile_id.clone();
        let mut session = UnifiedGroupSession::new("grp-retry", "spk-coordinator", 1);

        // Seq 1 carries an ineligible board: refused, and nothing is recorded or changed.
        assert_eq!(
            session.apply_command(admit(1, 1, "spk-a", hypothesis.clone())),
            Err(SessionError::IneligibleAudioBoard {
                profile_id: hypothesis_id.clone()
            })
        );
        assert_eq!(session.state_revision, 0);
        assert!(session.members.is_empty());
        assert!(session.applied_commands.seqs.is_empty());

        // The same command again is judged afresh and refused for its real reason, not as a duplicate.
        assert_eq!(
            session.apply_command(admit(1, 1, "spk-a", hypothesis)),
            Err(SessionError::IneligibleAudioBoard {
                profile_id: hypothesis_id
            })
        );

        // The corrected command under the same sequence number gets its real outcome: applied.
        assert_eq!(
            session.apply_command(admit(1, 1, "spk-a", fixture_s5())),
            Ok(1)
        );
        assert_eq!(session.members.len(), 1);

        // Now that seq 1 was applied, redelivering it is a duplicate and changes nothing, even
        // with a payload that would otherwise be admitted.
        assert_eq!(
            session.apply_command(admit(1, 1, "spk-b", fixture_s5())),
            Err(SessionError::DuplicateCommand {
                epoch: 1,
                command_seq: 1
            })
        );
        assert_eq!(session.members.len(), 1);
        assert_eq!(session.state_revision, 1);
    }

    #[test]
    fn a_duplicate_of_an_applied_command_stays_a_duplicate_even_when_its_payload_would_now_fail() {
        let mut session = UnifiedGroupSession::new("grp-dup", "spk-coordinator", 1);
        session
            .apply_command(admit(1, 1, "spk-a", fixture_s5()))
            .unwrap();
        assert_eq!(session.apply_command(remove(1, 2, "spk-a")), Ok(2));

        // The member is gone, so running this payload again would fail with UnknownMember. The
        // answer is still Duplicate, because the command was applied.
        assert_eq!(
            session.apply_command(remove(1, 2, "spk-a")),
            Err(SessionError::DuplicateCommand {
                epoch: 1,
                command_seq: 2
            })
        );
        // A never-applied sequence number with the same payload gets the real reason...
        assert_eq!(
            session.apply_command(remove(1, 3, "spk-a")),
            Err(SessionError::UnknownMember {
                member_id: "spk-a".to_string()
            })
        );
        // ...and that refusal did not burn seq 3.
        let tracked: Vec<u64> = session.applied_commands.seqs.iter().copied().collect();
        assert_eq!(tracked, [1, 2]);
    }

    #[test]
    fn out_of_order_and_gapped_sequence_numbers_are_each_applied_exactly_once() {
        let mut session = UnifiedGroupSession::new("grp-order", "spk-coordinator", 1);
        for seq in [1u64, 3, 2] {
            assert!(
                session.apply_command(set_volume(1, seq, 10)).is_ok(),
                "seq {seq}"
            );
        }
        assert_eq!(
            session.apply_command(set_volume(1, 2, 11)),
            Err(SessionError::DuplicateCommand {
                epoch: 1,
                command_seq: 2
            })
        );
        assert_eq!(session.group_master_volume, 10);
        assert_eq!(session.state_revision, 3);
    }

    #[test]
    fn the_record_stays_bounded_over_a_long_stream_and_below_window_commands_are_refused() {
        let mut session = UnifiedGroupSession::new("grp-long", "spk-coordinator", 1);
        for seq in 1..=100_000u64 {
            assert!(
                session.apply_command(set_volume(1, seq, 20)).is_ok(),
                "seq {seq}"
            );
            assert!(session.applied_commands.seqs.len() <= COMMAND_DEDUP_WINDOW);
        }
        assert_eq!(session.state_revision, 100_000);
        assert_eq!(session.applied_commands.seqs.len(), COMMAND_DEDUP_WINDOW);
        // The newest 1024 numbers, 98_977..=100_000, are remembered; 98_976 and below are not.
        assert_eq!(session.applied_commands.evicted_through, Some(98_976));
        assert_eq!(session.applied_commands.seqs.first(), Some(&98_977));
        assert_eq!(session.applied_commands.seqs.last(), Some(&100_000));

        let before = (session.state_revision, session.group_master_volume);
        // A long-evicted number is refused as below the window and is not applied again.
        assert_eq!(
            session.apply_command(set_volume(1, 1, 99)),
            Err(SessionError::CommandBelowWindow {
                epoch: 1,
                command_seq: 1,
                window_floor: 98_976
            })
        );
        // So is the floor itself, which can no longer be proven unapplied.
        assert_eq!(
            session.apply_command(set_volume(1, 98_976, 99)),
            Err(SessionError::CommandBelowWindow {
                epoch: 1,
                command_seq: 98_976,
                window_floor: 98_976
            })
        );
        assert_eq!(
            (session.state_revision, session.group_master_volume),
            before
        );

        // The oldest and newest remembered numbers are still plain duplicates.
        for seq in [98_977u64, 100_000] {
            assert_eq!(
                session.apply_command(set_volume(1, seq, 99)),
                Err(SessionError::DuplicateCommand {
                    epoch: 1,
                    command_seq: seq
                })
            );
        }
        assert_eq!(
            (session.state_revision, session.group_master_volume),
            before
        );

        // Permitted positive: the next fresh number is applied.
        assert_eq!(
            session.apply_command(set_volume(1, 100_001, 21)),
            Ok(100_001)
        );
        assert_eq!(session.group_master_volume, 21);
    }

    #[test]
    fn a_large_sequence_jump_costs_one_slot_and_does_not_lock_out_the_numbers_below_it() {
        let mut session = UnifiedGroupSession::new("grp-jump", "spk-coordinator", 1);
        assert!(session.apply_command(set_volume(1, 1_000_000, 30)).is_ok());
        assert!(session.apply_command(set_volume(1, u64::MAX, 31)).is_ok());
        for seq in 1..=3u64 {
            assert!(
                session.apply_command(set_volume(1, seq, 32)).is_ok(),
                "seq {seq} must still be accepted after a jump"
            );
        }
        assert_eq!(session.applied_commands.seqs.len(), 5);
        assert_eq!(session.applied_commands.evicted_through, None);
        assert_eq!(session.group_master_volume, 32);
    }

    #[test]
    fn adopting_a_newer_epoch_drops_the_older_epochs_record() {
        let mut session = UnifiedGroupSession::new("grp-epochs", "spk-coordinator", 1);
        for seq in 1..=2_000u64 {
            session.apply_command(set_volume(1, seq, 5)).unwrap();
        }
        // 2000 applied, 1024 remembered (977..=2000), floor 976.
        assert_eq!(session.applied_commands.evicted_through, Some(976));

        // A rejected command at a newer epoch records nothing and adopts nothing.
        assert_eq!(
            session.apply_command(remove(7, 1, "ghost")),
            Err(SessionError::UnknownMember {
                member_id: "ghost".to_string()
            })
        );
        assert_eq!(session.current_epoch, 1);
        assert_eq!(session.applied_commands.seqs.len(), COMMAND_DEDUP_WINDOW);
        assert_eq!(session.applied_commands.evicted_through, Some(976));

        // The corrected command at the same epoch and sequence is applied: the epoch is adopted
        // and the old epoch's record, floor included, is dropped.
        assert_eq!(session.apply_command(set_volume(7, 1, 6)), Ok(2_001));
        assert_eq!(session.current_epoch, 7);
        assert_eq!(session.applied_commands.seqs.len(), 1);
        assert_eq!(session.applied_commands.evicted_through, None);

        // Within the new epoch a duplicate is a duplicate and a low fresh number is fresh.
        assert_eq!(
            session.apply_command(set_volume(7, 1, 7)),
            Err(SessionError::DuplicateCommand {
                epoch: 7,
                command_seq: 1
            })
        );
        assert_eq!(session.apply_command(set_volume(7, 2, 7)), Ok(2_002));
        // The old epoch is fenced as stale, not as a duplicate or below-window.
        assert_eq!(
            session.apply_command(set_volume(1, 5, 9)),
            Err(SessionError::StaleEpoch {
                command_epoch: 1,
                current_epoch: 7
            })
        );
    }
}
