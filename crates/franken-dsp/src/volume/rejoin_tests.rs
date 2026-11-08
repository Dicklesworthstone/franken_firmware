//! What a rejoin may and may not do (`G02` / `ffw-ld0`, box 3, first half): *"Rejoin cannot restore a stale loud
//! volume or undo local/fault mute."*
//!
//! `tests.rs` and `local_mute_tests.rs` already pin that a rejoin takes the group's *current* volume, keeps the room's
//! own mute and trim, and that a restored member is silent until it rejoins. These tests pin what was left open:
//!
//! * a snapshot from the member's own epoch that is **older than what the member has applied** is a stale volume
//!   too. It is refused with nothing changed (an equal or newer one is taken, a newer epoch numbers afresh);
//! * a rejoin cannot clear a **fault mute**, and neither can completing the join; only the board returning to
//!   `Active` does, and it leaves the room's own mute standing;
//! * a rejoin keeps the **fault ceiling**, so the ramp is never handed more than it, before, during or after;
//! * a restarted member that rejoins on a **fail-muted board** stays silent and never arms the stored volume.
//!
//! Every refusal sits beside the behaviour it must not break (the equal or newer snapshot, the board returning to
//! `Active`, the same steps on a healthy board). Expected values are written by hand from the contract, not read
//! back from the code under test. The same behaviour is also in the Python vectors (`G02-MBR-020..024`).
//!
//! What they do not show: a transport that delivers snapshots, or who decides which snapshot is the group's
//! current one. The member only refuses one that is older than its own state.

use super::*;
use crate::StereoAudioBlock;
use crate::protection::{
    Admission, BoardStatus, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for,
};
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};

const EPOCH: u64 = 7;

fn stamp(revision: u64) -> Stamp {
    Stamp {
        epoch: EPOCH,
        revision,
    }
}

fn snapshot(revision: u64, master_volume: u8, group_mute: bool) -> GroupSnapshot {
    GroupSnapshot {
        epoch: EPOCH,
        revision,
        master_volume,
        group_mute,
    }
}

/// A member at epoch 7 with its join already complete and no ceiling below unity.
fn member() -> MemberVolume {
    let mut m = MemberVolume::new(1.0);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    m
}

fn set(m: &mut MemberVolume, revision: u64, command: VolumeCommand) -> CommandReceipt {
    m.apply(stamp(revision), command).expect("accepted")
}

fn fixture(model: &str) -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .expect("fixture board")
}

/// A calibrated board: `Active`, so the member's mute and gain apply.
fn live_board() -> ProtectedBoardDsp {
    let profile = fixture("S3");
    let calibration = synthetic_calibration_for(&profile);
    ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
}

/// An uncalibrated board: not admitted, so it is `FailMuted` and refuses to unmute.
fn failed_board() -> ProtectedBoardDsp {
    ProtectedBoardDsp::admit(&fixture("S3"), None, Admission::HostSimulation)
}

/// Render `frames` single frames of silence and return D02's applied gain after each one.
fn applied_after_each_frame(dsp: &mut ProtectedBoardDsp, frames: usize) -> Vec<f32> {
    let mut out = ProtectedOutput::new();
    let mut one = StereoAudioBlock::silence(0);
    one.frames = 1;
    (0..frames)
        .map(|_| {
            dsp.render_into(&one, &mut out);
            dsp.applied_gain()
        })
        .collect()
}

#[test]
fn a_snapshot_older_than_what_the_member_has_applied_is_refused_and_changes_nothing() {
    let mut m = member();
    set(&mut m, 1, VolumeCommand::SetVolume(80));
    set(&mut m, 2, VolumeCommand::SetVolume(30));
    m.local_mute(true);
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));

    // A delayed snapshot: the group as it was at revision 1, loud, which the member has already replaced.
    assert_eq!(
        m.reconnect(snapshot(1, 80, false)),
        Err(VolumeError::StaleRevision {
            revision: 1,
            last: 2
        })
    );
    assert_eq!(m.desired_volume(), 30, "the stale 80 was not taken");
    assert_eq!(m.last_revision(), 2, "the revision did not roll back");
    assert_eq!(m.epoch(), Some(EPOCH));
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    m.local_mute(false);
    assert_eq!(
        m.effective_mute(),
        None,
        "a refused rejoin did not even start a join"
    );
    assert_eq!(m.output_gain(), 0.3);

    // The same member, at its own revision: the same state again, taken. It starts a join and holds the group's value.
    m.reconnect(snapshot(2, 35, false)).unwrap();
    assert_eq!(m.desired_volume(), 35);
    assert_eq!(m.last_revision(), 2);
    assert_eq!(m.effective_mute(), Some(MuteReason::Join));
    m.complete_join();
    assert_eq!(m.output_gain(), 0.35);

    // A newer snapshot: taken.
    m.reconnect(snapshot(6, 55, false)).unwrap();
    assert_eq!(m.desired_volume(), 55);
    assert_eq!(m.last_revision(), 6);
    m.complete_join();
    assert_eq!(m.output_gain(), 0.55);

    // And an old one is old relative to the member's *latest* revision, not to the one it started with.
    assert_eq!(
        m.reconnect(snapshot(5, 99, false)),
        Err(VolumeError::StaleRevision {
            revision: 5,
            last: 6
        })
    );
    assert_eq!(m.desired_volume(), 55);
    assert_eq!(m.last_revision(), 6);
}

#[test]
fn a_newer_epoch_takes_its_snapshot_at_any_revision_and_an_older_one_is_refused_at_any() {
    let mut m = member();
    set(&mut m, 1, VolumeCommand::SetVolume(80));
    set(&mut m, 5, VolumeCommand::AdjustVolume(-10));
    assert_eq!((m.desired_volume(), m.last_revision()), (70, 5));

    // A new epoch numbers its revisions afresh: revision 1 of epoch 8 is not older than revision 5 of epoch 7.
    m.reconnect(GroupSnapshot {
        epoch: EPOCH + 1,
        revision: 1,
        master_volume: 60,
        group_mute: false,
    })
    .unwrap();
    assert_eq!(m.epoch(), Some(EPOCH + 1));
    assert_eq!(m.last_revision(), 1);
    assert_eq!(m.desired_volume(), 60);
    m.complete_join();

    // Inside the new epoch the revision rule applies again.
    assert_eq!(
        m.apply(
            Stamp {
                epoch: EPOCH + 1,
                revision: 2
            },
            VolumeCommand::SetVolume(40)
        )
        .map(|receipt| receipt.duplicate),
        Ok(false)
    );
    assert_eq!(
        m.reconnect(GroupSnapshot {
            epoch: EPOCH + 1,
            revision: 1,
            master_volume: 90,
            group_mute: false,
        }),
        Err(VolumeError::StaleRevision {
            revision: 1,
            last: 2
        })
    );

    // An older epoch is refused as an old epoch, however high its revision.
    assert_eq!(
        m.reconnect(snapshot(99, 90, false)),
        Err(VolumeError::StaleEpoch {
            command: EPOCH,
            current: EPOCH + 1
        })
    );
    assert_eq!((m.desired_volume(), m.last_revision()), (40, 2));
}

#[test]
fn a_refused_old_snapshot_leaves_retries_and_command_outcomes_exactly_as_they_were() {
    let mut m = member();
    let first = set(&mut m, 1, VolumeCommand::SetVolume(80));
    let second = set(&mut m, 2, VolumeCommand::SetVolume(30));
    assert!(m.reconnect(snapshot(1, 80, false)).is_err());

    // The last command is still the last command: a retry is a duplicate, applied once; another payload conflicts.
    let replay = m
        .apply(stamp(2), VolumeCommand::SetVolume(30))
        .expect("a replay of the last command");
    assert!(replay.duplicate, "the retry was applied again");
    assert_eq!(m.desired_volume(), 30);
    assert_eq!(
        m.apply(stamp(2), VolumeCommand::SetVolume(95)),
        Err(VolumeError::RevisionConflict { revision: 2 })
    );
    // The old loud command is still stale, and is not armed again by the snapshot that tried to roll back to it.
    assert_eq!(
        m.apply(stamp(1), VolumeCommand::SetVolume(80)),
        Err(VolumeError::StaleRevision {
            revision: 1,
            last: 2
        })
    );
    assert_eq!(m.desired_volume(), 30);

    // Both results are still reported as they were produced.
    assert_eq!(
        m.command_outcome(stamp(1)),
        Ok(CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(80),
            receipt: first
        })
    );
    assert_eq!(
        m.command_outcome(stamp(2)),
        Ok(CommandOutcome::Applied {
            command: VolumeCommand::SetVolume(30),
            receipt: second
        })
    );
    assert_eq!(
        m.command_outcome(stamp(3)),
        Ok(CommandOutcome::NotApplied),
        "and the next revision is still the next one"
    );
    assert!(m.apply(stamp(3), VolumeCommand::SetVolume(45)).is_ok());
}

#[test]
fn a_rejoin_cannot_clear_a_fault_mute_and_only_the_board_returning_to_active_does() {
    let failed = failed_board();
    let mut m = member();
    set(&mut m, 1, VolumeCommand::SetVolume(80));
    m.observe_board(failed.status());
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));

    m.reconnect(snapshot(3, 60, false)).unwrap();
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Fault),
        "the rejoin did not clear the fault"
    );
    m.complete_join();
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Fault),
        "nor did completing the join"
    );
    set(&mut m, 4, VolumeCommand::SetGroupMute(false));
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Fault),
        "nor does a group unmute"
    );
    assert_eq!(m.output_gain(), 0.0);

    // The permitted behaviour beside it: the board returns to Active, and the group's 60 plays, never the stored 80.
    m.observe_board(BoardStatus::Active);
    assert_eq!(m.effective_mute(), None);
    assert_eq!(m.output_gain(), 0.6);

    // The fault outranks the room's own mute and clears first; the local mute is still there when it does.
    m.local_mute(true);
    m.observe_board(failed.status());
    m.reconnect(snapshot(6, 40, false)).unwrap();
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));
    m.observe_board(BoardStatus::Active);
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Local),
        "the fault cleared, the room's own mute did not"
    );
    m.complete_join();
    m.local_mute(false);
    assert_eq!(m.effective_mute(), None);
    assert_eq!(m.output_gain(), 0.4);
}

#[test]
fn a_rejoin_keeps_the_fault_ceiling_so_the_ramp_is_never_handed_more_than_it() {
    let mut dsp = live_board();
    let mut m = member();
    m.set_fault_ceiling(Some(0.25));
    set(&mut m, 1, VolumeCommand::SetVolume(100));
    m.sync(&mut dsp).unwrap();
    let before = applied_after_each_frame(&mut dsp, 600);
    assert!(before.iter().all(|&g| g <= 0.25));
    assert_eq!(*before.last().unwrap(), 0.25, "a group at 100 plays 0.25");

    // The room rejoins a group at 80. The ceiling is the room's, not the group's, so it stays.
    m.reconnect(snapshot(3, 80, false)).unwrap();
    assert_eq!(m.effective_ceiling(), 0.25);
    assert_eq!(m.unmuted_gain(), 0.25);
    m.sync(&mut dsp).unwrap();
    let fade = applied_after_each_frame(&mut dsp, 600);
    assert!(
        fade.iter().all(|&g| g <= 0.25),
        "the fade out starts at the ceiling"
    );
    assert_eq!(*fade.last().unwrap(), 0.0);
    m.complete_join();
    m.sync(&mut dsp).unwrap();
    let up = applied_after_each_frame(&mut dsp, 600);
    assert!(
        up.iter().all(|&g| g <= 0.25),
        "the join brings the room back under the ceiling, not to the group's 0.8"
    );
    assert_eq!(*up.last().unwrap(), 0.25);

    // The permitted behaviour beside it: removing the ceiling is what lets the room reach the group's 80.
    m.set_fault_ceiling(None);
    m.sync(&mut dsp).unwrap();
    let freed = applied_after_each_frame(&mut dsp, 600);
    assert!(freed.windows(2).all(|w| w[1] >= w[0]));
    assert_eq!(*freed.last().unwrap(), 0.8);
}

#[test]
fn a_restarted_member_is_silent_on_a_fail_muted_board_and_plays_only_the_groups_on_a_live_one() {
    let stored = PersistedMember {
        volume: 95,
        trim_permille: 1000,
        local_mute: false,
    };

    // On a fail-muted board: nothing is audible before the rejoin, and nothing after it.
    let mut failed = failed_board();
    let mut m = MemberVolume::restore(stored, 1.0);
    m.sync(&mut failed).unwrap();
    assert_eq!(
        m.unmuted_gain(),
        0.0,
        "a restored member has no bounded gain until it rejoins"
    );
    assert!(
        applied_after_each_frame(&mut failed, 300)
            .iter()
            .all(|&g| g == 0.0)
    );
    m.reconnect(snapshot(1, 20, false)).unwrap();
    m.complete_join();
    m.sync(&mut failed).unwrap();
    assert_eq!(
        m.desired_volume(),
        20,
        "the group's volume, not the stored 95"
    );
    assert_eq!(m.unmuted_gain(), 0.2);
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));
    assert!(
        applied_after_each_frame(&mut failed, 600)
            .iter()
            .all(|&g| g == 0.0),
        "the rejoin did not unmute a board that is not admitted"
    );

    // The same steps on a healthy board: audible, and only ever the group's 20.
    let mut live = live_board();
    let mut restored = MemberVolume::restore(stored, 1.0);
    restored.sync(&mut live).unwrap();
    assert_eq!(restored.unmuted_gain(), 0.0);
    assert!(
        applied_after_each_frame(&mut live, 300)
            .iter()
            .all(|&g| g == 0.0)
    );
    restored.reconnect(snapshot(1, 20, false)).unwrap();
    restored.complete_join();
    restored.sync(&mut live).unwrap();
    assert_eq!(restored.effective_mute(), None);
    let after = applied_after_each_frame(&mut live, 600);
    assert!(
        after.iter().all(|&g| g <= 0.2),
        "the stored 95 was never audible"
    );
    assert_eq!(*after.last().unwrap(), 0.2);
}
