//! Local mute without authority (`G02` / `ffw-ld0`, the fresh-eyes refinement): *"Local mute/stop remains available
//! without WAN or a functioning remote controller ... reconnect may not clear local mute or restore stale louder
//! state."*
//!
//! `local_mute` takes no epoch, no revision and no network, so it holds by construction. These tests pin that for a
//! member that has NO authority (never joined, or restarted without a network) and for one whose controller has
//! moved on without it, and pair each with the remote path shown dead, so "the button still works" is not vacuous.
//!
//! What they do not show: the physical button adapter that turns debounced P04 events into `local_mute` calls (it
//! waits on a workspace-edge decision), or any transport.

use super::*;
use crate::protection::{Admission, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for};
use crate::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_board_profile::synthetic_test_fixture_catalog;

const EPOCH: u64 = 7;

fn stamp(epoch: u64, revision: u64) -> Stamp {
    Stamp { epoch, revision }
}

fn close(a: f32, b: f32) -> bool {
    (a - b).abs() < 1e-6
}

fn render_silence(dsp: &mut ProtectedBoardDsp, frames: usize) {
    let mut out = ProtectedOutput::new();
    let mut left = frames;
    while left > 0 {
        let now = left.min(FRAMES_PER_BLOCK);
        let mut block = StereoAudioBlock::silence(0);
        block.frames = now;
        dsp.render_into(&block, &mut out);
        left -= now;
    }
}

fn board() -> ProtectedBoardDsp {
    let profile = synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == "S5")
        .expect("fixture board S5");
    let calibration = synthetic_calibration_for(&profile);
    ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
}

#[test]
fn a_member_with_no_authority_can_still_be_muted_locally_and_the_remote_path_is_shown_dead() {
    // Never joined: no network, no controller, no epoch.
    let mut m = MemberVolume::new(1.0);
    assert_eq!(m.epoch(), None);

    // The remote path is dead: no command of any kind is accepted.
    for command in [
        VolumeCommand::SetVolume(50),
        VolumeCommand::AdjustVolume(5),
        VolumeCommand::SetTrim(900),
        VolumeCommand::ResetTrim,
        VolumeCommand::SetGroupMute(false),
    ] {
        assert_eq!(
            m.apply(stamp(EPOCH, 1), command),
            Err(VolumeError::NoAuthority),
            "{command:?}"
        );
    }

    // The room's own button still works, and it is what the room reports: a local mute outranks the join mute.
    assert_eq!(m.effective_mute(), Some(MuteReason::Join));
    m.local_mute(true);
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    assert!(close(m.output_gain(), 0.0));
    assert!(m.persisted().local_mute);

    // The same button clears it, leaving only the join reason (a member that has not joined is still silent).
    m.local_mute(false);
    assert_eq!(m.effective_mute(), Some(MuteReason::Join));
    assert!(!m.persisted().local_mute);

    // The local volume buttons work too, and neither unmutes nor makes a sound.
    m.local_mute(true);
    assert_eq!(m.local_trim_step(-200), Ok(800));
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    assert!(close(m.output_gain(), 0.0));

    // A restart with no network: the persisted local mute comes back with no authority, and still holds.
    let restored = MemberVolume::restore(m.persisted(), 1.0);
    assert_eq!(restored.epoch(), None);
    assert_eq!(restored.effective_mute(), Some(MuteReason::Local));
    assert_eq!(restored.trim_permille(), 800);
    assert!(close(restored.output_gain(), 0.0));
}

#[test]
fn a_member_cut_off_from_its_controller_stops_its_own_sound_and_a_heal_does_not_undo_it() {
    let mut m = MemberVolume::new(1.0);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    let mut dsp = board();
    m.sync(&mut dsp).expect("hand the state to the board");
    m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    assert!(close(dsp.applied_gain(), 0.5));

    // The controller's authority has moved on (epoch 8) and this member was cut off before it could follow. Its
    // remote path is dead, and the sound goes on: nothing remote can stop it.
    assert_eq!(
        m.apply(stamp(EPOCH + 1, 1), VolumeCommand::SetGroupMute(true)),
        Err(VolumeError::UndeclaredEpoch {
            command: EPOCH + 1,
            current: EPOCH
        })
    );
    render_silence(&mut dsp, 100);
    assert!(close(dsp.applied_gain(), 0.5), "still playing");

    // The room's own button stops it, with no controller and no network.
    m.local_mute(true);
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(dsp.applied_gain(), 0.0);
    assert!(dsp.is_muted());
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));

    // The partition heals: the member rejoins from the new epoch's snapshot at a LOUDER group volume. The room's own
    // mute survives, and it stays silent through the whole join.
    m.reconnect(GroupSnapshot {
        epoch: EPOCH + 1,
        revision: 3,
        master_volume: 90,
        group_mute: false,
    })
    .expect("reconnect");
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(dsp.applied_gain(), 0.0, "silent while joining");
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    m.complete_join();
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(
        dsp.applied_gain(),
        0.0,
        "the join finished, and the room's own mute still holds"
    );
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));

    // Only the room's own button lifts it, and then it plays the GROUP's current volume (0.9): not the stale 0.5
    // it had, and not louder than the group.
    m.local_mute(false);
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert!(close(dsp.applied_gain(), 0.9), "{}", dsp.applied_gain());
    assert_eq!(m.effective_mute(), None);
}
