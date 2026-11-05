//! Tests for accepted versus completed (`G02` / `ffw-ld0`, section 2: "The adapter must not report completed
//! playback merely because it queued a command"). They drive the REAL D02 board and read its applied gain.
//!
//! What they show: a command that is only queued is `Accepted`, never `Completed`, however settled the board looks;
//! it completes on the exact sample D02's ramp lands; a newer command, a local change, a fault or a pending profile
//! switch stops it completing; a caller that bypasses the member cannot make a stale completion appear; and, over
//! random operations, `Completed` means the board is truly at rest (rendering more frames moves nothing) while an
//! accepted-and-handed-over command always completes and a never-handed-over one never does.
//!
//! What they do not show: any transport (G03, X01 own those), group-wide completion (each member is asked with its
//! own board), or limiter and thermal scaling, which act after the gain and are in D02's block report.

use super::*;
use crate::protection::{
    Admission, BoardStatus, ProtectedBoardDsp, ProtectedOutput, synthetic_calibration_for,
};
use crate::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_board_profile::{BoardProfile, synthetic_test_fixture_catalog};

const EPOCH: u64 = 7;

/// D02 moves its applied gain by at most this much per sample (`ramp_ms` = 10 at 48 kHz).
const STEP: f32 = 1.0 / 480.0;

/// Seeded and fixed, so a failure replays: SplitMix64.
struct SplitMix(u64);

impl SplitMix {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn stamp(revision: u64) -> Stamp {
    Stamp {
        epoch: EPOCH,
        revision,
    }
}

fn member() -> MemberVolume {
    let mut m = MemberVolume::new(1.0);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    m
}

fn fixture(model: &str) -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .expect("fixture board")
}

fn board(model: &str) -> ProtectedBoardDsp {
    let profile = fixture(model);
    let calibration = synthetic_calibration_for(&profile);
    ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation)
}

/// A member whose initial state (volume 0, unmuted) has been handed to an admitted S5 board.
fn live() -> (MemberVolume, ProtectedBoardDsp) {
    let mut m = member();
    let mut dsp = board("S5");
    m.sync(&mut dsp)
        .expect("hand the initial state to the board");
    (m, dsp)
}

/// Render `frames` frames of digital silence; the gain ramp advances one step per rendered sample.
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

fn nyquist_left(amplitude: f32) -> StereoAudioBlock {
    let mut block = StereoAudioBlock::silence(0);
    for (i, sample) in block.left.iter_mut().enumerate() {
        *sample = if i.is_multiple_of(2) {
            amplitude
        } else {
            -amplitude
        };
    }
    block
}

fn progress(m: &MemberVolume, dsp: &ProtectedBoardDsp, revision: u64) -> CommandProgress {
    m.progress(stamp(revision), dsp).expect("same epoch")
}

fn close(a: f32, b: f32) -> bool {
    (a - b).abs() < 1e-6
}

// ---- queued is not completed ---------------------------------------------------------------------------------

#[test]
fn a_queued_command_is_accepted_not_completed_and_completes_on_the_sample_the_ramp_lands() {
    let (mut m, mut dsp) = live();
    let receipt = m
        .apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    assert!(close(receipt.target_gain, 0.5), "{receipt:?}");

    // 1. Accepted and only QUEUED: the board has not been told, so nothing has started. Not completed.
    assert_eq!(
        m.progress(stamp(1), &dsp),
        Ok(CommandProgress::Accepted {
            handed_to_board: false,
            applied_gain: 0.0,
            target_gain: receipt.target_gain
        })
    );

    // 2. Handed to the board, no sample rendered yet: still not completed.
    m.apply_to(&mut dsp).expect("hand over");
    assert_eq!(
        m.progress(stamp(1), &dsp),
        Ok(CommandProgress::Accepted {
            handed_to_board: true,
            applied_gain: 0.0,
            target_gain: receipt.target_gain
        })
    );

    // 3. Frame by frame: completed exactly when D02's own applied gain equals the target, never before.
    let target = receipt.target_gain;
    let mut landed_at = None;
    for frame in 1..=260usize {
        render_silence(&mut dsp, 1);
        let landed = dsp.applied_gain() == target;
        let answer = progress(&m, &dsp, 1);
        match answer {
            CommandProgress::Completed { .. } => {
                assert!(landed, "frame {frame}: completed early: {answer:?}")
            }
            CommandProgress::Accepted {
                handed_to_board,
                applied_gain,
                target_gain,
            } => {
                assert!(
                    !landed,
                    "frame {frame}: landed but not reported: {answer:?}"
                );
                assert!(handed_to_board);
                assert!(
                    applied_gain > 0.0 && applied_gain < target,
                    "frame {frame}: {answer:?}"
                );
                assert!(close(target_gain, target));
            }
            other => panic!("frame {frame}: {other:?}"),
        }
        if landed && landed_at.is_none() {
            landed_at = Some(frame);
        }
    }
    // 0 -> 0.5 at 1/480 per sample is 240 steps; f32 accumulation may need one more.
    let landed_at = landed_at.expect("the ramp must land");
    assert!(
        (240..=241).contains(&landed_at),
        "landed at frame {landed_at}"
    );
    assert_eq!(
        m.progress(stamp(1), &dsp),
        Ok(CommandProgress::Completed {
            target_gain: target,
            effective_mute: None
        })
    );
}

#[test]
fn a_caller_that_bypasses_the_member_cannot_make_a_stale_completion_appear() {
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));

    // Someone mutes the board directly. The applied gain has not moved yet, so applied == target still holds,
    // and a check that looked only at that would call this completed while D02 is about to ramp to silence.
    dsp.set_muted(true).expect("an active board can be muted");
    assert!(close(dsp.applied_gain(), 0.5));
    assert!(
        matches!(
            progress(&m, &dsp, 1),
            CommandProgress::Accepted {
                handed_to_board: false,
                ..
            }
        ),
        "{:?}",
        progress(&m, &dsp, 1)
    );
    // The same for a direct gain change.
    dsp.set_muted(false).expect("unmute");
    dsp.set_user_gain(0.9);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Accepted {
            handed_to_board: false,
            ..
        }
    ));

    // Paired positive: handing the member's state back to the board is what makes it completed again.
    m.apply_to(&mut dsp).expect("hand over");
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));
}

#[test]
fn a_board_holding_a_different_gain_has_not_been_told_even_when_both_are_silent() {
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply(stamp(2), VolumeCommand::SetGroupMute(true))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 700);
    assert_eq!(
        progress(&m, &dsp, 2),
        CommandProgress::Completed {
            target_gain: 0.0,
            effective_mute: Some(MuteReason::Group)
        }
    );

    // A caller gives the board a different gain behind the member's back. The board is still muted and silent and
    // the applied gain is 0, which is exactly where the mute asked, so nothing audible differs. But the board no
    // longer holds the member's gain: it has not been told, and that is what the answer says.
    dsp.set_user_gain(0.9);
    assert_eq!(dsp.applied_gain(), 0.0);
    assert!(
        matches!(progress(&m, &dsp, 2), CommandProgress::Accepted { handed_to_board: false, applied_gain, .. } if applied_gain == 0.0),
        "{:?}",
        progress(&m, &dsp, 2)
    );
    // Paired positive: telling the board completes it again.
    m.apply_to(&mut dsp).expect("hand over");
    assert!(matches!(
        progress(&m, &dsp, 2),
        CommandProgress::Completed { .. }
    ));
}

#[test]
fn an_older_command_with_the_same_target_is_still_superseded_so_the_newest_is_the_one_to_ask_about()
{
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    let second = m
        .apply(stamp(2), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    // Both asked for 0.5 and the output is at 0.5, but only the command that holds the current target completes.
    assert_eq!(
        progress(&m, &dsp, 2),
        CommandProgress::Completed {
            target_gain: second.target_gain,
            effective_mute: None
        }
    );
    assert_eq!(progress(&m, &dsp, 1), CommandProgress::Superseded);
}

// ---- something else took over the target -------------------------------------------------------------------------

#[test]
fn a_newer_command_supersedes_an_unfinished_one_and_a_completed_newer_one_does_not_revive_it() {
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 100);
    // Mid-ramp: heading for 0.5, now at 100 steps of 1/480.
    match progress(&m, &dsp, 1) {
        CommandProgress::Accepted {
            handed_to_board: true,
            applied_gain,
            ..
        } => {
            assert!((applied_gain - 100.0 * STEP).abs() < 1e-4, "{applied_gain}");
        }
        other => panic!("{other:?}"),
    }

    let second = m
        .apply(stamp(2), VolumeCommand::SetVolume(80))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    assert_eq!(progress(&m, &dsp, 1), CommandProgress::Superseded);
    assert!(matches!(
        progress(&m, &dsp, 2),
        CommandProgress::Accepted {
            handed_to_board: true,
            ..
        }
    ));

    render_silence(&mut dsp, 700);
    assert_eq!(
        progress(&m, &dsp, 2),
        CommandProgress::Completed {
            target_gain: second.target_gain,
            effective_mute: None
        }
    );
    assert_eq!(
        progress(&m, &dsp, 1),
        CommandProgress::Superseded,
        "the older command stays superseded"
    );
}

#[test]
fn a_local_change_after_acceptance_overtakes_the_command_but_its_own_target_returning_completes_it()
{
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));

    // The room's own mute button: the target is now silence, so the command's 0.5 is no longer being pursued.
    m.local_mute(true);
    assert_eq!(progress(&m, &dsp, 1), CommandProgress::Superseded);
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert_eq!(
        progress(&m, &dsp, 1),
        CommandProgress::Superseded,
        "silent, but not what the command asked for"
    );

    // The answer describes the state NOW: unmuting restores the command's own target, and it completes again.
    m.local_mute(false);
    m.sync(&mut dsp).expect("sync");
    render_silence(&mut dsp, 600);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));
}

#[test]
fn a_group_mute_completes_when_the_output_is_silent_and_says_why() {
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);

    let mute = m
        .apply(stamp(2), VolumeCommand::SetGroupMute(true))
        .expect("accepted");
    assert_eq!(mute.effective_mute, Some(MuteReason::Group));
    assert!(close(mute.target_gain, 0.0));
    // Queued: the board still plays at 0.5.
    assert!(matches!(
        progress(&m, &dsp, 2),
        CommandProgress::Accepted { handed_to_board: false, applied_gain, .. } if close(applied_gain, 0.5)
    ));
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 10);
    assert!(matches!(
        progress(&m, &dsp, 2),
        CommandProgress::Accepted {
            handed_to_board: true,
            ..
        }
    ));
    render_silence(&mut dsp, 600);
    assert_eq!(
        progress(&m, &dsp, 2),
        CommandProgress::Completed {
            target_gain: 0.0,
            effective_mute: Some(MuteReason::Group)
        }
    );
    assert_eq!(progress(&m, &dsp, 1), CommandProgress::Superseded);
}

// ---- the board decides --------------------------------------------------------------------------------------------

#[test]
fn a_board_that_cannot_unmute_completes_silent_and_the_command_says_why() {
    // Not admitted (no calibration): fail-muted. A requested volume cannot be audible.
    let profile = fixture("S5");
    let mut dsp = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation);
    assert!(matches!(dsp.status(), BoardStatus::FailMuted(_)));
    let mut m = member();
    m.sync(&mut dsp)
        .expect("the member follows the board into a fault mute");
    let receipt = m
        .apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    assert_eq!(receipt.effective_mute, Some(MuteReason::Fault));
    assert!(close(receipt.target_gain, 0.0));
    m.apply_to(&mut dsp).expect("hand over");
    assert_eq!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed {
            target_gain: 0.0,
            effective_mute: Some(MuteReason::Fault)
        },
        "completed means the output is where it was told to be, and it is silent because of the fault"
    );

    // Paired positive: the same command on an admitted board completes AUDIBLE.
    let (mut ok_member, mut ok_board) = live();
    ok_member
        .apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    ok_member.apply_to(&mut ok_board).expect("hand over");
    render_silence(&mut ok_board, 300);
    assert_eq!(
        progress(&ok_member, &ok_board, 1),
        CommandProgress::Completed {
            target_gain: ok_member.output_gain(),
            effective_mute: None
        }
    );
    assert!(close(ok_member.output_gain(), 0.5));
}

#[test]
fn a_fault_the_member_has_not_seen_is_not_completion_and_once_seen_it_supersedes_the_command() {
    // A fast thermal calibration on S3, as the D02 thermal test uses, so sustained overdrive latches a fault.
    let profile = fixture("S3");
    let mut calibration = synthetic_calibration_for(&profile);
    {
        let thermal = &mut calibration.channels[0].thermal;
        thermal.tau_s = 0.05;
        thermal.soft_ms = 0.05;
        thermal.hard_ms = 0.2;
    }
    let mut dsp = ProtectedBoardDsp::admit(&profile, Some(&calibration), Admission::HostSimulation);
    let mut m = member();
    m.sync(&mut dsp).expect("sync");
    m.apply(stamp(1), VolumeCommand::SetVolume(100))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 600);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));

    // Overdrive until the board latches a thermal fault. The member is not told.
    let drive = nyquist_left(0.6);
    let mut out = ProtectedOutput::new();
    for _ in 0..16 {
        dsp.render_into(&drive, &mut out);
        if matches!(dsp.status(), BoardStatus::Faulted(_)) {
            break;
        }
    }
    assert!(
        matches!(dsp.status(), BoardStatus::Faulted(_)),
        "the overdrive must latch a fault"
    );
    dsp.render_into(&drive, &mut out);
    dsp.render_into(&drive, &mut out);
    // The board is heading for silence; the member still intends sound. The gains match, so only the board's own
    // state says it is not at the target: this must not be called completed.
    assert!(
        matches!(
            progress(&m, &dsp, 1),
            CommandProgress::Accepted {
                handed_to_board: true,
                ..
            }
        ),
        "{:?}",
        progress(&m, &dsp, 1)
    );
    // Once the member observes the fault it mutes itself, which moves the target away from the command's.
    m.sync(&mut dsp).expect("sync");
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));
    assert_eq!(progress(&m, &dsp, 1), CommandProgress::Superseded);
}

#[test]
fn a_pending_profile_switch_is_not_completion_while_the_board_drains_to_silence() {
    let profile = fixture("S5");
    let calibration = synthetic_calibration_for(&profile);
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 300);
    assert!(matches!(
        progress(&m, &dsp, 1),
        CommandProgress::Completed { .. }
    ));

    dsp.request_profile_switch(&profile, &calibration, Admission::HostSimulation)
        .expect("a valid switch is accepted");
    assert!(dsp.has_pending_switch());
    // The gains still match and the applied gain is still 0.5, but the board now heads for silence to swap.
    assert!(close(dsp.applied_gain(), 0.5));
    assert!(
        matches!(
            progress(&m, &dsp, 1),
            CommandProgress::Accepted {
                handed_to_board: true,
                ..
            }
        ),
        "{:?}",
        progress(&m, &dsp, 1)
    );
    // Whatever it says while the switch drains, it never says Completed while the switch is pending.
    for _ in 0..40 {
        render_silence(&mut dsp, 20);
        if dsp.has_pending_switch() {
            assert!(!matches!(
                progress(&m, &dsp, 1),
                CommandProgress::Completed { .. }
            ));
        }
    }
    assert!(
        !dsp.has_pending_switch(),
        "the switch has drained and installed"
    );
}

// ---- ids that were never accepted ---------------------------------------------------------------------------------

#[test]
fn ids_that_were_never_accepted_report_the_outcome_and_the_epoch_rules_apply() {
    let (mut m, dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(10))
        .expect("accepted");
    m.apply(stamp(4), VolumeCommand::SetVolume(40))
        .expect("accepted"); // 2 and 3 never arrived
    assert_eq!(
        progress(&m, &dsp, 2),
        CommandProgress::NotAccepted(CommandOutcome::Skipped)
    );
    assert_eq!(
        progress(&m, &dsp, 5),
        CommandProgress::NotAccepted(CommandOutcome::NotApplied)
    );
    m.reconnect(GroupSnapshot {
        epoch: EPOCH,
        revision: 10,
        master_volume: 30,
        group_mute: false,
    })
    .expect("reconnect");
    assert_eq!(
        progress(&m, &dsp, 4),
        CommandProgress::NotAccepted(CommandOutcome::Forgotten {
            remembered_from: 11
        })
    );

    assert_eq!(
        m.progress(
            Stamp {
                epoch: EPOCH - 1,
                revision: 1
            },
            &dsp
        ),
        Err(VolumeError::StaleEpoch {
            command: EPOCH - 1,
            current: EPOCH
        })
    );
    assert_eq!(
        MemberVolume::new(1.0).progress(stamp(1), &dsp),
        Err(VolumeError::NoAuthority)
    );
}

#[test]
fn asking_for_progress_changes_neither_the_member_nor_the_board() {
    let (mut m, mut dsp) = live();
    m.apply(stamp(1), VolumeCommand::SetVolume(50))
        .expect("accepted");
    m.apply_to(&mut dsp).expect("hand over");
    render_silence(&mut dsp, 100);
    let (member_before, board_before) = (format!("{m:?}"), format!("{dsp:?}"));
    for revision in [0, 1, 2, 99] {
        let _ = m.progress(stamp(revision), &dsp);
    }
    assert_eq!(format!("{m:?}"), member_before);
    assert_eq!(format!("{dsp:?}"), board_before);
}

// ---- against the real board, with independent oracles ---------------------------------------------------------------

#[test]
fn over_random_operations_completed_means_the_board_is_at_rest_and_a_queued_command_never_completes()
 {
    let mut rng = SplitMix(0x00_6704_C0A1);
    // completed, accepted and handed over, accepted and queued, superseded: how often each was probed.
    let mut tally = [0u32; 4];
    for seed in 0..3u64 {
        let (mut m, mut dsp) = live();
        let mut revision = 0u64;
        for step in 0..1500u32 {
            let context = format!("seed {seed} step {step}");
            match rng.draw() % 8 {
                0 | 1 => {
                    revision += 1;
                    let command = match rng.draw() % 3 {
                        0 => VolumeCommand::SetVolume((rng.draw() % 101) as u8),
                        1 => VolumeCommand::AdjustVolume((rng.draw() % 61) as i16 - 30),
                        _ => VolumeCommand::SetGroupMute(rng.draw().is_multiple_of(3)),
                    };
                    m.apply(stamp(revision), command)
                        .unwrap_or_else(|e| panic!("{context}: {e:?}"));
                }
                2 => m.local_mute(rng.draw().is_multiple_of(2)),
                3 => m.sync(&mut dsp).expect("an active board can be synced"),
                4 => render_silence(&mut dsp, 1 + (rng.draw() % 300) as usize),
                5 => {
                    // a caller going around the member
                    if rng.draw().is_multiple_of(2) {
                        dsp.set_muted(rng.draw().is_multiple_of(2))
                            .expect("an active board");
                    } else {
                        dsp.set_user_gain((rng.draw() % 101) as f32 / 100.0);
                    }
                }
                6 => {
                    let _ = m.local_trim_step((rng.draw() % 601) as i16 - 300);
                }
                _ => {
                    if revision == 0 {
                        continue;
                    }
                    // Every older accepted command still remembered (the last 30 here, inside the retained 32) is
                    // superseded, whatever the board is doing.
                    if revision > 1 {
                        let span = (revision - 1).min(30);
                        let older = revision - 1 - rng.draw() % span;
                        assert_eq!(
                            progress(&m, &dsp, older),
                            CommandProgress::Superseded,
                            "{context}: revision {older}"
                        );
                    }
                    match progress(&m, &dsp, revision) {
                        CommandProgress::Completed { .. } => {
                            tally[0] += 1;
                            // Independent oracle: completed means the board is at rest. More frames move nothing.
                            let before = dsp.applied_gain();
                            render_silence(&mut dsp, 300);
                            assert_eq!(
                                dsp.applied_gain(),
                                before,
                                "{context}: reported completed, but the board was still moving"
                            );
                            assert!(
                                matches!(
                                    progress(&m, &dsp, revision),
                                    CommandProgress::Completed { .. }
                                ),
                                "{context}"
                            );
                        }
                        CommandProgress::Accepted {
                            handed_to_board: true,
                            ..
                        } => {
                            tally[1] += 1;
                            // Liveness: handed over and nothing else changing, it must complete (a full-scale ramp is 480 samples).
                            render_silence(&mut dsp, 700);
                            assert!(
                                matches!(
                                    progress(&m, &dsp, revision),
                                    CommandProgress::Completed { .. }
                                ),
                                "{context}: handed over and left alone, it never completed: {:?}",
                                progress(&m, &dsp, revision)
                            );
                        }
                        CommandProgress::Accepted {
                            handed_to_board: false,
                            ..
                        } => {
                            tally[2] += 1;
                            // The queued case: however many frames render, it is not completed until the board is told.
                            render_silence(&mut dsp, 700);
                            assert!(
                                matches!(
                                    progress(&m, &dsp, revision),
                                    CommandProgress::Accepted {
                                        handed_to_board: false,
                                        ..
                                    }
                                ),
                                "{context}: queued but never handed over, yet it changed: {:?}",
                                progress(&m, &dsp, revision)
                            );
                        }
                        CommandProgress::Superseded => {
                            tally[3] += 1;
                            render_silence(&mut dsp, 700);
                            assert_eq!(
                                progress(&m, &dsp, revision),
                                CommandProgress::Superseded,
                                "{context}"
                            );
                        }
                        CommandProgress::NotAccepted(outcome) => {
                            panic!("{context}: the last revision was accepted, yet {outcome:?}")
                        }
                    }
                }
            }
        }
    }
    // Floors at about a third of what the schedule produces in the Python mirror (completed 98, handed over 40,
    // queued 349, superseded 91), so every branch is reached.
    assert!(
        tally[0] >= 30 && tally[1] >= 12 && tally[2] >= 100 && tally[3] >= 30,
        "the schedule stopped reaching every branch: completed {} / handed over {} / queued {} / superseded {}",
        tally[0],
        tally[1],
        tally[2],
        tally[3]
    );
}
