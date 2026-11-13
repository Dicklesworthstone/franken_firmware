//! Unit tests for `G02`. The pure-control tests use closed forms; the integration tests drive the
//! real D02 renderer and look at its applied-gain trajectory, because "no spike" is only meaningful
//! there. Independent expected outcomes for scripted sequences come from `tests/g02/` (Python).

use super::*;
// Explicit, so these tests do not depend on `use super::*` re-exporting the parent's private imports.
use crate::protection::{
    Admission, BoardStatus, FaultCode, ProtectedBoardDsp, ProtectedOutput, ProtectionError,
    synthetic_calibration_for,
};
use crate::{FRAMES_PER_BLOCK, StereoAudioBlock};
use franken_board_profile::{BoardProfile, TransducerRole, synthetic_test_fixture_catalog};

const EPOCH: u64 = 7;

fn stamp(epoch: u64, revision: u64) -> Stamp {
    Stamp { epoch, revision }
}

/// A member at epoch 7 with its join already complete.
fn member(ceiling: f32) -> MemberVolume {
    let mut m = MemberVolume::new(ceiling);
    m.declare_epoch(EPOCH).expect("declare");
    m.complete_join();
    m
}

fn set(m: &mut MemberVolume, revision: u64, command: VolumeCommand) -> CommandReceipt {
    m.apply(stamp(EPOCH, revision), command).expect("accepted")
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

/// D02 moves its applied gain by at most this much per sample (ramp_ms = 10 at 48 kHz).
const STEP: f32 = 1.0 / 480.0;

// ---- gain composition ---------------------------------------------------------------------------

#[test]
fn gain_is_volume_times_trim_clamped_to_the_ceilings_before_any_ramp() {
    let mut m = member(1.0);
    assert_eq!(
        set(&mut m, 1, VolumeCommand::SetVolume(80)).target_gain,
        0.8
    );
    assert_eq!(
        set(&mut m, 2, VolumeCommand::SetTrim(500)).target_gain,
        0.8 * 0.5
    );
    assert_eq!(
        set(&mut m, 3, VolumeCommand::SetVolume(100)).target_gain,
        0.5
    );
    // Boost beyond the ceiling is clamped, not passed on: 1.0 * 2.0 = 2.0 -> 1.0.
    assert_eq!(
        set(&mut m, 4, VolumeCommand::SetTrim(2000)).target_gain,
        1.0
    );

    // A lower protection ceiling clamps the same product.
    m.set_protection_ceiling(0.5);
    assert_eq!(m.output_gain(), 0.5);
    // A fault ceiling lowers it further; removing it restores the protection ceiling.
    m.set_fault_ceiling(Some(0.3));
    assert_eq!(m.output_gain(), 0.3);
    m.set_fault_ceiling(None);
    assert_eq!(m.output_gain(), 0.5);
    // A fault ceiling never raises the bound above the protection ceiling.
    m.set_fault_ceiling(Some(0.9));
    assert_eq!(m.output_gain(), 0.5);
    // Non-finite ceilings fail closed.
    m.set_protection_ceiling(f32::NAN);
    assert_eq!(m.output_gain(), 0.0);
    m.set_protection_ceiling(f32::INFINITY);
    assert_eq!(m.output_gain(), 0.0);
}

#[test]
fn endpoints_saturate_and_overflowing_steps_are_refused_with_nothing_changed() {
    let mut m = member(1.0);
    assert_eq!(set(&mut m, 1, VolumeCommand::SetVolume(0)).target_gain, 0.0);
    assert_eq!(
        set(&mut m, 2, VolumeCommand::SetVolume(100)).target_gain,
        1.0
    );
    set(&mut m, 3, VolumeCommand::SetVolume(95));
    set(&mut m, 4, VolumeCommand::AdjustVolume(20));
    assert_eq!(m.desired_volume(), 100, "saturates at the top");
    set(&mut m, 5, VolumeCommand::SetVolume(10));
    set(&mut m, 6, VolumeCommand::AdjustVolume(-20));
    assert_eq!(m.desired_volume(), 0, "saturates at the bottom");
    set(&mut m, 7, VolumeCommand::AdjustVolume(100));
    set(&mut m, 8, VolumeCommand::AdjustVolume(-100));
    assert_eq!(m.desired_volume(), 0);

    set(&mut m, 9, VolumeCommand::SetVolume(40));
    let before = (m.desired_volume(), m.last_revision());
    for delta in [101, -101, i16::MAX, i16::MIN] {
        assert_eq!(
            m.apply(stamp(EPOCH, 10), VolumeCommand::AdjustVolume(delta)),
            Err(VolumeError::StepOutOfRange { delta }),
            "{delta}"
        );
    }
    assert_eq!(
        m.apply(stamp(EPOCH, 10), VolumeCommand::SetVolume(101)),
        Err(VolumeError::VolumeOutOfRange { value: 101 })
    );
    assert_eq!(
        m.apply(stamp(EPOCH, 10), VolumeCommand::SetTrim(2001)),
        Err(VolumeError::TrimOutOfRange { permille: 2001 })
    );
    assert_eq!(
        (m.desired_volume(), m.last_revision()),
        before,
        "nothing changed"
    );
    // An invalid payload does not consume its revision: the same revision is still usable.
    assert_eq!(
        set(&mut m, 10, VolumeCommand::SetVolume(41)).target_gain,
        0.41
    );
}

#[test]
fn a_group_volume_change_preserves_the_room_trim_until_it_is_explicitly_reset() {
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetTrim(600));
    set(&mut m, 2, VolumeCommand::SetVolume(50));
    set(&mut m, 3, VolumeCommand::AdjustVolume(10));
    assert_eq!(
        m.trim_permille(),
        600,
        "group volume changes leave the trim alone"
    );
    assert_eq!(m.unmuted_gain(), 0.6 * 0.6);
    set(&mut m, 4, VolumeCommand::ResetTrim);
    assert_eq!(m.trim_permille(), TRIM_UNITY_PERMILLE);
    assert_eq!(m.unmuted_gain(), 0.6);
}

// ---- mute priority --------------------------------------------------------------------------------------

#[test]
fn mute_wins_over_volume_and_each_reason_has_exactly_one_owner() {
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(60));
    assert_eq!(m.effective_mute(), None);

    let receipt = set(&mut m, 2, VolumeCommand::SetGroupMute(true));
    assert_eq!(
        (receipt.effective_mute, receipt.target_gain),
        (Some(MuteReason::Group), 0.0)
    );
    // A volume command while muted is stored but never unmutes.
    let receipt = set(&mut m, 3, VolumeCommand::SetVolume(90));
    assert_eq!(
        (receipt.effective_mute, receipt.target_gain),
        (Some(MuteReason::Group), 0.0)
    );
    assert_eq!(m.desired_volume(), 90);

    // The local reason outranks the group one, and a group unmute cannot clear it.
    m.local_mute(true);
    assert_eq!(m.effective_mute(), Some(MuteReason::Local));
    let receipt = set(&mut m, 4, VolumeCommand::SetGroupMute(false));
    assert_eq!(
        receipt.effective_mute,
        Some(MuteReason::Local),
        "the UI can say why"
    );
    assert_eq!(receipt.target_gain, 0.0);

    // A fault outranks everything, and only the board returning to Active clears it.
    m.observe_board(BoardStatus::Faulted(FaultCode::ThermalHard { channel: 0 }));
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));
    m.local_mute(false);
    set(&mut m, 5, VolumeCommand::SetGroupMute(false));
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Fault),
        "unmute requests cannot override a fault"
    );
    assert_eq!(m.output_gain(), 0.0);
    m.observe_board(BoardStatus::Active);
    assert_eq!(m.effective_mute(), None);
    assert_eq!(
        m.output_gain(),
        0.9,
        "back to the stored target, which D02 then ramps to"
    );
}

#[test]
fn the_reported_mute_reason_follows_the_declared_priority() {
    let mut m = MemberVolume::new(1.0); // starts join-muted
    m.declare_epoch(EPOCH).unwrap();
    set(&mut m, 1, VolumeCommand::SetGroupMute(true));
    m.local_mute(true);
    m.observe_board(BoardStatus::FailMuted(ProtectionError::NoCalibration));
    let mut order = Vec::new();
    while let Some(reason) = m.effective_mute() {
        order.push(reason);
        match reason {
            MuteReason::Fault => m.observe_board(BoardStatus::Active),
            MuteReason::Local => m.local_mute(false),
            MuteReason::Join => m.complete_join(),
            MuteReason::Group => {
                set(&mut m, 2, VolumeCommand::SetGroupMute(false));
            }
        }
    }
    assert_eq!(
        order,
        [
            MuteReason::Fault,
            MuteReason::Local,
            MuteReason::Join,
            MuteReason::Group
        ]
    );
    assert!(MuteReason::Fault < MuteReason::Local && MuteReason::Join < MuteReason::Group);
}

#[test]
fn local_buttons_adjust_the_trim_within_bounds_and_never_unmute() {
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(50));
    m.local_mute(true);
    assert_eq!(m.local_trim_step(100), Ok(1100));
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Local),
        "a volume button does not unmute"
    );
    assert_eq!(m.local_trim_step(500), Ok(1600));
    assert_eq!(
        m.local_trim_step(500),
        Ok(2000),
        "clamped at the maximum trim"
    );
    assert_eq!(m.local_trim_step(-500), Ok(1500));
    for _ in 0..4 {
        m.local_trim_step(-500).unwrap();
    }
    assert_eq!(m.trim_permille(), 0, "clamped at zero");
    for delta in [501, -501, i16::MAX, i16::MIN] {
        assert_eq!(
            m.local_trim_step(delta),
            Err(VolumeError::StepOutOfRange { delta })
        );
    }
    assert_eq!(m.trim_permille(), 0);
}

// ---- authority: stale, duplicate, undeclared --------------------------------------------------------------------

#[test]
fn stale_and_unauthorized_commands_are_refused_with_nothing_changed() {
    let mut m = MemberVolume::new(1.0);
    m.complete_join();
    assert_eq!(
        m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(50)),
        Err(VolumeError::NoAuthority),
        "no epoch has been declared"
    );
    m.declare_epoch(EPOCH).unwrap();
    set(&mut m, 1, VolumeCommand::SetVolume(50));
    set(&mut m, 2, VolumeCommand::SetVolume(60));

    let before = (m.desired_volume(), m.last_revision(), m.epoch());
    let refusals = [
        (
            stamp(EPOCH, 1),
            VolumeError::StaleRevision {
                revision: 1,
                last: 2,
            },
        ),
        (
            stamp(EPOCH, 0),
            VolumeError::StaleRevision {
                revision: 0,
                last: 2,
            },
        ),
        (
            stamp(EPOCH - 1, 9),
            VolumeError::StaleEpoch {
                command: EPOCH - 1,
                current: EPOCH,
            },
        ),
        (
            stamp(EPOCH + 2, 9),
            VolumeError::UndeclaredEpoch {
                command: EPOCH + 2,
                current: EPOCH,
            },
        ),
    ];
    for (s, error) in refusals {
        assert_eq!(
            m.apply(s, VolumeCommand::SetVolume(99)),
            Err(error),
            "{s:?}"
        );
    }
    assert_eq!((m.desired_volume(), m.last_revision(), m.epoch()), before);
    // The permitted positive: the next legitimate revision is still accepted.
    assert_eq!(
        set(&mut m, 3, VolumeCommand::SetVolume(70)).target_gain,
        0.7
    );
}

#[test]
fn a_command_can_never_mint_an_epoch_and_declared_epochs_only_move_forward() {
    let mut m = member(1.0);
    assert!(m.apply(stamp(99, 1), VolumeCommand::SetVolume(5)).is_err());
    assert_eq!(
        m.epoch(),
        Some(EPOCH),
        "an undeclared epoch is not adopted from a command"
    );
    assert_eq!(
        m.declare_epoch(EPOCH - 1),
        Err(VolumeError::StaleEpoch {
            command: EPOCH - 1,
            current: EPOCH
        })
    );
    set(&mut m, 1, VolumeCommand::SetVolume(40));
    assert_eq!(m.declare_epoch(EPOCH), Ok(()));
    assert_eq!(
        m.last_revision(),
        1,
        "re-declaring the same epoch keeps revision tracking"
    );
    assert_eq!(m.declare_epoch(EPOCH + 1), Ok(()));
    assert_eq!(
        m.last_revision(),
        0,
        "a newer epoch starts its revisions again"
    );
    assert_eq!(
        m.apply(stamp(EPOCH, 5), VolumeCommand::SetVolume(5)),
        Err(VolumeError::StaleEpoch {
            command: EPOCH,
            current: EPOCH + 1
        })
    );
    assert!(
        m.apply(stamp(EPOCH + 1, 1), VolumeCommand::SetVolume(5))
            .is_ok()
    );
}

#[test]
fn retries_are_idempotent_and_a_relative_command_applies_exactly_once() {
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(50));
    let first = set(&mut m, 2, VolumeCommand::AdjustVolume(10));
    assert!(!first.duplicate);
    assert_eq!(m.desired_volume(), 60);
    for _ in 0..3 {
        let replay = set(&mut m, 2, VolumeCommand::AdjustVolume(10));
        assert!(replay.duplicate, "an identical replay is recognized");
        assert_eq!(replay.target_gain, first.target_gain);
    }
    assert_eq!(m.desired_volume(), 60, "three retries did not add 30");
    // The same revision with a different payload is a conflict, not a replay.
    assert_eq!(
        m.apply(stamp(EPOCH, 2), VolumeCommand::AdjustVolume(20)),
        Err(VolumeError::RevisionConflict { revision: 2 })
    );
    assert_eq!(m.desired_volume(), 60);
    set(&mut m, 3, VolumeCommand::AdjustVolume(10));
    assert_eq!(m.desired_volume(), 70);
}

// ---- reconnect and restart -------------------------------------------------------------------------------------

#[test]
fn a_rejoining_member_takes_the_groups_current_state_and_starts_muted() {
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(95));
    set(&mut m, 2, VolumeCommand::SetTrim(800));
    m.local_mute(true);

    let snapshot = GroupSnapshot {
        epoch: EPOCH,
        revision: 9,
        master_volume: 20,
        group_mute: false,
    };
    m.reconnect(snapshot).unwrap();
    assert_eq!(
        m.desired_volume(),
        20,
        "the group's value replaces the stored 95"
    );
    assert_eq!(m.trim_permille(), 800, "the room's own trim is kept");
    assert_eq!(
        m.effective_mute(),
        Some(MuteReason::Local),
        "a local mute survives the rejoin"
    );
    m.local_mute(false);
    assert_eq!(m.effective_mute(), Some(MuteReason::Join));
    assert_eq!(m.output_gain(), 0.0, "silent until the join completes");
    m.complete_join();
    assert_eq!(m.output_gain(), 0.2 * 0.8);
    assert_eq!(m.last_revision(), 9);

    // A snapshot from an older epoch, or an invalid one, changes nothing.
    let before = (m.desired_volume(), m.epoch());
    assert_eq!(
        m.reconnect(GroupSnapshot {
            epoch: EPOCH - 1,
            ..snapshot
        }),
        Err(VolumeError::StaleEpoch {
            command: EPOCH - 1,
            current: EPOCH
        })
    );
    assert_eq!(
        m.reconnect(GroupSnapshot {
            master_volume: 101,
            ..snapshot
        }),
        Err(VolumeError::VolumeOutOfRange { value: 101 })
    );
    assert_eq!((m.desired_volume(), m.epoch()), before);
    // A group mute in the snapshot is honoured.
    m.reconnect(GroupSnapshot {
        group_mute: true,
        ..snapshot
    })
    .unwrap();
    m.complete_join();
    assert_eq!(m.effective_mute(), Some(MuteReason::Group));
}

#[test]
fn a_restored_member_is_silent_and_powerless_until_it_rejoins() {
    let stored = PersistedMember {
        volume: 95,
        trim_permille: 1500,
        local_mute: false,
    };
    let mut m = MemberVolume::restore(stored, 1.0);
    assert_eq!(m.desired_volume(), 95);
    assert_eq!(m.effective_mute(), Some(MuteReason::Join));
    assert_eq!(
        m.unmuted_gain(),
        0.0,
        "no authority, so the stale value is not even armed"
    );
    assert_eq!(
        m.apply(stamp(EPOCH, 1), VolumeCommand::SetVolume(50)),
        Err(VolumeError::NoAuthority)
    );

    m.reconnect(GroupSnapshot {
        epoch: EPOCH,
        revision: 4,
        master_volume: 30,
        group_mute: false,
    })
    .unwrap();
    m.complete_join();
    assert_eq!(
        m.output_gain(),
        0.3 * 1.5,
        "the group's 30, never the stored 95"
    );

    // The persisted form is small, stable and round-trips.
    let text = serde_json::to_string(&m.persisted()).unwrap();
    assert_eq!(
        serde_json::from_str::<PersistedMember>(&text).unwrap(),
        m.persisted()
    );
    // A restored local mute stays: a restart cannot undo it.
    let mut muted = MemberVolume::restore(
        PersistedMember {
            local_mute: true,
            ..stored
        },
        1.0,
    );
    muted
        .reconnect(GroupSnapshot {
            epoch: EPOCH,
            revision: 1,
            master_volume: 50,
            group_mute: false,
        })
        .unwrap();
    muted.complete_join();
    assert_eq!(muted.effective_mute(), Some(MuteReason::Local));
    // Out-of-range persisted values are clamped on the way in.
    let wild = MemberVolume::restore(
        PersistedMember {
            volume: 250,
            trim_permille: 9999,
            local_mute: false,
        },
        1.0,
    );
    assert_eq!(
        (wild.desired_volume(), wild.trim_permille()),
        (MAX_VOLUME, MAX_TRIM_PERMILLE)
    );
}

// ---- roles --------------------------------------------------------------------------------------------------

#[test]
fn roles_map_onto_the_admitted_layout_and_absent_roles_are_refused_by_name() {
    let unavailable = |profile: &BoardProfile, role| match RolePlan::for_profile(profile, role) {
        Err(VolumeError::RoleUnavailable { reason, .. }) => Some(reason),
        _ => None,
    };
    // S5: tweeters, mids and a woofer; no sub path.
    let s5 = fixture("S5");
    for role in [Role::Stereo, Role::Left, Role::Right] {
        assert_eq!(RolePlan::for_profile(&s5, role).map(|p| p.role()), Ok(role));
    }
    assert_eq!(
        unavailable(&s5, Role::Sub),
        Some(RoleRefusal::NoSubwooferPath)
    );
    // The Sub fixture is a pure sub: only the Sub role exists.
    let sub = fixture("Sub");
    assert_eq!(
        RolePlan::for_profile(&sub, Role::Sub).map(|p| p.role()),
        Ok(Role::Sub)
    );
    for role in [Role::Stereo, Role::Left, Role::Right] {
        assert_eq!(
            unavailable(&sub, role),
            Some(RoleRefusal::SubwooferOnly),
            "{role:?}"
        );
    }
    // The Bridge has no output at all: every role is refused for exactly that reason.
    let bridge = fixture("BR100");
    for role in [Role::Stereo, Role::Left, Role::Right, Role::Sub] {
        assert_eq!(
            unavailable(&bridge, role),
            Some(RoleRefusal::NoAudioOutput),
            "{role:?}"
        );
    }
    // A layout that disagrees with its channel count, and a sub mixed with other drivers.
    let mut short = fixture("S3");
    short.channel_routing.pop();
    assert_eq!(
        unavailable(&short, Role::Stereo),
        Some(RoleRefusal::InvalidLayout)
    );
    let mut mixed = fixture("S3");
    mixed.channel_routing[2] = TransducerRole::SubwooferLfe;
    for role in [Role::Stereo, Role::Left, Role::Right, Role::Sub] {
        assert_eq!(
            unavailable(&mixed, role),
            Some(RoleRefusal::MixedSubLayout),
            "{role:?}"
        );
    }
    // The error names both the role and the reason.
    assert_eq!(
        RolePlan::for_profile(&s5, Role::Sub),
        Err(VolumeError::RoleUnavailable {
            role: Role::Sub,
            reason: RoleRefusal::NoSubwooferPath
        })
    );
}

#[test]
fn each_role_feeds_the_board_the_signal_it_names() {
    let profile = fixture("S5");
    let (l, r) = (0.2f32, -0.6f32);
    let mid = 0.5 * (l + r);
    for (role, want) in [
        (Role::Stereo, (l, r)),
        (Role::Left, (l, l)),
        (Role::Right, (r, r)),
    ] {
        assert_eq!(
            RolePlan::for_profile(&profile, role).unwrap().map(l, r),
            want,
            "{role:?}"
        );
    }
    let sub = RolePlan::for_profile(&fixture("Sub"), Role::Sub).unwrap();
    assert_eq!(
        sub.map(l, r),
        (mid, mid),
        "the sub gets the mono mix; its crossover is D02's"
    );

    // Whole blocks: partial frames, the start frame, and nothing written past the end.
    let mut input = StereoAudioBlock::silence(4096);
    input.frames = 5;
    for (i, (left, right)) in input
        .left
        .iter_mut()
        .zip(input.right.iter_mut())
        .enumerate()
    {
        *left = i as f32 / 1000.0;
        *right = -(i as f32) / 1000.0;
    }
    let plan = RolePlan::for_profile(&profile, Role::Right).unwrap();
    let mut out = StereoAudioBlock::silence(0);
    out.left = [9.0; FRAMES_PER_BLOCK];
    plan.map_block(&input, &mut out);
    assert_eq!((out.start_frame, out.frames), (4096, 5));
    for ((&l, &r), &want) in out.left.iter().zip(&out.right).zip(&input.right).take(5) {
        assert_eq!(
            (l, r),
            (want, want),
            "a Right room plays the right channel on both lanes"
        );
    }
    assert_eq!(out.left[5], 9.0, "frames past the block are untouched");
    input.frames = FRAMES_PER_BLOCK + 40;
    plan.map_block(&input, &mut out);
    assert_eq!(out.frames, FRAMES_PER_BLOCK, "oversize blocks are clamped");
}

// ---- group with missing members ------------------------------------------------------------------------------------

fn accepted(results: &[(u32, MemberResult)]) -> usize {
    results
        .iter()
        .filter(|(_, r)| matches!(r, MemberResult::Accepted(_)))
        .count()
}

#[test]
fn group_commands_skip_missing_members_and_a_rejoin_takes_the_current_volume() {
    let mut group = GroupVolume::new(3);
    for id in [1, 2, 3] {
        group.add_member(id, 1.0).unwrap();
        group.member_mut(id).unwrap().complete_join();
    }
    let results = group
        .apply(stamp(3, 1), VolumeCommand::SetVolume(40))
        .unwrap();
    assert_eq!(accepted(&results), 3);

    group.set_present(2, false).unwrap();
    let results = group
        .apply(stamp(3, 2), VolumeCommand::SetVolume(80))
        .unwrap();
    assert_eq!(accepted(&results), 2);
    assert_eq!(results[1], (2, MemberResult::Missing));
    assert_eq!(
        group.member(2).unwrap().desired_volume(),
        40,
        "the absent member missed it"
    );
    assert_eq!(group.member(1).unwrap().desired_volume(), 80);

    // It comes back: the group's current 80, join-muted, never its stale 40 (or anything louder).
    group.rejoin(2).unwrap();
    let back = group.member(2).unwrap();
    assert_eq!(
        (
            back.desired_volume(),
            back.effective_mute(),
            back.output_gain()
        ),
        (80, Some(MuteReason::Join), 0.0)
    );
    group.member_mut(2).unwrap().complete_join();

    // A relative command reaches the rejoined member once; a retry of it changes nothing anywhere.
    let results = group
        .apply(stamp(3, 3), VolumeCommand::AdjustVolume(5))
        .unwrap();
    assert_eq!(accepted(&results), 3);
    let retry = group
        .apply(stamp(3, 3), VolumeCommand::AdjustVolume(5))
        .unwrap();
    assert!(
        retry
            .iter()
            .all(|(_, r)| matches!(r, MemberResult::Accepted(c) if c.duplicate))
    );
    for id in [1, 2, 3] {
        assert_eq!(
            group.member(id).unwrap().desired_volume(),
            85,
            "member {id}"
        );
    }

    // Stale at the authority: nothing changes anywhere.
    assert_eq!(
        group.apply(stamp(3, 2), VolumeCommand::SetVolume(5)),
        Err(VolumeError::StaleRevision {
            revision: 2,
            last: 3
        })
    );
    assert_eq!(group.member(1).unwrap().desired_volume(), 85);
    // Per-room commands are not group-wide.
    assert_eq!(
        group.apply(stamp(3, 4), VolumeCommand::SetTrim(500)),
        Err(VolumeError::NotGroupWide)
    );
    assert_eq!(
        group.apply(stamp(3, 4), VolumeCommand::ResetTrim),
        Err(VolumeError::NotGroupWide)
    );
    // Members validate independently: one that was told about a newer epoch rejects the old one.
    group.member_mut(3).unwrap().declare_epoch(4).unwrap();
    let results = group
        .apply(stamp(3, 4), VolumeCommand::SetVolume(60))
        .unwrap();
    assert_eq!(
        results[2],
        (
            3,
            MemberResult::Rejected(VolumeError::StaleEpoch {
                command: 3,
                current: 4
            })
        )
    );
    assert_eq!(accepted(&results), 2);
    assert_eq!(
        group.snapshot(),
        GroupSnapshot {
            epoch: 3,
            revision: 4,
            master_volume: 60,
            group_mute: false
        }
    );
}

#[test]
fn unknown_and_duplicate_members_are_refused_by_name_with_nothing_changed() {
    let mut group = GroupVolume::new(1);
    group.add_member(1, 1.0).unwrap();
    group.member_mut(1).unwrap().complete_join();
    group
        .apply(stamp(1, 1), VolumeCommand::SetVolume(70))
        .unwrap();

    assert_eq!(
        group.add_member(1, 0.2),
        Err(VolumeError::DuplicateMember { id: 1 })
    );
    assert_eq!(
        group.member(1).unwrap().desired_volume(),
        70,
        "the existing member is untouched"
    );
    assert_eq!(group.member(1).unwrap().effective_ceiling(), 1.0);
    assert_eq!(
        group.set_present(9, false),
        Err(VolumeError::UnknownMember { id: 9 })
    );
    assert_eq!(group.rejoin(9), Err(VolumeError::UnknownMember { id: 9 }));
    assert!(group.member(9).is_none() && group.member_mut(9).is_none());

    // A member added late holds the group's current volume, join-muted, never zero-and-loud.
    group.add_member(2, 1.0).unwrap();
    let late = group.member(2).unwrap();
    assert_eq!(
        (
            late.desired_volume(),
            late.effective_mute(),
            late.output_gain()
        ),
        (70, Some(MuteReason::Join), 0.0)
    );
    assert_eq!(late.epoch(), Some(1));
    assert_eq!(
        VolumeError::UnknownMember { id: 9 }.code(),
        "unknown_member"
    );
    assert_eq!(
        VolumeError::DuplicateMember { id: 1 }.code(),
        "duplicate_member"
    );
}

#[test]
fn the_view_keeps_desired_bounded_and_applied_gain_apart_and_explains_a_silent_unmute() {
    let mut dsp = board("S3");
    let mut m = member(0.5);
    set(&mut m, 1, VolumeCommand::SetVolume(80));
    set(&mut m, 2, VolumeCommand::SetTrim(1500)); // requested 0.8 * 1.5 = 1.2
    m.sync(&mut dsp).unwrap();
    applied_after_each_frame(&mut dsp, 60);

    let view = m.view(&dsp);
    assert_eq!(
        view.desired_volume, 80,
        "the persisted intent is the slider, not the ramp"
    );
    assert_eq!(view.requested_gain, 0.8 * 1.5);
    assert_eq!(view.bounded_gain, 0.5);
    assert_eq!(view.ceiling, 0.5);
    assert!(view.limited_by_ceiling);
    assert!(
        view.applied_gain > 0.0 && view.applied_gain < view.bounded_gain,
        "mid-ramp, not yet at the target"
    );
    assert_eq!(view.effective_mute, None);

    // A fault overrides a requested unmute, and the view says so; the desired volume is unchanged.
    m.observe_board(BoardStatus::Faulted(FaultCode::StateRange { channel: 0 }));
    set(&mut m, 3, VolumeCommand::SetGroupMute(false));
    let view = m.view(&dsp);
    assert_eq!(view.effective_mute, Some(MuteReason::Fault));
    assert_eq!(view.desired_volume, 80);
    // A fault ceiling is distinguished from the protection ceiling by the lower bound it imposes.
    m.observe_board(BoardStatus::Active);
    m.set_fault_ceiling(Some(0.25));
    let view = m.view(&dsp);
    assert_eq!(
        (view.ceiling, view.bounded_gain, view.limited_by_ceiling),
        (0.25, 0.25, true)
    );
    // With no authority there is no valid requested volume to be limited.
    let restored = MemberVolume::restore(
        PersistedMember {
            volume: 95,
            trim_permille: 2000,
            local_mute: false,
        },
        0.5,
    );
    assert!(!restored.view(&dsp).limited_by_ceiling);
}

#[test]
fn a_group_mute_reaches_a_rejoining_member_through_the_snapshot() {
    let mut group = GroupVolume::new(1);
    group.add_member(1, 1.0).unwrap();
    group.member_mut(1).unwrap().complete_join();
    group
        .apply(stamp(1, 1), VolumeCommand::SetVolume(70))
        .unwrap();
    group.set_present(1, false).unwrap();
    group
        .apply(stamp(1, 2), VolumeCommand::SetGroupMute(true))
        .unwrap();
    group.rejoin(1).unwrap();
    group.member_mut(1).unwrap().complete_join();
    assert_eq!(
        group.member(1).unwrap().effective_mute(),
        Some(MuteReason::Group)
    );
    assert_eq!(group.member(1).unwrap().output_gain(), 0.0);
}

// ---- integration with the real D02 renderer ----------------------------------------------------------------------------

#[test]
fn the_target_is_bounded_before_the_ramp_and_the_ramp_never_overshoots_it() {
    let mut dsp = board("S3");
    let mut m = member(0.5);
    set(&mut m, 1, VolumeCommand::SetVolume(100));
    set(&mut m, 2, VolumeCommand::SetTrim(2000)); // 1.0 * 2.0 would be 2.0
    assert_eq!(m.unmuted_gain(), 0.5);
    m.sync(&mut dsp).unwrap();
    let trace = applied_after_each_frame(&mut dsp, 600);
    assert!(
        trace.iter().all(|&g| g <= 0.5),
        "never above the bounded target"
    );
    assert!(
        trace
            .windows(2)
            .all(|w| w[1] >= w[0] && w[1] - w[0] <= STEP * 1.0001),
        "one smooth ramp"
    );
    assert_eq!(
        *trace.last().unwrap(),
        0.5,
        "the ramp ends exactly on the bounded target"
    );
}

#[test]
fn a_new_target_mid_ramp_retargets_from_the_current_gain() {
    let mut dsp = board("S3");
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(100));
    m.sync(&mut dsp).unwrap();
    let up = applied_after_each_frame(&mut dsp, 100);
    let at_change = *up.last().unwrap();
    assert!((at_change - 100.0 * STEP).abs() < 1e-4, "{at_change}");

    set(&mut m, 2, VolumeCommand::SetVolume(20));
    m.sync(&mut dsp).unwrap();
    let down = applied_after_each_frame(&mut dsp, 12);
    assert!(
        down[0] <= at_change && at_change - down[0] <= STEP * 1.0001,
        "continues from where it was"
    );
    assert!(
        down.windows(2).all(|w| w[1] <= w[0]),
        "heads straight to the new target"
    );
    assert!(down.iter().all(|&g| g >= 0.2), "and does not undershoot it");
    assert_eq!(*down.last().unwrap(), 0.2);
}

#[test]
fn mute_wins_over_a_volume_command_in_flight() {
    let mut dsp = board("S3");
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(100));
    m.sync(&mut dsp).unwrap();
    let rising = applied_after_each_frame(&mut dsp, 200);
    let mid_ramp = *rising.last().unwrap();

    m.local_mute(true);
    m.sync(&mut dsp).unwrap();
    // A louder volume arrives while the mute ramp is running: it must not raise the output.
    let falling_a = applied_after_each_frame(&mut dsp, 50);
    set(&mut m, 2, VolumeCommand::SetVolume(100));
    set(&mut m, 3, VolumeCommand::AdjustVolume(100));
    m.sync(&mut dsp).unwrap();
    let falling_b = applied_after_each_frame(&mut dsp, 400);
    let all: Vec<f32> = falling_a.into_iter().chain(falling_b).collect();
    assert!(all[0] <= mid_ramp);
    assert!(
        all.windows(2).all(|w| w[1] <= w[0]),
        "monotone down to silence despite the volume commands"
    );
    assert_eq!(*all.last().unwrap(), 0.0);

    // Local unmute: it ramps up again from the current (zero) gain, not from the old target.
    m.local_mute(false);
    m.sync(&mut dsp).unwrap();
    let back = applied_after_each_frame(&mut dsp, 10);
    assert!(back[0] <= STEP * 1.0001 && back.windows(2).all(|w| w[1] >= w[0]));
}

#[test]
fn reconnect_never_spikes_for_a_live_board_or_a_restarted_one() {
    // Live board at a loud volume, then the member rejoins a group that is now much quieter.
    let mut dsp = board("S3");
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(90));
    m.sync(&mut dsp).unwrap();
    let loud = applied_after_each_frame(&mut dsp, 600);
    assert_eq!(*loud.last().unwrap(), 0.9);

    m.reconnect(GroupSnapshot {
        epoch: EPOCH,
        revision: 5,
        master_volume: 20,
        group_mute: false,
    })
    .unwrap();
    m.sync(&mut dsp).unwrap();
    let down = applied_after_each_frame(&mut dsp, 600);
    assert!(down.iter().all(|&g| g <= 0.9) && down.windows(2).all(|w| w[1] <= w[0]));
    assert_eq!(
        *down.last().unwrap(),
        0.0,
        "silent before the new level is applied"
    );
    m.complete_join();
    m.sync(&mut dsp).unwrap();
    let up = applied_after_each_frame(&mut dsp, 600);
    assert!(
        up.iter().all(|&g| g <= 0.2),
        "never above the group's current volume"
    );
    assert!(
        up.windows(2)
            .all(|w| w[1] >= w[0] && w[1] - w[0] <= STEP * 1.0001)
    );
    assert_eq!(*up.last().unwrap(), 0.2);

    // A restarted device: a fresh renderer and a restored member that holds a stale loud volume.
    let mut fresh = board("S3");
    let mut restored = MemberVolume::restore(
        PersistedMember {
            volume: 95,
            trim_permille: 1000,
            local_mute: false,
        },
        1.0,
    );
    restored.sync(&mut fresh).unwrap();
    assert!(
        applied_after_each_frame(&mut fresh, 300)
            .iter()
            .all(|&g| g == 0.0),
        "silent before it rejoins"
    );
    restored
        .reconnect(GroupSnapshot {
            epoch: EPOCH,
            revision: 1,
            master_volume: 20,
            group_mute: false,
        })
        .unwrap();
    restored.complete_join();
    restored.sync(&mut fresh).unwrap();
    let after = applied_after_each_frame(&mut fresh, 600);
    assert!(
        after.iter().all(|&g| g <= 0.2),
        "the stored 95 was never audible"
    );
    assert_eq!(*after.last().unwrap(), 0.2);
}

#[test]
fn a_board_that_is_not_active_keeps_the_member_fault_muted_whatever_is_requested() {
    let profile = fixture("S3");
    let mut dsp = ProtectedBoardDsp::admit(&profile, None, Admission::HostSimulation); // fail-muted
    let mut m = member(1.0);
    set(&mut m, 1, VolumeCommand::SetVolume(100));
    let receipt = set(&mut m, 2, VolumeCommand::SetGroupMute(false));
    assert_eq!(receipt.effective_mute, None, "before the board is observed");
    m.sync(&mut dsp).unwrap();
    assert_eq!(m.effective_mute(), Some(MuteReason::Fault));
    assert!(dsp.is_muted());
    let receipt = set(&mut m, 3, VolumeCommand::SetGroupMute(false));
    assert_eq!(
        receipt.effective_mute,
        Some(MuteReason::Fault),
        "the UI can report why the unmute is silent"
    );
    assert!(
        applied_after_each_frame(&mut dsp, 300)
            .iter()
            .all(|&g| g == 0.0)
    );
}

#[test]
fn mono_sum_is_bounded_and_only_admitted_for_non_sub_layouts() {
    let s5 = fixture("S5");
    let plan = RolePlan::for_profile(&s5, Role::MonoSum).unwrap();
    assert_eq!(plan.role(), Role::MonoSum);
    for (left, right, want) in [
        (0.2_f32, -0.6_f32, 0.5_f32 * 0.2_f32 + 0.5_f32 * -0.6_f32),
        (1.0, -1.0, 0.0),
        (f32::MAX, f32::MAX, f32::MAX),
        (-f32::MAX, -f32::MAX, -f32::MAX),
        (f32::MAX, -f32::MAX, 0.0),
    ] {
        let (a, b) = plan.map(left, right);
        assert!(a.is_finite() && b.is_finite());
        assert_eq!((a, b), (want, want));
    }
    let mut input = StereoAudioBlock::silence(73);
    input.frames = 3;
    input.left[..3].copy_from_slice(&[1.0, 0.5, -0.25]);
    input.right[..3].copy_from_slice(&[-1.0, 0.25, 0.5]);
    let mut output = StereoAudioBlock::silence(0);
    output.left.fill(9.0);
    output.right.fill(9.0);
    plan.map_block(&input, &mut output);
    assert_eq!((output.start_frame, output.frames), (73, 3));
    assert_eq!(&output.left[..3], &[0.0, 0.375, 0.125]);
    assert_eq!(&output.right[..3], &[0.0, 0.375, 0.125]);
    assert_eq!(output.left[3], 9.0);
    assert_eq!(output.right[3], 9.0);

    for (board, reason) in [
        (fixture("Sub"), RoleRefusal::SubwooferOnly),
        (fixture("BR100"), RoleRefusal::NoAudioOutput),
        (
            {
                let mut mixed = fixture("S3");
                mixed.channel_routing[2] = TransducerRole::SubwooferLfe;
                mixed
            },
            RoleRefusal::MixedSubLayout,
        ),
        (
            {
                let mut invalid = fixture("S3");
                invalid.channel_routing.pop();
                invalid
            },
            RoleRefusal::InvalidLayout,
        ),
    ] {
        assert_eq!(
            RolePlan::for_profile(&board, Role::MonoSum),
            Err(VolumeError::RoleUnavailable {
                role: Role::MonoSum,
                reason
            })
        );
    }
}
