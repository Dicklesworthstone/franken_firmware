//! Private G02 integration controls: real localhost PCM + real membership,
//! synthetic board calibration and retained FakeBackend. Not device evidence.
use super::*;
use crate::settled_render::AdmissionError;
use franken_board_profile::BoardProfile;

fn role_board(model: &str) -> BoardProfile {
    franken_board_profile::synthetic_test_fixture_catalog()
        .into_iter()
        .find(|board| board.model_number == model)
        .unwrap()
}

#[derive(Clone, Copy)]
enum PriorSwitch {
    None,
    Pending,
    Rejected,
}

fn role_fixture(
    board: &BoardProfile,
    role: ChannelRole,
    final_frame: u64,
) -> Result<ControllerRig, AdmissionError> {
    role_fixture_with_switch(board, role, final_frame, PriorSwitch::None)
}
fn role_fixture_with_switch(
    board: &BoardProfile,
    role: ChannelRole,
    final_frame: u64,
    prior: PriorSwitch,
) -> Result<ControllerRig, AdmissionError> {
    let net = network();
    let address = net.endpoint.carrier().media_addr().unwrap();
    let start_local_ns = net
        .clock
        .local_for_group(net.start_group_ns, net.now.get())
        .unwrap();
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: u32::from(board.hardware_channels),
        bytes_per_sample: 2,
    };
    cfg.completion_delay_ticks = 2;
    cfg.min_submission_lead_ticks = Some(6);
    cfg.flush_ack_delay_ticks = Some(3);
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(128);
    let suppress_flush = Rc::new(Cell::new(false));
    let flush_requests = Rc::new(Cell::new(0));
    let backend = RetainedPurge {
        inner: backend,
        capable: true,
        suppress_next_flush: Rc::clone(&suppress_flush),
        flush_requests: Rc::clone(&flush_requests),
    };
    let session_config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut hal = HalSession::open(board.clone(), backend, session_config).unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(
        hal.prime_silence().unwrap().accepted_bytes,
        RENDER_FRAMES * usize::from(board.hardware_channels) * 2
    );
    let calibration = synthetic_calibration_for(board);
    let mut dsp = ProtectedBoardDsp::admit(
        board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    match prior {
        PriorSwitch::None => {}
        PriorSwitch::Pending => {
            dsp.request_profile_switch(board, &calibration, ProtectionAdmission::HostSimulation)
                .unwrap();
            assert!(dsp.has_pending_switch());
        }
        PriorSwitch::Rejected => {
            let mut bad = calibration.clone();
            bad.profile_digest = "0".repeat(64);
            assert!(
                dsp.request_profile_switch(board, &bad, ProtectionAdmission::HostSimulation)
                    .is_err()
            );
            assert!(!dsp.has_pending_switch());
            assert!(matches!(
                dsp.status(),
                franken_dsp::protection::BoardStatus::FailMuted(_)
            ));
        }
    }
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    let render = RenderLoop::new(
        hal,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    )
    .unwrap();
    let first = render.next_slot().unwrap();
    let mapping = TickMapping {
        anchor_tick: first.presentation_tick,
        anchor_group_ns: net.start_group_ns,
        ns_numerator: 1_000_000,
        tick_denominator: 3,
        uncertainty_ns: 0,
        presentation_tolerance_ns: 1,
    };
    let schedule = StartSchedule {
        epoch: 1,
        start_group_ns: net.start_group_ns,
    };
    let network = NetworkRender::admit(
        net.endpoint,
        net.platform,
        net.clock,
        render,
        NetworkRenderAdmission {
            schedule,
            anchor_frame: 0,
            final_frame,
            mapping,
            capacity_frames: 1024,
            start: StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            },
        },
    )
    .unwrap();
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, u64::MAX);
    let (control, soap, storage_fail) = test_fleet_unleased();
    let bundle = provision_bundle(control, token.clone()).unwrap();
    let owner = SettledRender::admit_fresh_group(
        bundle,
        soap,
        network,
        PendingMember {
            member_id: TEST_MEMBER.into(),
            profile_id: board.profile_id.clone(),
            role,
            ceiling: 1.0,
        },
        7,
    )?;
    Ok(ControllerRig {
        owner,
        clock_fail: net.fail,
        local_now: net.now,
        suppress_flush,
        flush_requests,
        storage_fail,
        token,
        probe,
        socket: net.socket,
        address,
        sender: net.sender,
        start_group_ns: net.start_group_ns,
        start_local_ns,
    })
}

fn role_activate(rig: &mut ControllerRig, board: &BoardProfile) {
    use franken_session::ProposalStatus;
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    let join = rig
        .owner
        .propose_join(
            rig.token.clone(),
            board.clone(),
            cutover,
            CLOCK_ORIGIN + 300_000_000,
        )
        .unwrap();
    rig.owner.ack_local(join).unwrap();
    assert!(matches!(
        rig.owner.commit_join(join),
        Ok(ProposalStatus::Committed { .. })
    ));
    rig.local_now.set(600_000_000);
    let actual = rig.owner.tick_membership(join).unwrap();
    assert!(actual.settled.iter().any(|(id, status)| *id == join
        && matches!(status, ProposalStatus::Activated { revision: 1, .. })));
}

fn stereo_sample(frame: u64) -> (i16, i16) {
    let left = ((frame % 113) as i16 - 56) * 180;
    let right = (((frame * 7 + 11) % 97) as i16 - 48) * 130;
    (left, right)
}
fn stereo_payload(start: u64, frames: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(frames * 4);
    for i in 0..frames {
        let (left, right) = stereo_sample(start + i as u64);
        bytes.extend_from_slice(&left.to_be_bytes());
        bytes.extend_from_slice(&right.to_be_bytes());
    }
    bytes
}
fn enqueue_role_audio(rig: &mut ControllerRig, frames: usize) {
    let mut left = frames;
    let mut block = 0_u64;
    while left > 0 {
        let n = left.min(BLOCK_FRAMES as usize);
        let frame = block * BLOCK_FRAMES;
        let pts = rig.start_group_ns + frames_to_ns(frame);
        let wire = rig
            .sender
            .send(OutboundFrame::media(
                frame,
                pts,
                pts - 5_333_333,
                stereo_payload(frame, n),
            ))
            .unwrap();
        rig.socket.send_to(&wire, rig.address).unwrap();
        let report = rig.owner.poll_media().unwrap();
        assert_eq!((report.media_read, report.media_accepted), (1, 1));
        left -= n;
        block += 1;
    }
}

/// Manual per-sample routing after a separate D03 resampler and before a
/// separate instance of the production calibrated D02. No RolePlan is used by
/// the oracle. The existing D02 filter tests, not this shared implementation,
/// qualify crossover behavior. On the Sub's Mid input, mapped stereo mid and
/// unmapped stereo are observationally equivalent; this check cannot prove
/// that the Sub RolePlan was installed or invoked.
fn expected_role_pcm(
    board: &BoardProfile,
    role: ChannelRole,
    frames: usize,
) -> (Vec<Vec<u8>>, usize) {
    let mut left = Vec::with_capacity(frames + 2);
    let mut right = Vec::with_capacity(frames + 2);
    for frame in 0..frames as u64 {
        let (l, r) = stereo_sample(frame);
        left.push(f32::from(l) / 32768.0);
        right.push(f32::from(r) / 32768.0);
    }
    left.extend([0.0; 2]);
    right.extend([0.0; 2]);
    let mut source = SliceSource::new(&left, &right).unwrap();
    let mut resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
    let calibration = synthetic_calibration_for(board);
    let mut dsp = ProtectedBoardDsp::admit(
        board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    // Group 50 * member 50 with unity local trim, as in the real fresh session.
    dsp.set_user_gain(0.25);
    dsp.set_muted(false).unwrap();
    let mut block = StereoAudioBlock::silence(0);
    let mut out = ProtectedOutput::new();
    let mut expected = Vec::new();
    let mut produced = 0_usize;
    for index in 0..(frames + 1) {
        let result = resampler
            .render(
                &mut source,
                &mut block.left[..RENDER_FRAMES],
                &mut block.right[..RENDER_FRAMES],
            )
            .unwrap();
        if result.produced == 0 {
            return (expected, produced);
        }
        produced += result.produced;
        block.left[result.produced..RENDER_FRAMES].fill(0.0);
        block.right[result.produced..RENDER_FRAMES].fill(0.0);
        for i in 0..RENDER_FRAMES {
            let l = block.left[i];
            let r = block.right[i];
            let (a, b) = match role {
                ChannelRole::Stereo => (l, r),
                ChannelRole::LeftMono => (l, l),
                ChannelRole::RightMono => (r, r),
                ChannelRole::SubLfe => {
                    let mid = 0.5 * (l + r);
                    (mid, mid)
                }
                other => panic!("unsupported reference role {other:?}"),
            };
            block.left[i] = a;
            block.right[i] = b;
        }
        block.frames = RENDER_FRAMES;
        block.start_frame = (index * RENDER_FRAMES) as u64;
        dsp.render_into(&block, &mut out);
        let mut bytes = Vec::new();
        for frame in 0..RENDER_FRAMES {
            for lane in out
                .samples
                .iter()
                .take(usize::from(board.hardware_channels))
            {
                bytes.extend_from_slice(&lane[frame].to_be_bytes());
            }
        }
        expected.push(bytes);
        if result.underrun {
            return (expected, produced);
        }
    }
    panic!("reference did not reach source EOF");
}

fn render_role_to_eof(board: &BoardProfile, role: ChannelRole, frames: usize) -> Vec<Vec<u8>> {
    let mut rig = role_fixture(board, role, frames as u64).unwrap();
    role_activate(&mut rig, board);
    enqueue_role_audio(&mut rig, frames);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut draining = false;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        if rig.owner.render_state() == RenderState::Draining {
            draining = true;
            break;
        }
    }
    assert!(draining, "finite role stream must reach actual drain");
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.render_state(), RenderState::Stopped);
    assert_eq!(rig.owner.received_frames_pulled(), frames as u64);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let captured = rig.probe.captured_submissions();
    assert_eq!(
        captured[0],
        vec![0; RENDER_FRAMES * usize::from(board.hardware_channels) * 2]
    );
    captured[1..].to_vec()
}

#[test]
fn admitted_roles_match_manual_per_channel_protected_oracle_through_finite_eof() {
    for (model, role) in [
        ("S5", ChannelRole::Stereo),
        ("S5", ChannelRole::LeftMono),
        ("S5", ChannelRole::RightMono),
        ("Sub", ChannelRole::SubLfe),
    ] {
        let board = role_board(model);
        for frames in [512, 549] {
            let actual = render_role_to_eof(&board, role, frames);
            let (expected, reference_frames) = expected_role_pcm(&board, role, frames);
            assert!(
                reference_frames >= frames,
                "reference must cover finite source"
            );
            assert_eq!(actual.len(), expected.len(), "{model} {role:?} block count");
            let channels = usize::from(board.hardware_channels);
            for lane in 0..channels {
                let gather = |blocks: &[Vec<u8>]| -> Vec<u8> {
                    blocks
                        .iter()
                        .flat_map(|block| {
                            block
                                .chunks_exact(channels * 2)
                                .flat_map(|frame| [frame[lane * 2], frame[lane * 2 + 1]])
                        })
                        .collect()
                };
                let heard = gather(&actual);
                let want = gather(&expected);
                assert!(
                    want.iter().any(|b| *b != 0),
                    "{model} {role:?} lane {lane} must be audible in model"
                );
                assert_eq!(
                    heard, want,
                    "{model} {role:?} lane {lane} routing/protection"
                );
            }
        }
    }
}

fn refused_at_admission_or_join(board: &BoardProfile, role: ChannelRole) {
    if role == ChannelRole::MonoSum {
        assert!(matches!(
            role_fixture(board, role, 512),
            Err(AdmissionError::Binding)
        ));
        return;
    }
    let mut rig = role_fixture(board, role, 512).unwrap();
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    assert!(
        matches!(
            rig.owner.propose_join(
                rig.token.clone(),
                board.clone(),
                cutover,
                CLOCK_ORIGIN + 300_000_000
            ),
            Err(OwnerError::Binding)
        ),
        "{role:?} must be refused against {}'s actual layout",
        board.model_number
    );
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert_eq!(
        rig.probe.captured_submissions(),
        vec![vec![
            0;
            RENDER_FRAMES * usize::from(board.hardware_channels) * 2
        ]]
    );
    rig.owner.request_stop().unwrap();
    assert!(finish_drain(&mut rig.owner).acknowledged);
}

#[test]
fn wrong_roles_bridge_and_same_id_wrong_profile_never_activate() {
    let s5 = role_board("S5");
    let sub = role_board("Sub");
    for role in [ChannelRole::SubLfe, ChannelRole::MonoSum] {
        refused_at_admission_or_join(&s5, role);
    }
    for role in [
        ChannelRole::Stereo,
        ChannelRole::LeftMono,
        ChannelRole::RightMono,
    ] {
        refused_at_admission_or_join(&sub, role);
    }
    let bridge = role_board("BR100");
    for role in [
        ChannelRole::Stereo,
        ChannelRole::LeftMono,
        ChannelRole::RightMono,
        ChannelRole::SubLfe,
    ] {
        use franken_dsp::volume::{Role, RolePlan, RoleRefusal, VolumeError};
        let planned = match role {
            ChannelRole::Stereo => Role::Stereo,
            ChannelRole::LeftMono => Role::Left,
            ChannelRole::RightMono => Role::Right,
            ChannelRole::SubLfe => Role::Sub,
            other => panic!("unexpected role {other:?}"),
        };
        assert!(matches!(
            RolePlan::for_profile(&bridge, planned),
            Err(VolumeError::RoleUnavailable {
                reason: RoleRefusal::NoAudioOutput,
                ..
            })
        ));
        let mut cfg = FakeConfig::retained();
        cfg.geometry = RawGeometry {
            ring_depth: 4,
            frames_per_block: 64,
            channels: 0,
            bytes_per_sample: 2,
        };
        let (backend, _) = FakeBackend::new(cfg);
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        assert!(
            matches!(
                HalSession::open(bridge.clone(), backend, config),
                Err(franken_hal::session::SessionError::ProfileRejected(
                    franken_board_profile::UnsupportedReasonCode::NonAudioAppliance { .. }
                ))
            ),
            "Bridge cannot reach role {role:?} without a valid audio HAL"
        );
    }
    // Same ID and internally valid digest are insufficient: it is not the
    // profile whose actual calibration and protection were admitted.
    let mut forged = s5.clone();
    forged.calibrated_output_delay_us += 1;
    forged = forged.with_computed_digest();
    assert_eq!(forged.profile_id, s5.profile_id);
    assert_ne!(forged.integrity_sha256, s5.integrity_sha256);
    assert!(forged.verify_integrity().is_ok());
    let mut rig = role_fixture(&s5, ChannelRole::LeftMono, 512).unwrap();
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    assert!(
        matches!(
            rig.owner.propose_join(
                rig.token.clone(),
                forged,
                cutover,
                CLOCK_ORIGIN + 300_000_000
            ),
            Err(OwnerError::Binding)
        ),
        "same-ID altered profile must not bind role"
    );
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    rig.owner.request_stop().unwrap();
    assert!(finish_drain(&mut rig.owner).acknowledged);

    // A forged, self-consistent sub-only routing with the S1 profile ID must
    // not authorize an LFE role against the original non-sub admitted DSP.
    let s1 = role_board("S1");
    let mut false_sub = s1.clone();
    false_sub
        .channel_routing
        .fill(franken_board_profile::TransducerRole::SubwooferLfe);
    false_sub = false_sub.with_computed_digest();
    assert_eq!(false_sub.profile_id, s1.profile_id);
    assert_ne!(false_sub.integrity_sha256, s1.integrity_sha256);
    assert!(false_sub.verify_integrity().is_ok());
    let mut rig = role_fixture(&s1, ChannelRole::SubLfe, 512).unwrap();
    assert!(
        matches!(
            rig.owner.propose_join(
                rig.token.clone(),
                false_sub,
                cutover,
                CLOCK_ORIGIN + 300_000_000
            ),
            Err(OwnerError::Binding)
        ),
        "same-ID forged Sub layout must not redirect a non-Sub DSP"
    );
    assert!(!rig.probe.calls().contains(&FakeCall::Start));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    rig.owner.request_stop().unwrap();
    assert!(finish_drain(&mut rig.owner).acknowledged);
}

#[test]
fn busy_left_role_cannot_rebind_and_stop_preserves_retained_custody() {
    let board = role_board("S5");
    for ack in [true, false] {
        let mut rig = role_fixture(&board, ChannelRole::LeftMono, 512).unwrap();
        role_activate(&mut rig, &board);
        enqueue_role_audio(&mut rig, 512);
        rig.probe.set_lose_completions(true);
        let mut timing = ScriptedTiming {
            default_cost: 2,
            ..ScriptedTiming::default()
        };
        let mut busy = false;
        for step in 0..5000_u64 {
            rig.local_now
                .set(rig.start_local_ns - 15_000_000 + step * 100_000);
            match rig.owner.render_step(&mut timing).unwrap() {
                PlaybackStep::Render(OwnerStep::Tick(report)) if report.started.is_some() => {
                    busy = true;
                    break;
                }
                PlaybackStep::Render(_) => {}
                other => panic!("unexpected pre-busy state {other:?}"),
            }
        }
        assert!(
            busy,
            "must observe an actual started block before completion"
        );
        let pulled = rig.owner.received_frames_pulled();
        assert!(pulled > 0);
        let captured = rig.probe.captured_submissions();
        let held = rig.probe.pending_slots();
        assert!(!held.is_empty(), "silent prime remains in model custody");
        let cutover = ((CLOCK_ORIGIN + 2_000_000_000) * 48_000) / 1_000_000_000;
        assert!(matches!(
            rig.owner.propose_join(
                rig.token.clone(),
                board.clone(),
                cutover,
                CLOCK_ORIGIN + 1_000_000_000
            ),
            Err(OwnerError::JoinState)
        ));
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.captured_submissions(), captured);
        assert_eq!(rig.probe.pending_slots(), held);
        rig.suppress_flush.set(!ack);
        assert!(matches!(
            rig.owner.request_stop(),
            Ok(RenderApplication::Stopping)
        ));
        assert_eq!(rig.owner.render_state(), RenderState::Draining);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        let stop = finish_drain(&mut rig.owner);
        assert_eq!(stop.acknowledged, ack);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.captured_submissions(), captured);
        if ack {
            assert_eq!(rig.probe.pending(), 0);
        } else {
            assert_eq!(rig.probe.pending_slots(), held);
        }
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

#[test]
fn manual_role_oracle_detects_swaps_and_a_wrong_sub_input() {
    let s5 = role_board("S5");
    let (stereo, _) = expected_role_pcm(&s5, ChannelRole::Stereo, 512);
    let (left, _) = expected_role_pcm(&s5, ChannelRole::LeftMono, 512);
    let (right, _) = expected_role_pcm(&s5, ChannelRole::RightMono, 512);
    assert_ne!(stereo, left, "stereo-vs-left routing must be observable");
    assert_ne!(stereo, right, "stereo-vs-right routing must be observable");
    assert_ne!(left, right, "left-right swaps must be observable");
    let sub = role_board("Sub");
    let (actual_mid, _) = expected_role_pcm(&sub, ChannelRole::SubLfe, 512);
    // Counterfactual only: the Sub profile must reject LeftMono at admission.
    let (wrong_left, _) = expected_role_pcm(&sub, ChannelRole::LeftMono, 512);
    assert_ne!(
        actual_mid, wrong_left,
        "Sub must use the agreed stereo mid before its low-pass"
    );
}

#[test]
fn pending_or_failed_protection_profile_switch_cannot_authorize_a_role() {
    let board = role_board("S5");
    for prior in [PriorSwitch::Pending, PriorSwitch::Rejected] {
        let mut rig = role_fixture_with_switch(&board, ChannelRole::RightMono, 512, prior).unwrap();
        let held = rig.probe.pending_slots();
        assert_eq!(held.len(), 1);
        let captured = rig.probe.captured_submissions();
        let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
        assert!(matches!(
            rig.owner.propose_join(
                rig.token.clone(),
                board.clone(),
                cutover,
                CLOCK_ORIGIN + 300_000_000
            ),
            Err(OwnerError::Binding)
        ));
        assert_eq!(rig.owner.render_state(), RenderState::Ready);
        assert_eq!(rig.owner.received_frames_pulled(), 0);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (1, 0));
        assert_eq!(rig.probe.captured_submissions(), captured);
        assert!(!rig.probe.calls().contains(&FakeCall::Start));
        rig.owner.request_stop().unwrap();
        assert!(finish_drain(&mut rig.owner).acknowledged);
        assert_eq!(rig.probe.pending(), 0);
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

fn pair_render(
    hal_board: &BoardProfile,
    dsp_board: &BoardProfile,
    calibrated: bool,
    pending: Option<&BoardProfile>,
) -> (
    Result<RenderLoop<FakeBackend>, crate::render::RenderError>,
    FakeProbe,
) {
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: u32::from(hal_board.hardware_channels),
        bytes_per_sample: 2,
    };
    cfg.min_submission_lead_ticks = Some(6);
    let (backend, probe) = FakeBackend::new(cfg);
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut hal = HalSession::open(hal_board.clone(), backend, config).unwrap();
    hal.prepare().unwrap();
    let calibration = synthetic_calibration_for(dsp_board);
    let mut dsp = ProtectedBoardDsp::admit(
        dsp_board,
        calibrated.then_some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    if let Some(next) = pending {
        let next_calibration = synthetic_calibration_for(next);
        dsp.request_profile_switch(next, &next_calibration, ProtectionAdmission::HostSimulation)
            .unwrap();
        assert!(dsp.has_pending_switch());
    }
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    let result = RenderLoop::new(
        hal,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    );
    (result, probe)
}

#[test]
fn same_geometry_hal_and_dsp_require_the_same_validated_profile() {
    let a = role_board("S5");
    let mut b = a.clone();
    b.calibrated_output_delay_us += 1;
    b = b.with_computed_digest();
    assert_eq!(a.profile_id, b.profile_id);
    assert_eq!(a.hardware_channels, b.hardware_channels);
    assert_ne!(a.integrity_sha256, b.integrity_sha256);
    assert!(a.verify_integrity().is_ok() && b.verify_integrity().is_ok());
    let (matched, matched_probe) = pair_render(&a, &a, true, None);
    assert!(
        matched.is_ok(),
        "matched real HAL/DSP composition must remain usable"
    );
    assert!(!matched_probe.calls().contains(&FakeCall::Start));
    let (different, different_probe) = pair_render(&a, &b, true, None);
    assert!(
        matches!(
            different,
            Err(crate::render::RenderError::Geometry(
                "the session and protection profiles disagree"
            ))
        ),
        "equal geometry and same ID must not hide a different DSP profile digest"
    );
    assert!(!different_probe.calls().contains(&FakeCall::Start));
    let (pending, pending_probe) = pair_render(&a, &a, true, Some(&b));
    assert!(
        matches!(
            pending,
            Err(crate::render::RenderError::Geometry(
                "the session and protection profiles disagree"
            ))
        ),
        "a preexisting mismatched pending DSP switch must not be bound"
    );
    assert!(!pending_probe.calls().contains(&FakeCall::Start));
    let (matched, _) = pair_render(&a, &a, true, None);
    let mut render = matched.unwrap();
    let b_calibration = synthetic_calibration_for(&b);
    assert!(
        matches!(
            render.dsp_mut().request_profile_switch(
                &b,
                &b_calibration,
                ProtectionAdmission::HostSimulation
            ),
            Err(franken_dsp::protection::ProtectionError::ProfileBindingMismatch)
        ),
        "a later different profile switch must remain refused"
    );
    assert!(!render.dsp_mut().has_pending_switch());
    assert!(matches!(
        render.dsp_mut().status(),
        franken_dsp::protection::BoardStatus::Active
    ));
    assert_eq!(
        render.dsp_mut().profile_digest(),
        Some(a.integrity_sha256.as_bytes())
    );
}

#[test]
fn missing_calibration_stays_constructible_but_cannot_start() {
    let board = role_board("S5");
    let (render, probe) = pair_render(&board, &board, false, None);
    let mut render = render.expect("existing fail-muted construction must remain available");
    assert!(matches!(
        render.start(StartPreconditions {
            presentation_mapping_installed: true,
            safe_gain_installed: true
        }),
        Err(crate::render::RenderError::ProtectionNotActive)
    ));
    assert!(!probe.calls().contains(&FakeCall::Start));
    assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
}

fn left_role_after_busy_rejoin(attempt: bool) -> Vec<Vec<u8>> {
    let board = role_board("S5");
    let mut rig = role_fixture(&board, ChannelRole::LeftMono, 512).unwrap();
    role_activate(&mut rig, &board);
    enqueue_role_audio(&mut rig, 512);
    let mut timing = ScriptedTiming {
        default_cost: 2,
        ..ScriptedTiming::default()
    };
    let mut seen_busy = false;
    let mut draining = false;
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        let result = rig.owner.render_step(&mut timing).unwrap();
        if !seen_busy
            && matches!(result, PlaybackStep::Render(OwnerStep::Tick(ref report)) if report.started.is_some())
        {
            seen_busy = true;
            let pulled = rig.owner.received_frames_pulled();
            let captured = rig.probe.captured_submissions();
            let held = rig.probe.pending_slots();
            let calls = rig.probe.calls();
            if attempt {
                let cutover = ((CLOCK_ORIGIN + 2_000_000_000) * 48_000) / 1_000_000_000;
                assert!(matches!(
                    rig.owner.propose_join(
                        rig.token.clone(),
                        board.clone(),
                        cutover,
                        CLOCK_ORIGIN + 1_000_000_000
                    ),
                    Err(OwnerError::JoinState)
                ));
            }
            assert_eq!(rig.owner.received_frames_pulled(), pulled);
            assert_eq!(rig.probe.captured_submissions(), captured);
            assert_eq!(rig.probe.pending_slots(), held);
            assert_eq!(rig.probe.calls(), calls);
        }
        if rig.owner.render_state() == RenderState::Draining {
            draining = true;
            break;
        }
    }
    assert!(seen_busy && draining);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), 512);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    rig.probe.captured_submissions()[1..].to_vec()
}

#[test]
fn rejected_busy_rejoin_does_not_reinterpret_or_interrupt_later_pcm() {
    let without_attempt = left_role_after_busy_rejoin(false);
    let after_refusal = left_role_after_busy_rejoin(true);
    let (expected, frames) = expected_role_pcm(&role_board("S5"), ChannelRole::LeftMono, 512);
    assert!(frames >= 512);
    assert_eq!(
        after_refusal, without_attempt,
        "rejected role change altered cached or later PCM"
    );
    assert_eq!(
        after_refusal, expected,
        "continued output must retain the original Left mapping"
    );
}

#[test]
fn actual_left_role_program_submission_remains_retained_until_ack() {
    let board = role_board("S5");
    for ack in [true, false] {
        let mut rig = role_fixture(&board, ChannelRole::LeftMono, 512).unwrap();
        role_activate(&mut rig, &board);
        enqueue_role_audio(&mut rig, 512);
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        let mut program_slot = None;
        for step in 0..5000_u64 {
            rig.local_now
                .set(rig.start_local_ns - 15_000_000 + step * 100_000);
            assert!(matches!(
                rig.owner.render_step(&mut timing).unwrap(),
                PlaybackStep::Render(_)
            ));
            let captures = rig.probe.captured_submissions();
            if captures.len() > 1 && captures.last().unwrap().iter().any(|byte| *byte != 0) {
                let calls = rig.probe.calls();
                let slot = calls
                    .iter()
                    .rev()
                    .find_map(|call| match call {
                        FakeCall::SubmitRetained {
                            slot, generation, ..
                        } => Some((*slot, *generation)),
                        _ => None,
                    })
                    .expect("actual program submission must name a retained slot");
                assert!(
                    rig.probe.pending_slots().contains(&slot),
                    "the exact nonzero submission must still be in backend custody"
                );
                program_slot = Some(slot);
                break;
            }
        }
        let slot = program_slot.expect("actual nonzero role-mapped PCM submission");
        rig.probe.set_lose_completions(true);
        let captured = rig.probe.captured_submissions();
        let held = rig.probe.pending_slots();
        assert!(held.contains(&slot));
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        let pulled = rig.owner.received_frames_pulled();
        assert!(pulled > 0);
        rig.suppress_flush.set(!ack);
        assert!(matches!(
            rig.owner.request_stop(),
            Ok(RenderApplication::Stopping)
        ));
        assert_eq!(rig.owner.render_state(), RenderState::Draining);
        assert!(rig.probe.pending_slots().contains(&slot));
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        let stop = finish_drain(&mut rig.owner);
        assert_eq!(stop.acknowledged, ack);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.captured_submissions(), captured);
        if ack {
            assert_eq!(rig.probe.pending(), 0);
            assert!(!rig.probe.pending_slots().contains(&slot));
        } else {
            assert!(rig.probe.pending_slots().contains(&slot));
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        }
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

/// Explicitly prepared and silence-primed retained model, so readiness checks
/// observe the same real HAL prerequisite as the co-owner rather than a flag.
fn retained_ready_renderer(board: &BoardProfile) -> (RenderLoop<RetainedPurge>, FakeProbe) {
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: u32::from(board.hardware_channels),
        bytes_per_sample: 2,
    };
    cfg.min_submission_lead_ticks = Some(6);
    cfg.completion_delay_ticks = 100;
    cfg.flush_ack_delay_ticks = Some(3);
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(8);
    let backend = RetainedPurge {
        inner: backend,
        capable: true,
        suppress_next_flush: Rc::new(Cell::new(false)),
        flush_requests: Rc::new(Cell::new(0)),
    };
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut hal = HalSession::open(board.clone(), backend, config).unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(
        hal.prime_silence().unwrap().accepted_bytes,
        RENDER_FRAMES * usize::from(board.hardware_channels) * 2
    );
    let calibration = synthetic_calibration_for(board);
    let dsp = ProtectedBoardDsp::admit(
        board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    (
        RenderLoop::new(
            hal,
            dsp,
            DriftResampler::new(ResamplerConfig::default()).unwrap(),
            config,
        )
        .unwrap(),
        probe,
    )
}

#[test]
fn retained_readiness_requires_matching_installed_profile_and_no_pending_switch() {
    let board = role_board("S5");
    let mut different = board.clone();
    different.calibrated_output_delay_us += 1;
    different = different.with_computed_digest();
    assert_eq!(board.profile_id, different.profile_id);
    assert_ne!(board.integrity_sha256, different.integrity_sha256);
    for mode in 0..3 {
        let (mut render, probe) = retained_ready_renderer(&board);
        assert!(
            render.prepared_join_ready(),
            "matching, primed profile must be ready"
        );
        let held = probe.pending_slots();
        assert_eq!(held.len(), 1);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        match mode {
            0 => {}
            1 => {
                let calibration = synthetic_calibration_for(&different);
                *render.dsp_mut() = ProtectedBoardDsp::admit(
                    &different,
                    Some(&calibration),
                    ProtectionAdmission::HostSimulation,
                );
            }
            2 => {
                let calibration = synthetic_calibration_for(&board);
                render
                    .dsp_mut()
                    .request_profile_switch(
                        &board,
                        &calibration,
                        ProtectionAdmission::HostSimulation,
                    )
                    .unwrap();
                assert!(render.dsp_mut().has_pending_switch());
            }
            _ => unreachable!(),
        }
        let before_calls = probe.calls();
        let before_output = probe.captured_submissions();
        assert_eq!(
            render.prepared_join_ready(),
            mode == 0,
            "readiness must reject replaced wrong-profile and pending-switch DSPs"
        );
        assert_eq!(
            probe.calls(),
            before_calls,
            "read-only readiness must not drive the HAL"
        );
        assert_eq!(probe.pending_slots(), held);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        assert_eq!(probe.captured_submissions(), before_output);
        assert!(!probe.calls().contains(&FakeCall::Start));
        if mode == 2 {
            assert!(render.dsp_mut().has_pending_switch());
        }
        // Restore only for deterministic fixture cleanup; this is not claimed
        // as runtime recovery or proof that a mismatched DSP was admitted.
        if mode != 0 {
            let calibration = synthetic_calibration_for(&board);
            *render.dsp_mut() = ProtectedBoardDsp::admit(
                &board,
                Some(&calibration),
                ProtectionAdmission::HostSimulation,
            );
        }
        render.cancel_prepared().unwrap();
        let mut source = PreparedPcm::new(1024, 0, 512, CLOCK_ORIGIN);
        let mut timing = ScriptedTiming::default();
        for _ in 0..20 {
            if render.state() != RenderState::Draining {
                break;
            }
            let tick = render.tick(&mut source, &mut timing);
            assert_eq!(tick.started, None);
        }
        assert_eq!(render.state(), RenderState::Stopped);
        assert!(render.stop_report().acknowledged);
        assert_eq!(probe.pending(), 0);
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
    }
}

/// Independent retained-HAL cleanup controls. The invalid DSP stays installed
/// through the complete cancel path; this is a scripted host model, not hardware.
type CancelDrainFixture = (
    RenderLoop<RetainedPurge>,
    FakeProbe,
    Rc<Cell<bool>>,
    Rc<Cell<u32>>,
);

fn cancel_drain_fixture(board: &BoardProfile) -> CancelDrainFixture {
    let mut cfg = FakeConfig::retained();
    cfg.geometry = RawGeometry {
        ring_depth: 4,
        frames_per_block: 64,
        channels: u32::from(board.hardware_channels),
        bytes_per_sample: 2,
    };
    cfg.min_submission_lead_ticks = Some(6);
    cfg.completion_delay_ticks = 100;
    cfg.flush_ack_delay_ticks = Some(3);
    cfg.stop_deadline_ticks = Some(8);
    let (backend, probe) = FakeBackend::new(cfg);
    probe.capture_submissions(8);
    probe.set_lose_completions(true);
    let suppress = Rc::new(Cell::new(false));
    let requests = Rc::new(Cell::new(0));
    let backend = RetainedPurge {
        inner: backend,
        capable: true,
        suppress_next_flush: Rc::clone(&suppress),
        flush_requests: Rc::clone(&requests),
    };
    let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
    let mut hal = HalSession::open(board.clone(), backend, config).unwrap();
    hal.prepare().unwrap();
    assert!(hal.abort_mute().unwrap().mute_acknowledged);
    hal.reset_device().unwrap();
    assert!(hal.silent_prepared_after_reset());
    assert_eq!(
        hal.prime_silence().unwrap().accepted_bytes,
        RENDER_FRAMES * usize::from(board.hardware_channels) * 2
    );
    let calibration = synthetic_calibration_for(board);
    let dsp = ProtectedBoardDsp::admit(
        board,
        Some(&calibration),
        ProtectionAdmission::HostSimulation,
    );
    let mut config = RenderConfig::standard(RENDER_FRAMES);
    config.window_ticks = 8;
    let render = RenderLoop::new(
        hal,
        dsp,
        DriftResampler::new(ResamplerConfig::default()).unwrap(),
        config,
    )
    .unwrap();
    (render, probe, suppress, requests)
}

#[derive(Default)]
struct CancelPullCounter(u64);
impl FrameSource for CancelPullCounter {
    fn pull(&mut self) -> Option<[f32; 2]> {
        self.0 += 1;
        Some([0.1, -0.1])
    }
}
impl crate::render::RenderSource for CancelPullCounter {
    fn starvation(&self) -> Option<crate::render::Starvation> {
        None
    }
}

fn install_invalid_cancel_dsp(
    render: &mut RenderLoop<RetainedPurge>,
    board: &BoardProfile,
    wrong_profile: bool,
) {
    if wrong_profile {
        let mut different = board.clone();
        different.calibrated_output_delay_us += 1;
        different = different.with_computed_digest();
        assert_eq!(board.profile_id, different.profile_id);
        assert_ne!(board.integrity_sha256, different.integrity_sha256);
        let calibration = synthetic_calibration_for(&different);
        *render.dsp_mut() = ProtectedBoardDsp::admit(
            &different,
            Some(&calibration),
            ProtectionAdmission::HostSimulation,
        );
        assert_eq!(
            render.dsp().profile_digest(),
            Some(different.integrity_sha256.as_bytes())
        );
    } else {
        *render.dsp_mut() =
            ProtectedBoardDsp::admit(board, None, ProtectionAdmission::HostSimulation);
        assert_eq!(render.dsp().profile_digest(), None);
    }
}

#[test]
fn invalid_dsp_cancel_drain_preserves_retained_ack_and_timeout_custody() {
    let board = role_board("S5");
    for active in [false, true] {
        for wrong_profile in [false, true] {
            for replace_after_cancel in [false, true] {
                for ack in [false, true] {
                    let (mut render, probe, suppress, requests) = cancel_drain_fixture(&board);
                    assert!(render.prepared_join_ready());
                    let token = probe
                        .calls()
                        .iter()
                        .rev()
                        .find_map(|call| match call {
                            FakeCall::SubmitRetained {
                                slot, generation, ..
                            } => Some((*slot, *generation)),
                            _ => None,
                        })
                        .expect("the HAL must actually submit its silent prime");
                    assert_eq!(probe.pending_slots(), vec![token]);
                    assert_eq!(probe.kernel_touch_pending(), (1, 0));
                    let captured = probe.captured_submissions();
                    assert_eq!(
                        captured,
                        vec![vec![
                            0;
                            RENDER_FRAMES * usize::from(board.hardware_channels) * 2
                        ]]
                    );
                    if active {
                        render
                            .start(StartPreconditions {
                                presentation_mapping_installed: true,
                                safe_gain_installed: true,
                            })
                            .unwrap();
                    }
                    if !replace_after_cancel {
                        install_invalid_cancel_dsp(&mut render, &board, wrong_profile);
                    }
                    let old_requests = requests.get();
                    suppress.set(!ack);
                    if active {
                        render.cancel().unwrap();
                    } else {
                        render.cancel_prepared().unwrap();
                    }
                    assert_eq!(requests.get(), old_requests + 1);
                    assert_eq!(render.state(), RenderState::Draining);
                    if replace_after_cancel {
                        install_invalid_cancel_dsp(&mut render, &board, wrong_profile);
                    }
                    let installed_digest = render.dsp().profile_digest().map(<[u8]>::to_vec);
                    assert_ne!(
                        installed_digest.as_deref(),
                        Some(board.integrity_sha256.as_bytes())
                    );
                    assert_eq!(probe.pending_slots(), vec![token]);
                    assert_eq!(probe.kernel_touch_pending(), (1, 0));
                    let submissions = probe
                        .calls()
                        .iter()
                        .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
                        .count();
                    let mut source = CancelPullCounter::default();
                    let mut timing = ScriptedTiming::default();
                    for _ in 0..20 {
                        if render.state() != RenderState::Draining {
                            break;
                        }
                        let tick = render.tick(&mut source, &mut timing);
                        assert_eq!(tick.started, None);
                        assert_eq!(source.0, 0);
                        assert_eq!(
                            probe
                                .calls()
                                .iter()
                                .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
                                .count(),
                            submissions
                        );
                        assert_eq!(probe.captured_submissions(), captured);
                        assert_eq!(render.dsp().profile_digest(), installed_digest.as_deref());
                        if render.state() == RenderState::Draining {
                            assert_eq!(probe.pending_slots(), vec![token]);
                            assert_eq!(probe.kernel_touch_pending(), (1, 0));
                        }
                    }
                    assert_eq!(render.stop_report().acknowledged, ack);
                    if ack {
                        assert_eq!(render.state(), RenderState::Stopped);
                        assert_eq!(probe.pending(), 0);
                        assert!(!probe.pending_slots().contains(&token));
                    } else {
                        assert_eq!(render.state(), RenderState::Faulted);
                        assert_eq!(
                            render.fault(),
                            Some(crate::render::FaultReason::DrainTimedOut)
                        );
                        assert_eq!(probe.pending_slots(), vec![token]);
                        assert_eq!(probe.kernel_touch_pending(), (1, 0));
                    }
                    assert_eq!(source.0, 0);
                    assert_eq!(probe.use_after_free(), 0);
                    assert_eq!(probe.modified_while_owned(), 0);
                }
            }
        }
    }
}

#[test]
fn invalid_dsp_graceful_drain_still_refuses_before_source_or_submit() {
    let board = role_board("S5");
    for wrong_profile in [false, true] {
        let (mut render, probe, _, _) = cancel_drain_fixture(&board);
        render
            .start(StartPreconditions {
                presentation_mapping_installed: true,
                safe_gain_installed: true,
            })
            .unwrap();
        render.stop().unwrap();
        assert_eq!(render.state(), RenderState::Draining);
        let held = probe.pending_slots();
        assert_eq!(held.len(), 1);
        let captured = probe.captured_submissions();
        let submissions = probe
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
            .count();
        install_invalid_cancel_dsp(&mut render, &board, wrong_profile);
        let mut source = CancelPullCounter::default();
        let tick = render.tick(&mut source, &mut ScriptedTiming::default());
        assert_eq!(tick.started, None);
        assert_eq!(source.0, 0);
        assert_eq!(render.state(), RenderState::Faulted);
        assert_eq!(
            render.fault(),
            Some(crate::render::FaultReason::ProtectionFault)
        );
        assert!(!render.stop_report().acknowledged);
        assert_eq!(probe.pending_slots(), held);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        assert_eq!(probe.captured_submissions(), captured);
        assert_eq!(
            probe
                .calls()
                .iter()
                .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
                .count(),
            submissions
        );
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
    }
}
