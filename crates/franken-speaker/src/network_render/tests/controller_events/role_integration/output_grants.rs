// Opt-in grants exercised through the real fresh-group and playback owners.
use super::*;

#[test]
fn fresh_owner_requires_whole_block_grant_then_renders_protected_pcm() {
    for role in [ChannelRole::Stereo, ChannelRole::LeftMono] {
        let board = role_board("S5");
        let mut rig = role_fixture(&board, role, 512).unwrap();
        rig.owner.require_output_grants().unwrap();
        role_activate(&mut rig, &board);
        assert!(matches!(
            rig.owner.require_output_grants(),
            Err(OwnerError::JoinState)
        ));
        enqueue_role_audio(&mut rig, 512);
        let primed = rig.probe.captured_submissions();
        assert_eq!(primed.len(), 1);
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        rig.local_now.set(rig.start_local_ns - 10_500_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(OwnerStep::Waiting)
        ));
        assert_eq!(rig.owner.received_frames_pulled(), 0);
        assert_eq!(rig.probe.captured_submissions(), primed);

        let mut wrong = rig.token.clone();
        wrong.issuer_id = "other-coordinator".into();
        let start_frame = rig.start_group_ns * 48_000 / 1_000_000_000;
        assert!(matches!(
            rig.owner.grant_output(&wrong, start_frame + 2048),
            Err(OwnerError::Binding)
        ));
        // A half-open grant ending before the first 64-frame block ends is
        // insufficient even before accounting for clock uncertainty.
        assert_eq!(
            rig.owner
                .grant_output(&rig.token, start_frame + 63)
                .unwrap(),
            start_frame + 63
        );
        assert!(matches!(
            rig.owner.grant_output(&rig.token, u64::MAX),
            Err(OwnerError::Membership(_))
        ));
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(OwnerStep::Waiting)
        ));
        assert_eq!(rig.owner.received_frames_pulled(), 0);
        assert_eq!(rig.probe.captured_submissions(), primed);

        assert_eq!(
            rig.owner
                .grant_output(&rig.token, start_frame + 2048)
                .unwrap(),
            start_frame + 2048
        );
        let mut draining = false;
        for step in 0..5000_u64 {
            rig.local_now
                .set(rig.start_local_ns - 10_500_000 + step * 100_000);
            assert!(matches!(
                rig.owner.render_step(&mut timing).unwrap(),
                PlaybackStep::Render(_)
            ));
            if rig.owner.render_state() == RenderState::Draining {
                draining = true;
                break;
            }
        }
        assert!(draining);
        assert!(finish_drain(&mut rig.owner).acknowledged);
        assert_eq!(rig.owner.received_frames_pulled(), 512);
        let captured = rig.probe.captured_submissions();
        let (expected, reference_frames) = expected_role_pcm(&board, role, 512);
        assert!(reference_frames >= 512);
        assert!(expected.iter().flatten().any(|byte| *byte != 0));
        assert_eq!(captured[1..], expected);
        assert_eq!(rig.probe.pending(), 0);
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
        println!(
            "FFW_OUTPUT_GRANT_ROLE: role={role:?} checked_source_frames={} protected_blocks={} nonzero=true drain_ack=true",
            rig.owner.received_frames_pulled(),
            captured.len() - 1
        );
    }
}

#[test]
fn expired_fresh_owner_authority_cannot_issue_or_render() {
    let parts = prepared_parts(true, 2);
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, CLOCK_ORIGIN + 1_200_000_000);
    let (control, soap, storage_fail) = test_fleet_unleased();
    let bundle = provision_bundle(control, token.clone()).unwrap();
    let owner =
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7).unwrap();
    let mut rig = ControllerRig {
        owner,
        clock_fail: parts.clock_fail,
        local_now: parts.local_now,
        suppress_flush: parts.suppress_flush,
        flush_requests: parts.flush_requests,
        storage_fail,
        token,
        probe: parts.probe,
        socket: parts.socket,
        address: parts.address,
        sender: parts.sender,
        start_group_ns: parts.start_group_ns,
        start_local_ns: parts.start_local_ns,
    };
    rig.owner.require_output_grants().unwrap();
    role_activate(&mut rig, &profile());
    let captured = rig.probe.captured_submissions();
    rig.local_now.set(1_250_000_000);
    let start_frame = rig.start_group_ns * 48_000 / 1_000_000_000;
    assert!(matches!(
        rig.owner.grant_output(&rig.token, start_frame + 2048),
        Err(OwnerError::LeaseExpired)
    ));
    let mut timing = ScriptedTiming::default();
    assert!(matches!(
        rig.owner.render_step(&mut timing),
        Ok(PlaybackStep::Stopping)
    ));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn real_owner_rechecks_lease_across_prepare_with_live_pcm_control() {
    const ADVANCE_NS: u64 = 100_000;
    for expires_during_prepare in [true, false] {
        let parts = prepared_parts(true, 2);
        let advance = Rc::clone(&parts.network.platform.ops().advance_after_read_ns);
        let base = parts.start_local_ns - 10_500_000;
        let clock = &parts.network.clock;
        let upper =
            |local| clock.group_ns(local).unwrap() + clock.report(local).uncertainty_ns.unwrap();
        let before_prepare = upper(base + 2 * ADVANCE_NS);
        let during_prepare = upper(base + 3 * ADVANCE_NS);
        let after_prepare = upper(base + 4 * ADVANCE_NS);
        // The same N03 clock remains within its independently admitted
        // authority. Only the canonical/control/join lease is varied.
        assert!(base + 5 * ADVANCE_NS < parts.start_local_ns + 2_000_000_000);
        let expires_at = if expires_during_prepare {
            during_prepare
        } else {
            after_prepare + 200_000_000
        };
        assert!(before_prepare < expires_at);
        assert_eq!(after_prepare >= expires_at, expires_during_prepare);
        let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
        let token = AuthorityToken::issue(&session, expires_at);
        let (control, soap, storage_fail) = test_fleet_unleased();
        let bundle = provision_bundle(control, token.clone()).unwrap();
        let owner =
            SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7)
                .unwrap();
        let mut rig = ControllerRig {
            owner,
            clock_fail: parts.clock_fail,
            local_now: parts.local_now,
            suppress_flush: parts.suppress_flush,
            flush_requests: parts.flush_requests,
            storage_fail,
            token,
            probe: parts.probe,
            socket: parts.socket,
            address: parts.address,
            sender: parts.sender,
            start_group_ns: parts.start_group_ns,
            start_local_ns: parts.start_local_ns,
        };
        rig.owner.require_output_grants().unwrap();
        role_activate(&mut rig, &profile());
        enqueue_role_audio(&mut rig, 512);
        rig.local_now.set(base);
        let end = rig.start_group_ns * 48_000 / 1_000_000_000 + 2048;
        assert_eq!(rig.owner.grant_output(&rig.token, end).unwrap(), end);
        let held = rig.probe.pending();
        let primed = rig.probe.captured_submissions();
        assert_eq!(held, 1);
        assert_eq!(primed.len(), 1);
        advance.set(ADVANCE_NS);
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        let result = rig.owner.render_step(&mut timing);
        // Reconcile, owned-policy readiness, pre-gate, actual N04 prepare,
        // and post-gate each read the scripted monotonic clock once.
        assert_eq!(rig.local_now.get(), base + 5 * ADVANCE_NS);
        advance.set(0);
        if expires_during_prepare {
            assert!(matches!(result, Err(OwnerError::LeaseExpired)));
            assert_eq!(rig.owner.render_state(), RenderState::Draining);
            assert_eq!(rig.owner.received_frames_pulled(), 0);
            assert_eq!(rig.probe.pending(), held);
            assert_eq!(rig.probe.captured_submissions(), primed);
            assert!(matches!(
                rig.owner.grant_output(&rig.token, end + 64),
                Err(OwnerError::Binding)
            ));
            assert!(matches!(
                rig.owner.render_step(&mut timing),
                Ok(PlaybackStep::Stopping)
            ));
            assert_eq!(rig.probe.pending(), held, "stop is not the flush ACK");
            assert!(finish_drain(&mut rig.owner).acknowledged);
            assert_eq!(rig.probe.pending(), 0);
            assert_eq!(rig.probe.captured_submissions(), primed);
        } else {
            assert!(matches!(
                result,
                Ok(PlaybackStep::Render(OwnerStep::Waiting))
            ));
            let mut submitted = false;
            for step in 5..400_u64 {
                rig.local_now.set(base + step * ADVANCE_NS);
                assert!(matches!(
                    rig.owner.render_step(&mut timing).unwrap(),
                    PlaybackStep::Render(_)
                ));
                if rig.probe.captured_submissions().len() > 1 {
                    submitted = true;
                    break;
                }
            }
            assert!(
                submitted,
                "live lease and grant must submit real protected PCM"
            );
            let captured = rig.probe.captured_submissions();
            assert!(captured[1].iter().any(|byte| *byte != 0));
            let (expected, _) = expected_role_pcm(&profile(), ChannelRole::Stereo, 512);
            assert_eq!(captured[1], expected[0]);
            assert!(rig.owner.received_frames_pulled() > 0);
            rig.owner.request_stop().unwrap();
            assert!(finish_drain(&mut rig.owner).acknowledged);
            assert_eq!(rig.probe.pending(), 0);
        }
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}
