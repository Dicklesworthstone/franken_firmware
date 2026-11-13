//! Fresh-provisioning configuration consistency, using the real journal and
//! retained fake HAL. This is not recovered-session or live authority proof.
use super::*;
use crate::settled_render::AdmissionError;

fn fleet_with_binding(
    binding: Option<(&str, &str, ChannelRole)>,
) -> (TestFleet, Endpoint, Rc<Cell<bool>>, AuthorityToken) {
    let (mut control, soap, storage_fail) = test_fleet_unleased();
    let coordinator = test_peer("coord");
    control
        .admit(
            &coordinator,
            PeerRole::Controller,
            &test_key("coord"),
            Some(TEST_EPOCH),
            1,
        )
        .unwrap();
    assert!(control.authority().version_of(&coordinator).is_some());
    if let Some((member, profile_id, role)) = binding {
        control
            .provision_recovery_binding("grp", &coordinator, [7; 16], member, profile_id, role)
            .unwrap();
        let stored = control.recovery_binding().unwrap().unwrap();
        assert_eq!(stored.group_id(), "grp");
        assert_eq!(stored.configured_issuer(), &coordinator);
        assert_eq!(stored.member_id(), member);
        assert_eq!(stored.profile_id(), profile_id);
        assert_eq!(stored.role(), role);
    } else {
        assert_eq!(control.recovery_binding().unwrap(), None);
    }
    // This is the original explicit fresh-provisioning token, not a claim
    // that a persisted binding authenticates a current recovered authority.
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, u64::MAX);
    (control, soap, storage_fail, token)
}

fn binding_rig(binding: bool) -> ControllerRig {
    let profile_id = profile().profile_id;
    let binding = binding.then_some((TEST_MEMBER, profile_id.as_str(), ChannelRole::Stereo));
    let (control, soap, storage_fail, token) = fleet_with_binding(binding);
    let bundle = provision_bundle(control, token.clone()).unwrap();
    let parts = prepared_parts(true, 2);
    assert_eq!(parts.network.received_frames_pulled(), 0);
    let owner =
        SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7).unwrap();
    ControllerRig {
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
    }
}

#[test]
fn fresh_stored_binding_and_absence_both_reach_join_and_protected_pcm() {
    for binding in [false, true] {
        let mut rig = binding_rig(binding);
        rig.probe.capture_submissions(128);
        assert_eq!(rig.owner.received_frames_pulled(), 0);
        assert!(!rig.probe.calls().contains(&FakeCall::Start));
        assert!(!rig.probe.calls().contains(&FakeCall::SetMute(false)));
        assert_eq!(
            rig.probe.captured_submissions(),
            vec![vec![0; RENDER_FRAMES * 4]]
        );
        // The helper performs an actual proposal, local ACK, commit, clock
        // cutover and authenticated localhost media delivery.
        activate_for_media(&mut rig);
        let mut timing = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        let mut nonzero = false;
        for step in 0..5000_u64 {
            rig.local_now
                .set(rig.start_local_ns - 15_000_000 + step * 100_000);
            assert!(matches!(
                rig.owner.render_step(&mut timing).unwrap(),
                PlaybackStep::Render(_)
            ));
            if rig
                .probe
                .captured_submissions()
                .iter()
                .skip(1)
                .flatten()
                .any(|b| *b != 0)
            {
                nonzero = true;
                break;
            }
        }
        assert!(
            nonzero,
            "binding={binding}: actual protected submission must be nonzero"
        );
        assert!(rig.probe.calls().contains(&FakeCall::Start));
        assert!(rig.owner.received_frames_pulled() > 0);
        assert!(rig.owner.request_stop().is_ok());
        assert!(finish_drain(&mut rig.owner).acknowledged);
        assert_eq!(rig.probe.pending(), 0);
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

#[test]
fn fresh_binding_member_profile_and_role_mismatches_refuse_before_start() {
    let profile_id = profile().profile_id;
    for (member, stored_profile, role) in [
        ("other-member", profile_id.as_str(), ChannelRole::Stereo),
        (TEST_MEMBER, "other-profile", ChannelRole::Stereo),
        (TEST_MEMBER, profile_id.as_str(), ChannelRole::LeftMono),
    ] {
        let (control, soap, _, token) = fleet_with_binding(Some((member, stored_profile, role)));
        let bundle = provision_bundle(control, token).unwrap();
        let parts = prepared_parts(true, 2);
        assert_eq!(parts.network.received_frames_pulled(), 0);
        assert_eq!(parts.network.concealed_frames_pulled(), 0);
        let probe = parts.probe.clone();
        let held = probe.pending_slots();
        assert_eq!(held.len(), 1);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        let captured = probe.captured_submissions();
        assert_eq!(captured, vec![vec![0; RENDER_FRAMES * 4]]);
        let submissions = probe
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
            .count();
        assert!(matches!(
            SettledRender::admit_fresh_group(bundle, soap, parts.network, pending_member(), 7),
            Err(AdmissionError::Binding)
        ));
        assert!(!probe.calls().contains(&FakeCall::Start));
        assert!(!probe.calls().contains(&FakeCall::SetMute(false)));
        assert_eq!(
            probe
                .calls()
                .iter()
                .filter(|call| matches!(call, FakeCall::SubmitRetained { .. }))
                .count(),
            submissions
        );
        assert_eq!(probe.captured_submissions(), captured);
        // The refused by-value owner was dropped without a flush ACK. The
        // actual primed token must remain readable, not silently freed.
        assert_eq!(probe.pending_slots(), held);
        assert_eq!(probe.kernel_touch_pending(), (1, 0));
        assert_eq!(probe.use_after_free(), 0);
        assert_eq!(probe.modified_while_owned(), 0);
    }
}
