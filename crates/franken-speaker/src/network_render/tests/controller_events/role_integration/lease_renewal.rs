// Trusted local renewal controls; localhost media and retained fake HAL only.
use super::*;

const OLD_EXPIRY: u64 = CLOCK_ORIGIN + 1_048_000_000;
const PUBLICATION_BUDGET: u64 = 10_000;

fn finite_owner(expiry: u64) -> ControllerRig {
    let board = role_board("S5");
    let mut rig = role_fixture_with_lease(
        &board,
        ChannelRole::Stereo,
        512,
        PriorSwitch::None,
        Some(expiry),
    )
    .unwrap();
    rig.owner.require_output_grants().unwrap();
    role_activate(&mut rig, &board);
    rig
}

fn exercise_renewal_and_pcm(reject_first: bool) {
    let board = role_board("S5");
    let mut rig = finite_owner(OLD_EXPIRY);
    enqueue_role_audio(&mut rig, 512);
    let start_frame = rig.start_group_ns * 48_000 / 1_000_000_000;
    let granted = start_frame + 2048;
    assert_eq!(
        rig.owner.grant_output(&rig.token, granted).unwrap(),
        granted
    );
    let old = rig.token.clone();
    let new_expiry = OLD_EXPIRY + 200_000_000;
    if reject_first {
        let mut wrong = old.clone();
        wrong.issuer_id = "other".into();
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&wrong, new_expiry, PUBLICATION_BUDGET),
            Err(OwnerError::Binding)
        ));
        wrong = old.clone();
        wrong.expires_at_ns -= 1;
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&wrong, new_expiry, PUBLICATION_BUDGET),
            Err(OwnerError::Binding)
        ));
        wrong = old.clone();
        wrong.group_id = "other".into();
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&wrong, new_expiry, PUBLICATION_BUDGET),
            Err(OwnerError::Binding)
        ));
        wrong = old.clone();
        wrong.epoch += 1;
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&wrong, new_expiry, PUBLICATION_BUDGET),
            Err(OwnerError::Binding)
        ));
        assert!(matches!(
            rig.owner.renew_owned_lease(&old, new_expiry, 0),
            Err(OwnerError::Binding)
        ));
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&old, OLD_EXPIRY, PUBLICATION_BUDGET),
            Err(OwnerError::Membership(_))
        ));
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&old, OLD_EXPIRY - 1, PUBLICATION_BUDGET),
            Err(OwnerError::Membership(_))
        ));
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&old, u64::MAX, PUBLICATION_BUDGET),
            Err(OwnerError::Membership(_))
        ));
        assert!(matches!(
            rig.owner.renew_owned_lease(&old, new_expiry, 1_000_000_000),
            Err(OwnerError::RenewalTooLate)
        ));
        assert!(matches!(
            rig.owner.renew_owned_lease(&old, new_expiry, u64::MAX),
            Err(OwnerError::RenewalTooLate)
        ));
        assert!(matches!(
            rig.owner.renew_owned_lease(&old, new_expiry, u64::MAX),
            Err(OwnerError::RenewalTooLate)
        ));
        let reference = network();
        let latest = reference.clock.group_ns(rig.local_now.get()).unwrap()
            + reference
                .clock
                .report(rig.local_now.get())
                .uncertainty_ns
                .unwrap();
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&old, new_expiry, OLD_EXPIRY - latest),
            Err(OwnerError::RenewalTooLate)
        ));
        assert_eq!(rig.owner.grant_output(&old, granted).unwrap(), granted);
    }
    let renewed = rig
        .owner
        .renew_owned_lease(&old, new_expiry, PUBLICATION_BUDGET)
        .unwrap();
    assert_eq!(renewed.group_id, old.group_id);
    assert_eq!(renewed.issuer_id, old.issuer_id);
    assert_eq!(renewed.epoch, old.epoch);
    assert_eq!(renewed.expires_at_ns, new_expiry);
    assert!(matches!(
        rig.owner.grant_output(&old, granted + 64),
        Err(OwnerError::Binding)
    ));
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&old, new_expiry + 1, PUBLICATION_BUDGET),
        Err(OwnerError::Binding)
    ));
    // A smaller grant returns the previously granted end; renewal itself did
    // not silently extend it. The returned token can explicitly extend it.
    assert_eq!(
        rig.owner.grant_output(&renewed, start_frame + 1).unwrap(),
        granted
    );
    assert_eq!(
        rig.owner.grant_output(&renewed, granted + 256).unwrap(),
        granted + 256
    );

    // Independent same-calibration clock computes a local instant whose
    // earliest possible group time has definitely passed the original lease.
    let reference = network();
    let after_old = reference
        .clock
        .local_for_group(OLD_EXPIRY + 2_000_000, reference.now.get())
        .unwrap();
    let lower = reference.clock.group_ns(after_old).unwrap()
        - reference.clock.report(after_old).uncertainty_ns.unwrap();
    assert!(lower > OLD_EXPIRY);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    let mut after_expiry_submission = false;
    let mut draining = false;
    for step in 0..5000_u64 {
        let local = rig.start_local_ns - 15_000_000 + step * 100_000;
        rig.local_now.set(local);
        let before = rig.probe.captured_submissions().len();
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        let captured = rig.probe.captured_submissions();
        if local >= after_old
            && captured.len() > before
            && captured.last().unwrap().iter().any(|byte| *byte != 0)
        {
            after_expiry_submission = true;
        }
        if rig.owner.render_state() == RenderState::Draining {
            draining = true;
            break;
        }
    }
    assert!(
        after_expiry_submission,
        "nonzero protected PCM must be submitted after the original lease expires"
    );
    assert!(draining);
    let drained = finish_drain(&mut rig.owner);
    assert!(drained.acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), 512);
    let captured = rig.probe.captured_submissions();
    let (expected, reference_frames) = expected_role_pcm(&board, ChannelRole::Stereo, 512);
    assert!(reference_frames >= 512);
    assert_eq!(captured[1..], expected);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    println!(
        "FFW_LEASE_RENEWAL_PCM rejected_first={reject_first} source_frames={} protected_blocks={} after_old_expiry={after_expiry_submission} drain_ack={}",
        rig.owner.received_frames_pulled(),
        captured.len() - 1,
        drained.acknowledged
    );
}

#[test]
fn timely_renewal_continues_real_protected_pcm_past_old_expiry() {
    exercise_renewal_and_pcm(false);
}

#[test]
fn rejected_renewals_preserve_all_live_copies_and_real_playback() {
    exercise_renewal_and_pcm(true);
}

#[test]
fn renewal_does_not_issue_output_grant() {
    let mut rig = finite_owner(OLD_EXPIRY);
    enqueue_role_audio(&mut rig, 512);
    let renewed = rig
        .owner
        .renew_owned_lease(&rig.token, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET)
        .unwrap();
    let captured = rig.probe.captured_submissions();
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
    assert_eq!(rig.probe.captured_submissions(), captured);
    let end = rig.start_group_ns * 48_000 / 1_000_000_000 + 2048;
    assert_eq!(rig.owner.grant_output(&renewed, end).unwrap(), end);
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
    let captured = rig.probe.captured_submissions();
    assert!(captured[1..].iter().flatten().any(|byte| *byte != 0));
    let (expected, _) = expected_role_pcm(&role_board("S5"), ChannelRole::Stereo, 512);
    assert_eq!(captured[1..], expected);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn expired_lease_clock_fault_and_stop_do_not_revive() {
    for case in 0..3 {
        let mut rig = finite_owner(OLD_EXPIRY);
        let old = rig.token.clone();
        let captured = rig.probe.captured_submissions();
        match case {
            0 => {
                rig.local_now.set(1_100_000_000);
                assert!(matches!(
                    rig.owner
                        .renew_owned_lease(&old, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET),
                    Err(OwnerError::LeaseExpired)
                ));
            }
            1 => {
                rig.clock_fail.set(true);
                assert!(matches!(
                    rig.owner
                        .renew_owned_lease(&old, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET),
                    Err(OwnerError::Render(NetworkRenderError::Clock))
                ));
                rig.clock_fail.set(false);
            }
            _ => {
                rig.owner.request_stop().unwrap();
                assert!(matches!(
                    rig.owner
                        .renew_owned_lease(&old, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET),
                    Err(OwnerError::Binding)
                ));
            }
        }
        assert!(matches!(
            rig.owner
                .renew_owned_lease(&old, OLD_EXPIRY + 300_000_000, PUBLICATION_BUDGET),
            Err(OwnerError::Binding)
        ));
        assert_eq!(rig.owner.received_frames_pulled(), 0);
        assert_eq!(rig.probe.captured_submissions(), captured);
        assert!(finish_drain(&mut rig.owner).acknowledged);
        assert_eq!(rig.probe.pending(), 0);
        assert_eq!(rig.probe.use_after_free(), 0);
        assert_eq!(rig.probe.modified_while_owned(), 0);
    }
}

#[test]
fn unchanged_n03_authority_expiry_still_stops_renewed_owner() {
    let mut rig = finite_owner(OLD_EXPIRY);
    let old = rig.token.clone();
    let renewed = rig
        .owner
        .renew_owned_lease(&old, OLD_EXPIRY + 3_000_000_000, PUBLICATION_BUDGET)
        .unwrap();
    // The fixture's independently admitted N03 authority ends at start+2 s;
    // the renewed group lease is still later than that instant.
    let local_after_n03 = rig.start_local_ns + 2_000_000_001;
    let reference = network();
    assert!(matches!(
        reference
            .clock
            .holdover(local_after_n03 - 2)
            .unwrap()
            .binding,
        franken_clock::group::Binding::Authority
    ));
    assert_eq!(
        reference.clock.status(local_after_n03 - 2),
        franken_clock::group::ClockStatus::Holdover
    );
    assert_eq!(
        reference.clock.status(local_after_n03),
        franken_clock::group::ClockStatus::Expired
    );
    let latest = reference.clock.group_ns(local_after_n03).unwrap()
        + reference
            .clock
            .report(local_after_n03)
            .uncertainty_ns
            .unwrap();
    assert!(latest < renewed.expires_at_ns);
    rig.local_now.set(local_after_n03);
    let captured = rig.probe.captured_submissions();
    let mut timing = ScriptedTiming::default();
    assert!(matches!(
        rig.owner.render_step(&mut timing),
        Err(OwnerError::Render(NetworkRenderError::Clock))
    ));
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&renewed, renewed.expires_at_ns + 1, PUBLICATION_BUDGET),
        Err(OwnerError::Binding)
    ));
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn old_lease_expiring_on_final_renewal_clock_sample_cannot_revive() {
    const STEP: u64 = 100_000;
    let parts = prepared_parts(true, 2);
    let advance = Rc::clone(&parts.network.platform.ops().advance_after_read_ns);
    let base = 600_000_000;
    let clock = &parts.network.clock;
    let upper =
        |local| clock.group_ns(local).unwrap() + clock.report(local).uncertainty_ns.unwrap();
    let expiry = upper(base + 2 * STEP);
    assert!(upper(base) < expiry);
    let session = UnifiedGroupSession::new("grp", "coord", TEST_EPOCH);
    let token = AuthorityToken::issue(&session, expiry);
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
    let held = rig.probe.pending();
    let captured = rig.probe.captured_submissions();
    advance.set(STEP);
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&rig.token, expiry + 1_000_000_000, PUBLICATION_BUDGET),
        Err(OwnerError::LeaseExpired)
    ));
    // Reconcile, owned policy and the final renewal bounds each take one read.
    assert_eq!(rig.local_now.get(), base + 3 * STEP);
    advance.set(0);
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&rig.token, expiry + 1_000_000_000, PUBLICATION_BUDGET),
        Err(OwnerError::Binding)
    ));
    assert_eq!(rig.probe.pending(), held);
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn failed_durable_control_prevents_later_lease_renewal() {
    let mut rig = finite_owner(OLD_EXPIRY);
    let captured = rig.probe.captured_submissions();
    rig.storage_fail.set(true);
    let command = test_wire(
        TEST_CONTROLLER,
        1,
        Some(1),
        ControlCommand::SetGroupVolume { volume: 90 },
    );
    assert!(matches!(
        rig.owner.receive(&command).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));
    let failed = rig.owner.step_control().unwrap();
    let error = failed
        .control
        .expect_err("injected storage write must fail");
    assert!(error.applied.is_empty());
    assert_eq!(error.withheld.len(), 1);
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&rig.token, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET),
        Err(OwnerError::Binding)
    ));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert_eq!(rig.probe.captured_submissions(), captured);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn stopped_owner_does_not_fabricate_a_missing_flush_ack() {
    let mut rig = finite_owner(OLD_EXPIRY);
    rig.probe.set_lose_completions(true);
    let held = rig.probe.pending_slots();
    assert!(!held.is_empty());
    rig.suppress_flush.set(true);
    rig.owner.request_stop().unwrap();
    assert!(matches!(
        rig.owner
            .renew_owned_lease(&rig.token, OLD_EXPIRY + 200_000_000, PUBLICATION_BUDGET),
        Err(OwnerError::Binding)
    ));
    let report = finish_drain(&mut rig.owner);
    assert!(!report.acknowledged);
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}
