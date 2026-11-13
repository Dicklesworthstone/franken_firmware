//! G03 localhost TCP -> bounded handoff -> single protected owner controls.
//! The PCM backend, credentials and member are public host fixtures; this is
//! not a physical device, provider, external client or reboot qualification.
use super::*;
use crate::fsonos_loopback::{
    FsonosLoopback, LoopbackLimits, Policy, fixture_session_for, mailbox_control,
};
use crate::settled_http::{
    HttpMailboxClient, HttpMailboxConfig, HttpMailboxError, HttpMailboxOwner, HttpService,
    http_mailbox,
};
use franken_control::fsonos::{HttpRequest, Ingress, Service};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

fn loopback_with_mailbox(client: HttpMailboxClient) -> FsonosLoopback {
    loopback_with_policy(client, Policy::UnauthenticatedTailnet)
}

fn loopback_with_policy(client: HttpMailboxClient, policy: Policy) -> FsonosLoopback {
    // This only seeds the shim's legacy diagnostic slot. Assertions about a
    // session use a snapshot returned by the actual owner after a request.
    let initial = fixture_session_for(TEST_MEMBER, "neighbor").unwrap();
    let server = FsonosLoopback::start_with_control(
        initial,
        TEST_MEMBER,
        policy,
        LoopbackLimits::standard(),
        move |_, _, _| Ok(mailbox_control(client)),
    )
    .unwrap();
    assert!(server.addr().ip().is_loopback());
    server
}

/// Same real signed RequestBody/HMAC and HTTP framing as the existing fleet
/// loopback client. This raw localhost client is not the external fsonos client.
fn signed_http(seq: u64, revision: u64, value: u8, relative: bool, valid_proof: bool) -> String {
    let command = if relative {
        ControlCommand::AdjustMemberVolume {
            member_id: TEST_MEMBER.into(),
            delta: i8::try_from(value).unwrap(),
        }
    } else {
        ControlCommand::SetMemberVolume {
            member_id: TEST_MEMBER.into(),
            volume: value,
        }
    };
    let body = RequestBody::new(
        test_peer(TEST_CONTROLLER),
        seq,
        TEST_EPOCH,
        Some(revision),
        command,
    )
    .unwrap();
    let key = if valid_proof {
        test_key(TEST_CONTROLLER)
    } else {
        test_key("wrong-controller")
    };
    let proof: String = compute_proof(&key, &body.signing_bytes())
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let value_text = value.to_string();
    let service = Service::RenderingControl;
    let (action, arg) = if relative {
        ("SetRelativeVolume", "Adjustment")
    } else {
        ("SetVolume", "DesiredVolume")
    };
    let xml = crate::control_adapter::envelope(
        service,
        action,
        &[
            ("InstanceID", "0"),
            ("Channel", "Master"),
            (arg, value_text.as_str()),
        ],
    );
    format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nSOAPACTION: \"{}#{}\"\r\nX-Franken-Peer: {}\r\nX-Franken-Seq: {}\r\nX-Franken-Epoch: {}\r\nX-Franken-Revision: {}\r\nX-Franken-Proof: {}\r\nContent-Length: {}\r\n\r\n{}",
        service.control_path(),
        service.urn(),
        action,
        TEST_CONTROLLER,
        seq,
        TEST_EPOCH,
        revision,
        proof,
        xml.len(),
        xml
    )
}

fn tcp_request(addr: SocketAddr, wire: String) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(wire.as_bytes()).unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                assert!(response.len() <= 64 * 1024);
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("reading localhost HTTP response: {error}"),
        }
    }
    String::from_utf8(response).unwrap()
}
fn status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// TCP can wait on its own bounded worker while the actual non-Send render
/// owner remains on this test thread and explicitly services at most one item.
fn call_serviced(
    rig: &mut ControllerRig,
    mailbox: &mut HttpMailboxOwner,
    server: &FsonosLoopback,
    wire: String,
) -> String {
    let addr = server.addr();
    let client = thread::spawn(move || tcp_request(addr, wire));
    let until = Instant::now() + Duration::from_secs(3);
    let mut serviced = false;
    while Instant::now() < until {
        match rig.owner.service_http(mailbox).unwrap() {
            HttpService::Idle => thread::sleep(Duration::from_millis(1)),
            HttpService::Replied => {
                serviced = true;
                break;
            }
            other => panic!("request not served: {other:?}"),
        }
    }
    assert!(serviced, "bounded owner service must actually run");
    client.join().expect("client thread")
}

fn capture_complete_pcm(mut rig: ControllerRig) -> Vec<Vec<u8>> {
    rig.probe.capture_submissions(128);
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
    assert!(draining);
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), 512);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    let pcm = rig.probe.captured_submissions();
    assert!(pcm.len() > 1);
    pcm[1..].to_vec()
}

#[test]
fn real_http_signed_set_and_relative_retry_change_same_owner_protected_pcm_once() {
    let mut reference = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut reference);
    let baseline = capture_complete_pcm(reference);
    assert!(baseline.iter().flatten().any(|b| *b != 0));

    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    let config = HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap();
    let (client, mut mailbox) = http_mailbox(config).unwrap();
    let server = loopback_with_mailbox(client);

    let bad = call_serviced(
        &mut rig,
        &mut mailbox,
        &server,
        signed_http(1, 1, 65, false, false),
    );
    assert_eq!(
        status(&bad),
        401,
        "bad proof must be rejected by authentication"
    );
    assert_ne!(status(&bad), 200, "bad proof must not succeed");
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    let set = call_serviced(
        &mut rig,
        &mut mailbox,
        &server,
        signed_http(1, 1, 65, false, true),
    );
    assert_eq!(status(&set), 200);
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (2, 65)
    );
    let relative = signed_http(2, 2, 10, true, true);
    let first = call_serviced(&mut rig, &mut mailbox, &server, relative.clone());
    assert_eq!(status(&first), 200);
    assert!(first.contains("<NewVolume>75</NewVolume>"));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (3, 75)
    );
    let retry = call_serviced(&mut rig, &mut mailbox, &server, relative);
    assert_eq!(status(&retry), 200);
    assert!(retry.contains("<NewVolume>75</NewVolume>"));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (3, 75)
    );
    assert_eq!(rig.owner.received_frames_pulled(), 0);
    assert!(server.stop().reconciled());

    let controlled = capture_complete_pcm(rig);
    assert_eq!(controlled.len(), baseline.len());
    assert!(controlled.iter().flatten().any(|b| *b != 0));
    assert_ne!(
        controlled, baseline,
        "committed HTTP control must affect actual protected PCM"
    );
}

/// Require an actual nonzero accepted program slot and then withhold ordinary
/// completions so only an actual flush acknowledgement can release it.
fn retain_program_submission(rig: &mut ControllerRig) -> (u16, u32) {
    rig.probe.capture_submissions(128);
    let mut timing = ScriptedTiming {
        default_cost: 1,
        ..ScriptedTiming::default()
    };
    for step in 0..5000_u64 {
        rig.local_now
            .set(rig.start_local_ns - 15_000_000 + step * 100_000);
        assert!(matches!(
            rig.owner.render_step(&mut timing).unwrap(),
            PlaybackStep::Render(_)
        ));
        let pcm = rig.probe.captured_submissions();
        if pcm.len() > 1 && pcm.last().unwrap().iter().any(|byte| *byte != 0) {
            let calls = rig.probe.calls();
            let token = calls
                .iter()
                .rev()
                .find_map(|call| match call {
                    FakeCall::SubmitRetained {
                        slot, generation, ..
                    } => Some((*slot, *generation)),
                    _ => None,
                })
                .expect("actual retained program submit");
            assert!(rig.probe.pending_slots().contains(&token));
            assert!(rig.owner.received_frames_pulled() > 0);
            rig.probe.set_lose_completions(true);
            let held = rig.probe.pending_slots();
            assert!(held.contains(&token));
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
            return token;
        }
    }
    panic!("actual nonzero retained program output not submitted")
}

fn queued_request() -> HttpRequest<'static> {
    HttpRequest {
        method: "POST",
        path: "/fixture-control",
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::Tailnet,
        headers: &[],
        body: b"queued fixture",
    }
}

#[test]
fn full_mailbox_refuses_real_tcp_without_blocking_local_mute_or_acknowledged_stop() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let token = retain_program_submission(&mut rig);
    let original_held = rig.probe.pending_slots();
    let original_pulls = rig.owner.received_frames_pulled();
    let original_pcm = rig.probe.captured_submissions();
    assert!(original_held.contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_secs(1)).unwrap())
            .unwrap();
    let server = loopback_with_mailbox(client.clone());
    let request = queued_request();
    let held = client.submit(&request).unwrap();
    assert!(matches!(
        client.clone().submit(&request),
        Err(HttpMailboxError::Busy)
    ));
    let addr = server.addr();
    let busy = thread::spawn(move || tcp_request(addr, signed_http(1, 1, 65, false, true)))
        .join()
        .unwrap();
    assert_eq!(
        status(&busy),
        503,
        "full queue must not masquerade as success"
    );
    let pulls = rig.owner.received_frames_pulled();
    let pcm = rig.probe.captured_submissions();
    assert_eq!(pulls, original_pulls);
    assert_eq!(pcm, original_pcm);
    assert_eq!(rig.probe.pending_slots(), original_held);
    assert!(rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    assert!(matches!(
        rig.owner.local_mute(true),
        Ok(RenderApplication::PolicyAccepted)
    ));
    assert_eq!(
        rig.owner.effective_mute(),
        Some(franken_dsp::volume::MuteReason::Local)
    );
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.probe.pending_slots(), original_held);
    assert!(rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.probe.pending(), 0);
    assert!(!rig.probe.pending_slots().contains(&token));
    // The original request is still actually occupying the only permit after
    // the local mute and acknowledged stop; an expired slot is not enough.
    assert!(matches!(
        client.submit(&request),
        Err(HttpMailboxError::Busy)
    ));
    assert!(server.stop().reconciled());
    drop(held);
    // No owner poll is needed to reclaim a cancelled queued entry. Its
    // replacement is itself cancelled before being presented to the owner.
    let replacement = client.submit(&request).unwrap();
    drop(replacement);
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Expired
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn expired_handoff_is_outcome_unknown_and_does_not_block_local_mute_or_stop() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let token = retain_program_submission(&mut rig);
    let original_held = rig.probe.pending_slots();
    let original_pulls = rig.owner.received_frames_pulled();
    let original_pcm = rig.probe.captured_submissions();
    assert!(original_held.contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(1024, 8, Duration::from_millis(50)).unwrap()).unwrap();
    let server = loopback_with_mailbox(client.clone());
    let addr = server.addr();
    // No owner service runs: the actual TCP request reaches its bounded
    // deadline, and the HTTP response must not promise it was uncommitted.
    let expired = thread::spawn(move || tcp_request(addr, signed_http(1, 1, 65, false, true)))
        .join()
        .unwrap();
    assert_eq!(status(&expired), 504);
    assert!(
        expired
            .to_ascii_lowercase()
            .contains("x-franken-outcome: unknown")
    );
    let pulls = rig.owner.received_frames_pulled();
    let pcm = rig.probe.captured_submissions();
    assert_eq!(pulls, original_pulls);
    assert_eq!(pcm, original_pcm);
    assert_eq!(rig.probe.pending_slots(), original_held);
    assert!(rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    assert!(matches!(
        rig.owner.local_mute(true),
        Ok(RenderApplication::PolicyAccepted)
    ));
    assert_eq!(
        rig.owner.effective_mute(),
        Some(franken_dsp::volume::MuteReason::Local)
    );
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.probe.pending_slots(), original_held);
    assert!(rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (original_held.len(), 0));
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.probe.pending(), 0);
    assert!(!rig.probe.pending_slots().contains(&token));
    assert!(server.stop().reconciled());
    // The next submit reclaims the expired queue slot without an owner poll.
    let request = queued_request();
    let replacement = client.submit(&request).unwrap();
    drop(replacement);
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Expired
    );
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

fn event_http(method: &str) -> String {
    let event_path = Service::RenderingControl.event_path();
    let headers = match method {
        "SUBSCRIBE" => {
            "CALLBACK: <http://127.0.0.1:3400/events>\r\nNT: upnp:event\r\nTIMEOUT: Second-300\r\n"
        }
        "UNSUBSCRIBE" => "SID: uuid:00000000-0000-4000-8000-000000000001\r\n",
        _ => panic!("test only the two event methods"),
    };
    format!(
        "{method} {event_path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: 0\r\n\r\n"
    )
}

fn local_get_volume_http() -> String {
    let service = Service::RenderingControl;
    let xml = crate::control_adapter::envelope(
        service,
        "GetVolume",
        &[("InstanceID", "0"), ("Channel", "Master")],
    );
    format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nSOAPACTION: \"{}#GetVolume\"\r\nContent-Length: {}\r\n\r\n{}",
        service.control_path(),
        service.urn(),
        xml.len(),
        xml
    )
}

fn assert_no_sid(response: &str) {
    assert!(
        !response
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("sid:"))
    );
}

#[test]
fn tcp_event_methods_are_refused_without_mailbox_work_and_soap_still_reaches_owner() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let local = loopback_with_policy(client.clone(), Policy::LocalLink);
    // Seed the shim's diagnostic mirror from a genuine owner response before
    // comparing it; the startup fixture is not evidence of owner state.
    let read = call_serviced(&mut rig, &mut mailbox, &local, local_get_volume_http());
    assert_eq!(status(&read), 200);
    assert!(read.contains("<CurrentVolume>50</CurrentVolume>"));
    assert_eq!(
        local.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );
    let calls = rig.probe.calls();
    let pcm = rig.probe.captured_submissions();
    let held = rig.probe.pending_slots();
    let pulled = rig.owner.received_frames_pulled();
    let state = rig.owner.render_state();
    assert!(local.callback_report().is_none());
    for method in ["SUBSCRIBE", "UNSUBSCRIBE"] {
        let response = tcp_request(local.addr(), event_http(method));
        assert_eq!(
            status(&response),
            405,
            "{method} must be explicitly refused"
        );
        assert!(
            response
                .lines()
                .any(|line| line.eq_ignore_ascii_case("allow: POST"))
        );
        assert_no_sid(&response);
        assert_eq!(
            rig.owner.service_http(&mut mailbox).unwrap(),
            HttpService::Idle
        );
        assert_eq!(
            local.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
            (1, 50)
        );
        assert_eq!(rig.owner.render_state(), state);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.calls(), calls);
        assert_eq!(rig.probe.captured_submissions(), pcm);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        assert!(local.callback_report().is_none());
    }
    let read_after = call_serviced(&mut rig, &mut mailbox, &local, local_get_volume_http());
    assert_eq!(status(&read_after), 200);
    assert!(read_after.contains("<CurrentVolume>50</CurrentVolume>"));
    assert_eq!(
        local.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );
    assert!(local.stop().reconciled());

    let tailnet = loopback_with_policy(client, Policy::UnauthenticatedTailnet);
    for method in ["SUBSCRIBE", "UNSUBSCRIBE"] {
        let response = tcp_request(tailnet.addr(), event_http(method));
        assert_eq!(
            status(&response),
            401,
            "{method} must reveal no tailnet event state"
        );
        assert_no_sid(&response);
        assert_eq!(
            rig.owner.service_http(&mut mailbox).unwrap(),
            HttpService::Idle
        );
        assert_eq!(rig.owner.render_state(), state);
        assert_eq!(rig.owner.received_frames_pulled(), pulled);
        assert_eq!(rig.probe.calls(), calls);
        assert_eq!(rig.probe.captured_submissions(), pcm);
        assert_eq!(rig.probe.pending_slots(), held);
        assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
        assert!(tailnet.callback_report().is_none());
    }
    let set = call_serviced(
        &mut rig,
        &mut mailbox,
        &tailnet,
        signed_http(1, 1, 65, false, true),
    );
    assert_eq!(status(&set), 200);
    assert_eq!(
        tailnet.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (2, 65)
    );
    assert!(tailnet.stop().reconciled());
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}
