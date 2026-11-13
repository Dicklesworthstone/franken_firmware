//! Owner-aware GENA over localhost: modeled retained HAL and raw TCP, not
//! hardware, provider, external-client or production target qualification.
use super::*;
use crate::fsonos_loopback::{
    CallbackLimits, CallbackTarget, FsonosLoopback, LoopbackLimits, Policy, fixture_session_for,
    mailbox_control, mailbox_eventing_control,
};
use crate::settled_http::{
    HttpMailboxClient, HttpMailboxConfig, HttpMailboxError, HttpMailboxOwner, HttpService,
    http_mailbox,
};
use franken_control::fsonos::Service;
use franken_control::fsonos::{HttpRequest, Ingress};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn callback_listener() -> (TcpListener, CallbackTarget) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = CallbackTarget::new(listener.local_addr().unwrap(), "/notify").unwrap();
    (listener, target)
}

/// Parse a complete bounded callback request; return its still-open stream so
/// tests can either acknowledge it or deliberately keep the callback slow.
fn accept_notification(listener: &TcpListener) -> (TcpStream, String) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "callback was not received");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("callback accept: {error}"),
        }
    };
    assert!(peer.ip().is_loopback());
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut wire = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "callback closed before complete request");
        wire.extend_from_slice(&chunk[..n]);
        assert!(wire.len() <= 16 * 1024);
        if let Some(split) = wire.windows(4).position(|v| v == b"\r\n\r\n") {
            let head = std::str::from_utf8(&wire[..split]).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .expect("callback Content-Length");
            if wire.len() >= split + 4 + length {
                break;
            }
        }
    }
    (stream, String::from_utf8(wire).unwrap())
}

fn acknowledge_notification(mut stream: TcpStream) {
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
}

fn header<'a>(wire: &'a str, name: &str) -> Option<&'a str> {
    wire.split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
}

fn no_callback_within(listener: &TcpListener, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        match listener.accept() {
            Ok(_) => panic!("unexpected callback after refusal/unsubscribe"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return;
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("callback accept: {error}"),
        }
    }
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
    let mut result = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                result.extend_from_slice(&buf[..n]);
                assert!(result.len() <= 64 * 1024);
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("localhost HTTP read: {error}"),
        }
    }
    String::from_utf8(result).unwrap()
}

fn status(wire: &str) -> u16 {
    wire.lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn finished_client_diagnostic(client: &mut Option<thread::JoinHandle<String>>) -> String {
    if !client.as_ref().is_some_and(thread::JoinHandle::is_finished) {
        return "client still running".to_owned();
    }
    match client.take().unwrap().join() {
        Ok(wire) => {
            let first_line: String = wire
                .lines()
                .next()
                .unwrap_or("<empty>")
                .chars()
                .take(256)
                .collect();
            format!("HTTP first line: {first_line}")
        }
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic>");
            let message: String = message.chars().take(256).collect();
            format!("client panic: {message}")
        }
    }
}

/// Only the actual owner is serviced on the test thread. TCP may wait on its
/// own bounded worker; no socket operation runs inside a render step.
#[track_caller]
fn call_owner(
    rig: &mut ControllerRig,
    mailbox: &mut HttpMailboxOwner,
    server: &FsonosLoopback,
    wire: String,
) -> String {
    let addr = server.addr();
    let request: String = wire
        .lines()
        .next()
        .unwrap_or("<empty>")
        .chars()
        .take(256)
        .collect();
    let call_site = std::panic::Location::caller();
    let mut client = Some(thread::spawn(move || tcp_request(addr, wire)));
    let started = Instant::now();
    let until = started + Duration::from_secs(3);
    let mut served = false;
    let mut idle_count = 0_u64;
    while Instant::now() < until {
        match rig.owner.service_http(mailbox) {
            Ok(HttpService::Idle) => {
                idle_count = idle_count.saturating_add(1);
                thread::sleep(Duration::from_millis(1));
            }
            Ok(HttpService::Replied) => {
                served = true;
                break;
            }
            other => {
                let client_detail = finished_client_diagnostic(&mut client);
                panic!(
                    "owner failed to service request: {other:?}; caller={call_site}; request={request}; idle={idle_count}; elapsed={:?}; {client_detail}",
                    started.elapsed()
                );
            }
        }
    }
    let client_detail = (!served).then(|| finished_client_diagnostic(&mut client));
    assert!(
        served,
        "owner must service one bounded request; caller={call_site}; request={request}; idle={idle_count}; elapsed={:?}; {client_detail:?}",
        started.elapsed()
    );
    client.take().unwrap().join().unwrap()
}

fn event_request(method: &str, headers: &[(&str, &str)]) -> String {
    let mut wire = format!(
        "{method} {} HTTP/1.1\r\nHost: 127.0.0.1\r\n",
        Service::RenderingControl.event_path()
    );
    for (name, value) in headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("Content-Length: 0\r\n\r\n");
    wire
}

fn set_volume_request(volume: u8) -> String {
    let service = Service::RenderingControl;
    let value = volume.to_string();
    let xml = crate::control_adapter::envelope(
        service,
        "SetVolume",
        &[
            ("InstanceID", "0"),
            ("Channel", "Master"),
            ("DesiredVolume", &value),
        ],
    );
    format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nSOAPACTION: \"{}#SetVolume\"\r\nContent-Length: {}\r\n\r\n{}",
        service.control_path(),
        service.urn(),
        xml.len(),
        xml
    )
}

fn finish_pcm(mut rig: ControllerRig) -> Vec<Vec<u8>> {
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

fn callback_limits(queue: usize) -> CallbackLimits {
    CallbackLimits {
        queue,
        io_timeout: Duration::from_secs(2),
        ..CallbackLimits::standard()
    }
}

fn eventing_server(
    client: HttpMailboxClient,
    policy: Policy,
    target: CallbackTarget,
    limits: CallbackLimits,
) -> Result<FsonosLoopback, String> {
    FsonosLoopback::start_eventing_with_control(
        fixture_session_for(TEST_MEMBER, "neighbor").unwrap(),
        TEST_MEMBER,
        policy,
        LoopbackLimits::standard(),
        target,
        limits,
        move |_, _, _| Ok(mailbox_eventing_control(client)),
    )
}

fn plain_server(client: HttpMailboxClient, policy: Policy, opt_in: bool) -> FsonosLoopback {
    FsonosLoopback::start_with_control(
        fixture_session_for(TEST_MEMBER, "neighbor").unwrap(),
        TEST_MEMBER,
        policy,
        LoopbackLimits::standard(),
        move |_, _, _| {
            Ok(if opt_in {
                mailbox_eventing_control(client)
            } else {
                mailbox_control(client)
            })
        },
    )
    .unwrap()
}

fn raw_request() -> HttpRequest<'static> {
    HttpRequest {
        method: "GET",
        path: "/state",
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::Tailnet,
        headers: &[],
        body: b"",
    }
}

fn signed_tailnet_set() -> String {
    let command = ControlCommand::SetMemberVolume {
        member_id: TEST_MEMBER.into(),
        volume: 90,
    };
    let body =
        RequestBody::new(test_peer(TEST_CONTROLLER), 1, TEST_EPOCH, Some(1), command).unwrap();
    let proof: String = compute_proof(&test_key(TEST_CONTROLLER), &body.signing_bytes())
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let service = Service::RenderingControl;
    let xml = crate::control_adapter::envelope(
        service,
        "SetVolume",
        &[
            ("InstanceID", "0"),
            ("Channel", "Master"),
            ("DesiredVolume", "90"),
        ],
    );
    format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nSOAPACTION: \"{}#SetVolume\"\r\nX-Franken-Peer: {}\r\nX-Franken-Seq: 1\r\nX-Franken-Epoch: {}\r\nX-Franken-Revision: 1\r\nX-Franken-Proof: {}\r\nContent-Length: {}\r\n\r\n{}",
        service.control_path(),
        service.urn(),
        TEST_CONTROLLER,
        TEST_EPOCH,
        proof,
        xml.len(),
        xml
    )
}

fn subscribe_request(callback: &str) -> String {
    let callback = format!("<{callback}>");
    event_request(
        "SUBSCRIBE",
        &[
            ("CALLBACK", &callback),
            ("NT", "upnp:event"),
            ("TIMEOUT", "Second-300"),
        ],
    )
}

fn assert_notification(wire: &str, sid: &str, seq: &str, volume: &str) {
    assert!(wire.starts_with("NOTIFY /notify HTTP/1.1\r\n"));
    assert_eq!(header(wire, "SID"), Some(sid));
    assert_eq!(header(wire, "SEQ"), Some(seq));
    assert_eq!(header(wire, "NT"), Some("upnp:event"));
    assert_eq!(header(wire, "NTS"), Some("upnp:propchange"));
    assert!(wire.contains(&format!("val=\"{volume}\"")));
}

#[test]
fn owner_eventing_delivers_real_callbacks_and_excludes_other_ingress_until_release() {
    let mut reference = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut reference);
    let baseline = finish_pcm(reference);
    assert!(baseline.iter().flatten().any(|byte| *byte != 0));

    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let config = HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap();
    let (client, mut mailbox) = http_mailbox(config).unwrap();
    let (listener, target) = callback_listener();
    assert!(listener.local_addr().unwrap().ip().is_loopback());
    // Establish this mailbox's actual owner association before exercising an
    // attached Tailnet worker that must refuse every event request.
    let seed = plain_server(client.clone(), Policy::LocalLink, false);
    let read = call_owner(&mut rig, &mut mailbox, &seed, get_volume_request());
    assert_eq!(status(&read), 200);
    assert!(read.contains("<CurrentVolume>50</CurrentVolume>"));
    assert!(seed.stop().reconciled());

    // Opting in without a real outbox is insufficient. Neither rejection may
    // enter the owner or create a subscription.
    for (policy, expected) in [
        (Policy::LocalLink, 405),
        (Policy::UnauthenticatedTailnet, 401),
    ] {
        let plain_optin = plain_server(client.clone(), policy, true);
        let refused = tcp_request(plain_optin.addr(), subscribe_request(target.url()));
        assert_eq!(status(&refused), expected);
        assert!(header(&refused, "SID").is_none());
        assert_eq!(
            rig.owner.service_http(&mut mailbox).unwrap(),
            HttpService::Idle
        );
        assert!(plain_optin.stop().reconciled());
    }
    no_callback_within(&listener, Duration::from_millis(100));

    // Even an opted-in worker with a real outbox must not expose event
    // registration to unauthenticated Tailnet ingress.
    let tail_eventing = eventing_server(
        client.clone(),
        Policy::UnauthenticatedTailnet,
        target.clone(),
        callback_limits(4),
    )
    .unwrap();
    for request in [
        subscribe_request(target.url()),
        event_request(
            "UNSUBSCRIBE",
            &[("SID", "uuid:00000000-0000-4000-8000-000000000001")],
        ),
    ] {
        let refused = tcp_request(tail_eventing.addr(), request);
        assert_eq!(status(&refused), 401);
        assert!(header(&refused, "SID").is_none());
        assert_eq!(
            rig.owner.service_http(&mut mailbox).unwrap(),
            HttpService::Idle
        );
    }
    no_callback_within(&listener, Duration::from_millis(100));
    assert!(tail_eventing.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);

    let server = eventing_server(
        client.clone(),
        Policy::LocalLink,
        target.clone(),
        callback_limits(4),
    )
    .unwrap();
    assert!(server.addr().ip().is_loopback());
    let wrong = subscribe_request(&format!("http://{}/wrong", listener.local_addr().unwrap()));
    let refused = tcp_request(server.addr(), wrong);
    assert_eq!(status(&refused), 412);
    assert!(header(&refused, "SID").is_none());
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Idle
    );
    no_callback_within(&listener, Duration::from_millis(100));

    let subscribe = call_owner(
        &mut rig,
        &mut mailbox,
        &server,
        subscribe_request(target.url()),
    );
    assert_eq!(status(&subscribe), 200);
    let sid = header(&subscribe, "SID").expect("actual SID").to_owned();
    assert!(sid.starts_with("uuid:"));
    let (first_stream, first) = accept_notification(&listener);
    assert_notification(&first, &sid, "0", "50");
    assert!(first.contains("<FrankenStateRevision>1</FrankenStateRevision>"));
    acknowledge_notification(first_stream);
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );

    // Other raw and ordinary-adapter clients of this same mailbox cannot
    // bypass the one attached worker or silently discard its notifications.
    assert!(matches!(
        client.clone().submit(&raw_request()),
        Err(HttpMailboxError::Busy)
    ));
    let plain = plain_server(client.clone(), Policy::LocalLink, false);
    let tail = plain_server(client.clone(), Policy::UnauthenticatedTailnet, false);
    assert_eq!(
        status(&tcp_request(plain.addr(), set_volume_request(80))),
        503
    );
    assert_eq!(status(&tcp_request(tail.addr(), signed_tailnet_set())), 503);
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Idle
    );
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );
    let (other_listener, other_target) = callback_listener();
    let second = eventing_server(
        client.clone(),
        Policy::LocalLink,
        other_target,
        callback_limits(4),
    );
    assert!(
        second.is_err(),
        "a second attached route must not become ready"
    );
    no_callback_within(&other_listener, Duration::from_millis(100));

    let set = call_owner(&mut rig, &mut mailbox, &server, set_volume_request(65));
    assert_eq!(status(&set), 200);
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (2, 65)
    );
    let (next_stream, next) = accept_notification(&listener);
    assert_notification(&next, &sid, "1", "65");
    assert!(next.contains("<FrankenStateRevision>2</FrankenStateRevision>"));
    acknowledge_notification(next_stream);

    let renew = event_request("SUBSCRIBE", &[("SID", &sid), ("TIMEOUT", "Second-300")]);
    let renewed = call_owner(&mut rig, &mut mailbox, &server, renew);
    assert_eq!(status(&renewed), 200);
    assert_eq!(header(&renewed, "SID"), Some(sid.as_str()));
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &sid)]);
    assert_eq!(
        status(&call_owner(&mut rig, &mut mailbox, &server, unsubscribe)),
        200
    );
    assert_eq!(
        status(&call_owner(
            &mut rig,
            &mut mailbox,
            &server,
            set_volume_request(75)
        )),
        200
    );
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (3, 75)
    );
    no_callback_within(&listener, Duration::from_millis(200));
    let until = Instant::now() + Duration::from_secs(3);
    let report = loop {
        let report = server.callback_report().unwrap();
        if report.reconciled() && report.delivered == 2 {
            break report;
        }
        assert!(Instant::now() < until, "callback deliveries must settle");
        thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(report.offered, 2);
    assert_eq!(report.delivered, 2);
    assert_eq!(report.subscribes_refused, 1);
    assert!(server.stop().reconciled());
    assert!(matches!(
        client.submit(&raw_request()),
        Err(HttpMailboxError::Busy)
    ));
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);

    // Explicit owner cleanup restores existing raw and normal HTTP admission.
    let pending = client.submit(&raw_request()).unwrap();
    drop(pending);
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Expired
    );
    let set = call_owner(&mut rig, &mut mailbox, &plain, set_volume_request(80));
    assert_eq!(status(&set), 200);
    assert_eq!(
        plain.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (4, 80)
    );
    assert!(plain.stop().reconciled());
    assert!(tail.stop().reconciled());
    let controlled = finish_pcm(rig);
    assert_eq!(controlled.len(), baseline.len());
    assert!(controlled.iter().flatten().any(|byte| *byte != 0));
    assert_ne!(
        controlled, baseline,
        "same owner's committed volume must change protected PCM"
    );
}

fn retained_program(rig: &mut ControllerRig) -> (u16, u32) {
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
                .expect("actual nonzero retained program submission");
            assert!(rig.probe.pending_slots().contains(&token));
            assert!(rig.owner.received_frames_pulled() > 0);
            rig.probe.set_lose_completions(true);
            let held = rig.probe.pending_slots();
            assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
            return token;
        }
    }
    panic!("no actual retained program output")
}

#[test]
fn slow_callback_and_full_outbox_do_not_block_owner_control_or_acknowledged_stop() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let token = retained_program(&mut rig);
    let held = rig.probe.pending_slots();
    let pulls = rig.owner.received_frames_pulled();
    let pcm = rig.probe.captured_submissions();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let (listener, target) = callback_listener();
    let limits = CallbackLimits {
        queue: 1,
        io_timeout: Duration::from_secs(5),
        ..CallbackLimits::standard()
    };
    let server = eventing_server(client, Policy::LocalLink, target.clone(), limits).unwrap();
    let subscribed = call_owner(
        &mut rig,
        &mut mailbox,
        &server,
        subscribe_request(target.url()),
    );
    assert_eq!(status(&subscribed), 200);
    let sid = header(&subscribed, "SID").unwrap().to_owned();
    let (slow_stream, initial) = accept_notification(&listener);
    assert_notification(&initial, &sid, "0", "50");
    // Keep that connection open without its callback HTTP status. The bounded
    // sender is now waiting there; one later event can queue, the next cannot.
    assert_eq!(
        status(&call_owner(
            &mut rig,
            &mut mailbox,
            &server,
            set_volume_request(65)
        )),
        200
    );
    assert_eq!(
        status(&call_owner(
            &mut rig,
            &mut mailbox,
            &server,
            set_volume_request(70)
        )),
        200
    );
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (3, 70)
    );
    let report = server.callback_report().unwrap();
    assert_eq!(report.offered, 3);
    assert!(
        report.dropped >= 1,
        "the bounded outbox must count saturation"
    );
    assert_eq!(report.delivered, 0, "no callback received a 200 yet");
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert_eq!(rig.probe.pending_slots(), held);
    assert!(held.contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert!(matches!(
        rig.owner.local_mute(true),
        Ok(RenderApplication::PolicyAccepted)
    ));
    assert_eq!(
        rig.owner.effective_mute(),
        Some(franken_dsp::volume::MuteReason::Local)
    );
    assert_eq!(rig.probe.pending_slots(), held);
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert!(!rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.pending(), 0);
    // Only after the owner has stopped do we answer the slow peer and drain
    // the one queued event, so the stop cannot be credited to that answer.
    acknowledge_notification(slow_stream);
    let (queued_stream, queued) = accept_notification(&listener);
    assert_notification(&queued, &sid, "1", "65");
    acknowledge_notification(queued_stream);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let report = server.callback_report().unwrap();
        if report.reconciled() && report.delivered == 2 {
            assert!(report.dropped >= 1);
            break;
        }
        assert!(Instant::now() < deadline, "callbacks must settle after ACK");
        thread::sleep(Duration::from_millis(2));
    }
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &sid)]);
    assert_eq!(
        status(&call_owner(&mut rig, &mut mailbox, &server, unsubscribe)),
        200
    );
    assert!(server.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

#[test]
fn unavailable_callback_is_counted_without_blocking_local_mute_or_stop() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let token = retained_program(&mut rig);
    let held = rig.probe.pending_slots();
    let pulls = rig.owner.received_frames_pulled();
    let pcm = rig.probe.captured_submissions();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let (listener, target) = callback_listener();
    // Keep the port reserved while the shim binds so it cannot accidentally
    // become the very callback we intend to make unavailable.
    let server = eventing_server(
        client,
        Policy::LocalLink,
        target.clone(),
        callback_limits(2),
    )
    .unwrap();
    drop(listener); // The test-owned localhost port has no accepting callback.
    let subscribed = call_owner(
        &mut rig,
        &mut mailbox,
        &server,
        subscribe_request(target.url()),
    );
    assert_eq!(status(&subscribed), 200);
    let sid = header(&subscribed, "SID").unwrap().to_owned();
    assert!(matches!(
        rig.owner.local_mute(true),
        Ok(RenderApplication::PolicyAccepted)
    ));
    assert_eq!(rig.probe.pending_slots(), held);
    assert!(held.contains(&token));
    assert_eq!(rig.probe.kernel_touch_pending(), (held.len(), 0));
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.owner.received_frames_pulled(), pulls);
    assert_eq!(rig.probe.captured_submissions(), pcm);
    assert!(!rig.probe.pending_slots().contains(&token));
    assert_eq!(rig.probe.pending(), 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let report = server.callback_report().unwrap();
        if report.reconciled() && report.failed == 1 {
            assert_eq!(report.delivered, 0);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "unavailable callback must be counted"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &sid)]);
    assert_eq!(
        status(&call_owner(&mut rig, &mut mailbox, &server, unsubscribe)),
        200
    );
    assert!(server.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}

/// A pass-through journal medium with one bounded, test-controlled program
/// delay. This is host fault injection, never a device latency measurement.
struct DelayedStorage {
    inner: RamMedium,
    arm: Rc<Cell<bool>>,
    triggered: Rc<Cell<bool>>,
}
impl franken_control::channel::pipeline::Storage for DelayedStorage {
    fn segment_bytes(&self) -> usize {
        self.inner.segment_bytes()
    }
    fn read(
        &self,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), franken_control::channel::pipeline::StorageFault> {
        self.inner.read(offset, out)
    }
    fn program(
        &mut self,
        offset: usize,
        data: &[u8],
    ) -> Result<(), franken_control::channel::pipeline::StorageFault> {
        if self.arm.replace(false) {
            self.triggered.set(true);
            thread::sleep(Duration::from_millis(1_200));
        }
        self.inner.program(offset, data)
    }
    fn erase(
        &mut self,
        segment: usize,
    ) -> Result<(), franken_control::channel::pipeline::StorageFault> {
        self.inner.erase(segment)
    }
    fn sync(&mut self) -> Result<(), franken_control::channel::pipeline::StorageFault> {
        self.inner.sync()
    }
}

type DelayedOwner = SettledRender<HarnessKeys, DelayedStorage, HostUdp, TestKernel, RetainedPurge>;

struct DelayedFixture {
    owner: DelayedOwner,
    armed: Rc<Cell<bool>>,
    triggered: Rc<Cell<bool>>,
    probe: FakeProbe,
}

fn delayed_owner() -> DelayedFixture {
    let armed = Rc::new(Cell::new(false));
    let triggered = Rc::new(Cell::new(false));
    let medium = DelayedStorage {
        inner: RamMedium::new(Limits::fleet_control_development().segment_bytes),
        arm: Rc::clone(&armed),
        triggered: Rc::clone(&triggered),
    };
    let (mut control, _) =
        FleetControlOwner::boot(HarnessKeys::new(), medium, ChannelConfig::provisional()).unwrap();
    for (name, role, epoch) in [
        (TEST_CONTROLLER, PeerRole::Controller, Some(TEST_EPOCH)),
        (TEST_BRIDGE, PeerRole::Controller, Some(TEST_EPOCH)),
        (TEST_PANEL, PeerRole::LocalUser, None),
    ] {
        control
            .admit(&test_peer(name), role, &test_key(name), epoch, 1)
            .unwrap();
    }
    control
        .reserve_legacy_peer(&test_peer(TEST_BRIDGE))
        .unwrap();
    let soap = Endpoint::new(
        EndpointConfig::provisional(TEST_MEMBER),
        LegacyBridge::new(test_peer(TEST_BRIDGE), test_key(TEST_BRIDGE)),
        1,
        1,
    )
    .unwrap();
    let token = AuthorityToken::issue(
        &UnifiedGroupSession::new("grp", "coord", TEST_EPOCH),
        u64::MAX,
    );
    let fresh = control
        .provision_fresh_group(
            "grp",
            "coord",
            TEST_EPOCH,
            MembershipConfig::default(),
            token.clone(),
            CLOCK_ORIGIN + 50_000_000,
        )
        .unwrap();
    let parts = prepared_parts(true, 2);
    let local_now = Rc::clone(&parts.local_now);
    let probe = parts.probe.clone();
    let mut owner =
        SettledRender::admit_fresh_group(fresh, soap, parts.network, pending_member(), 7).unwrap();
    let cutover = ((CLOCK_ORIGIN + 500_000_000) * 48_000) / 1_000_000_000;
    let id = owner
        .propose_join(token, profile(), cutover, CLOCK_ORIGIN + 300_000_000)
        .unwrap();
    owner.ack_local(id).unwrap();
    assert!(matches!(
        owner.commit_join(id),
        Ok(franken_session::ProposalStatus::Committed { .. })
    ));
    local_now.set(600_000_000);
    assert!(
        owner
            .tick_membership(id)
            .unwrap()
            .settled
            .iter()
            .any(|(actual, status)| *actual == id
                && matches!(
                    status,
                    franken_session::ProposalStatus::Activated { revision: 1, .. }
                ))
    );
    DelayedFixture {
        owner,
        armed,
        triggered,
        probe,
    }
}

fn call_delayed_owner(
    owner: &mut DelayedOwner,
    mailbox: &mut HttpMailboxOwner,
    server: &FsonosLoopback,
    wire: String,
) -> (HttpService, String) {
    let addr = server.addr();
    let client = thread::spawn(move || tcp_request(addr, wire));
    let deadline = Instant::now() + Duration::from_secs(3);
    let outcome = loop {
        match owner.service_http(mailbox).unwrap() {
            HttpService::Idle => {
                assert!(Instant::now() < deadline, "owner did not receive request");
                thread::sleep(Duration::from_millis(1));
            }
            result => break result,
        }
    };
    (outcome, client.join().unwrap())
}

fn get_volume_request() -> String {
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

#[test]
fn committed_owner_response_after_http_timeout_counts_actual_undelivered_event() {
    let DelayedFixture {
        mut owner,
        armed,
        triggered,
        probe,
    } = delayed_owner();
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(500)).unwrap())
            .unwrap();
    let (listener, target) = callback_listener();
    let server = eventing_server(
        client.clone(),
        Policy::LocalLink,
        target.clone(),
        callback_limits(4),
    )
    .unwrap();
    let (result, subscribed) = call_delayed_owner(
        &mut owner,
        &mut mailbox,
        &server,
        subscribe_request(target.url()),
    );
    assert_eq!(result, HttpService::Replied);
    assert_eq!(status(&subscribed), 200);
    let sid = header(&subscribed, "SID").unwrap().to_owned();
    let (initial_stream, initial) = accept_notification(&listener);
    assert_notification(&initial, &sid, "0", "50");
    acknowledge_notification(initial_stream);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let report = server.callback_report().unwrap();
        if report.reconciled() && report.delivered == 1 {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(client.diagnostics().lost_replies, 0);
    assert_eq!(client.diagnostics().lost_notifications, 0);
    armed.set(true);
    let (result, timed_out) =
        call_delayed_owner(&mut owner, &mut mailbox, &server, set_volume_request(65));
    assert!(
        triggered.get(),
        "the real journal program must have begun and been delayed"
    );
    assert_eq!(result, HttpService::ReplyLost);
    assert_eq!(status(&timed_out), 504);
    assert!(
        timed_out
            .to_ascii_lowercase()
            .contains("x-franken-outcome: unknown")
    );
    assert_eq!(client.diagnostics().lost_replies, 1);
    assert_eq!(client.diagnostics().lost_notifications, 1);
    // A lost response cannot refresh the diagnostic snapshot. A later actual
    // owner-serviced read proves the delayed write committed exactly once.
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (1, 50)
    );
    let (result, read) =
        call_delayed_owner(&mut owner, &mut mailbox, &server, get_volume_request());
    assert_eq!(result, HttpService::Replied);
    assert_eq!(status(&read), 200);
    assert!(read.contains("<CurrentVolume>65</CurrentVolume>"));
    assert_eq!(
        server.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (2, 65)
    );
    no_callback_within(&listener, Duration::from_millis(200));
    let report = server.callback_report().unwrap();
    assert_eq!(report.offered, 1);
    assert_eq!(report.delivered, 1);
    assert_eq!(client.diagnostics().lost_notifications, 1);
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &sid)]);
    let (result, ended) = call_delayed_owner(&mut owner, &mut mailbox, &server, unsubscribe);
    assert_eq!(result, HttpService::Replied);
    assert_eq!(status(&ended), 200);
    assert!(owner.request_stop().is_ok());
    let mut timing = ScriptedTiming::default();
    let mut stopped = None;
    for _ in 0..20 {
        match owner.drain_tick(&mut timing).unwrap() {
            DrainProgress::Tick { report, .. } => assert_eq!(report.started, None),
            DrainProgress::Finished(report) => {
                stopped = Some(report);
                break;
            }
            DrainProgress::NotStartedUnacknowledged => panic!("missing drain"),
        }
    }
    assert!(stopped.expect("bounded drain").acknowledged);
    assert_eq!(probe.pending(), 0);
    assert!(server.stop().reconciled());
    assert_eq!(owner.release_http_eventing(&mut mailbox).unwrap(), 0);
}

#[test]
fn live_subscription_detach_fences_until_real_owner_cleanup_and_new_target() {
    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    // Bind a distinct real owner to its own mailbox through actual service.
    let mut other = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut other);
    let (other_client, mut other_mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let other_server = plain_server(other_client, Policy::LocalLink, false);
    assert_eq!(
        status(&call_owner(
            &mut other,
            &mut other_mailbox,
            &other_server,
            get_volume_request()
        )),
        200
    );
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let (old_listener, old_target) = callback_listener();
    let first = eventing_server(
        client.clone(),
        Policy::LocalLink,
        old_target.clone(),
        callback_limits(4),
    )
    .unwrap();
    let subscribed = call_owner(
        &mut rig,
        &mut mailbox,
        &first,
        subscribe_request(old_target.url()),
    );
    assert_eq!(status(&subscribed), 200);
    let old_sid = header(&subscribed, "SID").unwrap().to_owned();
    let (stream, event) = accept_notification(&old_listener);
    assert_notification(&event, &old_sid, "0", "50");
    acknowledge_notification(stream);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let report = first.callback_report().unwrap();
        if report.reconciled() && report.delivered == 1 {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    let (_unused_client, mut second_mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    assert!(matches!(
        rig.owner.release_http_eventing(&mut second_mailbox),
        Err(HttpMailboxError::Unavailable)
    ));
    assert!(matches!(
        rig.owner.service_http(&mut second_mailbox),
        Err(HttpMailboxError::Unavailable)
    ));
    assert!(matches!(
        mailbox.service_one(|_| panic!("generic handler must not run")),
        Err(HttpMailboxError::Unavailable)
    ));
    let addr = first.addr();
    let pending_get = thread::spawn(move || tcp_request(addr, get_volume_request()));
    assert!(matches!(
        other.owner.service_http(&mut mailbox),
        Err(HttpMailboxError::Unavailable)
    ));
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match rig.owner.service_http(&mut mailbox).unwrap() {
            HttpService::Idle => thread::sleep(Duration::from_millis(1)),
            HttpService::Replied => break,
            other => panic!("matching owner failed to service request: {other:?}"),
        }
        assert!(Instant::now() < until);
    }
    assert_eq!(status(&pending_get.join().unwrap()), 200);
    assert!(matches!(
        rig.owner.release_http_eventing(&mut mailbox),
        Err(HttpMailboxError::Busy)
    ));
    assert!(first.stop().reconciled());

    // Dropping the worker is not proof that the owner's subscriptions ended.
    // Both raw submission and a second target remain fenced until owner cleanup.
    assert!(matches!(
        client.submit(&raw_request()),
        Err(HttpMailboxError::Busy)
    ));
    let (new_listener, new_target) = callback_listener();
    assert!(
        eventing_server(
            client.clone(),
            Policy::LocalLink,
            new_target.clone(),
            callback_limits(4)
        )
        .is_err()
    );
    assert!(matches!(
        other.owner.release_http_eventing(&mut mailbox),
        Err(HttpMailboxError::Unavailable)
    ));
    assert!(matches!(
        client.submit(&raw_request()),
        Err(HttpMailboxError::Busy)
    ));
    assert!(
        eventing_server(
            client.clone(),
            Policy::LocalLink,
            new_target.clone(),
            callback_limits(4)
        )
        .is_err()
    );
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 1);
    let pending = client.submit(&raw_request()).unwrap();
    drop(pending);
    assert_eq!(
        rig.owner.service_http(&mut mailbox).unwrap(),
        HttpService::Expired
    );
    let plain = plain_server(client.clone(), Policy::LocalLink, false);
    let changed = call_owner(&mut rig, &mut mailbox, &plain, set_volume_request(60));
    assert_eq!(status(&changed), 200);
    assert_eq!(
        plain.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (2, 60)
    );
    no_callback_within(&old_listener, Duration::from_millis(200));
    assert!(plain.stop().reconciled());

    let second = eventing_server(
        client,
        Policy::LocalLink,
        new_target.clone(),
        callback_limits(4),
    )
    .unwrap();
    let old_renew = event_request("SUBSCRIBE", &[("SID", &old_sid), ("TIMEOUT", "Second-300")]);
    let refused = call_owner(&mut rig, &mut mailbox, &second, old_renew);
    assert_eq!(status(&refused), 412);
    assert!(header(&refused, "SID").is_none());
    no_callback_within(&new_listener, Duration::from_millis(100));
    let fresh = call_owner(
        &mut rig,
        &mut mailbox,
        &second,
        subscribe_request(new_target.url()),
    );
    assert_eq!(status(&fresh), 200);
    let fresh_sid = header(&fresh, "SID").unwrap().to_owned();
    assert_ne!(fresh_sid, old_sid);
    let (stream, initial) = accept_notification(&new_listener);
    assert_notification(&initial, &fresh_sid, "0", "60");
    acknowledge_notification(stream);
    assert_eq!(
        status(&call_owner(
            &mut rig,
            &mut mailbox,
            &second,
            set_volume_request(65)
        )),
        200
    );
    let (stream, changed) = accept_notification(&new_listener);
    assert_notification(&changed, &fresh_sid, "1", "65");
    acknowledge_notification(stream);
    no_callback_within(&old_listener, Duration::from_millis(200));
    assert_eq!(
        second.with_session(|s| (s.state_revision, s.members[TEST_MEMBER].volume_0_to_100)),
        (3, 65)
    );
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &fresh_sid)]);
    assert_eq!(
        status(&call_owner(&mut rig, &mut mailbox, &second, unsubscribe)),
        200
    );
    assert!(second.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
    assert!(other.owner.request_stop().is_ok());
    assert!(finish_drain(&mut other.owner).acknowledged);
    assert!(other_server.stop().reconciled());
}

#[test]
fn natural_http_exit_keeps_live_callback_fenced_until_actual_delivery_thread_exits() {
    use crate::fsonos_loopback::{CallbackStop, StopCause};

    let mut rig = prepared_owner_with_completion(true, 2);
    activate_for_media(&mut rig);
    let (client, mut mailbox) =
        http_mailbox(HttpMailboxConfig::new(16 * 1024, 32, Duration::from_millis(800)).unwrap())
            .unwrap();
    let (old_listener, old_target) = callback_listener();
    let limits = LoopbackLimits {
        max_connections: 1,
        ..LoopbackLimits::standard()
    };
    let old_callback_limits = CallbackLimits {
        queue: 2,
        io_timeout: Duration::from_secs(10),
        ..CallbackLimits::standard()
    };
    let old = FsonosLoopback::start_eventing_with_control(
        fixture_session_for(TEST_MEMBER, "neighbor").unwrap(),
        TEST_MEMBER,
        Policy::LocalLink,
        limits,
        old_target.clone(),
        old_callback_limits,
        {
            let attached = client.clone();
            move |_, _, _| Ok(mailbox_eventing_control(attached))
        },
    )
    .unwrap();
    let subscribed = call_owner(
        &mut rig,
        &mut mailbox,
        &old,
        subscribe_request(old_target.url()),
    );
    assert_eq!(status(&subscribed), 200);
    let old_sid = header(&subscribed, "SID").unwrap().to_owned();
    let (slow_stream, initial) = accept_notification(&old_listener);
    assert_notification(&initial, &old_sid, "0", "50");

    // Retain the handle and the unanswered actual callback while observing the
    // one-connection HTTP worker finish on its own, not through stop().
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if old.report().stopped_by == StopCause::ConnectionCap
            && matches!(
                TcpStream::connect_timeout(&old.addr(), Duration::from_millis(20)),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused
            )
        {
            break;
        }
        assert!(Instant::now() < deadline, "HTTP listener did not retire");
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(old.report().accepted, 1);
    let report = old.callback_report().unwrap();
    assert_eq!(report.offered, 1);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.stopped_by, CallbackStop::Running);
    assert!(matches!(
        rig.owner.release_http_eventing(&mut mailbox),
        Err(HttpMailboxError::Busy)
    ));
    assert!(matches!(
        client.submit(&raw_request()),
        Err(HttpMailboxError::Busy)
    ));
    let (new_listener, new_target) = callback_listener();
    assert!(
        eventing_server(
            client.clone(),
            Policy::LocalLink,
            new_target.clone(),
            callback_limits(4)
        )
        .is_err()
    );

    // A real 200 lets the delivery thread finish. Only the owner's repeated
    // nonblocking cleanup observes the actual terminal fence and clears SID.
    acknowledge_notification(slow_stream);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match rig.owner.release_http_eventing(&mut mailbox) {
            Ok(removed) => {
                assert_eq!(removed, 1);
                break;
            }
            Err(HttpMailboxError::Busy) => {
                assert!(Instant::now() < deadline, "delivery did not retire");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("cleanup failed: {error:?}"),
        }
    }
    let report = old.callback_report().unwrap();
    assert_eq!(report.stopped_by, CallbackStop::Closed);
    assert_eq!(report.delivered, 1);
    assert!(report.reconciled());
    no_callback_within(&old_listener, Duration::from_millis(100));

    let fresh = eventing_server(
        client,
        Policy::LocalLink,
        new_target.clone(),
        callback_limits(4),
    )
    .unwrap();
    let renewal = event_request("SUBSCRIBE", &[("SID", &old_sid), ("TIMEOUT", "Second-300")]);
    let refused = call_owner(&mut rig, &mut mailbox, &fresh, renewal);
    assert_eq!(status(&refused), 412);
    assert!(header(&refused, "SID").is_none());
    no_callback_within(&new_listener, Duration::from_millis(100));
    let subscribed = call_owner(
        &mut rig,
        &mut mailbox,
        &fresh,
        subscribe_request(new_target.url()),
    );
    assert_eq!(status(&subscribed), 200);
    let fresh_sid = header(&subscribed, "SID").unwrap().to_owned();
    assert_ne!(fresh_sid, old_sid);
    let (stream, initial) = accept_notification(&new_listener);
    assert_notification(&initial, &fresh_sid, "0", "50");
    acknowledge_notification(stream);
    assert_eq!(
        status(&call_owner(
            &mut rig,
            &mut mailbox,
            &fresh,
            set_volume_request(65)
        )),
        200
    );
    let (stream, changed) = accept_notification(&new_listener);
    assert_notification(&changed, &fresh_sid, "1", "65");
    acknowledge_notification(stream);
    no_callback_within(&old_listener, Duration::from_millis(200));
    let unsubscribe = event_request("UNSUBSCRIBE", &[("SID", &fresh_sid)]);
    assert_eq!(
        status(&call_owner(&mut rig, &mut mailbox, &fresh, unsubscribe)),
        200
    );
    assert!(fresh.stop().reconciled());
    assert_eq!(rig.owner.release_http_eventing(&mut mailbox).unwrap(), 0);
    assert!(old.stop().reconciled());
    assert!(rig.owner.request_stop().is_ok());
    assert!(finish_drain(&mut rig.owner).acknowledged);
    assert_eq!(rig.probe.pending(), 0);
    assert_eq!(rig.probe.use_after_free(), 0);
    assert_eq!(rig.probe.modified_while_owned(), 0);
}
