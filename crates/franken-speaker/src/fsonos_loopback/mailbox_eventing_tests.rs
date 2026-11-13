//! Host-only startup and callback tests for the opt-in mailbox adapter.
//! The core is real; a modeled render result is not playback evidence.
use super::*;
use crate::settled_http::{
    HttpMailboxConfig, HttpMailboxError, HttpService, OwnedHttpReply, http_mailbox,
};
use crate::settled_render::{ControlResult, OwnerError};
use franken_control::fsonos::Service;

fn mailbox_pair() -> (HttpMailboxClient, crate::settled_http::HttpMailboxOwner) {
    http_mailbox(HttpMailboxConfig::new(4096, 16, Duration::from_secs(1)).unwrap()).unwrap()
}

fn callback_listener() -> (TcpListener, CallbackTarget) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = CallbackTarget::new(listener.local_addr().unwrap(), "/events").unwrap();
    (listener, target)
}

fn request(target: &CallbackTarget) -> Vec<u8> {
    format!(
        "SUBSCRIBE {} HTTP/1.1\r\nHost: 127.0.0.1\r\nCALLBACK: <{}>\r\nNT: upnp:event\r\nTIMEOUT: Second-300\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        Service::RenderingControl.event_path(),
        target.url()
    )
    .into_bytes()
}

fn exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.len() <= 64 * 1024);
    response
}

fn idle(owner: &mut crate::settled_http::HttpMailboxOwner) {
    assert_eq!(
        owner
            .service_one(|_| panic!("request must not reach mailbox"))
            .unwrap(),
        HttpService::Idle
    );
}

fn read_callback(listener: &TcpListener) -> String {
    let until = Instant::now() + Duration::from_secs(2);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("callback accept: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut received = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        received.extend_from_slice(&chunk[..count]);
        assert!(received.len() <= 64 * 1024);
        let text = String::from_utf8_lossy(&received);
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let length = head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            });
            if length.is_some_and(|length| body.len() >= length) {
                break;
            }
        }
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .unwrap();
    String::from_utf8(received).unwrap()
}

#[test]
fn eventing_opt_in_without_outbox_still_refuses_without_mailbox_work() {
    let (client, mut owner) = mailbox_pair();
    let (_listener, target) = callback_listener();
    // A safe caller without the private actual-Outbox witness can only pass
    // None; invoking the public trait directly must not unlock eventing.
    let mut unbacked = mailbox_eventing_control(client.clone());
    unbacked.prepare_eventing(None).unwrap();
    let callback = format!("<{}>", target.url());
    let headers = [("CALLBACK", callback.as_str()), ("NT", "upnp:event")];
    let direct_request = HttpRequest {
        method: "SUBSCRIBE",
        path: Service::RenderingControl.event_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: &[],
    };
    let mut diagnostic = fixture_session().unwrap();
    let direct = unbacked.handle_request(&mut diagnostic, START_NS, &direct_request);
    assert_eq!(direct.response.status, 405);
    assert!(direct.notifications.is_empty());
    idle(&mut owner);
    let server = FsonosLoopback::start_with_control(
        fixture_session().unwrap(),
        FIXTURE_MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        move |_, _, _| Ok(mailbox_eventing_control(client)),
    )
    .unwrap();
    let response = String::from_utf8(exchange(server.addr(), &request(&target))).unwrap();
    assert!(response.starts_with("HTTP/1.1 405 "));
    assert!(!response.to_ascii_lowercase().contains("\r\nsid:"));
    idle(&mut owner);
    assert!(server.callback_report().is_none());
    assert_eq!(server.stop().stopped_by, StopCause::Requested);
}

#[test]
fn plain_mailbox_with_real_outbox_is_refused_at_startup() {
    let (client, mut owner) = mailbox_pair();
    let (_listener, target) = callback_listener();
    let result = FsonosLoopback::start_eventing_with_control(
        fixture_session().unwrap(),
        FIXTURE_MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        target,
        CallbackLimits::standard(),
        move |_, _, _| Ok(mailbox_control(client)),
    );
    assert_eq!(
        result.err().as_deref(),
        Some("control owner does not admit transport-local extras")
    );
    idle(&mut owner);
}

#[test]
fn opted_in_outbox_delivers_real_core_initial_notification() {
    let (client, mut owner) = mailbox_pair();
    let raw_client = client.clone();
    let (listener, target) = callback_listener();
    let mut session = fixture_session().unwrap();
    let mut core = ControlPlane::new(&session, FIXTURE_MEMBER, START_NS).unwrap();
    let server = FsonosLoopback::start_eventing_with_control(
        session.clone(),
        FIXTURE_MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        target.clone(),
        CallbackLimits::standard(),
        move |_, _, _| Ok(mailbox_eventing_control(client)),
    )
    .unwrap();
    // A second actual worker cannot claim this mailbox while the first is
    // attached, even though each worker owns a separate callback outbox.
    let second_client = raw_client.clone();
    let second = FsonosLoopback::start_eventing_with_control(
        session.clone(),
        FIXTURE_MEMBER,
        Policy::LocalLink,
        LoopbackLimits::standard(),
        target.clone(),
        CallbackLimits::standard(),
        move |_, _, _| Ok(mailbox_eventing_control(second_client)),
    );
    assert_eq!(
        second.err().as_deref(),
        Some("owner eventing attachment is unavailable")
    );
    let service = Service::RenderingControl;
    let body = crate::control_adapter::envelope(
        service,
        "GetVolume",
        &[("InstanceID", "0"), ("Channel", "Master")],
    );
    let soap_action = format!("\"{}#GetVolume\"", service.urn());
    let headers = [
        ("SOAPACTION", soap_action.as_str()),
        ("Content-Type", "text/xml"),
    ];
    let raw_request = HttpRequest {
        method: "POST",
        path: service.control_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: body.as_bytes(),
    };
    assert!(matches!(
        raw_client.submit(&raw_request),
        Err(HttpMailboxError::Busy)
    ));
    let mut other_adapter = mailbox_control(raw_client.clone());
    let mut other_snapshot = session.clone();
    let refused = other_adapter.handle_request(&mut other_snapshot, START_NS, &raw_request);
    assert_eq!(refused.response.status, 503);
    assert!(refused.notifications.is_empty());
    assert_eq!(other_snapshot.state_revision, session.state_revision);
    idle(&mut owner);
    let addr = server.addr();
    let wire_request = request(&target);
    let client = thread::spawn(move || exchange(addr, &wire_request));
    let deadline = Instant::now() + Duration::from_millis(900);
    loop {
        let result = owner
            .service_one(|request| {
                let handled = core.handle_request(&mut session, START_NS, &request);
                OwnedHttpReply {
                    result: Ok(ControlResult {
                        control: handled,
                        // This unit exercises the transport, not a renderer.
                        render: Err(OwnerError::Clock),
                        notifications: Vec::new(),
                    }),
                    session: session.clone(),
                }
            })
            .unwrap();
        if result == HttpService::Replied {
            break;
        }
        assert_eq!(result, HttpService::Idle);
        assert!(Instant::now() < deadline, "subscription was not admitted");
        thread::sleep(Duration::from_millis(1));
    }
    let response = String::from_utf8(client.join().unwrap()).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 "));
    let sid = response
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sid")
                .then(|| value.trim().to_string())
        })
        .expect("real endpoint grants a SID");
    assert!(sid.starts_with("uuid:"));
    let notification = read_callback(&listener);
    assert!(notification.starts_with("NOTIFY /events HTTP/1.1\r\n"));
    assert!(
        notification
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("SID: {sid}")))
    );
    assert!(
        notification
            .lines()
            .any(|line| line.eq_ignore_ascii_case("SEQ: 0"))
    );
    assert!(
        notification.contains("<"),
        "real core event body is present"
    );
    assert!(notification.contains("<LastChange>"));
    assert!(notification.contains("&lt;Volume"));
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let report = server.callback_report().unwrap();
        if report.delivered == 1 {
            assert_eq!(report.offered, 1);
            assert_eq!(report.failed, 0);
            break;
        }
        assert!(Instant::now() < until, "callback 200 was not accounted");
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(server.stop().stopped_by, StopCause::Requested);
    // The live SID belongs to the stopped worker's outbox. This transport
    // fixture has no real SettledRender to invalidate it, so raw and plain
    // access must remain fenced until an actual owner performs cleanup.
    assert!(matches!(
        raw_client.submit(&raw_request),
        Err(HttpMailboxError::Busy)
    ));
    let refused_after = other_adapter.handle_request(&mut other_snapshot, START_NS, &raw_request);
    assert_eq!(refused_after.response.status, 503);
    assert!(refused_after.notifications.is_empty());
    idle(&mut owner);
}
