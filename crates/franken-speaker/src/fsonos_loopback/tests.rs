//! Tests for the loopback shim through a raw `std` client: the HTTP framing, the bounds and the refusals. The actual `fsonos` client is
//! `tests/g03/fsonos-client`. Each refusal here is paired with the permitted request that follows it, and every test ends with the
//! shim's own count of what it did.

use std::net::UdpSocket;
use std::path::Path;

use franken_control::fsonos::Service;
use franken_control::fsonos::ssdp::DEVICE_TYPE;

use super::*;
use crate::control_adapter::envelope;

const RC: Service = Service::RenderingControl;
const MASTER: [(&str, &str); 2] = [("InstanceID", "0"), ("Channel", "Master")];

fn quick() -> LoopbackLimits {
    LoopbackLimits {
        io_timeout: Duration::from_millis(250),
        request_deadline: Duration::from_millis(900),
        lifetime: Duration::from_secs(30),
        ..LoopbackLimits::standard()
    }
}

fn start_with(policy: Policy, limits: LoopbackLimits) -> FsonosLoopback {
    let session = fixture_session().expect("the fixture session builds");
    FsonosLoopback::start(session, FIXTURE_MEMBER, policy, limits).expect("the shim starts")
}

fn start() -> FsonosLoopback {
    start_with(Policy::LocalLink, quick())
}

struct Wire {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Wire {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn parse_wire(raw: &[u8]) -> Option<Wire> {
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("an answer has a complete head");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("an answer has a status");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    Some(Wire {
        status,
        headers,
        body: body.to_string(),
    })
}

/// Send `bytes`, then read until the shim closes the connection (bounded). `None` when it closed without any answer.
fn exchange(addr: SocketAddr, bytes: &[u8]) -> Option<Wire> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .expect("the shim accepts a connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("a read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("a write timeout");
    // A refusing shim may close before it has read everything: the answer is what matters, so a failed write is not an error here.
    let _ = stream.write_all(bytes);
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                assert!(raw.len() <= 64 * 1024, "the answer stays bounded");
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break,
            Err(error) => panic!("reading the answer failed: {:?}", error.kind()),
        }
    }
    parse_wire(&raw)
}

fn http(method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// A SOAP call exactly as a controller frames it: the quoted `SOAPACTION` and the envelope.
fn post(service: Service, action: &str, args: &[(&str, &str)]) -> Vec<u8> {
    let body = envelope(service, action, args);
    let soap_action = format!("\"{}#{action}\"", service.urn());
    http(
        "POST",
        service.control_path(),
        &[
            ("SOAPACTION", soap_action.as_str()),
            ("Content-Type", "text/xml; charset=\"utf-8\""),
        ],
        body.as_bytes(),
    )
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < give_up, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn volume(server: &FsonosLoopback, member: &str) -> u8 {
    server.with_session(|session| session.members[member].volume_0_to_100)
}

// ---- the permitted path: the real endpoint's answers, on the wire --------------------------------------------------------

#[test]
fn a_volume_read_over_the_wire_is_the_real_endpoints_answer_from_the_live_session() {
    let server = start();
    let wire = exchange(server.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 200);
    assert!(wire.body.contains("<CurrentVolume>50</CurrentVolume>"));
    let length = wire.body.len().to_string();
    assert_eq!(wire.header("content-length"), Some(length.as_str()));
    assert_eq!(wire.header("connection"), Some("close"));
    assert!(
        wire.header("content-type")
            .is_some_and(|kind| kind.starts_with("text/xml"))
    );
    let report = server.stop();
    assert_eq!(
        (
            report.accepted,
            report.served,
            report.refused,
            report.dropped
        ),
        (1, 1, 0, 0)
    );
    assert!(report.reconciled());
    assert_eq!(report.stopped_by, StopCause::Requested);
    assert!(report.bytes_in > 0 && report.bytes_out > 0);
}

#[test]
fn a_set_over_the_wire_changes_the_session_and_only_the_named_member() {
    let server = start();
    let set = [MASTER[0], MASTER[1], ("DesiredVolume", "37")];
    let wire = exchange(server.addr(), &post(RC, "SetVolume", &set)).expect("an answer");
    assert_eq!(wire.status, 200);
    assert_eq!(volume(&server, FIXTURE_MEMBER), 37);
    assert_eq!(volume(&server, "den"), 50, "the other member is untouched");
    let wire = exchange(server.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert!(wire.body.contains("<CurrentVolume>37</CurrentVolume>"));

    let mute = [MASTER[0], MASTER[1], ("DesiredMute", "1")];
    let wire = exchange(server.addr(), &post(RC, "SetMute", &mute)).expect("an answer");
    assert_eq!(wire.status, 200);
    assert!(server.with_session(|session| session.members[FIXTURE_MEMBER].muted));
    let wire = exchange(server.addr(), &post(RC, "GetMute", &MASTER)).expect("an answer");
    assert!(wire.body.contains("<CurrentMute>1</CurrentMute>"));
    let report = server.stop();
    assert_eq!((report.served, report.refused, report.dropped), (4, 0, 0));
    assert!(report.reconciled());
}

#[test]
fn the_endpoints_own_refusals_pass_through_unchanged_and_change_nothing() {
    let server = start();
    // An argument out of range: the endpoint answers a UPnP fault (HTTP 500 with code 402), and the shim forwards it as it is.
    let bad = [MASTER[0], MASTER[1], ("DesiredVolume", "101")];
    let wire = exchange(server.addr(), &post(RC, "SetVolume", &bad)).expect("an answer");
    assert_eq!(wire.status, 500);
    assert!(wire.body.contains("<errorCode>402</errorCode>"));
    // An unknown action: UPnP 401.
    let wire = exchange(server.addr(), &post(RC, "NoSuchAction", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 500);
    assert!(wire.body.contains("<errorCode>401</errorCode>"));
    // Not XML at all: the endpoint's own 400, with no body.
    let soap_action = format!("\"{}#SetVolume\"", RC.urn());
    let garbage = http(
        "POST",
        RC.control_path(),
        &[("SOAPACTION", soap_action.as_str())],
        b"<not xml",
    );
    let wire = exchange(server.addr(), &garbage).expect("an answer");
    assert_eq!(wire.status, 400);
    assert!(wire.body.is_empty());
    // A path the endpoint does not serve, and a method it does not speak.
    let wire = exchange(server.addr(), &http("POST", "/nowhere", &[], b"")).expect("an answer");
    assert_eq!(wire.status, 404);
    let wire = exchange(server.addr(), &http("GET", "/", &[], b"")).expect("an answer");
    assert_eq!(wire.status, 405);
    assert_eq!(
        volume(&server, FIXTURE_MEMBER),
        50,
        "no refusal changed the session"
    );
    // The permitted counterpart: a valid set is applied.
    let ok = [MASTER[0], MASTER[1], ("DesiredVolume", "100")];
    let wire = exchange(server.addr(), &post(RC, "SetVolume", &ok)).expect("an answer");
    assert_eq!(wire.status, 200);
    assert_eq!(volume(&server, FIXTURE_MEMBER), 100);
    let report = server.stop();
    assert_eq!((report.served, report.refused, report.dropped), (6, 0, 0));
}

#[test]
fn an_unauthenticated_tailnet_connection_is_refused_by_the_endpoint_and_a_local_one_is_not() {
    let tailnet = start_with(Policy::UnauthenticatedTailnet, quick());
    let wire = exchange(tailnet.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 401);
    assert!(
        wire.body.is_empty(),
        "the refusal says nothing about the matrix"
    );
    let set = [MASTER[0], MASTER[1], ("DesiredVolume", "10")];
    let wire = exchange(tailnet.addr(), &post(RC, "SetVolume", &set)).expect("an answer");
    assert_eq!(wire.status, 401);
    assert_eq!(volume(&tailnet, FIXTURE_MEMBER), 50);
    drop(tailnet);

    let local = start();
    let wire = exchange(local.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 200);
}

// ---- the shim's own refusals --------------------------------------------------------------------------------------------

#[test]
fn a_head_the_shim_cannot_read_is_refused_by_the_shim_and_never_reaches_the_endpoint() {
    let server = start();
    let many_headers = {
        let mut head = String::from("POST / HTTP/1.1\r\n");
        for index in 0..33 {
            head.push_str(&format!("H{index}: v\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    };
    let cases = [
        ("garbage request line", b"NONSENSE\r\n\r\n".to_vec(), 400),
        (
            "lower-case method",
            b"post / HTTP/1.1\r\n\r\n".to_vec(),
            400,
        ),
        (
            "absolute-form target",
            b"POST http://x/ HTTP/1.1\r\n\r\n".to_vec(),
            400,
        ),
        ("another version", b"POST / HTTP/2.0\r\n\r\n".to_vec(), 505),
        (
            "folded header",
            b"POST / HTTP/1.1\r\nA: b\r\n c\r\n\r\n".to_vec(),
            400,
        ),
        (
            "header without a colon",
            b"POST / HTTP/1.1\r\nbroken\r\n\r\n".to_vec(),
            400,
        ),
        (
            "control character in a value",
            b"POST / HTTP/1.1\r\nA: b\x01c\r\n\r\n".to_vec(),
            400,
        ),
        (
            "two different lengths",
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx".to_vec(),
            400,
        ),
        (
            "a length that is not a number",
            b"POST / HTTP/1.1\r\nContent-Length: 12a\r\n\r\n".to_vec(),
            400,
        ),
        (
            "chunked request body",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            501,
        ),
        (
            "a declared body over the cap",
            b"POST / HTTP/1.1\r\nContent-Length: 16385\r\n\r\n".to_vec(),
            413,
        ),
        ("more headers than the cap", many_headers, 431),
    ];
    for (label, bytes, status) in &cases {
        let wire = exchange(server.addr(), bytes).expect(label);
        assert_eq!(wire.status, *status, "{label}");
        assert!(wire.body.is_empty(), "{label}");
    }
    let report = server.report();
    assert_eq!(report.served, 0, "none of them reached the endpoint");
    let expected: Vec<u16> = cases.iter().map(|(_, _, status)| *status).collect();
    assert_eq!(report.refused_statuses, expected);
    // The permitted counterpart: a valid request after all of them is served.
    let wire = exchange(server.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 200);
    let report = server.stop();
    assert_eq!(
        (report.served, report.refused, report.dropped),
        (1, u32::try_from(cases.len()).unwrap_or(u32::MAX), 0)
    );
    assert!(report.reconciled());
}

#[test]
fn an_oversize_head_is_refused_and_a_body_at_the_cap_reaches_the_endpoint() {
    let server = start();
    // A head over the 8 KiB cap: one 9000-byte header value.
    let big_value = "a".repeat(9000);
    let wire = exchange(
        server.addr(),
        &http("POST", "/", &[("X", big_value.as_str())], b""),
    )
    .expect("an answer");
    assert_eq!(wire.status, 431);
    // A head under the cap whose one value is over the 1 KiB value limit.
    let long_value = "a".repeat(2000);
    let wire = exchange(
        server.addr(),
        &http("POST", "/", &[("X", long_value.as_str())], b""),
    )
    .expect("an answer");
    assert_eq!(wire.status, 400);
    // A declared body one over the shim's cap is refused before it is read.
    let wire = exchange(
        server.addr(),
        b"POST / HTTP/1.1\r\nContent-Length: 16385\r\n\r\n",
    )
    .expect("an answer");
    assert_eq!(wire.status, 413);
    let refused_by_the_shim = server.report();
    assert_eq!(
        (refused_by_the_shim.served, refused_by_the_shim.refused),
        (0, 3)
    );
    // A body exactly at the shim's cap is read in full and handed to the endpoint, whose own 8 KiB limit refuses it with 413.
    let soap_action = format!("\"{}#SetVolume\"", RC.urn());
    let at_cap = vec![b'a'; 16 * 1024];
    let wire = exchange(
        server.addr(),
        &http(
            "POST",
            RC.control_path(),
            &[("SOAPACTION", soap_action.as_str())],
            &at_cap,
        ),
    )
    .expect("an answer");
    assert_eq!(wire.status, 413);
    let report = server.stop();
    assert_eq!(
        (report.served, report.refused),
        (1, 3),
        "that one reached the endpoint"
    );
    assert!(
        report.bytes_in <= 64 * 1024,
        "the shim buffered a bounded amount"
    );
    assert!(report.reconciled());
}

#[test]
fn a_client_that_stalls_midway_is_answered_408_and_one_that_says_nothing_is_closed_unanswered() {
    let server = start();
    let stalled = exchange(server.addr(), b"POST / HTTP/1.1\r\nHost: x\r\n").expect("a 408");
    assert_eq!(stalled.status, 408);
    let silent = exchange(server.addr(), b"");
    assert!(silent.is_none(), "nothing arrived, so nothing is answered");
    // The permitted counterpart: the next client is served as if neither had happened.
    let wire = exchange(server.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 200);
    let report = server.stop();
    assert_eq!(report.refused_statuses, vec![408]);
    assert_eq!((report.served, report.refused, report.dropped), (1, 1, 1));
    assert!(report.reconciled());
}

// ---- bounds of the shim itself ---------------------------------------------------------------------------------------------

#[test]
fn the_shim_accepts_a_bounded_number_of_connections_and_then_closes_its_listener() {
    let server = start_with(
        Policy::LocalLink,
        LoopbackLimits {
            max_connections: 2,
            ..quick()
        },
    );
    for _ in 0..2 {
        let wire = exchange(server.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
        assert_eq!(wire.status, 200);
    }
    wait_until("the worker to stop at the cap", || {
        server
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
    });
    assert_eq!(server.report().stopped_by, StopCause::ConnectionCap);
    assert!(
        TcpStream::connect_timeout(&server.addr(), Duration::from_millis(500)).is_err(),
        "the listener is closed"
    );
    assert!(server.report().reconciled());
}

#[test]
fn the_shim_stops_by_itself_at_its_lifetime_and_dropping_it_closes_the_listener() {
    let short = start_with(
        Policy::LocalLink,
        LoopbackLimits {
            lifetime: Duration::from_millis(150),
            ..quick()
        },
    );
    wait_until("the worker to stop at its lifetime", || {
        short
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
    });
    assert_eq!(short.report().stopped_by, StopCause::Lifetime);

    let server = start();
    let addr = server.addr();
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok());
    drop(server);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err(),
        "dropping the handle stopped and joined the worker"
    );
}

#[test]
fn the_listener_is_loopback_only_and_unusable_limits_are_refused() {
    let server = start();
    assert_eq!(server.addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(server.addr().port(), 0);
    for (label, limits) in [
        (
            "no connections",
            LoopbackLimits {
                max_connections: 0,
                ..quick()
            },
        ),
        (
            "no read time",
            LoopbackLimits {
                io_timeout: Duration::ZERO,
                ..quick()
            },
        ),
        (
            "no lifetime",
            LoopbackLimits {
                lifetime: Duration::ZERO,
                ..quick()
            },
        ),
        (
            "a head too small for a request line",
            LoopbackLimits {
                max_head_bytes: 16,
                ..quick()
            },
        ),
    ] {
        let session = fixture_session().expect("the fixture session builds");
        assert!(
            FsonosLoopback::start(session, FIXTURE_MEMBER, Policy::LocalLink, limits).is_err(),
            "{label}"
        );
    }
    // The permitted counterpart: the standard limits start.
    let session = fixture_session().expect("the fixture session builds");
    assert!(
        FsonosLoopback::start(
            session,
            FIXTURE_MEMBER,
            Policy::LocalLink,
            LoopbackLimits::standard()
        )
        .is_ok()
    );
}

#[test]
fn an_endpoint_for_a_member_that_left_the_group_answers_with_its_own_fault_not_a_made_up_volume() {
    let session = fixture_session().expect("the fixture session builds");
    let absent = FsonosLoopback::start(session, "absent", Policy::LocalLink, quick())
        .expect("an endpoint for a member the session does not hold");
    let wire = exchange(absent.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert_eq!(wire.status, 500);
    assert!(wire.body.contains("<errorCode>501</errorCode>"));
    assert!(!wire.body.contains("<CurrentVolume>"));
    // The permitted counterpart: the member the session does hold is read.
    let present = start();
    let wire = exchange(present.addr(), &post(RC, "GetVolume", &MASTER)).expect("an answer");
    assert!(wire.body.contains("<CurrentVolume>50</CurrentVolume>"));
}

// ---- the pure parts --------------------------------------------------------------------------------------------------------

#[test]
fn a_head_parses_strictly_and_keeps_the_case_the_client_sent() {
    let limits = LoopbackLimits::standard();
    let head = parse_head(
        concat!(
            "POST /MediaRenderer/RenderingControl/Control HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "SOAPACTION:  \"x#y\" \r\n",
            "Content-Length: 12"
        ),
        &limits,
    )
    .expect("a valid head");
    assert_eq!(head.method, "POST");
    assert_eq!(head.target, "/MediaRenderer/RenderingControl/Control");
    assert_eq!(head.content_length, 12);
    assert_eq!(
        head.headers,
        vec![
            ("Host".to_string(), "127.0.0.1".to_string()),
            ("SOAPACTION".to_string(), "\"x#y\"".to_string()),
            ("Content-Length".to_string(), "12".to_string()),
        ]
    );
    // Equal repeated lengths are one length; a bare request line has none; HTTP/1.0 is read.
    assert!(
        parse_head(
            "POST / HTTP/1.1\r\nContent-Length: 3\r\ncontent-length: 3",
            &limits
        )
        .is_ok()
    );
    assert_eq!(
        parse_head("GET / HTTP/1.0", &limits).map(|head| head.content_length),
        Ok(0)
    );
    // And what it refuses: a fifth part of the request line, a space where the colon must be, a ten-digit length.
    assert_eq!(parse_head("GET / HTTP/1.1 extra", &limits), Err(400));
    assert_eq!(parse_head("GET / HTTP/1.1\r\nA : b", &limits), Err(400));
    assert_eq!(
        parse_head("POST / HTTP/1.1\r\nContent-Length: 1234567890", &limits),
        Err(400)
    );
}

#[test]
fn an_answer_is_framed_with_its_own_length_and_a_line_break_cannot_split_it() {
    let headers = vec![
        ("CONTENT-TYPE".to_string(), "text/xml".to_string()),
        ("Content-Length".to_string(), "999".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
    ];
    let bytes = render_response(200, &headers, b"abc").expect("a frameable answer");
    let text = String::from_utf8(bytes).expect("ASCII");
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("CONTENT-TYPE: text/xml\r\n"));
    assert!(text.contains("Content-Length: 3\r\nConnection: close\r\n\r\nabc"));
    assert!(
        !text.contains("999"),
        "the endpoint's own length is replaced"
    );
    assert!(
        !text.contains("keep-alive"),
        "the endpoint cannot keep a connection alive"
    );
    // The permitted counterpart above; now the refusals: a value that would start a new header line, and a bad name.
    let split = vec![("X".to_string(), "a\r\nSet-Cookie: b".to_string())];
    assert!(render_response(200, &split, b"").is_none());
    let bad_name = vec![("X Y".to_string(), "a".to_string())];
    assert!(render_response(200, &bad_name, b"").is_none());
    // A bare refusal has no body and says so.
    let bare = render_response(413, &[], b"").expect("a bare answer");
    assert_eq!(
        String::from_utf8(bare).expect("ASCII"),
        "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

// ---- discovery: the description, the topology entry and the responder beside the HTTP shim -------------------------------------

const WAIT: Duration = Duration::from_millis(300);

fn discovery_session() -> UnifiedGroupSession {
    let (first, second) = (FIXTURE_DEVICE_UUID, FIXTURE_OTHER_UUID);
    fixture_session_for(first, second).expect("a session")
}

fn try_start(
    identity: &DiscoveryIdentity,
    discovery: DiscoveryLimits,
) -> Result<FsonosLoopback, String> {
    let session = discovery_session();
    FsonosLoopback::start_discoverable(session, identity, Policy::LocalLink, quick(), discovery)
}

fn discoverable(policy: Policy) -> FsonosLoopback {
    let identity = DiscoveryIdentity::fixture();
    let discovery = DiscoveryLimits::standard();
    FsonosLoopback::start_discoverable(discovery_session(), &identity, policy, quick(), discovery)
        .expect("the discoverable shim starts")
}

fn fixture_device() -> Device {
    DiscoveryIdentity::fixture().device().expect("accepted")
}

/// A raw UDP search for `target` sent to the responder, and every datagram it answers with (bounded in time and in number).
fn ask(server: &FsonosLoopback, target: &str) -> Vec<String> {
    let to = server.discovery_addr().expect("a discoverable shim");
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = UdpSocket::bind(any).expect("a client socket");
    let wait = Some(WAIT);
    socket.set_read_timeout(wait).expect("a read timeout");
    let head = "M-SEARCH * HTTP/1.1\r\nHOST: x\r\n";
    let man = "\"ssdp:discover\"";
    let bytes = format!("{head}MAN: {man}\r\nMX: 1\r\nST: {target}\r\n\r\n").into_bytes();
    socket.send_to(&bytes, to).expect("sent");
    let mut out = Vec::new();
    let mut buf = [0_u8; 2048];
    while out.len() < 32 {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => out.push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(_) => break,
        }
    }
    out
}

fn received(server: &FsonosLoopback) -> u32 {
    match server.discovery_report() {
        Some(report) => report.received,
        None => 0,
    }
}

#[test]
fn the_description_is_the_cores_document_served_to_the_local_link_and_nothing_else_changes() {
    let server = discoverable(Policy::LocalLink);
    let device = fixture_device();
    let get = http("GET", DESCRIPTION_PATH, &[], b"");
    let wire = exchange(server.addr(), &get).expect("an answer");
    assert_eq!(wire.status, 200);
    let kind = wire.header("content-type");
    assert_eq!(kind, Some(DESCRIPTION_CONTENT_TYPE));
    let length = wire.header("content-length").expect("a length");
    assert_eq!(length, wire.body.len().to_string());
    assert_eq!(wire.body, device.description_xml());
    // Independent of the core's builder: the room label the actual client reads is on the wire as its own element.
    let room = format!("<roomName>{FIXTURE_ROOM}</roomName>");
    assert!(wire.body.contains(&room));

    // The paired refusals: another path and another method are the endpoint's, not the description's.
    let other = http("GET", "/xml/other.xml", &[], b"");
    let wire = exchange(server.addr(), &other).expect("an answer");
    assert_ne!(wire.status, 200);
    assert!(!wire.body.contains("<UDN>"));
    let posted = http("POST", DESCRIPTION_PATH, &[], b"x");
    let wire = exchange(server.addr(), &posted).expect("an answer");
    assert_ne!(wire.status, 200);
    assert!(!wire.body.contains("<UDN>"));

    let report = server.stop();
    assert_eq!(report.described, 1);
    assert_eq!(report.served, 2);
    assert!(report.reconciled());
}

#[test]
fn a_tailnet_connection_is_not_given_the_description_and_a_plain_shim_has_none_to_give() {
    let tailnet = discoverable(Policy::UnauthenticatedTailnet);
    let get = http("GET", DESCRIPTION_PATH, &[], b"");
    let wire = exchange(tailnet.addr(), &get).expect("an answer");
    // The endpoint speaks POST, SUBSCRIBE and UNSUBSCRIBE and answers every other method with its bare 405, whatever the ingress (a
    // control POST from the same connection is the 401). What matters here is that the document is not given.
    assert_eq!(wire.status, 405);
    assert!(wire.body.is_empty());
    let report = tailnet.stop();
    assert_eq!(report.described, 0);
    assert_eq!(report.served, 1);

    let plain = start();
    assert_eq!(plain.discovery_addr(), None);
    assert_eq!(plain.discovery_report(), None);
    let wire = exchange(plain.addr(), &get).expect("an answer");
    assert_ne!(wire.status, 200);
    assert!(!wire.body.contains("<UDN>"));
    assert_eq!(plain.stop().described, 0);
}

#[test]
fn the_topology_names_the_served_member_and_leaves_its_neighbour_without_a_location() {
    let server = discoverable(Policy::LocalLink);
    let location = fixture_device().location();
    let zones = post(Service::ZoneGroupTopology, "GetZoneGroupState", &[]);
    let wire = exchange(server.addr(), &zones).expect("an answer");
    assert_eq!(wire.status, 200);
    assert!(wire.body.contains(FIXTURE_DEVICE_UUID));
    assert!(wire.body.contains(FIXTURE_OTHER_UUID));
    assert!(wire.body.contains(FIXTURE_ROOM));
    // Exactly one location in the whole document: the neighbour has none to show.
    assert_eq!(wire.body.matches(location.as_str()).count(), 1);

    // The permitted counterpart above; a shim not started discoverable lists no location at all.
    let plain = start();
    let wire = exchange(plain.addr(), &zones).expect("an answer");
    assert_eq!(wire.status, 200);
    assert!(!wire.body.contains(location.as_str()));
}

#[test]
fn a_discoverable_start_that_the_core_or_the_limits_refuse_fails_and_a_valid_one_starts() {
    let valid = DiscoveryIdentity::fixture();
    let standard = DiscoveryLimits::standard();
    assert!(try_start(&valid, standard).is_ok());

    let unusable = DiscoveryLimits {
        max_datagrams: 0,
        ..standard
    };
    let Err(error) = try_start(&valid, unusable) else {
        panic!("unusable discovery limits are refused");
    };
    assert!(error.contains("discovery limits"));

    let bad_id = DiscoveryIdentity {
        uuid: "not-a-uuid".to_string(),
        room: FIXTURE_ROOM.to_string(),
    };
    let Err(error) = try_start(&bad_id, standard) else {
        panic!("a malformed id is refused");
    };
    assert!(error.contains("bad_uuid"));
}

#[test]
fn the_answer_the_description_and_the_topology_name_one_device_at_one_location() {
    let server = discoverable(Policy::LocalLink);
    let location = fixture_device().location();

    let answers = ask(&server, DEVICE_TYPE);
    assert_eq!(answers.len(), 1);
    assert!(answers[0].contains(&format!("LOCATION: {location}")));
    let usn = format!("USN: uuid:{FIXTURE_DEVICE_UUID}::{DEVICE_TYPE}");
    assert!(answers[0].contains(&usn));

    let get = http("GET", DESCRIPTION_PATH, &[], b"");
    let described = exchange(server.addr(), &get).expect("an answer");
    let udn = format!("<UDN>uuid:{FIXTURE_DEVICE_UUID}</UDN>");
    assert!(described.body.contains(&udn));

    let zones = post(Service::ZoneGroupTopology, "GetZoneGroupState", &[]);
    let topology = exchange(server.addr(), &zones).expect("an answer");
    assert!(topology.body.contains(location.as_str()));
    assert!(topology.body.contains(FIXTURE_DEVICE_UUID));

    wait_until("counted", || received(&server) == 1);
    let report = server.discovery_report().expect("a responder");
    assert_eq!(report.answered, 1);
    assert_eq!(report.replies_sent, 1);
    assert!(report.reconciled());
}

#[test]
fn a_restart_with_the_same_identity_answers_the_same_and_another_identity_answers_differently() {
    let first = discoverable(Policy::LocalLink);
    let before = ask(&first, DEVICE_TYPE);
    assert_eq!(before.len(), 1);
    drop(first);

    // Same identity, new sockets: the answer carries no port, boot counter or household, so it is the same bytes.
    let second = discoverable(Policy::LocalLink);
    assert_eq!(ask(&second, DEVICE_TYPE), before);
    drop(second);

    let other = DiscoveryIdentity {
        uuid: FIXTURE_OTHER_UUID.to_string(),
        room: "Den".to_string(),
    };
    let third = try_start(&other, DiscoveryLimits::standard()).expect("starts");
    let after = ask(&third, DEVICE_TYPE);
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    let usn = format!("USN: uuid:{FIXTURE_OTHER_UUID}::");
    assert!(after[0].contains(&usn));
}

#[test]
fn stopping_the_shim_stops_the_responder_and_neither_answers_afterwards() {
    let mut server = discoverable(Policy::LocalLink);
    assert_eq!(ask(&server, DEVICE_TYPE).len(), 1);
    let http_addr = server.addr();
    assert!(TcpStream::connect_timeout(&http_addr, WAIT).is_ok());

    server.shutdown();
    let report = server.discovery_report().expect("a responder");
    assert_eq!(report.stopped_by, DiscoveryStop::Requested);
    assert!(ask(&server, DEVICE_TYPE).is_empty());
    assert!(TcpStream::connect_timeout(&http_addr, WAIT).is_err());
}

// ---- the boot incarnation: a stale subscription id is not honoured after a restart, even after a fresh subscription --------

/// The `SID` of the subscription granted to a new `SUBSCRIBE` for the RenderingControl events, sent to the shim at `addr`.
fn new_subscription(addr: SocketAddr) -> String {
    let callback = format!("<http://{}:4000/RenderingControl>", Ipv4Addr::LOCALHOST);
    let headers = [
        ("CALLBACK", callback.as_str()),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];
    let path = Service::RenderingControl.event_path();
    let request = http("SUBSCRIBE", path, &headers, b"");
    let wire = exchange(addr, &request).expect("an answer");
    assert_eq!(wire.status, 200);
    wire.header("sid").expect("a SID").to_string()
}

/// The whole answer to a renewal (`SUBSCRIBE` with a `SID`) or an unsubscribe, sent to the shim at `addr`.
fn event_answer(addr: SocketAddr, method: &str, headers: &[(&str, &str)]) -> Wire {
    let path = Service::RenderingControl.event_path();
    let request = http(method, path, headers, b"");
    exchange(addr, &request).expect("an answer")
}

/// Whether `sid` is `uuid:` and a lowercase 8-4-4-4-12 hex UUID with version 4, a variant of 8, 9, a or b, and the counter at 1.
fn is_boot_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("uuid:") else {
        return false;
    };
    let groups: Vec<&str> = rest.split('-').collect();
    let widths = [8, 4, 4, 4, 12];
    let hex = |group: &str, width: usize| {
        let lower = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        group.len() == width && group.bytes().all(lower)
    };
    if groups.len() != widths.len() || !groups.iter().zip(widths).all(|(g, w)| hex(g, w)) {
        return false;
    }
    let version = groups[2].starts_with('4');
    let variant = matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b');
    version && variant && groups[4] == "000000000001"
}

#[test]
fn a_restarted_shim_never_honours_an_old_sid_even_after_a_fresh_subscription() {
    let first = start();
    let old = new_subscription(first.addr());
    drop(first);

    let second = start();
    let addr = second.addr();
    let fresh = new_subscription(addr);
    // Two boots, two incarnations: the first id of the second boot is not the first id of the first (they share a namespace with
    // probability 2^-74). Each is a UUID-shaped id whose counter is the 48-bit 1.
    assert_ne!(old, fresh, "two boots handed out the same subscription id");
    for sid in [&old, &fresh] {
        assert!(is_boot_sid(sid), "{sid}");
    }

    // The counterexample a constant nonce allows, retried AFTER the fresh subscription: the old id must change nothing.
    let gone = event_answer(addr, "UNSUBSCRIBE", &[("SID", old.as_str())]);
    assert_eq!(gone.status, 412);
    let timeout = ("TIMEOUT", "Second-900");
    let stale = event_answer(addr, "SUBSCRIBE", &[("SID", old.as_str()), timeout]);
    assert_eq!(stale.status, 412);

    // The permitted counterpart: the fresh subscription is untouched. Its own SID renews (the new time is granted), and only its
    // own unsubscribe removes it.
    let renewed = event_answer(addr, "SUBSCRIBE", &[("SID", fresh.as_str()), timeout]);
    assert_eq!(renewed.status, 200);
    assert_eq!(renewed.header("sid"), Some(fresh.as_str()));
    assert_eq!(renewed.header("timeout"), Some("Second-900"));
    let ended = event_answer(addr, "UNSUBSCRIBE", &[("SID", fresh.as_str())]);
    assert_eq!(ended.status, 200);
    let again = event_answer(addr, "UNSUBSCRIBE", &[("SID", fresh.as_str())]);
    assert_eq!(again.status, 412);
}

/// A shim whose boot incarnation is whatever `boot` hands it. Only the plant below uses a given value.
fn start_with_boot(
    boot: impl FnOnce() -> Result<[u8; INCARNATION_BYTES], IncarnationError>,
) -> FsonosLoopback {
    let session = fixture_session().expect("the fixture session builds");
    let policy = Policy::LocalLink;
    FsonosLoopback::start_inner(session, FIXTURE_MEMBER, policy, quick(), None, None, boot)
        .expect("the shim starts")
}

#[test]
fn plant_two_boots_handed_the_same_bytes_let_a_stale_sid_remove_the_new_subscription() {
    // PLANT, not a feature: both boots are handed the SAME ten bytes through the `boot` seam, which is what one constant nonce did.
    // It reproduces the defect, so the restart test above is shown able to fail: the first ids are equal, and the stale unsubscribe
    // of the old boot removes the subscription the new boot has just granted.
    let same = || Ok([7, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let first = start_with_boot(same);
    let old = new_subscription(first.addr());
    drop(first);

    let second = start_with_boot(same);
    let addr = second.addr();
    let fresh = new_subscription(addr);
    assert_eq!(
        old, fresh,
        "one incarnation gives every boot the same first id"
    );
    let stale = event_answer(addr, "UNSUBSCRIBE", &[("SID", old.as_str())]);
    assert_eq!(
        stale.status, 200,
        "the stale id removed the new subscription"
    );
    let gone = event_answer(addr, "UNSUBSCRIBE", &[("SID", fresh.as_str())]);
    assert_eq!(gone.status, 412);
}

/// The `SID` the core grants a local-link `SUBSCRIBE` made straight to `plane`.
fn granted_sid(plane: &mut ControlPlane, session: &mut UnifiedGroupSession) -> String {
    let callback = format!("<http://{}:4000/RenderingControl>", Ipv4Addr::LOCALHOST);
    let headers = [
        ("CALLBACK", callback.as_str()),
        ("NT", "upnp:event"),
        ("TIMEOUT", "Second-300"),
    ];
    let request = HttpRequest {
        method: "SUBSCRIBE",
        path: Service::RenderingControl.event_path(),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        ingress: Ingress::LocalLegacy,
        headers: &headers,
        body: b"",
    };
    let handled = plane.handle_request(session, START_NS, &request);
    assert_eq!(handled.response.status, 200);
    let sid = handled
        .response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("sid"))
        .map(|(_, value)| value.clone());
    sid.expect("a SID")
}

#[test]
fn the_boot_key_is_the_only_input_that_makes_two_boots_ids_differ() {
    // CONTROL, not a feature: the fixture constructor gives every boot the same nonce, so the first id of two boots is the same
    // string, and a stale id of one is a valid id of the other. This is the defect the incarnation closes.
    let mut one = fixture_session().expect("a session");
    let mut two = fixture_session().expect("a session");
    let mut plane_one = ControlPlane::new(&one, FIXTURE_MEMBER, START_NS).expect("a plane");
    let mut plane_two = ControlPlane::new(&two, FIXTURE_MEMBER, START_NS).expect("a plane");
    let sid_one = granted_sid(&mut plane_one, &mut one);
    let sid_two = granted_sid(&mut plane_two, &mut two);
    assert_eq!(sid_one, sid_two, "the fixture nonce is constant");
    // The legacy constructor's ids are today's, byte for byte: nonce, four zero hex digits, the fixed version and variant groups,
    // and the 48-bit counter at 1.
    assert_eq!(sid_one, "uuid:51510001-0000-4000-8000-000000000001");

    // With an incarnation as input the same first id differs, and the same incarnation repeats it: the input, and nothing the
    // endpoint adds, decides. (These values are controls for the plumbing; the shim's own value comes from the host.)
    let member = FIXTURE_MEMBER;
    let mut a = ControlPlane::with_incarnation(&one, member, START_NS, [1; 10]).expect("a plane");
    let mut b = ControlPlane::with_incarnation(&two, member, START_NS, [2; 10]).expect("a plane");
    let mut c = ControlPlane::with_incarnation(&two, member, START_NS, [2; 10]).expect("a plane");
    let sid_a = granted_sid(&mut a, &mut one);
    let sid_b = granted_sid(&mut b, &mut two);
    let sid_c = granted_sid(&mut c, &mut two);
    assert_ne!(sid_a, sid_b);
    assert_eq!(sid_b, sid_c);
}

#[test]
fn the_host_incarnation_comes_from_the_host_and_differs_between_reads() {
    // Two reads of the host entropy are equal with probability 2^-80; a failure here is that, or an entropy device that is not one.
    let first = host_incarnation().expect("the host gives an incarnation");
    let second = host_incarnation().expect("the host gives an incarnation");
    assert_ne!(first, second, "two reads gave the same incarnation");
}

#[test]
fn a_boot_that_cannot_get_an_incarnation_fails_typed_and_starts_nothing() {
    let session = fixture_session().expect("the fixture session builds");
    let failing = || Err(IncarnationError::Short);
    let started = FsonosLoopback::start_inner(
        session,
        FIXTURE_MEMBER,
        Policy::LocalLink,
        quick(),
        None,
        None,
        failing,
    );
    let Err(reason) = started else {
        panic!("a boot without an incarnation started");
    };
    assert_eq!(reason, "incarnation: entropy_short");

    // The device itself failing is typed the same way, by what went wrong.
    let missing = incarnation::incarnation_from(Path::new("/nonexistent/entropy"));
    assert_eq!(
        missing,
        Err(IncarnationError::Unavailable(io::ErrorKind::NotFound))
    );
    assert_eq!(IncarnationError::Short.code(), "entropy_short");
    assert_eq!(missing.unwrap_err().code(), "entropy_unavailable");

    // The permitted counterpart: with the host's incarnation the same start succeeds.
    assert!(start_with(Policy::LocalLink, quick()).stop().reconciled());
}

#[cfg(unix)]
#[test]
fn an_entropy_device_that_ends_early_is_short_and_one_that_cannot_be_read_is_unavailable() {
    let empty = incarnation::incarnation_from(Path::new("/dev/null"));
    assert_eq!(empty, Err(IncarnationError::Short));
    let directory = incarnation::incarnation_from(Path::new("/"));
    assert!(matches!(directory, Err(IncarnationError::Unavailable(_))));
    // A device that answers with ten identical bytes (`/dev/zero` is one) is not entropy, and is refused as such.
    let zeros = incarnation::incarnation_from(Path::new("/dev/zero"));
    assert_eq!(zeros, Err(IncarnationError::Degenerate));
    assert_eq!(IncarnationError::Degenerate.code(), "entropy_degenerate");
    // The permitted counterpart: the real device gives ten bytes.
    assert!(incarnation::incarnation_from(Path::new("/dev/urandom")).is_ok());
}

// ---- discovery and eventing on one shim ---------------------------------------------------------------------------------------

/// A callback destination for a shim that is only asked to GRANT subscriptions: a loopback port that was bound and let go, so a
/// delivery to it is refused at once and counted as failed. Nothing listens, and nothing here needs an event to arrive; the actual
/// client test (`tests/g03/fsonos-client/tests/composed.rs`) is where an `EventSink` hears them.
fn closed_target() -> CallbackTarget {
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let addr = TcpListener::bind(any)
        .and_then(|listener| listener.local_addr())
        .expect("a loopback port");
    CallbackTarget::new(addr, "/RenderingControl").expect("an allowed target")
}

/// Every argument of `start_discoverable_eventing` with a valid value, for a test to change the one it is about.
struct ComposeArgs {
    identity: DiscoveryIdentity,
    policy: Policy,
    limits: LoopbackLimits,
    discovery: DiscoveryLimits,
    callbacks: CallbackLimits,
    target: CallbackTarget,
}

impl ComposeArgs {
    fn new() -> Self {
        Self {
            identity: DiscoveryIdentity::fixture(),
            policy: Policy::LocalLink,
            limits: quick(),
            discovery: DiscoveryLimits::standard(),
            callbacks: CallbackLimits::standard(),
            target: closed_target(),
        }
    }

    fn start(self) -> Result<FsonosLoopback, String> {
        FsonosLoopback::start_discoverable_eventing(
            discovery_session(),
            &self.identity,
            self.policy,
            self.limits,
            self.discovery,
            self.target,
            self.callbacks,
        )
    }
}

fn start_composed(change: impl FnOnce(&mut ComposeArgs)) -> Result<FsonosLoopback, String> {
    let mut setup = ComposeArgs::new();
    change(&mut setup);
    setup.start()
}

#[test]
fn a_composed_start_that_the_core_or_any_limits_refuse_fails_and_a_valid_one_starts() {
    // The permitted counterpart: both features are on the one shim, on loopback sockets of its own.
    let both = start_composed(|_| {}).expect("a composed start");
    assert!(both.addr().ip().is_loopback());
    assert!(both.discovery_addr().is_some_and(|a| a.ip().is_loopback()));
    assert!(both.callback_report().is_some());
    drop(both);

    let refusals = [
        (
            "discovery limits",
            start_composed(|s| s.discovery.max_datagrams = 0),
            "discovery limits",
        ),
        (
            "callback limits",
            start_composed(|s| s.callbacks.queue = 0),
            "callback limits",
        ),
        (
            "loopback limits",
            start_composed(|s| s.limits.lifetime = Duration::ZERO),
            "loopback limits",
        ),
        (
            "a malformed id",
            start_composed(|s| s.identity.uuid = "not-a-uuid".to_string()),
            "bad_uuid",
        ),
    ];
    for (label, started, word) in refusals {
        let Err(error) = started else {
            panic!("{label}: a refusal was expected");
        };
        assert!(error.contains(word), "{label}: {error}");
    }

    // The checks run in the order `start_discoverable` runs its own: with both sets of limits unusable, the discovery limits are
    // the ones named.
    let both_unusable = start_composed(|s| {
        s.discovery.max_datagrams = 0;
        s.callbacks.queue = 0;
    });
    let Err(error) = both_unusable else {
        panic!("both unusable");
    };
    assert!(error.contains("discovery limits"), "{error}");

    // A refusal leaves nothing behind that a valid start cannot get past.
    assert!(start_composed(|_| {}).is_ok());
}

#[test]
fn a_composed_shim_describes_serves_and_subscribes_on_one_endpoint_and_counts_each() {
    let setup = ComposeArgs::new();
    let allowed = format!("<{}>", setup.target.url());
    let server = setup.start().expect("a composed start");
    let addr = server.addr();

    // Discovery: the search is answered by the responder of this shim.
    assert_eq!(ask(&server, DEVICE_TYPE).len(), 1);

    // The description is the core's document, answered by the shim itself.
    let get = http("GET", DESCRIPTION_PATH, &[], b"");
    let described = exchange(addr, &get).expect("an answer");
    assert_eq!(described.status, 200);
    let udn = format!("<UDN>uuid:{FIXTURE_DEVICE_UUID}</UDN>");
    assert!(described.body.contains(&udn));

    // Control on the same endpoint reads the live session of the member the identity names.
    let read = post(RC, "GetVolume", &MASTER);
    let volume = exchange(addr, &read).expect("an answer");
    assert_eq!(volume.status, 200);
    assert!(volume.body.contains("<CurrentVolume>50</CurrentVolume>"));

    // Events: a callback other than the allowed one is the shim's 412 before the core is called, and counted; the allowed one is
    // granted by the core, and its first event is offered to the delivery queue.
    let other = format!("<http://{}:4000/RenderingControl>", Ipv4Addr::LOCALHOST);
    let path = RC.event_path();
    let subscribe = |callback: &str| {
        let headers = [
            ("CALLBACK", callback),
            ("NT", "upnp:event"),
            ("TIMEOUT", "Second-300"),
        ];
        exchange(addr, &http("SUBSCRIBE", path, &headers, b"")).expect("an answer")
    };
    assert_eq!(subscribe(other.as_str()).status, 412);
    let granted = subscribe(allowed.as_str());
    assert_eq!(granted.status, 200);
    assert!(
        granted
            .header("sid")
            .is_some_and(|sid| sid.starts_with("uuid:"))
    );
    wait_until("the first event to be offered", || {
        let report = server.callback_report();
        report.is_some_and(|report| report.offered == 1)
    });
    let sent = server.callback_report().expect("an eventing shim");
    assert_eq!(sent.offered, 1);
    assert_eq!(sent.subscribes_refused, 1);

    wait_until("the search to be counted", || received(&server) == 1);
    let heard = server.discovery_report().expect("a responder");
    assert_eq!(heard.answered, 1);
    assert!(heard.reconciled());

    // The shim's own count: the description once, two requests the endpoint answered (the read and the granted subscribe), and the
    // one refusal, a 412 that never reached the endpoint.
    let report = server.stop();
    assert_eq!(report.accepted, 4);
    assert_eq!(report.described, 1);
    assert_eq!(report.served, 2);
    assert_eq!(report.refused_statuses, [412]);
    assert!(report.reconciled());
}

#[test]
fn a_composed_tailnet_shim_describes_nothing_grants_nothing_and_offers_nothing() {
    // The permitted counterpart: the same server on the local link describes itself.
    let local = start_composed(|_| {}).expect("a composed start");
    let get = http("GET", DESCRIPTION_PATH, &[], b"");
    assert_eq!(exchange(local.addr(), &get).expect("an answer").status, 200);
    drop(local);

    let mut setup = ComposeArgs::new();
    setup.policy = Policy::UnauthenticatedTailnet;
    let allowed = format!("<{}>", setup.target.url());
    let server = setup.start().expect("a composed start");
    let addr = server.addr();
    assert_eq!(exchange(addr, &get).expect("an answer").status, 405);

    // The shim's callback check applies to the local link only: on the tailnet the endpoint's own refusal is the answer, whichever
    // callback is named, and nothing is counted as a refused subscribe or offered.
    let other = format!("<http://{}:4000/RenderingControl>", Ipv4Addr::LOCALHOST);
    let path = RC.event_path();
    for callback in [allowed.as_str(), other.as_str()] {
        let headers = [("CALLBACK", callback), ("NT", "upnp:event")];
        let wire = exchange(addr, &http("SUBSCRIBE", path, &headers, b"")).expect("an answer");
        assert_eq!(wire.status, 401);
    }
    let sent = server.callback_report().expect("an eventing shim");
    assert_eq!(sent.offered, 0);
    assert_eq!(sent.subscribes_refused, 0);
    let report = server.stop();
    assert_eq!(report.described, 0);
    assert_eq!(report.served, 3);
    assert!(report.refused_statuses.is_empty());
    assert!(report.reconciled());
}
