//! Tests for the loopback shim through a raw `std` client: the HTTP framing, the bounds and the refusals. The actual `fsonos` client is
//! `tests/g03/fsonos-client`. Each refusal here is paired with the permitted request that follows it, and every test ends with the
//! shim's own count of what it did.

use franken_control::fsonos::Service;

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
