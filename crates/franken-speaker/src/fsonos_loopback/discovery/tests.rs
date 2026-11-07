//! Tests for the SSDP responder through a raw `std` UDP client: the core's decisions on the wire, the bounds and the refusals. The
//! actual `fsonos` client is `tests/g03/fsonos-client/tests/discovery.rs`. Each refusal here is paired with the permitted search that
//! sits beside it, and every test that runs the responder ends with the responder's own count of what it did.

use super::*;

const MAN: &str = "\"ssdp:discover\"";
const TYPE: &str = ssdp::DEVICE_TYPE;
const CONTENT_DIRECTORY: &str = "urn:schemas-upnp-org:service:ContentDirectory:1";
const MEDIA_RENDERER: &str = "urn:schemas-upnp-org:device:MediaRenderer:1";
const OTHER_DEVICE_ID: &str = "uuid:00000000-0000-4000-8000-00000000ffff";
const UPPER_CASE_ID: &str = "00000000-0000-4000-8000-00000000A001";

fn device() -> Device {
    let identity = DiscoveryIdentity::fixture();
    identity.device().expect("the fixture is valid")
}

/// A search datagram as a controller frames it, with the `MAN` and `MX` the caller chooses.
fn search_with(man: &str, mx: &str, target: &str) -> Vec<u8> {
    let head = "M-SEARCH * HTTP/1.1\r\nHOST: x\r\n";
    format!("{head}MAN: {man}\r\nMX: {mx}\r\nST: {target}\r\n\r\n").into_bytes()
}

fn search(target: &str) -> Vec<u8> {
    search_with(MAN, "1", target)
}

/// What the core says to a well-formed search for `target`.
fn core_replies(target: &str) -> Vec<String> {
    let search = ssdp::MSearch {
        target: target.to_string(),
        mx: 1,
    };
    device().search_responses(&search)
}

fn limits() -> DiscoveryLimits {
    DiscoveryLimits {
        max_datagrams: 64,
        lifetime: Duration::from_secs(30),
    }
}

fn start(limits: DiscoveryLimits) -> Responder {
    Responder::start(device(), limits).expect("the responder starts")
}

fn client() -> UdpSocket {
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let socket = UdpSocket::bind(any).expect("a client socket");
    let wait = Some(Duration::from_millis(300));
    socket.set_read_timeout(wait).expect("a read timeout");
    socket
}

/// The read errors that mean "nothing more is coming".
fn quiet(kind: io::ErrorKind) -> bool {
    kind == io::ErrorKind::WouldBlock
        || kind == io::ErrorKind::TimedOut
        || kind == io::ErrorKind::ConnectionRefused
        || kind == io::ErrorKind::ConnectionReset
}

/// Everything that reaches `socket` until nothing arrives for the read timeout. Bounded by count as well.
fn collect(socket: &UdpSocket) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 2048];
    while out.len() < 32 {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => out.push(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Err(error) if quiet(error.kind()) => break,
            Err(error) => panic!("reading the answers failed: {:?}", error.kind()),
        }
    }
    out
}

fn send(from: &UdpSocket, to: SocketAddr, bytes: &[u8]) {
    from.send_to(bytes, to).expect("the datagram is sent");
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < give_up, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_stop(responder: &Responder, cause: DiscoveryStop) {
    wait_until("the stop", || responder.report().stopped_by == cause);
}

fn assert_refused(device: &Device, label: &str, bytes: &[u8], word: &str) {
    match judge(device, bytes) {
        Verdict::Refused(got) => assert_eq!(got, word, "{label}"),
        other => panic!("{label}: expected a refusal, got {other:?}"),
    }
}

fn assert_identity_refused(label: &str, uuid: &str, room: &str, word: &str) {
    let identity = DiscoveryIdentity {
        uuid: uuid.to_string(),
        room: room.to_string(),
    };
    let error = identity.device().expect_err(label);
    assert!(error.ends_with(word), "{label}: {error}");
}

// ---- the decision is the core's ---------------------------------------------------------------------------------------------

#[test]
fn the_core_decides_what_is_answered_and_a_service_it_does_not_serve_is_silent() {
    let device = device();
    // Permitted: the device type, each service the core advertises, and `ssdp:all`.
    let typed = judge(&device, &search(TYPE));
    assert_eq!(typed, Verdict::Replies(core_replies(TYPE)));
    for service in ssdp::SERVICES {
        let urn = service.urn();
        let answer = judge(&device, &search(urn));
        assert_eq!(answer, Verdict::Replies(core_replies(urn)));
        assert_eq!(core_replies(urn).len(), 1);
    }
    let all = judge(&device, &search("ssdp:all"));
    assert_eq!(all, Verdict::Replies(core_replies("ssdp:all")));
    assert_eq!(core_replies("ssdp:all").len(), ssdp::TARGET_COUNT);

    // The answer names this device's location and the type that was asked for.
    let replies = core_replies(TYPE);
    let reply = &replies[0];
    let location = format!("LOCATION: {}", device.location());
    assert!(reply.contains(&location));
    assert!(reply.contains(&format!("ST: {TYPE}")));

    // Silent, each well formed: the retired catalog, a device type this is not, another device's id, and other traffic.
    for target in [CONTENT_DIRECTORY, MEDIA_RENDERER, OTHER_DEVICE_ID] {
        assert_eq!(judge(&device, &search(target)), Verdict::Silent);
    }
    let notify = b"NOTIFY * HTTP/1.1\r\nHOST: x\r\nNT: x\r\nNTS: x\r\n\r\n";
    assert_eq!(judge(&device, notify), Verdict::Silent);
    let echoed = b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n";
    assert_eq!(judge(&device, echoed), Verdict::Silent);
}

#[test]
fn a_malformed_datagram_is_refused_under_the_cores_fixed_word_and_never_answered() {
    let device = device();
    // Permitted: the same search, well formed, is answered.
    let positive = judge(&device, &search(TYPE));
    assert!(matches!(positive, Verdict::Replies(_)));

    let no_quotes = search_with("ssdp:discover", "1", TYPE);
    assert_refused(&device, "no quotes", &no_quotes, "bad_man");
    let zero = search_with(MAN, "0", TYPE);
    assert_refused(&device, "mx zero", &zero, "bad_mx");
    let text = search_with(MAN, "abc", TYPE);
    assert_refused(&device, "mx text", &text, "bad_mx");
    let high = search_with(MAN, "121", TYPE);
    assert_refused(&device, "mx high", &high, "bad_mx");
    let accent = b"M-SEARCH \xc3\xa9\r\n\r\n";
    assert_refused(&device, "non ascii", accent, "not_printable_ascii");
    let open = b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\n";
    assert_refused(&device, "no empty line", open, "unterminated");
    let trailing = [search(TYPE), b"x".to_vec()].concat();
    assert_refused(&device, "trailing", &trailing, "trailing_bytes");
    let bare = b"M-SEARCH * HTTP/1.1\nHOST: x\n\n";
    assert_refused(&device, "bare lf", bare, "bare_line_ending");
    let unknown = b"GET / HTTP/1.1\r\n\r\n";
    assert_refused(&device, "unknown", unknown, "bad_request_line");
    let twice = b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\nHOST: y\r\n\r\n";
    assert_refused(&device, "host twice", twice, "duplicate_header");
    let huge = vec![b'a'; MAX_DATAGRAM + 1];
    assert_refused(&device, "over the cap", &huge, "too_large");
    // At the cap a datagram is not refused for its size but for being nonsense, which is another word.
    let at_cap = vec![b'a'; MAX_DATAGRAM];
    assert_refused(&device, "at the cap", &at_cap, "unterminated");
}

#[test]
fn only_a_loopback_peer_is_judged() {
    let device = device();
    let bytes = search(TYPE);
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let near = judge_from(&device, &bytes, loopback);
    assert_eq!(near, Some(Verdict::Replies(core_replies(TYPE))));
    assert_eq!(judge_from(&device, &bytes, elsewhere), None);
    // Nothing from elsewhere is parsed, so even nonsense from there leaves no refusal word behind.
    assert_eq!(judge_from(&device, b"\xff\xff", elsewhere), None);
}

// ---- the identity is the core's ---------------------------------------------------------------------------------------------

#[test]
fn an_identity_the_core_refuses_never_becomes_a_device_and_the_fixture_does() {
    let device = DiscoveryIdentity::fixture().device().expect("accepted");
    let host = Ipv4Addr::LOCALHOST;
    let expected = format!("http://{host}:{PLAYER_PORT}{}", ssdp::DESCRIPTION_PATH);
    assert_eq!(device.location(), expected);
    let xml = device.description_xml();
    assert!(xml.contains(FIXTURE_DEVICE_UUID));
    assert!(xml.contains(FIXTURE_ROOM));

    assert_identity_refused("bad id", "not-a-uuid", FIXTURE_ROOM, "bad_uuid");
    assert_identity_refused("upper", UPPER_CASE_ID, FIXTURE_ROOM, "bad_uuid");
    assert_identity_refused("no room", FIXTURE_DEVICE_UUID, "", "bad_name");
    assert_identity_refused("newline", FIXTURE_DEVICE_UUID, "Kit\r\nchen", "bad_name");
}

#[test]
fn unusable_limits_are_refused_and_the_standard_ones_are_not() {
    assert!(DiscoveryLimits::standard().usable());
    assert!(limits().usable());
    let none = DiscoveryLimits {
        max_datagrams: 0,
        ..limits()
    };
    let instant = DiscoveryLimits {
        lifetime: Duration::ZERO,
        ..limits()
    };
    assert!(!none.usable());
    assert!(!instant.usable());
}

// ---- the responder on its socket --------------------------------------------------------------------------------------------

#[test]
fn the_responder_answers_the_sender_only_from_a_loopback_socket_and_counts_what_it_read() {
    let responder = start(limits());
    assert_eq!(responder.addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_ne!(responder.addr().port(), 0);
    let (asker, bystander) = (client(), client());

    send(&asker, responder.addr(), &search(TYPE));
    assert_eq!(collect(&asker), core_replies(TYPE));
    assert!(collect(&bystander).is_empty());

    wait_until("counted", || responder.report().received == 1);
    let report = responder.report();
    assert_eq!(report.answered, 1);
    assert_eq!(report.replies_sent, 1);
    assert_eq!(report.silent + report.foreign + report.failed, 0);
    assert!(report.refusals.is_empty());
    assert!(report.reconciled());
    assert_eq!(report.stopped_by, DiscoveryStop::Running);
}

#[test]
fn a_responder_nobody_asked_says_nothing() {
    let responder = start(limits());
    let listener = client();
    assert!(collect(&listener).is_empty());
    let report = responder.report();
    assert_eq!(report.received, 0);
    assert_eq!(report.replies_sent, 0);
    assert!(report.reconciled());
}

#[test]
fn malformed_and_wrong_service_datagrams_get_no_answer_and_the_search_beside_them_does() {
    let responder = start(limits());
    let asker = client();
    let to = responder.addr();

    // The refused and the silent first, all sent before anything is read back, so one bounded wait covers them.
    send(&asker, to, &search_with("ssdp:discover", "1", TYPE));
    send(&asker, to, &search_with(MAN, "0", TYPE));
    send(&asker, to, b"M-SEARCH \xc3\xa9\r\n\r\n");
    send(&asker, to, &vec![b'a'; MAX_DATAGRAM + 1]);
    send(&asker, to, &search(CONTENT_DIRECTORY));
    send(&asker, to, b"NOTIFY * HTTP/1.1\r\nHOST: x\r\n\r\n");
    assert!(collect(&asker).is_empty());

    // The permitted counterpart, on the same socket, is answered.
    send(&asker, to, &search(TYPE));
    assert_eq!(collect(&asker), core_replies(TYPE));

    wait_until("counted", || responder.report().received == 7);
    let mut report = responder.report();
    assert_eq!(report.answered, 1);
    assert_eq!(report.replies_sent, 1);
    assert_eq!(report.silent, 2);
    report.refusals.sort_unstable();
    let expected = ["bad_man", "bad_mx", "not_printable_ascii", "too_large"];
    assert_eq!(report.refusals, expected);
    assert!(report.reconciled());
}

#[test]
fn the_responder_stops_at_its_datagram_cap_and_a_search_after_it_gets_no_answer() {
    let capped = DiscoveryLimits {
        max_datagrams: 3,
        ..limits()
    };
    let responder = start(capped);
    let asker = client();
    for round in 0..3 {
        send(&asker, responder.addr(), &search(TYPE));
        assert_eq!(collect(&asker), core_replies(TYPE), "round {round}");
    }
    wait_for_stop(&responder, DiscoveryStop::DatagramCap);
    send(&asker, responder.addr(), &search(TYPE));
    assert!(collect(&asker).is_empty());
    let report = responder.report();
    assert_eq!(report.received, 3);
    assert_eq!(report.replies_sent, 3);
    assert!(report.reconciled());
}

#[test]
fn the_responder_socket_bounds_writes_as_well_as_reads_and_the_responder_still_answers() {
    let (socket, addr) = bound_socket().expect("a bound socket");
    let read = socket.read_timeout().expect("a read timeout");
    let write = socket.write_timeout().expect("a write timeout");
    assert_eq!(read, Some(POLL));
    assert_eq!(write, Some(POLL));
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(socket.local_addr().expect("an address"), addr);
    drop(socket);

    // The permitted counterpart: a responder built the same way still answers a search.
    let responder = start(limits());
    let asker = client();
    send(&asker, responder.addr(), &search(TYPE));
    assert_eq!(collect(&asker), core_replies(TYPE));
    wait_until("counted", || responder.report().received == 1);
    let report = responder.report();
    assert_eq!(report.replies_sent, 1);
    assert!(report.reconciled());
}

#[test]
fn the_responder_stops_by_itself_at_its_lifetime_and_when_asked_and_when_dropped() {
    let brief = DiscoveryLimits {
        lifetime: Duration::from_millis(150),
        ..limits()
    };
    let short = start(brief);
    wait_for_stop(&short, DiscoveryStop::Lifetime);

    // Permitted while it runs; silent once stopped.
    let mut asked = start(limits());
    let asker = client();
    send(&asker, asked.addr(), &search(TYPE));
    assert_eq!(collect(&asker).len(), 1);
    asked.stop(Duration::from_secs(2));
    assert_eq!(asked.report().stopped_by, DiscoveryStop::Requested);
    send(&asker, asked.addr(), &search(TYPE));
    assert!(collect(&asker).is_empty());

    // Dropping the handle stops and joins the thread.
    let dropped = start(limits());
    let at = dropped.addr();
    send(&asker, at, &search(TYPE));
    assert_eq!(collect(&asker).len(), 1);
    drop(dropped);
    send(&asker, at, &search(TYPE));
    assert!(collect(&asker).is_empty());
}
