//! Tests of the callback delivery by itself, against plain `std` listeners and hand-built notifications: the framing, the single
//! allowed destination, and the bounds. The end-to-end behaviour (the core's own notifications, the actual `fsonos` client
//! subscribing and a real `fsonos-proto` listener receiving) is `tests/g03/fsonos-client/tests/eventing.rs`. Each refusal here is
//! paired with the permitted delivery that sits beside it.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

use franken_control::fsonos::Service;

use super::*;

const BODY: &str = "<e:propertyset/>";
const OK: &str = "HTTP/1.1 200 OK";
const MOVED: &str = "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.9/";
const EMPTY: &str = "HTTP/1.1 204 No Content";

fn limits() -> CallbackLimits {
    CallbackLimits {
        queue: 4,
        max_request_bytes: 4096,
        connect_timeout: Duration::from_millis(500),
        io_timeout: Duration::from_millis(400),
        lifetime: Duration::from_secs(30),
    }
}

/// A listener on an ephemeral loopback port, not yet accepting.
fn listener() -> TcpListener {
    let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let listener = TcpListener::bind(any).expect("a listener");
    listener.set_nonblocking(true).expect("nonblocking");
    listener
}

fn target_of(listener: &TcpListener, path: &str) -> CallbackTarget {
    let addr = listener.local_addr().expect("an address");
    CallbackTarget::new(addr, path).expect("an allowed target")
}

fn notification(callback: &str, seq: u32, body: &str) -> Notification {
    Notification {
        sid: "uuid:test-sid".to_string(),
        service: Service::RenderingControl,
        callback: callback.to_string(),
        seq,
        body: body.to_string(),
    }
}

/// Wait up to `within` for a connection; `None` when none came.
fn accept_within(listener: &TcpListener, within: Duration) -> Option<TcpStream> {
    let give_up = Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(_) if Instant::now() < give_up => thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    }
}

/// Whether a whole request (head and the body its `Content-Length` names) is in `buf`.
fn complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

/// Accept one connection per status in `statuses`, in order: read one whole request, answer it with that status, and return
/// every request received.
fn serve(listener: TcpListener, statuses: Vec<&'static str>) -> JoinHandle<Vec<Vec<u8>>> {
    let tail = "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let answer = |status: &str| format!("{status}{tail}").into_bytes();
    let answers = statuses.into_iter().map(answer).collect();
    serve_raw(listener, answers)
}

/// Accept one connection per answer in `answers`, in order: read one whole request, write exactly those bytes (nothing added,
/// so a status line can be left unterminated or ended any way), close, and return every request received.
fn serve_raw(listener: TcpListener, answers: Vec<Vec<u8>>) -> JoinHandle<Vec<Vec<u8>>> {
    thread::spawn(move || {
        let mut requests = Vec::new();
        for answer in answers {
            let within = Duration::from_secs(5);
            let mut stream = accept_within(&listener, within).expect("a connection");
            stream.set_nonblocking(false).expect("blocking");
            let wait = Some(within);
            stream.set_read_timeout(wait).expect("a read timeout");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !complete(&request) {
                let n = stream.read(&mut chunk).expect("a read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            stream.write_all(&answer).expect("an answer");
            requests.push(request);
        }
        requests
    })
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < give_up, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn idle(deliverer: &Deliverer) -> CallbackReport {
    wait_until("the delivery to settle", || deliverer.report().reconciled());
    deliverer.report()
}

#[test]
fn a_target_admits_one_plain_loopback_socket_and_path_and_nothing_else() {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 4000));
    let target = CallbackTarget::new(loopback, "/RenderingControl").expect("allowed");
    assert_eq!(target.url(), format!("http://{loopback}/RenderingControl"));

    let elsewhere = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 4000));
    let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4000));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 4000));
    let no_port = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    for (label, addr) in [
        ("a LAN address", elsewhere),
        ("the wildcard", wildcard),
        ("IPv6", v6),
        ("port zero", no_port),
    ] {
        assert!(CallbackTarget::new(addr, "/x").is_err(), "{label}");
    }
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    for (label, path) in [
        ("an empty path", ""),
        ("a relative path", "x"),
        ("a query", "/x?y=1"),
        ("a fragment", "/x#y"),
        ("a space", "/x y"),
        ("a percent escape", "/x%2fy"),
        ("a dot segment", "/x/../y"),
        ("a path over the bound", long.as_str()),
    ] {
        assert!(CallbackTarget::new(loopback, path).is_err(), "{label}");
    }
}

#[test]
fn the_cores_notification_is_delivered_unchanged_and_counted_only_on_a_200_answer() {
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    let url = target.url().to_string();
    let addr = target.addr;
    let (deliverer, outbox) = Deliverer::start(target, limits()).expect("starts");
    let served = serve(listener, vec![OK, MOVED, EMPTY]);

    // Three notifications, in order: answered 200, answered with a redirect, answered 204.
    let sent = notification(&url, 3, BODY);
    outbox.offer(std::slice::from_ref(&sent));
    outbox.offer(&[notification(&url, 4, BODY)]);
    outbox.offer(&[notification(&url, 5, BODY)]);
    let requests = served.join().expect("the listener");
    assert_eq!(requests.len(), 3);

    let first = String::from_utf8(requests[0].clone()).expect("ASCII");
    let head = format!("NOTIFY /RenderingControl HTTP/1.1\r\nHost: {addr}\r\n");
    assert!(first.starts_with(&head));
    // Exactly one `Host` and one `Content-Length` on the wire.
    assert_eq!(first.matches("Host: ").count(), 1);
    assert_eq!(first.matches("Content-Length: ").count(), 1);
    for (name, value) in sent.headers() {
        let line = format!("{name}: {value}\r\n");
        assert!(first.contains(&line), "{name}");
    }
    let length = BODY.len();
    let tail = format!("Content-Length: {length}\r\nConnection: close\r\n\r\n{BODY}");
    assert!(first.ends_with(&tail));
    assert!(String::from_utf8_lossy(&requests[1]).contains("SEQ: 4\r\n"));

    // The redirect is not followed and neither it nor a 204 is a delivery: one delivered, two failed, nothing else contacted.
    let report = idle(&deliverer);
    assert_eq!(report.offered, 3);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.failed, 2);
    let written: usize = requests.iter().map(Vec::len).sum();
    assert_eq!(report.bytes_out, to_u64(written));
    assert_eq!(report.refused + report.dropped + report.unframed, 0);
}

#[test]
fn a_notification_for_any_other_callback_is_refused_and_nothing_connects() {
    let allowed = listener();
    let other = listener();
    let target = target_of(&allowed, "/RenderingControl");
    let url = target.url().to_string();
    let (deliverer, outbox) = Deliverer::start(target, limits()).expect("starts");

    let elsewhere = other.local_addr().expect("an address");
    let wrong_port = format!("http://{elsewhere}/RenderingControl");
    let wrong_path = url.replace("RenderingControl", "AVTransport");
    let wrong_scheme = url.replace("http://", "https://");
    let not_a_url = "<script>".to_string();
    for callback in [&wrong_port, &wrong_path, &wrong_scheme, &not_a_url] {
        outbox.offer(&[notification(callback, 0, BODY)]);
    }
    let report = deliverer.report();
    assert_eq!(report.offered, 4);
    assert_eq!(report.refused, 4);
    assert_eq!(report.queued, 0);
    assert!(accept_within(&other, Duration::from_millis(150)).is_none());
    assert!(accept_within(&allowed, Duration::from_millis(150)).is_none());

    // The permitted counterpart on the same delivery: the allowed callback is contacted and answers.
    let served = serve(allowed, vec![OK]);
    outbox.offer(&[notification(&url, 0, BODY)]);
    served.join().expect("the listener");
    let report = idle(&deliverer);
    assert_eq!(report.offered, 5);
    assert_eq!(report.refused, 4);
    assert_eq!(report.delivered, 1);
}

#[test]
fn the_callback_header_is_matched_by_exact_equality_only() {
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    let url = target.url().to_string();
    let (_deliverer, outbox) = Deliverer::start(target, limits()).expect("starts");
    assert!(outbox.allows(&format!("<{url}>")));
    let wrong = [
        url.clone(),
        format!("<{url}"),
        format!("{url}>"),
        format!("<{url}/>"),
        format!("<{}>", url.to_uppercase()),
        format!("<{url}><{url}>"),
        String::new(),
    ];
    for value in &wrong {
        assert!(!outbox.allows(value), "{value}");
    }
}

#[test]
fn a_request_over_the_byte_bound_or_with_a_header_that_cannot_be_framed_is_not_sent() {
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    let url = target.url().to_string();
    let small = CallbackLimits {
        max_request_bytes: 512,
        ..limits()
    };
    let (deliverer, outbox) = Deliverer::start(target, small).expect("starts");

    let big = "x".repeat(600);
    outbox.offer(&[notification(&url, 0, &big)]);
    let mut split = notification(&url, 1, BODY);
    split.sid = "uuid:a\r\nSet-Cookie: b".to_string();
    outbox.offer(&[split]);
    let report = deliverer.report();
    assert_eq!(report.offered, 2);
    assert_eq!(report.unframed, 2);
    assert_eq!(report.queued, 0);
    assert!(accept_within(&listener, Duration::from_millis(150)).is_none());

    // The permitted counterpart: a request inside the bound is queued and delivered.
    let served = serve(listener, vec![OK]);
    outbox.offer(&[notification(&url, 2, BODY)]);
    served.join().expect("the listener");
    let report = idle(&deliverer);
    assert_eq!(report.unframed, 2);
    assert_eq!(report.delivered, 1);
}

#[test]
fn a_stalled_callback_is_bounded_and_a_full_queue_is_counted_without_blocking_the_offerer() {
    // A listener that takes connections into its backlog and never reads or answers: the delivery thread connects, writes, and
    // then waits for a status line that never comes.
    let stalled = listener();
    let target = target_of(&stalled, "/RenderingControl");
    let url = target.url().to_string();
    let quick = CallbackLimits {
        queue: 2,
        io_timeout: Duration::from_millis(100),
        ..limits()
    };
    let (deliverer, outbox) = Deliverer::start(target, quick).expect("starts");

    let started = Instant::now();
    for seq in 0..8 {
        outbox.offer(&[notification(&url, seq, BODY)]);
    }
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "the offerer never waits"
    );
    let report = deliverer.report();
    assert_eq!(report.offered, 8);
    assert_eq!(report.queued + report.dropped, 8);
    assert!(report.dropped >= 1, "{report:?}");

    // Every queued one is attempted within the bound and counted as failed, none as delivered.
    let report = idle(&deliverer);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failed, report.queued);
    assert!(report.reconciled());
}

#[test]
fn stopping_abandons_what_is_queued_counts_it_and_later_offers_are_dropped() {
    let stalled = listener();
    let target = target_of(&stalled, "/RenderingControl");
    let url = target.url().to_string();
    let quick = CallbackLimits {
        io_timeout: Duration::from_millis(100),
        ..limits()
    };
    let (mut deliverer, outbox) = Deliverer::start(target, quick).expect("starts");
    for seq in 0..4 {
        outbox.offer(&[notification(&url, seq, BODY)]);
    }
    deliverer.stop();
    let report = deliverer.report();
    assert_eq!(report.stopped_by, CallbackStop::Requested);
    assert_eq!(report.queued, 4);
    assert!(report.abandoned >= 3, "{report:?}");
    assert_eq!(report.failed + report.abandoned, report.queued);
    assert!(report.reconciled());

    // Once stopped, an offer is dropped and counted, never blocked or sent.
    outbox.offer(&[notification(&url, 9, BODY)]);
    let report = deliverer.report();
    assert_eq!(report.offered, 5);
    assert_eq!(report.dropped, 1);
    assert!(report.reconciled());
}

#[test]
fn unusable_limits_are_refused_and_the_standard_ones_are_not() {
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    assert!(Deliverer::start(target.clone(), CallbackLimits::standard()).is_ok());
    let no_queue = CallbackLimits {
        queue: 0,
        ..limits()
    };
    let tiny = CallbackLimits {
        max_request_bytes: 16,
        ..limits()
    };
    let no_io = CallbackLimits {
        io_timeout: Duration::ZERO,
        ..limits()
    };
    for (label, bad) in [("no queue", no_queue), ("tiny", tiny), ("no io", no_io)] {
        assert!(Deliverer::start(target.clone(), bad).is_err(), "{label}");
    }
}

// ---- the byte bound, the whole-write deadline, the status line, the join budget ---------------------------------------------

const ROOMY: usize = 1 << 20;

fn plain_target() -> CallbackTarget {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4000));
    CallbackTarget::new(addr, "/RenderingControl").expect("allowed")
}

/// The request the framing must produce, built here by plain formatting from the core's own headers: the oracle for the bytes
/// and for their exact count.
fn expected_request(target: &CallbackTarget, sent: &Notification) -> Vec<u8> {
    let (path, addr) = (&target.path, &target.addr);
    let mut text = format!("NOTIFY {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (name, value) in sent.headers() {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    let (length, body) = (sent.body.len(), &sent.body);
    let tail = format!("Content-Length: {length}\r\nConnection: close\r\n\r\n{body}");
    text.push_str(&tail);
    text.into_bytes()
}

#[test]
fn the_request_keeps_its_framing_byte_for_byte_and_the_bound_is_exact_to_the_byte() {
    let target = plain_target();
    let url = target.url().to_string();
    let sent = notification(&url, 3, BODY);
    let expected = expected_request(&target, &sent);

    // The bytes are the framing the module documents, in a roomy bound.
    let built = target.request(&sent, ROOMY);
    assert_eq!(built.as_deref(), Some(expected.as_slice()));

    // The paired bound: exactly the request's length admits it, with the same bytes; one byte less refuses it.
    let exact = expected.len();
    let at_exact = target.request(&sent, exact);
    assert_eq!(at_exact.as_deref(), Some(expected.as_slice()));
    assert!(target.request(&sent, exact - 1).is_none());
    assert!(target.request(&sent, exact + 1).is_some());
}

#[test]
fn a_body_or_an_sid_one_byte_past_the_bound_is_refused_and_one_inside_is_not() {
    let target = plain_target();
    let url = target.url().to_string();
    let with_body = |len: usize| notification(&url, 3, &"b".repeat(len));
    let with_sid = |len: usize| {
        let mut sent = notification(&url, 3, BODY);
        sent.sid = format!("uuid:{}", "s".repeat(len));
        sent
    };

    // A body of 100 bytes fills the bound exactly and 101 is one byte over (the length field has three digits either way).
    let exact = expected_request(&target, &with_body(100)).len();
    assert!(target.request(&with_body(100), exact).is_some());
    assert!(target.request(&with_body(101), exact).is_none());
    assert!(target.request(&with_body(101), exact + 1).is_some());

    // The same for the SID, which the core writes whole as the value of its `SID` header.
    let exact = expected_request(&target, &with_sid(100)).len();
    assert!(target.request(&with_sid(100), exact).is_some());
    assert!(target.request(&with_sid(101), exact).is_none());
    assert!(target.request(&with_sid(101), exact + 1).is_some());

    // Megabytes past a small bound are refused. That nothing proportional is built before the refusal is the order of the
    // checks in `request`, read from the source: the answer is `None` either way, and no heap is measured here.
    let small = 4096;
    assert!(target.request(&with_body(8 << 20), small).is_none());
    assert!(target.request(&with_sid(8 << 20), small).is_none());
}

#[test]
fn the_length_sum_is_checked_and_an_overflow_is_refused() {
    assert_eq!(wire_len([1, 2, 3]), Some(6));
    assert_eq!(wire_len(Vec::<usize>::new()), Some(0));
    assert_eq!(wire_len([usize::MAX]), Some(usize::MAX));
    assert_eq!(wire_len([usize::MAX - 1, 1]), Some(usize::MAX));
    assert_eq!(wire_len([usize::MAX, 1]), None);
    assert_eq!(wire_len([usize::MAX / 2 + 1, usize::MAX / 2 + 1]), None);
}

/// One scripted `write` call.
enum Step {
    Take(usize),
    Zero,
    Interrupt,
    Fail,
}

/// NOT a socket. A writer that does what its script says on each `write` call, after a fixed pause, and records the bytes it was
/// given and every timeout it was armed with. It drives the loop around `write` through cases a loopback socket cannot be made to
/// produce on demand (a zero-byte write, an interrupted call, a peer that moves one byte per call); it shows that loop's logic and
/// nothing about the kernel.
struct Scripted {
    steps: VecDeque<Step>,
    chunk: usize,
    pause: Duration,
    got: Vec<u8>,
    armed: Vec<Duration>,
    calls: usize,
}

impl Scripted {
    fn new(steps: Vec<Step>, chunk: usize, pause: Duration) -> Self {
        Self {
            steps: steps.into(),
            chunk,
            pause,
            got: Vec::new(),
            armed: Vec::new(),
            calls: 0,
        }
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        thread::sleep(self.pause);
        match self.steps.pop_front().unwrap_or(Step::Take(self.chunk)) {
            Step::Take(wanted) => {
                let taken = wanted.min(buf.len());
                self.got.extend_from_slice(&buf[..taken]);
                Ok(taken)
            }
            Step::Zero => Ok(0),
            Step::Interrupt => Err(io::Error::from(ErrorKind::Interrupted)),
            Step::Fail => Err(io::Error::from(ErrorKind::TimedOut)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The arming a real stream gets, recorded instead of applied.
fn record(sink: &mut Scripted, wait: Duration) -> io::Result<()> {
    sink.armed.push(wait);
    Ok(())
}

#[test]
fn the_write_loop_delivers_every_byte_in_order_across_short_and_interrupted_calls() {
    let bytes: Vec<u8> = (0..20_u8).collect();
    let steps = vec![Step::Take(3), Step::Interrupt, Step::Take(2)];
    let mut sink = Scripted::new(steps, 4, Duration::ZERO);
    let io_timeout = Duration::from_millis(400);
    let deadline = deadline_after(Duration::from_secs(5));
    assert!(write_within(
        &mut sink, &bytes, deadline, io_timeout, record
    ));
    assert_eq!(sink.got, bytes);
    // 3, an interruption, 2, then 4, 4, 4 and 3: seven calls, each armed first with a timeout inside 1 ms..=io_timeout.
    assert_eq!(sink.calls, 7);
    assert_eq!(sink.armed.len(), 7);
    let floor = Duration::from_millis(1);
    let inside = |wait: &Duration| *wait >= floor && *wait <= io_timeout;
    assert!(sink.armed.iter().all(inside));
}

#[test]
fn a_peer_taking_one_byte_per_call_runs_out_of_the_whole_deadline_and_a_quick_one_does_not() {
    let io_timeout = Duration::from_secs(1);
    let pause = Duration::from_millis(10);
    let request = vec![b'r'; 10_000];

    // The paired positive: the same peer and the same per-call pace, a request it can take well inside the deadline.
    let mut quick = Scripted::new(Vec::new(), 1, pause);
    let roomy = deadline_after(Duration::from_secs(2));
    assert!(write_within(
        &mut quick,
        &request[..5],
        roomy,
        io_timeout,
        record
    ));
    assert_eq!(quick.got, &request[..5]);

    // Every call is far inside `io_timeout`, so a per-call timeout alone would let all 10,000 of them (about 100 s) run. The whole
    // deadline ends it.
    let mut slow = Scripted::new(Vec::new(), 1, pause);
    let whole = Duration::from_millis(80);
    let deadline = deadline_after(whole);
    let started = Instant::now();
    let finished = write_within(&mut slow, &request, deadline, io_timeout, record);
    let took = started.elapsed();
    assert!(!finished);
    assert!(took < whole + Duration::from_millis(300), "{took:?}");
    assert!(slow.got.len() < request.len());
    // Each call was armed with the time left: never more than the whole deadline, and never more than the one before.
    assert!(slow.armed.iter().all(|wait| *wait <= whole));
    assert!(slow.armed.windows(2).all(|pair| pair[1] <= pair[0]));
}

#[test]
fn the_write_loop_ends_on_every_way_a_write_can_go_wrong() {
    // A zero-byte call, an error, a failed arm, a deadline already gone and an interrupt storm. The positives that pair with
    // these are the two tests above; the deadline is roomy except in the last two cases.
    let io_timeout = Duration::from_millis(400);
    let bytes = [7_u8; 10];
    let roomy = || deadline_after(Duration::from_secs(5));

    let mut zero = Scripted::new(vec![Step::Take(2), Step::Zero], 4, Duration::ZERO);
    assert!(!write_within(
        &mut zero,
        &bytes,
        roomy(),
        io_timeout,
        record
    ));
    assert_eq!(zero.got.len(), 2);
    assert_eq!(zero.calls, 2);

    let mut failing = Scripted::new(vec![Step::Fail], 4, Duration::ZERO);
    assert!(!write_within(
        &mut failing,
        &bytes,
        roomy(),
        io_timeout,
        record
    ));
    assert_eq!(failing.calls, 1);

    let mut unarmed = Scripted::new(Vec::new(), 4, Duration::ZERO);
    let refuse = |_sink: &mut Scripted, _wait: Duration| -> io::Result<()> {
        Err(io::Error::from(ErrorKind::InvalidInput))
    };
    assert!(!write_within(
        &mut unarmed,
        &bytes,
        roomy(),
        io_timeout,
        refuse
    ));
    assert_eq!(unarmed.calls, 0);

    // A deadline already gone: nothing is written.
    let mut late = Scripted::new(Vec::new(), 4, Duration::ZERO);
    let gone = Instant::now();
    thread::sleep(Duration::from_millis(5));
    assert!(!write_within(&mut late, &bytes, gone, io_timeout, record));
    assert_eq!(late.calls, 0);

    // Interruptions retry, but only while time is left: a storm of them ends at the deadline, not after all of them.
    let storm: Vec<Step> = (0..1000).map(|_| Step::Interrupt).collect();
    let mut stormy = Scripted::new(storm, 4, Duration::from_millis(1));
    let short = deadline_after(Duration::from_millis(30));
    let started = Instant::now();
    assert!(!write_within(
        &mut stormy,
        &bytes,
        short,
        io_timeout,
        record
    ));
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(stormy.got.is_empty());
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[test]
fn a_real_peer_that_drains_slowly_cannot_stretch_a_delivery_past_its_bound() {
    // A real loopback peer that reads 4 KiB and pauses 20 ms, over and over, against a 32 MiB request. Each of the sender's write
    // calls then finishes well inside `io_timeout`, so only the whole deadline can stop the delivery. Whether the kernel's socket
    // buffers could absorb a request of this size first depends on the host; 32 MiB is far past the buffering of the hosts this
    // runs on (argued, not measured), so the write path is what is expected to end it. The assertions hold either way: the delivery
    // ends inside its own bound and is not counted as delivered. With only a per-call timeout it would run for minutes.
    let listener = listener();
    let addr = listener.local_addr().expect("an address");
    let done = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&done);
    let drain = thread::spawn(move || {
        let within = Duration::from_secs(5);
        let mut stream = accept_within(&listener, within).expect("a connection");
        stream.set_nonblocking(false).expect("blocking");
        let wait = Some(Duration::from_millis(200));
        stream.set_read_timeout(wait).expect("a read timeout");
        let mut chunk = [0_u8; 4096];
        while !signal.load(Ordering::SeqCst) {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(_) => thread::sleep(Duration::from_millis(20)),
                Err(error) if is_timeout(&error) => {}
                Err(_) => break,
            }
        }
    });

    let quick = CallbackLimits {
        io_timeout: Duration::from_millis(150),
        ..limits()
    };
    let bound = quick.delivery_bound();
    let request = vec![b'x'; 32 << 20];
    let started = Instant::now();
    let got = attempt(addr, &request, &quick);
    let took = started.elapsed();
    done.store(true, Ordering::SeqCst);
    drain.join().expect("the peer thread");
    let limit = bound + Duration::from_millis(500);
    assert!(took < limit, "{took:?} against {limit:?}");
    assert!(!got.accepted);
}

#[test]
fn only_a_complete_crlf_terminated_http_1_status_200_line_is_a_delivery() {
    let delivered = [
        "HTTP/1.1 200 OK\r\n",
        "HTTP/1.0 200 OK\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200\r\n",
        "HTTP/1.1 200 \r\n",
        "HTTP/1.1 200 fine\tby me\r\n",
    ];
    for text in delivered {
        assert!(is_delivered(text.as_bytes()), "{text:?}");
    }

    let refused = [
        ("an unterminated line", "HTTP/1.1 200"),
        ("a line with no end", "HTTP/1.1 200 OK"),
        ("a CR with no LF", "HTTP/1.1 200 OK\r"),
        ("a bare LF", "HTTP/1.1 200 OK\n"),
        ("a bare LF before a CRLF", "HTTP/1.1 200 OK\n\r\n"),
        ("a malformed version", "HTTP/1.bad 200 OK\r\n"),
        ("a version past 1.1", "HTTP/1.2 200 OK\r\n"),
        ("a longer minor version", "HTTP/1.10 200 OK\r\n"),
        ("HTTP/2", "HTTP/2 200 OK\r\n"),
        ("HTTP/0.9", "HTTP/0.9 200 OK\r\n"),
        ("a lower case name", "http/1.1 200 OK\r\n"),
        ("no version", "200 OK\r\n"),
        ("two spaces", "HTTP/1.1  200 OK\r\n"),
        ("a longer code", "HTTP/1.1 2000 OK\r\n"),
        ("a code glued to its reason", "HTTP/1.1 200OK\r\n"),
        ("another 2xx", "HTTP/1.1 201 Created\r\n"),
        ("no content", "HTTP/1.1 204 No Content\r\n"),
        ("a redirect", "HTTP/1.1 302 Found\r\n"),
        ("a refusal", "HTTP/1.1 412 Precondition Failed\r\n"),
        ("a server error", "HTTP/1.1 500 Oops\r\n"),
        ("a leading space", " HTTP/1.1 200 OK\r\n"),
        ("an empty first line", "\r\nHTTP/1.1 200 OK\r\n"),
        ("a CR inside the reason", "HTTP/1.1 200 O\rK\r\n"),
        ("a doubled CR", "HTTP/1.1 200 OK\r\r\n"),
        ("a NUL in the reason", "HTTP/1.1 200 O\0K\r\n"),
        ("a later 200", "HTTP/1.1 404 No\r\nHTTP/1.1 200 OK\r\n"),
        ("nothing", ""),
        ("a lone LF", "\n"),
    ];
    for (label, text) in refused {
        assert!(!is_delivered(text.as_bytes()), "{label}");
    }
}

#[test]
fn a_real_callback_answering_with_anything_but_a_complete_status_200_line_is_not_a_delivery() {
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    let url = target.url().to_string();
    let (deliverer, outbox) = Deliverer::start(target, limits()).expect("starts");

    // The status line must end inside the `STATUS_BYTES` read: 64 bytes with the CRLF are a delivery, 65 are not.
    let fits = format!("HTTP/1.1 200 {}\r\n", "x".repeat(STATUS_BYTES - 15));
    let over = format!("HTTP/1.1 200 {}\r\n", "x".repeat(STATUS_BYTES - 14));
    assert_eq!(fits.len(), STATUS_BYTES);
    assert_eq!(over.len(), STATUS_BYTES + 1);

    // Each refusal is followed by a permitted answer on the same shim, so a refusal is a verdict on the line and not a dead shim.
    let plan = [
        ("HTTP/1.1 200", false),
        ("HTTP/1.1 200 OK\r\n\r\n", true),
        ("HTTP/1.bad 200 OK\r\n\r\n", false),
        ("HTTP/1.0 200 OK\r\n\r\n", true),
        ("HTTP/1.1 200 OK\n\n", false),
        (fits.as_str(), true),
        (over.as_str(), false),
        ("HTTP/1.1 200 OK\r\n\r\n", true),
    ];
    let bytes = |text: &str| text.as_bytes().to_vec();
    let answers = plan.iter().map(|(text, _)| bytes(text)).collect();
    let served = serve_raw(listener, answers);

    let (mut delivered, mut failed) = (0_u32, 0_u32);
    for (n, (text, good)) in plan.iter().enumerate() {
        let seq = u32::try_from(n).expect("a small index");
        outbox.offer(&[notification(&url, seq, BODY)]);
        let report = idle(&deliverer);
        delivered += u32::from(*good);
        failed += u32::from(!*good);
        assert_eq!(report.delivered, delivered, "{text:?}");
        assert_eq!(report.failed, failed, "{text:?}");
    }
    served.join().expect("the listener");
    assert_eq!((delivered, failed), (4, 4));
}

#[test]
fn stopping_with_a_join_budget_too_large_to_add_to_an_instant_does_not_panic() {
    // `Instant::now() + Duration::MAX` panics; the checked deadline does not. The thread ends by itself at its lifetime first, so
    // `stop` has nothing to wait for and the cause it recorded stands.
    let listener = listener();
    let target = target_of(&listener, "/RenderingControl");
    let huge = CallbackLimits {
        io_timeout: Duration::MAX,
        lifetime: Duration::from_millis(30),
        ..limits()
    };
    let (mut deliverer, _outbox) = Deliverer::start(target, huge).expect("starts");
    let ended = |d: &Deliverer| d.worker.as_ref().is_some_and(JoinHandle::is_finished);
    wait_until("the thread to end at its lifetime", || ended(&deliverer));
    deliverer.stop();
    assert_eq!(deliverer.report().stopped_by, CallbackStop::Lifetime);
}
