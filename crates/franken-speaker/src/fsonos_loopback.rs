//! A bounded loopback HTTP transport for an ACTUAL `fsonos` client, over the real G03 endpoint (`ffw-xvv`,
//! `docs/contracts/g03.md` section 11 item 1).
//!
//! `franken-control` answers SOAP as a pure function of an [`HttpRequest`] and opens no socket, by design. The acceptance clause it
//! leaves open is a real controller talking to it, and that needs a transport. This module is that transport and nothing more:
//!
//! * **One listener, on `127.0.0.1`, on an ephemeral port.** There is no address parameter, so no other interface can be asked for,
//!   and every accepted peer is checked to be loopback again.
//! * **One request per connection**, read within fixed bounds (head bytes, header count, body bytes, one read, the whole request),
//!   handed unchanged to the REAL [`franken_control::fsonos::Endpoint`] through the speaker's real control plane (the real channel,
//!   peer directory, lease and legacy bridge), and answered with exactly what the endpoint returned, framed with `Content-Length`
//!   and `Connection: close`.
//! * **Bounded for life.** At most [`LoopbackLimits::max_connections`] connections are accepted. The worker stops by itself at
//!   [`LoopbackLimits::lifetime`] or when asked, and stopping joins it within a deadline.
//! * **It never invents an answer.** A request it cannot read it refuses itself with a bare status and no body, counts the refusal
//!   and does not call the endpoint. Nothing the peer sent is echoed or logged: the report holds counts and statuses only.
//!
//! What it is not: no SSDP, no device-description route, no GENA delivery (a `Handled` that asks for `NOTIFY` messages is answered
//! and the messages are not sent), no TLS, no keep-alive and no tailnet. It is evidence for the HTTP and SOAP path an actual client
//! takes and says nothing about a speaker, a board or the real LAN. The client side lives outside this workspace
//! (`tests/g03/fsonos-client`) because it needs the sibling `frankensonos` checkout, transferred by RCH's multi-root closure.
//!
//! The control plane is built inside the worker thread and never leaves it: one of its stepper variants holds an `Rc`, so the
//! plane is not `Send`. Only the group session (for inspection) and the report are shared.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use franken_control::fsonos::{HttpRequest, Ingress};
use franken_session::{
    ChannelRole, FencedControlCommand, GroupCommandPayload, UnifiedGroupSession,
};

use crate::control_adapter::ControlPlane;

/// The member the fixture session's endpoint is: what `GetVolume` and `GetMute` read and `SetVolume` and `SetMute` change.
pub const FIXTURE_MEMBER: &str = "kitchen";
/// The address a client names for the player: loopback itself. A client is routed from it to [`FsonosLoopback::addr`]; a route that
/// failed to apply would dial this address on the player port (1400), where nothing listens, instead of leaving the host.
pub const FIXTURE_PLAYER_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

const FIXTURE_EPOCH: u64 = 1;
/// The virtual clock the control plane runs on: it starts here and moves one step per request. No wall clock reaches the endpoint.
const START_NS: u64 = 1_000_000_000;
const STEP_NS: u64 = 1_000_000;
/// How long the accept loop sleeps when nobody is connecting.
const POLL: Duration = Duration::from_millis(2);
/// How long `start` waits for the worker to build the control plane.
const STARTUP: Duration = Duration::from_secs(10);
/// Extra time `stop` allows beyond one request's deadline.
const JOIN_SLACK: Duration = Duration::from_secs(1);
const JOIN_CAP: Duration = Duration::from_secs(60);
/// After answering, how long and how much the shim reads and discards before closing, so an unread request tail cannot turn the close
/// into a reset that destroys the answer.
const LINGER: Duration = Duration::from_millis(100);
const LINGER_BYTES: usize = 32 * 1024;
const READ_CHUNK: usize = 2048;
const MAX_METHOD_BYTES: usize = 16;
const MAX_TARGET_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_LENGTH_DIGITS: usize = 9;

/// Which ingress every connection is judged as. Both are loopback; the second exists to show the endpoint refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// The local link: plain UPnP, reads and legacy commands, as a LAN controller is treated.
    LocalLink,
    /// Every connection is treated as arriving on the tailnet with no command authorization. The endpoint must refuse all of it
    /// (HTTP 401 and no body), reads included.
    UnauthenticatedTailnet,
}

impl Policy {
    const fn ingress(self) -> Ingress {
        match self {
            Self::LocalLink => Ingress::LocalLegacy,
            Self::UnauthenticatedTailnet => Ingress::Tailnet,
        }
    }
}

/// Every bound of the shim. All of them are enforced; none is a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackLimits {
    /// Connections accepted over the shim's life. After this many it stops accepting and its listener closes.
    pub max_connections: u32,
    /// Request line, headers and the blank line together.
    pub max_head_bytes: usize,
    pub max_headers: usize,
    /// Larger than the endpoint's own SOAP limit (8 KiB), so the endpoint's refusal of an oversize body is reachable.
    pub max_body_bytes: usize,
    /// One read or one write.
    pub io_timeout: Duration,
    /// Reading, handling and answering one request.
    pub request_deadline: Duration,
    /// The shim stops by itself after this long.
    pub lifetime: Duration,
}

impl LoopbackLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_connections: 64,
            max_head_bytes: 8 * 1024,
            max_headers: 32,
            max_body_bytes: 16 * 1024,
            io_timeout: Duration::from_secs(2),
            request_deadline: Duration::from_secs(5),
            lifetime: Duration::from_secs(60),
        }
    }

    fn usable(&self) -> bool {
        self.max_connections > 0
            && self.max_head_bytes >= 256
            && self.max_headers > 0
            && !self.io_timeout.is_zero()
            && !self.request_deadline.is_zero()
            && !self.lifetime.is_zero()
    }
}

/// Why the worker is not running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StopCause {
    #[default]
    Running,
    Requested,
    ConnectionCap,
    Lifetime,
    ListenerFailed,
    WorkerPanicked,
    /// The worker did not stop within the join deadline and was left to stop by itself at its lifetime.
    WorkerStuck,
}

/// What the shim did. Counts and statuses only: no byte of any request or answer is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoopbackReport {
    pub accepted: u32,
    /// Requests the endpoint answered and whose answer was written completely.
    pub served: u32,
    /// Requests the shim answered itself with a bare error status, without calling the endpoint (or whose endpoint answer it
    /// refused to forward).
    pub refused: u32,
    /// Connections closed with no complete answer: the client went away or sent nothing, or the answer could not be written.
    pub dropped: u32,
    /// The status of each refusal, in order. At most one per accepted connection.
    pub refused_statuses: Vec<u16>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub stopped_by: StopCause,
}

impl LoopbackReport {
    /// Every accepted connection ended in exactly one of served, refused or dropped. True once the worker is idle or stopped.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        self.accepted
            == self
                .served
                .saturating_add(self.refused)
                .saturating_add(self.dropped)
    }
}

/// Two members at the default volume 50 and unmuted, in epoch 1: the session the endpoint serves.
///
/// # Errors
/// If a fixture board is missing or a member does not admit.
pub fn fixture_session() -> Result<UnifiedGroupSession, String> {
    let catalog = franken_board_profile::synthetic_test_fixture_catalog();
    let board = |model: &str| {
        catalog
            .iter()
            .find(|profile| profile.model_number == model)
            .cloned()
            .ok_or_else(|| format!("no fixture board {model}"))
    };
    let mut session = UnifiedGroupSession::new("grp", "coord", FIXTURE_EPOCH);
    for (seq, member, model) in [(1_u64, FIXTURE_MEMBER, "S5"), (2, "den", "S12")] {
        session
            .apply_command(FencedControlCommand {
                epoch: FIXTURE_EPOCH,
                command_seq: seq,
                payload: GroupCommandPayload::AdmitMember {
                    member_id: member.to_string(),
                    board: board(model)?,
                    role: ChannelRole::Stereo,
                },
            })
            .map_err(|error| format!("admitting {member}: {error:?}"))?;
    }
    Ok(session)
}

// ---- shared state ----------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Shared {
    session: Arc<Mutex<UnifiedGroupSession>>,
    report: Arc<Mutex<LoopbackReport>>,
    stop: Arc<AtomicBool>,
}

impl Shared {
    fn session(&self) -> MutexGuard<'_, UnifiedGroupSession> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn report(&self) -> MutexGuard<'_, LoopbackReport> {
        self.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note(&self, change: impl FnOnce(&mut LoopbackReport)) {
        let mut report = self.report();
        change(&mut report);
    }
}

#[derive(Clone, Copy)]
struct Config {
    limits: LoopbackLimits,
    policy: Policy,
}

// ---- the public handle -----------------------------------------------------------------------------------------------

/// A running shim. Dropping it stops and joins it.
pub struct FsonosLoopback {
    addr: SocketAddr,
    shared: Shared,
    worker: Option<JoinHandle<()>>,
    join_budget: Duration,
}

impl FsonosLoopback {
    /// Bind `127.0.0.1:0`, build the real control plane over `session` for `member_id` inside a worker thread, and start serving.
    ///
    /// # Errors
    /// If the limits are unusable, the listener cannot be bound or is not on loopback, the worker cannot start, or the control
    /// plane cannot be built (the reason names a label or an error kind, never a request).
    pub fn start(
        session: UnifiedGroupSession,
        member_id: &str,
        policy: Policy,
        limits: LoopbackLimits,
    ) -> Result<Self, String> {
        if !limits.usable() {
            return Err("the loopback limits are unusable".to_string());
        }
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|error| format!("bind: {}", error.kind()))?;
        let addr = listener
            .local_addr()
            .map_err(|error| format!("local address: {}", error.kind()))?;
        if !addr.ip().is_loopback() {
            return Err("the listener is not on loopback".to_string());
        }
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("nonblocking: {}", error.kind()))?;
        let shared = Shared {
            session: Arc::new(Mutex::new(session)),
            report: Arc::new(Mutex::new(LoopbackReport::default())),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let member = member_id.to_string();
        let cfg = Config { limits, policy };
        let for_worker = shared.clone();
        let worker = thread::Builder::new()
            .name("g03-fsonos-loopback".to_string())
            .spawn(move || worker_main(&listener, for_worker, &member, cfg, &ready_tx))
            .map_err(|error| format!("spawn: {}", error.kind()))?;
        match ready_rx.recv_timeout(STARTUP) {
            Ok(Ok(())) => Ok(Self {
                addr,
                shared,
                worker: Some(worker),
                join_budget: limits
                    .request_deadline
                    .saturating_add(JOIN_SLACK)
                    .min(JOIN_CAP),
            }),
            Ok(Err(reason)) => {
                let _ = worker.join();
                Err(reason)
            }
            Err(_) => {
                // The worker is slow or gone; it will see the flag before it serves anything and leave.
                shared.stop.store(true, Ordering::SeqCst);
                Err("the loopback worker did not start".to_string())
            }
        }
    }

    /// Where the shim listens: always `127.0.0.1` and an ephemeral port.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Look at the group session the endpoint serves, as it is now. This is the ground truth a test compares an answer with.
    pub fn with_session<R>(&self, read: impl FnOnce(&UnifiedGroupSession) -> R) -> R {
        let session = self.shared.session();
        read(&session)
    }

    #[must_use]
    pub fn report(&self) -> LoopbackReport {
        self.shared.report().clone()
    }

    /// Stop, join within the deadline, and return the final report.
    pub fn stop(mut self) -> LoopbackReport {
        self.shutdown();
        self.report()
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let Some(worker) = self.worker.take() else {
            return;
        };
        let give_up = Instant::now() + self.join_budget;
        while !worker.is_finished() {
            if Instant::now() >= give_up {
                // Dropping the handle detaches the thread; it stops by itself at its lifetime.
                self.shared
                    .note(|report| report.stopped_by = StopCause::WorkerStuck);
                return;
            }
            thread::sleep(POLL);
        }
        if worker.join().is_err() {
            self.shared
                .note(|report| report.stopped_by = StopCause::WorkerPanicked);
        }
    }
}

impl Drop for FsonosLoopback {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_main(
    listener: &TcpListener,
    shared: Shared,
    member: &str,
    cfg: Config,
    ready: &mpsc::Sender<Result<(), String>>,
) {
    let built = {
        let session = shared.session();
        ControlPlane::new(&session, member, START_NS)
    };
    let plane = match built {
        Ok(plane) => plane,
        Err(reason) => {
            let _ = ready.send(Err(reason));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    let mut worker = Worker {
        plane,
        now_ns: START_NS,
        shared,
        cfg,
    };
    let cause = worker.run(listener);
    worker.shared.note(|report| report.stopped_by = cause);
}

// ---- the worker ------------------------------------------------------------------------------------------------------

struct Worker {
    plane: ControlPlane,
    now_ns: u64,
    shared: Shared,
    cfg: Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Served,
    Refused(u16),
    Dropped,
}

impl Worker {
    fn run(&mut self, listener: &TcpListener) -> StopCause {
        let started = Instant::now();
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                return StopCause::Requested;
            }
            if started.elapsed() >= self.cfg.limits.lifetime {
                return StopCause::Lifetime;
            }
            if self.shared.report().accepted >= self.cfg.limits.max_connections {
                return StopCause::ConnectionCap;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    self.shared
                        .note(|report| report.accepted = report.accepted.saturating_add(1));
                    self.serve(stream, peer);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return StopCause::ListenerFailed,
            }
        }
    }

    fn serve(&mut self, mut stream: TcpStream, peer: SocketAddr) {
        // An accepted socket can inherit the listener's non-blocking mode: ask for blocking explicitly.
        let ready = peer.ip().is_loopback() && stream.set_nonblocking(false).is_ok();
        let mut bytes_in = 0_u64;
        let (outcome, bytes_out) = if ready {
            let deadline = deadline_after(self.cfg.limits.request_deadline);
            match read_request(&mut stream, &self.cfg.limits, deadline, &mut bytes_in) {
                Ok(request) => self.answer(&mut stream, peer, &request, deadline),
                Err(Failure::Refuse(status)) => self.refuse(&mut stream, status, deadline),
                Err(Failure::Drop) => (Outcome::Dropped, 0),
            }
        } else {
            (Outcome::Dropped, 0)
        };
        // Recorded BEFORE the half-close in `linger`: the half-close is what tells the client the connection is finished, so a caller
        // that reads the report once the client has returned must already see this connection counted.
        self.shared.note(move |report| {
            report.bytes_in = report.bytes_in.saturating_add(bytes_in);
            report.bytes_out = report.bytes_out.saturating_add(bytes_out);
            match outcome {
                Outcome::Served => report.served = report.served.saturating_add(1),
                Outcome::Refused(status) => {
                    report.refused = report.refused.saturating_add(1);
                    report.refused_statuses.push(status);
                }
                Outcome::Dropped => report.dropped = report.dropped.saturating_add(1),
            }
        });
        linger(&mut stream);
    }

    /// Hand the request to the real endpoint and write its answer.
    fn answer(
        &mut self,
        stream: &mut TcpStream,
        peer: SocketAddr,
        request: &Request,
        deadline: Instant,
    ) -> (Outcome, u64) {
        let headers: Vec<(&str, &str)> = request
            .head
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let http = HttpRequest {
            method: &request.head.method,
            path: &request.head.target,
            peer_ip: peer.ip(),
            ingress: self.cfg.policy.ingress(),
            headers: &headers,
            body: &request.body,
        };
        self.now_ns = self.now_ns.saturating_add(STEP_NS);
        let handled = {
            let mut session = self.shared.session();
            self.plane.handle_request(&mut session, self.now_ns, &http)
        };
        let response = &handled.response;
        let Some(bytes) =
            render_response(response.status, &response.headers, response.body.as_bytes())
        else {
            // The endpoint's answer cannot be framed safely (a header with a line break): say so, forward nothing of it.
            return self.refuse(stream, 500, deadline);
        };
        match send(stream, &bytes, &self.cfg.limits, deadline) {
            Ok(()) => (Outcome::Served, to_u64(bytes.len())),
            Err(_) => (Outcome::Dropped, 0),
        }
    }

    /// Answer with a bare status and no body, without calling the endpoint.
    fn refuse(&self, stream: &mut TcpStream, status: u16, deadline: Instant) -> (Outcome, u64) {
        let bytes = render_response(status, &[], b"").unwrap_or_default();
        match send(stream, &bytes, &self.cfg.limits, deadline) {
            Ok(()) => (Outcome::Refused(status), to_u64(bytes.len())),
            Err(_) => (Outcome::Refused(status), 0),
        }
    }
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn deadline_after(span: Duration) -> Instant {
    // A span too large to add is no deadline at all, which would be unbounded: treat it as already expired.
    Instant::now()
        .checked_add(span)
        .unwrap_or_else(Instant::now)
}

// ---- reading a request -----------------------------------------------------------------------------------------------

/// How a read failed: answer with a status, or close without answering.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Refuse(u16),
    Drop,
}

#[derive(Debug, PartialEq, Eq)]
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    content_length: usize,
}

struct Request {
    head: Head,
    body: Vec<u8>,
}

/// A request is silent while nothing at all has arrived: closing it unanswered is right. Once something arrived a stall is a 408.
fn timed_out(silent: bool) -> Failure {
    if silent {
        Failure::Drop
    } else {
        Failure::Refuse(408)
    }
}

fn fill(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    limits: &LoopbackLimits,
    deadline: Instant,
    bytes_in: &mut u64,
) -> Result<(), Failure> {
    let silent = buf.is_empty();
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(timed_out(silent));
    }
    let wait = left.min(limits.io_timeout).max(Duration::from_millis(1));
    if stream.set_read_timeout(Some(wait)).is_err() {
        return Err(Failure::Drop);
    }
    let mut chunk = [0_u8; READ_CHUNK];
    match stream.read(&mut chunk) {
        Ok(0) => Err(Failure::Drop),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            *bytes_in = bytes_in.saturating_add(to_u64(n));
            Ok(())
        }
        Err(error) => match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Err(timed_out(silent)),
            io::ErrorKind::Interrupted => Ok(()),
            _ => Err(Failure::Drop),
        },
    }
}

/// Where the blank line that ends the head starts.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(
    stream: &mut TcpStream,
    limits: &LoopbackLimits,
    deadline: Instant,
    bytes_in: &mut u64,
) -> Result<Request, Failure> {
    let mut buf: Vec<u8> = Vec::new();
    let end = loop {
        if let Some(at) = head_end(&buf) {
            break at;
        }
        if buf.len() > limits.max_head_bytes {
            return Err(Failure::Refuse(431));
        }
        fill(stream, &mut buf, limits, deadline, bytes_in)?;
    };
    if end + 4 > limits.max_head_bytes {
        return Err(Failure::Refuse(431));
    }
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| Failure::Refuse(400))?;
    let head = parse_head(text, limits).map_err(Failure::Refuse)?;
    if head.content_length > limits.max_body_bytes {
        return Err(Failure::Refuse(413));
    }
    let total = end + 4 + head.content_length;
    while buf.len() < total {
        fill(stream, &mut buf, limits, deadline, bytes_in)?;
    }
    let body = buf[end + 4..total].to_vec();
    Ok(Request { head, body })
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn valid_target(target: &str) -> bool {
    target.starts_with('/')
        && target.len() <= MAX_TARGET_BYTES
        && target.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_header_value(value: &str) -> bool {
    value.len() <= MAX_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
}

fn parse_length(value: &str) -> Option<usize> {
    if value.is_empty()
        || value.len() > MAX_LENGTH_DIGITS
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

/// The request line and headers, or the status to refuse with. Strict on purpose: a head that is odd is refused, not repaired.
fn parse_head(text: &str, limits: &LoopbackLimits) -> Result<Head, u16> {
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(400);
    };
    if !valid_method(method) || !valid_target(target) {
        return Err(400);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(505);
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if headers.len() >= limits.max_headers {
            return Err(431);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(400);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(400);
        };
        let value = value.trim_matches([' ', '\t']);
        if !valid_header_name(name) || !valid_header_value(value) {
            return Err(400);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(501);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = parse_length(value).ok_or(400_u16)?;
            if content_length.is_some_and(|earlier| earlier != parsed) {
                return Err(400);
            }
            content_length = Some(parsed);
        }
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        content_length: content_length.unwrap_or(0),
    })
}

// ---- writing an answer -----------------------------------------------------------------------------------------------

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// The bytes of one answer: the endpoint's headers (less the three the shim owns), then `Content-Length` and `Connection: close`.
/// `None` when a header cannot be framed safely, so a value with a line break can never split the answer.
fn render_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Option<Vec<u8>> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status)).into_bytes();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if !valid_header_name(name) || !valid_header_value(value) {
            return None;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    Some(out)
}

fn send(
    stream: &mut TcpStream,
    bytes: &[u8],
    limits: &LoopbackLimits,
    deadline: Instant,
) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    let wait = left.min(limits.io_timeout).max(Duration::from_millis(1));
    stream.set_write_timeout(Some(wait))?;
    stream.write_all(bytes)?;
    stream.flush()
}

/// Half-close, then read and discard for a short bounded time before the socket closes. A client that is still sending would
/// otherwise get a reset that can discard the answer it has not read yet.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    if stream.set_read_timeout(Some(LINGER)).is_err() {
        return;
    }
    let started = Instant::now();
    let mut sink = [0_u8; READ_CHUNK];
    let mut left = LINGER_BYTES;
    while left > 0 && started.elapsed() < LINGER {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => left = left.saturating_sub(n),
        }
    }
}

#[cfg(test)]
mod tests;
