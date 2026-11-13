//! Opt-in, loopback-only delivery of the GENA notifications the core already produces (`docs/contracts/g03.md` section 11 item 5).
//!
//! `franken_control::fsonos::Endpoint` returns [`Notification`] values with its answers and sends nothing. What each says, to whom, in
//! what order, and when a subscription ends is the core's subscription table; this module neither decides nor repeats any of it. It
//! carries what the core produced, unchanged, to ONE explicitly allowed callback, and counts everything else:
//!
//! * **One allowed callback.** [`CallbackTarget`] is an IPv4 loopback socket address and one path, fixed at construction. A local
//!   `SUBSCRIBE` naming any other callback is answered 412 by the shim before the core is called (the core alone would grant any
//!   loopback socket), and a notification whose callback is not exactly that URL is refused before any socket is created for it,
//!   both by exact string equality. Nothing is resolved, no
//!   redirect is followed (the answer is read for its status line and the connection is closed), and no multicast, wildcard or LAN
//!   address can be named.
//! * **Off the control path.** The shim's HTTP worker only offers notifications to a bounded queue with a non-blocking send, after the
//!   SOAP or GENA answer has been written. A full queue drops the notification and COUNTS it; the subscriber sees a jump in `SEQ`,
//!   which is how GENA shows a missed event. A separate thread connects, writes and reads, in order, one connection per notification.
//! * **Bounded.** Queue length, bytes of one request (its exact length is summed before it is built), the connect, the whole delivery
//!   (connect, the whole write, the status line), each read and write call, the thread's lifetime, and the join at stop. What is
//!   still queued at stop is counted as abandoned and never sent.
//! * **Never success by assumption.** A notification counts as delivered only when the callback answers it with a complete status
//!   line, `HTTP/1.0` or `HTTP/1.1`, status 200.
//!
//! What it is not: a subscription state machine (there is none here), a retry (a failed delivery is counted and not repeated, so no
//! event is ever sent twice or out of order), or a client for any address but the one it was built for.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use franken_control::fsonos::Notification;

use super::{deadline_after, to_u64, valid_header_name, valid_header_value};

/// How long the thread waits for work, and so how quickly it notices a stop request.
const POLL: Duration = Duration::from_millis(5);
/// Extra time `stop` allows beyond the longest one delivery can take.
const JOIN_SLACK: Duration = Duration::from_secs(1);
const MAX_PATH_BYTES: usize = 128;
/// How much of the callback's answer is read: a status line, its CRLF included. A line that has not ended within it is not a delivery.
const STATUS_BYTES: usize = 64;

/// The one callback a shim may deliver to: an IPv4 loopback socket address and a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackTarget {
    addr: SocketAddr,
    path: String,
    url: String,
}

impl CallbackTarget {
    /// # Errors
    /// If `addr` is not an IPv4 loopback address with a real port, or `path` is not a short absolute path of printable ASCII without
    /// a query, a fragment, a percent escape, a dot segment or a space. Nothing is contacted, resolved or bound here.
    pub fn new(addr: SocketAddr, path: &str) -> Result<Self, String> {
        if !addr.is_ipv4() || !addr.ip().is_loopback() || addr.port() == 0 {
            return Err("the callback must be an IPv4 loopback address and a port".to_string());
        }
        let printable = path.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        let plain = printable && !path.contains(['?', '#', '%']) && !path.contains("..");
        if !path.starts_with('/') || path.len() > MAX_PATH_BYTES || !plain {
            return Err("the callback path is not a plain absolute path".to_string());
        }
        Ok(Self {
            addr,
            path: path.to_string(),
            url: format!("http://{addr}{path}"),
        })
    }

    /// The URL a subscriber names to be called back on, exactly as the core stores and returns it.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The whole `NOTIFY` for `notification`: the core's own headers and body, framed with the request line, `Host`, `Content-Length`
    /// and `Connection: close`. `None` when a header cannot be framed safely or the request would pass `max_bytes`.
    ///
    /// The exact length is summed (checked) from the parts BEFORE any byte of the request is built, and the buffer is then allocated
    /// once at that length, so what is copied is only ever a request already admitted. The body and the SID are each written whole
    /// into the request (the body last, the SID as the value of the core's `SID` header), so one of them longer than the bound
    /// puts the request over it whatever else it holds: that is said first, from the lengths alone, before `headers()` clones the
    /// SID. This order is read from the source; no test can observe it (the answer is `None` either way), and no heap is measured.
    fn request(&self, notification: &Notification, max_bytes: usize) -> Option<Vec<u8>> {
        let body = notification.body.as_bytes();
        if body.len() > max_bytes || notification.sid.len() > max_bytes {
            return None;
        }
        let headers = notification.headers();
        for (name, value) in &headers {
            // The three headers written below are the shim's alone: a second `Host` or `Content-Length` would split the request.
            let framing = ["host", "content-length", "connection", "transfer-encoding"]
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved));
            if framing || !valid_header_name(name) || !valid_header_value(value) {
                return None;
            }
        }
        let head = format!("NOTIFY {} HTTP/1.1\r\nHost: {}\r\n", self.path, self.addr);
        let tail = format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        // Each header line is `name`, `: `, `value`, CRLF.
        let lines = headers
            .iter()
            .flat_map(|(name, value)| [name.len(), 2, value.len(), 2]);
        let fixed = [head.len(), tail.len(), body.len()];
        let parts = fixed.into_iter().chain(lines);
        let total = wire_len(parts).filter(|total| *total <= max_bytes)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(head.as_bytes());
        for (name, value) in &headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(tail.as_bytes());
        out.extend_from_slice(body);
        debug_assert_eq!(out.len(), total);
        Some(out)
    }
}

/// The exact size of a request made of parts of these sizes, or `None` when the sum does not fit a `usize`.
fn wire_len(parts: impl IntoIterator<Item = usize>) -> Option<usize> {
    parts.into_iter().try_fold(0_usize, usize::checked_add)
}

/// Every bound of the delivery. All of them are enforced; none is a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackLimits {
    /// Notifications waiting for delivery. A notification offered to a full queue is dropped and counted.
    pub queue: usize,
    /// One whole request, head and body. A larger one is not sent and is counted.
    pub max_request_bytes: usize,
    pub connect_timeout: Duration,
    /// One read or one write call. The whole write and the reading of the status line are further held to what is left of the
    /// delivery bound (the connect timeout plus two of these), so a peer that takes the request a little at a time cannot stretch
    /// a delivery past it.
    pub io_timeout: Duration,
    /// The thread stops by itself after this long.
    pub lifetime: Duration,
}

impl CallbackLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            queue: 16,
            max_request_bytes: 16 * 1024,
            connect_timeout: Duration::from_millis(500),
            io_timeout: Duration::from_secs(1),
            lifetime: Duration::from_secs(60),
        }
    }

    fn usable(&self) -> bool {
        self.queue > 0
            && self.max_request_bytes >= 256
            && !self.connect_timeout.is_zero()
            && !self.io_timeout.is_zero()
            && !self.lifetime.is_zero()
    }

    /// The longest one delivery can take: the connect, the write and the reading of the status line.
    fn delivery_bound(&self) -> Duration {
        self.connect_timeout
            .saturating_add(self.io_timeout)
            .saturating_add(self.io_timeout)
    }
}

/// Why the delivery thread is not running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CallbackStop {
    #[default]
    Running,
    Requested,
    /// The shim's HTTP worker ended and dropped its end of the queue.
    Closed,
    Lifetime,
    WorkerPanicked,
    /// The thread did not stop within the join deadline and was left to stop by itself at its lifetime.
    WorkerStuck,
}

/// What the delivery did. Counts only: no byte of any notification is kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackReport {
    /// Notifications the shim handed over, whatever became of them.
    pub offered: u32,
    /// Refused with no contact: the notification's callback is not the allowed one.
    pub refused: u32,
    /// Refused with no contact: a header could not be framed safely, or the request would pass the byte bound.
    pub unframed: u32,
    /// Lost to saturation: the queue was full or closed. The subscriber sees a jump in `SEQ`.
    pub dropped: u32,
    /// Taken into the queue.
    pub queued: u32,
    /// Answered by the callback with status 200.
    pub delivered: u32,
    /// Attempted and not delivered: the connect, write or read failed or timed out, or the status was not 200.
    pub failed: u32,
    /// Queued and never attempted, because the shim stopped.
    pub abandoned: u32,
    /// `SUBSCRIBE` requests the shim answered 412 itself, before the core, because they named a callback other than the allowed one.
    /// Not notifications: they are outside the reconciliation above.
    pub subscribes_refused: u32,
    /// Bytes of requests written completely.
    pub bytes_out: u64,
    pub stopped_by: CallbackStop,
}

impl CallbackReport {
    /// Every offered notification ended in exactly one of refused, unframed, dropped or queued, and every queued one in exactly one
    /// of delivered, failed or abandoned. True once the thread is idle or stopped.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        let handed_over = self
            .refused
            .saturating_add(self.unframed)
            .saturating_add(self.dropped)
            .saturating_add(self.queued);
        let attempted = self
            .delivered
            .saturating_add(self.failed)
            .saturating_add(self.abandoned);
        self.offered == handed_over && self.queued == attempted
    }
}

fn lock(report: &Mutex<CallbackReport>) -> MutexGuard<'_, CallbackReport> {
    report.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The shim's end of the queue. It only offers; it never connects, waits or blocks.
#[derive(Clone)]
pub(super) struct Outbox {
    target: CallbackTarget,
    max_request_bytes: usize,
    queue: SyncSender<Vec<u8>>,
    report: Arc<Mutex<CallbackReport>>,
    terminal: Arc<AtomicBool>,
}

impl Outbox {
    /// Latches only after the actual delivery loop has ended its socket I/O.
    /// A stop request or a timed-out join is never a terminal observation.
    pub(super) fn terminal_fence(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.terminal)
    }
    /// Whether the `CALLBACK` header `value` (`<url>`) names exactly the allowed callback. Exact string equality: nothing is parsed,
    /// resolved or normalised.
    pub(super) fn allows(&self, value: &str) -> bool {
        let Some(rest) = value.strip_prefix('<') else {
            return false;
        };
        rest.strip_suffix('>') == Some(self.target.url.as_str())
    }

    /// Count a `SUBSCRIBE` the shim refused for naming another callback.
    pub(super) fn note_subscribe_refused(&self) {
        let mut counts = lock(&self.report);
        counts.subscribes_refused = counts.subscribes_refused.saturating_add(1);
    }

    /// Hand the core's notifications over, in the order the core produced them.
    pub(super) fn offer(&self, notifications: &[Notification]) {
        for notification in notifications {
            self.offer_one(notification);
        }
    }

    fn offer_one(&self, notification: &Notification) {
        // The guard is held across the non-blocking send, so the counts and the queue never disagree for the delivery thread.
        let mut counts = lock(&self.report);
        counts.offered = counts.offered.saturating_add(1);
        if notification.callback != self.target.url {
            counts.refused = counts.refused.saturating_add(1);
            return;
        }
        let Some(request) = self.target.request(notification, self.max_request_bytes) else {
            counts.unframed = counts.unframed.saturating_add(1);
            return;
        };
        match self.queue.try_send(request) {
            Ok(()) => counts.queued = counts.queued.saturating_add(1),
            Err(_) => counts.dropped = counts.dropped.saturating_add(1),
        }
    }
}

/// The delivery thread. Dropping it stops and joins it.
pub(super) struct Deliverer {
    report: Arc<Mutex<CallbackReport>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    join_budget: Duration,
}

impl Deliverer {
    /// Start the thread for `target`. Nothing is contacted until the first notification is queued.
    pub(super) fn start(
        target: CallbackTarget,
        limits: CallbackLimits,
    ) -> Result<(Self, Outbox), String> {
        if !limits.usable() {
            return Err("the callback limits are unusable".to_string());
        }
        let (queue, jobs) = mpsc::sync_channel::<Vec<u8>>(limits.queue);
        let report = Arc::new(Mutex::new(CallbackReport::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let terminal = Arc::new(AtomicBool::new(false));
        let addr = target.addr;
        let outbox = Outbox {
            target,
            max_request_bytes: limits.max_request_bytes,
            queue,
            report: Arc::clone(&report),
            terminal: Arc::clone(&terminal),
        };
        let (for_report, for_stop) = (Arc::clone(&report), Arc::clone(&stop));
        let worker = thread::Builder::new()
            .name("g03-fsonos-callback".to_string())
            .spawn(move || {
                // Declared before run: unwinding drops socket-owning frames
                // before this guard can certify that no more writes occur.
                let _terminal = DeliveryTerminal(terminal);
                let cause = run(jobs, addr, limits, &for_stop, &for_report);
                lock(&for_report).stopped_by = cause;
            })
            .map_err(|error| format!("spawn: {}", error.kind()))?;
        let deliverer = Self {
            report,
            stop,
            worker: Some(worker),
            join_budget: limits.delivery_bound().saturating_add(JOIN_SLACK),
        };
        Ok((deliverer, outbox))
    }

    pub(super) fn report(&self) -> CallbackReport {
        lock(&self.report).clone()
    }

    /// Ask the thread to stop and join it within the longest one delivery can take.
    pub(super) fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let Some(worker) = self.worker.take() else {
            return;
        };
        // A budget too large to add to an instant is no deadline at all, which would be unbounded: it counts as already expired.
        let give_up = deadline_after(self.join_budget);
        while !worker.is_finished() {
            if Instant::now() >= give_up {
                // Dropping the handle detaches the thread; it stops by itself at its lifetime.
                lock(&self.report).stopped_by = CallbackStop::WorkerStuck;
                return;
            }
            thread::sleep(POLL);
        }
        if worker.join().is_err() {
            lock(&self.report).stopped_by = CallbackStop::WorkerPanicked;
        }
    }
}

struct DeliveryTerminal(Arc<AtomicBool>);

impl Drop for DeliveryTerminal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Drop for Deliverer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    jobs: Receiver<Vec<u8>>,
    addr: SocketAddr,
    limits: CallbackLimits,
    stop: &AtomicBool,
    report: &Mutex<CallbackReport>,
) -> CallbackStop {
    let started = Instant::now();
    let cause = loop {
        if stop.load(Ordering::SeqCst) {
            break CallbackStop::Requested;
        }
        if started.elapsed() >= limits.lifetime {
            break CallbackStop::Lifetime;
        }
        match jobs.recv_timeout(POLL) {
            Ok(request) => deliver(addr, &request, &limits, report),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break CallbackStop::Closed,
        }
    };
    retire_queue(jobs, report, || {});
    cause
}

/// Finish ordinary shutdown while admission is serialized with final cleanup.
/// The no-op in normal delivery is also a synchronization point for tests:
/// it observes the actual final-drain boundary, not a second queue algorithm.
fn retire_queue(
    jobs: Receiver<Vec<u8>>,
    report: &Mutex<CallbackReport>,
    after_final_drain: impl FnOnce(),
) {
    // Outbox::offer_one holds this same mutex across admission. Keep it
    // through the final finite drain and receiver disconnect, so no producer
    // can enqueue a notification after the count but before the queue closes.
    // Receiver ownership makes closure happen here, before the lock is released.
    let mut counts = lock(report);
    let mut left = 0_u32;
    while jobs.try_recv().is_ok() {
        left = left.saturating_add(1);
    }
    after_final_drain();
    drop(jobs);
    counts.abandoned = counts.abandoned.saturating_add(left);
}

/// What one attempt got as far as.
struct Attempt {
    /// The whole request was written.
    wrote: bool,
    /// The callback answered with status 200.
    accepted: bool,
}

impl Attempt {
    const NOTHING: Self = Self {
        wrote: false,
        accepted: false,
    };
}

fn deliver(
    addr: SocketAddr,
    request: &[u8],
    limits: &CallbackLimits,
    report: &Mutex<CallbackReport>,
) {
    let Attempt { wrote, accepted } = attempt(addr, request, limits);
    let mut counts = lock(report);
    if wrote {
        counts.bytes_out = counts.bytes_out.saturating_add(to_u64(request.len()));
    }
    if accepted {
        counts.delivered = counts.delivered.saturating_add(1);
    } else {
        counts.failed = counts.failed.saturating_add(1);
    }
}

/// One connection, one request, one status line. `addr` is the allowed loopback socket itself, never a name.
fn attempt(addr: SocketAddr, request: &[u8], limits: &CallbackLimits) -> Attempt {
    let deadline = deadline_after(limits.delivery_bound());
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, limits.connect_timeout) else {
        return Attempt::NOTHING;
    };
    let arm = |sink: &mut TcpStream, wait: Duration| sink.set_write_timeout(Some(wait));
    if !write_within(&mut stream, request, deadline, limits.io_timeout, arm) {
        return Attempt::NOTHING;
    }
    let accepted = read_status(&mut stream, deadline, limits.io_timeout);
    let _ = stream.shutdown(Shutdown::Both);
    Attempt {
        wrote: true,
        accepted,
    }
}

/// Write all of `bytes` before `deadline`, or say it could not. Each `write` call is armed (by `arm`, which sets the sink's write
/// timeout) with the time left, at most `io_timeout` and at least a millisecond, and the time left is looked at again before every
/// call. A peer that takes a little at a time, each call well inside `io_timeout`, therefore still runs out of the whole deadline,
/// which a single `write_all` under one per-call timeout does not enforce. A call that moved nothing (`Ok(0)`) or failed (a timeout
/// included) ends the write; an interrupted one is tried again while time is left. The last call can run a millisecond past the
/// deadline, because a zero timeout is not a valid socket option.
fn write_within<W: Write>(
    sink: &mut W,
    bytes: &[u8],
    deadline: Instant,
    io_timeout: Duration,
    mut arm: impl FnMut(&mut W, Duration) -> io::Result<()>,
) -> bool {
    let mut sent = 0_usize;
    while sent < bytes.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let wait = left.min(io_timeout).max(Duration::from_millis(1));
        if arm(sink, wait).is_err() {
            return false;
        }
        let Some(rest) = bytes.get(sent..) else {
            return false;
        };
        match sink.write(rest) {
            Ok(0) => return false,
            Ok(moved) => sent = sent.saturating_add(moved),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Read until the first line break (or the bound), each read within the time left, and judge the status line.
fn read_status(stream: &mut TcpStream, deadline: Instant, io_timeout: Duration) -> bool {
    let mut head = [0_u8; STATUS_BYTES];
    let mut filled = 0_usize;
    while filled < head.len() && !head[..filled].contains(&b'\n') {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let wait = left.min(io_timeout).max(Duration::from_millis(1));
        if stream.set_read_timeout(Some(wait)).is_err() {
            return false;
        }
        match stream.read(&mut head[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    is_delivered(&head[..filled])
}

/// Whether the first line of `head` is a COMPLETE status line of a delivery: exactly `HTTP/1.0` or `HTTP/1.1`, one space, exactly
/// `200`, then the end of the line or one space and a reason phrase, and the line ended by CRLF. Later lines are not looked at.
/// Anything else is not a delivery: a line that has not ended (the bytes stopped, or `STATUS_BYTES` ran out first), one ended by a
/// bare LF, any other version (`HTTP/1.bad`, `HTTP/1.2`, `HTTP/2`), another 2xx, a redirect, a code with more digits or glued to
/// its reason, a reason phrase with a control byte in it.
fn is_delivered(head: &[u8]) -> bool {
    let Some(end) = head.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    let Some(line) = head[..end].strip_suffix(b"\r") else {
        return false;
    };
    let v10 = line.strip_prefix(b"HTTP/1.0 200");
    let v11 = line.strip_prefix(b"HTTP/1.1 200");
    let Some(rest) = v10.or(v11) else {
        return false;
    };
    match rest.split_first() {
        None => true,
        Some((&b' ', reason)) => reason.iter().copied().all(reason_byte),
        Some(_) => false,
    }
}

/// A byte a reason phrase may hold: a tab, a space, a visible character, or a byte of 0x80 and up. No other control byte.
fn reason_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b'\t' | b' ' | 0x80..=0xff)
}

#[cfg(test)]
mod tests;
