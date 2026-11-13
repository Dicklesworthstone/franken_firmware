//! A loopback-only SSDP responder for the actual `fsonos` client (`docs/contracts/g03.md` section 11 item 2).
//!
//! The pure part already exists: `franken_control::fsonos::ssdp` parses a search datagram, decides which targets the device
//! answers, builds the answer and builds the device description. It opens no socket and reads no clock. This module is the transport
//! it asks for, and nothing more:
//!
//! * **One UDP socket, on `127.0.0.1`, on an ephemeral port.** There is no address parameter, no multicast group is joined and no
//!   wildcard is bound, so the responder can neither hear nor reach anything off the host. A datagram from a peer that is not
//!   loopback is counted and ignored.
//! * **It answers; it never announces.** An answer goes to the peer that asked, as unicast. Nothing is sent unprompted, and the
//!   device's announcement builders are not called anywhere in this module.
//! * **Bounded for life.** At most [`DiscoveryLimits::max_datagrams`] datagrams are read. The thread stops by itself at
//!   [`DiscoveryLimits::lifetime`] or when asked, and stopping joins it within a deadline. Every read AND every write on the socket
//!   has a timeout, so no blocked call can hold the thread past its next stop check. A datagram is read in one call into a
//!   buffer one byte larger than the core's cap, so an oversize datagram is seen as oversize and refused by the core's parser.
//! * **No delay is added.** `MX` spreads the answers of many responders over seconds; one responder answering one unicast client has
//!   nothing to spread, and drawing entropy for it would be a framework this slice does not need. The client's own wait window
//!   bounds the exchange, and `response_delay_ms` is deliberately unused.
//! * **It invents nothing.** A well-formed datagram with nothing to say (another device's message, or a target this device does not
//!   serve) gets no answer, as UPnP requires. A malformed one is counted under the core parser's fixed refusal word and gets no
//!   answer. The report holds counts and those fixed words only: no byte of any datagram is kept.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use franken_control::fsonos::ssdp::{self, Datagram, Device, MAX_DATAGRAM, MIN_MAX_AGE};

/// The port a player serves on. The `Location` a client reads names it, and the client's own routes map it to the shim.
pub const PLAYER_PORT: u16 = 1400;
/// A synthetic device id: lowercase, in the 8-4-4-4-12 shape the core requires. It is also the endpoint's member id, so the
/// description's `UDN`, the answer's `USN` and the topology's `UUID` are one string by construction.
pub const FIXTURE_DEVICE_UUID: &str = "00000000-0000-4000-8000-00000000a001";
/// The id of the second member of the discoverable fixture session. It has no location in the directory.
pub const FIXTURE_OTHER_UUID: &str = "00000000-0000-4000-8000-00000000a002";
/// The room name of the discoverable fixture device.
pub const FIXTURE_ROOM: &str = "Kitchen";

/// How long one read waits, and so how quickly the thread notices a stop request.
const POLL: Duration = Duration::from_millis(5);
/// How long dropping a responder that was not stopped waits for its thread.
const DROP_BUDGET: Duration = Duration::from_secs(2);

/// The synthetic device the responder announces and the description describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryIdentity {
    /// Lowercase 8-4-4-4-12. Also the member id the endpoint serves.
    pub uuid: String,
    /// The friendly name in the description and the `ZoneName` in the topology.
    pub room: String,
}

impl DiscoveryIdentity {
    /// The fixture device: [`FIXTURE_DEVICE_UUID`] in [`FIXTURE_ROOM`].
    #[must_use]
    pub fn fixture() -> Self {
        Self {
            uuid: FIXTURE_DEVICE_UUID.to_string(),
            room: FIXTURE_ROOM.to_string(),
        }
    }

    /// The core's device for this identity, on the loopback address and the player port. The core validates every field, so a value
    /// that could break a header or the document is refused here, before anything is bound.
    pub(super) fn device(&self) -> Result<Device, String> {
        self.device_at_loopback(Ipv4Addr::LOCALHOST)
    }

    /// Build the same validated device at a logical IPv4 loopback address.
    /// The advertised port remains 1400; this does not bind a socket.
    ///
    /// # Errors
    /// Refuses non-loopback addresses, the loopback network and broadcast
    /// addresses, and identities the core device validator refuses.
    pub fn device_at_loopback(&self, ip: Ipv4Addr) -> Result<Device, String> {
        if !ip.is_loopback()
            || ip == Ipv4Addr::new(127, 0, 0, 0)
            || ip == Ipv4Addr::new(127, 255, 255, 255)
        {
            return Err("device identity: bad_loopback_address".to_string());
        }
        Device::new(
            &self.uuid,
            ip.octets(),
            PLAYER_PORT,
            &self.room,
            MIN_MAX_AGE,
        )
        .map_err(|error| format!("device identity: {}", error.code()))
    }
}

/// Every bound of the responder. All of them are enforced; none is a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryLimits {
    /// Datagrams read over the responder's life. After this many it stops and its socket closes.
    pub max_datagrams: u32,
    /// The responder stops by itself after this long.
    pub lifetime: Duration,
}

impl DiscoveryLimits {
    /// A real client sends each search twice per interface, so 256 is far more than a survey needs.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_datagrams: 256,
            lifetime: Duration::from_secs(60),
        }
    }

    pub(super) fn usable(&self) -> bool {
        self.max_datagrams > 0 && !self.lifetime.is_zero()
    }
}

/// Why the responder is not running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiscoveryStop {
    #[default]
    Running,
    Requested,
    DatagramCap,
    Lifetime,
    SocketFailed,
    WorkerPanicked,
    /// The thread did not stop within the join deadline and was left to stop by itself at its lifetime.
    WorkerStuck,
}

/// What the responder did. Counts and the core's fixed refusal words only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub received: u32,
    /// Searches for which at least one answer datagram was written.
    pub answered: u32,
    /// Answer datagrams written, over all searches.
    pub replies_sent: u32,
    /// Well-formed datagrams with nothing to say: another device's message, or a target this device does not serve.
    pub silent: u32,
    /// The core parser's fixed word (`bad_man`, `bad_mx`, ...) for each datagram it refused, in order.
    pub refusals: Vec<&'static str>,
    /// Datagrams from a peer that was not loopback. They are not parsed.
    pub foreign: u32,
    /// Searches that had answers to give and could not write any of them.
    pub failed: u32,
    pub stopped_by: DiscoveryStop,
}

impl DiscoveryReport {
    /// Every datagram read ended in exactly one of answered, silent, refused, foreign or failed. True once the thread is idle or
    /// stopped.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        let refused = u32::try_from(self.refusals.len()).unwrap_or(u32::MAX);
        self.received
            == self
                .answered
                .saturating_add(self.silent)
                .saturating_add(refused)
                .saturating_add(self.foreign)
                .saturating_add(self.failed)
    }
}

/// What to do with one datagram.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The answer datagrams to write back to the sender, in order. Never empty.
    Replies(Vec<String>),
    /// Well-formed, and not a search this device answers.
    Silent,
    /// The core parser refused it, under this fixed word.
    Refused(&'static str),
}

/// The decision for one datagram, made entirely by the core: its parser, its answer list and its answer builder.
pub(super) fn judge(device: &Device, datagram: &[u8]) -> Verdict {
    match ssdp::parse_datagram(datagram) {
        Ok(Datagram::Search(search)) => {
            let replies = device.search_responses(&search);
            if replies.is_empty() {
                Verdict::Silent
            } else {
                Verdict::Replies(replies)
            }
        }
        Ok(Datagram::Other(_)) => Verdict::Silent,
        Err(error) => Verdict::Refused(error.code()),
    }
}

/// [`judge`], but only for a loopback peer: a datagram from anywhere else is not parsed at all, and `None` says so.
pub(super) fn judge_from(device: &Device, datagram: &[u8], peer: IpAddr) -> Option<Verdict> {
    peer.is_loopback().then(|| judge(device, datagram))
}

fn lock(report: &Mutex<DiscoveryReport>) -> MutexGuard<'_, DiscoveryReport> {
    report.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The responder's socket: bound to loopback on an ephemeral port, with a timeout on every read and on every write, so a send
/// that blocks cannot hold the thread past its next stop check. Both are set before the thread exists, and any failure is an error.
fn bound_socket() -> Result<(UdpSocket, SocketAddr), String> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|error| format!("udp bind: {}", error.kind()))?;
    let addr = socket
        .local_addr()
        .map_err(|error| format!("udp local address: {}", error.kind()))?;
    if !addr.ip().is_loopback() {
        return Err("the responder socket is not on loopback".to_string());
    }
    socket
        .set_read_timeout(Some(POLL))
        .map_err(|error| format!("udp read timeout: {}", error.kind()))?;
    socket
        .set_write_timeout(Some(POLL))
        .map_err(|error| format!("udp write timeout: {}", error.kind()))?;
    Ok((socket, addr))
}

/// A running responder. Dropping it stops and joins it.
pub(super) struct Responder {
    addr: SocketAddr,
    report: Arc<Mutex<DiscoveryReport>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Responder {
    /// Bind `127.0.0.1:0` and start answering for `device`.
    pub(super) fn start(device: Device, limits: DiscoveryLimits) -> Result<Self, String> {
        let (socket, addr) = bound_socket()?;
        let report = Arc::new(Mutex::new(DiscoveryReport::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (for_report, for_stop) = (Arc::clone(&report), Arc::clone(&stop));
        let worker = thread::Builder::new()
            .name("g03-fsonos-ssdp".to_string())
            .spawn(move || {
                let cause = run(&socket, &device, limits, &for_stop, &for_report);
                lock(&for_report).stopped_by = cause;
            })
            .map_err(|error| format!("spawn: {}", error.kind()))?;
        Ok(Self {
            addr,
            report,
            stop,
            worker: Some(worker),
        })
    }

    /// Where the responder listens: always `127.0.0.1` and an ephemeral port.
    pub(super) const fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(super) fn report(&self) -> DiscoveryReport {
        lock(&self.report).clone()
    }

    /// Ask the thread to stop and join it within `budget`.
    pub(super) fn stop(&mut self, budget: Duration) {
        self.stop.store(true, Ordering::SeqCst);
        let Some(worker) = self.worker.take() else {
            return;
        };
        let give_up = Instant::now() + budget;
        while !worker.is_finished() {
            if Instant::now() >= give_up {
                // Dropping the handle detaches the thread; it stops by itself at its lifetime.
                lock(&self.report).stopped_by = DiscoveryStop::WorkerStuck;
                return;
            }
            thread::sleep(POLL);
        }
        if worker.join().is_err() {
            lock(&self.report).stopped_by = DiscoveryStop::WorkerPanicked;
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.stop(DROP_BUDGET);
    }
}

fn run(
    socket: &UdpSocket,
    device: &Device,
    limits: DiscoveryLimits,
    stop: &AtomicBool,
    report: &Mutex<DiscoveryReport>,
) -> DiscoveryStop {
    let started = Instant::now();
    // One byte more than the core accepts: a datagram of exactly that size was truncated by the kernel and is refused as too large.
    let mut buf = [0_u8; MAX_DATAGRAM + 1];
    loop {
        if stop.load(Ordering::SeqCst) {
            return DiscoveryStop::Requested;
        }
        if started.elapsed() >= limits.lifetime {
            return DiscoveryStop::Lifetime;
        }
        if lock(report).received >= limits.max_datagrams {
            return DiscoveryStop::DatagramCap;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => handle(socket, device, &buf[..n], peer, report),
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => {}
                // A peer that already closed its socket can surface as an error on the next read: not a reason to stop.
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused => {
                    thread::sleep(POLL);
                }
                _ => return DiscoveryStop::SocketFailed,
            },
        }
    }
}

/// Judge one datagram, write its answers to the sender, and count it. The count is made after the answers are written, so a caller
/// that reads the report must wait for the datagram it sent to be counted before it reads anything else from it.
fn handle(
    socket: &UdpSocket,
    device: &Device,
    datagram: &[u8],
    peer: SocketAddr,
    report: &Mutex<DiscoveryReport>,
) {
    let judged = judge_from(device, datagram, peer.ip());
    let mut sent = 0_u32;
    if let Some(Verdict::Replies(replies)) = &judged {
        for reply in replies {
            if socket.send_to(reply.as_bytes(), peer).is_ok() {
                sent = sent.saturating_add(1);
            }
        }
    }
    let mut counts = lock(report);
    counts.received = counts.received.saturating_add(1);
    match judged {
        None => counts.foreign = counts.foreign.saturating_add(1),
        Some(Verdict::Silent) => counts.silent = counts.silent.saturating_add(1),
        Some(Verdict::Refused(word)) => counts.refusals.push(word),
        Some(Verdict::Replies(_)) if sent > 0 => {
            counts.answered = counts.answered.saturating_add(1);
            counts.replies_sent = counts.replies_sent.saturating_add(sent);
        }
        Some(Verdict::Replies(_)) => counts.failed = counts.failed.saturating_add(1),
    }
}

#[cfg(test)]
mod tests;
