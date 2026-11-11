//! A bounded, paced UDP carrier for N01 authenticated datagrams (`N07` / `ffw-ybr`, `docs/contracts/n07.md`).
//!
//! This is the packet send/receive half of N07 and nothing else: it moves [`crate::OutboundFrame`]s to peers over
//! real UDP sockets that are bound to loopback addresses, and brings authenticated packets back out of them. It does
//! not manage interfaces, leases, resolvers or radios, and it contacts nothing but the loopback addresses it is given.
//!
//! * **Bounded.** Every queue has a cap in packets and bytes (per peer, and across all peers), the work per call is
//!   capped, and a datagram larger than a peer's path allows is refused up front (the N01 block is 256 frames and
//!   cannot be split, so a path that cannot carry one is refused and never fragmented).
//! * **Paced.** One token bucket per interface, driven by a clock the caller passes in (nothing here reads a clock),
//!   charges each datagram its wire size plus the IP and UDP headers. Peers are served round robin.
//! * **Fenced.** Frames are queued as frames, not as signed datagrams, and signed at send time by a per-peer
//!   [`crate::StreamSender`], so sequence numbers stay dense for what was really sent. A send under a stale epoch is
//!   refused, and advancing the epoch drops everything queued under the old one: queued audio is never replayed.
//! * **Isolated.** A receiver reports, authenticated, how far it has consumed. A peer whose report stops opens no
//!   more than a fixed window of packets, its queue fills and drops its own oldest frames, and the other peers are
//!   served as before. Frames past their own `consume_by` are dropped, so a recovering peer is sent fresh audio only, with one
//!   exception that exists for recovery and is not audio: the datagram that holds the last sequence number the receiver is
//!   certain to admit (and a probe, which sends the newest transmitted datagram again) may go after its `consume_by`. It
//!   is authentic, the receiver's engine calls it late and never plays it, and what it earns is the receiver's authenticated
//!   report, which moves the sequence budget (see [`SEQ_AHEAD_LIMIT`]). It renders nothing.
//! * **Prioritised.** Control datagrams travel on a second socket, are sent ahead of media in every pump, and are
//!   limited per pump, so neither side can starve the other.
//! * **Grouped.** One sender owns one interface and may carry several streams on it (a group is a key, a stream identity
//!   and an epoch, with its own peers). Every group's peers draw on the same bucket, the same control share, the same
//!   aggregate caps, the same per-pump work bounds and the same admission sum: those bounds are the interface's, not a
//!   group's, and a second sender over the same interface would have its own, which is why groups live here. Peers are
//!   served round robin as peers, so a group's share of a saturated interface follows its member count. Selected host N06
//!   source, repair and feedback replies use those same interface budgets; selection alone is not negotiation or board admission.
//!
//! A pump never blocks: sockets are non-blocking and a would-block is counted, not waited on.

use crate::{
    AUTH_TAG_LEN_BYTES, AuthenticatedStreamPacket, HEADER_LEN_BYTES, HmacSha256,
    MAX_DATAGRAM_BYTES, MAX_PAYLOAD_BYTES, OutboundFrame, StreamError, StreamId, StreamKey,
    StreamReceiver, StreamSender, be_u64, tags_equal,
};
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// IPv4 header (20) plus UDP header (8).
pub const IPV4_UDP_OVERHEAD_BYTES: usize = 28;
/// IPv6 header (40) plus UDP header (8).
pub const IPV6_UDP_OVERHEAD_BYTES: usize = 48;
/// N01 header plus tag: what a datagram costs beyond its payload.
pub const WIRE_OVERHEAD_BYTES: usize = HEADER_LEN_BYTES + AUTH_TAG_LEN_BYTES;
/// Largest opaque control datagram.
pub const MAX_CONTROL_BYTES: usize = 512;
/// Size of a receiver report: 32 bytes of body and a 16-byte tag.
pub const REPORT_LEN_BYTES: usize = 48;

const REPORT_MAGIC: [u8; 4] = *b"FFWR";
const REPORT_VERSION: u8 = 1;
const REPORT_CONTEXT: &[u8] = b"FFWR-v1-auth";
const NANOS_PER_SEC: u64 = 1_000_000_000;
/// A refill never credits more than this much elapsed time, which keeps the arithmetic inside `u64`.
const MAX_REFILL_ELAPSED_NS: u64 = 4 * NANOS_PER_SEC;
/// Control may spend at most `1 / CONTROL_SHARE_DIVISOR` of the interface rate over time (plus a burst of `control_per_pump`
/// largest control datagrams), on top of being charged to the interface bucket: control is protected from media saturation
/// and cannot starve media.
const CONTROL_SHARE_DIVISOR: u64 = 8;
/// A peer that can send nothing new (its window is full of transmitted-but-unreported datagrams, or its sequence budget is
/// spent) is sent one probe per this interval: its newest transmitted datagram again, byte for byte. A window full of lost
/// datagrams cannot stall it for ever, and a frozen peer costs one datagram per interval.
pub const STALL_PROBE_NS: u64 = 250_000_000;
/// The largest window that can be configured. The per-peer list of unreported datagrams is bounded by the smaller of this and
/// [`SEQ_AHEAD_LIMIT`]: a window larger than the sequence budget is a supported setting whose effective size is the budget,
/// because nothing is allocated beyond it.
pub const MAX_WINDOW_PACKETS: u64 = 4096;
/// How far ahead of what its receiver has reported consumed a peer's sequence numbers may be allocated. N01's receiver refuses
/// a number more than `MAX_FORWARD_SEQ_GAP` (1024) beyond the highest it has admitted, and that highest is at least one below
/// any position it reports, so a number allocated within this distance of the report is always one the receiver can admit.
/// Past it nothing new is signed: whatever was allocated last is kept and retried until it goes, so a long outage can neither
/// run the sequence out of the receiver's reach nor leave the peer without a number that will be admitted when it returns.
pub const SEQ_AHEAD_LIMIT: u64 = 1000;
const _: () = assert!(SEQ_AHEAD_LIMIT < crate::MAX_FORWARD_SEQ_GAP);
/// Attempts at one signed datagram before it is dropped. A sequence number is allocated when a frame is signed and is never
/// reused, so a transport that refuses is retried with the same bytes, and a datagram that cannot go costs one number.
pub const SEND_RETRY_ATTEMPTS: u8 = 3;
/// A stream the sender carries on its interface. Ids are handed out by [`CarrierSender::add_group`] and never reused.
pub type GroupId = u32;
/// The group a sender is built with. It is the one [`CarrierSender::add_peer`], [`CarrierSender::submit_media`] and
/// [`CarrierSender::advance_epoch`] mean, and it is never removed.
pub const PRIMARY_GROUP: GroupId = 0;

/// The largest N01 payload that fits one datagram of a path with this MTU, in whole frames, or `None` when not even
/// one frame fits. The path must carry the IP and UDP headers, the N01 header and its tag.
#[must_use]
pub fn max_payload_for_path_mtu(path_mtu: usize, ipv6: bool) -> Option<usize> {
    let headers = if ipv6 {
        IPV6_UDP_OVERHEAD_BYTES
    } else {
        IPV4_UDP_OVERHEAD_BYTES
    };
    let room = path_mtu.checked_sub(headers + WIRE_OVERHEAD_BYTES)?;
    let payload = (room / 4 * 4).min(MAX_PAYLOAD_BYTES);
    if payload == 0 { None } else { Some(payload) }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CarrierError {
    #[error("invalid carrier limits: {0}")]
    InvalidLimits(&'static str),
    #[error("socket error: {0}")]
    Io(String),
    #[error("address {0} is not a loopback address and this carrier is loopback-only")]
    NotLoopback(SocketAddr),
    #[error("address {0} is of an address family this profile does not declare")]
    UnsupportedAddressFamily(SocketAddr),
    #[error("path MTU {path_mtu} carries {capacity} payload bytes but {required} are required")]
    PathMtuTooSmall {
        path_mtu: usize,
        capacity: usize,
        required: usize,
    },
    #[error("admitting peer {peer} needs {needed} B/s of a {budget} B/s budget")]
    OverBudget { peer: u32, needed: u64, budget: u64 },
    #[error("the carrier already has its {max} peers")]
    TooManyPeers { max: usize },
    #[error("peer {0} is not known")]
    UnknownPeer(u32),
    #[error("peer {0} is already present")]
    DuplicatePeer(u32),
    #[error("peer id {0} does not fit the three bytes a report names it in")]
    PeerIdTooLarge(u32),
    #[error("a send under epoch {submitted} is refused: the active epoch is {current}")]
    StaleEpoch { submitted: u64, current: u64 },
    #[error("a payload of {len} bytes is not a whole number of frames within the N01 maximum")]
    BadPayload { len: usize },
    #[error("a control datagram of {len} bytes is larger than the maximum")]
    ControlTooLarge { len: usize },
    #[error("the control queue of peer {0} is full")]
    ControlQueueFull(u32),
    #[error("group {0} is not known")]
    UnknownGroup(GroupId),
    #[error("the carrier already has its {max} groups")]
    TooManyGroups { max: usize },
    #[error("stream id {0} is already carried by a group on this interface")]
    StreamIdInUse(u64),
    #[error("the primary group is the one the sender was built with and cannot be removed")]
    PrimaryGroupIsFixed,
    #[error(transparent)]
    Stream(#[from] StreamError),
}

impl CarrierError {
    /// Stable machine-readable name, used in logs and in the scenario vectors.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits(_) => "INVALID_LIMITS",
            Self::Io(_) => "IO",
            Self::NotLoopback(_) => "NOT_LOOPBACK",
            Self::UnsupportedAddressFamily(_) => "UNSUPPORTED_ADDRESS_FAMILY",
            Self::PathMtuTooSmall { .. } => "PATH_MTU_TOO_SMALL",
            Self::OverBudget { .. } => "OVER_BUDGET",
            Self::TooManyPeers { .. } => "TOO_MANY_PEERS",
            Self::UnknownPeer(_) => "UNKNOWN_PEER",
            Self::DuplicatePeer(_) => "DUPLICATE_PEER",
            Self::PeerIdTooLarge(_) => "PEER_ID_TOO_LARGE",
            Self::StaleEpoch { .. } => "STALE_EPOCH",
            Self::BadPayload { .. } => "BAD_PAYLOAD",
            Self::ControlTooLarge { .. } => "CONTROL_TOO_LARGE",
            Self::ControlQueueFull(_) => "CONTROL_QUEUE_FULL",
            Self::UnknownGroup(_) => "UNKNOWN_GROUP",
            Self::TooManyGroups { .. } => "TOO_MANY_GROUPS",
            Self::StreamIdInUse(_) => "STREAM_ID_IN_USE",
            Self::PrimaryGroupIsFixed => "PRIMARY_GROUP_IS_FIXED",
            Self::Stream(err) => err.code(),
        }
    }
}

fn io_err(err: io::Error) -> CarrierError {
    CarrierError::Io(err.to_string())
}

/// Which of an endpoint's two sockets a port call is about. Control has a socket of its own so that a media flood can
/// fill the media socket's receive queue without ever delaying a stop or a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Media,
    Control,
}

/// Why a port call did not complete. `WouldBlock` is the normal answer of a non-blocking socket with nothing to do; the
/// others are faults the carrier counts in [`PortFaults`] and the link manager can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortFault {
    WouldBlock,
    /// The kernel said the datagram does not fit the path (`EMSGSIZE`). The carrier never fragments: this is evidence for
    /// an MTU fence, not something to retry.
    MessageTooLong,
    /// The local address or the route is gone (`EADDRNOTAVAIL`, `ENETUNREACH`, a down interface): a link-manager matter.
    PathUnavailable,
    /// A datagram was read and consumed by the kernel but cannot be used (its sender address was cut or unparsable, so it
    /// is never decoded as a peer). The caller counts it and keeps reading.
    Discarded,
    /// Any other error, as text (bounded by the port).
    Other(String),
}

/// One datagram read by a port. `from` is `None` when the port cannot say who sent it (a port over a sender-less `recv`):
/// the carrier then attributes a report by the peer id the report carries, never by guessing. The P02 port knows the sender
/// of every datagram (`recvfrom`), so a report from the wrong path is refused there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Bytes stored in the caller's buffer. A datagram longer than the buffer reports the buffer's length, so a buffer
    /// one byte larger than the largest legal datagram turns every oversize datagram into a rejected one.
    pub len: usize,
    pub from: Option<SocketAddr>,
}

/// The carrier's whole view of the network: two non-blocking datagram sockets and nothing else. `CarrierSender` and
/// `CarrierReceiver` are generic over it so that the same bounded logic runs over host `std` sockets ([`HostUdp`], for
/// host tests and harnesses) and over the P02 datagram boundary on a device (`franken-speaker`, `net_carrier`).
///
/// A port never blocks and never retries; it does not read a clock.
pub trait DatagramPort {
    /// Send one datagram from `lane`'s socket.
    ///
    /// # Errors
    /// [`PortFault`]; the carrier counts it and drops the datagram, it is never queued again.
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault>;

    /// Read one datagram from `lane`'s socket into `buf`; [`PortFault::WouldBlock`] when there is none.
    ///
    /// # Errors
    /// [`PortFault`].
    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault>;

    /// The local address of `lane`'s socket.
    ///
    /// # Errors
    /// [`PortFault`].
    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault>;

    /// Replace both sockets with new ones bound to `ip` (the local address changed). All or nothing: on an error the
    /// old sockets are still in place and still the endpoint's.
    ///
    /// # Errors
    /// [`PortFault`].
    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault>;
}

fn fault_text(fault: &PortFault) -> String {
    match fault {
        PortFault::WouldBlock => "would block".to_owned(),
        PortFault::MessageTooLong => "message too long for the path".to_owned(),
        PortFault::PathUnavailable => "address or route unavailable".to_owned(),
        PortFault::Discarded => "a consumed datagram could not be used".to_owned(),
        PortFault::Other(text) => text.chars().take(120).collect(),
    }
}

fn port_addr<P: DatagramPort>(port: &P, lane: Lane) -> Result<SocketAddr, CarrierError> {
    port.local_addr(lane)
        .map_err(|fault| CarrierError::Io(fault_text(&fault)))
}

/// Port-level faults, kept apart from [`CarrierStats`] and [`PeerCounters`] (whose field sets are the model's).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PortFaults {
    pub send_path_unavailable: u64,
    pub send_message_too_long: u64,
    pub send_other: u64,
    pub recv_path_unavailable: u64,
    pub recv_discarded: u64,
    pub recv_other: u64,
    pub rebinds: u64,
    pub rebind_failures: u64,
}

impl PortFaults {
    fn on_send(&mut self, fault: &PortFault) {
        let slot = match fault {
            PortFault::WouldBlock | PortFault::Discarded | PortFault::Other(_) => {
                &mut self.send_other
            }
            PortFault::MessageTooLong => &mut self.send_message_too_long,
            PortFault::PathUnavailable => &mut self.send_path_unavailable,
        };
        *slot = slot.saturating_add(1);
    }

    fn on_recv(&mut self, fault: &PortFault) {
        let slot = match fault {
            PortFault::PathUnavailable => &mut self.recv_path_unavailable,
            PortFault::Discarded => &mut self.recv_discarded,
            _ => &mut self.recv_other,
        };
        *slot = slot.saturating_add(1);
    }
}

/// The host port: two non-blocking `std` UDP sockets on one address, with OS-chosen ports. It is for host tests and
/// harnesses. A pass over it is a statement about this carrier's logic over the host's loopback, not about a legacy
/// kernel, an interface or a radio.
pub struct HostUdp {
    media: UdpSocket,
    control: UdpSocket,
}

impl HostUdp {
    /// Bind both sockets on `ip` (port 0).
    ///
    /// # Errors
    /// [`CarrierError::Io`].
    pub fn bind(ip: IpAddr) -> Result<Self, CarrierError> {
        Ok(Self {
            media: bind_nonblocking(ip).map_err(io_err)?,
            control: bind_nonblocking(ip).map_err(io_err)?,
        })
    }

    const fn socket(&self, lane: Lane) -> &UdpSocket {
        match lane {
            Lane::Media => &self.media,
            Lane::Control => &self.control,
        }
    }
}

fn host_fault(err: &io::Error) -> PortFault {
    match err.kind() {
        io::ErrorKind::WouldBlock => PortFault::WouldBlock,
        io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkDown => PortFault::PathUnavailable,
        _ => PortFault::Other(err.to_string()),
    }
}

impl DatagramPort for HostUdp {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        self.socket(lane)
            .send_to(bytes, to)
            .map(|_| ())
            .map_err(|err| host_fault(&err))
    }

    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        self.socket(lane)
            .recv_from(buf)
            .map(|(len, from)| Received {
                len,
                from: Some(from),
            })
            .map_err(|err| host_fault(&err))
    }

    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        self.socket(lane)
            .local_addr()
            .map_err(|err| host_fault(&err))
    }

    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        let media = bind_nonblocking(ip).map_err(|err| host_fault(&err))?;
        let control = bind_nonblocking(ip).map_err(|err| host_fault(&err))?;
        self.media = media;
        self.control = control;
        Ok(())
    }
}

/// Every bound the sending side keeps. All of them are checked by [`CarrierLimits::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierLimits {
    /// Refuse any address that is not loopback. This slice never leaves the host.
    pub loopback_only: bool,
    /// IPv6 is declared per profile; an address of an undeclared family is refused, never routed.
    pub allow_ipv6: bool,
    /// Payload bytes every admitted peer's path must carry (a full block is 1024).
    pub required_payload_bytes: usize,
    pub max_peers: usize,
    /// Conservative load of one peer; admission refuses a peer the pacing budget cannot carry on top of the others.
    pub peer_load_bytes_per_sec: u64,
    /// Interface pacing rate, charged per datagram with its IP and UDP headers.
    pub pace_bytes_per_sec: u64,
    pub pace_burst_bytes: u64,
    pub peer_queue_packets: usize,
    pub peer_queue_bytes: usize,
    pub aggregate_queue_packets: usize,
    pub aggregate_queue_bytes: usize,
    /// Per-peer control queue; the control budget of the interface is this times `max_peers`.
    pub control_queue_packets: usize,
    pub control_per_pump: usize,
    /// Packets a peer may have sent beyond its last report before its sending pauses. At most [`MAX_WINDOW_PACKETS`]; in effect
    /// never more than [`SEQ_AHEAD_LIMIT`], which stops allocation first when the window is larger.
    pub window_packets: u64,
    /// Attempts on the media lane one pump may make: sends that left, sends the transport refused and probes all count.
    pub max_sends_per_pump: usize,
    pub max_reads_per_pump: usize,
}

impl CarrierLimits {
    /// Values sized for 5.333 ms blocks of 1104-byte datagrams to up to eight peers.
    #[must_use]
    pub const fn baseline() -> Self {
        Self {
            loopback_only: true,
            allow_ipv6: false,
            required_payload_bytes: MAX_PAYLOAD_BYTES,
            max_peers: 8,
            peer_load_bytes_per_sec: 220_000,
            pace_bytes_per_sec: 1_760_000,
            pace_burst_bytes: 8_192,
            peer_queue_packets: 32,
            peer_queue_bytes: 36_864,
            aggregate_queue_packets: 128,
            aggregate_queue_bytes: 147_456,
            control_queue_packets: 8,
            control_per_pump: 4,
            window_packets: 16,
            max_sends_per_pump: 64,
            max_reads_per_pump: 64,
        }
    }

    /// The most payload and sequence allocation these limits allow, by kind: the queued bytes the aggregate and per-peer caps
    /// allow, one cached datagram per peer, the unreported list allocated at its bound (8 bytes a slot, the smaller of the window
    /// and [`SEQ_AHEAD_LIMIT`] slots, from admission on) and a full control queue. The cached datagram and the unreported list are
    /// outside the queue caps and are bounded here instead. `queue_slots` is not bounded here: it is struct-sized and reported
    /// apart.
    #[must_use]
    pub fn max_retained_bytes(&self) -> RetainedBytes {
        let peers = self.max_peers;
        let unreported = self.window_packets.min(SEQ_AHEAD_LIMIT) as usize;
        RetainedBytes {
            queued: self
                .aggregate_queue_bytes
                .min(peers.saturating_mul(self.peer_queue_bytes)),
            cached: peers.saturating_mul(MAX_DATAGRAM_BYTES),
            unreported: peers
                .saturating_mul(unreported)
                .saturating_mul(std::mem::size_of::<u64>()),
            control: peers
                .saturating_mul(self.control_queue_packets)
                .saturating_mul(MAX_CONTROL_BYTES),
            queue_slots: 0,
        }
    }

    /// The peer table at its bound: `max_peers` slots, each the size of one peer's fixed state (its counters, addresses, key,
    /// queue headers and options, all inline; the queues' slot arrays and payloads are not in it, see [`RetainedBytes`]). The
    /// sender allocates the table once, at this size, when it is built, and admitting a peer fills a slot without allocating, so
    /// [`CarrierSender::peer_table_bytes`] is this figure from construction on, however few peers are admitted. It is struct
    /// state, not payload or sequence allocation, so it is reported and bounded apart from [`Self::max_retained_bytes`].
    /// Saturating, like that figure.
    #[must_use]
    pub fn max_peer_table_bytes(&self) -> usize {
        self.max_peers
            .saturating_mul(std::mem::size_of::<PeerState>())
    }

    /// The group table at its bound: `max_peers` slots (the bound on groups), each the size of one group's state (its key, stream
    /// identity, epoch and id). Like the peer table it is allocated once, at this size, when the sender is built, with the
    /// primary group in the first slot, so adding or removing a group never allocates and [`CarrierSender::group_table_bytes`] is
    /// this figure from construction on. It is struct state, not payload or sequence allocation, so it is reported and bounded
    /// apart from [`Self::max_retained_bytes`]. Saturating, like that figure.
    #[must_use]
    pub fn max_group_table_bytes(&self) -> usize {
        self.max_peers
            .saturating_mul(std::mem::size_of::<GroupState>())
    }

    pub fn validate(&self) -> Result<(), CarrierError> {
        let bad = |why: &'static str| -> Result<(), CarrierError> {
            Err(CarrierError::InvalidLimits(why))
        };
        if self.required_payload_bytes == 0
            || self.required_payload_bytes > MAX_PAYLOAD_BYTES
            || !self.required_payload_bytes.is_multiple_of(4)
        {
            return bad("required payload is not whole frames within the N01 maximum");
        }
        if self.max_peers == 0 || self.max_peers > 64 {
            return bad("peer count outside 1..=64");
        }
        if self.peer_load_bytes_per_sec == 0 {
            return bad("peer load is zero");
        }
        if self.pace_bytes_per_sec == 0 || self.pace_bytes_per_sec > NANOS_PER_SEC {
            return bad("pace outside 1..=1e9 bytes per second");
        }
        let largest = (MAX_DATAGRAM_BYTES + IPV6_UDP_OVERHEAD_BYTES) as u64;
        if self.pace_burst_bytes < largest || self.pace_burst_bytes > 1_000_000 {
            return bad("burst cannot carry one datagram, or is over 1 MB");
        }
        if self.peer_queue_packets == 0 || self.peer_queue_bytes < MAX_DATAGRAM_BYTES {
            return bad("per-peer queue cannot hold one datagram");
        }
        if self.aggregate_queue_packets == 0 || self.aggregate_queue_bytes < MAX_DATAGRAM_BYTES {
            return bad("aggregate queue cannot hold one datagram");
        }
        if self.control_queue_packets == 0 || self.control_per_pump == 0 {
            return bad("control queue or control budget is zero");
        }
        if self.window_packets > MAX_WINDOW_PACKETS {
            return bad("window over 4096 packets");
        }
        if self.window_packets == 0 || self.max_sends_per_pump == 0 || self.max_reads_per_pump == 0
        {
            return bad("window or per-call work cap is zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    /// The path MTU cannot carry the required payload; nothing is fragmented and nothing is sent.
    PathMtuTooSmall,
}

/// What a peer's path can do after an MTU change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOutcome {
    Carrying,
    Fenced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropKind {
    Overflow,
    Aggregate,
    Late,
    Fenced,
    SendError,
}

/// Per-peer accounting. For media, `submitted = sent + dropped_* + queued` holds at every call boundary, in packets
/// and in wire bytes (header, payload and tag).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PeerCounters {
    pub media_submitted_packets: u64,
    pub media_submitted_bytes: u64,
    pub media_sent_packets: u64,
    pub media_sent_bytes: u64,
    pub fec_sent_packets: u64,
    pub fec_feedback_accepted: u64,
    pub fec_feedback_refused: u64,
    pub fec_feedback_deferred: u64,
    pub fec_feedback_overflow: u64,
    pub media_dropped_overflow_packets: u64,
    pub media_dropped_overflow_bytes: u64,
    pub media_dropped_aggregate_packets: u64,
    pub media_dropped_aggregate_bytes: u64,
    pub media_dropped_late_packets: u64,
    pub media_dropped_late_bytes: u64,
    pub media_dropped_fenced_packets: u64,
    pub media_dropped_fenced_bytes: u64,
    pub media_dropped_send_error_packets: u64,
    pub media_dropped_send_error_bytes: u64,
    pub control_submitted: u64,
    pub control_sent: u64,
    pub control_rejected_full: u64,
    pub control_dropped_send_error: u64,
    pub reports_accepted: u64,
    pub window_stalled_pumps: u64,
    /// Sum and maximum of the time sent packets waited in the queue: the pacing delay.
    pub queue_delay_ns_total: u64,
    pub queue_delay_ns_max: u64,
}

fn add_drop(counters: &mut PeerCounters, kind: DropKind, wire_len: usize) {
    let bytes = wire_len as u64;
    let (packets, total) = match kind {
        DropKind::Overflow => (
            &mut counters.media_dropped_overflow_packets,
            &mut counters.media_dropped_overflow_bytes,
        ),
        DropKind::Aggregate => (
            &mut counters.media_dropped_aggregate_packets,
            &mut counters.media_dropped_aggregate_bytes,
        ),
        DropKind::Late => (
            &mut counters.media_dropped_late_packets,
            &mut counters.media_dropped_late_bytes,
        ),
        DropKind::Fenced => (
            &mut counters.media_dropped_fenced_packets,
            &mut counters.media_dropped_fenced_bytes,
        ),
        DropKind::SendError => (
            &mut counters.media_dropped_send_error_packets,
            &mut counters.media_dropped_send_error_bytes,
        ),
    };
    *packets += 1;
    *total += bytes;
}

/// Interface-wide counters that belong to no one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CarrierStats {
    pub pumps: u64,
    pub link_down_pumps: u64,
    pub pace_limited_pumps: u64,
    pub send_cap_pumps: u64,
    pub stale_submits: u64,
    pub admissions_rejected: u64,
    pub control_datagrams_in: u64,
    pub reports_malformed: u64,
    pub reports_bad_tag: u64,
    pub reports_wrong_stream: u64,
    pub reports_stale_epoch: u64,
    pub reports_unknown_source: u64,
    pub reports_invalid: u64,
    pub fec_feedback_accepted: u64,
    pub fec_feedback_refused: u64,
    pub fec_work_refused: u64,
    pub fec_feedback_deferred: u64,
    pub fec_feedback_overflow: u64,
    pub recv_errors: u64,
    pub link_events: u64,
    pub path_changes: u64,
    pub mtu_fences: u64,
    pub mtu_unfences: u64,
    pub epoch_advances: u64,
    pub removed_peer_dropped_packets: u64,
    pub removed_peer_dropped_bytes: u64,
}

/// What one [`CarrierSender::submit_media`] did across the peers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SubmitReport {
    pub queued: u32,
    /// Older queued frames dropped to make room (this peer's own, or the longest queue's under aggregate pressure).
    pub evicted: u32,
    pub rejected_aggregate: u32,
    pub skipped_fenced: u32,
}

/// What one [`CarrierSender::pump`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PumpReport {
    pub link_down: bool,
    pub reports_applied: u32,
    pub control_sent: u32,
    pub media_sent: u32,
    pub late_dropped: u32,
    pub window_stalled_peers: u32,
    pub pace_limited: bool,
    pub send_cap_hit: bool,
    /// When the pacer will next afford the datagram it just could not (absolute, on the caller's clock).
    pub next_send_ns: Option<u64>,
}

/// The payload and sequence allocations the sender holds, by kind, counted by what is allocated (`capacity`), not by what is
/// logically in use: an allocation that stays after its contents are gone is still held, and is still reported. `queued` is what
/// [`PeerView::queued_bytes`] and the per-peer and aggregate caps count (queue and held datagram, as wire bytes). The rest is
/// bounded separately and was outside those caps: `cached` is the newest transmitted datagram of each peer, kept whole so that a
/// probe can send it again; `unreported` is the list of numbers transmitted and not yet reported (8 bytes a slot, allocated at
/// its bound when the peer is admitted and kept until it leaves); `control` is the queued control datagrams. Every byte vector
/// here is built to its exact length (a clone, `to_vec` or `with_capacity`), so for them capacity and length agree, which a
/// test holds. The slot arrays of the two queues are struct-sized and are counted in `queue_slots` (slots, not bytes) and left out
/// of [`RetainedBytes::total`], as are counters, keys, fixed fields, the allocator's overhead, kernel buffers and resident set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RetainedBytes {
    pub queued: usize,
    pub cached: usize,
    pub unreported: usize,
    pub control: usize,
    /// Slots allocated in the media and control queues of all peers: a count, not bytes.
    pub queue_slots: usize,
}

impl RetainedBytes {
    /// Sum the payload and sequence allocations, saturating at `usize::MAX` if the accounting range is exceeded.
    /// A saturated total is not a finite memory-admission budget; queue slots and the other exclusions above remain separate.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.queued
            .saturating_add(self.cached)
            .saturating_add(self.unreported)
            .saturating_add(self.control)
    }
}

/// A read-only view of one peer, for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerView {
    pub peer: u32,
    pub fence: Option<FenceReason>,
    pub path_mtu: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
    pub control_queued: usize,
    pub fec_feedback_pending: bool,
    pub sent_next: u64,
    pub reported_next: u64,
    pub in_flight: u64,
    pub stalled: bool,
    pub counters: PeerCounters,
}

/// A read-only view of one group: the stream it carries and what its peers hold. The queue figures are sums over its peers; the
/// caps they are held to are the interface's ([`CarrierLimits`]), shared with every other group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupView {
    pub group: GroupId,
    pub stream_id: u64,
    pub epoch: u64,
    /// Host development format; this is not board admission or negotiation proof.
    pub selected_strategy: &'static str,
    pub fec_retained_windows: usize,
    pub peers: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
}

/// What one stream on the interface is: the key that signs it and its reports, its identity and its epoch.
struct GroupState {
    id: GroupId,
    key: StreamKey,
    stream_id: StreamId,
    epoch: u64,
    fec: Option<FecGroup>,
    /// A selected FEC epoch was interrupted and cannot silently become N01.
    fec_fenced: bool,
}

/// Trusted transport provision for one already-enrolled carrier peer.
/// This does not authenticate a control member or authorize distributed activation.
#[derive(Clone)]
pub struct TargetFecBinding {
    /// Existing carrier peer receiving this target's datagrams and feedback replies.
    pub peer_id: u32,
    /// Trusted provisioned stream, epoch, origin and authentication key for that peer.
    pub config: crate::fec::SessionConfig,
}

// Two independently authenticated targets fit the existing per-window work bound.
const MAX_TARGET_FEC_PEERS: usize = 2;
const FEC_SOURCE_WORK: u64 = 2
    * (66 * crate::fec::solver::HASH_WORK + (crate::fec::K * crate::fec::BYTES) as u64)
    + crate::fec::N as u64 * (crate::fec::AUTH_WORK + (crate::fec::K * crate::fec::BYTES) as u64);
// Include the target-specific wire copies charged to the existing queues.
const FEC_TARGET_WORK: u64 = FEC_SOURCE_WORK + (crate::fec::N * crate::fec::DATAGRAM) as u64;

// Explicit live arrays in target submission; this is not a compiler stack/RSS bound.
const FEC_TARGET_SCRATCH_BYTES: usize =
    std::mem::size_of::<[[[u8; crate::fec::DATAGRAM]; crate::fec::N]; MAX_TARGET_FEC_PEERS]>()
        + std::mem::size_of::<[Option<crate::fec::SenderWindow>; MAX_TARGET_FEC_PEERS]>()
        + std::mem::size_of::<[[u8; crate::fec::BYTES]; crate::fec::K]>()
        + std::mem::size_of::<[u8; crate::fec::BYTES]>()
        + std::mem::size_of::<[u8; 64]>()
        + std::mem::size_of::<[u8; 32]>()
        + std::mem::size_of::<[u64; MAX_TARGET_FEC_PEERS]>()
        + std::mem::size_of::<[u32; MAX_TARGET_FEC_PEERS]>();

/// Owned local preparation, not proof of peer readiness or an activation decision.
/// The caller must hold the supplied numeric reservation until this is dropped or
/// committed. The token cannot be copied or used with another sender.
pub struct PreparedTargetFec {
    staged: Option<FecGroup>,
    owner: Arc<AtomicBool>,
    generation: u64,
    group: GroupId,
    epoch: u64,
    origin_ns: u64,
    local_media: SocketAddr,
    local_control: SocketAddr,
    charge_bytes: usize,
    initial_retained_bytes: usize,
    allowance_bytes: usize,
}

impl PreparedTargetFec {
    /// Total measured overlap and named scratch required at preparation.
    #[must_use]
    pub const fn required_bytes(&self) -> usize {
        self.charge_bytes
    }
}

impl Drop for PreparedTargetFec {
    fn drop(&mut self) {
        // Retire the actual allocations before making a subsequent preparation possible.
        drop(self.staged.take());
        self.owner.store(false, Ordering::Release);
    }
}

struct FecTarget {
    peer_id: u32,
    config: crate::fec::SessionConfig,
    windows: VecDeque<(u64, crate::fec::SenderWindow)>,
}

struct FecGroup {
    config: crate::fec::SessionConfig,
    windows: VecDeque<(u64, crate::fec::SenderWindow)>,
    targets: Vec<FecTarget>,
    next_window: u64,
    last_group_ns: Option<u64>,
    clock_failed: bool,
}

impl FecGroup {
    fn config_for_peer(&self, peer: u32) -> Option<&crate::fec::SessionConfig> {
        if self.targets.is_empty() {
            Some(&self.config)
        } else {
            self.targets
                .iter()
                .find(|target| target.peer_id == peer)
                .map(|target| &target.config)
        }
    }
    fn windows_for_peer(&self, peer: u32) -> Option<&VecDeque<(u64, crate::fec::SenderWindow)>> {
        if self.targets.is_empty() {
            Some(&self.windows)
        } else {
            self.targets
                .iter()
                .find(|target| target.peer_id == peer)
                .map(|target| &target.windows)
        }
    }
}

struct FecDatagram {
    wire: Vec<u8>,
    enqueued_ns: u64,
    consume_by_ns: u64,
    attempts: u8,
}

struct QueuedFrame {
    frame: OutboundFrame,
    wire_len: usize,
    enqueued_ns: u64,
}

/// A signed datagram the transport refused, kept whole for another attempt. It is never re-signed: its sequence number is its own.
struct HeldDatagram {
    wire: Vec<u8>,
    seq: u64,
    wire_len: usize,
    enqueued_ns: u64,
    consume_by_ns: u64,
    attempts: u8,
}

/// The newest datagram that was actually transmitted, kept whole: it is what a probe sends again. A retransmission is the same
/// bytes (so the same number, which is inside them), never a new payload under an old number. At most one per peer and at most
/// [`MAX_DATAGRAM_BYTES`], outside the queue caps and accounted in [`RetainedBytes::cached`].
struct SentDatagram {
    wire: Vec<u8>,
    wire_len: usize,
}

struct PeerState {
    id: u32,
    /// The stream this peer is a member of.
    group: GroupId,
    media_addr: SocketAddr,
    control_addr: SocketAddr,
    ipv6: bool,
    path_mtu: usize,
    fence: Option<FenceReason>,
    sender: StreamSender,
    media_q: VecDeque<QueuedFrame>,
    media_q_bytes: usize,
    fec_q: VecDeque<FecDatagram>,
    fec_q_bytes: usize,
    /// At most one attributable feedback request awaiting a usable group clock.
    pending_fec_feedback: Option<[u8; crate::fec::FEEDBACK_BYTES]>,
    control_q: VecDeque<Vec<u8>>,
    /// The next sequence number the framer will allocate. A number is allocated when a frame is signed and is never reused; it
    /// says nothing about what was transmitted (that is `in_flight`).
    sent_next: u64,
    reported_next: u64,
    /// Sequence numbers of datagrams that were transmitted and are not yet reported consumed, oldest first. This, not
    /// `sent_next - reported_next`, is what the window counts: a datagram that never left cannot be waiting for a report.
    in_flight: VecDeque<u64>,
    /// When a peer whose window is full may next be sent one probe datagram.
    probe_due_ns: Option<u64>,
    /// At most one signed datagram waiting for another attempt; nothing behind it is signed meanwhile. It counts in every
    /// queue and aggregate bound (see [`PeerState::queued_packets`]).
    held: Option<HeldDatagram>,
    /// The newest transmitted datagram, for probes.
    last_sent: Option<SentDatagram>,
    /// No attempt before this time: the next pump for a retry, or a full interval after a datagram was given up on.
    send_hold_until_ns: Option<u64>,
    counters: PeerCounters,
}

impl PeerState {
    const fn overhead(&self) -> usize {
        if self.ipv6 {
            IPV6_UDP_OVERHEAD_BYTES
        } else {
            IPV4_UDP_OVERHEAD_BYTES
        }
    }

    fn stalled(&self, window: u64) -> bool {
        self.in_flight.len() as u64 >= window
    }

    /// Nothing new may be signed and sent: the window is full of unreported datagrams, or the sequence budget is spent.
    fn waiting(&self, window: u64) -> bool {
        self.stalled(window) || self.sequence_blocked()
    }

    /// The numbers within [`SEQ_AHEAD_LIMIT`] of the report are all allocated and nothing is held to retry: only a probe, and
    /// the receiver's answer to it, can move the report and so the budget.
    fn sequence_blocked(&self) -> bool {
        self.held.is_none() && self.sent_next >= self.reported_next.saturating_add(SEQ_AHEAD_LIMIT)
    }

    /// The datagram that holds the last number the receiver is certain to admit must not be dropped, evicted or aged out:
    /// nothing after it can be signed, so dropping it would leave the peer without a number that will be admitted.
    fn must_keep(&self, datagram: &HeldDatagram) -> bool {
        datagram.seq.saturating_add(1) >= self.reported_next.saturating_add(SEQ_AHEAD_LIMIT)
    }

    /// A probe may be sent: the peer is waiting, its time has come, there is something to send, and something to send again.
    fn probe_due(&self, window: u64, now_ns: u64) -> bool {
        self.waiting(window)
            && self.probe_due_ns.is_some_and(|due| now_ns >= due)
            && self.last_sent.is_some()
            && !self.media_q.is_empty()
    }

    /// Bytes allocated for the cached newest transmitted datagram: kept for probes, outside the queue caps.
    fn cached_bytes(&self) -> usize {
        self.last_sent
            .as_ref()
            .map_or(0, |sent| sent.wire.capacity())
    }

    /// Packets queued for this peer: the queue and the held datagram.
    fn queued_packets(&self) -> usize {
        self.media_q.len() + self.fec_q.len() + usize::from(self.held.is_some())
    }

    /// Wire bytes queued for this peer: the queue and the held datagram.
    fn queued_bytes(&self) -> usize {
        self.media_q_bytes + self.fec_q_bytes + self.held.as_ref().map_or(0, |held| held.wire_len)
    }

    /// A report moved `reported_next`: forget the datagrams it covers, and re-open probing if the window is open again.
    fn on_reported(&mut self, window: u64) {
        while self
            .in_flight
            .front()
            .is_some_and(|seq| *seq < self.reported_next)
        {
            self.in_flight.pop_front();
        }
        if !self.waiting(window) {
            self.probe_due_ns = None;
        }
    }

    /// Number again from 0 under a new epoch or a new stream: everything queued or held is dropped (counted as fenced), and no
    /// count, report position, probe or retained datagram of the old numbering survives. The peer's address, path and an MTU
    /// fence are not part of the numbering and are kept.
    fn restart_numbering(&mut self) {
        self.purge_all(DropKind::Fenced);
        self.pending_fec_feedback = None;
        self.sent_next = 0;
        self.reported_next = 0;
        self.forget_in_flight();
    }

    /// A new epoch restarts every count: nothing from the old one can be reported or retried.
    fn forget_in_flight(&mut self) {
        self.in_flight.clear();
        self.probe_due_ns = None;
        self.send_hold_until_ns = None;
        self.last_sent = None;
    }

    fn drop_oldest(&mut self, kind: DropKind) {
        let fec_first = match (self.media_q.front(), self.fec_q.front()) {
            (Some(a), Some(b)) => b.enqueued_ns < a.enqueued_ns,
            (None, Some(_)) => true,
            _ => false,
        };
        if fec_first {
            if let Some(old) = self.fec_q.pop_front() {
                self.fec_q_bytes -= old.wire.len();
                add_drop(&mut self.counters, kind, old.wire.len());
            }
        } else if let Some(old) = self.media_q.pop_front() {
            self.media_q_bytes -= old.wire_len;
            add_drop(&mut self.counters, kind, old.wire_len);
        }
    }

    /// Drop everything queued, and the held datagram unless it holds the last number the receiver is certain to admit.
    fn purge_media(&mut self, kind: DropKind) {
        if let Some(held) = self.held.take() {
            if self.must_keep(&held) {
                self.held = Some(held);
            } else {
                add_drop(&mut self.counters, kind, held.wire_len);
            }
        }
        while !self.media_q.is_empty() || !self.fec_q.is_empty() {
            self.drop_oldest(kind);
        }
    }

    /// Drop everything, held datagram included: a new epoch numbers from 0 and nothing of the old one can be sent.
    fn purge_all(&mut self, kind: DropKind) {
        if let Some(held) = self.held.take() {
            add_drop(&mut self.counters, kind, held.wire_len);
        }
        self.purge_media(kind);
    }
}

/// A token bucket in nano-bytes (a byte is 10^9 of them), so that refills by whole nanoseconds lose nothing.
#[derive(Debug, Clone)]
struct Pacer {
    rate: u64,
    cap_nb: u64,
    tokens_nb: u64,
    last_ns: Option<u64>,
}

impl Pacer {
    fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        Self {
            rate: rate_bytes_per_sec,
            cap_nb: burst_bytes * NANOS_PER_SEC,
            tokens_nb: 0,
            last_ns: None,
        }
    }

    /// The bucket starts full at the first refill.
    fn refill(&mut self, now_ns: u64) {
        match self.last_ns {
            None => self.tokens_nb = self.cap_nb,
            Some(prev) => {
                let elapsed = now_ns.saturating_sub(prev).min(MAX_REFILL_ELAPSED_NS);
                self.tokens_nb = (self.tokens_nb + elapsed * self.rate).min(self.cap_nb);
            }
        }
        self.last_ns = Some(now_ns);
    }

    fn can_afford(&self, cost_bytes: u64) -> bool {
        self.tokens_nb >= cost_bytes * NANOS_PER_SEC
    }

    fn spend(&mut self, cost_bytes: u64) {
        self.tokens_nb -= cost_bytes * NANOS_PER_SEC;
    }

    /// Nanoseconds until `cost_bytes` can be afforded.
    fn wait_ns(&self, cost_bytes: u64) -> u64 {
        (cost_bytes * NANOS_PER_SEC)
            .saturating_sub(self.tokens_nb)
            .div_ceil(self.rate)
    }
}

fn bind_nonblocking(ip: IpAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn report_tag(key: &StreamKey, body: &[u8]) -> [u8; AUTH_TAG_LEN_BYTES] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("32-byte HMAC key is valid");
    mac.update(REPORT_CONTEXT);
    mac.update(body);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; AUTH_TAG_LEN_BYTES];
    tag.copy_from_slice(&full[..AUTH_TAG_LEN_BYTES]);
    tag
}

/// Largest peer id a report can name: three bytes. Id 0 in a report means "unattributed" (the sender then needs the
/// datagram's source address, which not every port can give), so an id that is to be attributable by number is 1 or more.
pub const MAX_ATTRIBUTABLE_PEER_ID: u32 = 0x00FF_FFFF;

/// The authenticated report a receiver sends back: which stream and epoch, the next sequence it has not consumed and, in
/// the three bytes that were reserved in the first slice, the peer id it was admitted under (0 = unattributed). The
/// peer id is covered by the tag, so it cannot be changed in flight; every receiver of a stream holds the stream key, so
/// it does not authenticate *which* receiver sent it, only that a holder of the key did. That is the same trust the
/// media itself rests on.
fn encode_report(
    key: &StreamKey,
    stream_id: StreamId,
    epoch: u64,
    consumed_next: u64,
    peer: u32,
) -> [u8; REPORT_LEN_BYTES] {
    let mut wire = [0u8; REPORT_LEN_BYTES];
    wire[0..4].copy_from_slice(&REPORT_MAGIC);
    wire[4] = REPORT_VERSION;
    let peer_bytes = (peer & MAX_ATTRIBUTABLE_PEER_ID).to_be_bytes();
    wire[5..8].copy_from_slice(&peer_bytes[1..4]);
    wire[8..16].copy_from_slice(&stream_id.get().to_be_bytes());
    wire[16..24].copy_from_slice(&epoch.to_be_bytes());
    wire[24..32].copy_from_slice(&consumed_next.to_be_bytes());
    let tag = report_tag(key, &wire[..32]);
    wire[32..].copy_from_slice(&tag);
    wire
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Report {
    stream_id: u64,
    epoch: u64,
    consumed_next: u64,
    /// 0 when the report does not name a peer.
    peer: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportError {
    Malformed,
    BadTag,
}

fn parse_report(key: &StreamKey, wire: &[u8]) -> Result<Report, ReportError> {
    if wire.len() != REPORT_LEN_BYTES || wire[0..4] != REPORT_MAGIC || wire[4] != REPORT_VERSION {
        return Err(ReportError::Malformed);
    }
    let tag = report_tag(key, &wire[..32]);
    if !tags_equal(&tag, &wire[32..]) {
        return Err(ReportError::BadTag);
    }
    Ok(Report {
        stream_id: be_u64(wire, 8),
        epoch: be_u64(wire, 16),
        consumed_next: be_u64(wire, 24),
        peer: u32::from_be_bytes([0, wire[5], wire[6], wire[7]]),
    })
}

/// The sending half: queues frames per peer, paces them out, sends control ahead of media, and reads receiver reports.
///
/// It owns one interface: one port, one bucket, one set of caps and one admission sum, shared by every group (stream) it
/// carries. `groups[0]` is the primary group, built with the sender, and is never removed.
pub struct CarrierSender<P: DatagramPort = HostUdp> {
    limits: CarrierLimits,
    port: P,
    groups: Vec<GroupState>,
    next_group: GroupId,
    peers: Vec<PeerState>,
    link_up: bool,
    pacer: Pacer,
    /// Control's own share of the interface rate; control is charged to this and to `pacer`.
    control_pacer: Pacer,
    media_cursor: usize,
    control_cursor: usize,
    fec_work_start_ns: Option<u64>,
    fec_work_charged: u64,
    stats: CarrierStats,
    control_stats: ControlStats,
    faults: PortFaults,
    stage_owner: Arc<AtomicBool>,
    stage_generation: u64,
}

/// What control cost the interface, apart from the model's counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ControlStats {
    /// Link bytes (payload plus IP and UDP headers) charged for control datagrams that were attempted.
    pub spent_bytes: u64,
    /// Pumps in which at least one queued control datagram had to wait for its budget.
    pub pace_limited_pumps: u64,
    /// Probes sent: a waiting peer's newest transmitted datagram, again. A probe is not a submitted frame and is in no
    /// media counter; the interface bucket is charged for it.
    pub probes_sent: u64,
    /// Link bytes (wire length plus IP and UDP headers) of the probes that were handed to the port.
    pub probe_bytes: u64,
}

impl CarrierSender<HostUdp> {
    /// Bind the media and control sockets on `ip` (a loopback address, unless the limits say otherwise) with
    /// OS-chosen ports, over host `std` sockets.
    pub fn bind(
        key: StreamKey,
        stream_id: StreamId,
        epoch: u64,
        limits: CarrierLimits,
        ip: IpAddr,
    ) -> Result<Self, CarrierError> {
        limits.validate()?;
        check_address(&limits, SocketAddr::new(ip, 0))?;
        let port = HostUdp::bind(ip)?;
        Self::with_port(key, stream_id, epoch, limits, port)
    }
}

impl<P: DatagramPort> CarrierSender<P> {
    /// A sender over any port. The limits are validated and the port's local addresses are held to the declared
    /// address policy before anything is sent.
    pub fn with_port(
        key: StreamKey,
        stream_id: StreamId,
        epoch: u64,
        limits: CarrierLimits,
        port: P,
    ) -> Result<Self, CarrierError> {
        limits.validate()?;
        for lane in [Lane::Media, Lane::Control] {
            check_address(&limits, port_addr(&port, lane)?)?;
        }
        let pacer = Pacer::new(limits.pace_bytes_per_sec, limits.pace_burst_bytes);
        let control_pacer = Pacer::new(
            (limits.pace_bytes_per_sec / CONTROL_SHARE_DIVISOR).max(1),
            limits.control_per_pump as u64 * (MAX_CONTROL_BYTES + IPV6_UDP_OVERHEAD_BYTES) as u64,
        );
        // the peer table is allocated once, at its bound (`validate` holds `max_peers` to 64), so admitting a peer never grows it
        let peers = Vec::with_capacity(limits.max_peers);
        // the group table likewise: groups are bounded by `max_peers` (`add_group` refuses the one past it), so it never grows
        let mut groups = Vec::with_capacity(limits.max_peers);
        groups.push(GroupState {
            id: PRIMARY_GROUP,
            key,
            stream_id,
            epoch,
            fec: None,
            fec_fenced: false,
        });
        Ok(Self {
            limits,
            port,
            groups,
            next_group: PRIMARY_GROUP + 1,
            peers,
            link_up: true,
            pacer,
            control_pacer,
            media_cursor: 0,
            control_cursor: 0,
            fec_work_start_ns: None,
            fec_work_charged: 0,
            stats: CarrierStats::default(),
            control_stats: ControlStats::default(),
            faults: PortFaults::default(),
            stage_owner: Arc::new(AtomicBool::new(false)),
            stage_generation: 0,
        })
    }

    pub fn media_addr(&self) -> Result<SocketAddr, CarrierError> {
        port_addr(&self.port, Lane::Media)
    }

    pub fn control_addr(&self) -> Result<SocketAddr, CarrierError> {
        port_addr(&self.port, Lane::Control)
    }

    /// Port-level faults and rebinds, apart from the model's counters.
    #[must_use]
    pub const fn faults(&self) -> &PortFaults {
        &self.faults
    }

    /// Whether this peer's sequence budget is spent: every number within [`SEQ_AHEAD_LIMIT`] of its receiver's report is
    /// allocated and nothing is held to retry. Only a probe and the receiver's answer to it can lift it; a peer that never
    /// answers stays blocked, and rejoining it is the control plane's epoch transition (`advance_epoch` on both sides), which
    /// nothing here performs by itself.
    #[must_use]
    pub fn sequence_blocked(&self, id: u32) -> bool {
        self.peers
            .iter()
            .find(|p| p.id == id)
            .is_some_and(PeerState::sequence_blocked)
    }

    /// What control cost the interface.
    #[must_use]
    pub const fn control_stats(&self) -> &ControlStats {
        &self.control_stats
    }

    /// The port, for a harness that wraps it and reads what it saw.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// The port, for a harness that moves its simulated state.
    pub fn port_mut(&mut self) -> &mut P {
        self.fence_prepared_target();
        &mut self.port
    }

    /// The local address changed (a link manager's `Rebind` action): replace both sockets with new ones on `ip`, all or
    /// nothing, and return the new `(media, control)` addresses. Queued audio is kept and ages out by its own
    /// `consume_by`; nothing is replayed. The caller must tell every receiver the new control address (over the
    /// control channel) before it expects reports again; until then reports from the old path are refused by the
    /// receivers' source check or never arrive.
    ///
    /// # Errors
    /// The address is outside the declared policy (nothing changed), or the port could not rebind (nothing changed).
    pub fn rebind(&mut self, ip: IpAddr) -> Result<(SocketAddr, SocketAddr), CarrierError> {
        check_address(&self.limits, SocketAddr::new(ip, 0))?;
        self.fence_prepared_target();
        if let Err(fault) = self.port.rebind(ip) {
            self.faults.rebind_failures = self.faults.rebind_failures.saturating_add(1);
            return Err(CarrierError::Io(fault_text(&fault)));
        }
        self.faults.rebinds = self.faults.rebinds.saturating_add(1);
        let groups: Vec<_> = self.groups.iter().map(|g| g.id).collect();
        for group in groups {
            self.invalidate_group_fec(group);
        }
        Ok((
            port_addr(&self.port, Lane::Media)?,
            port_addr(&self.port, Lane::Control)?,
        ))
    }

    /// The primary group's epoch (see [`Self::group_view`] for the others).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.groups[0].epoch
    }

    /// The ids of the groups this interface carries, primary first.
    #[must_use]
    pub fn group_ids(&self) -> Vec<GroupId> {
        self.groups.iter().map(|g| g.id).collect()
    }

    #[must_use]
    pub fn group_view(&self, group: GroupId) -> Option<GroupView> {
        let state = self.groups.iter().find(|g| g.id == group)?;
        let members = || self.peers.iter().filter(move |p| p.group == group);
        Some(GroupView {
            group,
            stream_id: state.stream_id.get(),
            epoch: state.epoch,
            selected_strategy: if state.fec_fenced
                || state.fec.as_ref().is_some_and(|fec| fec.clock_failed)
            {
                "transition-required"
            } else if state.fec.is_some() {
                crate::fec::PROFILE
            } else {
                "n01"
            },
            fec_retained_windows: state.fec.as_ref().map_or(0, |fec| {
                fec.windows.len()
                    + fec
                        .targets
                        .iter()
                        .map(|target| target.windows.len())
                        .sum::<usize>()
            }),
            peers: members().count(),
            queued_packets: members().map(PeerState::queued_packets).sum(),
            queued_bytes: members().map(PeerState::queued_bytes).sum(),
        })
    }

    fn group_index(&self, group: GroupId) -> Result<usize, CarrierError> {
        self.groups
            .iter()
            .position(|g| g.id == group)
            .ok_or(CarrierError::UnknownGroup(group))
    }

    #[must_use]
    pub const fn stats(&self) -> &CarrierStats {
        &self.stats
    }

    /// The payload and sequence allocations of every peer, by kind and by capacity (see [`RetainedBytes`]). Shrinking a list
    /// does not shrink what is allocated, and the report says so. The sum of the bounds is [`CarrierLimits::max_retained_bytes`].
    #[must_use]
    pub fn retained_bytes(&self) -> RetainedBytes {
        let mut out = RetainedBytes::default();
        for peer in &self.peers {
            out.queued += peer.queued_bytes();
            out.cached += peer.cached_bytes();
            out.unreported += peer.in_flight.capacity() * std::mem::size_of::<u64>();
            out.control += peer.control_q.iter().map(Vec::capacity).sum::<usize>();
            out.queue_slots +=
                peer.media_q.capacity() + peer.fec_q.capacity() + peer.control_q.capacity();
        }
        out
    }

    /// Bytes allocated for the peer table: its slots (`capacity`) times the size of one peer's fixed state. Reported apart from
    /// [`Self::retained_bytes`] because it is a table of structs, not payload or sequence allocation. The table is allocated once,
    /// at `max_peers`, when the sender is built, so this equals [`CarrierLimits::max_peer_table_bytes`] and does not move with
    /// admissions, removals or epochs; the slots no peer fills are allocated and are counted here all the same.
    #[must_use]
    pub fn peer_table_bytes(&self) -> usize {
        self.peers
            .capacity()
            .saturating_mul(std::mem::size_of::<PeerState>())
    }

    /// Bytes allocated for the group table: its slots (`capacity`) times the size of one group's state. Reported apart from
    /// [`Self::retained_bytes`] for the same reason as the peer table. It is allocated once, at `max_peers`, when the sender is
    /// built (the primary group fills the first slot), so this equals [`CarrierLimits::max_group_table_bytes`] and does not move
    /// as groups come and go; the slots no group fills are allocated and are counted here all the same.
    #[must_use]
    pub fn group_table_bytes(&self) -> usize {
        self.groups
            .capacity()
            .saturating_mul(std::mem::size_of::<GroupState>())
    }

    #[must_use]
    pub fn peer_ids(&self) -> Vec<u32> {
        self.peers.iter().map(|p| p.id).collect()
    }

    #[must_use]
    pub fn peer_view(&self, id: u32) -> Option<PeerView> {
        let window = self.limits.window_packets;
        self.peers.iter().find(|p| p.id == id).map(|p| PeerView {
            peer: p.id,
            fence: p.fence,
            path_mtu: p.path_mtu,
            queued_packets: p.queued_packets(),
            queued_bytes: p.queued_bytes(),
            control_queued: p.control_q.len(),
            fec_feedback_pending: p.pending_fec_feedback.is_some(),
            sent_next: p.sent_next,
            reported_next: p.reported_next,
            in_flight: p.in_flight.len() as u64,
            stalled: p.stalled(window),
            counters: p.counters.clone(),
        })
    }

    fn fence_prepared_target(&mut self) {
        self.stage_generation = self.stage_generation.saturating_add(1);
    }

    fn no_target_preparation(&self) -> Result<(), CarrierError> {
        if self.stage_owner.load(Ordering::Acquire) {
            return Err(CarrierError::InvalidLimits(
                "target preparation unavailable",
            ));
        }
        Ok(())
    }

    fn target_preparation_available(&self) -> Result<(), CarrierError> {
        self.no_target_preparation()?;
        if self.stage_generation == u64::MAX {
            return Err(CarrierError::InvalidLimits("target generation exhausted"));
        }
        Ok(())
    }

    fn index_of(&self, id: u32) -> Result<usize, CarrierError> {
        self.peers
            .iter()
            .position(|p| p.id == id)
            .ok_or(CarrierError::UnknownPeer(id))
    }

    /// Admit a peer. Everything that could disturb the peers already carried is checked first, and a refusal leaves
    /// them exactly as they were: a duplicate id, the peer count, the addresses, a path that cannot carry a block, and
    /// a pacing budget that cannot carry one more peer.
    pub fn add_peer(
        &mut self,
        id: u32,
        media_addr: SocketAddr,
        control_addr: SocketAddr,
        path_mtu: usize,
    ) -> Result<(), CarrierError> {
        self.add_peer_in_group(PRIMARY_GROUP, id, media_addr, control_addr, path_mtu)
    }

    /// Admit a peer as a member of `group`. The checks are [`Self::add_peer`]'s and the budgets they test are the interface's: the
    /// peer count and the pacing sum cover every group, so a group added later is admitted against what the groups already
    /// playing hold, and a refusal leaves all of them exactly as they were. A peer id names one peer on the interface (a
    /// report carries it), so a speaker that is a member of two groups is two peers.
    pub fn add_peer_in_group(
        &mut self,
        group: GroupId,
        id: u32,
        media_addr: SocketAddr,
        control_addr: SocketAddr,
        path_mtu: usize,
    ) -> Result<(), CarrierError> {
        let result = self.admit(group, id, media_addr, control_addr, path_mtu);
        if result.is_err() {
            self.stats.admissions_rejected += 1;
        }
        result
    }

    fn admit(
        &mut self,
        group: GroupId,
        id: u32,
        media_addr: SocketAddr,
        control_addr: SocketAddr,
        path_mtu: usize,
    ) -> Result<(), CarrierError> {
        let gi = self.group_index(group)?;
        if self.groups[gi].fec.is_some() {
            return Err(CarrierError::InvalidLimits(
                "change FEC membership only after an epoch transition",
            ));
        }
        if self.peers.iter().any(|p| p.id == id) {
            return Err(CarrierError::DuplicatePeer(id));
        }
        if id > MAX_ATTRIBUTABLE_PEER_ID {
            return Err(CarrierError::PeerIdTooLarge(id));
        }
        if self.peers.len() >= self.limits.max_peers {
            return Err(CarrierError::TooManyPeers {
                max: self.limits.max_peers,
            });
        }
        check_address(&self.limits, media_addr)?;
        check_address(&self.limits, control_addr)?;
        let ipv6 = media_addr.is_ipv6();
        let capacity = max_payload_for_path_mtu(path_mtu, ipv6).unwrap_or(0);
        if capacity < self.limits.required_payload_bytes {
            return Err(CarrierError::PathMtuTooSmall {
                path_mtu,
                capacity,
                required: self.limits.required_payload_bytes,
            });
        }
        let existing = self.peers.iter().fold(0_u64, |sum, p| {
            let selected = self
                .groups
                .iter()
                .any(|g| g.id == p.group && g.fec.is_some());
            let rate = if selected {
                let cost = (crate::fec::N + crate::fec::K) as u64
                    * (crate::fec::DATAGRAM + p.overhead()) as u64
                    * 48_000;
                self.limits.peer_load_bytes_per_sec.max(cost.div_ceil(1024))
            } else {
                self.limits.peer_load_bytes_per_sec
            };
            sum.saturating_add(rate)
        });
        let needed = existing.saturating_add(self.limits.peer_load_bytes_per_sec);
        if needed > self.limits.pace_bytes_per_sec {
            return Err(CarrierError::OverBudget {
                peer: id,
                needed,
                budget: self.limits.pace_bytes_per_sec,
            });
        }
        self.fence_prepared_target();
        let state = &self.groups[gi];
        let sender = StreamSender::new(state.key.clone(), state.stream_id, state.epoch);
        self.peers.push(PeerState {
            id,
            group,
            media_addr,
            control_addr,
            ipv6,
            path_mtu,
            fence: None,
            sender,
            media_q: VecDeque::new(),
            media_q_bytes: 0,
            fec_q: VecDeque::new(),
            fec_q_bytes: 0,
            pending_fec_feedback: None,
            control_q: VecDeque::new(),
            sent_next: 0,
            reported_next: 0,
            // allocated once, at its bound: transmitted-and-unreported numbers never exceed the window or the sequence budget,
            // so the list never grows, and what it holds is a fixed, reported allocation rather than a doubling one
            in_flight: VecDeque::with_capacity(
                usize::try_from(self.limits.window_packets.min(SEQ_AHEAD_LIMIT)).unwrap_or(0),
            ),
            probe_due_ns: None,
            held: None,
            last_sent: None,
            send_hold_until_ns: None,
            counters: PeerCounters::default(),
        });
        Ok(())
    }

    /// A peer leaves. What it still had queued is counted, not forgotten.
    pub fn remove_peer(&mut self, id: u32) -> Result<(), CarrierError> {
        let idx = self.index_of(id)?;
        let group = self.peers[idx].group;
        self.invalidate_group_fec(group);
        let gone = self.peers.remove(idx);
        self.stats.removed_peer_dropped_packets +=
            gone.media_q.len() as u64 + u64::from(gone.held.is_some());
        self.stats.removed_peer_dropped_bytes +=
            gone.media_q_bytes as u64 + gone.held.as_ref().map_or(0, |held| held.wire_len as u64);
        Ok(())
    }

    /// The peer keeps its identity, its sequence and its counters; only the addresses change. Reports that still
    /// arrive from the old control address are no longer anyone's and are refused.
    pub fn peer_address_changed(
        &mut self,
        id: u32,
        media_addr: SocketAddr,
        control_addr: SocketAddr,
    ) -> Result<(), CarrierError> {
        let idx = self.index_of(id)?;
        check_address(&self.limits, media_addr)?;
        check_address(&self.limits, control_addr)?;
        // A move onto a family with more header overhead (IPv6 after IPv4) shrinks what the same path MTU carries. A peer the new
        // path cannot carry a block to is refused here, before anything changes, as it would be at admission.
        let required = self.limits.required_payload_bytes;
        let peer = &mut self.peers[idx];
        let capacity = max_payload_for_path_mtu(peer.path_mtu, media_addr.is_ipv6()).unwrap_or(0);
        if capacity < required {
            return Err(CarrierError::PathMtuTooSmall {
                path_mtu: peer.path_mtu,
                capacity,
                required,
            });
        }
        let group = peer.group;
        self.invalidate_group_fec(group);
        let peer = &mut self.peers[idx];
        peer.media_addr = media_addr;
        peer.control_addr = control_addr;
        peer.ipv6 = media_addr.is_ipv6();
        self.stats.path_changes += 1;
        Ok(())
    }

    /// A path MTU change. A path that can no longer carry a block fences the peer (its queue is dropped and nothing is
    /// sent to it until the path recovers); other peers are untouched. Nothing is ever fragmented.
    pub fn set_path_mtu(&mut self, id: u32, path_mtu: usize) -> Result<PathOutcome, CarrierError> {
        let idx = self.index_of(id)?;
        self.fence_prepared_target();
        let required = self.limits.required_payload_bytes;
        let group = self.peers[idx].group;
        let selected = self.groups.iter().any(|g| g.id == group && g.fec.is_some());
        let peer = &mut self.peers[idx];
        let capacity = max_payload_for_path_mtu(path_mtu, peer.ipv6).unwrap_or(0);
        let fec_too_small = selected && path_mtu < crate::fec::DATAGRAM + peer.overhead();
        peer.path_mtu = path_mtu;
        if capacity < required || fec_too_small {
            if peer.fence.is_none() {
                peer.fence = Some(FenceReason::PathMtuTooSmall);
                peer.purge_media(DropKind::Fenced);
                self.stats.mtu_fences += 1;
            }
            Ok(PathOutcome::Fenced)
        } else {
            if peer.fence == Some(FenceReason::PathMtuTooSmall) {
                peer.fence = None;
                self.stats.mtu_unfences += 1;
            }
            Ok(PathOutcome::Carrying)
        }
    }

    /// Interface up or down (a simulated event: no interface is touched). While down nothing is sent or read, queues
    /// stay bounded, and frames past their `consume_by` are dropped when the link returns.
    pub fn set_link_up(&mut self, up: bool) {
        if self.link_up != up {
            self.fence_prepared_target();
        }
        self.link_up = up;
        self.stats.link_events += 1;
    }

    /// Move to a strictly newer epoch. Everything queued under the old epoch is dropped, never sent, and every
    /// peer's sequence and consumed position start again from zero.
    pub fn advance_epoch(&mut self, new_epoch: u64) -> Result<(), CarrierError> {
        self.advance_group_epoch(PRIMARY_GROUP, new_epoch)
    }

    /// [`Self::advance_epoch`] for one group: only that group's peers are fenced and renumbered; the other groups on the
    /// interface keep their queues, numbers and epochs.
    pub fn advance_group_epoch(
        &mut self,
        group: GroupId,
        new_epoch: u64,
    ) -> Result<(), CarrierError> {
        let gi = self.group_index(group)?;
        let current = self.groups[gi].epoch;
        if new_epoch <= current {
            return Err(CarrierError::Stream(StreamError::EpochNotAdvancing {
                requested: new_epoch,
                current,
            }));
        }
        self.fence_prepared_target();
        for peer in self.peers.iter_mut().filter(|p| p.group == group) {
            peer.pending_fec_feedback = None;
            peer.sender.advance_epoch(new_epoch)?;
            peer.restart_numbering();
        }
        self.groups[gi].epoch = new_epoch;
        self.groups[gi].fec = None;
        self.groups[gi].fec_fenced = false;
        self.stats.epoch_advances += 1;
        Ok(())
    }

    /// Carry another stream on this interface, with its own key, stream identity and epoch, and no peers yet. Its peers are
    /// admitted with [`Self::add_peer_in_group`] against the interface's budgets, not against a budget of its own. The stream
    /// identity must differ from every group's here (a report names it, and it selects the key the report is checked with),
    /// and the number of groups is bounded by `max_peers`: a group without a peer holds only its slot of the group table
    /// ([`Self::group_table_bytes`], allocated when the sender is built), and each peer is a member of one.
    ///
    /// # Errors
    /// [`CarrierError::StreamIdInUse`], [`CarrierError::TooManyGroups`]. Nothing changes.
    pub fn add_group(
        &mut self,
        key: StreamKey,
        stream_id: StreamId,
        epoch: u64,
    ) -> Result<GroupId, CarrierError> {
        if self.groups.iter().any(|g| {
            g.stream_id == stream_id
                || g.fec.as_ref().is_some_and(|fec| {
                    fec.targets
                        .iter()
                        .any(|target| target.config.stream == stream_id)
                })
        }) {
            return Err(CarrierError::StreamIdInUse(stream_id.get()));
        }
        if self.groups.len() >= self.limits.max_peers {
            return Err(CarrierError::TooManyGroups {
                max: self.limits.max_peers,
            });
        }
        self.fence_prepared_target();
        let id = self.next_group;
        self.next_group = id.saturating_add(1);
        self.groups.push(GroupState {
            id,
            key,
            stream_id,
            epoch,
            fec: None,
            fec_fenced: false,
        });
        Ok(id)
    }

    /// A group leaves the interface with its peers. What they still had queued is counted as a removed peer's is, and the
    /// interface's budgets are theirs to the other groups again. Nothing of another group changes.
    ///
    /// # Errors
    /// [`CarrierError::PrimaryGroupIsFixed`], [`CarrierError::UnknownGroup`].
    pub fn remove_group(&mut self, group: GroupId) -> Result<(), CarrierError> {
        if group == PRIMARY_GROUP {
            return Err(CarrierError::PrimaryGroupIsFixed);
        }
        let gi = self.group_index(group)?;
        self.fence_prepared_target();
        let stats = &mut self.stats;
        self.peers.retain(|gone| {
            if gone.group != group {
                return true;
            }
            stats.removed_peer_dropped_packets +=
                gone.media_q.len() as u64 + u64::from(gone.held.is_some());
            stats.removed_peer_dropped_bytes += gone.media_q_bytes as u64
                + gone.held.as_ref().map_or(0, |held| held.wire_len as u64);
            false
        });
        self.groups.remove(gi);
        Ok(())
    }

    /// A source restart: the group carries a new stream. Policy: the restart is **a fresh stream identity and a strictly newer
    /// epoch**, both announced by the control plane (the carrier makes up neither), and the identity must differ from every
    /// group's on this interface, the group's own included. Everything the group's peers had queued, held, retained for a probe
    /// or in flight is dropped (counted as fenced) and never sent; their numbering starts again at 0 under the new stream;
    /// their addresses, paths and an MTU fence stay. A report that names the old stream is refused as a wrong stream, and a
    /// submit under the old epoch is refused as stale. No other group is touched. The key is the group's: a rekey is a new
    /// group, not a restart.
    ///
    /// # Errors
    /// [`CarrierError::UnknownGroup`], [`CarrierError::StreamIdInUse`], or the epoch does not advance. Nothing changes.
    pub fn restart_group(
        &mut self,
        group: GroupId,
        new_stream_id: StreamId,
        new_epoch: u64,
    ) -> Result<(), CarrierError> {
        let gi = self.group_index(group)?;
        if self.groups.iter().any(|g| {
            g.stream_id == new_stream_id
                || g.fec.as_ref().is_some_and(|fec| {
                    fec.targets
                        .iter()
                        .any(|target| target.config.stream == new_stream_id)
                })
        }) {
            return Err(CarrierError::StreamIdInUse(new_stream_id.get()));
        }
        let current = self.groups[gi].epoch;
        if new_epoch <= current {
            return Err(CarrierError::Stream(StreamError::EpochNotAdvancing {
                requested: new_epoch,
                current,
            }));
        }
        self.fence_prepared_target();
        let key = self.groups[gi].key.clone();
        for peer in self.peers.iter_mut().filter(|p| p.group == group) {
            peer.sender = StreamSender::new(key.clone(), new_stream_id, new_epoch);
            peer.restart_numbering();
        }
        self.groups[gi].stream_id = new_stream_id;
        self.groups[gi].epoch = new_epoch;
        self.groups[gi].fec = None;
        self.groups[gi].fec_fenced = false;
        self.stats.epoch_advances += 1;
        Ok(())
    }

    fn aggregate_media(&self) -> (usize, usize) {
        let packets: usize = self.peers.iter().map(PeerState::queued_packets).sum();
        let bytes: usize = self.peers.iter().map(PeerState::queued_bytes).sum();
        (packets, bytes)
    }

    /// The peer with the most queued media bytes (the lowest index on a tie), if any peer has anything queued.
    fn largest_media_queue(&self) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for (idx, peer) in self.peers.iter().enumerate() {
            if peer.media_q.is_empty() && peer.fec_q.is_empty() {
                continue;
            }
            let longer = match best {
                Some((_, bytes)) => peer.media_q_bytes + peer.fec_q_bytes > bytes,
                None => true,
            };
            if longer {
                best = Some((idx, peer.media_q_bytes + peer.fec_q_bytes));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// Fixed retained source-window allocation, separate from queued datagrams.
    #[must_use]
    pub fn fec_retained_bytes(&self) -> usize {
        self.groups
            .iter()
            .filter_map(|g| g.fec.as_ref())
            .map(|f| {
                f.windows
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u64, crate::fec::SenderWindow)>())
                    .saturating_add(
                        f.targets
                            .capacity()
                            .saturating_mul(std::mem::size_of::<FecTarget>()),
                    )
                    .saturating_add(
                        f.targets
                            .iter()
                            .map(|target| {
                                target
                                    .windows
                                    .capacity()
                                    .saturating_mul(std::mem::size_of::<(
                                        u64,
                                        crate::fec::SenderWindow,
                                    )>())
                            })
                            .sum::<usize>(),
                    )
            })
            .sum()
    }

    /// Synthetic work charged across all groups in the current sender interval.
    #[must_use]
    pub const fn fec_work_charged(&self) -> u64 {
        self.fec_work_charged
    }

    fn reserve_fec_work(&mut self, now_ns: u64, cost: u64) -> bool {
        const INTERVAL_NS: u64 = 21_333_334;
        if self.fec_work_start_ns.is_none_or(|start| {
            now_ns
                .checked_sub(start)
                .is_some_and(|elapsed| elapsed >= INTERVAL_NS)
        }) {
            self.fec_work_start_ns = Some(now_ns);
            self.fec_work_charged = 0;
        }
        let Some(total) = self.fec_work_charged.checked_add(cost) else {
            self.stats.fec_work_refused += 1;
            return false;
        };
        if total > crate::fec::WINDOW_ALLOWANCE_NS / crate::fec::WORK_UNIT_NS {
            self.stats.fec_work_refused += 1;
            return false;
        }
        self.fec_work_charged = total;
        true
    }

    fn fec_work_available(&self, now_ns: u64, cost: u64) -> bool {
        const INTERVAL_NS: u64 = 21_333_334;
        let charged = if self.fec_work_start_ns.is_none_or(|start| {
            now_ns
                .checked_sub(start)
                .is_some_and(|elapsed| elapsed >= INTERVAL_NS)
        }) {
            0
        } else {
            self.fec_work_charged
        };
        charged.checked_add(cost).is_some_and(|total| {
            total <= crate::fec::WINDOW_ALLOWANCE_NS / crate::fec::WORK_UNIT_NS
        })
    }

    fn invalidate_group_fec(&mut self, group: GroupId) {
        self.fence_prepared_target();
        if let Some(state) = self.groups.iter_mut().find(|g| g.id == group)
            && state.fec.take().is_some()
        {
            state.fec_fenced = true;
        }
        for peer in self.peers.iter_mut().filter(|p| p.group == group) {
            peer.pending_fec_feedback = None;
            while let Some(packet) = peer.fec_q.pop_front() {
                peer.fec_q_bytes -= packet.wire.len();
                add_drop(&mut peer.counters, DropKind::Fenced, packet.wire.len());
            }
        }
    }

    /// Select the fixed host profile after the trusted control plane validates
    /// the exact member list. This call does not authenticate negotiation.
    pub fn select_group_fec(
        &mut self,
        group: GroupId,
        epoch: u64,
        origin_ns: u64,
        validated_peer_ids: &[u32],
    ) -> Result<(), CarrierError> {
        self.no_target_preparation()?;
        let (gi, config) = self.preflight_group_fec(group, epoch, origin_ns, validated_peer_ids)?;
        self.advance_group_epoch(group, epoch)?;
        self.groups[gi].fec = Some(FecGroup {
            config,
            windows: VecDeque::with_capacity(crate::fec::WINDOWS),
            targets: Vec::new(),
            next_window: 0,
            last_group_ns: None,
            clock_failed: false,
        });
        Ok(())
    }

    /// Select separately keyed future-epoch targets supplied by a trusted transport provisioner.
    /// A raw peer/config pair is not proof of control-member identity or distributed readiness.
    /// `retained_budget_bytes` is the caller's allowance for all currently retained FEC state
    /// plus this selection's measured capacities and explicitly held submission arrays. The caller
    /// must continue reserving that allowance while this selection lives.
    pub fn select_group_target_fec(
        &mut self,
        group: GroupId,
        epoch: u64,
        origin_ns: u64,
        bindings: &[TargetFecBinding],
        retained_budget_bytes: usize,
    ) -> Result<(), CarrierError> {
        self.no_target_preparation()?;
        if bindings.is_empty() || bindings.len() > MAX_TARGET_FEC_PEERS {
            return Err(CarrierError::InvalidLimits("per-target FEC work cap"));
        }
        let gi = self.group_index(group)?;
        if self.groups[gi].epoch.checked_add(1) != Some(epoch) {
            return Err(CarrierError::StaleEpoch {
                submitted: epoch,
                current: self.groups[gi].epoch,
            });
        }
        for (i, binding) in bindings.iter().enumerate() {
            if binding.config.epoch != epoch
                || binding.config.presentation_origin_ns != origin_ns
                || bindings.iter().skip(i + 1).any(|other| {
                    other.peer_id == binding.peer_id || other.config.stream == binding.config.stream
                })
                || self.groups.iter().any(|other| {
                    other.id != group
                        && (other.stream_id == binding.config.stream
                            || other.fec.as_ref().is_some_and(|fec| {
                                fec.targets
                                    .iter()
                                    .any(|target| target.config.stream == binding.config.stream)
                            }))
                })
            {
                return Err(CarrierError::InvalidLimits(
                    "inconsistent target FEC binding",
                ));
            }
            binding
                .config
                .metadata(0)
                .map_err(|_| CarrierError::InvalidLimits("invalid target timeline"))?;
        }
        let mut ids = [0_u32; MAX_TARGET_FEC_PEERS];
        for (i, binding) in bindings.iter().enumerate() {
            ids[i] = binding.peer_id;
        }
        let (_, common_config) =
            self.preflight_group_fec(group, epoch, origin_ns, &ids[..bindings.len()])?;
        let work = FEC_TARGET_WORK
            .checked_mul(bindings.len() as u64)
            .ok_or(CarrierError::InvalidLimits("target FEC work overflow"))?;
        if work > crate::fec::WINDOW_ALLOWANCE_NS / crate::fec::WORK_UNIT_NS {
            return Err(CarrierError::InvalidLimits("per-target FEC work cap"));
        }
        // Charge each explicitly held submission array, not a whole-stack/RSS estimate.
        let scratch = FEC_TARGET_SCRATCH_BYTES;
        let minimum = self
            .fec_retained_bytes()
            .checked_add(scratch)
            .and_then(|v| v.checked_add(bindings.len() * std::mem::size_of::<FecTarget>()))
            .and_then(|v| {
                v.checked_add(
                    bindings.len()
                        * crate::fec::WINDOWS
                        * std::mem::size_of::<(u64, crate::fec::SenderWindow)>(),
                )
            })
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        if minimum > retained_budget_bytes {
            return Err(CarrierError::InvalidLimits("target FEC memory cap"));
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(bindings.len())
            .map_err(|_| CarrierError::InvalidLimits("target FEC allocation"))?;
        let mut actual = self
            .fec_retained_bytes()
            .checked_add(scratch)
            .and_then(|v| {
                targets
                    .capacity()
                    .checked_mul(std::mem::size_of::<FecTarget>())
                    .and_then(|bytes| v.checked_add(bytes))
            })
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        if actual > retained_budget_bytes {
            return Err(CarrierError::InvalidLimits("target FEC memory cap"));
        }
        for binding in bindings {
            let mut windows = VecDeque::new();
            windows
                .try_reserve_exact(crate::fec::WINDOWS)
                .map_err(|_| CarrierError::InvalidLimits("target FEC allocation"))?;
            actual = actual
                .checked_add(
                    windows
                        .capacity()
                        .checked_mul(std::mem::size_of::<(u64, crate::fec::SenderWindow)>())
                        .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?,
                )
                .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
            if actual > retained_budget_bytes {
                return Err(CarrierError::InvalidLimits("target FEC memory cap"));
            }
            targets.push(FecTarget {
                peer_id: binding.peer_id,
                config: binding.config.clone(),
                windows,
            });
        }
        self.advance_group_epoch(group, epoch)?;
        self.groups[gi].fec = Some(FecGroup {
            config: common_config,
            windows: VecDeque::new(),
            targets,
            next_window: 0,
            last_group_ns: None,
            clock_failed: false,
        });
        Ok(())
    }

    /// Allocate a bounded future target selection while the current stream remains live.
    /// This does not authenticate members, check clocks, or authorize activation. The trusted
    /// caller must hold `retained_budget_bytes` until token drop or successful commit, and
    /// must include other users of the same budget. Only one token may exist per sender.
    /// The caller must retain exclusive custody of the port: external mutations through
    /// shared backend aliases cannot be observed reliably, including an address ABA.
    /// The owner identity Arc backing is a fixed sender allocation, excluded from this FEC
    /// allowance; account for it in the caller's sender budget. This is not an RSS bound.
    pub fn prepare_group_target_fec(
        &mut self,
        group: GroupId,
        epoch: u64,
        origin_ns: u64,
        bindings: &[TargetFecBinding],
        retained_budget_bytes: usize,
    ) -> Result<PreparedTargetFec, CarrierError> {
        self.target_preparation_available()?;
        if bindings.is_empty() || bindings.len() > MAX_TARGET_FEC_PEERS {
            return Err(CarrierError::InvalidLimits("per-target FEC work cap"));
        }
        let gi = self.group_index(group)?;
        if self.groups[gi].epoch.checked_add(1) != Some(epoch) {
            return Err(CarrierError::StaleEpoch {
                submitted: epoch,
                current: self.groups[gi].epoch,
            });
        }
        for (i, binding) in bindings.iter().enumerate() {
            if binding.config.epoch != epoch
                || binding.config.presentation_origin_ns != origin_ns
                || bindings.iter().skip(i + 1).any(|other| {
                    other.peer_id == binding.peer_id || other.config.stream == binding.config.stream
                })
                || self.groups.iter().any(|other| {
                    other.id != group
                        && (other.stream_id == binding.config.stream
                            || other.fec.as_ref().is_some_and(|fec| {
                                fec.targets
                                    .iter()
                                    .any(|target| target.config.stream == binding.config.stream)
                            }))
                })
            {
                return Err(CarrierError::InvalidLimits(
                    "inconsistent target FEC binding",
                ));
            }
            binding
                .config
                .metadata(0)
                .map_err(|_| CarrierError::InvalidLimits("invalid target timeline"))?;
        }
        let mut ids = [0_u32; MAX_TARGET_FEC_PEERS];
        for (i, binding) in bindings.iter().enumerate() {
            ids[i] = binding.peer_id;
        }
        let (_, common_config) =
            self.preflight_group_fec(group, epoch, origin_ns, &ids[..bindings.len()])?;
        if self
            .peers
            .iter()
            .any(|peer| peer.group == group && peer.fence.is_some())
        {
            return Err(CarrierError::InvalidLimits("target peer is fenced"));
        }
        let work = FEC_TARGET_WORK
            .checked_mul(bindings.len() as u64)
            .ok_or(CarrierError::InvalidLimits("target FEC work overflow"))?;
        if work > crate::fec::WINDOW_ALLOWANCE_NS / crate::fec::WORK_UNIT_NS {
            return Err(CarrierError::InvalidLimits("per-target FEC work cap"));
        }
        // Charge each explicitly held submission array, not a whole-stack/RSS estimate.
        let scratch = FEC_TARGET_SCRATCH_BYTES
            .checked_add(std::mem::size_of::<PreparedTargetFec>())
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        let minimum = self
            .fec_retained_bytes()
            .checked_add(scratch)
            .and_then(|v| v.checked_add(bindings.len() * std::mem::size_of::<FecTarget>()))
            .and_then(|v| {
                v.checked_add(
                    bindings.len()
                        * crate::fec::WINDOWS
                        * std::mem::size_of::<(u64, crate::fec::SenderWindow)>(),
                )
            })
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        if minimum > retained_budget_bytes {
            return Err(CarrierError::InvalidLimits("target FEC memory cap"));
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(bindings.len())
            .map_err(|_| CarrierError::InvalidLimits("target FEC allocation"))?;
        let mut actual = self
            .fec_retained_bytes()
            .checked_add(scratch)
            .and_then(|v| {
                targets
                    .capacity()
                    .checked_mul(std::mem::size_of::<FecTarget>())
                    .and_then(|bytes| v.checked_add(bytes))
            })
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        if actual > retained_budget_bytes {
            return Err(CarrierError::InvalidLimits("target FEC memory cap"));
        }
        for binding in bindings {
            let mut windows = VecDeque::new();
            windows
                .try_reserve_exact(crate::fec::WINDOWS)
                .map_err(|_| CarrierError::InvalidLimits("target FEC allocation"))?;
            actual = actual
                .checked_add(
                    windows
                        .capacity()
                        .checked_mul(std::mem::size_of::<(u64, crate::fec::SenderWindow)>())
                        .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?,
                )
                .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
            if actual > retained_budget_bytes {
                return Err(CarrierError::InvalidLimits("target FEC memory cap"));
            }
            targets.push(FecTarget {
                peer_id: binding.peer_id,
                config: binding.config.clone(),
                windows,
            });
        }
        let local_media = self.media_addr()?;
        let local_control = self.control_addr()?;
        self.stage_owner.store(true, Ordering::Release);
        Ok(PreparedTargetFec {
            staged: Some(FecGroup {
                config: common_config,
                windows: VecDeque::new(),
                targets,
                next_window: 0,
                last_group_ns: None,
                clock_failed: false,
            }),
            owner: Arc::clone(&self.stage_owner),
            generation: self.stage_generation,
            group,
            epoch,
            origin_ns,
            local_media,
            local_control,
            charge_bytes: actual,
            initial_retained_bytes: self.fec_retained_bytes(),
            allowance_bytes: retained_budget_bytes,
        })
    }

    /// Consume the prepared allocations at a caller-authorized local boundary. The caller
    /// decides timing and activation, and continues reserving the allowance while selected.
    /// All checks precede queue or epoch mutation; failure consumes and drops this token.
    pub fn commit_group_target_fec(
        &mut self,
        mut prepared: PreparedTargetFec,
        retained_budget_bytes: usize,
    ) -> Result<(), CarrierError> {
        if !Arc::ptr_eq(&self.stage_owner, &prepared.owner)
            || !self.stage_owner.load(Ordering::Acquire)
            || prepared.generation != self.stage_generation
            || self.stage_generation == u64::MAX
        {
            return Err(CarrierError::InvalidLimits("stale target preparation"));
        }
        if self.media_addr()? != prepared.local_media
            || self.control_addr()? != prepared.local_control
        {
            return Err(CarrierError::InvalidLimits("stale target preparation"));
        }
        let staged = prepared
            .staged
            .as_ref()
            .ok_or(CarrierError::InvalidLimits("stale target preparation"))?;
        let mut ids = [0_u32; MAX_TARGET_FEC_PEERS];
        for (index, target) in staged.targets.iter().enumerate() {
            ids[index] = target.peer_id;
        }
        let (gi, _) = self.preflight_group_fec(
            prepared.group,
            prepared.epoch,
            prepared.origin_ns,
            &ids[..staged.targets.len()],
        )?;
        if self
            .peers
            .iter()
            .any(|peer| peer.group == prepared.group && peer.fence.is_some())
        {
            return Err(CarrierError::InvalidLimits("target peer is fenced"));
        }
        if self.groups[gi].epoch.checked_add(1) != Some(prepared.epoch)
            || self
                .peers
                .iter()
                .filter(|p| p.group == prepared.group)
                .any(|p| p.sender.epoch() != self.groups[gi].epoch)
        {
            return Err(CarrierError::InvalidLimits("stale target preparation"));
        }
        // Recheck other retained capacity as well as a caller-supplied changed allowance.
        let required = prepared
            .charge_bytes
            .checked_sub(prepared.initial_retained_bytes)
            .and_then(|v| v.checked_add(self.fec_retained_bytes()))
            .ok_or(CarrierError::InvalidLimits("target FEC memory overflow"))?;
        if required > retained_budget_bytes || required > prepared.allowance_bytes {
            return Err(CarrierError::InvalidLimits("target FEC memory cap"));
        }
        self.advance_group_epoch(prepared.group, prepared.epoch)?;
        self.groups[gi].fec = prepared.staged.take();
        Ok(())
    }

    fn preflight_group_fec(
        &self,
        group: GroupId,
        epoch: u64,
        origin_ns: u64,
        validated_peer_ids: &[u32],
    ) -> Result<(usize, crate::fec::SessionConfig), CarrierError> {
        let gi = self.group_index(group)?;
        let member_count = self.peers.iter().filter(|peer| peer.group == group).count();
        if member_count == 0
            || member_count > crate::fec::MAX_GROUP_MEMBERS
            || validated_peer_ids.len() != member_count
            || self
                .peers
                .iter()
                .filter(|peer| peer.group == group)
                .any(|peer| {
                    validated_peer_ids
                        .iter()
                        .filter(|id| **id == peer.id)
                        .count()
                        != 1
                })
            || self
                .peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| peer.group == group)
                .any(|(i, peer)| {
                    self.peers.iter().skip(i + 1).any(|other| {
                        other.group == group && peer.control_addr == other.control_addr
                    })
                })
        {
            return Err(CarrierError::InvalidLimits(
                "FEC requires the exact unique acknowledged members",
            ));
        }
        if epoch <= self.groups[gi].epoch {
            return Err(CarrierError::StaleEpoch {
                submitted: epoch,
                current: self.groups[gi].epoch,
            });
        }
        let config = crate::fec::SessionConfig {
            stream: self.groups[gi].stream_id,
            epoch,
            presentation_origin_ns: origin_ns,
            key: self.groups[gi].key.clone(),
        };
        config
            .metadata(0)
            .map_err(|_| CarrierError::InvalidLimits("invalid FEC timeline"))?;
        let mut needed = 0_u64;
        for p in &self.peers {
            let selected = p.group == group
                || self
                    .groups
                    .iter()
                    .any(|g| g.id == p.group && g.fec.is_some());
            if selected && p.path_mtu < crate::fec::DATAGRAM + p.overhead() {
                return Err(CarrierError::PathMtuTooSmall {
                    path_mtu: p.path_mtu,
                    capacity: p.path_mtu.saturating_sub(p.overhead()),
                    required: crate::fec::DATAGRAM,
                });
            }
            // At most eight original symbols and four aggregate feedback replies per 1024 frames.
            let fec_rate = ((crate::fec::N + crate::fec::K) as u64
                * (crate::fec::DATAGRAM + p.overhead()) as u64
                * 48_000)
                .div_ceil(1024);
            needed = needed.saturating_add(if selected {
                self.limits.peer_load_bytes_per_sec.max(fec_rate)
            } else {
                self.limits.peer_load_bytes_per_sec
            });
        }
        if needed > self.limits.pace_bytes_per_sec {
            return Err(CarrierError::OverBudget {
                peer: 0,
                needed,
                budget: self.limits.pace_bytes_per_sec,
            });
        }
        let max_overhead = self
            .peers
            .iter()
            .filter(|peer| peer.group == group)
            .map(|peer| peer.overhead())
            .max()
            .unwrap_or(0);
        if self.limits.pace_burst_bytes < (crate::fec::DATAGRAM + max_overhead) as u64
            || self.limits.peer_queue_bytes < crate::fec::DATAGRAM
            || self.limits.aggregate_queue_bytes < crate::fec::DATAGRAM
        {
            return Err(CarrierError::InvalidLimits(
                "FEC datagram does not fit carrier bounds",
            ));
        }
        Ok((gi, config))
    }

    /// Queue a complete host FEC window for the registered group, on the
    /// existing per-peer and aggregate media queues and interface pacer.
    pub fn submit_group_fec_window(
        &mut self,
        group: GroupId,
        epoch: u64,
        window: u64,
        source: [[u8; crate::fec::BYTES]; crate::fec::K],
        now_ns: u64,
    ) -> Result<SubmitReport, CarrierError> {
        let gi = self.group_index(group)?;
        let current = self.groups[gi].epoch;
        if epoch != current {
            return Err(CarrierError::StaleEpoch {
                submitted: epoch,
                current,
            });
        }
        let fec = self.groups[gi]
            .fec
            .as_ref()
            .ok_or(CarrierError::InvalidLimits("FEC not selected"))?;
        if fec.clock_failed || window != fec.next_window {
            return Err(CarrierError::InvalidLimits("FEC window unavailable"));
        }
        if !fec.targets.is_empty() {
            return self.submit_target_fec_window(gi, group, window, source, now_ns);
        }
        let config = fec.config.clone();
        let metadata = config
            .metadata(window)
            .map_err(|_| CarrierError::InvalidLimits("invalid FEC window"))?;
        // Source work plus one wire copy per symbol and member. This conservative
        // synthetic interface-wide charge is not a measured CPU or WCET claim.
        let members = self.peers.iter().filter(|p| p.group == group).count();
        let work = u64::try_from(members)
            .ok()
            .and_then(|count| count.checked_mul((crate::fec::N * crate::fec::DATAGRAM) as u64))
            .and_then(|copies| FEC_SOURCE_WORK.checked_add(copies))
            .ok_or(CarrierError::InvalidLimits("common FEC work overflow"))?;
        if !self.reserve_fec_work(now_ns, work) {
            return Err(CarrierError::InvalidLimits("aggregate FEC work exhausted"));
        }
        let deadline = be_u64(&metadata, 52);
        let digest = crate::fec::content_digest(&metadata, &source);
        let retained = crate::fec::SenderWindow::new(config.clone(), window, source, members)
            .map_err(|_| CarrierError::InvalidLimits("invalid FEC sender window"))?;
        let mut wires = Vec::with_capacity(crate::fec::N);
        for esi in 0..crate::fec::N {
            let symbol = crate::fec::encode_symbol(&source, esi)
                .map_err(|_| CarrierError::InvalidLimits("FEC symbol encoding failed"))?;
            let kind = if esi < crate::fec::K { 0 } else { 2 };
            let wire = crate::fec::sign_symbol(&config, window, esi, kind, digest, &symbol)
                .map_err(|_| CarrierError::InvalidLimits("FEC symbol signing failed"))?;
            wires.push(wire);
        }
        let fec = self.groups[gi].fec.as_mut().expect("selection checked");
        if fec.windows.len() == crate::fec::WINDOWS {
            // New sequential source windows replace the oldest bounded slot.
            // A failed submission above must never evict a useful window.
            fec.windows.pop_front();
        }
        fec.windows.push_back((window, retained));
        fec.next_window = window
            .checked_add(1)
            .ok_or(CarrierError::InvalidLimits("FEC window exhausted"))?;
        let mut report = SubmitReport::default();
        for idx in 0..self.peers.len() {
            if self.peers[idx].group != group {
                continue;
            }
            for (esi, wire) in wires.iter().enumerate() {
                let offset = if esi < crate::fec::K {
                    crate::playout::frames_to_ns(esi as u64 * 256)
                } else {
                    // A repair equation can still recover the last live source
                    // after an earlier source has already been committed.
                    crate::playout::frames_to_ns((crate::fec::K as u64 - 1) * 256)
                };
                self.enqueue_fec(
                    idx,
                    wire,
                    now_ns,
                    deadline.saturating_add(offset),
                    &mut report,
                );
            }
        }
        Ok(report)
    }

    fn submit_target_fec_window(
        &mut self,
        gi: usize,
        group: GroupId,
        window: u64,
        source: [[u8; crate::fec::BYTES]; crate::fec::K],
        now_ns: u64,
    ) -> Result<SubmitReport, CarrierError> {
        let next = window
            .checked_add(1)
            .ok_or(CarrierError::InvalidLimits("FEC window exhausted"))?;
        let count = self.groups[gi]
            .fec
            .as_ref()
            .expect("selected")
            .targets
            .len();
        let work = FEC_TARGET_WORK
            .checked_mul(count as u64)
            .ok_or(CarrierError::InvalidLimits("target FEC work overflow"))?;
        if !self.reserve_fec_work(now_ns, work) {
            return Err(CarrierError::InvalidLimits("aggregate FEC work exhausted"));
        }
        // A bounded fixed scratch is admitted at selection. Finish every target's
        // encoding before any queue or retained-window state is modified.
        let mut wires = [[[0_u8; crate::fec::DATAGRAM]; crate::fec::N]; MAX_TARGET_FEC_PEERS];
        let mut windows: [Option<crate::fec::SenderWindow>; MAX_TARGET_FEC_PEERS] = [None, None];
        let mut deadlines = [0_u64; MAX_TARGET_FEC_PEERS];
        {
            let fec = self.groups[gi].fec.as_ref().expect("selected");
            for (i, target) in fec.targets.iter().enumerate() {
                let metadata = target
                    .config
                    .metadata(window)
                    .map_err(|_| CarrierError::InvalidLimits("invalid target FEC window"))?;
                deadlines[i] = be_u64(&metadata, 52);
                let digest = crate::fec::content_digest(&metadata, &source);
                windows[i] = Some(
                    crate::fec::SenderWindow::new(target.config.clone(), window, source, 1)
                        .map_err(|_| CarrierError::InvalidLimits("invalid target FEC window"))?,
                );
                for (esi, wire) in wires[i].iter_mut().enumerate() {
                    let symbol = crate::fec::encode_symbol(&source, esi)
                        .map_err(|_| CarrierError::InvalidLimits("FEC symbol encoding failed"))?;
                    let kind = if esi < crate::fec::K { 0 } else { 2 };
                    *wire =
                        crate::fec::sign_symbol(&target.config, window, esi, kind, digest, &symbol)
                            .map_err(|_| {
                                CarrierError::InvalidLimits("FEC symbol signing failed")
                            })?;
                }
            }
        }
        let mut peer_ids = [0_u32; MAX_TARGET_FEC_PEERS];
        {
            let fec = self.groups[gi].fec.as_mut().expect("selected");
            for (i, target) in fec.targets.iter_mut().enumerate() {
                peer_ids[i] = target.peer_id;
                if target.windows.len() == crate::fec::WINDOWS {
                    target.windows.pop_front();
                }
                target
                    .windows
                    .push_back((window, windows[i].take().expect("built")));
            }
            fec.next_window = next;
        }
        let mut report = SubmitReport::default();
        for ((&peer_id, target_wires), &deadline) in peer_ids[..count]
            .iter()
            .zip(&wires[..count])
            .zip(&deadlines[..count])
        {
            let idx = self
                .peers
                .iter()
                .position(|peer| peer.group == group && peer.id == peer_id)
                .expect("membership cannot change while FEC selected");
            for (esi, wire) in target_wires.iter().enumerate() {
                let block = if esi < crate::fec::K {
                    esi
                } else {
                    crate::fec::K - 1
                };
                self.enqueue_fec(
                    idx,
                    wire,
                    now_ns,
                    deadline.saturating_add(crate::playout::frames_to_ns(block as u64 * 256)),
                    &mut report,
                );
            }
        }
        Ok(report)
    }

    fn enqueue_fec(
        &mut self,
        idx: usize,
        wire: &[u8; crate::fec::DATAGRAM],
        now_ns: u64,
        deadline: u64,
        report: &mut SubmitReport,
    ) {
        let len = wire.len();
        self.peers[idx].counters.media_submitted_packets += 1;
        self.peers[idx].counters.media_submitted_bytes += len as u64;
        if self.peers[idx].fence.is_some() {
            add_drop(&mut self.peers[idx].counters, DropKind::Fenced, len);
            report.skipped_fenced += 1;
            return;
        }
        loop {
            let p = &self.peers[idx];
            if p.queued_packets() < self.limits.peer_queue_packets
                && p.queued_bytes() + len <= self.limits.peer_queue_bytes
            {
                break;
            }
            if p.media_q.is_empty() && p.fec_q.is_empty() {
                add_drop(&mut self.peers[idx].counters, DropKind::Overflow, len);
                return;
            }
            self.peers[idx].drop_oldest(DropKind::Overflow);
            report.evicted += 1;
        }
        loop {
            let (packets, bytes) = self.aggregate_media();
            if packets < self.limits.aggregate_queue_packets
                && bytes + len <= self.limits.aggregate_queue_bytes
            {
                break;
            }
            let Some(victim) = self.largest_media_queue() else {
                add_drop(&mut self.peers[idx].counters, DropKind::Aggregate, len);
                report.rejected_aggregate += 1;
                return;
            };
            self.peers[victim].drop_oldest(DropKind::Aggregate);
            report.evicted += 1;
        }
        let p = &mut self.peers[idx];
        p.fec_q_bytes += len;
        p.fec_q.push_back(FecDatagram {
            wire: wire.to_vec(),
            enqueued_ns: now_ns,
            consume_by_ns: deadline,
            attempts: 0,
        });
        report.queued += 1;
    }

    /// Queue one frame for every peer, under the epoch the caller was authorised for. A stale epoch is refused before
    /// anything is queued. Per peer, the oldest of its own frames make room first; under aggregate pressure the oldest
    /// frames of the longest queue do, so one slow peer cannot take the room of the others.
    pub fn submit_media(
        &mut self,
        epoch: u64,
        frame: &OutboundFrame,
        now_ns: u64,
    ) -> Result<SubmitReport, CarrierError> {
        self.submit_group_media(PRIMARY_GROUP, epoch, frame, now_ns)
    }

    /// [`Self::submit_media`] for one group: the frame is queued for that group's peers only, under that group's epoch. The
    /// caps it meets are the interface's: under aggregate pressure the victim is the longest queue on the interface, in
    /// whatever group, so a slow peer's backlog gives way first and cannot take the room of the rest, in its group or another.
    pub fn submit_group_media(
        &mut self,
        group: GroupId,
        epoch: u64,
        frame: &OutboundFrame,
        now_ns: u64,
    ) -> Result<SubmitReport, CarrierError> {
        let group_index = self.group_index(group)?;
        let current = self.groups[group_index].epoch;
        if self.groups[group_index].fec.is_some() || self.groups[group_index].fec_fenced {
            return Err(CarrierError::InvalidLimits(
                "group uses FEC or needs an epoch transition",
            ));
        }
        if epoch != current {
            self.stats.stale_submits += 1;
            return Err(CarrierError::StaleEpoch {
                submitted: epoch,
                current,
            });
        }
        let len = frame.payload.len();
        if len == 0 || len > MAX_PAYLOAD_BYTES || !len.is_multiple_of(4) {
            return Err(CarrierError::BadPayload { len });
        }
        let wire_len = WIRE_OVERHEAD_BYTES + len;
        let mut report = SubmitReport::default();
        for idx in 0..self.peers.len() {
            if self.peers[idx].group != group {
                continue;
            }
            self.peers[idx].counters.media_submitted_packets += 1;
            self.peers[idx].counters.media_submitted_bytes += wire_len as u64;
            if self.peers[idx].fence.is_some() {
                add_drop(&mut self.peers[idx].counters, DropKind::Fenced, wire_len);
                report.skipped_fenced += 1;
                continue;
            }
            let queued = QueuedFrame {
                frame: frame.clone(),
                wire_len,
                enqueued_ns: now_ns,
            };
            self.enqueue_media(idx, queued, &mut report);
        }
        Ok(report)
    }

    fn enqueue_media(&mut self, idx: usize, queued: QueuedFrame, report: &mut SubmitReport) {
        let wire_len = queued.wire_len;
        loop {
            let peer = &self.peers[idx];
            let fits = peer.queued_packets() < self.limits.peer_queue_packets
                && peer.queued_bytes() + wire_len <= self.limits.peer_queue_bytes;
            if fits {
                break;
            }
            // The held datagram occupies room but is not evictable: with nothing else queued, the newcomer is what is refused.
            if peer.media_q.is_empty() && peer.fec_q.is_empty() {
                add_drop(&mut self.peers[idx].counters, DropKind::Overflow, wire_len);
                return;
            }
            self.peers[idx].drop_oldest(DropKind::Overflow);
            report.evicted += 1;
        }
        loop {
            let (packets, bytes) = self.aggregate_media();
            if packets < self.limits.aggregate_queue_packets
                && bytes + wire_len <= self.limits.aggregate_queue_bytes
            {
                break;
            }
            let Some(victim) = self.largest_media_queue() else {
                add_drop(&mut self.peers[idx].counters, DropKind::Aggregate, wire_len);
                report.rejected_aggregate += 1;
                return;
            };
            self.peers[victim].drop_oldest(DropKind::Aggregate);
            report.evicted += 1;
        }
        let peer = &mut self.peers[idx];
        peer.media_q_bytes += wire_len;
        peer.media_q.push_back(queued);
        report.queued += 1;
    }

    /// Queue an opaque control datagram for one peer (the control channel above authenticates it). It never evicts
    /// media and media never evicts it: a full control queue refuses the new datagram.
    pub fn submit_control(&mut self, id: u32, bytes: &[u8]) -> Result<(), CarrierError> {
        let idx = self.index_of(id)?;
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(CarrierError::ControlTooLarge { len: bytes.len() });
        }
        let cap = self.limits.control_queue_packets;
        let peer = &mut self.peers[idx];
        if peer.control_q.len() >= cap {
            peer.counters.control_rejected_full += 1;
            return Err(CarrierError::ControlQueueFull(id));
        }
        peer.control_q.push_back(bytes.to_vec());
        peer.counters.control_submitted += 1;
        Ok(())
    }

    /// One bounded step: read reports, send control (at most `control_per_pump`), drop frames past their `consume_by`,
    /// then try media for as long as the pacer, the windows and `max_sends_per_pump` (a common bound on every media-lane attempt,
    /// probes and refused sends included) allow.
    pub fn pump(&mut self, now_ns: u64) -> PumpReport {
        self.pump_fec(now_ns, &[], &std::sync::atomic::AtomicBool::new(false))
    }

    /// Pump all groups through the same interface pacer and per-call limits.
    /// FEC groups without exactly one usable group-clock view are not sent.
    pub fn pump_fec(
        &mut self,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> PumpReport {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            let groups: Vec<_> = self
                .groups
                .iter()
                .filter(|g| g.fec.is_some())
                .map(|g| g.id)
                .collect();
            for group in groups {
                self.invalidate_group_fec(group);
            }
        }
        for group in &mut self.groups {
            if let Some(fec) = &mut group.fec {
                let mut matching = clocks.iter().filter(|(id, _)| *id == group.id);
                if let (Some((_, view)), None) = (matching.next(), matching.next())
                    && view.usable
                {
                    if fec.last_group_ns.is_some_and(|last| view.group_ns < last) {
                        fec.clock_failed = true;
                    }
                    fec.last_group_ns = Some(view.group_ns);
                    if !fec.clock_failed {
                        while let Some((window, _)) = fec.windows.front() {
                            let Ok(metadata) = fec.config.metadata(*window) else {
                                break;
                            };
                            let last = be_u64(&metadata, 52)
                                .saturating_add(crate::playout::frames_to_ns(3 * 256));
                            if view.group_ns <= last {
                                break;
                            }
                            fec.windows.pop_front();
                        }
                        for target in &mut fec.targets {
                            while let Some((window, _)) = target.windows.front() {
                                let Ok(metadata) = target.config.metadata(*window) else {
                                    break;
                                };
                                let last = be_u64(&metadata, 52)
                                    .saturating_add(crate::playout::frames_to_ns(3 * 256));
                                if view.group_ns <= last {
                                    break;
                                }
                                target.windows.pop_front();
                            }
                        }
                    }
                }
            }
        }
        let mut out = PumpReport::default();
        self.stats.pumps += 1;
        if !self.link_up {
            self.stats.link_down_pumps += 1;
            out.link_down = true;
            return out;
        }
        out.reports_applied = self.poll_reports_fec(now_ns, clocks, cancelled);
        self.pacer.refill(now_ns);
        self.control_pacer.refill(now_ns);
        out.control_sent = self.pump_control();
        out.late_dropped = self.expire_late(now_ns);
        self.pump_media(now_ns, clocks, cancelled, &mut out);
        let window = self.limits.window_packets;
        for peer in &mut self.peers {
            if !peer.media_q.is_empty() && peer.fence.is_none() && peer.stalled(window) {
                peer.counters.window_stalled_pumps += 1;
                out.window_stalled_peers += 1;
            }
        }
        out
    }

    /// Read the receiver reports that have arrived (at most `max_reads_per_pump` datagrams) and apply the authentic,
    /// current ones. A pump does this first; a caller that wants to see a report's effect before the next pump may too.
    /// Returns how many reports moved a peer's position.
    pub fn poll_reports(&mut self) -> u32 {
        self.poll_reports_fec(0, &[], &std::sync::atomic::AtomicBool::new(false))
    }

    fn poll_reports_fec(
        &mut self,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> u32 {
        let mut applied = 0;
        let mut budget = self.limits.max_reads_per_pump;
        for idx in 0..self.peers.len() {
            if budget == 0 {
                break;
            }
            let group = self.peers[idx].group;
            if self.peers[idx].pending_fec_feedback.is_some() && self.fec_has_clock(group, clocks) {
                let wire = self.peers[idx].pending_fec_feedback.expect("checked");
                if !self.feedback_relevant(idx, &wire) {
                    self.peers[idx].pending_fec_feedback = None;
                    self.peers[idx].counters.fec_feedback_refused += 1;
                    self.stats.fec_feedback_refused += 1;
                    continue;
                }
                let requested = u64::from((wire[64] & 15).count_ones());
                let work =
                    crate::fec::AUTH_WORK + requested * (crate::fec::AUTH_WORK + 1024 + 1000);
                if !self.fec_work_available(now_ns, work) {
                    continue;
                }
                let wire = self.peers[idx]
                    .pending_fec_feedback
                    .take()
                    .expect("checked");
                let addr = self.peers[idx].control_addr;
                budget -= 1;
                if self.on_fec_feedback(&wire, Some(addr), now_ns, clocks, cancelled) {
                    applied += 1;
                }
            }
        }
        let mut buf = [0u8; 128];
        for _ in 0..budget {
            // With no budget even to authenticate an FEC message, leave the
            // next control datagram in the bounded port instead of consuming
            // a one-shot request that cannot yet be checked.
            if self.groups.iter().any(|g| g.fec.is_some())
                && !self.fec_work_available(now_ns, crate::fec::AUTH_WORK)
            {
                break;
            }
            match self.port.recv(Lane::Control, &mut buf) {
                Ok(got) => {
                    let len = got.len.min(buf.len());
                    if &buf[..len.min(4)] == b"FFWA" {
                        self.stats.control_datagrams_in += 1;
                        let peer = self.feedback_source(&buf[..len], got.from);
                        if let Some(idx) = peer
                            && (!self.fec_has_clock(self.peers[idx].group, clocks)
                                || !self.fec_work_available(
                                    now_ns,
                                    crate::fec::AUTH_WORK
                                        + u64::from((buf[64] & 15).count_ones())
                                            * (crate::fec::AUTH_WORK + 1024 + 1000),
                                ))
                        {
                            if self.peers[idx]
                                .pending_fec_feedback
                                .is_some_and(|wire| !self.feedback_relevant(idx, &wire))
                            {
                                self.peers[idx].pending_fec_feedback = None;
                                self.stats.fec_feedback_refused += 1;
                                self.peers[idx].counters.fec_feedback_refused += 1;
                            }
                            if !self.feedback_relevant(idx, &buf[..len]) {
                                self.peers[idx].counters.fec_feedback_refused += 1;
                                self.stats.fec_feedback_refused += 1;
                            } else if self.peers[idx].pending_fec_feedback.is_some() {
                                self.peers[idx].counters.fec_feedback_overflow += 1;
                                self.stats.fec_feedback_overflow += 1;
                                self.stats.fec_feedback_refused += 1;
                            } else if self.reserve_fec_work(now_ns, crate::fec::AUTH_WORK)
                                && self
                                    .groups
                                    .iter()
                                    .find(|g| g.id == self.peers[idx].group)
                                    .and_then(|g| g.fec.as_ref())
                                    .is_some_and(|fec| {
                                        fec.config_for_peer(self.peers[idx].id).is_some_and(
                                            |config| {
                                                crate::fec::verify_feedback(config, &buf[..len])
                                            },
                                        )
                                    })
                            {
                                let mut wire = [0; crate::fec::FEEDBACK_BYTES];
                                wire.copy_from_slice(&buf[..len]);
                                self.peers[idx].pending_fec_feedback = Some(wire);
                                self.peers[idx].counters.fec_feedback_deferred += 1;
                                self.stats.fec_feedback_deferred += 1;
                            } else {
                                self.peers[idx].counters.fec_feedback_refused += 1;
                                self.stats.fec_feedback_refused += 1;
                            }
                        } else if self.on_fec_feedback(
                            &buf[..len],
                            got.from,
                            now_ns,
                            clocks,
                            cancelled,
                        ) {
                            applied += 1;
                        }
                    } else if self.on_control_datagram(&buf[..len], got.from) {
                        applied += 1;
                    }
                }
                Err(PortFault::WouldBlock) => break,
                Err(PortFault::Discarded) => {
                    self.faults.recv_discarded = self.faults.recv_discarded.saturating_add(1);
                }
                Err(fault) => {
                    self.stats.recv_errors += 1;
                    self.faults.on_recv(&fault);
                    break;
                }
            }
        }
        applied
    }

    fn fec_has_clock(
        &self,
        group: GroupId,
        clocks: &[(GroupId, crate::playout::ClockView)],
    ) -> bool {
        let usable_group = self
            .groups
            .iter()
            .find(|g| g.id == group)
            .and_then(|g| g.fec.as_ref())
            .is_some_and(|fec| !fec.clock_failed);
        let mut views = clocks.iter().filter(|(id, _)| *id == group);
        usable_group
            && matches!((views.next(), views.next()), (Some((_, view)), None) if view.usable)
    }

    fn feedback_relevant(&self, peer: usize, wire: &[u8]) -> bool {
        if wire.len() != crate::fec::FEEDBACK_BYTES {
            return false;
        }
        let Some(peer) = self.peers.get(peer) else {
            return false;
        };
        let window = be_u64(wire, 28);
        self.groups
            .iter()
            .find(|g| g.id == peer.group)
            .and_then(|g| g.fec.as_ref())
            .and_then(|fec| fec.windows_for_peer(peer.id))
            .and_then(|windows| windows.iter().find(|(id, _)| *id == window))
            .is_some_and(|(_, retained)| retained.has_unserved(wire[64]))
    }

    fn feedback_source(&self, wire: &[u8], from: Option<SocketAddr>) -> Option<usize> {
        if wire.len() != crate::fec::FEEDBACK_BYTES {
            return None;
        }
        let addr = from?;
        let stream = be_u64(wire, 12);
        let epoch = be_u64(wire, 20);
        self.peers.iter().position(|peer| {
            peer.control_addr == addr
                && self
                    .groups
                    .iter()
                    .find(|group| group.id == peer.group && group.epoch == epoch)
                    .and_then(|group| group.fec.as_ref())
                    .and_then(|fec| fec.config_for_peer(peer.id))
                    .is_some_and(|config| config.stream.get() == stream && config.epoch == epoch)
        })
    }

    fn on_fec_feedback(
        &mut self,
        wire: &[u8],
        from: Option<SocketAddr>,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> bool {
        let accepted = self.process_fec_feedback(wire, from, now_ns, clocks, cancelled);
        if accepted {
            self.stats.fec_feedback_accepted += 1;
        } else {
            self.stats.fec_feedback_refused += 1;
        }
        accepted
    }

    fn process_fec_feedback(
        &mut self,
        wire: &[u8],
        from: Option<SocketAddr>,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> bool {
        if wire.len() != crate::fec::FEEDBACK_BYTES {
            return false;
        }
        let window = be_u64(wire, 28);
        let Some(peer) = self.feedback_source(wire, from) else {
            return false;
        };
        let group = self.peers[peer].group;
        let Some(gi) = self
            .groups
            .iter()
            .position(|state| state.id == group && state.fec.is_some())
        else {
            return false;
        };
        // Charge an upper bound before authentication, including every requested
        // symbol, so forged requests cannot obtain free cryptographic work.
        let requested = u64::from((wire[64] & 15).count_ones());
        let work = crate::fec::AUTH_WORK + requested * (crate::fec::AUTH_WORK + 1024 + 1000);
        if !self.reserve_fec_work(now_ns, work) {
            self.peers[peer].counters.fec_feedback_refused += 1;
            return false;
        }
        let mut views = clocks.iter().filter(|(id, _)| *id == group);
        let view = match (views.next(), views.next()) {
            (Some((_, view)), None) if view.usable => crate::fec::profile_view(*view),
            _ => {
                self.peers[peer].counters.fec_feedback_refused += 1;
                return false;
            }
        };
        let peer_id = self.peers[peer].id;
        let fec = self.groups[gi].fec.as_mut().expect("selected");
        if fec.clock_failed {
            self.peers[peer].counters.fec_feedback_refused += 1;
            return false;
        }
        let targeted = !fec.targets.is_empty();
        let (config, windows) = if targeted {
            let Some(target) = fec
                .targets
                .iter_mut()
                .find(|target| target.peer_id == peer_id)
            else {
                return false;
            };
            (&target.config, &mut target.windows)
        } else {
            (&fec.config, &mut fec.windows)
        };
        let Some((_, retained)) = windows.iter_mut().find(|(id, _)| *id == window) else {
            self.peers[peer].counters.fec_feedback_refused += 1;
            return false;
        };
        let replies = match retained.serve(view, wire, cancelled) {
            Ok(replies) => replies,
            Err(_) => {
                self.peers[peer].counters.fec_feedback_refused += 1;
                return false;
            }
        };
        let metadata = match config.metadata(window) {
            Ok(meta) => meta,
            Err(_) => return false,
        };
        let first_deadline = be_u64(&metadata, 52);
        self.peers[peer].counters.fec_feedback_accepted += 1;
        let mut report = SubmitReport::default();
        for idx in 0..self.peers.len() {
            if self.peers[idx].group != group || (targeted && idx != peer) {
                continue;
            }
            for (esi, packet) in replies.packets.iter().enumerate() {
                if let Some(packet) = packet {
                    let deadline = first_deadline
                        .saturating_add(crate::playout::frames_to_ns(esi as u64 * 256))
                        .saturating_sub(crate::fec::TAIL_TRANSIT_RESERVE_NS);
                    self.enqueue_fec(idx, packet, now_ns, deadline, &mut report);
                }
            }
        }
        true
    }

    fn send_fec_datagram(
        &mut self,
        idx: usize,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        out: &mut PumpReport,
    ) {
        let Some(mut packet) = self.peers[idx].fec_q.pop_front() else {
            return;
        };
        let len = packet.wire.len();
        self.peers[idx].fec_q_bytes -= len;
        let Some((_, view)) = clocks.iter().find(|(id, _)| *id == self.peers[idx].group) else {
            return;
        };
        let deadline = packet
            .consume_by_ns
            .saturating_sub(view.uncertainty_ns.saturating_sub(500_000));
        if view.group_ns >= deadline {
            add_drop(&mut self.peers[idx].counters, DropKind::Late, len);
            out.late_dropped += 1;
            return;
        }
        let result = self
            .port
            .send_to(Lane::Media, &packet.wire, self.peers[idx].media_addr);
        let peer = &mut self.peers[idx];
        match result {
            Ok(()) => {
                peer.send_hold_until_ns = None;
                peer.counters.media_sent_packets += 1;
                peer.counters.media_sent_bytes += len as u64;
                peer.counters.fec_sent_packets += 1;
                let delay = now_ns.saturating_sub(packet.enqueued_ns);
                peer.counters.queue_delay_ns_total += delay;
                peer.counters.queue_delay_ns_max = peer.counters.queue_delay_ns_max.max(delay);
                out.media_sent += 1;
            }
            Err(fault) => {
                self.faults.on_send(&fault);
                packet.attempts += 1;
                if fault == PortFault::MessageTooLong {
                    add_drop(&mut peer.counters, DropKind::SendError, len);
                    if peer.fence.is_none() {
                        peer.fence = Some(FenceReason::PathMtuTooSmall);
                        peer.purge_media(DropKind::Fenced);
                        self.stats.mtu_fences += 1;
                    }
                } else if packet.attempts >= SEND_RETRY_ATTEMPTS {
                    add_drop(&mut peer.counters, DropKind::SendError, len);
                    peer.send_hold_until_ns = Some(now_ns.saturating_add(STALL_PROBE_NS));
                } else {
                    peer.fec_q_bytes += len;
                    peer.fec_q.push_front(packet);
                    peer.send_hold_until_ns = Some(now_ns.saturating_add(1));
                }
            }
        }
    }

    /// The peer a report belongs to. A report that names a peer is attributed by that number, and, when the port can say
    /// where the datagram came from, only if it came from that peer's registered control address. A report that names
    /// no peer (0) needs the source address, so a port that cannot give one cannot attribute it: refused, never guessed.
    fn attribute(&self, group: GroupId, peer: u32, from: Option<SocketAddr>) -> Option<usize> {
        let member = |p: &PeerState| p.group == group;
        match (peer, from) {
            (0, Some(addr)) => self
                .peers
                .iter()
                .position(|p| member(p) && p.control_addr == addr),
            (0, None) => None,
            (id, Some(addr)) => self
                .peers
                .iter()
                .position(|p| member(p) && p.id == id && p.control_addr == addr),
            (id, None) => self.peers.iter().position(|p| member(p) && p.id == id),
        }
    }

    /// The group a report belongs to: the one whose stream identity it names. The identity is read before the tag is checked,
    /// and only to choose which key checks the tag, so a forged one gets a bad tag and moves nothing. A report that names no
    /// group here is checked against the primary group's key, as a report always was: it is then refused as a wrong stream if
    /// authentic, or as a bad tag if not.
    fn report_group(&self, datagram: &[u8]) -> usize {
        if datagram.len() != REPORT_LEN_BYTES {
            return 0;
        }
        let named = be_u64(datagram, 8);
        self.groups
            .iter()
            .position(|g| g.stream_id.get() == named)
            .unwrap_or(0)
    }

    fn on_control_datagram(&mut self, datagram: &[u8], from: Option<SocketAddr>) -> bool {
        self.stats.control_datagrams_in += 1;
        let gi = self.report_group(datagram);
        let report = match parse_report(&self.groups[gi].key, datagram) {
            Ok(report) => report,
            Err(ReportError::Malformed) => {
                self.stats.reports_malformed += 1;
                return false;
            }
            Err(ReportError::BadTag) => {
                self.stats.reports_bad_tag += 1;
                return false;
            }
        };
        if report.stream_id != self.groups[gi].stream_id.get() {
            self.stats.reports_wrong_stream += 1;
            return false;
        }
        if report.epoch != self.groups[gi].epoch {
            self.stats.reports_stale_epoch += 1;
            return false;
        }
        let group = self.groups[gi].id;
        let Some(idx) = self.attribute(group, report.peer, from) else {
            self.stats.reports_unknown_source += 1;
            return false;
        };
        let peer = &mut self.peers[idx];
        if report.consumed_next > peer.sent_next {
            self.stats.reports_invalid += 1;
            return false;
        }
        peer.reported_next = peer.reported_next.max(report.consumed_next);
        peer.on_reported(self.limits.window_packets);
        peer.counters.reports_accepted += 1;
        true
    }

    /// Send queued control, oldest first, round robin over the peers: at most `control_per_pump` datagrams, and only what
    /// both budgets afford. A control datagram is charged its length plus the IP and UDP headers to the interface bucket (so
    /// control counts against the aggregate cap, however often the caller pumps) and to control's own share of it (so control
    /// cannot take the whole interface from media). What is not affordable stays queued, bounded by its own queue.
    fn pump_control(&mut self) -> u32 {
        let n = self.peers.len();
        if n == 0 {
            return 0;
        }
        let mut budget = self.limits.control_per_pump;
        let mut sent = 0u32;
        let mut progressed = true;
        let mut deferred = false;
        while budget > 0 && progressed {
            progressed = false;
            for step in 0..n {
                if budget == 0 {
                    break;
                }
                let idx = (self.control_cursor + step) % n;
                let Some(len) = self.peers[idx].control_q.front().map(Vec::len) else {
                    continue;
                };
                let cost = (len + self.peers[idx].overhead()) as u64;
                if !self.control_pacer.can_afford(cost) || !self.pacer.can_afford(cost) {
                    deferred = true;
                    continue;
                }
                let Some(message) = self.peers[idx].control_q.pop_front() else {
                    continue;
                };
                // The attempt uses the budget whether or not the port takes the datagram.
                self.control_pacer.spend(cost);
                self.pacer.spend(cost);
                self.control_stats.spent_bytes += cost;
                let addr = self.peers[idx].control_addr;
                match self.port.send_to(Lane::Control, &message, addr) {
                    Ok(()) => {
                        self.peers[idx].counters.control_sent += 1;
                        sent += 1;
                    }
                    Err(fault) => {
                        self.faults.on_send(&fault);
                        self.peers[idx].counters.control_dropped_send_error += 1;
                    }
                }
                budget -= 1;
                progressed = true;
            }
        }
        if deferred {
            self.control_stats.pace_limited_pumps += 1;
        }
        self.control_cursor = (self.control_cursor + 1) % n;
        sent
    }

    /// Drop every queued frame whose own `consume_by` has passed: sent late it could only be heard late.
    fn expire_late(&mut self, now_ns: u64) -> u32 {
        let mut dropped = 0u32;
        for peer in &mut self.peers {
            let before = peer.media_q.len();
            let mut late_bytes = Vec::new();
            peer.media_q.retain(|q| {
                let late = now_ns > q.frame.consume_by_ns;
                if late {
                    late_bytes.push(q.wire_len);
                }
                !late
            });
            debug_assert_eq!(before - peer.media_q.len(), late_bytes.len());
            for wire_len in late_bytes {
                peer.media_q_bytes -= wire_len;
                add_drop(&mut peer.counters, DropKind::Late, wire_len);
                dropped += 1;
            }
            if peer
                .held
                .as_ref()
                .is_some_and(|held| now_ns > held.consume_by_ns && !peer.must_keep(held))
                && let Some(held) = peer.held.take()
            {
                add_drop(&mut peer.counters, DropKind::Late, held.wire_len);
                dropped += 1;
            }
        }
        dropped
    }

    /// The next peer, round robin from the cursor, that is not fenced, is not holding off and has something to send, with the
    /// cost in link bytes. A peer that is waiting (a full window, or a spent sequence budget) is offered only for a probe
    /// that is due: its newest transmitted datagram, again. Otherwise a held datagram goes first, else the queue's head.
    fn next_sendable(
        &self,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Option<(usize, usize, bool)> {
        let n = self.peers.len();
        let window = self.limits.window_packets;
        for step in 0..n {
            let idx = (self.media_cursor + step) % n;
            let peer = &self.peers[idx];
            if peer.fence.is_some() || peer.send_hold_until_ns.is_some_and(|until| now_ns < until) {
                continue;
            }
            let mut views = clocks.iter().filter(|(id, _)| *id == peer.group);
            let view = match (views.next(), views.next()) {
                (Some((_, view)), None) if view.usable => Some(*view),
                _ => None,
            };
            let fec_ok = self
                .groups
                .iter()
                .find(|g| g.id == peer.group)
                .and_then(|g| g.fec.as_ref())
                .is_some_and(|f| !f.clock_failed)
                && !cancelled.load(std::sync::atomic::Ordering::Acquire)
                && view.is_some();
            if fec_ok && let Some(head) = peer.fec_q.front() {
                return Some((idx, head.wire.len() + peer.overhead(), true));
            }
            if peer.waiting(window) {
                if peer.probe_due(window, now_ns)
                    && let Some(last) = &peer.last_sent
                {
                    return Some((idx, last.wire_len + peer.overhead(), false));
                }
                continue;
            }
            let wire_len = match (&peer.held, peer.media_q.front()) {
                (Some(held), _) => held.wire_len,
                (None, Some(head)) => head.wire_len,
                (None, None) => continue,
            };
            return Some((idx, wire_len + peer.overhead(), false));
        }
        None
    }

    /// Send peer `idx` its newest transmitted datagram again, as a probe. It is the same bytes under the same number, so no
    /// number is allocated and nothing new is signed; it is charged to the interface bucket and counted apart from media. If
    /// the receiver is there and admits it (a number within N01's forward gap, by the [`SEQ_AHEAD_LIMIT`] rule), its report
    /// moves `reported_next` and the window and the budget reopen; if it already had it, N01 refuses the copy as a replay.
    fn send_probe(&mut self, idx: usize, now_ns: u64) {
        let addr = self.peers[idx].media_addr;
        let Some(last) = &self.peers[idx].last_sent else {
            return;
        };
        let (wire_len, overhead) = (last.wire_len, self.peers[idx].overhead());
        let result = self.port.send_to(Lane::Media, &last.wire, addr);
        let peer = &mut self.peers[idx];
        peer.probe_due_ns = Some(now_ns.saturating_add(STALL_PROBE_NS));
        match result {
            Ok(()) => {
                self.control_stats.probes_sent += 1;
                self.control_stats.probe_bytes += (wire_len + overhead) as u64;
            }
            Err(fault) => {
                self.faults.on_send(&fault);
                if fault == PortFault::MessageTooLong && peer.fence.is_none() {
                    peer.fence = Some(FenceReason::PathMtuTooSmall);
                    peer.purge_media(DropKind::Fenced);
                    self.stats.mtu_fences += 1;
                }
            }
        }
    }

    fn pump_media(
        &mut self,
        now_ns: u64,
        clocks: &[(GroupId, crate::playout::ClockView)],
        cancelled: &std::sync::atomic::AtomicBool,
        out: &mut PumpReport,
    ) {
        let n = self.peers.len();
        if n == 0 {
            return;
        }
        let window = self.limits.window_packets;
        // Every attempt on the media lane costs work, whatever came of it: an ordinary send, a send the transport refused, a
        // probe. They share the one per-pump bound; `media_sent` counts only the datagrams that left.
        let mut attempts = 0_usize;
        loop {
            if attempts >= self.limits.max_sends_per_pump {
                out.send_cap_hit = true;
                self.stats.send_cap_pumps += 1;
                break;
            }
            let Some((idx, cost, fec)) = self.next_sendable(now_ns, clocks, cancelled) else {
                break;
            };
            let cost = cost as u64;
            if !self.pacer.can_afford(cost) {
                out.pace_limited = true;
                out.next_send_ns = Some(now_ns.saturating_add(self.pacer.wait_ns(cost)));
                self.stats.pace_limited_pumps += 1;
                break;
            }
            self.pacer.spend(cost);
            self.media_cursor = (idx + 1) % n;
            if fec {
                attempts += 1;
                self.send_fec_datagram(idx, now_ns, clocks, out);
                continue;
            }
            if self.peers[idx].waiting(window) {
                attempts += 1;
                self.send_probe(idx, now_ns);
                continue;
            }
            // A held datagram goes first, with the bytes and the number it was signed with; otherwise the head of the queue
            // is signed now, which allocates its number for good.
            let mut datagram = match self.peers[idx].held.take() {
                Some(held) => held,
                None => {
                    let Some(queued) = self.peers[idx].media_q.pop_front() else {
                        break;
                    };
                    self.peers[idx].media_q_bytes -= queued.wire_len;
                    let (wire_len, enqueued_ns, consume_by_ns) = (
                        queued.wire_len,
                        queued.enqueued_ns,
                        queued.frame.consume_by_ns,
                    );
                    let seq = self.peers[idx].sender.next_seq();
                    match self.peers[idx].sender.send(queued.frame) {
                        Ok(wire) => {
                            self.peers[idx].sent_next = self.peers[idx].sender.next_seq();
                            HeldDatagram {
                                wire,
                                seq,
                                wire_len,
                                enqueued_ns,
                                consume_by_ns,
                                attempts: 0,
                            }
                        }
                        Err(_) => {
                            add_drop(&mut self.peers[idx].counters, DropKind::SendError, wire_len);
                            continue;
                        }
                    }
                }
            };
            // A datagram that aged while it waited is not sent late, unless it holds the last number the receiver is
            // certain to admit: that one goes however stale, because the receiver's answer to it is what reopens the budget.
            if now_ns > datagram.consume_by_ns && !self.peers[idx].must_keep(&datagram) {
                add_drop(
                    &mut self.peers[idx].counters,
                    DropKind::Late,
                    datagram.wire_len,
                );
                continue;
            }
            let addr = self.peers[idx].media_addr;
            attempts += 1;
            let result = self.port.send_to(Lane::Media, &datagram.wire, addr);
            match result {
                Ok(()) => {
                    let peer = &mut self.peers[idx];
                    peer.in_flight.push_back(datagram.seq);
                    peer.send_hold_until_ns = None;
                    let delay = now_ns.saturating_sub(datagram.enqueued_ns);
                    let counters = &mut peer.counters;
                    counters.media_sent_packets += 1;
                    counters.media_sent_bytes += datagram.wire_len as u64;
                    counters.queue_delay_ns_total += delay;
                    counters.queue_delay_ns_max = counters.queue_delay_ns_max.max(delay);
                    out.media_sent += 1;
                    peer.last_sent = Some(SentDatagram {
                        wire: datagram.wire,
                        wire_len: datagram.wire_len,
                    });
                    // A peer that has just used the last of its window or its budget is waited on from now.
                    peer.probe_due_ns = peer
                        .waiting(window)
                        .then(|| now_ns.saturating_add(STALL_PROBE_NS));
                }
                Err(fault) => {
                    self.faults.on_send(&fault);
                    datagram.attempts += 1;
                    let wire_len = datagram.wire_len;
                    let peer = &mut self.peers[idx];
                    if fault == PortFault::MessageTooLong {
                        // The kernel says a block does not fit this peer's path. Nothing is fragmented and nothing is
                        // retried: the path is fenced like a measured MTU drop until `set_path_mtu` says it carries again.
                        // The datagram that holds the last number is the one exception: it is kept, whole, for the day the
                        // path carries it, because dropping it would leave no number the receiver is certain to admit.
                        if peer.must_keep(&datagram) {
                            datagram.attempts = 0;
                            peer.held = Some(datagram);
                        } else {
                            add_drop(&mut peer.counters, DropKind::SendError, wire_len);
                        }
                        if peer.fence.is_none() {
                            peer.fence = Some(FenceReason::PathMtuTooSmall);
                            peer.purge_media(DropKind::Fenced);
                            self.stats.mtu_fences += 1;
                        }
                    } else if datagram.attempts >= SEND_RETRY_ATTEMPTS && !peer.must_keep(&datagram)
                    {
                        // Given up on: one number is spent, and the peer is left alone for a full interval. The sequence
                        // budget bounds how many can be spent (SEQ_AHEAD_LIMIT), and the last one is never given up on.
                        add_drop(&mut peer.counters, DropKind::SendError, wire_len);
                        peer.send_hold_until_ns = Some(now_ns.saturating_add(STALL_PROBE_NS));
                    } else {
                        // Another attempt, with the same bytes. Nothing behind it is signed meanwhile. The datagram that
                        // holds the last number is tried once per interval for as long as it takes.
                        let wait = if datagram.attempts >= SEND_RETRY_ATTEMPTS {
                            datagram.attempts = 0;
                            STALL_PROBE_NS
                        } else {
                            1
                        };
                        peer.send_hold_until_ns = Some(now_ns.saturating_add(wait));
                        peer.held = Some(datagram);
                    }
                }
            }
        }
    }
}

fn check_address(limits: &CarrierLimits, addr: SocketAddr) -> Result<(), CarrierError> {
    if addr.is_ipv6() && !limits.allow_ipv6 {
        return Err(CarrierError::UnsupportedAddressFamily(addr));
    }
    if limits.loopback_only && !addr.ip().is_loopback() {
        return Err(CarrierError::NotLoopback(addr));
    }
    Ok(())
}

/// Bounds of the receiving side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverLimits {
    /// Authenticated packets held for the consumer; the next one over this is dropped and counted.
    pub inbound_packets: usize,
    pub control_inbox_packets: usize,
    /// Datagrams read from each socket per [`CarrierReceiver::poll`]: the cap on unauthenticated work per call.
    pub max_reads_per_poll: usize,
}

impl ReceiverLimits {
    #[must_use]
    pub const fn baseline() -> Self {
        Self {
            inbound_packets: 32,
            control_inbox_packets: 8,
            max_reads_per_poll: 64,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReceiverStats {
    pub media_read: u64,
    pub media_accepted: u64,
    pub media_rejected: u64,
    pub inbound_overflow: u64,
    pub control_read: u64,
    pub control_delivered: u64,
    pub control_dropped_full: u64,
    pub control_oversize: u64,
    pub control_wrong_source: u64,
    pub reports_sent: u64,
    pub io_errors: u64,
}

/// What one [`CarrierReceiver::poll`] read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PollReport {
    pub media_read: u32,
    pub media_accepted: u32,
    pub control_read: u32,
}

/// What a consumer that does its own admission says about one raw media datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkVerdict {
    /// The datagram was authentic and consumed (whatever the consumer then did with the block, late or not, it is
    /// consumed from the sender's point of view). `seq` is its N01 sequence number.
    Admitted { seq: u64 },
    /// Not admitted (structure, authentication, stream, epoch, replay, not media): dropped, no credit.
    Refused,
    /// The consumer cannot take it now and has not consumed it from its replay window (its platform clock failed):
    /// dropped, no credit.
    Backpressure,
}

/// A consumer of raw media datagrams that authenticates them itself. See [`CarrierReceiver::poll_into`].
pub trait MediaSink {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict;

    /// Whether the sink can take a datagram now. [`CarrierReceiver::poll_into`] asks before each media read, inside the
    /// `max_reads_per_poll` loop (the per-poll work cap is unchanged), and when this is `false` it stops reading media for this
    /// poll, before any `recv`: nothing is read, counted or dropped by a `false` answer, so `media_read`, the sink verdict
    /// counters and the judge's identities keep their meaning. A sink that cannot say answers `true` (the default).
    ///
    /// The datagrams that wait are held by the port's socket receive buffer, which the kernel bounds and overflows by dropping.
    /// That is a limit, not a promise to retain and retry forever: a datagram that waits earns no credit until it is read, so
    /// the sender's window stalls and its probes (copies of its newest datagram) arrive later, as replays or as late.
    fn ready(&mut self) -> bool {
        true
    }

    /// The largest datagram, in bytes, this sink can be offered (the default is N01's [`MAX_DATAGRAM_BYTES`]). The carrier reads
    /// into a buffer one byte larger, so a longer datagram arrives as oversize and is the sink's structure check to refuse; a
    /// sink whose wire is longer than N01's (the selected N06 hybrid is 1152 bytes) must say so, or every one of its datagrams
    /// would be cut and refused. Values outside `MAX_DATAGRAM_BYTES..=MAX_SINK_DATAGRAM_BYTES` are clamped into it.
    fn max_datagram_bytes(&self) -> usize {
        MAX_DATAGRAM_BYTES
    }
}

/// The largest datagram any [`MediaSink`] may declare through [`MediaSink::max_datagram_bytes`]: the selected N06 hybrid's wire.
pub const MAX_SINK_DATAGRAM_BYTES: usize = crate::fec::DATAGRAM;
const _: () = assert!(MAX_SINK_DATAGRAM_BYTES >= MAX_DATAGRAM_BYTES);

/// What the sink did with the datagrams [`CarrierReceiver::poll_into`] offered it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SinkCounters {
    pub admitted: u64,
    pub refused: u64,
    pub backpressure: u64,
}

/// The receiving half: reads both sockets, admits media through the N01 receiver, holds a bounded number of packets
/// for the consumer, and reports consumption back to the sender.
pub struct CarrierReceiver<P: DatagramPort = HostUdp> {
    limits: ReceiverLimits,
    key: StreamKey,
    stream_id: StreamId,
    port: P,
    sender_control: SocketAddr,
    receiver: StreamReceiver,
    inbound: VecDeque<AuthenticatedStreamPacket>,
    control_inbox: VecDeque<Vec<u8>>,
    consumed_next: u64,
    stats: ReceiverStats,
    /// The id this receiver's reports name (0 = none; the sender then needs the source address).
    peer: u32,
    faults: PortFaults,
    sink: SinkCounters,
}

impl CarrierReceiver<HostUdp> {
    /// Bind both sockets on `ip` over host `std` sockets.
    pub fn bind(
        key: StreamKey,
        stream_id: StreamId,
        epoch: u64,
        limits: ReceiverLimits,
        ip: IpAddr,
        sender_control: SocketAddr,
    ) -> Result<Self, CarrierError> {
        Self::with_port(
            key,
            stream_id,
            epoch,
            limits,
            HostUdp::bind(ip)?,
            sender_control,
        )
    }
}

impl<P: DatagramPort> CarrierReceiver<P> {
    /// A receiver over any port.
    pub fn with_port(
        key: StreamKey,
        stream_id: StreamId,
        epoch: u64,
        limits: ReceiverLimits,
        port: P,
        sender_control: SocketAddr,
    ) -> Result<Self, CarrierError> {
        if limits.inbound_packets == 0
            || limits.control_inbox_packets == 0
            || limits.max_reads_per_poll == 0
        {
            return Err(CarrierError::InvalidLimits("receiver limit is zero"));
        }
        Ok(Self {
            receiver: StreamReceiver::new(key.clone(), stream_id, epoch),
            limits,
            key,
            stream_id,
            port,
            sender_control,
            inbound: VecDeque::new(),
            control_inbox: VecDeque::new(),
            consumed_next: 0,
            stats: ReceiverStats::default(),
            peer: 0,
            faults: PortFaults::default(),
            sink: SinkCounters::default(),
        })
    }

    /// Name the peer id this receiver was admitted under, so that its reports are attributable without a source
    /// address (the P02 `recv` seam returns none).
    ///
    /// # Errors
    /// [`CarrierError::PeerIdTooLarge`] for an id that does not fit three bytes.
    pub fn with_peer_id(mut self, peer: u32) -> Result<Self, CarrierError> {
        if peer > MAX_ATTRIBUTABLE_PEER_ID {
            return Err(CarrierError::PeerIdTooLarge(peer));
        }
        self.peer = peer;
        Ok(self)
    }

    /// The sender announced a new control address (it rebound after an address change). The announcement arrives
    /// over the authenticated control channel; this call is the carrier's half of it.
    pub fn set_sender_control(&mut self, sender_control: SocketAddr) {
        self.sender_control = sender_control;
    }

    pub fn media_addr(&self) -> Result<SocketAddr, CarrierError> {
        port_addr(&self.port, Lane::Media)
    }

    pub fn control_addr(&self) -> Result<SocketAddr, CarrierError> {
        port_addr(&self.port, Lane::Control)
    }

    /// Port-level faults and rebinds, apart from the model's counters.
    #[must_use]
    pub const fn faults(&self) -> &PortFaults {
        &self.faults
    }

    /// The port, for a harness that reads what it saw.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// This receiver's own address changed: replace both sockets, all or nothing, and return the new
    /// `(media, control)` addresses, which the caller announces to the sender over the control channel. The replay
    /// window, the inbound queue and the consumed position are kept: the stream did not change, only the path.
    ///
    /// # Errors
    /// The port could not rebind (nothing changed).
    pub fn rebind(&mut self, ip: IpAddr) -> Result<(SocketAddr, SocketAddr), CarrierError> {
        if let Err(fault) = self.port.rebind(ip) {
            self.faults.rebind_failures = self.faults.rebind_failures.saturating_add(1);
            return Err(CarrierError::Io(fault_text(&fault)));
        }
        self.faults.rebinds = self.faults.rebinds.saturating_add(1);
        Ok((
            port_addr(&self.port, Lane::Media)?,
            port_addr(&self.port, Lane::Control)?,
        ))
    }

    #[must_use]
    pub const fn stats(&self) -> &ReceiverStats {
        &self.stats
    }

    /// The N01 receiver's own counters: every datagram it was handed is in exactly one bucket.
    #[must_use]
    pub const fn stream_counters(&self) -> &crate::ReceiverCounters {
        self.receiver.counters()
    }

    #[must_use]
    pub const fn consumed_next(&self) -> u64 {
        self.consumed_next
    }

    /// The epoch this receiver's reports name, and the only one whose authenticated media may earn credit. A read-only getter:
    /// it holds no state of its own.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.receiver.active_epoch()
    }

    /// The stream this receiver's reports name, and the only one whose authenticated media may earn credit. A read-only getter.
    #[must_use]
    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// A new numbering began inside the current epoch (a stream whose sequence numbers restart from zero at a new origin): the
    /// consumed position starts again from zero, so reports name the new numbering. An epoch change does the same through
    /// [`Self::advance_epoch`]. The inbound queue is not touched.
    ///
    /// This can only lower this receiver's own `consumed_next`. It never invents credit: the sender keeps the highest
    /// `reported_next` it has seen, so a lower report is inert, and a report can never claim a number the sender has not
    /// allocated. Its only caller is a start that changes the FEC origin within an epoch (`MediaEndpoint::admit_start`).
    pub fn restart_credit(&mut self) {
        self.consumed_next = 0;
    }

    #[must_use]
    pub fn inbound_len(&self) -> usize {
        self.inbound.len()
    }

    /// Adopt an epoch announced by the control channel: the replay window resets and nothing held under the old epoch
    /// is kept.
    pub fn advance_epoch(&mut self, epoch: u64) {
        self.receiver.advance_epoch(epoch);
        self.inbound.clear();
        self.consumed_next = 0;
    }

    /// Follow a source restart announced by the control channel (see [`CarrierSender::restart_group`]): a new stream identity
    /// under the same key, and a newer epoch. N01's receiver resets its replay window for the new identity and refuses the old
    /// stream's packets as a wrong stream; this receiver's reports now name the new identity at position 0, and nothing held
    /// from the old stream is kept. Control datagrams already received are not stream state and stay. Binding the identity
    /// already bound only advances the epoch (as N01 documents), and the position and the backlog are reset all the same.
    pub fn restart_stream(&mut self, stream_id: StreamId, epoch: u64) {
        self.receiver.bind_stream(stream_id, epoch);
        self.stream_id = stream_id;
        self.inbound.clear();
        self.consumed_next = 0;
    }

    /// Read what has arrived, control first, at most `max_reads_per_poll` datagrams from each socket.
    pub fn poll(&mut self) -> PollReport {
        let mut report = PollReport::default();
        self.read_control(&mut report);
        let mut media_buf = [0u8; MAX_DATAGRAM_BYTES + 1];
        for _ in 0..self.limits.max_reads_per_poll {
            match self.port.recv(Lane::Media, &mut media_buf) {
                Ok(got) => {
                    let len = got.len.min(media_buf.len());
                    report.media_read += 1;
                    self.stats.media_read += 1;
                    match self.receiver.accept(&media_buf[..len]) {
                        Ok(packet) => {
                            self.stats.media_accepted += 1;
                            report.media_accepted += 1;
                            if self.inbound.len() >= self.limits.inbound_packets {
                                self.stats.inbound_overflow += 1;
                            } else {
                                self.inbound.push_back(packet);
                            }
                        }
                        Err(_) => self.stats.media_rejected += 1,
                    }
                }
                Err(PortFault::WouldBlock) => break,
                Err(PortFault::Discarded) => {
                    self.faults.recv_discarded = self.faults.recv_discarded.saturating_add(1);
                }
                Err(fault) => {
                    self.stats.io_errors += 1;
                    self.faults.on_recv(&fault);
                    break;
                }
            }
        }
        report
    }

    /// Read what has arrived on the control socket, at most `max_reads_per_poll` datagrams.
    fn read_control(&mut self, report: &mut PollReport) {
        let mut control_buf = [0u8; MAX_CONTROL_BYTES + 1];
        for _ in 0..self.limits.max_reads_per_poll {
            match self.port.recv(Lane::Control, &mut control_buf) {
                Ok(got) => {
                    let len = got.len.min(control_buf.len());
                    report.control_read += 1;
                    self.stats.control_read += 1;
                    // A port that cannot say who sent a datagram (`from` is None) cannot be held to the source
                    // check; the control layer above authenticates what it delivers, so this is not the only gate.
                    let wrong_source =
                        matches!(got.from, Some(from) if from != self.sender_control);
                    if wrong_source {
                        self.stats.control_wrong_source += 1;
                    } else if len > MAX_CONTROL_BYTES {
                        self.stats.control_oversize += 1;
                    } else if self.control_inbox.len() >= self.limits.control_inbox_packets {
                        self.stats.control_dropped_full += 1;
                    } else {
                        self.control_inbox.push_back(control_buf[..len].to_vec());
                        self.stats.control_delivered += 1;
                    }
                }
                Err(PortFault::WouldBlock) => break,
                Err(PortFault::Discarded) => {
                    self.faults.recv_discarded = self.faults.recv_discarded.saturating_add(1);
                }
                Err(fault) => {
                    self.stats.io_errors += 1;
                    self.faults.on_recv(&fault);
                    break;
                }
            }
        }
    }

    /// Like [`Self::poll`], but every media datagram goes to `sink` instead of this receiver's own N01 admission. This is for
    /// a consumer that authenticates, orders and decides in one place and must see the datagram before the replay window
    /// moves (the speaker's `MediaPlayout`): admitting twice would reject every datagram the second time as a replay.
    /// A datagram the sink admits counts as consumed at the sequence the sink names; one it refuses, or cannot take now,
    /// is dropped and counted, and earns no credit. The inbound queue and `take_media` are not used in this mode.
    pub fn poll_into<S: MediaSink + ?Sized>(&mut self, sink: &mut S) -> PollReport {
        let mut report = PollReport::default();
        self.read_control(&mut report);
        let read_len = sink
            .max_datagram_bytes()
            .clamp(MAX_DATAGRAM_BYTES, MAX_SINK_DATAGRAM_BYTES)
            + 1;
        let mut media_buf = [0u8; MAX_SINK_DATAGRAM_BYTES + 1];
        for _ in 0..self.limits.max_reads_per_poll {
            // A sink that cannot take a datagram now leaves the rest where they are: in the port's bounded receive queue.
            if !sink.ready() {
                break;
            }
            match self.port.recv(Lane::Media, &mut media_buf[..read_len]) {
                Ok(got) => {
                    let len = got.len.min(read_len);
                    report.media_read += 1;
                    self.stats.media_read += 1;
                    match sink.offer(&media_buf[..len]) {
                        SinkVerdict::Admitted { seq } => {
                            self.stats.media_accepted += 1;
                            report.media_accepted += 1;
                            self.sink.admitted += 1;
                            self.consumed_next = self.consumed_next.max(seq.saturating_add(1));
                        }
                        SinkVerdict::Refused => {
                            self.stats.media_rejected += 1;
                            self.sink.refused += 1;
                        }
                        SinkVerdict::Backpressure => {
                            self.stats.media_rejected += 1;
                            self.sink.backpressure += 1;
                        }
                    }
                }
                Err(PortFault::WouldBlock) => break,
                Err(PortFault::Discarded) => {
                    self.faults.recv_discarded = self.faults.recv_discarded.saturating_add(1);
                }
                Err(fault) => {
                    self.stats.io_errors += 1;
                    self.faults.on_recv(&fault);
                    break;
                }
            }
        }
        report
    }

    /// What the sink did with the datagrams [`Self::poll_into`] offered it.
    #[must_use]
    pub const fn sink_counters(&self) -> &SinkCounters {
        &self.sink
    }

    /// Hand the consumer up to `max` packets. What the consumer has taken is what the next report says is consumed.
    pub fn take_media(&mut self, max: usize) -> Vec<AuthenticatedStreamPacket> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(packet) = self.inbound.pop_front() else {
                break;
            };
            if packet.session_epoch == self.receiver.active_epoch() {
                self.consumed_next = self.consumed_next.max(packet.seq.saturating_add(1));
            }
            out.push(packet);
        }
        out
    }

    pub fn take_control(&mut self, max: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(message) = self.control_inbox.pop_front() else {
                break;
            };
            out.push(message);
        }
        out
    }

    /// Send one fixed-size N06 feedback message for this stream and epoch to the
    /// configured sender. The sender authenticates it and attributes its source.
    pub fn send_fec_feedback(
        &mut self,
        feedback: &crate::fec::Feedback,
    ) -> Result<(), CarrierError> {
        let wire = &feedback.0;
        if &wire[..4] != b"FFWA"
            || be_u64(wire, 12) != self.stream_id.get()
            || be_u64(wire, 20) != self.receiver.active_epoch()
        {
            return Err(CarrierError::InvalidLimits(
                "FEC feedback stream or epoch mismatch",
            ));
        }
        if let Err(fault) = self.port.send_to(Lane::Control, wire, self.sender_control) {
            self.faults.on_send(&fault);
            return Err(CarrierError::Io(fault_text(&fault)));
        }
        Ok(())
    }

    /// Send the authenticated consumption report to the sender's control socket.
    pub fn send_report(&mut self) -> Result<(), CarrierError> {
        let wire = encode_report(
            &self.key,
            self.stream_id,
            self.receiver.active_epoch(),
            self.consumed_next,
            self.peer,
        );
        if let Err(fault) = self.port.send_to(Lane::Control, &wire, self.sender_control) {
            self.faults.on_send(&fault);
            return Err(CarrierError::Io(fault_text(&fault)));
        }
        self.stats.reports_sent += 1;
        Ok(())
    }
}

#[cfg(test)]
mod fec_tests;
#[cfg(test)]
mod tests;
