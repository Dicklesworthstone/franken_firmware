//! The speaker's half of the bounded carrier (`N07` / `ffw-ybr`, `docs/contracts/n07.md` section 9): the carrier and the link
//! manager from `franken-stream`, joined to the P02 datagram boundary, the N01 receiver and the N04 playout path.
//!
//! * **P02.** [`SocketPort`] is a [`DatagramPort`] built from `franken_platform`'s own functions: `socket::open_datagram_socket`
//!   and `bind_v4`/`bind_v6` (nonblocking and close-on-exec by construction), and the additive
//!   `datagram::{send_datagram_to, recv_datagram_from}` (flags fixed, `MSG_TRUNC` on every read, bounded `EINTR`, a typed error
//!   for every errno, the sender of every datagram). That module is **IvoryFalcon's** and is a prerequisite of this one: this
//!   file is stacked on it and names only `DatagramOps`, `PeerAddr`, `Received`, `DatagramError`, `send_datagram_to` and
//!   `recv_datagram_from`. There is no second send seam here. The port binds **configured** ports (a profile's fixed ports;
//!   the local address is the configured one, so there is no `getsockname`), and sends with `sendto` from the bound socket, so
//!   the source port is the advertised one. Because `recvfrom` names the sender, a report is held to its peer's registered
//!   control address, and a report that also names its peer is attributed by number.
//! * **N01.** Frames are signed at send time by the carrier's per-peer `StreamSender`; the receiving side hands each raw
//!   datagram to [`MediaPlayout::ingest_authenticated`], which owns the one admission (MAC, stream, epoch, replay
//!   window) and returns the authenticated sequence, epoch and format credit is given under. The carrier's own admission is
//!   not run in this mode, so nothing is admitted twice. With the explicit host-development N06 hybrid selected the same call
//!   admits the 1152-byte N06 wire instead (never parsed as an N01 header), and its refusals, deferrals and buffered repair
//!   symbols are mapped to the same three verdicts; see `PlayoutSink`. This receiving side drives no paced FEC sender and
//!   negotiates no peer format: the selection is the local trusted control call `MediaPlayout::enable_host_fec`.
//! * **N04.** [`MediaEndpoint`] ends in [`MediaPlayout::prepare`]: authenticated PCM prepared for a scheduled downstream sink
//!   while the group clock allows it. Preparing is not playing, and nothing here drives a DAC. A catch-up after an outage is
//!   muted by the engine itself (bounded concealment, then silence, then fresh blocks only): the carrier never replays queued
//!   audio, it ages out by `consume_by`. The one exception is not audio and exists for recovery: after a long refusal the
//!   datagram that holds the last allowed sequence number, and the probes that send the newest transmitted datagram again,
//!   may reach a room long after their block's presentation time. `MediaEndpoint` gives them to N01 first and to the N04
//!   engine second; the engine answers `Late`, the media sink counts that as consumed, and the room's authenticated report
//!   carries the credit back. No PCM is decided or prepared for them (the engine decides a block as real only before its
//!   presentation time), which the composed tests show on the actual endpoint and clock.
//! * **Link.** [`SenderEndpoint`] applies the link manager's actions to the carrier (`set_link_up`, `rebind`), moves a
//!   peer's addresses without changing its identity, and exposes the transport reasons the readiness state shows.
//!
//! What this is not: it does not open an interface, a lease or a resolver, and it does not claim a radio. The link events
//! come from the caller; on a device the source of those events does not exist yet (`link.state_events`). The device
//! backend that implements `DatagramOps` is the Linux leaf's, which no guest has run (no guest has issued a `socketcall` on
//! either ABI), so nothing here qualifies a kernel; the tests use a private simulated host kernel and say so.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use franken_clock::group::GroupClock;
use franken_platform::abi::{Abi, SysError};
use franken_platform::clock::ClockError;
use franken_platform::datagram::{
    DatagramError, DatagramOps, PeerAddr, Received as P02Received, recv_datagram_from,
    send_datagram_to,
};
use franken_platform::layer::PlatformLayer;
use franken_platform::net::{Datagram, Family, NetErrno, SockAddrIn, SockAddrIn6};
use franken_platform::ops::KernelOps;
use franken_platform::socket::{
    DatagramSocket, SocketError, bind_v4, bind_v6, open_datagram_socket,
};
use franken_stream::StreamId;
use franken_stream::carrier::{
    CarrierError, CarrierReceiver, CarrierSender, DatagramPort, Lane, MediaSink, PollReport,
    PortFault, Received, SinkVerdict,
};
use franken_stream::fec::{self, DecodeState, Feedback};
use franken_stream::link::{
    Announced, DirectoryError, LinkAction, LinkEvent, LinkManager, LinkState, PeerDirectory,
    TransportReason,
};
use franken_stream::playout::{Admission, BLOCK_PAYLOAD_BYTES};
use serde::Serialize;
use std::sync::atomic::AtomicBool;

use crate::SpeakerReadinessState;
use crate::clock_view::ClockViewBridge;
use crate::media_playout::{
    AuthenticatedFormat, AuthenticatedIngress, MediaPlayout, MediaRefusal, Preparation,
    StartRefusal,
};

// ----------------------------------------------------------------------------------------------------- fault classification

fn fault_of(abi: Abi, error: SysError) -> PortFault {
    match error {
        SysError::WouldBlock | SysError::Interrupted => PortFault::WouldBlock,
        SysError::Errno(errno) => match abi.classify_net_errno(errno) {
            Some(NetErrno::MsgSize) => PortFault::MessageTooLong,
            Some(NetErrno::AddrNotAvail | NetErrno::NetUnreach) => PortFault::PathUnavailable,
            Some(other) => PortFault::Other(other.name().to_owned()),
            None => PortFault::Other(format!("errno {errno}")),
        },
        other => PortFault::Other(other.to_string()),
    }
}

fn socket_fault(abi: Abi, error: &SocketError) -> PortFault {
    match error {
        SocketError::Sys { error, .. } => fault_of(abi, *error),
        other => PortFault::Other(other.to_string()),
    }
}

/// A bad sender (cut, or not a decodable address) means the kernel consumed the datagram and it is unusable: counted, never
/// decoded as a peer, and reading goes on. Every other error is the kernel's or the boundary's own.
fn datagram_fault(abi: Abi, error: &DatagramError) -> PortFault {
    match error {
        DatagramError::Sys { error, .. } => fault_of(abi, *error),
        DatagramError::SenderTruncated { .. } | DatagramError::SenderUnparsed(_) => {
            PortFault::Discarded
        }
        other => PortFault::Other(format!("{other:?}")),
    }
}

fn peer_of(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V4(v4) => PeerAddr::V4 {
            addr: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => PeerAddr::V6 {
            addr: v6.ip().octets(),
            port: v6.port(),
            scope_id: v6.scope_id(),
        },
    }
}

fn socket_of(peer: PeerAddr) -> SocketAddr {
    match peer {
        PeerAddr::V4 { addr, port } => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(addr), port))
        }
        PeerAddr::V6 {
            addr,
            port,
            scope_id,
        } => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(addr), port, 0, scope_id)),
    }
}

// ------------------------------------------------------------------------------------------------------------- the port

/// One lane's socket: bound to its configured address, never connected, so it hears every peer and sends from the
/// advertised port.
struct LaneSocket {
    socket: DatagramSocket,
    local: SocketAddr,
}

/// A [`DatagramPort`] over the P02 datagram boundary. It carries whatever family its configured addresses use; which family a
/// profile may use is the carrier's address policy, not the port's.
pub struct SocketPort<S: DatagramOps> {
    ops: S,
    abi: Abi,
    media: LaneSocket,
    control: LaneSocket,
}

fn close_quietly<S: DatagramOps>(ops: &mut S, fd: i32) {
    // Cleanup after a failure: a close error leaves nothing to decide.
    let _ = ops.close(fd);
}

fn open_lane<S: DatagramOps>(
    ops: &mut S,
    abi: Abi,
    local: SocketAddr,
) -> Result<LaneSocket, PortFault> {
    let family = match local {
        SocketAddr::V4(_) => Family::Inet,
        SocketAddr::V6(_) => Family::Inet6,
    };
    let socket =
        open_datagram_socket(ops, abi, family).map_err(|error| socket_fault(abi, &error))?;
    let bound = match local {
        SocketAddr::V4(v4) => bind_v4(
            ops,
            abi,
            socket.fd(),
            SockAddrIn {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
        ),
        SocketAddr::V6(v6) => bind_v6(
            ops,
            abi,
            socket.fd(),
            SockAddrIn6 {
                addr: v6.ip().octets(),
                port: v6.port(),
                flowinfo: 0,
                scope_id: v6.scope_id(),
            },
        ),
    };
    if let Err(error) = bound {
        close_quietly(ops, socket.into_fd());
        return Err(socket_fault(abi, &error));
    }
    Ok(LaneSocket { socket, local })
}

fn close_lane<S: DatagramOps>(ops: &mut S, lane: LaneSocket) {
    close_quietly(ops, lane.socket.into_fd());
}

impl<S: DatagramOps> SocketPort<S> {
    /// Open the media and control lanes bound to their configured addresses.
    ///
    /// # Errors
    /// [`PortFault`] from the first call that failed; nothing stays open.
    pub fn open(
        mut ops: S,
        abi: Abi,
        media: SocketAddr,
        control: SocketAddr,
    ) -> Result<Self, PortFault> {
        let media = open_lane(&mut ops, abi, media)?;
        let control = match open_lane(&mut ops, abi, control) {
            Ok(control) => control,
            Err(fault) => {
                close_lane(&mut ops, media);
                return Err(fault);
            }
        };
        Ok(Self {
            ops,
            abi,
            media,
            control,
        })
    }

    /// The kernel seam, for inspection.
    #[must_use]
    pub const fn ops(&self) -> &S {
        &self.ops
    }

    /// The kernel seam, for a test that moves its simulated state.
    pub fn ops_mut(&mut self) -> &mut S {
        &mut self.ops
    }

    fn lane_mut(&mut self, lane: Lane) -> &mut LaneSocket {
        match lane {
            Lane::Media => &mut self.media,
            Lane::Control => &mut self.control,
        }
    }
}

impl<S: DatagramOps> Drop for SocketPort<S> {
    fn drop(&mut self) {
        let fds = [self.media.socket.fd(), self.control.socket.fd()];
        for fd in fds {
            close_quietly(&mut self.ops, fd);
        }
    }
}

impl<S: DatagramOps> DatagramPort for SocketPort<S> {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        let abi = self.abi;
        let socket = match lane {
            Lane::Media => &self.media.socket,
            Lane::Control => &self.control.socket,
        };
        send_datagram_to(&mut self.ops, abi, socket, &peer_of(to), bytes)
            .map(|_| ())
            .map_err(|error| datagram_fault(abi, &error))
    }

    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        let abi = self.abi;
        let socket = match lane {
            Lane::Media => &self.media.socket,
            Lane::Control => &self.control.socket,
        };
        let P02Received { datagram, from } = recv_datagram_from(&mut self.ops, abi, socket, buf)
            .map_err(|error| datagram_fault(abi, &error))?;
        let from = Some(socket_of(from));
        match datagram {
            Datagram::Complete { len } => Ok(Received { len, from }),
            // The buffer is one byte larger than the largest legal datagram, so a datagram that did not fit is oversize:
            // report the buffer's length and let the structure check name it. The sender is known, so it can be accounted.
            Datagram::Truncated { stored, .. } => Ok(Received { len: stored, from }),
        }
    }

    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        Ok(match lane {
            Lane::Media => self.media.local,
            Lane::Control => self.control.local,
        })
    }

    /// Replace both sockets with ones bound to `ip` on the same configured ports. The same address again is no change and
    /// no call (the old sockets hold the ports); a failure keeps the old sockets.
    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        if self.media.local.ip() == ip && self.control.local.ip() == ip {
            return Ok(());
        }
        let abi = self.abi;
        let media_local = SocketAddr::new(ip, self.media.local.port());
        let control_local = SocketAddr::new(ip, self.control.local.port());
        let media = open_lane(&mut self.ops, abi, media_local)?;
        let control = match open_lane(&mut self.ops, abi, control_local) {
            Ok(control) => control,
            Err(fault) => {
                close_lane(&mut self.ops, media);
                return Err(fault);
            }
        };
        let old_media = std::mem::replace(self.lane_mut(Lane::Media), media);
        let old_control = std::mem::replace(self.lane_mut(Lane::Control), control);
        close_lane(&mut self.ops, old_media);
        close_lane(&mut self.ops, old_control);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------- the receiver

/// What the playout engine said to each authentic datagram it was handed, by its own stable code, plus the datagrams it
/// could not take. Nothing here is a count of sound.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EngineVerdicts {
    pub by_code: BTreeMap<&'static str, u64>,
    /// Refused by the stream receiver (structure, MAC, stream, epoch, replay window) or not media.
    pub refused: u64,
    /// The platform clock failed first: not consumed from the replay window, no credit.
    pub backpressure: u64,
    /// Authenticated, but its epoch or format is not the one this endpoint selected: no credit.
    pub credit_refused: u64,
    /// Selected N06 ingress that authenticated and was credited, by what it was: a source symbol, a retransmitted source
    /// symbol, or a repair symbol buffered for the decoder (no engine verdict exists for it).
    pub fec_source: u64,
    pub fec_retransmit: u64,
    pub fec_repair_buffered: u64,
    /// Polls that stopped reading media because the selected FEC receiver would have deferred the next datagram. Nothing was
    /// read, so nothing was lost: the datagrams stayed in the port's receive queue.
    pub fec_deferred_polls: u64,
    /// A datagram read and then deferred after all (render protection began between the readiness check and its offer):
    /// dropped and counted as backpressure, no credit.
    pub fec_deferred_dropped: u64,
}

impl EngineVerdicts {
    fn record(&mut self, admission: Admission) {
        let slot = self.by_code.entry(admission.code()).or_insert(0);
        *slot = slot.saturating_add(1);
    }

    /// The count for one engine code (`admitted`, `late`, `duplicate`, ...).
    #[must_use]
    pub fn count(&self, code: &str) -> u64 {
        self.by_code.get(code).copied().unwrap_or(0)
    }
}

/// The media path as the carrier's sink. It takes the datagram's identity from [`MediaPlayout::ingest_authenticated`], the
/// authenticated sequence, epoch and format the media path itself returns, and never reads a sequence number out of the raw
/// bytes: a selected N06 datagram has no N01 header, so a byte-offset read of it would be a constant, not a sequence.
///
/// Credit follows one rule for every format: an authenticated datagram of this endpoint's stream, epoch, FEC origin generation
/// and selected format family is consumed at its own authenticated sequence, whatever the engine then decided (late, duplicate, too far ahead) and even if
/// it is only buffered (an N06 repair symbol has no engine verdict). The carrier keeps the highest, so credit is monotone.
/// For a selected N06 stream the bound on what can be credited is the FEC receiver's authenticated window range
/// `[current - 6, current + 1]` (at most 64 buffered symbols, fixed state): a window outside it is refused before any state
/// changes and earns nothing.
struct PlayoutSink<'a, O: KernelOps> {
    media: &'a mut MediaPlayout,
    platform: &'a mut PlatformLayer<O>,
    clock: &'a mut GroupClock,
    verdicts: &'a mut EngineVerdicts,
    /// The carrier's epoch when this poll began: the only epoch whose authenticated media may earn credit.
    epoch: u64,
    /// The carrier's stream id (as a number) when this poll began: the only stream whose media may earn credit.
    stream: u64,
    /// The FEC origin generation this endpoint is crediting (0 with no N06 selected, as an N01 event carries none): the only
    /// origin whose authenticated media may earn credit.
    origin: u64,
    /// Whether the media path had the N06 hybrid selected when this poll began (a control call cannot change it mid-poll).
    fec_selected: bool,
}

impl<O: KernelOps> PlayoutSink<'_, O> {
    fn backpressure(&mut self) -> SinkVerdict {
        self.verdicts.backpressure = self.verdicts.backpressure.saturating_add(1);
        SinkVerdict::Backpressure
    }

    fn refused(&mut self) -> SinkVerdict {
        self.verdicts.refused = self.verdicts.refused.saturating_add(1);
        SinkVerdict::Refused
    }

    /// A refusal from the selected N06 path. "Cannot take it now" (the clock, the shared work ledger, a window being decoded,
    /// render protection) is backpressure; everything else (shape, identity, epoch, duplicate, storm, conflict, ...) is a refusal.
    /// Neither earns credit. A pre-authentication refusal carries no authenticated sequence, so none could be credited anyway.
    fn fec_refusal(&mut self, refusal: fec::Refusal) -> SinkVerdict {
        match refusal {
            fec::Refusal::Protected { .. } => {
                self.verdicts.fec_deferred_dropped =
                    self.verdicts.fec_deferred_dropped.saturating_add(1);
                self.backpressure()
            }
            fec::Refusal::Clock | fec::Refusal::Work | fec::Refusal::Busy => self.backpressure(),
            _ => self.refused(),
        }
    }

    fn credit(&mut self, event: &AuthenticatedIngress) -> SinkVerdict {
        let family = match event.format {
            AuthenticatedFormat::N01Media => !self.fec_selected,
            AuthenticatedFormat::N06Source
            | AuthenticatedFormat::N06Retransmit
            | AuthenticatedFormat::N06RepairSymbol => self.fec_selected,
        };
        if event.stream != self.stream
            || event.source_epoch != self.epoch
            || event.origin_ns != self.origin
            || !family
        {
            self.verdicts.credit_refused = self.verdicts.credit_refused.saturating_add(1);
            return SinkVerdict::Refused;
        }
        match event.format {
            AuthenticatedFormat::N01Media => {}
            AuthenticatedFormat::N06Source => {
                self.verdicts.fec_source = self.verdicts.fec_source.saturating_add(1);
            }
            AuthenticatedFormat::N06Retransmit => {
                self.verdicts.fec_retransmit = self.verdicts.fec_retransmit.saturating_add(1);
            }
            AuthenticatedFormat::N06RepairSymbol => {
                self.verdicts.fec_repair_buffered =
                    self.verdicts.fec_repair_buffered.saturating_add(1);
            }
        }
        if let Some(admission) = event.admission {
            self.verdicts.record(admission);
        }
        SinkVerdict::Admitted {
            seq: event.sequence,
        }
    }
}

impl<O: KernelOps> MediaSink for PlayoutSink<'_, O> {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict {
        match self
            .media
            .ingest_authenticated(self.platform, self.clock, datagram)
        {
            // The datagram was authentic and left the replay window (N01) or was stored (N06), whatever the engine then
            // decided (late, duplicate, off the timeline): from the sender's side it is consumed, and the window must keep
            // moving on a stale stream.
            Ok(event) => self.credit(&event),
            Err(MediaRefusal::Clock(_) | MediaRefusal::Resolution(_)) => self.backpressure(),
            Err(MediaRefusal::Stream(_) | MediaRefusal::NotMedia) => self.refused(),
            Err(MediaRefusal::Fec(refusal)) => self.fec_refusal(refusal),
        }
    }

    /// Render protection of a selected N06 receiver is a question about the clock, not about a datagram, so it is asked before
    /// a datagram is read: while it holds, the media loop stops and the datagrams wait in the port (see [`MediaSink::ready`]).
    /// They wait in the socket's receive buffer, which the kernel bounds and overflows by dropping, so this is a limit and not a
    /// retry queue. With no N06 selected this is `true` without reading any clock, so the baseline's kernel calls are unchanged.
    fn ready(&mut self) -> bool {
        if !self.fec_selected {
            return true;
        }
        match self
            .media
            .checked_host_fec_deferral(self.platform, self.clock)
        {
            Ok(Some(_)) => {
                self.verdicts.fec_deferred_polls =
                    self.verdicts.fec_deferred_polls.saturating_add(1);
                false
            }
            Ok(None) => true,
            Err(_) => {
                // The readiness read itself is a real platform clock read.
                // Do not swallow its failure and admit the datagram using a
                // second, successful read; leave the wire in the port instead.
                self.backpressure();
                false
            }
        }
    }

    /// The selected N06 wire is longer than N01's largest datagram; with it selected the carrier must read that much.
    fn max_datagram_bytes(&self) -> usize {
        if self.fec_selected {
            fec::DATAGRAM
        } else {
            franken_stream::MAX_DATAGRAM_BYTES
        }
    }
}

/// One room's receiving side: the carrier receiver, and the media path that admits and decides. The platform and the group
/// clock stay with the composition root, as for [`MediaPlayout`].
pub struct MediaEndpoint<P: DatagramPort> {
    carrier: CarrierReceiver<P>,
    media: MediaPlayout,
    verdicts: EngineVerdicts,
    /// The FEC origin generation credit is being held under, if the N06 hybrid has been selected. A change restarts credit.
    credit_origin: Option<u64>,
    pending_feedback: Option<PendingFeedback>,
    feedback_clock: ClockViewBridge,
    feedback_counters: FeedbackCounters,
}

/// Feedback is generated once per coding window; a failed datagram write must
/// not consume that opportunity without a bounded retry of the same bytes.
struct PendingFeedback {
    wire: Feedback,
    identity: (u64, u64, u64),
    retry_at_local_ns: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FeedbackCounters {
    pub generated: u64,
    pub sent: u64,
    pub retries: u64,
    pub send_errors: u64,
    pub expired: u64,
    pub retired: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackProgress {
    Idle,
    Deferred,
    Sent { window: u64 },
    Expired { window: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedbackError {
    #[error("feedback media admission refused: {0:?}")]
    Media(MediaRefusal),
    #[error("feedback transport refused: {0}")]
    Transport(CarrierError),
}

#[derive(Debug)]
pub struct FecPollReport {
    pub decode: DecodeState,
    pub feedback: Result<FeedbackProgress, FeedbackError>,
}

const FEEDBACK_RETRY_NS: u64 = 1_000_000;

fn feedback_u64(wire: &Feedback, offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&wire.0[offset..offset + 8]);
    u64::from_be_bytes(bytes)
}

/// Last useful *send* time, earlier than the last requested block's consume-by.
/// The sender still rechecks its own current clock and work budget on arrival.
fn feedback_send_deadline(wire: &Feedback, uncertainty_ns: u64) -> Option<u64> {
    let mask = wire.0[64];
    if mask == 0 || mask & !15 != 0 {
        return None;
    }
    let last = (0..fec::K).rev().find(|i| mask & (1 << i) != 0)?;
    let presentation = feedback_u64(wire, 44)
        .checked_add(franken_stream::playout::frames_to_ns(last as u64 * 256))?;
    let cutoff = franken_stream::playout::consume_by(
        presentation,
        1_000_000,
        1_000_000,
        uncertainty_ns.max(500_000),
    );
    let tail_work = u64::from(mask.count_ones())
        .checked_mul(fec::AUTH_WORK + 1024 + 1000)?
        .checked_mul(fec::WORK_UNIT_NS)?;
    cutoff.checked_sub(fec::TAIL_TRANSIT_RESERVE_NS.checked_add(tail_work)?)
}

impl<P: DatagramPort> MediaEndpoint<P> {
    #[must_use]
    pub fn new(carrier: CarrierReceiver<P>, media: MediaPlayout) -> Self {
        Self {
            carrier,
            media,
            verdicts: EngineVerdicts::default(),
            credit_origin: None,
            pending_feedback: None,
            feedback_clock: ClockViewBridge::default(),
            feedback_counters: FeedbackCounters::default(),
        }
    }

    /// Hold credit under the FEC origin generation the media path is bound to now. The generation is the presentation origin: a
    /// start that moves it begins a new window numbering, so credit starts again from zero, once, whichever call admitted the
    /// start (this endpoint's `admit_start`, or the media path reached through `media_mut`). The first generation, and a
    /// generation after FEC was deselected, start from whatever credit stands (an epoch change already reset it).
    fn note_generation(&mut self) {
        let identity = self.media.host_fec_identity();
        if self.pending_feedback.as_ref().is_some_and(|pending| {
            Some(pending.identity) != identity
                || pending.identity.0 != self.carrier.stream_id().get()
                || pending.identity.1 != self.carrier.epoch()
        }) {
            self.retire_feedback();
        }
        let origin = self.media.host_fec_origin();
        if let (Some(held), Some(now)) = (self.credit_origin, origin)
            && held != now
        {
            self.carrier.restart_credit();
        }
        self.credit_origin = origin;
    }

    #[must_use]
    pub const fn carrier(&self) -> &CarrierReceiver<P> {
        &self.carrier
    }

    pub fn carrier_mut(&mut self) -> &mut CarrierReceiver<P> {
        &mut self.carrier
    }

    #[must_use]
    pub const fn media(&self) -> &MediaPlayout {
        &self.media
    }

    pub fn media_mut(&mut self) -> &mut MediaPlayout {
        &mut self.media
    }

    #[must_use]
    pub const fn verdicts(&self) -> &EngineVerdicts {
        &self.verdicts
    }

    /// Read what has arrived: control into the inbox, media into the playout engine through
    /// [`MediaPlayout::ingest_authenticated`], which returns the authenticated identity credit is given under. With the N06
    /// hybrid selected, media is read only while the receiver is not in render protection, and the datagrams that wait stay in
    /// the port's receive queue (`EngineVerdicts::fec_deferred_polls`).
    pub fn poll<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> PollReport {
        self.note_generation();
        let epoch = self.carrier.epoch();
        let stream = self.carrier.stream_id().get();
        let origin = self.credit_origin.unwrap_or(0);
        let fec_selected = self.media.host_fec_selected();
        let mut sink = PlayoutSink {
            media: &mut self.media,
            platform,
            clock,
            verdicts: &mut self.verdicts,
            epoch,
            stream,
            origin,
            fec_selected,
        };
        self.carrier.poll_into(&mut sink)
    }

    /// Drive the selected N06 decoder one bounded step and publish a finished recovery; see [`MediaPlayout::poll_host_fec`]. The
    /// caller owns the cancellation token and the schedule.
    ///
    /// # Errors
    /// [`MediaRefusal`], including `Fec(Protected { .. })` when render protection defers the step (retry after it).
    pub fn poll_fec<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        cancelled: &AtomicBool,
    ) -> Result<DecodeState, MediaRefusal> {
        self.media.poll_host_fec(platform, clock, cancelled)
    }

    /// The aggregate tail request for the earliest window that still needs one, if any; see [`MediaPlayout::host_fec_feedback`].
    /// The returned bytes go to the sender over the reliable control lane: this endpoint sends nothing and there is no paced
    /// FEC sender yet.
    ///
    /// # Errors
    /// [`MediaRefusal`].
    pub fn fec_feedback<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> Result<Option<Feedback>, MediaRefusal> {
        self.media.host_fec_feedback(platform, clock)
    }

    fn retire_feedback(&mut self) {
        if self.pending_feedback.take().is_some() {
            self.feedback_counters.retired = self.feedback_counters.retired.saturating_add(1);
        }
    }

    #[must_use]
    pub const fn feedback_counters(&self) -> &FeedbackCounters {
        &self.feedback_counters
    }

    /// Retained wire payload, excluding this endpoint's fixed inline state.
    #[must_use]
    pub fn pending_feedback_bytes(&self) -> usize {
        self.pending_feedback
            .as_ref()
            .map_or(0, |_| fec::FEEDBACK_BYTES)
    }

    /// Generate at most one aggregate request and attempt one control write.
    /// A failed write retains exactly the same authenticated bytes, with at
    /// most one retry per millisecond and only while a tail can still arrive.
    /// Selection/epoch/origin changes, cancellation or a clock fault retire it.
    /// This is host-development transport behavior, not radio/board admission.
    pub fn pump_fec_feedback<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        cancelled: &AtomicBool,
    ) -> Result<FeedbackProgress, FeedbackError> {
        self.note_generation();
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            self.retire_feedback();
            return Err(FeedbackError::Media(MediaRefusal::Fec(
                fec::Refusal::Cancelled,
            )));
        }
        let Some(identity) = self.media.host_fec_identity() else {
            return Ok(FeedbackProgress::Idle);
        };
        if identity.0 != self.carrier.stream_id().get() || identity.1 != self.carrier.epoch() {
            self.retire_feedback();
            return Err(FeedbackError::Media(MediaRefusal::Fec(
                fec::Refusal::Identity,
            )));
        }
        if self.pending_feedback.is_none() {
            let Some(wire) = self
                .media
                .host_fec_feedback(platform, clock)
                .map_err(FeedbackError::Media)?
            else {
                return Ok(FeedbackProgress::Idle);
            };
            self.pending_feedback = Some(PendingFeedback {
                wire,
                identity,
                retry_at_local_ns: 0,
            });
            self.feedback_counters.generated = self.feedback_counters.generated.saturating_add(1);
        }
        // Retrying a previously authenticated request still does socket work.
        // Leave that work outside the same protected render interval as ingress
        // and decoder work; use a fresh reading below after this readiness check.
        match self.media.checked_host_fec_deferral(platform, clock) {
            Ok(Some(_)) => return Ok(FeedbackProgress::Deferred),
            Ok(None) => {}
            Err(error) => {
                self.retire_feedback();
                return Err(FeedbackError::Media(error));
            }
        }
        let local = match platform.now_ns() {
            Ok(local) => local,
            Err(error) => {
                clock.report_clock_fault();
                self.retire_feedback();
                return Err(FeedbackError::Media(MediaRefusal::Clock(error)));
            }
        };
        let view = self.feedback_clock.at_local(clock, local);
        if !view.usable || matches!(clock.output(local), franken_clock::group::Output::Muted(_)) {
            self.retire_feedback();
            return Err(FeedbackError::Media(MediaRefusal::Fec(fec::Refusal::Clock)));
        }
        // Time can cross the render fence between the readiness read and this
        // fresh send-authorizing reading. Reuse this exact view for protection
        // as well as the deadline; another clock read would reopen that gap.
        if self.media.host_fec_deferral_at(view).is_some() {
            return Ok(FeedbackProgress::Deferred);
        }
        let pending = self
            .pending_feedback
            .as_ref()
            .expect("generated or retained feedback");
        let window = feedback_u64(&pending.wire, 28);
        if view.group_ns < feedback_u64(&pending.wire, 72) {
            self.retire_feedback();
            return Err(FeedbackError::Media(MediaRefusal::Fec(fec::Refusal::Clock)));
        }
        if feedback_send_deadline(&pending.wire, view.uncertainty_ns)
            .is_none_or(|deadline| view.group_ns >= deadline)
        {
            self.pending_feedback = None;
            self.feedback_counters.expired = self.feedback_counters.expired.saturating_add(1);
            return Ok(FeedbackProgress::Expired { window });
        }
        if local < pending.retry_at_local_ns {
            return Ok(FeedbackProgress::Deferred);
        }
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            self.retire_feedback();
            return Err(FeedbackError::Media(MediaRefusal::Fec(
                fec::Refusal::Cancelled,
            )));
        }
        if pending.retry_at_local_ns != 0 {
            self.feedback_counters.retries = self.feedback_counters.retries.saturating_add(1);
        }
        match self.carrier.send_fec_feedback(&pending.wire) {
            Ok(()) => {
                self.pending_feedback = None;
                self.feedback_counters.sent = self.feedback_counters.sent.saturating_add(1);
                Ok(FeedbackProgress::Sent { window })
            }
            Err(error) => {
                self.feedback_counters.send_errors =
                    self.feedback_counters.send_errors.saturating_add(1);
                self.pending_feedback
                    .as_mut()
                    .expect("retained feedback")
                    .retry_at_local_ns = local.saturating_add(FEEDBACK_RETRY_NS);
                Err(FeedbackError::Transport(error))
            }
        }
    }

    /// One cooperative endpoint step: bounded decode/publication followed by
    /// bounded feedback transport. A transport failure cannot rewrite the
    /// decoder's outcome and remains separately visible to the caller.
    pub fn poll_fec_with_feedback<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        cancelled: &AtomicBool,
    ) -> Result<FecPollReport, MediaRefusal> {
        let decode = match self.poll_fec(platform, clock, cancelled) {
            Ok(decode) => decode,
            Err(error) => {
                if matches!(
                    error,
                    MediaRefusal::Clock(_)
                        | MediaRefusal::Fec(fec::Refusal::Clock | fec::Refusal::Cancelled)
                ) {
                    self.retire_feedback();
                }
                return Err(error);
            }
        };
        let feedback = self.pump_fec_feedback(platform, clock, cancelled);
        Ok(FecPollReport { decode, feedback })
    }

    /// Prepare at most one block of PCM for a scheduled downstream sink; see [`MediaPlayout::prepare`].
    ///
    /// # Errors
    /// The platform clock failed (the group clock was told).
    pub fn prepare<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        out: &mut [u8; BLOCK_PAYLOAD_BYTES],
    ) -> Result<Preparation, ClockError> {
        self.media.prepare(platform, clock, out)
    }

    /// Admit a start the control path scheduled; see [`MediaPlayout::admit_start`].
    ///
    /// With the N06 hybrid selected, a start inside the same epoch that moves its presentation origin begins a new window
    /// numbering (`window * 8 + esi` restarts from zero), so credit starts again from zero with it: credit is held under the
    /// stream, the epoch, the origin generation and the format. A refused start changes neither.
    ///
    /// # Errors
    /// [`StartRefusal`].
    pub fn admit_start<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        sched: franken_clock::group::StartSchedule,
        anchor_frame: u64,
    ) -> Result<franken_clock::group::StartPlan, StartRefusal> {
        let plan = self
            .media
            .admit_start(platform, clock, sched, anchor_frame)?;
        self.note_generation();
        Ok(plan)
    }

    /// Follow a source restart announced by the control path (see `CarrierSender::restart_group`): a fresh stream identity under
    /// the same key and a strictly newer epoch. Two calls, with nothing between them, so no poll sees one without the other: the
    /// media path binds the new stream ([`MediaPlayout::bind_stream`]: its replay window restarts at `epoch`, the old stream's
    /// datagrams are refused as a wrong stream, and a selected N06 session, which names the old stream, ends with the bind: the
    /// owner selects it again for the new stream with `enable_host_fec`), then the carrier follows
    /// ([`CarrierReceiver::restart_stream`]: its reports name the new stream from position 0 and the old stream's backlog is
    /// dropped). The group clock and the engine are the control path's calls, as for an epoch restart: `MediaPlayout::begin_epoch`
    /// and [`Self::admit_start`].
    pub fn restart_stream(&mut self, stream_id: StreamId, epoch: u64) {
        self.retire_feedback();
        self.media.bind_stream(stream_id, epoch);
        self.carrier.restart_stream(stream_id, epoch);
    }

    /// Send the authenticated consumption report to the sender.
    ///
    /// # Errors
    /// [`CarrierError::Io`] when the port could not send it.
    pub fn report(&mut self) -> Result<(), CarrierError> {
        self.carrier.send_report()
    }
}

// ------------------------------------------------------------------------------------------------------------ the sender

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("{0}")]
    Directory(#[from] DirectoryError),
    #[error("{0}")]
    Carrier(#[from] CarrierError),
    #[error("FEC agreement refused: {0:?}")]
    FecAgreement(franken_control::channel::fec_negotiation::FecError),
    #[error("FEC control-to-carrier binding refused: {0}")]
    FecBinding(&'static str),
}

/// Where this sender can be reached now, for the control channel to tell its receivers after a rebind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LocalPath {
    pub media: SocketAddr,
    pub control: SocketAddr,
    pub generation: u64,
}

/// The most link actions one call applies (a rebind answers with at most one more event, so this only bounds a fault).
const MAX_APPLIED_ACTIONS: usize = 16;

/// The sending side: the carrier, the link manager that decides when it may run, and the directory that keeps each speaker's
/// identity and peer handle across address changes.
pub struct SenderEndpoint<P: DatagramPort> {
    carrier: CarrierSender<P>,
    link: LinkManager,
    directory: PeerDirectory,
}

impl<P: DatagramPort> SenderEndpoint<P> {
    #[must_use]
    pub fn new(mut carrier: CarrierSender<P>, link: LinkManager, max_speakers: usize) -> Self {
        // The carrier's gate starts where the link manager does (down), so nothing is sent before the manager has said the
        // link is up: the manager emits no `Quiesce` for an interface that was never up.
        carrier.set_link_up(link.status().state == LinkState::Up);
        Self {
            carrier,
            link,
            directory: PeerDirectory::new(max_speakers),
        }
    }

    #[must_use]
    pub const fn carrier(&self) -> &CarrierSender<P> {
        &self.carrier
    }

    pub fn carrier_mut(&mut self) -> &mut CarrierSender<P> {
        &mut self.carrier
    }

    #[must_use]
    pub const fn link(&self) -> &LinkManager {
        &self.link
    }

    #[must_use]
    pub const fn directory(&self) -> &PeerDirectory {
        &self.directory
    }

    /// Select the local sender from a freshly revalidated authenticated round.
    /// Routes bind enrolled control peers to the configured speaker identities;
    /// no caller-created proof or boolean can stand in for member acknowledgments.
    /// All checks precede the carrier's atomic local epoch/profile transition.
    ///
    /// This does not perform remote receiver preflight or a distributed cutover.
    /// The control owner still coordinates the group's session, clocks and starts.
    pub fn select_acknowledged_host_fec<A: franken_control::channel::peer::PeerAuthority>(
        &mut self,
        group: franken_stream::carrier::GroupId,
        coordinator: &franken_control::channel::fec_negotiation::FecCoordinator,
        authority: &A,
        session: &franken_session::UnifiedGroupSession,
        member_routes: &[(franken_control::channel::peer::PeerId, u64)],
    ) -> Result<(), EndpointError> {
        let selected = coordinator
            .validated_selection(authority, session)
            .map_err(EndpointError::FecAgreement)?;
        if selected.profile() != fec::PROFILE
            || selected.coding_revision() != fec::CODING_REVISION
            || usize::from(selected.k()) != fec::K
            || usize::from(selected.n()) != fec::N
            || usize::from(selected.datagram_bytes()) != fec::DATAGRAM
        {
            return Err(EndpointError::FecBinding("unsupported exact profile"));
        }
        let proposal = selected.proposal();
        let current = self
            .carrier
            .group_view(group)
            .ok_or(CarrierError::UnknownGroup(group))?;
        if current.stream_id != proposal.stream() || current.epoch != proposal.current_epoch() {
            return Err(EndpointError::FecBinding("stream or epoch changed"));
        }
        if member_routes.len() != selected.members().len() {
            return Err(EndpointError::FecBinding("incomplete member routes"));
        }
        let mut peer_ids = Vec::with_capacity(selected.members().len());
        for member in selected.members() {
            let mut routes = member_routes
                .iter()
                .filter(|(peer, _)| peer == &member.peer);
            let (Some((_, speaker)), None) = (routes.next(), routes.next()) else {
                return Err(EndpointError::FecBinding(
                    "missing or duplicate control peer route",
                ));
            };
            let Some((peer, _)) = self.directory.lookup(*speaker) else {
                return Err(EndpointError::FecBinding("speaker is not announced"));
            };
            if peer_ids.contains(&peer) {
                return Err(EndpointError::FecBinding("duplicate carrier peer route"));
            }
            peer_ids.push(peer);
        }
        self.carrier.select_group_fec(
            group,
            proposal.next_epoch(),
            proposal.origin_ns(),
            &peer_ids,
        )?;
        Ok(())
    }

    /// Where this sender's receivers must now send reports.
    ///
    /// # Errors
    /// [`CarrierError`] when the port cannot say.
    pub fn local_path(&self) -> Result<LocalPath, CarrierError> {
        Ok(LocalPath {
            media: self.carrier.media_addr()?,
            control: self.carrier.control_addr()?,
            generation: self.link.status().generation,
        })
    }

    /// Feed a link event and apply what the manager decides to the carrier. Returns every action taken, in order.
    pub fn on_link_event(&mut self, now_ns: u64, event: LinkEvent) -> Vec<LinkAction> {
        let first = self.link.on_event(now_ns, event);
        self.apply(now_ns, first)
    }

    /// Advance the link manager's timers and apply what is due.
    pub fn on_tick(&mut self, now_ns: u64) -> Vec<LinkAction> {
        let first = self.link.on_tick(now_ns);
        self.apply(now_ns, first)
    }

    fn apply(&mut self, now_ns: u64, first: Vec<LinkAction>) -> Vec<LinkAction> {
        let mut taken = Vec::new();
        let mut pending = VecDeque::from(first);
        while let Some(action) = pending.pop_front() {
            if taken.len() >= MAX_APPLIED_ACTIONS {
                break;
            }
            taken.push(action);
            match action {
                LinkAction::Quiesce { .. } => self.carrier.set_link_up(false),
                LinkAction::Resume { .. } => self.carrier.set_link_up(true),
                LinkAction::Rebind { ip, .. } => {
                    let ok = self.carrier.rebind(ip).is_ok();
                    pending.extend(
                        self.link
                            .on_event(now_ns, LinkEvent::RebindResult { ip, ok }),
                    );
                }
                LinkAction::ReleaseStale { .. } | LinkAction::GiveUp { .. } => {}
            }
        }
        taken
    }

    /// A speaker announced where it can be reached (the control channel authenticated the announcement). A new speaker
    /// becomes a carrier peer; a moved one keeps its identity, handle and sequence and only its addresses change; a stale or
    /// conflicting claim changes nothing. The directory and the carrier change together or not at all.
    ///
    /// # Errors
    /// [`EndpointError`].
    pub fn announce(
        &mut self,
        speaker: u64,
        peer: u32,
        media: SocketAddr,
        control: SocketAddr,
        generation: u64,
    ) -> Result<Announced, EndpointError> {
        let mut trial = self.directory.clone();
        let result = trial.announce(speaker, peer, media, control, generation)?;
        match result {
            Announced::New => {
                let mtu = self.link.config().profile.default_path_mtu;
                self.carrier.add_peer(peer, media, control, mtu)?;
            }
            Announced::Moved { .. } => {
                self.carrier.peer_address_changed(peer, media, control)?;
            }
            Announced::Unchanged => {}
        }
        self.directory = trial;
        Ok(result)
    }

    /// A speaker left the group. What it still had queued is counted by the carrier, not forgotten.
    pub fn leave(&mut self, speaker: u64) -> bool {
        let Some((peer, _)) = self.directory.lookup(speaker) else {
            return false;
        };
        // The carrier may not know the peer if it was never admitted; the directory entry goes either way.
        let _ = self.carrier.remove_peer(peer);
        self.directory.remove(speaker)
    }
}

// ---------------------------------------------------------------------------------------------------------------- UX01

/// The readiness state a transport action implies, or `None` when the action asks for no change. The reason is the local
/// network condition; no reason mentions the WAN, and a transport reason is never a safe-mute fault: local control and
/// playback of what already arrived are not coupled to it.
#[must_use]
pub fn transport_readiness(action: &LinkAction) -> Option<SpeakerReadinessState> {
    let reason = match action {
        LinkAction::Quiesce { reason } | LinkAction::GiveUp { reason } => *reason,
        LinkAction::Rebind { .. } | LinkAction::ReleaseStale { .. } | LinkAction::Resume { .. } => {
            return None;
        }
    };
    Some(readiness_for(reason))
}

/// The readiness state for one transport reason.
#[must_use]
pub fn readiness_for(reason: TransportReason) -> SpeakerReadinessState {
    SpeakerReadinessState::DegradedStandaloneRecovery {
        reason: reason.ux_text().to_owned(),
    }
}

#[cfg(test)]
mod fec_tests;
#[cfg(test)]
mod tests;
