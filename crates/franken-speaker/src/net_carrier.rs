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
//!   datagram to [`MediaPlayout::ingest`], which owns the one `StreamReceiver` admission (MAC, stream, epoch, replay
//!   window). The carrier's own admission is not run in this mode, so nothing is admitted twice.
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
use franken_stream::carrier::{
    CarrierError, CarrierReceiver, CarrierSender, DatagramPort, Lane, MediaSink, PollReport,
    PortFault, Received, SinkVerdict,
};
use franken_stream::link::{
    Announced, DirectoryError, LinkAction, LinkEvent, LinkManager, LinkState, PeerDirectory,
    TransportReason,
};
use franken_stream::playout::{Admission, BLOCK_PAYLOAD_BYTES};
use serde::Serialize;

use crate::SpeakerReadinessState;
use crate::media_playout::{MediaPlayout, MediaRefusal, Preparation, StartRefusal};

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

struct PlayoutSink<'a, O: KernelOps> {
    media: &'a mut MediaPlayout,
    platform: &'a mut PlatformLayer<O>,
    clock: &'a mut GroupClock,
    verdicts: &'a mut EngineVerdicts,
}

impl<O: KernelOps> MediaSink for PlayoutSink<'_, O> {
    fn offer(&mut self, datagram: &[u8]) -> SinkVerdict {
        match self.media.ingest(self.platform, self.clock, datagram) {
            // The datagram was authentic and left the replay window, whatever the engine then decided (late, duplicate,
            // off the timeline): from the sender's side it is consumed, and the window must keep moving on a stale stream.
            Ok(admission) => {
                self.verdicts.record(admission);
                match franken_stream::untrusted_sequence(datagram) {
                    Ok(seq) => SinkVerdict::Admitted { seq },
                    Err(_) => SinkVerdict::Refused,
                }
            }
            Err(MediaRefusal::Clock(_) | MediaRefusal::Resolution(_)) => {
                self.verdicts.backpressure = self.verdicts.backpressure.saturating_add(1);
                SinkVerdict::Backpressure
            }
            Err(MediaRefusal::Stream(_) | MediaRefusal::NotMedia) => {
                self.verdicts.refused = self.verdicts.refused.saturating_add(1);
                SinkVerdict::Refused
            }
        }
    }
}

/// One room's receiving side: the carrier receiver, and the media path that admits and decides. The platform and the group
/// clock stay with the composition root, as for [`MediaPlayout`].
pub struct MediaEndpoint<P: DatagramPort> {
    carrier: CarrierReceiver<P>,
    media: MediaPlayout,
    verdicts: EngineVerdicts,
}

impl<P: DatagramPort> MediaEndpoint<P> {
    #[must_use]
    pub fn new(carrier: CarrierReceiver<P>, media: MediaPlayout) -> Self {
        Self {
            carrier,
            media,
            verdicts: EngineVerdicts::default(),
        }
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

    /// Read what has arrived: control into the inbox, media into the playout engine through [`MediaPlayout::ingest`].
    pub fn poll<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
    ) -> PollReport {
        let mut sink = PlayoutSink {
            media: &mut self.media,
            platform,
            clock,
            verdicts: &mut self.verdicts,
        };
        self.carrier.poll_into(&mut sink)
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
    /// # Errors
    /// [`StartRefusal`].
    pub fn admit_start<O: KernelOps>(
        &mut self,
        platform: &mut PlatformLayer<O>,
        clock: &mut GroupClock,
        sched: franken_clock::group::StartSchedule,
        anchor_frame: u64,
    ) -> Result<franken_clock::group::StartPlan, StartRefusal> {
        self.media.admit_start(platform, clock, sched, anchor_frame)
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
mod tests;
