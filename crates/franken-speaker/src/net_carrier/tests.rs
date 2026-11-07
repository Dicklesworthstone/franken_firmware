//! Tests of the speaker's carrier wiring (`N07`): the P02-backed port over a host kernel that answers with real loopback UDP
//! sockets, and the isolated-loopback end-to-end scenarios that run the real carrier, the real N01 framers, the real link
//! manager and the real N04 playout path against independent sample and state oracles.
//!
//! What a pass here says. The host kernel (`HostKernel`) implements IvoryFalcon's `franken_platform::datagram::DatagramOps`
//! over `std` loopback sockets and answers `Provenance::Simulated`: it stands behind the P02 boundary so that the boundary's
//! own policy functions run over real bytes, and nothing it does is evidence about the Linux leaf, `socketcall` on either
//! ABI, a legacy kernel, an interface, a lease server or a radio. Link events are synthetic and say so. The tests bind
//! `127.0.0.0/8` addresses only. The address-change scenario binds `127.0.0.2`, which a Linux host has and a macOS host does
//! not; on a host without it that scenario fails at its first bind with a message that says so.

use super::*;
use crate::guest_evidence;
use crate::media_playout::{Release, synthetic_ledger};
use franken_clock::group::{GroupClockConfig, ProbeResponse, StartSchedule};
use franken_platform::net::{MSG_TRUNC, SockKind};
use franken_platform::ops::{Provenance, Timespec};
use franken_platform::socket::SocketOps;
use franken_stream::carrier::{
    CarrierLimits, FenceReason, PathOutcome, PortFaults, PumpReport, ReceiverLimits,
    SEQ_AHEAD_LIMIT, STALL_PROBE_NS,
};
use franken_stream::link::{LinkConfig, LinkState, PROFILES};
use franken_stream::playout::{
    BLOCK_FRAMES, BLOCK_NS, CONCEAL_GAIN_Q15, Outcome, PlayoutConfig, PlayoutProfile, Poll,
    frames_to_ns,
};
use franken_stream::{OutboundFrame, StreamId, StreamKey, StreamReceiver};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::io;
use std::net::UdpSocket;
use std::rc::Rc;
use std::time::{Duration, Instant};

const ABI: Abi = Abi::PowerPc32;
const OLD_TIMELINE_NS: u64 = 100_000_000_000;
const ENOSYS_PPC: isize = 38;
const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;

fn key() -> StreamKey {
    StreamKey::from_bytes([0x37; 32])
}

fn stream() -> StreamId {
    StreamId::new(0x0700_0000_0000_0042).expect("nonzero stream id")
}

/// One step of `SplitMix64`: the fault schedule is a function of its seed.
fn splitmix(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ------------------------------------------------------------------------------------------------------- the host kernel

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct HostCalls {
    socket: u64,
    bind: u64,
    sendto: u64,
    recvfrom: u64,
    close: u64,
}

struct HostSocket {
    udp: Option<UdpSocket>,
}

/// IvoryFalcon's `DatagramOps` (and the five-call `SocketOps` under it) over `std` loopback sockets. It checks what the
/// boundary promises: `socket` must arrive with the ABI's datagram type and both `SOCK_NONBLOCK` and `SOCK_CLOEXEC`,
/// `sendto` with flags 0, `recvfrom` with `MSG_TRUNC`. A call that breaks any of them answers `-EINVAL`, so a boundary that
/// stopped passing them would fail every test here. It answers `Provenance::Simulated`.
struct HostKernel {
    time: Rc<Cell<u64>>,
    sockets: BTreeMap<i32, HostSocket>,
    next_fd: i32,
    scratch: Vec<u8>,
    /// A raw `-errno` the next `sendto` answers with instead of sending (one shot).
    inject_send: Option<isize>,
    /// The most address room the boundary ever offered `recvfrom`.
    max_offered_addr: usize,
    calls: HostCalls,
}

impl HostKernel {
    fn new(time: &Rc<Cell<u64>>) -> Self {
        Self {
            time: Rc::clone(time),
            sockets: BTreeMap::new(),
            next_fd: 100,
            scratch: vec![0; 65_527],
            inject_send: None,
            max_offered_addr: 0,
            calls: HostCalls::default(),
        }
    }

    fn open_sockets(&self) -> usize {
        self.sockets.len()
    }

    fn neg(error: &io::Error) -> isize {
        let net = |errno: NetErrno| -(errno.number(ABI) as isize);
        match error.kind() {
            io::ErrorKind::WouldBlock => -11,
            io::ErrorKind::AddrNotAvailable => net(NetErrno::AddrNotAvail),
            io::ErrorKind::ConnectionRefused => net(NetErrno::ConnRefused),
            io::ErrorKind::NetworkUnreachable => net(NetErrno::NetUnreach),
            _ => -5,
        }
    }

    fn udp(&self, fd: i32) -> Option<&UdpSocket> {
        self.sockets.get(&fd).and_then(|socket| socket.udp.as_ref())
    }
}

impl KernelOps for HostKernel {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }
    fn backend_abi(&self) -> Option<Abi> {
        None
    }
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        let now = self.time.get();
        out.secs = i64::try_from(now / 1_000_000_000).unwrap_or(i64::MAX);
        out.nanos = i64::try_from(now % 1_000_000_000).unwrap_or(0);
        0
    }
    fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn open_dev_random(&mut self, _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
        -ENOSYS_PPC
    }
    fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
        -ENOSYS_PPC
    }
    fn close(&mut self, fd: i32) -> isize {
        self.calls.close += 1;
        self.sockets.remove(&fd);
        0
    }
}

impl SocketOps for HostKernel {
    fn socket(&mut self, domain: u32, kind: u32, _protocol: u32) -> isize {
        self.calls.socket += 1;
        let flags = ABI.o_nonblock() | franken_platform::net::SOCK_CLOEXEC;
        if domain != u32::from(Family::Inet.number())
            || kind & 0xF != ABI.sock_type(SockKind::Dgram)
            || kind & flags != flags
        {
            return -22;
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        self.sockets.insert(fd, HostSocket { udp: None });
        fd as isize
    }

    fn bind(&mut self, fd: i32, addr: &[u8]) -> isize {
        self.calls.bind += 1;
        let Ok(addr) = SockAddrIn::from_bytes(addr) else {
            return -22;
        };
        let Some(socket) = self.sockets.get_mut(&fd) else {
            return -9;
        };
        match UdpSocket::bind((Ipv4Addr::from(addr.addr), addr.port)) {
            Ok(udp) => {
                if udp.set_nonblocking(true).is_err() {
                    return -22;
                }
                socket.udp = Some(udp);
                0
            }
            Err(error) => Self::neg(&error),
        }
    }

    fn listen(&mut self, _fd: i32, _backlog: i32) -> isize {
        -ENOSYS_PPC
    }

    fn accept4(&mut self, _fd: i32, _flags: u32) -> isize {
        -ENOSYS_PPC
    }

    fn recv(&mut self, _fd: i32, _buf: &mut [u8], _flags: u32) -> isize {
        // The carrier reads with `recvfrom` so that it knows the sender; the sender-less `recv` is not used here.
        -ENOSYS_PPC
    }
}

impl DatagramOps for HostKernel {
    fn sendto(&mut self, fd: i32, buf: &[u8], flags: u32, addr: &[u8]) -> isize {
        self.calls.sendto += 1;
        if flags != 0 {
            return -22;
        }
        if let Some(errno) = self.inject_send.take() {
            return errno;
        }
        let Ok(to) = SockAddrIn::from_bytes(addr) else {
            return -22;
        };
        let Some(udp) = self.udp(fd) else {
            return -9;
        };
        match udp.send_to(buf, (Ipv4Addr::from(to.addr), to.port)) {
            Ok(sent) => sent as isize,
            Err(error) => Self::neg(&error),
        }
    }

    fn recvfrom(
        &mut self,
        fd: i32,
        buf: &mut [u8],
        flags: u32,
        addr: &mut [u8],
        addr_len: &mut u32,
    ) -> isize {
        self.calls.recvfrom += 1;
        if flags & MSG_TRUNC == 0 {
            return -22;
        }
        self.max_offered_addr = self.max_offered_addr.max(addr.len());
        let Some(udp) = self.sockets.get(&fd).and_then(|socket| socket.udp.as_ref()) else {
            return -9;
        };
        match udp.recv_from(&mut self.scratch) {
            Ok((real, SocketAddr::V4(from))) => {
                let stored = real.min(buf.len());
                buf[..stored].copy_from_slice(&self.scratch[..stored]);
                let sockaddr = SockAddrIn {
                    addr: from.ip().octets(),
                    port: from.port(),
                }
                .to_bytes();
                let written = sockaddr.len().min(addr.len());
                addr[..written].copy_from_slice(&sockaddr[..written]);
                *addr_len = sockaddr.len() as u32;
                real as isize
            }
            Ok((_, SocketAddr::V6(_))) => -22,
            Err(error) => Self::neg(&error),
        }
    }
}

/// A kernel that only keeps time: the admitted platform layer of one room.
struct ClockKernel {
    time: Rc<Cell<u64>>,
}

impl KernelOps for ClockKernel {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }
    fn backend_abi(&self) -> Option<Abi> {
        None
    }
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        let now = self.time.get();
        out.secs = i64::try_from(now / 1_000_000_000).unwrap_or(i64::MAX);
        out.nanos = i64::try_from(now % 1_000_000_000).unwrap_or(0);
        0
    }
    fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn open_dev_random(&mut self, _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
        7
    }
    fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
        -ENOSYS_PPC
    }
    fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
        -ENOSYS_PPC
    }
    fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
        -ENOSYS_PPC
    }
    fn close(&mut self, _fd: i32) -> isize {
        0
    }
}

// ----------------------------------------------------------------------------------------------------- the fault injector

/// What the network does to one media datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Fault {
    Drop,
    Reorder,
}

/// A port that loses and reorders media datagrams on a seeded schedule, below the carrier and above the P02 port. Every
/// decision is recorded, so the schedule in a log is the schedule that ran. Control is never touched.
struct FaultPort<P: DatagramPort> {
    inner: P,
    seed: u64,
    drop_permille: u64,
    reorder_permille: u64,
    media_index: u64,
    /// Datagram indexes `[active.0, active.1)` are subject to faults; the rest always pass.
    active: (u64, u64),
    held: Option<(Vec<u8>, SocketAddr)>,
    schedule: Vec<(u64, Fault)>,
    forwarded: BTreeMap<SocketAddr, u64>,
    largest: usize,
    /// A fault the transport answers every media send with: the kernel refuses, nothing leaves, no index is spent.
    refuse: Option<PortFault>,
    /// The next this-many media sends are accepted by the kernel and lost on the network (recorded in the schedule).
    lose_next: u64,
    /// When set, the bytes of every media datagram the kernel accepts are kept in `recorded`, in order.
    record: bool,
    recorded: Vec<Vec<u8>>,
}

impl<P: DatagramPort> FaultPort<P> {
    fn new(inner: P) -> Self {
        Self {
            inner,
            seed: 0,
            drop_permille: 0,
            reorder_permille: 0,
            media_index: 0,
            active: (0, u64::MAX),
            held: None,
            schedule: Vec::new(),
            forwarded: BTreeMap::new(),
            largest: 0,
            refuse: None,
            lose_next: 0,
            record: false,
            recorded: Vec::new(),
        }
    }

    fn forward(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        self.inner.send_to(lane, bytes, to)?;
        if lane == Lane::Media {
            *self.forwarded.entry(to).or_insert(0) += 1;
            self.largest = self.largest.max(bytes.len());
        }
        Ok(())
    }

    fn decide(&self, index: u64) -> Option<Fault> {
        if index < self.active.0 || index >= self.active.1 {
            return None;
        }
        let draw = splitmix(self.seed ^ index.wrapping_mul(0xA24B_AED4_963E_E407)) % 1000;
        if draw < self.drop_permille {
            Some(Fault::Drop)
        } else if draw < self.drop_permille + self.reorder_permille {
            Some(Fault::Reorder)
        } else {
            None
        }
    }
}

impl<P: DatagramPort> DatagramPort for FaultPort<P> {
    fn send_to(&mut self, lane: Lane, bytes: &[u8], to: SocketAddr) -> Result<(), PortFault> {
        if lane != Lane::Media {
            return self.inner.send_to(lane, bytes, to);
        }
        if let Some(fault) = self.refuse.clone() {
            return Err(fault);
        }
        if self.record {
            self.recorded.push(bytes.to_vec());
        }
        let index = self.media_index;
        self.media_index += 1;
        if self.lose_next > 0 {
            self.lose_next -= 1;
            self.schedule.push((index, Fault::Drop));
            return Ok(());
        }
        match self.decide(index) {
            Some(Fault::Drop) => {
                self.schedule.push((index, Fault::Drop));
                Ok(())
            }
            Some(Fault::Reorder) => {
                self.schedule.push((index, Fault::Reorder));
                if let Some((held, held_to)) = self.held.take() {
                    self.forward(lane, &held, held_to)?;
                }
                self.held = Some((bytes.to_vec(), to));
                Ok(())
            }
            None => {
                let result = self.forward(lane, bytes, to);
                if let Some((held, held_to)) = self.held.take() {
                    self.forward(lane, &held, held_to)?;
                }
                result
            }
        }
    }

    fn recv(&mut self, lane: Lane, buf: &mut [u8]) -> Result<Received, PortFault> {
        self.inner.recv(lane, buf)
    }

    fn local_addr(&self, lane: Lane) -> Result<SocketAddr, PortFault> {
        self.inner.local_addr(lane)
    }

    fn rebind(&mut self, ip: IpAddr) -> Result<(), PortFault> {
        self.inner.rebind(ip)
    }
}

type HostPort = SocketPort<HostKernel>;

fn loopback() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

/// Two ports the host has free right now. A device profile has fixed ports; a host test has to find some. Another process may
/// take one before it is bound, which `open_port` answers by trying again.
fn free_pair(ip: Ipv4Addr) -> (SocketAddr, SocketAddr) {
    let first = UdpSocket::bind((ip, 0)).expect("a free port");
    let second = UdpSocket::bind((ip, 0)).expect("a second free port");
    (
        first.local_addr().expect("first address"),
        second.local_addr().expect("second address"),
    )
}

fn open_port(time: &Rc<Cell<u64>>, ip: Ipv4Addr) -> HostPort {
    for _ in 0..8 {
        let (media, control) = free_pair(ip);
        if let Ok(port) = SocketPort::open(HostKernel::new(time), ABI, media, control) {
            return port;
        }
    }
    panic!("the host kernel could not bind two ports on {ip} in eight tries");
}

// -------------------------------------------------------------------------------------------------- the P02 port, directly

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_micros(200));
    }
}

fn receive_one(port: &mut HostPort, lane: Lane, buf: &mut [u8]) -> Received {
    let mut got = None;
    wait_until("a datagram", || match port.recv(lane, buf) {
        Ok(received) => {
            got = Some(received);
            true
        }
        Err(PortFault::WouldBlock) => false,
        Err(other) => panic!("unexpected fault {other:?}"),
    });
    got.expect("received")
}

#[test]
fn n07_the_p02_port_carries_datagrams_and_names_the_sender_through_the_boundary() {
    let time = Rc::new(Cell::new(0));
    let mut a = open_port(&time, loopback());
    let mut b = open_port(&time, loopback());
    // opening used the seam's own calls: one socket and one bind per lane, no getsockname, no connect
    let calls = a.ops().calls.clone();
    assert_eq!(
        (calls.socket, calls.bind, calls.sendto, calls.recvfrom),
        (2, 2, 0, 0)
    );
    let to = b.local_addr(Lane::Media).expect("b media address");
    assert!(to.ip().is_loopback() && to.port() != 0);

    a.send_to(Lane::Media, b"hello over p02", to).expect("sent");
    let mut buf = [0u8; 64];
    let received = receive_one(&mut b, Lane::Media, &mut buf);
    assert_eq!(&buf[..received.len], b"hello over p02");
    // sendto from the bound socket: the sender is the advertised media address, not an ephemeral one
    assert_eq!(
        received.from,
        Some(a.local_addr(Lane::Media).expect("a media"))
    );

    // the control lane is a socket of its own, with its own source address
    let control_to = b.local_addr(Lane::Control).expect("b control address");
    a.send_to(Lane::Control, b"stop", control_to).expect("sent");
    let received = receive_one(&mut b, Lane::Control, &mut buf);
    assert_eq!(&buf[..received.len], b"stop");
    assert_eq!(
        received.from,
        Some(a.local_addr(Lane::Control).expect("a control"))
    );
    assert_eq!(a.ops().calls.sendto, 2);
    assert!(
        b.ops().max_offered_addr >= 16,
        "the boundary offers room for a sockaddr_in at least"
    );
    // nothing arrived where nothing was sent: a would-block, not a fault
    let mut none = [0u8; 8];
    assert_eq!(a.recv(Lane::Control, &mut none), Err(PortFault::WouldBlock));
}

#[test]
fn n07_the_p02_port_reports_an_oversize_datagram_as_cut_with_its_sender() {
    let time = Rc::new(Cell::new(0));
    let mut a = open_port(&time, loopback());
    let mut b = open_port(&time, loopback());
    let to = b.local_addr(Lane::Media).expect("address");
    a.send_to(Lane::Media, &vec![0xAB; 3000], to).expect("sent");
    let mut buf = vec![0u8; 1105];
    let received = receive_one(&mut b, Lane::Media, &mut buf);
    // MSG_TRUNC told the boundary the datagram was longer than the buffer; the port reports the buffer's length, which the
    // carrier's structure check names as too long, and the sender is known so the flood can be accounted to it
    assert_eq!(received.len, 1105);
    assert_eq!(
        received.from,
        Some(a.local_addr(Lane::Media).expect("a media"))
    );
    assert!(franken_stream::untrusted_sequence(&buf[..1105]).is_err());
}

#[test]
fn n07_a_send_errno_is_classified_by_the_abis_own_numbers() {
    let time = Rc::new(Cell::new(0));
    let mut a = open_port(&time, loopback());
    let b = open_port(&time, loopback());
    let to = b.local_addr(Lane::Media).expect("address");
    for (errno, want) in [
        (NetErrno::MsgSize, PortFault::MessageTooLong),
        (NetErrno::NetUnreach, PortFault::PathUnavailable),
        (NetErrno::AddrNotAvail, PortFault::PathUnavailable),
        (NetErrno::NoBufs, PortFault::Other("ENOBUFS".to_owned())),
    ] {
        a.ops_mut().inject_send = Some(-(errno.number(ABI) as isize));
        assert_eq!(a.send_to(Lane::Media, b"x", to), Err(want), "{errno:?}");
    }
    // the same numbers on the other ABI name other errors: the classification is the ABI's, not the host's
    assert_ne!(
        NetErrno::MsgSize.number(Abi::PowerPc32),
        NetErrno::MsgSize.number(Abi::Mips32)
    );
    // EAGAIN is a would-block, an errno nobody classified is carried as a number
    a.ops_mut().inject_send = Some(-11);
    assert_eq!(a.send_to(Lane::Media, b"x", to), Err(PortFault::WouldBlock));
    a.ops_mut().inject_send = Some(-77);
    assert_eq!(
        a.send_to(Lane::Media, b"x", to),
        Err(PortFault::Other("errno 77".to_owned()))
    );
    // the permitted positive: with no fault the datagram goes
    assert_eq!(a.send_to(Lane::Media, b"x", to), Ok(()));
}

#[test]
fn n07_a_peer_address_round_trips_through_the_platform_key_in_both_families() {
    let v4: SocketAddr = "127.0.0.1:5004".parse().expect("address");
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5006, 0, 3));
    for addr in [v4, v6] {
        assert_eq!(socket_of(peer_of(addr)), addr);
    }
    // the scope of a link-local address is part of the key, so two interfaces never alias
    let (a, b) = (
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5006, 0, 3),
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5006, 0, 4),
    );
    assert_ne!(peer_of(SocketAddr::V6(a)), peer_of(SocketAddr::V6(b)));
}

#[test]
fn n07_a_rebind_keeps_the_configured_ports_closes_the_old_sockets_and_a_failure_keeps_them() {
    let time = Rc::new(Cell::new(0));
    let mut port = open_port(&time, loopback());
    let before = (
        port.local_addr(Lane::Media).expect("media"),
        port.local_addr(Lane::Control).expect("control"),
    );
    assert_eq!(port.ops().open_sockets(), 2);
    // the same address again is no change and no call: the old sockets hold the ports
    let sockets_made = port.ops().calls.socket;
    port.rebind(IpAddr::V4(loopback()))
        .expect("nothing to do is a success");
    assert_eq!(port.ops().calls.socket, sockets_made);
    // an address this host does not have: refused by the kernel, nothing changes, nothing leaks
    let missing: IpAddr = "203.0.113.77".parse().expect("ip");
    assert_eq!(port.rebind(missing), Err(PortFault::PathUnavailable));
    assert_eq!(
        port.ops().open_sockets(),
        2,
        "the failed rebind closed what it opened"
    );
    assert!(port.ops().calls.close >= 1, "and said so to the kernel");
    assert_eq!(
        (
            port.local_addr(Lane::Media).expect("media"),
            port.local_addr(Lane::Control).expect("control")
        ),
        before
    );
    // a family the host kernel does not carry fails the same way and also keeps the old sockets
    assert!(port.rebind("::1".parse().expect("ip")).is_err());
    assert_eq!(port.ops().open_sockets(), 2);
}

// ------------------------------------------------------------------------------------------------------------ the world

/// The source: an independent oracle of what every block of a stream is, a pure function of the stream's tag and the block
/// index. Nothing in the carrier, the framers or the playout path computes it.
fn source_block(tag: u8, index: u64) -> Vec<u8> {
    let mut block: Vec<u8> = (0..BLOCK_PAYLOAD_BYTES)
        .map(|i| {
            let mix = (i % 251) as u64 + index * 7 + u64::from(tag) * 13;
            0x11 + (mix % 200) as u8
        })
        .collect();
    // The pattern alone repeats every 200 blocks (7 and 200 are coprime), so blocks 0 and 200 were the same bytes and the
    // identification oracle named both. The first two frames now carry the block index, so every block of every stream length
    // has bytes of its own, whatever the pattern does.
    block[..8].copy_from_slice(&index.to_be_bytes());
    block
}

#[derive(Debug, Clone)]
struct Heard {
    block: u64,
    outcome: Outcome,
    armed: bool,
    pcm: Vec<u8>,
    /// The room's local clock, and the group time it read, when the engine's decision for this block was taken.
    decided_local_ns: u64,
    decided_group_ns: u64,
}

/// What has stopped in a room. A frozen process reads nothing, reports nothing and decides nothing. A stalled network side reads
/// nothing and reports nothing while the renderer goes on deciding with whatever the room already holds. The two are different
/// faults with different obligations, and a test names which one it injects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stall {
    None,
    Process,
    Ingress,
}

/// Independent counters of what a room has done so far. Nothing here is read back from an expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally {
    heard: usize,
    quiet: u64,
    decided_real: u64,
    media_read: u64,
    reports_sent: u64,
}

impl Tally {
    fn of(room: &Room) -> Self {
        Self {
            heard: room.heard.len(),
            quiet: room.quiet,
            decided_real: room.endpoint.media().engine_stats().decided_real,
            media_read: room.endpoint.carrier().stats().media_read,
            reports_sent: room.endpoint.carrier().stats().reports_sent,
        }
    }
}

/// Blocks whose PCM was handed on at or after their own presentation time: stale audio. The engine decides a block as real only
/// before its presentation (later is `MutedOverdue`); this checks the room's own record of when each decision was taken against
/// the source's schedule `pts`, so it does not rest on the engine's account of itself.
fn decided_too_late(heard: &[Heard], pts: &dyn Fn(u64) -> u64) -> Vec<u64> {
    heard
        .iter()
        .filter(|h| h.decided_group_ns >= pts(h.block))
        .map(|h| h.block)
        .collect()
}

/// The path generation the documented rule gives after the addresses a script told the link manager about, in order: it advances
/// every time the address differs from the one before (the first included), whether or not the address could then be bound. It
/// is counted from the script and not read from the manager.
fn generation_after(script: &[IpAddr]) -> u64 {
    let mut generation = 0;
    let mut previous = None;
    for ip in script {
        if previous != Some(*ip) {
            generation += 1;
        }
        previous = Some(*ip);
    }
    generation
}

struct Room {
    speaker: u64,
    peer: u32,
    endpoint: MediaEndpoint<HostPort>,
    platform: PlatformLayer<ClockKernel>,
    clock: GroupClock,
    heard: Vec<Heard>,
    /// Decisions that prepared nothing (a muted gap, an overdue block, a skip).
    quiet: u64,
    stall: Stall,
    /// Whether the room sends its consumption reports (a test holds them back to see what credit the sender has not yet had).
    reports_enabled: bool,
    time: Rc<Cell<u64>>,
    /// Datagrams the sender handed the kernel for this room's current address, and how many of them are already counted.
    expect_media: u64,
    fwd_seen: u64,
    media_addr: SocketAddr,
    control_addr: SocketAddr,
}

impl Room {
    fn new(
        time: &Rc<Cell<u64>>,
        ip: Ipv4Addr,
        sender_control: SocketAddr,
        speaker: u64,
        peer: u32,
    ) -> Self {
        let port = open_port(time, ip);
        let media_addr = port.local_addr(Lane::Media).expect("media address");
        let control_addr = port.local_addr(Lane::Control).expect("control address");
        let carrier = CarrierReceiver::with_port(
            key(),
            stream(),
            1,
            ReceiverLimits::baseline(),
            port,
            sender_control,
        )
        .expect("receiver over the P02 port")
        .with_peer_id(peer)
        .expect("peer id");
        let config = PlayoutConfig {
            work_ns: 2 * MS,
            lead_ns: MS,
            tolerance_ns: MS,
        };
        let media = MediaPlayout::new(
            StreamReceiver::new(key(), stream(), 1),
            PlayoutProfile::MUSIC,
            config,
            &synthetic_ledger(2 * 1024 * 1024),
            0,
        )
        .expect("media path");
        // The one sanctioned way for a test to get a layer (the P02 pin allows exactly one construction site in the speaker).
        let platform = crate::platform_start::admit_test_layer(
            &guest_evidence::for_abi(ABI).matrix(),
            ClockKernel {
                time: Rc::clone(time),
            },
        )
        .expect("admitted platform layer");
        let clock = GroupClock::new(GroupClockConfig::standard().expect("config"), 1, 7, 100)
            .expect("group clock");
        Self {
            speaker,
            peer,
            endpoint: MediaEndpoint::new(carrier, media),
            platform,
            clock,
            heard: Vec::new(),
            quiet: 0,
            stall: Stall::None,
            reports_enabled: true,
            time: Rc::clone(time),
            expect_media: 0,
            fwd_seen: 0,
            media_addr,
            control_addr,
        }
    }

    /// Four accepted exchanges 10 ms apart starting at `local_origin_ns`; the clock then reads `group_origin_ns` there.
    fn lock(&mut self, local_origin_ns: u64, group_origin_ns: u64) {
        for k in 1..=4_u64 {
            let offset = k * 10 * MS;
            let t1 = local_origin_ns + offset;
            let req = self.clock.next_probe(t1);
            let (epoch, leader) = (self.clock.epoch(), self.clock.leader());
            self.clock
                .on_response(
                    ProbeResponse {
                        epoch,
                        leader,
                        seq: req.seq,
                        t1_echo_ns: req.t1_local_ns,
                        t2_group_ns: group_origin_ns + offset + 400_000,
                        t3_group_ns: group_origin_ns + offset + 450_000,
                    },
                    t1 + 850_000,
                )
                .expect("accepted exchange");
        }
    }

    /// One more exchange, as the control path would feed it, so a long run stays locked.
    fn probe(&mut self, local_ns: u64) {
        let t1 = local_ns - MS;
        let req = self.clock.next_probe(t1);
        let (epoch, leader) = (self.clock.epoch(), self.clock.leader());
        self.clock
            .on_response(
                ProbeResponse {
                    epoch,
                    leader,
                    seq: req.seq,
                    t1_echo_ns: req.t1_local_ns,
                    t2_group_ns: OLD_TIMELINE_NS + t1 + 400_000,
                    t3_group_ns: OLD_TIMELINE_NS + t1 + 450_000,
                },
                t1 + 850_000,
            )
            .expect("accepted exchange");
    }

    /// Take every decision the engine has due, up to a few per call. Returns how many it took.
    fn drain(&mut self) -> usize {
        let mut taken = 0;
        for _ in 0..8 {
            let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
            let local = self.time.get();
            match self
                .endpoint
                .prepare(&mut self.platform, &mut self.clock, &mut out)
                .expect("the platform clock answers")
            {
                Preparation::Prepared(prepared) => {
                    let frames = usize::from(prepared.decision.frames);
                    let decided_group_ns = self.clock.group_ns(local).expect("a fitted clock");
                    self.heard.push(Heard {
                        block: prepared.decision.block,
                        outcome: prepared.decision.outcome,
                        armed: matches!(prepared.release, Release::Armed { .. }),
                        pcm: out[..frames * 4].to_vec(),
                        decided_local_ns: local,
                        decided_group_ns,
                    });
                    taken += 1;
                }
                Preparation::Quiet {
                    poll: Poll::Decision(_),
                    ..
                } => {
                    self.quiet += 1;
                    taken += 1;
                }
                _ => break,
            }
        }
        taken
    }

    /// Take every decision that is due now, however many.
    fn drain_all(&mut self) {
        while self.drain() == 8 {}
    }

    /// This room's addresses changed (its own sockets were rebound).
    fn moved(&mut self, media: SocketAddr, control: SocketAddr) {
        self.media_addr = media;
        self.control_addr = control;
        self.fwd_seen = 0;
    }
}

struct Plan {
    rooms: usize,
    blocks: u64,
    ahead_ns: u64,
    limits: CarrierLimits,
    seed: u64,
    tag: u8,
}

impl Plan {
    fn new(rooms: usize, blocks: u64) -> Self {
        Self {
            rooms,
            blocks,
            ahead_ns: 100 * MS,
            limits: CarrierLimits::baseline(),
            seed: 0x0707,
            tag: 1,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Peak {
    packets: usize,
    bytes: usize,
    in_flight: u64,
}

struct World {
    time: Rc<Cell<u64>>,
    sender: SenderEndpoint<FaultPort<HostPort>>,
    rooms: Vec<Room>,
    start_group: u64,
    anchor_block: u64,
    blocks: u64,
    next_block: u64,
    ahead_ns: u64,
    epoch: u64,
    tag: u8,
    steps: u64,
    seed: u64,
    limits: CarrierLimits,
    link_log: Vec<String>,
    link_actions: Vec<LinkAction>,
    /// The addresses the script has told the link manager about, in order (the construction's first): the independent source of
    /// every expected generation and rebind count.
    address_script: Vec<IpAddr>,
    peaks: BTreeMap<u32, Peak>,
}

impl World {
    fn new(plan: Plan) -> Self {
        let time = Rc::new(Cell::new(0));
        let ip = loopback();
        let carrier = CarrierSender::with_port(
            key(),
            stream(),
            1,
            plan.limits.clone(),
            FaultPort::new(open_port(&time, ip)),
        )
        .expect("sender over the P02 port");
        let link = LinkManager::new(LinkConfig::baseline(PROFILES[0], plan.seed))
            .expect("link configuration");
        let mut sender = SenderEndpoint::new(carrier, link, 8);
        let mut link_log = Vec::new();
        // Bring the link up the way a device would: the interface, then its address. The sockets are already bound there, so
        // the rebind the manager asks for changes nothing, and it resumes.
        sender.on_link_event(0, LinkEvent::InterfaceUp);
        let up = sender.on_link_event(
            0,
            LinkEvent::AddressBound {
                ip: IpAddr::V4(ip),
                lease_ns: Some(3_600 * SEC),
            },
        );
        assert!(
            matches!(
                up.as_slice(),
                [LinkAction::Rebind { .. }, LinkAction::Resume { .. }]
            ),
            "{up:?}"
        );
        link_log.push(format!("0:{up:?}"));
        let path = sender.local_path().expect("sender path");
        let mut rooms = Vec::new();
        for index in 0..plan.rooms {
            let mut room = Room::new(
                &time,
                ip,
                path.control,
                0xA000 + index as u64,
                index as u32 + 1,
            );
            room.lock(0, OLD_TIMELINE_NS);
            rooms.push(room);
        }
        time.set(50 * MS);
        let start_group = rooms[0].clock.group_ns(50 * MS).expect("a fitted clock") + 1_000 * MS;
        for room in &mut rooms {
            let epoch = room.clock.epoch();
            room.endpoint
                .admit_start(
                    &mut room.platform,
                    &mut room.clock,
                    StartSchedule {
                        epoch,
                        start_group_ns: start_group,
                    },
                    0,
                )
                .expect("the start is admitted");
            sender
                .announce(
                    room.speaker,
                    room.peer,
                    room.media_addr,
                    room.control_addr,
                    1,
                )
                .expect("the speaker is announced");
        }
        Self {
            time,
            sender,
            rooms,
            start_group,
            anchor_block: 0,
            blocks: plan.blocks,
            next_block: 0,
            ahead_ns: plan.ahead_ns,
            epoch: 1,
            tag: plan.tag,
            steps: 0,
            seed: plan.seed,
            limits: plan.limits,
            link_log,
            link_actions: up,
            address_script: vec![IpAddr::V4(ip)],
            peaks: BTreeMap::new(),
        }
    }

    fn pts(&self, block: u64) -> u64 {
        self.start_group + frames_to_ns((block - self.anchor_block) * BLOCK_FRAMES)
    }

    fn consume_by(&self, block: u64) -> u64 {
        self.pts(block) - BLOCK_NS
    }

    fn frame(&self, block: u64) -> OutboundFrame {
        OutboundFrame::media(
            block * BLOCK_FRAMES,
            self.pts(block),
            self.consume_by(block),
            source_block(self.tag, block),
        )
    }

    fn group_now(&self) -> u64 {
        self.rooms[0]
            .clock
            .group_ns(self.time.get())
            .expect("a fitted clock")
    }

    fn note(&mut self, group: u64, actions: &[LinkAction]) {
        for action in actions {
            self.link_actions.push(*action);
            if self.link_log.len() < 64 {
                self.link_log.push(format!("{group}:{action:?}"));
            }
        }
    }

    /// A link event, synthetic: no interface is touched.
    fn link(&mut self, event: LinkEvent) -> Vec<LinkAction> {
        let group = self.group_now();
        if let LinkEvent::AddressBound { ip, .. } = event {
            self.address_script.push(ip);
        }
        let actions = self.sender.on_link_event(group, event);
        if self.link_log.len() < 64 {
            self.link_log.push(format!("{group}:{event:?}"));
        }
        self.note(group, &actions);
        actions
    }

    /// The control channel's announcement of the sender's new addresses, which the receivers apply (a stand-in for the N02
    /// message; the carrier's half of it is `set_sender_control`).
    fn tell_rooms_sender_path(&mut self) {
        let path = self.sender.local_path().expect("sender path");
        for room in &mut self.rooms {
            room.endpoint.carrier_mut().set_sender_control(path.control);
        }
    }

    fn peer_sent(&self, peer: u32) -> u64 {
        self.sender
            .carrier()
            .peer_view(peer)
            .expect("peer")
            .counters
            .media_sent_packets
    }

    fn step(&mut self) -> PumpReport {
        let local = self.time.get() + MS;
        self.time.set(local);
        if self.steps % 400 == 399 {
            for room in &mut self.rooms {
                room.probe(local);
            }
        }
        let group = self.group_now();
        let ticked = self.sender.on_tick(group);
        self.note(group, &ticked);
        while self.next_block < self.blocks && self.pts(self.next_block) <= group + self.ahead_ns {
            let block = self.next_block;
            self.next_block += 1;
            let frame = self.frame(block);
            let epoch = self.epoch;
            self.sender
                .carrier_mut()
                .submit_media(epoch, &frame, group)
                .expect("the epoch is current");
        }
        let report = self.sender.carrier_mut().pump(group);
        for index in 0..self.rooms.len() {
            self.service(index);
        }
        for room in &self.rooms {
            if let Some(view) = self.sender.carrier().peer_view(room.peer) {
                let peak = self.peaks.entry(room.peer).or_default();
                peak.packets = peak.packets.max(view.queued_packets);
                peak.bytes = peak.bytes.max(view.queued_bytes);
                peak.in_flight = peak.in_flight.max(view.in_flight);
            }
        }
        self.steps += 1;
        report
    }

    /// Read everything the sender handed the kernel for this room, then take the decisions that are due and report.
    fn service(&mut self, index: usize) {
        match self.rooms[index].stall {
            // The whole process is stopped: nothing is read, reported or decided.
            Stall::Process => return,
            // The network side is stopped: nothing is read or reported, and the renderer goes on with what the room holds.
            Stall::Ingress => {
                self.rooms[index].drain();
                return;
            }
            Stall::None => {}
        }
        let forwarded = self
            .sender
            .carrier()
            .port()
            .forwarded
            .get(&self.rooms[index].media_addr)
            .copied()
            .unwrap_or(0);
        let reporting = self.steps.is_multiple_of(8);
        let room = &mut self.rooms[index];
        room.expect_media += forwarded - room.fwd_seen;
        room.fwd_seen = forwarded;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            room.endpoint.poll(&mut room.platform, &mut room.clock);
            if room.endpoint.carrier().stats().media_read >= room.expect_media {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "room {}: the sender handed the kernel {} datagrams but {} arrived",
                room.peer,
                room.expect_media,
                room.endpoint.carrier().stats().media_read
            );
            std::thread::sleep(Duration::from_micros(200));
        }
        room.drain();
        if reporting && room.reports_enabled {
            room.endpoint.report().expect("the report is sent");
        }
    }

    fn run_to_group(&mut self, target: u64) {
        while self.group_now() < target {
            self.step();
        }
    }

    /// The path generation the script so far implies; see [`generation_after`].
    fn expected_generation(&self) -> u64 {
        generation_after(&self.address_script)
    }

    /// Rebinds the carrier is expected to have accepted, counted from the link manager's `Rebind` actions (the construction's
    /// included) less those for an address the loopback-only profile refuses before any socket is touched. Not read from the
    /// carrier's counters.
    fn expected_port_rebinds(&self) -> u64 {
        self.link_actions
            .iter()
            .filter(|action| matches!(action, LinkAction::Rebind { ip, .. } if ip.is_loopback()))
            .count() as u64
    }

    /// The sender's kernel calls, `(socket, bind, close)`, the accepted rebinds imply: two sockets to open the port, and two more
    /// (and two closes) for each rebind onto an address the port was not already bound to. The same address again is no change
    /// and no call.
    fn expected_kernel_calls(&self) -> (u64, u64, u64) {
        let mut bound = IpAddr::V4(loopback());
        let mut replacements = 0;
        for action in &self.link_actions {
            if let LinkAction::Rebind { ip, .. } = action
                && ip.is_loopback()
                && *ip != bound
            {
                replacements += 1;
                bound = *ip;
            }
        }
        (2 + 2 * replacements, 2 + 2 * replacements, 2 * replacements)
    }

    /// The sender's own kernel's call counters.
    fn sender_kernel_calls(&self) -> &HostCalls {
        &self.sender.carrier().port().inner.ops().calls
    }

    /// One coarse step of an outage: `dt` of local time passes in one go, every room keeps its clock locked, the sender is asked
    /// to send what is due (its transport may refuse it), and every room, whose network side is fine, goes on deciding. The
    /// source goes on in real time but is sampled: one block per step, the newest whose presentation time is within reach.
    /// Returns the block submitted, if any.
    fn coarse_step(&mut self, dt: u64) -> Option<u64> {
        let local = self.time.get() + dt;
        self.time.set(local);
        for room in &mut self.rooms {
            room.probe(local);
        }
        let group = self.group_now();
        let ticked = self.sender.on_tick(group);
        self.note(group, &ticked);
        let due = group + self.ahead_ns;
        let mut newest = self.next_block;
        while newest + 1 < self.blocks && self.pts(newest + 1) <= due {
            newest += 1;
        }
        let submitted = if newest < self.blocks && self.pts(newest) <= due {
            let frame = self.frame(newest);
            let epoch = self.epoch;
            self.sender
                .carrier_mut()
                .submit_media(epoch, &frame, group)
                .expect("the epoch is current");
            self.next_block = newest + 1;
            Some(newest)
        } else {
            None
        };
        self.sender.carrier_mut().pump(group);
        for index in 0..self.rooms.len() {
            self.service(index);
            self.rooms[index].drain_all();
        }
        self.steps += 1;
        submitted
    }
}

/// What a room heard, after every sample was held to the source oracle.
#[derive(Debug, Default)]
struct Summary {
    real: u64,
    concealed: u64,
    max_run: u8,
    first_real: Option<(u64, bool)>,
}

fn check_room(room: &Room, tag: u8, submitted: u64) -> Summary {
    let mut summary = Summary::default();
    let mut last_real: Option<&Heard> = None;
    for heard in &room.heard {
        match heard.outcome {
            Outcome::Real => {
                assert!(
                    heard.block < submitted,
                    "room {}: block {}",
                    room.peer,
                    heard.block
                );
                assert_eq!(
                    heard.pcm,
                    source_block(tag, heard.block),
                    "room {} block {}: the samples are the source's",
                    room.peer,
                    heard.block
                );
                // independent identification: the bytes equal exactly one source block, and it is the one named
                let named: Vec<u64> = (0..submitted)
                    .filter(|candidate| source_block(tag, *candidate) == heard.pcm)
                    .collect();
                assert_eq!(named, vec![heard.block], "room {}", room.peer);
                summary.real += 1;
                if summary.first_real.is_none() {
                    summary.first_real = Some((heard.block, heard.armed));
                }
                last_real = Some(heard);
            }
            Outcome::Concealed { run } => {
                assert!(
                    (1..=PlayoutProfile::MUSIC.max_conceal_blocks).contains(&run),
                    "room {}: run {run}",
                    room.peer
                );
                let real = last_real.expect("a concealed block follows a real one");
                for (c, r) in heard
                    .pcm
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .zip(real.pcm.as_chunks::<2>().0.iter())
                {
                    let c = i32::from(i16::from_be_bytes([c[0], c[1]]));
                    let r = i32::from(i16::from_be_bytes([r[0], r[1]]));
                    assert!(
                        c.abs() <= r.abs(),
                        "concealment is never louder than the source"
                    );
                    if run == 1 {
                        assert_eq!(c, (r * CONCEAL_GAIN_Q15[0] + 16384) >> 15);
                    }
                }
                summary.concealed += 1;
                summary.max_run = summary.max_run.max(run);
            }
            other => panic!(
                "room {}: only real or concealed blocks are prepared, got {other:?}",
                room.peer
            ),
        }
    }
    summary
}

fn real_blocks(room: &Room) -> Vec<u64> {
    room.heard
        .iter()
        .filter(|heard| heard.outcome == Outcome::Real)
        .map(|heard| heard.block)
        .collect()
}

fn observe(case: &str, world: &World, extra: serde_json::Value) {
    let carrier = world.sender.carrier();
    let rooms: Vec<serde_json::Value> = world
        .rooms
        .iter()
        .map(|room| {
            let view = carrier.peer_view(room.peer);
            serde_json::json!({
                "peer": room.peer,
                "heard_real": room.heard.iter().filter(|h| h.outcome == Outcome::Real).count(),
                "heard_concealed": room.heard.iter().filter(|h| matches!(h.outcome, Outcome::Concealed { .. })).count(),
                "quiet_decisions": room.quiet,
                "sender_side": view.as_ref().map(|v| serde_json::to_value(&v.counters).expect("counters")),
                "queued_packets": view.as_ref().map(|v| v.queued_packets),
                "queued_bytes": view.as_ref().map(|v| v.queued_bytes),
                "receiver": serde_json::to_value(room.endpoint.carrier().stats()).expect("stats"),
                "sink": serde_json::to_value(room.endpoint.carrier().sink_counters()).expect("sink"),
                "n01": serde_json::to_value(room.endpoint.media().receiver_counters()).expect("n01"),
                "engine": serde_json::to_value(room.endpoint.media().engine_stats()).expect("engine"),
                "verdicts": serde_json::to_value(room.endpoint.verdicts()).expect("verdicts"),
            })
        })
        .collect();
    let schedule: Vec<serde_json::Value> = carrier
        .port()
        .schedule
        .iter()
        .map(|(index, fault)| serde_json::json!([index, fault]))
        .collect();
    println!(
        "N07-OBSERVED {}",
        serde_json::json!({
            "case": case,
            "seed": world.seed,
            "provenance": "simulated_host_loopback",
            "blocks": world.blocks,
            "steps": world.steps,
            "fault_schedule": schedule,
            "link_log": world.link_log,
            "carrier": serde_json::to_value(carrier.stats()).expect("carrier stats"),
            "port_faults": serde_json::to_value(carrier.faults()).expect("port faults"),
            "largest_datagram_bytes": carrier.port().largest,
            "rooms": rooms,
            "extra": extra,
            "cpu_memory": "not_measured",
        })
    );
}

// ----------------------------------------------------------------------------------------------------------- scenarios

/// An N01 datagram's size on the wire: the 64-byte header, a full 1024-byte block, the 16-byte tag.
const WIRE_BLOCK: u64 = 64 + 1024 + 16;

fn dropped_total(counters: &franken_stream::carrier::PeerCounters) -> u64 {
    counters.media_dropped_overflow_packets
        + counters.media_dropped_aggregate_packets
        + counters.media_dropped_late_packets
        + counters.media_dropped_fenced_packets
        + counters.media_dropped_send_error_packets
}

/// Per peer, `submitted = sent + dropped + queued`, in packets and in wire bytes, at every call boundary.
fn assert_conserved(world: &World, scenario: &str) {
    for room in &world.rooms {
        let view = world.sender.carrier().peer_view(room.peer).expect("peer");
        let c = &view.counters;
        assert_eq!(
            c.media_submitted_packets,
            c.media_sent_packets + dropped_total(c) + view.queued_packets as u64,
            "{scenario}: peer {} packets",
            room.peer
        );
        let dropped_bytes = c.media_dropped_overflow_bytes
            + c.media_dropped_aggregate_bytes
            + c.media_dropped_late_bytes
            + c.media_dropped_fenced_bytes
            + c.media_dropped_send_error_bytes;
        assert_eq!(
            c.media_submitted_bytes,
            c.media_sent_bytes + dropped_bytes + view.queued_bytes as u64,
            "{scenario}: peer {} bytes",
            room.peer
        );
    }
}

fn assert_n01_clean(room: &Room, scenario: &str) {
    let n01 = room.endpoint.media().receiver_counters();
    assert_eq!(
        (
            n01.rejected_authentication,
            n01.rejected_replay,
            n01.rejected_future_sequence,
            n01.rejected_stale_epoch,
            n01.rejected_wrong_stream
        ),
        (0, 0, 0, 0, 0),
        "{scenario}: room {}",
        room.peer
    );
}

#[test]
fn n07_s1_zero_loss_paced_delivery_into_the_playout_path() {
    let blocks = 48;
    let mut world = World::new(Plan::new(2, blocks));
    let last = world.pts(blocks - 1);
    world.run_to_group(last);
    for room in &world.rooms {
        let summary = check_room(room, world.tag, blocks);
        assert_eq!(
            (summary.real, summary.concealed),
            (blocks, 0),
            "room {}",
            room.peer
        );
        assert_eq!(
            summary.first_real,
            Some((0, true)),
            "block 0 is prepared while armed and is not lost"
        );
        let view = world.sender.carrier().peer_view(room.peer).expect("peer");
        let c = &view.counters;
        assert_eq!(
            (c.media_submitted_packets, c.media_sent_packets),
            (blocks, blocks)
        );
        assert_eq!(c.media_sent_bytes, blocks * WIRE_BLOCK);
        assert_eq!(dropped_total(c), 0);
        assert_eq!(c.window_stalled_pumps, 0);
        assert!(view.reported_next > 0, "reports flowed back");
        let rx = room.endpoint.carrier().stats();
        assert_eq!(
            (rx.media_read, rx.media_accepted, rx.media_rejected),
            (blocks, blocks, 0)
        );
        assert_eq!(room.endpoint.verdicts().count("admitted"), blocks);
        assert_eq!(room.endpoint.media().engine_stats().decided_real, blocks);
        assert_eq!(room.endpoint.media().receiver_counters().accepted, blocks);
        assert_n01_clean(room, "S1");
    }
    assert_conserved(&world, "S1");
    // zero-loss overhead, measured: a datagram is exactly header + block + tag, and costs 28 more bytes of IP and UDP
    assert_eq!(world.sender.carrier().port().largest as u64, WIRE_BLOCK);
    // The construction brings the link up, and a first address always asks for a rebind: the manager decided exactly one (the log
    // above asserts it), the carrier executed it, and the port, whose sockets were already bound on that address, accepted it
    // as no change. So one rebind is counted and the kernel was called for nothing but the two sockets that opened the port. The
    // expectation is the script's and the kernel's own counters, not the carrier's.
    let rebinds = world.expected_port_rebinds();
    assert_eq!(rebinds, 1, "one Rebind action in the construction");
    assert_eq!(
        world.sender.carrier().faults(),
        &PortFaults {
            rebinds,
            ..PortFaults::default()
        }
    );
    let (sockets, binds, closes) = world.expected_kernel_calls();
    assert_eq!((sockets, binds, closes), (2, 2, 0));
    let calls = world.sender_kernel_calls();
    assert_eq!(
        (calls.socket, calls.bind, calls.close),
        (sockets, binds, closes)
    );
    assert_eq!(
        world.expected_generation(),
        1,
        "one address, one generation"
    );
    observe(
        "S1",
        &world,
        serde_json::json!({
            "wire_block_bytes": WIRE_BLOCK,
            "link_bytes_per_block": WIRE_BLOCK + 28,
            "payload_efficiency_permille": 1024 * 1000 / (WIRE_BLOCK + 28),
        }),
    );
}

/// What a peer that stopped answering costs the sender, whichever way it stopped: no more new datagrams than its window holds, then
/// only probes (its newest datagram again, one per interval of the stall; they are not media and take no sequence number), bounded
/// queues, and its own oldest frames dropped for it.
fn assert_stalled_sender_is_bounded(world: &World, peer: u32, sent_at_stall: u64, stall_ns: u64) {
    let sent_while_stalled = world.peer_sent(peer) - sent_at_stall;
    assert!(
        sent_while_stalled <= world.limits.window_packets,
        "a stalled peer was sent {sent_while_stalled} new datagrams"
    );
    let probes = world.sender.carrier().control_stats().probes_sent;
    assert!(
        probes <= stall_ns / STALL_PROBE_NS + 1,
        "a stalled peer was probed {probes} times"
    );
    let limits = &world.limits;
    let peak = world.peaks[&peer];
    assert!(peak.packets <= limits.peer_queue_packets, "{peak:?}");
    assert!(peak.bytes <= limits.peer_queue_bytes, "{peak:?}");
    assert!(peak.in_flight <= limits.window_packets, "{peak:?}");
    let counters = world
        .sender
        .carrier()
        .peer_view(peer)
        .expect("the stalled peer")
        .counters;
    assert!(counters.window_stalled_pumps > 0, "{counters:?}");
    assert!(
        counters.media_dropped_overflow_packets + counters.media_dropped_late_packets > 0,
        "its own oldest frames were dropped: {counters:?}"
    );
}

/// The healthy rooms of a stalled-peer world paid nothing for the slow one.
fn assert_healthy_rooms_paid_nothing(world: &World, healthy: usize, scenario: &str) {
    for room in &world.rooms[..healthy] {
        let summary = check_room(room, world.tag, world.blocks);
        assert_eq!(
            (summary.real, summary.concealed),
            (world.blocks, 0),
            "room {} paid nothing for the slow one",
            room.peer
        );
        let c = world
            .sender
            .carrier()
            .peer_view(room.peer)
            .expect("peer")
            .counters;
        assert_eq!(dropped_total(&c), 0, "peer {}", room.peer);
        assert_n01_clean(room, scenario);
    }
}

#[test]
fn n07_s2_a_slow_peer_is_isolated_bounded_and_recovers_with_fresh_audio_only() {
    let blocks = 200;
    let mut world = World::new(Plan::new(3, blocks));
    let freeze_block = 50;
    world.run_to_group(world.pts(freeze_block));
    // The whole process of room 3 stops here: it reads nothing, reports nothing and decides nothing, while its clock goes on (a
    // stalled network side with a live renderer is S2b). The first version of this test took the first block presented at the
    // freeze to be stale: it was not. Block 50's cutoff comes before its presentation by the work, the lead and the clock's
    // uncertainty, so by the step in which the group clock reached its presentation time the engine had already decided it
    // (in time, `Real`); the freeze began after that. What can be stale is only what is decided after the freeze, and the
    // oracle below says so from the room's own record of when each decision was taken.
    let freeze_local = world.time.get();
    let freeze_group = world.group_now();
    world.rooms[2].stall = Stall::Process;
    let at_freeze = Tally::of(&world.rooms[2]);
    let held_at_freeze = {
        let stats = world.rooms[2].endpoint.media().engine_stats();
        stats.admitted - stats.decided_real
    };
    let sent_at_freeze = world.peer_sent(3);
    world.run_to_group(world.pts(110));
    let thaw_local = world.time.get();
    let thaw_group = world.group_now();
    assert_eq!(
        Tally::of(&world.rooms[2]),
        at_freeze,
        "a frozen process read, reported and decided nothing"
    );
    assert_stalled_sender_is_bounded(
        &world,
        3,
        sent_at_freeze,
        world.pts(110) - world.pts(freeze_block),
    );
    let peak = world.peaks[&3];
    world.rooms[2].stall = Stall::None;
    world.run_to_group(world.pts(blocks - 1));

    assert_healthy_rooms_paid_nothing(&world, 2, "S2");
    let slow = &world.rooms[2];
    let summary = check_room(slow, world.tag, blocks);
    let real = real_blocks(slow);
    assert!(
        real.windows(2).all(|pair| pair[0] < pair[1]),
        "no block is heard twice or out of order"
    );
    // No PCM was handed on at or after its own presentation time, by the source's schedule.
    let pts = |block: u64| world.pts(block);
    assert_eq!(
        decided_too_late(&slow.heard, &pts),
        Vec::<u64>::new(),
        "a block was decided after it should have been heard"
    );
    // Every decision was taken either before the freeze or after the return, never inside it, and what was decided after the
    // return is presented after it.
    for heard in &slow.heard {
        assert!(
            heard.decided_local_ns <= freeze_local || heard.decided_local_ns >= thaw_local,
            "block {} was decided at {} ns, inside the freeze {freeze_local}..{thaw_local}",
            heard.block,
            heard.decided_local_ns
        );
        if heard.decided_local_ns >= thaw_local {
            assert!(
                world.pts(heard.block) > thaw_group,
                "block {} was decided after the return but presented before it",
                heard.block
            );
        }
    }
    // The block at the freeze boundary was heard, in time, before the freeze.
    let boundary = slow
        .heard
        .iter()
        .find(|heard| heard.block == freeze_block)
        .expect("block 50 was decided before the freeze");
    assert!(
        boundary.decided_local_ns <= freeze_local
            && boundary.decided_group_ns < world.pts(freeze_block)
            && boundary.decided_group_ns <= freeze_group,
        "block 50 was decided at group {} ns, presentation {} ns, freeze {freeze_group} ns",
        boundary.decided_group_ns,
        world.pts(freeze_block)
    );
    // The blocks it held and could not present in time were refused PCM by the engine itself: each is an overdue decision.
    let overdue = slow.endpoint.media().engine_stats().decided_muted_overdue;
    assert!(
        overdue >= held_at_freeze && overdue > 0,
        "{overdue} overdue decisions for {held_at_freeze} blocks held at the freeze"
    );
    assert!(
        (blocks - 20..blocks).all(|block| real.contains(&block)),
        "the room recovered and hears the live stream"
    );
    assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
    assert!(
        slow.endpoint.verdicts().count("late") > 0,
        "the backlog it had missed arrived after its cutoff and was not played"
    );
    assert_conserved(&world, "S2");
    observe(
        "S2",
        &world,
        serde_json::json!({
            "fault_model": "frozen_process",
            "frozen_from_block": freeze_block,
            "freeze_local_ns": freeze_local,
            "thaw_local_ns": thaw_local,
            "thawed_at_group_ns": thaw_group,
            "held_at_freeze": held_at_freeze,
            "overdue_decisions": overdue,
            "peak_peer3": { "packets": peak.packets, "bytes": peak.bytes, "in_flight": peak.in_flight },
        }),
    );
}

#[test]
fn n07_s2b_a_stalled_network_side_with_a_live_renderer_plays_what_it_holds_and_then_nothing_old() {
    let blocks = 200;
    let mut world = World::new(Plan::new(3, blocks));
    let stall_block = 50;
    world.run_to_group(world.pts(stall_block));
    // Only the network side of room 3 stops: it reads and reports nothing, its renderer and clock go on.
    let stall_local = world.time.get();
    world.rooms[2].stall = Stall::Ingress;
    let at_stall = Tally::of(&world.rooms[2]);
    let (admitted_at_stall, held_at_stall) = {
        let stats = world.rooms[2].endpoint.media().engine_stats();
        (stats.admitted, stats.admitted - stats.decided_real)
    };
    let sent_at_stall = world.peer_sent(3);
    world.run_to_group(world.pts(110));
    let thaw_local = world.time.get();
    let thaw_group = world.group_now();
    let during = Tally::of(&world.rooms[2]);
    assert_eq!(
        (during.media_read, during.reports_sent),
        (at_stall.media_read, at_stall.reports_sent),
        "a stalled network side reads and reports nothing"
    );
    // The renderer did not stop: it played, in time, the blocks it already held (and no others: none arrived), and then it
    // had nothing to decide with.
    let played = during.decided_real - at_stall.decided_real;
    assert!(
        played > 0 && played <= held_at_stall,
        "the renderer played {played} of the {held_at_stall} blocks it held"
    );
    assert!(
        during.quiet > at_stall.quiet,
        "after the blocks it held ran out it decided silence"
    );
    assert_stalled_sender_is_bounded(
        &world,
        3,
        sent_at_stall,
        world.pts(110) - world.pts(stall_block),
    );
    let peak = world.peaks[&3];
    world.rooms[2].stall = Stall::None;
    world.run_to_group(world.pts(blocks - 1));

    assert_healthy_rooms_paid_nothing(&world, 2, "S2b");
    let slow = &world.rooms[2];
    let summary = check_room(slow, world.tag, blocks);
    let pts = |block: u64| world.pts(block);
    assert_eq!(
        decided_too_late(&slow.heard, &pts),
        Vec::<u64>::new(),
        "a block was decided after it should have been heard"
    );
    // What was played while the network side was stalled is what the room already held: blocks admitted before the stall.
    for heard in slow.heard.iter().filter(|heard| {
        heard.outcome == Outcome::Real
            && heard.decided_local_ns > stall_local
            && heard.decided_local_ns < thaw_local
    }) {
        assert!(
            heard.block < admitted_at_stall,
            "block {} was played during the stall but had not been admitted before it ({admitted_at_stall} had)",
            heard.block
        );
    }
    // What was decided after the return is presented after it; the backlog it then read was late and was not played.
    for heard in slow
        .heard
        .iter()
        .filter(|heard| heard.decided_local_ns >= thaw_local)
    {
        assert!(
            world.pts(heard.block) > thaw_group,
            "block {} was decided after the return but presented before it",
            heard.block
        );
    }
    assert!(
        slow.endpoint.verdicts().count("late") > 0,
        "the backlog it read on return was late and was not played"
    );
    let real = real_blocks(slow);
    assert!(
        (blocks - 20..blocks).all(|block| real.contains(&block)),
        "the room recovered and hears the live stream"
    );
    assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
    assert_conserved(&world, "S2b");
    observe(
        "S2b",
        &world,
        serde_json::json!({
            "fault_model": "stalled_network_side_live_renderer",
            "stalled_from_block": stall_block,
            "held_at_stall": held_at_stall,
            "played_while_stalled": played,
            "thawed_at_group_ns": thaw_group,
            "peak_peer3": { "packets": peak.packets, "bytes": peak.bytes, "in_flight": peak.in_flight },
        }),
    );
}

#[test]
fn n07_s3_control_is_sent_first_under_media_saturation_and_media_still_flows() {
    let mut plan = Plan::new(2, 120);
    plan.limits.pace_bytes_per_sec = 200_000;
    plan.limits.peer_load_bytes_per_sec = 100_000;
    plan.ahead_ns = 450 * MS;
    let mut world = World::new(plan);
    world.run_to_group(world.pts(40));
    let backlog = world
        .sender
        .carrier()
        .peer_view(1)
        .expect("peer 1")
        .queued_packets;
    assert!(backlog > 4, "the pacer is saturated: {backlog} queued");
    // a stop for peer 1 goes out in the very pump after it is submitted, ahead of the media backlog
    world
        .sender
        .carrier_mut()
        .submit_control(1, b"STOP")
        .expect("queued");
    let report = world.step();
    assert_eq!(report.control_sent, 1, "{report:?}");
    assert!(
        world
            .sender
            .carrier()
            .peer_view(1)
            .expect("peer 1")
            .queued_packets
            > 0,
        "the media backlog was still queued behind it"
    );
    let mut stops: Vec<Vec<u8>> = Vec::new();
    wait_until("the stop", || {
        let room = &mut world.rooms[0];
        room.endpoint.poll(&mut room.platform, &mut room.clock);
        stops.extend(room.endpoint.carrier_mut().take_control(8));
        !stops.is_empty()
    });
    assert_eq!(stops, vec![b"STOP".to_vec()]);

    // a control flood is bounded by its own queue and per-pump budget, and media is not starved by it
    let sent_before = world.peer_sent(1) + world.peer_sent(2);
    let control_spent_before = world.sender.carrier().control_stats().spent_bytes;
    let mut control_sent = 0_u32;
    for _ in 0..50 {
        for _ in 0..6 {
            // refusals are the point; the counters below say how many
            let _ = world.sender.carrier_mut().submit_control(2, b"flood");
        }
        control_sent += world.step().control_sent;
    }
    let media = world.peer_sent(1) + world.peer_sent(2) - sent_before;
    // control is charged to the interface bucket and to its own share (1/8 of 200,000 B/s, plus a burst of four largest
    // control datagrams): it spends no more than that, and media gets the rest of the 50 ms * 200 B/ms, less one datagram
    let control_spent = world.sender.carrier().control_stats().spent_bytes - control_spent_before;
    assert!(
        control_spent <= 2240 + 25 * 50,
        "control spent {control_spent} B"
    );
    assert!(
        media * 1132 + control_spent + 1132 > 50 * 200,
        "media {media} datagrams, control {control_spent} B"
    );
    assert!(media >= 5, "media got {media} datagrams");
    assert!(
        control_sent <= 4 * 50,
        "control_per_pump bounds it: {control_sent}"
    );
    let two = world
        .sender
        .carrier()
        .peer_view(2)
        .expect("peer 2")
        .counters;
    assert!(two.control_rejected_full > 0, "{two:?}");
    assert!(
        world.rooms[1]
            .endpoint
            .carrier()
            .stats()
            .control_dropped_full
            > 0,
        "the receiver's control inbox is bounded too"
    );
    let limits = world.limits.clone();
    for peer in [1_u32, 2] {
        let peak = world.peaks[&peer];
        assert!(
            peak.packets <= limits.peer_queue_packets,
            "peer {peer}: {peak:?}"
        );
        assert!(
            peak.bytes <= limits.peer_queue_bytes,
            "peer {peer}: {peak:?}"
        );
        let c = world
            .sender
            .carrier()
            .peer_view(peer)
            .expect("peer")
            .counters;
        assert!(
            c.media_dropped_overflow_packets + c.media_dropped_late_packets > 0,
            "congestion dropped the oldest frames of peer {peer}: {c:?}"
        );
    }
    for room in &world.rooms {
        check_room(room, world.tag, world.blocks);
    }
    assert_conserved(&world, "S3");
    observe(
        "S3",
        &world,
        serde_json::json!({
            "media_datagrams_in_50ms": media,
            "control_sent_in_50ms": control_sent,
            "pace_bytes_per_sec": 200_000,
        }),
    );
}

#[test]
fn n07_s4_interface_and_address_events_keep_identity_resume_muted_and_refuse_stale_paths() {
    let blocks = 220;
    let mut world = World::new(Plan::new(2, blocks));
    let ip1 = IpAddr::V4(loopback());
    let ip2: IpAddr = "127.0.0.2".parse().expect("ip");
    let ports_before = (
        world.sender.carrier().media_addr().expect("media").port(),
        world
            .sender
            .carrier()
            .control_addr()
            .expect("control")
            .port(),
    );

    // the interface goes down: nothing is sent, queues stay bounded, audio ages out instead of being replayed
    world.run_to_group(world.pts(30));
    let sent_before = world.peer_sent(1);
    assert_eq!(
        world.link(LinkEvent::InterfaceDown),
        vec![LinkAction::Quiesce {
            reason: TransportReason::InterfaceDown
        }]
    );
    world.run_to_group(world.pts(60));
    assert_eq!(
        world.peer_sent(1),
        sent_before,
        "nothing was sent while the link was down"
    );
    assert!(world.sender.carrier().stats().link_down_pumps > 0);
    let up_group = world.group_now();
    let up = world.link(LinkEvent::InterfaceUp);
    let generation = world.expected_generation();
    assert_eq!(generation, 1, "one address told so far");
    assert!(
        matches!(
            up.as_slice(),
            [LinkAction::Resume { ip, generation: got }] if *ip == ip1 && *got == generation
        ),
        "the same address is still bound: resume without a rebind or a new generation, got {up:?}"
    );
    world.run_to_group(world.pts(90));
    let first_fresh = (sent_before..blocks)
        .find(|block| world.consume_by(*block) >= up_group)
        .expect("a block still fresh at the return");

    // the sender's own address changes: a real rebind on the same configured ports, the old path is released
    let moved = world.link(LinkEvent::AddressBound {
        ip: ip2,
        lease_ns: None,
    });
    assert_eq!(
        moved,
        vec![
            LinkAction::Quiesce {
                reason: TransportReason::AddressChanged
            },
            LinkAction::Rebind {
                ip: ip2,
                attempt: 1
            },
            LinkAction::ReleaseStale { old_ip: ip1 },
            LinkAction::Resume {
                ip: ip2,
                generation: world.expected_generation()
            },
        ]
    );
    assert_eq!(world.expected_generation(), 2);
    world.tell_rooms_sender_path();
    let media_now = world.sender.carrier().media_addr().expect("media");
    assert_eq!(media_now.ip(), ip2);
    assert_eq!(
        media_now.port(),
        ports_before.0,
        "the configured ports are kept"
    );
    world.run_to_group(world.pts(115));

    // a room moves: identity and sequence are kept, and until the sender is told, its reports from the new path are refused
    let ip3 = Ipv4Addr::new(127, 0, 0, 3);
    let (media3, control3) = world.rooms[1]
        .endpoint
        .carrier_mut()
        .rebind(IpAddr::V4(ip3))
        .expect("the room rebinds");
    world.rooms[1].moved(media3, control3);
    let refused_before = world.sender.carrier().stats().reports_unknown_source;
    // seven blocks to the old path: fewer than the window, so the peer is not stalled when the move is announced
    world.run_to_group(world.pts(122));
    assert!(
        world.sender.carrier().stats().reports_unknown_source > refused_before,
        "reports from a path that is not registered are refused"
    );
    let accepted_before = world
        .sender
        .carrier()
        .peer_view(2)
        .expect("peer 2")
        .counters
        .reports_accepted;
    let (speaker, peer) = (world.rooms[1].speaker, world.rooms[1].peer);
    let announced = world
        .sender
        .announce(speaker, peer, media3, control3, 2)
        .expect("the move is announced");
    assert!(
        matches!(announced, Announced::Moved { .. }),
        "{announced:?}"
    );
    world.run_to_group(world.pts(160));
    assert!(
        world
            .sender
            .carrier()
            .peer_view(2)
            .expect("peer 2")
            .counters
            .reports_accepted
            > accepted_before,
        "the new path's reports are accepted once it is announced"
    );
    let held = world.sender.directory().lookup(speaker).expect("known");
    assert_eq!(
        (held.0, held.1.media, held.1.control, held.1.generation),
        (peer, media3, control3, 2),
        "the speaker keeps its identity and handle across the move"
    );

    // an address outside the declared profile is refused before any socket changes, and the manager backs off
    let bad: IpAddr = "203.0.113.77".parse().expect("ip");
    assert_eq!(
        world.link(LinkEvent::AddressBound {
            ip: bad,
            lease_ns: None
        }),
        vec![
            LinkAction::Quiesce {
                reason: TransportReason::AddressChanged
            },
            LinkAction::Rebind {
                ip: bad,
                attempt: 1
            },
        ]
    );
    assert_eq!(world.sender.link().status().state, LinkState::Backoff);
    assert_eq!(
        world.sender.link().status().reason,
        Some(TransportReason::RebindFailed)
    );
    let sent_in_backoff = world.peer_sent(1);
    world.run_to_group(world.pts(166));
    assert_eq!(
        world.peer_sent(1),
        sent_in_backoff,
        "nothing is sent while backing off"
    );
    // a good address returns before the budget is spent: rebind, release the stale path, resume. The script has told the manager of
    // four addresses by now, ip1, ip2, the refused one and ip1 again, and every change of address is a generation of its own,
    // the refused one included (a generation names a desired address, not a bound one; the S4b world and the link tests count
    // the same way). The first version of this test expected 3, which counted only the addresses that could be bound.
    let back = world.link(LinkEvent::AddressBound {
        ip: ip1,
        lease_ns: None,
    });
    assert_eq!(world.expected_generation(), 4);
    assert_eq!(
        back,
        vec![
            LinkAction::Rebind {
                ip: ip1,
                attempt: 1
            },
            LinkAction::ReleaseStale { old_ip: ip2 },
            LinkAction::Resume {
                ip: ip1,
                generation: world.expected_generation()
            },
        ]
    );
    assert_eq!(
        world.sender.link().status().generation,
        world.expected_generation()
    );
    world.tell_rooms_sender_path();
    world.run_to_group(world.pts(blocks - 1));

    // independent oracles: samples, order, muted catch-up and no replay of the outage's audio
    for room in &world.rooms {
        let summary = check_room(room, world.tag, blocks);
        let real = real_blocks(room);
        assert!(
            real.windows(2).all(|pair| pair[0] < pair[1]),
            "room {}",
            room.peer
        );
        for block in sent_before..first_fresh {
            assert!(
                !real.contains(&block),
                "room {}: block {block} was staged during the outage, aged out, and must not be heard",
                room.peer
            );
        }
        assert!(
            real.iter().any(|block| *block >= first_fresh),
            "audio resumed"
        );
        assert!(
            real.iter().any(|block| *block >= 95),
            "audio continued after the address change"
        );
        assert!(
            real.iter().any(|block| *block >= 210),
            "audio continued to the end"
        );
        assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
        assert!(
            room.quiet > 0 || summary.concealed > 0,
            "the outage was heard as silence or concealment, not as old audio"
        );
        assert_n01_clean(room, "S4");
    }
    let c = world
        .sender
        .carrier()
        .peer_view(2)
        .expect("peer 2")
        .counters;
    assert_eq!(
        c.media_submitted_packets, blocks,
        "the peer's counters were never reset"
    );
    let link = world.sender.link().counters();
    assert_eq!((link.rebinds_failed, link.stale_releases), (1, 2));
    // The rebinds the port accepted are the manager's Rebind actions less the one for the refused address, which the carrier's
    // address policy turned back before the port was touched: bring-up, address change, recovery. The kernel agrees: the
    // bring-up changed nothing, each of the other two opened two sockets and closed the two it replaced.
    let rebinds = world.expected_port_rebinds();
    assert_eq!(rebinds, 3, "bring-up, address change, recovery");
    assert_eq!(world.sender.carrier().faults().rebinds, rebinds);
    assert_eq!(
        world.sender.carrier().faults().rebind_failures,
        0,
        "the refused address never reached the port, so the port failed nothing"
    );
    let (sockets, binds, closes) = world.expected_kernel_calls();
    assert_eq!((sockets, binds, closes), (6, 6, 4));
    let calls = world.sender_kernel_calls();
    assert_eq!(
        (calls.socket, calls.bind, calls.close),
        (sockets, binds, closes)
    );
    assert_eq!(world.sender.carrier().port().inner.ops().open_sockets(), 2);
    assert_conserved(&world, "S4");
    observe(
        "S4",
        &world,
        serde_json::json!({
            "sent_before_outage": sent_before,
            "first_fresh_block_after_outage": first_fresh,
            "link_counters": serde_json::to_value(link).expect("link counters"),
            "physical_radio": "unqualified (Q03/Q06); events are synthetic",
        }),
    );
}

#[test]
fn n07_s4b_a_spent_reconnect_budget_is_reported_to_the_readiness_state_and_a_good_address_recovers()
{
    let mut world = World::new(Plan::new(1, 4));
    let good = IpAddr::V4(loopback());
    let bad: IpAddr = "203.0.113.77".parse().expect("ip");
    world.link(LinkEvent::AddressBound {
        ip: bad,
        lease_ns: None,
    });
    for _ in 0..8_000 {
        world.step();
        if world.sender.link().status().state == LinkState::Failed {
            break;
        }
    }
    let status = world.sender.link().status();
    assert_eq!(status.state, LinkState::Failed, "{status:?}");
    assert_eq!(status.reason, Some(TransportReason::ReconnectBudgetSpent));
    let give_up = LinkAction::GiveUp {
        reason: TransportReason::ReconnectBudgetSpent,
    };
    assert_eq!(
        world.link_actions.iter().filter(|a| **a == give_up).count(),
        1,
        "reported once"
    );
    assert_eq!(
        world.sender.link().counters().rebinds_requested,
        1 + u64::from(world.sender.link().config().max_rebind_attempts),
        "bring-up plus the whole budget, and no more"
    );
    // the readiness state shows the local network condition, never a safe-mute fault and never the WAN
    match transport_readiness(&give_up) {
        Some(SpeakerReadinessState::DegradedStandaloneRecovery { reason }) => {
            assert_eq!(reason, TransportReason::ReconnectBudgetSpent.ux_text());
        }
        other => panic!("expected a degraded state, got {other:?}"),
    }
    for reason in TransportReason::ALL {
        assert!(!matches!(
            readiness_for(reason),
            SpeakerReadinessState::FaultedSafeMuted { .. }
        ));
    }
    assert!(world.sender.carrier().stats().link_down_pumps > 0);
    // a good address returns: the sockets never left it, so the manager resumes without touching them
    let sockets_before = world.sender.carrier().port().inner.ops().calls.socket;
    let back = world.link(LinkEvent::AddressBound {
        ip: good,
        lease_ns: None,
    });
    assert!(
        matches!(back.as_slice(), [LinkAction::Resume { ip, .. }] if *ip == good),
        "{back:?}"
    );
    assert_eq!(
        world.sender.carrier().port().inner.ops().calls.socket,
        sockets_before
    );
    assert_eq!(world.sender.link().status().state, LinkState::Up);
    assert!(!world.step().link_down, "the carrier runs again");
    observe(
        "S4b",
        &world,
        serde_json::json!({
            "rebinds_requested": world.sender.link().counters().rebinds_requested,
            "give_ups": world.sender.link().counters().give_ups,
        }),
    );
}

impl World {
    /// The source restarts under a newer epoch: everything queued under the old one is dropped, the receivers adopt the
    /// epoch, relock and are admitted for a fresh timeline, muted until it is reached.
    fn restart(&mut self, epoch: u64) {
        let local = self.time.get();
        let group = self.group_now();
        self.sender
            .carrier_mut()
            .advance_epoch(epoch)
            .expect("a strictly newer epoch");
        self.epoch = epoch;
        self.anchor_block = self.next_block;
        self.start_group = group + 500 * MS;
        for room in &mut self.rooms {
            let leader = room.clock.leader();
            room.endpoint
                .media_mut()
                .begin_epoch(&mut room.clock, epoch, leader)
                .expect("a newer epoch");
            room.endpoint.carrier_mut().advance_epoch(epoch);
            room.lock(local - 50 * MS, group - 50 * MS);
            room.endpoint
                .admit_start(
                    &mut room.platform,
                    &mut room.clock,
                    StartSchedule {
                        epoch,
                        start_group_ns: self.start_group,
                    },
                    self.anchor_block * BLOCK_FRAMES,
                )
                .expect("the restart is admitted");
        }
    }

    /// `restart`, for a source that restarts under a new stream identity: the sender's group moves to `stream_id` and `epoch`, and
    /// every room follows through `MediaEndpoint::restart_stream` between the clock's epoch and its start, as the control path
    /// would call them.
    fn restart_stream(&mut self, stream_id: StreamId, epoch: u64) {
        let local = self.time.get();
        let group = self.group_now();
        self.sender
            .carrier_mut()
            .restart_group(franken_stream::carrier::PRIMARY_GROUP, stream_id, epoch)
            .expect("a fresh stream under a strictly newer epoch");
        self.epoch = epoch;
        self.anchor_block = self.next_block;
        self.start_group = group + 500 * MS;
        for room in &mut self.rooms {
            let leader = room.clock.leader();
            room.endpoint
                .media_mut()
                .begin_epoch(&mut room.clock, epoch, leader)
                .expect("a newer epoch");
            room.endpoint.restart_stream(stream_id, epoch);
            room.lock(local - 50 * MS, group - 50 * MS);
            room.endpoint
                .admit_start(
                    &mut room.platform,
                    &mut room.clock,
                    StartSchedule {
                        epoch,
                        start_group_ns: self.start_group,
                    },
                    self.anchor_block * BLOCK_FRAMES,
                )
                .expect("the restart is admitted");
        }
    }
}

#[test]
fn n07_s9_a_source_restart_under_a_new_stream_identity_is_followed_through_the_real_endpoint() {
    let blocks = 160;
    let new_stream = StreamId::new(0x0700_0000_0000_0043).expect("nonzero stream id");
    let mut world = World::new(Plan::new(2, blocks));
    world.run_to_group(world.pts(40));
    let queued: Vec<u64> = world
        .rooms
        .iter()
        .map(|room| {
            world
                .sender
                .carrier()
                .peer_view(room.peer)
                .expect("peer")
                .queued_packets as u64
        })
        .collect();
    let old_next = world.next_block;
    for room in &world.rooms {
        let view = world.sender.carrier().peer_view(room.peer).expect("peer");
        assert!(view.reported_next > 0, "credit stood before the restart");
    }

    // the source restarts under a fresh stream and a newer epoch, and every room follows
    world.restart_stream(new_stream, 2);
    let group = world
        .sender
        .carrier()
        .group_view(franken_stream::carrier::PRIMARY_GROUP)
        .expect("the primary group");
    assert_eq!((group.stream_id, group.epoch), (new_stream.get(), 2));
    for (room, was_queued) in world.rooms.iter().zip(&queued) {
        let view = world.sender.carrier().peer_view(room.peer).expect("peer");
        assert_eq!(
            view.counters.media_dropped_fenced_packets, *was_queued,
            "everything queued under the old stream was dropped, never sent"
        );
        assert_eq!(
            (view.sent_next, view.reported_next),
            (0, 0),
            "numbering and credit start again"
        );
        let carrier = room.endpoint.carrier();
        assert_eq!(
            (carrier.stream_id(), carrier.consumed_next()),
            (new_stream, 0)
        );
    }
    // a datagram of the old stream, authentic and signed with the right key, reaches a room that follows the new one
    let mut old_signer = franken_stream::StreamSender::new(key(), stream(), 1);
    let planted = old_signer.send(world.frame(old_next)).expect("signed");
    let socket = UdpSocket::bind((loopback(), 0)).expect("a socket");
    socket
        .send_to(&planted, world.rooms[0].media_addr)
        .expect("planted");
    world.rooms[0].expect_media += 1;
    world.run_to_group(world.pts(blocks - 1));

    let n01 = world.rooms[0].endpoint.media().receiver_counters();
    assert_eq!(
        n01.rejected_wrong_stream, 1,
        "the planted datagram is refused as the old stream's"
    );
    assert_eq!(world.rooms[0].endpoint.verdicts().refused, 1);
    for (room, was_queued) in world.rooms.iter().zip(&queued) {
        let summary = check_room(room, world.tag, blocks);
        let real = real_blocks(room);
        let lost_from = old_next - was_queued;
        for block in lost_from..world.anchor_block {
            assert!(
                !real.contains(&block),
                "room {}: block {block} was queued under the old stream and must not be heard",
                room.peer
            );
        }
        let after: Vec<&Heard> = room
            .heard
            .iter()
            .filter(|h| h.outcome == Outcome::Real && h.block >= world.anchor_block)
            .collect();
        assert!(
            after.len() >= 20,
            "room {}: audio resumed under the new stream",
            room.peer
        );
        assert!(
            after[0].armed,
            "the restarted stream's first block is prepared while armed"
        );
        assert!(
            real.iter().any(|b| *b < lost_from),
            "audio before the restart was heard"
        );
        let n01 = room.endpoint.media().receiver_counters();
        assert_eq!(
            (
                n01.rejected_replay,
                n01.rejected_future_sequence,
                n01.rejected_authentication
            ),
            (0, 0, 0),
            "sequence numbers restart at 0 under the new stream without a replay"
        );
        assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
        // credit under the new stream flowed: the sender's report position moved off zero, and no report was a bad tag
        let view = world.sender.carrier().peer_view(room.peer).expect("peer");
        assert!(
            view.reported_next > 0,
            "room {}: the new stream earned credit",
            room.peer
        );
    }
    assert_eq!(world.sender.carrier().stats().reports_bad_tag, 0);
    assert_conserved(&world, "S9");
}

#[test]
fn n07_s5_an_epoch_restart_fences_stale_sends_stale_packets_and_stale_reports() {
    let blocks = 160;
    let mut world = World::new(Plan::new(2, blocks));
    world.run_to_group(world.pts(40));
    let queued: Vec<u64> = world
        .rooms
        .iter()
        .map(|room| {
            world
                .sender
                .carrier()
                .peer_view(room.peer)
                .expect("peer")
                .queued_packets as u64
        })
        .collect();
    let old_next = world.next_block;

    // the source advances its epoch; the receivers have not adopted it yet
    world
        .sender
        .carrier_mut()
        .advance_epoch(2)
        .expect("a strictly newer epoch");
    world.epoch = 2;
    let stale_frame = world.frame(old_next);
    let group = world.group_now();
    assert_eq!(
        world
            .sender
            .carrier_mut()
            .submit_media(1, &stale_frame, group),
        Err(CarrierError::StaleEpoch {
            submitted: 1,
            current: 2
        })
    );
    assert_eq!(world.sender.carrier().stats().stale_submits, 1);
    for (room, was_queued) in world.rooms.iter().zip(&queued) {
        let c = world
            .sender
            .carrier()
            .peer_view(room.peer)
            .expect("peer")
            .counters;
        assert_eq!(
            c.media_dropped_fenced_packets, *was_queued,
            "everything queued under the old epoch was dropped, never sent"
        );
    }
    // a receiver that has not adopted the epoch still reports under the old one: the report is inert
    world.rooms[1].endpoint.report().expect("report");
    wait_until("the stale report", || {
        world.sender.carrier_mut().poll_reports();
        world.sender.carrier().stats().reports_stale_epoch >= 1
    });
    // the source restarts under a still newer epoch: the receivers adopt it, relock, and are admitted for a fresh timeline
    world.restart(3);
    assert_eq!(world.sender.carrier().epoch(), 3);

    // a datagram signed under the old epoch reaches a room that has adopted the new one
    let mut old_signer = franken_stream::StreamSender::new(key(), stream(), 1);
    let planted = old_signer.send(world.frame(old_next)).expect("signed");
    let socket = UdpSocket::bind((loopback(), 0)).expect("a socket");
    socket
        .send_to(&planted, world.rooms[0].media_addr)
        .expect("planted");
    world.rooms[0].expect_media += 1;
    world.run_to_group(world.pts(blocks - 1));

    let rejected = world.rooms[0].endpoint.media().receiver_counters();
    assert_eq!(
        rejected.rejected_stale_epoch, 1,
        "the planted datagram is refused"
    );
    assert_eq!(world.rooms[0].endpoint.verdicts().refused, 1);
    for (room, was_queued) in world.rooms.iter().zip(&queued) {
        let summary = check_room(room, world.tag, blocks);
        let real = real_blocks(room);
        let lost_from = old_next - was_queued;
        for block in lost_from..world.anchor_block {
            assert!(
                !real.contains(&block),
                "room {}: block {block} was queued under the old epoch and must not be heard",
                room.peer
            );
        }
        let after: Vec<&Heard> = room
            .heard
            .iter()
            .filter(|h| h.outcome == Outcome::Real && h.block >= world.anchor_block)
            .collect();
        assert!(
            after.len() >= 20,
            "room {}: audio resumed under the new epoch",
            room.peer
        );
        assert!(
            after[0].armed,
            "the restarted stream's first block is prepared while armed"
        );
        assert!(
            real.iter().any(|b| *b < lost_from),
            "audio before the restart was heard"
        );
        let n01 = room.endpoint.media().receiver_counters();
        assert_eq!(
            (
                n01.rejected_replay,
                n01.rejected_future_sequence,
                n01.rejected_authentication
            ),
            (0, 0, 0),
            "sequence numbers restart at 0 in the new epoch without a replay"
        );
        assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
    }
    assert_conserved(&world, "S5");
    observe(
        "S5",
        &world,
        serde_json::json!({
            "queued_at_restart": queued,
            "anchor_block": world.anchor_block,
            "new_stream_identity": "not exercised by this world: see n07_s9",
        }),
    );
}

#[test]
fn n07_s6_an_mtu_change_fences_a_peer_without_fragmenting_and_recovers() {
    let blocks = 120;
    let mut world = World::new(Plan::new(2, blocks));
    world.run_to_group(world.pts(30));
    let fenced_at = world.next_block;
    let queued_at_fence = world
        .sender
        .carrier()
        .peer_view(1)
        .expect("peer 1")
        .queued_packets as u64;
    // a measured path change: this peer's path can no longer carry a whole block
    assert_eq!(
        world.sender.carrier_mut().set_path_mtu(1, 1100),
        Ok(PathOutcome::Fenced)
    );
    let sent_at_fence = world.peer_sent(1);
    world.run_to_group(world.pts(60));
    assert_eq!(
        world.peer_sent(1),
        sent_at_fence,
        "nothing is sent to a fenced path"
    );
    assert_eq!(
        world.sender.carrier().peer_view(1).expect("peer 1").fence,
        Some(FenceReason::PathMtuTooSmall)
    );
    let unfenced_at = world.next_block;
    assert_eq!(
        world.sender.carrier_mut().set_path_mtu(1, 1500),
        Ok(PathOutcome::Carrying)
    );
    let fenced_drops = world
        .sender
        .carrier()
        .peer_view(1)
        .expect("peer 1")
        .counters
        .media_dropped_fenced_packets;
    assert_eq!(
        fenced_drops,
        queued_at_fence + (unfenced_at - fenced_at),
        "the queue at the fence plus every block submitted while fenced, and nothing else"
    );
    world.run_to_group(world.pts(90));

    // the kernel itself says a block does not fit one peer's path: that peer is fenced, not retried
    world
        .sender
        .carrier_mut()
        .port_mut()
        .inner
        .ops_mut()
        .inject_send = Some(-(NetErrno::MsgSize.number(ABI) as isize));
    world.run_to_group(world.pts(95));
    let fenced: Vec<u32> = world
        .rooms
        .iter()
        .map(|room| room.peer)
        .filter(|peer| {
            world
                .sender
                .carrier()
                .peer_view(*peer)
                .expect("peer")
                .fence
                .is_some()
        })
        .collect();
    assert_eq!(
        fenced.len(),
        1,
        "exactly the peer that was sent to: {fenced:?}"
    );
    assert_eq!(world.sender.carrier().faults().send_message_too_long, 1);
    let victim = fenced[0];
    assert_eq!(
        world.sender.carrier_mut().set_path_mtu(victim, 1500),
        Ok(PathOutcome::Carrying)
    );
    world.run_to_group(world.pts(blocks - 1));

    // independent oracles
    assert!(
        world.sender.carrier().port().largest as u64 <= WIRE_BLOCK,
        "nothing larger than a block was ever handed to the kernel; nothing was fragmented"
    );
    let one = &world.rooms[0];
    check_room(one, world.tag, blocks);
    let real = real_blocks(one);
    for block in (fenced_at - queued_at_fence)..unfenced_at {
        assert!(
            !real.contains(&block),
            "block {block} was fenced away from peer 1"
        );
    }
    assert!(
        real.iter().any(|b| *b >= 110),
        "peer 1 hears the live stream again"
    );
    let two = &world.rooms[1];
    check_room(two, world.tag, blocks);
    assert!(
        (0..90).all(|block| real_blocks(two).contains(&block)) || victim == 2,
        "peer 2 lost nothing to peer 1's fence"
    );
    assert_conserved(&world, "S6");
    observe(
        "S6",
        &world,
        serde_json::json!({
            "fenced_drops_peer1": fenced_drops,
            "kernel_fenced_peer": victim,
            "largest_datagram_bytes": world.sender.carrier().port().largest,
        }),
    );
}

#[test]
fn n07_s7_seeded_loss_and_reorder_are_concealed_and_every_sample_matches_the_oracle() {
    let blocks = 120;
    let seed = 0x5EED_0707;
    let mut plan = Plan::new(1, blocks);
    plan.seed = seed;
    let mut world = World::new(plan);
    {
        let port = world.sender.carrier_mut().port_mut();
        port.seed = seed;
        port.drop_permille = 100;
        port.reorder_permille = 100;
        // the first two and the last four datagrams always pass, so there is history to conceal with and nothing is held
        port.active = (2, blocks - 4);
    }
    world.run_to_group(world.pts(blocks - 1));
    let schedule = world.sender.carrier().port().schedule.clone();
    let dropped: BTreeSet<u64> = schedule
        .iter()
        .filter(|(_, fault)| *fault == Fault::Drop)
        .map(|(index, _)| *index)
        .collect();
    let reordered = schedule
        .iter()
        .filter(|(_, fault)| *fault == Fault::Reorder)
        .count();
    assert!(
        dropped.len() >= 3 && reordered >= 3,
        "the plant is not vacuous: {schedule:?}"
    );

    let room = &world.rooms[0];
    let summary = check_room(room, world.tag, blocks);
    let real: BTreeSet<u64> = real_blocks(room).into_iter().collect();
    let expected: BTreeSet<u64> = (0..blocks).filter(|b| !dropped.contains(b)).collect();
    assert_eq!(
        real, expected,
        "exactly the blocks the network did not drop are heard"
    );
    let concealed: BTreeSet<u64> = room
        .heard
        .iter()
        .filter(|h| matches!(h.outcome, Outcome::Concealed { .. }))
        .map(|h| h.block)
        .collect();
    assert!(
        dropped.iter().all(|b| concealed.contains(b)) && concealed.is_subset(&dropped),
        "every lost block is concealed, and nothing else is: lost {dropped:?}, concealed {concealed:?}"
    );
    assert!(summary.max_run <= PlayoutProfile::MUSIC.max_conceal_blocks);
    // denominators: what the carrier believed it sent, what reached the kernel, what the receiver read
    let handed: u64 = world.sender.carrier().port().forwarded.values().sum();
    assert_eq!(handed, blocks - dropped.len() as u64);
    let rx = room.endpoint.carrier().stats();
    assert_eq!((rx.media_read, rx.media_accepted), (handed, handed));
    assert_eq!(world.peer_sent(1), blocks);
    assert_n01_clean(room, "S7");
    assert_conserved(&world, "S7");
    observe(
        "S7",
        &world,
        serde_json::json!({
            "dropped": dropped.len(),
            "reordered": reordered,
            "drop_permille": 100,
            "reorder_permille": 100,
        }),
    );
}

#[test]
fn n07_the_carrier_gate_starts_with_the_link_manager_and_opens_only_when_the_link_is_up() {
    let time = Rc::new(Cell::new(0));
    let ip = loopback();
    let carrier = CarrierSender::with_port(
        key(),
        stream(),
        1,
        CarrierLimits::baseline(),
        FaultPort::new(open_port(&time, ip)),
    )
    .expect("sender");
    let link = LinkManager::new(LinkConfig::baseline(PROFILES[0], 1)).expect("link");
    let mut sender = SenderEndpoint::new(carrier, link, 4);
    // a listener for the peer to be sent to
    let listener = open_port(&time, ip);
    let (media, control) = (
        listener.local_addr(Lane::Media).expect("media"),
        listener.local_addr(Lane::Control).expect("control"),
    );
    sender
        .announce(0xA1, 1, media, control, 1)
        .expect("announced");
    sender
        .carrier_mut()
        .submit_media(
            1,
            &OutboundFrame::media(0, 4 * SEC, 2 * SEC, vec![0x11; BLOCK_PAYLOAD_BYTES]),
            0,
        )
        .expect("queued");
    // before the manager has said the link is up, nothing leaves, whatever has been queued
    let before = sender.carrier_mut().pump(1);
    assert!(before.link_down, "{before:?}");
    assert_eq!(before.media_sent, 0);
    assert!(sender.carrier().port().forwarded.is_empty());
    // an interface that is not up stays closed, and a pump after the down event too
    sender.on_link_event(2, LinkEvent::InterfaceDown);
    assert!(sender.carrier_mut().pump(3).link_down);
    // the permitted positive: the interface, the address and the rebind open it, and the queued block goes
    sender.on_link_event(4, LinkEvent::InterfaceUp);
    let up = sender.on_link_event(
        5,
        LinkEvent::AddressBound {
            ip: IpAddr::V4(ip),
            lease_ns: Some(3_600 * SEC),
        },
    );
    assert!(
        matches!(
            up.as_slice(),
            [LinkAction::Rebind { .. }, LinkAction::Resume { .. }]
        ),
        "{up:?}"
    );
    let after = sender.carrier_mut().pump(6);
    assert!(!after.link_down);
    assert_eq!(after.media_sent, 1);
    assert_eq!(sender.carrier().port().forwarded.get(&media), Some(&1));
}

#[test]
fn n07_the_freshness_oracle_flags_pcm_decided_at_or_after_its_presentation_time() {
    let heard = |block: u64, decided_group_ns: u64| Heard {
        block,
        outcome: Outcome::Real,
        armed: false,
        pcm: Vec::new(),
        decided_local_ns: 0,
        decided_group_ns,
    };
    let pts = |block: u64| 1_000 * MS + block * 5 * MS;
    // the permitted positive: decided strictly before presentation, by a nanosecond or by the whole margin
    let fresh = [heard(1, pts(1) - 1), heard(2, pts(2) - 3 * MS)];
    assert_eq!(decided_too_late(&fresh, &pts), Vec::<u64>::new());
    // planted stale: decided exactly at presentation, and long after it
    let stale = [
        heard(1, pts(1) - 1),
        heard(2, pts(2)),
        heard(3, pts(3) + 400 * MS),
    ];
    assert_eq!(decided_too_late(&stale, &pts), vec![2, 3]);
    // remove the plant and the finding goes
    assert_eq!(decided_too_late(&stale[..1], &pts), Vec::<u64>::new());
}

#[test]
fn n07_the_expected_path_generation_is_counted_from_the_script_and_not_from_the_manager() {
    let ip = |text: &str| text.parse::<IpAddr>().expect("ip");
    let (a, b, refused) = (ip("127.0.0.1"), ip("127.0.0.2"), ip("203.0.113.77"));
    assert_eq!(generation_after(&[]), 0);
    assert_eq!(generation_after(&[a]), 1);
    assert_eq!(
        generation_after(&[a, a]),
        1,
        "the same address again is no change"
    );
    assert_eq!(generation_after(&[a, b]), 2);
    // S4's script: the refused address is an address the manager was told about, so it is a generation of its own
    assert_eq!(generation_after(&[a, b, refused, a]), 4);
    assert_ne!(
        generation_after(&[a, b, refused, a]),
        3,
        "counting only the addresses that could be bound would say 3"
    );
    // S4b's script, which passed natively and counts the same way
    assert_eq!(generation_after(&[a, refused, a]), 3);
}

#[test]
fn n07_a_stale_authentic_datagram_and_its_copy_through_the_real_endpoint_advance_credit_and_render_nothing()
 {
    let mut world = World::new(Plan::new(1, 400));
    // The sender is never pumped here. The datagrams are signed by a framer of the same stream and delivered by a plain socket,
    // so the room's endpoint is what is under test: its real carrier receiver, the real N01 admission, the N04 engine and the
    // platform clock. Four seconds pass in tenths with the clock kept locked and the renderer deciding what is due, and nothing
    // has ever arrived.
    for _ in 0..40 {
        let local = world.time.get() + 100 * MS;
        world.time.set(local);
        world.rooms[0].probe(local);
        world.rooms[0].drain_all();
    }
    let now_group = world.group_now();
    let stale_block = 3;
    assert!(
        world.pts(stale_block) + 2 * SEC < now_group,
        "the block's presentation time is more than two seconds past"
    );
    let before = Tally::of(&world.rooms[0]);
    let late_before = world.rooms[0].endpoint.verdicts().count("late");
    let sink_before = world.rooms[0].endpoint.carrier().sink_counters().clone();
    assert_eq!(world.rooms[0].endpoint.carrier().consumed_next(), 0);

    let socket = UdpSocket::bind((loopback(), 0)).expect("a socket");
    let deliver = |world: &mut World, wire: &[u8]| {
        socket
            .send_to(wire, world.rooms[0].media_addr)
            .expect("delivered");
        world.rooms[0].expect_media += 1;
        world.service(0);
    };

    // (1) an authentic datagram for a block long past: N01 admits it, the engine calls it late, and the only effect is credit
    let mut framer = franken_stream::StreamSender::new(key(), stream(), 1);
    let stale = framer.send(world.frame(stale_block)).expect("signed");
    deliver(&mut world, stale.as_slice());
    let room = &world.rooms[0];
    assert_eq!(room.endpoint.verdicts().count("late"), late_before + 1);
    assert_eq!(room.endpoint.verdicts().count("admitted"), 0);
    assert_eq!(
        room.endpoint.carrier().consumed_next(),
        1,
        "authenticated credit advanced"
    );
    assert_eq!(
        room.endpoint.carrier().sink_counters().admitted,
        sink_before.admitted + 1
    );
    let after = Tally::of(room);
    assert_eq!(
        (after.heard, after.decided_real),
        (before.heard, before.decided_real),
        "no PCM was prepared for it"
    );

    // (2) the same bytes again, as a probe sends them: N01 refuses the copy as a replay, with no credit and no PCM
    deliver(&mut world, stale.as_slice());
    let room = &world.rooms[0];
    assert_eq!(room.endpoint.media().receiver_counters().rejected_replay, 1);
    assert_eq!(
        room.endpoint.verdicts().refused,
        1,
        "the copy was refused, not decided"
    );
    assert_eq!(room.endpoint.carrier().consumed_next(), 1);
    assert_eq!(room.endpoint.verdicts().count("late"), late_before + 1);
    assert_eq!(Tally::of(room).heard, before.heard);

    // (3) the protected datagram of a long refusal: the same stale block under a number 900 further on, still within N01's gap
    let mut protected = Vec::new();
    for _ in 1..=900 {
        protected = framer.send(world.frame(stale_block)).expect("signed");
    }
    deliver(&mut world, protected.as_slice());
    let room = &world.rooms[0];
    assert_eq!(
        room.endpoint
            .media()
            .receiver_counters()
            .rejected_future_sequence,
        0
    );
    assert_eq!(
        room.endpoint.carrier().consumed_next(),
        901,
        "credit follows the authenticated number, however stale the block"
    );
    assert_eq!(room.endpoint.verdicts().count("late"), late_before + 2);
    assert_eq!(
        (Tally::of(room).heard, Tally::of(room).decided_real),
        (before.heard, before.decided_real),
        "still no PCM"
    );

    // (4) the permitted positive: a fresh block, authentic and in time, is admitted and heard, so the silence above is the stale
    // block's and not a dead path
    let fresh_block = (0..1_000)
        .find(|block| world.pts(*block) >= now_group + 60 * MS)
        .expect("a block still ahead");
    let fresh = framer.send(world.frame(fresh_block)).expect("signed");
    deliver(&mut world, fresh.as_slice());
    assert_eq!(world.rooms[0].endpoint.verdicts().count("admitted"), 1);
    for step in 0..200 {
        let local = world.time.get() + MS;
        world.time.set(local);
        if step % 50 == 0 {
            world.rooms[0].probe(local);
        }
        world.rooms[0].drain();
        if world.rooms[0].heard.len() > before.heard {
            break;
        }
    }
    let room = &world.rooms[0];
    assert_eq!(
        room.heard.len(),
        before.heard + 1,
        "exactly the fresh block"
    );
    let heard = &room.heard[before.heard];
    assert_eq!((heard.block, heard.outcome), (fresh_block, Outcome::Real));
    assert_eq!(heard.pcm, source_block(world.tag, fresh_block));
    assert_ne!(
        source_block(world.tag, fresh_block),
        source_block(world.tag, stale_block),
        "the two blocks differ, so the oracle could tell them apart"
    );
    assert!(
        room.heard
            .iter()
            .all(|h| h.pcm != source_block(world.tag, stale_block)),
        "nothing of the stale block was ever heard"
    );
    let pts = |block: u64| world.pts(block);
    assert_eq!(decided_too_late(&room.heard, &pts), Vec::<u64>::new());
}

/// The long outage, end to end through the real endpoint. `lose_original`: the network loses the first transmission of the
/// protected datagram, so the first probe is the first copy to arrive (S8); otherwise the protected datagram itself arrives
/// and both probes are copies of it (S8b).
fn recover_a_long_outage(case: &str, lose_original: bool) {
    let mut world = World::new(Plan::new(1, 40_000));
    // Keep the bytes of every media datagram the port is handed from the start: those from before the outage are the authentic
    // history an independent observer needs (see below). A refused send is not recorded, so nothing is kept during the outage.
    world.sender.carrier_mut().port_mut().record = true;
    world.run_to_group(world.pts(40));
    let healthy = Tally::of(&world.rooms[0]);
    assert!(healthy.decided_real >= 30, "audio was flowing: {healthy:?}");

    // The sender's transport refuses everything until the sequence budget is spent. The room's network side is fine and its
    // renderer goes on deciding, so the room hears the outage as the engine's own concealment and then silence.
    world.sender.carrier_mut().port_mut().refuse = Some(PortFault::WouldBlock);
    let mut ticks = 0_u32;
    loop {
        world.coarse_step(100 * MS);
        ticks += 1;
        let view = world.sender.carrier().peer_view(1).expect("peer");
        if view.sent_next >= view.reported_next + SEQ_AHEAD_LIMIT {
            break;
        }
        assert!(
            ticks < 2_000,
            "the budget was not spent after {ticks} refused steps: {view:?}"
        );
    }
    let spent = world.sender.carrier().peer_view(1).expect("peer");
    assert_eq!(spent.sent_next, spent.reported_next + SEQ_AHEAD_LIMIT);
    // twenty seconds more of refusals burn no further number and keep the last datagram, held, to be tried again
    for _ in 0..200 {
        world.coarse_step(100 * MS);
    }
    let held = world.sender.carrier().peer_view(1).expect("peer");
    assert_eq!(
        (held.sent_next, held.reported_next),
        (spent.sent_next, spent.reported_next),
        "no number was burned past the budget"
    );
    assert!(held.queued_packets >= 1);
    assert!(
        !world.sender.carrier().sequence_blocked(1),
        "a datagram is held to be tried"
    );
    assert_eq!(
        world.rooms[0].endpoint.carrier().consumed_next(),
        held.reported_next,
        "the sender's base is the room's own authenticated credit"
    );

    // The transport returns, and the room's reports are held back, so the sender must probe. The room sees the protected
    // datagram, long expired, and then copies of it: the first probe is the first copy to arrive when the network lost the
    // original, otherwise the original is.
    {
        let port = world.sender.carrier_mut().port_mut();
        port.refuse = None;
        port.lose_next = u64::from(lose_original);
    }
    let handed_before_recovery = world.sender.carrier().port().recorded.len();
    let primer = world
        .sender
        .carrier()
        .port()
        .recorded
        .last()
        .cloned()
        .expect("datagrams were sent before the outage");
    let copies_refused: u64 = if lose_original { 1 } else { 2 };
    world.rooms[0].reports_enabled = false;
    let before = Tally::of(&world.rooms[0]);
    let late_before = world.rooms[0].endpoint.verdicts().count("late");
    let refused_before = world.rooms[0].endpoint.verdicts().refused;
    let probes_before = world.sender.carrier().control_stats().probes_sent;
    let mut steps = 0_u32;
    while world.sender.carrier().control_stats().probes_sent < probes_before + 2 {
        world.step();
        steps += 1;
        assert!(steps < 3_000, "two probes were not sent in {steps} steps");
    }

    // The first media datagram the port was handed after the outage is the one that held the last number; the oracle for its number
    // and block is the datagram itself. Its number is a thousand beyond the report, so it is far beyond N01's forward gap from
    // nothing: a fresh observer refuses it, exactly as the room's receiver would have if it had never heard the stream (the
    // fence is unchanged and this is its negative control). The room has heard the stream, and so has an observer given the same
    // authentic history, here the last datagram sent before the outage, so the same N01 rule that lets the room admit it lets
    // the observer decode it.
    let protected_wire = world
        .sender
        .carrier()
        .port()
        .recorded
        .get(handed_before_recovery)
        .cloned()
        .expect("the port was handed the protected datagram");
    assert!(
        matches!(
            StreamReceiver::new(key(), stream(), 1).accept(&protected_wire),
            Err(franken_stream::StreamError::SequenceBeyondFutureWindow { .. })
        ),
        "a receiver that has heard nothing refuses a number this far ahead"
    );
    let mut observer = StreamReceiver::new(key(), stream(), 1);
    let history = observer
        .accept(&primer)
        .expect("an authentic datagram from before the outage");
    let lost = observer.accept(&protected_wire).expect(
        "an authentic datagram of the stream, within the gap of what the observer has heard",
    );
    assert!(
        lost.seq > franken_stream::MAX_FORWARD_SEQ_GAP,
        "the protected number is beyond the gap from nothing: {}",
        lost.seq
    );
    assert!(
        lost.seq - history.seq <= franken_stream::MAX_FORWARD_SEQ_GAP,
        "and within it of the last number heard"
    );
    let stale_block = lost.start_frame / BLOCK_FRAMES;
    assert_eq!(lost.seq, held.sent_next - 1, "it holds the last number");
    assert!(
        world.pts(stale_block) + 10 * SEC < world.group_now(),
        "the protected datagram had expired long before it was sent"
    );

    // Through the real endpoint: the first copy to arrive was admitted by N01 and called late by the engine, every other copy was
    // refused as a replay, the room's credit followed the authenticated number, and nothing was prepared or heard.
    let room = &world.rooms[0];
    assert_eq!(
        room.endpoint.carrier().consumed_next(),
        lost.seq + 1,
        "the late datagram, and nothing else, advanced the room's authenticated credit"
    );
    assert_eq!(room.endpoint.verdicts().count("late"), late_before + 1);
    assert_eq!(
        room.endpoint.verdicts().refused,
        refused_before + copies_refused,
        "every copy after the first was a replay"
    );
    assert_eq!(
        room.endpoint.media().receiver_counters().rejected_replay,
        copies_refused
    );
    let after = Tally::of(room);
    assert_eq!(
        (after.heard, after.decided_real),
        (before.heard, before.decided_real),
        "no PCM was prepared for either copy"
    );
    assert!(room.heard.iter().all(|heard| heard.block != stale_block));
    let view = world.sender.carrier().peer_view(1).expect("peer");
    assert_eq!(
        view.reported_next, held.reported_next,
        "the sender has had none of that credit yet: the reports were held back"
    );
    assert!(world.sender.carrier().sequence_blocked(1));

    // The reports resume. The sender's base moves to the room's credit, the budget reopens, and fresh audio flows.
    world.rooms[0].reports_enabled = true;
    let mut waited = 0_u32;
    while world
        .sender
        .carrier()
        .peer_view(1)
        .expect("peer")
        .reported_next
        <= lost.seq
    {
        world.step();
        waited += 1;
        assert!(waited < 200, "the report did not arrive in {waited} steps");
    }
    let reopened = world.sender.carrier().peer_view(1).expect("peer");
    assert_eq!(reopened.reported_next, lost.seq + 1);
    assert!(!world.sender.carrier().sequence_blocked(1));
    let resume_block = world.next_block;
    world.run_to_group(world.pts(resume_block + 60));

    let room = &world.rooms[0];
    let pts = |block: u64| world.pts(block);
    assert_eq!(
        decided_too_late(&room.heard, &pts),
        Vec::<u64>::new(),
        "a block was decided after it should have been heard"
    );
    for heard in room
        .heard
        .iter()
        .filter(|heard| heard.outcome == Outcome::Real)
    {
        assert_eq!(
            heard.pcm,
            source_block(world.tag, heard.block),
            "block {}: the samples are the source's",
            heard.block
        );
    }
    let fresh = room
        .heard
        .iter()
        .filter(|heard| heard.outcome == Outcome::Real && heard.block > stale_block)
        .count();
    assert!(fresh >= 20, "audio resumed: {fresh} fresh blocks");
    assert!(room.heard.iter().all(|heard| heard.block != stale_block));
    let n01 = room.endpoint.media().receiver_counters();
    assert_eq!(
        (
            n01.rejected_authentication,
            n01.rejected_future_sequence,
            n01.rejected_stale_epoch,
            n01.rejected_wrong_stream
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        n01.rejected_replay, copies_refused,
        "exactly the copies of the protected datagram after the first"
    );
    assert_eq!(
        world.sender.carrier().control_stats().probes_sent,
        probes_before + 2
    );
    assert_conserved(&world, case);
    observe(
        case,
        &world,
        serde_json::json!({
            "fault_model": "transport_refusal_then_held_reports",
            "original_lost_by_the_network": lose_original,
            "refused_steps_to_spend_the_budget": ticks,
            "sequence_budget": SEQ_AHEAD_LIMIT,
            "protected_seq": lost.seq,
            "protected_block": stale_block,
            "probes_sent": world.sender.carrier().control_stats().probes_sent,
            "fresh_blocks_heard": fresh,
        }),
    );
}

#[test]
fn n07_s8_a_long_outage_is_recovered_through_the_real_endpoint_with_credit_and_no_stale_pcm() {
    recover_a_long_outage("S8", true);
}

#[test]
fn n07_s8b_when_the_protected_datagram_arrives_its_probes_are_replays_that_change_nothing() {
    recover_a_long_outage("S8b", false);
}

#[test]
fn n07_the_source_oracle_gives_every_block_its_own_bytes_and_the_old_pattern_did_not() {
    // the cause of the native S4 failure (room 1 named blocks [0, 200] for block 0's bytes): the old pattern alone, which the
    // fixture used, repeats every 200 blocks
    let old = |tag: u8, index: u64| -> Vec<u8> {
        (0..BLOCK_PAYLOAD_BYTES)
            .map(|i| {
                let mix = (i % 251) as u64 + index * 7 + u64::from(tag) * 13;
                0x11 + (mix % 200) as u8
            })
            .collect()
    };
    assert_eq!(
        old(1, 0),
        old(1, 200),
        "the negative control: the old pattern collides"
    );
    assert_eq!(
        old(1, 19),
        old(1, 219),
        "and so does every block of S4's last twenty"
    );
    assert_ne!(source_block(1, 0), source_block(1, 200));
    // the permitted positive: distinct over a domain far past any world here, and across streams
    let mut seen = BTreeSet::new();
    for tag in [1_u8, 2, 3] {
        for index in 0..3_000 {
            assert!(
                seen.insert(source_block(tag, index)),
                "tag {tag} block {index} repeats an earlier block"
            );
        }
    }
    // and it is still a pure function of its arguments
    assert_eq!(source_block(1, 40), source_block(1, 40));
    assert_eq!(source_block(1, 40).len(), BLOCK_PAYLOAD_BYTES);
}
