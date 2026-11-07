//! The datagram carrier seam (`N07` / `ffw-ybr`, on `P02` / `ffw-jub`): `sendto` and `recvfrom`, so a carrier can send one datagram to a named
//! peer and learn who sent the one it read. Contract: `docs/contracts/p02.md`, "The datagram seam".
//!
//! **Additive.** Nothing in `socket.rs` changed. [`DatagramOps`] sits on [`SocketOps`], so only a backend that already passed socket admission can
//! implement it (`franken-platform-linux`'s `SocketKernel`), and [`DatagramSocket`] (built only by `open_datagram_socket`) is the only descriptor
//! either function takes: a stream descriptor cannot reach them. The sockaddr codecs and `MSG_TRUNC` rule are `net.rs`'s and are used, not restated.
//!
//! ## The rules, and where each is held
//! * **Raw below, policy above.** Each [`DatagramOps`] method issues exactly one kernel call and returns what the kernel returned: a non-negative
//!   result or `-errno`. [`send_datagram_to`] and [`recv_datagram_from`] build the arguments, decode the return with [`Abi`], bound `EINTR`, and
//!   refuse a return the call cannot have produced.
//! * **The send flags are 0 and the receive flags are `MSG_TRUNC`.** The socket is already nonblocking (the call that made it sets
//!   `SOCK_NONBLOCK`), so a full send buffer is `EAGAIN`, reported as [`SysError::WouldBlock`] and never retried here or dropped silently.
//! * **A datagram is sent whole or not at all.** A send that returns fewer bytes than requested is [`DatagramError::ShortSend`], including `0` for
//!   a non-empty payload; `0` is a result only for an empty datagram. A return above the payload's length is [`DatagramError::NotAResult`]. A
//!   payload above [`net::MAX_DATAGRAM`] is refused before any call.
//! * **The sender is never guessed.** The address buffer is [`PEER_ADDR_CAPACITY`] bytes (a `sockaddr_in6`) and the kernel's reported length is read
//!   back. A length above the capacity (the address was cut), a length that is not a whole IPv4 or IPv6 address, an unknown family, or non-zero
//!   IPv4 padding is an error and **never** a [`PeerAddr`].
//! * **An `Err` for a bad sender means the datagram was consumed.** The kernel has already taken it off the socket. The caller must count it and
//!   keep reading; nothing here can give it back, and its bytes are not returned.
//! * **A truncated datagram still names its sender.** [`Received::datagram`] is [`Datagram::Truncated`] and [`Received::from`] is the peer, so an
//!   oversize flood can be accounted per source. The stored bytes of a truncated datagram are not the message.
//! * **`EINTR` is bounded** at [`MAX_INTERRUPTED_ATTEMPTS`] attempts, then [`SysError::Interrupted`]. Every receive attempt starts with a fresh,
//!   zeroed address buffer and the full capacity offered again, so a retry never sees the previous attempt's length or bytes. A send retried after
//!   `EINTR` sends the same payload to the same address: the interrupted attempt sent nothing.
//! * **No allocation.** The address buffer is on the stack, and [`PeerAddr`] and [`Received`] are `Copy`.
//!
//! What this is not: it says nothing about a kernel. The tests below drive a scripted double that answers `Provenance::Simulated`; the Linux leaf
//! issues these calls as `socketcall` sub-calls 11 and 12 on both ABIs, and **no guest has issued a `socketcall` on either ABI** (see the contract).

use std::fmt;

use thiserror::Error;

use crate::abi::{Abi, MAX_INTERRUPTED_ATTEMPTS, SysError};
use crate::net::{
    self, Datagram, Family, NetError, SOCKADDR_IN_LEN, SOCKADDR_IN6_LEN, SockAddrIn, SockAddrIn6,
};
use crate::socket::{DatagramSocket, SocketOps};

/// The flags every datagram send passes: none. A larger flag set is not part of this seam.
pub const SEND_FLAGS: u32 = 0;

/// The room offered for the sender's address on every receive: a `sockaddr_in6`, the larger of the two families a UDP socket reports.
pub const PEER_ADDR_CAPACITY: usize = SOCKADDR_IN6_LEN;

/// [`PEER_ADDR_CAPACITY`] as the `socklen_t` the kernel reads (a 32-bit `int`): it is 28, far below `i32::MAX`.
const PEER_ADDR_OFFER: u32 = 28;
const _: () = assert!(PEER_ADDR_OFFER as usize == PEER_ADDR_CAPACITY);

/// The two datagram calls, for error messages and for tests that count them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOp {
    SendTo,
    RecvFrom,
}

impl DatagramOp {
    /// The syscall's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SendTo => "sendto",
            Self::RecvFrom => "recvfrom",
        }
    }
}

impl fmt::Display for DatagramOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A peer's address as a datagram carrier keys it: no allocation, `Copy`, ordered and hashable. The IPv6 flow information is not part of it (it is
/// dropped on receive and 0 on send).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerAddr {
    V4 {
        addr: [u8; 4],
        port: u16,
    },
    V6 {
        addr: [u8; 16],
        port: u16,
        scope_id: u32,
    },
}

/// One datagram read and the peer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Whether the datagram fit the buffer (see [`Datagram`]). A truncated datagram's stored bytes are not the message.
    pub datagram: Datagram,
    /// The sender, decoded only from a whole IPv4 or IPv6 address.
    pub from: PeerAddr,
}

/// Why a datagram call did not produce its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DatagramError {
    /// The kernel's answer to `op`, classified by [`Abi::decode`]. `EAGAIN` is [`SysError::WouldBlock`]; `EINTR` arrives here only after
    /// [`MAX_INTERRUPTED_ATTEMPTS`] attempts. Network errnos (`EMSGSIZE`, `ENETUNREACH`, ...) are [`SysError::Errno`]: classify them with
    /// [`Abi::net_errno_of`].
    #[error("{op}: {error}")]
    Sys { op: DatagramOp, error: SysError },
    /// The payload is longer than any UDP datagram; nothing was sent.
    #[error("a payload of {len} bytes is above the largest UDP datagram")]
    PayloadTooLong { len: usize },
    /// `sendto` sent fewer bytes than the datagram has (including 0 for a non-empty one). A datagram goes whole or not at all, so this is a defect
    /// of the backend or the socket, not a partial success.
    #[error("sendto sent {sent} of {wanted} bytes: a datagram goes whole or not at all")]
    ShortSend { sent: usize, wanted: usize },
    /// A success value that `op` cannot have returned (a send above the payload's length).
    #[error("{op}: the return value {value} cannot be a result of this call")]
    NotAResult { op: DatagramOp, value: usize },
    /// A refusal from `net.rs`'s decoder that is not a kernel error (a datagram length above the UDP maximum).
    #[error("recvfrom: {0}")]
    Net(NetError),
    /// The kernel reported a sender address longer than the room offered, so it was cut. The datagram was **consumed**; its sender is unknown.
    #[error(
        "recvfrom: the sender address is {real} bytes, more than the {capacity} offered: the datagram was consumed and its sender is unknown"
    )]
    SenderTruncated { real: u32, capacity: usize },
    /// The sender address is not a whole IPv4 or IPv6 address. The datagram was **consumed**; its sender is unknown.
    #[error(
        "recvfrom: the sender address is not a whole IPv4 or IPv6 address ({0}): the datagram was consumed and its sender is unknown"
    )]
    SenderUnparsed(NetError),
}

/// The two datagram calls, one method each. A supertrait step on [`SocketOps`], so a backend that has not passed socket admission cannot
/// implement it. Each method issues exactly one kernel call and returns its raw result: a non-negative value, or `-errno`. No emulation: a kernel
/// without the call answers its own `-ENOSYS`.
pub trait DatagramOps: SocketOps {
    /// `sendto(fd, buf, buf.len(), flags, addr, addr.len())`: the number of bytes sent. `addr` is the big-endian `sockaddr` the codec in `net.rs`
    /// produced. `flags` is passed unchanged.
    fn sendto(&mut self, fd: i32, buf: &[u8], flags: u32, addr: &[u8]) -> isize;

    /// `recvfrom(fd, buf, buf.len(), flags, addr, &addr_len)`: the number of bytes stored, or, when `flags` has `MSG_TRUNC`, the datagram's real
    /// length (which may exceed `buf.len()`). The backend offers the kernel **exactly `addr.len()`** as the address length, never more, and
    /// stores what the kernel reports in `*addr_len` (the real length of the sender's address, which may exceed `addr.len()`). `flags` is passed
    /// unchanged. The incoming value of `*addr_len` is ignored.
    fn recvfrom(
        &mut self,
        fd: i32,
        buf: &mut [u8],
        flags: u32,
        addr: &mut [u8],
        addr_len: &mut u32,
    ) -> isize;
}

/// The `sockaddr` bytes of `to`, in a buffer of [`PEER_ADDR_CAPACITY`] bytes, and how many of them are the address.
fn peer_bytes(to: &PeerAddr) -> ([u8; PEER_ADDR_CAPACITY], usize) {
    let mut out = [0u8; PEER_ADDR_CAPACITY];
    match *to {
        PeerAddr::V4 { addr, port } => {
            let bytes = SockAddrIn { addr, port }.to_bytes();
            out[..SOCKADDR_IN_LEN].copy_from_slice(&bytes);
            (out, SOCKADDR_IN_LEN)
        }
        PeerAddr::V6 {
            addr,
            port,
            scope_id,
        } => {
            let bytes = SockAddrIn6 {
                addr,
                port,
                flowinfo: 0,
                scope_id,
            }
            .to_bytes();
            out.copy_from_slice(&bytes);
            (out, SOCKADDR_IN6_LEN)
        }
    }
}

/// Decode the sender the kernel wrote: `out_len` is the length it reported, `addr` the buffer it wrote into. Never returns a peer for a cut,
/// short, unknown-family or padded address.
fn decode_sender(addr: &[u8; PEER_ADDR_CAPACITY], out_len: u32) -> Result<PeerAddr, DatagramError> {
    let real = usize::try_from(out_len).unwrap_or(usize::MAX);
    if real > PEER_ADDR_CAPACITY {
        return Err(DatagramError::SenderTruncated {
            real: out_len,
            capacity: PEER_ADDR_CAPACITY,
        });
    }
    let bytes = &addr[..real];
    if real < 2 {
        return Err(DatagramError::SenderUnparsed(NetError::BadLength {
            expected: SOCKADDR_IN_LEN,
            got: real,
        }));
    }
    let family = u16::from_be_bytes([bytes[0], bytes[1]]);
    if family == Family::Inet.number() {
        SockAddrIn::from_bytes(bytes)
            .map(|sender| PeerAddr::V4 {
                addr: sender.addr,
                port: sender.port,
            })
            .map_err(DatagramError::SenderUnparsed)
    } else if family == Family::Inet6.number() {
        SockAddrIn6::from_bytes(bytes)
            .map(|sender| PeerAddr::V6 {
                addr: sender.addr,
                port: sender.port,
                scope_id: sender.scope_id,
            })
            .map_err(DatagramError::SenderUnparsed)
    } else {
        Err(DatagramError::SenderUnparsed(NetError::BadFamily {
            expected: Family::Inet.number(),
            got: family,
        }))
    }
}

/// Send `payload` as one datagram to `to` and return the number of bytes sent, which is `payload.len()` or an error.
///
/// # Errors
/// [`DatagramError::PayloadTooLong`] (nothing sent), [`DatagramError::Sys`] for a kernel error (`EAGAIN` is [`SysError::WouldBlock`]),
/// [`DatagramError::ShortSend`] for any return below the payload's length (including 0 for a non-empty payload), and
/// [`DatagramError::NotAResult`] for a return above it.
pub fn send_datagram_to<S: DatagramOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    socket: &DatagramSocket,
    to: &PeerAddr,
    payload: &[u8],
) -> Result<usize, DatagramError> {
    if payload.len() > net::MAX_DATAGRAM {
        return Err(DatagramError::PayloadTooLong { len: payload.len() });
    }
    let fd = socket.fd();
    let (bytes, len) = peer_bytes(to);
    let addr = &bytes[..len];
    let sent = abi
        .call_retrying(|| ops.sendto(fd, payload, SEND_FLAGS, addr))
        .map_err(|error| DatagramError::Sys {
            op: DatagramOp::SendTo,
            error,
        })?;
    if sent > payload.len() {
        return Err(DatagramError::NotAResult {
            op: DatagramOp::SendTo,
            value: sent,
        });
    }
    if sent != payload.len() {
        return Err(DatagramError::ShortSend {
            sent,
            wanted: payload.len(),
        });
    }
    Ok(sent)
}

/// Read one datagram into `buf` with `MSG_TRUNC` and say who sent it. Takes a [`DatagramSocket`]: on a stream socket `MSG_TRUNC` does not mean what
/// the decoder assumes, so a stream descriptor cannot be passed.
///
/// **An `Err` for the sender ([`DatagramError::SenderTruncated`], [`DatagramError::SenderUnparsed`]) means the datagram was consumed**: count it and
/// keep reading.
///
/// # Errors
/// [`DatagramError::Sys`] for a kernel error (`EAGAIN` on a nonblocking socket with nothing waiting is [`SysError::WouldBlock`]),
/// [`DatagramError::Net`] for a length above the largest UDP datagram, and the two sender errors above.
pub fn recv_datagram_from<S: DatagramOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    socket: &DatagramSocket,
    buf: &mut [u8],
) -> Result<Received, DatagramError> {
    let fd = socket.fd();
    let capacity = buf.len();
    for _ in 0..MAX_INTERRUPTED_ATTEMPTS {
        // A fresh, zeroed address buffer and the full capacity offered again on every attempt: a retry after EINTR never sees the previous
        // attempt's length or bytes.
        let mut addr = [0u8; PEER_ADDR_CAPACITY];
        let mut addr_len = PEER_ADDR_OFFER;
        let raw = ops.recvfrom(fd, buf, net::RECV_FLAGS, &mut addr, &mut addr_len);
        match net::decode_datagram(abi, raw, capacity) {
            Err(NetError::Sys(SysError::Interrupted)) => {}
            Ok(datagram) => {
                let from = decode_sender(&addr, addr_len)?;
                return Ok(Received { datagram, from });
            }
            Err(NetError::Sys(error)) => {
                return Err(DatagramError::Sys {
                    op: DatagramOp::RecvFrom,
                    error,
                });
            }
            Err(other) => return Err(DatagramError::Net(other)),
        }
    }
    Err(DatagramError::Sys {
        op: DatagramOp::RecvFrom,
        error: SysError::Interrupted,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet, VecDeque};

    use super::*;
    use crate::net::{MSG_TRUNC, NetErrno};
    use crate::ops::{KernelOps, Provenance, Timespec};
    use crate::socket::open_datagram_socket;

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];
    // Errnos typed from the kernels' own headers. EAGAIN and EINTR are the same on both ABIs; ENOSYS is not.
    const NEG_EAGAIN: isize = -11;
    const NEG_EINTR: isize = -4;
    const FD: i32 = 7;

    // The `sockaddr`s as the kernel lays them out on a big-endian target (family in the target's own byte order, port and address in network
    // order), typed by hand rather than built with the codecs under test. Addresses are documentation ranges.
    //
    // 192.0.2.7:40000
    const V4_SENDER: [u8; 16] = [0, 2, 0x9C, 0x40, 192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0];
    // [2001:db8::1]:8080, flow information 0x2A (which must be dropped), scope 3
    const V6_SENDER: [u8; 28] = [
        0, 10, 0x1F, 0x90, 0, 0, 0, 0x2A, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 3,
    ];
    const V4_PEER: PeerAddr = PeerAddr::V4 {
        addr: [192, 0, 2, 7],
        port: 40000,
    };
    const V6_PEER: PeerAddr = PeerAddr::V6 {
        addr: [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port: 8080,
        scope_id: 3,
    };
    // What a send to a peer must put in the `sockaddr`: 198.51.100.9:5000, and V6_PEER with the flow information 0.
    const SEND_V4_PEER: PeerAddr = PeerAddr::V4 {
        addr: [198, 51, 100, 9],
        port: 5000,
    };
    const SEND_V4_BYTES: [u8; 16] = [0, 2, 0x13, 0x88, 198, 51, 100, 9, 0, 0, 0, 0, 0, 0, 0, 0];
    const SEND_V6_BYTES: [u8; 28] = [
        0, 10, 0x1F, 0x90, 0, 0, 0, 0, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 3,
    ];

    /// What the double saw, in order. `socket` is not logged: it only hands out the descriptor token.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        SendTo {
            fd: i32,
            payload: Vec<u8>,
            flags: u32,
            addr: Vec<u8>,
        },
        RecvFrom {
            fd: i32,
            capacity: usize,
            flags: u32,
            /// The value of `*addr_len` the policy handed in.
            offered_len: u32,
            /// The length of the address buffer the policy handed in.
            addr_room: usize,
            addr_was_clear: bool,
        },
    }

    enum SendStep {
        /// The kernel sends the whole datagram.
        All,
        Raw(isize),
    }

    enum RecvStep {
        /// The call answers `raw` and writes nothing.
        Raw(isize),
        /// An interrupted call that left stale values in what it was handed.
        InterruptedDirty,
        /// A datagram on the wire. The double stores what fits, writes at most `addr.len()` bytes of `sender`, reports the real datagram length
        /// only when `MSG_TRUNC` was asked (the kernel's rule), and reports `reported_len` (or the sender's real length) as the address length.
        Datagram {
            data: Vec<u8>,
            sender: Vec<u8>,
            reported_len: Option<u32>,
        },
    }

    struct Double {
        socket_fd: isize,
        sends: VecDeque<SendStep>,
        recvs: VecDeque<RecvStep>,
        log: Vec<Call>,
    }

    impl Double {
        fn new() -> Self {
            Self {
                socket_fd: isize::try_from(FD).expect("fits"),
                sends: VecDeque::new(),
                recvs: VecDeque::new(),
                log: Vec::new(),
            }
        }
    }

    fn unexpected(what: &str) -> ! {
        panic!("double: the datagram policy must never issue {what}");
    }

    impl KernelOps for Double {
        fn provenance(&self) -> Provenance {
            Provenance::Simulated
        }

        fn backend_abi(&self) -> Option<Abi> {
            None
        }

        fn clock_gettime_monotonic(&mut self, _out: &mut Timespec) -> isize {
            unexpected("clock_gettime_monotonic")
        }

        fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
            unexpected("getrandom")
        }

        fn open_dev_random(&mut self, _flags: u32) -> isize {
            unexpected("open_dev_random")
        }

        fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
            unexpected("eventfd2")
        }

        fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
            unexpected("pipe2")
        }

        fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
            unexpected("write")
        }

        fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
            unexpected("read")
        }

        fn close(&mut self, _fd: i32) -> isize {
            unexpected("close")
        }
    }

    impl SocketOps for Double {
        fn socket(&mut self, _domain: u32, _kind: u32, _protocol: u32) -> isize {
            self.socket_fd
        }

        fn bind(&mut self, _fd: i32, _addr: &[u8]) -> isize {
            unexpected("bind")
        }

        fn listen(&mut self, _fd: i32, _backlog: i32) -> isize {
            unexpected("listen")
        }

        fn accept4(&mut self, _fd: i32, _flags: u32) -> isize {
            unexpected("accept4")
        }

        fn recv(&mut self, _fd: i32, _buf: &mut [u8], _flags: u32) -> isize {
            unexpected("recv")
        }
    }

    impl DatagramOps for Double {
        fn sendto(&mut self, fd: i32, buf: &[u8], flags: u32, addr: &[u8]) -> isize {
            self.log.push(Call::SendTo {
                fd,
                payload: buf.to_vec(),
                flags,
                addr: addr.to_vec(),
            });
            match self.sends.pop_front().expect("double: unscripted sendto") {
                SendStep::All => isize::try_from(buf.len()).expect("fits"),
                SendStep::Raw(raw) => raw,
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
            self.log.push(Call::RecvFrom {
                fd,
                capacity: buf.len(),
                flags,
                offered_len: *addr_len,
                addr_room: addr.len(),
                addr_was_clear: addr.iter().all(|byte| *byte == 0),
            });
            match self.recvs.pop_front().expect("double: unscripted recvfrom") {
                RecvStep::Raw(raw) => raw,
                RecvStep::InterruptedDirty => {
                    addr[0] = 0xFF;
                    *addr_len = 3;
                    NEG_EINTR
                }
                RecvStep::Datagram {
                    data,
                    sender,
                    reported_len,
                } => {
                    let stored = data.len().min(buf.len());
                    buf[..stored].copy_from_slice(&data[..stored]);
                    let written = sender.len().min(addr.len());
                    addr[..written].copy_from_slice(&sender[..written]);
                    *addr_len =
                        reported_len.unwrap_or_else(|| u32::try_from(sender.len()).expect("fits"));
                    let reported = if flags & MSG_TRUNC != 0 {
                        data.len()
                    } else {
                        stored
                    };
                    isize::try_from(reported).expect("fits")
                }
            }
        }
    }

    fn token(double: &mut Double, abi: Abi) -> DatagramSocket {
        open_datagram_socket(double, abi, Family::Inet).expect("the double hands out a descriptor")
    }

    fn datagram(data_len: usize, sender: &[u8]) -> RecvStep {
        RecvStep::Datagram {
            data: vec![0xAB; data_len],
            sender: sender.to_vec(),
            reported_len: None,
        }
    }

    /// One read of a 10-byte datagram whose sender the double writes as `sender` and reports as `reported_len`.
    fn read_one(
        abi: Abi,
        sender: &[u8],
        reported_len: Option<u32>,
    ) -> Result<Received, DatagramError> {
        let mut double = Double::new();
        let socket = token(&mut double, abi);
        double.recvs.push_back(RecvStep::Datagram {
            data: vec![0xAB; 10],
            sender: sender.to_vec(),
            reported_len,
        });
        let mut buf = [0u8; 32];
        recv_datagram_from(&mut double, abi, &socket, &mut buf)
    }

    fn attempts() -> usize {
        usize::try_from(MAX_INTERRUPTED_ATTEMPTS).expect("fits")
    }

    // ------------------------------------------------------------------------------------------------ receive

    #[test]
    fn a_complete_datagram_reports_its_ipv4_sender_and_the_call_offered_the_full_room() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.recvs.push_back(datagram(24, &V4_SENDER));
            let mut buf = [0u8; 64];
            let received = recv_datagram_from(&mut double, abi, &socket, &mut buf)
                .expect("a complete datagram with a whole sender");
            assert_eq!(
                received,
                Received {
                    datagram: Datagram::Complete { len: 24 },
                    from: V4_PEER
                },
                "{abi:?}"
            );
            assert_eq!(
                double.log,
                [Call::RecvFrom {
                    fd: FD,
                    capacity: 64,
                    flags: MSG_TRUNC,
                    offered_len: 28,
                    addr_room: 28,
                    addr_was_clear: true
                }],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn an_ipv6_sender_keeps_its_scope_id_and_drops_its_flow_information() {
        for abi in BOTH {
            let received = read_one(abi, &V6_SENDER, None)
                .expect("a 28-byte sender fills the room exactly and is not cut");
            assert_eq!(received.from, V6_PEER, "{abi:?}");
            assert_eq!(received.datagram, Datagram::Complete { len: 10 }, "{abi:?}");
        }
    }

    #[test]
    fn a_truncated_datagram_still_names_its_sender() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.recvs.push_back(datagram(24, &V4_SENDER));
            let mut buf = [0u8; 16];
            let received = recv_datagram_from(&mut double, abi, &socket, &mut buf)
                .expect("a cut datagram is a result, with its sender");
            assert_eq!(
                received,
                Received {
                    datagram: Datagram::Truncated {
                        stored: 16,
                        real: 24
                    },
                    from: V4_PEER
                },
                "{abi:?}"
            );
        }
    }

    #[test]
    fn a_sender_address_that_was_cut_short_or_is_not_whole_is_never_a_peer() {
        let mut v4_in_28 = V4_SENDER.to_vec();
        v4_in_28.resize(28, 0);
        let mut v4_dirty = V4_SENDER;
        v4_dirty[12] = 1;
        let mut af_unix = V4_SENDER;
        af_unix[1] = 1;
        for abi in BOTH {
            // The address was cut: the kernel reports more than the room offered.
            assert_eq!(
                read_one(abi, &V6_SENDER, Some(29)),
                Err(DatagramError::SenderTruncated {
                    real: 29,
                    capacity: 28
                }),
                "{abi:?}"
            );
            assert_eq!(
                read_one(abi, &V6_SENDER, Some(u32::MAX)),
                Err(DatagramError::SenderTruncated {
                    real: u32::MAX,
                    capacity: 28
                }),
                "{abi:?}"
            );
            // Not a whole address.
            let short = |got| {
                Err(DatagramError::SenderUnparsed(NetError::BadLength {
                    expected: SOCKADDR_IN_LEN,
                    got,
                }))
            };
            assert_eq!(read_one(abi, &[], Some(0)), short(0), "{abi:?}");
            assert_eq!(read_one(abi, &[0], Some(1)), short(1), "{abi:?}");
            assert_eq!(
                read_one(abi, &v4_in_28, None),
                Err(DatagramError::SenderUnparsed(NetError::BadLength {
                    expected: SOCKADDR_IN_LEN,
                    got: 28
                })),
                "{abi:?}"
            );
            assert_eq!(
                read_one(abi, &V6_SENDER[..16], Some(16)),
                Err(DatagramError::SenderUnparsed(NetError::BadLength {
                    expected: SOCKADDR_IN6_LEN,
                    got: 16
                })),
                "{abi:?}"
            );
            assert_eq!(
                read_one(abi, &af_unix, None),
                Err(DatagramError::SenderUnparsed(NetError::BadFamily {
                    expected: 2,
                    got: 1
                })),
                "{abi:?}"
            );
            assert_eq!(
                read_one(abi, &v4_dirty, None),
                Err(DatagramError::SenderUnparsed(NetError::NonZeroPadding)),
                "{abi:?}"
            );
            // The permitted positives, from the same helper: a whole address of either family is a peer.
            assert_eq!(
                read_one(abi, &V4_SENDER, None).map(|received| received.from),
                Ok(V4_PEER),
                "{abi:?}"
            );
            assert_eq!(
                read_one(abi, &V6_SENDER, Some(28)).map(|received| received.from),
                Ok(V6_PEER),
                "{abi:?}"
            );
        }
    }

    #[test]
    fn a_datagram_with_a_bad_sender_is_consumed_and_the_next_read_works() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.recvs.push_back(datagram(10, &[0, 1, 0, 0]));
            double.recvs.push_back(datagram(12, &V4_SENDER));
            let mut buf = [0u8; 32];
            assert!(
                matches!(
                    recv_datagram_from(&mut double, abi, &socket, &mut buf),
                    Err(DatagramError::SenderUnparsed(_))
                ),
                "{abi:?}"
            );
            // Nothing is queued any more for the first datagram: the next call reads the next one.
            assert_eq!(
                recv_datagram_from(&mut double, abi, &socket, &mut buf),
                Ok(Received {
                    datagram: Datagram::Complete { len: 12 },
                    from: V4_PEER
                }),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), 2, "{abi:?}");
            assert!(double.recvs.is_empty(), "{abi:?}");
        }
    }

    #[test]
    fn every_interrupted_attempt_is_handed_the_full_room_again() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.recvs.extend([
                RecvStep::InterruptedDirty,
                RecvStep::InterruptedDirty,
                datagram(8, &V4_SENDER),
            ]);
            let mut buf = [0u8; 32];
            assert_eq!(
                recv_datagram_from(&mut double, abi, &socket, &mut buf),
                Ok(Received {
                    datagram: Datagram::Complete { len: 8 },
                    from: V4_PEER
                }),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), 3, "{abi:?}");
            for call in &double.log {
                assert!(
                    matches!(
                        call,
                        Call::RecvFrom {
                            offered_len: 28,
                            addr_room: 28,
                            addr_was_clear: true,
                            ..
                        }
                    ),
                    "{abi:?}: a retry must not see the previous attempt's length or bytes: {call:?}"
                );
            }
        }
    }

    #[test]
    fn interruption_is_bounded_and_the_last_attempt_still_counts() {
        for abi in BOTH {
            // MAX - 1 interruptions and then a datagram: the last allowed attempt succeeds.
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            for _ in 0..attempts() - 1 {
                double.recvs.push_back(RecvStep::Raw(NEG_EINTR));
            }
            double.recvs.push_back(datagram(8, &V4_SENDER));
            let mut buf = [0u8; 32];
            assert!(
                recv_datagram_from(&mut double, abi, &socket, &mut buf).is_ok(),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), attempts(), "{abi:?}");

            // MAX interruptions: Interrupted, after exactly MAX calls.
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            for _ in 0..attempts() {
                double.recvs.push_back(RecvStep::Raw(NEG_EINTR));
            }
            assert_eq!(
                recv_datagram_from(&mut double, abi, &socket, &mut buf),
                Err(DatagramError::Sys {
                    op: DatagramOp::RecvFrom,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), attempts(), "{abi:?}");
        }
    }

    #[test]
    fn a_read_with_nothing_waiting_a_missing_call_and_an_impossible_length_are_each_their_own_error()
     {
        for (abi, neg_enosys) in [(Abi::PowerPc32, -38), (Abi::Mips32, -89)] {
            let read = |raw| {
                let mut double = Double::new();
                let socket = token(&mut double, abi);
                double.recvs.push_back(RecvStep::Raw(raw));
                let mut buf = [0u8; 32];
                recv_datagram_from(&mut double, abi, &socket, &mut buf)
            };
            assert_eq!(
                read(NEG_EAGAIN),
                Err(DatagramError::Sys {
                    op: DatagramOp::RecvFrom,
                    error: SysError::WouldBlock
                }),
                "{abi:?}"
            );
            assert_eq!(
                read(neg_enosys),
                Err(DatagramError::Sys {
                    op: DatagramOp::RecvFrom,
                    error: SysError::Absent
                }),
                "{abi:?}"
            );
            assert_eq!(
                read(70_000),
                Err(DatagramError::Net(NetError::DatagramLength {
                    real: 70_000
                })),
                "{abi:?}"
            );
        }
    }

    // --------------------------------------------------------------------------------------------------- send

    #[test]
    fn a_datagram_goes_to_a_named_ipv4_peer_as_the_sockaddr_the_kernel_reads() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.sends.push_back(SendStep::All);
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, b"hello"),
                Ok(5),
                "{abi:?}"
            );
            assert_eq!(
                double.log,
                [Call::SendTo {
                    fd: FD,
                    payload: b"hello".to_vec(),
                    flags: 0,
                    addr: SEND_V4_BYTES.to_vec()
                }],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn an_ipv6_peer_goes_out_as_a_28_byte_sockaddr_with_zero_flow_information() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double.sends.push_back(SendStep::All);
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &V6_PEER, b"hello"),
                Ok(5),
                "{abi:?}"
            );
            assert_eq!(
                double.log,
                [Call::SendTo {
                    fd: FD,
                    payload: b"hello".to_vec(),
                    flags: 0,
                    addr: SEND_V6_BYTES.to_vec()
                }],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn every_short_send_is_an_error_and_zero_is_a_result_only_for_an_empty_datagram() {
        for abi in BOTH {
            let send = |step, payload: &[u8]| {
                let mut double = Double::new();
                let socket = token(&mut double, abi);
                double.sends.push_back(step);
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, payload)
            };
            assert_eq!(
                send(SendStep::Raw(3), b"hello"),
                Err(DatagramError::ShortSend { sent: 3, wanted: 5 }),
                "{abi:?}"
            );
            assert_eq!(
                send(SendStep::Raw(0), b"hello"),
                Err(DatagramError::ShortSend { sent: 0, wanted: 5 }),
                "{abi:?}"
            );
            assert_eq!(
                send(SendStep::Raw(9), b"hello"),
                Err(DatagramError::NotAResult {
                    op: DatagramOp::SendTo,
                    value: 9
                }),
                "{abi:?}"
            );
            // The permitted positives: the whole datagram, and an empty datagram that sent nothing.
            assert_eq!(send(SendStep::All, b"hello"), Ok(5), "{abi:?}");
            assert_eq!(send(SendStep::Raw(0), b""), Ok(0), "{abi:?}");
        }
    }

    #[test]
    fn a_payload_above_the_udp_maximum_is_refused_before_any_call() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            let too_long = vec![0u8; net::MAX_DATAGRAM + 1];
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, &too_long),
                Err(DatagramError::PayloadTooLong {
                    len: net::MAX_DATAGRAM + 1
                }),
                "{abi:?}"
            );
            assert!(double.log.is_empty(), "{abi:?}: nothing reached the kernel");

            // The largest datagram is permitted and does reach it.
            double.sends.push_back(SendStep::All);
            let largest = vec![0u8; net::MAX_DATAGRAM];
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, &largest),
                Ok(net::MAX_DATAGRAM),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), 1, "{abi:?}");
        }
    }

    #[test]
    fn send_errors_arrive_classified_and_network_errnos_stay_classifiable() {
        // (ABI, EMSGSIZE, EADDRNOTAVAIL, ENETUNREACH) typed from the kernels' headers.
        for (abi, msgsize, addr_not_avail, net_unreach) in
            [(Abi::PowerPc32, 90, 99, 101), (Abi::Mips32, 97, 126, 128)]
        {
            let send = |raw| {
                let mut double = Double::new();
                let socket = token(&mut double, abi);
                double.sends.push_back(SendStep::Raw(raw));
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, b"hello")
            };
            assert_eq!(
                send(NEG_EAGAIN),
                Err(DatagramError::Sys {
                    op: DatagramOp::SendTo,
                    error: SysError::WouldBlock
                }),
                "{abi:?}"
            );
            for (errno, expected) in [
                (msgsize, NetErrno::MsgSize),
                (addr_not_avail, NetErrno::AddrNotAvail),
                (net_unreach, NetErrno::NetUnreach),
            ] {
                let Err(DatagramError::Sys {
                    op: DatagramOp::SendTo,
                    error,
                }) = send(-errno)
                else {
                    panic!("{abi:?}: errno {errno} must arrive as a kernel error");
                };
                assert_eq!(error, SysError::Errno(i32::try_from(errno).expect("fits")));
                assert_eq!(abi.net_errno_of(error), Some(expected), "{abi:?}");
            }
        }
    }

    #[test]
    fn an_interrupted_send_is_retried_whole_and_the_retries_are_bounded() {
        for abi in BOTH {
            let mut double = Double::new();
            let socket = token(&mut double, abi);
            double
                .sends
                .extend([SendStep::Raw(NEG_EINTR), SendStep::All]);
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, b"hello"),
                Ok(5),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), 2, "{abi:?}");
            assert_eq!(
                double.log[0], double.log[1],
                "{abi:?}: the retry sends the same payload to the same address"
            );

            let mut double = Double::new();
            let socket = token(&mut double, abi);
            for _ in 0..attempts() {
                double.sends.push_back(SendStep::Raw(NEG_EINTR));
            }
            assert_eq!(
                send_datagram_to(&mut double, abi, &socket, &SEND_V4_PEER, b"hello"),
                Err(DatagramError::Sys {
                    op: DatagramOp::SendTo,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(double.log.len(), attempts(), "{abi:?}");
        }
    }

    // ----------------------------------------------------------------------------------- the values a carrier holds

    #[test]
    fn the_results_and_errors_are_plain_values_and_a_bad_sender_says_the_datagram_was_consumed() {
        let truncated = DatagramError::SenderTruncated {
            real: 29,
            capacity: 28,
        };
        let copy = truncated;
        assert_eq!(truncated, copy);
        let unparsed = DatagramError::SenderUnparsed(NetError::NonZeroPadding);
        for error in [truncated, unparsed] {
            let text = error.to_string();
            assert!(
                text.contains("consumed"),
                "a bad sender must say its datagram was consumed: {text}"
            );
        }
        let received = Received {
            datagram: Datagram::Complete { len: 1 },
            from: V4_PEER,
        };
        let again = received;
        assert_eq!(received, again);
        assert_eq!(DatagramOp::SendTo.to_string(), "sendto");
        assert_eq!(DatagramOp::RecvFrom.to_string(), "recvfrom");
    }

    #[test]
    fn a_peer_is_a_copy_key_ordered_hashed_and_a_scope_id_makes_a_different_peer() {
        let mut other_scope = V6_PEER;
        if let PeerAddr::V6 { scope_id, .. } = &mut other_scope {
            *scope_id = 4;
        }
        assert_ne!(V6_PEER, other_scope);
        let ordered: BTreeSet<PeerAddr> = [V6_PEER, V4_PEER, V4_PEER, other_scope]
            .into_iter()
            .collect();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered.iter().next(), Some(&V4_PEER));
        let hashed: HashSet<PeerAddr> = [V4_PEER, V4_PEER, V6_PEER].into_iter().collect();
        assert_eq!(hashed.len(), 2);
    }
}
