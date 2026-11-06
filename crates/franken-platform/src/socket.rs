//! The socket capability through the seam (`P02` / `ffw-jub`): `socket`, `bind`, `listen`, `accept4`, and a datagram read that says when it
//! was cut. Contract: `docs/contracts/p02.md`, "The socket capability".
//!
//! **Status: written, never compiled, never run against a kernel.** The host tests below drive the policy with a scripted double that
//! answers `Provenance::Simulated`; nothing here is evidence about a kernel, and no leaf backend implements [`SocketOps`] yet (the unsafe
//! half, `sys.rs`, is a later slice).
//!
//! What this module is. [`SocketOps`] is the seam for five more kernel calls, raw in the way [`KernelOps`] is: each method issues one call and
//! returns what the kernel returned, a non-negative result or `-errno`. The functions below are the policy on top: they build the arguments
//! the contract requires, decode the return with [`Abi`], bound `EINTR`, and refuse a return the call cannot have produced.
//!
//! What it is not, so that nothing is duplicated (`net.rs`, `P06`, already gives the pure half and says the seam wiring is `P02`'s):
//! * the ABI numbers (`SOCK_STREAM`/`SOCK_DGRAM`, `SOCK_NONBLOCK`, `SOCK_CLOEXEC`, `MSG_TRUNC`), the `sockaddr` codecs and
//!   [`net::decode_datagram`] are `net.rs`'s and are used here, not restated;
//! * which syscall number, or `socketcall` sub-call, a call travels as is the leaf's decision per ABI (`franken-platform-linux`,
//!   `numbers.rs`, `SocketPlan`): this module is blind to the route.
//!
//! ## The rules, and where each is held
//! * **The flags are set by the call.** [`open_stream_socket`] and [`open_datagram_socket`] pass `SOCK_NONBLOCK | SOCK_CLOEXEC` in `type` and [`accept4`]
//!   passes them in `flags`. There is no `fcntl` method on the seam, so a flag cannot be set afterwards, and no `accept` method, so `accept` plus `fcntl`
//!   cannot be built from it. A backend passes `type` and `flags` through unchanged and never adds or drops a bit (the same rule as
//!   [`KernelOps::open_dev_random`]).
//! * **`accept4` answering `ENOSYS` or `EINVAL` is [`SysError::Absent`]**: the profile's decision (BeigeMaple, mail 6790), stated once, in [`accept4`].
//!   It is not repaired underneath: no second syscall is issued. `ENOSYS` is the plain case (a kernel with no direct `accept4`). `EINVAL` is read as
//!   absence here and nowhere else, and **it is a defensive reading: it is reachable on none of the kernels whose source was read** (v2.6.14, v2.6.26,
//!   v2.6.27, v2.6.28 and v2.6.35, as the verbatim lines in `tests/p02/socket_kernel_evidence.json`):
//!   - a PowerPC `socketcall` kernel answers a sub-call above its bound with `-EINVAL`, not `-ENOSYS`; at v2.6.14 and v2.6.26 the bound is
//!     `SYS_RECVMSG` (17) and `accept4` is sub-call 18. But those kernels take no flags in `socket`'s `type` (that arrived in 2.6.27), so
//!     [`open_stream_socket`] fails first, with the `EINVAL` of the flags, and there is no [`Listener`]: `accept4` is never reached.
//!   - at v2.6.27 flags are accepted and sub-call 18 exists, but it is **`paccept`** (`SYS_PACCEPT`, six words), not `accept4`: through `socketcall` the
//!     call does not fail, it **runs a different call** on a four-word block. A profile must not admit that kernel for the `socketcall` route. From
//!     v2.6.28 sub-call 18 is `accept4` (four words).
//!   - `accept4` also answers `EINVAL` for flags outside `SOCK_CLOEXEC | SOCK_NONBLOCK` and for a socket that is not listening (v2.6.35). Neither can
//!     come from this function: the flags are fixed by it, and it takes a [`Listener`], which only a successful [`listen`] produces.
//!   - So the reading can fire only on a kernel that takes flags in `type` yet refuses `accept4` with `EINVAL` (none read), or on a descriptor the caller
//!     closed through [`Listener::fd`] and that was reused (see "Tokens"): the second is not detectable here and would read as absence.
//!   - `listen`, `bind`, `socket` and the read keep `EINVAL` as [`SysError::Invalid`]. On `socket`, `EINVAL` means a kernel before 2.6.27 that
//!     takes no flags in `type` (see [`Abi::socket_type_arg`]); it is reported, and the socket is **not** created plainly and fixed up with
//!     `fcntl`, because that is the race the flags exist to close.
//! * **`EINTR` is bounded** at [`MAX_INTERRUPTED_ATTEMPTS`] attempts and then [`SysError::Interrupted`] (through [`Abi::call_retrying`], and the same
//!   loop for the read, which needs the raw return).
//! * **A datagram is never silently cut.** [`recv_datagram`] always passes [`net::RECV_FLAGS`] (`MSG_TRUNC`), so the kernel reports the datagram's
//!   real length, and [`net::decode_datagram`] turns a datagram longer than the buffer into [`Datagram::Truncated`]. The caller must not treat the
//!   stored bytes of a truncated datagram as the message. [`recv_datagram`] takes a [`DatagramSocket`], which only [`open_datagram_socket`] builds,
//!   so a stream descriptor cannot reach it: on a stream socket `MSG_TRUNC` is not "report the real length" (the kernel discards the bytes it was asked
//!   to truncate, which would make the function return `Complete` over an untouched buffer; this is the independent reviewer's recollection of
//!   `tcp_recvmsg`, not read here).
//! * **Tokens.** [`Listener`] and [`DatagramSocket`] are built only by [`listen`] and [`open_datagram_socket`]. `fd()` is for inspection and polling and
//!   does not consume the token; to close, hand `into_fd()` to `KernelOps::close`, which consumes it. A descriptor closed through `fd()` leaves a
//!   live token whose number the kernel may reuse, which the types cannot prevent.
//! * **No fake success.** A descriptor above `i32::MAX`, or a `bind`/`listen` that returns anything but `0`, is [`SocketError::NotAResult`],
//!   never coerced to success.
//!
//! Known gap: the read is `recv`, which does not return the sender. A reply to a datagram's sender (SSDP) needs `recvfrom`, six slots, which the
//! leaf's five-slot trampoline cannot carry as a direct call on MIPS o32; `numbers.rs` records that, and the route for it is `socketcall` on both
//! ABIs. It is not part of this slice.

use std::fmt;

use thiserror::Error;

use crate::abi::{Abi, MAX_INTERRUPTED_ATTEMPTS, SysError};
use crate::net::{self, Datagram, Family, NetError, SockAddrIn, SockAddrIn6, SockKind};
use crate::ops::KernelOps;

/// The calls this module issues, for error messages and for tests that count them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOp {
    Socket,
    Bind,
    Listen,
    Accept4,
    Recv,
}

impl SocketOp {
    /// Every call, in the order a server issues them.
    pub const ALL: [Self; 5] = [
        Self::Socket,
        Self::Bind,
        Self::Listen,
        Self::Accept4,
        Self::Recv,
    ];

    /// The syscall's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Accept4 => "accept4",
            Self::Recv => "recv",
        }
    }
}

impl fmt::Display for SocketOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a socket call did not produce its result. Nothing here is a capability verdict about the kernel except [`SysError::Absent`], which is the
/// profile's reading of one call's answer (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SocketError {
    /// The kernel's answer to `op`, classified by [`Abi::decode`]. For [`SocketOp::Accept4`] an `EINVAL` arrives here as [`SysError::Absent`].
    #[error("{op}: {error}")]
    Sys { op: SocketOp, error: SysError },
    /// A success value that `op` cannot have returned: a descriptor above `i32::MAX`, or a non-zero return from `bind` or `listen`.
    #[error("{op}: the return value {value} cannot be a result of this call")]
    NotAResult { op: SocketOp, value: usize },
    /// A refusal from `net.rs`'s decoder that is not a kernel error (a datagram length above the UDP maximum).
    #[error("recv: {0}")]
    Net(NetError),
}

/// A socket that `listen` accepted. Only [`listen`] builds one, which is what lets [`accept4`] read `EINVAL` as absence: the listening state, the
/// other cause of that errno, holds by construction. It owns no descriptor (this module has no `Drop`): close it through [`KernelOps::close`] with
/// [`Listener::into_fd`].
#[derive(Debug, PartialEq, Eq)]
pub struct Listener {
    fd: i32,
}

impl Listener {
    /// The listening descriptor, for inspection and polling only: this does not consume the token. To close it, pass [`Listener::into_fd`] to
    /// `KernelOps::close`.
    #[must_use]
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The descriptor, for `KernelOps::close`; the token is consumed, so nothing can be accepted on it afterwards.
    #[must_use]
    pub const fn into_fd(self) -> i32 {
        self.fd
    }
}

/// A datagram socket that [`open_datagram_socket`] made. Only it builds one, which is what lets [`recv_datagram`] pass `MSG_TRUNC` without being
/// handed a stream descriptor. Like [`Listener`] it owns no descriptor: `fd()` is for `bind`, polling and inspection and does not consume the token,
/// and `into_fd()` is the close path.
#[derive(Debug, PartialEq, Eq)]
pub struct DatagramSocket {
    fd: i32,
}

impl DatagramSocket {
    /// The descriptor, for [`bind_v4`], [`bind_v6`], polling and inspection: this does not consume the token.
    #[must_use]
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The descriptor, for `KernelOps::close`; the token is consumed.
    #[must_use]
    pub const fn into_fd(self) -> i32 {
        self.fd
    }
}

/// The five socket calls, one method each. A supertrait of [`KernelOps`] so that provenance, the backend's ABI and `close` come with it and a
/// backend that does not do sockets is unchanged.
///
/// Each method issues exactly one kernel call (on a `socketcall` ABI, one `socketcall`) and returns its raw result: a non-negative value, or
/// `-errno`. **No emulation:** a kernel without the call answers its own `-ENOSYS` (or, on the stock PowerPC `socketcall`, `-EINVAL`); the backend
/// does not answer `accept4` with `accept` plus `fcntl`, or `socket` flags with `fcntl`.
pub trait SocketOps: KernelOps {
    /// `socket(domain, kind, protocol)`: the descriptor. `kind` already carries `SOCK_NONBLOCK | SOCK_CLOEXEC`; pass it unchanged.
    fn socket(&mut self, domain: u32, kind: u32, protocol: u32) -> isize;

    /// `bind(fd, addr, addr.len())`: 0 on success. `addr` is the big-endian `sockaddr` the codec in `net.rs` produced.
    fn bind(&mut self, fd: i32, addr: &[u8]) -> isize;

    /// `listen(fd, backlog)`: 0 on success.
    fn listen(&mut self, fd: i32, backlog: i32) -> isize;

    /// `accept4(fd, NULL, NULL, flags)`: the new descriptor. The peer address is not requested. `flags` is passed unchanged.
    fn accept4(&mut self, fd: i32, flags: u32) -> isize;

    /// `recv(fd, buf, buf.len(), flags)`: the number of bytes stored, or, when `flags` has `MSG_TRUNC`, the datagram's real length (which may exceed
    /// `buf.len()`). `flags` is passed unchanged.
    fn recv(&mut self, fd: i32, buf: &mut [u8], flags: u32) -> isize;
}

fn sys_error(op: SocketOp, error: SysError) -> SocketError {
    SocketError::Sys { op, error }
}

/// A call whose success value is a descriptor.
fn descriptor(op: SocketOp, result: Result<usize, SysError>) -> Result<i32, SocketError> {
    let value = result.map_err(|error| sys_error(op, error))?;
    i32::try_from(value).map_err(|_| SocketError::NotAResult { op, value })
}

/// A call whose only success value is 0.
fn zero(op: SocketOp, result: Result<usize, SysError>) -> Result<(), SocketError> {
    match result.map_err(|error| sys_error(op, error))? {
        0 => Ok(()),
        value => Err(SocketError::NotAResult { op, value }),
    }
}

/// The `flags` argument of `accept4` on `abi`: `SOCK_NONBLOCK` (which is the ABI's `O_NONBLOCK`, 0x800 on PowerPC and 0x80 on MIPS) and
/// `SOCK_CLOEXEC`.
#[must_use]
pub const fn accept4_flags(abi: Abi) -> u32 {
    abi.o_nonblock() | net::SOCK_CLOEXEC
}

/// Create a nonblocking, close-on-exec stream socket: `socket(family, type, 0)` with both flags in `type`. The descriptor is for [`bind_v4`],
/// [`bind_v6`] and [`listen`].
///
/// # Errors
/// [`SocketError::Sys`] with the classified kernel error. `EINVAL` stays [`SysError::Invalid`] (a kernel before 2.6.27 takes no flags in `type`);
/// the socket is not created without them.
pub fn open_stream_socket<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    family: Family,
) -> Result<i32, SocketError> {
    open_socket(ops, abi, family, SockKind::Stream)
}

/// Create a nonblocking, close-on-exec datagram socket, the only way to get the [`DatagramSocket`] that [`recv_datagram`] takes.
///
/// # Errors
/// As [`open_stream_socket`].
pub fn open_datagram_socket<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    family: Family,
) -> Result<DatagramSocket, SocketError> {
    let fd = open_socket(ops, abi, family, SockKind::Dgram)?;
    Ok(DatagramSocket { fd })
}

/// The one place `socket` is issued. Private: a public form that returned a bare descriptor for either kind would hand `recv_datagram` a stream.
fn open_socket<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    family: Family,
    kind: SockKind,
) -> Result<i32, SocketError> {
    let domain = u32::from(family.number());
    let kind_arg = abi.socket_type_arg(kind, true, true);
    descriptor(
        SocketOp::Socket,
        abi.call_retrying(|| ops.socket(domain, kind_arg, 0)),
    )
}

/// Bind `fd` to an IPv4 address.
///
/// # Errors
/// [`SocketError::Sys`], or [`SocketError::NotAResult`] for a non-zero success value.
pub fn bind_v4<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    fd: i32,
    addr: SockAddrIn,
) -> Result<(), SocketError> {
    bind_bytes(ops, abi, fd, &addr.to_bytes())
}

/// Bind `fd` to an IPv6 address.
///
/// # Errors
/// As [`bind_v4`].
pub fn bind_v6<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    fd: i32,
    addr: SockAddrIn6,
) -> Result<(), SocketError> {
    bind_bytes(ops, abi, fd, &addr.to_bytes())
}

fn bind_bytes<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    fd: i32,
    bytes: &[u8],
) -> Result<(), SocketError> {
    zero(SocketOp::Bind, abi.call_retrying(|| ops.bind(fd, bytes)))
}

/// Start listening on `fd`.
///
/// # Errors
/// [`SocketError::Sys`] (`EINVAL` stays [`SysError::Invalid`]), or [`SocketError::NotAResult`] for a non-zero success value.
pub fn listen<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    fd: i32,
    backlog: u16,
) -> Result<Listener, SocketError> {
    let backlog = i32::from(backlog);
    zero(
        SocketOp::Listen,
        abi.call_retrying(|| ops.listen(fd, backlog)),
    )?;
    Ok(Listener { fd })
}

/// Accept one connection with `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`, both set by the call, and return the new descriptor.
///
/// `ENOSYS` and `EINVAL` are [`SysError::Absent`]; either is reported after exactly one call, and nothing is issued to repair it (no `accept`, no
/// `fcntl`). `EAGAIN` (nothing pending on the nonblocking listener) is [`SysError::WouldBlock`], which is not absence.
///
/// # Errors
/// [`SocketError::Sys`], or [`SocketError::NotAResult`] for a descriptor above `i32::MAX`.
pub fn accept4<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    listener: &Listener,
) -> Result<i32, SocketError> {
    let flags = accept4_flags(abi);
    let fd = listener.fd();
    let result = abi
        .call_retrying(|| ops.accept4(fd, flags))
        .map_err(|error| match error {
            SysError::Invalid => SysError::Absent,
            other => other,
        });
    descriptor(SocketOp::Accept4, result)
}

/// Read one datagram into `buf` with `MSG_TRUNC`, and say whether it fit. Takes a [`DatagramSocket`]: on a stream socket `MSG_TRUNC` does not mean what the
/// decoder assumes, so a stream descriptor cannot be passed.
///
/// # Errors
/// [`SocketError::Sys`] for a kernel error (`EAGAIN` on a nonblocking socket with nothing waiting is [`SysError::WouldBlock`]), and
/// [`SocketError::Net`] for a length above the largest UDP datagram.
pub fn recv_datagram<S: SocketOps + ?Sized>(
    ops: &mut S,
    abi: Abi,
    socket: &DatagramSocket,
    buf: &mut [u8],
) -> Result<Datagram, SocketError> {
    let fd = socket.fd();
    let capacity = buf.len();
    for _ in 0..MAX_INTERRUPTED_ATTEMPTS {
        let raw = ops.recv(fd, buf, net::RECV_FLAGS);
        match net::decode_datagram(abi, raw, capacity) {
            Err(NetError::Sys(SysError::Interrupted)) => {}
            Ok(datagram) => return Ok(datagram),
            Err(NetError::Sys(error)) => return Err(sys_error(SocketOp::Recv, error)),
            Err(other) => return Err(SocketError::Net(other)),
        }
    }
    Err(sys_error(SocketOp::Recv, SysError::Interrupted))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;
    use crate::ops::{Provenance, Timespec};

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    // Errno values typed from the kernels' own headers (asm-generic/errno-base.h, and the per-ABI errno.h for ENOSYS and EADDRINUSE), not read from
    // the tables under test.
    const NEG_EINTR: isize = -4;
    const NEG_EAGAIN: isize = -11;
    const NEG_EINVAL: isize = -22;
    const NEG_EMFILE: isize = -24;

    fn neg_enosys(abi: Abi) -> isize {
        match abi {
            Abi::PowerPc32 => -38,
            Abi::Mips32 => -89,
        }
    }

    fn neg_eaddrinuse(abi: Abi) -> isize {
        match abi {
            Abi::PowerPc32 => -98,
            Abi::Mips32 => -125,
        }
    }

    // The flag bits as the kernels and the E03 probes have them: SOCK_NONBLOCK is O_NONBLOCK (0x800 on PowerPC, 0x80 on MIPS), SOCK_CLOEXEC is
    // 0x80000 (`SOCK_CLOEXEC` in e03_probes/net.rs), MSG_TRUNC is 0x20 on both.
    const CLOEXEC_BIT: u32 = 0x80000;
    const MSG_TRUNC_BIT: u32 = 0x20;

    fn nonblock_bit(abi: Abi) -> u32 {
        match abi {
            Abi::PowerPc32 => 0x800,
            Abi::Mips32 => 0x80,
        }
    }

    fn attempts() -> usize {
        usize::try_from(MAX_INTERRUPTED_ATTEMPTS).expect("fits")
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Socket {
            domain: u32,
            kind: u32,
            protocol: u32,
        },
        Bind {
            fd: i32,
            addr: Vec<u8>,
        },
        Listen {
            fd: i32,
            backlog: i32,
        },
        Accept4 {
            fd: i32,
            flags: u32,
        },
        Recv {
            fd: i32,
            cap: usize,
            flags: u32,
        },
        Close {
            fd: i32,
        },
        /// Any other `KernelOps` method: this module must never issue one.
        Other(&'static str),
    }

    /// What the call's flags did to a descriptor, as the kernel would have: set at creation, from the flags argument, per ABI.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Status {
        nonblock: bool,
        cloexec: bool,
    }

    enum RecvStep {
        Raw(isize),
        /// A datagram on the wire: the double stores what fits, and reports the real length only when `MSG_TRUNC` was asked (the kernel's rule).
        Datagram(Vec<u8>),
    }

    struct Double {
        abi: Abi,
        log: Vec<Call>,
        socket: VecDeque<isize>,
        bind: VecDeque<isize>,
        listen: VecDeque<isize>,
        accept4: VecDeque<isize>,
        recv: VecDeque<RecvStep>,
        status: BTreeMap<i32, Status>,
    }

    impl Double {
        fn new(abi: Abi) -> Self {
            Self {
                abi,
                log: Vec::new(),
                socket: VecDeque::new(),
                bind: VecDeque::new(),
                listen: VecDeque::new(),
                accept4: VecDeque::new(),
                recv: VecDeque::new(),
                status: BTreeMap::new(),
            }
        }

        fn with_socket(mut self, replies: impl IntoIterator<Item = isize>) -> Self {
            self.socket.extend(replies);
            self
        }

        fn with_bind(mut self, replies: impl IntoIterator<Item = isize>) -> Self {
            self.bind.extend(replies);
            self
        }

        fn with_listen(mut self, replies: impl IntoIterator<Item = isize>) -> Self {
            self.listen.extend(replies);
            self
        }

        fn with_accept4(mut self, replies: impl IntoIterator<Item = isize>) -> Self {
            self.accept4.extend(replies);
            self
        }

        fn with_recv(mut self, steps: impl IntoIterator<Item = RecvStep>) -> Self {
            self.recv.extend(steps);
            self
        }

        fn flags_of(&self, bits: u32) -> Status {
            Status {
                nonblock: bits & nonblock_bit(self.abi) != 0,
                cloexec: bits & CLOEXEC_BIT != 0,
            }
        }

        fn other(&mut self, name: &'static str) -> isize {
            self.log.push(Call::Other(name));
            neg_enosys(self.abi)
        }
    }

    impl KernelOps for Double {
        fn provenance(&self) -> Provenance {
            Provenance::Simulated
        }

        fn backend_abi(&self) -> Option<Abi> {
            None
        }

        fn clock_gettime_monotonic(&mut self, _out: &mut Timespec) -> isize {
            self.other("clock_gettime_monotonic")
        }

        fn getrandom(&mut self, _buf: &mut [u8], _flags: u32) -> isize {
            self.other("getrandom")
        }

        fn open_dev_random(&mut self, _flags: u32) -> isize {
            self.other("open_dev_random")
        }

        fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
            self.other("eventfd2")
        }

        fn pipe2(&mut self, _fds: &mut [i32; 2], _flags: u32) -> isize {
            self.other("pipe2")
        }

        fn write(&mut self, _fd: i32, _buf: &[u8]) -> isize {
            self.other("write")
        }

        fn read(&mut self, _fd: i32, _buf: &mut [u8]) -> isize {
            self.other("read")
        }

        fn close(&mut self, fd: i32) -> isize {
            self.log.push(Call::Close { fd });
            0
        }
    }

    impl SocketOps for Double {
        fn socket(&mut self, domain: u32, kind: u32, protocol: u32) -> isize {
            self.log.push(Call::Socket {
                domain,
                kind,
                protocol,
            });
            let reply = self.socket.pop_front().expect("double: unscripted socket");
            if reply >= 0
                && let Ok(fd) = i32::try_from(reply)
            {
                let status = self.flags_of(kind);
                self.status.insert(fd, status);
            }
            reply
        }

        fn bind(&mut self, fd: i32, addr: &[u8]) -> isize {
            self.log.push(Call::Bind {
                fd,
                addr: addr.to_vec(),
            });
            self.bind.pop_front().expect("double: unscripted bind")
        }

        fn listen(&mut self, fd: i32, backlog: i32) -> isize {
            self.log.push(Call::Listen { fd, backlog });
            self.listen.pop_front().expect("double: unscripted listen")
        }

        fn accept4(&mut self, fd: i32, flags: u32) -> isize {
            self.log.push(Call::Accept4 { fd, flags });
            let reply = self
                .accept4
                .pop_front()
                .expect("double: unscripted accept4");
            if reply >= 0
                && let Ok(new_fd) = i32::try_from(reply)
            {
                let status = self.flags_of(flags);
                self.status.insert(new_fd, status);
            }
            reply
        }

        fn recv(&mut self, fd: i32, buf: &mut [u8], flags: u32) -> isize {
            self.log.push(Call::Recv {
                fd,
                cap: buf.len(),
                flags,
            });
            match self.recv.pop_front().expect("double: unscripted recv") {
                RecvStep::Raw(raw) => raw,
                RecvStep::Datagram(datagram) => {
                    let stored = datagram.len().min(buf.len());
                    buf[..stored].copy_from_slice(&datagram[..stored]);
                    let reported = if flags & MSG_TRUNC_BIT != 0 {
                        datagram.len()
                    } else {
                        stored
                    };
                    isize::try_from(reported).expect("fits")
                }
            }
        }
    }

    fn sys(op: SocketOp, error: SysError) -> SocketError {
        SocketError::Sys { op, error }
    }

    fn listening(abi: Abi, fd: i32) -> Listener {
        let mut ops = Double::new(abi).with_listen([0]);
        listen(&mut ops, abi, fd, 4).expect("listening")
    }

    fn datagram_socket(abi: Abi, fd: isize) -> DatagramSocket {
        let mut ops = Double::new(abi).with_socket([fd]);
        open_datagram_socket(&mut ops, abi, Family::Inet).expect("a datagram socket")
    }

    /// The public constructor for `kind`, as a descriptor: what the flag test needs to see through either one.
    fn open_fd<S: SocketOps + ?Sized>(
        ops: &mut S,
        abi: Abi,
        family: Family,
        kind: SockKind,
    ) -> Result<i32, SocketError> {
        match kind {
            SockKind::Stream => open_stream_socket(ops, abi, family),
            SockKind::Dgram => open_datagram_socket(ops, abi, family).map(DatagramSocket::into_fd),
        }
    }

    // ------------------------------------------------------------------------------------------------ socket

    #[test]
    fn open_socket_sets_nonblock_and_cloexec_in_the_call_itself_on_both_abis() {
        // `type` typed from the kernels: SOCK_STREAM 1 / SOCK_DGRAM 2 on PowerPC, 2 / 1 on MIPS, plus O_NONBLOCK (0x800 / 0x80) and 0x80000.
        let cases = [
            (Abi::PowerPc32, SockKind::Stream, 0x80801_u32),
            (Abi::PowerPc32, SockKind::Dgram, 0x80802),
            (Abi::Mips32, SockKind::Stream, 0x80082),
            (Abi::Mips32, SockKind::Dgram, 0x80081),
        ];
        for (abi, kind, expected) in cases {
            let mut ops = Double::new(abi).with_socket([7]);
            let fd = open_fd(&mut ops, abi, Family::Inet, kind).expect("a socket");
            assert_eq!(fd, 7);
            assert_eq!(
                ops.log,
                [Call::Socket {
                    domain: 2,
                    kind: expected,
                    protocol: 0
                }],
                "{abi:?} {kind:?}"
            );
            assert_eq!(
                ops.status[&7],
                Status {
                    nonblock: true,
                    cloexec: true
                },
                "{abi:?} {kind:?}: both flags were set by the call"
            );
        }
        let mut ops = Double::new(Abi::PowerPc32).with_socket([8]);
        open_datagram_socket(&mut ops, Abi::PowerPc32, Family::Inet6).expect("a socket");
        assert_eq!(
            ops.log,
            [Call::Socket {
                domain: 10,
                kind: 0x80802,
                protocol: 0
            }],
            "AF_INET6 is 10"
        );
    }

    #[test]
    fn a_socket_refused_with_einval_is_reported_and_never_made_plainly_and_fixed_up() {
        for abi in BOTH {
            let mut permitted = Double::new(abi).with_socket([3]);
            assert_eq!(
                open_socket(&mut permitted, abi, Family::Inet, SockKind::Dgram),
                Ok(3)
            );
            let mut ops = Double::new(abi).with_socket([NEG_EINVAL]);
            assert_eq!(
                open_socket(&mut ops, abi, Family::Inet, SockKind::Dgram),
                Err(sys(SocketOp::Socket, SysError::Invalid)),
                "{abi:?}: a kernel before 2.6.27 refuses flags in `type`; that is not absence"
            );
            assert_eq!(
                ops.log.len(),
                1,
                "{abi:?}: no second socket call, no fcntl: {:?}",
                ops.log
            );
        }
    }

    #[test]
    fn a_socket_call_the_kernel_does_not_have_is_absent_after_one_call() {
        for abi in BOTH {
            let mut permitted = Double::new(abi).with_socket([3]);
            assert_eq!(
                open_socket(&mut permitted, abi, Family::Inet, SockKind::Stream),
                Ok(3)
            );
            let mut ops = Double::new(abi).with_socket([neg_enosys(abi)]);
            assert_eq!(
                open_socket(&mut ops, abi, Family::Inet, SockKind::Stream),
                Err(sys(SocketOp::Socket, SysError::Absent)),
                "{abi:?}"
            );
            assert_eq!(ops.log.len(), 1, "{abi:?}");
        }
    }

    #[test]
    fn socket_interruptions_are_bounded_and_the_last_attempt_still_counts() {
        for abi in BOTH {
            let mut last_succeeds = Double::new(abi)
                .with_socket(std::iter::repeat_n(NEG_EINTR, attempts() - 1).chain([5]));
            assert_eq!(
                open_socket(&mut last_succeeds, abi, Family::Inet, SockKind::Dgram),
                Ok(5),
                "{abi:?}: seven interruptions then success is a success"
            );
            assert_eq!(last_succeeds.log.len(), attempts());
            let mut exhausted =
                Double::new(abi).with_socket(std::iter::repeat_n(NEG_EINTR, attempts()));
            assert_eq!(
                open_socket(&mut exhausted, abi, Family::Inet, SockKind::Dgram),
                Err(sys(SocketOp::Socket, SysError::Interrupted)),
                "{abi:?}"
            );
            assert_eq!(
                exhausted.log.len(),
                attempts(),
                "{abi:?}: exactly MAX_INTERRUPTED_ATTEMPTS calls, then Interrupted"
            );
        }
    }

    #[test]
    fn a_datagram_token_comes_only_from_a_datagram_open_and_carries_its_descriptor() {
        for abi in BOTH {
            // The type argument tells the two constructors apart: SOCK_DGRAM is 2 on PowerPC and 1 on MIPS, SOCK_STREAM the other way round.
            let (stream_kind, dgram_kind) = match abi {
                Abi::PowerPc32 => (0x80801_u32, 0x80802_u32),
                Abi::Mips32 => (0x80082, 0x80081),
            };
            let mut ops = Double::new(abi).with_socket([7, 8]);
            let token =
                open_datagram_socket(&mut ops, abi, Family::Inet).expect("a datagram socket");
            assert_eq!(token.fd(), 7, "{abi:?}");
            assert_eq!(
                open_stream_socket(&mut ops, abi, Family::Inet),
                Ok(8),
                "{abi:?}"
            );
            let kinds: Vec<u32> = ops
                .log
                .iter()
                .map(|call| match call {
                    Call::Socket { kind, .. } => *kind,
                    other => panic!("{abi:?}: not a socket call: {other:?}"),
                })
                .collect();
            assert_eq!(kinds, [dgram_kind, stream_kind], "{abi:?}");
            // A refused datagram open gives no token; the permitted open above is its pair.
            let mut refused = Double::new(abi).with_socket([NEG_EINVAL]);
            assert_eq!(
                open_datagram_socket(&mut refused, abi, Family::Inet),
                Err(sys(SocketOp::Socket, SysError::Invalid)),
                "{abi:?}"
            );
            assert_eq!(refused.log.len(), 1, "{abi:?}");
        }
    }

    #[test]
    fn the_tokens_are_closed_through_into_fd_which_consumes_them_and_fd_does_not() {
        for abi in BOTH {
            let listener = listening(abi, 6);
            assert_eq!(
                (listener.fd(), listener.fd()),
                (6, 6),
                "{abi:?}: fd() is for inspection"
            );
            let datagram = datagram_socket(abi, 7);
            assert_eq!((datagram.fd(), datagram.fd()), (7, 7), "{abi:?}");
            let mut ops = Double::new(abi);
            assert_eq!(ops.close(listener.into_fd()), 0);
            assert_eq!(ops.close(datagram.into_fd()), 0);
            assert_eq!(
                ops.log,
                [Call::Close { fd: 6 }, Call::Close { fd: 7 }],
                "{abi:?}: the close path is into_fd, one close per descriptor"
            );
        }
    }

    // ------------------------------------------------------------------------------------------ bind, listen

    #[test]
    fn bind_and_listen_interruptions_are_bounded_and_the_last_attempt_still_counts() {
        let addr = SockAddrIn {
            addr: [0, 0, 0, 0],
            port: 1,
        };
        for abi in BOTH {
            let mut last_succeeds = Double::new(abi)
                .with_bind(std::iter::repeat_n(NEG_EINTR, attempts() - 1).chain([0]));
            assert_eq!(bind_v4(&mut last_succeeds, abi, 6, addr), Ok(()), "{abi:?}");
            assert_eq!(last_succeeds.log.len(), attempts());
            let mut exhausted =
                Double::new(abi).with_bind(std::iter::repeat_n(NEG_EINTR, attempts()));
            assert_eq!(
                bind_v4(&mut exhausted, abi, 6, addr),
                Err(sys(SocketOp::Bind, SysError::Interrupted)),
                "{abi:?}"
            );
            assert_eq!(exhausted.log.len(), attempts(), "{abi:?}");

            let mut last_succeeds = Double::new(abi)
                .with_listen(std::iter::repeat_n(NEG_EINTR, attempts() - 1).chain([0]));
            assert_eq!(
                listen(&mut last_succeeds, abi, 6, 4).map(|listener| listener.fd()),
                Ok(6),
                "{abi:?}"
            );
            assert_eq!(last_succeeds.log.len(), attempts());
            let mut exhausted =
                Double::new(abi).with_listen(std::iter::repeat_n(NEG_EINTR, attempts()));
            assert_eq!(
                listen(&mut exhausted, abi, 6, 4),
                Err(sys(SocketOp::Listen, SysError::Interrupted)),
                "{abi:?}"
            );
            assert_eq!(exhausted.log.len(), attempts(), "{abi:?}");
        }
    }

    #[test]
    fn bind_v4_passes_the_sixteen_big_endian_bytes_and_zero_is_the_only_success() {
        // 0.0.0.0:1400 (0x0578): family 2, port, address, eight zero bytes.
        let expected = [0, 2, 0x05, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for abi in BOTH {
            let addr = SockAddrIn {
                addr: [0, 0, 0, 0],
                port: 1400,
            };
            let mut ops = Double::new(abi).with_bind([0]);
            assert_eq!(bind_v4(&mut ops, abi, 6, addr), Ok(()), "{abi:?}");
            assert_eq!(
                ops.log,
                [Call::Bind {
                    fd: 6,
                    addr: expected.to_vec()
                }],
                "{abi:?}"
            );
            let mut positive = Double::new(abi).with_bind([5]);
            assert_eq!(
                bind_v4(&mut positive, abi, 6, addr),
                Err(SocketError::NotAResult {
                    op: SocketOp::Bind,
                    value: 5
                }),
                "{abi:?}: a bind that returns 5 did not succeed"
            );
            let mut in_use = Double::new(abi).with_bind([neg_eaddrinuse(abi)]);
            let refused = bind_v4(&mut in_use, abi, 6, addr).expect_err("address in use");
            let SocketError::Sys { op, error } = refused else {
                panic!("{abi:?}: not a kernel error: {refused:?}");
            };
            assert_eq!(op, SocketOp::Bind);
            assert_eq!(
                abi.net_errno_of(error),
                Some(net::NetErrno::AddrInUse),
                "{abi:?}"
            );
            assert_eq!(in_use.log.len(), 1, "{abi:?}");
        }
    }

    #[test]
    fn bind_v6_passes_the_twenty_eight_big_endian_bytes() {
        // [::1]:1900 (0x076c): family 10, port, flow information 0, the address, scope 0.
        let mut expected = [0u8; 28];
        expected[1] = 10;
        expected[2] = 0x07;
        expected[3] = 0x6c;
        expected[23] = 1;
        let mut address = [0u8; 16];
        address[15] = 1;
        for abi in BOTH {
            let addr = SockAddrIn6 {
                addr: address,
                port: 1900,
                flowinfo: 0,
                scope_id: 0,
            };
            let mut ops = Double::new(abi).with_bind([0]);
            assert_eq!(bind_v6(&mut ops, abi, 6, addr), Ok(()), "{abi:?}");
            assert_eq!(
                ops.log,
                [Call::Bind {
                    fd: 6,
                    addr: expected.to_vec()
                }],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn listen_makes_a_listener_only_on_zero_and_passes_the_backlog() {
        for abi in BOTH {
            let mut ops = Double::new(abi).with_listen([0]);
            let listener = listen(&mut ops, abi, 6, 8).expect("listening");
            assert_eq!(listener.fd(), 6);
            assert_eq!(ops.log, [Call::Listen { fd: 6, backlog: 8 }], "{abi:?}");
            let mut positive = Double::new(abi).with_listen([1]);
            assert_eq!(
                listen(&mut positive, abi, 6, 8),
                Err(SocketError::NotAResult {
                    op: SocketOp::Listen,
                    value: 1
                }),
                "{abi:?}: no token for a listen that did not return 0"
            );
            let mut refused = Double::new(abi).with_listen([NEG_EMFILE]);
            assert_eq!(
                listen(&mut refused, abi, 6, 8),
                Err(sys(SocketOp::Listen, SysError::Errno(24))),
                "{abi:?}"
            );
        }
    }

    #[test]
    fn only_accept4_reads_einval_as_absent() {
        for abi in BOTH {
            let mut ops = Double::new(abi).with_listen([NEG_EINVAL]);
            assert_eq!(
                listen(&mut ops, abi, 6, 8),
                Err(sys(SocketOp::Listen, SysError::Invalid)),
                "{abi:?}"
            );
            let mut ops = Double::new(abi).with_bind([NEG_EINVAL]);
            let addr = SockAddrIn {
                addr: [0, 0, 0, 0],
                port: 1,
            };
            assert_eq!(
                bind_v4(&mut ops, abi, 6, addr),
                Err(sys(SocketOp::Bind, SysError::Invalid)),
                "{abi:?}"
            );
            let mut ops = Double::new(abi).with_recv([RecvStep::Raw(NEG_EINVAL)]);
            let mut buf = [0u8; 8];
            assert_eq!(
                recv_datagram(&mut ops, abi, &datagram_socket(abi, 6), &mut buf),
                Err(sys(SocketOp::Recv, SysError::Invalid)),
                "{abi:?}"
            );
            let mut ops = Double::new(abi).with_accept4([NEG_EINVAL]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Absent)),
                "{abi:?}: accept4's EINVAL is the profile's absence"
            );
        }
    }

    // ----------------------------------------------------------------------------------------------- accept4

    #[test]
    fn accept4_sets_both_flags_in_the_call_and_returns_the_descriptor() {
        // accept4's `flags`: O_NONBLOCK (0x800 / 0x80) | 0x80000, typed, per ABI.
        for (abi, expected) in [(Abi::PowerPc32, 0x80800_u32), (Abi::Mips32, 0x80080)] {
            let mut ops = Double::new(abi).with_accept4([9]);
            let fd = accept4(&mut ops, abi, &listening(abi, 6)).expect("accepted");
            assert_eq!(fd, 9);
            assert_eq!(
                ops.log,
                [Call::Accept4 {
                    fd: 6,
                    flags: expected
                }],
                "{abi:?}: one accept4, on the listener, and no accept, fcntl or other call"
            );
            assert_eq!(accept4_flags(abi), expected);
            assert_eq!(
                ops.status[&9],
                Status {
                    nonblock: true,
                    cloexec: true
                },
                "{abi:?}: the accepted descriptor is nonblocking and close-on-exec because the call said so"
            );
        }
    }

    #[test]
    fn accept4_enosys_is_absent_and_no_second_call_is_issued() {
        for abi in BOTH {
            let mut permitted = Double::new(abi).with_accept4([9]);
            assert_eq!(accept4(&mut permitted, abi, &listening(abi, 6)), Ok(9));
            let mut ops = Double::new(abi).with_accept4([neg_enosys(abi)]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Absent)),
                "{abi:?}"
            );
            assert_eq!(
                ops.log,
                [Call::Accept4 {
                    fd: 6,
                    flags: accept4_flags(abi)
                }],
                "{abi:?}: ENOSYS is reported as it came; nothing repairs it"
            );
            assert!(ops.status.is_empty(), "{abi:?}: no descriptor was made");
        }
    }

    #[test]
    fn accept4_einval_is_absent_and_no_second_call_is_issued() {
        for abi in BOTH {
            let mut ops = Double::new(abi).with_accept4([NEG_EINVAL]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Absent)),
                "{abi:?}: the stock PowerPC socketcall answers an unknown sub-call with EINVAL"
            );
            assert_eq!(
                ops.log,
                [Call::Accept4 {
                    fd: 6,
                    flags: accept4_flags(abi)
                }],
                "{abi:?}: no accept, no fcntl, no retry"
            );
            assert!(ops.status.is_empty(), "{abi:?}: no descriptor was made");
        }
    }

    #[test]
    fn accept4_interruptions_are_bounded_and_the_last_attempt_still_counts() {
        for abi in BOTH {
            let mut last_succeeds = Double::new(abi)
                .with_accept4(std::iter::repeat_n(NEG_EINTR, attempts() - 1).chain([9]));
            assert_eq!(
                accept4(&mut last_succeeds, abi, &listening(abi, 6)),
                Ok(9),
                "{abi:?}"
            );
            assert_eq!(last_succeeds.log.len(), attempts());
            let mut exhausted =
                Double::new(abi).with_accept4(std::iter::repeat_n(NEG_EINTR, attempts()));
            assert_eq!(
                accept4(&mut exhausted, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Interrupted)),
                "{abi:?}"
            );
            assert_eq!(
                exhausted.log.len(),
                attempts(),
                "{abi:?}: exactly MAX_INTERRUPTED_ATTEMPTS accept4 calls, then Interrupted, and nothing else"
            );
            assert!(
                exhausted
                    .log
                    .iter()
                    .all(|call| matches!(call, Call::Accept4 { .. })),
                "{abi:?}"
            );
        }
    }

    #[test]
    fn accept4_with_nothing_pending_would_block_and_is_not_absence() {
        for abi in BOTH {
            let mut permitted = Double::new(abi).with_accept4([9]);
            assert_eq!(accept4(&mut permitted, abi, &listening(abi, 6)), Ok(9));
            let mut ops = Double::new(abi).with_accept4([NEG_EAGAIN]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::WouldBlock)),
                "{abi:?}"
            );
            assert_eq!(ops.log.len(), 1, "{abi:?}");
        }
    }

    #[test]
    fn accept4_passes_other_errnos_through_and_refuses_what_is_not_a_result() {
        for abi in BOTH {
            let mut ops = Double::new(abi).with_accept4([NEG_EMFILE]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Errno(24))),
                "{abi:?}"
            );
            let mut malformed = Double::new(abi).with_accept4([-5000]);
            assert_eq!(
                accept4(&mut malformed, abi, &listening(abi, 6)),
                Err(sys(SocketOp::Accept4, SysError::Malformed(-5000))),
                "{abi:?}"
            );
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_descriptor_above_i32_max_is_not_a_result() {
        let too_big = isize::try_from(i64::from(i32::MAX) + 1).expect("64-bit host");
        for abi in BOTH {
            let mut ops = Double::new(abi).with_accept4([too_big]);
            assert_eq!(
                accept4(&mut ops, abi, &listening(abi, 6)),
                Err(SocketError::NotAResult {
                    op: SocketOp::Accept4,
                    value: 2_147_483_648
                }),
                "{abi:?}"
            );
            let mut ops = Double::new(abi).with_socket([too_big]);
            assert_eq!(
                open_socket(&mut ops, abi, Family::Inet, SockKind::Dgram),
                Err(SocketError::NotAResult {
                    op: SocketOp::Socket,
                    value: 2_147_483_648
                }),
                "{abi:?}"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------- datagrams

    #[test]
    fn recv_datagram_asks_for_msg_trunc_and_reports_a_cut_datagram() {
        let wire: Vec<u8> = (0..24).collect();
        for abi in BOTH {
            // Permitted: a datagram that fits, exactly full and with room to spare, is complete.
            let mut exact = Double::new(abi).with_recv([RecvStep::Datagram(wire[..16].to_vec())]);
            let mut buf = [0u8; 16];
            assert_eq!(
                recv_datagram(&mut exact, abi, &datagram_socket(abi, 6), &mut buf),
                Ok(Datagram::Complete { len: 16 }),
                "{abi:?}: a datagram exactly as long as the buffer is not truncated"
            );
            let mut roomy = Double::new(abi).with_recv([RecvStep::Datagram(wire[..10].to_vec())]);
            assert_eq!(
                recv_datagram(&mut roomy, abi, &datagram_socket(abi, 6), &mut buf),
                Ok(Datagram::Complete { len: 10 }),
                "{abi:?}"
            );
            // Refused: 24 bytes into 16 is reported with the real length, never returned as if it were the message.
            let mut cut = Double::new(abi).with_recv([RecvStep::Datagram(wire.clone())]);
            assert_eq!(
                recv_datagram(&mut cut, abi, &datagram_socket(abi, 6), &mut buf),
                Ok(Datagram::Truncated {
                    stored: 16,
                    real: 24
                }),
                "{abi:?}"
            );
            assert_eq!(
                cut.log,
                [Call::Recv {
                    fd: 6,
                    cap: 16,
                    flags: MSG_TRUNC_BIT
                }],
                "{abi:?}: the read asked for MSG_TRUNC and nothing else"
            );
            assert_eq!(&buf[..], &wire[..16], "{abi:?}: the first bytes are stored");
        }
    }

    #[test]
    fn the_double_cuts_silently_without_msg_trunc_which_is_why_the_flag_is_asserted() {
        // A control for the test above: the same datagram read WITHOUT the flag looks complete, so a reader that dropped the flag would pass a
        // check that only looked at the result. The test above also asserts the flags the read passed.
        let wire: Vec<u8> = (0..24).collect();
        for abi in BOTH {
            let mut ops = Double::new(abi).with_recv([RecvStep::Datagram(wire.clone())]);
            let mut buf = [0u8; 16];
            let raw = ops.recv(6, &mut buf, 0);
            assert_eq!(
                net::decode_datagram(abi, raw, buf.len()),
                Ok(Datagram::Complete { len: 16 }),
                "{abi:?}: without MSG_TRUNC the kernel reports the stored length"
            );
        }
    }

    #[test]
    fn recv_datagram_interruptions_are_bounded_and_the_last_attempt_still_counts() {
        for abi in BOTH {
            let mut buf = [0u8; 16];
            let mut last_succeeds = Double::new(abi).with_recv(
                std::iter::repeat_n(NEG_EINTR, attempts() - 1)
                    .map(RecvStep::Raw)
                    .chain([RecvStep::Datagram(vec![1, 2, 3])]),
            );
            assert_eq!(
                recv_datagram(&mut last_succeeds, abi, &datagram_socket(abi, 6), &mut buf),
                Ok(Datagram::Complete { len: 3 }),
                "{abi:?}"
            );
            assert_eq!(last_succeeds.log.len(), attempts());
            let mut exhausted = Double::new(abi)
                .with_recv(std::iter::repeat_n(NEG_EINTR, attempts()).map(RecvStep::Raw));
            assert_eq!(
                recv_datagram(&mut exhausted, abi, &datagram_socket(abi, 6), &mut buf),
                Err(sys(SocketOp::Recv, SysError::Interrupted)),
                "{abi:?}"
            );
            assert_eq!(exhausted.log.len(), attempts(), "{abi:?}");
        }
    }

    #[test]
    fn recv_datagram_reports_nothing_waiting_absence_and_impossible_lengths_as_what_they_are() {
        for abi in BOTH {
            let mut buf = [0u8; 16];
            let mut permitted = Double::new(abi).with_recv([RecvStep::Datagram(vec![7; 4])]);
            assert_eq!(
                recv_datagram(&mut permitted, abi, &datagram_socket(abi, 6), &mut buf),
                Ok(Datagram::Complete { len: 4 })
            );
            let mut empty = Double::new(abi).with_recv([RecvStep::Raw(NEG_EAGAIN)]);
            assert_eq!(
                recv_datagram(&mut empty, abi, &datagram_socket(abi, 6), &mut buf),
                Err(sys(SocketOp::Recv, SysError::WouldBlock)),
                "{abi:?}"
            );
            let mut absent = Double::new(abi).with_recv([RecvStep::Raw(neg_enosys(abi))]);
            assert_eq!(
                recv_datagram(&mut absent, abi, &datagram_socket(abi, 6), &mut buf),
                Err(sys(SocketOp::Recv, SysError::Absent)),
                "{abi:?}"
            );
            assert_eq!(absent.log.len(), 1, "{abi:?}");
            // 70 000 bytes cannot be a UDP datagram (the largest is 65 527): refused, not reported as truncated.
            let mut huge = Double::new(abi).with_recv([RecvStep::Raw(70_000)]);
            assert_eq!(
                recv_datagram(&mut huge, abi, &datagram_socket(abi, 6), &mut buf),
                Err(SocketError::Net(NetError::DatagramLength { real: 70_000 })),
                "{abi:?}"
            );
        }
    }

    // ------------------------------------------------------------------------------------------------ whole

    #[test]
    fn a_server_is_four_calls_in_order_and_nothing_else_issues_a_call() {
        for abi in BOTH {
            let mut ops = Double::new(abi)
                .with_socket([4])
                .with_bind([0])
                .with_listen([0])
                .with_accept4([9]);
            let fd = open_stream_socket(&mut ops, abi, Family::Inet).expect("socket");
            let addr = SockAddrIn {
                addr: [0, 0, 0, 0],
                port: 1400,
            };
            bind_v4(&mut ops, abi, fd, addr).expect("bind");
            let listener = listen(&mut ops, abi, fd, 8).expect("listen");
            let connection = accept4(&mut ops, abi, &listener).expect("accept4");
            assert_eq!((fd, listener.fd(), connection), (4, 4, 9));
            let kinds: Vec<String> = ops
                .log
                .iter()
                .map(|call| match call {
                    Call::Socket { .. } => "socket".to_owned(),
                    Call::Bind { .. } => "bind".to_owned(),
                    Call::Listen { .. } => "listen".to_owned(),
                    Call::Accept4 { .. } => "accept4".to_owned(),
                    Call::Recv { .. } => "recv".to_owned(),
                    Call::Close { .. } => "close".to_owned(),
                    Call::Other(name) => format!("other:{name}"),
                })
                .collect();
            assert_eq!(kinds, ["socket", "bind", "listen", "accept4"], "{abi:?}");
            assert_eq!(listener.into_fd(), 4);
        }
    }

    #[test]
    fn errors_name_the_call_and_the_ops_are_the_five_the_seam_has() {
        assert_eq!(
            sys(SocketOp::Accept4, SysError::Absent).to_string(),
            "accept4: the kernel has no such call (ENOSYS)"
        );
        assert_eq!(
            SocketError::NotAResult {
                op: SocketOp::Bind,
                value: 5
            }
            .to_string(),
            "bind: the return value 5 cannot be a result of this call"
        );
        let names: Vec<&str> = SocketOp::ALL.iter().map(|op| op.name()).collect();
        assert_eq!(names, ["socket", "bind", "listen", "accept4", "recv"]);
    }
}
