//! Readiness and datagram ABI core for the legacy big-endian kernels (`P06` / `ffw-2nw`). Contract: `docs/contracts/p06.md`.
//!
//! The renderer's control I/O and its HAL need three kernel facts that the E03 matrix marks **Required** on the legacy images
//! and that no other module of this crate decodes: `poll` readiness, a datagram socket, and a datagram read that says when the
//! datagram did not fit. This module is the pure half of that: the numbers each ABI uses, the byte layouts the kernel reads and
//! writes, and the decoders that turn a raw return into a typed result. It issues no call and holds no state; the
//! `KernelOps` wiring and the leaf's wrappers (the only `unsafe`) are `P02`'s and are not part of this slice.
//!
//! Why the numbers are here and not borrowed. The two admitted ABIs disagree on exactly the constants a portable library
//! assumes are universal: MIPS has `SOCK_DGRAM = 1` and `SOCK_STREAM = 2` (PowerPC the reverse), `SOCK_NONBLOCK` is `0x80` on
//! MIPS and `0x800` on PowerPC, `SOL_SOCKET` is `0xffff` on MIPS and `1` on PowerPC, every socket option number moves, `POLLWRNORM`
//! and `POLLWRBAND` move, and all ten network errnos below differ. The FrankenLibC `errno` table at the pin recorded in
//! `tests/p06/ledger.json` is the generic one: it defines nine of those ten (no `EMSGSIZE`), each with PowerPC's number and
//! none with MIPS's. A library that
//! merely drops its `x86_64`/`aarch64` `compile_error!` would therefore build and misread MIPS, which is why nothing here is
//! derived from it. Each number below has more than one witness (`tests/p06`): the vector file, the E03 probe source, and the
//! `libc` crate's per-architecture files.
//!
//! What is deliberately not here:
//! * **No thread-local `errno`.** A failure arrives in-band as `-errno` (see [`crate::abi`]); there is no TLS to set up, read or
//!   race, which is also why no TLS fact is needed for these calls.
//! * **No `SO_RCVTIMEO_NEW` / `SO_SNDTIMEO_NEW`.** Those take a 64-bit timeval and need a 5.1+ kernel; the options used are the
//!   32-bit ones, and [`Timeval32`] refuses a value that does not fit 32 bits instead of truncating it.
//! * **No emulation.** `accept4`, `eventfd` and the like are not rebuilt from other calls (`P02` contract, "The seam").
//!
//! Layout notes. Both ABIs are big-endian and 32-bit, so every multi-byte field below is written big-endian whatever the host
//! is; a codec that used the host's byte order would pass on the device and fail on a laptop, which is what the vectors catch.

use std::time::Duration;

use thiserror::Error;

use crate::abi::{Abi, MAX_INTERRUPTED_ATTEMPTS, O_CLOEXEC, SysError};

/// Why a request was not built, or why a kernel answer is not believed. Nothing here is a capability verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NetError {
    /// The raw return was an error (`-errno`), classified by [`Abi::decode`].
    #[error("{0}")]
    Sys(#[from] SysError),
    /// `poll` reported more ready descriptors than were asked about.
    #[error("poll reported {ready} ready descriptors for {requested} requested")]
    ReadyAboveRequested { ready: usize, requested: usize },
    /// `poll` returned a ready bit this layer never asks for.
    #[error("poll returned the ready bits {bits:#06x}, which are not in this ABI's known set")]
    UnknownReadyBits { bits: u16 },
    /// A descriptor to poll was negative; the kernel ignores such an entry, so it is never built.
    #[error("descriptor {fd} is negative, and poll ignores a negative entry")]
    NegativeDescriptor { fd: i32 },
    /// An event request named a bit the kernel only reports (`POLLERR`, `POLLHUP`, `POLLNVAL`).
    #[error("events {bits:#06x} are output-only")]
    OutputOnlyEvent { bits: u16 },
    /// An event request named a bit outside this ABI's known set.
    #[error("events {bits:#06x} are not in this ABI's known set")]
    UnknownEventBits { bits: u16 },
    /// A socket timeout of zero: the kernel reads it as "never time out".
    #[error("a zero socket timeout means no timeout to the kernel; ask for it explicitly")]
    ZeroTimeout,
    /// A time does not fit the legacy 32-bit seconds of `timeval` or the `int` milliseconds of `poll`, or it is so long that the
    /// oldest admitted kernel would read it as "forever" ([`POLL_MAX_FINITE_MS`], [`TIMEVAL_MAX_FINITE_SEC`]).
    #[error(
        "the time does not fit the legacy 32-bit field, or is long enough for the kernel to read as forever"
    )]
    TimeWidth,
    /// A `timeval` read back was not a valid time (negative seconds, microseconds outside `0..1_000_000`).
    #[error("not a valid timeval")]
    BadTimeval,
    /// A buffer that should hold one structure had another length.
    #[error("expected {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
    /// The family field was not the one this structure is for.
    #[error("expected address family {expected}, got {got}")]
    BadFamily { expected: u16, got: u16 },
    /// The padding of a `sockaddr_in` was not zero.
    #[error("the padding is not zero")]
    NonZeroPadding,
    /// A datagram read claims a length no UDP datagram can have.
    #[error("a datagram length of {real} is above the largest UDP datagram")]
    DatagramLength { real: usize },
}

// ---------------------------------------------------------------------------------------------------- sockets

/// Socket kinds the renderer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockKind {
    Stream,
    Dgram,
}

/// Address families the renderer uses; the numbers are the same on both ABIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
}

impl Family {
    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            Self::Inet => 2,
            Self::Inet6 => 10,
        }
    }
}

/// Socket options the renderer sets or reads at level `SOL_SOCKET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpt {
    ReuseAddr,
    Broadcast,
    SendBuf,
    RecvBuf,
    /// The 32-bit [`Timeval32`] option (`SO_RCVTIMEO_OLD`), never the 64-bit `_NEW` one.
    RecvTimeout,
    /// The 32-bit [`Timeval32`] option (`SO_SNDTIMEO_OLD`), never the 64-bit `_NEW` one.
    SendTimeout,
    PendingError,
    Type,
}

/// `SOCK_CLOEXEC` (0o2000000) on both ABIs, the same bit as `O_CLOEXEC`.
pub const SOCK_CLOEXEC: u32 = O_CLOEXEC;

impl Abi {
    /// `SOCK_STREAM` / `SOCK_DGRAM`: MIPS numbers them the other way round from PowerPC.
    #[must_use]
    pub const fn sock_type(self, kind: SockKind) -> u32 {
        match (self, kind) {
            (Self::PowerPc32, SockKind::Stream) => 1,
            (Self::PowerPc32, SockKind::Dgram) => 2,
            (Self::Mips32, SockKind::Stream) => 2,
            (Self::Mips32, SockKind::Dgram) => 1,
        }
    }

    /// The `type` argument of `socket(2)`: the kind, with `SOCK_NONBLOCK` and `SOCK_CLOEXEC` set by the call itself (the
    /// E03 `accept4` row's reason: setting them afterwards with `fcntl` is a race).
    ///
    /// **Kernel floor: Linux 2.6.27.** Before that, `socket` takes no flags in `type` and answers `-EINVAL` for a value at or
    /// above `SOCK_MAX`, so on the stock PowerPC 2.6.14 kernel a call built with either flag fails and the only way to set them
    /// is `fcntl` afterwards, which is the race. The E03 guests (4.9, 4.19) are above the floor. Nothing here selects by kernel
    /// version; that is the leaf's decision.
    #[must_use]
    pub const fn socket_type_arg(self, kind: SockKind, nonblock: bool, cloexec: bool) -> u32 {
        let mut value = self.sock_type(kind);
        if nonblock {
            value |= self.o_nonblock();
        }
        if cloexec {
            value |= SOCK_CLOEXEC;
        }
        value
    }

    /// `SOL_SOCKET`: `1` on PowerPC, `0xffff` on MIPS.
    #[must_use]
    pub const fn sol_socket(self) -> i32 {
        match self {
            Self::PowerPc32 => 1,
            Self::Mips32 => 0xffff,
        }
    }

    /// The option number at `SOL_SOCKET`.
    #[must_use]
    pub const fn sockopt(self, option: SockOpt) -> i32 {
        match (self, option) {
            (Self::PowerPc32, SockOpt::ReuseAddr) => 2,
            (Self::PowerPc32, SockOpt::Broadcast) => 6,
            (Self::PowerPc32, SockOpt::SendBuf) => 7,
            (Self::PowerPc32, SockOpt::RecvBuf) => 8,
            (Self::PowerPc32, SockOpt::RecvTimeout) => 18,
            (Self::PowerPc32, SockOpt::SendTimeout) => 19,
            (Self::PowerPc32, SockOpt::PendingError) => 4,
            (Self::PowerPc32, SockOpt::Type) => 3,
            (Self::Mips32, SockOpt::ReuseAddr) => 0x4,
            (Self::Mips32, SockOpt::Broadcast) => 0x20,
            (Self::Mips32, SockOpt::SendBuf) => 0x1001,
            (Self::Mips32, SockOpt::RecvBuf) => 0x1002,
            (Self::Mips32, SockOpt::RecvTimeout) => 0x1006,
            (Self::Mips32, SockOpt::SendTimeout) => 0x1005,
            (Self::Mips32, SockOpt::PendingError) => 0x1007,
            (Self::Mips32, SockOpt::Type) => 0x1008,
        }
    }
}

/// Message flags, the same on both ABIs.
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_DONTWAIT: u32 = 0x40;

// ------------------------------------------------------------------------------------------------ network errno

/// The network errnos the renderer must tell apart. The numbers are per ABI: all ten differ between PowerPC and MIPS, and a
/// number that names one error on one ABI names another error (or none of these) on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetErrno {
    MsgSize,
    AddrInUse,
    AddrNotAvail,
    NetUnreach,
    ConnReset,
    NoBufs,
    NotConn,
    TimedOut,
    ConnRefused,
    InProgress,
}

impl NetErrno {
    pub const ALL: [Self; 10] = [
        Self::MsgSize,
        Self::AddrInUse,
        Self::AddrNotAvail,
        Self::NetUnreach,
        Self::ConnReset,
        Self::NoBufs,
        Self::NotConn,
        Self::TimedOut,
        Self::ConnRefused,
        Self::InProgress,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MsgSize => "EMSGSIZE",
            Self::AddrInUse => "EADDRINUSE",
            Self::AddrNotAvail => "EADDRNOTAVAIL",
            Self::NetUnreach => "ENETUNREACH",
            Self::ConnReset => "ECONNRESET",
            Self::NoBufs => "ENOBUFS",
            Self::NotConn => "ENOTCONN",
            Self::TimedOut => "ETIMEDOUT",
            Self::ConnRefused => "ECONNREFUSED",
            Self::InProgress => "EINPROGRESS",
        }
    }

    /// This error's number on `abi`.
    #[must_use]
    pub const fn number(self, abi: Abi) -> i32 {
        match (self, abi) {
            (Self::MsgSize, Abi::PowerPc32) => 90,
            (Self::MsgSize, Abi::Mips32) => 97,
            (Self::AddrInUse, Abi::PowerPc32) => 98,
            (Self::AddrInUse, Abi::Mips32) => 125,
            (Self::AddrNotAvail, Abi::PowerPc32) => 99,
            (Self::AddrNotAvail, Abi::Mips32) => 126,
            (Self::NetUnreach, Abi::PowerPc32) => 101,
            (Self::NetUnreach, Abi::Mips32) => 128,
            (Self::ConnReset, Abi::PowerPc32) => 104,
            (Self::ConnReset, Abi::Mips32) => 131,
            (Self::NoBufs, Abi::PowerPc32) => 105,
            (Self::NoBufs, Abi::Mips32) => 132,
            (Self::NotConn, Abi::PowerPc32) => 107,
            (Self::NotConn, Abi::Mips32) => 134,
            (Self::TimedOut, Abi::PowerPc32) => 110,
            (Self::TimedOut, Abi::Mips32) => 145,
            (Self::ConnRefused, Abi::PowerPc32) => 111,
            (Self::ConnRefused, Abi::Mips32) => 146,
            (Self::InProgress, Abi::PowerPc32) => 115,
            (Self::InProgress, Abi::Mips32) => 150,
        }
    }
}

impl Abi {
    /// Which network error `errno` is **on this ABI**, or `None` if it is none of the ten (it may still be another errno).
    #[must_use]
    pub fn classify_net_errno(self, errno: i32) -> Option<NetErrno> {
        NetErrno::ALL
            .into_iter()
            .find(|candidate| candidate.number(self) == errno)
    }

    /// The same for a decoded error: only [`SysError::Errno`] can be a network error.
    #[must_use]
    pub fn net_errno_of(self, error: SysError) -> Option<NetErrno> {
        match error {
            SysError::Errno(errno) => self.classify_net_errno(errno),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------------------------------------------- poll

pub const POLLIN: u16 = 0x1;
pub const POLLPRI: u16 = 0x2;
pub const POLLOUT: u16 = 0x4;
pub const POLLERR: u16 = 0x8;
pub const POLLHUP: u16 = 0x10;
pub const POLLNVAL: u16 = 0x20;
pub const POLLRDNORM: u16 = 0x40;
pub const POLLRDBAND: u16 = 0x80;
/// The bits the kernel only reports; asking for them is meaningless.
pub const POLL_OUTPUT_ONLY: u16 = POLLERR | POLLHUP | POLLNVAL;

impl Abi {
    /// `POLLWRNORM`: `0x100` on PowerPC, and the same bit as `POLLOUT` (`0x4`) on MIPS.
    #[must_use]
    pub const fn pollwrnorm(self) -> u16 {
        match self {
            Self::PowerPc32 => 0x100,
            Self::Mips32 => 0x4,
        }
    }

    /// `POLLWRBAND`: `0x200` on PowerPC, `0x100` on MIPS.
    #[must_use]
    pub const fn pollwrband(self) -> u16 {
        match self {
            Self::PowerPc32 => 0x200,
            Self::Mips32 => 0x100,
        }
    }

    /// Every poll bit this layer understands on this ABI. A ready bit outside it is not believed.
    #[must_use]
    pub const fn poll_known_bits(self) -> u16 {
        POLLIN
            | POLLPRI
            | POLLOUT
            | POLLERR
            | POLLHUP
            | POLLNVAL
            | POLLRDNORM
            | POLLRDBAND
            | self.pollwrnorm()
            | self.pollwrband()
    }
}

/// The size of one `struct pollfd` on both ABIs: `int fd; short events; short revents;`.
pub const POLLFD_LEN: usize = 8;

/// One `struct pollfd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

impl PollFd {
    /// A request to be told when `fd` has any of `events` (`revents` starts at zero). A negative descriptor, an output-only
    /// bit or a bit outside the ABI's known set is refused rather than sent.
    ///
    /// # Errors
    /// [`NetError::NegativeDescriptor`], [`NetError::OutputOnlyEvent`] or [`NetError::UnknownEventBits`].
    pub fn request(abi: Abi, fd: i32, events: u16) -> Result<Self, NetError> {
        if fd < 0 {
            return Err(NetError::NegativeDescriptor { fd });
        }
        let output_only = events & POLL_OUTPUT_ONLY;
        if output_only != 0 {
            return Err(NetError::OutputOnlyEvent { bits: output_only });
        }
        let unknown = events & !abi.poll_known_bits();
        if unknown != 0 {
            return Err(NetError::UnknownEventBits { bits: unknown });
        }
        Ok(Self {
            fd,
            events,
            revents: 0,
        })
    }

    /// The bytes the kernel reads: `fd` then `events` then `revents`, big-endian.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; POLLFD_LEN] {
        let fd = self.fd.to_be_bytes();
        let events = self.events.to_be_bytes();
        let revents = self.revents.to_be_bytes();
        [
            fd[0], fd[1], fd[2], fd[3], events[0], events[1], revents[0], revents[1],
        ]
    }

    /// The structure the kernel wrote back.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; POLLFD_LEN]) -> Self {
        Self {
            fd: i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            events: u16::from_be_bytes([bytes[4], bytes[5]]),
            revents: u16::from_be_bytes([bytes[6], bytes[7]]),
        }
    }

    /// The ready bits of a returned entry, refused when the kernel set a bit outside the ABI's known set.
    ///
    /// # Errors
    /// [`NetError::UnknownReadyBits`].
    pub fn ready(self, abi: Abi) -> Result<u16, NetError> {
        let unknown = self.revents & !abi.poll_known_bits();
        if unknown == 0 {
            Ok(self.revents)
        } else {
            Err(NetError::UnknownReadyBits { bits: unknown })
        }
    }
}

/// The longest finite `poll` timeout, in milliseconds, that the oldest admitted kernel (the stock 2.6.14) does not read as
/// "forever". Its `sys_poll` sets `timeout = MAX_SCHEDULE_TIMEOUT` (no timeout) unless `timeout < MAX_SCHEDULE_TIMEOUT / HZ`,
/// with `MAX_SCHEDULE_TIMEOUT = LONG_MAX = 2^31 - 1` on these 32-bit ABIs. At the largest `HZ` the kernel offers on these
/// platforms (1000) that is `2_147_483 - 1`; a smaller `HZ` allows more, so this bound is safe for every configuration.
pub const POLL_MAX_FINITE_MS: u32 = 2_147_482;

/// The largest whole-second part of a finite `SO_RCVTIMEO`/`SO_SNDTIMEO` that the kernel does not read as "no timeout".
/// `sock_set_timeout` stores `MAX_SCHEDULE_TIMEOUT` (wait forever) unless `tv_sec < MAX_SCHEDULE_TIMEOUT / HZ - 1`, so at
/// `HZ = 1000` the largest finite second count is `2_147_483 - 2`. Read at 2.6.14 and 2.6.35.
pub const TIMEVAL_MAX_FINITE_SEC: i32 = 2_147_481;

/// How long a `poll` may block. The kernel's argument is an `int` of milliseconds in which `0` is "do not block" and `-1` is
/// "forever", so the three cases are separate values and a duration is never allowed to become either by accident. A finite
/// value is also kept below [`POLL_MAX_FINITE_MS`], above which the old kernel itself reads it as forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollTimeout {
    Immediate,
    Millis(u32),
    Infinite,
}

impl PollTimeout {
    /// A finite timeout, rounded **up** to whole milliseconds (so a sub-millisecond wait is not a busy loop), and refused when
    /// it does not fit the kernel's `int` or exceeds [`POLL_MAX_FINITE_MS`] (where the old kernel would wait forever).
    ///
    /// # Errors
    /// [`NetError::TimeWidth`].
    pub fn from_duration(duration: Duration) -> Result<Self, NetError> {
        if duration.is_zero() {
            return Ok(Self::Immediate);
        }
        let millis = duration.as_nanos().div_ceil(1_000_000);
        let millis = u32::try_from(millis)
            .ok()
            .filter(|ms| *ms <= POLL_MAX_FINITE_MS)
            .ok_or(NetError::TimeWidth)?;
        Ok(Self::Millis(millis))
    }

    /// The `int` the kernel is given. `Millis` is a public variant, so a hand-built value above [`POLL_MAX_FINITE_MS`] is
    /// clamped to it: a shorter wait than asked for, never the `-1` or the kernel's "forever" threshold. Build with
    /// [`PollTimeout::from_duration`] to be told instead.
    #[must_use]
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Immediate => 0,
            Self::Millis(ms) => i32::try_from(ms.min(POLL_MAX_FINITE_MS)).unwrap_or(i32::MAX),
            Self::Infinite => -1,
        }
    }

    /// What is left of this timeout after `elapsed` has gone by, rounded up to a whole millisecond (never early, at most one
    /// millisecond late). An expired timeout is `Immediate`: one last look at the descriptors, not a wait.
    #[must_use]
    pub fn remaining(self, elapsed: Duration) -> Self {
        match self {
            Self::Immediate => Self::Immediate,
            Self::Infinite => Self::Infinite,
            Self::Millis(ms) => {
                let left = Duration::from_millis(u64::from(ms)).saturating_sub(elapsed);
                if left.is_zero() {
                    Self::Immediate
                } else {
                    let rounded = left.as_nanos().div_ceil(1_000_000);
                    Self::Millis(u32::try_from(rounded).unwrap_or(ms))
                }
            }
        }
    }
}

/// Decode the return of one `poll` call over `requested` entries: the number of entries with a nonzero `revents` (`0` is a
/// timeout). A count above the request is the kernel contradicting itself and is not believed.
///
/// `-EINTR` comes back as [`SysError::Interrupted`] and is **not** retried here: retrying with the same timeout would stretch
/// the wait (see [`poll_retrying`]).
///
/// # Errors
/// [`NetError::Sys`] for a kernel error, [`NetError::ReadyAboveRequested`] for an impossible count.
pub fn decode_poll(abi: Abi, raw: isize, requested: usize) -> Result<usize, NetError> {
    let ready = abi.decode(raw)?;
    if ready > requested {
        return Err(NetError::ReadyAboveRequested { ready, requested });
    }
    Ok(ready)
}

/// Issue a `poll` through `call` (given the timeout in milliseconds to pass), retrying an interrupted call with the time that
/// is **left** of `timeout`, measured by `elapsed` since the operation began, and at most [`MAX_INTERRUPTED_ATTEMPTS`] times.
///
/// This is the difference between this and [`Abi::call_retrying`]: that one repeats the same call, which for `poll` would give
/// a 100 ms wait up to eight full waits. The caller supplies `elapsed` from the monotonic clock; this function reads no clock.
///
/// # Errors
/// As [`decode_poll`], and [`SysError::Interrupted`] when every attempt was interrupted.
pub fn poll_retrying<C, E>(
    abi: Abi,
    requested: usize,
    timeout: PollTimeout,
    mut call: C,
    mut elapsed: E,
) -> Result<usize, NetError>
where
    C: FnMut(i32) -> isize,
    E: FnMut() -> Duration,
{
    let mut left = timeout;
    for _ in 0..MAX_INTERRUPTED_ATTEMPTS {
        match decode_poll(abi, call(left.to_raw()), requested) {
            Err(NetError::Sys(SysError::Interrupted)) => left = timeout.remaining(elapsed()),
            other => return other,
        }
    }
    Err(NetError::Sys(SysError::Interrupted))
}

// --------------------------------------------------------------------------------------------------- datagrams

/// The largest payload any UDP datagram can carry: the 16-bit IPv6 payload length (65 535, no jumbograms) minus the 8-byte UDP
/// header. (Over IPv4 it is 65 507; this bound is the looser of the two, so a length above it is impossible on either.)
pub const MAX_DATAGRAM: usize = 65_527;

/// The flags every datagram read passes: `MSG_TRUNC`, so that the kernel returns the datagram's **real** length even when it
/// did not fit, which is the only way a read can tell "exactly full" from "cut off". The E03 loopback probe's fact: a 24-byte
/// datagram read into a 16-byte buffer returns 24.
pub const RECV_FLAGS: u32 = MSG_TRUNC;

/// What one datagram read produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram {
    /// The whole datagram is in the buffer.
    Complete { len: usize },
    /// The buffer holds only the first `stored` bytes of a datagram that is `real` bytes long. The caller must not treat the
    /// stored bytes as the message.
    Truncated { stored: usize, real: usize },
}

/// Decode the return of a datagram read issued with [`RECV_FLAGS`] into a buffer of `buf_len` bytes.
///
/// # Errors
/// [`NetError::Sys`] for a kernel error (including `EAGAIN` on a nonblocking socket with nothing waiting), and
/// [`NetError::DatagramLength`] for a length above [`MAX_DATAGRAM`].
pub fn decode_datagram(abi: Abi, raw: isize, buf_len: usize) -> Result<Datagram, NetError> {
    let real = abi.decode(raw)?;
    if real > MAX_DATAGRAM {
        return Err(NetError::DatagramLength { real });
    }
    if real <= buf_len {
        Ok(Datagram::Complete { len: real })
    } else {
        Ok(Datagram::Truncated {
            stored: buf_len,
            real,
        })
    }
}

// ------------------------------------------------------------------------------------------------- sockaddr

/// The size of `struct sockaddr_in`.
pub const SOCKADDR_IN_LEN: usize = 16;
/// The size of `struct sockaddr_in6`.
pub const SOCKADDR_IN6_LEN: usize = 28;

fn check_len(bytes: &[u8], expected: usize) -> Result<(), NetError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(NetError::BadLength {
            expected,
            got: bytes.len(),
        })
    }
}

fn check_family(bytes: &[u8], family: Family) -> Result<(), NetError> {
    let got = u16::from_be_bytes([bytes[0], bytes[1]]);
    if got == family.number() {
        Ok(())
    } else {
        Err(NetError::BadFamily {
            expected: family.number(),
            got,
        })
    }
}

/// An IPv4 socket address: family, port and address, with the 8 bytes of padding zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn {
    pub addr: [u8; 4],
    pub port: u16,
}

impl SockAddrIn {
    /// The 16 bytes the kernel reads: family (the target's own byte order, big-endian), port and address (network order),
    /// zero padding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SOCKADDR_IN_LEN] {
        let mut out = [0u8; SOCKADDR_IN_LEN];
        out[0..2].copy_from_slice(&Family::Inet.number().to_be_bytes());
        out[2..4].copy_from_slice(&self.port.to_be_bytes());
        out[4..8].copy_from_slice(&self.addr);
        out
    }

    /// Read what the kernel wrote back.
    ///
    /// # Errors
    /// [`NetError::BadLength`], [`NetError::BadFamily`] or [`NetError::NonZeroPadding`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetError> {
        check_len(bytes, SOCKADDR_IN_LEN)?;
        check_family(bytes, Family::Inet)?;
        if bytes[8..16].iter().any(|byte| *byte != 0) {
            return Err(NetError::NonZeroPadding);
        }
        Ok(Self {
            addr: [bytes[4], bytes[5], bytes[6], bytes[7]],
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
        })
    }
}

/// An IPv6 socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn6 {
    pub addr: [u8; 16],
    pub port: u16,
    pub flowinfo: u32,
    pub scope_id: u32,
}

impl SockAddrIn6 {
    /// The 28 bytes the kernel reads: family, port, flow information, the 16 address bytes, scope id; all big-endian.
    #[must_use]
    pub fn to_bytes(self) -> [u8; SOCKADDR_IN6_LEN] {
        let mut out = [0u8; SOCKADDR_IN6_LEN];
        out[0..2].copy_from_slice(&Family::Inet6.number().to_be_bytes());
        out[2..4].copy_from_slice(&self.port.to_be_bytes());
        out[4..8].copy_from_slice(&self.flowinfo.to_be_bytes());
        out[8..24].copy_from_slice(&self.addr);
        out[24..28].copy_from_slice(&self.scope_id.to_be_bytes());
        out
    }

    /// Read what the kernel wrote back.
    ///
    /// # Errors
    /// [`NetError::BadLength`] or [`NetError::BadFamily`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetError> {
        check_len(bytes, SOCKADDR_IN6_LEN)?;
        check_family(bytes, Family::Inet6)?;
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&bytes[8..24]);
        Ok(Self {
            addr,
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
            flowinfo: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            scope_id: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
        })
    }
}

// ------------------------------------------------------------------------------------------------- timeval

/// The size of the 32-bit `struct timeval` that `SO_RCVTIMEO_OLD` and `SO_SNDTIMEO_OLD` take on these ABIs.
pub const TIMEVAL32_LEN: usize = 8;

/// A socket timeout as the legacy kernels take it: 32-bit seconds and 32-bit microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeval32 {
    sec: i32,
    usec: i32,
}

impl Timeval32 {
    /// No timeout: the kernel's reading of an all-zero `timeval`. It is only ever built by name.
    pub const FOREVER: Self = Self { sec: 0, usec: 0 };

    /// A finite timeout, rounded **up** to whole microseconds. Zero is refused (the kernel would read it as forever), so is a
    /// value whose seconds do not fit 32 bits (it is not truncated), and so is one whose seconds exceed
    /// [`TIMEVAL_MAX_FINITE_SEC`] (the kernel's own threshold for "no timeout").
    ///
    /// # Errors
    /// [`NetError::ZeroTimeout`] or [`NetError::TimeWidth`].
    pub fn from_duration(duration: Duration) -> Result<Self, NetError> {
        if duration.is_zero() {
            return Err(NetError::ZeroTimeout);
        }
        let micros = duration.as_nanos().div_ceil(1_000);
        let sec = i32::try_from(micros / 1_000_000)
            .ok()
            .filter(|sec| *sec <= TIMEVAL_MAX_FINITE_SEC)
            .ok_or(NetError::TimeWidth)?;
        let usec = i32::try_from(micros % 1_000_000).map_err(|_| NetError::TimeWidth)?;
        Ok(Self { sec, usec })
    }

    #[must_use]
    pub const fn secs(self) -> i32 {
        self.sec
    }

    #[must_use]
    pub const fn micros(self) -> i32 {
        self.usec
    }

    /// The 8 bytes the kernel reads: seconds then microseconds, big-endian.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; TIMEVAL32_LEN] {
        let sec = self.sec.to_be_bytes();
        let usec = self.usec.to_be_bytes();
        [
            sec[0], sec[1], sec[2], sec[3], usec[0], usec[1], usec[2], usec[3],
        ]
    }

    /// Read a `timeval` back, refusing one that is not a time.
    ///
    /// # Errors
    /// [`NetError::BadTimeval`].
    pub fn from_be_bytes(bytes: [u8; TIMEVAL32_LEN]) -> Result<Self, NetError> {
        let sec = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let usec = i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if sec < 0 || !(0..1_000_000).contains(&usec) {
            return Err(NetError::BadTimeval);
        }
        Ok(Self { sec, usec })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    use serde_json::Value;

    use super::*;

    /// Written by hand from the kernel headers' values as the `libc` crate and the E03 probe state them; replayed here and read
    /// again, independently, by `tests/p06/test_net_abi.py`. Nothing in it was produced by this module.
    const VECTORS: &str = include_str!("../tests/vectors/p06_net_abi.json");
    /// This file's own text, for the source test at the end.
    const SOURCE: &str = include_str!("net.rs");
    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("the vector file parses")
    }

    fn abi_named(name: &str) -> Abi {
        match name {
            "powerpc32" => Abi::PowerPc32,
            "mips32" => Abi::Mips32,
            other => panic!("unknown ABI {other}"),
        }
    }

    fn key(abi: Abi) -> &'static str {
        match abi {
            Abi::PowerPc32 => "powerpc32",
            Abi::Mips32 => "mips32",
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        assert!(rest.is_empty(), "odd-length hex {text:?}");
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                    .expect("hex digits")
            })
            .collect()
    }

    fn num(value: &Value, field: &str) -> i64 {
        value[field]
            .as_i64()
            .unwrap_or_else(|| panic!("{field} is not a number in {value}"))
    }

    fn text<'a>(value: &'a Value, field: &str) -> &'a str {
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is not a string in {value}"))
    }

    fn cases<'a>(v: &'a Value, group: &str) -> &'a Vec<Value> {
        v[group]
            .as_array()
            .unwrap_or_else(|| panic!("{group} is not a list"))
    }

    fn error_name(error: &NetError) -> String {
        match error {
            NetError::Sys(SysError::Interrupted) => "interrupted".to_string(),
            NetError::Sys(SysError::Absent) => "absent".to_string(),
            NetError::Sys(SysError::WouldBlock) => "would_block".to_string(),
            NetError::Sys(SysError::Invalid) => "invalid".to_string(),
            NetError::Sys(SysError::Errno(errno)) => format!("errno:{errno}"),
            NetError::Sys(SysError::Malformed(_)) => "malformed".to_string(),
            NetError::ReadyAboveRequested { .. } => "ready_above_requested".to_string(),
            NetError::UnknownReadyBits { .. } => "unknown_ready_bits".to_string(),
            NetError::NegativeDescriptor { .. } => "negative_descriptor".to_string(),
            NetError::OutputOnlyEvent { .. } => "output_only_event".to_string(),
            NetError::UnknownEventBits { .. } => "unknown_event_bits".to_string(),
            NetError::ZeroTimeout => "zero_timeout".to_string(),
            NetError::TimeWidth => "time_width".to_string(),
            NetError::BadTimeval => "bad_timeval".to_string(),
            NetError::BadLength { .. } => "bad_length".to_string(),
            NetError::BadFamily { .. } => "bad_family".to_string(),
            NetError::NonZeroPadding => "non_zero_padding".to_string(),
            NetError::DatagramLength { .. } => "datagram_length".to_string(),
        }
    }

    /// Hold a count-valued result to a vector's `{"ok": n}` or `{"err": name}`.
    fn check_count(result: &Result<usize, NetError>, expect: &Value, context: &str) {
        match (result, expect.get("ok"), expect.get("err")) {
            (Ok(got), Some(want), None) => {
                assert_eq!(
                    i64::try_from(*got).expect("fits"),
                    want.as_i64().expect("number"),
                    "{context}"
                );
            }
            (Err(got), None, Some(want)) => {
                assert_eq!(error_name(got), want.as_str().expect("string"), "{context}");
            }
            _ => panic!("{context}: got {result:?}, the vector says {expect}"),
        }
    }

    /// The kernel's own encoding of a poll timeout: `-1` forever, `0` do not block, otherwise milliseconds.
    fn timeout_of(raw: i64) -> PollTimeout {
        match raw {
            -1 => PollTimeout::Infinite,
            0 => PollTimeout::Immediate,
            ms => PollTimeout::Millis(u32::try_from(ms).expect("a positive timeout")),
        }
    }

    // ------------------------------------------------------------------------------------------ the numbers

    #[test]
    fn the_per_abi_numbers_are_the_vectors() {
        let v = vectors();
        for abi in BOTH {
            let row = &v["abi"][key(abi)];
            let who = format!("{abi:?}");
            assert_eq!(
                i64::from(abi.sock_type(SockKind::Stream)),
                num(row, "sock_stream"),
                "{who}"
            );
            assert_eq!(
                i64::from(abi.sock_type(SockKind::Dgram)),
                num(row, "sock_dgram"),
                "{who}"
            );
            assert_eq!(
                i64::from(abi.o_nonblock()),
                num(row, "sock_nonblock"),
                "{who}"
            );
            assert_eq!(i64::from(SOCK_CLOEXEC), num(row, "sock_cloexec"), "{who}");
            assert_eq!(i64::from(abi.sol_socket()), num(row, "sol_socket"), "{who}");
            for (name, option) in [
                ("reuseaddr", SockOpt::ReuseAddr),
                ("broadcast", SockOpt::Broadcast),
                ("sndbuf", SockOpt::SendBuf),
                ("rcvbuf", SockOpt::RecvBuf),
                ("rcvtimeo", SockOpt::RecvTimeout),
                ("sndtimeo", SockOpt::SendTimeout),
                ("error", SockOpt::PendingError),
                ("type", SockOpt::Type),
            ] {
                assert_eq!(
                    i64::from(abi.sockopt(option)),
                    num(&row["so"], name),
                    "{who} {name}"
                );
            }
            assert_eq!(i64::from(abi.pollwrnorm()), num(row, "pollwrnorm"), "{who}");
            assert_eq!(i64::from(abi.pollwrband()), num(row, "pollwrband"), "{who}");
            for errno in NetErrno::ALL {
                assert_eq!(
                    i64::from(errno.number(abi)),
                    num(&row["errno"], errno.name()),
                    "{who} {}",
                    errno.name()
                );
            }
        }
    }

    #[test]
    fn the_numbers_that_are_the_same_on_both_abis_are_the_vectors_common_block() {
        let v = vectors();
        let common = &v["common"];
        assert_eq!(i64::from(Family::Inet.number()), num(common, "af_inet"));
        assert_eq!(i64::from(Family::Inet6.number()), num(common, "af_inet6"));
        assert_eq!(i64::from(MSG_PEEK), num(common, "msg_peek"));
        assert_eq!(i64::from(MSG_TRUNC), num(common, "msg_trunc"));
        assert_eq!(i64::from(MSG_DONTWAIT), num(common, "msg_dontwait"));
        assert_eq!(i64::from(POLLIN), num(common, "pollin"));
        assert_eq!(i64::from(POLLPRI), num(common, "pollpri"));
        assert_eq!(i64::from(POLLOUT), num(common, "pollout"));
        assert_eq!(i64::from(POLLERR), num(common, "pollerr"));
        assert_eq!(i64::from(POLLHUP), num(common, "pollhup"));
        assert_eq!(i64::from(POLLNVAL), num(common, "pollnval"));
        assert_eq!(i64::from(POLLRDNORM), num(common, "pollrdnorm"));
        assert_eq!(i64::from(POLLRDBAND), num(common, "pollrdband"));
        assert_eq!(RECV_FLAGS, MSG_TRUNC);
    }

    #[test]
    fn the_two_abis_differ_exactly_where_the_vectors_say() {
        let (p, m) = (Abi::PowerPc32, Abi::Mips32);
        assert_ne!(p.sock_type(SockKind::Stream), m.sock_type(SockKind::Stream));
        assert_ne!(p.sock_type(SockKind::Dgram), m.sock_type(SockKind::Dgram));
        // MIPS numbers the two kinds the other way round.
        assert_eq!(p.sock_type(SockKind::Stream), m.sock_type(SockKind::Dgram));
        assert_eq!(p.sock_type(SockKind::Dgram), m.sock_type(SockKind::Stream));
        assert_ne!(p.o_nonblock(), m.o_nonblock());
        assert_ne!(p.sol_socket(), m.sol_socket());
        for option in [
            SockOpt::ReuseAddr,
            SockOpt::Broadcast,
            SockOpt::SendBuf,
            SockOpt::RecvBuf,
            SockOpt::RecvTimeout,
            SockOpt::SendTimeout,
            SockOpt::PendingError,
            SockOpt::Type,
        ] {
            assert_ne!(p.sockopt(option), m.sockopt(option), "{option:?}");
        }
        assert_ne!(p.pollwrnorm(), m.pollwrnorm());
        assert_ne!(p.pollwrband(), m.pollwrband());
        // MIPS's write-normal bit is the plain write bit.
        assert_eq!(m.pollwrnorm(), POLLOUT);
        for errno in NetErrno::ALL {
            assert_ne!(errno.number(p), errno.number(m), "{}", errno.name());
        }
        // ...and what does not differ is not duplicated per ABI.
        assert_eq!(SOCK_CLOEXEC, O_CLOEXEC);
        assert_eq!(Family::Inet.number(), 2);
    }

    #[test]
    fn a_number_never_names_a_network_error_on_both_abis_so_the_generic_table_is_wrong_on_mips() {
        // The generic numbering (PowerPC's, and the one FrankenLibC's errno module carries) read on MIPS: every one of the ten
        // numbers is some other error, or none of the ten.
        for errno in NetErrno::ALL {
            let generic = errno.number(Abi::PowerPc32);
            assert_eq!(Abi::PowerPc32.classify_net_errno(generic), Some(errno));
            assert_eq!(
                Abi::Mips32.classify_net_errno(generic),
                None,
                "{} as {generic}",
                errno.name()
            );
            let mips = errno.number(Abi::Mips32);
            assert_eq!(Abi::Mips32.classify_net_errno(mips), Some(errno));
            assert_eq!(
                Abi::PowerPc32.classify_net_errno(mips),
                None,
                "{} as {mips}",
                errno.name()
            );
        }
    }

    #[test]
    fn errno_classification_follows_the_vectors_and_only_a_decoded_errno_can_be_a_network_error() {
        let v = vectors();
        for case in cases(&v, "net_errno") {
            let abi = abi_named(text(case, "abi"));
            let got = abi
                .classify_net_errno(i32::try_from(num(case, "errno")).expect("fits"))
                .map(NetErrno::name);
            assert_eq!(got, case["expect"].as_str(), "{case}");
        }
        assert_eq!(
            Abi::Mips32.net_errno_of(SysError::Errno(146)),
            Some(NetErrno::ConnRefused)
        );
        assert_eq!(Abi::PowerPc32.net_errno_of(SysError::Errno(146)), None);
        for other in [
            SysError::Interrupted,
            SysError::WouldBlock,
            SysError::Invalid,
            SysError::Absent,
        ] {
            assert_eq!(Abi::Mips32.net_errno_of(other), None, "{other:?}");
        }
    }

    #[test]
    fn the_socket_type_argument_carries_the_flags_the_call_itself_sets() {
        let v = vectors();
        for case in cases(&v, "socket_type_arg") {
            let abi = abi_named(text(case, "abi"));
            let kind = match text(case, "kind") {
                "stream" => SockKind::Stream,
                "dgram" => SockKind::Dgram,
                other => panic!("unknown kind {other}"),
            };
            let nonblock = case["nonblock"].as_bool().expect("bool");
            let cloexec = case["cloexec"].as_bool().expect("bool");
            assert_eq!(
                i64::from(abi.socket_type_arg(kind, nonblock, cloexec)),
                num(case, "value"),
                "{case}"
            );
        }
        // The same number is a different socket on the two ABIs: PowerPC datagram|cloexec is MIPS stream|cloexec.
        assert_eq!(
            Abi::PowerPc32.socket_type_arg(SockKind::Dgram, false, true),
            Abi::Mips32.socket_type_arg(SockKind::Stream, false, true)
        );
    }

    #[test]
    fn the_timeout_options_are_the_32_bit_ones_and_never_the_64_bit_new_ones() {
        let v = vectors();
        let never = &v["never_used_sockopts"];
        for abi in BOTH {
            for option in [SockOpt::RecvTimeout, SockOpt::SendTimeout] {
                for name in ["so_rcvtimeo_new", "so_sndtimeo_new"] {
                    assert_ne!(
                        i64::from(abi.sockopt(option)),
                        num(never, name),
                        "{abi:?} {option:?}"
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------ poll layout

    #[test]
    fn pollfd_bytes_are_big_endian_and_round_trip() {
        let v = vectors();
        for case in cases(&v, "pollfd") {
            let entry = PollFd {
                fd: i32::try_from(num(case, "fd")).expect("fits"),
                events: u16::try_from(num(case, "events")).expect("fits"),
                revents: u16::try_from(num(case, "revents")).expect("fits"),
            };
            let bytes = hex(text(case, "bytes"));
            assert_eq!(bytes.len(), POLLFD_LEN);
            assert_eq!(entry.to_be_bytes().as_slice(), bytes.as_slice(), "{case}");
            let back = PollFd::from_be_bytes(bytes.as_slice().try_into().expect("8 bytes"));
            assert_eq!(back, entry, "{case}");
        }
    }

    #[test]
    fn a_host_endian_pollfd_is_not_the_layout() {
        // What a codec that wrote each field little-endian would produce for fd 0x01020304, events 4, revents 0, which is what a
        // host-order codec produces on the usual little-endian development host. The kernel on both ABIs reads the other thing.
        let entry = PollFd {
            fd: 0x0102_0304,
            events: 4,
            revents: 0,
        };
        let big = entry.to_be_bytes();
        let little = {
            let fd = entry.fd.to_le_bytes();
            let ev = entry.events.to_le_bytes();
            let rev = entry.revents.to_le_bytes();
            [fd[0], fd[1], fd[2], fd[3], ev[0], ev[1], rev[0], rev[1]]
        };
        assert_ne!(big, little);
        assert_eq!(big, [1, 2, 3, 4, 0, 4, 0, 0]);
    }

    #[test]
    fn a_poll_request_is_built_only_for_a_real_descriptor_and_events_the_abi_knows() {
        let v = vectors();
        for case in cases(&v, "pollfd_request") {
            let abi = abi_named(text(case, "abi"));
            let got = PollFd::request(
                abi,
                i32::try_from(num(case, "fd")).expect("fits"),
                u16::try_from(num(case, "events")).expect("fits"),
            )
            .map(|entry| usize::from(entry.revents == 0));
            check_count(&got, &case["expect"], &case.to_string());
        }
    }

    #[test]
    fn ready_bits_are_believed_only_inside_the_abis_known_set() {
        let v = vectors();
        for case in cases(&v, "poll_ready_bits") {
            let abi = abi_named(text(case, "abi"));
            let entry = PollFd {
                fd: 3,
                events: POLLIN,
                revents: u16::try_from(num(case, "revents")).expect("fits"),
            };
            let got = entry.ready(abi).map(usize::from);
            check_count(&got, &case["expect"], &case.to_string());
        }
        // The one bit that is write-band on PowerPC is unknown on MIPS, and the reverse for MIPS's write-band bit.
        assert!(
            PollFd {
                fd: 3,
                events: 0,
                revents: 0x200
            }
            .ready(Abi::PowerPc32)
            .is_ok()
        );
        assert!(
            PollFd {
                fd: 3,
                events: 0,
                revents: 0x200
            }
            .ready(Abi::Mips32)
            .is_err()
        );
    }

    // ----------------------------------------------------------------------------------------- poll timing

    #[test]
    fn poll_timeouts_round_up_never_become_forever_and_refuse_what_does_not_fit_an_int() {
        let v = vectors();
        for case in cases(&v, "poll_timeout") {
            let duration = Duration::from_nanos(u64::try_from(num(case, "nanos")).expect("fits"));
            let got = PollTimeout::from_duration(duration)
                .map(|t| usize::try_from(t.to_raw()).expect("not negative"));
            check_count(&got, &case["expect"], &case.to_string());
        }
        assert_eq!(PollTimeout::Infinite.to_raw(), -1);
        // The constant is the vector's, derived there from the kernel's formula (`timeout < LONG_MAX / HZ`).
        let ceiling = num(&v["legacy_forever"], "poll_max_ms");
        assert_eq!(i64::from(POLL_MAX_FINITE_MS), ceiling);
        // The edge: the last finite value is accepted, the next is refused rather than silently read as forever.
        let ms = Duration::from_millis;
        let edge = u64::try_from(ceiling).expect("positive");
        assert_eq!(
            PollTimeout::from_duration(ms(edge)),
            Ok(PollTimeout::Millis(POLL_MAX_FINITE_MS))
        );
        assert_eq!(
            PollTimeout::from_duration(ms(edge + 1)),
            Err(NetError::TimeWidth)
        );
        assert_eq!(
            PollTimeout::from_duration(ms(u64::from(u32::MAX))),
            Err(NetError::TimeWidth)
        );
        // A public Millis above the ceiling is clamped to it: never i32::MAX (the old kernel's forever), never the -1.
        assert_eq!(
            PollTimeout::Millis(u32::MAX).to_raw(),
            i32::try_from(POLL_MAX_FINITE_MS).expect("fits")
        );
        assert_eq!(
            PollTimeout::Millis(POLL_MAX_FINITE_MS + 1).to_raw(),
            i32::try_from(POLL_MAX_FINITE_MS).expect("fits")
        );
        assert_eq!(PollTimeout::Immediate.to_raw(), 0);
    }

    #[test]
    fn the_time_left_after_an_interruption_is_rounded_up_and_an_expired_wait_is_one_last_look() {
        let ms = Duration::from_millis;
        let t = PollTimeout::Millis(100);
        assert_eq!(t.remaining(ms(0)), PollTimeout::Millis(100));
        assert_eq!(t.remaining(ms(60)), PollTimeout::Millis(40));
        assert_eq!(
            t.remaining(Duration::from_micros(59_500)),
            PollTimeout::Millis(41)
        );
        assert_eq!(t.remaining(ms(100)), PollTimeout::Immediate);
        assert_eq!(t.remaining(ms(150)), PollTimeout::Immediate);
        assert_eq!(
            PollTimeout::Infinite.remaining(ms(10_000)),
            PollTimeout::Infinite
        );
        assert_eq!(
            PollTimeout::Immediate.remaining(ms(10_000)),
            PollTimeout::Immediate
        );
    }

    #[test]
    fn poll_results_decode_with_the_abis_own_errno_and_an_impossible_count_is_not_believed() {
        let v = vectors();
        for case in cases(&v, "poll_decode") {
            let abi = abi_named(text(case, "abi"));
            let got = decode_poll(
                abi,
                isize::try_from(num(case, "raw")).expect("fits"),
                usize::try_from(num(case, "requested")).expect("fits"),
            );
            check_count(&got, &case["expect"], &case.to_string());
        }
    }

    /// Run `poll_retrying` against a vector's script: each call returns the next scripted value, and the clock reads the elapsed
    /// time recorded for the call that just returned. Returns the result and the timeouts the calls were given.
    fn run_retry(case: &Value) -> (Result<usize, NetError>, Vec<i64>) {
        let abi = abi_named(text(case, "abi"));
        let requested = usize::try_from(num(case, "requested")).expect("fits");
        let script: Vec<(isize, u64)> = cases(case, "script")
            .iter()
            .map(|step| {
                (
                    isize::try_from(num(step, "raw")).expect("fits"),
                    u64::try_from(num(step, "elapsed_ms")).expect("fits"),
                )
            })
            .collect();
        let step = Cell::new(0usize);
        let given = RefCell::new(Vec::<i64>::new());
        let result = poll_retrying(
            abi,
            requested,
            timeout_of(num(case, "timeout_ms")),
            |ms| {
                given.borrow_mut().push(i64::from(ms));
                let index = step.get();
                step.set(index + 1);
                script[index].0
            },
            || Duration::from_millis(script[step.get() - 1].1),
        );
        (result, given.into_inner())
    }

    #[test]
    fn an_interrupted_poll_is_retried_with_the_time_left_and_never_the_whole_timeout() {
        let v = vectors();
        for case in cases(&v, "poll_retry") {
            let (result, given) = run_retry(case);
            check_count(&result, &case["expect"], &case.to_string());
            let want: Vec<i64> = cases(case, "calls_ms")
                .iter()
                .map(|ms| ms.as_i64().expect("number"))
                .collect();
            assert_eq!(given, want, "{}", text(case, "name"));
        }
    }

    /// The judge: every call must have been given no more time than was left of the budget when it was made (one millisecond of
    /// rounding allowed). `already` is the time that had passed before each call.
    fn budget_respected(timeout_ms: i64, already_ms: &[i64], given_ms: &[i64]) -> bool {
        already_ms
            .iter()
            .zip(given_ms)
            .all(|(already, given)| *given < 0 || already + given <= timeout_ms + 1)
    }

    #[test]
    fn the_naive_retry_stretches_the_wait_and_the_judge_tells_it_from_the_real_one() {
        let v = vectors();
        let case = cases(&v, "poll_retry")
            .iter()
            .find(|c| text(c, "name") == "interrupted_once_then_ready")
            .expect("the vector exists");
        let timeout_ms = num(case, "timeout_ms");
        let (_, given) = run_retry(case);
        let already = [0, 60];
        assert!(budget_respected(timeout_ms, &already, &given), "{given:?}");
        // Planted: the same script through the generic retry, which repeats the identical call. It passes the whole timeout again
        // after 60 ms have gone, which the judge refuses; removing the plant (the run above) is what passes it.
        let planted_given = RefCell::new(Vec::<i64>::new());
        let attempt = Cell::new(0usize);
        let outcome = Abi::Mips32.call_retrying(|| {
            planted_given.borrow_mut().push(timeout_ms);
            attempt.set(attempt.get() + 1);
            if attempt.get() == 1 { -4 } else { 1 }
        });
        assert_eq!(outcome, Ok(1));
        assert!(!budget_respected(
            timeout_ms,
            &already,
            &planted_given.into_inner()
        ));
    }

    #[test]
    fn a_poll_that_is_interrupted_every_time_is_reported_after_the_bound_and_not_swallowed() {
        let v = vectors();
        let case = cases(&v, "poll_retry")
            .iter()
            .find(|c| text(c, "name") == "always_interrupted")
            .expect("the vector exists");
        let (result, given) = run_retry(case);
        assert_eq!(result, Err(NetError::Sys(SysError::Interrupted)));
        assert_eq!(
            given.len(),
            usize::try_from(MAX_INTERRUPTED_ATTEMPTS).expect("fits")
        );
    }

    // -------------------------------------------------------------------------------------------- datagrams

    #[test]
    fn a_datagram_read_says_complete_or_truncated_with_the_real_length() {
        let v = vectors();
        // The bound is the vector's: 65 535 minus the 8-byte UDP header. Its two edges are rows of `recv_decode` below.
        assert_eq!(
            i64::try_from(MAX_DATAGRAM).expect("fits"),
            num(&v["legacy_forever"], "max_datagram")
        );
        for case in cases(&v, "recv_decode") {
            let abi = abi_named(text(case, "abi"));
            let got = decode_datagram(
                abi,
                isize::try_from(num(case, "raw")).expect("fits"),
                usize::try_from(num(case, "buf")).expect("fits"),
            );
            let expect = &case["expect"];
            match (
                &got,
                expect.get("complete"),
                expect.get("truncated"),
                expect.get("err"),
            ) {
                (Ok(Datagram::Complete { len }), Some(want), None, None) => {
                    assert_eq!(
                        i64::try_from(*len).expect("fits"),
                        want.as_i64().expect("number"),
                        "{case}"
                    );
                }
                (Ok(Datagram::Truncated { stored, real }), None, Some(want), None) => {
                    assert_eq!(
                        i64::try_from(*stored).expect("fits"),
                        num(want, "stored"),
                        "{case}"
                    );
                    assert_eq!(
                        i64::try_from(*real).expect("fits"),
                        num(want, "real"),
                        "{case}"
                    );
                }
                (Err(error), None, None, Some(want)) => {
                    assert_eq!(error_name(error), want.as_str().expect("string"), "{case}");
                }
                _ => panic!("got {got:?}, the vector says {expect}"),
            }
        }
    }

    #[test]
    fn the_e03_loopback_fact_is_a_truncated_read_of_24_bytes_into_a_16_byte_buffer() {
        // Run 1412ac47's UDP_LOOPBACK line: rc 24 for a 16-byte buffer, which is how a read with MSG_TRUNC reports a datagram
        // that did not fit. Never "complete", and never the 16 bytes that were stored presented as the message.
        for abi in BOTH {
            assert_eq!(
                decode_datagram(abi, 24, 16),
                Ok(Datagram::Truncated {
                    stored: 16,
                    real: 24
                })
            );
        }
    }

    // --------------------------------------------------------------------------------------- sockaddr, timeval

    #[test]
    fn sockaddr_in_bytes_are_the_vectors_and_round_trip() {
        let v = vectors();
        for case in cases(&v, "sockaddr_in") {
            let addr: Vec<u8> = cases(case, "addr")
                .iter()
                .map(|b| u8::try_from(b.as_i64().expect("number")).expect("byte"))
                .collect();
            let value = SockAddrIn {
                addr: addr.as_slice().try_into().expect("4 bytes"),
                port: u16::try_from(num(case, "port")).expect("fits"),
            };
            let bytes = hex(text(case, "bytes"));
            assert_eq!(value.to_bytes().as_slice(), bytes.as_slice(), "{case}");
            assert_eq!(SockAddrIn::from_bytes(&bytes), Ok(value), "{case}");
        }
        // The family is the target's own order: [0, 2], not the host-little [2, 0].
        assert_eq!(
            &SockAddrIn {
                addr: [0; 4],
                port: 0
            }
            .to_bytes()[0..2],
            &[0, 2]
        );
    }

    #[test]
    fn a_sockaddr_in_that_is_the_wrong_length_family_or_padding_is_refused() {
        let v = vectors();
        for case in cases(&v, "sockaddr_in_reject") {
            let got = SockAddrIn::from_bytes(&hex(text(case, "bytes")));
            let name = got.as_ref().map(|_| 0usize);
            check_count(&name.map_err(|e| *e), &case["expect"], &case.to_string());
        }
    }

    #[test]
    fn sockaddr_in6_bytes_are_the_vectors_and_round_trip() {
        let v = vectors();
        for case in cases(&v, "sockaddr_in6") {
            let addr: Vec<u8> = hex(text(case, "addr"));
            let value = SockAddrIn6 {
                addr: addr.as_slice().try_into().expect("16 bytes"),
                port: u16::try_from(num(case, "port")).expect("fits"),
                flowinfo: u32::try_from(num(case, "flowinfo")).expect("fits"),
                scope_id: u32::try_from(num(case, "scope_id")).expect("fits"),
            };
            let bytes = hex(text(case, "bytes"));
            assert_eq!(value.to_bytes().as_slice(), bytes.as_slice(), "{case}");
            assert_eq!(SockAddrIn6::from_bytes(&bytes), Ok(value), "{case}");
        }
        for case in cases(&v, "sockaddr_in6_reject") {
            let got = SockAddrIn6::from_bytes(&hex(text(case, "bytes")));
            let name = got.as_ref().map(|_| 0usize);
            check_count(&name.map_err(|e| *e), &case["expect"], &case.to_string());
        }
    }

    #[test]
    fn a_socket_timeout_is_32_bit_microseconds_rounded_up_and_refuses_zero_and_overflow() {
        let v = vectors();
        for case in cases(&v, "timeval32") {
            let duration = Duration::from_nanos(u64::try_from(num(case, "nanos")).expect("fits"));
            match (
                Timeval32::from_duration(duration),
                case.get("bytes"),
                case.get("err"),
            ) {
                (Ok(value), Some(want), None) => {
                    assert_eq!(
                        value.to_be_bytes().as_slice(),
                        hex(want.as_str().expect("string")).as_slice(),
                        "{case}"
                    );
                    assert_eq!(Timeval32::from_be_bytes(value.to_be_bytes()), Ok(value));
                }
                (Err(error), None, Some(want)) => {
                    assert_eq!(error_name(&error), want.as_str().expect("string"), "{case}");
                }
                (got, ..) => panic!("got {got:?}, the vector says {case}"),
            }
        }
        // The constant is the vector's, derived there from the kernel's formula (`tv_sec < LONG_MAX / HZ - 1`).
        let ceiling = num(&v["legacy_forever"], "timeval_max_sec");
        assert_eq!(i64::from(TIMEVAL_MAX_FINITE_SEC), ceiling);
        let sec = u64::try_from(ceiling).expect("positive");
        // The last finite second count is accepted with its microseconds; the next second is refused, not read as no timeout.
        let last = Timeval32::from_duration(Duration::new(sec, 999_999_000))
            .expect("the last finite timeout");
        assert_eq!(i64::from(last.secs()), ceiling);
        assert_eq!(last.micros(), 999_999);
        assert_eq!(
            Timeval32::from_duration(Duration::from_secs(sec + 1)),
            Err(NetError::TimeWidth)
        );
    }

    #[test]
    fn a_timeval_read_back_must_be_a_time_and_forever_is_only_ever_asked_for_by_name() {
        let v = vectors();
        for case in cases(&v, "timeval32_read") {
            let bytes: [u8; TIMEVAL32_LEN] = hex(text(case, "bytes"))
                .as_slice()
                .try_into()
                .expect("8 bytes");
            match (Timeval32::from_be_bytes(bytes), case.get("err")) {
                (Ok(value), None) => assert_eq!(
                    (i64::from(value.secs()), i64::from(value.micros())),
                    (num(case, "sec"), num(case, "usec")),
                    "{case}"
                ),
                (Err(error), Some(want)) => {
                    assert_eq!(error_name(&error), want.as_str().expect("string"), "{case}")
                }
                (got, _) => panic!("got {got:?}, the vector says {case}"),
            }
        }
        assert_eq!(Timeval32::FOREVER.to_be_bytes(), [0; TIMEVAL32_LEN]);
        assert_eq!(
            Timeval32::from_duration(Duration::ZERO),
            Err(NetError::ZeroTimeout)
        );
    }

    // ------------------------------------------------------------------------------------------ the source

    #[test]
    fn the_source_has_no_thread_local_errno_no_unsafe_and_no_other_libraries_net_code() {
        let code: String = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("the code comes before the tests")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "thread_local",
            "unsafe",
            "std::net",
            "libc::",
            "gettimeofday",
            "fcntl",
            "extern ",
        ] {
            assert!(!code.contains(forbidden), "the code mentions {forbidden:?}");
        }
    }
}
