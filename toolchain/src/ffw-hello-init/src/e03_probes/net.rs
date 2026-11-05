//! Real-syscall E03 slice-2 probes (ffw-q2p, BLK-006): `LOOPBACK_UP`, `UDP_LOOPBACK`, `ACCEPT4`,
//! `REACTOR_WAKE`, `CHARDEV_POLL`. Child of `e03_probes`, so it reaches that module's helpers through
//! `super::` and the audited trampoline in `main.rs` through `crate::`. The pass/fail decision lives in
//! `ffw_hello_init::e03_judge::net`, where it has host tests.
//!
//! Line contract (same as slice 1): `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<value>`. When a syscall
//! that must succeed fails, `<value>` is that raw negative return, so `-ENOSYS` is an explicit
//! capability failure and any other errno is ambiguous. On a pass it is the probe's success value.
//!
//! Bounds: every `poll` has a timeout, receives are `MSG_DONTWAIT`, the listener and the client are
//! nonblocking, and the one forked child exits right after a single write. Worst case for the module is
//! under two seconds.
//!
//! Constraint worth knowing: the trampoline carries at most five syscall arguments and leaves the sixth
//! undefined. So there is no `sendto`/`recvfrom` with an address here: the sender `connect`s and
//! `send`s, and the receiver uses `recv`/`recvmsg`, all of which take four arguments or fewer.
//!
//! Scope: nothing here touches a real network path or the retained audio driver; see the judge docs.

use ffw_hello_init::e03_judge::net as judge;
use ffw_hello_init::e03_judge::{Verdict, POLLIN};

use super::{mono_ns, report, sc, sleep_ms};
use crate::{sys, sys_close, sys_exit, sys_open, sys_read, sys_write, PollFd};

/// Per-ABI numbers, from the libc 0.2.191 tables (MIPS o32 is 4000-based; PowerPC32 is generic), and
/// the two socket/errno values that differ between the ABIs.
#[cfg(target_arch = "mips")]
mod nr {
    pub const FORK: usize = 4002;
    pub const IOCTL: usize = 4054;
    pub const FCNTL: usize = 4055;
    pub const WAIT4: usize = 4114;
    pub const BIND: usize = 4169;
    pub const CONNECT: usize = 4170;
    pub const GETSOCKNAME: usize = 4172;
    pub const LISTEN: usize = 4174;
    pub const RECV: usize = 4175;
    pub const RECVMSG: usize = 4177;
    pub const SEND: usize = 4178;
    pub const ACCEPT4: usize = 4334;
    /// MIPS swaps the socket types: STREAM is 2 and DGRAM is 1.
    pub const SOCK_STREAM: usize = 2;
    pub const EINPROGRESS: isize = 150;
}

#[cfg(target_arch = "powerpc")]
mod nr {
    pub const FORK: usize = 2;
    pub const IOCTL: usize = 54;
    pub const FCNTL: usize = 55;
    pub const WAIT4: usize = 114;
    pub const BIND: usize = 327;
    pub const CONNECT: usize = 328;
    pub const GETSOCKNAME: usize = 331;
    pub const LISTEN: usize = 329;
    pub const RECV: usize = 336;
    pub const RECVMSG: usize = 342;
    pub const SEND: usize = 334;
    pub const ACCEPT4: usize = 344;
    pub const SOCK_STREAM: usize = 1;
    pub const EINPROGRESS: isize = 115;
}

const AF_INET: u16 = 2;
const MSG_TRUNC_FLAG: usize = 0x20;
const MSG_DONTWAIT: usize = 0x40;
const SIOCGIFFLAGS: usize = 0x8913;
const SIOCSIFFLAGS: usize = 0x8914;
const F_GETFD: usize = 1;
const F_GETFL: usize = 3;
const F_SETFL: usize = 4;
const WNOHANG: usize = 1;
/// `SOCK_CLOEXEC` equals `O_CLOEXEC` (0o2000000) on both ABIs; `SOCK_NONBLOCK` equals `O_NONBLOCK`.
const SOCK_CLOEXEC: usize = 0x80000;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const POLL_MS: usize = 100;
const LOOPBACK_ADDR: [u8; 4] = [127, 0, 0, 1];

/// `struct iovec` and the 32-bit `struct msghdr` (seven 4-byte fields, no padding, per libc's table).
// The fields are read by the kernel through the pointer, not by Rust (only `flags` is read back).
#[allow(dead_code)]
#[repr(C)]
struct IoVec32 {
    base: usize,
    len: usize,
}

#[allow(dead_code)]
#[repr(C)]
struct MsgHdr32 {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
    flags: i32,
}

/// Descriptors to close when a probe ends, however early it stopped.
struct Fds {
    list: [usize; 8],
    n: usize,
}

impl Fds {
    const fn new() -> Self {
        Self { list: [0; 8], n: 0 }
    }

    fn add(&mut self, fd: isize) {
        if fd >= 0 && self.n < self.list.len() {
            self.list[self.n] = fd as usize;
            self.n += 1;
        }
    }

    fn close_all(&mut self) {
        while self.n > 0 {
            self.n -= 1;
            let _ = sys_close(self.list[self.n]);
        }
    }
}

/// Record the first failure of a syscall that must succeed. Returns whether to carry on.
fn must(rc: isize, err: &mut isize) -> bool {
    if rc < 0 {
        *err = rc;
        false
    } else {
        true
    }
}

fn elapsed(start: Option<i64>, end: Option<i64>) -> i64 {
    match (start, end) {
        (Some(a), Some(b)) => b - a,
        _ => -1,
    }
}

fn poll_fd(fd: isize, events: i16, timeout_ms: usize) -> (isize, i16) {
    let mut p = PollFd {
        fd: fd as i32,
        events,
        revents: 0,
    };
    let rc = sc(
        sys::NR_POLL,
        &mut p as *mut PollFd as usize,
        1,
        timeout_ms,
        0,
    );
    (rc, p.revents)
}

/// `struct sockaddr_in` as bytes: native-endian family, big-endian port, 127.0.0.1, zero padding.
fn sockaddr_in(port: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..2].copy_from_slice(&AF_INET.to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&LOOPBACK_ADDR);
    a
}

fn socket(kind: usize) -> isize {
    sc(sys::NR_SOCKET, AF_INET as usize, kind, 0, 0)
}

fn bind_ephemeral(fd: usize) -> isize {
    let addr = sockaddr_in(0);
    sc(nr::BIND, fd, addr.as_ptr() as usize, addr.len(), 0)
}

fn bound_port(fd: usize) -> (isize, u16) {
    let mut addr = [0u8; 16];
    let mut len: u32 = 16;
    let rc = sc(
        nr::GETSOCKNAME,
        fd,
        addr.as_mut_ptr() as usize,
        &mut len as *mut u32 as usize,
        0,
    );
    (rc, u16::from_be_bytes([addr[2], addr[3]]))
}

fn connect_to(fd: usize, port: u16) -> isize {
    let addr = sockaddr_in(port);
    sc(nr::CONNECT, fd, addr.as_ptr() as usize, addr.len(), 0)
}

// ----------------------------------------------------------------------------------- LOOPBACK_UP

/// `struct ifreq` (40 bytes covers both the 32- and 64-bit layouts) naming `lo`; flags live at 16.
fn ifreq_lo() -> [u8; 40] {
    let mut r = [0u8; 40];
    r[0] = b'l';
    r[1] = b'o';
    r
}

fn probe_loopback_up() -> Verdict {
    let mut fds = Fds::new();
    let mut o = judge::LoopbackObs {
        socket_rc: judge::NOT_RUN,
        get_rc: 0,
        set_rc: judge::NOT_RUN,
        reread_rc: 0,
        flags_after: 0,
    };
    // Bring the loopback interface up the way `ip link set lo up` does: read flags, add IFF_UP, set.
    // Nothing else brings it up in this initramfs, and the kernel adds 127.0.0.1/8 itself on NETDEV_UP.
    let sock = socket(sys::SOCK_DGRAM);
    fds.add(sock);
    o.socket_rc = sock;
    if sock >= 0 {
        let fd = sock as usize;
        let mut req = ifreq_lo();
        o.get_rc = sc(nr::IOCTL, fd, SIOCGIFFLAGS, req.as_mut_ptr() as usize, 0);
        if o.get_rc >= 0 {
            let flags = i16::from_ne_bytes([req[16], req[17]]);
            req[16..18].copy_from_slice(&(flags | judge::IFF_UP).to_ne_bytes());
            o.set_rc = sc(nr::IOCTL, fd, SIOCSIFFLAGS, req.as_mut_ptr() as usize, 0);
            if o.set_rc >= 0 {
                let mut again = ifreq_lo();
                o.reread_rc = sc(nr::IOCTL, fd, SIOCGIFFLAGS, again.as_mut_ptr() as usize, 0);
                o.flags_after = i16::from_ne_bytes([again[16], again[17]]);
            }
        }
    }
    fds.close_all();
    judge::judge_loopback(&o)
}

// ----------------------------------------------------------------------------------- UDP_LOOPBACK

fn payload(base: u8) -> [u8; judge::UDP_PAYLOAD_LEN] {
    let mut p = [0u8; judge::UDP_PAYLOAD_LEN];
    for (i, b) in p.iter_mut().enumerate() {
        *b = base.wrapping_add(i as u8);
    }
    p
}

/// `recvmsg` with `MSG_DONTWAIT` into a 16-byte buffer: the return and the kernel's `msg_flags`.
fn recvmsg_dontwait(fd: usize, buf: &mut [u8; judge::UDP_RECV_BUF]) -> (isize, i32) {
    let mut iov = IoVec32 {
        base: buf.as_mut_ptr() as usize,
        len: buf.len(),
    };
    let mut msg = MsgHdr32 {
        name: 0,
        namelen: 0,
        iov: &mut iov as *mut IoVec32 as usize,
        iovlen: 1,
        control: 0,
        controllen: 0,
        flags: 0,
    };
    let ret = sc(
        nr::RECVMSG,
        fd,
        &mut msg as *mut MsgHdr32 as usize,
        MSG_DONTWAIT,
        0,
    );
    (ret, msg.flags)
}

fn udp_steps(o: &mut judge::UdpObs, fds: &mut Fds) {
    let rx = socket(sys::SOCK_DGRAM);
    fds.add(rx);
    if !must(rx, &mut o.err) {
        return;
    }
    let tx = socket(sys::SOCK_DGRAM);
    fds.add(tx);
    if !must(tx, &mut o.err) {
        return;
    }
    let (rx, tx) = (rx as usize, tx as usize);
    if !must(bind_ephemeral(rx), &mut o.err) {
        return;
    }
    let (rc, port) = bound_port(rx);
    if !must(rc, &mut o.err) {
        return;
    }
    o.port = port;
    if !must(connect_to(tx, port), &mut o.err) {
        return;
    }
    let (a, b, c) = (payload(0x41), payload(0x61), payload(0x30));
    let mut buf = [0u8; judge::UDP_RECV_BUF];

    // 24 bytes into a 16-byte buffer: 16 come back and the kernel flags the truncation.
    if !must(
        sc(nr::SEND, tx, a.as_ptr() as usize, a.len(), 0),
        &mut o.err,
    ) || !must(poll_fd(rx as isize, POLLIN, POLL_MS).0, &mut o.err)
    {
        return;
    }
    let (ret, flags) = recvmsg_dontwait(rx, &mut buf);
    if !must(ret, &mut o.err) {
        return;
    }
    o.trunc_ret = ret;
    o.trunc_flags = flags;
    o.trunc_prefix_ok = buf[..] == a[..judge::UDP_RECV_BUF];

    // MSG_TRUNC on recv returns the REAL datagram length although only 16 bytes are copied.
    if !must(
        sc(nr::SEND, tx, b.as_ptr() as usize, b.len(), 0),
        &mut o.err,
    ) || !must(poll_fd(rx as isize, POLLIN, POLL_MS).0, &mut o.err)
    {
        return;
    }
    let ret = sc(
        nr::RECV,
        rx,
        buf.as_mut_ptr() as usize,
        buf.len(),
        MSG_TRUNC_FLAG | MSG_DONTWAIT,
    );
    if !must(ret, &mut o.err) {
        return;
    }
    o.real_len_ret = ret;
    o.real_len_prefix_ok = buf[..] == b[..judge::UDP_RECV_BUF];

    // An 8-byte datagram fits: whole, and not flagged.
    if !must(
        sc(nr::SEND, tx, c.as_ptr() as usize, judge::UDP_SHORT_LEN, 0),
        &mut o.err,
    ) || !must(poll_fd(rx as isize, POLLIN, POLL_MS).0, &mut o.err)
    {
        return;
    }
    let (ret, flags) = recvmsg_dontwait(rx, &mut buf);
    if !must(ret, &mut o.err) {
        return;
    }
    o.short_ret = ret;
    o.short_flags = flags;
    o.short_ok = buf[..judge::UDP_SHORT_LEN] == c[..judge::UDP_SHORT_LEN];

    // Nothing left: a nonblocking receive must say so, not block and not return data.
    o.empty_rc = sc(
        nr::RECV,
        rx,
        buf.as_mut_ptr() as usize,
        buf.len(),
        MSG_DONTWAIT,
    );
}

fn probe_udp() -> Verdict {
    let mut fds = Fds::new();
    let mut o = judge::UdpObs {
        err: 0,
        port: 0,
        trunc_ret: judge::NOT_RUN,
        trunc_flags: 0,
        trunc_prefix_ok: false,
        real_len_ret: judge::NOT_RUN,
        real_len_prefix_ok: false,
        short_ret: judge::NOT_RUN,
        short_flags: 0,
        short_ok: false,
        empty_rc: judge::NOT_RUN,
    };
    udp_steps(&mut o, &mut fds);
    fds.close_all();
    judge::judge_udp(&o)
}

// ----------------------------------------------------------------------------------- ACCEPT4

fn accept_steps(o: &mut judge::AcceptObs, fds: &mut Fds) {
    // Setup uses only calls that exist on every kernel in scope (socket, bind, listen, fcntl, connect),
    // so a kernel without accept4 reaches it and answers -ENOSYS there.
    let lis = socket(nr::SOCK_STREAM);
    fds.add(lis);
    if !must(lis, &mut o.err) {
        return;
    }
    let lis = lis as usize;
    if !must(bind_ephemeral(lis), &mut o.err) {
        return;
    }
    let (rc, port) = bound_port(lis);
    if !must(rc, &mut o.err) || !must(sc(nr::LISTEN, lis, 1, 0, 0), &mut o.err) {
        return;
    }
    // A nonblocking listener cannot hang PID 1; accept4 returns -EAGAIN if no connection is pending.
    // Linux does not pass O_NONBLOCK on to accepted sockets, so this does not confound the flag check.
    if !must(sc(nr::FCNTL, lis, F_SETFL, sys::O_NONBLOCK, 0), &mut o.err) {
        return;
    }
    let cli = socket(nr::SOCK_STREAM);
    fds.add(cli);
    if !must(cli, &mut o.err) {
        return;
    }
    let cli = cli as usize;
    if !must(sc(nr::FCNTL, cli, F_SETFL, sys::O_NONBLOCK, 0), &mut o.err) {
        return;
    }
    let rc = connect_to(cli, port);
    if rc < 0 && rc != -nr::EINPROGRESS {
        o.err = rc;
        return;
    }
    // Let the handshake finish: the client becomes writable and the listener readable.
    if !must(poll_fd(cli as isize, judge::POLLOUT, POLL_MS).0, &mut o.err)
        || !must(poll_fd(lis as isize, POLLIN, POLL_MS).0, &mut o.err)
    {
        return;
    }

    // The defining call: both flags are applied by accept4 itself, not by a later fcntl.
    let acc = sc(nr::ACCEPT4, lis, 0, 0, sys::O_NONBLOCK | SOCK_CLOEXEC);
    o.accepted_fd = acc;
    if acc <= 0 {
        return;
    }
    fds.add(acc);
    let acc = acc as usize;
    o.status_flags = sc(nr::FCNTL, acc, F_GETFL, 0, 0);
    o.fd_flags = sc(nr::FCNTL, acc, F_GETFD, 0, 0);
    let mut msg = [0u8; 4];
    o.empty_read = sys_read(acc, &mut msg);
    if !must(sys_write(cli, b"PING"), &mut o.err)
        || !must(poll_fd(acc as isize, POLLIN, POLL_MS).0, &mut o.err)
    {
        return;
    }
    let n = sys_read(acc, &mut msg);
    o.data_ret = n;
    o.data_ok = n == judge::TCP_MESSAGE_LEN && &msg == b"PING";
}

fn probe_accept4() -> Verdict {
    let mut fds = Fds::new();
    let mut o = judge::AcceptObs {
        err: 0,
        accepted_fd: judge::NOT_RUN,
        status_flags: judge::NOT_RUN,
        fd_flags: judge::NOT_RUN,
        empty_read: judge::NOT_RUN,
        data_ret: judge::NOT_RUN,
        data_ok: false,
    };
    accept_steps(&mut o, &mut fds);
    fds.close_all();
    judge::judge_accept4(&o, sys::O_NONBLOCK as isize)
}

// ----------------------------------------------------------------------------------- REACTOR_WAKE

fn reactor_steps(o: &mut judge::ReactorObs, fds: &mut Fds) {
    let mut p = [-1i32; 2];
    let rc = sc(
        sys::NR_PIPE2,
        p.as_mut_ptr() as usize,
        sys::O_NONBLOCK,
        0,
        0,
    );
    if !must(rc, &mut o.err) {
        return;
    }
    fds.add(p[0] as isize);
    fds.add(p[1] as isize);
    let (rfd, wfd) = (p[0] as isize, p[1] as usize);

    // A timed wait with nothing to report expires after the time asked, not at once.
    let t0 = mono_ns();
    let (rc, _) = poll_fd(rfd, POLLIN, 50);
    o.timeout_rc = rc;
    o.timeout_elapsed_ns = elapsed(t0, mono_ns());

    // Another context wakes a blocked wait: a child writes one byte 20 ms after the fork.
    let pid = sc(nr::FORK, 0, 0, 0, 0);
    if !must(pid, &mut o.err) {
        return;
    }
    if pid == 0 {
        sleep_ms(20);
        let _ = sys_write(wfd, b"W");
        sys_exit(0);
    }
    let t1 = mono_ns();
    let (rc, revents) = poll_fd(rfd, POLLIN, 500);
    o.wake_rc = rc;
    o.wake_revents = revents;
    o.wake_elapsed_ns = elapsed(t1, mono_ns());
    let mut byte = [0u8; 1];
    let n = sys_read(rfd as usize, &mut byte);
    o.byte_ret = n;
    o.byte_ok = n == 1 && byte[0] == b'W';
    // The wake is consumed exactly once: nothing is left to wake on.
    o.drained_rc = poll_fd(rfd, POLLIN, 0).0;

    // Reap the writer (PID 1 must not leave zombies), without ever blocking.
    for _ in 0..20 {
        let mut status: i32 = -1;
        let r = sc(
            nr::WAIT4,
            pid as usize,
            &mut status as *mut i32 as usize,
            WNOHANG,
            0,
        );
        if r == pid {
            o.reaped = status == 0;
            break;
        }
        if r < 0 {
            o.err = r;
            break;
        }
        sleep_ms(10);
    }
}

fn probe_reactor() -> Verdict {
    let mut fds = Fds::new();
    let mut o = judge::ReactorObs {
        err: 0,
        timeout_rc: judge::NOT_RUN,
        timeout_elapsed_ns: -1,
        wake_rc: judge::NOT_RUN,
        wake_revents: 0,
        wake_elapsed_ns: -1,
        byte_ret: judge::NOT_RUN,
        byte_ok: false,
        drained_rc: judge::NOT_RUN,
        reaped: false,
    };
    reactor_steps(&mut o, &mut fds);
    fds.close_all();
    judge::judge_reactor(&o)
}

// ----------------------------------------------------------------------------------- CHARDEV_POLL

fn chardev_steps(o: &mut judge::CharDevObs, fds: &mut Fds) {
    let zf = sys_open(
        c"/dev/zero".as_ptr().cast::<u8>(),
        O_RDONLY | sys::O_NONBLOCK,
        0,
    );
    fds.add(zf);
    if !must(zf, &mut o.err) {
        return;
    }
    let nf = sys_open(
        c"/dev/null".as_ptr().cast::<u8>(),
        O_WRONLY | sys::O_NONBLOCK,
        0,
    );
    fds.add(nf);
    if !must(nf, &mut o.err) {
        return;
    }
    let mut pfds = [
        PollFd {
            fd: zf as i32,
            events: POLLIN,
            revents: 0,
        },
        PollFd {
            fd: nf as i32,
            events: judge::POLLOUT,
            revents: 0,
        },
    ];
    let t0 = mono_ns();
    o.poll_rc = sc(sys::NR_POLL, pfds.as_mut_ptr() as usize, 2, POLL_MS, 0);
    o.poll_elapsed_ns = elapsed(t0, mono_ns());
    o.zero_revents = pfds[0].revents;
    o.null_revents = pfds[1].revents;
    let out = [0x5au8; judge::CHAR_IO_BYTES as usize];
    o.write_rc = sys_write(nf as usize, &out);
    let mut input = [0xffu8; judge::CHAR_IO_BYTES as usize];
    o.read_rc = sys_read(zf as usize, &mut input);
    o.zeros_ok = o.read_rc == judge::CHAR_IO_BYTES && input.iter().all(|&b| b == 0);
}

fn probe_chardev() -> Verdict {
    let mut fds = Fds::new();
    let mut o = judge::CharDevObs {
        err: 0,
        poll_rc: judge::NOT_RUN,
        zero_revents: 0,
        null_revents: 0,
        poll_elapsed_ns: -1,
        write_rc: judge::NOT_RUN,
        read_rc: judge::NOT_RUN,
        zeros_ok: false,
    };
    chardev_steps(&mut o, &mut fds);
    fds.close_all();
    judge::judge_chardev(&o)
}

/// Run slice 2 in order, printing each line as soon as its probe finishes. Returns the number of
/// ambiguous results (guest failures); an exact `-ENOSYS` is reported but not counted.
pub fn run(console_fd: usize) -> usize {
    report(console_fd, b"LOOPBACK_UP", b"rc", probe_loopback_up())
        + report(console_fd, b"UDP_LOOPBACK", b"rc", probe_udp())
        + report(console_fd, b"ACCEPT4", b"fd", probe_accept4())
        + report(console_fd, b"REACTOR_WAKE", b"rc", probe_reactor())
        + report(console_fd, b"CHARDEV_POLL", b"rc", probe_chardev())
}
