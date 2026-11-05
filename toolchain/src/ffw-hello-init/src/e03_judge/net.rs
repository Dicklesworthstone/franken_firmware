//! Pure verdict logic for the E03 slice-2 guest probes (ffw-q2p, BLK-006): loopback bring-up, UDP with
//! truncated-datagram reporting, `accept4`, a reactor wakeup over a self-pipe, and char-device poll.
//!
//! Same contract as the parent module: the PID-1 binary (`e03_probes/net.rs`) issues the real syscalls
//! and hands raw observations here. `Verdict::rc` is the raw return that stopped the probe when a
//! syscall that must succeed failed (`err`, a negative errno), otherwise the probe's success value, so
//! `-ENOSYS` decodes as an explicit capability failure and everything else that is not a pass is
//! ambiguous. A field the probe never reached holds [`NOT_RUN`] (or `false` / `-1`), never a value
//! that happens to equal the expected one, so a skipped step cannot count as a pass.
//!
//! What these judges can and cannot show is stated per function. None of them qualifies the retained
//! audio driver: [`judge_chardev`] is generic character-device poll/read/write behavior only.

use super::{Verdict, EAGAIN, POLLIN};

/// Marks an `isize` observation the probe never made. Equal to no errno and no success value.
pub const NOT_RUN: isize = isize::MIN;

pub const POLLOUT: i16 = 4;
pub const POLLERR: i16 = 8;
pub const POLLHUP: i16 = 0x10;
pub const POLLNVAL: i16 = 0x20;
pub const MSG_TRUNC: i32 = 0x20;
pub const IFF_UP: i16 = 1;
pub const IFF_LOOPBACK: i16 = 8;
pub const FD_CLOEXEC: isize = 1;

/// UDP sizes: a 24-byte datagram into a 16-byte buffer is truncated; an 8-byte one is not.
pub const UDP_PAYLOAD_LEN: usize = 24;
pub const UDP_RECV_BUF: usize = 16;
pub const UDP_SHORT_LEN: usize = 8;
/// Bytes exchanged over the accepted TCP connection.
pub const TCP_MESSAGE_LEN: isize = 4;
/// One audio-period-sized transfer on the char devices (4096 bytes; not an audio-driver claim).
pub const CHAR_IO_BYTES: isize = 4096;

/// A blocked `poll` with nothing to report must take at least this long (50 ms asked, 40 ms floor).
pub const REACTOR_TIMEOUT_MIN_NS: i64 = 40_000_000;
/// The child sleeps 20 ms before writing; the parent's blocked `poll` must have waited for it.
pub const REACTOR_WAKE_MIN_NS: i64 = 8_000_000;
pub const REACTOR_WAKE_MAX_NS: i64 = 400_000_000;
/// Readiness on `/dev/zero` and `/dev/null` must be immediate.
pub const CHAR_POLL_MAX_NS: i64 = 50_000_000;

/// The first negative value of the slice, or 0 if none.
fn first_negative(values: &[isize]) -> isize {
    values.iter().copied().find(|&v| v < 0).unwrap_or(0)
}

fn rc_of(err: isize, value: isize) -> isize {
    if err != 0 {
        err
    } else {
        value
    }
}

// ----------------------------------------------------------------------------------- loopback

#[derive(Debug, Clone, Copy)]
pub struct LoopbackObs {
    pub socket_rc: isize,
    /// `ioctl(SIOCGIFFLAGS, "lo")`, `ioctl(SIOCSIFFLAGS, "lo")` with `IFF_UP` added, and a re-read.
    pub get_rc: isize,
    pub set_rc: isize,
    pub reread_rc: isize,
    pub flags_after: i16,
}

/// `lo` must be up and identify as a loopback interface after the set. `rc` is 0 on a pass.
pub fn judge_loopback(o: &LoopbackObs) -> Verdict {
    let err = first_negative(&[o.socket_rc, o.get_rc, o.set_rc, o.reread_rc]);
    let pass = err == 0
        && o.set_rc == 0
        && (o.flags_after & IFF_UP) != 0
        && (o.flags_after & IFF_LOOPBACK) != 0;
    Verdict {
        rc: rc_of(err, o.set_rc),
        pass,
    }
}

// ----------------------------------------------------------------------------------- UDP

#[derive(Debug, Clone, Copy)]
pub struct UdpObs {
    /// First must-succeed syscall that returned negative (socket, bind, getsockname, connect, send,
    /// recv/recvmsg), or 0.
    pub err: isize,
    pub port: u16,
    /// `recvmsg` of a 24-byte datagram into a 16-byte buffer: 16 bytes, `MSG_TRUNC` in `msg_flags`.
    pub trunc_ret: isize,
    pub trunc_flags: i32,
    pub trunc_prefix_ok: bool,
    /// `recv(.., MSG_TRUNC)` on a second 24-byte datagram reports the REAL length, 24.
    pub real_len_ret: isize,
    pub real_len_prefix_ok: bool,
    /// An 8-byte datagram arrives whole with no `MSG_TRUNC`.
    pub short_ret: isize,
    pub short_flags: i32,
    pub short_ok: bool,
    /// A nonblocking receive on the now-empty socket must be `-EAGAIN`.
    pub empty_rc: isize,
}

/// Proves, on loopback UDP: bind to an ephemeral port, connect, send, receive; truncation is reported
/// through `msg_flags`; `MSG_TRUNC` on `recv` returns the real datagram length; an untruncated datagram
/// is not flagged; an empty nonblocking receive is `-EAGAIN`. It does not prove anything about a real
/// network path, only the kernel's UDP semantics over `lo`. `rc` is the real length (24) on a pass.
pub fn judge_udp(o: &UdpObs) -> Verdict {
    let pass = o.err == 0
        && o.port != 0
        && o.trunc_ret == UDP_RECV_BUF as isize
        && (o.trunc_flags & MSG_TRUNC) != 0
        && o.trunc_prefix_ok
        && o.real_len_ret == UDP_PAYLOAD_LEN as isize
        && o.real_len_prefix_ok
        && o.short_ret == UDP_SHORT_LEN as isize
        && (o.short_flags & MSG_TRUNC) == 0
        && o.short_ok
        && o.empty_rc == -EAGAIN;
    Verdict {
        rc: rc_of(o.err, o.real_len_ret),
        pass,
    }
}

// ----------------------------------------------------------------------------------- accept4

#[derive(Debug, Clone, Copy)]
pub struct AcceptObs {
    /// First setup syscall that must succeed (socket, bind, getsockname, listen, fcntl, connect other
    /// than `-EINPROGRESS`) that returned negative, or 0. Setup uses only calls every kernel has, so
    /// a missing `accept4` is never reported through here.
    pub err: isize,
    /// Raw `accept4(listener, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC)` return.
    pub accepted_fd: isize,
    /// `fcntl(accepted, F_GETFL)` and `fcntl(accepted, F_GETFD)` raw returns.
    pub status_flags: isize,
    pub fd_flags: isize,
    /// A read on the accepted socket with nothing sent: `-EAGAIN` proves `SOCK_NONBLOCK` took effect.
    pub empty_read: isize,
    /// Four bytes written by the client are read back exactly.
    pub data_ret: isize,
    pub data_ok: bool,
}

/// `o_nonblock` is the guest ABI's `O_NONBLOCK` bit (0x80 on MIPS, 0x800 on PowerPC). The flags must
/// be set atomically by `accept4` itself (the contract warns that accept-then-fcntl races), the
/// connection must carry data, and the new fd must be positive. `rc` is the new fd on a pass.
pub fn judge_accept4(o: &AcceptObs, o_nonblock: isize) -> Verdict {
    let pass = o.err == 0
        && o.accepted_fd > 0
        && o.status_flags >= 0
        && (o.status_flags & o_nonblock) != 0
        && o.fd_flags >= 0
        && (o.fd_flags & FD_CLOEXEC) != 0
        && o.empty_read == -EAGAIN
        && o.data_ret == TCP_MESSAGE_LEN
        && o.data_ok;
    Verdict {
        rc: rc_of(o.err, o.accepted_fd),
        pass,
    }
}

// ----------------------------------------------------------------------------------- reactor

#[derive(Debug, Clone, Copy)]
pub struct ReactorObs {
    /// `pipe2`, `fork` or `wait4` failure that must not happen, or 0.
    pub err: isize,
    /// A 50 ms `poll` on an empty self-pipe: 0 (timed out) after at least [`REACTOR_TIMEOUT_MIN_NS`].
    pub timeout_rc: isize,
    pub timeout_elapsed_ns: i64,
    /// A blocked `poll` while a forked child writes one byte 20 ms later: 1 with `POLLIN`, after a
    /// real wait.
    pub wake_rc: isize,
    pub wake_revents: i16,
    pub wake_elapsed_ns: i64,
    /// The byte is read back (1, the value written), and the next zero-timeout `poll` is 0.
    pub byte_ret: isize,
    pub byte_ok: bool,
    pub drained_rc: isize,
    /// The child was reaped with a clean exit status.
    pub reaped: bool,
}

/// Proves the self-pipe wake mechanism with another context as the source: a timed wait expires, a
/// blocked wait is woken by a write that happens later, the wake is consumed exactly once, and the
/// writer is reaped. It does not exercise eventfd or timerfd wakeups (slice 1 does), and it uses
/// `pipe2`, so a kernel without it is reported through `err`/`-ENOSYS` rather than by testing the old
/// `pipe`. `rc` is 1 (the `poll` result) on a pass.
pub fn judge_reactor(o: &ReactorObs) -> Verdict {
    let pass = o.err == 0
        && o.timeout_rc == 0
        && o.timeout_elapsed_ns >= REACTOR_TIMEOUT_MIN_NS
        && o.wake_rc == 1
        && (o.wake_revents & POLLIN) != 0
        && o.wake_elapsed_ns >= REACTOR_WAKE_MIN_NS
        && o.wake_elapsed_ns <= REACTOR_WAKE_MAX_NS
        && o.byte_ret == 1
        && o.byte_ok
        && o.drained_rc == 0
        && o.reaped;
    Verdict {
        rc: rc_of(o.err, o.wake_rc),
        pass,
    }
}

// ----------------------------------------------------------------------------------- char devices

#[derive(Debug, Clone, Copy)]
pub struct CharDevObs {
    /// An `open` of `/dev/zero` or `/dev/null` that failed, or 0.
    pub err: isize,
    /// One `poll` over `{/dev/zero POLLIN, /dev/null POLLOUT}`: both ready.
    pub poll_rc: isize,
    pub zero_revents: i16,
    pub null_revents: i16,
    pub poll_elapsed_ns: i64,
    /// A nonblocking 4096-byte write to `/dev/null` and read from `/dev/zero` complete in full.
    pub write_rc: isize,
    pub read_rc: isize,
    pub zeros_ok: bool,
}

/// Proves only the VFS character-device contract: `poll` reports a device with no `poll` method of its
/// own as always ready, without blocking, and a nonblocking period-sized read/write then completes
/// in full. It does NOT show anything about the retained audio driver, whose readiness, underrun
/// and wake behavior need that driver in an exact-version guest. `rc` is 2 on a pass.
pub fn judge_chardev(o: &CharDevObs) -> Verdict {
    let hard = POLLERR | POLLHUP | POLLNVAL;
    let pass = o.err == 0
        && o.poll_rc == 2
        && (o.zero_revents & POLLIN) != 0
        && (o.null_revents & POLLOUT) != 0
        && ((o.zero_revents | o.null_revents) & hard) == 0
        && o.poll_elapsed_ns >= 0
        && o.poll_elapsed_ns < CHAR_POLL_MAX_NS
        && o.write_rc == CHAR_IO_BYTES
        && o.read_rc == CHAR_IO_BYTES
        && o.zeros_ok;
    Verdict {
        rc: rc_of(o.err, o.poll_rc),
        pass,
    }
}

#[cfg(test)]
mod tests {
    use super::super::Class;
    use super::*;

    /// One planted single-check regression: its name, and the edit to a good observation that must
    /// make the probe fail. An alias keeps `[Mutation<_>; N]` readable (clippy::type_complexity).
    type Mutation<T> = (&'static str, fn(&mut T));

    const PPC_ENOSYS: isize = 38;
    const MIPS_ENOSYS: isize = 89;
    const PPC_O_NONBLOCK: isize = 0x800;
    const MIPS_O_NONBLOCK: isize = 0x80;

    // ----- loopback
    fn good_loopback() -> LoopbackObs {
        LoopbackObs {
            socket_rc: 3,
            get_rc: 0,
            set_rc: 0,
            reread_rc: 0,
            flags_after: IFF_UP | IFF_LOOPBACK | 0x40,
        }
    }

    #[test]
    fn loopback_up_and_identified_passes_with_rc_zero() {
        let v = judge_loopback(&good_loopback());
        assert_eq!(v, Verdict { rc: 0, pass: true });
        assert_eq!(v.class(PPC_ENOSYS), Class::Supported);
    }

    #[test]
    fn loopback_each_dropped_check_would_be_caught() {
        assert!(judge_loopback(&good_loopback()).pass);
        let mutations: [Mutation<LoopbackObs>; 6] = [
            ("socket failed", |o| o.socket_rc = -24),
            ("get flags failed", |o| o.get_rc = -19),
            ("set flags failed", |o| o.set_rc = -1),
            ("re-read failed", |o| o.reread_rc = -5),
            ("interface not up after the set", |o| {
                o.flags_after = IFF_LOOPBACK
            }),
            ("interface not a loopback", |o| o.flags_after = IFF_UP),
        ];
        for (name, mutate) in mutations {
            let mut o = good_loopback();
            mutate(&mut o);
            assert!(!judge_loopback(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn loopback_reports_the_first_errno_raw() {
        let mut o = good_loopback();
        o.socket_rc = -PPC_ENOSYS;
        o.get_rc = -19;
        let v = judge_loopback(&o);
        assert_eq!(v.rc, -38);
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        o.socket_rc = 3;
        let w = judge_loopback(&o);
        assert_eq!(w.rc, -19);
        assert_eq!(w.class(PPC_ENOSYS), Class::Ambiguous);
    }

    // ----- UDP
    fn good_udp() -> UdpObs {
        UdpObs {
            err: 0,
            port: 40123,
            trunc_ret: 16,
            trunc_flags: MSG_TRUNC,
            trunc_prefix_ok: true,
            real_len_ret: 24,
            real_len_prefix_ok: true,
            short_ret: 8,
            short_flags: 0,
            short_ok: true,
            empty_rc: -EAGAIN,
        }
    }

    #[test]
    fn udp_truncation_reporting_passes_with_the_real_length() {
        let v = judge_udp(&good_udp());
        assert_eq!(v, Verdict { rc: 24, pass: true });
    }

    #[test]
    fn udp_each_dropped_check_would_be_caught() {
        assert!(judge_udp(&good_udp()).pass);
        let mutations: [Mutation<UdpObs>; 12] = [
            ("setup syscall failed", |o| o.err = -98),
            ("no ephemeral port", |o| o.port = 0),
            ("truncated read returned the wrong size", |o| {
                o.trunc_ret = 24
            }),
            ("truncation not flagged in msg_flags", |o| o.trunc_flags = 0),
            ("truncated prefix differs", |o| o.trunc_prefix_ok = false),
            (
                "MSG_TRUNC recv gave the buffer size, not the real length",
                |o| o.real_len_ret = 16,
            ),
            ("real-length datagram prefix differs", |o| {
                o.real_len_prefix_ok = false
            }),
            ("short datagram not whole", |o| o.short_ret = 4),
            ("short datagram wrongly flagged truncated", |o| {
                o.short_flags = MSG_TRUNC
            }),
            ("short datagram bytes differ", |o| o.short_ok = false),
            ("empty receive did not report EAGAIN", |o| o.empty_rc = 0),
            ("empty receive blocked or errored otherwise", |o| {
                o.empty_rc = -4
            }),
        ];
        for (name, mutate) in mutations {
            let mut o = good_udp();
            mutate(&mut o);
            assert!(!judge_udp(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn udp_setup_error_is_the_printed_value_and_enosys_is_unsupported() {
        let mut o = good_udp();
        o.err = -MIPS_ENOSYS;
        let v = judge_udp(&o);
        assert_eq!(v.rc, -89);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Unsupported);
        o.err = -101; // ENETUNREACH: loopback was not up
        let w = judge_udp(&o);
        assert_eq!(w.class(MIPS_ENOSYS), Class::Ambiguous);
        assert!(w.is_guest_failure(MIPS_ENOSYS));
    }

    // ----- accept4
    fn good_accept() -> AcceptObs {
        AcceptObs {
            err: 0,
            accepted_fd: 7,
            status_flags: 0o2 | PPC_O_NONBLOCK,
            fd_flags: FD_CLOEXEC,
            empty_read: -EAGAIN,
            data_ret: 4,
            data_ok: true,
        }
    }

    #[test]
    fn accept4_flags_applied_atomically_and_data_flows() {
        let v = judge_accept4(&good_accept(), PPC_O_NONBLOCK);
        assert_eq!(v, Verdict { rc: 7, pass: true });
    }

    #[test]
    fn accept4_each_dropped_check_would_be_caught() {
        assert!(judge_accept4(&good_accept(), PPC_O_NONBLOCK).pass);
        let mutations: [Mutation<AcceptObs>; 9] = [
            ("setup failed", |o| o.err = -111),
            ("fd not positive", |o| o.accepted_fd = 0),
            ("F_GETFL failed", |o| o.status_flags = -9),
            ("SOCK_NONBLOCK not applied", |o| o.status_flags = 0o2),
            ("F_GETFD failed", |o| o.fd_flags = -9),
            ("SOCK_CLOEXEC not applied", |o| o.fd_flags = 0),
            ("empty read did not report EAGAIN", |o| o.empty_read = 0),
            ("data short", |o| o.data_ret = 2),
            ("data differs", |o| o.data_ok = false),
        ];
        for (name, mutate) in mutations {
            let mut o = good_accept();
            mutate(&mut o);
            assert!(
                !judge_accept4(&o, PPC_O_NONBLOCK).pass,
                "{name} must fail the probe"
            );
        }
    }

    #[test]
    fn accept4_nonblock_bit_is_the_guests_own_abi() {
        // PowerPC's 0x800 is not MIPS's O_NONBLOCK (0x80), so a flag word valid on one fails on the other.
        let ppc = good_accept();
        assert!(judge_accept4(&ppc, PPC_O_NONBLOCK).pass);
        assert!(!judge_accept4(&ppc, MIPS_O_NONBLOCK).pass);
        let mips = AcceptObs {
            status_flags: 0o2 | MIPS_O_NONBLOCK,
            ..good_accept()
        };
        assert!(judge_accept4(&mips, MIPS_O_NONBLOCK).pass);
        assert!(!judge_accept4(&mips, PPC_O_NONBLOCK).pass);
    }

    #[test]
    fn accept4_missing_call_is_unsupported_and_setup_failure_is_not() {
        // Setup succeeded; the call itself is ENOSYS: an explicit capability failure.
        let absent = AcceptObs {
            accepted_fd: -PPC_ENOSYS,
            status_flags: NOT_RUN,
            fd_flags: NOT_RUN,
            empty_read: NOT_RUN,
            data_ret: NOT_RUN,
            data_ok: false,
            ..good_accept()
        };
        let v = judge_accept4(&absent, PPC_O_NONBLOCK);
        assert_eq!((v.rc, v.pass), (-38, false));
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        // A listener that could not be set up says nothing about accept4 and stays ambiguous.
        let broken = AcceptObs { err: -98, ..absent };
        assert_eq!(
            judge_accept4(&broken, PPC_O_NONBLOCK).class(PPC_ENOSYS),
            Class::Ambiguous
        );
    }

    // ----- reactor
    fn good_reactor() -> ReactorObs {
        ReactorObs {
            err: 0,
            timeout_rc: 0,
            timeout_elapsed_ns: 51_000_000,
            wake_rc: 1,
            wake_revents: POLLIN,
            wake_elapsed_ns: 21_000_000,
            byte_ret: 1,
            byte_ok: true,
            drained_rc: 0,
            reaped: true,
        }
    }

    #[test]
    fn reactor_timed_wait_and_cross_context_wake_pass() {
        assert_eq!(
            judge_reactor(&good_reactor()),
            Verdict { rc: 1, pass: true }
        );
    }

    #[test]
    fn reactor_each_dropped_check_would_be_caught() {
        assert!(judge_reactor(&good_reactor()).pass);
        let mutations: [Mutation<ReactorObs>; 12] = [
            ("pipe/fork/wait failed", |o| o.err = -12),
            ("empty wait did not time out", |o| o.timeout_rc = 1),
            ("empty wait returned early", |o| {
                o.timeout_elapsed_ns = 39_999_999
            }),
            ("empty wait elapsed unknown", |o| o.timeout_elapsed_ns = -1),
            ("blocked poll was not woken", |o| o.wake_rc = 0),
            ("wake without POLLIN", |o| o.wake_revents = 0),
            ("wake was instantaneous, so the poll never blocked", |o| {
                o.wake_elapsed_ns = 1_000_000
            }),
            ("wake took longer than any sane delay", |o| {
                o.wake_elapsed_ns = 400_000_001
            }),
            ("byte not read", |o| o.byte_ret = 0),
            ("byte differs", |o| o.byte_ok = false),
            ("spurious readiness after the drain", |o| o.drained_rc = 1),
            ("writer not reaped", |o| o.reaped = false),
        ];
        for (name, mutate) in mutations {
            let mut o = good_reactor();
            mutate(&mut o);
            assert!(!judge_reactor(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn reactor_fork_enosys_is_unsupported_and_a_not_run_step_never_passes() {
        let absent = ReactorObs {
            err: -PPC_ENOSYS,
            timeout_rc: NOT_RUN,
            timeout_elapsed_ns: -1,
            wake_rc: NOT_RUN,
            wake_revents: 0,
            wake_elapsed_ns: -1,
            byte_ret: NOT_RUN,
            byte_ok: false,
            drained_rc: NOT_RUN,
            reaped: false,
        };
        assert_eq!(judge_reactor(&absent).class(PPC_ENOSYS), Class::Unsupported);
        // No error recorded but nothing observed: still not a pass.
        let silent = ReactorObs { err: 0, ..absent };
        assert!(!judge_reactor(&silent).pass);
    }

    // ----- char devices
    fn good_chardev() -> CharDevObs {
        CharDevObs {
            err: 0,
            poll_rc: 2,
            zero_revents: POLLIN | 0x40,
            null_revents: POLLOUT | 0x100,
            poll_elapsed_ns: 80_000,
            write_rc: 4096,
            read_rc: 4096,
            zeros_ok: true,
        }
    }

    #[test]
    fn chardev_poll_ready_without_blocking_and_full_transfer_pass() {
        assert_eq!(
            judge_chardev(&good_chardev()),
            Verdict { rc: 2, pass: true }
        );
    }

    #[test]
    fn chardev_each_dropped_check_would_be_caught() {
        assert!(judge_chardev(&good_chardev()).pass);
        let mutations: [Mutation<CharDevObs>; 12] = [
            ("open failed", |o| o.err = -2),
            ("only one device ready", |o| o.poll_rc = 1),
            ("zero not readable", |o| o.zero_revents = 0),
            ("null not writable", |o| o.null_revents = POLLIN),
            ("error bit on zero", |o| o.zero_revents = POLLIN | POLLERR),
            ("hangup on null", |o| o.null_revents = POLLOUT | POLLHUP),
            ("invalid descriptor on null", |o| {
                o.null_revents = POLLOUT | POLLNVAL
            }),
            ("poll blocked too long", |o| {
                o.poll_elapsed_ns = CHAR_POLL_MAX_NS
            }),
            ("poll time unknown", |o| o.poll_elapsed_ns = -1),
            ("write was partial", |o| o.write_rc = 2048),
            ("read was partial", |o| o.read_rc = 0),
            ("zero device returned non-zero bytes", |o| {
                o.zeros_ok = false
            }),
        ];
        for (name, mutate) in mutations {
            let mut o = good_chardev();
            mutate(&mut o);
            assert!(!judge_chardev(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn chardev_missing_node_is_ambiguous_not_unsupported() {
        // ENOENT (-2) means the device node is absent from the image, not that a syscall is missing.
        let mut o = good_chardev();
        o.err = -2;
        let v = judge_chardev(&o);
        assert_eq!(v.rc, -2);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Ambiguous);
    }

    #[test]
    fn a_pass_never_carries_a_negative_return_for_any_slice_two_probe() {
        let passes = [
            judge_loopback(&good_loopback()),
            judge_udp(&good_udp()),
            judge_accept4(&good_accept(), PPC_O_NONBLOCK),
            judge_reactor(&good_reactor()),
            judge_chardev(&good_chardev()),
        ];
        for v in passes {
            assert!(v.pass && v.rc >= 0, "{v:?}");
        }
    }

    #[test]
    fn not_run_equals_no_errno_and_no_success_value() {
        assert!(NOT_RUN < -4096 && NOT_RUN != 0);
        assert_eq!(first_negative(&[0, 5, NOT_RUN]), NOT_RUN);
        assert_eq!(first_negative(&[0, 5, 1]), 0);
    }
}
