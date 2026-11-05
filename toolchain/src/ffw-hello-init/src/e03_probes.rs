//! Real-syscall E03 guest probes (ffw-q2p, BLK-003): `getrandom`, `eventfd2`, `timerfd`, `futex`,
//! plus slice 2 (`net`).
//!
//! Declared from `main.rs` (`mod e03_probes;`), so it reaches the audited syscall trampoline and the
//! console writer through `super::`. Every probe issues the real syscall and checks its observable
//! behavior; the pass/fail decision lives in `ffw_hello_init::e03_judge`, where it has host tests.
//!
//! Bounds: no probe can block PID 1. Reads use nonblocking descriptors, every `poll` carries a
//! timeout, every futex wait carries a deadline, and `getrandom` uses `GRND_NONBLOCK` with a short
//! retry. Worst case, if every wait ran to its limit, derived per probe in milliseconds: slice 1 is
//! 820 (GETRANDOM 10 retries x 20 = 200, EVENTFD2 one poll = 100, TIMERFD 5 polls x 100 = 500, FUTEX
//! four waits x 5 = 20) and slice 2 is 1450 (UDP 3 polls x 100 = 300, ACCEPT4 3 polls x 100 = 300,
//! REACTOR 50 + 500 + 20 reaps x 10 = 750, CHARDEV 100, LOOPBACK_UP 0). A poll can run nearly to its
//! limit and still succeed, so every poll on a path that carries on is counted. That is at most about
//! 2.27 s, and typically a few hundred milliseconds: an unseeded guest always spends the 200 ms
//! `getrandom` retry, and the rest is a few tens of milliseconds of timers. This excludes
//! `e03_probes_rt`, which has its own budget; the guest timeout must cover the sum of the two.
//!
//! Line contract: `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<raw defining-syscall return>`, and for
//! `GETRANDOM` alone `status=UNSEEDED rc=-11` (see `Reported`). A kernel that lacks the call answers
//! `-ENOSYS` and that is printed as is; it does not count as a guest failure
//! (`Verdict::is_guest_failure`). A call that exists but misbehaves does.

use core::sync::atomic::AtomicU32;

use ffw_hello_init::e03_judge::{
    self, EventfdObs, FutexObs, GetrandomObs, Reported, Status, TimerfdObs, Verdict,
};

use super::{
    emit_console, emit_test_result, sys, sys_close, sys_raw, sys_read, sys_write, LineWriter,
    PollFd, Timespec32,
};

/// Slice 2 (BLK-006): loopback, UDP truncation reporting, `accept4`, reactor wakeup, char-device poll.
mod net;

/// Per-ABI syscall numbers and errno values, from the libc crate's `linux/gnu/b32` tables
/// (libc 0.2.191): MIPS o32 is 4000-based; PowerPC32 uses the generic numbering.
#[cfg(target_arch = "mips")]
mod nr {
    pub const GETRANDOM: usize = 4353;
    pub const EVENTFD2: usize = 4325;
    pub const TIMERFD_CREATE: usize = 4321;
    pub const TIMERFD_SETTIME: usize = 4323;
    pub const FUTEX: usize = 4238;
    /// MIPS errno numbering differs from the generic one.
    pub const ETIMEDOUT: isize = 145;
}

#[cfg(target_arch = "powerpc")]
mod nr {
    pub const GETRANDOM: usize = 359;
    pub const EVENTFD2: usize = 314;
    pub const TIMERFD_CREATE: usize = 306;
    pub const TIMERFD_SETTIME: usize = 311;
    pub const FUTEX: usize = 221;
    pub const ETIMEDOUT: isize = 110;
}

const CLOCK_MONOTONIC: usize = 1;
const GRND_NONBLOCK: usize = 1;
/// Futex operations. The plain ones exist on every kernel in scope; Rust's std and musl use the
/// `PRIVATE` wake and `WAIT_BITSET|PRIVATE` wait, which arrived in 2.6.22 and 2.6.25. A probe of the
/// plain ops alone would not support a "threads OK" claim, so both families are exercised and both
/// must pass.
const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_PRIVATE_FLAG: usize = 128;
/// "Wake or wait on any bit": the bitset std passes (`!0`), as the sixth syscall argument.
const FUTEX_BITSET_MATCH_ANY: usize = 0xffff_ffff;

/// `getrandom` retry while the pool is not yet seeded: 10 x 20 ms.
const GETRANDOM_RETRIES: usize = 10;
const GETRANDOM_RETRY_MS: usize = 20;
/// Per-`poll` timeout, and the most rounds the timerfd probe will wait for expirations.
const POLL_TIMEOUT_MS: usize = 100;
const TIMERFD_MAX_ROUNDS: usize = 5;

/// `struct itimerspec` with the 32-bit `time_t` of the legacy 32-bit ABI.
// The fields are read by the kernel through the pointer passed to `timerfd_settime`, never by Rust.
#[allow(dead_code)]
#[repr(C)]
struct ITimerSpec32 {
    it_interval: Timespec32,
    it_value: Timespec32,
}

fn sc(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    // SAFETY: a raw Linux syscall through the per-architecture trampoline in `main.rs`. Every
    // pointer argument passed by the callers in this file refers to a live, correctly sized stack
    // object or static that outlives the call; the kernel validates the rest.
    unsafe { sys_raw(nr, a0, a1, a2, a3) }
}

/// A six-argument syscall. The trampoline in `main.rs` carries five and leaves the sixth undefined
/// (a stack slot holding `$at` on MIPS, a clobbered `r8` on PowerPC), but `FUTEX_WAIT_BITSET` takes its
/// bitset there and a garbage bitset of 0 is `-EINVAL`. Same contract as `sys::sys_raw5`.
///
/// `e03_probes_rt` has its own private `sc6` for the same reason; the two can be merged once both are
/// known to compile, which is not yet the case for either.
#[cfg(target_arch = "mips")]
#[inline(never)]
fn sc6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    let err: usize;
    // SAFETY: O32 passes arguments 5 and 6 at 16($sp) and 20($sp) and returns the error flag in `$7`
    // (non-zero means `$2` is a positive errno). The 32 bytes are allocated below the live frame
    // before they are written and released straight after the syscall; `$1` (`$at`) is saved at
    // 24($sp) and restored, exactly as `sys_raw5` does. Callers pass only pointers to live objects.
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set noat",
            "addiu $29, $29, -32",
            "sw $1, 24($29)",
            "sw {a5}, 20($29)",
            "sw {a4}, 16($29)",
            "syscall",
            "lw $1, 24($29)",
            "addiu $29, $29, 32",
            ".set pop",
            a4 = in(reg) a4,
            a5 = in(reg) a5,
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            inlateout("$6") a2 => _,
            inlateout("$7") a3 => err,
            lateout("$3") _,
            lateout("$8") _,
            lateout("$9") _,
            lateout("$10") _,
            lateout("$11") _,
            lateout("$12") _,
            lateout("$13") _,
            lateout("$14") _,
            lateout("$15") _,
            lateout("$24") _,
            lateout("$25") _,
        );
    }
    if err != 0 {
        -ret
    } else {
        ret
    }
}

#[cfg(target_arch = "powerpc")]
#[inline(never)]
fn sc6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let r3: isize;
    // SAFETY: same contract as `sys::sys_raw5`, with `r8` carrying the sixth argument instead of being
    // clobbered. On error `cr0.SO` is set and `r3` holds a positive errno, normalised by `neg`.
    unsafe {
        core::arch::asm!(
            "sc",
            "bns+ 1f",
            "neg 3, 3",
            "1:",
            inlateout("r0") nr => _,
            inlateout("r3") a0 as isize => r3,
            inlateout("r4") a1 => _,
            inlateout("r5") a2 => _,
            inlateout("r6") a3 => _,
            inlateout("r7") a4 => _,
            inlateout("r8") a5 => _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            lateout("r12") _,
            lateout("cr0") _,
            lateout("ctr") _,
            lateout("xer") _,
            options(nostack),
        );
    }
    r3
}

/// A bounded sleep: `poll(NULL, 0, ms)`. An interruption only shortens it.
fn sleep_ms(ms: usize) {
    let _ = sc(sys::NR_POLL, 0, 0, ms, 0);
}

fn poll_in(fd: isize, timeout_ms: usize) -> (isize, i16) {
    let mut p = PollFd {
        fd: fd as i32,
        events: e03_judge::POLLIN,
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

/// Read one native-endian `u64` counter (eventfd and timerfd both use host byte order).
fn read_u64(fd: usize) -> (isize, u64) {
    let mut buf = [0u8; 8];
    let n = sys_read(fd, &mut buf);
    (n, u64::from_ne_bytes(buf))
}

fn write_u64(fd: usize, value: u64) -> isize {
    sys_write(fd, &value.to_ne_bytes())
}

/// The monotonic clock as the kernel's own `struct timespec`, or `None` if the clock call fails.
fn mono_ts() -> Option<Timespec32> {
    let mut ts = Timespec32 {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = sc(
        sys::NR_CLOCK_GETTIME,
        CLOCK_MONOTONIC,
        &mut ts as *mut Timespec32 as usize,
        0,
        0,
    );
    if rc == 0 {
        Some(ts)
    } else {
        None
    }
}

fn ts_ns(ts: &Timespec32) -> i64 {
    ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
}

/// `ts + ns` with the nanosecond carry done by hand (no 64-bit division, so no compiler-builtins call).
/// `ns` is small and `ts.tv_nsec` is below one second, so the sum cannot overflow an `i32`.
fn add_ns(ts: &Timespec32, ns: i32) -> Timespec32 {
    let mut sec = ts.tv_sec;
    let mut nsec = ts.tv_nsec + ns;
    if nsec >= 1_000_000_000 {
        sec += 1;
        nsec -= 1_000_000_000;
    }
    Timespec32 {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

/// Monotonic time in nanoseconds, or `None` if the clock call fails.
fn mono_ns() -> Option<i64> {
    mono_ts().map(|ts| ts_ns(&ts))
}

/// Nanoseconds since `start_ns` on the monotonic clock, or -1 if the clock call fails.
fn since(start_ns: i64) -> i64 {
    mono_ns().map_or(-1, |end| end - start_ns)
}

fn sys_getrandom(buf: &mut [u8; 16], flags: usize) -> isize {
    sc(
        nr::GETRANDOM,
        buf.as_mut_ptr() as usize,
        buf.len(),
        flags,
        0,
    )
}

fn probe_getrandom() -> Reported {
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    // A freshly booted guest without an entropy device may not have a seeded pool yet. With
    // GRND_NONBLOCK that is a bounded `-EAGAIN`; wait a little in case it seeds, then report the truth
    // rather than block PID 1, credit entropy, or fall back to a non-secure source.
    let mut first_rc = sys_getrandom(&mut first, GRND_NONBLOCK);
    let mut tries = 0;
    while first_rc == -e03_judge::EAGAIN && tries < GETRANDOM_RETRIES {
        sleep_ms(GETRANDOM_RETRY_MS);
        first_rc = sys_getrandom(&mut first, GRND_NONBLOCK);
        tries += 1;
    }
    let second_rc = if first_rc == e03_judge::GETRANDOM_BYTES {
        sys_getrandom(&mut second, GRND_NONBLOCK)
    } else {
        0
    };
    // Still unseeded: prove the call exists without needing entropy. An invalid flag bit is rejected
    // with -EINVAL before the kernel looks at the pool, so that exact answer separates "present, not
    // seeded yet" from "absent" and from "broken".
    let existence_rc = if first_rc == -e03_judge::EAGAIN {
        let mut scratch = [0u8; 16];
        sys_getrandom(&mut scratch, e03_judge::GETRANDOM_INVALID_FLAG)
    } else {
        e03_judge::net::NOT_RUN
    };
    e03_judge::judge_getrandom(&GetrandomObs {
        first_rc,
        second_rc,
        first,
        second,
        existence_rc,
    })
}

fn probe_eventfd() -> Verdict {
    let fd = sc(
        nr::EVENTFD2,
        e03_judge::EVENTFD_INITVAL as usize,
        sys::O_NONBLOCK,
        0,
        0,
    );
    if fd < 0 {
        return e03_judge::judge_eventfd(&EventfdObs {
            fd,
            first_read: 0,
            first_val: 0,
            empty_read: 0,
            write_rc: 0,
            poll_rc: 0,
            poll_revents: 0,
            second_read: 0,
            second_val: 0,
        });
    }
    let ufd = fd as usize;
    // The initial counter reads back once; the drained nonblocking read must then be EAGAIN.
    let (first_read, first_val) = read_u64(ufd);
    let (empty_read, _) = read_u64(ufd);
    // A write makes the descriptor readable again, which poll must report, and reads back exactly.
    let write_rc = write_u64(ufd, e03_judge::EVENTFD_ADDED);
    let (poll_rc, poll_revents) = poll_in(fd, POLL_TIMEOUT_MS);
    let (second_read, second_val) = read_u64(ufd);
    let _ = sys_close(ufd);
    e03_judge::judge_eventfd(&EventfdObs {
        fd,
        first_read,
        first_val,
        empty_read,
        write_rc,
        poll_rc,
        poll_revents,
        second_read,
        second_val,
    })
}

fn probe_timerfd() -> Verdict {
    let fd = sc(nr::TIMERFD_CREATE, CLOCK_MONOTONIC, sys::O_NONBLOCK, 0, 0);
    if fd < 0 {
        return e03_judge::judge_timerfd(&TimerfdObs {
            fd,
            settime_rc: 0,
            expirations: 0,
            reads: 0,
            elapsed_ns: -1,
        });
    }
    let ufd = fd as usize;
    // Periodic 5 ms timer: waiting for several expirations exercises repeated timer wakeups.
    let armed = ITimerSpec32 {
        it_interval: Timespec32 {
            tv_sec: 0,
            tv_nsec: e03_judge::TIMERFD_INTERVAL_NS,
        },
        it_value: Timespec32 {
            tv_sec: 0,
            tv_nsec: e03_judge::TIMERFD_INTERVAL_NS,
        },
    };
    let start = mono_ns();
    let settime_rc = sc(
        nr::TIMERFD_SETTIME,
        ufd,
        0,
        &armed as *const ITimerSpec32 as usize,
        0,
    );
    let mut expirations: u64 = 0;
    let mut reads: u32 = 0;
    if settime_rc == 0 {
        for _ in 0..TIMERFD_MAX_ROUNDS {
            let (rc, revents) = poll_in(fd, POLL_TIMEOUT_MS);
            if rc != 1 || (revents & e03_judge::POLLIN) == 0 {
                break;
            }
            let (n, count) = read_u64(ufd);
            if n != 8 {
                break;
            }
            reads += 1;
            expirations = expirations.saturating_add(count);
            // Stop only when there are enough expirations AND enough separate wakeups. If a slow guest
            // finds all three queued in one read, keep waiting for a second wakeup instead of failing.
            if expirations >= e03_judge::TIMERFD_MIN_EXPIRATIONS
                && reads >= e03_judge::TIMERFD_MIN_READS
            {
                break;
            }
        }
    }
    let elapsed_ns = start.map_or(-1, since);
    // Disarm before closing so nothing fires into a closed descriptor's wait queue.
    let disarmed = ITimerSpec32 {
        it_interval: Timespec32 {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec32 {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let _ = sc(
        nr::TIMERFD_SETTIME,
        ufd,
        0,
        &disarmed as *const ITimerSpec32 as usize,
        0,
    );
    let _ = sys_close(ufd);
    e03_judge::judge_timerfd(&TimerfdObs {
        fd,
        settime_rc,
        expirations,
        reads,
        elapsed_ns,
    })
}

/// The futex word stays 0 for the whole run; nothing else ever waits on it.
static FUTEX_WORD: AtomicU32 = AtomicU32::new(0);

/// `FUTEX_WAIT_BITSET|PRIVATE` with `FUTEX_BITSET_MATCH_ANY` and an ABSOLUTE `CLOCK_MONOTONIC` deadline
/// `FUTEX_TIMEOUT_NS` ahead, which is how std and musl wait with a timeout. Returns the raw result and
/// the monotonic time that elapsed around the call (-1 if the clock is unavailable, in which case the
/// wait is not made and the result is `NOT_RUN`).
fn bitset_wait(addr: usize, expected: usize) -> (isize, i64) {
    let Some(now) = mono_ts() else {
        return (e03_judge::net::NOT_RUN, -1);
    };
    let deadline = add_ns(&now, e03_judge::FUTEX_TIMEOUT_NS);
    let start = ts_ns(&now);
    let rc = sc6(
        nr::FUTEX,
        addr,
        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
        expected,
        &deadline as *const Timespec32 as usize,
        0,
        FUTEX_BITSET_MATCH_ANY,
    );
    (rc, since(start))
}

fn probe_futex() -> Verdict {
    let addr = FUTEX_WORD.as_ptr() as usize;
    let none = e03_judge::net::NOT_RUN;
    let mut o = FutexObs {
        wake_rc: none,
        mismatch_rc: none,
        timeout_rc: none,
        timeout_elapsed_ns: -1,
        plain_wake_rc: none,
        plain_mismatch_rc: none,
        plain_timeout_rc: none,
        plain_timeout_elapsed_ns: -1,
    };
    // What std and musl use: a private wake, then bitset waits. The word is 0, so waiting for 1
    // mismatches and returns -EAGAIN at once; waiting for 0 sleeps until the deadline.
    o.wake_rc = sc(nr::FUTEX, addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0);
    if o.wake_rc < 0 {
        return e03_judge::judge_futex(&o, nr::ETIMEDOUT, sys::ENOSYS_EXPECTED);
    }
    o.mismatch_rc = bitset_wait(addr, 1).0;
    (o.timeout_rc, o.timeout_elapsed_ns) = bitset_wait(addr, 0);

    // The legacy shared ops, kept so that both families must pass. A timeout is always passed so a
    // broken kernel cannot hang PID 1.
    o.plain_wake_rc = sc(nr::FUTEX, addr, FUTEX_WAKE, 1, 0);
    let relative = Timespec32 {
        tv_sec: 0,
        tv_nsec: e03_judge::FUTEX_TIMEOUT_NS,
    };
    let relative_ptr = &relative as *const Timespec32 as usize;
    o.plain_mismatch_rc = sc(nr::FUTEX, addr, FUTEX_WAIT, 1, relative_ptr);
    let start = mono_ns();
    o.plain_timeout_rc = sc(nr::FUTEX, addr, FUTEX_WAIT, 0, relative_ptr);
    o.plain_timeout_elapsed_ns = start.map_or(-1, since);
    e03_judge::judge_futex(&o, nr::ETIMEDOUT, sys::ENOSYS_EXPECTED)
}

/// Print one probe line and return 1 if it counts as a guest failure, else 0.
fn report(console_fd: usize, name: &[u8], key: &[u8], verdict: Verdict) -> usize {
    let _ = emit_test_result(
        console_fd,
        b"FFW_PROBE",
        name,
        verdict.pass,
        key,
        verdict.rc,
    );
    usize::from(verdict.is_guest_failure(sys::ENOSYS_EXPECTED))
}

/// Print a probe line that can also be `UNSEEDED`, built with the same writer `emit_test_result` uses.
fn report_reported(console_fd: usize, name: &[u8], key: &[u8], result: Reported) -> usize {
    let status: &[u8] = match result.status {
        Status::Pass => b" status=PASS ",
        Status::Fail => b" status=FAIL ",
        Status::Unseeded => b" status=UNSEEDED ",
    };
    let mut line = LineWriter::new();
    line.push(b"FFW_PROBE:");
    line.push(name);
    line.push(status);
    line.push(key);
    line.push(b"=");
    line.push_isize(result.rc);
    line.push(b"\n");
    emit_console(console_fd, line.as_slice());
    usize::from(result.is_guest_failure(sys::ENOSYS_EXPECTED))
}

/// Run every probe in order, printing each line as soon as its probe finishes so a hang in a later
/// probe cannot hide an earlier result. Returns how many probes were ambiguous (guest failures).
/// Slice 2 (`net`) runs last: it brings `lo` up and forks once, so the slice-1 results are already
/// on the console if anything there misbehaves.
pub fn run(console_fd: usize) -> usize {
    report_reported(console_fd, b"GETRANDOM", b"rc", probe_getrandom())
        + report(console_fd, b"EVENTFD2", b"fd", probe_eventfd())
        + report(console_fd, b"TIMERFD", b"fd", probe_timerfd())
        + report(console_fd, b"FUTEX", b"rc", probe_futex())
        + net::run(console_fd)
}
