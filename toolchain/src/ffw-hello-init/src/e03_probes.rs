//! Real-syscall E03 guest probes (ffw-q2p, BLK-003): `getrandom`, `eventfd2`, `timerfd`, `futex`.
//!
//! Declared from `main.rs` (`mod e03_probes;`), so it reaches the audited syscall trampoline and the
//! console writer through `super::`. Every probe issues the real syscall and checks its observable
//! behavior; the pass/fail decision lives in `ffw_hello_init::e03_judge`, where it has host tests.
//!
//! Bounds: no probe can block PID 1. Reads use nonblocking descriptors, every `poll` carries a
//! timeout, every futex wait carries a timeout, and `getrandom` uses `GRND_NONBLOCK` with a short
//! retry. The worst case for the whole module is well under one second.
//!
//! Line contract: `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<raw defining-syscall return>`.
//! A kernel that lacks the call answers `-ENOSYS` and that is printed as is; it does not count as a
//! guest failure (`Verdict::is_guest_failure`). A call that exists but misbehaves does.

use core::sync::atomic::AtomicU32;

use ffw_hello_init::e03_judge::{self, EventfdObs, FutexObs, TimerfdObs, Verdict};

use super::{emit_test_result, sys, sys_close, sys_raw, sys_read, sys_write, PollFd, Timespec32};

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
/// Plain (shared) futex operations: they exist on every kernel in scope. `FUTEX_PRIVATE_FLAG`
/// arrived in 2.6.22 and would report a 2.6.14 kernel as ENOSYS although futex is present.
const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;

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

/// Monotonic time in nanoseconds, or `None` if the clock call fails.
fn mono_ns() -> Option<i64> {
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
        Some(ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64)
    } else {
        None
    }
}

fn sys_getrandom(buf: &mut [u8; 16]) -> isize {
    sc(
        nr::GETRANDOM,
        buf.as_mut_ptr() as usize,
        buf.len(),
        GRND_NONBLOCK,
        0,
    )
}

fn probe_getrandom() -> Verdict {
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    // A freshly booted guest without an entropy device may not have a seeded pool yet. With
    // GRND_NONBLOCK that is a bounded `-EAGAIN`; wait a little, then report the truth rather than
    // block PID 1 or fall back to a non-secure source.
    let mut first_rc = sys_getrandom(&mut first);
    let mut tries = 0;
    while first_rc == -e03_judge::EAGAIN && tries < GETRANDOM_RETRIES {
        sleep_ms(GETRANDOM_RETRY_MS);
        first_rc = sys_getrandom(&mut first);
        tries += 1;
    }
    let second_rc = if first_rc == e03_judge::GETRANDOM_BYTES {
        sys_getrandom(&mut second)
    } else {
        0
    };
    e03_judge::judge_getrandom(first_rc, second_rc, &first, &second)
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
            expirations = expirations.saturating_add(count);
            if expirations >= e03_judge::TIMERFD_MIN_EXPIRATIONS {
                break;
            }
        }
    }
    let end = mono_ns();
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
    let elapsed_ns = match (start, end) {
        (Some(a), Some(b)) => b - a,
        _ => -1,
    };
    e03_judge::judge_timerfd(&TimerfdObs {
        fd,
        settime_rc,
        expirations,
        elapsed_ns,
    })
}

/// The futex word stays 0 for the whole run; nothing else ever waits on it.
static FUTEX_WORD: AtomicU32 = AtomicU32::new(0);

fn probe_futex() -> Verdict {
    let addr = FUTEX_WORD.as_ptr() as usize;
    let wake_rc = sc(nr::FUTEX, addr, FUTEX_WAKE, 1, 0);
    if wake_rc < 0 {
        return e03_judge::judge_futex(
            &FutexObs {
                wake_rc,
                mismatch_rc: 0,
                timeout_rc: 0,
            },
            nr::ETIMEDOUT,
        );
    }
    let timeout = Timespec32 {
        tv_sec: 0,
        tv_nsec: e03_judge::FUTEX_TIMEOUT_NS,
    };
    let timeout_ptr = &timeout as *const Timespec32 as usize;
    // The word is 0, so waiting for 1 mismatches and returns -EAGAIN at once. A timeout is still
    // passed so a broken kernel cannot hang PID 1.
    let mismatch_rc = sc(nr::FUTEX, addr, FUTEX_WAIT, 1, timeout_ptr);
    // Waiting for the matching value sleeps until the relative timeout and returns -ETIMEDOUT.
    let timeout_rc = sc(nr::FUTEX, addr, FUTEX_WAIT, 0, timeout_ptr);
    e03_judge::judge_futex(
        &FutexObs {
            wake_rc,
            mismatch_rc,
            timeout_rc,
        },
        nr::ETIMEDOUT,
    )
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

/// Run every probe in order, printing each line as soon as its probe finishes so a hang in a later
/// probe cannot hide an earlier result. Returns how many probes were ambiguous (guest failures).
/// Slice 2 (`net`) runs last: it brings `lo` up and forks once, so the slice-1 results are already
/// on the console if anything there misbehaves.
pub fn run(console_fd: usize) -> usize {
    report(console_fd, b"GETRANDOM", b"rc", probe_getrandom())
        + report(console_fd, b"EVENTFD2", b"fd", probe_eventfd())
        + report(console_fd, b"TIMERFD", b"fd", probe_timerfd())
        + report(console_fd, b"FUTEX", b"rc", probe_futex())
        + net::run(console_fd)
}
