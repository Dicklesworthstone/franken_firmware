//! Pure verdict logic for the E03 guest capability probes (ffw-q2p, BLK-003).
//!
//! The PID-1 binary (`main.rs` + `e03_probes.rs`) performs the real syscalls and hands the raw
//! observations to these functions, so the pass/fail decision is unit-testable on a host while
//! the syscalls themselves are exercised only inside the matching guest.
//!
//! Output contract (see `tests/e03/abi.py`, `_LINE`): `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<int>`.
//! `<int>` is the RAW return of the probe's defining syscall (negative errno on failure), never a
//! derived flag, so a reader can decode `-ENOSYS` as an explicit capability failure. `PASS` is
//! produced only when the whole behavior check passed; a syscall that exists but misbehaves is
//! `FAIL` with a non-ENOSYS return, which the classifier reports as ambiguous, not unsupported.

#![forbid(unsafe_code)]

/// Slice 2 (BLK-006): loopback, UDP truncation reporting, `accept4`, reactor wakeup, char-device poll.
pub mod net;

pub const EAGAIN: isize = 11;
pub const POLLIN: i16 = 1;

/// Bytes requested from `getrandom` per draw.
pub const GETRANDOM_BYTES: isize = 16;
/// Initial `eventfd2` counter and the value written afterwards.
pub const EVENTFD_INITVAL: u32 = 3;
pub const EVENTFD_ADDED: u64 = 5;
/// Periodic timerfd interval, and what must be observed before the probe passes.
pub const TIMERFD_INTERVAL_NS: i32 = 5_000_000;
pub const TIMERFD_MIN_EXPIRATIONS: u64 = 3;
/// Three expirations of a 5 ms periodic timer cannot legitimately arrive in under 10 ms.
pub const TIMERFD_MIN_ELAPSED_NS: i64 = 10_000_000;
/// Relative timeout for the futex wait that must time out.
pub const FUTEX_TIMEOUT_NS: i32 = 5_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Raw return of the defining syscall (negative errno on failure).
    pub rc: isize,
    /// True only if every behavior check passed.
    pub pass: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Supported,
    /// The defining syscall returned exactly `-ENOSYS` for this ABI: an explicit capability failure.
    Unsupported,
    /// Anything else that is not a pass: the call exists (or failed some other way) but the
    /// behavior is wrong or unproven. This is a guest-visible defect, never silently green.
    Ambiguous,
}

impl Verdict {
    /// `enosys` is the positive ENOSYS number of the guest ABI (38 on PowerPC, 89 on MIPS).
    pub const fn class(self, enosys: isize) -> Class {
        if self.pass {
            Class::Supported
        } else if self.rc == -enosys {
            Class::Unsupported
        } else {
            Class::Ambiguous
        }
    }

    /// Only an ambiguous result counts against the guest's `failures` total. An exact `-ENOSYS`
    /// is reported as `FAIL` on its own probe line but is a capability answer, not a malfunction,
    /// so a stock-kernel guest can still print `TEST_SUCCESS`.
    pub const fn is_guest_failure(self, enosys: isize) -> bool {
        matches!(self.class(enosys), Class::Ambiguous)
    }
}

/// `getrandom(buf, 16, GRND_NONBLOCK)` twice. Requires two full draws, a non-zero first draw and
/// two different draws. A draw that is all zero or repeated is not entropy.
pub fn judge_getrandom(
    first_rc: isize,
    second_rc: isize,
    first: &[u8; 16],
    second: &[u8; 16],
) -> Verdict {
    let pass = first_rc == GETRANDOM_BYTES
        && second_rc == GETRANDOM_BYTES
        && first.iter().any(|&b| b != 0)
        && first != second;
    Verdict { rc: first_rc, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct EventfdObs {
    /// Raw `eventfd2(EVENTFD_INITVAL, O_NONBLOCK)` return.
    pub fd: isize,
    pub first_read: isize,
    pub first_val: u64,
    /// Read of a drained nonblocking eventfd: must be `-EAGAIN`.
    pub empty_read: isize,
    pub write_rc: isize,
    pub poll_rc: isize,
    pub poll_revents: i16,
    pub second_read: isize,
    pub second_val: u64,
}

pub fn judge_eventfd(o: &EventfdObs) -> Verdict {
    let pass = o.fd > 0
        && o.first_read == 8
        && o.first_val == EVENTFD_INITVAL as u64
        && o.empty_read == -EAGAIN
        && o.write_rc == 8
        && o.poll_rc == 1
        && (o.poll_revents & POLLIN) != 0
        && o.second_read == 8
        && o.second_val == EVENTFD_ADDED;
    Verdict { rc: o.fd, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct TimerfdObs {
    /// Raw `timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK)` return.
    pub fd: isize,
    pub settime_rc: isize,
    /// Sum of the expiration counts read from the descriptor.
    pub expirations: u64,
    /// Monotonic time from just before arming to just after the last read; negative if unknown.
    pub elapsed_ns: i64,
}

pub fn judge_timerfd(o: &TimerfdObs) -> Verdict {
    let pass = o.fd > 0
        && o.settime_rc == 0
        && o.expirations >= TIMERFD_MIN_EXPIRATIONS
        && o.elapsed_ns >= TIMERFD_MIN_ELAPSED_NS;
    Verdict { rc: o.fd, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct FutexObs {
    /// Raw `FUTEX_WAKE` return on a word nobody waits on: must be 0.
    pub wake_rc: isize,
    /// `FUTEX_WAIT` with a value that does not match the word: must be `-EAGAIN`, immediately.
    pub mismatch_rc: isize,
    /// `FUTEX_WAIT` with a matching value and a 5 ms timeout: must be `-ETIMEDOUT`.
    pub timeout_rc: isize,
}

/// `etimedout` is the positive ETIMEDOUT number of the guest ABI (110 on PowerPC, 145 on MIPS).
pub fn judge_futex(o: &FutexObs, etimedout: isize) -> Verdict {
    let pass = o.wake_rc == 0 && o.mismatch_rc == -EAGAIN && o.timeout_rc == -etimedout;
    Verdict {
        rc: o.wake_rc,
        pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One planted single-check regression: its name, and the edit to a good observation that must
    /// make the probe fail. An alias keeps `[Mutation<_>; N]` readable (clippy::type_complexity).
    type Mutation<T> = (&'static str, fn(&mut T));

    const PPC_ENOSYS: isize = 38;
    const MIPS_ENOSYS: isize = 89;
    const PPC_ETIMEDOUT: isize = 110;
    const MIPS_ETIMEDOUT: isize = 145;

    const DRAW_A: [u8; 16] = [
        0x9d, 0x01, 0x7c, 0x42, 0xe8, 0x33, 0x05, 0xaa, 0x61, 0xf0, 0x1b, 0x77, 0xc4, 0x2e, 0x90,
        0x58,
    ];
    const DRAW_B: [u8; 16] = [
        0x13, 0xb7, 0x40, 0x8e, 0x2a, 0xd5, 0x6c, 0x09, 0xfe, 0x31, 0x84, 0x57, 0xa0, 0xcb, 0x66,
        0xd2,
    ];

    // ----- getrandom
    #[test]
    fn getrandom_two_distinct_full_draws_pass() {
        let v = judge_getrandom(16, 16, &DRAW_A, &DRAW_B);
        assert_eq!(v, Verdict { rc: 16, pass: true });
        assert_eq!(v.class(PPC_ENOSYS), Class::Supported);
        assert!(!v.is_guest_failure(PPC_ENOSYS));
    }

    #[test]
    fn getrandom_enosys_is_unsupported_not_a_guest_failure() {
        let v = judge_getrandom(-PPC_ENOSYS, 0, &[0; 16], &[0; 16]);
        assert!(!v.pass);
        assert_eq!(v.rc, -38);
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        assert!(!v.is_guest_failure(PPC_ENOSYS));
        let m = judge_getrandom(-MIPS_ENOSYS, 0, &[0; 16], &[0; 16]);
        assert_eq!(m.class(MIPS_ENOSYS), Class::Unsupported);
    }

    #[test]
    fn getrandom_failures_that_are_not_enosys_are_ambiguous() {
        // EAGAIN: the call exists but the pool was not ready. Absence is not shown.
        let eagain = judge_getrandom(-EAGAIN, 0, &[0; 16], &[0; 16]);
        assert_eq!(eagain.class(PPC_ENOSYS), Class::Ambiguous);
        assert!(eagain.is_guest_failure(PPC_ENOSYS));
        // A short first draw, a failed or short second draw, an all-zero draw and a repeated
        // draw each break the pass on their own.
        for (a, b, c, d) in [
            (8, 16, DRAW_A, DRAW_B),
            (16, 8, DRAW_A, DRAW_B),
            (16, -EAGAIN, DRAW_A, DRAW_B),
            (16, 16, [0u8; 16], DRAW_B),
            (16, 16, DRAW_A, DRAW_A),
        ] {
            let v = judge_getrandom(a, b, &c, &d);
            assert!(!v.pass, "{a} {b} must not pass");
            assert_eq!(v.class(PPC_ENOSYS), Class::Ambiguous);
        }
    }

    #[test]
    fn enosys_of_the_other_abi_is_not_recognised() {
        // -38 is ENOSYS on PowerPC only. On MIPS, 38 is some other errno, so it stays ambiguous.
        let v = judge_getrandom(-38, 0, &[0; 16], &[0; 16]);
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Ambiguous);
    }

    // ----- eventfd2
    fn good_eventfd() -> EventfdObs {
        EventfdObs {
            fd: 5,
            first_read: 8,
            first_val: 3,
            empty_read: -EAGAIN,
            write_rc: 8,
            poll_rc: 1,
            poll_revents: POLLIN,
            second_read: 8,
            second_val: 5,
        }
    }

    #[test]
    fn eventfd_full_behavior_passes() {
        let v = judge_eventfd(&good_eventfd());
        assert_eq!(v, Verdict { rc: 5, pass: true });
        assert_eq!(v.class(MIPS_ENOSYS), Class::Supported);
    }

    #[test]
    fn eventfd_each_dropped_check_would_be_caught() {
        // Baseline first: the unmutated observation must pass, or a "catch" proves nothing.
        assert!(judge_eventfd(&good_eventfd()).pass);
        let mutations: [Mutation<EventfdObs>; 9] = [
            ("fd not positive", |o| o.fd = 0),
            ("first read short", |o| o.first_read = 4),
            ("initial value wrong", |o| o.first_val = 4),
            ("drained read not EAGAIN", |o| o.empty_read = 8),
            ("write short", |o| o.write_rc = 4),
            ("poll saw nothing", |o| o.poll_rc = 0),
            ("poll without POLLIN", |o| o.poll_revents = 4),
            ("second read short", |o| o.second_read = 0),
            ("written value not read back", |o| o.second_val = 3),
        ];
        for (name, mutate) in mutations {
            let mut o = good_eventfd();
            mutate(&mut o);
            assert!(!judge_eventfd(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn eventfd_enosys_reports_the_raw_errno_and_is_unsupported() {
        let mut o = good_eventfd();
        o.fd = -PPC_ENOSYS;
        let v = judge_eventfd(&o);
        assert_eq!(
            v,
            Verdict {
                rc: -38,
                pass: false
            }
        );
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        assert!(!v.is_guest_failure(PPC_ENOSYS));
    }

    // ----- timerfd
    fn good_timerfd() -> TimerfdObs {
        TimerfdObs {
            fd: 6,
            settime_rc: 0,
            expirations: 3,
            elapsed_ns: 16_000_000,
        }
    }

    #[test]
    fn timerfd_repeated_wakeups_pass() {
        assert_eq!(
            judge_timerfd(&good_timerfd()),
            Verdict { rc: 6, pass: true }
        );
    }

    #[test]
    fn timerfd_each_dropped_check_would_be_caught() {
        assert!(judge_timerfd(&good_timerfd()).pass);
        let mutations: [Mutation<TimerfdObs>; 5] = [
            ("fd not positive", |o| o.fd = 0),
            ("arming failed", |o| o.settime_rc = -22),
            ("only two expirations", |o| o.expirations = 2),
            ("fired faster than the interval allows", |o| {
                o.elapsed_ns = 9_999_999
            }),
            ("elapsed time unknown", |o| o.elapsed_ns = -1),
        ];
        for (name, mutate) in mutations {
            let mut o = good_timerfd();
            mutate(&mut o);
            assert!(!judge_timerfd(&o).pass, "{name} must fail the probe");
        }
    }

    #[test]
    fn timerfd_absent_is_unsupported_and_armed_failure_is_ambiguous() {
        let absent = TimerfdObs {
            fd: -MIPS_ENOSYS,
            settime_rc: 0,
            expirations: 0,
            elapsed_ns: -1,
        };
        let v = judge_timerfd(&absent);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Unsupported);
        // The descriptor exists but never fires: the call is present and wrong, which is a defect.
        let silent = TimerfdObs {
            expirations: 0,
            ..good_timerfd()
        };
        let s = judge_timerfd(&silent);
        assert_eq!(s.rc, 6);
        assert_eq!(s.class(MIPS_ENOSYS), Class::Ambiguous);
        assert!(s.is_guest_failure(MIPS_ENOSYS));
    }

    // ----- futex
    fn good_futex(etimedout: isize) -> FutexObs {
        FutexObs {
            wake_rc: 0,
            mismatch_rc: -EAGAIN,
            timeout_rc: -etimedout,
        }
    }

    #[test]
    fn futex_wake_mismatch_and_timeout_pass_on_both_abis() {
        assert!(judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT).pass);
        assert!(judge_futex(&good_futex(MIPS_ETIMEDOUT), MIPS_ETIMEDOUT).pass);
    }

    #[test]
    fn futex_timeout_errno_is_abi_specific() {
        // MIPS ETIMEDOUT is 145; reading PowerPC's 110 there means the wrong errno was observed.
        assert!(!judge_futex(&good_futex(PPC_ETIMEDOUT), MIPS_ETIMEDOUT).pass);
        assert!(!judge_futex(&good_futex(MIPS_ETIMEDOUT), PPC_ETIMEDOUT).pass);
    }

    #[test]
    fn futex_each_dropped_check_would_be_caught() {
        assert!(judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT).pass);
        let mutations: [Mutation<FutexObs>; 3] = [
            ("wake reported a waiter that does not exist", |o| {
                o.wake_rc = 1
            }),
            ("mismatched wait did not return EAGAIN", |o| {
                o.mismatch_rc = 0
            }),
            ("matching wait did not time out", |o| o.timeout_rc = 0),
        ];
        for (name, mutate) in mutations {
            let mut o = good_futex(PPC_ETIMEDOUT);
            mutate(&mut o);
            assert!(
                !judge_futex(&o, PPC_ETIMEDOUT).pass,
                "{name} must fail the probe"
            );
        }
    }

    #[test]
    fn futex_enosys_is_unsupported_and_other_errno_is_ambiguous() {
        let absent = FutexObs {
            wake_rc: -PPC_ENOSYS,
            mismatch_rc: 0,
            timeout_rc: 0,
        };
        let v = judge_futex(&absent, PPC_ETIMEDOUT);
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        let einval = FutexObs {
            wake_rc: -22,
            ..absent
        };
        let w = judge_futex(&einval, PPC_ETIMEDOUT);
        assert_eq!(w.class(PPC_ENOSYS), Class::Ambiguous);
        assert!(w.is_guest_failure(PPC_ENOSYS));
    }

    #[test]
    fn a_pass_never_carries_a_negative_return_for_any_probe() {
        let passes = [
            judge_getrandom(16, 16, &DRAW_A, &DRAW_B),
            judge_eventfd(&good_eventfd()),
            judge_timerfd(&good_timerfd()),
            judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT),
        ];
        for v in passes {
            assert!(v.pass && v.rc >= 0, "{v:?}");
        }
    }
}
