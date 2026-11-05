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
//!
//! One probe has a third state. `GETRANDOM` can print `status=UNSEEDED rc=-11`: the call exists and
//! works, but the kernel's entropy pool was never seeded before the probe gave up waiting. That is a
//! property of the boot, reported as such; it is neither a pass nor a guest malfunction, and no other
//! probe may use it (see [`Reported`]).

#![forbid(unsafe_code)]

/// Slice 2 (BLK-006): loopback, UDP truncation reporting, `accept4`, reactor wakeup, char-device poll.
pub mod net;

pub const EAGAIN: isize = 11;
pub const EINVAL: isize = 22;
pub const POLLIN: i16 = 1;

/// Bytes requested from `getrandom` per draw.
pub const GETRANDOM_BYTES: isize = 16;
/// A `getrandom` flag bit no kernel defines (`GRND_NONBLOCK` is 1, `GRND_RANDOM` 2, `GRND_INSECURE` 4).
/// The kernel rejects it with `-EINVAL` before it looks at the entropy pool, so that exact answer
/// proves the syscall exists even when no entropy is available.
pub const GETRANDOM_INVALID_FLAG: usize = 0x8;
/// Initial `eventfd2` counter and the value written afterwards.
pub const EVENTFD_INITVAL: u32 = 3;
pub const EVENTFD_ADDED: u64 = 5;
/// Periodic timerfd interval, and what must be observed before the probe passes.
pub const TIMERFD_INTERVAL_NS: i32 = 5_000_000;
pub const TIMERFD_MIN_EXPIRATIONS: u64 = 3;
/// "Repeated wakeups" means at least two separate reads that returned, not one read of a backlog.
pub const TIMERFD_MIN_READS: u32 = 2;
/// Three expirations of a 5 ms periodic timer cannot legitimately arrive in under 15 ms (3 x 5 ms).
pub const TIMERFD_MIN_ELAPSED_NS: i64 = 15_000_000;
/// Timeout given to each futex wait that must time out: relative for the plain op, absolute
/// (`CLOCK_MONOTONIC`, this far ahead) for `FUTEX_WAIT_BITSET`.
pub const FUTEX_TIMEOUT_NS: i32 = 5_000_000;
/// A 5 ms wait that reports `-ETIMEDOUT` after less than 4 ms did not wait: an immediate timeout fails.
pub const FUTEX_MIN_ELAPSED_NS: i64 = 4_000_000;

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

/// The `status=` token a probe line carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    /// The call exists and works but the kernel had no entropy to give. `GETRANDOM` only.
    Unseeded,
}

/// A probe result that can be `UNSEEDED` as well as pass or fail. It is separate from [`Verdict`] so
/// that every other probe keeps the two-state type it has always had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reported {
    /// The value printed after the key: the raw return that decided the outcome.
    pub rc: isize,
    pub status: Status,
}

impl Reported {
    /// `UNSEEDED` is not a guest failure (the boot condition is real and is reported, not hidden);
    /// a `FAIL` is one unless it is exactly this ABI's `-ENOSYS`.
    pub const fn is_guest_failure(self, enosys: isize) -> bool {
        match self.status {
            Status::Pass | Status::Unseeded => false,
            Status::Fail => self.rc != -enosys,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GetrandomObs {
    /// The last raw `getrandom(buf, 16, GRND_NONBLOCK)` return, after the probe's bounded retries.
    pub first_rc: isize,
    pub second_rc: isize,
    pub first: [u8; 16],
    pub second: [u8; 16],
    /// `getrandom(buf, 16, GETRANDOM_INVALID_FLAG)`, made only when `first_rc` is still `-EAGAIN`;
    /// [`net::NOT_RUN`] otherwise.
    pub existence_rc: isize,
}

/// Seeded: two full, non-zero, different draws. Persistent `-EAGAIN` is judged by the existence
/// check: exactly `-EINVAL` means the call is there and the pool never seeded (`Unseeded`, printed as
/// `rc=-11`); `-ENOSYS` means it is absent; anything else is ambiguous. No entropy is credited or
/// faked to get out of this state.
pub fn judge_getrandom(o: &GetrandomObs) -> Reported {
    if o.first_rc == GETRANDOM_BYTES {
        let pass = o.second_rc == GETRANDOM_BYTES
            && o.first.iter().any(|&b| b != 0)
            && o.first != o.second;
        let status = if pass { Status::Pass } else { Status::Fail };
        return Reported {
            rc: o.first_rc,
            status,
        };
    }
    if o.first_rc == -EAGAIN {
        if o.existence_rc == -EINVAL {
            return Reported {
                rc: o.first_rc,
                status: Status::Unseeded,
            };
        }
        // Not proven present. An exact -ENOSYS here is read as unsupported by the caller's ABI.
        let rc = if o.existence_rc == net::NOT_RUN {
            o.first_rc
        } else {
            o.existence_rc
        };
        return Reported {
            rc,
            status: Status::Fail,
        };
    }
    Reported {
        rc: o.first_rc,
        status: Status::Fail,
    }
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
    /// How many 8-byte reads returned. A slow guest can find several expirations queued in one read;
    /// "repeated wakeups" needs at least [`TIMERFD_MIN_READS`] separate ones.
    pub reads: u32,
    /// Monotonic time from just before arming to just after the last read; negative if unknown.
    pub elapsed_ns: i64,
}

pub fn judge_timerfd(o: &TimerfdObs) -> Verdict {
    let pass = o.fd > 0
        && o.settime_rc == 0
        && o.expirations >= TIMERFD_MIN_EXPIRATIONS
        && o.reads >= TIMERFD_MIN_READS
        && o.elapsed_ns >= TIMERFD_MIN_ELAPSED_NS;
    Verdict { rc: o.fd, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct FutexObs {
    /// The operations Rust's std and musl actually use: `FUTEX_WAKE|PRIVATE` on a word nobody waits
    /// on (raw return must be 0), then `FUTEX_WAIT_BITSET|PRIVATE` with `FUTEX_BITSET_MATCH_ANY` and an
    /// ABSOLUTE `CLOCK_MONOTONIC` deadline. Plain ops alone would not support a "threads OK" claim.
    pub wake_rc: isize,
    /// Wait for a value that does not match the word: `-EAGAIN`, at once.
    pub mismatch_rc: isize,
    /// Wait for the matching value until a deadline 5 ms ahead: `-ETIMEDOUT`.
    pub timeout_rc: isize,
    /// Monotonic time around that wait. An immediate `-ETIMEDOUT` did not wait and fails.
    pub timeout_elapsed_ns: i64,
    /// The legacy shared ops (`FUTEX_WAKE`, `FUTEX_WAIT` with a relative timeout), kept so that both
    /// families must pass: same three expectations and the same elapsed-time floor.
    pub plain_wake_rc: isize,
    pub plain_mismatch_rc: isize,
    pub plain_timeout_rc: isize,
    pub plain_timeout_elapsed_ns: i64,
}

/// `etimedout` and `enosys` are the positive ETIMEDOUT / ENOSYS numbers of the guest ABI (110 / 38 on
/// PowerPC, 145 / 89 on MIPS). The printed value is the raw return that stopped the probe: an exact
/// `-ENOSYS` from the wake or from either bitset wait means the operations std needs are absent, and
/// is printed as such (unsupported), not as the 0 an earlier wake may have returned.
pub fn judge_futex(o: &FutexObs, etimedout: isize, enosys: isize) -> Verdict {
    let std_ops = o.wake_rc == 0
        && o.mismatch_rc == -EAGAIN
        && o.timeout_rc == -etimedout
        && o.timeout_elapsed_ns >= FUTEX_MIN_ELAPSED_NS;
    let plain_ops = o.plain_wake_rc == 0
        && o.plain_mismatch_rc == -EAGAIN
        && o.plain_timeout_rc == -etimedout
        && o.plain_timeout_elapsed_ns >= FUTEX_MIN_ELAPSED_NS;
    let rc = if o.wake_rc < 0 {
        o.wake_rc
    } else if o.mismatch_rc == -enosys {
        o.mismatch_rc
    } else if o.timeout_rc == -enosys {
        o.timeout_rc
    } else {
        o.wake_rc
    };
    Verdict {
        rc,
        pass: std_ops && plain_ops,
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
    fn seeded() -> GetrandomObs {
        GetrandomObs {
            first_rc: 16,
            second_rc: 16,
            first: DRAW_A,
            second: DRAW_B,
            existence_rc: net::NOT_RUN,
        }
    }

    /// The boot condition BeigeMaple read from the committed logs: no RNG device, never seeded.
    fn unseeded() -> GetrandomObs {
        GetrandomObs {
            first_rc: -EAGAIN,
            second_rc: 0,
            first: [0; 16],
            second: [0; 16],
            existence_rc: -EINVAL,
        }
    }

    #[test]
    fn getrandom_seeded_is_a_pass_with_rc_16() {
        let r = judge_getrandom(&seeded());
        assert_eq!(
            r,
            Reported {
                rc: 16,
                status: Status::Pass
            }
        );
        assert!(!r.is_guest_failure(PPC_ENOSYS));
    }

    #[test]
    fn getrandom_unseeded_with_the_einval_existence_check_is_its_own_outcome() {
        let r = judge_getrandom(&unseeded());
        assert_eq!(
            r,
            Reported {
                rc: -11,
                status: Status::Unseeded
            }
        );
        // Not a pass, and not a guest failure on either ABI: the boot condition is reported as is.
        assert_ne!(r.status, Status::Pass);
        assert!(!r.is_guest_failure(PPC_ENOSYS));
        assert!(!r.is_guest_failure(MIPS_ENOSYS));
    }

    #[test]
    fn getrandom_unseeded_needs_the_exact_existence_answer() {
        // The call must be proven to exist with exactly -EINVAL; any other answer is ambiguous.
        for existence in [0, 16, -EAGAIN, -1, -9, -14, -4, net::NOT_RUN] {
            let o = GetrandomObs {
                existence_rc: existence,
                ..unseeded()
            };
            let r = judge_getrandom(&o);
            assert_eq!(r.status, Status::Fail, "existence {existence}");
            assert!(r.is_guest_failure(PPC_ENOSYS), "existence {existence}");
        }
        // The printed value for a not-run check stays the -EAGAIN that stopped the probe.
        let not_run = GetrandomObs {
            existence_rc: net::NOT_RUN,
            ..unseeded()
        };
        assert_eq!(judge_getrandom(&not_run).rc, -11);
    }

    #[test]
    fn getrandom_unseeded_requires_the_first_return_to_be_exactly_eagain() {
        // EINVAL on the existence call proves nothing if the draw itself failed another way.
        for first in [-4, -12, -14, 0, 8, 15] {
            let o = GetrandomObs {
                first_rc: first,
                ..unseeded()
            };
            let r = judge_getrandom(&o);
            assert_eq!(r.status, Status::Fail, "first_rc {first}");
            assert!(r.is_guest_failure(PPC_ENOSYS), "first_rc {first}");
        }
    }

    #[test]
    fn getrandom_enosys_is_unsupported_whichever_call_reports_it() {
        let direct = GetrandomObs {
            first_rc: -PPC_ENOSYS,
            ..unseeded()
        };
        let r = judge_getrandom(&direct);
        assert_eq!((r.rc, r.status), (-38, Status::Fail));
        assert!(!r.is_guest_failure(PPC_ENOSYS));
        // Through the existence check, with the pool unseeded.
        let via_existence = GetrandomObs {
            existence_rc: -MIPS_ENOSYS,
            ..unseeded()
        };
        let m = judge_getrandom(&via_existence);
        assert_eq!((m.rc, m.status), (-89, Status::Fail));
        assert!(!m.is_guest_failure(MIPS_ENOSYS));
        // 89 is not ENOSYS on PowerPC, and 38 is not ENOSYS on MIPS.
        assert!(m.is_guest_failure(PPC_ENOSYS));
        assert!(r.is_guest_failure(MIPS_ENOSYS));
    }

    #[test]
    fn getrandom_seeded_checks_each_catch_their_own_regression() {
        assert_eq!(judge_getrandom(&seeded()).status, Status::Pass);
        let mutations: [Mutation<GetrandomObs>; 5] = [
            ("first draw short", |o| o.first_rc = 8),
            ("second draw failed", |o| o.second_rc = -EAGAIN),
            ("second draw short", |o| o.second_rc = 8),
            ("first draw all zero", |o| o.first = [0; 16]),
            ("draw repeated", |o| o.second = o.first),
        ];
        for (name, mutate) in mutations {
            let mut o = seeded();
            mutate(&mut o);
            let r = judge_getrandom(&o);
            assert_eq!(r.status, Status::Fail, "{name} must fail the probe");
            assert!(r.is_guest_failure(PPC_ENOSYS), "{name}");
        }
    }

    #[test]
    fn a_successful_draw_is_never_reported_unseeded() {
        // Even if an existence value were present, a seeded pool is judged on the draws.
        let o = GetrandomObs {
            existence_rc: -EINVAL,
            ..seeded()
        };
        assert_eq!(judge_getrandom(&o).status, Status::Pass);
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
            reads: 3,
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
        let mutations: [Mutation<TimerfdObs>; 7] = [
            ("fd not positive", |o| o.fd = 0),
            ("arming failed", |o| o.settime_rc = -22),
            ("only two expirations", |o| o.expirations = 2),
            ("all expirations in one read, so no repeated wakeup", |o| {
                o.reads = 1
            }),
            ("no read returned", |o| o.reads = 0),
            ("fired faster than three intervals allow", |o| {
                o.elapsed_ns = 14_999_999
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
    fn timerfd_two_separate_reads_with_a_backlog_still_pass() {
        // A slow guest: 2 expirations queued for the first read, 1 for the second. Two wakeups, three
        // expirations, 16 ms: the repeated-wakeup claim holds, so this must not fail spuriously.
        let o = TimerfdObs {
            expirations: 3,
            reads: 2,
            ..good_timerfd()
        };
        assert!(judge_timerfd(&o).pass);
    }

    #[test]
    fn timerfd_absent_is_unsupported_and_armed_failure_is_ambiguous() {
        let absent = TimerfdObs {
            fd: -MIPS_ENOSYS,
            settime_rc: 0,
            expirations: 0,
            reads: 0,
            elapsed_ns: -1,
        };
        let v = judge_timerfd(&absent);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Unsupported);
        // The descriptor exists but never fires: the call is present and wrong, which is a defect.
        let silent = TimerfdObs {
            expirations: 0,
            reads: 0,
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
            timeout_elapsed_ns: 5_200_000,
            plain_wake_rc: 0,
            plain_mismatch_rc: -EAGAIN,
            plain_timeout_rc: -etimedout,
            plain_timeout_elapsed_ns: 5_100_000,
        }
    }

    #[test]
    fn futex_std_ops_and_plain_ops_pass_on_both_abis() {
        let ppc = judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT, PPC_ENOSYS);
        assert_eq!(ppc, Verdict { rc: 0, pass: true });
        assert!(judge_futex(&good_futex(MIPS_ETIMEDOUT), MIPS_ETIMEDOUT, MIPS_ENOSYS).pass);
    }

    #[test]
    fn futex_timeout_errno_is_abi_specific() {
        // MIPS ETIMEDOUT is 145; reading PowerPC's 110 there means the wrong errno was observed.
        assert!(!judge_futex(&good_futex(PPC_ETIMEDOUT), MIPS_ETIMEDOUT, MIPS_ENOSYS).pass);
        assert!(!judge_futex(&good_futex(MIPS_ETIMEDOUT), PPC_ETIMEDOUT, PPC_ENOSYS).pass);
    }

    #[test]
    fn futex_each_dropped_check_would_be_caught() {
        assert!(judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT, PPC_ENOSYS).pass);
        let mutations: [Mutation<FutexObs>; 10] = [
            ("private wake reported a waiter that does not exist", |o| {
                o.wake_rc = 1
            }),
            (
                "bitset wait on a mismatched value did not return EAGAIN",
                |o| o.mismatch_rc = 0,
            ),
            ("bitset wait did not time out", |o| o.timeout_rc = 0),
            ("bitset wait timed out at once", |o| {
                o.timeout_elapsed_ns = 3_999_999
            }),
            ("bitset wait elapsed time unknown", |o| {
                o.timeout_elapsed_ns = -1
            }),
            ("plain wake reported a waiter that does not exist", |o| {
                o.plain_wake_rc = 1
            }),
            (
                "plain wait on a mismatched value did not return EAGAIN",
                |o| o.plain_mismatch_rc = 0,
            ),
            ("plain wait did not time out", |o| o.plain_timeout_rc = 0),
            ("plain wait timed out at once", |o| {
                o.plain_timeout_elapsed_ns = 0
            }),
            ("plain wait elapsed time unknown", |o| {
                o.plain_timeout_elapsed_ns = -1
            }),
        ];
        for (name, mutate) in mutations {
            let mut o = good_futex(PPC_ETIMEDOUT);
            mutate(&mut o);
            assert!(
                !judge_futex(&o, PPC_ETIMEDOUT, PPC_ENOSYS).pass,
                "{name} must fail the probe"
            );
        }
    }

    #[test]
    fn futex_elapsed_floor_is_exactly_four_milliseconds() {
        let mut at_floor = good_futex(PPC_ETIMEDOUT);
        at_floor.timeout_elapsed_ns = FUTEX_MIN_ELAPSED_NS;
        at_floor.plain_timeout_elapsed_ns = FUTEX_MIN_ELAPSED_NS;
        assert!(judge_futex(&at_floor, PPC_ETIMEDOUT, PPC_ENOSYS).pass);
        at_floor.timeout_elapsed_ns -= 1;
        assert!(!judge_futex(&at_floor, PPC_ETIMEDOUT, PPC_ENOSYS).pass);
    }

    /// Every field the probe never reached.
    fn futex_not_run() -> FutexObs {
        FutexObs {
            wake_rc: net::NOT_RUN,
            mismatch_rc: net::NOT_RUN,
            timeout_rc: net::NOT_RUN,
            timeout_elapsed_ns: -1,
            plain_wake_rc: net::NOT_RUN,
            plain_mismatch_rc: net::NOT_RUN,
            plain_timeout_rc: net::NOT_RUN,
            plain_timeout_elapsed_ns: -1,
        }
    }

    #[test]
    fn futex_missing_private_wake_is_unsupported() {
        // A kernel without FUTEX_PRIVATE_FLAG (before 2.6.22) answers -ENOSYS to the wake.
        let absent = FutexObs {
            wake_rc: -PPC_ENOSYS,
            ..futex_not_run()
        };
        let v = judge_futex(&absent, PPC_ETIMEDOUT, PPC_ENOSYS);
        assert_eq!((v.rc, v.pass), (-38, false));
        assert_eq!(v.class(PPC_ENOSYS), Class::Unsupported);
        // Any other errno from the wake is a defect.
        let einval = FutexObs {
            wake_rc: -EINVAL,
            ..futex_not_run()
        };
        let w = judge_futex(&einval, PPC_ETIMEDOUT, PPC_ENOSYS);
        assert_eq!(w.class(PPC_ENOSYS), Class::Ambiguous);
        assert!(w.is_guest_failure(PPC_ENOSYS));
    }

    #[test]
    fn futex_missing_bitset_wait_after_a_working_wake_is_unsupported_not_zero() {
        // The wake worked (0) but WAIT_BITSET is absent (before 2.6.25): the printed value must be
        // the -ENOSYS, not the 0, or the line would read as an ambiguous failure.
        for (mismatch, timeout) in [(-MIPS_ENOSYS, -MIPS_ENOSYS), (-EAGAIN, -MIPS_ENOSYS)] {
            let o = FutexObs {
                wake_rc: 0,
                mismatch_rc: mismatch,
                timeout_rc: timeout,
                ..futex_not_run()
            };
            let v = judge_futex(&o, MIPS_ETIMEDOUT, MIPS_ENOSYS);
            assert_eq!((v.rc, v.pass), (-89, false), "{mismatch} {timeout}");
            assert_eq!(v.class(MIPS_ENOSYS), Class::Unsupported);
        }
    }

    #[test]
    fn a_pass_never_carries_a_negative_return_for_any_probe() {
        let passes = [
            judge_eventfd(&good_eventfd()),
            judge_timerfd(&good_timerfd()),
            judge_futex(&good_futex(PPC_ETIMEDOUT), PPC_ETIMEDOUT, PPC_ENOSYS),
        ];
        for v in passes {
            assert!(v.pass && v.rc >= 0, "{v:?}");
        }
        let r = judge_getrandom(&seeded());
        assert!(r.status == Status::Pass && r.rc >= 0, "{r:?}");
    }
}
