//! Pure verdict logic for the second batch of E03 guest probes (ffw-q2p): threads and TLS (BLK-003),
//! signals, timers, allocator-relevant kernel behavior, peak memory and the atomic width (BLK-004), and
//! fs sync plus rename-over-existing on the initramfs rootfs (BLK-006).
//!
//! The PID-1 binary (`e03_probes_rt.rs`) performs the real syscalls and hands the raw observations to
//! these functions, exactly as `e03_judge` does for the first batch, so every pass/fail decision is
//! unit-testable on a host while the syscalls run only inside the matching guest.
//!
//! Output contract (same grammar as `e03_judge`, see `tests/e03/abi.py` `_LINE`):
//! `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<int>`. `<int>` is the RAW return of the probe's defining
//! syscall, or of the first step that failed, never a derived flag; a kernel that lacks the call answers
//! exactly `-ENOSYS`, which `Verdict::class` reports as a capability absence rather than a malfunction.
//! `PASS` is produced only when the whole behavior check passed. A step that exists but misbehaves is a
//! `FAIL` with a non-ENOSYS return, which the verifier refuses, so it is never silently green.

#![forbid(unsafe_code)]

use crate::e03_judge::Verdict;

pub const EINTR: isize = 4;
pub const ENOENT: isize = 2;
pub const ENOMEM: isize = 12;

pub const PAGE: usize = 4096;
/// Value passed to `clone` with `CLONE_SETTLS`; the child must read exactly this from its thread
/// pointer (`rdhwr $29` on MIPS, `r2` on PowerPC).
pub const TLS_MAGIC: usize = 0x1234_5678;
/// Total sleep requested while a 5 ms periodic `SIGALRM` keeps interrupting it.
pub const TIMER_SLEEP_NS: i64 = 40_000_000;
pub const TIMER_MIN_SIGNALS: u32 = 3;
pub const TIMER_MIN_INTERRUPTED_SLEEPS: u32 = 2;
/// Length of each fs payload; the two payloads differ so a rename that did not replace is visible.
pub const FS_PAYLOAD_LEN: isize = 16;
pub const ALLOC_PAGES: usize = 3;
/// `brk` growth requested above the current break.
pub const BRK_GROW: usize = 2 * PAGE;
/// A mapping larger than any 32-bit user address space (TASK_SIZE is 2 GiB on MIPS32 and 3 GiB on
/// PowerPC32), so the kernel must refuse it with `-ENOMEM` whatever the guest RAM or overcommit mode.
pub const HUGE_MAP_LEN: usize = 0xE000_0000;
/// Atomic widths in bits, indexed like `AtomicObs::claimed` / `verified`.
pub const ATOMIC_WIDTHS: [isize; 4] = [8, 16, 32, 64];

/// A raw return in `-4095..=-1` is an errno. Anything else is a value, including a 32-bit PowerPC
/// `mmap` address above 2 GiB, which is negative as an `isize` but is not an error.
pub fn is_errno(rc: isize) -> bool {
    (-4095..0).contains(&rc)
}

// ---------------------------------------------------------------------------------------------
// THREADS and TLS: one `clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|
// CLONE_SETTLS|CLONE_CHILD_CLEARTID)` serves both lines.

#[derive(Debug, Clone, Copy)]
pub struct ThreadObs {
    /// Raw `mmap2` return for the child's stack: an address, or `-errno` (then no clone is made).
    pub stack_rc: isize,
    /// Raw `clone` return in the parent: the child's tid, or `-errno`.
    pub clone_rc: isize,
    pub parent_tid: isize,
    /// `gettid()` as the child saw it; 0 if the child never ran.
    pub child_tid: isize,
    /// The child stored its marker into memory shared with the parent (`CLONE_VM`).
    pub child_ran: bool,
    /// The kernel cleared the tid word at thread exit (`CLONE_CHILD_CLEARTID`) within the bound.
    pub joined: bool,
}

pub fn judge_threads(o: &ThreadObs) -> Verdict {
    let rc = if is_errno(o.stack_rc) {
        o.stack_rc
    } else {
        o.clone_rc
    };
    let pass = !is_errno(o.stack_rc)
        && o.clone_rc > 0
        && o.parent_tid > 0
        && o.clone_rc != o.parent_tid
        && o.child_ran
        && o.child_tid == o.clone_rc
        && o.joined;
    Verdict { rc, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct TlsObs {
    /// MIPS: raw `set_thread_area` return. PowerPC has no such syscall (the thread pointer is `r2`),
    /// so the probe passes 0 there.
    pub set_area_rc: isize,
    /// Raw `clone` return in the parent (or the `-errno` that stopped the attempt earlier).
    pub clone_rc: isize,
    pub child_ran: bool,
    /// The parent's thread pointer read back right after it was set (MIPS) or first read (PowerPC).
    pub parent_tp_before: usize,
    /// What the parent set (MIPS) or read (PowerPC); must equal `parent_tp_before`.
    pub parent_tp_expected: usize,
    /// The parent's thread pointer after the child exited: must be untouched by the child.
    pub parent_tp_after: usize,
    /// The thread pointer the child read; `CLONE_SETTLS` was given `TLS_MAGIC`.
    pub child_tp: usize,
}

pub fn judge_tls(o: &TlsObs) -> Verdict {
    let rc = if is_errno(o.set_area_rc) {
        o.set_area_rc
    } else if is_errno(o.clone_rc) {
        o.clone_rc
    } else {
        o.child_tp as isize
    };
    let pass = o.set_area_rc == 0
        && o.clone_rc > 0
        && o.child_ran
        && o.parent_tp_before == o.parent_tp_expected
        && o.parent_tp_after == o.parent_tp_before
        && o.child_tp == TLS_MAGIC
        && o.child_tp != o.parent_tp_before;
    Verdict { rc, pass }
}

// ---------------------------------------------------------------------------------------------
// BLK-004: signal delivery (and the SIGTERM an init receives to start a shutdown), EINTR, timers.

#[derive(Debug, Clone, Copy)]
pub struct SignalObs {
    /// Raw `rt_sigaction(SIGTERM, handler)` return.
    pub act_rc: isize,
    /// Raw `rt_sigprocmask(SIG_BLOCK, {SIGTERM})` return.
    pub block_rc: isize,
    /// Raw `tkill(self, SIGTERM)` return.
    pub kill_rc: isize,
    /// Handler runs seen while the signal was blocked: must be 0 (it stays pending).
    pub count_while_blocked: u32,
    /// Raw `rt_sigprocmask(SIG_UNBLOCK, {SIGTERM})` return.
    pub unblock_rc: isize,
    /// Handler runs seen once the pending signal was unblocked: must be exactly 1.
    pub count_after_unblock: u32,
}

pub fn judge_signal(o: &SignalObs) -> Verdict {
    let pass = o.act_rc == 0
        && o.block_rc == 0
        && o.kill_rc == 0
        && o.count_while_blocked == 0
        && o.unblock_rc == 0
        && o.count_after_unblock == 1;
    Verdict { rc: o.act_rc, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct EintrObs {
    pub pipe_rc: isize,
    pub act_rc: isize,
    /// Raw `setitimer` return for the periodic `SIGALRM`.
    pub timer_rc: isize,
    /// Raw return of the `read` on an empty blocking pipe: must be `-EINTR`.
    pub read_rc: isize,
    pub handler_count: u32,
    pub disarm_rc: isize,
}

pub fn judge_eintr_read(o: &EintrObs) -> Verdict {
    let rc = if o.pipe_rc != 0 {
        o.pipe_rc
    } else if o.act_rc != 0 {
        o.act_rc
    } else if o.timer_rc != 0 {
        o.timer_rc
    } else {
        o.read_rc
    };
    let pass = o.pipe_rc == 0
        && o.act_rc == 0
        && o.timer_rc == 0
        && o.read_rc == -EINTR
        && o.handler_count >= 1
        && o.disarm_rc == 0;
    Verdict { rc, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct TimerSigObs {
    pub act_rc: isize,
    /// Raw `setitimer` return arming the 5 ms periodic `SIGALRM`.
    pub timer_rc: isize,
    /// Last `nanosleep` return: 0 only when the whole interval finally elapsed.
    pub final_sleep_rc: isize,
    /// `nanosleep` calls that were cut short with `-EINTR` and resumed with the reported remainder.
    pub interrupted_sleeps: u32,
    pub signals: u32,
    /// Monotonic time from just before arming to just after the last sleep; negative if unknown.
    pub elapsed_ns: i64,
    pub disarm_rc: isize,
}

pub fn judge_timer_signals(o: &TimerSigObs) -> Verdict {
    let rc = if o.act_rc != 0 { o.act_rc } else { o.timer_rc };
    let pass = o.act_rc == 0
        && o.timer_rc == 0
        && o.final_sleep_rc == 0
        && o.interrupted_sleeps >= TIMER_MIN_INTERRUPTED_SLEEPS
        && o.signals >= TIMER_MIN_SIGNALS
        && o.elapsed_ns >= TIMER_SLEEP_NS / 10 * 9
        && o.disarm_rc == 0;
    Verdict { rc, pass }
}

// ---------------------------------------------------------------------------------------------
// BLK-004: allocator-relevant kernel behavior and peak memory.

#[derive(Debug, Clone, Copy)]
pub struct AllocObs {
    /// Raw `mmap2` of `ALLOC_PAGES` anonymous pages: an address or `-errno`.
    pub map_rc: isize,
    /// The fresh pages read as zero.
    pub zero_ok: bool,
    /// A distinct byte written to each page read back unchanged.
    pub fill_ok: bool,
    /// Raw `mmap2` of `HUGE_MAP_LEN`: must be `-ENOMEM`.
    pub huge_rc: isize,
    /// Raw `munmap` of the first mapping.
    pub unmap_rc: isize,
    /// `brk(0)`: the current break.
    pub brk_start: usize,
    /// `brk(start + BRK_GROW)`: must return the requested break.
    pub brk_grown: usize,
    pub brk_fill_ok: bool,
    /// `brk(start)`: must return the original break.
    pub brk_restored: usize,
}

pub fn judge_alloc(o: &AllocObs) -> Verdict {
    let rc = if is_errno(o.map_rc) {
        o.map_rc
    } else {
        o.unmap_rc
    };
    let aligned = !is_errno(o.map_rc) && o.map_rc != 0 && (o.map_rc as usize) % PAGE == 0;
    let pass = aligned
        && o.zero_ok
        && o.fill_ok
        && o.huge_rc == -ENOMEM
        && o.unmap_rc == 0
        && o.brk_start != 0
        && o.brk_grown == o.brk_start.wrapping_add(BRK_GROW)
        && o.brk_fill_ok
        && o.brk_restored == o.brk_start;
    Verdict { rc, pass }
}

/// Value in kB of a `/proc/<pid>/status` line such as `VmHWM:\t    1234 kB`. The key must start the
/// line (so `xVmHWM:` is not a match), the number must be followed by the `kB` unit, and an
/// overflowing number is not a value.
pub fn parse_status_kb(text: &[u8], key: &[u8]) -> Option<u64> {
    for line in text.split(|&b| b == b'\n') {
        if line.len() < key.len() || line[..key.len()] != *key {
            continue;
        }
        let mut i = key.len();
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        let start = i;
        let mut value: u64 = 0;
        while i < line.len() && line[i].is_ascii_digit() {
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(line[i] - b'0'))?;
            i += 1;
        }
        if i == start {
            return None;
        }
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        let unit = &line[i..];
        return if unit == b"kB" || unit == b"kB\r" {
            Some(value)
        } else {
            None
        };
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct MemPeakObs {
    /// Raw `open("/proc/self/status")` return.
    pub open_rc: isize,
    /// Bytes read (negative: the raw read error).
    pub read_len: isize,
    pub vm_peak_kb: Option<u64>,
    pub vm_hwm_kb: Option<u64>,
}

pub fn judge_mem_peak(o: &MemPeakObs) -> Verdict {
    let hwm = o.vm_hwm_kb.unwrap_or(0);
    let rc = if o.open_rc < 0 {
        o.open_rc
    } else if o.read_len < 0 {
        o.read_len
    } else {
        hwm as isize
    };
    let pass = o.open_rc >= 0
        && o.read_len > 0
        && o.vm_peak_kb.is_some()
        && o.vm_hwm_kb.is_some()
        && hwm > 0
        && o.vm_peak_kb.unwrap_or(0) >= hwm;
    Verdict { rc, pass }
}

#[derive(Debug, Clone, Copy)]
pub struct AtomicObs {
    /// What the compiler reports (`cfg(target_has_atomic)`) for 8, 16, 32 and 64 bits.
    pub claimed: [bool; 4],
    /// Whether a runtime fetch-add plus compare-exchange on that width produced the right values.
    pub verified: [bool; 4],
}

/// The atomic situation as observed. `rc` is the widest width that is both claimed and verified; the
/// 32-bit width the project depends on must be claimed, and every claimed width must work. A target
/// without 64-bit atomics (both Sonos SoC families) reports `32`, which is the recorded fact that
/// `AtomicU64` must come from a portable fallback rather than the hardware.
pub fn judge_atomic_width(o: &AtomicObs) -> Verdict {
    let mut widest = 0;
    let mut claimed_all_work = true;
    let mut no_unclaimed_success = true;
    for (i, width) in ATOMIC_WIDTHS.iter().enumerate() {
        if o.claimed[i] {
            if o.verified[i] {
                widest = *width;
            } else {
                claimed_all_work = false;
            }
        } else if o.verified[i] {
            no_unclaimed_success = false;
        }
    }
    Verdict {
        rc: widest,
        pass: o.claimed[2] && claimed_all_work && no_unclaimed_success,
    }
}

// ---------------------------------------------------------------------------------------------
// BLK-006: fs sync and rename-over-existing on the initramfs rootfs.

#[derive(Debug, Clone, Copy)]
pub struct FsObs {
    pub create_a: isize,
    pub write_a: isize,
    pub fsync_a: isize,
    pub create_b: isize,
    pub write_b: isize,
    /// Raw `rename(a, b)` return where `b` already exists.
    pub rename_rc: isize,
    /// Bytes read back from `b`.
    pub read_back: isize,
    /// `b` now holds exactly `a`'s payload.
    pub content_ok: bool,
    /// `open(a)` after the rename: must be `-ENOENT`.
    pub old_name_rc: isize,
    /// Raw `unlink(b)` cleanup return.
    pub cleanup_rc: isize,
}

pub fn judge_fs_rename(o: &FsObs) -> Verdict {
    let rc = if o.create_a < 0 {
        o.create_a
    } else if o.fsync_a != 0 {
        o.fsync_a
    } else if o.create_b < 0 {
        o.create_b
    } else {
        o.rename_rc
    };
    let pass = o.create_a >= 0
        && o.write_a == FS_PAYLOAD_LEN
        && o.fsync_a == 0
        && o.create_b >= 0
        && o.write_b == FS_PAYLOAD_LEN
        && o.rename_rc == 0
        && o.read_back == FS_PAYLOAD_LEN
        && o.content_ok
        && o.old_name_rc == -ENOENT
        && o.cleanup_rc == 0;
    Verdict { rc, pass }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e03_judge::Class;

    const PPC_ENOSYS: isize = 38;
    const MIPS_ENOSYS: isize = 89;

    fn good_threads() -> ThreadObs {
        ThreadObs {
            stack_rc: 0x77f0_0000,
            clone_rc: 2,
            parent_tid: 1,
            child_tid: 2,
            child_ran: true,
            joined: true,
        }
    }

    #[test]
    fn errno_window_is_not_confused_with_high_addresses() {
        assert!(is_errno(-1));
        assert!(is_errno(-89));
        assert!(is_errno(-4095));
        assert!(!is_errno(0));
        assert!(!is_errno(1));
        assert!(!is_errno(-4096));
        // A PowerPC32 mmap address such as 0xb7f00000 is negative as an isize but is a success.
        assert!(!is_errno(0xb7f0_0000_u32 as i32 as isize));
    }

    // ----- threads
    #[test]
    fn threads_pass_when_the_child_ran_and_was_joined() {
        let v = judge_threads(&good_threads());
        assert_eq!(v, Verdict { rc: 2, pass: true });
        assert_eq!(v.class(PPC_ENOSYS), Class::Supported);
    }

    #[test]
    fn threads_each_missing_fact_breaks_the_pass() {
        let base = good_threads();
        let cases = [
            ThreadObs {
                child_ran: false,
                ..base
            },
            ThreadObs {
                joined: false,
                ..base
            },
            ThreadObs {
                child_tid: 3,
                ..base
            },
            ThreadObs {
                child_tid: 0,
                ..base
            },
            ThreadObs {
                clone_rc: 1,
                child_tid: 1,
                ..base
            },
            ThreadObs {
                parent_tid: 0,
                ..base
            },
            ThreadObs {
                clone_rc: 0,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_threads(o).pass, "case {n} must not pass");
        }
    }

    #[test]
    fn threads_enosys_is_a_capability_absence_on_each_abi() {
        let ppc = judge_threads(&ThreadObs {
            clone_rc: -PPC_ENOSYS,
            child_tid: 0,
            child_ran: false,
            joined: false,
            ..good_threads()
        });
        assert!(!ppc.pass);
        assert_eq!(ppc.rc, -38);
        assert_eq!(ppc.class(PPC_ENOSYS), Class::Unsupported);
        assert!(!ppc.is_guest_failure(PPC_ENOSYS));
        let mips = judge_threads(&ThreadObs {
            clone_rc: -MIPS_ENOSYS,
            child_tid: 0,
            child_ran: false,
            joined: false,
            ..good_threads()
        });
        assert_eq!(mips.class(MIPS_ENOSYS), Class::Unsupported);
        // -38 is not ENOSYS on MIPS.
        assert_eq!(ppc.class(MIPS_ENOSYS), Class::Ambiguous);
    }

    #[test]
    fn threads_stack_failure_reports_the_mmap_errno_and_never_passes() {
        let v = judge_threads(&ThreadObs {
            stack_rc: -ENOMEM,
            clone_rc: -ENOMEM,
            child_tid: 0,
            child_ran: false,
            joined: false,
            ..good_threads()
        });
        assert!(!v.pass);
        assert_eq!(v.rc, -12);
        assert_eq!(v.class(PPC_ENOSYS), Class::Ambiguous);
    }

    #[test]
    fn threads_accept_a_powerpc_stack_address_above_two_gib() {
        let v = judge_threads(&ThreadObs {
            stack_rc: 0xb7f0_0000_u32 as i32 as isize,
            ..good_threads()
        });
        assert!(v.pass);
    }

    // ----- tls
    fn good_tls() -> TlsObs {
        TlsObs {
            set_area_rc: 0,
            clone_rc: 2,
            child_ran: true,
            parent_tp_before: 0x0a0b_0c0d,
            parent_tp_expected: 0x0a0b_0c0d,
            parent_tp_after: 0x0a0b_0c0d,
            child_tp: TLS_MAGIC,
        }
    }

    #[test]
    fn tls_pass_prints_the_magic_the_child_read() {
        let v = judge_tls(&good_tls());
        assert!(v.pass);
        assert_eq!(v.rc, 305_419_896);
        assert_eq!(v.rc, TLS_MAGIC as isize);
    }

    #[test]
    fn tls_each_broken_fact_fails() {
        let base = good_tls();
        let cases = [
            TlsObs {
                child_tp: 0x1234_5679,
                ..base
            },
            TlsObs {
                child_tp: 0,
                ..base
            },
            TlsObs {
                child_ran: false,
                ..base
            },
            TlsObs {
                parent_tp_after: 0x1234_5678,
                ..base
            },
            TlsObs {
                parent_tp_before: 0x1111,
                ..base
            },
            // The child must have its own thread pointer, not the parent's.
            TlsObs {
                parent_tp_before: TLS_MAGIC,
                parent_tp_expected: TLS_MAGIC,
                parent_tp_after: TLS_MAGIC,
                ..base
            },
            TlsObs {
                clone_rc: 0,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_tls(o).pass, "case {n} must not pass");
        }
    }

    #[test]
    fn tls_syscall_absence_is_reported_with_the_syscall_errno() {
        let no_area = judge_tls(&TlsObs {
            set_area_rc: -MIPS_ENOSYS,
            clone_rc: 0,
            child_ran: false,
            child_tp: 0,
            ..good_tls()
        });
        assert!(!no_area.pass);
        assert_eq!(no_area.rc, -89);
        assert_eq!(no_area.class(MIPS_ENOSYS), Class::Unsupported);
        let no_clone = judge_tls(&TlsObs {
            clone_rc: -PPC_ENOSYS,
            child_ran: false,
            child_tp: 0,
            ..good_tls()
        });
        assert_eq!(no_clone.rc, -38);
        assert_eq!(no_clone.class(PPC_ENOSYS), Class::Unsupported);
    }

    // ----- signal
    fn good_signal() -> SignalObs {
        SignalObs {
            act_rc: 0,
            block_rc: 0,
            kill_rc: 0,
            count_while_blocked: 0,
            unblock_rc: 0,
            count_after_unblock: 1,
        }
    }

    #[test]
    fn signal_blocked_then_delivered_exactly_once_passes() {
        assert_eq!(judge_signal(&good_signal()), Verdict { rc: 0, pass: true });
    }

    #[test]
    fn signal_each_deviation_fails() {
        let base = good_signal();
        let cases = [
            SignalObs {
                count_while_blocked: 1,
                ..base
            },
            SignalObs {
                count_after_unblock: 0,
                ..base
            },
            SignalObs {
                count_after_unblock: 2,
                ..base
            },
            SignalObs {
                block_rc: -22,
                ..base
            },
            SignalObs {
                kill_rc: -3,
                ..base
            },
            SignalObs {
                unblock_rc: -22,
                ..base
            },
            SignalObs {
                act_rc: -22,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_signal(o).pass, "case {n} must not pass");
        }
    }

    // ----- eintr read
    fn good_eintr() -> EintrObs {
        EintrObs {
            pipe_rc: 0,
            act_rc: 0,
            timer_rc: 0,
            read_rc: -EINTR,
            handler_count: 2,
            disarm_rc: 0,
        }
    }

    #[test]
    fn eintr_read_prints_the_raw_read_return() {
        let v = judge_eintr_read(&good_eintr());
        assert_eq!(v, Verdict { rc: -4, pass: true });
    }

    #[test]
    fn eintr_read_other_outcomes_fail() {
        let base = good_eintr();
        // A read that returned data, EOF or EAGAIN is not an interrupted read.
        for read_rc in [1, 0, -11, -5] {
            let v = judge_eintr_read(&EintrObs { read_rc, ..base });
            assert!(!v.pass, "read_rc {read_rc}");
            assert_eq!(v.rc, read_rc);
        }
        assert!(
            !judge_eintr_read(&EintrObs {
                handler_count: 0,
                ..base
            })
            .pass
        );
        assert!(
            !judge_eintr_read(&EintrObs {
                disarm_rc: -22,
                ..base
            })
            .pass
        );
    }

    #[test]
    fn eintr_read_setup_failures_are_reported_before_the_read() {
        let base = good_eintr();
        assert_eq!(
            judge_eintr_read(&EintrObs {
                pipe_rc: -24,
                read_rc: 0,
                ..base
            })
            .rc,
            -24
        );
        assert_eq!(
            judge_eintr_read(&EintrObs {
                act_rc: -22,
                read_rc: 0,
                ..base
            })
            .rc,
            -22
        );
        let timer = judge_eintr_read(&EintrObs {
            timer_rc: -PPC_ENOSYS,
            read_rc: 0,
            ..base
        });
        assert_eq!(timer.rc, -38);
        assert_eq!(timer.class(PPC_ENOSYS), Class::Unsupported);
    }

    // ----- timer under repeated signals
    fn good_timer() -> TimerSigObs {
        TimerSigObs {
            act_rc: 0,
            timer_rc: 0,
            final_sleep_rc: 0,
            interrupted_sleeps: 7,
            signals: 8,
            elapsed_ns: 41_000_000,
            disarm_rc: 0,
        }
    }

    #[test]
    fn timer_signals_complete_sleep_despite_interruptions_passes() {
        assert_eq!(
            judge_timer_signals(&good_timer()),
            Verdict { rc: 0, pass: true }
        );
    }

    #[test]
    fn timer_signals_each_deviation_fails() {
        let base = good_timer();
        let cases = [
            // The sleep ended early with the signals still firing.
            TimerSigObs {
                elapsed_ns: 20_000_000,
                ..base
            },
            TimerSigObs {
                elapsed_ns: -1,
                ..base
            },
            TimerSigObs {
                final_sleep_rc: -EINTR,
                ..base
            },
            // Never interrupted: that proves nothing about wakeups under repeated signals.
            TimerSigObs {
                interrupted_sleeps: 1,
                ..base
            },
            TimerSigObs { signals: 2, ..base },
            TimerSigObs {
                disarm_rc: -22,
                ..base
            },
            TimerSigObs {
                timer_rc: -22,
                ..base
            },
            TimerSigObs {
                act_rc: -22,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_timer_signals(o).pass, "case {n} must not pass");
        }
    }

    #[test]
    fn timer_signals_boundary_is_ninety_percent_of_the_sleep() {
        let base = good_timer();
        assert!(
            judge_timer_signals(&TimerSigObs {
                elapsed_ns: 36_000_000,
                ..base
            })
            .pass
        );
        assert!(
            !judge_timer_signals(&TimerSigObs {
                elapsed_ns: 35_999_999,
                ..base
            })
            .pass
        );
    }

    #[test]
    fn timer_enosys_on_setitimer_is_unsupported() {
        let v = judge_timer_signals(&TimerSigObs {
            timer_rc: -MIPS_ENOSYS,
            ..good_timer()
        });
        assert!(!v.pass);
        assert_eq!(v.class(MIPS_ENOSYS), Class::Unsupported);
    }

    // ----- alloc
    fn good_alloc() -> AllocObs {
        AllocObs {
            map_rc: 0x77f0_0000,
            zero_ok: true,
            fill_ok: true,
            huge_rc: -ENOMEM,
            unmap_rc: 0,
            brk_start: 0x1001_2000,
            brk_grown: 0x1001_2000 + BRK_GROW,
            brk_fill_ok: true,
            brk_restored: 0x1001_2000,
        }
    }

    #[test]
    fn alloc_pass_prints_the_munmap_return() {
        assert_eq!(judge_alloc(&good_alloc()), Verdict { rc: 0, pass: true });
    }

    #[test]
    fn alloc_each_broken_fact_fails() {
        let base = good_alloc();
        let cases = [
            AllocObs {
                map_rc: 0x77f0_0010,
                ..base
            },
            AllocObs {
                zero_ok: false,
                ..base
            },
            AllocObs {
                fill_ok: false,
                ..base
            },
            // An oversized mapping must be refused, and with ENOMEM specifically.
            AllocObs {
                huge_rc: 0x1000_0000,
                ..base
            },
            AllocObs {
                huge_rc: -22,
                ..base
            },
            AllocObs {
                unmap_rc: -22,
                ..base
            },
            AllocObs {
                brk_start: 0,
                brk_grown: BRK_GROW,
                brk_restored: 0,
                ..base
            },
            AllocObs {
                brk_grown: 0x1001_2000,
                ..base
            },
            AllocObs {
                brk_fill_ok: false,
                ..base
            },
            AllocObs {
                brk_restored: 0x1001_4000,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_alloc(o).pass, "case {n} must not pass");
        }
    }

    #[test]
    fn alloc_map_failure_reports_its_errno_and_a_high_address_still_passes() {
        let failed = judge_alloc(&AllocObs {
            map_rc: -ENOMEM,
            ..good_alloc()
        });
        assert!(!failed.pass);
        assert_eq!(failed.rc, -12);
        let high = judge_alloc(&AllocObs {
            map_rc: 0xb7f0_0000_u32 as i32 as isize,
            ..good_alloc()
        });
        assert!(high.pass);
    }

    // ----- status parsing and peak memory
    const STATUS: &[u8] = b"Name:\tinit\nUmask:\t0022\nState:\tR (running)\nPid:\t1\n\
VmPeak:\t    1204 kB\nVmSize:\t    1204 kB\nVmLck:\t       0 kB\nVmHWM:\t     312 kB\n\
VmRSS:\t     312 kB\nThreads:\t1\n";

    #[test]
    fn status_values_are_read_by_key() {
        assert_eq!(parse_status_kb(STATUS, b"VmPeak:"), Some(1204));
        assert_eq!(parse_status_kb(STATUS, b"VmHWM:"), Some(312));
        assert_eq!(parse_status_kb(STATUS, b"VmLck:"), Some(0));
    }

    #[test]
    fn status_parser_rejects_malformed_and_lookalike_lines() {
        assert_eq!(parse_status_kb(STATUS, b"VmSwap:"), None);
        assert_eq!(parse_status_kb(b"", b"VmHWM:"), None);
        // The key must start the line.
        assert_eq!(parse_status_kb(b"xVmHWM:\t10 kB\n", b"VmHWM:"), None);
        assert_eq!(parse_status_kb(b"  VmHWM:\t10 kB\n", b"VmHWM:"), None);
        // No digits, a wrong unit, a missing unit and a number that overflows are not values.
        assert_eq!(parse_status_kb(b"VmHWM:\tabc kB\n", b"VmHWM:"), None);
        assert_eq!(parse_status_kb(b"VmHWM:\t10 MB\n", b"VmHWM:"), None);
        assert_eq!(parse_status_kb(b"VmHWM:\t10\n", b"VmHWM:"), None);
        assert_eq!(
            parse_status_kb(b"VmHWM:\t99999999999999999999999 kB\n", b"VmHWM:"),
            None
        );
        // A final line without a newline, and a carriage return, still parse.
        assert_eq!(parse_status_kb(b"VmHWM:\t7 kB", b"VmHWM:"), Some(7));
        assert_eq!(parse_status_kb(b"VmHWM:\t7 kB\r\n", b"VmHWM:"), Some(7));
    }

    fn good_mem() -> MemPeakObs {
        MemPeakObs {
            open_rc: 3,
            read_len: 400,
            vm_peak_kb: Some(1204),
            vm_hwm_kb: Some(312),
        }
    }

    #[test]
    fn mem_peak_prints_the_high_water_mark() {
        assert_eq!(
            judge_mem_peak(&good_mem()),
            Verdict {
                rc: 312,
                pass: true
            }
        );
    }

    #[test]
    fn mem_peak_unavailable_or_inconsistent_is_a_fail_with_the_raw_error() {
        let base = good_mem();
        let no_proc = judge_mem_peak(&MemPeakObs {
            open_rc: -ENOENT,
            read_len: 0,
            vm_peak_kb: None,
            vm_hwm_kb: None,
        });
        assert!(!no_proc.pass);
        assert_eq!(no_proc.rc, -2);
        assert_eq!(no_proc.class(PPC_ENOSYS), Class::Ambiguous);
        let read_error = judge_mem_peak(&MemPeakObs {
            read_len: -5,
            ..base
        });
        assert_eq!((read_error.pass, read_error.rc), (false, -5));
        for o in [
            MemPeakObs {
                vm_hwm_kb: None,
                ..base
            },
            MemPeakObs {
                vm_peak_kb: None,
                ..base
            },
            MemPeakObs {
                vm_hwm_kb: Some(0),
                ..base
            },
            // The peak size cannot be below the resident high-water mark.
            MemPeakObs {
                vm_peak_kb: Some(100),
                ..base
            },
            MemPeakObs {
                read_len: 0,
                ..base
            },
        ] {
            assert!(!judge_mem_peak(&o).pass);
        }
    }

    // ----- atomic width
    #[test]
    fn atomic_width_32_bit_targets_report_32() {
        // Both Sonos SoC families: native atomics up to 32 bits, none at 64.
        let v = judge_atomic_width(&AtomicObs {
            claimed: [true, true, true, false],
            verified: [true, true, true, false],
        });
        assert_eq!(v, Verdict { rc: 32, pass: true });
    }

    #[test]
    fn atomic_width_reports_64_only_when_it_is_claimed_and_works() {
        let v = judge_atomic_width(&AtomicObs {
            claimed: [true; 4],
            verified: [true; 4],
        });
        assert_eq!(v, Verdict { rc: 64, pass: true });
        let broken = judge_atomic_width(&AtomicObs {
            claimed: [true; 4],
            verified: [true, true, true, false],
        });
        assert!(!broken.pass);
        assert_eq!(broken.rc, 32);
    }

    #[test]
    fn atomic_width_failures() {
        // A claimed width that does not work.
        assert!(
            !judge_atomic_width(&AtomicObs {
                claimed: [true, true, true, false],
                verified: [true, false, true, false],
            })
            .pass
        );
        // No 32-bit atomics at all.
        let none = judge_atomic_width(&AtomicObs {
            claimed: [true, true, false, false],
            verified: [true, true, false, false],
        });
        assert!(!none.pass);
        assert_eq!(none.rc, 16);
        // Nothing claimed: nothing observed.
        let nothing = judge_atomic_width(&AtomicObs {
            claimed: [false; 4],
            verified: [false; 4],
        });
        assert_eq!((nothing.pass, nothing.rc), (false, 0));
        // A width that works although the compiler does not claim it is an inconsistent observation.
        assert!(
            !judge_atomic_width(&AtomicObs {
                claimed: [true, true, true, false],
                verified: [true, true, true, true],
            })
            .pass
        );
    }

    // ----- fs
    fn good_fs() -> FsObs {
        FsObs {
            create_a: 3,
            write_a: FS_PAYLOAD_LEN,
            fsync_a: 0,
            create_b: 4,
            write_b: FS_PAYLOAD_LEN,
            rename_rc: 0,
            read_back: FS_PAYLOAD_LEN,
            content_ok: true,
            old_name_rc: -ENOENT,
            cleanup_rc: 0,
        }
    }

    #[test]
    fn fs_rename_over_existing_passes() {
        assert_eq!(judge_fs_rename(&good_fs()), Verdict { rc: 0, pass: true });
    }

    #[test]
    fn fs_a_descriptor_zero_is_a_valid_descriptor() {
        let v = judge_fs_rename(&FsObs {
            create_a: 0,
            create_b: 0,
            ..good_fs()
        });
        assert!(v.pass);
    }

    #[test]
    fn fs_each_broken_fact_fails() {
        let base = good_fs();
        let cases = [
            FsObs { write_a: 8, ..base },
            FsObs {
                fsync_a: -22,
                ..base
            },
            FsObs {
                write_b: -28,
                ..base
            },
            FsObs {
                rename_rc: -18,
                ..base
            },
            FsObs {
                read_back: 8,
                ..base
            },
            // The destination still holds the old payload: the rename did not replace it.
            FsObs {
                content_ok: false,
                ..base
            },
            // The source name survived: not a rename.
            FsObs {
                old_name_rc: 5,
                ..base
            },
            FsObs {
                old_name_rc: -13,
                ..base
            },
            FsObs {
                cleanup_rc: -2,
                ..base
            },
        ];
        for (n, o) in cases.iter().enumerate() {
            assert!(!judge_fs_rename(o).pass, "case {n} must not pass");
        }
    }

    #[test]
    fn fs_reports_the_first_failing_step() {
        let base = good_fs();
        assert_eq!(
            judge_fs_rename(&FsObs {
                create_a: -30,
                ..base
            })
            .rc,
            -30
        );
        assert_eq!(
            judge_fs_rename(&FsObs {
                fsync_a: -22,
                ..base
            })
            .rc,
            -22
        );
        assert_eq!(
            judge_fs_rename(&FsObs {
                create_b: -28,
                ..base
            })
            .rc,
            -28
        );
        assert_eq!(
            judge_fs_rename(&FsObs {
                rename_rc: -18,
                ..base
            })
            .rc,
            -18
        );
    }
}
