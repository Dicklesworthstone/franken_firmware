//! Real-syscall E03 guest probes, second batch (ffw-q2p): threads and TLS (BLK-003), signal delivery,
//! timers under repeated signals, EINTR, allocator-relevant kernel behavior, peak memory and the atomic
//! width (BLK-004), and fs sync plus rename-over-existing (BLK-006).
//!
//! Declared from `main.rs` (`mod e03_probes_rt;`), so it reaches the audited syscall trampoline and the
//! console writer through `super::`. Every probe issues the real syscalls and records the raw returns;
//! the pass/fail decision lives in `ffw_hello_init::e03_judge_rt`, where it has host tests.
//!
//! Line contract (same as `e03_probes`): `FFW_PROBE:<NAME> status=PASS|FAIL <key>=<raw return>`. An exact
//! `-ENOSYS` is a classified capability absence (`Verdict::is_guest_failure` is false for it); any other
//! non-pass is a guest-visible defect.
//!
//! | name            | key  | printed value on PASS                              |
//! |-----------------|------|----------------------------------------------------|
//! | `THREADS`       | tid  | `clone` return in the parent (the child's tid)     |
//! | `TLS`           | tp   | thread pointer the child read (`0x12345678`)       |
//! | `SIGNAL`        | rc   | `rt_sigaction` return (0)                          |
//! | `TIMER_SIGNALS` | rc   | `setitimer` return (0)                             |
//! | `EINTR_READ`    | rc   | the interrupted `read` return (-4)                 |
//! | `ALLOC`         | rc   | `munmap` return (0)                                |
//! | `MEM_PEAK`      | kb   | `VmHWM` from `/proc/self/status`                   |
//! | `ATOMIC_WIDTH`  | bits | widest native atomic width verified (32)           |
//! | `FS_RENAME`     | rc   | `rename` return over an existing file (0)          |
//!
//! "Shutdown" in the BLK-004 sense is the signal an init receives to begin an orderly shutdown
//! (SIGTERM), exercised by `SIGNAL`; the guest's final `reboot(2)` is already proven by its marker.
//!
//! Bounds: nothing here can block PID 1 indefinitely. Sleeps and futex waits carry timeouts, the
//! blocking `read` is interrupted by a periodic timer that keeps firing until the read returns, and the
//! thread join gives up after about two seconds. Worst case for the whole module is a few seconds.
//!
//! Handlers installed for SIGTERM and SIGALRM are left in place on purpose: PID 1 discards signals whose
//! disposition is the default, but a late periodic SIGALRM with the default action must never be the
//! thing that decides the outcome.
//!
//! The only code here that can wedge or kill PID 1 is the thread probe (a hand-written `clone`
//! trampoline that has never run). `run_threads` is separate from `run_core` so the integrator can stage it.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use ffw_hello_init::e03_judge::Verdict;
use ffw_hello_init::e03_judge_rt as judge;

use super::{emit_test_result, sys, sys_close, sys_open, sys_raw, sys_read, sys_write, Timespec32};

/// Per-ABI syscall numbers, signal-mask `how` values, mmap flag and open flag, from the libc crate's
/// `linux/{gnu,musl}/b32` tables (libc 0.2.191). MIPS o32 is 4000-based; PowerPC32 uses the generic
/// numbering. The MIPS signal numbers 1..15 match the generic ones; `SIG_*` and `MAP_ANONYMOUS` do not.
#[cfg(target_arch = "mips")]
mod nr {
    pub const GETTID: usize = 4222;
    pub const FUTEX: usize = 4238;
    pub const SET_THREAD_AREA: usize = 4283;
    pub const RT_SIGACTION: usize = 4194;
    pub const RT_SIGPROCMASK: usize = 4195;
    pub const TKILL: usize = 4236;
    pub const MMAP2: usize = 4210;
    pub const MUNMAP: usize = 4091;
    pub const BRK: usize = 4045;
    pub const FSYNC: usize = 4118;
    pub const RENAME: usize = 4038;
    pub const UNLINK: usize = 4010;
    pub const SETITIMER: usize = 4104;
    pub const NANOSLEEP: usize = 4166;

    pub const SIG_BLOCK: usize = 1;
    pub const SIG_UNBLOCK: usize = 2;
    /// `sizeof(sigset_t)` in the kernel: `_NSIG` is 128 on MIPS.
    pub const SIGSETSIZE: usize = 16;
    pub const MAP_ANONYMOUS: usize = 0x800;
    pub const O_CREAT: usize = 0o400;
}

#[cfg(target_arch = "powerpc")]
mod nr {
    pub const GETTID: usize = 207;
    pub const FUTEX: usize = 221;
    pub const RT_SIGACTION: usize = 173;
    pub const RT_SIGPROCMASK: usize = 174;
    pub const TKILL: usize = 208;
    pub const MMAP2: usize = 192;
    pub const MUNMAP: usize = 91;
    pub const BRK: usize = 45;
    pub const FSYNC: usize = 118;
    pub const RENAME: usize = 38;
    pub const UNLINK: usize = 10;
    pub const SETITIMER: usize = 104;
    pub const NANOSLEEP: usize = 162;

    pub const SIG_BLOCK: usize = 0;
    pub const SIG_UNBLOCK: usize = 1;
    /// `sizeof(sigset_t)` in the kernel: `_NSIG` is 64 on PowerPC32.
    pub const SIGSETSIZE: usize = 8;
    pub const MAP_ANONYMOUS: usize = 0x20;
    pub const O_CREAT: usize = 0o100;
}

const CLOCK_MONOTONIC: usize = 1;
const SIGALRM: usize = 14;
const SIGTERM: usize = 15;
const PROT_READ_WRITE: usize = 3;
const MAP_PRIVATE: usize = 2;
const O_WRONLY: usize = 1;
const O_TRUNC: usize = 0o1000;
/// Plain (shared) futex operations, as in `e03_probes`: the kernel's `CLONE_CHILD_CLEARTID` wake at
/// thread exit uses the shared key, so a private wait would never be woken by it.
const FUTEX_WAIT: usize = 0;

/// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
/// CLONE_CHILD_CLEARTID`: a pthread-style thread whose exit clears (and wakes) a tid word, which is how
/// the parent knows the child can no longer touch its stack.
const CLONE_FLAGS: u32 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x20_0000;
const STACK_LEN: usize = 4 * judge::PAGE;
const JOIN_ROUNDS: usize = 40;
const JOIN_WAIT_NS: i32 = 50_000_000;
const TIMER_TICK_US: i32 = 5_000;
const EINTR_TICK_US: i32 = 10_000;
const TIMER_MAX_SLEEPS: usize = 64;
const STATUS_BUF: usize = 4096;
const PAYLOAD_A: &[u8; 16] = b"ffw-fs-payload-A";
const PAYLOAD_B: &[u8; 16] = b"ffw-fs-payload-B";

/// Kernel `struct sigaction` for `rt_sigaction`. The layouts differ per ABI. The trailing padding only
/// over-allocates, so a kernel that copies a slightly larger struct never reads past this one.
#[cfg(target_arch = "mips")]
#[repr(C)]
struct KSigaction {
    sa_flags: u32,
    sa_handler: usize,
    sa_mask: [u32; 4],
    _pad: [u32; 2],
}

#[cfg(target_arch = "powerpc")]
#[repr(C)]
struct KSigaction {
    sa_handler: usize,
    sa_flags: u32,
    sa_restorer: usize,
    sa_mask: [u32; 2],
    _pad: [u32; 2],
}

impl KSigaction {
    /// No `SA_RESTART` (an interrupted blocking call must report `-EINTR`) and no restorer: both
    /// kernels return through their vDSO (or their own stack) trampoline.
    #[cfg(target_arch = "mips")]
    fn with_handler(handler: usize) -> Self {
        Self {
            sa_flags: 0,
            sa_handler: handler,
            sa_mask: [0; 4],
            _pad: [0; 2],
        }
    }

    #[cfg(target_arch = "powerpc")]
    fn with_handler(handler: usize) -> Self {
        Self {
            sa_handler: handler,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: [0; 2],
            _pad: [0; 2],
        }
    }
}

/// `struct itimerval` with the 32-bit `time_t` / `suseconds_t` of the legacy 32-bit ABI.
#[repr(C)]
struct ITimerVal {
    interval_sec: i32,
    interval_usec: i32,
    value_sec: i32,
    value_usec: i32,
}

fn sc(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    // SAFETY: a raw Linux syscall through the per-architecture trampoline in `main.rs`. Every pointer
    // argument passed by the callers in this file refers to a live, correctly sized stack object,
    // static or mapping that outlives the call; the kernel validates the rest.
    unsafe { sys_raw(nr, a0, a1, a2, a3) }
}

/// Six-argument syscall (`mmap2`). `main.rs` only has the five-argument form, whose sixth slot is stack
/// garbage on MIPS and a clobbered `r8` on PowerPC; a garbage `pgoff` could turn into `-EOVERFLOW`.
#[cfg(target_arch = "mips")]
#[inline(never)]
fn sc6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    let err: usize;
    // SAFETY: same contract as `sys::sys_raw5` (O32: arguments 5 and 6 go at 16($sp) and 20($sp), `$7`
    // returns the error flag). The 32 bytes are allocated below the live frame before being written and
    // released straight after the syscall.
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set noat",
            "addiu $29, $29, -32",
            "sw {a4}, 16($29)",
            "sw {a5}, 20($29)",
            "syscall",
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

// `clone` trampoline. The child starts on a stack the parent chose, so it cannot return into the Rust
// frame that called `clone`; this routine runs `entry(arg)` on the new stack and then exits the thread.
//
//     isize ffw_clone_thread(void (*entry)(usize), usize arg, usize stack_top, usize tls, usize ctid)
//
// The kernel sees (flags, new_sp, ptid = 0, tls, ctid) on both ABIs. The new stack gets 32 bytes: a
// 16-byte argument home area for the callee, then `entry` and `arg`, which the child loads back. A
// parent gets the tid, or `-errno`; the child never returns.
#[cfg(target_arch = "mips")]
core::arch::global_asm!(
    ".text",
    ".set push",
    ".set noreorder",
    ".set noat",
    ".globl ffw_clone_thread",
    ".type ffw_clone_thread, @function",
    ".align 2",
    "ffw_clone_thread:",
    // a0 = entry, a1 = arg, a2 = stack_top, a3 = tls, 16($sp) = ctid (already where clone reads it)
    "addiu $8, $0, -16",
    "and $6, $6, $8",
    "addiu $6, $6, -32",
    "sw $4, 16($6)",
    "sw $5, 20($6)",
    "move $5, $6",
    "lui $4, {hi}",
    "ori $4, $4, {lo}",
    "move $6, $0",
    "li $2, 4120",
    "syscall",
    "beqz $7, 1f",
    "nop",
    "jr $31",
    "subu $2, $0, $2",
    "1:",
    "bnez $2, 2f",
    "nop",
    // child: $sp is the new stack
    "lw $25, 16($29)",
    "lw $4, 20($29)",
    "jalr $25",
    "nop",
    "li $2, 4001",
    "move $4, $0",
    "syscall",
    "2:",
    "jr $31",
    "nop",
    ".size ffw_clone_thread, .-ffw_clone_thread",
    ".set pop",
    hi = const (CLONE_FLAGS >> 16),
    lo = const (CLONE_FLAGS & 0xFFFF),
);

#[cfg(target_arch = "powerpc")]
core::arch::global_asm!(
    ".text",
    ".globl ffw_clone_thread",
    ".type ffw_clone_thread, @function",
    ".align 2",
    "ffw_clone_thread:",
    // r3 = entry, r4 = arg, r5 = stack_top, r6 = tls, r7 = ctid
    "clrrwi 5, 5, 4",
    "addi 5, 5, -32",
    "li 0, 0",
    "stw 0, 0(5)",
    "stw 3, 8(5)",
    "stw 4, 12(5)",
    "lis 3, {hi}",
    "ori 3, 3, {lo}",
    "mr 4, 5",
    "li 5, 0",
    "li 0, 120",
    "sc",
    "bso 2f",
    "cmpwi 3, 0",
    "bnelr",
    // child: r1 is the new stack, r2 the TLS pointer
    "lwz 0, 8(1)",
    "lwz 3, 12(1)",
    "mtctr 0",
    "bctrl",
    "li 0, 1",
    "li 3, 0",
    "sc",
    "2:",
    "neg 3, 3",
    "blr",
    ".size ffw_clone_thread, .-ffw_clone_thread",
    hi = const (CLONE_FLAGS >> 16),
    lo = const (CLONE_FLAGS & 0xFFFF),
);

extern "C" {
    fn ffw_clone_thread(
        entry: extern "C" fn(usize),
        arg: usize,
        stack_top: usize,
        tls: usize,
        ctid: usize,
    ) -> isize;
}

/// The thread pointer of the calling thread: `rdhwr $29` (UserLocal, emulated by the kernel on cores
/// without it) on MIPS, `r2` on PowerPC32.
#[cfg(target_arch = "mips")]
fn read_thread_pointer() -> usize {
    let tp: usize;
    // SAFETY: RDHWR $29 only reads the UserLocal register; no memory or flags are touched.
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set mips32r2",
            "rdhwr {0}, $29",
            ".set pop",
            out(reg) tp,
            options(nomem, nostack, preserves_flags),
        );
    }
    tp
}

#[cfg(target_arch = "powerpc")]
fn read_thread_pointer() -> usize {
    let tp: usize;
    // SAFETY: a register-to-register move out of r2, which this freestanding binary never uses itself.
    unsafe {
        core::arch::asm!(
            "mr {0}, 2",
            out(reg) tp,
            options(nomem, nostack, preserves_flags),
        );
    }
    tp
}

/// MIPS: set the thread area through the real syscall and report its raw return. PowerPC has no such
/// syscall (the thread pointer is a register), so there is nothing to call and the result is 0.
#[cfg(target_arch = "mips")]
fn set_thread_area(value: usize) -> isize {
    sc(nr::SET_THREAD_AREA, value, 0, 0, 0)
}

#[cfg(target_arch = "powerpc")]
fn set_thread_area(_value: usize) -> isize {
    0
}

/// A value for the parent's thread pointer: MIPS sets it explicitly (and reads it back); PowerPC keeps
/// whatever `r2` already holds, which the probe only compares before and after.
#[cfg(target_arch = "mips")]
const PARENT_TP: usize = 0x0a0b_0c0d;
#[cfg(target_arch = "powerpc")]
const PARENT_TP: usize = 0;

/// A bounded sleep: `poll(NULL, 0, ms)`. An interruption only shortens it.
fn sleep_ms(ms: usize) {
    let _ = sc(sys::NR_POLL, 0, 0, ms, 0);
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
        Some(i64::from(ts.tv_sec) * 1_000_000_000 + i64::from(ts.tv_nsec))
    } else {
        None
    }
}

fn gettid() -> isize {
    sc(nr::GETTID, 0, 0, 0, 0)
}

fn mmap_anon(len: usize) -> isize {
    // fd = -1, pgoff = 0.
    sc6(
        nr::MMAP2,
        0,
        len,
        PROT_READ_WRITE,
        MAP_PRIVATE | nr::MAP_ANONYMOUS,
        usize::MAX,
        0,
    )
}

fn munmap(addr: usize, len: usize) -> isize {
    sc(nr::MUNMAP, addr, len, 0, 0)
}

// --------------------------------------------------------------------------- signals and timers

/// Handler runs since the last reset; the handler touches nothing else.
static SIG_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_sig: i32) {
    SIG_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_handler(sig: usize) -> isize {
    let act = KSigaction::with_handler(on_signal as extern "C" fn(i32) as usize);
    sc(
        nr::RT_SIGACTION,
        sig,
        &act as *const KSigaction as usize,
        0,
        nr::SIGSETSIZE,
    )
}

/// `rt_sigprocmask(how, {sig}, NULL)`. Signals 1..32 live in the first word on both ABIs.
fn sigprocmask(how: usize, sig: usize) -> isize {
    let mut set = [0u32; 4];
    set[0] = 1u32 << (sig - 1);
    sc(
        nr::RT_SIGPROCMASK,
        how,
        set.as_ptr() as usize,
        0,
        nr::SIGSETSIZE,
    )
}

fn setitimer_real(interval_us: i32, first_us: i32) -> isize {
    let v = ITimerVal {
        interval_sec: 0,
        interval_usec: interval_us,
        value_sec: 0,
        value_usec: first_us,
    };
    // ITIMER_REAL is 0.
    sc(nr::SETITIMER, 0, &v as *const ITimerVal as usize, 0, 0)
}

fn probe_signal() -> Verdict {
    SIG_COUNT.store(0, Ordering::SeqCst);
    let act_rc = install_handler(SIGTERM);
    let block_rc = sigprocmask(nr::SIG_BLOCK, SIGTERM);
    let mut kill_rc = -1;
    let mut count_while_blocked = 0;
    let mut unblock_rc = -1;
    let mut count_after_unblock = 0;
    // Only send the signal once a handler is installed and the signal is blocked: PID 1 would discard
    // a default-action SIGTERM, but a delivery that was not blocked would hide what is being measured.
    if act_rc == 0 && block_rc == 0 {
        kill_rc = sc(nr::TKILL, gettid() as usize, SIGTERM, 0, 0);
        count_while_blocked = SIG_COUNT.load(Ordering::SeqCst);
        // A pending, unblocked signal is delivered before this syscall returns to user mode.
        unblock_rc = sigprocmask(nr::SIG_UNBLOCK, SIGTERM);
        count_after_unblock = SIG_COUNT.load(Ordering::SeqCst);
    } else {
        let _ = sigprocmask(nr::SIG_UNBLOCK, SIGTERM);
    }
    judge::judge_signal(&judge::SignalObs {
        act_rc,
        block_rc,
        kill_rc,
        count_while_blocked,
        unblock_rc,
        count_after_unblock,
    })
}

fn probe_timer_signals() -> Verdict {
    SIG_COUNT.store(0, Ordering::SeqCst);
    let act_rc = install_handler(SIGALRM);
    let _ = sigprocmask(nr::SIG_UNBLOCK, SIGALRM);
    let mut timer_rc = -1;
    let mut final_sleep_rc = -1;
    let mut interrupted_sleeps = 0;
    let mut elapsed_ns = -1;
    let mut disarm_rc = -1;
    if act_rc == 0 {
        let start = mono_ns();
        timer_rc = setitimer_real(TIMER_TICK_US, TIMER_TICK_US);
        if timer_rc == 0 {
            let mut req = Timespec32 {
                tv_sec: 0,
                tv_nsec: judge::TIMER_SLEEP_NS as i32,
            };
            let mut rem = Timespec32 {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // Resume with the reported remainder every time a signal cuts the sleep short.
            for _ in 0..TIMER_MAX_SLEEPS {
                final_sleep_rc = sc(
                    nr::NANOSLEEP,
                    &req as *const Timespec32 as usize,
                    &mut rem as *mut Timespec32 as usize,
                    0,
                    0,
                );
                if final_sleep_rc != -judge::EINTR {
                    break;
                }
                interrupted_sleeps += 1;
                req.tv_sec = rem.tv_sec;
                req.tv_nsec = rem.tv_nsec;
            }
        }
        let end = mono_ns();
        disarm_rc = setitimer_real(0, 0);
        if let (Some(a), Some(b)) = (start, end) {
            elapsed_ns = b - a;
        }
    }
    judge::judge_timer_signals(&judge::TimerSigObs {
        act_rc,
        timer_rc,
        final_sleep_rc,
        interrupted_sleeps,
        signals: SIG_COUNT.load(Ordering::SeqCst),
        elapsed_ns,
        disarm_rc,
    })
}

fn probe_eintr_read() -> Verdict {
    SIG_COUNT.store(0, Ordering::SeqCst);
    let mut fds = [-1i32; 2];
    // A blocking pipe with nothing in it: a `read` can only return because a signal interrupted it.
    let pipe_rc = sc(sys::NR_PIPE2, fds.as_mut_ptr() as usize, 0, 0, 0);
    let act_rc = install_handler(SIGALRM);
    let _ = sigprocmask(nr::SIG_UNBLOCK, SIGALRM);
    let mut timer_rc = -1;
    let mut read_rc = 0;
    let mut disarm_rc = -1;
    if pipe_rc == 0 && act_rc == 0 {
        // Periodic, so a tick that lands before the `read` blocks cannot leave the read waiting forever.
        timer_rc = setitimer_real(EINTR_TICK_US, EINTR_TICK_US);
        if timer_rc == 0 {
            let mut buf = [0u8; 1];
            read_rc = sys_read(fds[0] as usize, &mut buf);
            disarm_rc = setitimer_real(0, 0);
        }
    }
    if pipe_rc == 0 {
        let _ = sys_close(fds[0] as usize);
        let _ = sys_close(fds[1] as usize);
    }
    judge::judge_eintr_read(&judge::EintrObs {
        pipe_rc,
        act_rc,
        timer_rc,
        read_rc,
        handler_count: SIG_COUNT.load(Ordering::SeqCst),
        disarm_rc,
    })
}

// --------------------------------------------------------------------------- memory

fn probe_alloc() -> Verdict {
    let len = judge::ALLOC_PAGES * judge::PAGE;
    let map_rc = mmap_anon(len);
    let mut zero_ok = false;
    let mut fill_ok = false;
    let mut unmap_rc = -1;
    if !judge::is_errno(map_rc) {
        let base = map_rc as usize as *mut u8;
        // SAFETY: `base` is a fresh private anonymous mapping of `len` bytes, readable and writable,
        // that nothing else references until it is unmapped below.
        unsafe {
            zero_ok = (0..judge::ALLOC_PAGES)
                .all(|page| core::ptr::read_volatile(base.add(page * judge::PAGE)) == 0);
            for page in 0..judge::ALLOC_PAGES {
                core::ptr::write_volatile(base.add(page * judge::PAGE), 0xA0 + page as u8);
            }
            fill_ok = (0..judge::ALLOC_PAGES).all(|page| {
                core::ptr::read_volatile(base.add(page * judge::PAGE)) == 0xA0 + page as u8
            });
        }
        unmap_rc = munmap(map_rc as usize, len);
    }
    // A request no 32-bit address space can satisfy must be refused with ENOMEM. Should the kernel
    // grant it anyway, give it back so the probe leaves nothing behind.
    let huge_rc = mmap_anon(judge::HUGE_MAP_LEN);
    if !judge::is_errno(huge_rc) {
        let _ = munmap(huge_rc as usize, judge::HUGE_MAP_LEN);
    }
    let brk_start = sc(nr::BRK, 0, 0, 0, 0) as usize;
    let mut brk_grown = 0;
    let mut brk_fill_ok = false;
    let mut brk_restored = 0;
    if brk_start != 0 {
        brk_grown = sc(nr::BRK, brk_start.wrapping_add(judge::BRK_GROW), 0, 0, 0) as usize;
        if brk_grown == brk_start.wrapping_add(judge::BRK_GROW) {
            let heap = brk_start as *mut u8;
            // SAFETY: the break was just extended by `BRK_GROW` bytes, so the range
            // [brk_start, brk_start + BRK_GROW) is mapped read-write and owned by this process.
            unsafe {
                core::ptr::write_volatile(heap, 0x5A);
                core::ptr::write_volatile(heap.add(judge::BRK_GROW - 1), 0xA5);
                brk_fill_ok = core::ptr::read_volatile(heap) == 0x5A
                    && core::ptr::read_volatile(heap.add(judge::BRK_GROW - 1)) == 0xA5;
            }
        }
        brk_restored = sc(nr::BRK, brk_start, 0, 0, 0) as usize;
    }
    judge::judge_alloc(&judge::AllocObs {
        map_rc,
        zero_ok,
        fill_ok,
        huge_rc,
        unmap_rc,
        brk_start,
        brk_grown,
        brk_fill_ok,
        brk_restored,
    })
}

fn probe_mem_peak() -> Verdict {
    let fd = sys_open(c"/proc/self/status".as_ptr().cast::<u8>(), 0, 0);
    if fd < 0 {
        return judge::judge_mem_peak(&judge::MemPeakObs {
            open_rc: fd,
            read_len: 0,
            vm_peak_kb: None,
            vm_hwm_kb: None,
        });
    }
    let mut buf = [0u8; STATUS_BUF];
    let mut len = 0usize;
    let mut read_len: isize = 0;
    // `/proc` files may return short reads; collect until EOF, an error or a full buffer.
    while len < buf.len() {
        let n = sys_read(fd as usize, &mut buf[len..]);
        if n < 0 {
            read_len = n;
            break;
        }
        if n == 0 {
            break;
        }
        len += n as usize;
        read_len = len as isize;
    }
    let _ = sys_close(fd as usize);
    let text = &buf[..len];
    judge::judge_mem_peak(&judge::MemPeakObs {
        open_rc: fd,
        read_len,
        vm_peak_kb: judge::parse_status_kb(text, b"VmPeak:"),
        vm_hwm_kb: judge::parse_status_kb(text, b"VmHWM:"),
    })
}

// --------------------------------------------------------------------------- atomics

#[cfg(target_has_atomic = "8")]
fn exercise_8() -> bool {
    use core::sync::atomic::AtomicU8;
    static CELL: AtomicU8 = AtomicU8::new(0xFE);
    let prev = CELL.fetch_add(1, Ordering::SeqCst);
    let swapped = CELL
        .compare_exchange(0xFF, 0x7E, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    prev == 0xFE && swapped && CELL.load(Ordering::SeqCst) == 0x7E
}
#[cfg(not(target_has_atomic = "8"))]
fn exercise_8() -> bool {
    false
}

#[cfg(target_has_atomic = "16")]
fn exercise_16() -> bool {
    use core::sync::atomic::AtomicU16;
    static CELL: AtomicU16 = AtomicU16::new(0xFFFE);
    let prev = CELL.fetch_add(1, Ordering::SeqCst);
    let swapped = CELL
        .compare_exchange(0xFFFF, 0x7E7E, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    prev == 0xFFFE && swapped && CELL.load(Ordering::SeqCst) == 0x7E7E
}
#[cfg(not(target_has_atomic = "16"))]
fn exercise_16() -> bool {
    false
}

#[cfg(target_has_atomic = "32")]
fn exercise_32() -> bool {
    static CELL: AtomicU32 = AtomicU32::new(0xFFFF_FFFE);
    let prev = CELL.fetch_add(1, Ordering::SeqCst);
    let swapped = CELL
        .compare_exchange(0xFFFF_FFFF, 0x7E7E_7E7E, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    prev == 0xFFFF_FFFE && swapped && CELL.load(Ordering::SeqCst) == 0x7E7E_7E7E
}
#[cfg(not(target_has_atomic = "32"))]
fn exercise_32() -> bool {
    false
}

#[cfg(target_has_atomic = "64")]
fn exercise_64() -> bool {
    use core::sync::atomic::AtomicU64;
    static CELL: AtomicU64 = AtomicU64::new(0xFFFF_FFFF_FFFF_FFFE);
    let prev = CELL.fetch_add(1, Ordering::SeqCst);
    let swapped = CELL
        .compare_exchange(
            0xFFFF_FFFF_FFFF_FFFF,
            0x7E7E_7E7E_7E7E_7E7E,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok();
    prev == 0xFFFF_FFFF_FFFF_FFFE && swapped && CELL.load(Ordering::SeqCst) == 0x7E7E_7E7E_7E7E_7E7E
}
#[cfg(not(target_has_atomic = "64"))]
fn exercise_64() -> bool {
    false
}

/// What the compiler claims for each width, against what a runtime fetch-add and compare-exchange on
/// that width actually does. Both Sonos SoC families report 32; 64-bit atomics are not native there.
fn probe_atomic_width() -> Verdict {
    judge::judge_atomic_width(&judge::AtomicObs {
        claimed: [
            cfg!(target_has_atomic = "8"),
            cfg!(target_has_atomic = "16"),
            cfg!(target_has_atomic = "32"),
            cfg!(target_has_atomic = "64"),
        ],
        verified: [exercise_8(), exercise_16(), exercise_32(), exercise_64()],
    })
}

// --------------------------------------------------------------------------- filesystem

const PATH_A: &core::ffi::CStr = c"/ffw_fs_a.tmp";
const PATH_B: &core::ffi::CStr = c"/ffw_fs_b.tmp";

fn path_ptr(path: &core::ffi::CStr) -> *const u8 {
    path.as_ptr().cast::<u8>()
}

/// Create (or truncate) `path`, write `payload`, optionally `fsync`, close. Returns the raw `open`
/// return, the raw `write` return and the raw `fsync` return (0 when not requested).
fn write_file(path: &core::ffi::CStr, payload: &[u8], sync: bool) -> (isize, isize, isize) {
    let fd = sys_open(path_ptr(path), O_WRONLY | nr::O_CREAT | O_TRUNC, 0o600);
    if fd < 0 {
        return (fd, 0, 0);
    }
    let written = sys_write(fd as usize, payload);
    let synced = if sync {
        sc(nr::FSYNC, fd as usize, 0, 0, 0)
    } else {
        0
    };
    let _ = sys_close(fd as usize);
    (fd, written, synced)
}

fn probe_fs_rename() -> Verdict {
    // Leftovers from an earlier run are ours; anything else at these names is overwritten anyway.
    let _ = sc(nr::UNLINK, path_ptr(PATH_A) as usize, 0, 0, 0);
    let _ = sc(nr::UNLINK, path_ptr(PATH_B) as usize, 0, 0, 0);
    let (create_a, write_a, fsync_a) = write_file(PATH_A, PAYLOAD_A, true);
    let (create_b, write_b, _) = write_file(PATH_B, PAYLOAD_B, false);
    let mut rename_rc = -1;
    let mut read_back = 0;
    let mut content_ok = false;
    let mut old_name_rc = 0;
    let mut cleanup_rc = -1;
    if create_a >= 0 && create_b >= 0 {
        rename_rc = sc(
            nr::RENAME,
            path_ptr(PATH_A) as usize,
            path_ptr(PATH_B) as usize,
            0,
            0,
        );
        // The destination must now hold A's bytes in full, and the old name must be gone.
        let fd = sys_open(path_ptr(PATH_B), 0, 0);
        if fd >= 0 {
            let mut buf = [0u8; 32];
            read_back = sys_read(fd as usize, &mut buf);
            let _ = sys_close(fd as usize);
            content_ok = read_back == judge::FS_PAYLOAD_LEN && buf[..16] == PAYLOAD_A[..];
        } else {
            read_back = fd;
        }
        old_name_rc = sys_open(path_ptr(PATH_A), 0, 0);
        if old_name_rc >= 0 {
            let _ = sys_close(old_name_rc as usize);
        }
        cleanup_rc = sc(nr::UNLINK, path_ptr(PATH_B) as usize, 0, 0, 0);
    }
    // Whatever happened above, leave neither name behind (a failed run must not poison the next).
    let _ = sc(nr::UNLINK, path_ptr(PATH_A) as usize, 0, 0, 0);
    judge::judge_fs_rename(&judge::FsObs {
        create_a,
        write_a,
        fsync_a,
        create_b,
        write_b,
        rename_rc,
        read_back,
        content_ok,
        old_name_rc,
        cleanup_rc,
    })
}

// --------------------------------------------------------------------------- threads and TLS

/// Written by the child, read by the parent after the join. All are plain 32-bit atomics.
static CHILD_RAN: AtomicU32 = AtomicU32::new(0);
static CHILD_TID: AtomicI32 = AtomicI32::new(0);
static CHILD_TP: AtomicUsize = AtomicUsize::new(0);
/// The `CLONE_CHILD_CLEARTID` word: nonzero while the child lives, zeroed (and futex-woken) by the
/// kernel when the child thread exits.
static CTID_WORD: AtomicI32 = AtomicI32::new(0);
const CHILD_MAGIC: u32 = 0xC0DE_F00D;
const CTID_LIVE: i32 = 0x0BAD_CAFE;

/// Runs on the child's own stack, with its own thread pointer. Touches only the statics above.
extern "C" fn thread_entry(_arg: usize) {
    CHILD_TP.store(read_thread_pointer(), Ordering::SeqCst);
    CHILD_TID.store(gettid() as i32, Ordering::SeqCst);
    CHILD_RAN.store(CHILD_MAGIC, Ordering::SeqCst);
}

/// Wait for the kernel to clear `CTID_WORD`. Every wait carries a timeout, and a kernel without
/// futex (`-ENOSYS`) still makes progress through a plain sleep, so this is bounded either way.
fn join_child() -> bool {
    let timeout = Timespec32 {
        tv_sec: 0,
        tv_nsec: JOIN_WAIT_NS,
    };
    let addr = CTID_WORD.as_ptr() as usize;
    for _ in 0..JOIN_ROUNDS {
        let seen = CTID_WORD.load(Ordering::SeqCst);
        if seen == 0 {
            return true;
        }
        let rc = sc(
            nr::FUTEX,
            addr,
            FUTEX_WAIT,
            seen as usize,
            &timeout as *const Timespec32 as usize,
        );
        if rc == -sys::ENOSYS_EXPECTED {
            sleep_ms(10);
        }
    }
    CTID_WORD.load(Ordering::SeqCst) == 0
}

/// One `clone` serves both `THREADS` and `TLS`; returns the two verdicts in that order.
fn probe_threads_and_tls() -> (Verdict, Verdict) {
    CHILD_RAN.store(0, Ordering::SeqCst);
    CHILD_TID.store(0, Ordering::SeqCst);
    CHILD_TP.store(0, Ordering::SeqCst);

    let set_area_rc = set_thread_area(PARENT_TP);
    let parent_tp_before = read_thread_pointer();
    let parent_tp_expected = if cfg!(target_arch = "mips") {
        PARENT_TP
    } else {
        parent_tp_before
    };
    let parent_tid = gettid();

    let stack_rc = mmap_anon(STACK_LEN);
    // A failed stack mapping stops the attempt and its errno is what both lines report. `THREADS` does
    // not depend on `set_thread_area`: `CLONE_SETTLS` sets the child's pointer without it.
    let mut clone_rc = if judge::is_errno(stack_rc) {
        stack_rc
    } else {
        0
    };
    let mut joined = false;
    if !judge::is_errno(stack_rc) {
        CTID_WORD.store(CTID_LIVE, Ordering::SeqCst);
        let stack_top = (stack_rc as usize).wrapping_add(STACK_LEN);
        // SAFETY: `stack_top` is the top of a fresh private mapping of `STACK_LEN` bytes that nothing
        // else uses; `thread_entry` is an `extern "C" fn` that only touches statics; `CTID_WORD` is a
        // static that outlives the child. The trampoline returns the child's tid (or `-errno`) here.
        clone_rc = unsafe {
            ffw_clone_thread(
                thread_entry,
                0,
                stack_top,
                judge::TLS_MAGIC,
                CTID_WORD.as_ptr() as usize,
            )
        };
        if clone_rc > 0 {
            joined = join_child();
        }
    }
    let parent_tp_after = read_thread_pointer();
    // Give the stack back only when no child can be using it: either `clone` never started one, or the
    // kernel has cleared the tid word, which it does once the child can no longer run user code. If the
    // join timed out the child may still be running on it, so the mapping is leaked instead.
    let child_started = clone_rc > 0;
    if !judge::is_errno(stack_rc) && (!child_started || joined) {
        let _ = munmap(stack_rc as usize, STACK_LEN);
    }

    let threads = judge::judge_threads(&judge::ThreadObs {
        stack_rc,
        clone_rc,
        parent_tid,
        child_tid: CHILD_TID.load(Ordering::SeqCst) as isize,
        child_ran: CHILD_RAN.load(Ordering::SeqCst) == CHILD_MAGIC,
        joined,
    });
    let tls = judge::judge_tls(&judge::TlsObs {
        set_area_rc,
        clone_rc,
        child_ran: CHILD_RAN.load(Ordering::SeqCst) == CHILD_MAGIC,
        parent_tp_before,
        parent_tp_expected,
        parent_tp_after,
        child_tp: CHILD_TP.load(Ordering::SeqCst),
    });
    (threads, tls)
}

// --------------------------------------------------------------------------- reporting

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

/// Everything except the thread probes. Each line is printed as soon as its probe finishes, so a hang
/// in a later probe cannot hide an earlier result. Returns how many probes were guest failures.
pub fn run_core(console_fd: usize) -> usize {
    report(console_fd, b"ATOMIC_WIDTH", b"bits", probe_atomic_width())
        + report(console_fd, b"ALLOC", b"rc", probe_alloc())
        + report(console_fd, b"MEM_PEAK", b"kb", probe_mem_peak())
        + report(console_fd, b"FS_RENAME", b"rc", probe_fs_rename())
        + report(console_fd, b"SIGNAL", b"rc", probe_signal())
        + report(console_fd, b"TIMER_SIGNALS", b"rc", probe_timer_signals())
        + report(console_fd, b"EINTR_READ", b"rc", probe_eintr_read())
}

/// `THREADS` and `TLS`: the only probes that start a second thread. Run last.
pub fn run_threads(console_fd: usize) -> usize {
    let (threads, tls) = probe_threads_and_tls();
    report(console_fd, b"THREADS", b"tid", threads) + report(console_fd, b"TLS", b"tp", tls)
}

/// All second-batch probes, threads last.
pub fn run(console_fd: usize) -> usize {
    run_core(console_fd) + run_threads(console_fd)
}
