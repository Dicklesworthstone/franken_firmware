//! FrankenFirmware bake-off & kernel ABI probe PID-1 binary (`no_std`, no libc).
//!
//! Runs directly against the Linux kernel syscall ABI on 32-bit big-endian
//! MIPS (O32) and 32-bit big-endian PowerPC (SVR4).
//!
//! Covers:
//! - E07 (ffw-ll1): normalized MIPS `$a3` error flag handling, audited PowerPC
//!   volatile register clobbers (`r4`..`r12`, `cr0`, `ctr`, `xer`), `/proc/version`
//!   mount + probe, negative syscall error-path tests (`ENOENT`, `EBADF`, `ENOSYS`),
//!   positive FD + short write verification, and distinct start/success/reboot markers.
//! - E03 (ffw-q2p): per-capability kernel ABI probes (`clock_gettime`/`clock_getres`,
//!   nonblocking `pipe2` + `EAGAIN`, `poll`, `epoll_create`, `socket(AF_INET, SOCK_DGRAM)`,
//!   `/dev/urandom` entropy, and 32-bit atomic compare-exchange/fetch-add).

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]
#![allow(unknown_lints, suspicious_runtime_symbol_definitions)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(target_endian = "big"))]
compile_error!("ffw-hello-init must be compiled for a big-endian target");

#[cfg(not(target_pointer_width = "32"))]
compile_error!("ffw-hello-init targets 32-bit Sonos platforms");

#[cfg(target_arch = "mips")]
mod sys {
    pub const ARCH_NAME: &[u8] = b"mips-be";
    // Linux MIPS O32 syscall numbers (base 4000).
    pub const NR_EXIT: usize = 4001;
    pub const NR_READ: usize = 4003;
    pub const NR_WRITE: usize = 4004;
    pub const NR_OPEN: usize = 4005;
    pub const NR_CLOSE: usize = 4006;
    pub const NR_GETPID: usize = 4020;
    pub const NR_MOUNT: usize = 4021;
    pub const NR_REBOOT: usize = 4088;
    pub const NR_SOCKET: usize = 4183;
    pub const NR_POLL: usize = 4188;
    pub const NR_EPOLL_CREATE: usize = 4248;
    pub const NR_CLOCK_GETTIME: usize = 4263;
    pub const NR_CLOCK_GETRES: usize = 4264;
    pub const NR_PIPE2: usize = 4328;
    pub const NR_INVALID: usize = 4999;

    pub const O_NONBLOCK: usize = 0o200;
    pub const ENOSYS_EXPECTED: isize = 89;
    pub const EAGAIN_EXPECTED: isize = 11;
    pub const SOCK_DGRAM: usize = 1;

    /// Raw Linux MIPS O32 5-argument syscall.
    ///
    /// ABI invariant (`man 2 syscall`):
    /// - `$2` (`v0`) holds syscall number on entry and result/errno on exit.
    /// - `$4`..`$7` (`a0`..`a3`) hold args 0..3; arg 4 is passed at `16($sp)`.
    /// - On exit, `$7` (`a3`) is 0 on success and non-zero on error. When `$7 != 0`,
    ///   `$2` (`v0`) is a positive errno value that MUST be negated.
    #[inline(never)]
    pub unsafe fn sys_raw5(
        nr: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> isize {
        let ret: isize;
        let err: usize;
        unsafe {
            core::arch::asm!(
                ".set push",
                ".set noat",
                "addiu $29, $29, -32",
                "sw $1, 20($29)",
                "sw {a4}, 16($29)",
                "syscall",
                "lw $1, 20($29)",
                "addiu $29, $29, 32",
                ".set pop",
                a4 = in(reg) a4,
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
}

#[cfg(target_arch = "powerpc")]
mod sys {
    pub const ARCH_NAME: &[u8] = b"powerpc-be";
    // Linux PowerPC32 syscall numbers.
    pub const NR_EXIT: usize = 1;
    pub const NR_READ: usize = 3;
    pub const NR_WRITE: usize = 4;
    pub const NR_OPEN: usize = 5;
    pub const NR_CLOSE: usize = 6;
    pub const NR_GETPID: usize = 20;
    pub const NR_MOUNT: usize = 21;
    pub const NR_REBOOT: usize = 88;
    pub const NR_POLL: usize = 167;
    pub const NR_EPOLL_CREATE: usize = 236;
    pub const NR_CLOCK_GETTIME: usize = 246;
    pub const NR_CLOCK_GETRES: usize = 247;
    pub const NR_PIPE2: usize = 317;
    pub const NR_SOCKET: usize = 326;
    pub const NR_INVALID: usize = 999;

    pub const O_NONBLOCK: usize = 0o4000;
    pub const ENOSYS_EXPECTED: isize = 38;
    pub const EAGAIN_EXPECTED: isize = 11;
    pub const SOCK_DGRAM: usize = 2;

    /// Raw Linux PowerPC32 SVR4 5-argument syscall.
    ///
    /// ABI invariant (`man 2 syscall`):
    /// - `r0` holds syscall number; `r3`..`r7` hold args 0..4.
    /// - Kernel `sc` clobbers `r0`, `r3`..`r12`, `cr0`, `ctr`, `xer`.
    ///   All input argument registers `r4`..`r7` MUST be declared `inlateout` so LLVM
    ///   never assumes their values survive across `sc`.
    /// - On error, `cr0.SO` is set and `r3` holds positive `errno`; `bns+ 1f; neg 3, 3`
    ///   normalizes errors to `-errno`.
    #[inline(never)]
    pub unsafe fn sys_raw5(
        nr: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> isize {
        let r3: isize;
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
                lateout("r8") _,
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
}

#[inline(always)]
unsafe fn sys_raw(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> isize {
    unsafe { sys::sys_raw5(nr, a0, a1, a2, a3, 0) }
}

fn sys_write(fd: usize, buf: &[u8]) -> isize {
    unsafe { sys_raw(sys::NR_WRITE, fd, buf.as_ptr() as usize, buf.len(), 0) }
}

fn sys_read(fd: usize, buf: &mut [u8]) -> isize {
    unsafe { sys_raw(sys::NR_READ, fd, buf.as_mut_ptr() as usize, buf.len(), 0) }
}

fn sys_open(path: *const u8, flags: usize, mode: usize) -> isize {
    unsafe { sys_raw(sys::NR_OPEN, path as usize, flags, mode, 0) }
}

fn sys_close(fd: usize) -> isize {
    unsafe { sys_raw(sys::NR_CLOSE, fd, 0, 0, 0) }
}

fn sys_getpid() -> isize {
    unsafe { sys_raw(sys::NR_GETPID, 0, 0, 0, 0) }
}

fn sys_mount(
    src: *const u8,
    target: *const u8,
    fstype: *const u8,
    flags: usize,
    data: usize,
) -> isize {
    unsafe {
        sys::sys_raw5(
            sys::NR_MOUNT,
            src as usize,
            target as usize,
            fstype as usize,
            flags,
            data,
        )
    }
}

fn sys_reboot_halt() -> isize {
    // LINUX_REBOOT_MAGIC1 = 0xfee1dead, MAGIC2 = 672274793 (0x28121969),
    // LINUX_REBOOT_CMD_RESTART = 0x01234567 (exits QEMU with -no-reboot).
    unsafe { sys_raw(sys::NR_REBOOT, 0xfee1_dead, 0x2812_1969, 0x0123_4567, 0) }
}

fn sys_exit(code: usize) -> ! {
    unsafe {
        let _ = sys_raw(sys::NR_EXIT, code, 0, 0, 0);
        core::hint::unreachable_unchecked();
    }
}

#[repr(C)]
struct Timespec32 {
    tv_sec: i32,
    tv_nsec: i32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

struct LineWriter {
    buf: [u8; 256],
    pos: usize,
}

impl LineWriter {
    const fn new() -> Self {
        Self {
            buf: [0u8; 256],
            pos: 0,
        }
    }

    fn push(&mut self, s: &[u8]) {
        for &b in s {
            if self.pos < self.buf.len() {
                self.buf[self.pos] = b;
                self.pos += 1;
            }
        }
    }

    fn push_usize(&mut self, mut v: usize) {
        if v == 0 {
            self.push(b"0");
            return;
        }
        let mut tmp = [0u8; 20];
        let mut idx = 0;
        while v > 0 {
            tmp[idx] = b'0' + (v % 10) as u8;
            v /= 10;
            idx += 1;
        }
        while idx > 0 {
            idx -= 1;
            self.push(&tmp[idx..=idx]);
        }
    }

    fn push_isize(&mut self, v: isize) {
        if v < 0 {
            self.push(b"-");
            self.push_usize((-v) as usize);
        } else {
            self.push_usize(v as usize);
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

fn emit_console(console_fd: usize, msg: &[u8]) {
    let written = sys_write(console_fd, msg);
    if written < 0 && console_fd != 1 {
        let _ = sys_write(1, msg);
    }
    // syslog(2) action 3 reads kernel messages INTO its buffer. It must never
    // be used as an output fallback with a pointer derived from shared &[u8].
}

fn open_console_fd() -> usize {
    const O_WRONLY: usize = 0o0001;
    for path in [
        b"/dev/console\0".as_slice(),
        b"/dev/ttyS0\0".as_slice(),
        b"/dev/ttyPZ0\0".as_slice(),
    ] {
        let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
        if fd >= 0 {
            return fd as usize;
        }
    }
    1
}

fn mount_and_echo_proc_version(console_fd: usize) -> bool {
    let _ = sys_mount(
        c"proc".as_ptr().cast::<u8>(),
        c"/proc".as_ptr().cast::<u8>(),
        c"proc".as_ptr().cast::<u8>(),
        0,
        0,
    );
    let fd = sys_open(c"/proc/version".as_ptr().cast::<u8>(), 0, 0);
    if fd < 0 {
        let mut w = LineWriter::new();
        w.push(b"FFW_KERNEL_VERSION_ERR errno=");
        w.push_isize(-fd);
        w.push(b"\n");
        emit_console(console_fd, w.as_slice());
        return false;
    }
    let mut vbuf = [0u8; 180];
    let n = sys_read(fd as usize, &mut vbuf);
    let _ = sys_close(fd as usize);
    if n <= 0 {
        return false;
    }
    let mut len = n as usize;
    while len > 0 && (vbuf[len - 1] == b'\n' || vbuf[len - 1] == b'\r') {
        len -= 1;
    }
    let mut w = LineWriter::new();
    w.push(b"FFW_KERNEL_VERSION: ");
    w.push(&vbuf[..len]);
    w.push(b"\n");
    emit_console(console_fd, w.as_slice());
    true
}

fn emit_test_result(
    console_fd: usize,
    prefix: &[u8],
    name: &[u8],
    pass: bool,
    detail_key: &[u8],
    detail_val: isize,
) -> bool {
    let mut w = LineWriter::new();
    w.push(prefix);
    w.push(b":");
    w.push(name);
    w.push(if pass {
        b" status=PASS "
    } else {
        b" status=FAIL "
    });
    w.push(detail_key);
    w.push(b"=");
    w.push_isize(detail_val);
    w.push(b"\n");
    emit_console(console_fd, w.as_slice());
    pass
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let console_fd = open_console_fd();

    emit_console(console_fd, b"FFW_MARKER:USERSPACE_START\n");

    // Endianness self-check: 0x01020304 in memory must start with 0x01 on big-endian.
    let word: u32 = 0x0102_0304;
    let first_byte = unsafe { *(&word as *const u32 as *const u8) };
    let pid = sys_getpid();

    let mut banner = LineWriter::new();
    banner.push(b"FFW_HELLO arch=");
    banner.push(sys::ARCH_NAME);
    banner.push(if first_byte == 0x01 {
        b" endian=0x01020304"
    } else {
        b" endian=WRONG"
    });
    banner.push(b" pid=");
    banner.push_isize(pid);
    banner.push(b" ptr_bits=32\n");
    emit_console(console_fd, banner.as_slice());

    let mut failures: usize = 0;
    if first_byte != 0x01 || pid != 1 {
        failures += 1;
    }

    if !mount_and_echo_proc_version(console_fd) {
        failures += 1;
    }

    // --- E07 Negative Syscall Error-Path Tests ---
    // 1. Nonexistent path -> ENOENT (-2)
    let r_enoent = sys_open(c"/nonexistent_ffw_entry".as_ptr().cast::<u8>(), 0, 0);
    if !emit_test_result(
        console_fd,
        b"FFW_TEST",
        b"ERR_ENOENT",
        r_enoent == -2,
        b"errno",
        -r_enoent,
    ) {
        failures += 1;
    }

    // 2. Invalid FD write -> EBADF (-9)
    let r_ebadf = sys_write(999, b"x");
    if !emit_test_result(
        console_fd,
        b"FFW_TEST",
        b"ERR_EBADF",
        r_ebadf == -9,
        b"errno",
        -r_ebadf,
    ) {
        failures += 1;
    }

    // 3. Invalid syscall -> ENOSYS (-89 on MIPS, -38 on PowerPC)
    let r_enosys = unsafe { sys_raw(sys::NR_INVALID, 0, 0, 0, 0) };
    if !emit_test_result(
        console_fd,
        b"FFW_TEST",
        b"ERR_ENOSYS",
        r_enosys == -sys::ENOSYS_EXPECTED,
        b"errno",
        -r_enosys,
    ) {
        failures += 1;
    }

    // 4. Positive FD + bounded short write on /dev/null
    let null_fd = sys_open(c"/dev/null".as_ptr().cast::<u8>(), 0o0001, 0);
    let short_ok = if null_fd > 0 {
        let payload = b"FFW_SHORT_WRITE_PAYLOAD";
        let nw = sys_write(null_fd as usize, &payload[..4]);
        let _ = sys_close(null_fd as usize);
        nw == 4
    } else {
        false
    };
    if !emit_test_result(
        console_fd,
        b"FFW_TEST",
        b"POS_FD_SHORT_WRITE",
        short_ok,
        b"fd",
        null_fd,
    ) {
        failures += 1;
    }

    // --- E03 Legacy Kernel ABI Capability Probes ---
    // Probe 1: CLOCK_MONOTONIC (id = 1) availability and resolution
    let mut ts1 = Timespec32 {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut ts2 = Timespec32 {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut res = Timespec32 {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r_clk1 = unsafe {
        sys_raw(
            sys::NR_CLOCK_GETTIME,
            1,
            &mut ts1 as *mut Timespec32 as usize,
            0,
            0,
        )
    };
    let r_clk2 = unsafe {
        sys_raw(
            sys::NR_CLOCK_GETTIME,
            1,
            &mut ts2 as *mut Timespec32 as usize,
            0,
            0,
        )
    };
    let r_res = unsafe {
        sys_raw(
            sys::NR_CLOCK_GETRES,
            1,
            &mut res as *mut Timespec32 as usize,
            0,
            0,
        )
    };
    let mono_ok = r_clk1 == 0
        && r_clk2 == 0
        && r_res == 0
        && (ts2.tv_sec > ts1.tv_sec || (ts2.tv_sec == ts1.tv_sec && ts2.tv_nsec >= ts1.tv_nsec))
        && (res.tv_sec >= 0 && res.tv_nsec > 0);
    if !emit_test_result(
        console_fd,
        b"FFW_PROBE",
        b"CLOCK_MONOTONIC",
        mono_ok,
        b"res_ns",
        res.tv_nsec as isize,
    ) {
        failures += 1;
    }

    // Probe 2: Nonblocking pipe2 + partial I/O + EAGAIN on empty read
    let mut pipefds = [-1i32; 2];
    let r_pipe = unsafe {
        sys_raw(
            sys::NR_PIPE2,
            pipefds.as_mut_ptr() as usize,
            sys::O_NONBLOCK,
            0,
            0,
        )
    };
    let mut pipe_ok = false;
    let mut poll_ok = false;
    if r_pipe == 0 && pipefds[0] > 0 && pipefds[1] > 0 {
        let rfd = pipefds[0] as usize;
        let wfd = pipefds[1] as usize;
        let mut rbuf = [0u8; 8];
        let empty_rd = sys_read(rfd, &mut rbuf);
        let nw = sys_write(wfd, b"ABCD");
        // Probe 3: poll readiness on readable pipe
        let mut pfd = PollFd {
            fd: pipefds[0],
            events: 1, // POLLIN
            revents: 0,
        };
        let r_poll = unsafe { sys_raw(sys::NR_POLL, &mut pfd as *mut PollFd as usize, 1, 0, 0) };
        poll_ok = r_poll == 1 && (pfd.revents & 1) != 0;

        let nr = sys_read(rfd, &mut rbuf);
        pipe_ok = empty_rd == -sys::EAGAIN_EXPECTED && nw == 4 && nr == 4 && &rbuf[..4] == b"ABCD";
        let _ = sys_close(rfd);
        let _ = sys_close(wfd);
    }
    if !emit_test_result(
        console_fd,
        b"FFW_PROBE",
        b"NONBLOCK_PIPE",
        pipe_ok,
        b"rc",
        r_pipe,
    ) {
        failures += 1;
    }
    if !emit_test_result(
        console_fd,
        b"FFW_PROBE",
        b"POLL",
        poll_ok,
        b"rc",
        if poll_ok { 1 } else { 0 },
    ) {
        failures += 1;
    }

    // Probe 4: epoll_create
    let epfd = unsafe { sys_raw(sys::NR_EPOLL_CREATE, 1, 0, 0, 0) };
    let epoll_ok = epfd > 0;
    if epoll_ok {
        let _ = sys_close(epfd as usize);
    }
    if !emit_test_result(console_fd, b"FFW_PROBE", b"EPOLL", epoll_ok, b"fd", epfd) {
        failures += 1;
    }

    // Probe 5: UDP socket creation (AF_INET = 2)
    let sockfd = unsafe { sys_raw(sys::NR_SOCKET, 2, sys::SOCK_DGRAM, 0, 0) };
    let sock_ok = sockfd > 0;
    if sock_ok {
        let _ = sys_close(sockfd as usize);
    }
    if !emit_test_result(
        console_fd,
        b"FFW_PROBE",
        b"SOCKET_UDP",
        sock_ok,
        b"fd",
        sockfd,
    ) {
        failures += 1;
    }

    // Probe 6: /dev/urandom entropy
    let ufd = sys_open(c"/dev/urandom".as_ptr().cast::<u8>(), 0, 0);
    let mut ent_ok = false;
    if ufd > 0 {
        let mut ebuf = [0u8; 16];
        let nr = sys_read(ufd as usize, &mut ebuf);
        let _ = sys_close(ufd as usize);
        let mut nonzero = 0usize;
        for &b in &ebuf {
            if b != 0 {
                nonzero += 1;
            }
        }
        ent_ok = nr == 16 && nonzero > 0;
    }
    if !emit_test_result(console_fd, b"FFW_PROBE", b"ENTROPY", ent_ok, b"fd", ufd) {
        failures += 1;
    }

    // Probe 7: 32-bit atomic operations
    static ATOMIC_CELL: AtomicUsize = AtomicUsize::new(0x1357_2468);
    let prev = ATOMIC_CELL.fetch_add(0x1111_1111, Ordering::SeqCst);
    let cas_ok = ATOMIC_CELL
        .compare_exchange(0x2468_3579, 0xCAFE_BABE, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    let atom_ok =
        prev == 0x1357_2468 && cas_ok && ATOMIC_CELL.load(Ordering::SeqCst) == 0xCAFE_BABE;
    if !emit_test_result(
        console_fd,
        b"FFW_PROBE",
        b"ATOMICS_32",
        atom_ok,
        b"ok",
        if atom_ok { 1 } else { 0 },
    ) {
        failures += 1;
    }

    if failures == 0 {
        emit_console(console_fd, b"FFW_MARKER:TEST_SUCCESS failures=0\n");
    } else {
        let mut fw = LineWriter::new();
        fw.push(b"FFW_MARKER:TEST_FAILURE failures=");
        fw.push_usize(failures);
        fw.push(b"\n");
        emit_console(console_fd, fw.as_slice());
    }

    emit_console(console_fd, b"FFW_MARKER:REBOOT_REQUEST\n");
    let _ = sys_reboot_halt();
    sys_exit(failures);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = sys_write(1, b"FFW_PANIC\n");
    sys_exit(101)
}

/// # Safety
/// `dest` must be writable for `n` bytes without conflicting access during
/// the call, as required by the C memset contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0usize;
    let byte = c as u8;
    while i < n {
        unsafe { core::ptr::write_volatile(dest.add(i), byte) };
        i += 1;
    }
    dest
}

/// # Safety
/// `src` must be readable and `dest` writable for `n` bytes. The regions
/// must not overlap; callers must prevent conflicting concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0usize;
    while i < n {
        unsafe {
            let b = core::ptr::read_volatile(src.add(i));
            core::ptr::write_volatile(dest.add(i), b);
        }
        i += 1;
    }
    dest
}
