//! Minimal PID-1 "hello" for the FrankenFirmware toolchain bake-off.
//!
//! Freestanding (`no_std`, no libc): issues raw Linux syscalls so the binary
//! proves endianness, ABI, and codegen for each big-endian target with zero
//! runtime dependencies. Boots as PID 1 from an initramfs under QEMU.
//!
//! What it does:
//! 1. writes a banner + architecture marker to fd 1 (the QEMU serial console)
//! 2. reads /proc/version via open/read syscalls and echoes it
//! 3. reboots the machine cleanly (reboot(RB_AUTOBOOT)) so QEMU exits
//!
//! Everything here is unsafe-by-nature syscall shims, quarantined to this one
//! binary; application crates in the real firmware keep forbid(unsafe_code).

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]
#![feature(asm_experimental_arch)]

use core::arch::asm;
use core::panic::PanicInfo;

/// Linux syscall numbers differ per architecture. Only the ones we need.
/// mips(32, BE) o32 ABI: syscall number in $v0, args $a0..$a3, return $v0;
///   error flag in $a3. powerpc: syscall in r0, args r3..r6, return r3,
///   cr0.SO flags error.
mod sysno {
    // MIPS o32 uses 4000-based numbers; PowerPC uses the generic table.
    #[cfg(target_arch = "mips")]
    pub const BASE: usize = 4000;
    #[cfg(not(target_arch = "mips"))]
    pub const BASE: usize = 0;
    pub const SYS_WRITE: usize = BASE + 4; // o32: 4004; ppc: 4
    pub const SYS_READ: usize = BASE + 3;
    pub const SYS_OPEN: usize = BASE + 5;
    pub const SYS_CLOSE: usize = BASE + 6;
    pub const SYS_REBOOT: usize = BASE + 88;
    pub const SYS_EXIT: usize = BASE + 1;
    pub const SYS_DUP2: usize = BASE + 33;
    pub const RB_AUTOBOOT: usize = 0x0123_4567;
}

#[inline(never)]
unsafe fn sys_raw(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    #[cfg(target_arch = "mips")]
    {
        // o32: nr in $2 (v0); args $4-$6; return $2; error flag $7 (a3).
        // syscall clobbers $1 (at), $2, $7, $8-$15, $24, $25 — the $1/`at`
        // clobber is emitted by the assembler naturally; $8-$15/$24/$25 are
        // declared below.
        let err: usize;
        unsafe {
            asm!(
                "syscall",
                "move $15, $7", /* stash a3 error flag in s7-scratch $15 */
                in("$2") nr,
                lateout("$2") ret,
                out("$15") err,
                in("$4") a0, in("$5") a1, in("$6") a2,
                out("$8") _, out("$9") _, out("$10") _,
                out("$11") _, out("$12") _, out("$13") _, out("$14") _,
                out("$24") _, out("$25") _,
                options(nostack),
            );
        }
        let _ = err; // o32 error flag; negative v0 covers our needs
    }
    #[cfg(target_arch = "powerpc")]
    {
        // PPC: nr in r0 (clobbered by sc); args r3-r5; return in r3;
        // sc clobbers r0, r3-r12, cr0-cr1/cr5-cr7, ctr, xer, lr.
        let ret_u: usize;
        unsafe {
            asm!(
                "sc",
                inout("0") nr => _,
                inlateout("3") a0 => ret_u,
                inout("4") a1 => _, inout("5") a2 => _,
                out("6") _, out("7") _, out("8") _, out("9") _,
                out("10") _, out("11") _, out("12") _,
                out("cr0") _, out("ctr") _, out("xer") _, out("lr") _,
                options(nostack),
            );
        }
        ret = ret_u as isize;
    }
    #[cfg(not(any(target_arch = "mips", target_arch = "powerpc")))]
    {
        // Host/unknown arch: not a bake-off target; dummy failure value
        ret = -1is;
    }
    ret
}

fn write(fd: i32, buf: &[u8]) -> isize {
    unsafe { sys_raw(sysno::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) }
}

fn puts(s: &str) {
    write(1, s.as_bytes());
}

/// strlen-style read of /proc/version: open, read into static buffer, print.
fn echo_proc_version() {
    const PATH: &[u8] = b"/proc/version\0";
    let fd = unsafe { sys_raw(sysno::SYS_OPEN, PATH.as_ptr() as usize, 0 /*O_RDONLY*/, 0) };
    if fd < 0 {
        puts("ffw-init: no /proc/version (fd<0)\n");
        return;
    }
    static mut BUF: [u8; 256] = [0; 256];
    let n = unsafe { sys_raw(sysno::SYS_READ, fd as usize, core::ptr::addr_of!(BUF) as usize, 255) };
    unsafe { sys_raw(sysno::SYS_CLOSE, fd as usize, 0, 0) };
    if n > 0 {
        let buf = unsafe { &*core::ptr::addr_of!(BUF) };
        let end = (n as usize).min(255);
        // ensure newline-termination for display
        let mut printed = 0usize;
        while printed < end {
            let chunk = &buf[printed..end];
            match chunk.iter().position(|&b| b == b'\n') {
                Some(p) => { write(1, &chunk[..=p]); break; }
                None => { write(1, chunk); printed = end; }
            }
        }
        if buf[end.saturating_sub(1)] != b'\n' { puts("\n"); }
    } else {
        puts("ffw-init: /proc/version read failed\n");
    }
}

/// Arch marker so the boot log unambiguously proves which build booted.
#[cfg(all(target_arch = "mips", target_pointer_width = "32"))]
const ARCH: &str = "ffw-init: hello from BIG-ENDIAN MIPS32 (o32) PID 1\n";
#[cfg(all(target_arch = "powerpc", target_pointer_width = "32"))]
const ARCH: &str = "ffw-init: hello from BIG-ENDIAN PowerPC32 PID 1\n";
#[cfg(not(any(all(target_arch = "mips", target_pointer_width = "32"), all(target_arch = "powerpc", target_pointer_width = "32"))))]
const ARCH: &str = "ffw-init: hello from OTHER arch PID 1\n";

#[panic_handler]
fn ph(_info: &PanicInfo) -> ! {
    puts("ffw-init: PANIC\n");
    loop { core::hint::spin_loop(); }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Some boards/kernel configs fail to wire fd0-2 for rdinit. Open the
    // console ourselves: /dev/console first, /dev/ttyS0 fallback, dup to 1.
    const CONSOLE: &[u8] = b"/dev/console\0";
    const TTYS0: &[u8] = b"/dev/ttyS0\0";
    let mut fd = unsafe { sys_raw(sysno::SYS_OPEN, CONSOLE.as_ptr() as usize, 2 /*O_RDWR*/, 0) };
    if fd < 0 {
        fd = unsafe { sys_raw(sysno::SYS_OPEN, TTYS0.as_ptr() as usize, 2, 0) };
    }
    if fd >= 0 && fd != 1 {
        // dup2(fd, 1) — sys_dup2 = 33 (o32 4033, ppc 33)
        unsafe { sys_raw(sysno::BASE + 33, fd as usize, 1, 0); }
    }
    puts(ARCH);
    puts("ffw-init: PID1 alive, issuing reboot(RB_AUTOBOOT)\n");
    // reboot(magic1=0xfee1dead, magic2=672274793, cmd=RB_AUTOBOOT, arg)
    let rc = unsafe { sys_raw(sysno::SYS_REBOOT, 0xfee1_dead, 672274793, sysno::RB_AUTOBOOT) };
    if rc < 0 {
        puts("ffw-init: reboot syscall failed, spinning\n");
    }
    loop { core::hint::spin_loop(); }
}
