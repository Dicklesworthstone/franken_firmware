//! The only `unsafe` in the platform backend: the raw syscall trampoline and typed wrappers around it.
//!
//! Compiled only for Linux on a 32-bit big-endian MIPS or PowerPC target (see `lib.rs`). The two `raw5` functions are the
//! trampolines of `toolchain/src/ffw-hello-init/src/main.rs`, which ran in full-system QEMU guests during E03/E07 and returned
//! the guest's own `ENOSYS` in the table's numbering (the `ERR_ENOSYS` calibration line); they are reproduced unchanged so that
//! evidence is about this code's shape.
//!
//! # Invariants every wrapper relies on
//! 1. The syscall number is fixed here from [`crate::numbers`] for this ABI, so safe callers cannot pair a number with the
//!    wrong call or the wrong ABI.
//! 2. Every pointer passed is derived from a live Rust reference (`&mut [i32; 2]`, `&mut [u8]`, `&[u8]`) that stays borrowed for the
//!    whole call, and every length passed is that reference's length, so a kernel that honors its contract writes or reads
//!    inside the referenced bytes. The kernel is trusted to honor `count`/`len`; a kernel that does not is outside what Rust can
//!    defend. The one pointer that is not a buffer is `open`'s path: the address of a `'static` NUL-terminated constant
//!    (`DEV_RANDOM`), valid for the whole program, which the kernel reads up to its NUL.
//! 3. The return value is normalized to the convention `franken_platform::ops::KernelOps` documents: a non-negative result, or
//!    `-errno`. MIPS reports errors in `$7` with a positive errno in `$2`; PowerPC in `cr0.SO` with a positive errno in `r3`.
//! 4. No call here blocks on its own: the callers pass nonblocking flags or descriptors, and `EINTR` is handled above.

use crate::numbers::Numbers;
use franken_platform::abi::Abi;

#[cfg(target_arch = "mips")]
mod arch {
    use super::{Abi, Numbers};

    pub(super) const ABI: Abi = Abi::Mips32;
    pub(super) const NR: Numbers = crate::numbers::MIPS32_O32;

    /// Raw Linux MIPS O32 syscall with up to five arguments (the fifth is passed at `16($sp)`).
    ///
    /// ABI invariant (`man 2 syscall`): `$2` holds the number on entry and the result or errno on exit; `$4`..`$7` hold arguments
    /// 0..3; on exit `$7` is 0 on success and non-zero on error, and then `$2` is a positive errno that is negated here.
    ///
    /// # Safety
    /// The caller guarantees that `nr` and the arguments form a valid call, and that every pointer argument refers to memory the
    /// kernel may read or write for the lengths passed.
    #[inline(never)]
    pub(super) unsafe fn raw5(
        nr: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> isize {
        let ret: isize;
        let err: usize;
        // SAFETY: the register constraints below are the audited ones: `$v1`, `$t0`..`$t7`, `$t8`, `$t9` are declared clobbered
        // and `$at` is saved and restored around the call; the fifth argument is stored in the 16-byte outgoing-argument area
        // of a 32-byte frame that is released before the block ends.
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
        if err != 0 { -ret } else { ret }
    }
}

#[cfg(target_arch = "powerpc")]
mod arch {
    use super::{Abi, Numbers};

    pub(super) const ABI: Abi = Abi::PowerPc32;
    pub(super) const NR: Numbers = crate::numbers::POWERPC32;

    /// Raw Linux PowerPC32 SVR4 syscall with up to five arguments.
    ///
    /// ABI invariant (`man 2 syscall`): `r0` holds the number; `r3`..`r7` hold arguments 0..4; the kernel's `sc` clobbers `r0`,
    /// `r3`..`r12`, `cr0`, `ctr` and `xer`, so every input register is declared `inlateout`. On error `cr0.SO` is set and `r3`
    /// holds a positive errno; `bns+ 1f; neg 3, 3` normalizes it to `-errno`.
    ///
    /// # Safety
    /// The caller guarantees that `nr` and the arguments form a valid call, and that every pointer argument refers to memory the
    /// kernel may read or write for the lengths passed.
    #[inline(never)]
    pub(super) unsafe fn raw5(
        nr: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> isize {
        let r3: isize;
        // SAFETY: the clobber list is the audited one; `options(nostack)` holds because `sc` does not touch the user stack.
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

use arch::{NR, raw5};

/// The ABI this build speaks.
pub(crate) const COMPILED_ABI: Abi = arch::ABI;

/// `getrandom(buf, buf.len(), flags)`.
pub(crate) fn getrandom(buf: &mut [u8], flags: u32) -> isize {
    // SAFETY: invariants 1 to 3: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe {
        raw5(
            NR.getrandom,
            buf.as_mut_ptr() as usize,
            buf.len(),
            flags as usize,
            0,
            0,
        )
    }
}

/// The one path the leaf opens, NUL-terminated for the kernel. It is a constant of this crate: nothing a caller passes can name another
/// file, so `/dev/urandom` (which never says whether the pool is seeded) cannot be opened through this backend.
pub(crate) const DEV_RANDOM: &[u8; 12] = b"/dev/random\0";

/// `open("/dev/random", flags)`: `O_RDONLY` is 0 on both ABIs, so `flags` (the policy's `O_NONBLOCK | O_CLOEXEC`) is the whole
/// flags argument, and the mode argument is unused without `O_CREAT`. A kernel without the device answers its own `-ENOENT`.
pub(crate) fn open_dev_random(flags: u32) -> isize {
    // SAFETY: invariants 1 to 3: the pointer is the address of the `'static` NUL-terminated constant `DEV_RANDOM`, valid for the
    // whole call and read by the kernel only up to its NUL; `flags` is a plain integer; no other pointer is passed.
    unsafe {
        raw5(
            NR.open,
            DEV_RANDOM.as_ptr() as usize,
            flags as usize,
            0,
            0,
            0,
        )
    }
}

/// `eventfd2(initval, flags)`.
pub(crate) fn eventfd2(initval: u32, flags: u32) -> isize {
    // SAFETY: invariant 1; no pointer argument.
    unsafe { raw5(NR.eventfd2, initval as usize, flags as usize, 0, 0, 0) }
}

/// `pipe2(fds, flags)`: the kernel stores two 32-bit descriptors.
pub(crate) fn pipe2(fds: &mut [i32; 2], flags: u32) -> isize {
    // SAFETY: invariants 1 to 3: `fds` is an exclusively borrowed `int[2]`.
    unsafe { raw5(NR.pipe2, fds.as_mut_ptr() as usize, flags as usize, 0, 0, 0) }
}

/// `write(fd, buf, buf.len())`.
pub(crate) fn write(fd: i32, buf: &[u8]) -> isize {
    // SAFETY: invariants 1 to 3: the kernel reads at most `buf.len()` bytes from `buf`. A negative `fd` is passed bit-for-bit and
    // the kernel answers `EBADF`.
    unsafe {
        raw5(
            NR.write,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            0,
            0,
        )
    }
}

/// `read(fd, buf, buf.len())`.
pub(crate) fn read(fd: i32, buf: &mut [u8]) -> isize {
    // SAFETY: invariants 1 to 3: the kernel writes at most `buf.len()` bytes into `buf`.
    unsafe {
        raw5(
            NR.read,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            0,
            0,
        )
    }
}

/// `close(fd)`.
pub(crate) fn close(fd: i32) -> isize {
    // SAFETY: invariant 1; no pointer argument.
    unsafe { raw5(NR.close, fd as usize, 0, 0, 0, 0) }
}
