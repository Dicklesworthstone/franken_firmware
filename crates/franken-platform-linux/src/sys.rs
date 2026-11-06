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
//! 5. A `socketcall` block (the PowerPC route of the socket wrappers) is a local array of six words that lives across the call; the kernel reads
//!    at most `nargs[sub]` of them, which is six at most. Each word is an integer or an address derived under invariant 2. Which words, and
//!    whether a call is direct or goes through `socketcall`, is decided by [`crate::socket_route::issue_for`] from the plan in
//!    [`crate::numbers`]; this module executes the result and chooses nothing. **No guest has issued a `socketcall`**; the five socket wrappers
//!    are written, never compiled, never run.

use crate::numbers::{Numbers, socket_plan_for};
use crate::socket_route::{
    Issue, accept4_args, bind_args, issue_for, listen_args, recv_args, socket_args,
};
use franken_platform::abi::Abi;
use franken_platform::socket::SocketOp;

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

// Every socket route must fit what this leaf can carry; a plan that did not would fail to build for this target.
const _: () = {
    let plan = socket_plan_for(arch::ABI);
    assert!(plan.socket.fits_the_leaf());
    assert!(plan.bind.fits_the_leaf());
    assert!(plan.listen.fits_the_leaf());
    assert!(plan.accept4.fits_the_leaf());
    assert!(plan.recv.fits_the_leaf());
};

/// Issue what `issue` says. The words and the route are chosen by [`issue_for`] from the plan; this function only executes them.
///
/// # Safety
/// Every word of `issue` that is an address (the `sockaddr` of `bind`, the buffer of `recv`) is the address of memory the kernel may read or
/// write for the length in the same issue, for the whole call.
unsafe fn execute(issue: Issue) -> isize {
    match issue {
        Issue::Direct { number, args } => {
            // SAFETY: forwarded from this function's contract; `raw5` takes exactly these five argument words.
            unsafe { raw5(number, args[0], args[1], args[2], args[3], args[4]) }
        }
        Issue::SocketCall { number, sub, block } => {
            // SAFETY: forwarded from this function's contract for the addresses inside `block`; `block` is a local array of six words that
            // lives across the call (invariant 5), and the kernel reads at most six words from it.
            unsafe { raw5(number, sub, block.as_ptr() as usize, 0, 0, 0) }
        }
    }
}

/// `socket(domain, kind, 0)`: `kind` already carries the ABI's `SOCK_NONBLOCK | SOCK_CLOEXEC`, passed unchanged.
pub(crate) fn socket(domain: u32, kind: u32, protocol: u32) -> isize {
    let issue = issue_for(
        COMPILED_ABI,
        SocketOp::Socket,
        socket_args(domain, kind, protocol),
    );
    // SAFETY: invariants 1 and 5; no address word.
    unsafe { execute(issue) }
}

/// `bind(fd, addr, addr.len())`.
pub(crate) fn bind(fd: i32, addr: &[u8]) -> isize {
    let issue = issue_for(
        COMPILED_ABI,
        SocketOp::Bind,
        bind_args(fd, addr.as_ptr() as usize, addr.len()),
    );
    // SAFETY: invariants 1, 2 and 5: the address word is the address of `addr`, borrowed for the whole call, and the length word is its length;
    // the kernel reads at most that many bytes.
    unsafe { execute(issue) }
}

/// `listen(fd, backlog)`.
pub(crate) fn listen(fd: i32, backlog: i32) -> isize {
    let issue = issue_for(COMPILED_ABI, SocketOp::Listen, listen_args(fd, backlog));
    // SAFETY: invariants 1 and 5; no address word.
    unsafe { execute(issue) }
}

/// `accept4(fd, NULL, NULL, flags)`: the peer address is not requested, so the kernel writes nothing.
pub(crate) fn accept4(fd: i32, flags: u32) -> isize {
    let issue = issue_for(COMPILED_ABI, SocketOp::Accept4, accept4_args(fd, flags));
    // SAFETY: invariants 1 and 5; the address and length words are zero (NULL), so the kernel reads and writes no memory of ours.
    unsafe { execute(issue) }
}

/// `recv(fd, buf, buf.len(), flags)`.
pub(crate) fn recv(fd: i32, buf: &mut [u8], flags: u32) -> isize {
    let issue = issue_for(
        COMPILED_ABI,
        SocketOp::Recv,
        recv_args(fd, buf.as_mut_ptr() as usize, buf.len(), flags),
    );
    // SAFETY: invariants 1, 2 and 5: the buffer word is the address of `buf`, exclusively borrowed for the whole call, and the length word is its
    // length; the kernel writes at most that many bytes.
    unsafe { execute(issue) }
}
