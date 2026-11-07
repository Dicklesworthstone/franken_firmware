//! The real Linux backend for `franken-platform`'s [`KernelOps`] seam (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! **Big-endian 32-bit MIPS (o32) and PowerPC only.** On any other target this crate has no [`LinuxKernel`]: the type is not
//! defined, so nothing can be built against a kernel it was not compiled for, and the host build of the workspace stays safe
//! Rust only ([`numbers`] is plain data and compiles everywhere).
//!
//! ## Why this is a separate crate
//! `franken-platform` forbids `unsafe`. A syscall is inline assembly, so the backend lives here with `unsafe_code = "deny"` and a
//! single `#[allow(unsafe_code)]` module (`sys`), every `unsafe` block of which states the invariants it relies on.
//!
//! ## What the backend does and does not do
//! * Six of its seven calls are raw syscalls, one per [`KernelOps`] method, returning what the kernel returned as `-errno`: it
//!   never retries, never converts, never substitutes, and a call the kernel lacks comes back as the kernel's own `-ENOSYS`. It is
//!   not built on libc for them, so no wrapper (`eventfd`, `pipe2`, `close`) can quietly turn one call into another. The seventh
//!   raw call, `open`, exists for the explicitly selected legacy entropy provider and can open exactly one file, the constant
//!   `/dev/random`: the method takes no path, so `/dev/urandom` cannot be reached through this backend.
//! * **The clock is not one of them.** The monotonic reading is `std::time::Instant` (`CLOCK_MONOTONIC` underneath), anchored when
//!   the backend is created, so a reading is the time since then and only differences are meaningful. Nothing in this slice
//!   consumes an absolute `CLOCK_MONOTONIC` value (no `timerfd` `TFD_TIMER_ABSTIME`, no kernel timestamp to compare with), so the
//!   leaf has no clock `unsafe` site. A later slice that does consume absolute values must add libc's `clock_gettime` (not a raw
//!   syscall number: on 32-bit musl 1.2 `time_t` is 64-bit and the raw `__NR_clock_gettime` is the y2038 ABI) and count that
//!   site in the leaf's unsafe inventory.
//! * **Sockets are a separate, admitted step.** [`LinuxKernel::admit_sockets`] returns a [`SocketKernel`], the only value that implements
//!   `franken_platform::socket::SocketOps`, and only after [`socket_route::admit`] has accepted the running kernel's release: on PowerPC the route
//!   is `socketcall`, whose sub-call 18 is `paccept` (a different call) on a v2.6.27 kernel, so that release is refused **by name, before any socket
//!   call**; MIPS o32 uses the direct calls and is admitted on any release. The five socket calls compile on both BE targets, but no
//!   guest has issued a `socketcall`. Which words each call is issued as is [`socket_route::issue_for`], host-tested; `sys.rs` only executes them.
//! * **The datagram carrier seam is a second, additive step on the same admission.** [`SocketKernel`] also implements
//!   `franken_platform::datagram::DatagramOps` (`sendto`, `recvfrom`), two more wrappers in `sys.rs`. Both are issued as `socketcall` sub-calls 11
//!   and 12 on **both** ABIs, with the words decided by [`datagram_route`] (host-tested, no `unsafe`); there is no wider trampoline. No guest has
//!   issued a `socketcall` on either ABI, and on MIPS o32 these would be the first (the leaf's other socket calls are direct there).
//! * It declares [`Provenance::Kernel`] and the ABI it was compiled for, which [`PlatformLayer::admit`] checks against the
//!   profile's.
//! * The socket wrappers have no guest execution proof. Other startup operations have run on the named QEMU harness kernels; the
//!   trampolines are the ones the E03 guest probes ran; the wrappers and this impl have only been type-checked for both targets.
//!
//! [`PlatformLayer::admit`]: franken_platform::layer::PlatformLayer::admit

#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]
#![deny(unsafe_code)]

pub mod datagram_route;
pub mod numbers;
pub mod socket_route;

/// Whether this build can issue kernel calls (Linux, 32-bit big-endian, MIPS or PowerPC).
pub const SUPPORTED_TARGET: bool = cfg!(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
));

#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
#[allow(unsafe_code)]
mod sys;

#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
mod backend {
    use super::sys;
    use crate::socket_route::{self, SocketRefusal};
    use franken_platform::abi::Abi;
    use franken_platform::datagram::DatagramOps;
    use franken_platform::ops::{KernelOps, Provenance, Timespec};
    use franken_platform::socket::SocketOps;
    use std::time::Instant;

    /// The kernel as a [`KernelOps`] backend. Its only state is the clock's anchor; every other method is one syscall.
    #[derive(Debug, Clone, Copy)]
    pub struct LinuxKernel {
        anchor: Instant,
    }

    impl LinuxKernel {
        /// The ABI this build was compiled for.
        pub const ABI: Abi = sys::COMPILED_ABI;

        /// A backend whose clock reads zero now.
        #[must_use]
        pub fn new() -> Self {
            Self {
                anchor: Instant::now(),
            }
        }
    }

    impl Default for LinuxKernel {
        fn default() -> Self {
            Self::new()
        }
    }

    impl LinuxKernel {
        /// Admit this backend for sockets on a kernel whose release is `release` (for example what `/proc/sys/kernel/osrelease` says), or refuse
        /// by name before any socket call is possible. See [`socket_route::admit`]: on PowerPC a v2.6.27 release, an unknown release and a
        /// v2.6.28 release candidate are refused; MIPS o32 is admitted on any release.
        ///
        /// # Errors
        /// [`SocketRefusal`], whose text names the release and the reason.
        pub fn admit_sockets(self, release: Option<&str>) -> Result<SocketKernel, SocketRefusal> {
            socket_route::admit(sys::COMPILED_ABI, release)?;
            Ok(SocketKernel { kernel: self })
        }
    }

    /// A [`LinuxKernel`] that [`LinuxKernel::admit_sockets`] accepted: every [`KernelOps`] method is the backend's own, and the five
    /// `SocketOps` methods are the socket calls. There is no other way to build one, so no socket call exists on a refused kernel.
    #[derive(Debug, Clone, Copy)]
    pub struct SocketKernel {
        kernel: LinuxKernel,
    }

    impl KernelOps for SocketKernel {
        fn provenance(&self) -> Provenance {
            self.kernel.provenance()
        }

        fn backend_abi(&self) -> Option<Abi> {
            self.kernel.backend_abi()
        }

        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
            self.kernel.clock_gettime_monotonic(out)
        }

        fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize {
            self.kernel.getrandom(buf, flags)
        }

        fn open_dev_random(&mut self, flags: u32) -> isize {
            self.kernel.open_dev_random(flags)
        }

        fn eventfd2(&mut self, initval: u32, flags: u32) -> isize {
            self.kernel.eventfd2(initval, flags)
        }

        fn pipe2(&mut self, fds: &mut [i32; 2], flags: u32) -> isize {
            self.kernel.pipe2(fds, flags)
        }

        fn write(&mut self, fd: i32, buf: &[u8]) -> isize {
            self.kernel.write(fd, buf)
        }

        fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize {
            self.kernel.read(fd, buf)
        }

        fn close(&mut self, fd: i32) -> isize {
            self.kernel.close(fd)
        }
    }

    impl SocketOps for SocketKernel {
        fn socket(&mut self, domain: u32, kind: u32, protocol: u32) -> isize {
            sys::socket(domain, kind, protocol)
        }

        fn bind(&mut self, fd: i32, addr: &[u8]) -> isize {
            sys::bind(fd, addr)
        }

        fn listen(&mut self, fd: i32, backlog: i32) -> isize {
            sys::listen(fd, backlog)
        }

        fn accept4(&mut self, fd: i32, flags: u32) -> isize {
            sys::accept4(fd, flags)
        }

        fn recv(&mut self, fd: i32, buf: &mut [u8], flags: u32) -> isize {
            sys::recv(fd, buf, flags)
        }
    }

    impl DatagramOps for SocketKernel {
        fn sendto(&mut self, fd: i32, buf: &[u8], flags: u32, addr: &[u8]) -> isize {
            sys::sendto(fd, buf, flags, addr)
        }

        fn recvfrom(
            &mut self,
            fd: i32,
            buf: &mut [u8],
            flags: u32,
            addr: &mut [u8],
            addr_len: &mut u32,
        ) -> isize {
            sys::recvfrom(fd, buf, flags, addr, addr_len)
        }
    }

    impl KernelOps for LinuxKernel {
        fn provenance(&self) -> Provenance {
            Provenance::Kernel
        }

        fn backend_abi(&self) -> Option<Abi> {
            Some(sys::COMPILED_ABI)
        }

        /// The time since this backend was created, from `Instant` (`CLOCK_MONOTONIC`). `Instant` has no error path, so the
        /// answer is always 0: `CLOCK_MONOTONIC` is unconditional on the kernels this targets, and a profile without it is
        /// refused at admission by the matrix, not at run time.
        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
            let elapsed = self.anchor.elapsed();
            out.secs = i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX);
            out.nanos = i64::from(elapsed.subsec_nanos());
            0
        }

        fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize {
            sys::getrandom(buf, flags)
        }

        /// One `open` of the constant path `/dev/random` with the policy's flags, answered as the kernel answered it. It opens no
        /// other file and substitutes nothing: a kernel without the device returns its own `-ENOENT`.
        fn open_dev_random(&mut self, flags: u32) -> isize {
            sys::open_dev_random(flags)
        }

        fn eventfd2(&mut self, initval: u32, flags: u32) -> isize {
            sys::eventfd2(initval, flags)
        }

        fn pipe2(&mut self, fds: &mut [i32; 2], flags: u32) -> isize {
            sys::pipe2(fds, flags)
        }

        fn write(&mut self, fd: i32, buf: &[u8]) -> isize {
            sys::write(fd, buf)
        }

        fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize {
            sys::read(fd, buf)
        }

        fn close(&mut self, fd: i32) -> isize {
            sys::close(fd)
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
pub use backend::{LinuxKernel, SocketKernel};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_build_has_no_backend_and_says_so() {
        // The workspace's host tests run on x86_64 or arm64: the backend must not exist there.
        assert_eq!(
            SUPPORTED_TARGET,
            cfg!(any(target_arch = "mips", target_arch = "powerpc"))
        );
    }
}
