//! The one seam between the platform policy layer and the kernel (`P02` / `ffw-jub`).
//!
//! [`KernelOps`] is deliberately **raw**: each method issues one kernel call and returns exactly what the
//! kernel returned, a non-negative result or `-errno`, as the E03 guest probes print it. The policy in
//! [`crate::entropy`], [`crate::clock`] and [`crate::wake`] decodes that with [`crate::abi::Abi`], so a
//! backend never gets to decide that a failure was fine.
//!
//! This crate forbids `unsafe`, so it contains no backend that talks to a kernel. A real backend needs the
//! raw syscall trampoline (assembly) and lives outside this crate, under its own review (contract section
//! "The real backend"). Until one exists and is exercised in a full-system guest that matches the profile,
//! nothing here has run against a kernel: the host tests drive the policy with a scripted double and say so.
//!
//! ## What a backend must declare
//! * [`KernelOps::provenance`]: [`Provenance::Kernel`] only for a backend that issues the calls to a kernel.
//!   Every double says [`Provenance::Simulated`], and the layer carries that to its owner
//!   ([`crate::layer::PlatformLayer::provenance`]), so a simulation cannot be taken for the real thing.
//! * [`KernelOps::backend_abi`]: the ABI a real backend was compiled for. [`crate::layer::PlatformLayer::admit`]
//!   refuses a backend whose ABI differs from the profile's, because the errno numbers and flag values this crate
//!   decodes with are the profile's and the numbers the backend issues are its own. A double has no ABI of its own
//!   (`None`): its replies are inputs a test chose, in whichever ABI the test names.
//!
//! ## What a backend must guarantee
//! * **Error convention.** A failure is returned as `-errno`. MIPS o32 reports errors with a flag register
//!   and a positive errno in `v0`; its backend must convert, and the E03 `ERR_ENOSYS` calibration line (the
//!   guest's own `ENOSYS` equals the table) is how a run proves it did.
//! * **No emulation.** A method that the kernel does not provide returns the kernel's `-ENOSYS`. It must
//!   not be implemented on top of another call (a `libc` shim that answers `accept4` with `accept` plus
//!   `fcntl`, or `getrandom` with `/dev/urandom`, is exactly the substitution the contract forbids).
//! * **Monotonic time.** `clock_gettime_monotonic` fills a [`Timespec`] with a monotonic reading and returns 0, or `-errno`.
//!   The epoch is the backend's choice (a double's scripted value, or for the Linux leaf the time since it was created, from
//!   `std::time::Instant`), so only differences between readings of one backend mean anything, and the layer never compares a
//!   reading with a time from outside its backend. A consumer that needs the kernel's absolute `CLOCK_MONOTONIC` (a `timerfd`
//!   with `TFD_TIMER_ABSTIME`, a kernel timestamp) is not served by this method; none exists in this slice.

/// A monotonic reading as the kernel reports it. The layer validates it ([`crate::clock`]); a backend
/// copies the kernel's fields and does nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    pub secs: i64,
    pub nanos: i64,
}

/// Where a backend's answers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// The calls are issued to a kernel.
    Kernel,
    /// The answers are a test double's. Nothing produced under this provenance is evidence about a kernel, and
    /// its "entropy" is not secret.
    Simulated,
}

/// One method per kernel call the platform layer issues. See the module documentation for the contract.
pub trait KernelOps {
    /// Where this backend's answers come from. There is no default: every backend states it.
    fn provenance(&self) -> Provenance;

    /// The ABI a real backend was compiled for, or `None` for a double (see the module documentation).
    fn backend_abi(&self) -> Option<crate::abi::Abi>;

    /// A monotonic reading into `out` (see the module documentation for its epoch): 0 on success.
    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize;

    /// `getrandom(buf, buf.len(), flags)`: the number of bytes written, which may be fewer than requested.
    fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize;

    /// `eventfd2(initval, flags)`: the new descriptor.
    fn eventfd2(&mut self, initval: u32, flags: u32) -> isize;

    /// `pipe2(fds, flags)`: 0 on success, with `[read end, write end]` in `fds`.
    fn pipe2(&mut self, fds: &mut [i32; 2], flags: u32) -> isize;

    /// `write(fd, buf, buf.len())`: the number of bytes written.
    fn write(&mut self, fd: i32, buf: &[u8]) -> isize;

    /// `read(fd, buf, buf.len())`: the number of bytes read.
    fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize;

    /// `close(fd)`: 0 on success. The layer issues it **once** per descriptor: on Linux a `close` that answers
    /// `EINTR` has already released the descriptor, and a second call could close an unrelated one.
    fn close(&mut self, fd: i32) -> isize;
}
