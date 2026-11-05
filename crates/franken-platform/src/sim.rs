//! SYNTHETIC kernel doubles for host tests and host harnesses (`P02` / `ffw-jub`). Never a device dependency.
//!
//! This module exists only in test builds and in builds that turn on the cargo feature `sim` (off by default; a
//! device image is built without it, so none of this is in one). Both doubles answer [`Provenance::Simulated`], the
//! layer carries that to its owner, and neither may be cited as evidence about a legacy kernel: the contract
//! (`docs/contracts/p02.md`) forbids standing a fake in for the driver or the kernel.
//!
//! * [`ScriptedOps`] (test builds only) replays replies a test chose, one per call, and logs every call. It models
//!   nothing, so a passing test shows what the *policy layer does with* that reply and nothing about a kernel. An
//!   unscripted call panics, so a test cannot pass by accident through a reply it never chose; `close` alone defaults
//!   to success, because closing is cleanup and not what a test is about.
//! * [`SeededSim`] (the `sim` feature) is a deterministic stand-in for a host harness that needs a platform layer to
//!   run against: a seeded byte stream for `getrandom`, a virtual monotonic clock, and in-memory wake descriptors.
//!   Its bytes are reproducible, so they are **not secret** and must not be used as a key. It uses only the errno
//!   numbers that are the same on both legacy ABIs (`EBADF`, `EAGAIN`, `EINVAL`).

use crate::ops::{KernelOps, Provenance, Timespec};
use std::collections::{BTreeMap, VecDeque};

/// Longest a [`SeededSim`] pipe holds before a write answers `EAGAIN` (the Linux default pipe size).
const SIM_PIPE_CAPACITY: usize = 65_536;
const EBADF: isize = 9;
const EAGAIN: isize = 11;
const EINVAL: isize = 22;

/// One step of `SplitMix64`, the generator [`SeededSim`] draws from.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[derive(Debug, Clone)]
enum Slot {
    Event(u64),
    PipeRead(usize),
    PipeWrite(usize),
}

/// A deterministic double for host harnesses. See the module documentation: simulated, reproducible, not secret.
#[derive(Debug, Clone)]
pub struct SeededSim {
    rng: u64,
    unseeded_calls: u32,
    now_ns: u64,
    step_ns: u64,
    next_fd: i32,
    slots: BTreeMap<i32, Slot>,
    pipes: Vec<VecDeque<u8>>,
    getrandom_calls: u64,
}

impl SeededSim {
    /// A double whose random bytes, and so everything derived from them, are a function of `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: seed,
            unseeded_calls: 0,
            now_ns: 1_000_000_000,
            step_ns: 1_000,
            next_fd: 3,
            slots: BTreeMap::new(),
            pipes: Vec::new(),
            getrandom_calls: 0,
        }
    }

    /// Answer the first `calls` `getrandom` calls with `-EAGAIN`, the way a kernel whose pool is not seeded yet does.
    #[must_use]
    pub fn with_unseeded_calls(mut self, calls: u32) -> Self {
        self.unseeded_calls = calls;
        self
    }

    /// Start the virtual monotonic clock at `start_ns` and advance it by `step_ns` per reading (never zero, so two
    /// readings always differ).
    #[must_use]
    pub fn with_clock(mut self, start_ns: u64, step_ns: u64) -> Self {
        self.now_ns = start_ns;
        self.step_ns = if step_ns == 0 { 1 } else { step_ns };
        self
    }

    /// How many `getrandom` calls were made, answered or not.
    #[must_use]
    pub const fn getrandom_calls(&self) -> u64 {
        self.getrandom_calls
    }

    /// Descriptors currently open in the double.
    #[must_use]
    pub fn open_descriptors(&self) -> usize {
        self.slots.len()
    }

    fn allocate(&mut self, slot: Slot) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.slots.insert(fd, slot);
        fd
    }
}

impl KernelOps for SeededSim {
    fn provenance(&self) -> Provenance {
        Provenance::Simulated
    }

    fn backend_abi(&self) -> Option<crate::abi::Abi> {
        None
    }

    fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
        let now = self.now_ns;
        self.now_ns = self.now_ns.saturating_add(self.step_ns);
        // `now` is at most u64::MAX, so the seconds always fit an i64 and the nanoseconds are below a billion.
        out.secs = i64::try_from(now / 1_000_000_000).unwrap_or(i64::MAX);
        out.nanos = i64::try_from(now % 1_000_000_000).unwrap_or(0);
        0
    }

    fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize {
        self.getrandom_calls += 1;
        // The layer passes `GRND_NONBLOCK` and nothing else; any other flag is a caller error, as on Linux for an
        // unknown bit.
        if flags != crate::entropy::GRND_NONBLOCK {
            return -EINVAL;
        }
        if self.unseeded_calls > 0 {
            self.unseeded_calls -= 1;
            return -EAGAIN;
        }
        for chunk in buf.chunks_mut(8) {
            let word = splitmix64(&mut self.rng).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        isize::try_from(buf.len()).unwrap_or(isize::MAX)
    }

    fn eventfd2(&mut self, initval: u32, _flags: u32) -> isize {
        self.allocate(Slot::Event(u64::from(initval))) as isize
    }

    fn pipe2(&mut self, fds: &mut [i32; 2], _flags: u32) -> isize {
        let index = self.pipes.len();
        self.pipes.push(VecDeque::new());
        fds[0] = self.allocate(Slot::PipeRead(index));
        fds[1] = self.allocate(Slot::PipeWrite(index));
        0
    }

    fn write(&mut self, fd: i32, buf: &[u8]) -> isize {
        match self.slots.get_mut(&fd) {
            Some(Slot::Event(counter)) => {
                let Ok(raw) = <[u8; 8]>::try_from(buf) else {
                    return -EINVAL;
                };
                let value = u64::from_ne_bytes(raw);
                // Linux: all-ones is invalid, and a sum above u64::MAX - 1 would block (EAGAIN when nonblocking).
                if value == u64::MAX {
                    return -EINVAL;
                }
                match counter.checked_add(value) {
                    Some(sum) if sum < u64::MAX => {
                        *counter = sum;
                        8
                    }
                    _ => -EAGAIN,
                }
            }
            Some(Slot::PipeWrite(index)) => {
                let pipe = &mut self.pipes[*index];
                let room = SIM_PIPE_CAPACITY - pipe.len();
                if room == 0 {
                    return -EAGAIN;
                }
                let take = room.min(buf.len());
                pipe.extend(&buf[..take]);
                isize::try_from(take).unwrap_or(isize::MAX)
            }
            Some(Slot::PipeRead(_)) | None => -EBADF,
        }
    }

    fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize {
        match self.slots.get_mut(&fd) {
            Some(Slot::Event(counter)) => {
                if buf.len() < 8 {
                    return -EINVAL;
                }
                if *counter == 0 {
                    return -EAGAIN;
                }
                buf[..8].copy_from_slice(&counter.to_ne_bytes());
                *counter = 0;
                8
            }
            Some(Slot::PipeRead(index)) => {
                let pipe = &mut self.pipes[*index];
                if pipe.is_empty() {
                    return -EAGAIN;
                }
                let take = pipe.len().min(buf.len());
                for slot in &mut buf[..take] {
                    *slot = pipe.pop_front().unwrap_or(0);
                }
                isize::try_from(take).unwrap_or(isize::MAX)
            }
            Some(Slot::PipeWrite(_)) | None => -EBADF,
        }
    }

    fn close(&mut self, fd: i32) -> isize {
        if self.slots.remove(&fd).is_some() {
            0
        } else {
            -EBADF
        }
    }
}

#[cfg(test)]
pub(crate) use scripted::{Call, ScriptedOps};

#[cfg(test)]
mod scripted {
    use super::{KernelOps, Provenance, Timespec};
    use crate::abi::Abi;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// One call as the layer issued it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Call {
        Clock,
        GetRandom { len: usize, flags: u32 },
        Eventfd2 { initval: u32, flags: u32 },
        Pipe2 { flags: u32 },
        Write { fd: i32, bytes: Vec<u8> },
        Read { fd: i32, cap: usize },
        Close { fd: i32 },
    }

    #[derive(Default)]
    pub(crate) struct ScriptedOps {
        abi: Option<Abi>,
        clock: VecDeque<(isize, Timespec)>,
        random: VecDeque<(isize, Vec<u8>)>,
        eventfd: VecDeque<isize>,
        pipe: VecDeque<(isize, [i32; 2])>,
        write: VecDeque<isize>,
        read: VecDeque<(isize, Vec<u8>)>,
        close: VecDeque<isize>,
        log: Rc<RefCell<Vec<Call>>>,
    }

    impl ScriptedOps {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Pretend to be a real backend compiled for `abi`, so the layer's ABI check has something to compare.
        pub(crate) fn compiled_for(mut self, abi: Abi) -> Self {
            self.abi = Some(abi);
            self
        }

        /// A handle on the call log that stays valid after the double is moved into a layer.
        pub(crate) fn log_handle(&self) -> Rc<RefCell<Vec<Call>>> {
            Rc::clone(&self.log)
        }

        pub(crate) fn calls(&self) -> Vec<Call> {
            self.log.borrow().clone()
        }

        pub(crate) fn clock(mut self, ret: isize, secs: i64, nanos: i64) -> Self {
            self.clock.push_back((ret, Timespec { secs, nanos }));
            self
        }

        /// Reply to `getrandom` with `ret`; `bytes` are copied to the front of the caller's buffer.
        pub(crate) fn random(mut self, ret: isize, bytes: &[u8]) -> Self {
            self.random.push_back((ret, bytes.to_vec()));
            self
        }

        pub(crate) fn eventfd(mut self, ret: isize) -> Self {
            self.eventfd.push_back(ret);
            self
        }

        pub(crate) fn pipe(mut self, ret: isize, fds: [i32; 2]) -> Self {
            self.pipe.push_back((ret, fds));
            self
        }

        pub(crate) fn write(mut self, ret: isize) -> Self {
            self.write.push_back(ret);
            self
        }

        /// Reply to `read` with `ret`; `bytes` are copied to the front of the caller's buffer.
        pub(crate) fn read(mut self, ret: isize, bytes: &[u8]) -> Self {
            self.read.push_back((ret, bytes.to_vec()));
            self
        }

        pub(crate) fn close(mut self, ret: isize) -> Self {
            self.close.push_back(ret);
            self
        }

        pub(crate) fn pending_random(&self) -> usize {
            self.random.len()
        }

        pub(crate) fn pending_read(&self) -> usize {
            self.read.len()
        }

        fn record(&self, call: Call) {
            self.log.borrow_mut().push(call);
        }
    }

    impl KernelOps for ScriptedOps {
        fn provenance(&self) -> Provenance {
            Provenance::Simulated
        }

        fn backend_abi(&self) -> Option<Abi> {
            self.abi
        }

        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
            self.record(Call::Clock);
            let (ret, ts) = self
                .clock
                .pop_front()
                .expect("sim: unscripted clock_gettime");
            if ret == 0 {
                *out = ts;
            }
            ret
        }

        fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize {
            self.record(Call::GetRandom {
                len: buf.len(),
                flags,
            });
            let (ret, bytes) = self.random.pop_front().expect("sim: unscripted getrandom");
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            ret
        }

        fn eventfd2(&mut self, initval: u32, flags: u32) -> isize {
            self.record(Call::Eventfd2 { initval, flags });
            self.eventfd.pop_front().expect("sim: unscripted eventfd2")
        }

        fn pipe2(&mut self, fds: &mut [i32; 2], flags: u32) -> isize {
            self.record(Call::Pipe2 { flags });
            let (ret, pair) = self.pipe.pop_front().expect("sim: unscripted pipe2");
            if ret == 0 {
                *fds = pair;
            }
            ret
        }

        fn write(&mut self, fd: i32, buf: &[u8]) -> isize {
            self.record(Call::Write {
                fd,
                bytes: buf.to_vec(),
            });
            self.write.pop_front().expect("sim: unscripted write")
        }

        fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize {
            self.record(Call::Read { fd, cap: buf.len() });
            let (ret, bytes) = self.read.pop_front().expect("sim: unscripted read");
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            ret
        }

        fn close(&mut self, fd: i32) -> isize {
            self.record(Call::Close { fd });
            self.close.pop_front().unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Abi;
    use crate::entropy::{self, EntropyError};
    use crate::layer::PlatformLayer;
    use crate::wake::{Drained, WakeOutcome};
    use crate::{CapabilityStatus, KernelCapabilityMatrix};

    const KERNEL: &str = "4.9.0-0.bpo.6-powerpc";

    fn matrix(getrandom: CapabilityStatus, eventfd: CapabilityStatus) -> KernelCapabilityMatrix {
        KernelCapabilityMatrix {
            profile_id: "sim-fixture".to_string(),
            target_triple: "powerpc-unknown-linux-musl".to_string(),
            nominal_kernel_version: KERNEL.to_string(),
            guest_kernel_observed: Some(KERNEL.to_string()),
            static_elf_startup: CapabilityStatus::Supported,
            clock_monotonic: CapabilityStatus::Supported,
            clock_monotonic_res_ns: 1,
            nonblocking_pipe_io: CapabilityStatus::Supported,
            poll_syscall: CapabilityStatus::Supported,
            epoll_syscall: CapabilityStatus::Supported,
            udp_socket_io: CapabilityStatus::Supported,
            urandom_entropy: CapabilityStatus::Supported,
            getrandom_syscall: getrandom,
            atomics_32bit: CapabilityStatus::Supported,
            atomics_64bit_fallback: CapabilityStatus::Supported,
            eventfd_syscall: eventfd,
        }
    }

    fn layer(sim: SeededSim) -> PlatformLayer<SeededSim> {
        PlatformLayer::admit(
            &matrix(CapabilityStatus::Supported, CapabilityStatus::Supported),
            sim,
        )
        .expect("admitted")
    }

    #[test]
    fn the_same_seed_gives_the_same_bytes_and_a_different_seed_gives_different_ones() {
        let draw = |seed: u64| {
            let mut sim = SeededSim::new(seed);
            let mut buf = [0u8; 37];
            assert_eq!(entropy::fill(&mut sim, Abi::PowerPc32, &mut buf), Ok(()));
            buf
        };
        assert_eq!(draw(7), draw(7));
        assert_ne!(draw(7), draw(8));
    }

    #[test]
    fn a_request_that_is_not_a_multiple_of_the_word_is_a_prefix_of_the_longer_stream() {
        let whole = {
            let mut sim = SeededSim::new(7);
            let mut buf = [0u8; 24];
            assert_eq!(entropy::fill(&mut sim, Abi::PowerPc32, &mut buf), Ok(()));
            buf
        };
        for len in [16usize, 17, 19, 23, 24] {
            let mut sim = SeededSim::new(7);
            let mut part = vec![0u8; len];
            assert_eq!(entropy::fill(&mut sim, Abi::PowerPc32, &mut part), Ok(()));
            assert_eq!(part, whole[..len], "{len}");
        }
    }

    #[test]
    fn successive_draws_continue_the_stream_and_do_not_repeat_it() {
        let mut sim = SeededSim::new(1);
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        entropy::fill(&mut sim, Abi::Mips32, &mut a).unwrap();
        entropy::fill(&mut sim, Abi::Mips32, &mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(sim.getrandom_calls(), 2);
    }

    #[test]
    fn splitmix_matches_the_published_reference_vector() {
        // Reference outputs of SplitMix64 for state 0 (Vigna, https://prng.di.unimi.it/splitmix64.c).
        let mut state = 0u64;
        assert_eq!(splitmix64(&mut state), 0xE220_A839_7B1D_CDAF);
        assert_eq!(splitmix64(&mut state), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(splitmix64(&mut state), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn an_unseeded_pool_is_modelled_as_eagain_and_then_bytes_through_the_layer() {
        let m = matrix(
            CapabilityStatus::ObservedUnseeded,
            CapabilityStatus::Supported,
        );
        let mut layer =
            PlatformLayer::admit(&m, SeededSim::new(3).with_unseeded_calls(2)).expect("admitted");
        let mut buf = [0xAAu8; 16];
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(buf, [0u8; 16], "a refused draw leaves nothing behind");
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(layer.fill_random(&mut buf), Ok(()));
        assert_ne!(buf, [0u8; 16]);
    }

    #[test]
    fn a_flag_other_than_nonblock_is_refused_as_invalid_not_served() {
        let mut sim = SeededSim::new(1);
        let mut buf = [0u8; 8];
        for flags in [0u32, 2, 3, 4] {
            assert_eq!(sim.getrandom(&mut buf, flags), -EINVAL, "flags {flags}");
        }
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn the_virtual_clock_is_strictly_increasing_and_starts_where_it_was_told() {
        let mut layer = layer(SeededSim::new(1).with_clock(5_000_000_000, 250));
        let first = layer.now_ns().unwrap();
        let second = layer.now_ns().unwrap();
        assert_eq!((first, second), (5_000_000_000, 5_000_000_250));
        // A zero step would make two readings equal; it is raised to 1.
        let mut layer = layer_with_zero_step();
        assert!(layer.now_ns().unwrap() < layer.now_ns().unwrap());
    }

    fn layer_with_zero_step() -> PlatformLayer<SeededSim> {
        layer(SeededSim::new(1).with_clock(10, 0))
    }

    #[test]
    fn the_wake_round_trips_through_an_in_memory_eventfd() {
        let mut layer = layer(SeededSim::new(1));
        assert_eq!(
            layer.drain_wake(),
            Ok(Drained {
                wakes: 0,
                more_pending: false
            })
        );
        assert_eq!(layer.signal_wake(), Ok(WakeOutcome::Signalled));
        assert_eq!(layer.signal_wake(), Ok(WakeOutcome::Signalled));
        assert_eq!(
            layer.drain_wake(),
            Ok(Drained {
                wakes: 2,
                more_pending: false
            })
        );
        assert_eq!(
            layer.drain_wake(),
            Ok(Drained {
                wakes: 0,
                more_pending: false
            })
        );
    }

    #[test]
    fn the_wake_round_trips_through_an_in_memory_self_pipe_and_close_releases_it() {
        let m = matrix(
            CapabilityStatus::Supported,
            CapabilityStatus::AbsentFallbackAdmitted,
        );
        let mut layer = PlatformLayer::admit(&m, SeededSim::new(1)).expect("admitted");
        assert_eq!(layer.ops().open_descriptors(), 2);
        assert_eq!(layer.signal_wake(), Ok(WakeOutcome::Signalled));
        assert_eq!(
            layer.drain_wake(),
            Ok(Drained {
                wakes: 1,
                more_pending: false
            })
        );
        assert_eq!(layer.close(), Ok(()));
    }

    #[test]
    fn the_double_follows_linux_for_a_bad_descriptor_a_short_buffer_and_a_full_counter() {
        let mut sim = SeededSim::new(1);
        let mut buf = [0u8; 8];
        assert_eq!(sim.read(99, &mut buf), -EBADF);
        assert_eq!(sim.write(99, &[1]), -EBADF);
        assert_eq!(sim.close(99), -EBADF);
        let fd = i32::try_from(sim.eventfd2(0, 0)).unwrap();
        assert_eq!(
            sim.read(fd, &mut [0u8; 4]),
            -EINVAL,
            "a counter read needs 8 bytes"
        );
        assert_eq!(
            sim.write(fd, &[1, 2, 3]),
            -EINVAL,
            "a counter write is exactly 8 bytes"
        );
        assert_eq!(
            sim.write(fd, &u64::MAX.to_ne_bytes()),
            -EINVAL,
            "all-ones is invalid"
        );
        assert_eq!(sim.write(fd, &(u64::MAX - 1).to_ne_bytes()), 8);
        assert_eq!(
            sim.write(fd, &1u64.to_ne_bytes()),
            -EAGAIN,
            "a counter that would overflow would block"
        );
        assert_eq!(sim.close(fd), 0);
        assert_eq!(sim.close(fd), -EBADF, "a second close finds nothing");
    }

    #[test]
    fn the_double_says_it_is_simulated_and_names_no_abi_so_it_cannot_be_taken_for_a_kernel() {
        let sim = SeededSim::new(1);
        assert_eq!(sim.provenance(), Provenance::Simulated);
        assert_eq!(sim.backend_abi(), None);
        let layer = layer(sim);
        assert_eq!(layer.provenance(), Provenance::Simulated);
    }
}
