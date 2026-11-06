//! Reactor wakeup: an `eventfd` or a self-pipe, chosen by the admitted matrix (`P02` / `ffw-jub`).
//! Contract: `docs/contracts/p02.md`.
//!
//! The mechanism comes from [`crate::KernelCapabilityMatrix::check_admission`]: `eventfd2` observed working selects
//! [`ReactorWakeMechanism::EventFd`], `eventfd2` observed absent with the fallback admitted selects
//! [`ReactorWakeMechanism::SelfPipe`]. This module never decides that for itself and never falls from one to the
//! other: if the admitted mechanism cannot be opened, [`Waker::open`] says so and stops. There is no plain `pipe`
//! fallback either: E03 probed `pipe2` and not `pipe`, so `pipe` has no observation behind it.
//!
//! What was observed, and what was not (E03 run `1412ac47`):
//! * a blocked `poll` was woken by a write to a `pipe2` pipe from another context, and the wake was consumed exactly
//!   once (`REACTOR_WAKE`); a nonblocking read of an empty pipe answers `-EAGAIN` (`NONBLOCK_PIPE`); `eventfd2`
//!   creates a descriptor whose counter reads back what was written (`EVENTFD2`).
//! * **not observed:** what a nonblocking *write* answers when the pipe is full or the eventfd counter would
//!   overflow. Linux documents `EAGAIN` for both and that a wake is then already pending, but no E03 line shows it.
//!   So [`Waker::signal`] returns [`WakeOutcome::Backlogged`] for it, a different value from
//!   [`WakeOutcome::Signalled`], and a reactor must drain regardless. It is never reported as a fresh wake.
//!
//! An interrupted call is repeated a bounded number of times ([`crate::abi::MAX_INTERRUPTED_ATTEMPTS`]).

use crate::ReactorWakeMechanism;
use crate::abi::{Abi, O_CLOEXEC, SysError};
use crate::ops::KernelOps;

/// Bytes an `eventfd` read or write moves: one native-endian `u64`.
pub const EVENTFD_COUNTER_BYTES: usize = 8;
/// The most pipe reads one [`Waker::drain`] issues, so a pipe that never empties cannot hold the reactor.
pub const MAX_DRAIN_READS: u32 = 64;
/// Bytes read from the self-pipe per call.
pub const PIPE_DRAIN_CHUNK: usize = 64;
/// The byte written to the self-pipe. Its value carries no meaning; only its arrival does.
pub const PIPE_WAKE_BYTE: u8 = 1;

/// Which kernel call a [`WakeError`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeCall {
    Eventfd2,
    Pipe2,
    Write,
    Read,
    Close,
}

/// Result of a wake request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// The kernel accepted the write.
    Signalled,
    /// The kernel answered `EAGAIN`. Documented Linux behavior says a wake is already pending, but E03 did not
    /// observe it, so this is reported as its own outcome and is never counted as a new wake.
    Backlogged,
}

/// What a drain consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    /// Wakes consumed: the eventfd counter, or the number of bytes read from the pipe. Zero means nothing was
    /// pending (a nonblocking read answered `EAGAIN`).
    pub wakes: u64,
    /// The drain stopped at [`MAX_DRAIN_READS`] with the pipe still readable.
    pub more_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WakeError {
    #[error(
        "{call:?} is absent (ENOSYS in this ABI); the admitted mechanism cannot be opened and no other is tried"
    )]
    Absent { call: WakeCall },
    #[error("{call:?} failed: {error}")]
    Sys { call: WakeCall, error: SysError },
    #[error("{call:?} returned {value}, expected {expected}")]
    Unexpected {
        call: WakeCall,
        value: usize,
        expected: usize,
    },
    #[error("the kernel returned unusable descriptors ({read_fd}, {write_fd})")]
    BadDescriptor { read_fd: i64, write_fd: i64 },
    #[error("write moved {wrote} of {expected} bytes")]
    ShortWrite { wrote: usize, expected: usize },
    #[error("read moved {got} bytes, expected {expected}")]
    ShortRead { got: usize, expected: usize },
    #[error("an eventfd read reported a counter of zero")]
    ZeroCounter,
    #[error("the self-pipe reported end of file although this layer holds the write end")]
    EndOfFile,
}

fn classify(call: WakeCall, error: SysError) -> WakeError {
    match error {
        SysError::Absent => WakeError::Absent { call },
        other => WakeError::Sys { call, error: other },
    }
}

/// An open wake source. `Copy`: it is only descriptor numbers, and closing is explicit ([`Waker::close`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waker {
    mechanism: ReactorWakeMechanism,
    read_fd: i32,
    write_fd: i32,
}

impl Waker {
    /// Open the admitted mechanism, nonblocking and close-on-exec. Nothing else is tried if it fails.
    ///
    /// # Errors
    /// [`WakeError::Absent`] when the admitted call answers `ENOSYS`, [`WakeError::Sys`] for any other failure, and
    /// [`WakeError::BadDescriptor`] when the kernel reports success with a descriptor that cannot be used.
    pub fn open<O: KernelOps + ?Sized>(
        ops: &mut O,
        abi: Abi,
        mechanism: ReactorWakeMechanism,
    ) -> Result<Self, WakeError> {
        let flags = abi.o_nonblock() | O_CLOEXEC;
        match mechanism {
            ReactorWakeMechanism::EventFd => {
                let raw = abi
                    .call_retrying(|| ops.eventfd2(0, flags))
                    .map_err(|error| classify(WakeCall::Eventfd2, error))?;
                let fd = i32::try_from(raw).map_err(|_| WakeError::BadDescriptor {
                    read_fd: i64::try_from(raw).unwrap_or(i64::MAX),
                    write_fd: i64::try_from(raw).unwrap_or(i64::MAX),
                })?;
                Ok(Self {
                    mechanism,
                    read_fd: fd,
                    write_fd: fd,
                })
            }
            ReactorWakeMechanism::SelfPipe => {
                let mut fds = [-1i32, -1i32];
                let returned = abi
                    .call_retrying(|| ops.pipe2(&mut fds, flags))
                    .map_err(|error| classify(WakeCall::Pipe2, error))?;
                if returned != 0 {
                    return Err(WakeError::Unexpected {
                        call: WakeCall::Pipe2,
                        value: returned,
                        expected: 0,
                    });
                }
                if fds[0] < 0 || fds[1] < 0 || fds[0] == fds[1] {
                    // Best effort: do not leak a descriptor the kernel did hand over. A number that appears twice
                    // is closed once: a second close of the same number could hit an unrelated descriptor.
                    if fds[0] >= 0 {
                        let _ = ops.close(fds[0]);
                    }
                    if fds[1] >= 0 && fds[1] != fds[0] {
                        let _ = ops.close(fds[1]);
                    }
                    return Err(WakeError::BadDescriptor {
                        read_fd: i64::from(fds[0]),
                        write_fd: i64::from(fds[1]),
                    });
                }
                Ok(Self {
                    mechanism,
                    read_fd: fds[0],
                    write_fd: fds[1],
                })
            }
        }
    }

    /// The mechanism this waker was opened with.
    #[must_use]
    pub const fn mechanism(&self) -> ReactorWakeMechanism {
        self.mechanism
    }

    /// The descriptor a reactor polls for readability.
    #[must_use]
    pub const fn read_fd(&self) -> i32 {
        self.read_fd
    }

    /// Request a wake.
    ///
    /// # Errors
    /// [`WakeError::Sys`] for any failure other than `EAGAIN` (which is [`WakeOutcome::Backlogged`]), and
    /// [`WakeError::ShortWrite`] when the kernel moved fewer bytes than the mechanism's unit.
    pub fn signal<O: KernelOps + ?Sized>(
        &self,
        ops: &mut O,
        abi: Abi,
    ) -> Result<WakeOutcome, WakeError> {
        let counter = 1u64.to_ne_bytes();
        let pipe_byte = [PIPE_WAKE_BYTE];
        let payload: &[u8] = match self.mechanism {
            ReactorWakeMechanism::EventFd => &counter,
            ReactorWakeMechanism::SelfPipe => &pipe_byte,
        };
        match abi.call_retrying(|| ops.write(self.write_fd, payload)) {
            Ok(wrote) if wrote == payload.len() => Ok(WakeOutcome::Signalled),
            Ok(wrote) => Err(WakeError::ShortWrite {
                wrote,
                expected: payload.len(),
            }),
            Err(SysError::WouldBlock) => Ok(WakeOutcome::Backlogged),
            Err(error) => Err(classify(WakeCall::Write, error)),
        }
    }

    /// Consume pending wakes without blocking.
    ///
    /// # Errors
    /// [`WakeError::Sys`] for any failure other than `EAGAIN` (which means nothing is pending), plus the shape
    /// errors for a read the kernel answers in a way the mechanism cannot produce.
    pub fn drain<O: KernelOps + ?Sized>(
        &self,
        ops: &mut O,
        abi: Abi,
    ) -> Result<Drained, WakeError> {
        match self.mechanism {
            ReactorWakeMechanism::EventFd => {
                let mut buf = [0u8; EVENTFD_COUNTER_BYTES];
                match abi.call_retrying(|| ops.read(self.read_fd, &mut buf)) {
                    Ok(EVENTFD_COUNTER_BYTES) => match u64::from_ne_bytes(buf) {
                        0 => Err(WakeError::ZeroCounter),
                        wakes => Ok(Drained {
                            wakes,
                            more_pending: false,
                        }),
                    },
                    Ok(got) => Err(WakeError::ShortRead {
                        got,
                        expected: EVENTFD_COUNTER_BYTES,
                    }),
                    Err(SysError::WouldBlock) => Ok(Drained {
                        wakes: 0,
                        more_pending: false,
                    }),
                    Err(error) => Err(classify(WakeCall::Read, error)),
                }
            }
            ReactorWakeMechanism::SelfPipe => {
                let mut total = 0u64;
                for _ in 0..MAX_DRAIN_READS {
                    let mut chunk = [0u8; PIPE_DRAIN_CHUNK];
                    match abi.call_retrying(|| ops.read(self.read_fd, &mut chunk)) {
                        Ok(0) => return Err(WakeError::EndOfFile),
                        Ok(got) if got <= PIPE_DRAIN_CHUNK => total += got as u64,
                        Ok(got) => {
                            return Err(WakeError::Unexpected {
                                call: WakeCall::Read,
                                value: got,
                                expected: PIPE_DRAIN_CHUNK,
                            });
                        }
                        Err(SysError::WouldBlock) => {
                            return Ok(Drained {
                                wakes: total,
                                more_pending: false,
                            });
                        }
                        Err(error) => return Err(classify(WakeCall::Read, error)),
                    }
                }
                Ok(Drained {
                    wakes: total,
                    more_pending: true,
                })
            }
        }
    }

    /// Close the descriptor(s), each **exactly once**. The first failure is returned after every close was attempted.
    ///
    /// A `close` is never repeated, not even after `EINTR`: on Linux the descriptor is released before the call
    /// returns that error, so a second call could close an unrelated descriptor another thread has just been given.
    /// An `EINTR` is therefore reported as the error the kernel returned, and the descriptor is treated as gone.
    ///
    /// # Errors
    /// [`WakeError::Sys`] with [`WakeCall::Close`] for the first close that failed, or [`WakeError::Unexpected`] for
    /// the first close that returned something other than 0.
    pub fn close<O: KernelOps + ?Sized>(self, ops: &mut O, abi: Abi) -> Result<(), WakeError> {
        let mut first_error: Option<WakeError> = None;
        let single = [self.read_fd];
        let pair = [self.read_fd, self.write_fd];
        let fds: &[i32] = match self.mechanism {
            ReactorWakeMechanism::EventFd => &single,
            ReactorWakeMechanism::SelfPipe => &pair,
        };
        for fd in fds {
            let failure = match abi.decode(ops.close(*fd)) {
                Ok(0) => None,
                Ok(value) => Some(WakeError::Unexpected {
                    call: WakeCall::Close,
                    value,
                    expected: 0,
                }),
                Err(error) => Some(classify(WakeCall::Close, error)),
            };
            if first_error.is_none() {
                first_error = failure;
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::MAX_INTERRUPTED_ATTEMPTS;
    use crate::sim::{Call, ScriptedOps};

    const PPC: Abi = Abi::PowerPc32;
    const MIPS: Abi = Abi::Mips32;

    fn eventfd_waker(ops: &mut ScriptedOps, abi: Abi) -> Waker {
        Waker::open(ops, abi, ReactorWakeMechanism::EventFd).expect("scripted eventfd2 succeeds")
    }

    fn pipe_waker(ops: &mut ScriptedOps, abi: Abi) -> Waker {
        Waker::open(ops, abi, ReactorWakeMechanism::SelfPipe).expect("scripted pipe2 succeeds")
    }

    #[test]
    fn the_eventfd_is_opened_nonblocking_and_cloexec_in_each_abis_own_flags() {
        for (abi, nonblock) in [(PPC, 0x800u32), (MIPS, 0x80)] {
            let mut ops = ScriptedOps::new().eventfd(7);
            let waker = eventfd_waker(&mut ops, abi);
            assert_eq!(waker.read_fd(), 7);
            assert_eq!(waker.mechanism(), ReactorWakeMechanism::EventFd);
            assert_eq!(
                ops.calls(),
                vec![Call::Eventfd2 {
                    initval: 0,
                    flags: nonblock | O_CLOEXEC
                }],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn the_self_pipe_is_opened_with_pipe2_nonblocking_and_cloexec() {
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]);
        let waker = pipe_waker(&mut ops, MIPS);
        assert_eq!(
            (waker.read_fd(), waker.mechanism()),
            (5, ReactorWakeMechanism::SelfPipe)
        );
        assert_eq!(
            ops.calls(),
            vec![Call::Pipe2 {
                flags: 0x80 | O_CLOEXEC
            }]
        );
    }

    #[test]
    fn an_absent_admitted_call_is_reported_and_no_other_mechanism_is_tried() {
        let mut ops = ScriptedOps::new().eventfd(-38);
        assert_eq!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::EventFd),
            Err(WakeError::Absent {
                call: WakeCall::Eventfd2
            })
        );
        assert_eq!(ops.calls().len(), 1, "no pipe2 after a failed eventfd2");

        let mut ops = ScriptedOps::new().pipe(-89, [0, 0]);
        assert_eq!(
            Waker::open(&mut ops, MIPS, ReactorWakeMechanism::SelfPipe),
            Err(WakeError::Absent {
                call: WakeCall::Pipe2
            })
        );
        assert_eq!(
            ops.calls().len(),
            1,
            "no plain pipe: the seam does not have one"
        );

        // The other ABI's number is not absence.
        let mut ops = ScriptedOps::new().eventfd(-89);
        assert_eq!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::EventFd),
            Err(WakeError::Sys {
                call: WakeCall::Eventfd2,
                error: SysError::Errno(89)
            })
        );
    }

    #[test]
    fn descriptors_the_kernel_hands_over_but_that_cannot_be_used_are_refused_and_not_leaked() {
        let mut ops = ScriptedOps::new().pipe(0, [4, 4]);
        assert_eq!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::SelfPipe),
            Err(WakeError::BadDescriptor {
                read_fd: 4,
                write_fd: 4
            })
        );
        let closes_of_four = ops
            .calls()
            .iter()
            .filter(|call| **call == Call::Close { fd: 4 })
            .count();
        assert_eq!(
            closes_of_four, 1,
            "a descriptor number returned twice is closed once"
        );

        let mut ops = ScriptedOps::new().pipe(0, [-1, 9]);
        assert!(matches!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::SelfPipe),
            Err(WakeError::BadDescriptor { .. })
        ));
        assert!(
            ops.calls().contains(&Call::Close { fd: 9 }),
            "the one valid descriptor is closed"
        );

        let mut ops = ScriptedOps::new().pipe(2, [4, 5]);
        assert_eq!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::SelfPipe),
            Err(WakeError::Unexpected {
                call: WakeCall::Pipe2,
                value: 2,
                expected: 0
            })
        );
    }

    #[test]
    fn signalling_writes_one_unit_per_mechanism() {
        let mut ops = ScriptedOps::new().eventfd(7).write(8);
        let waker = eventfd_waker(&mut ops, PPC);
        assert_eq!(waker.signal(&mut ops, PPC), Ok(WakeOutcome::Signalled));
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]).write(1);
        let waker = pipe_waker(&mut ops, PPC);
        assert_eq!(waker.signal(&mut ops, PPC), Ok(WakeOutcome::Signalled));
        assert_eq!(
            ops.calls().last(),
            Some(&Call::Write {
                fd: 6,
                bytes: vec![PIPE_WAKE_BYTE]
            })
        );
    }

    #[test]
    fn the_eventfd_write_is_a_native_endian_counter_of_one() {
        let mut ops = ScriptedOps::new().eventfd(7).write(8);
        let waker = eventfd_waker(&mut ops, MIPS);
        waker.signal(&mut ops, MIPS).unwrap();
        assert_eq!(
            ops.calls().last(),
            Some(&Call::Write {
                fd: 7,
                bytes: 1u64.to_ne_bytes().to_vec()
            })
        );
    }

    #[test]
    fn eagain_on_a_write_is_backlogged_not_a_fresh_wake_and_is_not_retried() {
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]).write(-11);
        let waker = pipe_waker(&mut ops, PPC);
        let outcome = waker.signal(&mut ops, PPC);
        assert_eq!(outcome, Ok(WakeOutcome::Backlogged));
        assert_ne!(outcome, Ok(WakeOutcome::Signalled));
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| matches!(call, Call::Write { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn a_short_or_failed_write_is_an_error_not_a_wake() {
        let mut ops = ScriptedOps::new().eventfd(7).write(4).write(0);
        let waker = eventfd_waker(&mut ops, PPC);
        assert_eq!(
            waker.signal(&mut ops, PPC),
            Err(WakeError::ShortWrite {
                wrote: 4,
                expected: 8
            })
        );
        assert_eq!(
            waker.signal(&mut ops, PPC),
            Err(WakeError::ShortWrite {
                wrote: 0,
                expected: 8
            })
        );
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]).write(-9);
        let waker = pipe_waker(&mut ops, PPC);
        assert_eq!(
            waker.signal(&mut ops, PPC),
            Err(WakeError::Sys {
                call: WakeCall::Write,
                error: SysError::Errno(9)
            })
        );
    }

    #[test]
    fn an_interrupted_write_is_retried_then_reported_after_the_bound() {
        let mut ops = ScriptedOps::new()
            .pipe(0, [5, 6])
            .write(-4)
            .write(-4)
            .write(1);
        let waker = pipe_waker(&mut ops, MIPS);
        assert_eq!(waker.signal(&mut ops, MIPS), Ok(WakeOutcome::Signalled));

        let mut storm = ScriptedOps::new().pipe(0, [5, 6]);
        for _ in 0..12 {
            storm = storm.write(-4);
        }
        let waker = pipe_waker(&mut storm, MIPS);
        assert_eq!(
            waker.signal(&mut storm, MIPS),
            Err(WakeError::Sys {
                call: WakeCall::Write,
                error: SysError::Interrupted
            })
        );
        let writes = storm
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Write { .. }))
            .count();
        assert_eq!(writes, MAX_INTERRUPTED_ATTEMPTS as usize);
    }

    #[test]
    fn draining_an_eventfd_returns_the_counter_and_eagain_means_nothing_pending() {
        let mut ops = ScriptedOps::new()
            .eventfd(7)
            .read(8, &3u64.to_ne_bytes())
            .read(-11, &[]);
        let waker = eventfd_waker(&mut ops, PPC);
        assert_eq!(
            waker.drain(&mut ops, PPC),
            Ok(Drained {
                wakes: 3,
                more_pending: false
            })
        );
        assert_eq!(
            waker.drain(&mut ops, PPC),
            Ok(Drained {
                wakes: 0,
                more_pending: false
            })
        );
    }

    #[test]
    fn an_eventfd_read_that_is_not_one_nonzero_counter_is_an_error() {
        let mut ops = ScriptedOps::new()
            .eventfd(7)
            .read(4, &[0, 0, 0, 1])
            .read(8, &0u64.to_ne_bytes())
            .read(-5, &[]);
        let waker = eventfd_waker(&mut ops, MIPS);
        assert_eq!(
            waker.drain(&mut ops, MIPS),
            Err(WakeError::ShortRead {
                got: 4,
                expected: 8
            })
        );
        assert_eq!(waker.drain(&mut ops, MIPS), Err(WakeError::ZeroCounter));
        assert_eq!(
            waker.drain(&mut ops, MIPS),
            Err(WakeError::Sys {
                call: WakeCall::Read,
                error: SysError::Errno(5)
            })
        );
    }

    #[test]
    fn draining_the_self_pipe_reads_until_it_is_empty() {
        let mut ops = ScriptedOps::new()
            .pipe(0, [5, 6])
            .read(3, &[1, 1, 1])
            .read(-11, &[]);
        let waker = pipe_waker(&mut ops, PPC);
        assert_eq!(
            waker.drain(&mut ops, PPC),
            Ok(Drained {
                wakes: 3,
                more_pending: false
            })
        );
        assert_eq!(ops.pending_read(), 0);
        assert_eq!(
            ops.calls().last(),
            Some(&Call::Read {
                fd: 5,
                cap: PIPE_DRAIN_CHUNK
            })
        );
    }

    #[test]
    fn a_pipe_that_never_empties_cannot_hold_the_reactor() {
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]);
        for _ in 0..100 {
            ops = ops.read(PIPE_DRAIN_CHUNK as isize, &[1u8; PIPE_DRAIN_CHUNK]);
        }
        let waker = pipe_waker(&mut ops, MIPS);
        assert_eq!(
            waker.drain(&mut ops, MIPS),
            Ok(Drained {
                wakes: u64::from(MAX_DRAIN_READS) * PIPE_DRAIN_CHUNK as u64,
                more_pending: true
            })
        );
        assert_eq!(ops.pending_read(), 100 - MAX_DRAIN_READS as usize);
    }

    #[test]
    fn a_pipe_read_the_mechanism_cannot_produce_is_an_error() {
        let mut ops = ScriptedOps::new()
            .pipe(0, [5, 6])
            .read(0, &[])
            .read(65, &[]);
        let waker = pipe_waker(&mut ops, PPC);
        assert_eq!(waker.drain(&mut ops, PPC), Err(WakeError::EndOfFile));
        assert_eq!(
            waker.drain(&mut ops, PPC),
            Err(WakeError::Unexpected {
                call: WakeCall::Read,
                value: 65,
                expected: PIPE_DRAIN_CHUNK
            })
        );
    }

    #[test]
    fn closing_attempts_every_descriptor_and_reports_the_first_failure() {
        let mut ops = ScriptedOps::new().pipe(0, [5, 6]).close(-9).close(0);
        let waker = pipe_waker(&mut ops, PPC);
        assert_eq!(
            waker.close(&mut ops, PPC),
            Err(WakeError::Sys {
                call: WakeCall::Close,
                error: SysError::Errno(9)
            })
        );
        let closes: Vec<Call> = ops
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .collect();
        assert_eq!(closes, vec![Call::Close { fd: 5 }, Call::Close { fd: 6 }]);

        let mut ops = ScriptedOps::new().eventfd(7);
        let waker = eventfd_waker(&mut ops, PPC);
        assert_eq!(waker.close(&mut ops, PPC), Ok(()));
        assert_eq!(ops.calls().last(), Some(&Call::Close { fd: 7 }));
    }

    #[test]
    fn a_close_is_issued_once_even_when_it_answers_eintr_and_a_nonzero_return_is_not_success() {
        // Linux has already released the descriptor when `close` answers EINTR. A second `close(7)` could close an
        // unrelated descriptor that another thread was just handed under the same number.
        for abi in [PPC, MIPS] {
            let mut ops = ScriptedOps::new().eventfd(7).close(-4).close(0);
            let waker = eventfd_waker(&mut ops, abi);
            assert_eq!(
                waker.close(&mut ops, abi),
                Err(WakeError::Sys {
                    call: WakeCall::Close,
                    error: SysError::Interrupted
                }),
                "{abi:?}: the interruption is reported as what it is, not retried into success"
            );
            let closes = ops
                .calls()
                .into_iter()
                .filter(|call| matches!(call, Call::Close { .. }))
                .count();
            assert_eq!(closes, 1, "{abi:?}");
        }

        // `close` succeeds with exactly 0.
        let mut ops = ScriptedOps::new().eventfd(7).close(3);
        let waker = eventfd_waker(&mut ops, MIPS);
        assert_eq!(
            waker.close(&mut ops, MIPS),
            Err(WakeError::Unexpected {
                call: WakeCall::Close,
                value: 3,
                expected: 0
            })
        );
    }

    // ---- an interrupted call, for every call the wake leaf issues (ffw-jub: "test absent syscalls and interrupted calls") ----
    //
    // `Waker` sends each call through `Abi::call_retrying`: the same call again while the kernel answers EINTR, at most
    // `MAX_INTERRUPTED_ATTEMPTS` times, then the error as `SysError::Interrupted`. The tests above reach that for a pipe write and for
    // `close` (which is never repeated). These cover the other five: `eventfd2` and `pipe2` at open, the eventfd write, and the eventfd
    // and self-pipe reads of a drain. Each runs on both ABIs and has the two halves: EINTR then the real answer (the repeated call is
    // identical), and an unending EINTR that stops after exactly the bound with nothing else tried (no other mechanism, no close).

    /// More interruptions than the bound, so a loop that did not stop would be seen asking for the next one.
    const STORM: usize = MAX_INTERRUPTED_ATTEMPTS as usize + 2;

    fn calls_of(ops: &ScriptedOps, kind: fn(&Call) -> bool) -> Vec<Call> {
        ops.calls().into_iter().filter(kind).collect()
    }

    fn is_write(call: &Call) -> bool {
        matches!(call, Call::Write { .. })
    }

    fn is_read(call: &Call) -> bool {
        matches!(call, Call::Read { .. })
    }

    #[test]
    fn an_interrupted_eventfd2_is_repeated_unchanged_then_reported_after_the_bound() {
        for (abi, nonblock) in [(PPC, 0x800u32), (MIPS, 0x80)] {
            let again = Call::Eventfd2 {
                initval: 0,
                flags: nonblock | O_CLOEXEC,
            };
            let mut ops = ScriptedOps::new().eventfd(-4).eventfd(-4).eventfd(7);
            let waker = eventfd_waker(&mut ops, abi);
            assert_eq!(waker.read_fd(), 7, "{abi:?}");
            assert_eq!(ops.calls(), vec![again.clone(); 3], "{abi:?}");

            let mut storm = ScriptedOps::new();
            for _ in 0..STORM {
                storm = storm.eventfd(-4);
            }
            assert_eq!(
                Waker::open(&mut storm, abi, ReactorWakeMechanism::EventFd),
                Err(WakeError::Sys {
                    call: WakeCall::Eventfd2,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            // Bounded, and nothing else was tried: no pipe2 in its place, no close of a descriptor that was never handed over.
            assert_eq!(
                storm.calls(),
                vec![again; MAX_INTERRUPTED_ATTEMPTS as usize],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn an_interrupted_pipe2_is_repeated_unchanged_then_reported_after_the_bound() {
        for (abi, nonblock) in [(PPC, 0x800u32), (MIPS, 0x80)] {
            let again = Call::Pipe2 {
                flags: nonblock | O_CLOEXEC,
            };
            let mut ops = ScriptedOps::new()
                .pipe(-4, [0, 0])
                .pipe(-4, [0, 0])
                .pipe(0, [5, 6]);
            let waker = pipe_waker(&mut ops, abi);
            assert_eq!(
                (waker.read_fd(), waker.mechanism()),
                (5, ReactorWakeMechanism::SelfPipe),
                "{abi:?}"
            );
            assert_eq!(ops.calls(), vec![again.clone(); 3], "{abi:?}");

            let mut storm = ScriptedOps::new();
            for _ in 0..STORM {
                storm = storm.pipe(-4, [0, 0]);
            }
            assert_eq!(
                Waker::open(&mut storm, abi, ReactorWakeMechanism::SelfPipe),
                Err(WakeError::Sys {
                    call: WakeCall::Pipe2,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(
                storm.calls(),
                vec![again; MAX_INTERRUPTED_ATTEMPTS as usize],
                "{abi:?}"
            );
        }
    }

    #[test]
    fn an_absence_that_follows_an_interruption_is_still_absence() {
        // The retry loop hands back the answer of the LAST attempt: an ENOSYS after an EINTR is absence in the guest's own
        // number, and no other mechanism is tried for it.
        let mut ops = ScriptedOps::new().eventfd(-4).eventfd(-38);
        assert_eq!(
            Waker::open(&mut ops, PPC, ReactorWakeMechanism::EventFd),
            Err(WakeError::Absent {
                call: WakeCall::Eventfd2
            })
        );
        assert_eq!(ops.calls().len(), 2, "no pipe2 after an absent eventfd2");

        let mut ops = ScriptedOps::new().pipe(-4, [0, 0]).pipe(-89, [0, 0]);
        assert_eq!(
            Waker::open(&mut ops, MIPS, ReactorWakeMechanism::SelfPipe),
            Err(WakeError::Absent {
                call: WakeCall::Pipe2
            })
        );
        assert_eq!(ops.calls().len(), 2, "no plain pipe after an absent pipe2");
    }

    #[test]
    fn an_interrupted_eventfd_write_is_repeated_with_the_same_counter_then_reported_after_the_bound()
     {
        for abi in [PPC, MIPS] {
            let one = Call::Write {
                fd: 7,
                bytes: 1u64.to_ne_bytes().to_vec(),
            };
            let mut ops = ScriptedOps::new().eventfd(7).write(-4).write(8);
            let waker = eventfd_waker(&mut ops, abi);
            assert_eq!(
                waker.signal(&mut ops, abi),
                Ok(WakeOutcome::Signalled),
                "{abi:?}"
            );
            assert_eq!(calls_of(&ops, is_write), vec![one.clone(); 2], "{abi:?}");

            let mut storm = ScriptedOps::new().eventfd(7);
            for _ in 0..STORM {
                storm = storm.write(-4);
            }
            let waker = eventfd_waker(&mut storm, abi);
            // An unending interruption is an error, not "a wake is already pending" (that is EAGAIN) and not a signal.
            assert_eq!(
                waker.signal(&mut storm, abi),
                Err(WakeError::Sys {
                    call: WakeCall::Write,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(
                calls_of(&storm, is_write),
                vec![one; MAX_INTERRUPTED_ATTEMPTS as usize],
                "{abi:?}"
            );
            // The filter above cannot see a stray `close` (the double answers one with 0): the opening call and the bound are every call.
            assert_eq!(
                storm.calls().len(),
                1 + MAX_INTERRUPTED_ATTEMPTS as usize,
                "{abi:?}"
            );
        }
    }

    #[test]
    fn an_interrupted_eventfd_read_is_repeated_then_reported_after_the_bound_and_is_not_nothing_pending()
     {
        for abi in [PPC, MIPS] {
            let read = Call::Read {
                fd: 7,
                cap: EVENTFD_COUNTER_BYTES,
            };
            let mut ops = ScriptedOps::new()
                .eventfd(7)
                .read(-4, &[])
                .read(8, &2u64.to_ne_bytes());
            let waker = eventfd_waker(&mut ops, abi);
            assert_eq!(
                waker.drain(&mut ops, abi),
                Ok(Drained {
                    wakes: 2,
                    more_pending: false
                }),
                "{abi:?}"
            );
            assert_eq!(calls_of(&ops, is_read), vec![read.clone(); 2], "{abi:?}");

            let mut storm = ScriptedOps::new().eventfd(7);
            for _ in 0..STORM {
                storm = storm.read(-4, &[]);
            }
            let waker = eventfd_waker(&mut storm, abi);
            // EAGAIN means nothing is pending and is a success; EINTR that never ends is not that, and is an error.
            assert_eq!(
                waker.drain(&mut storm, abi),
                Err(WakeError::Sys {
                    call: WakeCall::Read,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(
                calls_of(&storm, is_read),
                vec![read; MAX_INTERRUPTED_ATTEMPTS as usize],
                "{abi:?}"
            );
            assert_eq!(
                storm.calls().len(),
                1 + MAX_INTERRUPTED_ATTEMPTS as usize,
                "{abi:?}"
            );
            assert_eq!(
                storm.pending_read(),
                2,
                "{abi:?}: the rest was never asked for"
            );
        }
    }

    #[test]
    fn an_interrupted_self_pipe_read_is_repeated_then_reported_after_the_bound() {
        for abi in [PPC, MIPS] {
            let read = Call::Read {
                fd: 5,
                cap: PIPE_DRAIN_CHUNK,
            };
            // An interruption before the data and another before the EAGAIN that ends the drain: each is repeated, and the
            // bytes already read still count.
            let mut ops = ScriptedOps::new()
                .pipe(0, [5, 6])
                .read(-4, &[])
                .read(2, &[1, 1])
                .read(-4, &[])
                .read(-11, &[]);
            let waker = pipe_waker(&mut ops, abi);
            assert_eq!(
                waker.drain(&mut ops, abi),
                Ok(Drained {
                    wakes: 2,
                    more_pending: false
                }),
                "{abi:?}"
            );
            assert_eq!(calls_of(&ops, is_read), vec![read.clone(); 4], "{abi:?}");
            assert_eq!(ops.pending_read(), 0, "{abi:?}");

            let mut storm = ScriptedOps::new().pipe(0, [5, 6]);
            for _ in 0..STORM {
                storm = storm.read(-4, &[]);
            }
            let waker = pipe_waker(&mut storm, abi);
            assert_eq!(
                waker.drain(&mut storm, abi),
                Err(WakeError::Sys {
                    call: WakeCall::Read,
                    error: SysError::Interrupted
                }),
                "{abi:?}"
            );
            assert_eq!(
                calls_of(&storm, is_read),
                vec![read; MAX_INTERRUPTED_ATTEMPTS as usize],
                "{abi:?}"
            );
            assert_eq!(
                storm.calls().len(),
                1 + MAX_INTERRUPTED_ATTEMPTS as usize,
                "{abi:?}"
            );
            assert_eq!(
                storm.pending_read(),
                2,
                "{abi:?}: the rest was never asked for"
            );
        }
    }

    #[test]
    fn the_bound_every_count_above_is_relative_to_is_the_contracts_eight() {
        // Each count above is relative to the constant, so moving it would leave them green. The contract says 8 in two places
        // (docs/contracts/p02.md: "repeated at most `MAX_INTERRUPTED_ATTEMPTS` (8) times"; the `-EINTR` row): move the constant, move that text.
        assert_eq!(MAX_INTERRUPTED_ATTEMPTS, 8);
    }
}
