//! One finite `poll` wait through the legacy kernel seam (`P02`).
//!
//! [`poll_once`] validates at most [`MAX_POLL_FDS`] descriptors, clears stale output, issues one raw
//! call, and checks both the returned event masks and the number of descriptors with events. A
//! count alone is never readiness evidence. Error, hangup, and invalid-descriptor bits are exposed
//! to the owner for fault handling; [`WaitOutcome::Ready`] does not mean an I/O operation succeeded.
//! An oversized array is refused before any element is touched; its unchanged output is never
//! readiness evidence from this call.
//!
//! [`PollTimeout`] permits zero through [`MAX_POLL_TIMEOUT_MS`] milliseconds, never the kernel's
//! infinite-wait sentinel. Converting a [`Duration`] rounds a positive fraction of a millisecond
//! upward. That quantization, kernel timer resolution, and scheduler overshoot mean this is not a
//! whole-driver or wall-clock deadline guarantee. An interrupted wait is returned without retry:
//! the owner must re-read its admitted clock and recompute its remaining deadline before another
//! call. There is no alternate wait mechanism or fallback here.
//!
//! This policy and its scripted unit tests do not admit a kernel, qualify a Linux leaf, or prove
//! guest or hardware execution. The descriptor array and all policy bookkeeping are caller-owned
//! or on the stack; the boundary allocates nothing.

use std::time::Duration;

use crate::abi::{Abi, SysError};

/// Request or return ordinary readable data (`POLLIN`).
pub const READABLE: i16 = 1;
/// Request or return priority data (`POLLPRI`).
pub const PRIORITY: i16 = 2;
/// Request or return writable space (`POLLOUT`).
pub const WRITABLE: i16 = 4;
/// A returned error (`POLLERR`), whether or not requested.
pub const ERROR: i16 = 8;
/// A returned hangup (`POLLHUP`), whether or not requested.
pub const HANGUP: i16 = 16;
/// A returned invalid descriptor (`POLLNVAL`), whether or not requested.
pub const INVALID: i16 = 32;

/// Maximum descriptors issued in one wait.
pub const MAX_POLL_FDS: usize = 16;
/// Longest interval accepted for one kernel wait, in milliseconds.
pub const MAX_POLL_TIMEOUT_MS: u32 = 1_000;

const REQUEST_EVENTS: i16 = READABLE | PRIORITY | WRITABLE;
const RETURN_EVENTS: i16 = REQUEST_EVENTS | ERROR | HANGUP | INVALID;

/// The Linux `pollfd` layout on both supported legacy ABIs.
///
/// `fd` and `events` are inputs, and `revents` is output. A raw backend must preserve the inputs.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

const _: () = {
    assert!(std::mem::size_of::<PollFd>() == 8);
    assert!(std::mem::align_of::<PollFd>() == 4);
};

/// A validated finite kernel timeout in milliseconds. The field is deliberately private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollTimeout(u32);

impl PollTimeout {
    /// Validate a timeout in milliseconds. Zero requests an immediate, nonblocking poll.
    ///
    /// # Errors
    /// [`WaitError::TimeoutTooLong`] above [`MAX_POLL_TIMEOUT_MS`].
    pub const fn new(milliseconds: u32) -> Result<Self, WaitError> {
        if milliseconds > MAX_POLL_TIMEOUT_MS {
            Err(WaitError::TimeoutTooLong)
        } else {
            Ok(Self(milliseconds))
        }
    }

    /// The validated value the raw backend passes to the kernel, always in `0..=1000`.
    #[must_use]
    pub const fn as_millis(self) -> u32 {
        self.0
    }
}

impl TryFrom<Duration> for PollTimeout {
    type Error = WaitError;

    /// Round up to whole milliseconds, refusing a duration above the finite bound.
    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        // Reject before any rounding or narrowing, including Duration::MAX.
        if duration > Duration::from_millis(u64::from(MAX_POLL_TIMEOUT_MS)) {
            return Err(WaitError::TimeoutTooLong);
        }
        let milliseconds =
            duration.as_millis() + u128::from(!duration.subsec_nanos().is_multiple_of(1_000_000));
        let milliseconds = u32::try_from(milliseconds).map_err(|_| WaitError::TimeoutTooLong)?;
        Self::new(milliseconds)
    }
}

/// One raw finite `poll` call. No retry, emulation, or alternate mechanism is allowed here.
///
/// The backend passes the slice and validated timeout unchanged, returns a nonnegative descriptor
/// count or raw `-errno`, and modifies only `revents`. In particular it must preserve every `fd`
/// and requested `events` value even on failure. [`poll_once`] owns validation and error decoding.
pub trait WaitOps {
    fn poll(&mut self, fds: &mut [PollFd], timeout: PollTimeout) -> isize;
}

/// The validated result of one finite wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The raw count was zero and every returned event mask was zero.
    TimedOut,
    /// Exactly this many descriptors have a nonzero, validated `revents` mask.
    /// The owner must inspect those masks, including [`ERROR`], [`HANGUP`], and [`INVALID`].
    Ready { ready: usize },
}

/// An argument refusal, decoded kernel error, or malformed successful answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WaitError {
    /// The admitted layer did not observe support for this particular poll route. The raw helper
    /// does not make admission decisions; the layer checks this before delegating to it.
    #[error("poll route is not admitted ({observed:?})")]
    NotAdmitted { observed: crate::CapabilityStatus },
    #[error("poll timeout exceeds the finite millisecond bound")]
    TimeoutTooLong,
    #[error("poll has {count} descriptors, above the finite descriptor bound")]
    TooManyDescriptors { count: usize },
    #[error("poll descriptor {index} is negative ({fd})")]
    NegativeDescriptor { index: usize, fd: i32 },
    #[error("poll descriptors {first} and {second} repeat descriptor {fd}")]
    DuplicateDescriptor {
        first: usize,
        second: usize,
        fd: i32,
    },
    #[error("poll descriptor {index} requests unsupported event bits ({events})")]
    UnsupportedEvents { index: usize, events: i16 },
    #[error("poll: {0}")]
    Sys(SysError),
    #[error("poll returned count {returned} for {slots} descriptors")]
    CountOutOfRange { returned: usize, slots: usize },
    #[error("poll descriptor {index} returned unknown event bits ({events})")]
    UnknownReturnedEvents { index: usize, events: i16 },
    #[error(
        "poll descriptor {index} returned unrequested readiness bits ({events}); requested {requested}"
    )]
    UnrequestedEvents {
        index: usize,
        events: i16,
        requested: i16,
    },
    #[error("poll backend changed descriptor inputs at index {index}")]
    InputChanged { index: usize },
    #[error("poll returned count {returned} but {observed} descriptors have events")]
    CountMismatch { returned: usize, observed: usize },
}

/// Issue one finite wait after validating its descriptor array.
///
/// Negative and duplicate descriptors, unsupported requested bits, and an oversized array are
/// refused before any backend call. Zero requested events is allowed, so an owner can observe
/// fault bits alone. Readable, priority, and writable return bits must have been requested;
/// error, hangup, and invalid-descriptor bits may arrive without a request.
///
/// An oversized array is refused before any element is read or written. It remains unchanged,
/// including stale output, which is never readiness evidence from this call. For arrays within
/// [`MAX_POLL_FDS`], stale `revents` are cleared before further validation and every output is
/// cleared on any error. This function never changes the input descriptors or requested masks;
/// preserving those inputs is also a requirement of [`WaitOps`]. The policy snapshots and
/// restores them after the call, and refuses a successful backend answer that changed them.
/// An empty array is allowed for a finite timeout-only wait.
///
/// # Errors
/// [`WaitError`] on an invalid argument, any decoded kernel error (including an un-retried
/// [`SysError::Interrupted`]), an invalid returned event mask, or an inconsistent returned count.
pub fn poll_once<O: WaitOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    slots: &mut [PollFd],
    timeout: PollTimeout,
) -> Result<WaitOutcome, WaitError> {
    if slots.len() > MAX_POLL_FDS {
        return Err(WaitError::TooManyDescriptors { count: slots.len() });
    }
    clear_events(slots);
    let mut original = [PollFd::default(); MAX_POLL_FDS];
    original[..slots.len()].copy_from_slice(slots);
    let result = (|| {
        for (index, slot) in slots.iter().enumerate() {
            if slot.fd < 0 {
                return Err(WaitError::NegativeDescriptor { index, fd: slot.fd });
            }
            if slot.events & !REQUEST_EVENTS != 0 {
                return Err(WaitError::UnsupportedEvents {
                    index,
                    events: slot.events,
                });
            }
            if let Some(first) = slots[..index].iter().position(|other| other.fd == slot.fd) {
                return Err(WaitError::DuplicateDescriptor {
                    first,
                    second: index,
                    fd: slot.fd,
                });
            }
        }

        let raw = ops.poll(slots, timeout);
        // Enforce the backend contract as well as relying on it: preserve the caller's inputs
        // on every return, and never validate readiness against a backend-edited request mask.
        let mut changed_input = None;
        for (index, slot) in slots.iter_mut().enumerate() {
            let before = original[index];
            if slot.fd != before.fd || slot.events != before.events {
                changed_input.get_or_insert(index);
            }
            slot.fd = before.fd;
            slot.events = before.events;
        }
        let returned = abi.decode(raw).map_err(WaitError::Sys)?;
        if returned > slots.len() {
            return Err(WaitError::CountOutOfRange {
                returned,
                slots: slots.len(),
            });
        }
        let mut observed = 0;
        for (index, slot) in slots.iter().enumerate() {
            if slot.revents & !RETURN_EVENTS != 0 {
                return Err(WaitError::UnknownReturnedEvents {
                    index,
                    events: slot.revents,
                });
            }
            if slot.revents & REQUEST_EVENTS & !slot.events != 0 {
                return Err(WaitError::UnrequestedEvents {
                    index,
                    events: slot.revents,
                    requested: slot.events,
                });
            }
            observed += usize::from(slot.revents != 0);
        }
        if let Some(index) = changed_input {
            return Err(WaitError::InputChanged { index });
        }
        if returned != observed {
            return Err(WaitError::CountMismatch { returned, observed });
        }
        Ok(if returned == 0 {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Ready { ready: returned }
        })
    })();
    if result.is_err() {
        clear_events(slots);
    }
    result
}

fn clear_events(slots: &mut [PollFd]) {
    for slot in slots {
        slot.revents = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    /// A raw scripted answer, with fixed storage and a call counter. It checks that the policy
    /// removed stale output before making the call and records the exact inputs it received.
    struct ScriptedWait {
        raw: isize,
        revents: [i16; MAX_POLL_FDS],
        calls: usize,
        received: [PollFd; MAX_POLL_FDS],
        received_len: usize,
        timeout: Option<PollTimeout>,
    }

    impl ScriptedWait {
        fn answer(raw: isize, revents: &[i16]) -> Self {
            let mut answer = Self {
                raw,
                revents: [0; MAX_POLL_FDS],
                calls: 0,
                received: [PollFd::default(); MAX_POLL_FDS],
                received_len: 0,
                timeout: None,
            };
            answer.revents[..revents.len()].copy_from_slice(revents);
            answer
        }
    }

    impl WaitOps for ScriptedWait {
        fn poll(&mut self, fds: &mut [PollFd], timeout: PollTimeout) -> isize {
            self.calls += 1;
            assert!(
                fds.iter().all(|slot| slot.revents == 0),
                "stale output reached the backend"
            );
            self.received_len = fds.len();
            self.received[..fds.len()].copy_from_slice(fds);
            self.timeout = Some(timeout);
            for (slot, revents) in fds.iter_mut().zip(self.revents) {
                slot.revents = revents;
            }
            self.raw
        }
    }

    fn timeout() -> PollTimeout {
        PollTimeout::new(37).unwrap()
    }

    fn slots<const N: usize>() -> [PollFd; N] {
        std::array::from_fn(|index| PollFd {
            fd: i32::try_from(index).unwrap(),
            events: READABLE,
            revents: -1,
        })
    }

    fn assert_inputs_unchanged(before: &[PollFd], after: &[PollFd]) {
        assert_eq!(before.len(), after.len());
        for (before, after) in before.iter().zip(after) {
            assert_eq!((before.fd, before.events), (after.fd, after.events));
        }
    }

    fn assert_refused_without_call(mut fds: impl AsMut<[PollFd]>, expected: WaitError) {
        for abi in BOTH {
            let slots = fds.as_mut();
            slots.iter_mut().for_each(|slot| slot.revents = -1);
            let mut ops = ScriptedWait::answer(0, &[]);
            assert_eq!(
                poll_once(&mut ops, abi, slots, timeout()),
                Err(expected),
                "{abi:?}"
            );
            assert_eq!(ops.calls, 0, "invalid input reached the backend");
            assert!(slots.iter().all(|slot| slot.revents == 0));
        }
    }

    #[test]
    fn pollfd_layout_and_flag_values_match_the_legacy_kernel_contract() {
        assert_eq!(std::mem::size_of::<PollFd>(), 8);
        assert_eq!(std::mem::align_of::<PollFd>(), 4);
        assert_eq!(std::mem::offset_of!(PollFd, fd), 0);
        assert_eq!(std::mem::offset_of!(PollFd, events), 4);
        assert_eq!(std::mem::offset_of!(PollFd, revents), 6);
        assert_eq!(
            [READABLE, PRIORITY, WRITABLE, ERROR, HANGUP, INVALID],
            [1, 2, 4, 8, 16, 32]
        );
    }

    #[test]
    fn finite_wait_and_p06_wire_model_share_the_kernel_layout_and_common_flags() {
        use crate::net;
        assert_eq!(
            [READABLE, PRIORITY, WRITABLE, ERROR, HANGUP, INVALID].map(|bit| bit as u16),
            [
                net::POLLIN,
                net::POLLPRI,
                net::POLLOUT,
                net::POLLERR,
                net::POLLHUP,
                net::POLLNVAL
            ]
        );
        assert_eq!(std::mem::size_of::<PollFd>(), net::POLLFD_LEN);
        const { assert!(MAX_POLL_TIMEOUT_MS <= net::POLL_MAX_FINITE_MS) };
    }

    #[test]
    fn backend_cannot_authorize_its_own_unrequested_readiness_by_editing_events() {
        struct EditingWait;
        impl WaitOps for EditingWait {
            fn poll(&mut self, fds: &mut [PollFd], _: PollTimeout) -> isize {
                fds[0].events |= WRITABLE;
                fds[0].revents = WRITABLE;
                1
            }
        }
        for abi in BOTH {
            let mut fds = slots::<1>();
            let before = fds;
            assert_eq!(
                poll_once(&mut EditingWait, abi, &mut fds, timeout()),
                Err(WaitError::UnrequestedEvents {
                    index: 0,
                    events: WRITABLE,
                    requested: READABLE
                })
            );
            assert_inputs_unchanged(&before, &fds);
            assert_eq!(fds[0].revents, 0);
        }
    }

    #[test]
    fn backend_input_edits_are_restored_on_success_and_error_and_never_count_as_readiness() {
        struct EditingWait {
            raw: isize,
            edit_fd: bool,
        }
        impl WaitOps for EditingWait {
            fn poll(&mut self, fds: &mut [PollFd], _: PollTimeout) -> isize {
                if self.edit_fd {
                    fds[0].fd += 1;
                } else {
                    fds[0].events |= WRITABLE;
                }
                fds[0].revents = READABLE;
                self.raw
            }
        }
        for abi in BOTH {
            for edit_fd in [false, true] {
                for raw in [1, -4] {
                    let mut fds = slots::<1>();
                    let before = fds;
                    let expected = if raw < 0 {
                        WaitError::Sys(SysError::Interrupted)
                    } else {
                        WaitError::InputChanged { index: 0 }
                    };
                    assert_eq!(
                        poll_once(&mut EditingWait { raw, edit_fd }, abi, &mut fds, timeout()),
                        Err(expected)
                    );
                    assert_inputs_unchanged(&before, &fds);
                    assert_eq!(fds[0].revents, 0);
                }
            }
        }
    }

    #[test]
    fn readable_data_and_a_clean_timeout_are_distinct_single_calls() {
        for abi in BOTH {
            for (raw, revents, expected) in [
                (1, READABLE, WaitOutcome::Ready { ready: 1 }),
                (0, 0, WaitOutcome::TimedOut),
            ] {
                let mut fds = slots::<1>();
                let before = fds;
                let mut ops = ScriptedWait::answer(raw, &[revents]);
                assert_eq!(poll_once(&mut ops, abi, &mut fds, timeout()), Ok(expected));
                assert_eq!(ops.calls, 1);
                assert_eq!(ops.timeout, Some(timeout()));
                assert_eq!(
                    ops.received[0],
                    PollFd {
                        fd: 0,
                        events: READABLE,
                        revents: 0
                    }
                );
                assert_eq!(fds[0].revents, revents);
                assert_inputs_unchanged(&before, &fds);
            }
        }
    }

    #[test]
    fn zero_timeout_reaches_the_backend_without_becoming_infinite() {
        for abi in BOTH {
            let mut ops = ScriptedWait::answer(0, &[]);
            assert_eq!(
                poll_once(&mut ops, abi, &mut [], PollTimeout::new(0).unwrap()),
                Ok(WaitOutcome::TimedOut)
            );
            assert_eq!(ops.calls, 1);
            assert_eq!(ops.timeout.unwrap().as_millis(), 0);
        }
    }

    #[test]
    fn writable_priority_and_combined_requested_readiness_are_preserved() {
        for abi in BOTH {
            for events in [WRITABLE, PRIORITY, READABLE | WRITABLE | PRIORITY] {
                let mut fds = [PollFd {
                    fd: i32::MAX,
                    events,
                    revents: -1,
                }];
                let mut ops = ScriptedWait::answer(1, &[events]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Ok(WaitOutcome::Ready { ready: 1 })
                );
                assert_eq!(fds[0].revents, events);
            }
        }
    }

    #[test]
    fn fault_bits_are_exposed_even_with_no_requested_events() {
        for abi in BOTH {
            for revents in [ERROR, HANGUP, INVALID, ERROR | HANGUP | INVALID] {
                let mut fds = [PollFd {
                    fd: 3,
                    events: 0,
                    revents: -1,
                }];
                let mut ops = ScriptedWait::answer(1, &[revents]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Ok(WaitOutcome::Ready { ready: 1 })
                );
                assert_eq!(fds[0].revents, revents);
            }
        }
    }

    #[test]
    fn combined_fault_and_requested_bits_count_descriptors_rather_than_bits() {
        for abi in BOTH {
            let mut fds = slots::<3>();
            let mut ops = ScriptedWait::answer(2, &[READABLE | ERROR | HANGUP, 0, INVALID]);
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Ok(WaitOutcome::Ready { ready: 2 })
            );
            assert_eq!(
                [fds[0].revents, fds[1].revents, fds[2].revents],
                [READABLE | ERROR | HANGUP, 0, INVALID]
            );
        }
    }

    #[test]
    fn zero_one_and_sixteen_slots_are_allowed_but_seventeen_never_reach_the_backend() {
        for abi in BOTH {
            for count in [0, 1, MAX_POLL_FDS - 1, MAX_POLL_FDS] {
                let mut fds = slots::<MAX_POLL_FDS>();
                let mut ops = ScriptedWait::answer(0, &[]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds[..count], timeout()),
                    Ok(WaitOutcome::TimedOut)
                );
                assert_eq!((ops.calls, ops.received_len), (1, count));
            }
            let mut fds = slots::<MAX_POLL_FDS>();
            let mut ops = ScriptedWait::answer(16, &[READABLE; MAX_POLL_FDS]);
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Ok(WaitOutcome::Ready { ready: 16 })
            );
            let mut oversized = slots::<64>();
            let before = oversized;
            for count in [17, 64] {
                let mut ops = ScriptedWait::answer(0, &[]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut oversized[..count], timeout()),
                    Err(WaitError::TooManyDescriptors { count })
                );
                assert_eq!(ops.calls, 0, "an oversized array reached the backend");
                assert_eq!(oversized, before, "oversized input or stale output changed");
            }
        }
    }

    #[test]
    fn negative_descriptors_are_refused_without_touching_the_kernel() {
        for fd in [-1, i32::MIN] {
            let mut fds = slots::<3>();
            fds[1].fd = fd;
            assert_refused_without_call(fds, WaitError::NegativeDescriptor { index: 1, fd });
        }
    }

    #[test]
    fn duplicate_descriptors_are_refused_even_when_their_requests_differ() {
        let mut fds = slots::<MAX_POLL_FDS>();
        fds[MAX_POLL_FDS - 1].fd = 0;
        fds[MAX_POLL_FDS - 1].events = WRITABLE;
        assert_refused_without_call(
            fds,
            WaitError::DuplicateDescriptor {
                first: 0,
                second: MAX_POLL_FDS - 1,
                fd: 0,
            },
        );
    }

    #[test]
    fn faults_unknown_bits_and_signed_masks_cannot_be_requested() {
        for events in [ERROR, HANGUP, INVALID, 64, i16::MIN, -1, READABLE | ERROR] {
            let mut fds = slots::<3>();
            fds[1].events = events;
            assert_refused_without_call(fds, WaitError::UnsupportedEvents { index: 1, events });
        }
    }

    #[test]
    fn each_abis_eintr_eagain_enosys_and_other_errors_return_after_one_call() {
        for abi in BOTH {
            for (raw, expected) in [
                (-4, SysError::Interrupted),
                (-11, SysError::WouldBlock),
                (-(abi.enosys() as isize), SysError::Absent),
                (-22, SysError::Invalid),
                (-9, SysError::Errno(9)),
            ] {
                let mut fds = slots::<2>();
                let before = fds;
                let mut ops = ScriptedWait::answer(raw, &[READABLE, ERROR]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Err(WaitError::Sys(expected)),
                    "{abi:?}"
                );
                assert_eq!(ops.calls, 1, "a failed finite wait was retried");
                assert!(fds.iter().all(|slot| slot.revents == 0));
                assert_inputs_unchanged(&before, &fds);
            }
        }
    }

    #[test]
    fn the_other_abis_enosys_number_is_not_absence() {
        for (abi, raw, errno) in [(Abi::PowerPc32, -89, 89), (Abi::Mips32, -38, 38)] {
            let mut ops = ScriptedWait::answer(raw, &[READABLE]);
            let mut fds = slots::<1>();
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Err(WaitError::Sys(SysError::Errno(errno)))
            );
            assert_eq!(ops.calls, 1);
            assert_eq!(fds[0].revents, 0);
        }
    }

    #[test]
    fn malformed_negative_returns_are_errors_and_clear_partial_output() {
        for abi in BOTH {
            for raw in [-4096, isize::MIN] {
                let mut ops = ScriptedWait::answer(raw, &[READABLE]);
                let mut fds = slots::<1>();
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Err(WaitError::Sys(SysError::Malformed(raw)))
                );
                assert_eq!(ops.calls, 1);
                assert_eq!(fds[0].revents, 0);
            }
        }
    }

    #[test]
    fn a_count_larger_than_the_array_is_not_readiness() {
        for abi in BOTH {
            for returned in [3, isize::MAX] {
                let mut fds = slots::<2>();
                let mut ops = ScriptedWait::answer(returned, &[READABLE, READABLE]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Err(WaitError::CountOutOfRange {
                        returned: returned.unsigned_abs(),
                        slots: 2
                    })
                );
                assert_eq!(ops.calls, 1);
                assert!(fds.iter().all(|slot| slot.revents == 0));
            }
            let mut ops = ScriptedWait::answer(1, &[]);
            assert_eq!(
                poll_once(&mut ops, abi, &mut [], timeout()),
                Err(WaitError::CountOutOfRange {
                    returned: 1,
                    slots: 0
                })
            );
        }
    }

    #[test]
    fn zero_with_events_or_positive_with_wrong_nonzero_count_is_refused() {
        for abi in BOTH {
            for (returned, revents, observed) in [
                (0, [READABLE, 0], 1),
                (1, [0, 0], 0),
                (1, [READABLE, ERROR], 2),
                (2, [READABLE, 0], 1),
            ] {
                let mut fds = slots::<2>();
                let before = fds;
                let mut ops = ScriptedWait::answer(returned, &revents);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Err(WaitError::CountMismatch {
                        returned: returned.unsigned_abs(),
                        observed
                    })
                );
                assert!(fds.iter().all(|slot| slot.revents == 0));
                assert_inputs_unchanged(&before, &fds);
            }
        }
    }

    #[test]
    fn unknown_returned_bits_in_any_slot_clear_every_output() {
        for abi in BOTH {
            for events in [64, READABLE | 64, i16::MIN, -1] {
                let mut fds = slots::<3>();
                let mut ops = ScriptedWait::answer(2, &[READABLE, 0, events]);
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Err(WaitError::UnknownReturnedEvents { index: 2, events })
                );
                assert!(fds.iter().all(|slot| slot.revents == 0));
            }
        }
    }

    #[test]
    fn each_unrequested_readiness_bit_is_refused_even_with_a_valid_fault_bit() {
        for abi in BOTH {
            for events in [READABLE, PRIORITY, WRITABLE] {
                for faults in [0, ERROR | HANGUP | INVALID] {
                    let mut fds = [PollFd {
                        fd: 7,
                        events: REQUEST_EVENTS & !events,
                        revents: -1,
                    }];
                    let mut ops = ScriptedWait::answer(1, &[events | faults]);
                    assert_eq!(
                        poll_once(&mut ops, abi, &mut fds, timeout()),
                        Err(WaitError::UnrequestedEvents {
                            index: 0,
                            events: events | faults,
                            requested: REQUEST_EVENTS & !events
                        })
                    );
                    assert_eq!(fds[0].revents, 0);
                }
            }
        }
    }

    #[test]
    fn every_allowed_return_mask_is_accepted_when_its_readiness_was_requested() {
        for abi in BOTH {
            for events in 0..=63 {
                let mut fds = [PollFd {
                    fd: 9,
                    events: events & 7,
                    revents: -1,
                }];
                let raw = isize::from(events != 0);
                let mut ops = ScriptedWait::answer(raw, &[events]);
                let expected = if events == 0 {
                    WaitOutcome::TimedOut
                } else {
                    WaitOutcome::Ready { ready: 1 }
                };
                assert_eq!(
                    poll_once(&mut ops, abi, &mut fds, timeout()),
                    Ok(expected),
                    "{abi:?}: mask {events}"
                );
                assert_eq!(fds[0].revents, events);
            }
        }
    }

    #[test]
    fn a_later_timeout_or_failure_cannot_reuse_a_previous_calls_readiness() {
        for abi in BOTH {
            let mut fds = slots::<1>();
            let mut ops = ScriptedWait::answer(1, &[READABLE]);
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Ok(WaitOutcome::Ready { ready: 1 })
            );
            ops.raw = 0;
            ops.revents = [0; MAX_POLL_FDS];
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Ok(WaitOutcome::TimedOut)
            );
            assert_eq!(fds[0].revents, 0);
            fds[0].revents = READABLE;
            ops.raw = -4;
            assert_eq!(
                poll_once(&mut ops, abi, &mut fds, timeout()),
                Err(WaitError::Sys(SysError::Interrupted))
            );
            assert_eq!(fds[0].revents, 0);
            assert_eq!(ops.calls, 3);
        }
    }

    #[test]
    fn the_timeout_constructor_accepts_zero_through_the_bound_only() {
        for milliseconds in [0, 1, 999, 1_000] {
            assert_eq!(
                PollTimeout::new(milliseconds).unwrap().as_millis(),
                milliseconds
            );
        }
        for milliseconds in [1_001, u32::MAX] {
            assert_eq!(
                PollTimeout::new(milliseconds),
                Err(WaitError::TimeoutTooLong)
            );
        }
    }

    #[test]
    fn duration_conversion_rounds_up_without_extending_the_finite_bound() {
        for (duration, milliseconds) in [
            (Duration::ZERO, 0),
            (Duration::from_nanos(1), 1),
            (Duration::from_nanos(999_999), 1),
            (Duration::from_millis(1), 1),
            (Duration::from_nanos(1_000_001), 2),
            (Duration::from_nanos(999_000_001), 1_000),
            (Duration::from_secs(1), 1_000),
        ] {
            assert_eq!(
                PollTimeout::try_from(duration).unwrap().as_millis(),
                milliseconds,
                "{duration:?}"
            );
        }
        for duration in [
            Duration::from_nanos(1_000_000_001),
            Duration::from_millis(1_001),
            Duration::MAX,
        ] {
            assert_eq!(
                PollTimeout::try_from(duration),
                Err(WaitError::TimeoutTooLong),
                "{duration:?}"
            );
        }
    }
}
