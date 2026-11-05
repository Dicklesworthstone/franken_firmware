#![no_std]
#![forbid(unsafe_code)]

/// Pure verdict logic for the E03 guest capability probes (the syscalls live in `e03_probes.rs`).
pub mod e03_judge;

/// Pure verdict logic for the E03 runtime-behavior probes (threads, TLS, signals, timers, allocator, rename,
/// atomic width; the syscalls live in `e03_probes_rt.rs`).
pub mod e03_judge_rt;

/// Why bounded output stopped before delivering every byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteCause {
    Syscall(isize),
    ZeroProgress,
    InvalidCount,
    AttemptLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteFailure {
    pub written: usize,
    pub cause: WriteCause,
}

/// Advance only by bytes actually written; retry EINTR within a fixed budget.
///
/// The injected operation follows the bootstrap's normalized syscall contract:
/// a byte count on success or a negative errno. EAGAIN is returned to the
/// caller, never spun on. This helper bounds attempts, not a blocking syscall's
/// duration; the external guest watchdog provides the wall-clock bound.
pub fn write_all_with(
    bytes: &[u8],
    attempts: usize,
    mut write: impl FnMut(&[u8]) -> isize,
) -> Result<(), WriteFailure> {
    let mut written = 0;
    for _ in 0..attempts {
        if written == bytes.len() {
            return Ok(());
        }
        let count = write(&bytes[written..]);
        let cause = if count == -4 {
            continue; // EINTR on both bootstrap Linux ABIs.
        } else if count < 0 {
            Some(WriteCause::Syscall(count))
        } else if count == 0 {
            Some(WriteCause::ZeroProgress)
        } else if count as usize > bytes.len() - written {
            Some(WriteCause::InvalidCount)
        } else {
            written += count as usize;
            None
        };
        if let Some(cause) = cause {
            return Err(WriteFailure { written, cause });
        }
    }
    if written == bytes.len() {
        Ok(())
    } else {
        Err(WriteFailure {
            written,
            cause: WriteCause::AttemptLimit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_writes_and_interrupts_preserve_exact_bytes() {
        let mut output = [0u8; 6];
        let mut cursor = 0;
        let mut call = 0;
        let result = write_all_with(b"abcdef", 5, |remaining| {
            call += 1;
            if call == 1 || call == 3 {
                return -4;
            }
            let count = remaining.len().min(2);
            output[cursor..cursor + count].copy_from_slice(&remaining[..count]);
            cursor += count;
            count as isize
        });
        assert_eq!(result, Ok(()));
        assert_eq!(&output, b"abcdef");
        assert_eq!(call, 5);
    }

    #[test]
    fn failure_preserves_resume_offset_without_resending_prefix() {
        let mut calls = 0;
        let result = write_all_with(b"abcd", 10, |remaining| {
            calls += 1;
            if calls == 1 {
                2
            } else {
                assert_eq!(remaining, b"cd");
                -11
            }
        });
        assert_eq!(
            result,
            Err(WriteFailure {
                written: 2,
                cause: WriteCause::Syscall(-11)
            })
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn interruption_storm_terminates() {
        let mut calls = 0;
        let result = write_all_with(b"x", 7, |_| {
            calls += 1;
            -4
        });
        assert_eq!(
            result,
            Err(WriteFailure {
                written: 0,
                cause: WriteCause::AttemptLimit
            })
        );
        assert_eq!(calls, 7);
    }

    #[test]
    fn zero_progress_is_not_success() {
        assert_eq!(
            write_all_with(b"x", 7, |_| 0),
            Err(WriteFailure {
                written: 0,
                cause: WriteCause::ZeroProgress
            })
        );
    }

    #[test]
    fn impossible_count_does_not_advance_or_panic() {
        assert_eq!(
            write_all_with(b"x", 1, |_| 2),
            Err(WriteFailure {
                written: 0,
                cause: WriteCause::InvalidCount
            })
        );
    }

    #[test]
    fn empty_output_needs_no_syscall_or_budget() {
        assert_eq!(write_all_with(b"", 0, |_| panic!("must not write")), Ok(()));
    }

    #[test]
    fn zero_budget_does_not_issue_io() {
        assert_eq!(
            write_all_with(b"x", 0, |_| panic!("must not write")),
            Err(WriteFailure {
                written: 0,
                cause: WriteCause::AttemptLimit
            })
        );
    }
}
