//! Pure verdict and wire-format logic for the franken-speaker smoke step (E07 runner change).
//!
//! `speaker_smoke.rs` in the PID 1 binary issues the syscalls (feature `speaker-smoke`); nothing here touches
//! the kernel, so every function is unit tested on the host. The output grammar is pinned a second time, in
//! Python, by `toolchain/src/run-qemu-verification.py`, and the example lines below appear verbatim in both
//! test suites.
//!
//! PID 1 prints one line after the child has been reaped:
//!
//! ```text
//! FFW_SPEAKER_EXIT status=0 stdout_bytes=<N> stdout_fnv1a64=<16 hex>    the only success line (N >= 1)
//! FFW_SPEAKER_EXIT status=<1..255> stdout_bytes=<N> stdout_fnv1a64=<16 hex>
//! FFW_SPEAKER_EXIT signal=<n> stdout_bytes=<N> stdout_fnv1a64=<16 hex>
//! FFW_SPEAKER_EXIT spawn=<pipe|fork|exec> errno=<n>
//! FFW_SPEAKER_EXIT read_error=<errno> | wait_error=<errno> | wait_status=<raw> | exec_probe_error=<|rc|>
//!     (each followed by the stdout_bytes / stdout_fnv1a64 pair)
//! ```
//!
//! `stdout_bytes` and `stdout_fnv1a64` describe the raw bytes the child wrote to its stdout, measured in the
//! guest before they are forwarded to the console. The runner recomputes both from the console transcript, so
//! a serial transcript that was corrupted, truncated or interleaved with other output does not verify.

/// FNV-1a, 64 bit. Not a security primitive: it ties the console transcript to the bytes the child wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fnv1a64(u64);

impl Fnv1a64 {
    pub const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    pub const PRIME: u64 = 0x0000_0100_0000_01b3;

    #[must_use]
    pub const fn new() -> Self {
        Self(Self::OFFSET)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    #[must_use]
    pub const fn finish(&self) -> u64 {
        self.0
    }
}

impl Default for Fnv1a64 {
    fn default() -> Self {
        Self::new()
    }
}

/// How `wait4` reported the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    Exited(u8),
    Signaled(u8),
    /// Stopped, continued or otherwise not a termination (`wait4` was called without `WUNTRACED`).
    Other(i32),
}

/// Decode a Linux wait status word (the same layout on MIPS and PowerPC).
#[must_use]
pub fn decode_wait_status(raw: i32) -> WaitStatus {
    let low = raw & 0x7f;
    if low == 0 {
        WaitStatus::Exited(((raw >> 8) & 0xff) as u8)
    } else if (raw & 0xff) == 0x7f || low == 0x7f {
        WaitStatus::Other(raw)
    } else {
        // Bit 7 is the core-dump flag; the low seven bits are the terminating signal.
        WaitStatus::Signaled(low as u8)
    }
}

/// What the exec-error pipe said once the child was gone. The child writes its `execve` errno there (four
/// bytes, big-endian) only if `execve` returned; a successful `execve` writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecProbe {
    Ran,
    Failed(u32),
    Unreadable(isize),
}

/// `read_rc` is the nonblocking read of the error pipe, taken after the child was reaped. `0` is end of file
/// (every writer closed, nothing written) and `-11` is EAGAIN (a stray writer is still open, nothing written);
/// both mean `execve` did not fail. EAGAIN is 11 on both bootstrap ABIs.
#[must_use]
pub fn decode_exec_probe(read_rc: isize, buf: [u8; 4]) -> ExecProbe {
    match read_rc {
        0 | -11 => ExecProbe::Ran,
        4 => ExecProbe::Failed(u32::from_be_bytes(buf)),
        other => ExecProbe::Unreadable(other),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnStage {
    Pipe,
    Fork,
    Exec,
}

impl SpawnStage {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Fork => "fork",
            Self::Exec => "exec",
        }
    }
}

/// The child's stdout as the guest measured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    pub bytes: u32,
    pub fnv1a64: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The program never ran. `Exec` also covers a failure of `dup2` in the child, which is reported through
    /// the same error pipe.
    Spawn {
        stage: SpawnStage,
        errno: u32,
    },
    Exited {
        code: u8,
        output: Output,
    },
    Signaled {
        signal: u8,
        output: Output,
    },
    ReadError {
        errno: u32,
        output: Output,
    },
    WaitError {
        errno: u32,
        output: Output,
    },
    UnrecognizedStatus {
        raw: u32,
        output: Output,
    },
    ExecProbeError {
        rc_magnitude: u32,
        output: Output,
    },
}

impl Outcome {
    /// Exit status 0 with at least one byte on stdout. A speaker that exits cleanly and prints nothing has not
    /// shown anything: `--catalog` is defined to print the board catalog.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Exited { code: 0, output } if output.bytes > 0
        )
    }
}

pub const LINE_CAP: usize = 128;

/// A fixed-capacity output line. The longest line this module can produce is shorter than `LINE_CAP`
/// (asserted in the tests); bytes beyond the capacity are dropped, which loses the trailing newline and
/// therefore fails the runner's grammar instead of passing a truncated line.
pub struct Line {
    buf: [u8; LINE_CAP],
    len: usize,
}

impl Line {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; LINE_CAP],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.len < LINE_CAP {
                self.buf[self.len] = byte;
                self.len += 1;
            }
        }
    }

    fn push_dec(&mut self, mut value: u32) {
        if value == 0 {
            self.push(b"0");
            return;
        }
        let mut digits = [0u8; 10];
        let mut count = 0;
        while value > 0 {
            digits[count] = b'0' + (value % 10) as u8;
            value /= 10;
            count += 1;
        }
        while count > 0 {
            count -= 1;
            self.push(&digits[count..=count]);
        }
    }

    fn push_hex16(&mut self, value: u64) {
        let mut shift = 64;
        while shift > 0 {
            shift -= 4;
            let nibble = ((value >> shift) & 0xf) as u8;
            let digit = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            self.push(&[digit]);
        }
    }

    fn push_output(&mut self, output: Output) {
        self.push(b" stdout_bytes=");
        self.push_dec(output.bytes);
        self.push(b" stdout_fnv1a64=");
        self.push_hex16(output.fnv1a64);
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

/// The `FFW_SPEAKER_EXIT` line for an outcome, newline included.
#[must_use]
pub fn exit_line(outcome: &Outcome) -> Line {
    let mut line = Line::new();
    line.push(b"FFW_SPEAKER_EXIT ");
    match *outcome {
        Outcome::Spawn { stage, errno } => {
            line.push(b"spawn=");
            line.push(stage.name().as_bytes());
            line.push(b" errno=");
            line.push_dec(errno);
        }
        Outcome::Exited { code, output } => {
            line.push(b"status=");
            line.push_dec(u32::from(code));
            line.push_output(output);
        }
        Outcome::Signaled { signal, output } => {
            line.push(b"signal=");
            line.push_dec(u32::from(signal));
            line.push_output(output);
        }
        Outcome::ReadError { errno, output } => {
            line.push(b"read_error=");
            line.push_dec(errno);
            line.push_output(output);
        }
        Outcome::WaitError { errno, output } => {
            line.push(b"wait_error=");
            line.push_dec(errno);
            line.push_output(output);
        }
        Outcome::UnrecognizedStatus { raw, output } => {
            line.push(b"wait_status=");
            line.push_dec(raw);
            line.push_output(output);
        }
        Outcome::ExecProbeError {
            rc_magnitude,
            output,
        } => {
            line.push(b"exec_probe_error=");
            line.push_dec(rc_magnitude);
            line.push_output(output);
        }
    }
    line.push(b"\n");
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire line for an outcome. Compared as bytes: this crate is `no_std` and its tests use core only.
    fn wire(outcome: &Outcome) -> Line {
        exit_line(outcome)
    }

    const OUT: Output = Output {
        bytes: 17812,
        fnv1a64: 0x0123_4567_89ab_cdef,
    };

    #[test]
    fn fnv_matches_published_vectors() {
        // The same four vectors are asserted by toolchain/tests/test_speaker_smoke.py against an independent
        // Python implementation.
        let hash = |bytes: &[u8]| {
            let mut fnv = Fnv1a64::new();
            fnv.update(bytes);
            fnv.finish()
        };
        assert_eq!(hash(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(hash(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(hash(b"foobar"), 0x8594_4171_f739_67e8);
        assert_eq!(hash(b"FFW_SPEAKER"), 0x76be_4069_4ade_6f20);
    }

    #[test]
    fn fnv_is_incremental() {
        let mut whole = Fnv1a64::new();
        whole.update(b"hello world");
        let mut parts = Fnv1a64::new();
        parts.update(b"hello");
        parts.update(b" ");
        parts.update(b"world");
        assert_eq!(whole, parts);
    }

    #[test]
    fn success_line_is_exact() {
        assert_eq!(
            wire(&Outcome::Exited {
                code: 0,
                output: OUT
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT status=0 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
    }

    #[test]
    fn every_failure_form_is_exact() {
        assert_eq!(
            wire(&Outcome::Exited {
                code: 3,
                output: OUT
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT status=3 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
        assert_eq!(
            wire(&Outcome::Signaled {
                signal: 11,
                output: OUT
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT signal=11 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
        assert_eq!(
            wire(&Outcome::Spawn {
                stage: SpawnStage::Pipe,
                errno: 24
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT spawn=pipe errno=24\n"
        );
        assert_eq!(
            wire(&Outcome::Spawn {
                stage: SpawnStage::Fork,
                errno: 11
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT spawn=fork errno=11\n"
        );
        assert_eq!(
            wire(&Outcome::Spawn {
                stage: SpawnStage::Exec,
                errno: 2
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT spawn=exec errno=2\n"
        );
        assert_eq!(
            wire(&Outcome::ReadError {
                errno: 5,
                output: OUT
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT read_error=5 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
        assert_eq!(
            wire(&Outcome::WaitError {
                errno: 10,
                output: OUT
            })
            .as_bytes(),
            b"FFW_SPEAKER_EXIT wait_error=10 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
        assert_eq!(
            wire(&Outcome::UnrecognizedStatus { raw: 4991, output: OUT }).as_bytes(),
            b"FFW_SPEAKER_EXIT wait_status=4991 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
        assert_eq!(
            wire(&Outcome::ExecProbeError { rc_magnitude: 1, output: OUT }).as_bytes(),
            b"FFW_SPEAKER_EXIT exec_probe_error=1 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef\n"
        );
    }

    #[test]
    fn hex_is_zero_padded_lowercase_sixteen_digits() {
        let line = wire(&Outcome::Exited {
            code: 0,
            output: Output {
                bytes: 1,
                fnv1a64: 0xA,
            },
        });
        assert!(line
            .as_bytes()
            .ends_with(b"stdout_fnv1a64=000000000000000a\n"));
    }

    #[test]
    fn the_longest_line_fits_with_its_newline() {
        let widest = Output {
            bytes: u32::MAX,
            fnv1a64: u64::MAX,
        };
        for outcome in [
            Outcome::Exited {
                code: 255,
                output: widest,
            },
            Outcome::Signaled {
                signal: 255,
                output: widest,
            },
            Outcome::ReadError {
                errno: u32::MAX,
                output: widest,
            },
            Outcome::WaitError {
                errno: u32::MAX,
                output: widest,
            },
            Outcome::UnrecognizedStatus {
                raw: u32::MAX,
                output: widest,
            },
            Outcome::ExecProbeError {
                rc_magnitude: u32::MAX,
                output: widest,
            },
            Outcome::Spawn {
                stage: SpawnStage::Exec,
                errno: u32::MAX,
            },
        ] {
            let line = wire(&outcome);
            assert!(line.as_bytes().len() < LINE_CAP, "{outcome:?}");
            assert_eq!(line.as_bytes().last(), Some(&b'\n'), "{outcome:?}");
        }
    }

    #[test]
    fn only_a_clean_exit_with_output_is_success() {
        assert!(Outcome::Exited {
            code: 0,
            output: OUT
        }
        .is_success());
        // Exit 0 with an empty stdout shows nothing.
        let empty = Output {
            bytes: 0,
            fnv1a64: Fnv1a64::OFFSET,
        };
        assert!(!Outcome::Exited {
            code: 0,
            output: empty
        }
        .is_success());
        assert!(!Outcome::Exited {
            code: 1,
            output: OUT
        }
        .is_success());
        assert!(!Outcome::Signaled {
            signal: 9,
            output: OUT
        }
        .is_success());
        assert!(!Outcome::Spawn {
            stage: SpawnStage::Exec,
            errno: 2
        }
        .is_success());
        assert!(!Outcome::ReadError {
            errno: 5,
            output: OUT
        }
        .is_success());
        assert!(!Outcome::WaitError {
            errno: 10,
            output: OUT
        }
        .is_success());
        assert!(!Outcome::UnrecognizedStatus {
            raw: 0x137f,
            output: OUT
        }
        .is_success());
        assert!(!Outcome::ExecProbeError {
            rc_magnitude: 1,
            output: OUT
        }
        .is_success());
    }

    #[test]
    fn wait_status_words_decode() {
        assert_eq!(decode_wait_status(0x0000), WaitStatus::Exited(0));
        assert_eq!(decode_wait_status(0x0100), WaitStatus::Exited(1));
        assert_eq!(decode_wait_status(0x7f00), WaitStatus::Exited(127));
        assert_eq!(decode_wait_status(0xff00), WaitStatus::Exited(255));
        assert_eq!(decode_wait_status(0x0009), WaitStatus::Signaled(9));
        // Core-dump flag set: still a termination by signal 11.
        assert_eq!(decode_wait_status(0x008b), WaitStatus::Signaled(11));
        // Stopped (0x137f) and continued (0xffff) are not terminations.
        assert_eq!(decode_wait_status(0x137f), WaitStatus::Other(0x137f));
        assert_eq!(decode_wait_status(0xffff), WaitStatus::Other(0xffff));
        assert_eq!(decode_wait_status(0x007f), WaitStatus::Other(0x007f));
    }

    #[test]
    fn exec_probe_distinguishes_ran_failed_and_unreadable() {
        assert_eq!(decode_exec_probe(0, [0; 4]), ExecProbe::Ran);
        assert_eq!(decode_exec_probe(-11, [0; 4]), ExecProbe::Ran);
        assert_eq!(
            decode_exec_probe(4, 2u32.to_be_bytes()),
            ExecProbe::Failed(2)
        );
        assert_eq!(
            decode_exec_probe(4, 13u32.to_be_bytes()),
            ExecProbe::Failed(13)
        );
        // A short read, or any other error, is not a statement about execve.
        assert_eq!(decode_exec_probe(1, [0; 4]), ExecProbe::Unreadable(1));
        assert_eq!(decode_exec_probe(3, [0; 4]), ExecProbe::Unreadable(3));
        assert_eq!(decode_exec_probe(-9, [0; 4]), ExecProbe::Unreadable(-9));
    }
}
