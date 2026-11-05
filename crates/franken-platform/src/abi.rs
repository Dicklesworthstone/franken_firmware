//! Per-ABI decoding of the raw kernel return convention (`P02` / `ffw-jub`). Contract:
//! `docs/contracts/p02.md`.
//!
//! The platform layer talks to the kernel through [`crate::ops::KernelOps`], whose calls return what the
//! kernel returned: a non-negative result, or `-errno`. This module is the only place that turns such a
//! value into a [`SysError`], and it does it the way the E03 oracle (`tests/e03/abi.py`) does:
//!
//! * `-ENOSYS` means "the call does not exist" only with the guest ABI's **own** `ENOSYS` number (38 on
//!   PowerPC, 89 on MIPS). The other ABI's number is just another errno.
//! * `EINVAL` is **not** absence. A call that exists and rejected its arguments is a different fact from a
//!   call that does not exist, and a library that treats the two alike hides real failures (see the
//!   `accept4` section of the contract).
//! * A negative value outside `-4095..=-1` is neither a result nor an errno, so it is
//!   [`SysError::Malformed`], never success.
//!
//! The errno table below is mirrored in `tests/vectors/p02_errno.json` (in this crate), which a unit test here holds
//! the tables to and which `tests/p02` holds to the E03 oracle (`tests/e03/abi.py`), to the table text in this file
//! and, when the cargo registry has it, to the `libc` crate: independent sources, one number each.

use serde::{Deserialize, Serialize};

/// The two legacy big-endian Linux ABIs this layer targets. There is no host variant: a host run decodes
/// with one of these and says so, because the numbers a decoder uses are part of what a test claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Abi {
    PowerPc32,
    Mips32,
}

/// `EINTR` and `EAGAIN`/`EINVAL` are the same on both ABIs (generic numbering; `EAGAIN` is 11 on MIPS too).
pub const EINTR: i32 = 4;
pub const EAGAIN: i32 = 11;
pub const EINVAL: i32 = 22;

/// The kernel reports a failure as `-errno` with `errno` in `1..=4095`; anything more negative is not an
/// errno.
pub const MAX_ERRNO: isize = 4095;

/// The most times one logical call is issued when it keeps answering `EINTR`. An interruption is an
/// ordinary event and the call is retried, but a signal storm must not turn a bounded call into a loop.
pub const MAX_INTERRUPTED_ATTEMPTS: u32 = 8;

/// `O_CLOEXEC` / `EFD_CLOEXEC` / `SOCK_CLOEXEC` (0o2000000) on both ABIs.
pub const O_CLOEXEC: u32 = 0o2_000_000;

/// The errno names and numbers the E03 oracle records, per ABI, in a fixed order. The cross-check test
/// compares this whole table, so adding a name here without adding it to `abi.py` (or the reverse) fails.
pub const POWERPC_ERRNO: [(&str, i32); 16] = [
    ("EPERM", 1),
    ("ENOENT", 2),
    ("EINTR", 4),
    ("EIO", 5),
    ("EBADF", 9),
    ("EAGAIN", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EFAULT", 14),
    ("EINVAL", 22),
    ("EMFILE", 24),
    ("ENOSYS", 38),
    ("ENOTSOCK", 88),
    ("EPROTONOSUPPORT", 93),
    ("EOPNOTSUPP", 95),
    ("EAFNOSUPPORT", 97),
];

pub const MIPS_ERRNO: [(&str, i32); 16] = [
    ("EPERM", 1),
    ("ENOENT", 2),
    ("EINTR", 4),
    ("EIO", 5),
    ("EBADF", 9),
    ("EAGAIN", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EFAULT", 14),
    ("EINVAL", 22),
    ("EMFILE", 24),
    ("ENOSYS", 89),
    ("ENOTSOCK", 95),
    ("EPROTONOSUPPORT", 120),
    ("EOPNOTSUPP", 122),
    ("EAFNOSUPPORT", 124),
];

/// What a raw kernel return means to the layer. Every variant is a statement about one call; none is a
/// capability verdict (that is the matrix's job, from probes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum SysError {
    /// Exactly `-ENOSYS` in this ABI's numbering: the kernel has no such call.
    #[error("the kernel has no such call (ENOSYS)")]
    Absent,
    /// `-EINTR`: a signal arrived. Not a failure of the call and not evidence of absence.
    #[error("interrupted by a signal (EINTR)")]
    Interrupted,
    /// `-EAGAIN`: a nonblocking call had nothing to do (or, for `getrandom`, the pool is not seeded).
    #[error("would block (EAGAIN)")]
    WouldBlock,
    /// `-EINVAL`: the call exists and refused its arguments. Never read as absence.
    #[error("invalid argument (EINVAL)")]
    Invalid,
    /// Any other errno, as the kernel numbered it.
    #[error("errno {0}")]
    Errno(i32),
    /// A negative value outside `-4095..=-1`: not a result and not an errno.
    #[error("return value {0} is neither a result nor an errno")]
    Malformed(isize),
}

impl Abi {
    /// The ABI named by a Rust target triple, or `None` for anything else. Only the two big-endian 32-bit
    /// Linux musl targets the project builds (`P01`); `mipsel-*` and 64-bit variants are not these ABIs.
    #[must_use]
    pub fn from_target_triple(triple: &str) -> Option<Self> {
        match triple {
            "powerpc-unknown-linux-musl" => Some(Self::PowerPc32),
            "mips-unknown-linux-musl" => Some(Self::Mips32),
            _ => None,
        }
    }

    /// This ABI's `ENOSYS`.
    #[must_use]
    pub const fn enosys(self) -> i32 {
        match self {
            Self::PowerPc32 => 38,
            Self::Mips32 => 89,
        }
    }

    /// `O_NONBLOCK` (also `EFD_NONBLOCK` and `SOCK_NONBLOCK`): 0x800 on PowerPC, 0x80 on MIPS.
    #[must_use]
    pub const fn o_nonblock(self) -> u32 {
        match self {
            Self::PowerPc32 => 0x800,
            Self::Mips32 => 0x80,
        }
    }

    /// The errno table for this ABI (see [`POWERPC_ERRNO`] and [`MIPS_ERRNO`]).
    #[must_use]
    pub const fn errno_table(self) -> &'static [(&'static str, i32); 16] {
        match self {
            Self::PowerPc32 => &POWERPC_ERRNO,
            Self::Mips32 => &MIPS_ERRNO,
        }
    }

    /// Decode a raw return: a non-negative result, or the classified error.
    ///
    /// The result is `Ok` only for a value the kernel can have returned as success. A value that is
    /// negative but not a valid `-errno` is [`SysError::Malformed`]; it is never coerced to success or to
    /// a guessed errno.
    ///
    /// # Errors
    /// Returns the classified [`SysError`] for any negative `raw`.
    pub fn decode(self, raw: isize) -> Result<usize, SysError> {
        if raw >= 0 {
            return Ok(raw.unsigned_abs());
        }
        if raw < -MAX_ERRNO {
            return Err(SysError::Malformed(raw));
        }
        let errno = i32::try_from(raw.unsigned_abs()).map_err(|_| SysError::Malformed(raw))?;
        Err(self.classify(errno))
    }

    fn classify(self, errno: i32) -> SysError {
        if errno == self.enosys() {
            SysError::Absent
        } else if errno == EINTR {
            SysError::Interrupted
        } else if errno == EAGAIN {
            SysError::WouldBlock
        } else if errno == EINVAL {
            SysError::Invalid
        } else {
            SysError::Errno(errno)
        }
    }

    /// Issue one logical call, repeating it while it answers `EINTR`, at most
    /// [`MAX_INTERRUPTED_ATTEMPTS`] times in all. After that the caller sees [`SysError::Interrupted`]:
    /// the interruption is reported, not swallowed and not turned into success.
    ///
    /// # Errors
    /// The classified error of the last attempt, or [`SysError::Interrupted`] when every attempt was
    /// interrupted.
    pub fn call_retrying<F: FnMut() -> isize>(self, mut call: F) -> Result<usize, SysError> {
        for _ in 0..MAX_INTERRUPTED_ATTEMPTS {
            match self.decode(call()) {
                Err(SysError::Interrupted) => {}
                other => return other,
            }
        }
        Err(SysError::Interrupted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    #[test]
    fn a_non_negative_return_is_a_result_and_zero_is_not_an_error() {
        for abi in BOTH {
            assert_eq!(abi.decode(0), Ok(0));
            assert_eq!(abi.decode(16), Ok(16));
            assert_eq!(abi.decode(4096), Ok(4096));
        }
    }

    #[test]
    fn enosys_is_absence_only_in_the_guests_own_numbering() {
        assert_eq!(Abi::PowerPc32.decode(-38), Err(SysError::Absent));
        assert_eq!(Abi::Mips32.decode(-89), Err(SysError::Absent));
        // Each ABI's number is an ordinary errno on the other: the E03 oracle's rule.
        assert_eq!(Abi::PowerPc32.decode(-89), Err(SysError::Errno(89)));
        assert_eq!(Abi::Mips32.decode(-38), Err(SysError::Errno(38)));
        assert_eq!(Abi::PowerPc32.enosys(), 38);
        assert_eq!(Abi::Mips32.enosys(), 89);
    }

    #[test]
    fn the_transient_and_argument_errnos_are_the_same_on_both_abis_and_einval_is_not_absence() {
        for abi in BOTH {
            assert_eq!(abi.decode(-4), Err(SysError::Interrupted), "{abi:?}");
            assert_eq!(abi.decode(-11), Err(SysError::WouldBlock), "{abi:?}");
            assert_eq!(abi.decode(-22), Err(SysError::Invalid), "{abi:?}");
            assert_ne!(abi.decode(-22), Err(SysError::Absent));
            assert_eq!(abi.decode(-9), Err(SysError::Errno(9)), "{abi:?}");
            assert_eq!(abi.decode(-1), Err(SysError::Errno(1)), "{abi:?}");
        }
    }

    #[test]
    fn a_negative_value_that_is_not_an_errno_is_malformed_and_never_coerced() {
        for abi in BOTH {
            assert_eq!(
                abi.decode(-4095),
                Err(SysError::Errno(4095)),
                "{abi:?}: the last valid errno"
            );
            assert_eq!(
                abi.decode(-4096),
                Err(SysError::Malformed(-4096)),
                "{abi:?}"
            );
            assert_eq!(
                abi.decode(-5000),
                Err(SysError::Malformed(-5000)),
                "{abi:?}"
            );
            assert_eq!(
                abi.decode(isize::MIN),
                Err(SysError::Malformed(isize::MIN)),
                "{abi:?}"
            );
        }
    }

    #[test]
    fn the_generic_errno_constants_match_both_tables() {
        for abi in BOTH {
            let table = abi.errno_table();
            let number = |name: &str| table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
            assert_eq!(number("EINTR"), Some(EINTR), "{abi:?}");
            assert_eq!(number("EAGAIN"), Some(EAGAIN), "{abi:?}");
            assert_eq!(number("EINVAL"), Some(EINVAL), "{abi:?}");
            assert_eq!(number("ENOSYS"), Some(abi.enosys()), "{abi:?}");
        }
    }

    #[test]
    fn each_table_has_unique_names_and_unique_numbers_and_the_two_abis_really_differ() {
        for abi in BOTH {
            let table = abi.errno_table();
            for (i, (name, number)) in table.iter().enumerate() {
                for (other_name, other_number) in &table[i + 1..] {
                    assert_ne!(name, other_name, "{abi:?}");
                    assert_ne!(number, other_number, "{abi:?}: {name} and {other_name}");
                }
            }
        }
        // The names that differ between the ABIs are exactly the ones whose numbers moved.
        let differing: Vec<&str> = POWERPC_ERRNO
            .iter()
            .zip(MIPS_ERRNO.iter())
            .filter(|(p, m)| p.1 != m.1)
            .map(|(p, _)| p.0)
            .collect();
        assert_eq!(
            differing,
            [
                "ENOSYS",
                "ENOTSOCK",
                "EPROTONOSUPPORT",
                "EOPNOTSUPP",
                "EAFNOSUPPORT"
            ]
        );
        assert!(
            POWERPC_ERRNO
                .iter()
                .zip(MIPS_ERRNO.iter())
                .all(|(p, m)| p.0 == m.0)
        );
    }

    #[test]
    fn the_nonblock_flag_is_each_abis_own_and_cloexec_is_shared() {
        assert_eq!(Abi::PowerPc32.o_nonblock(), 0x800);
        assert_eq!(Abi::Mips32.o_nonblock(), 0x80);
        assert_ne!(Abi::PowerPc32.o_nonblock(), Abi::Mips32.o_nonblock());
        assert_eq!(O_CLOEXEC, 0x80000);
        for abi in BOTH {
            assert_eq!(
                abi.o_nonblock() & O_CLOEXEC,
                0,
                "{abi:?}: the two flags are different bits"
            );
        }
    }

    #[test]
    fn the_tables_and_flags_equal_the_committed_vectors_generated_from_the_e03_oracle() {
        use std::collections::BTreeMap;
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/p02_errno.json"))
                .expect("the vector file is JSON");
        assert_eq!(vectors["schema"], "ffw.p02.errno.v1");
        for (abi, key) in [(Abi::PowerPc32, "powerpc32"), (Abi::Mips32, "mips32")] {
            let entry = &vectors["abis"][key];
            let expected: BTreeMap<String, i64> = entry["errno"]
                .as_object()
                .expect("an errno object")
                .iter()
                .map(|(name, number)| (name.clone(), number.as_i64().expect("a number")))
                .collect();
            let actual: BTreeMap<String, i64> = abi
                .errno_table()
                .iter()
                .map(|(name, number)| ((*name).to_string(), i64::from(*number)))
                .collect();
            assert_eq!(actual, expected, "{abi:?}: the table is not the oracle's");
            assert_eq!(
                entry["enosys"].as_i64(),
                Some(i64::from(abi.enosys())),
                "{abi:?}"
            );
            assert_eq!(
                entry["o_nonblock"].as_i64(),
                Some(i64::from(abi.o_nonblock())),
                "{abi:?}"
            );
            assert_eq!(
                entry["o_cloexec"].as_i64(),
                Some(i64::from(O_CLOEXEC)),
                "{abi:?}"
            );
        }
    }

    #[test]
    fn only_the_two_big_endian_musl_triples_name_an_abi() {
        assert_eq!(
            Abi::from_target_triple("powerpc-unknown-linux-musl"),
            Some(Abi::PowerPc32)
        );
        assert_eq!(
            Abi::from_target_triple("mips-unknown-linux-musl"),
            Some(Abi::Mips32)
        );
        for triple in [
            "mipsel-unknown-linux-musl",
            "powerpc64-unknown-linux-musl",
            "powerpc64le-unknown-linux-musl",
            "mips64-unknown-linux-muslabi64",
            "powerpc-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "powerpc",
            "",
        ] {
            assert_eq!(Abi::from_target_triple(triple), None, "{triple:?}");
        }
    }

    #[test]
    fn a_call_is_retried_only_while_it_is_interrupted_and_only_a_bounded_number_of_times() {
        for abi in BOTH {
            let mut replies = vec![-4isize, -4, 7].into_iter();
            let mut calls = 0;
            let outcome = abi.call_retrying(|| {
                calls += 1;
                replies.next().expect("no more replies")
            });
            assert_eq!((outcome, calls), (Ok(7), 3), "{abi:?}");

            // Any other answer, success or failure, is final on the first attempt.
            let mut calls = 0;
            assert_eq!(
                abi.call_retrying(|| {
                    calls += 1;
                    -11
                }),
                Err(SysError::WouldBlock)
            );
            assert_eq!(calls, 1, "EAGAIN is not retried");
            let mut calls = 0;
            assert_eq!(
                abi.call_retrying(|| {
                    calls += 1;
                    -abi.enosys() as isize
                }),
                Err(SysError::Absent)
            );
            assert_eq!(calls, 1, "ENOSYS is not retried");

            // Always interrupted: exactly the bound, then the interruption is reported.
            let mut calls = 0u32;
            assert_eq!(
                abi.call_retrying(|| {
                    calls += 1;
                    -4
                }),
                Err(SysError::Interrupted)
            );
            assert_eq!(calls, MAX_INTERRUPTED_ATTEMPTS, "{abi:?}");
        }
    }
}
