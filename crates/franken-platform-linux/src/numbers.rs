//! Linux syscall numbers for the seven calls the leaf issues raw, per legacy ABI. (The clock is not among them: it is `std::time::Instant`.)
//!
//! `open` is the legacy entropy provider's one addition (the plain `open`, not `openat`: `openat` arrived in 2.6.16, after the stock
//! PowerPC kernel's 2.6.14). The leaf only ever opens one constant path, `/dev/random`.
//!
//! Plain data, compiled on every target so that a host test can hold it to its sources. Two independent sources agree on every
//! number below:
//! * the audited E03 guest probes (`toolchain/src/ffw-hello-init`), which issued these exact calls in full-system QEMU guests
//!   (open, pipe2, read, write and close in `main.rs`, getrandom and eventfd2 in `e03_probes.rs`);
//! * the `libc` crate's tables for the musl targets (`tests/p02/test_syscall_numbers.py` reads them from the cargo registry).
//!
//! MIPS o32 numbers are 4000-based; PowerPC32 uses the generic numbering.

use franken_platform::abi::Abi;

/// The syscall number of each call, for one ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numbers {
    pub getrandom: usize,
    pub eventfd2: usize,
    pub pipe2: usize,
    pub open: usize,
    pub read: usize,
    pub write: usize,
    pub close: usize,
}

/// PowerPC32 (generic numbering).
pub const POWERPC32: Numbers = Numbers {
    getrandom: 359,
    eventfd2: 314,
    pipe2: 317,
    open: 5,
    read: 3,
    write: 4,
    close: 6,
};

/// MIPS o32 (base 4000).
pub const MIPS32_O32: Numbers = Numbers {
    getrandom: 4000 + 353,
    eventfd2: 4000 + 325,
    pipe2: 4000 + 328,
    open: 4000 + 5,
    read: 4000 + 3,
    write: 4000 + 4,
    close: 4000 + 6,
};

/// The numbers for `abi`.
#[must_use]
pub const fn for_abi(abi: Abi) -> Numbers {
    match abi {
        Abi::PowerPc32 => POWERPC32,
        Abi::Mips32 => MIPS32_O32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_abi_gets_its_own_table_and_the_tables_differ_in_every_call() {
        assert_eq!(for_abi(Abi::PowerPc32), POWERPC32);
        assert_eq!(for_abi(Abi::Mips32), MIPS32_O32);
        let (p, m) = (POWERPC32, MIPS32_O32);
        for (name, a, b) in [
            ("getrandom", p.getrandom, m.getrandom),
            ("eventfd2", p.eventfd2, m.eventfd2),
            ("pipe2", p.pipe2, m.pipe2),
            ("open", p.open, m.open),
            ("read", p.read, m.read),
            ("write", p.write, m.write),
            ("close", p.close, m.close),
        ] {
            assert_ne!(a, b, "{name}");
        }
    }

    #[test]
    fn the_numbers_are_the_ones_the_audited_guest_probes_issued() {
        // Copied from toolchain/src/ffw-hello-init (main.rs `sys`, e03_probes.rs `nr`), which ran them in QEMU guests.
        assert_eq!(
            (MIPS32_O32.pipe2, MIPS32_O32.getrandom, MIPS32_O32.eventfd2),
            (4328, 4353, 4325)
        );
        assert_eq!(
            (POWERPC32.pipe2, POWERPC32.getrandom, POWERPC32.eventfd2),
            (317, 359, 314)
        );
        assert_eq!(
            (MIPS32_O32.read, MIPS32_O32.write, MIPS32_O32.close),
            (4003, 4004, 4006)
        );
        assert_eq!(
            (POWERPC32.read, POWERPC32.write, POWERPC32.close),
            (3, 4, 6)
        );
        // `open`: `NR_OPEN` in the probes' `main.rs`, which opened `/dev/urandom` and `/dev/null` in the same guests.
        assert_eq!((MIPS32_O32.open, POWERPC32.open), (4005, 5));
    }

    #[test]
    fn mips_numbers_are_four_thousand_based_and_powerpc_numbers_are_not() {
        for n in [
            MIPS32_O32.getrandom,
            MIPS32_O32.eventfd2,
            MIPS32_O32.pipe2,
            MIPS32_O32.open,
            MIPS32_O32.read,
            MIPS32_O32.write,
            MIPS32_O32.close,
        ] {
            assert!((4000..5000).contains(&n), "{n}");
        }
        for n in [
            POWERPC32.getrandom,
            POWERPC32.eventfd2,
            POWERPC32.pipe2,
            POWERPC32.open,
            POWERPC32.read,
            POWERPC32.write,
            POWERPC32.close,
        ] {
            assert!(n < 1000, "{n}");
        }
    }
}
