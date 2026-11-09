//! The argument plan for the finite P02 `poll` boundary.
//!
//! This is plain data on every host. The audited leaf executes this exact plan;
//! these tests establish its number and argument shape, not kernel execution.

use crate::numbers::p06_for_abi;
use franken_platform::abi::Abi;
use franken_platform::wait::PollTimeout;

/// Three native-width words, in Linux `poll(fds, nfds, timeout_ms)` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollIssue {
    pub number: usize,
    pub words: [usize; 3],
}

/// Plan the one call. `address` and `count` come from the same borrowed slice in
/// the leaf; this function neither dereferences an address nor issues a call.
#[must_use]
pub fn issue_for(abi: Abi, address: usize, count: usize, timeout: PollTimeout) -> PollIssue {
    PollIssue {
        number: p06_for_abi(abi).poll.number,
        words: [address, count, timeout.as_millis() as usize],
    }
}

const _: () = {
    assert!(p06_for_abi(Abi::Mips32).poll.slots == 3);
    assert!(p06_for_abi(Abi::PowerPc32).poll.slots == 3);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_legacy_abis_use_the_existing_poll_table_and_three_ordered_words() {
        for (abi, number) in [(Abi::Mips32, 4188), (Abi::PowerPc32, 167)] {
            let plan = issue_for(abi, 0x1020, 3, PollTimeout::new(17).unwrap());
            assert_eq!(plan.number, number);
            assert_eq!(plan.words, [0x1020, 3, 17]);
        }
    }

    #[test]
    fn zero_and_maximum_finite_timeouts_are_not_a_signed_infinite_wait() {
        for abi in [Abi::Mips32, Abi::PowerPc32] {
            for millis in [0, 1000] {
                let plan = issue_for(abi, 0x1020, 0, PollTimeout::new(millis).unwrap());
                assert_eq!(plan.words, [0x1020, 0, millis as usize]);
                assert!(plan.words[2] <= i32::MAX as usize);
            }
        }
    }
}
