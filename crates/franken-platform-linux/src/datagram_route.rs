//! The `sendto` and `recvfrom` routes of the Linux leaf as plain data (`N07` / `ffw-ybr`, on `P02` / `ffw-jub`), compiled on every target so that a host
//! test can hold them. The words are decided here, before any `unsafe` code runs; `sys.rs` only executes them.
//!
//! **Both calls travel as `socketcall(sub, &block)` on both ABIs.** A direct `sendto` or `recvfrom` takes six arguments, and on MIPS o32 the sixth goes
//! at `20($sp)`, which the leaf's five-slot trampoline (`raw5`) uses to save a register; carrying six words directly would need a second, wider
//! trampoline, which this leaf does not have and does not add. `socketcall` is two slots on both ABIs (102 on PowerPC, 4102 on MIPS o32), takes the
//! six words in a block in memory, and the kernel reads `nargs[sub]` words of it, which is six for both sub-calls at every kernel version read
//! (`tests/p02/socket_kernel_evidence.json`: v2.6.14, .26, .27, .28, .35). [`crate::socket_route::BLOCK_WORDS`] is already six.
//!
//! No number is typed here: the `socketcall` number and the two sub-calls come from the `P06Calls` rows in [`crate::numbers`], where the kernel files
//! and the probes already hold them. Both sub-calls (11 and 12) are within the stock 2.6.14 `socketcall` bound, and neither is sub-call 18, so the
//! release rule of [`crate::socket_route::admit`] (which concerns only `accept4`/`paccept`) does not apply to them.
//!
//! **What this is not.** No guest has issued a `socketcall` on either ABI. On MIPS o32 the leaf's other socket calls are direct (the E03 probes
//! issued those), so these two would be the first `socketcall` that ABI sends.

use franken_platform::abi::Abi;

use crate::numbers::p06_for_abi;
use crate::socket_route::{BLOCK_WORDS, Issue};

/// The two datagram calls the leaf issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramCall {
    SendTo,
    RecvFrom,
}

impl DatagramCall {
    /// Both calls.
    pub const ALL: [Self; 2] = [Self::SendTo, Self::RecvFrom];

    /// The syscall's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SendTo => "sendto",
            Self::RecvFrom => "recvfrom",
        }
    }
}

/// What `call` is issued as on `abi`: always one `socketcall`, with `words` as the block. There is no direct form.
#[must_use]
pub const fn datagram_issue_for(
    abi: Abi,
    call: DatagramCall,
    words: [usize; BLOCK_WORDS],
) -> Issue {
    let rows = p06_for_abi(abi);
    let sub = match call {
        DatagramCall::SendTo => rows.sendto.sub,
        DatagramCall::RecvFrom => rows.recvfrom.sub,
    };
    Issue::SocketCall {
        number: rows.socketcall.number,
        sub,
        block: words,
    }
}

/// `sendto(fd, buf, len, flags, addr, addr_len)`: `buf` and `addr` are addresses, `len` and `addr_len` lengths.
#[must_use]
pub const fn sendto_words(
    fd: i32,
    buf: usize,
    len: usize,
    flags: u32,
    addr: usize,
    addr_len: usize,
) -> [usize; BLOCK_WORDS] {
    [fd as u32 as usize, buf, len, flags as usize, addr, addr_len]
}

/// `recvfrom(fd, buf, len, flags, addr, addr_len_ptr)`: `buf` and `addr` are addresses, `len` a length, and `addr_len_ptr` the address of the
/// 32-bit length the kernel reads (how much room `addr` has) and then overwrites (how long the address is).
#[must_use]
pub const fn recvfrom_words(
    fd: i32,
    buf: usize,
    len: usize,
    flags: u32,
    addr: usize,
    addr_len_ptr: usize,
) -> [usize; BLOCK_WORDS] {
    [
        fd as u32 as usize,
        buf,
        len,
        flags as usize,
        addr,
        addr_len_ptr,
    ]
}

// Both calls are two slots by `socketcall` and the block the leaf passes covers the six words the kernel reads for each, on both ABIs.
const _: () = {
    let ppc = p06_for_abi(Abi::PowerPc32);
    let mips = p06_for_abi(Abi::Mips32);
    assert!(ppc.socketcall.fits_the_leaf() && mips.socketcall.fits_the_leaf());
    assert!(ppc.sendto.direct.slots == BLOCK_WORDS && ppc.recvfrom.direct.slots == BLOCK_WORDS);
    assert!(mips.sendto.direct.slots == BLOCK_WORDS && mips.recvfrom.direct.slots == BLOCK_WORDS);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::numbers::STOCK_SOCKETCALL_MAX_SUB;
    use crate::socket_route::ACCEPT4_SUBCALL;

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    // Typed from the kernel files, not read from the tables under test: `linux/net.h` (SYS_SENDTO 11, SYS_RECVFROM 12), the PowerPC
    // `__NR_socketcall` 102, and MIPS o32's 4000 + 102. The block size is the `nargs` entry for both sub-calls, `AL(6)`.
    const SYS_SENDTO: usize = 11;
    const SYS_RECVFROM: usize = 12;
    const PPC_SOCKETCALL: usize = 102;
    const MIPS_O32_SOCKETCALL: usize = 4102;
    const NARGS: usize = 6;

    fn socketcall_number(abi: Abi) -> usize {
        match abi {
            Abi::PowerPc32 => PPC_SOCKETCALL,
            Abi::Mips32 => MIPS_O32_SOCKETCALL,
        }
    }

    #[test]
    fn each_call_is_one_socketcall_on_both_abis_with_the_sub_calls_of_linux_net_h() {
        let words = [1, 2, 3, 4, 5, 6];
        for abi in BOTH {
            assert_eq!(
                datagram_issue_for(abi, DatagramCall::SendTo, words),
                Issue::SocketCall {
                    number: socketcall_number(abi),
                    sub: SYS_SENDTO,
                    block: words
                },
                "{abi:?}"
            );
            assert_eq!(
                datagram_issue_for(abi, DatagramCall::RecvFrom, words),
                Issue::SocketCall {
                    number: socketcall_number(abi),
                    sub: SYS_RECVFROM,
                    block: words
                },
                "{abi:?}"
            );
        }
    }

    #[test]
    fn the_sendto_block_is_the_syscalls_own_arguments_in_order() {
        // Six distinct values, so a swap of any two words shows.
        assert_eq!(
            sendto_words(7, 0x1000, 5, 0x40, 0x2000, 16),
            [7, 0x1000, 5, 0x40, 0x2000, 16]
        );
    }

    #[test]
    fn the_recvfrom_block_ends_with_the_address_of_the_length_and_not_its_value() {
        assert_eq!(
            recvfrom_words(7, 0x1000, 64, 0x20, 0x2000, 0x3000),
            [7, 0x1000, 64, 0x20, 0x2000, 0x3000]
        );
    }

    #[test]
    fn a_negative_descriptor_keeps_its_32_bit_pattern_whatever_the_host_width() {
        // On the 32-bit device `-1 as usize` is 0xFFFF_FFFF; on a 64-bit host a sign-extending cast would give more. The builders go through u32.
        assert_eq!(sendto_words(-1, 0, 0, 0, 0, 0)[0], 0xFFFF_FFFF);
        assert_eq!(recvfrom_words(-1, 0, 0, 0, 0, 0)[0], 0xFFFF_FFFF);
        // The flags are passed bit for bit.
        assert_eq!(recvfrom_words(3, 0, 0, 0x20, 0, 0)[3], 0x20);
        assert_eq!(sendto_words(3, 0, 0, 0, 0, 0)[3], 0);
    }

    #[test]
    fn both_calls_fit_two_slots_and_the_block_covers_the_kernels_six_words() {
        assert_eq!(BLOCK_WORDS, NARGS);
        for abi in BOTH {
            let rows = p06_for_abi(abi);
            assert!(rows.socketcall.fits_the_leaf(), "{abi:?}");
            assert_eq!(rows.socketcall.slots, 2, "{abi:?}: socketcall(sub, &block)");
            assert_eq!(rows.sendto.direct.slots, NARGS, "{abi:?}");
            assert_eq!(rows.recvfrom.direct.slots, NARGS, "{abi:?}");
            for call in DatagramCall::ALL {
                let Issue::SocketCall { block, .. } =
                    datagram_issue_for(abi, call, [0; BLOCK_WORDS])
                else {
                    panic!("{abi:?} {call:?}: a datagram call is never a direct syscall");
                };
                assert_eq!(block.len(), NARGS, "{abi:?} {call:?}");
            }
        }
    }

    #[test]
    fn the_sub_calls_are_inside_the_stock_bound_and_neither_is_the_paccept_sub_call() {
        for sub in [SYS_SENDTO, SYS_RECVFROM] {
            assert!(
                sub <= STOCK_SOCKETCALL_MAX_SUB,
                "sub-call {sub} is above the stock socketcall bound"
            );
            assert_ne!(
                sub, ACCEPT4_SUBCALL,
                "sub-call {sub} is the paccept sub-call"
            );
        }
        // And the rows say the same.
        for abi in BOTH {
            let rows = p06_for_abi(abi);
            assert_eq!(rows.sendto.sub, SYS_SENDTO, "{abi:?}");
            assert_eq!(rows.recvfrom.sub, SYS_RECVFROM, "{abi:?}");
        }
    }

    #[test]
    fn the_calls_are_named_as_the_syscalls_are() {
        assert_eq!(DatagramCall::SendTo.name(), "sendto");
        assert_eq!(DatagramCall::RecvFrom.name(), "recvfrom");
        assert_eq!(DatagramCall::ALL.len(), 2);
    }
}
