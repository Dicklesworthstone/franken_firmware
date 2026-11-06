//! The socket routes of the Linux leaf as plain data (`P02` / `ffw-jub`), compiled on every target so that a host test can hold them.
//!
//! **Status: written, never compiled, never run against a kernel, and no guest has issued a `socketcall`.** Two things live here, both
//! decided before any `unsafe` code runs:
//!
//! * [`issue_for`]: what one socket call is issued as on one ABI, as the exact words. The route comes from [`crate::numbers::socket_plan_for`]
//!   (so no number is typed twice): a direct syscall with its arguments in registers, or `socketcall(sub, &block)` with the arguments in a block
//!   of [`BLOCK_WORDS`] words. `sys.rs` only executes an [`Issue`]; it chooses nothing.
//! * [`admit`]: the one kernel-release rule of the `socketcall` route. Sub-call 18 is `accept4` (four words) from v2.6.28 and `paccept` (six words,
//!   a different call) at v2.6.27; the answer to a `socketcall(18, ..)` on a v2.6.27 kernel says nothing about that, so the leaf refuses the route
//!   there **by name, before any socket call** (the lines are in `tests/p02/socket_kernel_evidence.json`; the argument is in `docs/contracts/p02.md`,
//!   "The socket capability"). The direct route (MIPS o32) never uses sub-call 18 and is admitted on any release.

use std::fmt;

use franken_platform::abi::Abi;
use franken_platform::socket::SocketOp;

use crate::numbers::{LEAF_ARG_SLOTS, Route, socket_plan_for};

/// Words in the `socketcall` argument block the leaf always passes: the kernel's largest `nargs` entry is six, so a block of six is read
/// completely whatever the sub-call, and unused words are zero.
pub const BLOCK_WORDS: usize = 6;

/// `socketcall`'s sub-call number for `accept4` (and, at v2.6.27 only, for `paccept`).
pub const ACCEPT4_SUBCALL: usize = 18;

/// What one socket call is issued as: the words, before any `unsafe` code runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    /// A direct syscall: its number and the five argument registers the leaf's trampoline carries (words past the call's arity are zero).
    Direct {
        number: usize,
        args: [usize; LEAF_ARG_SLOTS],
    },
    /// `socketcall(sub, &block)`: the `socketcall` syscall number, the sub-call, and the block of the call's own arguments in order.
    SocketCall {
        number: usize,
        sub: usize,
        block: [usize; BLOCK_WORDS],
    },
}

/// `op` with its arguments `words` (the syscall's own arguments in order, unused words 0), as the plan routes it on `abi`.
#[must_use]
pub const fn issue_for(abi: Abi, op: SocketOp, words: [usize; 4]) -> Issue {
    let plan = socket_plan_for(abi);
    let route = match op {
        SocketOp::Socket => plan.socket,
        SocketOp::Bind => plan.bind,
        SocketOp::Listen => plan.listen,
        SocketOp::Accept4 => plan.accept4,
        SocketOp::Recv => plan.recv,
    };
    match route {
        Route::Direct { call, .. } => Issue::Direct {
            number: call.number,
            args: [words[0], words[1], words[2], words[3], 0],
        },
        Route::ViaSocketCall {
            socketcall, sub, ..
        } => Issue::SocketCall {
            number: socketcall.number,
            sub,
            block: [words[0], words[1], words[2], words[3], 0, 0],
        },
    }
}

/// `socket(domain, type, protocol)`.
#[must_use]
pub const fn socket_args(domain: u32, kind: u32, protocol: u32) -> [usize; 4] {
    [domain as usize, kind as usize, protocol as usize, 0]
}

/// `bind(fd, addr, addrlen)`: `addr` is the address of the `sockaddr` bytes and `len` their length.
#[must_use]
pub const fn bind_args(fd: i32, addr: usize, len: usize) -> [usize; 4] {
    [fd as u32 as usize, addr, len, 0]
}

/// `listen(fd, backlog)`.
#[must_use]
pub const fn listen_args(fd: i32, backlog: i32) -> [usize; 4] {
    [fd as u32 as usize, backlog as u32 as usize, 0, 0]
}

/// `accept4(fd, NULL, NULL, flags)`: the peer address is not requested.
#[must_use]
pub const fn accept4_args(fd: i32, flags: u32) -> [usize; 4] {
    [fd as u32 as usize, 0, 0, flags as usize]
}

/// `recv(fd, buf, len, flags)`: `buf` is the address of the buffer and `len` its length.
#[must_use]
pub const fn recv_args(fd: i32, buf: usize, len: usize, flags: u32) -> [usize; 4] {
    [fd as u32 as usize, buf, len, flags as usize]
}

/// The first three numbers of a kernel release (`2.6.27`, or `4.19.0` in `4.19.0-21-4kc-malta`). A fourth number (`2.6.27.59`) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// The kernel whose `socketcall` sub-call 18 is `paccept`.
pub const PACCEPT_KERNEL: KernelVersion = KernelVersion {
    major: 2,
    minor: 6,
    patch: 27,
};

/// The first kernel whose sub-call 18 is `accept4`. Its release candidates are not told apart from the `paccept` kernel by anything read.
pub const ACCEPT4_FIRST_KERNEL: KernelVersion = KernelVersion {
    major: 2,
    minor: 6,
    patch: 28,
};

/// A parsed release: the version and whether the text after it starts a release candidate (`-rc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    pub version: KernelVersion,
    pub pre_release: bool,
}

/// Parse the leading `major.minor.patch` of a release string, or `None` if it does not start with three numbers.
#[must_use]
pub fn parse_release(text: &str) -> Option<Release> {
    let text = text.trim();
    let end = text
        .find(|c: char| !matches!(c, '0'..='9' | '.'))
        .unwrap_or(text.len());
    let (numeric, suffix) = text.split_at(end);
    let mut parts = numeric.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    Some(Release {
        version: KernelVersion {
            major,
            minor,
            patch,
        },
        pre_release: suffix.starts_with("-rc"),
    })
}

/// Why the `socketcall` route is not used: a typed refusal, returned before any socket call is possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketRefusal {
    /// The kernel is v2.6.27, where sub-call 18 is `paccept` (a six-word block), not `accept4`.
    SubCall18IsPaccept { release: String },
    /// The release is unknown, not a kernel version, or a v2.6.28 release candidate: nothing read rules out a kernel whose sub-call 18 is `paccept`.
    ReleaseNotVerified { release: Option<String> },
}

impl fmt::Display for SocketRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SubCall18IsPaccept { release } => write!(
                f,
                "kernel {release}: socketcall sub-call 18 is paccept (a six-word block) on this release, not accept4; the socketcall route is refused before any socket call"
            ),
            Self::ReleaseNotVerified {
                release: Some(release),
            } => write!(
                f,
                "kernel release {release:?} cannot be told from a release whose socketcall sub-call 18 is paccept; the socketcall route is refused before any socket call"
            ),
            Self::ReleaseNotVerified { release: None } => f.write_str(
                "the kernel's release is unknown, so a release whose socketcall sub-call 18 is paccept cannot be ruled out; the socketcall route is refused before any socket call",
            ),
        }
    }
}

impl std::error::Error for SocketRefusal {}

/// Whether the leaf may use the socket routes of `abi` on a kernel whose release is `release`.
///
/// Only a route that goes through `socketcall` sub-call 18 is concerned: the direct route is admitted on any release (a kernel without the direct
/// `accept4` answers its own `ENOSYS`, which the policy reads as absence).
///
/// # Errors
/// [`SocketRefusal::SubCall18IsPaccept`] for a v2.6.27 release, and [`SocketRefusal::ReleaseNotVerified`] for no release, a text that is not a
/// kernel version, or a v2.6.28 release candidate.
pub fn admit(abi: Abi, release: Option<&str>) -> Result<(), SocketRefusal> {
    let uses_sub_call_18 = matches!(
        socket_plan_for(abi).accept4,
        Route::ViaSocketCall { sub, .. } if sub == ACCEPT4_SUBCALL
    );
    if !uses_sub_call_18 {
        return Ok(());
    }
    let Some(text) = release else {
        return Err(SocketRefusal::ReleaseNotVerified { release: None });
    };
    let Some(parsed) = parse_release(text) else {
        return Err(SocketRefusal::ReleaseNotVerified {
            release: Some(text.to_owned()),
        });
    };
    if parsed.version == PACCEPT_KERNEL {
        return Err(SocketRefusal::SubCall18IsPaccept {
            release: text.to_owned(),
        });
    }
    if parsed.version == ACCEPT4_FIRST_KERNEL && parsed.pre_release {
        return Err(SocketRefusal::ReleaseNotVerified {
            release: Some(text.to_owned()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    #[test]
    fn each_op_is_issued_as_the_plan_routes_it_with_the_words_in_the_syscalls_own_order() {
        // PowerPC: socketcall (102) with the sub-call and the call's own arguments in a six-word block. Numbers typed from the kernel files and the
        // probes (see `numbers.rs`): sub-calls 1, 2, 4, 18, 10.
        let ppc = |sub, block| Issue::SocketCall {
            number: 102,
            sub,
            block,
        };
        let abi = Abi::PowerPc32;
        assert_eq!(
            issue_for(abi, SocketOp::Socket, socket_args(2, 0x80801, 0)),
            ppc(1, [2, 0x80801, 0, 0, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Bind, bind_args(6, 0x1000, 16)),
            ppc(2, [6, 0x1000, 16, 0, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Listen, listen_args(6, 8)),
            ppc(4, [6, 8, 0, 0, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Accept4, accept4_args(6, 0x80800)),
            ppc(18, [6, 0, 0, 0x80800, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Recv, recv_args(7, 0x2000, 16, 0x20)),
            ppc(10, [7, 0x2000, 16, 0x20, 0, 0])
        );
        // MIPS o32: the direct syscall with the same words in the argument registers.
        let abi = Abi::Mips32;
        let mips = |number, args| Issue::Direct { number, args };
        assert_eq!(
            issue_for(abi, SocketOp::Socket, socket_args(2, 0x80082, 0)),
            mips(4183, [2, 0x80082, 0, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Bind, bind_args(6, 0x1000, 16)),
            mips(4169, [6, 0x1000, 16, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Listen, listen_args(6, 8)),
            mips(4174, [6, 8, 0, 0, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Accept4, accept4_args(6, 0x80080)),
            mips(4334, [6, 0, 0, 0x80080, 0])
        );
        assert_eq!(
            issue_for(abi, SocketOp::Recv, recv_args(7, 0x2000, 16, 0x20)),
            mips(4175, [7, 0x2000, 16, 0x20, 0])
        );
    }

    #[test]
    fn the_argument_builders_put_the_syscalls_own_arguments_in_order_and_zero_the_rest() {
        assert_eq!(socket_args(10, 2, 0), [10, 2, 0, 0]);
        assert_eq!(bind_args(3, 0xAAAA, 28), [3, 0xAAAA, 28, 0]);
        assert_eq!(listen_args(3, 128), [3, 128, 0, 0]);
        // accept4 asks for no peer address: the address and length words are NULL, only the flags are set.
        assert_eq!(accept4_args(3, 0x80800), [3, 0, 0, 0x80800]);
        assert_eq!(recv_args(3, 0xBBBB, 64, 0x20), [3, 0xBBBB, 64, 0x20]);
    }

    #[test]
    fn a_negative_descriptor_keeps_its_32_bit_pattern_whatever_the_host_width() {
        // On the 32-bit device `-1 as usize` is 0xFFFF_FFFF; on a 64-bit host a sign-extending cast would give more. The builders go through u32.
        assert_eq!(listen_args(-1, 0)[0], 0xFFFF_FFFF);
        assert_eq!(accept4_args(-1, 0)[0], 0xFFFF_FFFF);
        assert_eq!(bind_args(-1, 0, 0)[0], 0xFFFF_FFFF);
        assert_eq!(recv_args(-1, 0, 0, 0)[0], 0xFFFF_FFFF);
        assert_eq!(listen_args(0, -1)[1], 0xFFFF_FFFF);
    }

    #[test]
    fn every_issue_fits_what_the_trampoline_and_the_kernel_read() {
        // The leaf's trampoline carries five registers; a socketcall block of six words covers the kernel's largest `nargs` entry (six).
        assert_eq!((LEAF_ARG_SLOTS, BLOCK_WORDS), (5, 6));
        let words = [1, 2, 3, 4];
        for abi in BOTH {
            for op in SocketOp::ALL {
                match issue_for(abi, op, words) {
                    Issue::Direct { args, .. } => {
                        assert_eq!(abi, Abi::Mips32, "{abi:?} {op:?}");
                        assert_eq!(args, [1, 2, 3, 4, 0], "{abi:?} {op:?}");
                    }
                    Issue::SocketCall { block, .. } => {
                        assert_eq!(abi, Abi::PowerPc32, "{abi:?} {op:?}");
                        assert_eq!(block, [1, 2, 3, 4, 0, 0], "{abi:?} {op:?}");
                    }
                }
            }
        }
        for abi in BOTH {
            for (name, route) in socket_plan_for(abi).routes() {
                assert!(route.fits_the_leaf(), "{abi:?} {name}");
            }
        }
    }

    #[test]
    fn release_strings_parse_to_the_first_three_numbers_and_the_pre_release_mark() {
        let version = |major, minor, patch| KernelVersion {
            major,
            minor,
            patch,
        };
        let cases = [
            ("2.6.14", version(2, 6, 14), false),
            ("2.6.27", version(2, 6, 27), false),
            ("2.6.27.59", version(2, 6, 27), false),
            ("2.6.27-rc3", version(2, 6, 27), true),
            ("2.6.28-rc1", version(2, 6, 28), true),
            ("2.6.35.14-vendor", version(2, 6, 35), false),
            ("4.19.0-21-4kc-malta", version(4, 19, 0), false),
            ("4.9.0-0.bpo.6-powerpc", version(4, 9, 0), false),
            ("  3.10.108\n", version(3, 10, 108), false),
        ];
        for (text, expected, pre_release) in cases {
            assert_eq!(
                parse_release(text),
                Some(Release {
                    version: expected,
                    pre_release
                }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_release_that_is_not_a_kernel_version_is_not_parsed() {
        for text in [
            "",
            "2.6",
            "2",
            "x.y.z",
            "linux-2.6.27",
            "2..27",
            ".6.27",
            "99999999999.1.1",
            "2.6.x",
        ] {
            assert_eq!(parse_release(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_socketcall_route_is_refused_by_name_on_v2_6_27_and_its_neighbours_are_admitted() {
        // Refused: every v2.6.27 release, with or without a stable-update number, a release-candidate mark or a vendor suffix.
        for text in ["2.6.27", "2.6.27.59", "2.6.27-rc3", "2.6.27.4-vendor"] {
            assert_eq!(
                admit(Abi::PowerPc32, Some(text)),
                Err(SocketRefusal::SubCall18IsPaccept {
                    release: text.to_owned()
                }),
                "{text:?}"
            );
        }
        // Admitted: the releases on either side of it, and the harness guests' kernels. Each refusal above is paired with these permitted positives.
        for text in [
            "2.6.14",
            "2.6.26.8",
            "2.6.28",
            "2.6.28.10",
            "2.6.35.14",
            "3.10.108",
            "4.9.0-0.bpo.6-powerpc",
            "4.19.0-21-4kc-malta",
        ] {
            assert_eq!(admit(Abi::PowerPc32, Some(text)), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn a_release_that_cannot_rule_out_v2_6_27_is_not_admitted_for_the_socketcall_route() {
        assert_eq!(
            admit(Abi::PowerPc32, None),
            Err(SocketRefusal::ReleaseNotVerified { release: None })
        );
        for text in ["", "garbage", "2.6", "2.6.28-rc1", "2.6.28-rc7"] {
            assert_eq!(
                admit(Abi::PowerPc32, Some(text)),
                Err(SocketRefusal::ReleaseNotVerified {
                    release: Some(text.to_owned())
                }),
                "{text:?}"
            );
        }
        // The permitted pairs: the final 2.6.28 and a later release candidate-free kernel.
        assert_eq!(admit(Abi::PowerPc32, Some("2.6.28")), Ok(()));
        assert_eq!(admit(Abi::PowerPc32, Some("2.6.29-rc1")), Ok(()));
    }

    #[test]
    fn the_direct_route_does_not_depend_on_the_release() {
        for release in [
            None,
            Some(""),
            Some("garbage"),
            Some("2.6.27"),
            Some("2.6.28-rc1"),
            Some("4.19.0-21-4kc-malta"),
        ] {
            assert_eq!(admit(Abi::Mips32, release), Ok(()), "{release:?}");
        }
    }

    #[test]
    fn the_admission_rule_applies_exactly_where_sub_call_18_is_used() {
        for abi in BOTH {
            let uses_it = matches!(
                socket_plan_for(abi).accept4,
                Route::ViaSocketCall {
                    sub: ACCEPT4_SUBCALL,
                    ..
                }
            );
            assert_eq!(admit(abi, None).is_err(), uses_it, "{abi:?}");
        }
        assert!(matches!(
            socket_plan_for(Abi::PowerPc32).accept4,
            Route::ViaSocketCall { sub: 18, .. }
        ));
        assert!(matches!(
            socket_plan_for(Abi::Mips32).accept4,
            Route::Direct { .. }
        ));
    }

    #[test]
    fn a_refusal_says_which_release_and_why() {
        let text = SocketRefusal::SubCall18IsPaccept {
            release: "2.6.27.59".to_owned(),
        }
        .to_string();
        assert!(
            text.contains("2.6.27.59")
                && text.contains("paccept")
                && text.contains("before any socket call"),
            "{text}"
        );
        let text = SocketRefusal::ReleaseNotVerified {
            release: Some("garbage".to_owned()),
        }
        .to_string();
        assert!(
            text.contains("\"garbage\"") && text.contains("before any socket call"),
            "{text}"
        );
        let text = SocketRefusal::ReleaseNotVerified { release: None }.to_string();
        assert!(
            text.contains("unknown") && text.contains("before any socket call"),
            "{text}"
        );
    }
}
