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
//!
//! A second table, [`P06Calls`], holds the calls the `P06` primitives (`franken-platform`'s `net` and `durable` modules) are used with,
//! seventeen in all, each with its **slot count**: the arguments the kernel's entry takes, which the leaf's five-slot trampoline
//! ([`LEAF_ARG_SLOTS`], `sys.rs`) must be able to carry. Nothing issues these calls yet: it is data and tests, with no wrapper, no
//! `KernelOps` method and no `unsafe` (`docs/contracts/p06.md`, S3). Three witnesses hold it, each where it applies: the E03 probes
//! that issued the call, the `libc` crate's tables, and the kernel's own `unistd.h`, call table and prototypes at v2.6.14 and v2.6.35
//! (`tests/p02/test_syscall_numbers.py`). The fact that matters most is in [`SocketCall`]: **the stock 32-bit PowerPC kernel has no
//! direct socket calls**, only `socketcall`, while the E03 guests' newer kernels do.

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

/// How many argument slots the leaf's `raw5` trampoline carries (`sys.rs`: "up to five arguments"; on MIPS o32 the fifth is passed on the
/// stack). A call whose entry takes more cannot be issued through it, whatever its number.
pub const LEAF_ARG_SLOTS: usize = 5;

/// One call as an ABI has it: its syscall number and how many argument slots the kernel's entry for it takes.
///
/// A slot is one register-sized argument. A 64-bit argument takes two, starting on an even register pair on both ABIs, and the pad slot
/// counts: `pread64` and `pwrite64` are `(fd, buf, count, pad, hi, lo)`, six slots, one more than the leaf can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    pub number: usize,
    pub slots: usize,
}

impl Call {
    /// Whether the leaf's trampoline can carry every argument of this call.
    #[must_use]
    pub const fn fits_the_leaf(self) -> bool {
        self.slots <= LEAF_ARG_SLOTS
    }
}

/// A socket-family call, which an ABI may have as a direct syscall, as a `socketcall` sub-call, or both.
///
/// **The stock 32-bit PowerPC kernel (2.6.14, read again at 2.6.35) has no direct socket syscalls:** its table has `socketcall` (102) and
/// nothing else, so `direct_on_stock` is `false` and a caller there issues `socketcall(sub, args)`, two slots, with the arguments in a
/// block in memory. The direct numbers PowerPC has here (326 and on) belong to newer kernels, and the E03 guests (4.x) issued them. MIPS
/// o32 has both forms at 2.6.14 and 2.6.35.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketCall {
    /// The `socketcall` sub-call number (`linux/net.h`): the same on every architecture.
    pub sub: usize,
    /// The direct syscall and the slots of its entry.
    pub direct: Call,
    /// Whether the stock kernel (2.6.x) has the direct syscall.
    pub direct_on_stock: bool,
}

/// The calls the `P06` primitives are used with, per legacy ABI (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P06Calls {
    pub poll: Call,
    /// The multiplexed socket entry: `socketcall(sub, args)`.
    pub socketcall: Call,
    pub socket: SocketCall,
    pub bind: SocketCall,
    pub connect: SocketCall,
    pub getsockname: SocketCall,
    pub send: SocketCall,
    pub recv: SocketCall,
    pub sendto: SocketCall,
    pub recvfrom: SocketCall,
    pub setsockopt: SocketCall,
    pub fsync: Call,
    pub rename: Call,
    pub unlink: Call,
    /// `_llseek(fd, hi, lo, &result, whence)`: five slots, the result stored through a pointer.
    pub llseek: Call,
    pub pread64: Call,
    pub pwrite64: Call,
}

impl P06Calls {
    /// Every call by its syscall name, in a fixed order, a socket-family call as its direct form.
    #[must_use]
    pub const fn calls(&self) -> [(&'static str, Call); 17] {
        [
            ("poll", self.poll),
            ("socketcall", self.socketcall),
            ("socket", self.socket.direct),
            ("bind", self.bind.direct),
            ("connect", self.connect.direct),
            ("getsockname", self.getsockname.direct),
            ("send", self.send.direct),
            ("recv", self.recv.direct),
            ("sendto", self.sendto.direct),
            ("recvfrom", self.recvfrom.direct),
            ("setsockopt", self.setsockopt.direct),
            ("fsync", self.fsync),
            ("rename", self.rename),
            ("unlink", self.unlink),
            ("_llseek", self.llseek),
            ("pread64", self.pread64),
            ("pwrite64", self.pwrite64),
        ]
    }

    /// Every socket-family call by name, in a fixed order.
    #[must_use]
    pub const fn socket_calls(&self) -> [(&'static str, SocketCall); 9] {
        [
            ("socket", self.socket),
            ("bind", self.bind),
            ("connect", self.connect),
            ("getsockname", self.getsockname),
            ("send", self.send),
            ("recv", self.recv),
            ("sendto", self.sendto),
            ("recvfrom", self.recvfrom),
            ("setsockopt", self.setsockopt),
        ]
    }
}

/// PowerPC32: `socketcall` only on the stock kernel; the direct numbers are those of newer kernels.
pub const P06_POWERPC32: P06Calls = P06Calls {
    poll: Call {
        number: 167,
        slots: 3,
    },
    socketcall: Call {
        number: 102,
        slots: 2,
    },
    socket: SocketCall {
        sub: 1,
        direct: Call {
            number: 326,
            slots: 3,
        },
        direct_on_stock: false,
    },
    bind: SocketCall {
        sub: 2,
        direct: Call {
            number: 327,
            slots: 3,
        },
        direct_on_stock: false,
    },
    connect: SocketCall {
        sub: 3,
        direct: Call {
            number: 328,
            slots: 3,
        },
        direct_on_stock: false,
    },
    getsockname: SocketCall {
        sub: 6,
        direct: Call {
            number: 331,
            slots: 3,
        },
        direct_on_stock: false,
    },
    send: SocketCall {
        sub: 9,
        direct: Call {
            number: 334,
            slots: 4,
        },
        direct_on_stock: false,
    },
    recv: SocketCall {
        sub: 10,
        direct: Call {
            number: 336,
            slots: 4,
        },
        direct_on_stock: false,
    },
    sendto: SocketCall {
        sub: 11,
        direct: Call {
            number: 335,
            slots: 6,
        },
        direct_on_stock: false,
    },
    recvfrom: SocketCall {
        sub: 12,
        direct: Call {
            number: 337,
            slots: 6,
        },
        direct_on_stock: false,
    },
    setsockopt: SocketCall {
        sub: 14,
        direct: Call {
            number: 339,
            slots: 5,
        },
        direct_on_stock: false,
    },
    fsync: Call {
        number: 118,
        slots: 1,
    },
    rename: Call {
        number: 38,
        slots: 2,
    },
    unlink: Call {
        number: 10,
        slots: 1,
    },
    llseek: Call {
        number: 140,
        slots: 5,
    },
    pread64: Call {
        number: 179,
        slots: 6,
    },
    pwrite64: Call {
        number: 180,
        slots: 6,
    },
};

/// MIPS o32 (base 4000): direct socket calls and `socketcall` both exist on the stock kernel.
pub const P06_MIPS32_O32: P06Calls = P06Calls {
    poll: Call {
        number: 4000 + 188,
        slots: 3,
    },
    socketcall: Call {
        number: 4000 + 102,
        slots: 2,
    },
    socket: SocketCall {
        sub: 1,
        direct: Call {
            number: 4000 + 183,
            slots: 3,
        },
        direct_on_stock: true,
    },
    bind: SocketCall {
        sub: 2,
        direct: Call {
            number: 4000 + 169,
            slots: 3,
        },
        direct_on_stock: true,
    },
    connect: SocketCall {
        sub: 3,
        direct: Call {
            number: 4000 + 170,
            slots: 3,
        },
        direct_on_stock: true,
    },
    getsockname: SocketCall {
        sub: 6,
        direct: Call {
            number: 4000 + 172,
            slots: 3,
        },
        direct_on_stock: true,
    },
    send: SocketCall {
        sub: 9,
        direct: Call {
            number: 4000 + 178,
            slots: 4,
        },
        direct_on_stock: true,
    },
    recv: SocketCall {
        sub: 10,
        direct: Call {
            number: 4000 + 175,
            slots: 4,
        },
        direct_on_stock: true,
    },
    sendto: SocketCall {
        sub: 11,
        direct: Call {
            number: 4000 + 180,
            slots: 6,
        },
        direct_on_stock: true,
    },
    recvfrom: SocketCall {
        sub: 12,
        direct: Call {
            number: 4000 + 176,
            slots: 6,
        },
        direct_on_stock: true,
    },
    setsockopt: SocketCall {
        sub: 14,
        direct: Call {
            number: 4000 + 181,
            slots: 5,
        },
        direct_on_stock: true,
    },
    fsync: Call {
        number: 4000 + 118,
        slots: 1,
    },
    rename: Call {
        number: 4000 + 38,
        slots: 2,
    },
    unlink: Call {
        number: 4000 + 10,
        slots: 1,
    },
    llseek: Call {
        number: 4000 + 140,
        slots: 5,
    },
    pread64: Call {
        number: 4000 + 200,
        slots: 6,
    },
    pwrite64: Call {
        number: 4000 + 201,
        slots: 6,
    },
};

/// The `P06` calls for `abi`.
#[must_use]
pub const fn p06_for_abi(abi: Abi) -> P06Calls {
    match abi {
        Abi::PowerPc32 => P06_POWERPC32,
        Abi::Mips32 => P06_MIPS32_O32,
    }
}

// ------------------------------------------------------------------------------------------ the socket capability

/// The highest `socketcall` sub-call the stock 2.6.14 kernel accepts: `SYS_RECVMSG`, 17, in `linux/net.h`. Its `sys_socketcall` answers anything above
/// that with `-EINVAL`, not `-ENOSYS` (`net/socket.c`, v2.6.14: `if (call < 1 || call > SYS_RECVMSG) return -EINVAL;`); `accept4` is sub-call 18 (absent from
/// the v2.6.14 `net.h`). **Sub-call 18 is not `accept4` on every kernel above that bound:** at v2.6.27 it is `paccept` (`SYS_PACCEPT`, six words in the block,
/// not four), and `accept4` replaced it at v2.6.28; so the `socketcall` route for `accept4` must not be used on a v2.6.27 kernel (the verbatim lines are in
/// `tests/p02/socket_kernel_evidence.json`).
pub const STOCK_SOCKETCALL_MAX_SUB: usize = 17;

/// `listen` and `accept4`: the two socket-family calls the socket capability (`franken-platform`'s `socket` module, `docs/contracts/p02.md`) needs that
/// [`P06Calls`] does not hold. A row means what a `P06Calls` row means ([`SocketCall`]).
///
/// **`accept4` is on neither stock kernel, by either route:** MIPS o32 has no entry 4334 in its v2.6.14 call table (the direct number came later) and the
/// stock `socketcall` has no sub-call 18. So `direct_on_stock` is `false` for `accept4` on both ABIs, where `listen` is a stock call on MIPS (direct) and,
/// on PowerPC, a stock `socketcall` sub-call (the direct number is a newer kernel's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerCalls {
    pub listen: SocketCall,
    pub accept4: SocketCall,
}

/// PowerPC32: the direct numbers (329, 344) are those the E03 guests' newer kernels have; the stock kernel has neither.
pub const SERVER_POWERPC32: ServerCalls = ServerCalls {
    listen: SocketCall {
        sub: 4,
        direct: Call {
            number: 329,
            slots: 2,
        },
        direct_on_stock: false,
    },
    accept4: SocketCall {
        sub: 18,
        direct: Call {
            number: 344,
            slots: 4,
        },
        direct_on_stock: false,
    },
};

/// MIPS o32 (base 4000): `listen` is a stock direct call; `accept4` (4334) is not.
pub const SERVER_MIPS32_O32: ServerCalls = ServerCalls {
    listen: SocketCall {
        sub: 4,
        direct: Call {
            number: 4000 + 174,
            slots: 2,
        },
        direct_on_stock: true,
    },
    accept4: SocketCall {
        sub: 18,
        direct: Call {
            number: 4000 + 334,
            slots: 4,
        },
        direct_on_stock: false,
    },
};

/// The `listen` and `accept4` rows for `abi`.
#[must_use]
pub const fn server_for_abi(abi: Abi) -> ServerCalls {
    match abi {
        Abi::PowerPc32 => SERVER_POWERPC32,
        Abi::Mips32 => SERVER_MIPS32_O32,
    }
}

/// How the leaf reaches one socket-family call on one ABI. Plain data: nothing here issues a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The direct syscall, its arguments in registers.
    Direct {
        call: Call,
        /// Whether the stock 2.6.14 kernel has this syscall.
        on_stock: bool,
    },
    /// `socketcall(sub, &block)`: two slots, the call's own arguments in a block of `block_words` machine words in memory (the kernel's `nargs[sub]`,
    /// which equals the direct entry's slot count). Passing the address of that block is the leaf's one new `unsafe` obligation.
    ViaSocketCall {
        socketcall: Call,
        sub: usize,
        block_words: usize,
        /// Whether the stock 2.6.14 `socketcall` accepts `sub` (`sub <= STOCK_SOCKETCALL_MAX_SUB`).
        on_stock: bool,
    },
}

impl Route {
    /// Whether the leaf's trampoline can carry every register argument of this route.
    #[must_use]
    pub const fn fits_the_leaf(self) -> bool {
        match self {
            Self::Direct { call, .. } => call.fits_the_leaf(),
            Self::ViaSocketCall { socketcall, .. } => socketcall.fits_the_leaf(),
        }
    }

    /// Whether the stock 2.6.14 kernel has this route. (Not a statement about the flags in `socket`'s `type`, which that kernel refuses: see
    /// `Abi::socket_type_arg`.)
    #[must_use]
    pub const fn on_stock(self) -> bool {
        match self {
            Self::Direct { on_stock, .. } | Self::ViaSocketCall { on_stock, .. } => on_stock,
        }
    }
}

/// The route of each call of the socket capability on one ABI.
///
/// **`socketcall` on PowerPC, direct on MIPS o32** (BeigeMaple 6790): the stock PowerPC kernel has no direct socket syscall at all, and `socketcall` exists
/// on every kernel in scope, so the PowerPC leaf uses it throughout, newer kernels included. MIPS o32 has the direct calls on the stock kernel, and every
/// call here fits the leaf's five slots direct. `recvfrom` (six slots) is not in the plan: see [`P06Calls::recvfrom`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPlan {
    pub socket: Route,
    pub bind: Route,
    pub listen: Route,
    pub accept4: Route,
    pub recv: Route,
}

impl SocketPlan {
    /// Every route by syscall name, in the order a server issues them.
    #[must_use]
    pub const fn routes(&self) -> [(&'static str, Route); 5] {
        [
            ("socket", self.socket),
            ("bind", self.bind),
            ("listen", self.listen),
            ("accept4", self.accept4),
            ("recv", self.recv),
        ]
    }
}

const fn route(abi: Abi, socketcall: Call, row: SocketCall) -> Route {
    match abi {
        Abi::PowerPc32 => Route::ViaSocketCall {
            socketcall,
            sub: row.sub,
            block_words: row.direct.slots,
            on_stock: row.sub <= STOCK_SOCKETCALL_MAX_SUB,
        },
        Abi::Mips32 => Route::Direct {
            call: row.direct,
            on_stock: row.direct_on_stock,
        },
    }
}

/// The socket capability's routes for `abi`, built from the `P06Calls` rows (`socket`, `bind`, `recv`) and the [`ServerCalls`] rows (`listen`, `accept4`),
/// so no number is stated twice.
#[must_use]
pub const fn socket_plan_for(abi: Abi) -> SocketPlan {
    let p06 = p06_for_abi(abi);
    let server = server_for_abi(abi);
    SocketPlan {
        socket: route(abi, p06.socketcall, p06.socket),
        bind: route(abi, p06.socketcall, p06.bind),
        listen: route(abi, p06.socketcall, server.listen),
        accept4: route(abi, p06.socketcall, server.accept4),
        recv: route(abi, p06.socketcall, p06.recv),
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

    #[test]
    fn the_p06_tables_differ_per_abi_in_every_number_and_share_every_sub_call() {
        assert_eq!(p06_for_abi(Abi::PowerPc32), P06_POWERPC32);
        assert_eq!(p06_for_abi(Abi::Mips32), P06_MIPS32_O32);
        for ((name, a), (other, b)) in P06_POWERPC32
            .calls()
            .into_iter()
            .zip(P06_MIPS32_O32.calls())
        {
            assert_eq!(name, other);
            assert_ne!(a.number, b.number, "{name}");
        }
        for ((name, a), (other, b)) in P06_POWERPC32
            .socket_calls()
            .into_iter()
            .zip(P06_MIPS32_O32.socket_calls())
        {
            assert_eq!(name, other);
            assert_eq!(a.sub, b.sub, "{name}: a sub-call number is not the ABI's");
        }
    }

    #[test]
    fn the_p06_numbers_and_slots_are_the_ones_the_kernel_tables_and_the_guest_probes_give() {
        // Typed by hand from the v2.6.14 and v2.6.35 `unistd.h` files, the MIPS o32 call table (`scall32-o32.S`: slots), the 32-bit PowerPC
        // `systbl.h` and `sys_ppc32.c` (`compat_sys_pread64(fd, buf, count, reg6, poshi, poslo)`), and the E03 probes' `nr` modules. The PowerPC
        // socket numbers (326 and on) are those of the newer kernels the E03 guests run; the 2.6 tables have none.
        let mips = P06_MIPS32_O32
            .calls()
            .map(|(name, call)| (name, call.number, call.slots));
        assert_eq!(
            mips,
            [
                ("poll", 4188, 3),
                ("socketcall", 4102, 2),
                ("socket", 4183, 3),
                ("bind", 4169, 3),
                ("connect", 4170, 3),
                ("getsockname", 4172, 3),
                ("send", 4178, 4),
                ("recv", 4175, 4),
                ("sendto", 4180, 6),
                ("recvfrom", 4176, 6),
                ("setsockopt", 4181, 5),
                ("fsync", 4118, 1),
                ("rename", 4038, 2),
                ("unlink", 4010, 1),
                ("_llseek", 4140, 5),
                ("pread64", 4200, 6),
                ("pwrite64", 4201, 6),
            ]
        );
        let ppc = P06_POWERPC32
            .calls()
            .map(|(name, call)| (name, call.number, call.slots));
        assert_eq!(
            ppc,
            [
                ("poll", 167, 3),
                ("socketcall", 102, 2),
                ("socket", 326, 3),
                ("bind", 327, 3),
                ("connect", 328, 3),
                ("getsockname", 331, 3),
                ("send", 334, 4),
                ("recv", 336, 4),
                ("sendto", 335, 6),
                ("recvfrom", 337, 6),
                ("setsockopt", 339, 5),
                ("fsync", 118, 1),
                ("rename", 38, 2),
                ("unlink", 10, 1),
                ("_llseek", 140, 5),
                ("pread64", 179, 6),
                ("pwrite64", 180, 6),
            ]
        );
    }

    #[test]
    fn a_powerpc_socket_call_is_direct_only_off_the_stock_kernel() {
        for (name, call) in P06_POWERPC32.socket_calls() {
            assert!(
                !call.direct_on_stock,
                "{name}: the stock PowerPC kernel has no direct socket call"
            );
        }
        for (name, call) in P06_MIPS32_O32.socket_calls() {
            assert!(call.direct_on_stock, "{name}");
        }
        // `linux/net.h`: SYS_SOCKET 1, SYS_BIND 2, SYS_CONNECT 3, SYS_GETSOCKNAME 6, SYS_SEND 9, SYS_RECV 10, SYS_SENDTO 11, SYS_RECVFROM 12, SYS_SETSOCKOPT 14.
        for table in [P06_POWERPC32, P06_MIPS32_O32] {
            assert_eq!(
                table.socket_calls().map(|(_, call)| call.sub),
                [1, 2, 3, 6, 9, 10, 11, 12, 14]
            );
            assert_eq!(table.socketcall.slots, 2, "socketcall(sub, args)");
        }
    }

    #[test]
    fn exactly_these_calls_need_more_slots_than_the_leaf_carries() {
        assert_eq!(LEAF_ARG_SLOTS, 5);
        for table in [P06_POWERPC32, P06_MIPS32_O32] {
            let too_big: Vec<&str> = table
                .calls()
                .into_iter()
                .filter(|(_, call)| !call.fits_the_leaf())
                .map(|(name, _)| name)
                .collect();
            assert_eq!(too_big, ["sendto", "recvfrom", "pread64", "pwrite64"]);
        }
    }

    #[test]
    fn p06_mips_numbers_are_four_thousand_based_powerpc_numbers_are_not_and_none_repeats() {
        for (name, call) in P06_MIPS32_O32.calls() {
            assert!((4000..5000).contains(&call.number), "{name}");
        }
        for (name, call) in P06_POWERPC32.calls() {
            assert!(call.number < 1000, "{name}");
        }
        for table in [P06_POWERPC32, P06_MIPS32_O32] {
            let mut numbers: Vec<usize> = table
                .calls()
                .into_iter()
                .map(|(_, call)| call.number)
                .collect();
            numbers.sort_unstable();
            numbers.dedup();
            assert_eq!(numbers.len(), 17, "two calls share a number");
        }
    }

    // ---- the socket capability's plan (`franken-platform`'s `socket` module is the policy; this is the route each call takes)

    const BOTH_ABIS: [Abi; 2] = [Abi::PowerPc32, Abi::Mips32];

    /// What a route is made of, in the unit that matters for its kind: (syscall number, slots) direct, or (sub-call, words in the block) by `socketcall`.
    fn shape(route: Route) -> (usize, usize) {
        match route {
            Route::Direct { call, .. } => (call.number, call.slots),
            Route::ViaSocketCall {
                sub, block_words, ..
            } => (sub, block_words),
        }
    }

    #[test]
    fn the_socket_plan_is_socketcall_on_powerpc_and_direct_on_mips_for_every_call() {
        for (name, route) in socket_plan_for(Abi::PowerPc32).routes() {
            let Route::ViaSocketCall { socketcall, .. } = route else {
                panic!("{name}: the PowerPC plan is socketcall throughout, got {route:?}");
            };
            assert_eq!(
                socketcall,
                Call {
                    number: 102,
                    slots: 2
                },
                "{name}: socketcall(sub, args) is syscall 102 with two slots"
            );
        }
        for (name, route) in socket_plan_for(Abi::Mips32).routes() {
            assert!(
                matches!(route, Route::Direct { .. }),
                "{name}: the MIPS o32 plan is direct throughout, got {route:?}"
            );
        }
        // The MIPS plan does not name socketcall's number, so a swapped plan cannot hide behind equal shapes.
        assert_eq!(P06_MIPS32_O32.socketcall.number, 4102);
    }

    #[test]
    fn the_socket_plan_numbers_sub_calls_and_block_sizes_are_the_ones_typed_from_the_kernel_files_and_for_mips_the_probes()
     {
        // PowerPC: (sub-call, words in the socketcall block). KERNEL FILES ONLY: no guest has ever issued a `socketcall` (the E03 probes issue direct calls), so
        // nothing but these typed numbers witnesses this route. `linux/net.h`: SYS_SOCKET 1, SYS_BIND 2, SYS_LISTEN 4, SYS_RECV 10, SYS_ACCEPT4 18 (v2.6.28 on; v2.6.27
        // had `paccept` there); the kernel's `nargs` table: AL(3), AL(3), AL(2), AL(4), AL(4) at those indices.
        let ppc = socket_plan_for(Abi::PowerPc32)
            .routes()
            .map(|(name, route)| (name, shape(route)));
        assert_eq!(
            ppc,
            [
                ("socket", (1, 3)),
                ("bind", (2, 3)),
                ("listen", (4, 2)),
                ("accept4", (18, 4)),
                ("recv", (10, 4)),
            ]
        );
        // MIPS o32: (syscall number, slots). `unistd.h`: __NR_Linux + 183, 169, 174, 334, 175; the o32 call table: `sys sys_listen 2`, `sys sys_accept4 4`.
        let mips = socket_plan_for(Abi::Mips32)
            .routes()
            .map(|(name, route)| (name, shape(route)));
        assert_eq!(
            mips,
            [
                ("socket", (4183, 3)),
                ("bind", (4169, 3)),
                ("listen", (4174, 2)),
                ("accept4", (4334, 4)),
                ("recv", (4175, 4)),
            ]
        );
    }

    #[test]
    fn the_socket_plan_reuses_the_s3_rows_and_adds_only_listen_and_accept4() {
        for abi in BOTH_ABIS {
            let p06 = p06_for_abi(abi);
            let server = server_for_abi(abi);
            let plan = socket_plan_for(abi);
            let expected_route = |row: SocketCall| match abi {
                Abi::PowerPc32 => Route::ViaSocketCall {
                    socketcall: p06.socketcall,
                    sub: row.sub,
                    block_words: row.direct.slots,
                    on_stock: row.sub <= 17,
                },
                Abi::Mips32 => Route::Direct {
                    call: row.direct,
                    on_stock: row.direct_on_stock,
                },
            };
            assert_eq!(plan.socket, expected_route(p06.socket), "{abi:?}");
            assert_eq!(plan.bind, expected_route(p06.bind), "{abi:?}");
            assert_eq!(plan.recv, expected_route(p06.recv), "{abi:?}");
            assert_eq!(plan.listen, expected_route(server.listen), "{abi:?}");
            assert_eq!(plan.accept4, expected_route(server.accept4), "{abi:?}");
        }
    }

    #[test]
    fn every_route_of_the_plan_fits_the_leaf_and_recvfrom_direct_is_the_call_that_does_not() {
        for abi in BOTH_ABIS {
            for (name, route) in socket_plan_for(abi).routes() {
                assert!(route.fits_the_leaf(), "{abi:?} {name}");
            }
        }
        // The known gap: the sender-returning read is six slots direct, so it is not in the plan; its socketcall form is two slots.
        let mips = p06_for_abi(Abi::Mips32);
        assert!(!mips.recvfrom.direct.fits_the_leaf());
        assert!(mips.socketcall.fits_the_leaf());
    }

    #[test]
    fn accept4_is_on_neither_stock_route_and_every_other_call_of_the_plan_is() {
        assert_eq!(STOCK_SOCKETCALL_MAX_SUB, 17);
        for abi in BOTH_ABIS {
            for (name, route) in socket_plan_for(abi).routes() {
                assert_eq!(route.on_stock(), name != "accept4", "{abi:?} {name}");
            }
        }
        // On PowerPC the answer is the sub-call bound, not a label.
        for (name, route) in socket_plan_for(Abi::PowerPc32).routes() {
            let Route::ViaSocketCall { sub, on_stock, .. } = route else {
                panic!("{name}: not a socketcall route");
            };
            assert_eq!(on_stock, sub <= STOCK_SOCKETCALL_MAX_SUB, "{name}");
        }
    }

    #[test]
    fn the_server_rows_differ_per_abi_share_sub_calls_and_repeat_no_p06_number() {
        let (p, m) = (SERVER_POWERPC32, SERVER_MIPS32_O32);
        assert_eq!(server_for_abi(Abi::PowerPc32), p);
        assert_eq!(server_for_abi(Abi::Mips32), m);
        assert_ne!(p.listen.direct.number, m.listen.direct.number);
        assert_ne!(p.accept4.direct.number, m.accept4.direct.number);
        assert_eq!((p.listen.sub, p.accept4.sub), (4, 18));
        assert_eq!((m.listen.sub, m.accept4.sub), (4, 18));
        assert!(p.listen.direct.number < 1000 && p.accept4.direct.number < 1000);
        assert!(
            (4000..5000).contains(&m.listen.direct.number)
                && (4000..5000).contains(&m.accept4.direct.number)
        );
        for (rows, table) in [(p, P06_POWERPC32), (m, P06_MIPS32_O32)] {
            let taken: Vec<usize> = table
                .calls()
                .into_iter()
                .map(|(_, call)| call.number)
                .collect();
            for number in [rows.listen.direct.number, rows.accept4.direct.number] {
                assert!(
                    !taken.contains(&number),
                    "{number} is already another call's"
                );
            }
        }
    }

    #[test]
    fn the_server_rows_are_the_numbers_the_audited_guest_probes_issued() {
        // `nr::LISTEN` and `nr::ACCEPT4` in toolchain/src/ffw-hello-init/src/e03_probes/net.rs, which issued them in full-system guests.
        assert_eq!(
            (
                SERVER_MIPS32_O32.listen.direct.number,
                SERVER_MIPS32_O32.accept4.direct.number
            ),
            (4174, 4334)
        );
        assert_eq!(
            (
                SERVER_POWERPC32.listen.direct.number,
                SERVER_POWERPC32.accept4.direct.number
            ),
            (329, 344)
        );
        // The slots: listen(fd, backlog) is two, accept4(fd, addr, addrlen, flags) is four.
        for rows in [SERVER_POWERPC32, SERVER_MIPS32_O32] {
            assert_eq!(
                (rows.listen.direct.slots, rows.accept4.direct.slots),
                (2, 4)
            );
        }
    }
}
