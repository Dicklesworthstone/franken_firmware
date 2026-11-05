//! P05's semantic 64-bit cells on the big-endian MIPS32 device target, run as PID 1 under QEMU.
//!
//! Bead ffw-ipz, open item `P05-EXT-GUEST`. This program includes the frozen `crates/franken-atomic` source files BY PATH,
//! unchanged, under their own module names, so it compiles the exact text the host tests run. It prints `FFW_P05T_*` lines;
//! `toolchain/src/measure-p05-target.py` runs it under QEMU and JUDGES the transcript against an independent Python
//! reference (`tests/p05/reference.py`) and hand-written vectors. The guest computes no expected value of its own.
//!
//! What a pass can and cannot say is written in the judge's footer. In short: the same source behaves as the reference says on
//! a 32-bit big-endian guest, under real preemption on a single CPU, on the Debian 4.19 Malta kernel; not the stock board
//! kernel, not a board.
//!
//! Replay defence: the host packs a per-run seed into `/ffw_seed`. The seeded sweeps start at that seed, so a transcript from
//! another run carries the wrong histories. `/plant-replay` (with `/replay`) makes the guest print an earlier run's seeded
//! sweep lines instead of computing them, so the judge can be shown to refuse exactly that.
#![allow(dead_code, unused_imports)]

#[path = "../../../../crates/franken-atomic/src/counter.rs"]
mod counter;
#[path = "../../../../crates/franken-atomic/src/error.rs"]
mod error;
#[path = "../../../../crates/franken-atomic/src/local.rs"]
mod local;
#[path = "../../../../crates/franken-atomic/src/model.rs"]
mod model;
#[path = "../../../../crates/franken-atomic/src/planted.rs"]
mod planted;
#[path = "../../../../crates/franken-atomic/src/shared.rs"]
mod shared;

use counter::Sequence;
use error::{ArithError, Exhausted};
use local::LocalU64;
use model::{
    Event, INITIAL, Kind, Op, POOL, Resp, SplitMix64, Verdict, apply_real, check, gen_plans,
    scripted_run, seeded_run,
};
use shared::{SharedI64, SharedU64};
use std::io::Write;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The same pinned profile file the host tests read (`tests/p05/vectors.txt`).
const VECTORS: &str = include_str!("../../../../tests/p05/vectors.txt");
/// The checker's node budget the host tests use for the seeded sweeps and the directed scripts.
const BUDGET: usize = 200_000;
/// The budget the host test uses for histories recorded from real threads.
const THREADED_BUDGET: usize = 2_000_000;
const THREADS: usize = 4;

/// The files this binary compiled, and the shared vectors, so the judge can bind the run to the repository's text.
const SOURCES: [(&str, &[u8]); 7] = [
    (
        "error.rs",
        include_bytes!("../../../../crates/franken-atomic/src/error.rs") as &[u8],
    ),
    (
        "shared.rs",
        include_bytes!("../../../../crates/franken-atomic/src/shared.rs") as &[u8],
    ),
    (
        "counter.rs",
        include_bytes!("../../../../crates/franken-atomic/src/counter.rs") as &[u8],
    ),
    (
        "local.rs",
        include_bytes!("../../../../crates/franken-atomic/src/local.rs") as &[u8],
    ),
    (
        "model.rs",
        include_bytes!("../../../../crates/franken-atomic/src/model.rs") as &[u8],
    ),
    (
        "planted.rs",
        include_bytes!("../../../../crates/franken-atomic/src/planted.rs") as &[u8],
    ),
    (
        "vectors.txt",
        include_bytes!("../../../../tests/p05/vectors.txt") as &[u8],
    ),
];

unsafe extern "C" {
    /// musl's `reboot(2)` wrapper (`int reboot(int)`), the same call the E07 PID 1 ends with.
    fn reboot(cmd: core::ffi::c_int) -> core::ffi::c_int;
    /// musl's `uname(2)` wrapper (`int uname(struct utsname *)`).
    fn uname(buf: *mut Utsname) -> core::ffi::c_int;
}

const RB_AUTOBOOT: core::ffi::c_int = 0x0123_4567;

/// Linux's `struct utsname` as musl lays it out: six NUL-terminated 65-byte fields.
#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

// ---- small helpers ------------------------------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv_update(mut state: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

fn vector(name: &str) -> Vec<u64> {
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some(name) {
            return parts
                .map(|part| part.parse::<u64>().expect("vector numbers are decimal"))
                .collect();
        }
    }
    panic!("vector {name} is missing from tests/p05/vectors.txt");
}

fn scalar(name: &str) -> u64 {
    let values = vector(name);
    assert_eq!(values.len(), 1, "{name} must be a single number");
    values[0]
}

struct Profile {
    threads: usize,
    ops: usize,
    first_seed: u64,
    seeds: u64,
}

fn profile() -> Profile {
    Profile {
        threads: usize::try_from(scalar("profile_threads")).expect("small"),
        ops: usize::try_from(scalar("profile_ops_per_thread")).expect("small"),
        first_seed: scalar("profile_first_seed"),
        seeds: scalar("profile_seeds"),
    }
}

fn read_seed() -> Option<u64> {
    std::fs::read_to_string("/ffw_seed")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

fn cstr(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

// ---- the canonical history text both sides implement --------------------------------------------------------------
//
// One event is `t<thread>:<inv>:<res>:<op>:<resp>`; a history is its events joined by `;`. Numbers in an op or a response are
// lower-case hex without padding; `thread`, `inv` and `res` are decimal. Ops: `L`, `S<v>`, `C<current>.<new>`, `A<delta>`.
// Responses: `V<v>`, `T`, `Co<prev>`, `Ce<seen>`, `Ao<prev>`, `Af<current>.<delta>`.

fn op_text(op: Op) -> String {
    match op {
        Op::Load => "L".to_string(),
        Op::Store(value) => format!("S{value:x}"),
        Op::Cas { current, new } => format!("C{current:x}.{new:x}"),
        Op::FetchAdd(delta) => format!("A{delta:x}"),
    }
}

fn resp_text(resp: Resp) -> String {
    match resp {
        Resp::Value(value) => format!("V{value:x}"),
        Resp::Stored => "T".to_string(),
        Resp::Cas(Ok(previous)) => format!("Co{previous:x}"),
        Resp::Cas(Err(seen)) => format!("Ce{seen:x}"),
        Resp::Add(Ok(previous)) => format!("Ao{previous:x}"),
        Resp::Add(Err(ArithError::Overflow { current, delta })) => {
            format!("Af{current:x}.{delta:x}")
        }
        Resp::Add(Err(ArithError::Underflow { current, delta })) => {
            format!("Au{current:x}.{delta:x}")
        }
    }
}

fn history_text(events: &[Event]) -> String {
    let parts: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                "t{}:{}:{}:{}:{}",
                e.thread,
                e.inv,
                e.res,
                op_text(e.op),
                resp_text(e.resp)
            )
        })
        .collect();
    parts.join(";")
}

fn verdict_mark(verdict: Verdict) -> char {
    match verdict {
        Verdict::Linearizable => 'L',
        Verdict::NotLinearizable => 'N',
        Verdict::Inconclusive => 'I',
    }
}

// ---- seeded sweeps: the model's scheduler, generator and checker, run on this target ------------------------------------

struct Sweep {
    violations: Vec<u64>,
    inconclusive: u64,
    digest: u64,
}

fn sweep(kind: Kind, first_seed: u64, seeds: u64, threads: usize, ops: usize) -> Sweep {
    let mut digest = FNV_OFFSET;
    let mut violations = Vec::new();
    let mut inconclusive = 0u64;
    for seed in first_seed..first_seed + seeds {
        let events = seeded_run(kind, seed, threads, ops);
        let verdict = check(INITIAL, &events, BUDGET);
        match verdict {
            Verdict::NotLinearizable => violations.push(seed),
            Verdict::Inconclusive => inconclusive += 1,
            Verdict::Linearizable => {}
        }
        let record = format!(
            "{seed:x}|{}|{}\n",
            verdict_mark(verdict),
            history_text(&events)
        );
        digest = fnv_update(digest, record.as_bytes());
    }
    Sweep {
        violations,
        inconclusive,
        digest,
    }
}

const KINDS: [(&str, Kind); 3] = [
    ("good", Kind::Real),
    ("split", Kind::SplitWord),
    ("trunc", Kind::Truncating),
];

fn sweep_line(set: &str, name: &str, first_seed: u64, p: &Profile, s: &Sweep) -> String {
    let head: Vec<String> = s
        .violations
        .iter()
        .take(8)
        .map(|seed| seed.to_string())
        .collect();
    let head = if head.is_empty() {
        "-".to_string()
    } else {
        head.join(",")
    };
    format!(
        "FFW_P05T_SWEEP set={set} kind={name} first_seed={first_seed} seeds={} violations={} inconclusive={} head={head} digest={:016x}",
        p.seeds,
        s.violations.len(),
        s.inconclusive,
        s.digest
    )
}

// ---- the directed scripts -----------------------------------------------------------------------------------------------

/// One scripted interleaving: its name, the cell's initial value, each thread's operations, and the order in which threads are picked.
struct DirectedCase {
    name: &'static str,
    initial: u64,
    plans: Vec<Vec<Op>>,
    picks: Vec<usize>,
}

fn directed_cases() -> Vec<DirectedCase> {
    vec![
        DirectedCase {
            name: "torn_store",
            initial: POOL[0],
            plans: vec![vec![Op::Store(0x1_0000_0000)], vec![Op::Load]],
            picks: vec![0, 1, 1, 0],
        },
        DirectedCase {
            name: "torn_carry",
            initial: POOL[0],
            plans: vec![vec![Op::FetchAdd(0x10)], vec![Op::Load]],
            picks: vec![0, 1, 1, 0],
        },
        DirectedCase {
            name: "truncated_store",
            initial: POOL[0],
            plans: vec![vec![Op::Store(0x1_0000_0001)], vec![Op::Load]],
            picks: vec![0, 1],
        },
    ]
}

fn directed_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for case in directed_cases() {
        let (name, initial) = (case.name, case.initial);
        for (kind_name, kind) in KINDS {
            let events = scripted_run(kind, initial, &case.plans, &case.picks);
            let loaded = events
                .iter()
                .find_map(|e| match e.resp {
                    Resp::Value(value) if e.op == Op::Load => Some(value),
                    _ => None,
                })
                .expect("every scenario loads once");
            let verdict = check(initial, &events, BUDGET);
            lines.push(format!(
                "FFW_P05T_DIRECTED name={name} kind={kind_name} verdict={} loaded={loaded:x} history={}",
                verdict_mark(verdict),
                history_text(&events)
            ));
        }
    }
    lines
}

// ---- hand-written vectors on the real cells -----------------------------------------------------------------------------

fn v(value: u64) -> String {
    format!("v:{value:x}")
}

fn vi(value: i64) -> String {
    format!("v:{:x}", value as u64)
}

fn tok_u(result: Result<u64, ArithError<u64>>) -> String {
    match result {
        Ok(value) => format!("ok:{value:x}"),
        Err(ArithError::Overflow { current, delta }) => format!("of:{current:x}/{delta:x}"),
        Err(ArithError::Underflow { current, delta }) => format!("uf:{current:x}/{delta:x}"),
    }
}

fn tok_i(result: Result<i64, ArithError<i64>>) -> String {
    match result {
        Ok(value) => format!("ok:{:x}", value as u64),
        Err(ArithError::Overflow { current, delta }) => {
            format!("of:{:x}/{:x}", current as u64, delta as u64)
        }
        Err(ArithError::Underflow { current, delta }) => {
            format!("uf:{:x}/{:x}", current as u64, delta as u64)
        }
    }
}

fn tok_cx(result: Result<u64, u64>) -> String {
    match result {
        Ok(value) => format!("cx_ok:{value:x}"),
        Err(value) => format!("cx_err:{value:x}"),
    }
}

fn tok_cxi(result: Result<i64, i64>) -> String {
    match result {
        Ok(value) => format!("cx_ok:{:x}", value as u64),
        Err(value) => format!("cx_err:{:x}", value as u64),
    }
}

fn tok_seq(result: Result<u64, Exhausted>) -> String {
    match result {
        Ok(value) => format!("ok:{value:x}"),
        Err(Exhausted) => "ex".to_string(),
    }
}

fn vec_line(id: &str, tokens: Vec<String>) -> String {
    format!("FFW_P05T_VEC id={id} r={}", tokens.join(","))
}

fn vector_lines() -> Vec<String> {
    let mut lines = Vec::new();

    // load / store / swap round trip over values with every word pattern
    let mut t = Vec::new();
    let values = [
        0u64,
        1,
        0xFFFF_FFFF,
        0x1_0000_0000,
        0x1_0000_0001,
        0xFFFF_FFFF_0000_0000,
        0x8000_0000_0000_0000,
        0x0123_4567_89AB_CDEF,
        u64::MAX,
    ];
    let cell = SharedU64::new(0);
    let mut previous = 0u64;
    for value in values {
        cell.store(value);
        t.push(v(cell.load()));
        t.push(v(cell.swap(previous)));
        t.push(v(cell.load()));
        previous = value;
    }
    t.push(v(SharedU64::default().load()));
    t.push(v(SharedU64::new(0xABCD_EF01_2345_6789).into_inner()));
    let mut exclusive = SharedU64::new(7);
    *exclusive.get_mut() = 0x1_0000_0007;
    t.push(v(exclusive.load()));
    lines.push(vec_line("load_store_roundtrip", t));

    // a carry out of the low word reaches the high word; an operand with a high word is not truncated
    let mut t = Vec::new();
    let cell = SharedU64::new(0xFFFF_FFFF);
    t.push(tok_u(cell.fetch_add(1)));
    t.push(v(cell.load()));
    let cell = SharedU64::new(5);
    t.push(tok_u(cell.fetch_add(0x1_0000_0000)));
    t.push(v(cell.load()));
    let cell = SharedU64::new(0x0000_0001_FFFF_FFF0);
    t.push(tok_u(cell.fetch_add(0x20)));
    t.push(v(cell.load()));
    lines.push(vec_line("add_carry", t));

    // a checked add that does not fit is a typed error and changes nothing
    let mut t = Vec::new();
    let cell = SharedU64::new(u64::MAX - 1);
    t.push(tok_u(cell.fetch_add(1)));
    t.push(v(cell.load()));
    t.push(tok_u(cell.fetch_add(1)));
    t.push(v(cell.load()));
    t.push(tok_u(cell.fetch_add(0)));
    let cell = SharedU64::new(1);
    t.push(tok_u(cell.fetch_add(u64::MAX)));
    t.push(v(cell.load()));
    lines.push(vec_line("add_overflow", t));

    // a borrow out of the low word reaches the high word; an underflow is typed
    let mut t = Vec::new();
    let cell = SharedU64::new(1);
    t.push(tok_u(cell.fetch_sub(1)));
    t.push(v(cell.load()));
    t.push(tok_u(cell.fetch_sub(1)));
    t.push(v(cell.load()));
    t.push(tok_u(cell.fetch_sub(0)));
    let cell = SharedU64::new(0x1_0000_0000);
    t.push(tok_u(cell.fetch_sub(1)));
    t.push(v(cell.load()));
    lines.push(vec_line("sub_underflow", t));

    // wrapping exists only under its own name
    let mut t = Vec::new();
    let cell = SharedU64::new(u64::MAX);
    t.push(v(cell.fetch_add_wrapping(2)));
    t.push(v(cell.load()));
    let cell = SharedU64::new(0);
    t.push(v(cell.fetch_sub_wrapping(1)));
    t.push(v(cell.load()));
    let cell = SharedU64::new(u64::MAX);
    t.push(tok_u(cell.fetch_add(2)));
    t.push(v(cell.load()));
    lines.push(vec_line("wrapping", t));

    // compare-exchange compares all 64 bits
    let mut t = Vec::new();
    let cell = SharedU64::new(0x1_0000_0001);
    t.push(tok_cx(cell.compare_exchange(1, 9)));
    t.push(v(cell.load()));
    t.push(tok_cx(cell.compare_exchange(0x1_0000_0001, 9)));
    t.push(v(cell.load()));
    t.push(tok_cx(cell.compare_exchange(9, 9)));
    t.push(tok_cx(cell.compare_exchange(0, 1)));
    lines.push(vec_line("cas_full_width", t));

    // max, min and the bit operations over a high word
    let mut t = Vec::new();
    let cell = SharedU64::new(5);
    t.push(v(cell.fetch_max(0x1_0000_0000)));
    t.push(v(cell.load()));
    t.push(v(cell.fetch_max(3)));
    t.push(v(cell.load()));
    t.push(v(cell.fetch_min(7)));
    t.push(v(cell.load()));
    t.push(v(cell.fetch_min(9)));
    t.push(v(cell.load()));
    let cell = SharedU64::new(0xF0F0_F0F0_F0F0_F0F0);
    t.push(v(cell.fetch_and(0xFFFF_FFFF_0000_0000)));
    t.push(v(cell.load()));
    t.push(v(cell.fetch_or(0x0000_0000_0F0F_0F0F)));
    t.push(v(cell.load()));
    lines.push(vec_line("max_min_bits", t));

    // the signed cell: the full range, and a negative value is all 64 bits
    let mut t = Vec::new();
    let cell = SharedI64::new(i64::MAX);
    t.push(tok_i(cell.fetch_add(1)));
    t.push(tok_i(cell.fetch_add(-1)));
    t.push(vi(cell.load()));
    t.push(tok_i(cell.fetch_sub(-1)));
    t.push(tok_i(cell.fetch_sub(-1)));
    let cell = SharedI64::new(i64::MIN);
    t.push(tok_i(cell.fetch_add(-1)));
    t.push(tok_i(cell.fetch_sub(1)));
    t.push(vi(cell.load()));
    t.push(tok_i(cell.fetch_sub(-1)));
    t.push(vi(cell.load()));
    let cell = SharedI64::new(0x0000_0000_FFFF_FFFF);
    t.push(tok_cxi(cell.compare_exchange(-1, 3)));
    cell.store(-0x1_0000_0000);
    t.push(vi(cell.load()));
    t.push(vi(cell.fetch_add_wrapping(i64::MAX)));
    lines.push(vec_line("i64_range", t));

    // the identifier sequence never wraps and reserves the maximum
    let mut t = Vec::new();
    let seq = Sequence::new(0);
    t.push(tok_seq(seq.next_id()));
    t.push(tok_seq(seq.next_id()));
    t.push(tok_seq(seq.next_id()));
    let seq = Sequence::new(u64::MAX - 2);
    t.push(tok_seq(seq.next_id()));
    t.push(tok_seq(seq.next_id()));
    t.push(v(seq.peek()));
    t.push(tok_seq(seq.next_id()));
    t.push(tok_seq(seq.next_id()));
    t.push(v(seq.peek()));
    let seq = Sequence::new(u64::MAX);
    t.push(tok_seq(seq.next_id()));
    lines.push(vec_line("sequence", t));

    // the owner-local cell: checked, wrapping by name, and it may move to another thread
    let mut t = Vec::new();
    let local = LocalU64::new(u64::MAX - 1);
    t.push(tok_u(local.add(1)));
    t.push(tok_u(local.add(1)));
    t.push(v(local.get()));
    t.push(v(local.add_wrapping(2)));
    t.push(v(local.get()));
    local.set(0x1_0000_0000);
    t.push(v(local.get()));
    t.push(v(LocalU64::default().get()));
    let moved = std::thread::spawn(move || {
        local.set(local.get() + 1);
        local.get()
    })
    .join()
    .expect("worker thread");
    t.push(v(moved));
    lines.push(vec_line("local_u64", t));

    lines
}

// ---- real threads on the real cell (deterministic outcomes for a correct cell) --------------------------------------------

fn threaded_history(seed: u64, threads: usize, ops_per_thread: usize) -> Vec<Event> {
    let mut rng = SplitMix64::new(seed);
    let plans = gen_plans(&mut rng, threads, ops_per_thread);
    let cell = SharedU64::new(INITIAL);
    let ticket = AtomicU32::new(0);
    let barrier = Barrier::new(threads);
    let mut all = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (thread, plan) in plans.iter().enumerate() {
            let cell = &cell;
            let ticket = &ticket;
            let barrier = &barrier;
            handles.push(scope.spawn(move || {
                barrier.wait();
                let mut out = Vec::new();
                for &op in plan {
                    // A ticket before the call and one after bracket the real execution of the operation.
                    let inv = u64::from(ticket.fetch_add(1, Ordering::SeqCst));
                    let resp = apply_real(cell, op);
                    let res = u64::from(ticket.fetch_add(1, Ordering::SeqCst));
                    out.push(Event {
                        thread,
                        inv,
                        res,
                        op,
                        resp,
                    });
                }
                out
            }));
        }
        for handle in handles {
            all.extend(handle.join().expect("worker thread"));
        }
    });
    all
}

fn threaded_line(first_seed: u64) -> String {
    const SEEDS: u64 = 24;
    let (mut linearizable, mut not, mut inconclusive) = (0u64, 0u64, 0u64);
    for seed in first_seed..first_seed + SEEDS {
        let events = threaded_history(seed, 3, 5);
        match check(INITIAL, &events, THREADED_BUDGET) {
            Verdict::Linearizable => linearizable += 1,
            Verdict::NotLinearizable => not += 1,
            Verdict::Inconclusive => inconclusive += 1,
        }
    }
    format!(
        "FFW_P05T_THREADED first_seed={first_seed} seeds={SEEDS} threads=3 ops=5 linearizable={linearizable} not={not} inconclusive={inconclusive}"
    )
}

fn tickets_line() -> String {
    const PER_THREAD: usize = 2_000;
    let cell = SharedU64::new(0);
    let mut batches: Vec<Vec<u64>> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                let mut mine = Vec::with_capacity(PER_THREAD);
                for _ in 0..PER_THREAD {
                    mine.push(
                        cell.fetch_add(1)
                            .expect("a count this small cannot overflow"),
                    );
                }
                mine
            }));
        }
        for handle in handles {
            batches.push(handle.join().expect("worker thread"));
        }
    });
    let total = THREADS * PER_THREAD;
    let mut seen = vec![false; total];
    let mut duplicates = 0u64;
    let mut out_of_range = 0u64;
    let mut increasing = true;
    for batch in &batches {
        if !batch.windows(2).all(|w| w[0] < w[1]) {
            increasing = false;
        }
        for &value in batch {
            match usize::try_from(value) {
                Ok(index) if index < total => {
                    if seen[index] {
                        duplicates += 1;
                    }
                    seen[index] = true;
                }
                _ => out_of_range += 1,
            }
        }
    }
    let complete = seen.iter().all(|&s| s);
    format!(
        "FFW_P05T_TICKETS threads={THREADS} per={PER_THREAD} total={total} duplicates={duplicates} out_of_range={out_of_range} complete={} increasing={} final={:x}",
        u8::from(complete),
        u8::from(increasing),
        cell.load()
    )
}

fn casloop_line() -> String {
    const PER_THREAD: usize = 2_000;
    // 0xFFFF_F000 plus 8000 crosses 2^32, so the carry happens under contention.
    let start = 0xFFFF_F000u64;
    let cell = SharedU64::new(start);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                for _ in 0..PER_THREAD {
                    loop {
                        let seen = cell.load();
                        if cell.compare_exchange(seen, seen + 1).is_ok() {
                            break;
                        }
                    }
                }
            });
        }
    });
    let final_value = cell.load();
    format!(
        "FFW_P05T_CASLOOP start={start:x} threads={THREADS} per={PER_THREAD} final={final_value:x} crossed={}",
        u8::from(final_value > 0xFFFF_FFFF)
    )
}

fn overflow_race_line() -> String {
    const ATTEMPTS: usize = 10;
    let cell = SharedU64::new(u64::MAX - 3);
    let mut results: Vec<Result<u64, ArithError<u64>>> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(scope.spawn(|| {
                let mut mine = Vec::new();
                for _ in 0..ATTEMPTS {
                    mine.push(cell.fetch_add(1));
                }
                mine
            }));
        }
        for handle in handles {
            results.extend(handle.join().expect("worker thread"));
        }
    });
    let mut oks: Vec<u64> = results
        .iter()
        .filter_map(|r| r.as_ref().ok().copied())
        .collect();
    oks.sort_unstable();
    let errors: Vec<ArithError<u64>> = results
        .iter()
        .filter_map(|r| r.as_ref().err().copied())
        .collect();
    let all_typed = errors.iter().all(|e| {
        *e == ArithError::Overflow {
            current: u64::MAX,
            delta: 1,
        }
    });
    let ok_text: Vec<String> = oks.iter().map(|value| format!("{value:x}")).collect();
    format!(
        "FFW_P05T_OVERFLOWRACE threads=8 attempts={ATTEMPTS} oks={} errors={} all_typed={} final={:x}",
        ok_text.join(","),
        errors.len(),
        u8::from(all_typed),
        cell.load()
    )
}

fn seqrace_line() -> String {
    const SPAN: u64 = 100;
    let seq = Sequence::new(u64::MAX - SPAN);
    let mut ids: Vec<u64> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                let mut mine = Vec::new();
                while let Ok(id) = seq.next_id() {
                    mine.push(id);
                }
                mine
            }));
        }
        for handle in handles {
            ids.extend(handle.join().expect("worker thread"));
        }
    });
    ids.sort_unstable();
    let expected: Vec<u64> = ((u64::MAX - SPAN)..u64::MAX).collect();
    format!(
        "FFW_P05T_SEQRACE span={SPAN} threads={THREADS} issued={} exact={} next_err={} peek={:x}",
        ids.len(),
        u8::from(ids == expected),
        u8::from(seq.next_id() == Err(Exhausted)),
        seq.peek()
    )
}

fn monotone_line() -> String {
    // A writer adds one 512 times across 2^32 while this thread reads. A read may be any value the counter really held, so the
    // reads never go backwards and never fall below the start.
    const ADDS: u64 = 512;
    let start = 0xFFFF_FF00u64;
    let cell = SharedU64::new(start);
    let mut reads = 0u64;
    let mut backwards = 0u64;
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for _ in 0..ADDS {
                cell.fetch_add(1).expect("no overflow near 2^32");
            }
        });
        let mut previous = start;
        // `is_finished` is also true if the writer panicked, so a failure ends the loop instead of hanging it.
        while !writer.is_finished() {
            let seen = cell.load();
            reads += 1;
            if seen < previous {
                backwards += 1;
            }
            previous = seen;
        }
    });
    let final_value = cell.load();
    format!(
        "FFW_P05T_MONOTONE start={start:x} adds={ADDS} reads={reads} backwards={backwards} final={final_value:x} crossed={}",
        u8::from(final_value > 0xFFFF_FFFF)
    )
}

/// INFORMATION ONLY, never a pass or a fail: whether a naive two-word store tears under this guest's preemption. It depends
/// on the schedule, so the judge prints it and counts nothing from it.
fn tear_info_line() -> String {
    const A: u64 = 0x0000_0000_FFFF_FFFF;
    const B: u64 = 0x0000_0001_0000_0000;
    let hi = AtomicU32::new(0);
    let lo = AtomicU32::new(u32::MAX);
    let done = AtomicBool::new(false);
    let mut reads = 0u64;
    let mut torn = 0u64;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for i in 0..200_000u32 {
                if i % 2 == 0 {
                    hi.store(1, Ordering::SeqCst);
                    lo.store(0, Ordering::SeqCst);
                } else {
                    hi.store(0, Ordering::SeqCst);
                    lo.store(u32::MAX, Ordering::SeqCst);
                }
            }
            done.store(true, Ordering::SeqCst);
        });
        while !done.load(Ordering::SeqCst) {
            let value =
                (u64::from(hi.load(Ordering::SeqCst)) << 32) | u64::from(lo.load(Ordering::SeqCst));
            reads += 1;
            if value != A && value != B {
                torn += 1;
            }
        }
    });
    format!("FFW_P05T_INFO what=naive_two_word_store_tear reads={reads} torn={torn}")
}

// ---- identity ------------------------------------------------------------------------------------------------------------

fn env_lines() -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "FFW_P05T_ENV target_arch={} target_endian={} pointer_width={} target_os={} size_usize={} size_u64={} ne_u32={:08x} ne_u64={:016x}",
        std::env::consts::ARCH,
        if cfg!(target_endian = "big") { "big" } else { "little" },
        usize::BITS,
        std::env::consts::OS,
        core::mem::size_of::<usize>(),
        core::mem::size_of::<u64>(),
        u32::from_ne_bytes([1, 2, 3, 4]),
        u64::from_ne_bytes([1, 2, 3, 4, 5, 6, 7, 8])
    ));
    let mut name = Utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    // SAFETY: `uname` writes one `struct utsname` through a valid, exclusively borrowed pointer to a buffer with musl's layout.
    let status = unsafe { uname(&mut name) };
    lines.push(if status == 0 {
        format!(
            "FFW_P05T_SYS sysname={} release={} machine={}",
            cstr(&name.sysname),
            cstr(&name.release),
            cstr(&name.machine)
        )
    } else {
        format!("FFW_P05T_SYS error={status}")
    });
    for (file, bytes) in SOURCES {
        lines.push(format!(
            "FFW_P05T_SRC file={file} bytes={} fnv={:016x}",
            bytes.len(),
            fnv_update(FNV_OFFSET, bytes)
        ));
    }
    lines
}

/// The planted replay: print the seeded sweep lines of an earlier transcript instead of computing any.
fn replayed_seeded_lines() -> Vec<String> {
    match std::fs::read_to_string("/replay") {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) => vec![format!("FFW_P05T_REPLAY_MISSING error={error}")],
    }
}

fn power_off() -> ! {
    let _ = std::io::stdout().flush();
    // SAFETY: a plain libc call with a valid command; it only returns on failure (for example when this program is not PID 1
    // and lacks the privilege), in which case the transcript says so and the process exits.
    let status = unsafe { reboot(RB_AUTOBOOT) };
    println!("FFW_P05T_REBOOT_FAILED status={status}");
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

fn main() {
    if !cfg!(target_arch = "mips") {
        println!(
            "FFW_P05T_HOST_BUILD this program is a guest probe; a host run proves nothing about the target"
        );
        std::process::exit(2);
    }
    println!("FFW_P05T_ALIVE");
    let _ = std::io::stdout().flush();

    let p = profile();
    let seed = read_seed();
    let run_seed = seed.unwrap_or(p.first_seed);
    let mut lines = vec![format!(
        "FFW_P05T_BEGIN version=1 threads={} ops={} seeds={} budget={BUDGET} threaded_budget={THREADED_BUDGET}",
        p.threads, p.ops, p.seeds
    )];
    lines.extend(env_lines());
    lines.push(match seed {
        Some(value) => format!("FFW_P05T_SEED value={value}"),
        None => "FFW_P05T_SEED value=none".to_string(),
    });
    lines.extend(vector_lines());

    // The pinned profile: the same seeds the host tests run, so the counts can be compared with the hand-pinned file.
    for (name, kind) in KINDS {
        let s = sweep(kind, p.first_seed, p.seeds, p.threads, p.ops);
        lines.push(sweep_line("pinned", name, p.first_seed, &p, &s));
    }
    // The seeded profile: the same checker from this run's seed, so a transcript from another run cannot match.
    if std::path::Path::new("/plant-replay").exists() {
        lines.extend(replayed_seeded_lines());
    } else {
        for (name, kind) in KINDS {
            let s = sweep(kind, run_seed, p.seeds, p.threads, p.ops);
            lines.push(sweep_line("seeded", name, run_seed, &p, &s));
        }
    }
    lines.extend(directed_lines());

    lines.push(threaded_line(run_seed));
    lines.push(tickets_line());
    lines.push(casloop_line());
    lines.push(overflow_race_line());
    lines.push(seqrace_line());
    lines.push(monotone_line());
    lines.push(tear_info_line());
    lines.push("FFW_P05T_END".to_string());

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        let _ = writeln!(out, "{line}");
    }
    drop(out);
    power_off();
}
