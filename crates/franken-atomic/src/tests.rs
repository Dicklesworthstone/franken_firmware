//! Acceptance tests for `P05` / `ffw-ipz` slice 1.
//!
//! Evidence: host simulation. The real cells are the `Mutex` code a device build runs, exercised here by
//! seeded interleavings (`model.rs`), by real threads, and by hand-written vectors; the planted wrong
//! versions (`planted.rs`) are exercised by the same harness and must be caught. Nothing here runs on a
//! device, and a pass says nothing about a device kernel's futex support or scheduling.

use crate::model::{
    Event, INITIAL, Kind, Op, Resp, SplitMix64, Verdict, apply_real, check, describe, gen_plans, scripted_run,
    seeded_run,
};
use crate::{ArithError, Exhausted, LocalU64, Sequence, SharedI64, SharedU64};
use std::sync::Barrier;
use std::sync::atomic::{AtomicU32, Ordering};

/// Pinned counts and seeds. `tests/p05/reference.py predict` produces them; `tests/p05/run_cases.py`
/// checks the file still equals that prediction; this module requires the Rust model to reproduce them.
const VECTORS: &str = include_str!("../../../tests/p05/vectors.txt");
const BUDGET: usize = 200_000;

fn vector(name: &str) -> Vec<u64> {
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() == Some(name) {
            return parts.map(|p| p.parse::<u64>().expect("vector numbers are decimal")).collect();
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

/// Seeds whose run is not linearizable, and seeds the checker could not decide.
fn sweep(kind: Kind) -> (Vec<u64>, Vec<u64>) {
    let p = profile();
    let mut violations = Vec::new();
    let mut inconclusive = Vec::new();
    for seed in p.first_seed..p.first_seed + p.seeds {
        let events = seeded_run(kind, seed, p.threads, p.ops);
        match check(INITIAL, &events, BUDGET) {
            Verdict::Linearizable => {}
            Verdict::NotLinearizable => violations.push(seed),
            Verdict::Inconclusive => inconclusive.push(seed),
        }
    }
    (violations, inconclusive)
}

// ---- hand-written vectors ----------------------------------------------------------------------------

#[test]
fn p05_vector_load_store_roundtrip_above_u32() {
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
        assert_eq!(cell.load(), value, "store then load must return all 64 bits of {value:#x}");
        assert_eq!(cell.swap(previous), value, "swap returns the stored value");
        assert_eq!(cell.load(), previous);
        previous = value;
    }
    assert_eq!(SharedU64::default().load(), 0);
    assert_eq!(SharedU64::new(0xABCD_EF01_2345_6789).into_inner(), 0xABCD_EF01_2345_6789);
    let mut exclusive = SharedU64::new(7);
    *exclusive.get_mut() = 0x1_0000_0007;
    assert_eq!(exclusive.load(), 0x1_0000_0007);
}

#[test]
fn p05_vector_fetch_add_carries_across_the_32_bit_boundary() {
    let cell = SharedU64::new(0xFFFF_FFFF);
    assert_eq!(cell.fetch_add(1), Ok(0xFFFF_FFFF));
    assert_eq!(cell.load(), 0x1_0000_0000, "the carry out of the low word must reach the high word");
    // An operand with a high word is not truncated to its low 32 bits.
    let cell = SharedU64::new(5);
    assert_eq!(cell.fetch_add(0x1_0000_0000), Ok(5));
    assert_eq!(cell.load(), 0x1_0000_0005);
    let cell = SharedU64::new(0x0000_0001_FFFF_FFF0);
    assert_eq!(cell.fetch_add(0x20), Ok(0x0000_0001_FFFF_FFF0));
    assert_eq!(cell.load(), 0x0000_0002_0000_0010);
}

#[test]
fn p05_vector_checked_add_overflow_is_typed_and_leaves_value() {
    let cell = SharedU64::new(u64::MAX - 1);
    assert_eq!(cell.fetch_add(1), Ok(u64::MAX - 1));
    assert_eq!(cell.load(), u64::MAX);
    assert_eq!(cell.fetch_add(1), Err(ArithError::Overflow { current: u64::MAX, delta: 1 }));
    assert_eq!(cell.load(), u64::MAX, "a refused add changes nothing");
    assert_eq!(cell.fetch_add(0), Ok(u64::MAX), "adding zero cannot overflow");
    let cell = SharedU64::new(1);
    assert_eq!(cell.fetch_add(u64::MAX), Err(ArithError::Overflow { current: 1, delta: u64::MAX }));
    assert_eq!(cell.load(), 1);
    let message = ArithError::Overflow { current: 1u64, delta: 2u64 }.to_string();
    assert!(message.contains("overflow"), "{message}");
}

#[test]
fn p05_vector_checked_sub_underflow_is_typed_and_leaves_value() {
    let cell = SharedU64::new(1);
    assert_eq!(cell.fetch_sub(1), Ok(1));
    assert_eq!(cell.load(), 0);
    assert_eq!(cell.fetch_sub(1), Err(ArithError::Underflow { current: 0, delta: 1 }));
    assert_eq!(cell.load(), 0, "a refused subtract changes nothing");
    assert_eq!(cell.fetch_sub(0), Ok(0));
    // A borrow out of the low word must reach the high word.
    let cell = SharedU64::new(0x1_0000_0000);
    assert_eq!(cell.fetch_sub(1), Ok(0x1_0000_0000));
    assert_eq!(cell.load(), 0xFFFF_FFFF);
}

#[test]
fn p05_vector_wrapping_ops_are_named_and_wrap_like_u64() {
    let cell = SharedU64::new(u64::MAX);
    assert_eq!(cell.fetch_add_wrapping(2), u64::MAX);
    assert_eq!(cell.load(), 1);
    let cell = SharedU64::new(0);
    assert_eq!(cell.fetch_sub_wrapping(1), 0);
    assert_eq!(cell.load(), u64::MAX);
    // The checked and wrapping forms disagree exactly where they should.
    let cell = SharedU64::new(u64::MAX);
    assert!(cell.fetch_add(2).is_err());
    assert_eq!(cell.load(), u64::MAX);
}

#[test]
fn p05_vector_compare_exchange_is_full_width() {
    let cell = SharedU64::new(0x1_0000_0001);
    // The low words are equal, the high words are not: a 32-bit comparison would succeed here.
    assert_eq!(cell.compare_exchange(1, 9), Err(0x1_0000_0001));
    assert_eq!(cell.load(), 0x1_0000_0001, "a failed compare-exchange changes nothing");
    assert_eq!(cell.compare_exchange(0x1_0000_0001, 9), Ok(0x1_0000_0001));
    assert_eq!(cell.load(), 9);
    assert_eq!(cell.compare_exchange(9, 9), Ok(9));
    assert_eq!(cell.compare_exchange(0, 1), Err(9));
}

#[test]
fn p05_vector_swap_max_min_and_bit_ops() {
    let cell = SharedU64::new(5);
    assert_eq!(cell.fetch_max(0x1_0000_0000), 5);
    assert_eq!(cell.load(), 0x1_0000_0000);
    assert_eq!(cell.fetch_max(3), 0x1_0000_0000);
    assert_eq!(cell.load(), 0x1_0000_0000);
    assert_eq!(cell.fetch_min(7), 0x1_0000_0000);
    assert_eq!(cell.load(), 7);
    assert_eq!(cell.fetch_min(9), 7);
    assert_eq!(cell.load(), 7);

    let cell = SharedU64::new(0xF0F0_F0F0_F0F0_F0F0);
    assert_eq!(cell.fetch_and(0xFFFF_FFFF_0000_0000), 0xF0F0_F0F0_F0F0_F0F0);
    assert_eq!(cell.load(), 0xF0F0_F0F0_0000_0000);
    assert_eq!(cell.fetch_or(0x0000_0000_0F0F_0F0F), 0xF0F0_F0F0_0000_0000);
    assert_eq!(cell.load(), 0xF0F0_F0F0_0F0F_0F0F);
}

#[test]
fn p05_vector_i64_signed_range() {
    let cell = SharedI64::new(i64::MAX);
    assert_eq!(cell.fetch_add(1), Err(ArithError::Overflow { current: i64::MAX, delta: 1 }));
    assert_eq!(cell.fetch_add(-1), Ok(i64::MAX));
    assert_eq!(cell.load(), i64::MAX - 1);
    assert_eq!(cell.fetch_sub(-1), Ok(i64::MAX - 1));
    assert_eq!(cell.fetch_sub(-1), Err(ArithError::Overflow { current: i64::MAX, delta: -1 }));

    let cell = SharedI64::new(i64::MIN);
    assert_eq!(cell.fetch_add(-1), Err(ArithError::Underflow { current: i64::MIN, delta: -1 }));
    assert_eq!(cell.fetch_sub(1), Err(ArithError::Underflow { current: i64::MIN, delta: 1 }));
    assert_eq!(cell.load(), i64::MIN, "refused operations change nothing");
    assert_eq!(cell.fetch_sub(-1), Ok(i64::MIN));
    assert_eq!(cell.load(), i64::MIN + 1);

    // A negative value is all 64 bits: the low word alone (0xFFFF_FFFF) is not -1.
    let cell = SharedI64::new(0x0000_0000_FFFF_FFFF);
    assert_eq!(cell.compare_exchange(-1, 3), Err(0x0000_0000_FFFF_FFFF));
    cell.store(-0x1_0000_0000);
    assert_eq!(cell.load(), -0x1_0000_0000);
    assert_eq!(cell.fetch_add_wrapping(i64::MAX), -0x1_0000_0000);
    assert_eq!(cell.fetch_max(5), i64::MAX - 0x1_0000_0000);
    assert_eq!(cell.load(), i64::MAX - 0x1_0000_0000);
}

#[test]
fn p05_sequence_never_wraps_and_reserves_max() {
    let seq = Sequence::new(0);
    assert_eq!((seq.next_id(), seq.next_id(), seq.next_id()), (Ok(0), Ok(1), Ok(2)));

    let seq = Sequence::new(u64::MAX - 2);
    assert_eq!(seq.next_id(), Ok(u64::MAX - 2));
    assert_eq!(seq.next_id(), Ok(u64::MAX - 1));
    assert_eq!(seq.peek(), u64::MAX);
    assert_eq!(seq.next_id(), Err(Exhausted), "u64::MAX is never issued");
    assert_eq!(seq.next_id(), Err(Exhausted), "and the sequence does not wrap to reuse an identifier");
    assert_eq!(seq.peek(), u64::MAX);

    let seq = Sequence::new(u64::MAX);
    assert_eq!(seq.next_id(), Err(Exhausted), "a sequence created at the end is exhausted from the start");
}

#[test]
fn p05_local_u64_checked_wrapping_and_send() {
    let local = LocalU64::new(u64::MAX - 1);
    assert_eq!(local.add(1), Ok(u64::MAX - 1));
    assert_eq!(local.add(1), Err(ArithError::Overflow { current: u64::MAX, delta: 1 }));
    assert_eq!(local.get(), u64::MAX, "a refused add changes nothing");
    assert_eq!(local.add_wrapping(2), u64::MAX);
    assert_eq!(local.get(), 1);
    local.set(0x1_0000_0000);
    assert_eq!(local.get(), 0x1_0000_0000);
    assert_eq!(LocalU64::default().get(), 0);
    // Ownership may move to another thread (Send); sharing a reference across threads is what Cell forbids.
    let moved = std::thread::spawn(move || {
        local.set(local.get() + 1);
        local.get()
    })
    .join()
    .expect("worker thread");
    assert_eq!(moved, 0x1_0000_0001);
}

// ---- the checker, on hand-written histories ----------------------------------------------------------

fn ev(thread: usize, inv: u64, res: u64, op: Op, resp: Resp) -> Event {
    Event { thread, inv, res, op, resp }
}

#[test]
fn p05_checker_accepts_legal_and_rejects_illegal_histories() {
    // A load that overlaps a store may return the old or the new value.
    for seen in [0u64, 1] {
        let history = [ev(0, 0, 3, Op::Store(1), Resp::Stored), ev(1, 1, 2, Op::Load, Resp::Value(seen))];
        assert_eq!(check(0, &history, BUDGET), Verdict::Linearizable, "overlapping load saw {seen}");
    }
    // A value nobody stored.
    let history = [ev(0, 0, 1, Op::Store(1), Resp::Stored), ev(1, 2, 3, Op::Load, Resp::Value(2))];
    assert_eq!(check(0, &history, BUDGET), Verdict::NotLinearizable);
    // A stale read: the store finished before the load started.
    let history = [ev(0, 0, 1, Op::Store(1), Resp::Stored), ev(1, 2, 3, Op::Load, Resp::Value(0))];
    assert_eq!(check(0, &history, BUDGET), Verdict::NotLinearizable);
    // The same at a tie: the store's response and the load's invocation share a clock position, which
    // still orders them (`res <= inv`), so the stale value is still wrong.
    let history = [ev(0, 0, 1, Op::Store(1), Resp::Stored), ev(1, 1, 2, Op::Load, Resp::Value(0))];
    assert_eq!(check(0, &history, BUDGET), Verdict::NotLinearizable);
    // Two compare-exchanges from the same value cannot both succeed ...
    let history = [
        ev(0, 0, 3, Op::Cas { current: 0, new: 1 }, Resp::Cas(Ok(0))),
        ev(1, 0, 3, Op::Cas { current: 0, new: 2 }, Resp::Cas(Ok(0))),
    ];
    assert_eq!(check(0, &history, BUDGET), Verdict::NotLinearizable);
    // ... but one may fail having seen the other's result.
    let history = [
        ev(0, 0, 3, Op::Cas { current: 0, new: 1 }, Resp::Cas(Ok(0))),
        ev(1, 0, 3, Op::Cas { current: 0, new: 2 }, Resp::Cas(Err(1))),
    ];
    assert_eq!(check(0, &history, BUDGET), Verdict::Linearizable);
    // A lost update: two fetch_adds that both claim to have seen the starting value.
    let history = [
        ev(0, 0, 3, Op::FetchAdd(1), Resp::Add(Ok(0))),
        ev(1, 0, 3, Op::FetchAdd(1), Resp::Add(Ok(0))),
    ];
    assert_eq!(check(0, &history, BUDGET), Verdict::NotLinearizable);
    // Overflow reported as success is wrong; reported as the typed error it is right.
    let wrapped = [ev(0, 0, 1, Op::FetchAdd(1), Resp::Add(Ok(u64::MAX)))];
    assert_eq!(check(u64::MAX, &wrapped, BUDGET), Verdict::NotLinearizable);
    let typed = [ev(
        0,
        0,
        1,
        Op::FetchAdd(1),
        Resp::Add(Err(ArithError::Overflow { current: u64::MAX, delta: 1 })),
    )];
    assert_eq!(check(u64::MAX, &typed, BUDGET), Verdict::Linearizable);
}

#[test]
fn p05_checker_budget_exhaustion_is_inconclusive_not_a_pass() {
    let history = [ev(0, 0, 1, Op::Store(1), Resp::Stored), ev(1, 2, 3, Op::Load, Resp::Value(1))];
    assert_eq!(check(0, &history, BUDGET), Verdict::Linearizable);
    assert_eq!(check(0, &history, 0), Verdict::Inconclusive);
}

// ---- seeded interleavings ----------------------------------------------------------------------------

#[test]
fn p05_model_good_cell_is_linearizable_on_every_seed() {
    let (violations, inconclusive) = sweep(Kind::Real);
    assert!(inconclusive.is_empty(), "inconclusive seeds: {inconclusive:?}");
    assert_eq!(violations, Vec::<u64>::new(), "the real cell must pass every seed");
    assert_eq!(scalar("good_violations"), 0);
    assert_eq!(scalar("good_inconclusive"), 0);
}

fn assert_caught_where_the_reference_says(kind: Kind, prefix: &str) {
    let p = profile();
    let (violations, inconclusive) = sweep(kind);
    assert!(inconclusive.is_empty(), "inconclusive seeds: {inconclusive:?}");
    assert_eq!(scalar(&format!("{prefix}_inconclusive")), 0);
    let expected = scalar(&format!("{prefix}_violations"));
    assert_eq!(
        violations.len() as u64,
        expected,
        "violation count differs from the reference model; first violating seeds {:?}",
        &violations[..violations.len().min(8)]
    );
    assert!(!violations.is_empty(), "the planted defect must be caught on at least one seed");
    for seed in vector(&format!("{prefix}_violation_seeds")) {
        let events = seeded_run(kind, seed, p.threads, p.ops);
        assert_eq!(
            check(INITIAL, &events, BUDGET),
            Verdict::NotLinearizable,
            "seed {seed} must expose the defect{}",
            describe(&events)
        );
    }
    for seed in vector(&format!("{prefix}_clean_seeds")) {
        let events = seeded_run(kind, seed, p.threads, p.ops);
        assert_eq!(
            check(INITIAL, &events, BUDGET),
            Verdict::Linearizable,
            "seed {seed} does not expose this defect{}",
            describe(&events)
        );
    }
}

#[test]
fn p05_model_split_word_is_caught_where_the_reference_says() {
    assert_caught_where_the_reference_says(Kind::SplitWord, "split");
}

#[test]
fn p05_model_truncating_is_caught_where_the_reference_says() {
    assert_caught_where_the_reference_says(Kind::Truncating, "trunc");
}

fn scenario(name: &str) -> (u64, Vec<Vec<Op>>, Vec<usize>) {
    match name {
        "torn_store" => (INITIAL, vec![vec![Op::Store(0x0000_0001_0000_0000)], vec![Op::Load]], vec![0, 1, 1, 0]),
        "torn_carry" => (INITIAL, vec![vec![Op::FetchAdd(0x10)], vec![Op::Load]], vec![0, 1, 1, 0]),
        "truncated_store" => (INITIAL, vec![vec![Op::Store(0x0000_0001_0000_0001)], vec![Op::Load]], vec![0, 1]),
        _ => panic!("unknown scenario {name}"),
    }
}

#[test]
fn p05_model_directed_scripts_match_hand_written_table() {
    // Derived by hand from the micro-step rules; tests/p05/cases.json carries the same table.
    //   torn_store      initial 0xFFFF_FFF0; t0 stores 0x1_0000_0000 (high word first), t1 loads between the
    //                   two word writes: the split-word cell returns 0x1_FFFF_FFF0, a value nobody stored.
    //   torn_carry      t0 adds 0x10 to 0xFFFF_FFF0: the low word wraps to 0 first, t1 loads before the high
    //                   word is bumped and reads 0, which the value never was.
    //   truncated_store t0 stores 0x1_0000_0001, t1 loads: the truncating cell returns 1. The split-word
    //                   cell gets lucky on this script and is linearizable: the script does not catch it.
    let table = [
        ("torn_store", Kind::Real, Verdict::Linearizable, 0x0000_0001_0000_0000u64),
        ("torn_store", Kind::SplitWord, Verdict::NotLinearizable, 0x0000_0001_FFFF_FFF0),
        ("torn_store", Kind::Truncating, Verdict::NotLinearizable, 0),
        ("torn_carry", Kind::Real, Verdict::Linearizable, 0x0000_0001_0000_0000),
        ("torn_carry", Kind::SplitWord, Verdict::NotLinearizable, 0),
        ("torn_carry", Kind::Truncating, Verdict::NotLinearizable, 0),
        ("truncated_store", Kind::Real, Verdict::Linearizable, 0x0000_0001_0000_0001),
        ("truncated_store", Kind::SplitWord, Verdict::Linearizable, 0x0000_0001_0000_0001),
        ("truncated_store", Kind::Truncating, Verdict::NotLinearizable, 1),
    ];
    for (name, kind, verdict, loaded) in table {
        let (initial, plans, picks) = scenario(name);
        let events = scripted_run(kind, initial, &plans, &picks);
        let got = events
            .iter()
            .find_map(|e| match e.resp {
                Resp::Value(v) if e.op == Op::Load => Some(v),
                _ => None,
            })
            .expect("every scenario loads once");
        assert_eq!(got, loaded, "{name} on {kind:?}: loaded value{}", describe(&events));
        assert_eq!(check(initial, &events, BUDGET), verdict, "{name} on {kind:?}{}", describe(&events));
    }
}

// ---- real threads -------------------------------------------------------------------------------------

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
                    out.push(Event { thread, inv, res, op, resp });
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

#[test]
fn p05_threads_history_is_linearizable() {
    for seed in 0..24u64 {
        let events = threaded_history(seed, 3, 5);
        assert_eq!(events.len(), 15);
        assert_eq!(
            check(INITIAL, &events, 2_000_000),
            Verdict::Linearizable,
            "real-thread history for seed {seed} is not linearizable{}",
            describe(&events)
        );
    }
}

const THREADS: usize = 4;

#[test]
fn p05_threads_fetch_add_is_unique_and_complete() {
    const PER_THREAD: usize = 2_000;
    let cell = SharedU64::new(0);
    let mut batches: Vec<Vec<u64>> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                let mut mine = Vec::with_capacity(PER_THREAD);
                for _ in 0..PER_THREAD {
                    mine.push(cell.fetch_add(1).expect("a count this small cannot overflow"));
                }
                mine
            }));
        }
        for handle in handles {
            batches.push(handle.join().expect("worker thread"));
        }
    });
    let mut seen = vec![false; THREADS * PER_THREAD];
    for batch in &batches {
        assert!(batch.windows(2).all(|w| w[0] < w[1]), "one thread's results must increase");
        for &value in batch {
            let index = usize::try_from(value).expect("small");
            assert!(!seen[index], "value {value} was returned to two callers");
            seen[index] = true;
        }
    }
    assert!(seen.iter().all(|&s| s), "every value 0..N must be returned exactly once");
    assert_eq!(cell.load(), (THREADS * PER_THREAD) as u64);
}

#[test]
fn p05_threads_compare_exchange_loop_loses_no_update_across_the_word_boundary() {
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
    assert_eq!(cell.load(), start + (THREADS * PER_THREAD) as u64);
    assert!(cell.load() > 0xFFFF_FFFF, "the run must have crossed the 32-bit boundary");
}

#[test]
fn p05_threads_checked_add_overflow_race_is_typed() {
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
    let mut oks: Vec<u64> = results.iter().filter_map(|r| r.as_ref().ok().copied()).collect();
    oks.sort_unstable();
    assert_eq!(oks, vec![u64::MAX - 3, u64::MAX - 2, u64::MAX - 1], "exactly three adds fit");
    let errors: Vec<ArithError<u64>> = results.iter().filter_map(|r| r.as_ref().err().copied()).collect();
    assert_eq!(errors.len(), 8 * ATTEMPTS - 3);
    assert!(
        errors.iter().all(|e| *e == ArithError::Overflow { current: u64::MAX, delta: 1 }),
        "every refusal is the typed overflow at the maximum"
    );
    assert_eq!(cell.load(), u64::MAX, "no add wrapped the value");
}

#[test]
fn p05_threads_sequence_exhaustion_is_exact() {
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
    assert_eq!(ids, expected, "every identifier up to MAX-1 was issued exactly once and nothing wrapped");
    assert_eq!(seq.next_id(), Err(Exhausted));
    assert_eq!(seq.peek(), u64::MAX);
}
