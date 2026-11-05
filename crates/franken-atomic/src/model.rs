//! Test-only seeded-interleaving model: a sequential specification of a 64-bit cell, a linearizability
//! checker, and a deterministic micro-step scheduler.
//!
//! `tests/p05/reference.py` is an independent implementation of the same rules (same SplitMix64, same
//! draw order, same checker). The pinned counts in `tests/p05/vectors.txt` are what that reference
//! predicts; the tests in `tests.rs` require this model to reproduce them.
//!
//! A cell under test is driven one **micro-step** at a time. A correct cell does an operation in one step;
//! a naive split-word cell needs several, and the scheduler may run another thread between any two.

use crate::error::ArithError;
use crate::shared::SharedU64;
use std::collections::HashSet;

/// Values the generator draws stores and compare-exchange operands from. They straddle the 32-bit word
/// boundary on purpose: a cell that tears or truncates must misreport one of them.
pub(crate) const POOL: [u64; 4] = [
    0x0000_0000_FFFF_FFF0,
    0x0000_0001_0000_0000,
    0x0000_0001_FFFF_FFF0,
    5,
];
/// Deltas for `fetch_add`. `16` carries out of the low word from `POOL[0]`.
pub(crate) const DELTAS: [u64; 4] = [1, 7, 16, 0x20];
/// The value every run starts from.
pub(crate) const INITIAL: u64 = POOL[0];

pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Load,
    Store(u64),
    Cas { current: u64, new: u64 },
    FetchAdd(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Resp {
    Value(u64),
    Stored,
    Cas(Result<u64, u64>),
    Add(Result<u64, ArithError<u64>>),
}

/// The sequential specification: what one operation does to a 64-bit register, applied atomically.
pub(crate) fn spec(state: u64, op: Op) -> (u64, Resp) {
    match op {
        Op::Load => (state, Resp::Value(state)),
        Op::Store(value) => (value, Resp::Stored),
        Op::Cas { current, new } => {
            if state == current {
                (new, Resp::Cas(Ok(state)))
            } else {
                (state, Resp::Cas(Err(state)))
            }
        }
        Op::FetchAdd(delta) => match state.checked_add(delta) {
            Some(next) => (next, Resp::Add(Ok(state))),
            None => (
                state,
                Resp::Add(Err(ArithError::Overflow {
                    current: state,
                    delta,
                })),
            ),
        },
    }
}

/// One completed operation. `inv` and `res` are positions on the scheduler's clock (or tickets, for real
/// threads): operation `a` must precede `b` when `a.res <= b.inv`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Event {
    pub(crate) thread: usize,
    pub(crate) inv: u64,
    pub(crate) res: u64,
    pub(crate) op: Op,
    pub(crate) resp: Resp,
}

pub(crate) fn describe(events: &[Event]) -> String {
    let mut text = String::new();
    for e in events {
        text.push_str(&format!(
            "\n  t{} [{}..{}] {:?} -> {:?}",
            e.thread, e.inv, e.res, e.op, e.resp
        ));
    }
    text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Linearizable,
    NotLinearizable,
    /// The search ran out of its node budget. Never counted as a pass.
    Inconclusive,
}

struct Search<'a> {
    events: &'a [Event],
    failed: HashSet<(u64, u64)>,
    nodes: usize,
    budget: usize,
}

impl Search<'_> {
    /// `Some(true)` a full linearization exists from here, `Some(false)` none does, `None` out of budget.
    fn dfs(&mut self, done: u64, state: u64) -> Option<bool> {
        let n = self.events.len();
        let full = (1u64 << n) - 1;
        if done == full {
            return Some(true);
        }
        if self.failed.contains(&(done, state)) {
            return Some(false);
        }
        self.nodes += 1;
        if self.nodes > self.budget {
            return None;
        }
        for i in 0..n {
            if done & (1u64 << i) != 0 {
                continue;
            }
            // An operation can go next only if no unplaced operation finished before it started.
            let blocked = (0..n).any(|j| {
                j != i && done & (1u64 << j) == 0 && self.events[j].res <= self.events[i].inv
            });
            if blocked {
                continue;
            }
            let (next, expect) = spec(state, self.events[i].op);
            if expect != self.events[i].resp {
                continue;
            }
            match self.dfs(done | (1u64 << i), next) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => return None,
            }
        }
        self.failed.insert((done, state));
        Some(false)
    }
}

/// Wing-Gong linearizability search over at most 62 operations.
pub(crate) fn check(initial: u64, events: &[Event], budget: usize) -> Verdict {
    assert!(
        events.len() <= 62,
        "the checker handles at most 62 operations"
    );
    let mut search = Search {
        events,
        failed: HashSet::new(),
        nodes: 0,
        budget,
    };
    match search.dfs(0, initial) {
        Some(true) => Verdict::Linearizable,
        Some(false) => Verdict::NotLinearizable,
        None => Verdict::Inconclusive,
    }
}

/// A cell driven by the scheduler. `begin` registers the operation a thread starts; `step` runs that
/// thread's next micro-step and returns the response once the operation is complete.
pub(crate) trait StepCell {
    fn begin(&mut self, thread: usize, op: Op);
    fn step(&mut self, thread: usize) -> Option<Resp>;
}

pub(crate) fn apply_real(cell: &SharedU64, op: Op) -> Resp {
    match op {
        Op::Load => Resp::Value(cell.load()),
        Op::Store(value) => {
            cell.store(value);
            Resp::Stored
        }
        Op::Cas { current, new } => Resp::Cas(cell.compare_exchange(current, new)),
        Op::FetchAdd(delta) => Resp::Add(cell.fetch_add(delta)),
    }
}

/// The real [`SharedU64`] as a step cell: every operation is one step.
pub(crate) struct RealCell {
    cell: SharedU64,
    pending: Vec<Option<Op>>,
}

impl RealCell {
    pub(crate) fn new(initial: u64, threads: usize) -> Self {
        Self {
            cell: SharedU64::new(initial),
            pending: vec![None; threads],
        }
    }
}

impl StepCell for RealCell {
    fn begin(&mut self, thread: usize, op: Op) {
        self.pending[thread] = Some(op);
    }

    fn step(&mut self, thread: usize) -> Option<Resp> {
        let op = self.pending[thread].take().expect("step without begin");
        Some(apply_real(&self.cell, op))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Real,
    SplitWord,
    Truncating,
}

pub(crate) fn build(kind: Kind, initial: u64, threads: usize) -> Box<dyn StepCell> {
    match kind {
        Kind::Real => Box::new(RealCell::new(initial, threads)),
        Kind::SplitWord => Box::new(crate::planted::SplitCell::new(initial, threads)),
        Kind::Truncating => Box::new(crate::planted::TruncCell::new(initial, threads)),
    }
}

pub(crate) fn gen_op(rng: &mut SplitMix64) -> Op {
    match rng.below(4) {
        0 => Op::Load,
        1 => {
            let value = POOL[rng.below(POOL.len())];
            Op::Store(value)
        }
        2 => {
            let current = POOL[rng.below(POOL.len())];
            let new = POOL[rng.below(POOL.len())];
            Op::Cas { current, new }
        }
        _ => {
            let delta = DELTAS[rng.below(DELTAS.len())];
            Op::FetchAdd(delta)
        }
    }
}

pub(crate) fn gen_plans(
    rng: &mut SplitMix64,
    threads: usize,
    ops_per_thread: usize,
) -> Vec<Vec<Op>> {
    let mut plans = Vec::new();
    for _ in 0..threads {
        let mut ops = Vec::new();
        for _ in 0..ops_per_thread {
            ops.push(gen_op(rng));
        }
        plans.push(ops);
    }
    plans
}

/// Runs `plans` (one list of operations per thread) against `cell`. `pick` chooses which runnable thread
/// takes the next micro-step; it is handed the runnable thread ids and returns one of them.
pub(crate) fn run_with(
    cell: &mut dyn StepCell,
    plans: &[Vec<Op>],
    pick: &mut dyn FnMut(&[usize]) -> usize,
) -> Vec<Event> {
    let threads = plans.len();
    let mut next_idx = vec![0usize; threads];
    let mut inflight: Vec<Option<(u64, Op)>> = vec![None; threads];
    let mut clock = 0u64;
    let mut events = Vec::new();
    loop {
        let runnable: Vec<usize> = (0..threads)
            .filter(|&t| inflight[t].is_some() || next_idx[t] < plans[t].len())
            .collect();
        if runnable.is_empty() {
            break;
        }
        let t = pick(runnable.as_slice());
        assert!(runnable.contains(&t), "picked thread {t} is not runnable");
        if inflight[t].is_none() {
            let op = plans[t][next_idx[t]];
            next_idx[t] += 1;
            cell.begin(t, op);
            inflight[t] = Some((clock, op));
        }
        let finished = cell.step(t);
        clock += 1;
        if let Some(resp) = finished {
            let (inv, op) = inflight[t].take().expect("an operation is in flight");
            events.push(Event {
                thread: t,
                inv,
                res: clock,
                op,
                resp,
            });
        }
    }
    events
}

/// One seeded run: the seed draws every thread's plan, then every scheduling choice.
pub(crate) fn seeded_run(
    kind: Kind,
    seed: u64,
    threads: usize,
    ops_per_thread: usize,
) -> Vec<Event> {
    let mut rng = SplitMix64::new(seed);
    let plans = gen_plans(&mut rng, threads, ops_per_thread);
    let mut cell = build(kind, INITIAL, threads);
    run_with(cell.as_mut(), &plans, &mut |runnable: &[usize]| {
        runnable[rng.below(runnable.len())]
    })
}

/// A scripted run. Picks are thread ids; one that is not runnable is skipped; when the script is used up
/// the lowest runnable thread goes next.
pub(crate) fn scripted_run(
    kind: Kind,
    initial: u64,
    plans: &[Vec<Op>],
    picks: &[usize],
) -> Vec<Event> {
    let mut cell = build(kind, initial, plans.len());
    let mut cursor = 0usize;
    run_with(cell.as_mut(), plans, &mut |runnable: &[usize]| {
        while cursor < picks.len() {
            let thread = picks[cursor];
            cursor += 1;
            if runnable.contains(&thread) {
                return thread;
            }
        }
        runnable[0]
    })
}
