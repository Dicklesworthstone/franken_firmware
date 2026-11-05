"""Independent model for P05 (ffw-ipz): a sequential specification of a shared 64-bit cell, a
linearizability checker, a seeded micro-step scheduler, and three cell models.

It mirrors the Rust test model in crates/franken-atomic/src/model.rs and planted.rs, written separately, so
that the Rust tests and this file can only agree if both implement the same rules. Nothing here imports the
Rust code, runs cargo or touches a device. Evidence label: model, host simulation.

The three cells:
  good   one operation is one indivisible step (what a Mutex around a u64 gives);
  split  two independent 32-bit words, each operation a sequence of single-word steps (the naive version);
  trunc  one 32-bit word, values cut with `as u32` (the truncating version).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

# ---- values the generator draws from (kept in step with model.rs) -------------------------------------
POOL = [0x0000_0000_FFFF_FFF0, 0x0000_0001_0000_0000, 0x0000_0001_FFFF_FFF0, 5]
DELTAS = [1, 7, 16, 0x20]
INITIAL = POOL[0]

# ---- operations: tuples so they hash ------------------------------------------------------------------
LOAD = ("load",)


def store(v: int):
    return ("store", v)


def cas(current: int, new: int):
    return ("cas", current, new)


def fetch_add(d: int):
    return ("add", d)


# ---- responses -----------------------------------------------------------------------------------------
# ("value", v) | ("stored",) | ("cas_ok", prev) | ("cas_err", seen) | ("add_ok", prev) | ("add_overflow", cur, d)


def spec(state: int, op, mutant: Optional[str] = None) -> Tuple[int, tuple]:
    """The sequential specification. `mutant` names a deliberately wrong rule, used only to prove the case
    corpus notices it: "cas_ignores_expected" (a compare-exchange always succeeds) and "overflow_wraps"
    (a fetch_add wraps instead of reporting overflow)."""
    kind = op[0]
    if kind == "load":
        return state, ("value", state)
    if kind == "store":
        return op[1], ("stored",)
    if kind == "cas":
        if state == op[1] or mutant == "cas_ignores_expected":
            return op[2], ("cas_ok", state)
        return state, ("cas_err", state)
    if kind == "add":
        total = state + op[1]
        if total > MASK64:
            if mutant == "overflow_wraps":
                return total & MASK64, ("add_ok", state)
            return state, ("add_overflow", state, op[1])
        return total, ("add_ok", state)
    raise ValueError(op)


# ---- seeded generator -----------------------------------------------------------------------------------
class SplitMix64:
    def __init__(self, seed: int):
        self.state = seed & MASK64

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E37_79B9_7F4A_7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        return self.next_u64() % n


def gen_op(rng: SplitMix64):
    kind = rng.below(4)
    if kind == 0:
        return LOAD
    if kind == 1:
        return store(POOL[rng.below(len(POOL))])
    if kind == 2:
        current = POOL[rng.below(len(POOL))]
        new = POOL[rng.below(len(POOL))]
        return cas(current, new)
    return fetch_add(DELTAS[rng.below(len(DELTAS))])


def gen_plans(rng: SplitMix64, threads: int, ops_per_thread: int):
    plans = []
    for _ in range(threads):
        plans.append([gen_op(rng) for _ in range(ops_per_thread)])
    return plans


# ---- cells: begin(thread, op) then step(thread) -> response or None -------------------------------------
def join(hi: int, lo: int) -> int:
    return (hi << 32) | lo


class GoodCell:
    """One operation, one step."""

    def __init__(self, initial: int, threads: int):
        self.state = initial
        self.pending: List[Optional[tuple]] = [None] * threads

    def begin(self, t: int, op) -> None:
        self.pending[t] = op

    def step(self, t: int):
        op = self.pending[t]
        self.pending[t] = None
        self.state, resp = spec(self.state, op)
        return resp


class SplitCell:
    """Two independent 32-bit words; every operation is a sequence of single-word steps."""

    def __init__(self, initial: int, threads: int):
        self.hi = initial >> 32
        self.lo = initial & MASK32
        self.pending: List[Optional[dict]] = [None] * threads

    def begin(self, t: int, op) -> None:
        self.pending[t] = {"op": op, "phase": 0, "hi": 0, "lo": 0, "seen": 0, "carry": 0}

    def step(self, t: int):
        p = self.pending[t]
        op = p["op"]
        kind = op[0]
        phase = p["phase"]
        p["phase"] = phase + 1
        if kind == "load":
            if phase == 0:
                p["hi"] = self.hi
                return None
            p["lo"] = self.lo
            self.pending[t] = None
            return ("value", join(p["hi"], p["lo"]))
        if kind == "store":
            if phase == 0:
                self.hi = op[1] >> 32
                return None
            self.lo = op[1] & MASK32
            self.pending[t] = None
            return ("stored",)
        if kind == "cas":
            if phase == 0:
                p["hi"] = self.hi
                return None
            if phase == 1:
                p["lo"] = self.lo
                p["seen"] = join(p["hi"], p["lo"])
                return None
            if phase == 2:
                if p["seen"] == op[1]:
                    self.hi = op[2] >> 32
                return None
            if p["seen"] == op[1]:
                self.lo = op[2] & MASK32
                resp = ("cas_ok", p["seen"])
            else:
                resp = ("cas_err", p["seen"])
            self.pending[t] = None
            return resp
        if kind == "add":
            delta = op[1]
            if phase == 0:
                old_lo = self.lo
                total = old_lo + (delta & MASK32)
                self.lo = total & MASK32
                p["lo"] = old_lo
                p["carry"] = 1 if total > MASK32 else 0
                return None
            old_hi = self.hi
            self.hi = (old_hi + (delta >> 32) + p["carry"]) & MASK32
            self.pending[t] = None
            return ("add_ok", join(old_hi, p["lo"]))
        raise ValueError(op)


class TruncCell:
    """One 32-bit word; 64-bit values are cut with `as u32`."""

    def __init__(self, initial: int, threads: int):
        self.word = initial & MASK32
        self.pending: List[Optional[tuple]] = [None] * threads

    def begin(self, t: int, op) -> None:
        self.pending[t] = op

    def step(self, t: int):
        op = self.pending[t]
        self.pending[t] = None
        kind = op[0]
        if kind == "load":
            return ("value", self.word)
        if kind == "store":
            self.word = op[1] & MASK32
            return ("stored",)
        if kind == "cas":
            seen = self.word
            if seen == op[1]:
                self.word = op[2] & MASK32
                return ("cas_ok", seen)
            return ("cas_err", seen)
        if kind == "add":
            old = self.word
            self.word = (old + (op[1] & MASK32)) & MASK32
            return ("add_ok", old)
        raise ValueError(op)


CELLS: Dict[str, Callable[[int, int], object]] = {"good": GoodCell, "split": SplitCell, "trunc": TruncCell}


# ---- scheduler ---------------------------------------------------------------------------------------------
@dataclass
class Event:
    thread: int
    inv: int
    res: int
    op: tuple
    resp: tuple


def run_with(cell, plans: Sequence[Sequence[tuple]], pick: Callable[[List[int]], int]) -> List[Event]:
    threads = len(plans)
    next_idx = [0] * threads
    inflight: List[Optional[Tuple[int, tuple]]] = [None] * threads
    clock = 0
    events: List[Event] = []
    while True:
        runnable = [t for t in range(threads) if inflight[t] is not None or next_idx[t] < len(plans[t])]
        if not runnable:
            break
        t = pick(runnable)
        assert t in runnable, (t, runnable)
        if inflight[t] is None:
            op = plans[t][next_idx[t]]
            next_idx[t] += 1
            cell.begin(t, op)
            inflight[t] = (clock, op)
        finished = cell.step(t)
        clock += 1
        if finished is not None:
            inv, op = inflight[t]
            inflight[t] = None
            events.append(Event(t, inv, clock, op, finished))
    return events


def seeded_run(kind: str, seed: int, threads: int, ops_per_thread: int) -> List[Event]:
    rng = SplitMix64(seed)
    plans = gen_plans(rng, threads, ops_per_thread)
    cell = CELLS[kind](INITIAL, threads)
    return run_with(cell, plans, lambda runnable: runnable[rng.below(len(runnable))])


def scripted_run(kind: str, initial: int, plans, picks: Sequence[int]) -> List[Event]:
    """Picks are thread ids; an id that is not runnable is skipped; once the script is used up the lowest
    runnable thread goes next."""
    cell = CELLS[kind](initial, len(plans))
    cursor = [0]

    def pick(runnable: List[int]) -> int:
        while cursor[0] < len(picks):
            t = picks[cursor[0]]
            cursor[0] += 1
            if t in runnable:
                return t
        return runnable[0]

    return run_with(cell, plans, pick)


# ---- linearizability checker --------------------------------------------------------------------------------
LINEARIZABLE, NOT_LINEARIZABLE, INCONCLUSIVE = "linearizable", "not_linearizable", "inconclusive"


CHECKER_MUTANTS = ("no_realtime", "strict_precedence", "no_response_check", "cas_ignores_expected",
                   "overflow_wraps")


def check(initial: int, events: Sequence[Event], budget: int = 200_000, mutant: Optional[str] = None) -> str:
    """Wing-Gong search. `a` must come before `b` when a.res <= b.inv. A spec mismatch prunes; running out of
    budget is INCONCLUSIVE, never a pass. `mutant` (see CHECKER_MUTANTS) weakens one rule so the case corpus can
    be shown to notice it: "no_realtime" drops the real-time order, "strict_precedence" uses < instead of <=,
    "no_response_check" stops comparing responses, and the two spec mutants change the specification."""
    n = len(events)
    assert n <= 62
    full = (1 << n) - 1
    failed = set()
    nodes = [0]

    def before(a: Event, b: Event) -> bool:
        if mutant == "no_realtime":
            return False
        return a.res < b.inv if mutant == "strict_precedence" else a.res <= b.inv

    class Budget(Exception):
        pass

    def dfs(done: int, state: int) -> bool:
        if done == full:
            return True
        if (done, state) in failed:
            return False
        nodes[0] += 1
        if nodes[0] > budget:
            raise Budget()
        for i in range(n):
            if done & (1 << i):
                continue
            if any(j != i and not done & (1 << j) and before(events[j], events[i]) for j in range(n)):
                continue
            nxt, expect = spec(state, events[i].op, mutant)
            if mutant != "no_response_check" and expect != events[i].resp:
                continue
            if dfs(done | (1 << i), nxt):
                return True
        failed.add((done, state))
        return False

    try:
        return LINEARIZABLE if dfs(0, initial) else NOT_LINEARIZABLE
    except Budget:
        return INCONCLUSIVE


def sweep(kind: str, first_seed: int, seeds: int, threads: int, ops_per_thread: int):
    violations: List[int] = []
    inconclusive: List[int] = []
    for seed in range(first_seed, first_seed + seeds):
        verdict = check(INITIAL, seeded_run(kind, seed, threads, ops_per_thread))
        if verdict == NOT_LINEARIZABLE:
            violations.append(seed)
        elif verdict == INCONCLUSIVE:
            inconclusive.append(seed)
    return violations, inconclusive


# ---- the pinned profile ---------------------------------------------------------------------------------------
PROFILE = {"threads": 3, "ops_per_thread": 4, "first_seed": 0, "seeds": 256}


def predict() -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for kind in ("good", "split", "trunc"):
        v, inc = sweep(kind, PROFILE["first_seed"], PROFILE["seeds"], PROFILE["threads"], PROFILE["ops_per_thread"])
        out[kind] = v
        out[kind + "_inconclusive"] = inc
    return out


# ---- directed scenarios (the expected values are written by hand in cases.json) ------------------------------
def scenario(name: str):
    """(initial, plans, picks) for the three directed schedules."""
    if name == "torn_store":
        return POOL[0], [[store(0x0000_0001_0000_0000)], [LOAD]], [0, 1, 1, 0]
    if name == "torn_carry":
        return POOL[0], [[fetch_add(0x10)], [LOAD]], [0, 1, 1, 0]
    if name == "truncated_store":
        return POOL[0], [[store(0x0000_0001_0000_0001)], [LOAD]], [0, 1]
    raise KeyError(name)


def run_scenario(kind: str, name: str):
    initial, plans, picks = scenario(name)
    events = scripted_run(kind, initial, plans, picks)
    return events, check(initial, events)


def load_value(events: Sequence[Event]) -> Optional[int]:
    for e in events:
        if e.op == LOAD:
            return e.resp[1]
    return None


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "predict":
        result = predict()
        print("# profile threads", PROFILE["threads"], "ops_per_thread", PROFILE["ops_per_thread"],
              "first_seed", PROFILE["first_seed"], "seeds", PROFILE["seeds"])
        for kind in ("good", "split", "trunc"):
            print(f"{kind}_violations {len(result[kind])}")
            print(f"{kind}_inconclusive {len(result[kind + '_inconclusive'])}")
        for kind in ("split", "trunc"):
            print(f"{kind}_first_violation_seeds " + " ".join(str(s) for s in result[kind][:4]))
            clean = [s for s in range(PROFILE["first_seed"], PROFILE["first_seed"] + PROFILE["seeds"])
                     if s not in set(result[kind])]
            print(f"{kind}_first_clean_seeds " + " ".join(str(s) for s in clean[:4]))
    else:
        print(__doc__)
