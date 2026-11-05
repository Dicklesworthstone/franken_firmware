"""N04 vector generator: scripted worlds for the playout engine, tables of pure-function cases, and the seeded
loss/jitter/reorder/duplicate schedules. Writes nothing itself; ``build()`` returns the document that
``run_cases.py --write-vectors`` stores as ``vectors.json``.

Every hand-written world carries ``expect`` anchors written by hand from docs/contracts/n04.md (not copied from the
model's output); ``build()`` refuses a world whose reference results disagree with them. The seeded worlds carry no
anchors: the judge and the Rust invariants check them. The ops are compact arrays:

  ["begin", epoch, anchor_frame, anchor_ns]
  ["packet", t, u, ok, epoch, frame, pres, frames, seed]      payload = synth_payload(seed, frames)
  ["repair", t, u, ok, epoch, frame, frames, seed]
  ["bad", t, u, ok, epoch, frame, pres, frames, payload_len]  a packet whose payload length is not frames * 4
  ["decide", t, u, ok]
  ["change", epoch, change_id, effective_frame, new_anchor_ns]
  ["deliver", accepted_at | null]                             against the last decision's submit_deadline
  ["advice"] / ["stats"]

Calls that carry a time are scheduled: they are sorted by (time, order) between untimed ops, because the engine
refuses a clock that runs backwards. ``raw=True`` bypasses that to script a regression on purpose.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

import reference as R

VERSION = "ffw.n04.vectors.v1"
# The diagnostics every world is also run with: labels, the pseudonym key and the owner-supplied member and group.
LOG = dict(run_id="n04-log", key_hex="07" * 32, member="member-a", group="group-a")

# The paired positive: a sink that keeps up (drained after every op, always taking the line).
KEEPS_UP = dict(capacity=4, drain_every=1, budget=8, replies=["taken"], final_budget=0)

# Sink scenarios: (id, world, plan, expect). ``expect`` is hand-derived from the contract (section 15), with the kind
# sequences written out in the comments; scenarios without one are held to the reference alone.
# W02 emits, in order: started(C) real(o) late(o) concealed(C) concealed(C) late(o) real(o), over 10 ops.
# W10 emits: started(C) clock-refusal(o) clock-poll(C) regression-refusal(o) regression-poll(C) real(o).
# Ring of 4: ordinary records may use 3 slots (a quarter is kept for critical ones), critical records 4.
# Ring of 2: 2 and 2. Ring of 1: 1 and 1. The sequences: W10 is C o C o C o.
NEVER = 1000      # drain_every larger than any world: the sink is never offered anything
SCENARIOS = [
    # C->1 o->2 o->3 C->4 C: full, lost(critical) o: full o: full -> queued 4, dropped 3, one critical lost
    ("LS-RING-4-NO-DRAIN", "W02-CUTOFF-BOUNDARY", dict(capacity=4, drain_every=NEVER, budget=8, replies=["taken"], final_budget=0),
     dict(emitted=7, delivered=0, queued=4, dropped_full=3, dropped_oversize=0, critical_lost=1, offers=0,
          sink_full_polls=0, sink_unavailable_polls=0)),
    # C->1 o->2 o: full, C: full(lost) C: full(lost) o o: full -> queued 2, dropped 5, two critical lost
    ("LS-RING-2-NO-DRAIN", "W02-CUTOFF-BOUNDARY", dict(capacity=2, drain_every=NEVER, budget=8, replies=["taken"], final_budget=0),
     dict(emitted=7, delivered=0, queued=2, dropped_full=5, dropped_oversize=0, critical_lost=2, offers=0,
          sink_full_polls=0, sink_unavailable_polls=0)),
    # one slot: only the first record fits; the 5 after it are dropped, two of them critical (the two clock polls)
    ("LS-RING-1-NO-DRAIN", "W10-CLOCK", dict(capacity=1, drain_every=NEVER, budget=8, replies=["taken"], final_budget=0),
     dict(emitted=6, delivered=0, queued=1, dropped_full=5, dropped_oversize=0, critical_lost=2, offers=0,
          sink_full_polls=0, sink_unavailable_polls=0)),
    # C->1 o->2 C->3 o: full (3 is the ordinary limit), C->4 (the kept room) o: full -> queued 4, two ordinary dropped,
    # no critical record lost: the reserve did its job
    ("LS-RING-4-RESERVE", "W10-CLOCK", dict(capacity=4, drain_every=NEVER, budget=8, replies=["taken"], final_budget=0),
     dict(emitted=6, delivered=0, queued=4, dropped_full=2, dropped_oversize=0, critical_lost=0, offers=0,
          sink_full_polls=0, sink_unavailable_polls=0)),
    # a sink that keeps up (drained after each of the 9 ops, always takes the line): each of the 6 records is offered once
    ("LS-KEEPS-UP-CLOCK", "W10-CLOCK", dict(capacity=4, drain_every=1, budget=4, replies=["taken"], final_budget=0),
     dict(emitted=6, delivered=6, queued=0, dropped_full=0, dropped_oversize=0, critical_lost=0, offers=6,
          sink_full_polls=0, sink_unavailable_polls=0)),
    # drained after each of the 10 ops; the sink is down every time, so the head is offered 10 times and never leaves;
    # the ring fills exactly as with no drain at all
    ("LS-UNAVAILABLE", "W02-CUTOFF-BOUNDARY", dict(capacity=4, drain_every=1, budget=4, replies=["unavailable"], final_budget=0),
     dict(emitted=7, delivered=0, queued=4, dropped_full=3, dropped_oversize=0, critical_lost=1, offers=10,
          sink_full_polls=0, sink_unavailable_polls=10)),
    ("LS-SINK-FULL", "W02-CUTOFF-BOUNDARY", dict(capacity=4, drain_every=1, budget=4, replies=["full"], final_budget=0),
     dict(emitted=7, delivered=0, queued=4, dropped_full=3, dropped_oversize=0, critical_lost=1, offers=10,
          sink_full_polls=10, sink_unavailable_polls=0)),
    ("LS-RECOVERS", "W02-CUTOFF-BOUNDARY", dict(capacity=4, drain_every=1, budget=4, replies=["unavailable", "full", "taken"], final_budget=8), None),
    ("LS-OVERSIZE", "W02-CUTOFF-BOUNDARY", dict(capacity=8, drain_every=1, budget=8, replies=["taken"], final_budget=0, max_line=400), None),
    ("LS-SLOW-DRAIN-MUSIC", "W16-SEEDED-MUSIC", dict(capacity=16, drain_every=40, budget=4, replies=["taken"], final_budget=0), None),
    ("LS-FLAPPING-MUSIC", "W16-SEEDED-MUSIC", dict(capacity=32, drain_every=5, budget=3,
                                                    replies=["taken", "taken", "unavailable", "full"], final_budget=2), None),
    ("LS-SINK-FULL-REALTIME", "W17-SEEDED-REALTIME", dict(capacity=8, drain_every=7, budget=2, replies=["full"], final_budget=0), None),
]
CFG = dict(work_ns=1_500_000, lead_ns=2_000_000, tolerance_ns=100_000)
U = 200_000                       # a typical clock uncertainty (N03 reports are in this range once locked)
ANCHOR = 2_000_000_000            # presentation of frame 0 in most worlds
BNS = R.BLOCK_NS
MASK = (1 << 64) - 1
EARLY = {"music": 100_000_000, "realtime": 30_000_000}      # how far ahead of presentation well-behaved packets arrive


class Rng:
    """xorshift64*: stable across Python versions, unlike random.Random's helper methods."""

    def __init__(self, seed: int):
        self.s = (seed or 1) & MASK

    def next(self) -> int:
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & MASK
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & MASK

    def below(self, n: int) -> int:
        return self.next() % n


def P(b: int, origin: int = ANCHOR) -> int:
    return origin + R.frames_to_ns(b * R.BLOCK_FRAMES)


def C(b: int, u: int = U, origin: int = ANCHOR) -> int:
    return R.consume_by(P(b, origin), CFG["work_ns"], CFG["lead_ns"], u)


class W:
    def __init__(self, wid: str, profile: str, note: str, tags: List[str], cfg: Optional[dict] = None):
        self.id, self.profile, self.note, self.tags = wid, profile, note, tags
        self.cfg = dict(CFG if cfg is None else cfg)
        self.ops: List[list] = []
        self.labels: Dict[str, int] = {}
        self.expect: List[dict] = []
        self._batch: List[Tuple[int, int, int, list, Optional[str]]] = []

    # a timed call joins the batch; the batch is sorted and emitted when an untimed op (or the end) arrives
    def _timed(self, t: int, order: int, op: list, label: Optional[str], raw: bool) -> None:
        if raw:
            self.add(op, label)
        else:
            self._batch.append((t, order, len(self._batch), op, label))

    def flush(self) -> None:
        for _, _, _, op, label in sorted(self._batch, key=lambda e: e[:3]):
            self._emit(op, label)
        self._batch = []

    def _emit(self, op: list, label: Optional[str]) -> None:
        self.ops.append(op)
        if label:
            assert label not in self.labels, label
            self.labels[label] = len(self.ops) - 1

    def add(self, op: list, label: Optional[str] = None) -> None:
        self.flush()
        self._emit(op, label)

    def begin(self, epoch=1, frame=0, ns=ANCHOR, label=None):
        self.add(["begin", epoch, frame, ns], label)

    def packet(self, t, b, seed=None, u=U, ok=1, epoch=1, pres=None, frames=256, origin=ANCHOR, label=None,
               frame=None, raw=False):
        f = b * 256 if frame is None else frame
        self._timed(t, 0, ["packet", t, u, ok, epoch, f, P(b, origin) if pres is None else pres, frames,
                           b if seed is None else seed], label, raw)

    def repair(self, t, b, seed, u=U, ok=1, epoch=1, frames=256, label=None, raw=False):
        self._timed(t, 0, ["repair", t, u, ok, epoch, b * 256, frames, seed], label, raw)

    def decide(self, t, u=U, ok=1, label=None, raw=False):
        self._timed(t, 1, ["decide", t, u, ok], label, raw)

    def decide_at_cutoff(self, b, u=U, origin=ANCHOR, label=None):
        self.decide(C(b, u, origin), u, label=label)

    def ex(self, label: str, key: str, value: Any) -> None:
        self.expect.append(dict(label=label, key=key, value=value))

    def doc(self) -> dict:
        self.flush()
        return dict(id=self.id, profile=self.profile, cfg=self.cfg, note=self.note, tags=self.tags, ops=self.ops,
                    labels=self.labels, expect=self.expect)


def _dig(result: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        result = result[part]
    return result


def check_expectations(world: dict, results: List[dict]) -> None:
    for e in world["expect"]:
        result = results[world["labels"][e["label"]]]
        try:
            got = _dig(result, e["key"])
        except (KeyError, TypeError):
            raise AssertionError("%s: %s has no %r in its result %r" % (world["id"], e["label"], e["key"], result))
        assert got == e["value"], "%s: %s.%s = %r, hand-written expectation %r" % (
            world["id"], e["label"], e["key"], got, e["value"])


# -- the worlds ----------------------------------------------------------------------------------------------------


def in_order(w: W, blocks: range, lost=()) -> None:
    early = EARLY[w.profile]
    for b in blocks:
        if b not in lost:
            w.packet(P(b) - early, b)
        w.decide_at_cutoff(b, label="d%d" % b)


def w01() -> W:
    w = W("W01-ONTIME", "music", "twenty blocks arrive in order well before their cutoffs: every decision is real", ["basic"])
    w.begin()
    in_order(w, range(20))
    w.add(["stats"], "stats")
    for b in (0, 7, 19):
        w.ex("d%d" % b, "d.outcome", "real")
        w.ex("d%d" % b, "d.block", b)
        w.ex("d%d" % b, "d.fnv", "%016x" % R.fnv1a64(R.synth_payload(b, 256)))
    w.ex("d0", "d.pres", ANCHOR)
    w.ex("d0", "d.submit_deadline", ANCHOR - CFG["lead_ns"])
    w.ex("stats", "stats.decided_real", 20)
    w.ex("stats", "stats.admitted", 20)
    return w


def w02() -> W:
    """The cutoff boundary: one nanosecond before plays, at the cutoff and after do not; and the positive twin."""
    w = W("W02-CUTOFF-BOUNDARY", "music",
          "cutoff = presentation - work - lead - uncertainty with all three positive; arrival strictly before it plays",
          ["boundary"])
    w.begin()
    w.decide(C(0) - 1, label="pending")
    w.packet(C(0) - 1, 0, label="b0-before")                      # admitted
    w.decide_at_cutoff(0, label="d0")
    w.packet(C(1), 1, label="b1-at")                                # margin 0: late
    w.decide_at_cutoff(1, label="d1")
    w.decide_at_cutoff(2, label="d2")
    w.packet(C(2) + 1, 2, label="b2-after")                         # block already decided: late
    w.packet(C(3) - 1, 3, label="b3-before")                        # the positive twin after two negatives
    w.decide_at_cutoff(3, label="d3")
    w.ex("pending", "poll", "pending")
    w.ex("b0-before", "r", "admitted")
    w.ex("d0", "d.outcome", "real")
    w.ex("d0", "d.late_by", 0)
    w.ex("b1-at", "r", "late")
    w.ex("d1", "d.outcome", "concealed")
    w.ex("d1", "d.run", 1)
    w.ex("d2", "d.outcome", "concealed")
    w.ex("d2", "d.run", 2)
    w.ex("b2-after", "r", "late")
    w.ex("b3-before", "r", "admitted")
    w.ex("d3", "d.outcome", "real")
    return w


def w03() -> W:
    """The uncertainty comes from the clock report, so a larger u moves the cutoff earlier at the same arrival."""
    w = W("W03-UNCERTAINTY-MOVES-CUTOFF", "music",
          "arrival 4 ms before presentation; guard = 3.5 ms + u, so margin = 500000 - u: u 499999 plays, 500000 and more do not",
          ["boundary", "clock"])
    w.begin()
    for b, u, label in ((0, 499_999, "u-499999"), (1, 500_000, "u-500000"), (2, 500_001, "u-500001"), (3, 200_000, "u-small")):
        w.packet(P(b) - 4_000_000, b, u=u, label=label)
    for b in range(4):
        w.decide_at_cutoff(b, label="d%d" % b)
    w.ex("u-499999", "r", "admitted")
    w.ex("u-500000", "r", "late")
    w.ex("u-500001", "r", "late")
    w.ex("u-small", "r", "admitted")
    w.ex("d0", "d.outcome", "real")
    w.ex("d1", "d.outcome", "concealed")
    w.ex("d3", "d.outcome", "real")
    return w


def w04() -> W:
    w = W("W04-REORDER-DUPLICATE", "music",
          "reordered arrivals play in frame order; a duplicate never plays twice; a late copy of a concealed block is late",
          ["reorder", "duplicate"])
    w.begin()
    t = P(0) - 90_000_000
    for i, b in enumerate([2, 0, 1, 3, 5, 4, 7, 6]):
        w.packet(t + i * 1_000_000, b, label="b%d" % b)
    w.packet(t + 9_000_000, 3, label="dup-same")                                 # identical copy
    w.packet(t + 10_000_000, 4, seed=99, label="dup-conflict")                    # same frame, different bytes
    for b in range(8):
        w.decide_at_cutoff(b, label="d%d" % b)
    w.packet(C(7) + 1_000_000, 0, label="dup-after-play")                         # copy of a block already played
    w.decide_at_cutoff(8, label="d8")                                             # block 8 never arrived
    w.packet(C(8) + 1_000_000, 8, label="late-copy")
    w.add(["stats"], "stats")
    for b in range(8):
        w.ex("d%d" % b, "d.outcome", "real")
        w.ex("d%d" % b, "d.block", b)
    w.ex("d4", "d.fnv", "%016x" % R.fnv1a64(R.synth_payload(4, 256)))             # first copy wins
    w.ex("dup-same", "r", "duplicate")
    w.ex("dup-conflict", "r", "duplicate")
    w.ex("dup-after-play", "r", "duplicate")
    w.ex("d8", "d.outcome", "concealed")
    w.ex("late-copy", "r", "late")
    w.ex("stats", "stats.duplicate", 3)
    w.ex("stats", "stats.duplicate_conflict", 1)
    w.ex("stats", "stats.late", 1)
    w.ex("stats", "stats.admitted", 8)
    return w


def burst(profile: str, wid: str, conceal: int) -> W:
    w = W(wid, profile, "a 19-block (about 100 ms) loss burst: concealed up to the maximum, then muted, then real again",
          ["loss", "conceal"])
    w.begin()
    in_order(w, range(40), lost=range(10, 29))
    w.add(["stats"], "stats")
    w.ex("d9", "d.outcome", "real")
    w.ex("d10", "d.outcome", "concealed")
    w.ex("d10", "d.run", 1)
    w.ex("d%d" % (9 + conceal), "d.outcome", "concealed")
    w.ex("d%d" % (10 + conceal), "d.outcome", "muted_gap")
    w.ex("d28", "d.outcome", "muted_gap")
    w.ex("d29", "d.outcome", "real")
    w.ex("d30", "d.outcome", "real")
    w.ex("stats", "stats.decided_concealed", conceal)
    w.ex("stats", "stats.decided_muted_gap", 19 - conceal)
    w.ex("stats", "stats.decided_real", 21)
    return w


def w07() -> W:
    w = W("W07-EPOCH", "music", "unbound, stale, future and restarted epochs; nothing a stale packet does changes the stream",
          ["epoch"])
    w.packet(P(0) - 100_000_000, 0, epoch=5, label="unbound")
    w.begin(epoch=5, label="begin5")
    w.packet(P(0) - 99_000_000, 0, epoch=4, label="stale")
    w.packet(P(0) - 98_000_000, 0, epoch=6, label="future")
    w.add(["stats"], "s1")
    w.packet(P(0) - 97_000_000, 0, epoch=5, label="good")
    w.add(["begin", 4, 0, ANCHOR], "begin4")
    w.add(["stats"], "s2")
    w.add(["begin", 5, 0, ANCHOR], "restart5")
    w.add(["stats"], "s3")
    w.packet(P(0) - 96_000_000, 0, epoch=5, label="again")
    w.add(["begin", 6, 0, ANCHOR], "begin6")
    w.packet(P(0) - 95_000_000, 0, epoch=5, label="old-after-6")
    w.packet(P(0) - 94_000_000, 0, epoch=6, label="new-after-6")
    w.add(["begin", 7, 3, ANCHOR], "misaligned")
    w.add(["begin", 7, 256, 1], "bad-anchor")                          # frame 256 cannot be presented at 1 ns
    w.ex("unbound", "r", "not_bound")
    w.ex("begin5", "ok", True)
    w.ex("stale", "r", "stale_epoch")
    w.ex("future", "r", "future_epoch")
    w.ex("s1", "queued", 0)                                           # neither stale nor future changed the stream
    w.ex("s1", "cursor", 0)
    w.ex("s1", "epoch", 5)
    w.ex("good", "r", "admitted")
    w.ex("begin4", "ok", False)
    w.ex("begin4", "reason", "stale_epoch")
    w.ex("s2", "queued", 1)                                           # the refused restart changed nothing
    w.ex("s2", "epoch", 5)
    w.ex("restart5", "ok", True)
    w.ex("s3", "queued", 0)                                           # same-epoch restart clears the queue
    w.ex("again", "r", "admitted")                                    # and is not a duplicate of the cleared packet
    w.ex("begin6", "ok", True)
    w.ex("old-after-6", "r", "stale_epoch")
    w.ex("new-after-6", "r", "admitted")
    w.ex("misaligned", "reason", "misaligned")
    w.ex("bad-anchor", "reason", "bad_anchor")
    return w


def w08() -> W:
    w = W("W08-WINDOW-AND-INPUT", "music",
          "horizon window edge, malformed inputs, and the timeline tolerance boundary", ["window", "input"])
    w.begin()
    tol = CFG["tolerance_ns"]
    t0 = P(0) - 500_000_000
    w.packet(t0, 93, label="last-slot")
    w.packet(t0 + 1, 94, label="one-past")
    w.packet(t0 + 2, 94, pres=1, label="far-bad-timeline")                # position is checked before the timeline
    w.packet(t0 + 3, 1, frames=0, label="frames-0")
    w.add(["bad", t0 + 4, U, 1, 1, 256, P(1), 256, 1023], "short-payload")
    w.packet(t0 + 5, 1, frames=257, label="frames-257")
    w.packet(t0 + 6, 1, frame=300, label="misaligned-frame")
    w.packet(t0 + 7, 1, pres=P(1) + tol, label="tol-plus")
    w.packet(t0 + 8, 2, pres=P(2) + tol + 1, label="tol-plus-1")
    w.packet(t0 + 9, 3, pres=P(3) - tol - 1, label="tol-minus-1")
    w.packet(t0 + 10, 3, pres=P(3) - tol, label="tol-minus")
    w.packet(t0 + 11, 4, frames=100, label="partial-final")
    w.ex("last-slot", "r", "admitted")
    w.ex("one-past", "r", "too_far_ahead")
    w.ex("far-bad-timeline", "r", "too_far_ahead")
    w.ex("frames-0", "r", "bad_input")
    w.ex("short-payload", "r", "bad_input")
    w.ex("frames-257", "r", "bad_input")
    w.ex("misaligned-frame", "r", "bad_input")
    w.ex("tol-plus", "r", "admitted")
    w.ex("tol-plus-1", "r", "timeline_mismatch")
    w.ex("tol-minus-1", "r", "timeline_mismatch")
    w.ex("tol-minus", "r", "admitted")
    w.ex("partial-final", "r", "admitted")
    return w


def w09() -> W:
    w = W("W09-REPAIR", "music",
          "a repair is judged by the same cutoff as media: before it plays, at or after it is late, even before the DAC",
          ["repair", "boundary"])
    w.begin()
    w.repair(C(0) - 1, 0, 50, label="r0-before")
    w.decide_at_cutoff(0, label="d0")
    w.repair(C(1), 1, 51, label="r1-at")                             # block 1 has no media: the repair is late
    w.decide_at_cutoff(1, label="d1")
    w.packet(P(2) - 50_000_000, 2, label="m2")
    w.repair(P(2) - 40_000_000, 2, 52, label="r2-dup")
    w.decide_at_cutoff(2, label="d2")
    w.decide_at_cutoff(3, label="d3")
    w.packet(C(3) + 1, 3, label="m3-late")                           # block 3 is already decided (concealed)
    w.repair(C(3) + 2, 3, 53, label="r3-late")
    w.repair(C(3) + 3, 0, 54, label="r0-after-play")
    w.add(["stats"], "stats")
    w.ex("r0-before", "r", "admitted")
    w.ex("d0", "d.outcome", "real")
    w.ex("d0", "d.fnv", "%016x" % R.fnv1a64(R.synth_payload(50, 256)))
    w.ex("r1-at", "r", "late")
    w.ex("d1", "d.outcome", "concealed")
    w.ex("r2-dup", "r", "duplicate")
    w.ex("d2", "d.fnv", "%016x" % R.fnv1a64(R.synth_payload(2, 256)))
    w.ex("d3", "d.outcome", "concealed")
    w.ex("m3-late", "r", "late")
    w.ex("r3-late", "r", "late")
    w.ex("r0-after-play", "r", "duplicate")
    w.ex("stats", "stats.admitted_repair", 1)
    w.ex("stats", "stats.late_repair", 2)
    w.ex("stats", "stats.duplicate_repair", 2)
    w.ex("stats", "stats.late", 1)
    return w


def w09b() -> W:
    """A repair that arrives after the cutoff but BEFORE the presentation time is still late and still not played."""
    w = W("W09B-REPAIR-BEFORE-DAC", "music", "recovery after consume_by but before the DAC presentation is late",
          ["repair", "boundary"])
    w.begin()
    w.decide_at_cutoff(0, label="d0")                                 # nothing arrived: no history, muted
    w.repair(P(0) - 1_000_000, 0, 60, label="repair-before-dac")
    w.add(["stats"], "stats")
    assert P(0) - 1_000_000 > C(0)
    w.ex("d0", "d.outcome", "muted_nohistory")
    w.ex("repair-before-dac", "r", "late")
    w.ex("stats", "stats.late_repair", 1)
    w.ex("stats", "queued", 0)
    return w


def w10() -> W:
    w = W("W10-CLOCK", "music", "an unusable or regressing clock admits nothing, decides nothing and consumes no block",
          ["clock"])
    w.begin()
    w.packet(P(0) - 80_000_000, 0, ok=0, label="p-unusable", raw=True)
    w.decide(C(0), ok=0, label="d-unusable", raw=True)
    w.add(["stats"], "s0")
    w.packet(P(0) - 70_000_000, 0, label="p-ok", raw=True)
    w.packet(P(0) - 80_000_000, 1, label="p-regress", raw=True)        # earlier than the last accepted view
    w.decide(P(0) - 75_000_000, label="d-regress", raw=True)
    w.decide_at_cutoff(0, label="d0")
    w.add(["stats"], "s1")
    w.ex("p-unusable", "r", "clock_unusable")
    w.ex("d-unusable", "poll", "clock_unusable")
    w.ex("s0", "cursor", 0)
    w.ex("s0", "queued", 0)
    w.ex("s0", "stats.clock_unusable", 1)
    w.ex("s0", "stats.clock_unusable_polls", 1)
    w.ex("p-ok", "r", "admitted")
    w.ex("p-regress", "r", "clock_regression")
    w.ex("d-regress", "poll", "clock_regression")
    w.ex("d0", "d.outcome", "real")
    w.ex("s1", "stats.clock_regressions", 2)
    w.ex("s1", "cursor", 1)
    return w


def w11() -> W:
    w = W("W11-OVERDUE", "music", "deciding after the presentation time cannot play: dropped, muted, and the loop catches up",
          ["overdue"])
    w.begin()
    for b in range(3):
        w.packet(P(b) - 100_000_000, b)
    t = P(1) + 1_000_000
    for i in range(3):
        w.decide(t, label="d%d" % i)
    w.decide_at_cutoff(2, label="d2b")
    w.add(["stats"], "stats")
    w.ex("d0", "d.outcome", "muted_overdue")
    w.ex("d0", "d.late_by", t - C(0))
    w.ex("d1", "d.outcome", "muted_overdue")
    w.ex("d2", "poll", "pending")                                     # block 2's own cutoff is still ahead
    w.ex("d2b", "d.outcome", "real")                                  # and it still holds its packet
    w.ex("stats", "stats.decided_muted_overdue", 2)
    w.ex("stats", "stats.decided_real", 1)
    return w


def w11b() -> W:
    """The overdue boundary: decided one nanosecond before the presentation time plays, at it does not."""
    w = W("W11B-OVERDUE-BOUNDARY", "music",
          "a block decided at t = presentation - 1 still plays; decided at t = presentation it is overdue",
          ["overdue", "boundary"])
    w.begin()
    w.packet(P(0) - 100_000_000, 0)
    w.packet(P(1) - 100_000_000, 1)
    w.decide(P(0) - 1, label="before")
    w.decide(P(1), label="at")
    w.ex("before", "d.outcome", "real")
    w.ex("before", "d.late_by", P(0) - 1 - C(0))
    w.ex("at", "d.outcome", "muted_overdue")
    w.ex("at", "d.late_by", P(1) - C(1))
    return w


def w12() -> W:
    w = W("W12-LATENCY-UP", "music",
          "a coordinated +3 block latency change: every refusal paired with the accepted change, a mapping mismatch "
          "refused, the gap reported on the first block after it", ["latency"])
    w.begin()
    fe, eb = 2560, 10
    ft_fe = R.frames_to_ns(fe)
    delta = 3 * BNS
    new_anchor = ANCHOR + ft_fe + delta
    w.add(["change", 1, 1, fe + 128, new_anchor], "ch-misaligned")
    w.add(["change", 1, 1, 7 * 256, new_anchor], "ch-too-soon")                       # eb 7 < cursor 0 + notice 8
    w.add(["change", 1, 1, 8 * 256, ANCHOR + R.frames_to_ns(8 * 256)], "ch-no-change")
    w.add(["change", 1, 1, 95 * 256, ANCHOR + R.frames_to_ns(95 * 256) + BNS], "ch-too-far")
    w.add(["change", 2, 1, fe, new_anchor], "ch-future-epoch")
    w.add(["change", 1, 1, fe, new_anchor], "ch-ok")
    w.add(["change", 1, 1, 12 * 256, ANCHOR + R.frames_to_ns(12 * 256) + BNS], "ch-replay")
    w.add(["change", 1, 2, 12 * 256, ANCHOR + R.frames_to_ns(12 * 256) + BNS], "ch-pending")
    new_origin = new_anchor - ft_fe
    for b in range(0, 14):
        origin = new_origin if b >= eb else ANCHOR
        w.packet(P(b, origin) - 100_000_000, b, origin=origin, label="p%d" % b)
        if b == eb:
            w.packet(P(b, ANCHOR) - 99_000_000, b, origin=ANCHOR, label="old-mapping-on-new-frame")
        w.decide(C(b, U, origin), label="d%d" % b)
    w.add(["change", 1, 3, 40 * 256, P(40, new_origin) + BNS], "ch-after-commit")
    w.add(["stats"], "stats")
    w.ex("ch-misaligned", "reason", "misaligned")
    w.ex("ch-too-soon", "reason", "too_soon")
    w.ex("ch-no-change", "reason", "no_change")
    w.ex("ch-too-far", "reason", "too_far_ahead")
    w.ex("ch-future-epoch", "reason", "future_epoch")
    w.ex("ch-ok", "ok", True)
    w.ex("ch-ok", "delta_ns", delta)
    w.ex("ch-replay", "reason", "replayed_change")
    w.ex("ch-pending", "reason", "change_pending")
    w.ex("old-mapping-on-new-frame", "r", "timeline_mismatch")
    w.ex("p10", "r", "admitted")
    w.ex("d9", "d.gap_before", 0)
    w.ex("d10", "d.outcome", "real")
    w.ex("d10", "d.gap_before", delta)
    w.ex("d10", "d.pres", P(10, new_origin))
    w.ex("d11", "d.gap_before", 0)
    w.ex("ch-after-commit", "ok", True)                                                # a second change is fine now
    w.ex("stats", "net_shift_ns", delta)
    w.ex("stats", "stats.decided_real", 14)
    return w


def w13() -> W:
    w = W("W13-LATENCY-DOWN", "music",
          "a coordinated latency decrease of 2.5 blocks skips three blocks so the sample clock never rewinds",
          ["latency"])
    w.begin()
    fe, eb = 2560, 10
    delta = -(5 * BNS // 2)                                            # -13_333_332
    new_anchor = ANCHOR + R.frames_to_ns(fe) + delta
    new_origin = new_anchor - R.frames_to_ns(fe)
    w.add(["change", 1, 1, fe, new_anchor], "ch")
    for b in range(0, 18):
        origin = new_origin if b >= eb else ANCHOR
        w.packet(P(b, origin) - 100_000_000, b, origin=origin)
    # The new mapping presents block 10 earlier than block 9's old cutoff, so per-block decision times would run
    # backwards. The cursor sequence is: 0..9 at their old cutoffs, three immediate skips, then 13.. at the new ones.
    for b in range(0, eb):
        w.decide(C(b), label="d%d" % b)
    for b in (10, 11, 12):
        w.decide(C(eb - 1) + 1, label="d%d" % b)
    for b in range(13, 18):
        w.decide(C(b, U, new_origin), label="d%d" % b)
    w.add(["stats"], "stats")
    w.ex("ch", "ok", True)
    w.ex("ch", "delta_ns", delta)
    w.ex("d9", "d.outcome", "real")
    for b in (10, 11, 12):
        w.ex("d%d" % b, "d.outcome", "skipped")
    w.ex("d13", "d.outcome", "real")
    w.ex("d13", "d.gap_before", delta + R.frames_to_ns(fe + 3 * 256) - R.frames_to_ns(fe))
    w.ex("stats", "stats.decided_skipped", 3)
    w.ex("stats", "net_shift_ns", delta)
    return w


def w13b() -> W:
    """A decrease equal to exactly three blocks of frames skips three blocks, not four, and leaves no gap."""
    w = W("W13B-LATENCY-DOWN-EXACT", "music",
          "when the shift equals three blocks' worth of time exactly, three blocks are skipped and the next starts with no gap",
          ["latency", "boundary"])
    w.begin()
    fe, eb = 2560, 10
    delta = -(R.frames_to_ns(fe + 3 * 256) - R.frames_to_ns(fe))          # -16_000_000
    new_anchor = ANCHOR + R.frames_to_ns(fe) + delta
    new_origin = new_anchor - R.frames_to_ns(fe)
    w.add(["change", 1, 1, fe, new_anchor], "ch")
    for b in range(0, 18):
        origin = new_origin if b >= eb else ANCHOR
        w.packet(P(b, origin) - 100_000_000, b, origin=origin)
    for b in range(0, eb):
        w.decide(C(b), label="d%d" % b)
    for b in (10, 11, 12):
        w.decide(C(eb - 1) + 1, label="d%d" % b)
    for b in range(13, 18):
        w.decide(C(b, U, new_origin), label="d%d" % b)
    w.add(["stats"], "stats")
    assert delta == -16_000_000
    w.ex("ch", "delta_ns", delta)
    for b in (10, 11, 12):
        w.ex("d%d" % b, "d.outcome", "skipped")
    w.ex("d13", "d.outcome", "real")
    w.ex("d13", "d.gap_before", 0)
    w.ex("d13", "d.pres", P(13, new_origin))
    w.ex("stats", "stats.decided_skipped", 3)
    w.ex("stats", "net_shift_ns", delta)
    return w


def w12b(over: int) -> W:
    w = W("W12%s-STEP-LIMIT" % ("C" if over else "B"), "music",
          "the largest single step is accepted at exactly max_step blocks and refused one nanosecond over",
          ["latency", "boundary"])
    w.begin()
    fe = 2560
    limit = R.frames_to_ns(38 * 256)
    w.add(["change", 1, 1, fe, ANCHOR + R.frames_to_ns(fe) + limit + over], "ch")
    w.ex("ch", "ok", not over)
    w.ex("ch", "reason", "transition_too_large" if over else "accepted")
    return w


def w12d() -> W:
    """Realtime: the net latency shift is capped (9 blocks), so repeated increases cannot grow without bound."""
    w = W("W12D-NET-CAP", "realtime", "two +4 block increases, then +4 would pass the 9-block net cap; +1 fits",
          ["latency", "cap"])
    w.begin()
    state = {"cursor": 0}

    def run_to(eb: int, o_before: int, o_after: int) -> None:
        while state["cursor"] <= eb + 1:
            c = state["cursor"]
            o = o_after if c >= eb else o_before
            w.packet(P(c, o) - 20_000_000, c, origin=o)
            w.decide(C(c, U, o), label="d%d" % c)
            state["cursor"] += 1

    o1 = ANCHOR + 4 * BNS
    w.add(["change", 1, 1, 3 * 256, ANCHOR + R.frames_to_ns(3 * 256) + 4 * BNS], "c1")
    run_to(3, ANCHOR, o1)
    o2 = o1 + 4 * BNS
    w.add(["change", 1, 2, 9 * 256, o1 + R.frames_to_ns(9 * 256) + 4 * BNS], "c2")
    run_to(9, o1, o2)
    w.add(["change", 1, 3, 15 * 256, o2 + R.frames_to_ns(15 * 256) + 4 * BNS], "c3-over-cap")       # 8 + 4 = 12 > 9
    w.add(["change", 1, 3, 15 * 256, o2 + R.frames_to_ns(15 * 256) + 1 * BNS], "c3-fits")           # 8 + 1 = 9
    w.add(["stats"], "s")
    w.ex("c1", "ok", True)
    w.ex("c2", "ok", True)
    w.ex("c3-over-cap", "reason", "latency_cap_exceeded")
    w.ex("c3-fits", "ok", True)
    w.ex("s", "net_shift_ns", 8 * BNS)
    return w


def w14() -> W:
    w = W("W14-BACKPRESSURE", "music",
          "positive downstream cost: a block is delivered only if the ring takes it by its submission deadline",
          ["backpressure"])
    w.begin()
    for b in range(3):
        w.packet(P(b) - 100_000_000, b)
    w.decide_at_cutoff(0, label="d0")
    dl = P(0) - CFG["lead_ns"]
    w.add(["deliver", dl], "at-deadline")
    w.decide_at_cutoff(1, label="d1")
    w.add(["deliver", P(1) - CFG["lead_ns"] + 1], "one-late")
    w.decide_at_cutoff(2, label="d2")
    w.add(["deliver", None], "never")
    w.decide_at_cutoff(3, label="d3")                               # block 3 never arrived: concealed, and delivered
    w.add(["deliver", C(3) + 1], "concealed-ok")
    w.add(["stats"], "stats")
    w.ex("d0", "d.submit_deadline", dl)
    w.ex("at-deadline", "delivery", "delivered")
    w.ex("one-late", "delivery", "abandoned")
    w.ex("never", "delivery", "abandoned")
    w.ex("d3", "d.outcome", "concealed")
    w.ex("concealed-ok", "delivery", "delivered")
    w.ex("stats", "stats.delivered", 2)
    w.ex("stats", "stats.abandoned", 2)
    w.ex("stats", "stats.decided_real", 3)                         # abandoning a delivery does not undo a decision
    return w


def w15() -> W:
    w = W("W15-ADVICE", "music", "latency advice from the arrival margins: filling, isolated late, repeated late",
          ["advice"])
    w.begin()
    for b in range(10):
        w.packet(P(b) - 60_000_000, b)
    w.add(["advice"], "few")
    for b in range(10, 24):
        w.packet(P(b) - 60_000_000, b)
    w.packet(C(24) + 1_000_000, 24, label="late1")
    w.add(["advice"], "one-late")
    w.packet(C(25) + 9_000_000, 25, label="late2")                       # 9 ms past: needs two blocks
    w.add(["advice"], "two-late")
    w.ex("few", "action", "hold")
    w.ex("few", "reason", "insufficient_data")
    w.ex("late1", "r", "late")
    w.ex("one-late", "reason", "isolated_late")
    w.ex("two-late", "action", "increase")
    w.ex("two-late", "blocks", 2)
    w.ex("two-late", "reason", "late_arrivals")
    return w


def w15b() -> W:
    """Arrivals 40 ms ahead, decisions in step: 64 margins of 36.3 ms leave 20.3 ms beyond the 3-block keep margin."""
    w = W("W15B-ADVICE-QUIET", "realtime",
          "a full quiet window with spare slack beyond the keep margin suggests a decrease of three blocks", ["advice"])
    w.begin()
    for b in range(70):
        w.packet(P(b) - 40_000_000, b)
        w.decide_at_cutoff(b)
    w.add(["advice"], "quiet")
    w.ex("quiet", "action", "decrease")
    w.ex("quiet", "blocks", 3)
    w.ex("quiet", "reason", "spare_slack")
    return w


def seeded(wid: str, profile: str, seed: int, nblocks: int, jitter_ns: int, early_ns: int, loss_pm: int,
           burst_at: int, burst_len: int, dup_pm: int, swap_pm: int, slow_pm: int) -> W:
    """Seeded independent loss, jitter, local reorder, duplicates, slow packets and one burst; calls in time order."""
    rng = Rng(seed)
    w = W(wid, profile, "seeded schedule: %d blocks, %d per mille loss, up to %d ns jitter, one %d-block burst, "
          "%d per mille duplicates, %d per mille swaps, %d per mille slow" % (
              nblocks, loss_pm, jitter_ns, burst_len, dup_pm, swap_pm, slow_pm),
          ["seeded", "loss", "jitter", "reorder", "duplicate"])
    w.begin()
    for b in range(nblocks):
        w.decide_at_cutoff(b)
        if burst_at <= b < burst_at + burst_len or rng.below(1000) < loss_pm:
            continue
        arrive = P(b) - early_ns + rng.below(jitter_ns + 1)
        if rng.below(1000) < swap_pm:
            arrive += 6_000_000                                          # arrives behind its successor
        if rng.below(1000) < slow_pm:
            arrive += early_ns - 20_000_000 + rng.below(30_000_000 + 1)  # may cross its cutoff
        w.packet(max(arrive, 0), b)
        if rng.below(1000) < dup_pm:
            w.packet(arrive + 1 + rng.below(3_000_000), b)
    w.add(["stats"], "stats")
    return w


def worlds() -> List[W]:
    return [
        w01(), w02(), w03(), w04(),
        burst("music", "W05-BURST-MUSIC", 8), burst("realtime", "W06-BURST-REALTIME", 3),
        w07(), w08(), w09(), w09b(), w10(), w11(), w11b(), w12(), w12b(0), w12b(1), w12d(), w13(), w13b(), w14(), w15(), w15b(),
        seeded("W16-SEEDED-MUSIC", "music", 0x4E30_4D01, 700, 50_000_000, 400_000_000, 10, 300, 19, 30, 30, 30),
        seeded("W17-SEEDED-REALTIME", "realtime", 0x4E30_5254, 700, 10_000_000, 35_000_000, 10, 300, 19, 30, 30, 30),
    ]


# -- tables --------------------------------------------------------------------------------------------------------


def tables() -> Dict[str, Any]:
    ft = [[f, R.frames_to_ns(f)] for f in (0, 1, 3, 48, 256, 512, 2_560, 48_000, 96_000, 12_345_678)]
    cb = [[p, w_, l, u, R.consume_by(p, w_, l, u)] for p, w_, l, u in (
        (1_000_000_000, 1_500_000, 2_000_000, 200_000), (1_000_000_000, 1, 1, 0),
        (7_000_000, 1_500_000, 2_000_000, 3_500_000), (7_000_000, 1_500_000, 2_000_000, 3_500_001),
        (0, 1, 1, 0), (1 << 62, 1_500_000, 2_000_000, 2_000_000))]
    conceal = []
    for seed in (1, 2, 3):
        for run in (1, 4, 8):
            blk = R.conceal_block(R.synth_payload(seed, 256), run)
            conceal.append(dict(seed=seed, run=run, frames=256, fnv="%016x" % R.fnv1a64(blk)))
    short = R.conceal_block(R.synth_payload(5, 100), 2)
    conceal.append(dict(seed=5, run=2, frames=100, fnv="%016x" % R.fnv1a64(short)))
    configs = [dict(cfg=c, bad=R.validate_config(R.PROFILES["music"], c)) for c in (
        dict(work_ns=1, lead_ns=1, tolerance_ns=0), dict(work_ns=0, lead_ns=1, tolerance_ns=0),
        dict(work_ns=1, lead_ns=0, tolerance_ns=0), dict(work_ns=1, lead_ns=1, tolerance_ns=BNS // 2 - 1),
        dict(work_ns=1, lead_ns=1, tolerance_ns=BNS // 2), dict(work_ns=1, lead_ns=1, tolerance_ns=-1))]
    adv = []
    for prof, margins, net in (
            ("music", [10_000_000] * 15, 0), ("music", [10_000_000] * 16, 0), ("music", [10_000_000] * 15 + [0], 0),
            ("music", [10_000_000] * 14 + [0, -1], 0), ("music", [10_000_000] * 14 + [0, -5_333_332], 0),
            ("music", [10_000_000] * 14 + [0, -5_333_333], 0), ("music", [10_000_000] * 14 + [0, -300_000_000], 0),
            ("realtime", [10_000_000] * 14 + [0, -300_000_000], 0),
            ("realtime", [10_000_000] * 14 + [0, -5_333_333], 8 * BNS),
            ("realtime", [10_000_000] * 14 + [0, -5_333_333], R.frames_to_ns(5 * 256)),
            ("music", [30_000_000] * 64, 0), ("music", [20_000_000] * 64, 0), ("music", [16_000_000] * 64, 0),
            ("music", [16_000_000] * 63, 0), ("music", [200_000_000] * 64, 0), ("realtime", [200_000_000] * 64, 0),
            ("music", [200_000_000] * 64, -94 * BNS)):
        adv.append(dict(profile=prof, margins=margins, net_shift_ns=net, out=R.advice(margins, net, R.PROFILES[prof])))
    return dict(frames_to_ns=ft, consume_by=cb, conceal_gains=list(R.CONCEAL_GAIN_Q15), conceal_blocks=conceal,
                configs=configs, advice=adv)


def digest(results: List[Any]) -> str:
    return hashlib.sha256(json.dumps(results, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _op_dict(o: list) -> Dict[str, Any]:
    """Compact array op -> the dict form ``reference.run_world`` takes."""
    k = o[0]
    if k == "begin":
        return dict(op=k, epoch=o[1], anchor_frame=o[2], anchor_ns=o[3])
    if k == "packet":
        return dict(op=k, t=o[1], u=o[2], ok=bool(o[3]), epoch=o[4], frame=o[5], pres=o[6], frames=o[7], seed=o[8])
    if k == "repair":
        return dict(op=k, t=o[1], u=o[2], ok=bool(o[3]), epoch=o[4], frame=o[5], frames=o[6], seed=o[7])
    if k == "bad":
        return dict(op="bad_packet", t=o[1], u=o[2], ok=bool(o[3]), epoch=o[4], frame=o[5], pres=o[6], frames=o[7],
                    payload_len=o[8])
    if k == "decide":
        return dict(op=k, t=o[1], u=o[2], ok=bool(o[3]))
    if k == "change":
        return dict(op=k, change=dict(epoch=o[1], change_id=o[2], effective_frame=o[3], new_anchor_ns=o[4]))
    if k == "deliver":
        return dict(op=k, accepted_at=o[1])
    return dict(op=k)


def world_results(doc: dict) -> List[Any]:
    return R.run_world(dict(profile=doc["profile"], cfg=doc["cfg"], ops=[_op_dict(o) for o in doc["ops"]]))


def log_digest(lines: List[str]) -> str:
    """sha256 of the lines, each followed by a newline: what a JSONL file of them would hash to."""
    return hashlib.sha256(("\n".join(lines) + "\n").encode("ascii")).hexdigest()


def scenario_outcome(doc: dict, plan: dict) -> Dict[str, Any]:
    """What the reference says a world, a ring and a scripted sink end up with."""
    _, ring = R.run_world_sinked(dict(id=doc["id"], profile=doc["profile"], cfg=doc["cfg"],
                                      ops=[_op_dict(o) for o in doc["ops"]]), LOG, plan)
    rest = list(ring.queue)
    return dict(stats=ring.stats(), complete=ring.critical_lost == 0,
                delivered=dict(count=len(ring.delivered), digest=log_digest(ring.delivered)),
                rest=dict(count=len(rest), digest=log_digest(rest)))


def world_logged(doc: dict, log: dict) -> Tuple[List[Any], "R.LogWriter"]:
    """The results of a world and the log lines the model says it writes (``log``: see reference.run_world_logged)."""
    return R.run_world_logged(dict(id=doc["id"], profile=doc["profile"], cfg=doc["cfg"],
                                   ops=[_op_dict(o) for o in doc["ops"]]), log)


def build() -> Dict[str, Any]:
    docs = []
    for w in worlds():
        doc = w.doc()
        results = world_results(doc)
        check_expectations(doc, results)
        doc["digest"] = digest(results)
        lines = world_logged(doc, LOG)[1].lines
        doc["log"] = dict(count=len(lines), digest=log_digest(lines))
        docs.append(doc)
    by_id = {d["id"]: d for d in docs}
    scenarios = []
    for sid, wid, plan, expect in SCENARIOS:
        scenarios.append(dict(id=sid, world=wid, plan=plan, expect=expect, **scenario_outcome(by_id[wid], plan)))
        if expect is not None and any(scenarios[-1]["stats"][k] != v for k, v in expect.items()):
            raise SystemExit("%s: the reference disagrees with the hand-derived counts %r" % (sid, expect))
    return dict(version=VERSION, profile_version=R.PROFILE_VERSION, profiles=R.PROFILES, defaults=CFG,
                log=dict(LOG, member_id=R.pseudonym(bytes.fromhex(LOG["key_hex"]), LOG["member"]),
                         group_id=R.pseudonym(bytes.fromhex(LOG["key_hex"]), LOG["group"])),
                keeps_up=KEEPS_UP, tables=tables(), worlds=docs, log_scenarios=scenarios)
