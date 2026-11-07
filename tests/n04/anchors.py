"""Hand-derived anchors for the N04 reference. Each value below was worked out on paper from docs/contracts/n04.md
with plain arithmetic (written out in the comments), NOT by calling the reference's own functions, so
``check()`` compares the reference with an independent route. The Rust unit tests assert the same literals.
"""
from __future__ import annotations

import hashlib
from typing import List

import reference as R

BLOCK = 5_333_333                    # floor(256 * 62500 / 3) = floor(5333333.33)
CAP_MUSIC = 501_333_333              # floor(94 * 256 * 62500 / 3) = floor(24064 * 20833.33...)
CAP_REALTIME = 48_000_000            # 9 * 256 = 2304 frames * 62500 / 3 = 48_000_000 exactly

FRAMES_TO_NS = [(0, 0), (3, 62_500), (256, 5_333_333), (48_000, 1_000_000_000), (96_000, 2_000_000_000),
                (94 * 256, CAP_MUSIC), (9 * 256, CAP_REALTIME)]

# (presentation, work, lead, uncertainty) -> cutoff. 1e9 - (1.5e6 + 2e6 + 0.2e6) = 996_300_000; a guard equal to or
# above the presentation time clamps to 0; one nanosecond less leaves 1.
CONSUME_BY = [((1_000_000_000, 1_500_000, 2_000_000, 200_000), 996_300_000),
              ((7_000_000, 1_500_000, 2_000_000, 3_500_000), 0),
              ((7_000_000, 1_500_000, 2_000_000, 3_500_001), 0),
              ((7_000_000, 1_500_000, 2_000_000, 3_499_999), 1),
              ((0, 1, 1, 0), 0)]

# floor((s * gain + 16384) / 32768) by integer division. +16384 rounds half up: 16384 * 1889 = 30_949_376 =
# 944.5 * 32768, so +16384 -> 945 while -16384 -> -944.
SAMPLES = [10_000, -10_000, 32_767, -32_768, 0, 1, -1, 2, -2, 16_384, -16_384]
CONCEAL = {1: [7_000, -7_000, 22_937, -22_938, 0, 1, -1, 1, -1, 11_469, -11_469],
           8: [576, -576, 1_889, -1_889, 0, 0, 0, 0, 0, 945, -944]}

# Memory admission (contract section 1). A slot is the 1024-byte payload, a u16 frame count (2) and a use flag (1) = 1027 bytes, rounded up to the
# count's 2-byte alignment = 1028. A queue is `horizon` slots, never fewer than one: 94 * 1028 = 94_000 + 94 * 28 = 94_000 + 2_632 = 96_632;
# 9 * 1028 = 9_000 + 252 = 9_252; a horizon of 0 or 1 is the one slot, 1_028.
SLOT_BYTES = 1028
CAPACITY_QUEUE = [(0, 1_028), (1, 1_028), (9, 9_252), (94, 96_632)]
# The engine's own struct must at least hold what the contract says it holds: the 128-entry history (a byte each), the 64 arrival margins
# (an i64 each) and the last real block: 128 + 64 * 8 + 1024 = 128 + 512 + 1024 = 1_664. Only the compiler knows the exact size.
INLINE_FLOOR = 1_664

# (profile, margins, net_shift_ns) -> (action, blocks, reason)
M10 = [10_000_000]
ADVICE = [
    (("music", M10 * 15, 0), ("hold", 0, "insufficient_data")),
    (("music", M10 * 16, 0), ("hold", 0, "window_filling")),
    (("music", M10 * 15 + [0], 0), ("hold", 0, "isolated_late")),
    # two late: need = ceil((1 - worst) / 5_333_333). worst -1 -> ceil(2 / 5333333) = 1
    (("music", M10 * 14 + [0, -1], 0), ("increase", 1, "late_arrivals")),
    # worst -5_333_332 -> 5_333_333 / 5_333_333 = exactly 1; worst -5_333_333 -> 5_333_334 -> 2
    (("music", M10 * 14 + [0, -5_333_332], 0), ("increase", 1, "late_arrivals")),
    (("music", M10 * 14 + [0, -5_333_333], 0), ("increase", 2, "late_arrivals")),
    # worst -300_000_000 -> ceil(300_000_001 / 5_333_333) = 57, limited to max_step 38 (music) / 4 (realtime)
    (("music", M10 * 14 + [0, -300_000_000], 0), ("increase", 38, "late_arrivals")),
    (("realtime", M10 * 14 + [0, -300_000_000], 0), ("increase", 4, "late_arrivals")),
    # realtime cap 48_000_000: net 8 blocks (42_666_664) + 2 blocks (10_666_666) = 53_333_330 > cap -> unhealthy;
    # net 5 blocks (26_666_666) + 10_666_666 = 37_333_332 <= cap -> increase 2
    (("realtime", M10 * 14 + [0, -5_333_333], 8 * BLOCK), ("unhealthy", 0, "latency_cap")),
    (("realtime", M10 * 14 + [0, -5_333_333], 26_666_666), ("increase", 2, "late_arrivals")),
    # 64 quiet margins: spare = worst - 3 * 5_333_333 (= 15_999_999). 30_000_000 -> 14_000_001 // 5_333_333 = 2
    (("music", [30_000_000] * 64, 0), ("decrease", 2, "spare_slack")),
    (("music", [20_000_000] * 64, 0), ("hold", 0, "stable")),             # spare 4_000_001: under one block
    (("music", [16_000_000] * 64, 0), ("hold", 0, "stable")),             # spare exactly 1: under one block
    (("music", [16_000_000] * 63, 0), ("hold", 0, "window_filling")),     # one short of a full window
    # 200_000_000 -> spare 184_000_001 // 5_333_333 = 34 (music, under max_step 38) / limited to 4 (realtime)
    (("music", [200_000_000] * 64, 0), ("decrease", 34, "spare_slack")),
    (("realtime", [200_000_000] * 64, 0), ("decrease", 4, "spare_slack")),
    # net already -94 blocks (-501_333_302): another 34 blocks (181_333_333) down would be 682_666_635 > cap
    (("music", [200_000_000] * 64, -94 * BLOCK), ("hold", 0, "stable")),
]


# -- ffw.log.v1 lines, assembled by hand from the contract. The pseudonyms come from hashlib directly:
# sha256("ffw.pseudonym.v1" || key || len(id) as 8 bytes big endian || id), first 16 hex, prefixed "p-". Key = 32 x 0x07.
LOG_KEY = bytes([7]) * 32


def _p(ident: str) -> str:
    raw = ident.encode()
    return "p-" + hashlib.sha256(b"ffw.pseudonym.v1" + LOG_KEY + len(raw).to_bytes(8, "big") + raw).hexdigest()[:16]


M, G = _p("member-a"), _p("group-a")
_HEAD = '{"schema_version":"ffw.log.v1","timestamp_mono_ns":%d,"run_id":"n04-log","case_id":"anchor","correlation_id":"%s#%d",'
_IDS = '"member_id":"%s","group_id":"%s",' % (M, G)

# (writer fault label, call arguments, expected line). Argument order: candidate_ts, n, epoch, revision, queue,
# latency_us, kind, message, cause. The third entry asks for timestamp 3 after timestamp 5: it must come out as 5.
LOG_LINES = [
    (None, (0, 0, 1, 0, 0, 0, "n04.stream.started", "epoch=1 anchor_frame=0 anchor_ns=2000000000", None),
     _HEAD % (0, M, 0) + _IDS + '"source_epoch":1,"state_revision":0,"event_kind":"n04.stream.started",'
     '"message":"epoch=1 anchor_frame=0 anchor_ns=2000000000","queue_depth":0,"latency_us":0}'),
    (None, (5, 3, 1, 4, 2, 7, "n04.decision.concealed",
            "block=3 frames=256 presentation_ns=2016000000 gap_before_ns=0 submit_deadline_ns=2014000000 late_by_ns=7000 run=2",
            "no_block_by_cutoff"),
     _HEAD % (5, M, 3) + _IDS + '"source_epoch":1,"state_revision":4,"event_kind":"n04.decision.concealed",'
     '"message":"block=3 frames=256 presentation_ns=2016000000 gap_before_ns=0 submit_deadline_ns=2014000000 late_by_ns=7000 run=2",'
     '"queue_depth":2,"latency_us":7,"cause":"no_block_by_cutoff"}'),
    (None, (3, 4, 1, 5, 1, 0, "n04.refusal.duplicate", "source=media frame=1024 frames=256 packet_epoch=1", None),
     _HEAD % (5, M, 4) + _IDS + '"source_epoch":1,"state_revision":5,"event_kind":"n04.refusal.duplicate",'
     '"message":"source=media frame=1024 frames=256 packet_epoch=1","queue_depth":1,"latency_us":0}'),
    ("sink-stalled", (9, 6, 2, 8, 0, 0, "n04.decision.muted_gap", "block=6 frames=0 presentation_ns=1 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0",
                      "gap_longer_than_conceal_maximum"),
     _HEAD % (9, M, 6) + _IDS + '"source_epoch":2,"state_revision":8,"event_kind":"n04.decision.muted_gap",'
     '"message":"block=6 frames=0 presentation_ns=1 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0",'
     '"queue_depth":0,"latency_us":0,"fault":"sink-stalled","cause":"gap_longer_than_conceal_maximum"}'),
]


# The same script and lines as playout/log/tests.rs (golden test), plus a late packet whose lateness is 5 700 000 ns.
# Config: work 1.5 ms, lead 2 ms, tolerance 100 us, uncertainty 200 us. Block 0 is presented at 2e9; its cutoff is
# 2e9 - (1.5e6 + 2e6 + 0.2e6) = 1_996_300_000; block 1 at 2_005_333_333, cutoff 2_001_633_333. A packet for block 0 read at
# 2_002_000_000 is 5_700_000 ns after its cutoff: latency_us 5700.
_CFG = dict(work_ns=1_500_000, lead_ns=2_000_000, tolerance_ns=100_000)
_GOLD_HEAD = '{"schema_version":"ffw.log.v1","timestamp_mono_ns":%d,"run_id":"n04-log","case_id":"unit","correlation_id":"%s#%d",'
_GOLD_TAIL = '"queue_depth":%d,"latency_us":%d%s}'


def _gold(ts, n, epoch, revision, kind, message, queue, latency, extra=""):
    return (_GOLD_HEAD % (ts, M, n) + _IDS + '"source_epoch":%d,"state_revision":%d,"event_kind":"%s","message":"%s",' % (
        epoch, revision, kind, message) + _GOLD_TAIL % (queue, latency, extra))


_OPS_A = [
    dict(op="begin", epoch=1, anchor_frame=0, anchor_ns=2_000_000_000),
    dict(op="packet", t=1_000_000_000, u=200_000, ok=True, epoch=1, frame=256, pres=2_005_333_333, frames=256, seed=0),
    dict(op="packet", t=1_000_000_500, u=200_000, ok=True, epoch=1, frame=256, pres=2_005_333_333, frames=256, seed=0),
    dict(op="decide", t=1_996_300_000, u=200_000, ok=True),
    dict(op="decide", t=2_001_633_333, u=200_000, ok=True),
    dict(op="packet", t=2_002_000_000, u=200_000, ok=True, epoch=1, frame=0, pres=2_000_000_000, frames=256, seed=0),
]
_LINES_A = [
    _gold(0, 0, 1, 0, "n04.stream.started", "epoch=1 anchor_frame=0 anchor_ns=2000000000", 0, 0),
    _gold(1_000_000_500, 1, 1, 0, "n04.refusal.duplicate", "source=media frame=256 frames=256 packet_epoch=1", 1, 0),
    _gold(1_996_300_000, 0, 1, 1, "n04.decision.muted_nohistory",
          "block=0 frames=0 presentation_ns=2000000000 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0", 1, 0,
          ',"cause":"nothing_played_yet"'),
    _gold(2_001_633_333, 1, 1, 2, "n04.decision.real",
          "block=1 frames=256 presentation_ns=2005333333 gap_before_ns=0 submit_deadline_ns=2003333333 late_by_ns=0", 0, 0),
    _gold(2_002_000_000, 0, 1, 2, "n04.refusal.late", "source=media frame=0 frames=256 packet_epoch=1", 0, 5700),
]
# A second script: a refused restart, an unusable clock, an accepted and a replayed change, two abandoned deliveries.
# begin(5) binds; begin(4) is stale: epoch stays 5, the timestamp is the previous record's (0). The unusable clock read at
# 1000 ns is a poll refusal at cursor 0. The change moves block 8 (frame 2048, 8 blocks of notice for music) one block
# (5_333_333 ns) later: old presentation 2e9 + 42_666_666 (floor(2048 * 62500 / 3)); new anchor 2_047_999_999. Replaying
# change_id 1 is refused. A block due by 1_000_000 ns taken at 3_500_000 is abandoned, 2500 us late; one never taken says none.
_OPS_B = [
    dict(op="begin", epoch=5, anchor_frame=0, anchor_ns=2_000_000_000),
    dict(op="begin", epoch=4, anchor_frame=0, anchor_ns=2_000_000_000),
    dict(op="decide", t=1000, u=200_000, ok=False),
    dict(op="change", change=dict(epoch=5, change_id=1, effective_frame=2048, new_anchor_ns=2_047_999_999)),
    dict(op="change", change=dict(epoch=5, change_id=1, effective_frame=2048, new_anchor_ns=2_047_999_999)),
    dict(op="deliver", submit_deadline=1_000_000, accepted_at=3_500_000),
    dict(op="deliver", submit_deadline=1_000_000, accepted_at=None),
]
_LINES_B = [
    _gold(0, 0, 5, 0, "n04.stream.started", "epoch=5 anchor_frame=0 anchor_ns=2000000000", 0, 0),
    _gold(0, 0, 5, 0, "n04.stream.refused", "epoch=4 anchor_frame=0 anchor_ns=2000000000", 0, 0, ',"cause":"stale_epoch"'),
    _gold(1000, 0, 5, 0, "n04.poll.clock_unusable", "cursor=0", 0, 0),
    _gold(1000, 8, 5, 0, "n04.change.accepted", "change_id=1 effective_frame=2048 delta_ns=5333333", 0, 0),
    _gold(1000, 8, 5, 0, "n04.change.refused", "change_id=1 effective_frame=2048", 0, 0, ',"cause":"replayed_change"'),
    _gold(3_500_000, 0, 5, 0, "n04.delivery.abandoned", "submit_deadline_ns=1000000 accepted_at_ns=3500000", 0, 2500),
    _gold(3_500_000, 0, 5, 0, "n04.delivery.abandoned", "submit_deadline_ns=1000000 accepted_at_ns=none", 0, 0),
]


# Script C: a decision taken late, a poll after it (so the cursor is 1), a repair that duplicates an admitted packet, and a
# coordinated decrease of one block. Block 0 (pres 2e9, cutoff 1_996_300_000) is decided at 1_997_534_567: 1_234_567 ns late,
# latency_us 1234; its submit deadline is pres - lead = 1_998_000_000. The unusable clock read at 1_998_000_000 is a poll at
# cursor 1. Music needs 8 blocks of notice, so with the cursor at 1 the earliest change is block 9 (frame 2304): old
# presentation 2e9 + 48_000_000 = 2_048_000_000, new anchor 2_042_666_667, delta -5_333_333.
_OPS_C = [
    dict(op="begin", epoch=1, anchor_frame=0, anchor_ns=2_000_000_000),
    dict(op="packet", t=1_000_000_000, u=200_000, ok=True, epoch=1, frame=0, pres=2_000_000_000, frames=256, seed=0),
    dict(op="repair", t=1_000_000_100, u=200_000, ok=True, epoch=1, frame=0, frames=256, seed=0),
    dict(op="decide", t=1_997_534_567, u=200_000, ok=True),
    dict(op="decide", t=1_998_000_000, u=200_000, ok=False),
    dict(op="change", change=dict(epoch=1, change_id=1, effective_frame=2304, new_anchor_ns=2_042_666_667)),
]
_LINES_C = [
    _gold(0, 0, 1, 0, "n04.stream.started", "epoch=1 anchor_frame=0 anchor_ns=2000000000", 0, 0),
    _gold(1_000_000_100, 0, 1, 0, "n04.refusal.duplicate", "source=repair frame=0 frames=256 packet_epoch=1", 1, 0),
    _gold(1_997_534_567, 0, 1, 1, "n04.decision.real",
          "block=0 frames=256 presentation_ns=2000000000 gap_before_ns=0 submit_deadline_ns=1998000000 late_by_ns=1234567", 0, 1234),
    _gold(1_998_000_000, 1, 1, 1, "n04.poll.clock_unusable", "cursor=1", 0, 0),
    _gold(1_998_000_000, 9, 1, 1, "n04.change.accepted", "change_id=1 effective_frame=2304 delta_ns=-5333333", 0, 0),
]
# Script D (realtime: 2 blocks of notice): a decrease of one block at frame 512 (block 2). Old presentation of frame 512
# 2e9 + 10_666_666; new anchor 2_005_333_333, delta -5_333_333; new origin 1_994_666_667. new_at(1) = 1_994_666_667 +
# floor(768 * 62500 / 3) = 2_010_666_667, not below the old end 2_010_666_666, so one block is skipped (block 2). Blocks 0 and 1
# (cutoffs 1_996_300_000 and 2_001_633_333) have no history; the third decide commits the change and skips block 2, which
# is presented at 2_005_333_333 under the new timeline.
_OPS_D = [
    dict(op="begin", epoch=1, anchor_frame=0, anchor_ns=2_000_000_000),
    dict(op="change", change=dict(epoch=1, change_id=1, effective_frame=512, new_anchor_ns=2_005_333_333)),
    dict(op="decide", t=1_996_300_000, u=200_000, ok=True),
    dict(op="decide", t=2_001_633_333, u=200_000, ok=True),
    dict(op="decide", t=2_001_633_333, u=200_000, ok=True),
]
_LINES_D = [
    _gold(0, 0, 1, 0, "n04.stream.started", "epoch=1 anchor_frame=0 anchor_ns=2000000000", 0, 0),
    _gold(0, 2, 1, 0, "n04.change.accepted", "change_id=1 effective_frame=512 delta_ns=-5333333", 0, 0),
    _gold(1_996_300_000, 0, 1, 1, "n04.decision.muted_nohistory",
          "block=0 frames=0 presentation_ns=2000000000 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0", 0, 0,
          ',"cause":"nothing_played_yet"'),
    _gold(2_001_633_333, 1, 1, 2, "n04.decision.muted_nohistory",
          "block=1 frames=0 presentation_ns=2005333333 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0", 0, 0,
          ',"cause":"nothing_played_yet"'),
    _gold(2_001_633_333, 2, 1, 3, "n04.decision.skipped",
          "block=2 frames=0 presentation_ns=2005333333 gap_before_ns=0 submit_deadline_ns=0 late_by_ns=0", 0, 0,
          ',"cause":"latency_decrease"'),
]


def _observe(profile, ops, expected) -> List[str]:
    """Run ``ops`` through the reference and its log writer; compare with the hand-assembled lines."""
    eng = R.Engine(profile, _CFG)
    w = R.LogWriter("n04-log", "unit", LOG_KEY, "member-a", "group-a")
    last = None
    for op in ops:
        r, last = R.apply_op(eng, op, last)
        w.observe(eng, op, r, last)
    if w.lines == expected:
        return []
    if len(w.lines) != len(expected):
        return ["the writer produced %d lines, %d were assembled by hand" % (len(w.lines), len(expected))]
    i = next(k for k in range(len(expected)) if w.lines[k] != expected[k])
    return ["line %d: writer %s, hand-assembled %s" % (i, w.lines[i], expected[i])]


def _ring_oversize() -> List[str]:
    """Script A through the writer and a ring of 8 with a bound that drops some of its lines. The lengths are those of the
    hand-assembled lines; the kinds (critical or not) are known from the script: started C, duplicate o, muted C, real o,
    late o. A bound equal to the second-longest line keeps it and drops only the longer ones."""
    lengths = [len(x) for x in _LINES_A]
    critical = [True, False, True, False, False]
    problems: List[str] = []
    for bound in sorted(set(lengths)) + [min(lengths) - 1, max(lengths)]:
        eng = R.Engine("music", _CFG)
        ring = R.LogRing(8)
        w = R.LogWriter("n04-log", "unit", LOG_KEY, "member-a", "group-a", None, bound)
        w.ring = ring
        last = None
        for op in _OPS_A:
            r, last = R.apply_op(eng, op, last)
            w.observe(eng, op, r, last)
        over = [n > bound for n in lengths]
        want = dict(emitted=5, queued=5 - sum(over), dropped_oversize=sum(over),
                    critical_lost=sum(1 for o, c in zip(over, critical) if o and c))
        got = ring.stats()
        for key, value in want.items():
            if got[key] != value:
                problems.append("bound %d: %s is %d, hand-derived %d" % (bound, key, got[key], value))
    return problems


def check_log() -> List[str]:
    problems: List[str] = []
    problems += ["oversize " + m for m in _ring_oversize()]
    problems += ["script A " + m for m in _observe("music", _OPS_A, _LINES_A)]
    problems += ["script B " + m for m in _observe("music", _OPS_B, _LINES_B)]
    problems += ["script C " + m for m in _observe("music", _OPS_C, _LINES_C)]
    problems += ["script D " + m for m in _observe("realtime", _OPS_D, _LINES_D)]
    # The bound is inclusive: a line of exactly max_line bytes is kept, one byte more is dropped whole.
    exact = len(LOG_LINES[1][2])
    for bound, kept in ((exact, True), (exact - 1, False)):
        w = R.LogWriter("n04-log", "anchor", LOG_KEY, "member-a", "group-a", None, bound)
        w.line(*LOG_LINES[0][1])
        got = w.line(*LOG_LINES[1][1])
        if (got is not None) != kept:
            problems.append("a %d byte line with a bound of %d should be %s" % (exact, bound, "kept" if kept else "dropped"))
    if R.pseudonym(LOG_KEY, "member-a") != M or R.pseudonym(LOG_KEY, "group-a") != G:
        problems.append("pseudonym disagrees with hashlib")
    writers = {}
    for fault, args, want in LOG_LINES:
        w = writers.setdefault(fault, R.LogWriter("n04-log", "anchor", LOG_KEY, "member-a", "group-a", fault))
        got = w.line(*args)
        if got != want:
            problems.append("log line %r: %s, hand-assembled %s" % (args[6], got, want))
    if R.is_critical("n04.decision.real") or R.is_critical("n04.refusal.late") or R.is_critical("n04.delivery.delivered"):
        problems.append("an ordinary event is marked critical")
    if not all(R.is_critical(k) for k in ("n04.decision.concealed", "n04.decision.skipped", "n04.stream.started",
                                          "n04.change.refused", "n04.poll.clock_unusable", "n04.delivery.abandoned")):
        problems.append("a critical event is marked ordinary")
    oversize = R.LogWriter("n04-log", "anchor", LOG_KEY, "member-a", "group-a", None, 100)
    if oversize.line(0, 0, 1, 0, 0, 0, "n04.stream.started", "x") is not None or oversize.dropped_oversize != 1:
        problems.append("an over-long line is not dropped and counted")
    return problems


def check() -> List[str]:
    """Problems found comparing the reference with the anchors above; empty means they agree."""
    problems: List[str] = []
    for frames, want in FRAMES_TO_NS:
        got = R.frames_to_ns(frames)
        if got != want:
            problems.append("frames_to_ns(%d) = %d, hand-derived %d" % (frames, got, want))
    if R.BLOCK_NS != BLOCK:
        problems.append("BLOCK_NS %d != %d" % (R.BLOCK_NS, BLOCK))
    for args, want in CONSUME_BY:
        got = R.consume_by(*args)
        if got != want:
            problems.append("consume_by%r = %d, hand-derived %d" % (args, got, want))
    for run, wants in CONCEAL.items():
        raw = b"".join(s.to_bytes(2, "big", signed=True) for s in SAMPLES)
        out = R.conceal_block(raw, run)
        got = [int.from_bytes(out[i:i + 2], "big", signed=True) for i in range(0, len(raw), 2)]
        if got != wants:
            problems.append("conceal run %d: %r, hand-derived %r" % (run, got, wants))
    if R.CONCEAL_GAIN_Q15 != [round(0.7 ** n * 32768) for n in range(1, 9)]:
        problems.append("gain table is not round(0.7^n * 32768)")
    for (profile, margins, net), want in ADVICE:
        got = R.advice(margins, net, R.PROFILES[profile])
        if (got["action"], got["blocks"], got["reason"]) != want:
            problems.append("advice(%s, %d margins, net %d) = %r, hand-derived %r" % (
                profile, len(margins), net, (got["action"], got["blocks"], got["reason"]), want))
    if R.SLOT_BYTES != SLOT_BYTES:
        problems.append("SLOT_BYTES %d != %d" % (R.SLOT_BYTES, SLOT_BYTES))
    for horizon, want in CAPACITY_QUEUE:
        got = R.queue_bytes(horizon)
        if got != want:
            problems.append("queue_bytes(%d) = %d, hand-derived %d" % (horizon, got, want))
    if (R.PROFILES["music"]["horizon"], R.PROFILES["realtime"]["horizon"]) != (94, 9):
        problems.append("the profile horizons are not the 94 and 9 the capacity anchors use")
    problems += check_log()
    caps = (R.frames_to_ns(R.PROFILES["music"]["max_net"] * 256), R.frames_to_ns(R.PROFILES["realtime"]["max_net"] * 256))
    if caps != (CAP_MUSIC, CAP_REALTIME):
        problems.append("profile net caps %r" % (caps,))
    return problems


if __name__ == "__main__":
    found = check()
    print("anchors: %s" % ("agree with the reference" if not found else "DISAGREE:\n  " + "\n  ".join(found)))
    raise SystemExit(1 if found else 0)
