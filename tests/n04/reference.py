"""N04 (ffw-nx0) reference model: bounded playout engine with a consume_by cutoff, exactly-once decisions,
bounded concealment, coordinated latency changes and latency advice.

Exact integer arithmetic only. Written from docs/contracts/n04.md; the Rust (crates/franken-stream/src/playout.rs)
is held to this model by tests/n04/run_cases.py, which re-derives every record the Rust prints. Same author as the
Rust, so independent in language, route and data (the scripted worlds exist only here), not in authorship.

Time is the GROUP clock in nanoseconds (u64). The engine never reads a clock: every call carries a view
``(t, u, ok)``: the group time now, the clock's uncertainty (N03 ``ClockReport.uncertainty_ns``), and whether the
clock may be used at all (N03 status Locked or Holdover).
"""
from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

FRAME_RATE = 48_000
BLOCK_FRAMES = 256
MAX_PAYLOAD = BLOCK_FRAMES * 4
MAX_TS = 1 << 62
HISTORY = 128           # decided blocks remembered, to tell a duplicate of a played block from a late arrival
MARGIN_WINDOW = 64      # arrival margins kept for latency advice
ADVICE_MIN_EVENTS = 16
ADVICE_LATE_TRIGGER = 2
ADVICE_KEEP_BLOCKS = 3
CONCEAL_MAX_RUN = 8
# round(0.7 ** n * 32768): the attenuation applied to the last played block, n = 1..8, Q15.
CONCEAL_GAIN_Q15 = [22938, 16056, 11239, 7868, 5507, 3855, 2699, 1889]

# Decided-block history codes.
H_NONE, H_REAL, H_CONCEALED, H_MUTED, H_SKIPPED = 0, 1, 2, 3, 4

# Profiles: fixed caps, frozen with PROFILE_VERSION. Provisional engineering parameters, not measurements.
PROFILE_VERSION = "n04.profiles.v1"
PROFILES = {
    "music": dict(horizon=94, max_conceal=8, notice=8, max_step=38, max_net=94),
    "realtime": dict(horizon=9, max_conceal=3, notice=2, max_step=4, max_net=9),
}

STAT_KEYS = [
    "packets_seen", "repairs_seen", "admitted", "admitted_repair", "duplicate", "duplicate_conflict",
    "duplicate_repair", "late", "late_repair", "not_bound", "stale_epoch", "future_epoch", "clock_unusable",
    "clock_regressions",
    "bad_input", "too_far_ahead", "timeline_mismatch", "decided_real", "decided_concealed", "decided_muted_gap",
    "decided_muted_nohistory", "decided_muted_overdue", "decided_skipped", "clock_unusable_polls", "delivered",
    "abandoned", "changes_applied", "changes_rejected",
]


def frames_to_ns(frames: int) -> int:
    """floor(frames * 1e9 / 48000): the exact frame-to-time mapping (1e9 / 48000 = 62500 / 3 ns per frame)."""
    return frames * 62_500 // 3


BLOCK_NS = frames_to_ns(BLOCK_FRAMES)      # 5_333_333: the unit latency advice counts in


def consume_by(presentation_ns: int, work_ns: int, lead_ns: int, uncertainty_ns: int) -> int:
    """presentation - (downstream work + submission lead + clock uncertainty), clamped at 0."""
    return max(0, presentation_ns - (work_ns + lead_ns + uncertainty_ns))


def conceal_block(last: bytes, run: int) -> bytes:
    """The ``run``-th (1-based) concealed block: the last played block, every 16-bit sample scaled by the Q15 gain
    for ``run`` with round-half-up (floor shift), zero padded to a whole 256-frame block."""
    gain = CONCEAL_GAIN_Q15[run - 1]
    out = bytearray(MAX_PAYLOAD)
    for j in range(0, len(last), 2):
        s = int.from_bytes(last[j:j + 2], "big", signed=True)
        v = (s * gain + 16384) >> 15
        out[j:j + 2] = v.to_bytes(2, "big", signed=True)
    return bytes(out)


def synth_payload(seed: int, frames: int) -> bytes:
    """Deterministic test audio: sample j (interleaved L, R) = ((seed * 7919 + j * 104729) mod 65536) - 32768."""
    out = bytearray()
    for j in range(frames * 2):
        out += (((seed * 7919 + j * 104729) % 65536) - 32768).to_bytes(2, "big", signed=True)
    return bytes(out)


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def validate_config(profile: Dict[str, int], cfg: Dict[str, int]) -> Optional[str]:
    if cfg["work_ns"] < 1:
        return "work_ns"
    if cfg["lead_ns"] < 1:
        return "lead_ns"
    if not 0 <= cfg["tolerance_ns"] < BLOCK_NS // 2:
        return "tolerance_ns"
    return None


def advice(margins: List[int], net_shift_ns: int, profile: Dict[str, int]) -> Dict[str, Any]:
    """Latency advice from the arrival margins (cutoff - arrival, in ns; <= 0 means the packet was late).

    Increase when at least ADVICE_LATE_TRIGGER late arrivals are in the window, by enough whole blocks to have made
    the worst one on time, at most max_step blocks and never past the net cap (then: unhealthy). Decrease when
    the window is full, nothing is late and the slack beyond ADVICE_KEEP_BLOCKS blocks covers at least one block.
    Advice is never applied by the engine: a change needs group coordination (apply_change)."""
    cap = frames_to_ns(profile["max_net"] * BLOCK_FRAMES)
    if len(margins) < ADVICE_MIN_EVENTS:
        return dict(action="hold", blocks=0, reason="insufficient_data")
    late = sum(1 for m in margins if m <= 0)
    worst = min(margins)
    if late >= ADVICE_LATE_TRIGGER:
        n = min(profile["max_step"], (1 - worst + BLOCK_NS - 1) // BLOCK_NS)
        if net_shift_ns + frames_to_ns(n * BLOCK_FRAMES) > cap:
            return dict(action="unhealthy", blocks=0, reason="latency_cap")
        return dict(action="increase", blocks=n, reason="late_arrivals")
    if late == 0 and len(margins) >= MARGIN_WINDOW:
        spare = worst - ADVICE_KEEP_BLOCKS * BLOCK_NS
        n = min(profile["max_step"], spare // BLOCK_NS) if spare > 0 else 0
        if n >= 1 and abs(net_shift_ns - frames_to_ns(n * BLOCK_FRAMES)) <= cap:
            return dict(action="decrease", blocks=n, reason="spare_slack")
        return dict(action="hold", blocks=0, reason="stable")
    return dict(action="hold", blocks=0, reason="isolated_late" if late else "window_filling")


class Engine:
    """The playout engine. Methods return plain dicts so the judge can compare them with what the Rust printed."""

    def __init__(self, profile_name: str, cfg: Dict[str, int]):
        self.p = PROFILES[profile_name]
        self.cfg = dict(cfg)
        bad = validate_config(self.p, self.cfg)
        if bad:
            raise ValueError("invalid config: " + bad)
        self.stats = {k: 0 for k in STAT_KEYS}
        self.epoch: Optional[int] = None
        self._reset(0, 0)

    def _reset(self, origin: int, first_block: int) -> None:
        self.origin = origin
        self.first_block = first_block
        self.cursor = first_block
        self.slots: List[Optional[Tuple[int, bytes]]] = [None] * self.p["horizon"]
        self.hist = [H_NONE] * HISTORY
        self.last_real: Optional[bytes] = None
        self.gap_run = 0
        self.pending: Optional[Dict[str, int]] = None
        self.skip_until = first_block
        self.gap_next = 0
        self.last_change_id = 0
        self.net_shift = 0
        self.margins: List[int] = []
        self.last_now: Optional[int] = None

    # -- timeline ---------------------------------------------------------------------------------------------

    def pres_of(self, frame: int) -> int:
        origin = self.pending["new_origin"] if self.pending and frame >= self.pending["effective_frame"] else self.origin
        return origin + frames_to_ns(frame)

    def cutoff_of(self, block: int, u: int) -> int:
        return consume_by(self.pres_of(block * BLOCK_FRAMES), self.cfg["work_ns"], self.cfg["lead_ns"], u)

    # -- control ----------------------------------------------------------------------------------------------

    def begin_stream(self, epoch: int, anchor_frame: int, anchor_ns: int) -> Dict[str, Any]:
        # An older epoch is stale. The SAME epoch is allowed: after a relock N03 re-admits a start within its epoch.
        if self.epoch is not None and epoch < self.epoch:
            return dict(ok=False, reason="stale_epoch")
        if anchor_frame % BLOCK_FRAMES:
            return dict(ok=False, reason="misaligned")
        if anchor_ns > MAX_TS or anchor_ns < frames_to_ns(anchor_frame):
            return dict(ok=False, reason="bad_anchor")
        self.epoch = epoch
        self._reset(anchor_ns - frames_to_ns(anchor_frame), anchor_frame // BLOCK_FRAMES)
        return dict(ok=True, reason="started")

    def apply_change(self, ch: Dict[str, int]) -> Dict[str, Any]:
        """A coordinated latency change from the control channel: from ``effective_frame`` on, the frame whose
        presentation was ``origin + ft(f)`` is presented at ``new_anchor_ns + ft(f - effective_frame)``."""
        def no(reason: str) -> Dict[str, Any]:
            self.stats["changes_rejected"] += 1
            return dict(ok=False, reason=reason)

        if self.epoch is None:
            return no("not_bound")
        if ch["epoch"] < self.epoch:
            return no("stale_epoch")
        if ch["epoch"] > self.epoch:
            return no("future_epoch")
        if ch["change_id"] <= self.last_change_id:
            return no("replayed_change")
        if self.pending is not None:
            return no("change_pending")
        fe = ch["effective_frame"]
        if fe % BLOCK_FRAMES:
            return no("misaligned")
        eb = fe // BLOCK_FRAMES
        if eb < self.cursor + self.p["notice"]:
            return no("too_soon")
        if eb > self.cursor + self.p["horizon"]:
            return no("too_far_ahead")
        old_p = self.origin + frames_to_ns(fe)
        new_origin = ch["new_anchor_ns"] - frames_to_ns(fe)
        if ch["new_anchor_ns"] > MAX_TS or new_origin < 0:
            return no("bad_anchor")
        delta = ch["new_anchor_ns"] - old_p
        if delta == 0:
            return no("no_change")
        if abs(delta) > frames_to_ns(self.p["max_step"] * BLOCK_FRAMES):
            return no("transition_too_large")
        if abs(self.net_shift + delta) > frames_to_ns(self.p["max_net"] * BLOCK_FRAMES):
            return no("latency_cap_exceeded")
        self.last_change_id = ch["change_id"]
        self.pending = dict(change_id=ch["change_id"], effective_frame=fe, new_origin=new_origin, delta=delta)
        self.stats["changes_applied"] += 1
        return dict(ok=True, reason="accepted", delta_ns=delta)

    # -- the clock view ---------------------------------------------------------------------------------------

    def _view(self, t: int, ok: bool) -> Optional[str]:
        if not ok:
            return "clock_unusable"
        if self.last_now is not None and t < self.last_now:
            return "clock_regression"
        self.last_now = t
        return None

    # -- admission --------------------------------------------------------------------------------------------

    def _admit(self, t: int, u: int, ok: bool, epoch: int, frame: int, frames: int, payload: bytes,
               presentation: Optional[int]) -> str:
        repair = presentation is None
        self.stats["repairs_seen" if repair else "packets_seen"] += 1
        late_k, dup_k, adm_k = ("late_repair", "duplicate_repair", "admitted_repair") if repair else (
            "late", "duplicate", "admitted")
        if self.epoch is None:
            self.stats["not_bound"] += 1
            return "not_bound"
        if epoch < self.epoch:
            self.stats["stale_epoch"] += 1
            return "stale_epoch"
        if epoch > self.epoch:
            self.stats["future_epoch"] += 1
            return "future_epoch"
        why = self._view(t, ok)
        if why:
            self.stats["clock_unusable" if why == "clock_unusable" else "clock_regressions"] += 1
            return why
        if frame % BLOCK_FRAMES or not 1 <= frames <= BLOCK_FRAMES or len(payload) != frames * 4:
            self.stats["bad_input"] += 1
            return "bad_input"
        b = frame // BLOCK_FRAMES
        if b < self.cursor:
            if b >= self.cursor - HISTORY and b >= self.first_block and self.hist[b % HISTORY] == H_REAL:
                self.stats[dup_k] += 1
                return "duplicate"
            if b >= self.first_block:       # a block from before this stream began says nothing about its latency
                self._note_margin(self.cutoff_of(b, u) - t)
            self.stats[late_k] += 1
            return "late"
        if b >= self.cursor + self.p["horizon"]:
            self.stats["too_far_ahead"] += 1
            return "too_far_ahead"
        held = self.slots[b % self.p["horizon"]]
        if held is not None:
            self.stats[dup_k] += 1
            if held[1] != payload or held[0] != frames:
                self.stats["duplicate_conflict"] += 1
            return "duplicate"
        if presentation is not None and abs(presentation - self.pres_of(frame)) > self.cfg["tolerance_ns"]:
            self.stats["timeline_mismatch"] += 1
            return "timeline_mismatch"
        margin = self.cutoff_of(b, u) - t
        self._note_margin(margin)
        if margin <= 0:
            self.stats[late_k] += 1
            return "late"
        self.slots[b % self.p["horizon"]] = (frames, payload)
        self.stats[adm_k] += 1
        return "admitted"

    def _note_margin(self, margin: int) -> None:
        self.margins.append(margin)
        if len(self.margins) > MARGIN_WINDOW:
            self.margins.pop(0)

    def on_packet(self, t: int, u: int, ok: bool, epoch: int, frame: int, presentation: int, frames: int,
                  payload: bytes) -> Dict[str, Any]:
        return dict(r=self._admit(t, u, ok, epoch, frame, frames, payload, presentation))

    def on_repair(self, t: int, u: int, ok: bool, epoch: int, frame: int, frames: int, payload: bytes) -> Dict[str, Any]:
        return dict(r=self._admit(t, u, ok, epoch, frame, frames, payload, None))

    # -- decisions --------------------------------------------------------------------------------------------

    def decide(self, t: int, u: int, ok: bool) -> Dict[str, Any]:
        why = self._view(t, ok)
        if why:
            if why == "clock_unusable":
                self.stats["clock_unusable_polls"] += 1
            else:
                self.stats["clock_regressions"] += 1
            return dict(poll=why)
        if self.epoch is None:
            return dict(poll="not_bound")
        b = self.cursor
        if self.pending is not None and b == self.pending["effective_frame"] // BLOCK_FRAMES:
            self._commit_change()
        if b < self.skip_until:
            self.slots[b % self.p["horizon"]] = None
            return self._finish(b, "skipped", t, u, None, 0, 0, H_SKIPPED, "decided_skipped")
        pres = self.pres_of(b * BLOCK_FRAMES)
        cutoff = self.cutoff_of(b, u)
        if t < cutoff:
            return dict(poll="pending")
        slot = self.slots[b % self.p["horizon"]]
        self.slots[b % self.p["horizon"]] = None
        late_by = t - cutoff
        if t >= pres:
            self.gap_run = min(self.gap_run + 1, 255)
            return self._finish(b, "muted_overdue", t, u, None, 0, late_by, H_MUTED, "decided_muted_overdue")
        if slot is not None:
            frames, payload = slot
            self.last_real = payload + bytes(MAX_PAYLOAD - len(payload))
            self.gap_run = 0
            return self._finish(b, "real", t, u, payload, frames, late_by, H_REAL, "decided_real")
        if self.last_real is None:
            self.gap_run = min(self.gap_run + 1, 255)
            return self._finish(b, "muted_nohistory", t, u, None, 0, late_by, H_MUTED, "decided_muted_nohistory")
        if self.gap_run >= self.p["max_conceal"]:
            self.gap_run = min(self.gap_run + 1, 255)
            return self._finish(b, "muted_gap", t, u, None, 0, late_by, H_MUTED, "decided_muted_gap")
        self.gap_run += 1
        out = conceal_block(self.last_real, self.gap_run)
        return self._finish(b, "concealed", t, u, out, BLOCK_FRAMES, late_by, H_CONCEALED, "decided_concealed",
                            run=self.gap_run)

    def _commit_change(self) -> None:
        ch = self.pending
        fe, old_origin = ch["effective_frame"], self.origin
        old_end = old_origin + frames_to_ns(fe)
        n = 0
        if ch["delta"] < 0:
            n = 1
            while ch["new_origin"] + frames_to_ns(fe + n * BLOCK_FRAMES) < old_end:
                n += 1
        self.gap_next = ch["new_origin"] + frames_to_ns(fe + n * BLOCK_FRAMES) - old_end
        self.skip_until = fe // BLOCK_FRAMES + n
        self.origin = ch["new_origin"]
        self.net_shift += ch["delta"]
        self.pending = None

    def _finish(self, b: int, outcome: str, t: int, u: int, payload: Optional[bytes], frames: int, late_by: int,
                code: int, stat: str, run: int = 0) -> Dict[str, Any]:
        self.hist[b % HISTORY] = code
        self.cursor = b + 1
        self.stats[stat] += 1
        pres = self.pres_of(b * BLOCK_FRAMES)
        gap = 0
        if outcome != "skipped":
            gap, self.gap_next = self.gap_next, 0
        d: Dict[str, Any] = dict(block=b, outcome=outcome, pres=pres, frames=frames, gap_before=gap,
                                 submit_deadline=max(0, pres - self.cfg["lead_ns"]) if payload is not None else 0,
                                 late_by=late_by)
        if run:
            d["run"] = run
        if payload is not None:
            d["fnv"] = "%016x" % fnv1a64(payload[:frames * 4])
        return dict(poll="decision", d=d)

    # -- downstream and diagnostics ---------------------------------------------------------------------------

    def settle_delivery(self, submit_deadline: int, accepted_at: Optional[int]) -> Dict[str, Any]:
        """The downstream ring took the block at ``accepted_at`` (None: it never had room). On time: delivered.
        Otherwise abandoned: the block is not retried past its submission deadline and nothing is queued for it."""
        if accepted_at is not None and accepted_at <= submit_deadline:
            self.stats["delivered"] += 1
            return dict(delivery="delivered")
        self.stats["abandoned"] += 1
        return dict(delivery="abandoned")

    def advice(self) -> Dict[str, Any]:
        return advice(self.margins, self.net_shift, self.p)

    def snapshot(self) -> Dict[str, Any]:
        queued = sum(1 for s in self.slots if s is not None)
        return dict(epoch=self.epoch, cursor=self.cursor, queued=queued, gap_run=self.gap_run,
                    net_shift_ns=self.net_shift, pending=self.pending is not None, stats=dict(self.stats))


# -- worlds --------------------------------------------------------------------------------------------------------

def apply_op(eng: Engine, op: Dict[str, Any], last_decision: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Apply one scripted op; returns (result, the last decision seen). ``payload`` is ``synth_payload(seed, frames)``."""
    kind = op["op"]
    ok = op.get("ok", True)
    if kind == "begin":
        r = eng.begin_stream(op["epoch"], op["anchor_frame"], op["anchor_ns"])
    elif kind == "packet":
        frames = op.get("frames", BLOCK_FRAMES)
        r = eng.on_packet(op["t"], op["u"], ok, op["epoch"], op["frame"], op["pres"], frames,
                          synth_payload(op["seed"], frames))
    elif kind == "repair":
        frames = op.get("frames", BLOCK_FRAMES)
        r = eng.on_repair(op["t"], op["u"], ok, op["epoch"], op["frame"], frames, synth_payload(op["seed"], frames))
    elif kind == "bad_packet":
        r = eng.on_packet(op["t"], op["u"], ok, op["epoch"], op["frame"], op["pres"], op["frames"],
                          bytes(op["payload_len"]))
    elif kind == "decide":
        r = eng.decide(op["t"], op["u"], ok)
        last_decision = r.get("d")
    elif kind == "change":
        r = eng.apply_change(op["change"])
    elif kind == "deliver":
        r = eng.settle_delivery(op["submit_deadline"] if "submit_deadline" in op else last_decision["submit_deadline"],
                                op["accepted_at"])
    elif kind == "advice":
        r = eng.advice()
    elif kind == "stats":
        r = eng.snapshot()
    else:
        raise ValueError("unknown op " + kind)
    return r, last_decision


def run_world(world: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Replay a scripted world and return one result per op."""
    eng = Engine(world["profile"], world["cfg"])
    out: List[Dict[str, Any]] = []
    last_decision: Optional[Dict[str, Any]] = None
    for op in world["ops"]:
        r, last_decision = apply_op(eng, op, last_decision)
        out.append(r)
    return out


# -- diagnostics (ffw.log.v1) --------------------------------------------------------------------------------------
#
# One bounded JSONL record per decision and per refusal, built from a fixed vocabulary and numbers only: nothing a peer
# supplied is ever copied, and member/group identifiers appear only as keyed one-way pseudonyms. The field order is the
# shared ``ffw.log.v1`` event's. The writer here is the model the Rust (``playout/log.rs``) is held to, line by line.

LOG_SCHEMA = "ffw.log.v1"
MAX_LINE_BYTES = 1024
MAX_LABEL_LEN = 64
# Why a decision that is not `real` happened, from a fixed vocabulary.
DECISION_CAUSE = {
    "concealed": "no_block_by_cutoff",
    "muted_gap": "gap_longer_than_conceal_maximum",
    "muted_nohistory": "nothing_played_yet",
    "muted_overdue": "decided_at_or_after_presentation",
    "skipped": "latency_decrease",
}


def pseudonym(key: bytes, ident: str) -> str:
    """``p-`` and 16 hex characters: SHA-256 of "ffw.pseudonym.v1", the key, the id's length (8 bytes, big endian)
    and the id. Identical to the shared diagnostics sink's and to N02's."""
    raw = ident.encode("utf-8")
    h = hashlib.sha256(b"ffw.pseudonym.v1" + key + len(raw).to_bytes(8, "big") + raw)
    return "p-" + h.hexdigest()[:16]


def valid_label(text: str) -> bool:
    return (0 < len(text) <= MAX_LABEL_LEN and (text[0].islower() or text[0].isdigit()) and text.isascii()
            and all(c.islower() or c.isdigit() or c in "._-" for c in text))


def is_critical(kind: str) -> bool:
    """Evidence a run cannot be trusted without: anything that changes what is heard or the timeline. Ordinary:
    a real decision, a delivered block, a refused packet."""
    return not (kind == "n04.decision.real" or kind == "n04.delivery.delivered" or kind.startswith("n04.refusal."))


class LogWriter:
    def __init__(self, run_id: str, case_id: str, key: bytes, member: str, group: str,
                 fault: Optional[str] = None, max_line: int = MAX_LINE_BYTES):
        for label in (run_id, case_id) + ((fault,) if fault is not None else ()):
            if not valid_label(label):
                raise ValueError("invalid label %r" % label)
        self.run_id, self.case_id, self.fault, self.max_line = run_id, case_id, fault, max_line
        self.member_p, self.group_p = pseudonym(key, member), pseudonym(key, group)
        self.last_ts = 0
        self.lines: List[str] = []
        self.kinds: List[str] = []
        self.dropped_oversize = 0
        self.ring: Optional["LogRing"] = None

    def line(self, candidate_ts: int, n: int, epoch: int, revision: int, queue: int, latency_us: int, kind: str,
             message: str, cause: Optional[str] = None) -> Optional[str]:
        """Build one record. The timestamp never goes backwards. A line longer than the bound is dropped, never cut."""
        ts = max(candidate_ts, self.last_ts)
        self.last_ts = ts
        rec: Dict[str, Any] = {
            "schema_version": LOG_SCHEMA, "timestamp_mono_ns": ts, "run_id": self.run_id, "case_id": self.case_id,
            "correlation_id": "%s#%d" % (self.member_p, n), "member_id": self.member_p, "group_id": self.group_p,
            "source_epoch": epoch, "state_revision": revision, "event_kind": kind, "message": message,
            "queue_depth": queue, "latency_us": latency_us,
        }
        if self.fault is not None:
            rec["fault"] = self.fault
        if cause is not None:
            rec["cause"] = cause
        text = json.dumps(rec, separators=(",", ":"))
        if len(text.encode("ascii")) > self.max_line:
            self.dropped_oversize += 1
            if self.ring is not None:
                self.ring.push(None, is_critical(kind))
            return None
        self.lines.append(text)
        self.kinds.append(kind)
        if self.ring is not None:
            self.ring.push(text, is_critical(kind))
        return text

    def observe(self, eng: Engine, op: Dict[str, Any], r: Dict[str, Any], last_decision: Optional[Dict[str, Any]]) -> None:
        """Write the record(s) for one applied op, from the engine's state AFTER the op."""
        epoch = eng.epoch or 0
        revision = eng.cursor
        queue = sum(1 for slot in eng.slots if slot is not None)
        kind = op["op"]

        def put(ts: int, n: int, latency_us: int, event: str, message: str, cause: Optional[str] = None) -> None:
            self.line(ts, n, epoch, revision, queue, latency_us, event, message, cause)

        if kind == "begin":
            msg = "epoch=%d anchor_frame=%d anchor_ns=%d" % (op["epoch"], op["anchor_frame"], op["anchor_ns"])
            n = op["anchor_frame"] // BLOCK_FRAMES
            if r["ok"]:
                put(self.last_ts, n, 0, "n04.stream.started", msg)
            else:
                put(self.last_ts, n, 0, "n04.stream.refused", msg, r["reason"])
        elif kind in ("packet", "repair", "bad_packet"):
            if r["r"] == "admitted":
                return
            frames = op["frames"] if kind == "bad_packet" else op.get("frames", BLOCK_FRAMES)
            msg = "source=%s frame=%d frames=%d packet_epoch=%d" % (
                "repair" if kind == "repair" else "media", op["frame"], frames, op["epoch"])
            late_us = 0
            if r["r"] == "late":
                late_us = max(0, op["t"] - eng.cutoff_of(op["frame"] // BLOCK_FRAMES, op["u"])) // 1000
            put(op["t"], op["frame"] // BLOCK_FRAMES, late_us, "n04.refusal." + r["r"], msg)
        elif kind == "decide":
            if r["poll"] == "pending":
                return
            if r["poll"] == "decision":
                d = r["d"]
                msg = "block=%d frames=%d presentation_ns=%d gap_before_ns=%d submit_deadline_ns=%d late_by_ns=%d" % (
                    d["block"], d["frames"], d["pres"], d["gap_before"], d["submit_deadline"], d["late_by"])
                if "run" in d:
                    msg += " run=%d" % d["run"]
                put(op["t"], d["block"], d["late_by"] // 1000, "n04.decision." + d["outcome"], msg,
                    DECISION_CAUSE.get(d["outcome"]))
            else:
                put(op["t"], eng.cursor, 0, "n04.poll." + r["poll"], "cursor=%d" % eng.cursor)
        elif kind == "change":
            ch = op["change"]
            base = "change_id=%d effective_frame=%d" % (ch["change_id"], ch["effective_frame"])
            n = ch["effective_frame"] // BLOCK_FRAMES
            if r["ok"]:
                put(self.last_ts, n, 0, "n04.change.accepted", "%s delta_ns=%d" % (base, r["delta_ns"]))
            else:
                put(self.last_ts, n, 0, "n04.change.refused", base, r["reason"])
        elif kind == "deliver":
            deadline = op["submit_deadline"] if "submit_deadline" in op else last_decision["submit_deadline"]
            at = op["accepted_at"]
            late_us = max(0, at - deadline) // 1000 if (r["delivery"] == "abandoned" and at is not None) else 0
            put(at if at is not None else self.last_ts, max(0, eng.cursor - 1), late_us, "n04.delivery." + r["delivery"],
                "submit_deadline_ns=%d accepted_at_ns=%s" % (deadline, "none" if at is None else str(at)))


def run_world_logged(world: Dict[str, Any], log: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], LogWriter]:
    """The results of a world and the log lines the model says it writes. ``log``: run_id, key_hex, member, group,
    and optionally fault and max_line; the case id is the world's id, lower-cased."""
    eng = Engine(world["profile"], world["cfg"])
    writer = LogWriter(log["run_id"], world["id"].lower(), bytes.fromhex(log["key_hex"]), log["member"], log["group"],
                       log.get("fault"), log.get("max_line", MAX_LINE_BYTES))
    out: List[Dict[str, Any]] = []
    last_decision: Optional[Dict[str, Any]] = None
    for op in world["ops"]:
        r, last_decision = apply_op(eng, op, last_decision)
        writer.observe(eng, op, r, last_decision)
        out.append(r)
    return out, writer


# -- the nonblocking sink -------------------------------------------------------------------------------------------
#
# The decision path writes into a bounded ring and never calls the sink. A separate drain offers queued lines to the
# sink, oldest first, at most ``budget`` offers per call; a sink that is full or unavailable leaves the line queued.
# Ordinary records may use ``capacity - capacity // 4`` slots, critical ones all of them, so a flood of ordinary records
# cannot crowd out the evidence a run is untrustworthy without. Every record is either delivered, queued or counted
# as dropped: emitted == delivered + queued + dropped_full + dropped_oversize.

SINK_REPLIES = ("taken", "full", "unavailable")
LOG_STAT_KEYS = ["emitted", "delivered", "queued", "dropped_full", "dropped_oversize", "critical_lost", "offers",
                 "sink_full_polls", "sink_unavailable_polls"]


class LogRing:
    def __init__(self, capacity: int):
        if capacity < 1:
            raise ValueError("capacity")
        self.capacity = capacity
        self.reserve = capacity // 4
        self.queue: deque = deque()
        self.delivered: List[str] = []
        self.emitted = self.dropped_full = self.dropped_oversize = self.critical_lost = 0
        self.offers = self.sink_full_polls = self.sink_unavailable_polls = 0

    def push(self, line: Optional[str], critical: bool) -> None:
        self.emitted += 1
        if line is None:
            self.dropped_oversize += 1
            self.critical_lost += 1 if critical else 0
            return
        limit = self.capacity if critical else self.capacity - self.reserve
        if len(self.queue) >= limit:
            self.dropped_full += 1
            self.critical_lost += 1 if critical else 0
            return
        self.queue.append(line)

    def drain(self, replies: List[str], cursor: int, budget: int) -> int:
        """Offer queued lines; ``replies`` is the sink's script, repeated; ``cursor`` is how many offers it has seen.
        Returns the new cursor."""
        for _ in range(budget):
            if not self.queue:
                break
            reply = replies[cursor % len(replies)]
            cursor += 1
            self.offers += 1
            if reply == "taken":
                self.delivered.append(self.queue.popleft())
            elif reply == "full":
                self.sink_full_polls += 1
                break
            else:
                self.sink_unavailable_polls += 1
                break
        return cursor

    def stats(self) -> Dict[str, int]:
        return dict(emitted=self.emitted, delivered=len(self.delivered), queued=len(self.queue),
                    dropped_full=self.dropped_full, dropped_oversize=self.dropped_oversize,
                    critical_lost=self.critical_lost, offers=self.offers, sink_full_polls=self.sink_full_polls,
                    sink_unavailable_polls=self.sink_unavailable_polls)


def run_world_sinked(world: Dict[str, Any], log: Dict[str, Any], plan: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], LogRing]:
    """Run a world with the log on and a scripted drain: after every ``drain_every`` ops offer up to ``budget`` lines to a
    sink that answers from ``replies``; ``final_budget`` (default 0) drains once more at the end."""
    ring = LogRing(plan["capacity"])
    eng = Engine(world["profile"], world["cfg"])
    writer = LogWriter(log["run_id"], world["id"].lower(), bytes.fromhex(log["key_hex"]), log["member"], log["group"],
                       log.get("fault"), plan.get("max_line", MAX_LINE_BYTES))
    writer.ring = ring
    out: List[Dict[str, Any]] = []
    last_decision: Optional[Dict[str, Any]] = None
    cursor = 0
    for i, op in enumerate(world["ops"]):
        r, last_decision = apply_op(eng, op, last_decision)
        writer.observe(eng, op, r, last_decision)
        out.append(r)
        if (i + 1) % plan["drain_every"] == 0:
            cursor = ring.drain(plan["replies"], cursor, plan["budget"])
    ring.drain(plan["replies"], cursor, plan.get("final_budget", 0))
    return out, ring
