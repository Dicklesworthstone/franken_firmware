#!/usr/bin/env python3
"""An independent model of the N07 loopback carrier and of the scripted worlds that exercise it (docs/contracts/n07.md).

Nothing here imports or runs the Rust. It restates the carrier's rules in exact integers: the token bucket, the round-robin
service, the per-peer and aggregate queue caps, the window, the epoch fence, the path-MTU fence and the receiver's replay window.
`expected(scenario)` plays a scripted world through those rules and returns the record the Rust interpreter in
`crates/franken-stream/tests/n07_carrier.rs` must print for the same script over real loopback sockets:
`run_cases.py` holds the two together. The scenario scripts live in `crates/franken-stream/tests/vectors/n07_scenarios.json`
(written by `model.py --write`), which the Rust test reads, so the script is one text and not two.

    model.py --write      regenerate the scenario file from the definitions below
    model.py --check      exit 1 if the committed file differs from a fresh generation
"""
from __future__ import annotations

import copy
import json
import os
import sys
from collections import deque

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SCENARIOS = os.path.join(REPO, "crates", "franken-stream", "tests", "vectors", "n07_scenarios.json")

NANOS = 1_000_000_000
MAX_REFILL = 4 * NANOS
WIRE_OVERHEAD = 80
MAX_PAYLOAD = 1024
OVERHEAD = {False: 28, True: 48}
BLOCK_NS = 5_333_333
MASK64 = (1 << 64) - 1
REPLAY_WINDOW = 64
MAX_FORWARD_GAP = 1024
# Control is charged to the interface bucket and to its own share of it (1/8 of the rate, burst = control_per_pump largest
# control datagrams); a scripted control datagram is 16 bytes (the Rust interpreter's), plus the IP and UDP headers.
CONTROL_DIVISOR = 8
MAX_CONTROL = 512
CONTROL_LEN = 16
# A peer that is waiting (its window is full of transmitted, unreported datagrams, or its sequence budget is spent) may be sent one
# probe per interval: its newest transmitted datagram again, under the same number. A probe allocates no number and holds no place.
STALL_PROBE_NS = 250_000_000
# The window may be configured up to 4096 packets, and a number is never allocated 1000 or more beyond what the receiver has
# reported: the receiver's highest admitted number is at least `reported - 1`, N01 admits a number up to 1024 beyond it, and
# 1000 leaves 24 spare. The two are separate limiters: a window larger than the budget is supported and its effective size is
# the budget. (The Rust also holds a datagram the transport refused; a world with no send faults never holds one.)
MAX_WINDOW = 4096
SEQ_AHEAD_LIMIT = 1000
assert SEQ_AHEAD_LIMIT < 1024

BASELINE_LIMITS = {
    "loopback_only": True, "allow_ipv6": False, "required_payload_bytes": 1024, "max_peers": 8,
    "peer_load_bytes_per_sec": 220_000, "pace_bytes_per_sec": 1_760_000, "pace_burst_bytes": 8_192,
    "peer_queue_packets": 32, "peer_queue_bytes": 36_864, "aggregate_queue_packets": 128, "aggregate_queue_bytes": 147_456,
    "control_queue_packets": 8, "control_per_pump": 4, "window_packets": 16, "max_sends_per_pump": 64, "max_reads_per_pump": 64,
}
BASELINE_RECEIVER = {"inbound_packets": 32, "control_inbox_packets": 8, "max_reads_per_poll": 64}

PEER_COUNTERS = [
    "media_submitted_packets", "media_submitted_bytes", "media_sent_packets", "media_sent_bytes",
    "media_dropped_overflow_packets", "media_dropped_overflow_bytes", "media_dropped_aggregate_packets",
    "media_dropped_aggregate_bytes", "media_dropped_late_packets", "media_dropped_late_bytes",
    "media_dropped_fenced_packets", "media_dropped_fenced_bytes", "media_dropped_send_error_packets",
    "media_dropped_send_error_bytes", "control_submitted", "control_sent", "control_rejected_full",
    "control_dropped_send_error", "reports_accepted", "window_stalled_pumps", "queue_delay_ns_total", "queue_delay_ns_max",
]
CARRIER_STATS = [
    "pumps", "link_down_pumps", "pace_limited_pumps", "send_cap_pumps", "stale_submits", "admissions_rejected",
    "control_datagrams_in", "reports_malformed", "reports_bad_tag", "reports_wrong_stream", "reports_stale_epoch",
    "reports_unknown_source", "reports_invalid", "recv_errors", "link_events", "path_changes", "mtu_fences", "mtu_unfences",
    "epoch_advances", "removed_peer_dropped_packets", "removed_peer_dropped_bytes",
]
RECEIVER_STATS = [
    "media_read", "media_accepted", "media_rejected", "inbound_overflow", "control_read", "control_delivered",
    "control_dropped_full", "control_oversize", "control_wrong_source", "reports_sent", "io_errors",
]
STREAM_COUNTERS = [
    "datagrams_seen", "accepted", "mac_verifications", "rejected_structure", "rejected_unsupported_version",
    "rejected_authentication", "rejected_malformed_fields", "rejected_wrong_stream", "rejected_stale_epoch",
    "rejected_future_epoch", "rejected_replay", "rejected_future_sequence", "rejected_not_negotiated",
]
# Explicit current telemetry schema. The v1 model/vector state above remains
# unchanged; FEC is never selected by these N01 scripted worlds.
IDLE_FEC_PEER_COUNTERS = ["fec_sent_packets", "fec_feedback_accepted", "fec_feedback_refused",
                          "fec_feedback_deferred", "fec_feedback_overflow"]
IDLE_FEC_CARRIER_STATS = ["fec_feedback_accepted", "fec_feedback_refused", "fec_work_refused",
                         "fec_feedback_deferred", "fec_feedback_overflow"]
OBSERVED_PEER_COUNTERS = PEER_COUNTERS[:4] + IDLE_FEC_PEER_COUNTERS + PEER_COUNTERS[4:]
_AFTER_REPORTS = CARRIER_STATS.index("reports_invalid") + 1
OBSERVED_CARRIER_STATS = CARRIER_STATS[:_AFTER_REPORTS] + IDLE_FEC_CARRIER_STATS + CARRIER_STATS[_AFTER_REPORTS:]
DROP_KINDS = ("overflow", "aggregate", "late", "fenced", "send_error")


def zero(names):
    return {name: 0 for name in names}


def max_payload_for_path_mtu(path_mtu, ipv6):
    room = path_mtu - (OVERHEAD[ipv6] + WIRE_OVERHEAD)
    if room < 0:
        return None
    payload = min(room // 4 * 4, MAX_PAYLOAD)
    return payload if payload else None


def payload_for_block(block):
    """The sample oracle: what block `b` carries, written down independently of the carrier."""
    return bytes((block * 131 + i * 7 + 3) & 0xFF for i in range(MAX_PAYLOAD))


class SplitMix64:
    def __init__(self, seed):
        self.state = seed & MASK64

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)


class Pacer:
    def __init__(self, rate, burst):
        self.rate, self.cap, self.tokens, self.last = rate, burst * NANOS, 0, None

    def refill(self, now):
        if self.last is None:
            self.tokens = self.cap
        else:
            elapsed = min(max(now - self.last, 0), MAX_REFILL)
            self.tokens = min(self.tokens + elapsed * self.rate, self.cap)
        self.last = now

    def can_afford(self, cost):
        return self.tokens >= cost * NANOS

    def spend(self, cost):
        self.tokens -= cost * NANOS

    def wait_ns(self, cost):
        missing = max(cost * NANOS - self.tokens, 0)
        return -(-missing // self.rate)


class Peer:
    def __init__(self, pid, ipv6, mtu, epoch_seq=0):
        self.id, self.ipv6, self.path_mtu, self.fence = pid, ipv6, mtu, None
        self.next_seq, self.media_q, self.media_q_bytes, self.control_q = epoch_seq, deque(), 0, deque()
        self.sent_next, self.reported_next, self.generation = 0, 0, 0
        self.inflight, self.probe_due = deque(), None    # transmitted, unreported sequence numbers; the next probe
        self.last_sent = None                            # (seq, block, wire_len) of the newest transmitted datagram: what a probe sends
        self.counters = zero(PEER_COUNTERS)

    def drop(self, entry, kind):
        self.counters["media_dropped_%s_packets" % kind] += 1
        self.counters["media_dropped_%s_bytes" % kind] += entry["wire_len"]

    def drop_oldest(self, kind):
        if self.media_q:
            entry = self.media_q.popleft()
            self.media_q_bytes -= entry["wire_len"]
            self.drop(entry, kind)

    def purge(self, kind):
        while self.media_q:
            self.drop_oldest(kind)

    def stalled(self, window):
        return len(self.inflight) >= window

    def sequence_blocked(self):
        """Every number within SEQ_AHEAD_LIMIT of the report is allocated (the model never holds a refused datagram)."""
        return self.sent_next >= self.reported_next + SEQ_AHEAD_LIMIT

    def waiting(self, window):
        """Nothing new may be signed and sent: a full window or a spent sequence budget. Only a probe may go."""
        return self.stalled(window) or self.sequence_blocked()

    def probe_is_due(self, window, now):
        return (self.waiting(window) and self.probe_due is not None and now >= self.probe_due
                and self.last_sent is not None and bool(self.media_q))

    def on_reported(self, window):
        while self.inflight and self.inflight[0] < self.reported_next:
            self.inflight.popleft()
        if not self.waiting(window):
            self.probe_due = None


class Sender:
    def __init__(self, limits, epoch):
        self.lim, self.epoch, self.peers, self.link_up = limits, epoch, [], True
        self.pacer = Pacer(limits["pace_bytes_per_sec"], limits["pace_burst_bytes"])
        self.control_pacer = Pacer(max(limits["pace_bytes_per_sec"] // CONTROL_DIVISOR, 1),
                                   limits["control_per_pump"] * (MAX_CONTROL + OVERHEAD[True]))
        self.media_cursor, self.control_cursor, self.stats = 0, 0, zero(CARRIER_STATS)
        self.emitted = []            # (peer, epoch, seq, block, wire_len) sent in the current pump
        self.probe_emitted = []      # the probes sent in the current pump: the same tuples, a datagram sent again
        self.control_emitted = []    # (peer, tag)
        self.control_spent, self.control_pace_limited_pumps = 0, 0
        self.probes_sent, self.probe_bytes = 0, 0
        assert 0 < limits["window_packets"] <= MAX_WINDOW, "the window is bounded"

    # ---- peers ----
    def add_peer(self, pid, kind, mtu):
        """kind: 'ok' for a loopback IPv4 peer, 'lan', 'v6'. Returns the error code or 'ok'."""
        code = self._admit(pid, kind, mtu)
        if code != "ok":
            self.stats["admissions_rejected"] += 1
        return code

    def _admit(self, pid, kind, mtu):
        lim = self.lim
        if any(p.id == pid for p in self.peers):
            return "DUPLICATE_PEER"
        if len(self.peers) >= lim["max_peers"]:
            return "TOO_MANY_PEERS"
        ipv6 = kind == "v6"
        if ipv6 and not lim["allow_ipv6"]:
            return "UNSUPPORTED_ADDRESS_FAMILY"
        if lim["loopback_only"] and kind == "lan":
            return "NOT_LOOPBACK"
        capacity = max_payload_for_path_mtu(mtu, ipv6) or 0
        if capacity < lim["required_payload_bytes"]:
            return "PATH_MTU_TOO_SMALL"
        if (len(self.peers) + 1) * lim["peer_load_bytes_per_sec"] > lim["pace_bytes_per_sec"]:
            return "OVER_BUDGET"
        self.peers.append(Peer(pid, ipv6, mtu))
        return "ok"

    def peer(self, pid):
        return next(p for p in self.peers if p.id == pid)

    def remove_peer(self, pid):
        p = self.peer(pid)
        self.peers.remove(p)
        self.stats["removed_peer_dropped_packets"] += len(p.media_q)
        self.stats["removed_peer_dropped_bytes"] += p.media_q_bytes

    def set_path_mtu(self, pid, mtu):
        p = self.peer(pid)
        capacity = max_payload_for_path_mtu(mtu, p.ipv6) or 0
        p.path_mtu = mtu
        if capacity < self.lim["required_payload_bytes"]:
            if p.fence is None:
                p.fence = "path_mtu_too_small"
                p.purge("fenced")
                self.stats["mtu_fences"] += 1
            return "fenced"
        if p.fence == "path_mtu_too_small":
            p.fence = None
            self.stats["mtu_unfences"] += 1
        return "carrying"

    def peer_address_changed(self, pid):
        self.peer(pid).generation += 1
        self.stats["path_changes"] += 1

    def set_link_up(self, up):
        self.link_up = up
        self.stats["link_events"] += 1

    def advance_epoch(self, new_epoch):
        assert new_epoch > self.epoch
        for p in self.peers:
            p.next_seq = 0
            p.purge("fenced")
            p.sent_next = 0
            p.reported_next = 0
            p.inflight.clear()
            p.probe_due = None
            p.last_sent = None
        self.epoch = new_epoch
        self.stats["epoch_advances"] += 1

    # ---- media ----
    def aggregate_media(self):
        return sum(len(p.media_q) for p in self.peers), sum(p.media_q_bytes for p in self.peers)

    def largest_media_queue(self):
        best = None
        for idx, p in enumerate(self.peers):
            if p.media_q and (best is None or p.media_q_bytes > best[1]):
                best = (idx, p.media_q_bytes)
        return None if best is None else best[0]

    def submit_media(self, epoch, block, consume_by, now):
        """Returns ('ok', report) or ('STALE_EPOCH', None)."""
        if epoch != self.epoch:
            self.stats["stale_submits"] += 1
            return "STALE_EPOCH", None
        wire_len = WIRE_OVERHEAD + MAX_PAYLOAD
        report = {"queued": 0, "evicted": 0, "rejected_aggregate": 0, "skipped_fenced": 0}
        for idx, p in enumerate(self.peers):
            p.counters["media_submitted_packets"] += 1
            p.counters["media_submitted_bytes"] += wire_len
            entry = {"block": block, "consume_by": consume_by, "wire_len": wire_len, "enq": now}
            if p.fence is not None:
                p.drop(entry, "fenced")
                report["skipped_fenced"] += 1
                continue
            self._enqueue(idx, entry, report)
        return "ok", report

    def _enqueue(self, idx, entry, report):
        lim, p = self.lim, self.peers[idx]
        while True:
            if len(p.media_q) < lim["peer_queue_packets"] and p.media_q_bytes + entry["wire_len"] <= lim["peer_queue_bytes"]:
                break
            if not p.media_q:
                p.drop(entry, "overflow")
                return
            p.drop_oldest("overflow")
            report["evicted"] += 1
        while True:
            packets, nbytes = self.aggregate_media()
            if packets < lim["aggregate_queue_packets"] and nbytes + entry["wire_len"] <= lim["aggregate_queue_bytes"]:
                break
            victim = self.largest_media_queue()
            if victim is None:
                p.drop(entry, "aggregate")
                report["rejected_aggregate"] += 1
                return
            self.peers[victim].drop_oldest("aggregate")
            report["evicted"] += 1
        p.media_q.append(entry)
        p.media_q_bytes += entry["wire_len"]
        report["queued"] += 1

    def submit_control(self, pid, tag):
        p = self.peer(pid)
        if len(p.control_q) >= self.lim["control_queue_packets"]:
            p.counters["control_rejected_full"] += 1
            return "CONTROL_QUEUE_FULL"
        p.control_q.append(tag)
        p.counters["control_submitted"] += 1
        return "ok"

    # ---- reports ----
    def on_report(self, epoch, consumed_next, generation_of_source, pid):
        """A report whose source address is peer `pid`'s control address of that generation. True if it was applied."""
        self.stats["control_datagrams_in"] += 1
        if epoch != self.epoch:
            self.stats["reports_stale_epoch"] += 1
            return False
        p = next((q for q in self.peers if q.id == pid and q.generation == generation_of_source), None)
        if p is None:
            self.stats["reports_unknown_source"] += 1
            return False
        if consumed_next > p.sent_next:
            self.stats["reports_invalid"] += 1
            return False
        p.reported_next = max(p.reported_next, consumed_next)
        p.on_reported(self.lim["window_packets"])
        p.counters["reports_accepted"] += 1
        return True

    # ---- the pump ----
    def pump(self, now):
        out = {"link_down": False, "reports_applied": 0, "control_sent": 0, "media_sent": 0, "late_dropped": 0,
               "window_stalled_peers": 0, "pace_limited": False, "send_cap_hit": False, "next_send_ns": None}
        self.emitted, self.control_emitted, self.probe_emitted = [], [], []
        self.stats["pumps"] += 1
        if not self.link_up:
            self.stats["link_down_pumps"] += 1
            out["link_down"] = True
            return out
        # reports were already applied by the world, in arrival order, before this call (the Rust pump reads none new)
        self.pacer.refill(now)
        self.control_pacer.refill(now)
        out["control_sent"] = self._pump_control()
        out["late_dropped"] = self._expire_late(now)
        self._pump_media(now, out)
        window = self.lim["window_packets"]
        for p in self.peers:
            if p.media_q and p.fence is None and p.stalled(window):
                p.counters["window_stalled_pumps"] += 1
                out["window_stalled_peers"] += 1
        return out

    def _pump_control(self):
        """Control goes first, at most `control_per_pump` per pump, and only what the interface bucket and control's own
        share both afford (the cost is the datagram plus its IP and UDP headers); the rest waits in its bounded queue."""
        n = len(self.peers)
        if n == 0:
            return 0
        budget, sent, progressed, deferred = self.lim["control_per_pump"], 0, True, False
        while budget > 0 and progressed:
            progressed = False
            for step in range(n):
                if budget == 0:
                    break
                p = self.peers[(self.control_cursor + step) % n]
                if not p.control_q:
                    continue
                cost = CONTROL_LEN + OVERHEAD[p.ipv6]
                if not self.control_pacer.can_afford(cost) or not self.pacer.can_afford(cost):
                    deferred = True
                    continue
                tag = p.control_q.popleft()
                self.control_pacer.spend(cost)
                self.pacer.spend(cost)
                self.control_spent += cost
                p.counters["control_sent"] += 1
                self.control_emitted.append((p.id, tag))
                sent += 1
                budget -= 1
                progressed = True
        if deferred:
            self.control_pace_limited_pumps += 1
        self.control_cursor = (self.control_cursor + 1) % n
        return sent

    def _expire_late(self, now):
        dropped = 0
        for p in self.peers:
            keep = deque()
            for entry in p.media_q:
                if now > entry["consume_by"]:
                    p.media_q_bytes -= entry["wire_len"]
                    p.drop(entry, "late")
                    dropped += 1
                else:
                    keep.append(entry)
            p.media_q = keep
        return dropped

    def _next_sendable(self, now):
        n = len(self.peers)
        window = self.lim["window_packets"]
        for step in range(n):
            idx = (self.media_cursor + step) % n
            p = self.peers[idx]
            if p.fence is not None:
                continue
            if p.waiting(window):
                if p.probe_is_due(window, now):
                    return idx, p.last_sent[2] + OVERHEAD[p.ipv6]
                continue
            if p.media_q:
                return idx, p.media_q[0]["wire_len"] + OVERHEAD[p.ipv6]
        return None

    def _pump_media(self, now, out):
        n = len(self.peers)
        if n == 0:
            return
        attempts = 0    # every attempt on the media lane, a probe included, shares the one bound on a pump's work
        while True:
            if attempts >= self.lim["max_sends_per_pump"]:
                out["send_cap_hit"] = True
                self.stats["send_cap_pumps"] += 1
                break
            pick = self._next_sendable(now)
            if pick is None:
                break
            idx, cost = pick
            if not self.pacer.can_afford(cost):
                out["pace_limited"] = True
                out["next_send_ns"] = now + self.pacer.wait_ns(cost)
                self.stats["pace_limited_pumps"] += 1
                break
            p = self.peers[idx]
            window = self.lim["window_packets"]
            self.pacer.spend(cost)
            self.media_cursor = (idx + 1) % n
            attempts += 1
            if p.waiting(window):
                # a probe: the newest transmitted datagram again, same bytes and number; nothing is allocated, nothing is
                # held in the window, and it is counted apart from media
                seq, block, wire_len = p.last_sent
                p.probe_due = now + STALL_PROBE_NS
                self.probes_sent += 1
                self.probe_bytes += wire_len + OVERHEAD[p.ipv6]
                self.probe_emitted.append((p.id, self.epoch, seq, block, wire_len))
                continue
            entry = p.media_q.popleft()
            p.media_q_bytes -= entry["wire_len"]
            delay = max(now - entry["enq"], 0)
            seq = p.next_seq
            p.next_seq += 1
            p.sent_next = p.next_seq
            p.inflight.append(seq)
            p.last_sent = (seq, entry["block"], entry["wire_len"])
            p.probe_due = now + STALL_PROBE_NS if p.waiting(window) else None
            c = p.counters
            c["media_sent_packets"] += 1
            c["media_sent_bytes"] += entry["wire_len"]
            c["queue_delay_ns_total"] += delay
            c["queue_delay_ns_max"] = max(c["queue_delay_ns_max"], delay)
            out["media_sent"] += 1
            self.emitted.append((p.id, self.epoch, seq, entry["block"], entry["wire_len"]))

    def peer_view(self, p):
        window = self.lim["window_packets"]
        return {
            "peer": p.id, "fence": p.fence, "path_mtu": p.path_mtu, "queued_packets": len(p.media_q),
            "queued_bytes": p.media_q_bytes, "control_queued": len(p.control_q), "sent_next": p.sent_next,
            "reported_next": p.reported_next, "in_flight": len(p.inflight),
            "stalled": p.stalled(window), "counters": dict(p.counters),
        }


class ReplayWindow:
    """The N01 receiver's replay window (crates/franken-stream/src/lib.rs `ReplayWindow`), as sets."""

    def __init__(self, epoch):
        self.epoch, self.highest, self.seen = epoch, None, set()

    def advance_epoch(self, epoch):
        if epoch > self.epoch:
            self.epoch, self.highest, self.seen = epoch, None, set()

    def check(self, epoch, seq):
        if epoch < self.epoch:
            return "rejected_stale_epoch"
        if epoch > self.epoch:
            return "rejected_future_epoch"
        if self.highest is None:
            if seq > MAX_FORWARD_GAP:
                return "rejected_future_sequence"
            self.highest, self.seen = seq, {seq}
            return None
        if seq > self.highest:
            if seq - self.highest > MAX_FORWARD_GAP:
                return "rejected_future_sequence"
            self.highest = seq
            self.seen.add(seq)
            return None
        if self.highest - seq >= REPLAY_WINDOW or seq in self.seen:
            return "rejected_replay"
        self.seen.add(seq)
        return None


class Receiver:
    def __init__(self, limits, epoch):
        self.lim, self.window, self.inbound, self.consumed_next = limits, ReplayWindow(epoch), deque(), 0
        self.stats, self.counters = zero(RECEIVER_STATS), zero(STREAM_COUNTERS)
        self.control_inbox = deque()
        self.delivered, self.control_received = [], []

    @property
    def epoch(self):
        return self.window.epoch

    def on_media(self, epoch, seq, block):
        self.stats["media_read"] += 1
        self.counters["datagrams_seen"] += 1
        self.counters["mac_verifications"] += 1
        verdict = self.window.check(epoch, seq)
        if verdict is not None:
            self.counters[verdict] += 1
            self.stats["media_rejected"] += 1
            return
        self.counters["accepted"] += 1
        self.stats["media_accepted"] += 1
        if len(self.inbound) >= self.lim["inbound_packets"]:
            self.stats["inbound_overflow"] += 1
        else:
            self.inbound.append((epoch, seq, block))

    def on_control(self, tag):
        self.stats["control_read"] += 1
        if len(self.control_inbox) >= self.lim["control_inbox_packets"]:
            self.stats["control_dropped_full"] += 1
        else:
            self.control_inbox.append(tag)
            self.stats["control_delivered"] += 1

    def take_all(self):
        while self.inbound:
            epoch, seq, block = self.inbound.popleft()
            if epoch == self.window.epoch:
                self.consumed_next = max(self.consumed_next, seq + 1)
            self.delivered.append([epoch, seq, block])

    def advance_epoch(self, epoch):
        self.window.advance_epoch(epoch)
        self.inbound.clear()
        self.consumed_next = 0


class Relay:
    def __init__(self, cfg):
        self.loss, self.reorder, self.rng = cfg["loss_permille"], cfg["reorder_permille"], SplitMix64(cfg["seed"])
        self.lost = self.reordered = self.forwarded = 0

    def forward(self, datagrams):
        out, held = [], None
        for d in datagrams:
            if self.rng.next() % 1000 < self.loss:
                self.lost += 1
                continue
            roll = self.rng.next() % 1000
            if held is not None:
                out += [d, held]
                self.reordered += 1
                held = None
            elif roll < self.reorder:
                held = d
            else:
                out.append(d)
        if held is not None:
            out.append(held)
        self.forwarded += len(out)
        return out


class World:
    def __init__(self, scenario):
        self.sc = scenario
        self.lim = dict(BASELINE_LIMITS, **scenario.get("limits", {}))
        self.rlim = dict(BASELINE_RECEIVER, **scenario.get("receiver_limits", {}))
        self.epoch = scenario.get("epoch", 1)
        self.sender = Sender(self.lim, self.epoch)
        self.now = 0
        self.rig = {}          # peer id -> {"rx": Receiver, "relay": Relay|None, "consumer": bool}
        self.retired = {}      # peer id -> receivers of earlier address generations
        self.trace = []
        for spec in scenario["peers"]:
            self.add_peer(spec["peer"], spec["mtu"], "ok", spec.get("relay"))

    def add_peer(self, pid, mtu, kind, relay=None):
        code = self.sender.add_peer(pid, kind, mtu)
        if code == "ok":
            self.rig[pid] = {"rx": Receiver(self.rlim, self.epoch), "relay": Relay(relay) if relay else None, "consumer": True}
        return code

    # ---- deliver one pump's datagrams, then let consumers consume and report ----
    def pump_and_deliver(self):
        report = self.sender.pump(self.now)
        # The scripted worlds keep every peer's window open inside a probe interval, so none is probed; probes have their own
        # tests (the Rust unit tests over a genuine N01 receiver, and the anchors of test_judge.py). A script that probes must
        # first teach this world, and the Rust interpreter, to deliver and count the copy.
        assert not self.sender.probe_emitted, "a scripted world probed a peer"
        emitted, control = self.sender.emitted, self.sender.control_emitted
        for pid in sorted(self.rig):
            rig = self.rig[pid]
            mine = [(e, s, b) for (p, e, s, b, _w) in emitted if p == pid]
            for epoch, seq, block in (rig["relay"].forward(mine) if rig["relay"] else mine):
                rig["rx"].on_media(epoch, seq, block)
        for (pid, tag) in control:
            self.rig[pid]["rx"].on_control(tag)
        for pid in sorted(self.rig):
            rx = self.rig[pid]["rx"]
            while rx.control_inbox:
                rx.control_received.append(rx.control_inbox.popleft())
        if self.sender.link_up:
            for pid in sorted(self.rig):
                rig = self.rig[pid]
                if not rig["consumer"]:
                    continue
                rig["rx"].take_all()
                self.send_report(pid, rig["rx"], self.sender.peer(pid).generation)
        else:
            for pid in sorted(self.rig):
                if self.rig[pid]["consumer"]:
                    self.rig[pid]["rx"].take_all()
        return report

    def send_report(self, pid, rx, generation):
        rx.stats["reports_sent"] += 1
        self.sender.on_report(rx.epoch, rx.consumed_next, generation, pid)

    def block_args(self, block, deadline):
        return block, self.now + deadline

    def submit_block(self, block, deadline, epoch=None):
        return self.sender.submit_media(self.sender.epoch if epoch is None else epoch, *self.block_args(block, deadline), self.now)

    # ---- the script ----
    def run(self):
        for index, op in enumerate(self.sc["ops"]):
            result = self.apply(op)
            if result is not None:
                self.trace.append(dict(result, op=index, name=op["op"]))
        return self.record()

    def apply(self, op):
        name = op["op"]
        if name == "submit":
            total = {"queued": 0, "evicted": 0, "rejected_aggregate": 0, "skipped_fenced": 0}
            for b in range(op["first_block"], op["first_block"] + op["blocks"]):
                code, report = self.submit_block(b, op["deadline_ns"])
                assert code == "ok"
                for k in total:
                    total[k] += report[k]
            return {"submitted": op["blocks"], **total}
        if name == "stream":
            total = {"queued": 0, "evicted": 0, "rejected_aggregate": 0, "skipped_fenced": 0, "media_sent": 0, "control_sent": 0,
                     "late_dropped": 0}
            for b in range(op["first_block"], op["first_block"] + op["blocks"]):
                code, report = self.submit_block(b, op["deadline_ns"])
                assert code == "ok"
                for k in ("queued", "evicted", "rejected_aggregate", "skipped_fenced"):
                    total[k] += report[k]
                pump = self.pump_and_deliver()
                for k in ("media_sent", "control_sent", "late_dropped"):
                    total[k] += pump[k]
                self.now += op["period_ns"]
            return {"submitted": op["blocks"], **total}
        if name == "pump":
            return {"pump": self.pump_and_deliver()}
        if name == "settle":
            pumps = 0
            first = None
            for _ in range(64):
                report = self.pump_and_deliver()
                pumps += 1
                first = first or report
                if report["pace_limited"]:
                    self.now = report["next_send_ns"]
                else:
                    break
            return {"settle_pumps": pumps, "final_pump": report, "now_ns": self.now}
        if name == "advance":
            self.now += op["ns"]
            return None
        if name == "consumer":
            self.rig[op["peer"]]["consumer"] = op["active"]
            return None
        if name == "control":
            return {"code": self.sender.submit_control(op["peer"], op["tag"])}
        if name == "add_peer":
            return {"code": self.add_peer(op["peer"], op["mtu"], op.get("kind", "ok"), op.get("relay"))}
        if name == "remove_peer":
            self.sender.remove_peer(op["peer"])
            del self.rig[op["peer"]]
            return None
        if name == "set_mtu":
            return {"outcome": self.sender.set_path_mtu(op["peer"], op["mtu"])}
        if name == "link":
            self.sender.set_link_up(op["up"])
            return None
        if name == "epoch":
            self.sender.advance_epoch(op["to"])
            self.epoch = op["to"]
            for pid in self.rig:
                if pid not in op.get("skip_receivers", []):
                    self.rig[pid]["rx"].advance_epoch(op["to"])
            return None
        if name == "receiver_epoch":
            self.rig[op["peer"]]["rx"].advance_epoch(op["to"])
            return None
        if name == "stale_submit":
            code, _ = self.submit_block(0, 1_000_000, epoch=op["epoch"])
            return {"code": code}
        if name == "inject_old":
            self.rig[op["peer"]]["rx"].on_media(op["epoch"], 0, 0)
            return None
        if name == "addr_change":
            pid = op["peer"]
            old = self.rig[pid]["rx"]
            self.retired.setdefault(pid, []).append(old)
            self.sender.peer_address_changed(pid)
            self.rig[pid]["rx"] = Receiver(self.rlim, self.sender.epoch)
            return None
        if name == "old_report":
            pid = op["peer"]
            old = self.retired[pid][-1]
            self.send_report(pid, old, self.sender.peer(pid).generation - 1)
            return None
        raise ValueError("unknown op %r" % name)

    def record(self):
        peers = {}
        for pid in sorted(self.rig):
            rx, rig = self.rig[pid]["rx"], self.rig[pid]
            view = self.sender.peer_view(self.sender.peer(pid))
            peers[str(pid)] = {
                "view": view,
                "delivered": [list(d) for d in self._all_delivered(pid)],
                "control_received": list(self._all_control(pid)),
                "samples_checked": len(self._all_delivered(pid)),
                "sample_mismatches": 0,
                "receiver": {"stats": dict(rx.stats), "stream": dict(rx.counters), "consumed_next": rx.consumed_next,
                             "inbound_len": len(rx.inbound)},
                "relay": None if rig["relay"] is None else {"lost": rig["relay"].lost, "reordered": rig["relay"].reordered,
                                                           "forwarded": rig["relay"].forwarded},
            }
        return {"id": self.sc["id"], "final_now_ns": self.now, "trace": self.trace, "peers": peers,
                "stats": dict(self.sender.stats)}

    def _all_delivered(self, pid):
        out = []
        for rx in self.retired.get(pid, []) + [self.rig[pid]["rx"]]:
            out += rx.delivered
        return out

    def _all_control(self, pid):
        out = []
        for rx in self.retired.get(pid, []) + [self.rig[pid]["rx"]]:
            out += rx.control_received
        return out


def expected(scenario):
    return World(copy.deepcopy(scenario)).run()


def expected_observation(scenario):
    """Extend the original N01-only record with explicitly idle N06 telemetry.

    The committed v1 scenario vectors remain byte-for-byte unchanged. These
    worlds never select FEC or send its feedback: its five interface counters,
    five per-peer counters and pending flag must therefore be exactly zero or
    false. Only the EXPECTED side is extended; an actual missing, nonzero,
    mistyped or unknown field must still fail the strict comparison.
    """
    result = expected(scenario)
    for field in IDLE_FEC_CARRIER_STATS:
        if field in result["stats"]:
            raise ValueError("legacy interface expectation already has " + field)
        result["stats"][field] = 0
    for peer in result["peers"].values():
        view = peer["view"]
        if view is None:
            continue
        if "fec_feedback_pending" in view:
            raise ValueError("legacy peer expectation already has fec_feedback_pending")
        view["fec_feedback_pending"] = False
        for field in IDLE_FEC_PEER_COUNTERS:
            if field in view["counters"]:
                raise ValueError("legacy peer expectation already has " + field)
            view["counters"][field] = 0
    return result


# ---------------------------------------------------------------------------------------------------------------------------
# The scripted worlds. Every one runs the real carrier over real loopback sockets in the Rust test, and this model in Python.

def scenarios():
    two = [{"peer": 1, "mtu": 1500}, {"peer": 2, "mtu": 1500}]
    three = two + [{"peer": 3, "mtu": 1500}]
    return [
        {"id": "N07-S1-zero-loss-paced", "what": "two peers, no loss: every block delivered in order, paced, with control sent ahead",
         "limits": {"pace_bytes_per_sec": 500_000}, "peers": two,
         "ops": [{"op": "control", "peer": 1, "tag": 11},
                 {"op": "submit", "first_block": 0, "blocks": 16, "deadline_ns": 1_000_000_000},
                 {"op": "settle"}]},
        {"id": "N07-S2-slow-peer-isolated", "what": "peer 2 stops consuming and reporting: its window closes, its queue drops its own, the others are untouched, and it recovers with fresh audio only",
         "limits": {"window_packets": 8, "peer_queue_packets": 12, "peer_queue_bytes": 13_248, "aggregate_queue_packets": 30,
                    "aggregate_queue_bytes": 33_120},
         "receiver_limits": {"inbound_packets": 8}, "peers": three,
         "ops": [{"op": "consumer", "peer": 2, "active": False},
                 {"op": "stream", "first_block": 0, "blocks": 40, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "consumer", "peer": 2, "active": True},
                 {"op": "stream", "first_block": 40, "blocks": 20, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "settle"}]},
        {"id": "N07-S3-saturation-control-priority", "what": "media saturates the pacer and the aggregate cap: control still goes first in its pump, and media keeps its share",
         "limits": {"peer_load_bytes_per_sec": 50_000, "pace_bytes_per_sec": 300_000, "peer_queue_packets": 16, "peer_queue_bytes": 17_664,
                    "aggregate_queue_packets": 24, "aggregate_queue_bytes": 26_496, "window_packets": 64},
         "peers": three,
         "ops": [{"op": "submit", "first_block": 0, "blocks": 40, "deadline_ns": 1_000_000_000},
                 {"op": "control", "peer": 3, "tag": 9},
                 {"op": "pump"},
                 {"op": "control", "peer": 3, "tag": 10},
                 {"op": "pump"},
                 {"op": "remove_peer", "peer": 1},
                 {"op": "settle"}]},
        {"id": "N07-S4-epoch-fence", "what": "advancing the epoch drops what was queued, a send under the old epoch is refused, a late receiver rejects the new epoch and is rejected in turn",
         "limits": {"pace_bytes_per_sec": 500_000}, "peers": two,
         "ops": [{"op": "submit", "first_block": 0, "blocks": 12, "deadline_ns": 1_000_000_000},
                 {"op": "pump"},
                 {"op": "epoch", "to": 2, "skip_receivers": [1]},
                 {"op": "stale_submit", "epoch": 1},
                 {"op": "submit", "first_block": 100, "blocks": 6, "deadline_ns": 1_000_000_000},
                 {"op": "settle"},
                 {"op": "receiver_epoch", "peer": 1, "to": 2},
                 {"op": "inject_old", "peer": 2, "epoch": 1},
                 {"op": "submit", "first_block": 200, "blocks": 4, "deadline_ns": 1_000_000_000},
                 {"op": "settle"}]},
        {"id": "N07-S5-mtu-admission-address-family", "what": "a peer whose path cannot carry a block is refused or fenced without fragmenting and without disturbing the others; so are an over-budget peer, a LAN address and an undeclared address family",
         "limits": {"pace_bytes_per_sec": 500_000}, "peers": two,
         "ops": [{"op": "add_peer", "peer": 3, "mtu": 1100},
                 {"op": "add_peer", "peer": 3, "mtu": 1500},
                 {"op": "add_peer", "peer": 4, "mtu": 1500, "kind": "lan"},
                 {"op": "add_peer", "peer": 5, "mtu": 1500, "kind": "v6"},
                 {"op": "add_peer", "peer": 1, "mtu": 1500},
                 {"op": "stream", "first_block": 0, "blocks": 12, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "set_mtu", "peer": 2, "mtu": 1100},
                 {"op": "stream", "first_block": 12, "blocks": 12, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "set_mtu", "peer": 2, "mtu": 1500},
                 {"op": "stream", "first_block": 24, "blocks": 12, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "settle"}]},
        {"id": "N07-S6-link-and-address-change", "what": "a simulated link-down ages queued audio out instead of replaying it; a peer keeps its identity across an address change and the old path's reports are refused",
         "limits": {"pace_bytes_per_sec": 500_000}, "peers": two,
         "ops": [{"op": "stream", "first_block": 0, "blocks": 6, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "link", "up": False},
                 {"op": "stream", "first_block": 6, "blocks": 12, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "link", "up": True},
                 {"op": "stream", "first_block": 18, "blocks": 6, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "addr_change", "peer": 2},
                 {"op": "old_report", "peer": 2},
                 {"op": "stream", "first_block": 24, "blocks": 6, "period_ns": BLOCK_NS, "deadline_ns": 30_000_000},
                 {"op": "settle"}]},
        {"id": "N07-S7-loss-and-reorder", "what": "a seeded relay drops and reorders peer 1's datagrams on the way to its receiver; the replay window and the reports cope and the clean peer is unaffected",
         "limits": {"pace_bytes_per_sec": 500_000, "pace_burst_bytes": 65_536, "window_packets": 64},
         "peers": [{"peer": 1, "mtu": 1500, "relay": {"loss_permille": 150, "reorder_permille": 200, "seed": 7}}, {"peer": 2, "mtu": 1500}],
         "ops": [{"op": "submit", "first_block": 0, "blocks": 30, "deadline_ns": 1_000_000_000},
                 {"op": "settle"},
                 {"op": "submit", "first_block": 30, "blocks": 30, "deadline_ns": 1_000_000_000},
                 {"op": "settle"}]},
    ]


def document():
    out = []
    for sc in scenarios():
        sc = copy.deepcopy(sc)
        sc["expect"] = expected(sc)
        out.append(sc)
    return {"schema": "ffw.n07.scenarios.v1", "scenarios": out}


def render(doc):
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


def main(argv):
    if argv == ["--write"]:
        with open(SCENARIOS, "w", encoding="utf-8") as handle:
            handle.write(render(document()))
        print("wrote", os.path.relpath(SCENARIOS, REPO))
        return 0
    if argv == ["--check"]:
        try:
            with open(SCENARIOS, encoding="utf-8") as handle:
                same = handle.read() == render(document())
        except OSError:
            same = False
        print("scenario file is up to date" if same else "scenario file differs from a fresh generation")
        return 0 if same else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
