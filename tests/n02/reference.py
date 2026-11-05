#!/usr/bin/env python3
"""Independent reference model of the N02 bounded control channel (bead ffw-ugf).

Written from docs/contracts/n02.md, not by porting crates/franken-control/src/channel. It is
deliberately built differently from the Rust:

* time is whole milliseconds and the rate limiter is a GCRA (theoretical arrival time), where the
  Rust uses a token bucket with a refill loop; tests/n02/test_reference_model.py checks that the two
  formulations agree on random schedules;
* the outcome memory is one ordered list of records plus a floor table, with lookups done by scan;
* "stopped" is a flag on the model, where the Rust reads each member's lifecycle back.

It replays crates/franken-control/tests/vectors/n02_scenarios.json, whose expectations were worked
out by hand before either implementation produced them, and checks the signing-bytes vectors with
an encoder written here from the byte layout in the contract.

    python3 -B -I tests/n02/reference.py [--check]      replay every scenario and vector, exit 1 on any mismatch

There is no --write: the vectors are hand-written on purpose. A generator that wrote its own
expectations would only ever agree with itself.

THIS DOES NOT RUN THE RUST. It shows that the vectors are self-consistent and that an independently
built model reaches them. The Rust half runs only in the centralized builds:
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-control
"""

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTORS = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_scenarios.json"

LANE = {
    "set_member_volume": "ordinary",
    "set_group_volume": "ordinary",
    "adjust_member_volume": "ordinary",
    "adjust_group_volume": "ordinary",
    "set_member_mute": "priority",
    "stop": "priority",
    "cancel": "priority",
}
RELATIVE = {"adjust_member_volume", "adjust_group_volume"}

# Peers of every scenario: role, the epoch the key is bound to (None = not epoch-scoped), version.
PEERS = {
    "ctl-a": ("controller", 10),
    "ctl-b": ("controller", 10),
    "panel": ("local", None),
    "rogue": ("controller", 900),
}
START = {"epoch": 10, "revision": 2, "group": 50, "members": {"kitchen": 50, "den": 50}}
SESSION_SEQ_BASE = 1000  # only matters to the Rust; recorded here so the vectors state it


# ---------------------------------------------------------------- signing bytes


def label(text):
    raw = text.encode("ascii")
    assert 0 < len(raw) < 256
    return bytes([len(raw)]) + raw


def signing_bytes(peer, seq, epoch, rev, cmd):
    """The bytes a proof covers, built from the layout in the contract (big-endian throughout)."""
    out = b"FFCP" + bytes([1]) + label(peer) + struct.pack(">QQ", seq, epoch)
    out += b"\x00" if rev is None else b"\x01" + struct.pack(">Q", rev)
    kind = cmd["kind"]
    if kind == "set_member_volume":
        out += b"\x01" + label(cmd["member"]) + bytes([cmd["volume"]])
    elif kind == "set_group_volume":
        out += b"\x02" + bytes([cmd["volume"]])
    elif kind == "adjust_member_volume":
        out += b"\x03" + label(cmd["member"]) + struct.pack(">b", cmd["delta"])
    elif kind == "adjust_group_volume":
        out += b"\x04" + struct.pack(">b", cmd["delta"])
    elif kind == "set_member_mute":
        out += b"\x05" + label(cmd["member"]) + bytes([1 if cmd["muted"] else 0])
    elif kind == "stop":
        out += b"\x06" + struct.pack(">QQ", cmd["now_ns"], cmd["tail_ns"])
    elif kind == "cancel":
        out += b"\x07" + struct.pack(">Q", cmd["target_seq"])
    else:
        raise ValueError(kind)
    return out


# ---------------------------------------------------------------- the model


class Gcra:
    """Rate limit as a theoretical arrival time. `burst` requests may arrive together; after that
    one more is allowed per `interval` ms. Returns None when allowed, else the wait in ms."""

    def __init__(self, burst, interval):
        self.burst, self.interval = burst, interval
        self.tat = None  # unset until the first request

    def take(self, now):
        if self.tat is None:
            self.tat = now
        new_tat = max(now, self.tat) + self.interval
        if new_tat - now > self.burst * self.interval:
            return new_tat - self.burst * self.interval - now
        self.tat = new_tat
        return None


class Model:
    def __init__(self, config):
        self.cfg = config
        self.epoch = START["epoch"]
        self.revision = START["revision"]
        self.group = START["group"]
        self.members = {name: {"volume": v, "muted": False} for name, v in START["members"].items()}
        self.stopped = False
        # peer directory
        self.peers = {n: {"role": r, "bound": b, "version": 1} for n, (r, b) in PEERS.items()}
        self.revoked = set()
        # queues hold dicts; ordinary and priority are separate lists, oldest first
        self.queues = {"ordinary": [], "priority": []}
        self.limits = {}
        # outcome memory: ordered records, oldest first, and per-peer floors
        self.records = []
        self.floors = {}
        self.clock = 0
        self.stats = dict.fromkeys(
            [
                "received", "unauthenticated", "epoch_not_bound", "rate_limited", "queue_full",
                "id_reuse", "from_ledger", "already_queued", "out_of_window", "accepted",
            ],
            0,
        )

    # -- session -------------------------------------------------------------

    def force_epoch(self, epoch):
        """A membership change under a newer epoch, outside the channel (one revision)."""
        self.epoch = epoch
        self.revision += 1

    def commit(self):
        self.revision += 1
        return self.revision

    def restart(self):
        """The channel process restarts: every queue, limiter and outcome is forgotten, the group state
        and the peer directory are not. Used only by the hazard test; no golden scenario restarts."""
        self.queues = {"ordinary": [], "priority": []}
        self.limits = {}
        self.records = []
        self.floors = {}

    # -- authority -----------------------------------------------------------

    def revoke(self, peer):
        if peer in self.peers:
            del self.peers[peer]
            self.revoked.add(peer)

    def rebind(self, peer, epoch):
        self.peers[peer]["bound"] = epoch
        self.peers[peer]["version"] += 1

    # -- outcome memory ------------------------------------------------------

    def _forget(self, record):
        self.records.remove(record)
        self.floors[record["peer"]] = max(self.floors.get(record["peer"], 0), record["seq"])

    def _age_out(self, now):
        self.clock = max(self.clock, now)
        while self.records and self.clock - self.records[0]["at"] >= self.cfg["retention_ms"]:
            self._forget(self.records[0])

    def _find(self, peer, seq):
        return next((r for r in self.records if r["peer"] == peer and r["seq"] == seq), None)

    def _remember(self, item, outcome, now):
        self._age_out(now)
        if self._find(item["peer"], item["seq"]):
            return
        while len(self.records) >= self.cfg["ledger_capacity"]:
            self._forget(self.records[0])
        self.records.append(
            {"peer": item["peer"], "seq": item["seq"], "body": body_of(item), "outcome": outcome,
             "at": self.clock}
        )

    # -- submit --------------------------------------------------------------

    def _rate(self, peer, lane, now):
        key = (peer, lane)
        if key not in self.limits:
            burst, interval = self.cfg[lane + "_rate"]
            self.limits[key] = Gcra(burst, interval)
        return self.limits[key].take(now)

    def _room(self, lane, role):
        if lane == "ordinary":
            return len(self.queues["ordinary"]) < self.cfg["ordinary_capacity"]
        reserved, shared = self.cfg["priority_local_reserved"], self.cfg["priority_shared_capacity"]
        local = sum(1 for q in self.queues["priority"] if q["role"] == "local")
        remote = len(self.queues["priority"]) - local
        free_shared = shared - remote - max(0, local - reserved)
        if role == "local":
            return local < reserved or free_shared > 0
        return free_shared > 0

    def submit(self, now, peer, seq, epoch, rev, cmd, forged=False):
        self.stats["received"] += 1
        # 1. who is calling
        if peer not in self.peers:
            self.stats["unauthenticated"] += 1
            return "rejected:unauthenticated:" + ("revoked" if peer in self.revoked else "unknown_peer")
        if forged:
            self.stats["unauthenticated"] += 1
            return "rejected:unauthenticated:bad_proof"
        record = self.peers[peer]
        # 2. a key bound to one epoch speaks only in that epoch
        if record["bound"] is not None and record["bound"] != epoch:
            self.stats["epoch_not_bound"] += 1
            return "rejected:epoch_not_bound"
        # 3. rate
        lane = LANE[cmd["kind"]]
        wait = self._rate(peer, lane, now)
        if wait is not None:
            self.stats["rate_limited"] += 1
            return f"rejected:rate_limited:{lane}:{wait}"
        item = {"peer": peer, "seq": seq, "epoch": epoch, "rev": rev, "cmd": cmd, "role": record["role"],
                "version": record["version"], "accepted": now, "lane": lane}
        # 4. a copy that is waiting, an outcome on record, a number forgotten
        for queue_lane in ("priority", "ordinary"):
            for waiting in self.queues[queue_lane]:
                if waiting["peer"] == peer and waiting["seq"] == seq:
                    if body_of(waiting) == body_of(item):
                        self.stats["already_queued"] += 1
                        return f"already_queued:{queue_lane}"
                    self.stats["id_reuse"] += 1
                    return "rejected:id_reuse"
        self._age_out(now)
        known = self._find(peer, seq)
        if known:
            if known["body"] == body_of(item):
                self.stats["from_ledger"] += 1
                return "settled:" + known["outcome"]
            self.stats["id_reuse"] += 1
            return "rejected:id_reuse"
        if peer in self.floors and seq <= self.floors[peer]:
            self.stats["out_of_window"] += 1
            return f"out_of_window:{self.floors[peer]}"
        # 5. room
        if not self._room(lane, record["role"]):
            self.stats["queue_full"] += 1
            return f"rejected:queue_full:{lane}"
        self.queues[lane].append(item)
        self.stats["accepted"] += 1
        return f"queued:{lane}"

    # -- step ----------------------------------------------------------------

    def step(self, now):
        self._age_out(now)
        done = []

        def settle(item, outcome):
            self._remember(item, outcome, now)
            done.append(f"{item['peer']}#{item['seq']}={outcome}")

        for lane in ("priority", "ordinary"):
            stale = [q for q in self.queues[lane] if now - q["accepted"] >= self.cfg["pending_ttl_ms"]]
            self.queues[lane] = [q for q in self.queues[lane] if q not in stale]
            for item in stale:
                settle(item, "refused:expired")
        for _ in range(self.cfg["max_per_step"]):
            item = self._next()
            if item is None:
                break
            settle_cancelled = []
            outcome = self._execute(item, settle_cancelled)
            for withdrawn in settle_cancelled:
                settle(withdrawn, "withdrawn")
            settle(item, outcome)
        return done

    def _next(self):
        priority = self.queues["priority"]
        if priority:
            pick = next((q for q in priority if q["role"] == "local"), priority[0])
            priority.remove(pick)
            return pick
        if self.queues["ordinary"]:
            return self.queues["ordinary"].pop(0)
        return None

    def _execute(self, item, withdrawn):
        peer = self.peers.get(item["peer"])
        if peer is None or peer["version"] != item["version"]:
            return "refused:authority_expired"
        cmd = item["cmd"]
        if cmd["kind"] == "cancel":
            return self._cancel(item, withdrawn)
        if item["role"] == "controller":
            if item["epoch"] < self.epoch:
                return "refused:stale_epoch"
            if item["epoch"] > self.epoch:
                return "refused:epoch_ahead"
            if item["rev"] is not None and item["rev"] != self.revision:
                return "refused:revision_mismatch"
        kind = cmd["kind"]
        if kind == "set_group_volume":
            self.group = cmd["volume"]
        elif kind == "adjust_group_volume":
            self.group = min(100, max(0, self.group + cmd["delta"]))
        elif kind in ("set_member_volume", "adjust_member_volume", "set_member_mute"):
            member = self.members.get(cmd["member"])
            if member is None:
                # A relative command resolves its member in the channel; the others reach the session.
                return "refused:unknown_member" if kind == "adjust_member_volume" else "refused:session"
            if kind == "set_member_volume":
                member["volume"] = cmd["volume"]
            elif kind == "adjust_member_volume":
                member["volume"] = min(100, max(0, member["volume"] + cmd["delta"]))
            else:
                member["muted"] = cmd["muted"]
        elif kind == "stop":
            self.stopped = True
        return f"committed:{self.commit()}"

    def _cancel(self, item, withdrawn):
        target = item["cmd"]["target_seq"]
        for queued in self.queues["ordinary"]:
            if queued["peer"] == item["peer"] and queued["seq"] == target:
                self.queues["ordinary"].remove(queued)
                withdrawn.append(queued)
                return f"cancel_applied:{target}"
        if any(q["peer"] == item["peer"] and q["seq"] == target for q in self.queues["priority"]):
            return "refused:not_cancellable"
        if self._find(item["peer"], target):
            return "refused:too_late_to_cancel"
        if item["peer"] in self.floors and target <= self.floors[item["peer"]]:
            return "refused:target_out_of_window"
        return "refused:nothing_to_cancel"

    # -- reading it back -----------------------------------------------------

    def final(self):
        return {
            "revision": self.revision,
            "epoch": self.epoch,
            "group_volume": self.group,
            "kitchen": self.members["kitchen"]["volume"],
            "den": self.members["den"]["volume"],
            "muted": sorted(n for n, m in self.members.items() if m["muted"]),
            "stopped": self.stopped,
        }

    def accounted(self):
        return sum(v for k, v in self.stats.items() if k != "received")


def body_of(item):
    """What identifies a request for the purpose of telling a retry from a different request."""
    return (item["peer"], item["seq"], item["epoch"], item["rev"], json.dumps(item["cmd"], sort_keys=True))


# ---------------------------------------------------------------- replay


def config_for(doc, scenario):
    cfg = dict(doc["base_config"])
    cfg.update(scenario.get("config", {}))
    return cfg


def replay(doc, scenario, model_class=Model):
    """Replay one scenario; return a list of mismatch descriptions (empty means it matched)."""
    problems = []
    model = model_class(config_for(doc, scenario))
    for index, step in enumerate(scenario["steps"]):
        where = f"{scenario['id']} step {index} ({step['op']})"
        op = step["op"]
        if op == "submit":
            for repeat in range(step.get("repeat", 1)):
                got = model.submit(
                    step["at_ms"], step["peer"], step["seq"], step["epoch"], step["rev"], step["cmd"],
                    forged=step.get("proof") == "forged",
                )
                if got != step["expect"]:
                    problems.append(f"{where} repeat {repeat}: expected {step['expect']!r}, got {got!r}")
                    break
        elif op == "step":
            got = model.step(step["at_ms"])
            if got != step["expect"]:
                problems.append(f"{where}: expected {step['expect']!r}, got {got!r}")
        elif op == "session_epoch":
            model.force_epoch(step["epoch"])
        elif op == "rebind":
            model.rebind(step["peer"], step["epoch"])
        elif op == "revoke":
            model.revoke(step["peer"])
        else:
            problems.append(f"{where}: unknown op")
    if model.final() != scenario["final"]:
        problems.append(f"{scenario['id']} final: expected {scenario['final']!r}, got {model.final()!r}")
    if model.accounted() != model.stats["received"]:
        problems.append(f"{scenario['id']} accounting: {model.stats!r}")
    return problems


def check_vectors(doc):
    problems = []
    for vector in doc["signing_vectors"]:
        got = signing_bytes(vector["peer"], vector["seq"], vector["epoch"], vector["rev"], vector["cmd"]).hex()
        if got != vector["hex"]:
            problems.append(f"{vector['id']}: expected {vector['hex']}, built {got}")
    return problems


def load(path=DEFAULT_VECTORS):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="the default; kept for symmetry with N01")
    parser.add_argument("--vectors", default=str(DEFAULT_VECTORS))
    args = parser.parse_args(argv)
    doc = load(args.vectors)
    problems = check_vectors(doc)
    for scenario in doc["scenarios"]:
        problems += replay(doc, scenario)
    for line in problems:
        print("MISMATCH", line, file=sys.stderr)
    status = "FAIL" if problems else "PASS"
    print(f"N02 reference: {status} ({len(doc['scenarios'])} scenarios, "
          f"{len(doc['signing_vectors'])} signing vectors, {len(problems)} mismatches)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
