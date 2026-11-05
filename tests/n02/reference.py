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
import hashlib
import hmac
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
# Commands a remote controller must send with the revision it last read, besides the relative ones.
NEEDS_REVISION = {"set_member_volume", "set_group_volume", "set_member_mute"}

# Peers of every scenario: role, the epoch the key is bound to (None = not epoch-scoped), version.
PEERS = {
    "ctl-a": ("controller", 10),
    "ctl-b": ("controller", 10),
    "panel": ("local", None),
    "rogue": ("controller", 900),
}
START = {"epoch": 10, "revision": 2, "group": 50, "members": {"kitchen": 50, "den": 50}}
AUTH_CONTEXT = b"FFCP-v1-auth"  # hashed before every request, so a tag is tied to this protocol
FIXTURE_SESSION_SEQS = {1, 2}  # the two membership admissions the fixture session starts with


# ---------------------------------------------------------------- well-formedness

MEMBER_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
MAX_MEMBER_LEN = 64
MAX_DELTA = 100


def malformed(seq, rev, cmd):
    """Why the Rust `RequestBody::new` would refuse this request, or None if it would build it.

    The rules are copied from the contract (section 2), not from the Rust: a sequence of at least 1; a
    member label of 1..=64 characters from the label alphabet; a volume of at most 100; a nonzero
    delta of at most 100 in size; a relative command that names its revision; a cancel that names
    an earlier command and not itself. A vector or a scenario step that breaks one cannot be replayed
    by the Rust, so the Python side must not call it valid either."""
    kind = cmd["kind"]
    if seq < 1:
        return "zero sequence"
    member = cmd.get("member")
    if member is not None and not (0 < len(member) <= MAX_MEMBER_LEN and set(member) <= MEMBER_ALPHABET):
        return "invalid member id"
    if cmd.get("volume", 0) > 100:
        return "volume out of range"
    if "delta" in cmd and (cmd["delta"] == 0 or abs(cmd["delta"]) > MAX_DELTA):
        return "delta out of range"
    if kind in RELATIVE and rev is None:
        return "a relative command needs an expected revision"
    if kind == "cancel" and (cmd["target_seq"] < 1 or cmd["target_seq"] == seq):
        return "a cancel must name an earlier command, not itself"
    return None


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
        # The session refuses a command number it has already applied in this epoch.
        self.session_seqs = set(FIXTURE_SESSION_SEQS)
        self.next_seq = config["session_seq_base"]
        # The session revision at this incarnation's first step; None until then.
        self.floor = None
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
                "received", "unauthenticated", "epoch_not_bound", "revision_required", "rate_limited", "queue_full",
                "id_reuse", "from_ledger", "already_queued", "out_of_window", "accepted",
            ],
            0,
        )

    # -- session -------------------------------------------------------------

    def force_epoch(self, epoch):
        """A membership change under a newer epoch, outside the channel (one revision)."""
        self.epoch = epoch
        self.revision += 1
        self.session_seqs = {3}  # a new epoch drops the old record; the change itself used number 3

    def commit(self):
        self.revision += 1
        return self.revision

    def external_command(self, seq):
        """Another caller of the session, in the same epoch, applies a change under a number of its own."""
        self.session_seqs.add(seq)
        self.revision += 1

    def restart(self):
        """The channel restarts: every queue, limiter, outcome and the revision floor is forgotten and
        its counter starts again at the configured base. The group state, the session's record of
        applied numbers and the peer directory carry on."""
        self.queues = {"ordinary": [], "priority": []}
        self.limits = {}
        self.records = []
        self.floors = {}
        self.floor = None
        self.next_seq = self.cfg["session_seq_base"]

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
        if record["role"] == "controller" and cmd["kind"] in NEEDS_REVISION and rev is None:
            self.stats["revision_required"] += 1
            return "rejected:revision_required"
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
        if self.floor is None:
            self.floor = self.revision
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
            observed = item["rev"]
            if observed is not None:
                relative = item["cmd"]["kind"] in RELATIVE
                if observed > self.revision or (relative and observed != self.revision):
                    return "refused:revision_mismatch"
                if observed < self.floor:
                    return "refused:stale_revision"
        kind = cmd["kind"]
        if kind == "adjust_member_volume" and cmd["member"] not in self.members:
            return "refused:unknown_member"  # resolved in the channel, before a number is spent
        number = self._mint()
        if number in self.session_seqs:
            return "refused:internal_fault"  # the session already applied this number: not the sender's doing
        if kind in ("set_member_volume", "set_member_mute") and cmd["member"] not in self.members:
            return "refused:session"
        if kind == "set_group_volume":
            self.group = cmd["volume"]
        elif kind == "adjust_group_volume":
            self.group = min(100, max(0, self.group + cmd["delta"]))
        elif kind == "set_member_volume":
            self.members[cmd["member"]]["volume"] = cmd["volume"]
        elif kind == "adjust_member_volume":
            member = self.members[cmd["member"]]
            member["volume"] = min(100, max(0, member["volume"] + cmd["delta"]))
        elif kind == "set_member_mute":
            self.members[cmd["member"]]["muted"] = cmd["muted"]
        elif kind == "stop":
            self.stopped = True
        self.session_seqs.add(number)
        return f"committed:{self.commit()}"

    def _mint(self):
        """The next session command number: at least the counter, and at least base + revision. The
        revision only ever grows, so a restarted channel lands above everything its predecessor used;
        the counter keeps a refused number (which the revision does not move on) from being tried twice."""
        number = max(self.next_seq, self.cfg["session_seq_base"] + self.revision)
        self.next_seq = number + 1
        return number

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
            why = malformed(step["seq"], step["rev"], step["cmd"])
            if why:
                problems.append(f"{where}: the Rust body constructor refuses this request ({why})")
                continue
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
        elif op == "restart":
            model.restart()
        elif op == "external_command":
            model.external_command(step["seq"])
        else:
            problems.append(f"{where}: unknown op")
    if model.final() != scenario["final"]:
        problems.append(f"{scenario['id']} final: expected {scenario['final']!r}, got {model.final()!r}")
    if model.accounted() != model.stats["received"]:
        problems.append(f"{scenario['id']} accounting: {model.stats!r}")
    return problems


def proof(key, message):
    """HMAC-SHA256 over the context label then the signed bytes, from the standard library."""
    return hmac.new(key, AUTH_CONTEXT + message, hashlib.sha256).digest()


def request_bytes(vector):
    return signing_bytes(vector["peer"], vector["seq"], vector["epoch"], vector["rev"], vector["cmd"])


def check_vectors(doc):
    problems = []
    signing = {v["id"]: v for v in doc["signing_vectors"]}
    for vector in list(doc["signing_vectors"]) + list(doc["tamper_vectors"]):
        why = malformed(vector["seq"], vector["rev"], vector["cmd"])
        if why:
            problems.append(f"{vector['id']}: the Rust body constructor refuses this request ({why})")
    for vector in doc["signing_vectors"]:
        got = request_bytes(vector).hex()
        if got != vector["hex"]:
            problems.append(f"{vector['id']}: expected {vector['hex']}, built {got}")
    auth = {a["id"]: a for a in doc["auth_vectors"]}
    for vector in doc["auth_vectors"]:
        source = signing[vector["signing_vector"]]
        got = proof(vector["key"].encode("ascii"), bytes.fromhex(source["hex"])).hex()
        if got != vector["tag_hex"]:
            problems.append(f"{vector['id']}: expected {vector['tag_hex']}, computed {got}")
        if len(vector["tag_hex"]) != 64:
            problems.append(f"{vector['id']}: the tag is not 32 bytes")
    for tamper in doc["tamper_vectors"]:
        base = auth[tamper["auth_vector"]]
        original = bytes.fromhex(signing[base["signing_vector"]]["hex"])
        changed = request_bytes(tamper)
        if changed == original:
            problems.append(f"{tamper['id']}: the tamper does not change the signed bytes")
        # The claimed peer's own key, as the directory would use, under the original tag.
        key = f"key-{tamper['peer']}-0123456789abcdef".encode("ascii")
        if hmac.compare_digest(proof(key, changed), bytes.fromhex(base["tag_hex"])):
            problems.append(f"{tamper['id']} ({tamper['field']}): the original tag still verifies")
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
          f"{len(doc['signing_vectors'])} signing vectors, {len(doc['auth_vectors'])} hmac vectors, "
          f"{len(doc['tamper_vectors'])} tampers, {len(problems)} mismatches)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
