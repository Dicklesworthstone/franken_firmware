#!/usr/bin/env python3
"""Independent reference model of the G01 group membership engine (bead ffw-kh0).

Written from docs/contracts/g01.md, not by porting crates/franken-session/src/membership.rs. It covers
both slices: the membership cutover protocol (propose, acknowledge, commit, activate, missing-ack
policy, exclusion and unresolved output, epoch advance) and the lease clause (quorum renewal,
takeover, partitions, fencing, the lease-expiry playback policy, the durable voter record).

It is deliberately built differently from the Rust where that is cheap:

* a lease voter keeps ONE ledger keyed by epoch (holder, expiry, confirmed or only granted), where
  the Rust keeps a confirmed view plus one grant. The two are the same rules in different state;
  tests/g01/test_reference_model.py runs the Rust's formulation next to this one on the seeded
  schedules and requires identical counts;
* every rule is a field of `Rules`, so a broken variant is one flag away and the tests can show the
  scenarios and the schedule actually notice each rule being removed;
* time is whole nanoseconds and frames, as plain integers.

It replays crates/franken-session/tests/vectors/g01_scenarios.json, whose expectations were worked out
by hand from the contract before either implementation produced them, and it predicts the exact
counts of the seeded partition schedule (the same SplitMix64 and draw order as the Rust test).

    python3 -B -I tests/g01/reference.py [--check]      replay every scenario, exit 1 on any mismatch
    python3 -B -I tests/g01/reference.py --print-schedule   print the model's schedule counts

There is no --write: the scenario expectations are hand-written on purpose. The schedule counts in the
vector file are the model's output (that is what they are for: a differential check once the Rust
replays them), and --check refuses any drift between them and the model.

The author of this model also wrote the Rust. It checks arithmetic, consistency between the contract
and the code, and that the scenarios can fail; it does not check the design.

THIS DOES NOT RUN THE RUST. It shows the vectors are self-consistent and that an independently built
model reaches them. The Rust half runs only in the centralized builds:
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-session
"""

import argparse
import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTORS = ROOT / "crates" / "franken-session" / "tests" / "vectors" / "g01_scenarios.json"

MAX_TERMINAL_HISTORY = 64
GROUP = "grp"
READY_FLAGS = ("format_ok", "buffer_ok", "clock_confident", "can_stop_flush")
INELIGIBLE_PREFIX = "hypothesis:"  # a board named so fails the offline admission gate


class Refuse(Exception):
    """A refusal with its stable code and the numbers the Rust error carries."""

    def __init__(self, code, **details):
        super().__init__(code)
        self.code = code
        self.details = details


@dataclasses.dataclass
class Rules:
    """Every rule of the contract as a switch. All True is the contract; a False is a broken variant."""

    majority: bool = True  # a quorum is a strict majority (False: one acknowledgement wins)
    expiry_wait: bool = True  # a takeover waits for the latest known expiry plus u
    one_candidate: bool = True  # one candidate per epoch (False: a rival overwrites the grant)
    next_epoch_only: bool = True  # a takeover is for highest + 1 (False: any higher epoch)
    renew_extends_view: bool = True  # acknowledging a renewal extends the voter's view of the lease
    refuse_older_renewal: bool = True  # a voter that saw a newer epoch refuses an older one's renewal
    refuse_unknown_renewal: bool = True  # an epoch nobody was granted cannot be minted by renewing it
    epoch_first: bool = True  # tokens are judged by epoch before issuer
    holder_margin: bool = True  # the holder stops u before its lease ends
    round_deadline: bool = True  # a round is over once the proposed lease is within u of ending
    needs_live_lease_for_grant: bool = True  # no live lease, no new output grant
    assume_gate: bool = True  # a takeover gates conflicting programs
    winner_observes: bool = True  # the winner's own voter learns its lease (the cluster applies this)
    durable_record: bool = True  # a restarted voter refuses until its record is restored
    mint_exclusive: bool = True  # advance_epoch refuses in a quorum group, quorum calls in an issuer group
    abort_on_epoch_change: bool = True  # a new epoch aborts the proposal in flight
    exclusion_unresolved: bool = True  # an excluded member's output stays unresolved
    commit_checks_tail: bool = True  # the cutover may not precede an irrevocable output tail
    evidence_never_shortens: bool = True  # a later bound replaces an earlier one only if later


@dataclasses.dataclass
class Config:
    mode: str = "issuer"  # "issuer" (advance_epoch is the only mint) or "quorum"
    policy: str = "abort"  # missing-ack policy: "abort" or "exclude"
    max_members: int = 32
    lead: int = 4800
    max_lease: int = 5_000_000_000
    u: int = 0
    horizon_ns: int = 10_000_000_000
    horizon_frames: int = 480_000

    @staticmethod
    def of(raw):
        c = Config()
        known = {f.name for f in dataclasses.fields(Config)}
        for key, value in (raw or {}).items():
            if key in known:
                setattr(c, key, value)
        return c


# ---------------------------------------------------------------------------------------- tokens


def token_of(group, issuer, epoch, expires):
    return {"group": group, "issuer": issuer, "epoch": epoch, "expires": expires}


class Session:
    """What the engine reads and changes of the group: epoch, issuer, members, revision."""

    def __init__(self, coordinator, group=GROUP):
        self.group, self.coord, self.epoch = group, coordinator, 1
        self.members = {"a": "ready", "b": "ready"}
        self.revision = 2

    def begin_epoch(self, epoch):
        self.epoch = epoch
        self.revision += 1


def authorize(rules, session, token, now_ns, margin):
    """The one authority rule every mutation applies (contract section 1)."""
    if token["group"] != session.group:
        raise Refuse("WRONG_GROUP")
    stale = token["epoch"] < session.epoch
    future = token["epoch"] > session.epoch
    wrong_issuer = token["issuer"] != session.coord
    if rules.epoch_first:
        if stale:
            raise Refuse("STALE_AUTHORITY", token_epoch=token["epoch"], current_epoch=session.epoch)
        if future:
            raise Refuse("FUTURE_AUTHORITY", token_epoch=token["epoch"], current_epoch=session.epoch)
        if wrong_issuer:
            raise Refuse("NOT_CONFIGURED_ISSUER")
    else:
        if wrong_issuer:
            raise Refuse("NOT_CONFIGURED_ISSUER")
        if stale:
            raise Refuse("STALE_AUTHORITY", token_epoch=token["epoch"], current_epoch=session.epoch)
        if future:
            raise Refuse("FUTURE_AUTHORITY", token_epoch=token["epoch"], current_epoch=session.epoch)
    if now_ns + margin >= token["expires"]:
        raise Refuse("AUTHORITY_EXPIRED", expires_at_ns=token["expires"], now_ns=now_ns)


# ---------------------------------------------------------------------------------- lease voters


class Voter:
    """One member of the electorate. The state is a ledger keyed by epoch.

    An entry is either confirmed (the holder is known to hold the epoch) or only granted (this voter
    promised the epoch to a candidate). Confirming an epoch drops every entry at or below it."""

    def __init__(self, vid, electorate, group, terms, rules):
        self.id, self.electorate, self.group = vid, electorate, group
        self.terms, self.rules = terms, rules
        self.ledger = {}
        self.trusted = True

    # -- the state the contract talks about
    def high(self):
        return max(self.ledger) if self.ledger else None

    def latest(self):
        return max((e["expires"] for e in self.ledger.values()), default=0)

    def confirmed_epoch(self):
        confirmed = [k for k, e in self.ledger.items() if e["confirmed"]]
        return max(confirmed) if confirmed else None

    def confirm(self, epoch, holder, expires):
        self.ledger = {k: e for k, e in self.ledger.items() if k > epoch}
        self.ledger[epoch] = {"holder": holder, "expires": expires, "confirmed": True, "prior": 0}

    def record(self):
        epoch = self.confirmed_epoch()
        view = None
        if epoch is not None:
            e = self.ledger[epoch]
            view = {"epoch": epoch, "holder": e["holder"], "expires": e["expires"]}
        grants = [k for k, e in self.ledger.items() if not e["confirmed"]]
        grant = None
        if grants:
            e = self.ledger[grants[0]]
            grant = {"epoch": grants[0], "candidate": e["holder"], "expires": e["expires"], "prior": e["prior"]}
        return {"voter_id": self.id, "view": view, "grant": grant}

    def restore(self, record):
        if record["voter_id"] != self.id:
            raise Refuse("VOTER_RECORD_UNAVAILABLE")
        self.ledger = {}
        if record["view"]:
            v = record["view"]
            self.ledger[v["epoch"]] = {"holder": v["holder"], "expires": v["expires"], "confirmed": True, "prior": 0}
        if record["grant"]:
            g = record["grant"]
            self.ledger[g["epoch"]] = {
                "holder": g["candidate"], "expires": g["expires"], "confirmed": False, "prior": g["prior"],
            }
        self.trusted = True

    # -- what a voter is told
    def observe(self, view):
        if view.get("group", self.group) != self.group:
            raise Refuse("WRONG_GROUP")
        if view["holder"] not in self.electorate:
            raise Refuse("NOT_A_VOTER", member_id=view["holder"])
        high = self.high()
        if high is not None and view["epoch"] < high:
            raise Refuse("STALE_AUTHORITY", token_epoch=view["epoch"], current_epoch=high)
        expires = view["expires"]
        entry = self.ledger.get(view["epoch"])
        if entry and entry["confirmed"]:
            if entry["holder"] != view["holder"]:
                raise Refuse(
                    "CONFLICTING_LEADERS", epoch=view["epoch"], held_by=entry["holder"], announced_by=view["holder"]
                )
            expires = max(expires, entry["expires"])
        self.confirm(view["epoch"], view["holder"], expires)

    # -- the requests a voter makes
    def make_request(self, kind, epoch, now, length):
        if length > self.terms["max_lease"]:
            raise Refuse("LEASE_TOO_LONG", expires_at_ns=now + length, max_ns=now + self.terms["max_lease"])
        return {"kind": kind, "group": self.group, "requester": self.id, "epoch": epoch, "expires": now + length}

    def renew_request(self, now, length):
        epoch = self.confirmed_epoch()
        if epoch is None:
            raise Refuse("NO_LEASE_VIEW")
        holder = self.ledger[epoch]["holder"]
        if holder != self.id:
            raise Refuse("NOT_LEASE_HOLDER", epoch=epoch, holder=holder)
        return self.make_request("renew", epoch, now, length)

    def takeover_request(self, now, length):
        high = self.high()
        if high is None:
            raise Refuse("NO_LEASE_VIEW")
        own = [k for k, e in self.ledger.items() if not e["confirmed"] and e["holder"] == self.id]
        return self.make_request("takeover", own[0] if own else high + 1, now, length)

    # -- the requests a voter answers
    def respond(self, req, now):
        if self.rules.durable_record and not self.trusted:
            raise Refuse("VOTER_RECORD_UNAVAILABLE")
        if req["group"] != self.group:
            raise Refuse("WRONG_GROUP")
        if req["requester"] not in self.electorate:
            raise Refuse("NOT_A_VOTER", member_id=req["requester"])
        prior = self._renewal(req) if req["kind"] == "renew" else self._takeover(req, now)
        return {
            "kind": req["kind"], "group": req["group"], "voter": self.id, "requester": req["requester"],
            "epoch": req["epoch"], "expires": req["expires"], "prior": prior,
        }

    def _renewal(self, req):
        high = self.high()
        if high is None:
            raise Refuse("NO_LEASE_VIEW")
        if self.rules.refuse_older_renewal and req["epoch"] < high:
            raise Refuse("STALE_AUTHORITY", token_epoch=req["epoch"], current_epoch=high)
        entry = self.ledger.get(req["epoch"])
        if entry is None:
            if self.rules.refuse_unknown_renewal:
                raise Refuse("FUTURE_AUTHORITY", token_epoch=req["epoch"], current_epoch=high)
            expires = req["expires"]
        else:
            if entry["holder"] != req["requester"]:
                raise Refuse("NOT_LEASE_HOLDER", epoch=req["epoch"], holder=entry["holder"])
            expires = max(req["expires"], entry["expires"])
        if self.rules.renew_extends_view:
            self.confirm(req["epoch"], req["requester"], expires)
        return 0

    def _takeover(self, req, now):
        high = self.high()
        if high is None:
            raise Refuse("NO_LEASE_VIEW")
        entry = self.ledger.get(req["epoch"])
        granted = entry is not None and not entry["confirmed"]
        if granted and entry["holder"] == req["requester"]:
            entry["expires"] = max(entry["expires"], req["expires"])
            return entry["prior"]
        if self.rules.one_candidate and granted:
            raise Refuse("CONFLICTING_LEADERS", epoch=req["epoch"], held_by=entry["holder"], announced_by=req["requester"])
        # With one-candidate-per-epoch removed, a rival replaces the grant it asks for, so what it is
        # measured against is the epoch below that grant.
        base = high - 1 if (granted and not self.rules.one_candidate) else high
        if self.rules.next_epoch_only:
            if req["epoch"] != base + 1:
                raise Refuse("NOT_NEXT_EPOCH", requested=req["epoch"], expected=base + 1)
        elif req["epoch"] <= base:
            raise Refuse("NOT_NEXT_EPOCH", requested=req["epoch"], expected=base + 1)
        latest = self.latest()
        wait = latest + self.terms["u"]
        if self.rules.expiry_wait and now < wait:
            raise Refuse("LEASE_NOT_EXPIRED", conservative_expiry_ns=wait, now_ns=now)
        # A new grant replaces any earlier grant this voter made.
        self.ledger = {k: e for k, e in self.ledger.items() if e["confirmed"]}
        self.ledger[req["epoch"]] = {"holder": req["requester"], "expires": req["expires"], "confirmed": False, "prior": latest}
        return latest


class Round:
    """The acknowledgements one request has gathered. Judged against the lease it proposed."""

    def __init__(self, electorate, group, terms, rules, req, now):
        self.electorate, self.terms, self.rules, self.req = electorate, terms, rules, req
        self.need = len(electorate) // 2 + 1 if rules.majority else 1
        self.acks = {}
        if req["group"] != group:
            raise Refuse("WRONG_GROUP")
        if req["requester"] not in electorate:
            raise Refuse("NOT_A_VOTER", member_id=req["requester"])
        max_ns = now + terms["max_lease"]
        if req["expires"] > max_ns:
            raise Refuse("LEASE_TOO_LONG", expires_at_ns=req["expires"], max_ns=max_ns)
        self.check_live(now)

    def check_live(self, now):
        deadline = max(self.req["expires"] - self.terms["u"], 0)
        if self.rules.round_deadline and now >= deadline:
            raise Refuse("ATTEMPT_EXPIRED", now_ns=now, deadline_ns=deadline)

    def record(self, ack, now):
        r = self.req
        same = (ack["kind"], ack["group"], ack["requester"], ack["epoch"], ack["expires"]) == (
            r["kind"], r["group"], r["requester"], r["epoch"], r["expires"],
        )
        if not same:
            raise Refuse("ATTEMPT_MISMATCH")
        if ack["voter"] not in self.electorate:
            raise Refuse("NOT_A_VOTER", member_id=ack["voter"])
        self.check_live(now)
        self.acks[ack["voter"]] = ack["prior"]

    def outcome(self, now):
        self.check_live(now)
        if len(self.acks) < self.need:
            raise Refuse("NO_QUORUM", have=len(self.acks), need=self.need)
        r = self.req
        return {
            "kind": r["kind"], "group": r["group"], "requester": r["requester"], "epoch": r["epoch"],
            "expires": r["expires"], "prior": max(self.acks.values(), default=0), "acks": len(self.acks),
        }


# -------------------------------------------------------------------------------------- the engine


class Engine:
    """GroupMembership: the cutover protocol, epoch changes, leases and the output policy."""

    def __init__(self, cfg, rules, discovered=True):
        self.cfg, self.rules, self.discovered = cfg, rules, discovered
        self.next_id = 1
        self.current = None
        self.history = []
        self.unresolved = {}
        self.grants = {}
        self.gate_until = None

    def margin(self):
        return self.cfg.u if self.rules.holder_margin else 0

    def authorize(self, session, token, now_ns):
        authorize(self.rules, session, token, now_ns, self.margin())

    def is_live(self, session, token, now_ns):
        try:
            self.authorize(session, token, now_ns)
            return True
        except Refuse:
            return False

    def require_discovered(self):
        if not self.discovered:
            raise Refuse("AUTHORITY_NOT_DISCOVERED")

    def require_quorum_group(self):
        if self.rules.mint_exclusive and self.cfg.mode != "quorum":
            raise Refuse("NOT_A_QUORUM_GROUP")

    def discover(self, session, token, now_ns):
        self.authorize(session, token, now_ns)
        self.discovered = True

    # -- proposals
    def finish(self, pid, status):
        if self.current and self.current["id"] == pid:
            self.current = None
        self.history.append((pid, status))
        self.history = self.history[-MAX_TERMINAL_HISTORY:]

    def ensure_live(self, pid):
        if self.current and self.current["id"] == pid:
            return
        for hid, status in self.history:
            if hid == pid:
                raise Refuse("NOT_PENDING", id=pid, phase=status["phase"])
        raise Refuse("UNKNOWN_PROPOSAL", id=pid)

    def status_of(self, pid):
        if self.current and self.current["id"] == pid:
            return self.proposal_status(self.current)
        for hid, status in self.history:
            if hid == pid:
                return status
        raise Refuse("UNKNOWN_PROPOSAL", id=pid)

    @staticmethod
    def required(p):
        return sorted(m for m in p["participants"] if m not in p["excluded"])

    def missing(self, p):
        return [m for m in self.required(p) if m not in p["acks"]]

    def proposal_status(self, p):
        if p["committed"]:
            return {"phase": "committed", "activate_at_frame": p["cutover"], "excluded": sorted(p["excluded"])}
        return {
            "phase": "pending", "acked": sorted(p["acks"]), "missing": self.missing(p), "excluded": sorted(p["excluded"]),
        }

    def propose(self, session, token, change, cutover, deadline, now):
        self.require_discovered()
        self.authorize(session, token, now[0])
        if self.current:
            raise Refuse("PROPOSAL_PENDING", pending=self.current["id"])
        participants = set(session.members)
        member = change["member"]
        if change["kind"] == "join":
            if member in session.members:
                raise Refuse("MEMBER_ALREADY_PRESENT", member_id=member)
            if member in self.unresolved:
                raise Refuse("OUTPUT_UNRESOLVED", member_id=member)
            if change["board"].startswith(INELIGIBLE_PREFIX):
                raise Refuse("INELIGIBLE_BOARD")
            if len(session.members) >= self.cfg.max_members:
                raise Refuse("GROUP_FULL", max=self.cfg.max_members)
            participants.add(member)
        else:
            if member not in session.members:
                raise Refuse("UNKNOWN_MEMBER", member_id=member)
        earliest = now[1] + self.cfg.lead
        if cutover < earliest:
            raise Refuse("CUTOVER_TOO_SOON", cutover_frame=cutover, earliest_frame=earliest)
        if deadline <= now[0]:
            raise Refuse("ACK_DEADLINE_NOT_IN_FUTURE", ack_deadline_ns=deadline, now_ns=now[0])
        pid = self.next_id
        self.next_id += 1
        self.current = {
            "id": pid, "change": dict(change), "cutover": cutover, "deadline": deadline,
            "participants": participants, "acks": {}, "excluded": set(), "committed": False,
        }
        return pid

    def ack(self, pid, member, report, now):
        self.ensure_live(pid)
        p = self.current
        if p["committed"]:
            raise Refuse("NOT_PENDING", id=pid, phase="committed")
        if member not in p["participants"] or member in p["excluded"]:
            raise Refuse("NOT_A_PARTICIPANT", member_id=member)
        if member in p["acks"]:
            if p["acks"][member] == report:
                return
            raise Refuse("ACK_CONFLICT", member_id=member)
        if now[0] >= p["deadline"]:
            raise Refuse("ACK_AFTER_DEADLINE", ack_deadline_ns=p["deadline"], now_ns=now[0])
        p["acks"][member] = report

    def commit(self, session, token, pid, now):
        self.require_discovered()
        self.authorize(session, token, now[0])
        self.ensure_live(pid)
        p = self.current
        if p["committed"]:
            raise Refuse("NOT_PENDING", id=pid, phase="committed")
        missing = self.missing(p)
        if missing:
            raise Refuse("MISSING_ACKS", members=missing)
        not_ready = [m for m in self.required(p) if not all(p["acks"][m][f] for f in READY_FLAGS)]
        if not_ready:
            raise Refuse("MEMBER_NOT_READY", members=not_ready)
        if now[1] >= p["cutover"]:
            raise Refuse("CUTOVER_PASSED", cutover_frame=p["cutover"], now_frame=now[1])
        tail = max((p["acks"][m]["tail"] for m in self.required(p)), default=0)
        if self.rules.commit_checks_tail and p["cutover"] < tail:
            raise Refuse("CUTOVER_BEFORE_OUTPUT_TAIL", cutover_frame=p["cutover"], tail_complete_frame=tail)
        p["committed"] = True
        return self.proposal_status(p)

    def abort(self, session, token, pid, now):
        self.require_discovered()
        self.authorize(session, token, now[0])
        self.ensure_live(pid)
        status = {"phase": "aborted", "reason": "BY_AUTHORITY"}
        self.finish(pid, status)
        return status

    def tick(self, session, now):
        settled = []
        p = self.current
        if p is None:
            return settled
        pid = p["id"]
        if p["committed"]:
            if now[1] < p["cutover"]:
                return settled
            status = self.activate(session, p)
            self.finish(pid, status)
            return [(pid, status)]
        if now[1] >= p["cutover"]:
            status = {"phase": "aborted", "reason": "CUTOVER_MISSED"}
            self.finish(pid, status)
            return [(pid, status)]
        if now[0] >= p["deadline"]:
            missing = self.missing(p)
            if missing:
                joiner = p["change"]["kind"] == "join" and p["change"]["member"] in missing
                if joiner or self.cfg.policy == "abort":
                    status = {"phase": "aborted", "reason": "ACK_DEADLINE_MISSED", "missing": missing}
                    self.finish(pid, status)
                    return [(pid, status)]
                p["excluded"].update(missing)
        return settled

    def activate(self, session, p):
        change = p["change"]
        remaining = [m for m in session.members if m not in p["excluded"]]
        if change["kind"] == "join":
            applicable = change["member"] not in session.members and len(remaining) < self.cfg.max_members
        else:
            applicable = change["member"] in session.members
        if not applicable:
            return {"phase": "aborted", "reason": "PRECONDITION_FAILED"}
        for m in [m for m in sorted(p["excluded"]) if m in session.members]:
            del session.members[m]
        if change["kind"] == "join":
            session.members[change["member"]] = "synchronized_ready"
        elif change["member"] not in p["excluded"]:
            del session.members[change["member"]]
        session.revision += 1
        if self.rules.exclusion_unresolved:
            for m in p["excluded"]:
                self.unresolved[m] = None  # None = unknown bound
        return {"phase": "activated", "revision": session.revision, "excluded": sorted(p["excluded"])}

    # -- epochs
    def abort_in_flight(self):
        if self.current and self.rules.abort_on_epoch_change:
            self.finish(self.current["id"], {"phase": "aborted", "reason": "EPOCH_ADVANCED"})

    def advance_epoch(self, session, token, epoch, now):
        self.require_discovered()
        if self.rules.mint_exclusive and self.cfg.mode == "quorum":
            raise Refuse("QUORUM_REQUIRED")
        self.authorize(session, token, now[0])
        if epoch <= session.epoch:
            raise Refuse("EPOCH_NOT_ADVANCING", requested=epoch, current=session.epoch)
        self.abort_in_flight()
        session.begin_epoch(epoch)
        return token_of(session.group, session.coord, session.epoch, token["expires"])

    def renew_lease(self, session, token, win, now):
        self.require_quorum_group()
        self.require_discovered()
        self.authorize(session, token, now[0])
        if win["kind"] != "renew" or win["group"] != token["group"] or win["requester"] != token["issuer"] or win["epoch"] != token["epoch"]:
            raise Refuse("WIN_NOT_APPLICABLE")
        if win["expires"] <= token["expires"]:
            raise Refuse("LEASE_NOT_EXTENDED", expires_at_ns=win["expires"], current_ns=token["expires"])
        max_ns = now[0] + self.cfg.max_lease
        if win["expires"] > max_ns:
            raise Refuse("LEASE_TOO_LONG", expires_at_ns=win["expires"], max_ns=max_ns)
        return dict(token, expires=win["expires"])

    def assume_authority(self, session, win, now):
        self.require_quorum_group()
        self.require_discovered()
        if win["kind"] != "takeover" or win["group"] != session.group:
            raise Refuse("WIN_NOT_APPLICABLE")
        if win["epoch"] <= session.epoch:
            raise Refuse("STALE_AUTHORITY", token_epoch=win["epoch"], current_epoch=session.epoch)
        margin = self.margin()
        if now[0] + margin >= win["expires"]:
            raise Refuse("AUTHORITY_EXPIRED", expires_at_ns=win["expires"], now_ns=now[0])
        self.abort_in_flight()
        session.coord = win["requester"]
        session.begin_epoch(win["epoch"])
        if self.rules.assume_gate:
            self.gate_until = win["prior"] + self.cfg.horizon_ns + margin
        return token_of(session.group, win["requester"], win["epoch"], win["expires"])

    def adopt_authority(self, session, view):
        self.require_quorum_group()
        if view.get("group", session.group) != session.group:
            raise Refuse("WRONG_GROUP")
        if view["epoch"] < session.epoch:
            raise Refuse("STALE_AUTHORITY", token_epoch=view["epoch"], current_epoch=session.epoch)
        if view["epoch"] == session.epoch:
            if view["holder"] == session.coord:
                self.discovered = True
                return
            raise Refuse("CONFLICTING_LEADERS", epoch=view["epoch"], held_by=session.coord, announced_by=view["holder"])
        self.abort_in_flight()
        session.coord = view["holder"]
        session.begin_epoch(view["epoch"])
        self.discovered = True

    # -- output
    def grant_output(self, session, token, member, through, now):
        self.require_discovered()
        if self.rules.needs_live_lease_for_grant:
            self.authorize(session, token, now[0])
        if member not in session.members:
            raise Refuse("UNKNOWN_MEMBER", member_id=member)
        max_frame = now[1] + self.cfg.horizon_frames
        if through > max_frame:
            raise Refuse("OUTPUT_HORIZON_EXCEEDED", requested_frame=through, max_frame=max_frame)
        self.grants[member] = max(self.grants.get(member, 0), through)
        return self.grants[member]

    def output_permitted(self, member, frame):
        return member in self.grants and frame < self.grants[member]

    def takeover_gate(self, now_ns):
        if self.gate_until is not None and now_ns < self.gate_until:
            return self.gate_until
        return None

    def resolve_output(self, member, resolution):
        if member not in self.unresolved:
            raise Refuse("NO_UNRESOLVED_OUTPUT", member_id=member)
        if resolution["kind"] == "stop":
            del self.unresolved[member]
            return
        frame, existing = resolution["frame"], self.unresolved[member]
        if self.rules.evidence_never_shortens and existing is not None:
            frame = max(frame, existing)
        self.unresolved[member] = frame

    def start_gate(self, frame):
        blocked = sorted(m for m, bound in self.unresolved.items() if bound is None or frame < bound)
        return blocked


# --------------------------------------------------------------------------- the seeded schedule

M64 = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed):
        self.x = seed & M64

    def next(self):
        self.x = (self.x + 0x9E3779B97F4A7C15) & M64
        z = self.x
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        return z ^ (z >> 31)

    def below(self, bound):
        return self.next() % bound


COUNT_FIELDS = (
    "renewals", "minority_refused", "takeovers", "takeovers_refused", "fenced", "mutations_accepted",
    "led_steps", "leaderless_steps", "overlaps", "conflicts",
)


class Node:
    def __init__(self, voter, engine, session, token, offset):
        self.voter, self.engine, self.session, self.token, self.offset = voter, engine, session, token, offset


class Cluster:
    """Nodes that renew, take over, mutate and hear announcements on a network that partitions at
    random and clocks that disagree by up to a bounded offset. The same draws as the Rust test."""

    def __init__(self, seed, n, u, max_offset, skew_holder=False, rules=None, voter_class=Voter):
        self.rules = rules or Rules()
        self.terms = {"max_lease": 2000, "u": u, "horizon_ns": 1000}
        self.cfg = Config(mode="quorum", u=u, max_lease=2000, horizon_ns=1000, horizon_frames=1000)
        ids = ["v%d" % (i + 1) for i in range(n)]
        self.electorate = set(ids)
        self.rng = SplitMix64(seed)
        span = 2 * max_offset + 1
        founding = 11500
        self.nodes = []
        for vid in ids:
            voter = voter_class(vid, self.electorate, GROUP, self.terms, self.rules)
            voter.observe({"epoch": 1, "holder": "v1", "expires": founding})
            offset = self.rng.below(span) - max_offset
            if skew_holder:
                offset = -max_offset if not self.nodes else max_offset
            session = Session("v1")
            token = token_of(GROUP, "v1", 1, founding) if not self.nodes else None
            self.nodes.append(Node(voter, Engine(self.cfg, self.rules), session, token, offset))
        self.side = [0] * n
        self.true_ns = 10000
        self.winners = {}
        self.c = dict.fromkeys(COUNT_FIELDS, 0)
        self.lossy = False
        self.mute = False

    def clock(self, i):
        return self.true_ns + self.nodes[i].offset

    def reach(self, i):
        return [j for j in range(len(self.nodes)) if self.side[j] == self.side[i]]

    def newest_holder(self):
        best = None
        for i, nd in enumerate(self.nodes):
            if nd.token is not None:
                key = (nd.token["epoch"], -i)
                if best is None or key > best[0]:
                    best = (key, i)
        return None if best is None else best[1]

    def collect(self, i, req):
        now = self.clock(i)
        try:
            rnd = Round(self.electorate, GROUP, self.terms, self.rules, req, now)
        except Refuse:
            return None
        for j in self.reach(i):
            try:
                ack = self.nodes[j].voter.respond(req, self.clock(j))
                rnd.record(ack, now)
            except Refuse:
                pass
        try:
            return ("ok", rnd.outcome(now))
        except Refuse as e:
            return ("err", e.code)

    def try_renew(self, i, length):
        nd = self.nodes[i]
        if nd.token is None:
            return
        now = self.clock(i)
        try:
            req = nd.voter.renew_request(now, length)
        except Refuse:
            return
        res = self.collect(i, req)
        if res is None:
            return
        if res[0] == "ok":
            try:
                nd.token = nd.engine.renew_lease(nd.session, nd.token, res[1], (now, now))
                self.c["renewals"] += 1
            except Refuse:
                pass
        elif res[1] == "NO_QUORUM":
            self.c["minority_refused"] += 1

    def try_takeover(self, i, length):
        nd = self.nodes[i]
        now = self.clock(i)
        try:
            req = nd.voter.takeover_request(now, length)
        except Refuse:
            return
        res = self.collect(i, req)
        if res is None:
            return
        if res[0] != "ok":
            self.c["takeovers_refused"] += 1
            return
        win = res[1]
        try:
            token = nd.engine.assume_authority(nd.session, win, (now, now))
        except Refuse:
            self.c["takeovers_refused"] += 1
            return
        nd.token = token
        if self.rules.winner_observes:
            nd.voter.observe({"epoch": token["epoch"], "holder": token["issuer"], "expires": token["expires"]})
        first = self.winners.setdefault(win["epoch"], i)
        if first != i:
            raise AssertionError("two nodes won epoch %d" % win["epoch"])
        self.c["takeovers"] += 1
        self.announce(i, {"epoch": token["epoch"], "holder": token["issuer"], "expires": token["expires"]})

    def announce(self, frm, view):
        if self.mute:
            return
        for j in self.reach(frm):
            if j == frm:
                continue
            if self.lossy and self.rng.below(3) == 0:
                continue
            nd = self.nodes[j]
            try:
                nd.voter.observe(view)
            except Refuse as e:
                if e.code == "CONFLICTING_LEADERS":
                    self.c["conflicts"] += 1
            try:
                nd.engine.adopt_authority(nd.session, view)
            except Refuse as e:
                if e.code == "CONFLICTING_LEADERS":
                    self.c["conflicts"] += 1

    def gossip(self):
        h = self.newest_holder()
        if h is None:
            return
        t = self.nodes[h].token
        self.announce(h, {"epoch": t["epoch"], "holder": t["issuer"], "expires": t["expires"]})

    def try_mutation(self, i):
        nd = self.nodes[i]
        if nd.token is None:
            return
        now = self.clock(i)
        live = nd.engine.is_live(nd.session, nd.token, now)
        try:
            nd.engine.authorize(nd.session, nd.token, now)
        except Refuse as e:
            if e.code == "STALE_AUTHORITY":
                self.c["fenced"] += 1
            if live:
                raise AssertionError("a live lease was refused")
            if e.code not in ("STALE_AUTHORITY", "AUTHORITY_EXPIRED"):
                raise AssertionError("node %d refused for the wrong reason: %s" % (i, e.code))
            return
        if not live:
            raise AssertionError("node %d mutated on a lease it should consider over" % i)
        self.c["mutations_accepted"] += 1

    def repartition(self):
        together = self.rng.below(4) == 0
        self.side = [0 if together else self.rng.below(2) for _ in self.nodes]
        self.gossip()

    def check(self):
        live = sum(
            1 for i, nd in enumerate(self.nodes)
            if nd.token is not None and nd.engine.is_live(nd.session, nd.token, self.clock(i))
        )
        if live == 0:
            self.c["leaderless_steps"] += 1
        elif live == 1:
            self.c["led_steps"] += 1
        else:
            self.c["overlaps"] += 1

    def prologue(self):
        self.true_ns += 200
        self.try_renew(0, 1500)
        self._expect("renewals", 1, "a connected holder renews")
        self.side[0] = 1
        self.true_ns += 100
        self.try_renew(0, 1500)
        self._expect("minority_refused", 1, "an isolated holder gets one acknowledgement and no more")
        # The earliest true time at which every other node's clock has reached the holder's expiry
        # plus u, so every voter on the majority side will grant.
        expiry = self.nodes[0].token["expires"]
        slowest = min(nd.offset for nd in self.nodes[1:])
        self.true_ns = max(self.true_ns, expiry + self.terms["u"] - slowest)
        self.check()
        self.try_takeover(1, 1500)
        self._expect("takeovers", 1, "the majority side takes over")
        self.check()
        self.side = [0] * len(self.nodes)
        self.gossip()
        self.try_mutation(0)
        self._expect("fenced", 1, "the old holder is fenced by epoch")
        self.check()
        self.duel()

    def duel(self):
        """Two candidates for one epoch, the first announcement lost. Node 2 wins epoch 3 with the
        nodes on its side; nodes 1 (and 4) never hear of it. Later node 1, unaware, asks a voter that
        holds only its grant for the same epoch."""
        n = len(self.nodes)
        late = [1] + ([4] if n == 5 else [])
        self.true_ns += 4000
        self.side = [1 if j in late else 0 for j in range(n)]
        self.mute = True
        before = self.c["takeovers"]
        self.try_takeover(2, 1500)
        self.mute = False
        self._expect("takeovers", before + 1, "the first candidate wins")
        self.true_ns += 3000
        together = [0, 1] + ([4] if n == 5 else [])
        self.side = [0 if j in together else 1 for j in range(n)]
        self.try_takeover(1, 1500)
        self._expect("takeovers", before + 1, "a rival for a granted epoch must not win")
        self.side = [0] * n
        self.gossip()
        self.check()

    def _expect(self, field, value, why):
        if self.c[field] != value:
            raise AssertionError("prologue: %s (%s = %d, wanted %d)" % (why, field, self.c[field], value))

    def step(self):
        self.true_ns += 1 + self.rng.below(300)
        length = 500 + self.rng.below(1500)
        actor = self.rng.below(len(self.nodes))
        r = self.rng.below(100)
        if r < 30:
            if self.rng.below(4) == 0:
                i = actor
            else:
                h = self.newest_holder()
                i = actor if h is None else h
            self.try_renew(i, length)
        elif r < 65:
            self.try_takeover(actor, length)
        elif r < 85:
            self.try_mutation(actor)
        else:
            self.repartition()
        self.check()


def run_schedule(seed, u, max_offset, skew_holder, steps, rules=None, voter_class=Voter):
    """The counts of one seeded run, as the Rust test counts them."""
    n = 3 + 2 * (seed % 2)
    cluster = Cluster(seed, n, u, max_offset, skew_holder, rules, voter_class)
    cluster.prologue()
    cluster.lossy = True
    for _ in range(steps):
        cluster.step()
    return dict(cluster.c)


# ---------------------------------------------------------------------------------- the replayer


# Faults planted in the DRIVER of the real engine, not in the engine: they change the configuration
# or the inputs a replay hands over, so the same plant can be applied to the Rust and to the model and
# the set of scenarios each one breaks compared. (Nothing in production code carries a fault switch.)
PLANTS = ("zero_uncertainty", "early_voter_clock", "flipped_policy", "flipped_mint")
FAR_FUTURE = 4 * 10**18


def flipped(mode):
    return "issuer" if mode == "quorum" else "quorum"


class Context:
    def __init__(self, scenario, rules, plant=None):
        self.rules, self.plant = rules, plant
        self.cfg = Config.of(scenario.get("config"))
        if plant == "zero_uncertainty":
            self.cfg.u = 0
        elif plant == "flipped_policy":
            self.cfg.policy = "exclude" if self.cfg.policy == "abort" else "abort"
        elif plant == "flipped_mint":
            self.cfg.mode = flipped(self.cfg.mode)
        raw = scenario.get("config", {})
        self.terms = {"max_lease": self.cfg.max_lease, "u": self.cfg.u, "horizon_ns": self.cfg.horizon_ns}
        self.electorate = set(raw.get("electorate", []))
        self.voters = {
            v: Voter(v, self.electorate, GROUP, self.terms, rules) for v in sorted(self.electorate)
        }
        self.nodes, self.saved = {}, {}


def now_of(step, key="now"):
    value = step[key]
    return (value[0], value[1])


def saved_or_inline(ctx, step, key):
    value = step[key]
    return ctx.saved[value] if isinstance(value, str) else value


def report_of(spec):
    r = {f: True for f in READY_FLAGS}
    r["tail"] = 0
    r.update(spec if isinstance(spec, dict) else {})
    return r


def win_view(win):
    return {"kind": win["kind"], "epoch": win["epoch"], "requester": win["requester"], "expires": win["expires"],
            "prior": win["prior"], "acks": win["acks"]}


def token_view(t):
    return {"epoch": t["epoch"], "issuer": t["issuer"], "expires": t["expires"], "group": t["group"]}


def do_step(ctx, step):
    """Run one step; return the value dict on success, raise Refuse on a refusal."""
    op = step["op"]
    v = ctx.voters
    if op == "quorum":
        voters = set(step["voters"])
        if not voters:
            raise Refuse("EMPTY_ELECTORATE")
        return {"need": len(voters) // 2 + 1 if ctx.rules.majority else 1}
    if op == "found":
        view = {"epoch": 1, "holder": step["holder"], "expires": step["expires"]}
        for voter in v.values():
            voter.observe(view)
        return {}
    if op == "observe":
        v[step["voter"]].observe(step["view"])
        return {}
    if op == "request":
        voter = v[step["voter"]]
        make = voter.renew_request if step["kind"] == "renew" else voter.takeover_request
        req = make(step["at"], step["len"])
        ctx.saved[step["save"]] = req
        return {"epoch": req["epoch"], "expires": req["expires"], "requester": req["requester"]}
    if op == "raw_request":
        req = {"kind": step["kind"], "group": step.get("group", GROUP), "requester": step["requester"],
               "epoch": step["epoch"], "expires": step["expires"]}
        ctx.saved[step["save"]] = req
        return {}
    if op == "respond":
        clock = FAR_FUTURE if ctx.plant == "early_voter_clock" else step["clock"]
        ack = v[step["voter"]].respond(saved_or_inline(ctx, step, "request"), clock)
        if "save" in step:
            ctx.saved[step["save"]] = ack
        return {"voter": ack["voter"], "epoch": ack["epoch"], "prior": ack["prior"], "expires": ack["expires"]}
    if op == "gather":
        req = ctx.saved[step["request"]]
        rnd = Round(ctx.electorate, GROUP, ctx.terms, ctx.rules, req, step["now"])
        clocks = step.get("clocks", {})
        for vid in step["reach"]:
            try:
                clock = FAR_FUTURE if ctx.plant == "early_voter_clock" else clocks.get(vid, step.get("clock", step["now"]))
                ack = v[vid].respond(req, clock)
            except Refuse:
                continue
            rnd.record(ack, step["now"])
        win = rnd.outcome(step["now"])
        if "save" in step:
            ctx.saved[step["save"]] = win
        return win_view(win)
    if op == "round_start":
        ctx.saved[step["round"]] = Round(ctx.electorate, GROUP, ctx.terms, ctx.rules, ctx.saved[step["request"]], step["now"])
        return {}
    if op == "round_ack":
        ack = dict(ctx.saved[step["ack"]], **step.get("tamper", {}))
        ctx.saved[step["round"]].record(ack, step["now"])
        return {}
    if op == "round_outcome":
        return win_view(ctx.saved[step["round"]].outcome(step["now"]))
    if op == "record":
        rec = v[step["voter"]].record()
        if "save" in step:
            ctx.saved[step["save"]] = rec
        return {"voter_id": rec["voter_id"], "view": rec["view"], "grant": rec["grant"]}
    if op == "restart":
        voter = Voter(step["voter"], ctx.electorate, GROUP, ctx.terms, ctx.rules)
        voter.trusted = False
        v[step["voter"]] = voter
        return {}
    if op == "restore":
        v[step["voter"]].restore(ctx.saved[step["record"]])
        return {}
    if op == "forget":
        voter = Voter(step["voter"], ctx.electorate, GROUP, ctx.terms, ctx.rules)
        voter.observe(step["view"])
        v[step["voter"]] = voter
        return {}
    # ---- engine and session
    if op == "node":
        explicit = step.get("mode")
        mode = flipped(explicit) if (ctx.plant == "flipped_mint" and explicit) else (explicit or ctx.cfg.mode)
        cfg = dataclasses.replace(ctx.cfg, mode=mode)
        coord = step.get("coordinator", "v1" if mode == "quorum" else "coord")
        ctx.nodes[step["name"]] = (Engine(cfg, ctx.rules, discovered=not step.get("restarted", False)), Session(coord))
        return {}
    engine, session = ctx.nodes[step["node"]]
    if op == "issue":
        t = token_of(GROUP, session.coord, session.epoch, step["expires"])
        t.update(step.get("override", {}))
        ctx.saved[step["save"]] = t
        return token_view(t)
    if op == "live":
        return {"live": engine.is_live(session, ctx.saved[step["token"]], step["at"])}
    if op == "renew":
        t = engine.renew_lease(session, ctx.saved[step["token"]], ctx.saved[step["win"]], now_of(step))
        if "save" in step:
            ctx.saved[step["save"]] = t
        return token_view(t)
    if op == "assume":
        t = engine.assume_authority(session, ctx.saved[step["win"]], now_of(step))
        if "save" in step:
            ctx.saved[step["save"]] = t
        return token_view(t)
    if op == "adopt":
        engine.adopt_authority(session, step["view"])
        return {}
    if op == "session":
        return {"epoch": session.epoch, "coordinator": session.coord, "revision": session.revision,
                "members": sorted(session.members)}
    if op == "probe":
        # a stand-in for a real mutation: propose a join of "probe" and abort it
        token = ctx.saved[step["token"]]
        pid = engine.propose(session, token, {"kind": "join", "member": "probe", "board": "S1"},
                             now_of(step)[1] + 100000, now_of(step)[0] + 10000, now_of(step))
        engine.abort(session, token, pid, now_of(step))
        return {}
    if op == "advance":
        t = engine.advance_epoch(session, ctx.saved[step["token"]], step["epoch"], now_of(step))
        if "save" in step:
            ctx.saved[step["save"]] = t
        return token_view(t)
    if op == "discover":
        engine.discover(session, ctx.saved[step["token"]], step["at"])
        return {}
    if op == "gate":
        until = engine.takeover_gate(step["at"])
        return {"open": until is None, "until": until}
    if op == "grant_output":
        granted = engine.grant_output(session, ctx.saved[step["token"]], step["member"], step["through"], now_of(step))
        return {"granted": granted}
    if op == "permitted":
        return {"permitted": engine.output_permitted(step["member"], step["frame"])}
    # ---- the cutover protocol
    if op == "propose":
        pid = engine.propose(session, ctx.saved[step["token"]], step["change"], step["cutover"], step["deadline"], now_of(step))
        return {"id": pid}
    if op == "ack":
        engine.ack(step["id"], step["member"], report_of(step.get("report")), now_of(step))
        return {}
    if op == "commit":
        return {"status": engine.commit(session, ctx.saved[step["token"]], step["id"], now_of(step))}
    if op == "abort":
        return {"status": engine.abort(session, ctx.saved[step["token"]], step["id"], now_of(step))}
    if op == "tick":
        settled = engine.tick(session, now_of(step))
        return {"settled": [{"id": pid, "status": status} for pid, status in settled]}
    if op == "status":
        return {"status": engine.status_of(step["id"])}
    if op == "resolve":
        engine.resolve_output(step["member"], step["resolution"])
        return {}
    if op == "start_gate":
        blocked = engine.start_gate(step["frame"])
        return {"open": not blocked, "blocked": blocked}
    if op == "unresolved":
        return {"members": sorted(engine.unresolved)}
    if op == "restart_node":
        ctx.nodes[step["node"]] = (Engine(engine.cfg, ctx.rules, discovered=False), session)
        return {}
    raise ValueError("unknown op %r" % op)


def subset(expected, actual, path=""):
    """Every key of `expected` is present in `actual` with an equal value (recursively for dicts)."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key, want in expected.items():
            if key not in actual:
                return "%s.%s missing" % (path, key)
            problem = subset(want, actual[key], "%s.%s" % (path, key))
            if problem:
                return problem
        return None
    return None if expected == actual else "%s: wanted %r, got %r" % (path, expected, actual)


def run_step(ctx, step):
    """Returns None when the step meets its expectation, else a short description of the mismatch."""
    expect = step["expect"]
    try:
        value = do_step(ctx, step)
    except (KeyError, IndexError, TypeError) as error:  # a plant can leave a later step without its inputs
        return "model could not run the step: %s %s" % (type(error).__name__, error)
    except Refuse as refusal:
        if "error" not in expect:
            return "refused %s%s, wanted success" % (refusal.code, refusal.details)
        if expect["error"] != refusal.code:
            return "refused %s, wanted %s" % (refusal.code, expect["error"])
        return subset(expect.get("details", {}), refusal.details, "details")
    if "error" in expect:
        return "succeeded with %r, wanted %s" % (value, expect["error"])
    return subset(expect.get("ok", {}), value, "ok")


def substitute(value, n):
    """Replace the placeholder "$n" (the 1-based iteration number) anywhere in a step."""
    if value == "$n":
        return n
    if isinstance(value, dict):
        return {k: substitute(v, n) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, n) for v in value]
    return value


def expand(steps):
    """A `repeat` step stands for `count` copies of its steps, with "$n" counting from 1."""
    out = []
    for step in steps:
        if step["op"] == "repeat":
            for n in range(1, step["count"] + 1):
                out.extend(substitute(inner, n) for inner in step["steps"])
        else:
            out.append(step)
    return out


def replay(doc, scenario, rules=None, plant=None):
    """Replay one scenario; return a list of (step index, op, problem) mismatches."""
    ctx = Context(scenario, rules or Rules(), plant)
    problems = []
    for index, step in enumerate(expand(scenario["steps"])):
        problem = run_step(ctx, step)
        if problem:
            problems.append((index, step["op"], problem))
    return problems


def plant_failures(doc, plant):
    """The scenarios a planted fault breaks, by id: the model's prediction for the Rust."""
    return sorted(s["id"] for s in doc["scenarios"] if replay(doc, s, plant=plant))


def check_plants(doc):
    problems = []
    recorded = doc["plants"]
    if sorted(p["name"] for p in recorded) != sorted(PLANTS):
        problems.append("plants recorded %s, the model has %s" % ([p["name"] for p in recorded], list(PLANTS)))
    for entry in recorded:
        got = plant_failures(doc, entry["name"])
        if got != entry["fails"]:
            problems.append("plant %s: recorded %s, model breaks %s" % (entry["name"], entry["fails"], got))
    return problems


def check_schedule(doc, rules=None, voter_class=Voter):
    """Compare the model's seeded-schedule counts with the vector file's. Returns mismatch strings."""
    section = doc["schedule"]
    problems = []
    for run in section["runs"]:
        got = run_schedule(run["seed"], run["u"], run["max_offset"], run["skew_holder"], section["steps"], rules, voter_class)
        if got != run["counts"]:
            diff = {k: (run["counts"].get(k), got[k]) for k in got if run["counts"].get(k) != got[k]}
            problems.append("seed %d u=%d offset=%d skew=%s: %s" % (run["seed"], run["u"], run["max_offset"], run["skew_holder"], diff))
    return problems


def load(path=DEFAULT_VECTORS):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="the default; kept for symmetry with N01 and N02")
    parser.add_argument("--print-schedule", action="store_true", help="print the model's schedule counts and exit")
    parser.add_argument("--print-plants", action="store_true", help="print the scenarios each planted fault breaks and exit")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    args = parser.parse_args(argv)
    doc = load(args.vectors)
    if args.print_plants:
        for name in PLANTS:
            print(json.dumps({"name": name, "fails": plant_failures(doc, name)}))
        return 0
    if args.print_schedule:
        steps = doc["schedule"]["steps"]
        for run in doc["schedule"]["runs"]:
            counts = run_schedule(run["seed"], run["u"], run["max_offset"], run["skew_holder"], steps)
            print(json.dumps({k: run[k] for k in ("seed", "u", "max_offset", "skew_holder")} | {"counts": counts}))
        return 0
    failures = 0
    for scenario in doc["scenarios"]:
        problems = replay(doc, scenario)
        for index, op, problem in problems:
            failures += 1
            print("FAIL %s step %d (%s): %s" % (scenario["id"], index, op, problem))
    for problem in check_schedule(doc):
        failures += 1
        print("FAIL schedule: %s" % problem)
    for problem in check_plants(doc):
        failures += 1
        print("FAIL plants: %s" % problem)
    total = len(doc["scenarios"])
    print("%d scenarios, %d schedule runs, %d plants: %s" % (
        total, len(doc["schedule"]["runs"]), len(doc["plants"]), "FAIL" if failures else "ok"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
