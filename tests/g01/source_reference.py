#!/usr/bin/env python3
"""Independent reference for G01 source ownership arbitration (bead ffw-kh0, contract section 10).

WHAT THIS IS. A stdlib-only model of the arbiter that sits in front of every audio source (Spotify,
AirPlay 2, line-in) and decides which one owns the group's program. It has:

  * the rules of the contract as switches (`SourceRules`), so each can be broken on purpose;
  * hand-derived golden scenarios (expected outcomes written from the contract text, not from
    running this model or the Rust);
  * a seeded interleaving schedule (SplitMix64, the same draw order the Rust test uses) judged by
    properties computed from the receipts alone;
  * a mutation matrix: every rule switched off, one at a time, must be noticed by a scenario or by
    the schedule, or be declared an equivalent mutant with its reason.

WHAT THIS IS NOT. It does not run the Rust, and it shares an author with it. A green run here shows
that the rules in section 10 are coherent and that the scenarios and the schedule can tell a broken
rule from a sound one. It is not evidence about `franken-session`; that needs the centralized build.

    python3 -B -I tests/g01/source_reference.py --check
"""

import dataclasses
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as base  # noqa: E402
from reference import Refuse, SplitMix64, token_of  # noqa: E402

ROOT = base.ROOT
U64_MAX = (1 << 64) - 1
MAX_LABEL = 64
LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._:-")

KINDS = ("spotify", "airplay2", "line_in")
CLASSES = ("start", "seek", "group_change", "stop")
REPLACE, REJECT = "replace", "reject"

# The policy table of contract section 10.1: row = the kind of the source that SENDS the command, column
# = the command class. It applies only when that source does not already own the group.
STANDARD = {
    "spotify": {"start": REPLACE, "seek": REJECT, "group_change": REJECT, "stop": REJECT},
    "airplay2": {"start": REPLACE, "seek": REJECT, "group_change": REPLACE, "stop": REJECT},
    "line_in": {"start": REJECT, "seek": REJECT, "group_change": REJECT, "stop": REJECT},
}

SOURCE_CODES = (
    "INVALID_SOURCE_LABEL",
    "SOURCE_EPOCH_STALE",
    "SOURCE_EPOCH_FUTURE",
    "SOURCE_EPOCH_EXHAUSTED",
    "SOURCE_REJECTED",
    "NO_ACTIVE_SOURCE",
    "SOURCE_REPLACED",
    "NOT_SOURCE_OWNER",
    "GROUP_EPOCH_ADVANCED",
)
AUTHORITY_CODES = ("WRONG_GROUP", "STALE_AUTHORITY", "FUTURE_AUTHORITY", "NOT_CONFIGURED_ISSUER", "AUTHORITY_EXPIRED")

# Short names used by the scenarios and the schedule.
SOURCES = {
    "s": ("spotify", "spotify-a"),
    "s2": ("spotify", "spotify-b"),
    "a": ("airplay2", "airplay-a"),
    "b": ("airplay2", "airplay-b"),
    "l": ("line_in", "linein-a"),
    "l2": ("line_in", "linein-b"),
}
NAME_OF = {v: k for k, v in SOURCES.items()}
# The four sources of the seeded schedule, in draw order.
SCHEDULE_SOURCES = ("s", "a", "b", "l")
FAR_FUTURE = 4 * 10**18


def source_id(kind, label, rules=None):
    """A validated source identity. The refusal carries the length only: a label might be a pasted secret."""
    if kind not in KINDS:
        raise ValueError(kind)
    size = len(label.encode("utf-8"))
    checked = rules.label_checked if rules is not None else True
    if checked and (size < 1 or size > MAX_LABEL or any(c not in LABEL_CHARS for c in label)):
        raise Refuse("INVALID_SOURCE_LABEL", len=size)
    return (kind, label)


# ------------------------------------------------------------------------------------------- rules


@dataclasses.dataclass
class SourceRules:
    """Every rule of section 10 as a switch. All True is the contract; a False is a broken variant."""

    authority_first: bool = True  # the group's authority token is judged before anything about the source
    start_cas: bool = True  # a Start must present the source epoch that is current (the race rule)
    seek_validated: bool = True  # a Seek is judged by epoch, owner and policy like any other command
    publish_validated: bool = True  # a publish must come from the owner under the current epoch
    epoch_before_policy: bool = True  # a stale or future epoch is reported before the policy verdict
    policy_applied: bool = True  # the table decides a non-owner's command (False: always replace)
    owner_restart_mints: bool = True  # the owner's own Start is a new stream: new epoch
    stop_mints: bool = True  # a Stop ends the stream: new epoch, so its late blocks are refused
    replace_mints: bool = True  # a replacement mints a new epoch
    typed_replaced: bool = True  # an older-epoch publish by a non-owner is SOURCE_REPLACED
    future_refused: bool = True  # an epoch above the current one is refused
    group_epoch_effective: bool = True  # after a group epoch advance a submit sees no owner
    group_epoch_fenced_publish: bool = True  # after a group epoch advance a publish is refused
    refusal_pure: bool = True  # a refused call changes nothing
    exhaustion_checked: bool = True  # an epoch counter at its maximum refuses to mint
    label_checked: bool = True  # a source label is validated


RULE_NAMES = tuple(f.name for f in dataclasses.fields(SourceRules))


def broken(name):
    assert name in RULE_NAMES, name
    return SourceRules(**{name: False})


# ----------------------------------------------------------------------------------------- engine


class Arbiter:
    """State: the group epoch it is bound to, the source epoch, and the owner (or None)."""

    def __init__(self, rules=None, table=None, margin=0, floor=None):
        self.rules = rules or SourceRules()
        self.table = {k: dict(v) for k, v in (table or STANDARD).items()}
        self.margin = margin
        self.bound = None
        self.owner = None
        self.epoch = 0 if floor is None else min(floor + 1, U64_MAX)

    def fingerprint(self):
        return (self.bound, self.epoch, self.owner)

    def effective(self, group_epoch):
        """What a command sees: after a group epoch advance the old owner's program is void and one
        epoch number has been spent on the transition. Nothing is stored."""
        if self.bound is None or self.bound == group_epoch or not self.rules.group_epoch_effective:
            return self.owner, self.epoch
        return None, min(self.epoch + 1, U64_MAX)

    def view(self, session):
        owner, epoch = self.effective(session.epoch)
        return (session.epoch, epoch, owner)

    def decide(self, owner, source, cls):
        """Returns (mints, owner after, source displaced) or raises."""
        if owner is None:
            if cls == "start":
                return True, source, None
            raise Refuse("NO_ACTIVE_SOURCE", cls=cls)
        if owner == source:
            if cls == "start":
                return self.rules.owner_restart_mints, source, None
            if cls == "stop":
                return self.rules.stop_mints, None, None
            return False, source, None
        policy = self.table[source[0]][cls] if self.rules.policy_applied else REPLACE
        if policy == REJECT:
            raise Refuse("SOURCE_REJECTED", cls=cls, requester=source, owner=owner)
        return self.rules.replace_mints, (None if cls == "stop" else source), owner

    def submit(self, session, token, now_ns, source, cls, expected):
        r = self.rules
        before = self.fingerprint()
        try:
            return self._submit(session, token, now_ns, source, cls, expected)
        except Refuse:
            if not r.refusal_pure:
                self.bound = session.epoch  # the broken variant: a refusal still binds the group epoch
            assert r.refusal_pure is False or self.fingerprint() == before
            raise

    def _submit(self, session, token, now_ns, source, cls, expected):
        r = self.rules
        if r.authority_first:
            base.authorize(base.Rules(), session, token, now_ns, self.margin)
        owner, cur = self.effective(session.epoch)
        if cls == "seek" and not r.seek_validated:
            if owner is None:
                raise Refuse("NO_ACTIVE_SOURCE", cls=cls)
            self.bound = session.epoch
            return {"class": cls, "epoch": cur, "owner": owner, "replaced": None, "minted": False}
        epoch_error = None
        if cls != "start" or r.start_cas:
            if expected < cur:
                epoch_error = Refuse("SOURCE_EPOCH_STALE", expected=expected, current=cur)
            elif expected > cur and r.future_refused:
                epoch_error = Refuse("SOURCE_EPOCH_FUTURE", expected=expected, current=cur)
        if r.epoch_before_policy:
            if epoch_error:
                raise epoch_error
            mints, new_owner, replaced = self.decide(owner, source, cls)
        else:
            mints, new_owner, replaced = self.decide(owner, source, cls)
            if epoch_error:
                raise epoch_error
        epoch_after = cur
        if mints:
            if cur >= U64_MAX and r.exhaustion_checked:
                raise Refuse("SOURCE_EPOCH_EXHAUSTED")
            epoch_after = min(cur + 1, U64_MAX)
        self.bound, self.owner, self.epoch = session.epoch, new_owner, epoch_after
        return {"class": cls, "epoch": epoch_after, "owner": new_owner, "replaced": replaced, "minted": mints}

    def check_publish(self, session, source, epoch):
        r = self.rules
        if not r.publish_validated:
            if self.bound is None or self.owner is None:
                raise Refuse("NO_ACTIVE_SOURCE")
            return
        if self.bound is None:
            raise Refuse("NO_ACTIVE_SOURCE")
        if self.bound != session.epoch and r.group_epoch_fenced_publish:
            raise Refuse("GROUP_EPOCH_ADVANCED", arbiter_epoch=self.bound, group_epoch=session.epoch)
        if self.owner is None:
            raise Refuse("NO_ACTIVE_SOURCE")
        if epoch < self.epoch:
            if self.owner == source or not r.typed_replaced:
                raise Refuse("SOURCE_EPOCH_STALE", expected=epoch, current=self.epoch)
            raise Refuse("SOURCE_REPLACED", source=source, epoch=epoch, current=self.epoch)
        if epoch > self.epoch:
            raise Refuse("SOURCE_EPOCH_FUTURE", expected=epoch, current=self.epoch)
        if self.owner != source:
            raise Refuse("NOT_SOURCE_OWNER", source=source, owner=self.owner)


# --------------------------------------------------------------------------------------- scenarios
#
# Every expectation below is written by hand from section 10 of the contract. A step is a dict:
#   op      start | seek | group_change | stop | publish | view | group_epoch | label
#   who     a key of SOURCES (None for view / group_epoch)
#   at      the source epoch the source presents (publish: the epoch stamped on the block)
#   tok     optional: stale | future | expired | wrong_group | wrong_issuer (a token that is not current)
#   expect  an error code, or for an admitted command a dict of the fields checked:
#           {"epoch": n, "owner": key or None, "replaced": key or None, "minted": bool}
#           for publish: "OK"; for view: {"group": g, "epoch": n, "owner": key or None}


def step(op, who=None, at=None, expect="OK", **extra):
    out = {"op": op, "who": who, "at": at, "expect": expect}
    out.update(extra)
    return out


def ok(epoch, owner, replaced=None, minted=True):
    return {"epoch": epoch, "owner": owner, "replaced": replaced, "minted": minted}


def view(epoch, owner, group=1):
    return step("view", expect={"group": group, "epoch": epoch, "owner": owner})


# Cells of the table written out by hand, independently of STANDARD, from the policy in section 10.1:
# Spotify and AirPlay 2 may start over any source, only AirPlay 2 may re-group over another source, and a
# line-in start, a seek or a stop never takes the group from a source that owns it.
EXPECTED_CELLS = {
    ("spotify", "start"): REPLACE,
    ("spotify", "seek"): REJECT,
    ("spotify", "group_change"): REJECT,
    ("spotify", "stop"): REJECT,
    ("airplay2", "start"): REPLACE,
    ("airplay2", "seek"): REJECT,
    ("airplay2", "group_change"): REPLACE,
    ("airplay2", "stop"): REJECT,
    ("line_in", "start"): REJECT,
    ("line_in", "seek"): REJECT,
    ("line_in", "group_change"): REJECT,
    ("line_in", "stop"): REJECT,
}


def cell_scenarios():
    """One scenario per (incumbent kind, requester kind, class): the requester presents the CURRENT epoch."""
    out = []
    incumbents = (("b", "airplay2"), ("l2", "line_in"))
    requesters = (("s", "spotify"), ("a", "airplay2"), ("l", "line_in"))
    for inc, inc_kind in incumbents:
        for req, req_kind in requesters:
            for cls in CLASSES:
                policy = EXPECTED_CELLS[(req_kind, cls)]
                steps = [step("start", inc, 0, ok(1, inc))]
                if policy == REJECT:
                    steps += [step(cls, req, 1, "SOURCE_REJECTED"), view(1, inc), step("publish", inc, 1, "OK")]
                else:
                    after_owner = None if cls == "stop" else req
                    steps += [step(cls, req, 1, ok(2, after_owner, replaced=inc)), view(2, after_owner)]
                    if after_owner:
                        steps += [step("publish", inc, 1, "SOURCE_REPLACED"), step("publish", req, 2, "OK")]
                    else:  # a replacing stop leaves nobody to own the group
                        steps += [step("publish", inc, 1, "NO_ACTIVE_SOURCE"), step("publish", req, 2, "NO_ACTIVE_SOURCE")]
                out.append((f"G01S-CELL-{inc_kind}-{req_kind}-{cls}", steps))
    return out


def scenarios():
    out = []
    add = lambda sid, steps: out.append((sid, steps))  # noqa: E731
    add("G01S-001-uncontested-start-plays", [
        view(0, None, group=1),
        step("start", "s", 0, ok(1, "s")),
        view(1, "s"),
        step("publish", "s", 1, "OK"),
    ])
    add("G01S-002-same-source-seek-is-applied", [
        step("start", "s", 0, ok(1, "s")),
        step("seek", "s", 1, ok(1, "s", minted=False)),
        step("publish", "s", 1, "OK"),
        view(1, "s"),
    ])
    add("G01S-003-replaced-source-cannot-publish", [
        step("start", "s", 0, ok(1, "s")),
        step("start", "a", 1, ok(2, "a", replaced="s")),
        step("publish", "s", 1, "SOURCE_REPLACED"),
        step("publish", "s", 2, "NOT_SOURCE_OWNER"),
        step("publish", "a", 2, "OK"),
        step("publish", "a", 1, "SOURCE_EPOCH_STALE"),
    ])
    add("G01S-004-two-starts-that-saw-the-same-epoch-admit-one", [
        step("start", "s", 0, ok(1, "s")),
        step("start", "a", 0, "SOURCE_EPOCH_STALE"),
        view(1, "s"),
        step("publish", "s", 1, "OK"),
        step("publish", "a", 1, "NOT_SOURCE_OWNER"),
    ])
    add("G01S-005-a-seek-from-the-losing-epoch-is-not-applied", [
        step("start", "s", 0, ok(1, "s")),
        step("start", "a", 1, ok(2, "a", replaced="s")),
        step("seek", "s", 1, "SOURCE_EPOCH_STALE"),
        step("seek", "s", 2, "SOURCE_REJECTED"),
        step("seek", "a", 2, ok(2, "a", minted=False)),
        view(2, "a"),
    ])
    add("G01S-006-the-owner-starting-again-is-a-new-stream", [
        step("start", "s", 0, ok(1, "s")),
        step("start", "s", 1, ok(2, "s")),
        step("publish", "s", 1, "SOURCE_EPOCH_STALE"),
        step("publish", "s", 2, "OK"),
    ])
    add("G01S-007-stop-ends-the-stream-and-fences-its-late-blocks", [
        step("start", "s", 0, ok(1, "s")),
        step("stop", "s", 1, ok(2, None)),
        step("publish", "s", 1, "NO_ACTIVE_SOURCE"),
        step("publish", "s", 2, "NO_ACTIVE_SOURCE"),
        step("seek", "s", 2, "NO_ACTIVE_SOURCE"),
        step("group_change", "a", 2, "NO_ACTIVE_SOURCE"),
        step("stop", "a", 2, "NO_ACTIVE_SOURCE"),
        step("start", "a", 2, ok(3, "a")),
    ])
    add("G01S-008-an-epoch-from-the-future-is-refused", [
        step("start", "s", 0, ok(1, "s")),
        step("seek", "s", 5, "SOURCE_EPOCH_FUTURE"),
        step("start", "a", 7, "SOURCE_EPOCH_FUTURE"),
        step("publish", "s", 3, "SOURCE_EPOCH_FUTURE"),
        view(1, "s"),
    ])
    add("G01S-009-authority-is-judged-before-the-source", [
        # A stale token AND a stale source epoch: the authority error wins.
        step("start", "s", 0, ok(1, "s")),
        step("start", "a", 0, "STALE_AUTHORITY", tok="stale"),
        step("start", "a", 0, "FUTURE_AUTHORITY", tok="future"),
        step("start", "a", 0, "AUTHORITY_EXPIRED", tok="expired"),
        step("start", "a", 0, "WRONG_GROUP", tok="wrong_group"),
        step("start", "a", 0, "NOT_CONFIGURED_ISSUER", tok="wrong_issuer"),
        view(1, "s"),
    ])
    add("G01S-010-a-group-epoch-advance-voids-the-program", [
        step("start", "s", 0, ok(1, "s")),
        step("group_epoch", at=2),
        step("publish", "s", 1, "GROUP_EPOCH_ADVANCED"),
        view(2, None, group=2),
        step("seek", "s", 1, "SOURCE_EPOCH_STALE"),
        step("seek", "s", 2, "NO_ACTIVE_SOURCE"),
        step("start", "s", 1, "SOURCE_EPOCH_STALE"),
        step("start", "s", 2, ok(3, "s")),
        step("publish", "s", 3, "OK"),
        step("publish", "s", 1, "SOURCE_EPOCH_STALE"),
    ])
    add("G01S-011-a-refusal-changes-nothing", [
        step("start", "l", 0, ok(1, "l")),
        step("group_epoch", at=2),
        step("start", "s", 9, "SOURCE_EPOCH_FUTURE"),
        step("seek", "s", 0, "SOURCE_EPOCH_STALE"),
        view(2, None, group=2),
        step("publish", "l", 1, "GROUP_EPOCH_ADVANCED"),
        step("start", "s", 2, ok(3, "s")),
        view(3, "s", group=2),
    ])
    add("G01S-012-a-line-in-start-does-not-take-the-group-but-an-idle-group-accepts-it", [
        step("start", "l", 0, ok(1, "l")),
        step("start", "l2", 1, "SOURCE_REJECTED"),
        step("stop", "l", 1, ok(2, None)),
        step("start", "l2", 2, ok(3, "l2")),
    ])
    add("G01S-013-replacement-by-group-change-is-airplay-only", [
        step("start", "s", 0, ok(1, "s")),
        step("group_change", "s2", 1, "SOURCE_REJECTED"),
        step("group_change", "a", 1, ok(2, "a", replaced="s")),
        step("group_change", "a", 2, ok(2, "a", minted=False)),
        step("publish", "s", 1, "SOURCE_REPLACED"),
    ])
    for racers in (("s", "a", "l"), ("s", "l", "a"), ("a", "s", "l"), ("a", "l", "s"), ("l", "s", "a"), ("l", "a", "s")):
        first, second, third = racers
        add("G01S-014-race-on-an-idle-group-" + "".join(racers), [
            step("start", first, 0, ok(1, first)),
            step("start", second, 0, "SOURCE_EPOCH_STALE"),
            step("start", third, 0, "SOURCE_EPOCH_STALE"),
            view(1, first),
        ])
    add("G01S-015-race-for-an-owned-group-first-admissible-wins", [
        step("start", "b", 0, ok(1, "b")),
        # All three saw epoch 1. The line-in start is rejected by policy, so it does not use the epoch up.
        step("start", "l", 1, "SOURCE_REJECTED"),
        step("start", "s", 1, ok(2, "s", replaced="b")),
        step("start", "a", 1, "SOURCE_EPOCH_STALE"),
        step("seek", "b", 1, "SOURCE_EPOCH_STALE"),
        view(2, "s"),
    ])
    add("G01S-016-a-seek-and-a-start-that-race-the-seek-first-then-the-start", [
        step("start", "s", 0, ok(1, "s")),
        step("seek", "s", 1, ok(1, "s", minted=False)),
        step("start", "a", 1, ok(2, "a", replaced="s")),
    ])
    add("G01S-017-a-seek-and-a-start-that-race-the-start-first-then-the-seek", [
        step("start", "s", 0, ok(1, "s")),
        step("start", "a", 1, ok(2, "a", replaced="s")),
        step("seek", "s", 1, "SOURCE_EPOCH_STALE"),
    ])
    add("G01S-018-labels", [
        step("label", "spotify:", at="", expect="INVALID_SOURCE_LABEL"),
        step("label", "spotify:", at="x" * 65, expect="INVALID_SOURCE_LABEL"),
        step("label", "spotify:", at="Phone", expect="INVALID_SOURCE_LABEL"),
        step("label", "spotify:", at="a@b", expect="INVALID_SOURCE_LABEL"),
        step("label", "airplay2:", at="x" * 64, expect="OK"),
        step("label", "line_in:", at="a", expect="OK"),
        step("label", "line_in:", at="a.b_c-d:9", expect="OK"),
    ])
    out.extend(cell_scenarios())
    return out


# Scenarios that need more than the standard fixture.
def custom_scenarios():
    """(id, table override or None, floor or None, steps). Cells the standard table never uses."""
    seek_replace = {k: dict(v) for k, v in STANDARD.items()}
    seek_replace["airplay2"]["seek"] = REPLACE
    seek_replace["airplay2"]["stop"] = REPLACE
    return [
        ("G01S-C01-a-replacing-seek-takes-the-group", seek_replace, None, [
            step("start", "s", 0, ok(1, "s")),
            step("seek", "a", 1, ok(2, "a", replaced="s")),
            step("publish", "s", 1, "SOURCE_REPLACED"),
        ]),
        ("G01S-C02-a-replacing-stop-leaves-the-group-idle", seek_replace, None, [
            step("start", "s", 0, ok(1, "s")),
            step("stop", "a", 1, ok(2, None, replaced="s")),
            step("publish", "s", 1, "NO_ACTIVE_SOURCE"),
            view(2, None),
        ]),
        ("G01S-C03-resume-after-a-durable-floor", None, 7, [
            view(8, None),
            step("start", "s", 7, "SOURCE_EPOCH_STALE"),
            step("start", "s", 8, ok(9, "s")),
        ]),
        ("G01S-C04-an-exhausted-counter-refuses-to-mint", None, U64_MAX, [
            view(U64_MAX, None),
            step("start", "s", U64_MAX, "SOURCE_EPOCH_EXHAUSTED"),
            view(U64_MAX, None),
        ]),
    ]


def make_token(session, kind):
    if kind is None:
        return token_of(session.group, session.coord, session.epoch, FAR_FUTURE)
    if kind == "stale":
        return token_of(session.group, session.coord, session.epoch - 1, FAR_FUTURE)
    if kind == "future":
        return token_of(session.group, session.coord, session.epoch + 1, FAR_FUTURE)
    if kind == "expired":
        return token_of(session.group, session.coord, session.epoch, 1_000)
    if kind == "wrong_group":
        return token_of("other", session.coord, session.epoch, FAR_FUTURE)
    if kind == "wrong_issuer":
        return token_of(session.group, "impostor", session.epoch, FAR_FUTURE)
    raise ValueError(kind)


def code_of(refusal):
    return refusal.code


def run_steps(steps, rules=None, table=None, floor=None):
    """Replay one scenario. Returns a list of failure strings (empty = every expectation held)."""
    session = base.Session("coord")
    arb = Arbiter(rules, table, floor=floor)
    failures = []
    for index, s in enumerate(steps):
        label = f"step {index} {s['op']}"
        op, who, at, expect = s["op"], s["who"], s["at"], s["expect"]
        if op == "group_epoch":
            session.begin_epoch(at)
            continue
        if op == "label":
            kind = who.rstrip(":")
            try:
                source_id(kind, at, rules)
                got = "OK"
            except Refuse as refusal:
                got = refusal.code
            if got != expect:
                failures.append(f"{label}: expected {expect}, got {got}")
            continue
        if op == "view":
            got = arb.view(session)
            want = (expect["group"], expect["epoch"], SOURCES[expect["owner"]] if expect["owner"] else None)
            if got != want:
                failures.append(f"{label}: expected view {want}, got {got}")
            continue
        source = SOURCES[who]
        before = arb.fingerprint()
        try:
            if op == "publish":
                arb.check_publish(session, source, at)
                got = "OK"
            else:
                receipt = arb.submit(session, make_token(session, s.get("tok")), 5_000, source, op, at)
                got = {
                    "epoch": receipt["epoch"],
                    "owner": NAME_OF[receipt["owner"]] if receipt["owner"] else None,
                    "replaced": NAME_OF[receipt["replaced"]] if receipt["replaced"] else None,
                    "minted": receipt["minted"],
                }
        except Refuse as refusal:
            got = refusal.code
            if arb.fingerprint() != before:
                failures.append(f"{label}: a refusal ({got}) changed the arbiter")
        if got != expect:
            failures.append(f"{label}: expected {expect}, got {got}")
    return failures


def run_scenarios(rules=None):
    """{scenario id: failures} for the standard and custom scenarios."""
    results = {}
    for sid, steps in scenarios():
        results[sid] = run_steps(steps, rules)
    for sid, table, floor, steps in custom_scenarios():
        results[sid] = run_steps(steps, rules, table=table, floor=floor)
    return results


def failing(results):
    return sorted(sid for sid, failures in results.items() if failures)


# ---------------------------------------------------------------------------------------- schedule

COUNT_FIELDS = (
    "starts_admitted", "replacements", "owner_restarts", "seeks_applied", "group_changes_applied",
    "stops_admitted", "stale_refused", "future_refused", "policy_refused", "no_source_refused",
    "authority_refused", "published", "publish_replaced", "publish_not_owner", "publish_stale",
    "publish_group_advanced", "publish_no_source", "race_rounds", "race_winners", "group_advances",
)


def add_count(counts, field, n=1):
    counts[field] = counts.get(field, 0) + n


def run_schedule(seed, steps, rules=None, table=None):
    """Drive four sources through random, deliberately stale interleavings.

    Every source remembers only what it was last told (`known`) and the epoch under which it believes it
    owns the group (`granted`), so stale views arise naturally. Returns (counts, violations), where
    the violations are computed from the receipts, never from the arbiter's own state alone."""
    rng = SplitMix64(seed ^ 0x4730_3153)
    rules = rules or SourceRules()
    session = base.Session("coord")
    arb = Arbiter(rules, table)
    tab = table or STANDARD
    token = make_token(session, None)
    known = [0] * 4
    granted = [None] * 4
    previous = [None] * 4  # the epoch of the stream a source owned before its latest grant
    now = 1_000
    counts = {}
    violations = []
    minted_epochs = set()
    void = [False]  # after a group epoch advance only a Start can be admitted, until one has been

    def check(cond, text):
        if not cond:
            violations.append(f"seed {seed}: {text}")

    def learn(index, receipt):
        new = receipt["epoch"] if receipt["owner"] == SOURCES[SCHEDULE_SOURCES[index]] else None
        if granted[index] is not None and new != granted[index]:
            previous[index] = granted[index]
        known[index] = receipt["epoch"]
        granted[index] = new

    def command(index, cls, expected, tok=None, racing=None):
        """Submit and judge by receipts. Returns the receipt or None."""
        source = SOURCES[SCHEDULE_SOURCES[index]]
        before_view = arb.view(session)
        before_state = arb.fingerprint()
        use = token if tok is None else tok
        try:
            receipt = arb.submit(session, use, now, source, cls, expected)
        except Refuse as refusal:
            check(arb.fingerprint() == before_state, f"a refused {cls} changed the arbiter ({refusal.code})")
            code = refusal.code
            _, before_epoch, _ = before_view
            if tok is not None:
                check(code in AUTHORITY_CODES, f"a token that is not current was refused as {code}")
            elif expected < before_epoch:
                check(code == "SOURCE_EPOCH_STALE", f"{cls} at epoch {expected} < {before_epoch} was refused as {code}")
            elif expected > before_epoch:
                check(code == "SOURCE_EPOCH_FUTURE", f"{cls} at epoch {expected} > {before_epoch} was refused as {code}")
            else:
                check(code in ("SOURCE_REJECTED", "NO_ACTIVE_SOURCE", "SOURCE_EPOCH_EXHAUSTED"),
                      f"{cls} at the current epoch was refused as {code}")
            if code in AUTHORITY_CODES:
                add_count(counts, "authority_refused")
            elif code == "SOURCE_EPOCH_STALE":
                add_count(counts, "stale_refused")
                known[index] = refusal.details["current"]
            elif code == "SOURCE_EPOCH_FUTURE":
                add_count(counts, "future_refused")
            elif code == "SOURCE_REJECTED":
                add_count(counts, "policy_refused")
            elif code == "NO_ACTIVE_SOURCE":
                add_count(counts, "no_source_refused")
            return None
        # Admitted: judge from the receipt and the view taken just before.
        _, before_epoch, before_owner = before_view
        check(tok is None, "a command under a token that is not current was admitted")
        check(cls == "start" or not void[0], f"a {cls} was admitted after a group epoch advance with no new Start")
        check(cls != "start" or receipt["minted"], "a Start did not begin a new stream")
        check(cls != "stop" or (receipt["minted"] and receipt["owner"] is None), "a Stop did not end the stream")
        check(expected == before_epoch, f"{cls} admitted at epoch {expected} while the current one was {before_epoch}")
        if receipt["minted"]:
            check(receipt["epoch"] == before_epoch + 1, f"minted epoch {receipt['epoch']} after {before_epoch}")
            check(receipt["epoch"] not in minted_epochs, f"epoch {receipt['epoch']} minted twice")
            minted_epochs.add(receipt["epoch"])
        else:
            check(receipt["epoch"] == before_epoch, f"a non-minting {cls} moved the epoch")
        if source != before_owner:
            check(before_owner is None and cls == "start" or tab[source[0]][cls] == REPLACE,
                  f"{cls} by a non-owner admitted against policy")
            check(receipt["minted"], f"a takeover by {cls} did not mint")
            check(receipt["replaced"] == before_owner, "the displaced source is not the previous owner")
        else:
            check(receipt["replaced"] is None, "the owner replaced itself")
            check(cls != "seek" or not receipt["minted"], "a seek minted an epoch")
        view_after = arb.view(session)
        check(view_after[1] == receipt["epoch"] and view_after[2] == receipt["owner"], "receipt and view disagree")
        learn(index, receipt)
        if cls == "start":
            void[0] = False
        if receipt["replaced"] is not None:
            add_count(counts, "replacements")
        key = {"start": "starts_admitted", "seek": "seeks_applied", "group_change": "group_changes_applied",
               "stop": "stops_admitted"}[cls]
        add_count(counts, key)
        if cls == "start" and source == before_owner:
            add_count(counts, "owner_restarts")
        return receipt

    def publish(index):
        source = SOURCES[SCHEDULE_SOURCES[index]]
        epoch = granted[index] if granted[index] is not None else known[index]
        if rng.below(6) == 0 and previous[index] is not None:
            epoch = previous[index]  # a late block of the stream this source owned before
        before_view = arb.view(session)
        try:
            arb.check_publish(session, source, epoch)
        except Refuse as refusal:
            code = refusal.code
            if before_view[2] is not None and source != before_view[2] and epoch < before_view[1] \
                    and arb.bound == session.epoch:
                check(code == "SOURCE_REPLACED", f"an older-epoch block from a non-owner was refused as {code}")
            field = {"SOURCE_REPLACED": "publish_replaced", "NOT_SOURCE_OWNER": "publish_not_owner",
                     "SOURCE_EPOCH_STALE": "publish_stale", "GROUP_EPOCH_ADVANCED": "publish_group_advanced",
                     "NO_ACTIVE_SOURCE": "publish_no_source", "SOURCE_EPOCH_FUTURE": "publish_stale"}[code]
            add_count(counts, field)
            if code == "SOURCE_REPLACED":
                granted[index] = None
                known[index] = refusal.details["current"]
            return
        # Accepted: only the owner, under the current epoch, in the current group epoch.
        check(source == before_view[2] and epoch == before_view[1],
              f"a block from {source} at epoch {epoch} reached output; the owner is {before_view[2]} at {before_view[1]}")
        check(not void[0], "a block reached output after a group epoch advance with no new Start")
        add_count(counts, "published")

    for _ in range(steps):
        now += 1 + rng.below(5)
        roll = rng.below(100)
        if roll < 28:
            index = rng.below(4)
            command(index, "start", known[index])
        elif roll < 42:
            index = rng.below(4)
            command(index, "seek", known[index])
        elif roll < 50:
            index = rng.below(4)
            command(index, "group_change", known[index])
        elif roll < 56:
            index = rng.below(4)
            command(index, "stop", known[index])
        elif roll < 78:
            publish(rng.below(4))
        elif roll < 90:
            index = rng.below(4)
            _, epoch, owner = arb.view(session)
            known[index] = epoch
            granted[index] = epoch if owner == SOURCES[SCHEDULE_SOURCES[index]] else None
        elif roll < 95:
            racers = 2 + rng.below(3)
            expected = arb.view(session)[1]
            add_count(counts, "race_rounds")
            minted_in_round = 0
            for _ in range(racers):
                index = rng.below(4)
                cls = CLASSES[rng.below(4)]
                receipt = command(index, cls, expected)
                if receipt is not None and receipt["minted"]:
                    minted_in_round += 1
            check(minted_in_round <= 1, f"{minted_in_round} commands that saw the same epoch were admitted as new epochs")
            if minted_in_round == 1:
                add_count(counts, "race_winners")
        elif roll < 98:
            session.begin_epoch(session.epoch + 1)
            token = make_token(session, None)
            void[0] = True
            add_count(counts, "group_advances")
        else:
            index = rng.below(4)
            stale = make_token(session, "stale") if session.epoch > 1 else make_token(session, "wrong_issuer")
            command(index, "start", known[index], tok=stale)
    return counts, violations


SCHEDULE_SEEDS = tuple(range(8))
SCHEDULE_STEPS = 600


def run_all_seeds(rules=None, table=None):
    totals = {}
    violations = []
    for seed in SCHEDULE_SEEDS:
        counts, found = run_schedule(seed, SCHEDULE_STEPS, rules, table)
        for field, n in counts.items():
            add_count(totals, field, n)
        violations.extend(found)
    return totals, violations


# --------------------------------------------------------------------------------- mutation matrix

# Rules that no scenario or schedule can notice, with the reason. Everything else must be caught.
EQUIVALENT = {}


def mutation_matrix():
    """{rule: (scenario ids that fail, schedule violations, in which seeds)} for each broken rule."""
    out = {}
    for name in RULE_NAMES:
        rules = broken(name)
        failed = failing(run_scenarios(rules))
        _, violations = run_all_seeds(rules)
        out[name] = (failed, violations)
    return out


def self_check():
    problems = []
    green = run_scenarios()
    problems += [f"baseline {sid}: {f}" for sid, fs in green.items() for f in fs]
    totals, violations = run_all_seeds()
    problems += [f"baseline schedule: {v}" for v in violations]
    for name, (failed, found) in mutation_matrix().items():
        if not failed and not found and name not in EQUIVALENT:
            problems.append(f"rule `{name}` can be broken and nothing notices")
    for (kind, cls), want in EXPECTED_CELLS.items():
        if STANDARD[kind][cls] != want:
            problems.append(f"table cell {kind}/{cls} is {STANDARD[kind][cls]}, the contract says {want}")
    return problems, totals


def main(argv):
    if argv[1:] not in ([], ["--check"]):
        print("usage: source_reference.py [--check]", file=sys.stderr)
        return 2
    problems, totals = self_check()
    if problems:
        print("source arbitration reference FAILED:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    matrix = mutation_matrix()
    print(f"ok: {len(scenarios()) + len(custom_scenarios())} scenarios, {len(SCHEDULE_SEEDS)} seeds x {SCHEDULE_STEPS} steps")
    print("schedule totals:", ", ".join(f"{k}={totals.get(k, 0)}" for k in COUNT_FIELDS))
    for name, (failed, found) in matrix.items():
        print(f"  broken {name:28s} scenarios failing: {len(failed):3d}  schedule violations: {len(found)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
