"""The U01 verification battery: every property the specification states, checked against `reference.py`. It is run by
the unit tests, and again by the mutation canary against a copy of the reference with one rule broken (a mutant that does
not make the battery fail means the battery is too weak). Exit status 0 only if every check holds."""
from __future__ import annotations

import copy
import sys
from typing import Any, Callable, Dict, List

import images
import reference as ref
import scenarios as sc

LIM = ref.TINY
b = sc.b


def fresh(lim: ref.Limits = LIM):
    media = ref.Media(lim.segment_bytes)
    journal, _rec = ref.Journal.open(media, lim)
    return media, journal


def run_steps(journal, steps, strict: bool = False):
    outcomes = []
    for step in steps:
        try:
            outcomes.append(getattr(journal, step[0])(*step[1:]) or "ok")
        except ref.JournalError as err:
            if strict:
                raise
            outcomes.append("ERR:" + err.code)
    return outcomes


def reopen(media, lim: ref.Limits = LIM):
    media.restart()
    return ref.Journal.open(media, lim)


def expect_error(code: str, fn: Callable[[], Any]) -> ref.JournalError:
    try:
        fn()
    except ref.JournalError as err:
        assert err.code == code, f"expected {code}, got {err.code}"
        return err
    raise AssertionError(f"expected {code}, but the operation succeeded")


# --------------------------------------------------------------------------- properties

def check_cut_points() -> None:
    """Power cut at every storage-operation boundary and every byte budget: old or new, never mixed."""
    for name, stride in (("rejections", 1), ("credentials", 1), ("namespaces", 1), ("cross_namespace", 1), ("churn", 5)):
        for reverse in (False, True):
            ref.enumerate_cuts(LIM, sc.SCENARIOS[name], reverse=reverse, stride=stride)


def check_cross_namespace_transactions() -> None:
    """One transaction that spans credentials and calibration is all-or-nothing: at every power cut and under every injected
    failure inside it, the credential and the calibration it wrote recover as the old pair or the new pair, never one of
    each. This holds for a transaction that is appended as a frame and for one that is published by compaction. A
    transaction rejected for one bad operation leaves even its valid operations unapplied."""
    txn = ("commit", [("install", b("peer"), 2, b("secret-2")), ("put", ref.NS_CALIBRATION, b("board-a"), b("cal-2"))])
    base = [("put", ref.NS_CALIBRATION, b("board-a"), b("cal-1")), ("install", b("peer"), 1, b("secret-1"))]
    old_pair = (("live", 1, b("secret-1")), b("cal-1"))
    new_pair = (("live", 2, b("secret-2")), b("cal-2"))

    def pair(journal):
        return journal.state[ref.NS_CREDENTIALS].get(b("peer")), journal.state[ref.NS_CALIBRATION].get(b("board-a"))

    def fill(rounds):
        return [s for i in range(rounds) for s in (("stage_setting", b("vol"), b(f"{i:02d}")), ("flush_settings", 100 * (i + 1)))]

    def outcome_of(prefix):
        _media, journal = fresh()
        for step in prefix:
            getattr(journal, step[0])(*step[1:])
        return journal.commit(txn[1])

    rounds = 0
    while outcome_of(base + fill(rounds)) != "compacted":
        rounds += 1
        assert rounds < 30, "no amount of filler makes the transaction compact"

    def cuts_and_failures(prefix):
        script = prefix + [txn]
        baseline = ref.Media(LIM.segment_bytes)
        _states, ranges, _j = ref.run_script(LIM, script, baseline)
        start, end = ranges[-1]
        assert end - start >= 2, "the transaction must take at least a write and a sync"
        pending = list(baseline.pending_before) + [0]
        reached = set()
        for n in range(start, end + 1):
            for k in (range(pending[n] + 1) if n < baseline.ops_done else range(1)):
                for reverse in (False, True):
                    media = ref.Media(LIM.segment_bytes)
                    media.cut_after_ops, media.cut_budget, media.cut_reverse = n, k, reverse
                    try:
                        ref.run_script(LIM, script, media)
                    except ref.JournalError:
                        pass
                    if not media.dead:
                        media.power_cut(0, reverse)
                    recovered, _ = reopen(media)
                    got = pair(recovered)
                    assert got in (old_pair, new_pair), f"cut n={n} k={k} reverse={reverse}: credential and calibration mixed: {got}"
                    reached.add(got == new_pair)
        assert reached == {False, True}, "the cuts must reach both the old pair and the new pair, or the check proves nothing"
        for i in range(start, end):
            for mode in ("io", "sync_lost", "sync_kept"):
                media = ref.Media(LIM.segment_bytes)
                journal, _rec = ref.Journal.open(media, LIM)
                for step in prefix:
                    getattr(journal, step[0])(*step[1:])
                before = ref.state_hex(journal.state)
                if mode == "io":
                    media.fail_op_at = i
                else:
                    media.sync_fail_at, media.sync_fail_persists = i, mode == "sync_kept"
                try:
                    journal.commit(txn[1])
                except ref.JournalError as err:
                    assert err.code == "storage", err.code
                else:
                    continue  # this op index is not of the kind the mode injects
                assert journal.poisoned and ref.state_hex(journal.state) == before, "a failed transaction published something"
                reopened, _ = reopen(media)
                assert pair(reopened) in (old_pair, new_pair), f"failure {mode} at op {i}: credential and calibration mixed"

    for label, prefix in (("appended", base), ("compacted", base + fill(rounds))):
        assert outcome_of(prefix) == label, f"the {label} variant did not take the {label} path"
        cuts_and_failures(prefix)

    # A rejected transaction: the first operation is valid on its own, the second is not. Nothing may change.
    _media, journal = fresh()
    for step in base:
        getattr(journal, step[0])(*step[1:])
    before, ops_before = ref.state_hex(journal.state), journal.media.ops_done
    rejected = [("put", ref.NS_CALIBRATION, b("board-a"), b("cal-REJ")), ("install", b("peer"), 1, b("secret-x"))]
    expect_error("not_newer", lambda: journal.commit(rejected))
    assert ref.state_hex(journal.state) == before, "a rejected transaction left its valid operations applied"
    assert journal.media.ops_done == ops_before, "a rejected transaction wrote to the medium"
    journal.commit(rejected[:1])  # control: the same first operation alone is valid and does change the state
    assert ref.state_hex(journal.state) != before


def check_failed_operations() -> None:
    """A write, erase or sync that reports failure (or whose outcome is unknown) poisons the journal, leaves the published
    state as it was, and reopening yields exactly the old or the new state."""
    script = sc.SCENARIOS["credentials"]
    target = 3  # revoke a: the tombstone boundary
    baseline = ref.Media(LIM.segment_bytes)
    states, ranges, _j = ref.run_script(LIM, script, baseline)
    start, end = ranges[target + 1]
    assert end > start
    for i in range(start, end):
        for mode in ("io", "sync_lost", "sync_kept"):
            media = ref.Media(LIM.segment_bytes)
            journal, _rec = ref.Journal.open(media, LIM)
            for step in script[:target]:
                try:
                    getattr(journal, step[0])(*step[1:])
                except ref.JournalError:
                    pass
            before = ref.state_hex(journal.state)
            if mode == "io":
                media.fail_op_at = i
            else:
                media.sync_fail_at, media.sync_fail_persists = i, mode == "sync_kept"
            failed = False
            try:
                getattr(journal, script[target][0])(*script[target][1:])
            except ref.JournalError as err:
                failed = err.code == "storage"
                assert failed, err.code
            if not failed:
                continue  # this op index is not of the kind the mode injects (a sync under "io", a program under "sync_*")
            assert journal.poisoned, "a failed storage operation must poison the journal"
            assert ref.state_hex(journal.state) == before, "the published state changed although the commit failed"
            expect_error("poisoned", lambda: journal.put(ref.NS_RECORDS, b("r"), b("v")))
            reopened, _ = reopen(media)
            got = ref.state_hex(reopened.state)
            assert got in (states[target], states[target + 1]), "a failed commit recovered neither old nor new"


def check_namespaces_are_separate() -> None:
    _media, j = fresh()
    j.put(ref.NS_SETTINGS, b("vol"), b("40"))
    j.put(ref.NS_CALIBRATION, b("board-a"), b("cal"))
    j.put(ref.NS_RECORDS, b("voter"), b("rec"))
    j.install(b("peer"), 1, b("secret"))
    j.raise_mark(b("epoch"), 9)
    snap = copy.deepcopy(j.state)

    j.reset_settings()
    assert j.state[ref.NS_SETTINGS] == {}
    for ns in (ref.NS_CALIBRATION, ref.NS_RECORDS, ref.NS_CREDENTIALS, ref.NS_MARKS):
        assert j.state[ns] == snap[ns], "a settings reset touched another namespace"
    j.clear_calibration()
    assert j.state[ref.NS_CALIBRATION] == {}
    for ns in (ref.NS_RECORDS, ref.NS_CREDENTIALS, ref.NS_MARKS):
        assert j.state[ns] == snap[ns], "clearing calibration touched another namespace"
    j.put(ref.NS_SETTINGS, b("vol"), b("41"))
    j.put(ref.NS_CALIBRATION, b("board-a"), b("cal"))
    j.reset_pairing()
    assert j.state[ref.NS_CREDENTIALS][b("peer")] == ("revoked", 1), "a pairing reset leaves a tombstone"
    assert j.state[ref.NS_SETTINGS] == {b("vol"): b("41")}, "a pairing reset touched settings"
    assert j.state[ref.NS_CALIBRATION] == {b("board-a"): b("cal")}, "a pairing reset touched calibration"
    assert j.state[ref.NS_RECORDS] == snap[ref.NS_RECORDS] and j.state[ref.NS_MARKS] == snap[ref.NS_MARKS]


def check_credentials_and_tombstones() -> None:
    media, j = fresh()
    j.install(b("a"), 1, b("s1"))
    expect_error("not_newer", lambda: j.install(b("a"), 1, b("other")))
    expect_error("not_newer", lambda: j.install(b("a"), 0 + 1, b("other")))
    j.install(b("a"), 2, b("s2"))                                       # replacement needs a strictly higher version
    assert j.state[ref.NS_CREDENTIALS][b("a")] == ("live", 2, b("s2"))
    j.revoke(b("a"))
    err = expect_error("revoked", lambda: j.install(b("a"), 2, b("s2")))
    assert err.detail.get("current") == 2
    expect_error("already_revoked", lambda: j.revoke(b("a")))
    expect_error("not_found", lambda: j.revoke(b("zz")))
    for _ in range(2):  # the refusal survives a restart and a compaction
        j, rec = reopen(media)
        assert rec.source == "segment"
        expect_error("revoked", lambda: j.install(b("a"), 2, b("s2")))
        for i in range(30):
            j.stage_setting(b("vol"), f"{i:02d}".encode())
            j.flush_settings(1000 * (i + 1) + 100_000 * _)
        assert j.compactions >= 1
        expect_error("revoked", lambda: j.install(b("a"), 1, b("s1")))
    j.install(b("a"), 3, b("s3"))                                       # a strictly higher version re-admits it
    assert j.state[ref.NS_CREDENTIALS][b("a")][0] == "live"
    # a tombstone still occupies the identity slot: three slots (a, b, c) and nothing can be recycled
    j.install(b("b"), 1, b("sb"))
    j.install(b("c"), 1, b("sc"))
    j.revoke(b("c"))
    expect_error("namespace_full", lambda: j.install(b("d"), 1, b("sd")))


def check_marks() -> None:
    media, j = fresh()
    j.raise_mark(b("epoch"), 5)
    expect_error("mark_regressed", lambda: j.raise_mark(b("epoch"), 4))
    before = media.ops_done
    assert j.raise_mark(b("epoch"), 5) == "noop" and media.ops_done == before, "an unchanged mark must write nothing"
    j.raise_mark(b("epoch"), 6)
    j2, _ = reopen(media)
    assert j2.state[ref.NS_MARKS][b("epoch")] == 6
    expect_error("namespace_full", lambda: j2.raise_mark(b("other"), 1))


def check_bounds_and_errors() -> None:
    media, j = fresh()
    expect_error("invalid_key", lambda: j.put(ref.NS_SETTINGS, b(""), b("v")))
    expect_error("invalid_key", lambda: j.put(ref.NS_SETTINGS, b("k" * 9), b("v")))
    expect_error("value_too_long", lambda: j.put(ref.NS_SETTINGS, b("k"), b("v" * 17)))
    expect_error("bad_op", lambda: j.put(ref.NS_CREDENTIALS, b("k"), b("v")))
    expect_error("bad_version", lambda: j.install(b("p"), 0, b("s")))
    j.put(ref.NS_SETTINGS, b("a"), b("1"))
    j.put(ref.NS_SETTINGS, b("b"), b("2"))
    expect_error("namespace_full", lambda: j.put(ref.NS_SETTINGS, b("c"), b("3")))
    expect_error("not_found", lambda: j.delete(ref.NS_SETTINGS, b("zz")))
    # a transaction larger than the cap is refused and writes nothing
    before = media.ops_done
    expect_error("txn_too_large", lambda: j.commit([("put", ref.NS_SETTINGS, b("a"), b("x" * 16))] * 6))
    assert media.ops_done == before, "a refused operation must not touch the medium"
    assert not j.poisoned
    # the same-value put and the unchanged reset are not written
    assert j.put(ref.NS_SETTINGS, b("a"), b("1")) == "noop" and media.ops_done == before
    # configurations that cannot fit are refused before any medium is touched
    expect_error("bad_config", lambda: ref.Limits(256, 128, (8, 16, 2), (8, 32, 1), (8, 32, 1), (8, 16, 3), (8, 8, 1), 10, 100).validate())


def check_write_bounds() -> None:
    """A volume storm: any number of changes inside one interval is one frame; flushes inside the interval write nothing."""
    media, j = fresh()
    base_ops = media.ops_done
    for i in range(500):
        j.stage_setting(b("vol"), f"{i % 100:02d}".encode())
    assert media.ops_done == base_ops, "staging must not touch the medium"
    assert j.flush_settings(1000) == "appended"
    one_flush = media.ops_done - base_ops
    for tick in (1001, 1005, 1009):
        j.stage_setting(b("vol"), b("77"))
        err = expect_error("rate_limited", lambda: j.flush_settings(tick))
        assert err.detail["retry_after"] == 1010 - tick
    assert media.ops_done - base_ops == one_flush, "a rate-limited flush must write nothing"
    assert j.flush_settings(1010) == "appended"
    assert j.frames_written == 2
    # wear: the compaction budget is a hard limit, and refusing it writes nothing and leaves reads and fitting appends working
    tight = ref.Limits(512, 128, (8, 16, 2), (8, 32, 1), (8, 32, 1), (8, 16, 3), (8, 8, 1), 10, 2)
    media2, j2 = fresh(tight)
    refused = None
    for i in range(80):
        before = media2.ops_done
        try:
            j2.put(ref.NS_SETTINGS, b("a"), f"{i:02d}".encode())
        except ref.JournalError as err:
            refused = err
            assert err.code == "wear_exhausted" and media2.ops_done == before and not j2.poisoned
            break
    assert refused is not None, "the wear budget was never enforced"
    assert j2.state[ref.NS_SETTINGS][b("a")] != b"", "reads still work"


def check_images() -> None:
    for case in images.build():
        media = ref.Media(LIM.segment_bytes)
        media.media[:] = bytes.fromhex(case["image_hex"])
        media.view[:] = media.media
        expect = case["expect"]
        if "error" in expect:
            expect_error(expect["error"], lambda: ref.Journal.open(media, LIM))
            continue
        journal, rec = ref.Journal.open(media, LIM)
        assert ref.state_hex(journal.state) == expect["state_hex"], f"{case['id']}: wrong recovered state"
        for key, attr in (("source", "source"), ("tail_dirty", "tail_dirty"), ("compacted", "compacted"),
                          ("migrated_from", "migrated_from"), ("retired_stale", "retired_stale"), ("gen", "gen")):
            if key in expect:
                assert getattr(rec, attr) == expect[key], f"{case['id']}: {key} is {getattr(rec, attr)!r}, want {expect[key]!r}"
        # the recovered journal is immediately usable and the next write is durable
        journal.put(ref.NS_SETTINGS, b("after"), b("ok"))
        again, rec_again = reopen(media)
        assert again.state[ref.NS_SETTINGS][b("after")] == b("ok"), f"{case['id']}: a write after recovery was lost"
        if "migrated_from" in expect:
            assert rec_again.migrated_from is None, f"{case['id']}: the medium is still in the old schema after migration"


def check_no_resurrection_across_compaction() -> None:
    """Revoke, force compactions, cut the power inside each of them: the revoked identity is never live again."""
    script = [("install", b("a"), 1, b("s")), ("revoke", b("a"))] + sc.churn(rounds=40)[3:]
    result = ref.enumerate_cuts(LIM, script, stride=7)
    assert result["cuts"] > 100


def check_redaction() -> None:
    secret_key, secret_value = b("PEERSECRETKEY"), b("TOPSECRETVALUE")
    media, j = fresh()
    j.install(b("peer"), 1, secret_value[:12])
    attempts = [
        lambda: j.install(secret_key[:8], 1, secret_value),            # value too long
        lambda: j.install(secret_key, 1, b("s")),                      # key too long
        lambda: j.install(b("peer"), 1, b("x" * 5)),                   # not newer
        lambda: j.revoke(b("nobody")),
        lambda: j.put(ref.NS_CREDENTIALS, b("peer"), b("zzzz")),
        lambda: j.put(ref.NS_SETTINGS, secret_key, b("v")),
    ]
    for attempt in attempts:
        try:
            attempt()
        except ref.JournalError as err:
            text = repr(err.detail) + str(err) + repr(err)
            for needle in (b"PEERSECRETKEY", b"TOPSECRETVALUE", b"peer", b"nobody", b"x" * 5):
                assert needle.decode() not in text, "an error carried a key or a value"
            assert all(isinstance(v, (int, str)) for v in err.detail.values()), "error detail must be plain numbers and names"


CHECKS: List[Callable[[], None]] = [
    check_cut_points, check_failed_operations, check_cross_namespace_transactions, check_namespaces_are_separate,
    check_credentials_and_tombstones,
    check_marks, check_bounds_and_errors, check_write_bounds, check_images, check_no_resurrection_across_compaction,
    check_redaction,
]


def main() -> int:
    failed = 0
    for check in CHECKS:
        try:
            check()
        except Exception as err:  # noqa: BLE001 - any divergence is a failure of the battery
            failed += 1
            print(f"FAIL {check.__name__}: {type(err).__name__}: {err}")
        else:
            print(f"ok   {check.__name__}")
    print("battery:", "FAILED" if failed else "all checks hold", f"({len(CHECKS) - failed}/{len(CHECKS)})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
