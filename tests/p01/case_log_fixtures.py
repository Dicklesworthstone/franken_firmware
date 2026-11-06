"""Worlds for P01-LOG-001: the runner's case execution against the shared Q00 diagnostic sink, in a baseline and with each planted failure of the
log. The expected values are hand-written; the sink, its redaction and its audit are the shared module's own (stdlib only, no I/O outside a
temporary directory).

A world is the same real cases run through `execute` with a log. The baseline (a permitted file sink) is the control: every plant is judged
against it, and taking the plant away gives the baseline back.

    baseline        a real file sink: header first, one critical begin and end per case, one run summary, footer last, closure identity
                    holds, the independent audit says complete, the verdicts are the cases' own and the run qualifies
    full            a target out of space after a few bytes: verdicts unchanged, evidence incomplete, run not qualified (exit 1)
    unavailable     a target that fails every write: the same
    slow            a target whose writer is blocked (a hung disk): `execute` returns in bounded time, verdicts unchanged, evidence incomplete
    unrecorded_end  a case whose `case.end` was never emitted, though the sink lost nothing it was given: the run's own count of critical
                    events falls short, so the evidence is incomplete
    no_sink         the shared module cannot be loaded: verdicts unchanged, no log, not qualified
    redaction       a secret value, a token and the home directory in a case's detail never reach the log

The original logging acceptance also names member and group pseudonyms, source epoch, command and state revision, queue/latency/resource
counters, an injected fault schedule and the render path's deadlines. A host check of manifests, the lockfile and committed records has no
member, group, epoch, queue or audio; docs/contracts/p01.md says so field by field and maps what does apply to these worlds and to the cases.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Callable, Dict, List, Sequence, Tuple

import case_log

SECRET_VALUE = "hunter" + "2-" + "swordfish-" + "9f3a"  # built from pieces so this file holds no literal secret
TOKEN = "ghp_" + "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8"
SLOW_BOUND_S = 5.0  # a blocked writer may cost the run its close timeout (0.3 s here), never an unbounded wait
LOG_NAME = "p01-diag-smoke-worldrun.jsonl"


def totals_of(results: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    return {"total": len(results), "passed": sum(r["status"] == "pass" for r in results),
            "failed": sum(r["status"] == "fail" for r in results), "blocked": sum(r["status"] == "blocked" for r in results)}


def run_world(repo: str, cases: List[Dict[str, Any]], execute: Callable, *, receipts: str = "", target: Any = None, limits: Any = None,
              log_class: Any = None, log_repo: str = "") -> Tuple[List[Dict[str, Any]], Any, float, Any]:
    """(results, evidence, seconds, log) of `cases` executed with a fresh log. `log_class` replaces CaseLog (a plant that overrides one
    method); `log_repo` is where the shared module is looked for (an empty directory makes it unavailable)."""
    log = (log_class or case_log.CaseLog).open(log_repo or repo, "worldrun", "smoke", receipts or None, target=target, limits=limits)
    started = time.monotonic()
    results = execute(cases, {}, log, False)
    seconds = time.monotonic() - started
    return results, log.finish(totals_of(results)), seconds, log


def read_log(path: str) -> List[Dict[str, Any]]:
    with open(path, "rb") as f:
        return [json.loads(line) for line in f.read().decode("ascii").splitlines() if line.strip()]


class SkipsOneEnd(case_log.CaseLog):
    """The plant of `unrecorded_end`: the second case's end event is never emitted."""

    def end(self, case, status, detail, started, error=None):
        if self.cases == 2:
            return
        super().end(case, status, detail, started, error)


def judge_worlds(repo: str, cases: List[Dict[str, Any]], execute: Callable, judge_run: Callable) -> str:
    """AssertionError naming every broken world, or a one-line summary when the baseline and all six plants behave."""
    diag = case_log.load(repo)
    problems: List[str] = []

    def need(ok: bool, message: str) -> None:
        if not ok:
            problems.append(message)

    if len(cases) != 3:
        raise AssertionError(f"want 3 real cases, got {len(cases)}")
    with tempfile.TemporaryDirectory() as tmp:
        base, evidence, _s, _l = run_world(repo, cases, execute, receipts=tmp)
        events = read_log(os.path.join(tmp, LOG_NAME))
    want = [(r["id"], r["status"]) for r in base]
    ids = [c["id"] for c in cases]
    body = [e for e in events if e["type"] == "event"]
    need(evidence.complete and not evidence.reasons, f"baseline: evidence {evidence.reasons}")
    need(events[0]["type"] == "header" and events[0]["schema"] == "ff.diag.v1" and events[-1]["type"] == "footer", "baseline: no header/footer")
    need([(e["kind"], e.get("case")) for e in body] == [k for i in ids for k in (("case.begin", i), ("case.end", i))] + [("run.summary", None)],
         "baseline: the events are not a begin and an end per case, then the summary")
    need(all(e["critical"] for e in body), "baseline: an event is not critical")
    need({e["case"]: e["fields"]["status"] for e in body if e["kind"] == "case.end"} == dict(want), "baseline: logged statuses differ from the results")
    j = judge_run(base, evidence.complete)
    need((j["qualified"], j["exit"], j["outcome"]) == (True, 0, "pass"), f"baseline: {j}")

    def plant(label: str, results, ev, extra: bool = True) -> None:
        need([(r["id"], r["status"]) for r in results] == want, f"{label}: a verdict changed with the log")
        need(not ev.complete and bool(ev.reasons) and extra, f"{label}: evidence still complete ({ev.reasons})")
        v = judge_run(results, ev.complete)
        need((v["qualified"], v["exit"], v["outcome"]) == (False, 1, "incomplete"), f"{label}: the run is {v}")

    full = diag.FaultableSink(capacity_bytes=1500)
    r, ev, _s, _l = run_world(repo, cases, execute, target=full)
    plant("full", r, ev)
    down = diag.FaultableSink()
    down.available = False
    r, ev, _s, _l = run_world(repo, cases, execute, target=down)
    plant("unavailable", r, ev)
    slow = diag.FaultableSink()
    slow.gate()
    r, ev, seconds, _l = run_world(repo, cases, execute, target=slow, limits=diag.SinkLimits(close_timeout_s=0.3))
    slow.ungate()
    plant("slow", r, ev, extra=seconds < SLOW_BOUND_S)
    with tempfile.TemporaryDirectory() as tmp:
        r, ev, _s, _l = run_world(repo, cases, execute, receipts=tmp, log_class=SkipsOneEnd)
    plant("unrecorded_end", r, ev, extra=any(x.startswith("critical_event_count:") for x in ev.reasons))
    with tempfile.TemporaryDirectory() as empty:
        r, ev, _s, _l = run_world(repo, cases, execute, log_repo=empty)
    plant("no_sink", r, ev, extra=any(x.startswith("diagnostics_unavailable") for x in ev.reasons))

    with tempfile.TemporaryDirectory() as tmp:
        log = case_log.CaseLog.open(repo, "worldrun", "smoke", tmp)
        probe = {"id": "P01-RED-1", "kind": "synthetic", "title": "redaction"}
        log.begin(probe)
        home = os.path.expanduser("~")
        log.end(probe, "fail", f"password={SECRET_VALUE} token {TOKEN} under {home}/work/file", time.monotonic())
        red = log.finish({"total": 1, "passed": 0, "failed": 1, "blocked": 0})
        with open(os.path.join(tmp, LOG_NAME), "rb") as f:
            text = f.read().decode("ascii")
    need(red.complete, f"redaction: evidence {red.reasons}")
    need(SECRET_VALUE not in text and TOKEN not in text and (len(home) < 4 or home + "/" not in text), "redaction: a secret, a token or the home directory reached the log")
    need("[REDACTED" in text, "redaction: nothing was marked as redacted")

    if problems:
        raise AssertionError("; ".join(problems))
    return (f"baseline complete ({evidence.log['events']} critical events, audited from the file); full, unavailable, slow, unrecorded-end and "
            "no-sink logs leave every verdict as it was but are incomplete and not qualified (exit 1); redaction holds")
