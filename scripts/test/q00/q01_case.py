#!/usr/bin/env python3
"""Run one Q01 case (bead ffw-gmq) as a run-suite case (result contract ffw.case-result.v1, v1.1).

    q01_case.py CASE_ID

The Q01 harness is a Rust simulation that runs only through the centralized RCH path, never on the orchestrator. Its evidence is the log
of that run: ``cargo test -p franken-speaker --features harness --lib -- --nocapture``. ``FFW_Q01_LOG`` names that log (several logs:
joined with os.pathsep). The judging is `tests/q01/run_cases.py`'s, unchanged, so the standalone replay (`scripts/e2e/q01 --judge LOG`)
and this path cannot disagree; this adapter only maps what that judge observed onto the verdict fields of the result file:

  pass        every test of the case reported ``ok`` in the log, and for the two measurement cases every record printed by the executed campaign
              re-derives (the digest of silence is recomputed here, the counter and the digest must agree, the contract's limit-1 table is
              held to it, the planted silence is named for each member and its unplanted control passed)
  fail        a test of the case FAILED (or reported two results), or a measurement record does not re-derive
  incomplete  the log is missing or unreadable, or a test of the case printed no result (absent, ignored, truncated, cancelled): never a
              pass, never a manufactured failure

Whether a case passes is never decided by absence of error text. The run-suite manifest also declares ``requires.env: FFW_Q01_LOG``, so
without a log the runner reports every case ``blocked`` and this adapter is not even started.

Exit codes: 0 pass, 1 fail, 2 incomplete or usage error. When FFW_RESULT_PATH is set the result is written atomically with the run id, case
id and nonce the runner supplied.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

RESULT_SCHEMA = "ffw.case-result.v1"
MAX_RESULT_BYTES = 256 * 1024
LOG_ENV = "FFW_Q01_LOG"
HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
JUDGE = os.path.join(REPO, "tests", "q01", "run_cases.py")
MEASUREMENT_RECORDS = {"Q01-M01": "Q01-MEMBER", "Q01-M02": "Q01-PLANT"}
ORACLE_KIND = {"Q01-M01": "sample"}  # every other case is judged by what its named tests asserted: a property


def load_judge(path: str = JUDGE) -> Any:
    """Import tests/q01/run_cases.py by explicit path: the one judge, shared with the standalone replay."""
    if not os.path.isfile(path):
        raise ImportError("the Q01 judge is not at %s" % path)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("ffw_q01_run_cases", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ffw_q01_run_cases"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_result(path: str, doc: Dict[str, Any]) -> None:
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    if len(data.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds the 256 KiB limit")
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "x", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)  # our own scratch file only
        except OSError:
            pass
        raise


def read_logs(paths: List[str]) -> Tuple[List[Tuple[str, str, str]], List[str]]:
    """(name, sha256, text) for every readable log, and a reason for every one that is not."""
    logs: List[Tuple[str, str, str]] = []
    problems: List[str] = []
    for path in paths:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as error:
            problems.append("log_unreadable:%s:%s" % (os.path.basename(path), type(error).__name__))
            continue
        logs.append((os.path.basename(path), hashlib.sha256(raw).hexdigest(), raw.decode("utf-8", errors="replace")))
    return logs, problems


def judge_case(rc: Any, case_id: str, logs: List[Tuple[str, str, str]], log_problems: List[str]) -> Dict[str, Any]:
    """Map what the Q01 judge observed in the log onto the verdict fields of the result file (pure; unit-tested)."""
    case = next((c for c in rc.load_cases() if c["id"] == case_id), None)
    if case is None:
        raise KeyError(case_id)
    base: Dict[str, Any] = {"oracle": "q01.cargo-test.%s" % case_id, "oracle_kind": ORACLE_KIND.get(case_id, "property"),
                            "independent": True}
    identities = [{"name": name, "sha256": digest} for name, digest, _text in logs]
    if log_problems or not logs:
        reasons = log_problems or ["no_log"]
        return dict(base, verdict="incomplete", finalized=False, incomplete_reasons=reasons, checks=0, mismatches=0, violation_kinds={},
                    expected=None, observed=None, first_causal_event=", ".join(reasons), counters={"logs_read": len(logs)})
    log = rc.Log()
    for name, _digest, text in logs:
        log.add(text, name)
    results, notes, measured = rc.judge_cases(log)
    result = next(r for r in results if r.case == case_id)
    tests = case["tests"]
    statuses = {t: log.status(t) for t in tests}
    ok = sum(1 for s in statuses.values() if s == "ok")
    failed = [t for t, s in statuses.items() if s in ("FAILED", "conflict")]
    absent = [t for t, s in statuses.items() if s in (None, "ignored")]
    records = 0
    if case_id == "Q01-M01":
        records = len(measured)
    elif case_id == "Q01-M02":
        records = len(log.plants)
    counters = {"tests": len(tests), "tests_ok": ok, "tests_failed": len(failed), "tests_absent": len(absent),
                "records_rederived": records if result.status == "pass" else 0, "logs_read": len(logs),
                "unterminated_names": len(log.unterminated)}
    if result.status == "pass":
        return dict(base, verdict="pass", finalized=True, incomplete_reasons=[], checks=ok + records, mismatches=0, violation_kinds={},
                    expected={"tests_ok": len(tests), "records": records}, observed={"tests_ok": ok, "records": records, "logs": identities},
                    first_causal_event="none: every test of the case reported ok" + (" and every record re-derived" if records else ""),
                    counters=counters)
    if result.status == "fail":
        record_problems = 0 if failed else 1
        kinds = {k: v for k, v in (("test_failed", len(failed)), ("record_mismatch", record_problems)) if v}
        return dict(base, verdict="fail", finalized=True, incomplete_reasons=[], checks=max(ok, 1), mismatches=len(failed) + record_problems,
                    violation_kinds=kinds, expected={"tests_failed": 0, "record_problems": 0},
                    observed={"tests_failed": len(failed), "failed": failed[:3], "detail": result.detail[:300], "logs": identities},
                    first_causal_event=result.detail[:300], counters=counters)
    reasons = ["tests_absent:%d" % len(absent)] if absent else ["blocked:%s" % result.detail[:120]]
    return dict(base, verdict="incomplete", finalized=False, incomplete_reasons=reasons, checks=ok, mismatches=0, violation_kinds={},
                expected=None, observed=None, first_causal_event="%s: %s" % (", ".join(reasons), ", ".join(absent[:3])), counters=counters)


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0].startswith("-"):
        print("usage: q01_case.py CASE_ID", file=sys.stderr)
        return 2
    case_id = args[0]
    try:
        rc = load_judge()
    except Exception as error:
        print("q01_case: cannot load the Q01 judge: %s" % error, file=sys.stderr)
        return 2
    target = None
    if os.environ.get("FFW_RESULT_PATH"):
        ids = {k: os.environ.get(k) for k in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE")}
        missing = [k for k, v in ids.items() if not v]
        if missing:
            print("q01_case: %s required when FFW_RESULT_PATH is set" % ", ".join(missing), file=sys.stderr)
            return 2
        target = (os.environ["FFW_RESULT_PATH"], ids)
    raw = os.environ.get(LOG_ENV, "")
    paths = [p for p in raw.split(os.pathsep) if p]
    logs, log_problems = read_logs(paths)
    try:
        verdict = judge_case(rc, case_id, logs, log_problems)
    except KeyError:
        print("q01_case: %s is not a Q01 case (tests/q01/cases.json)" % case_id, file=sys.stderr)
        return 2
    c = verdict["counters"]
    print("Q01 %s: verdict=%s tests_ok=%s tests_failed=%s tests_absent=%s records=%s first=%s" % (
        case_id, verdict["verdict"], c.get("tests_ok", 0), c.get("tests_failed", 0), c.get("tests_absent", 0),
        c.get("records_rederived", 0), verdict["first_causal_event"][:200]), flush=True)
    if target is not None:
        path_out, ids = target
        doc = dict(verdict, schema=RESULT_SCHEMA, run_id=ids["FFW_RUN_ID"], case_id=ids["FFW_CASE_ID"], nonce=ids["FFW_RESULT_NONCE"])
        _write_result(path_out, doc)
    return {"pass": 0, "fail": 1}.get(verdict["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
