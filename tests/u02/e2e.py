#!/usr/bin/env python3
"""U02 end-to-end runner (offline, stdlib only; it builds nothing and never invokes cargo).

    e2e.py                       the full tier: the host checks; the Rust tests are BLOCKED until a central log is supplied (counted, never skipped)
    e2e.py --tier smoke          the quick host checks
    e2e.py --tier soak           NOT RUN, with the reason: exit 4, never a pass
    e2e.py --judge LOG           also judge a `cargo test -p franken-update` log by test name (repeatable)
    e2e.py --case ID             run only this case (repeatable; the replay of one case)
    e2e.py --receipts DIR        keep the JSONL diagnostic log and a JSON receipt under DIR
    e2e.py --list                list the cases of the tier

Cases:
  U02-E-001  the vectors are exactly what the generator writes (make_vectors.py --check)
  U02-E-002  the reference, the oracle, the hand-derived pins, the paired positives, the Rust-source agreement and the contract (tests/u02/test_u02.py)
  U02-E-003  every planted defect is caught with the remove-the-plant control green (judge.py), by the stored vectors and by properties alone
  U02-E-004  the Ed25519 oracle against OpenSSL: BLOCKED (not run) if the `cryptography` module is missing, never passed
  U02-E-005  the by-name judge catches planted failures in synthetic logs (judge_log.py --self-test)
  U02-E-006  the Rust tests of crates/franken-update passed centrally, by test name: BLOCKED without --judge
Exit codes: 0 every case passed, none is blocked and the diagnostic log is complete; 1 a case failed or the log lost critical evidence; 3 only blocked
cases stand in the way; 4 --tier soak; 2 usage.

Every decided case writes a CRITICAL begin and end event through the shared Q00 `DiagnosticSink` (case_log.py); a run whose log lost critical evidence is
NOT QUALIFIED. Without --receipts the log is kept in a fresh mkdtemp directory whose path is printed; the runner never deletes it. Each child process is
bounded in time and in the output it may produce.

The central form of the Rust cases (RCH only):
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-update --locked --offline -j 2 -- --nocapture > u02.log 2>&1
    scripts/e2e/u02 --tier full --judge u02.log
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import case_log  # noqa: E402
import judge_log  # noqa: E402

PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
TIERS = ("smoke", "full", "soak")
SMOKE = ("U02-E-001", "U02-E-002")
SOAK_EXIT = 4
SOAK_NOT_RUN = ("U02 soak: NOT RUN. There is no long-running campaign for this task: the update model has no clock and no I/O, and its exhaustive checks (a cut at every "
                "storage operation of every transition) are in the Rust tests. This is not a pass.")
RECEIPT_SCHEMA = "ffw.u02.receipt.v1"
CHILD_TIMEOUT_S = 600
OUTPUT_CAP = 1 << 20
CAUSE_CAP = 400
JUDGED_ARTIFACTS = ("tests/u02/e2e.py", "tests/u02/case_log.py", "tests/u02/judge_log.py", "tests/u02/judge.py", "tests/u02/reference.py", "tests/u02/make_vectors.py",
                    "tests/u02/ed25519_ref.py", "tests/u02/test_u02.py", "crates/franken-update/tests/vectors/u02_vectors.json", "docs/contracts/u02.md",
                    "scripts/test/test_support/diagnostics.py", "tests/u01/e2e.py")


_U01_E2E = os.path.join(REPO, "tests", "u01", "e2e.py")
_U01_BARE_IMPORTS = ("case_log", "reference", "scenarios")   # the modules that file imports by bare name; two of them are also ours


def _u01_run_bounded() -> Callable[..., "subprocess.CompletedProcess[str]"]:
    """U01's owned-process primitive, loaded from its own file and not copied: a child in its own session, both streams drained through bounded pumps, one
    absolute deadline, the child's whole process group killed and reaped on every path, and a timeout or an overflow raised as an `AssertionError` with a
    sentence. U01 imports `case_log` and `reference` by bare name, as this runner does, so the names are held aside while it loads and put back after.
    If the file is missing or does not load, this raises: there is no fallback to an unbounded runner."""
    held = {name: sys.modules.pop(name) for name in _U01_BARE_IMPORTS if name in sys.modules}
    saved_path, saved_bytecode = list(sys.path), sys.dont_write_bytecode
    sys.dont_write_bytecode = True      # loading must not leave a __pycache__ in the U01 directory
    try:
        spec = importlib.util.spec_from_file_location("ffw_u01_e2e", _U01_E2E)
        if spec is None or spec.loader is None:
            raise AssertionError(f"U01's bounded runner could not be loaded from {os.path.relpath(_U01_E2E, REPO)}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        primitive = getattr(module, "run_bounded", None)
        if primitive is None:
            raise AssertionError("U01's e2e.py has no run_bounded")
        return primitive
    finally:
        sys.path[:] = saved_path
        sys.dont_write_bytecode = saved_bytecode
        for name in _U01_BARE_IMPORTS:
            sys.modules.pop(name, None)
        sys.modules.update(held)


def run_bounded(argv: List[str], what: str, timeout: float = CHILD_TIMEOUT_S) -> "subprocess.CompletedProcess[str]":
    """Every child this runner starts goes through U01's bounded primitive: at most OUTPUT_CAP bytes kept from each stream (a larger output is a failure, never
    a truncation into a pass), killed with its whole process group at the deadline. The result's streams are decoded text."""
    return _u01_run_bounded()(argv, timeout, what, cap=OUTPUT_CAP, cwd=REPO)


def cause(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return (lines[-1] if lines else "no output")[:CAUSE_CAP]


def case_vectors(_: Any) -> Tuple[str, str]:
    p = run_bounded([sys.executable, "-B", os.path.join(HERE, "make_vectors.py"), "--check"], "make_vectors.py --check")
    out = p.stdout + p.stderr
    return (PASS, cause(out)) if p.returncode == 0 else (FAIL, cause(out))


def case_unit(_: Any) -> Tuple[str, str]:
    p = run_bounded([sys.executable, "-B", "-W", "error", "-m", "unittest", os.path.join("tests", "u02", "test_u02.py")], "tests/u02/test_u02.py")
    out = p.stdout + p.stderr
    skipped = [ln for ln in out.splitlines() if "NOT RUN" in ln]
    if p.returncode != 0:
        return FAIL, cause(out)
    return PASS, cause(out) + ("; " + skipped[0] if skipped else "")


def case_defects(_: Any) -> Tuple[str, str]:
    import judge
    import reference as ref

    doc = json.load(open(os.path.join(REPO, "crates", "franken-update", "tests", "vectors", "u02_vectors.json"), encoding="utf-8"))
    if judge.failing(doc) or judge.unsound(doc):
        return FAIL, "the baseline is not green: " + ", ".join(judge.failing(doc) + judge.unsound(doc))[:CAUSE_CAP]
    missed = [b for b in ref.BUGS if b not in judge.NEEDS_A_CRASH and not judge.failing(doc, frozenset({b}))]
    blind = [b for b in ref.BUGS if b not in judge.NEEDS_A_CRASH and b not in judge.OVER_REFUSAL and not judge.unsound(doc, frozenset({b}))]
    if missed or blind:
        return FAIL, f"not caught by the vectors: {missed}; invisible to the properties: {blind}"
    if judge.failing(doc) or judge.unsound(doc):
        return FAIL, "the remove-the-plant control is not green after the plants"
    return PASS, f"{len(ref.BUGS)} planted defects: {len(ref.BUGS) - len(judge.NEEDS_A_CRASH)} caught by the vectors, the rest by the crash test; the control is green after each"


def case_openssl(_: Any) -> Tuple[str, str]:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return BLOCKED, "NOT RUN: the `cryptography` module is not installed, so the oracle was not compared with OpenSSL (never counted as passed)"
    p = run_bounded([sys.executable, "-B", "-W", "error", "-m", "unittest", "tests.u02.test_u02.Oracle.test_it_agrees_with_openssl_when_openssl_is_present"], "the OpenSSL comparison")
    out = p.stdout + p.stderr
    return (PASS, "signatures byte-equal to OpenSSL, verdicts equal on flipped bits") if p.returncode == 0 and "skipped" not in out else (FAIL, cause(out))


def case_judge_selftest(_: Any) -> Tuple[str, str]:
    p = run_bounded([sys.executable, "-B", os.path.join(HERE, "judge_log.py"), "--self-test"], "judge_log.py --self-test")
    out = p.stdout + p.stderr
    return (PASS, cause(out)) if p.returncode == 0 else (FAIL, cause(out))


def case_rust(logs: List[str]) -> Tuple[str, str]:
    if not logs:
        return BLOCKED, "needs a central `cargo test -p franken-update` log (see --help); never counted as passed"
    text = ""
    for path in logs:
        with open(path, encoding="utf-8", errors="replace") as f:
            text += f.read() + "\n"
    verdict, lines = judge_log.judge(text, judge_log.source_tests(REPO))
    return {0: PASS, 1: FAIL, 3: BLOCKED}[verdict], lines[-1] + ("" if verdict == 0 else "; " + "; ".join(lines[:-1])[:CAUSE_CAP])


CASES: List[Tuple[str, str, Callable]] = [
    ("U02-E-001", "the vectors are exactly what the generator writes", case_vectors),
    ("U02-E-002", "reference, oracle, pins, paired positives, Rust-source agreement, contract", case_unit),
    ("U02-E-003", "every planted defect is caught, the control is green", case_defects),
    ("U02-E-004", "the Ed25519 oracle against OpenSSL", case_openssl),
    ("U02-E-005", "the by-name judge catches planted failures", case_judge_selftest),
    ("U02-E-006", "the Rust tests of franken-update, by test name, from a central log", case_rust),
]


def safe(text: str) -> str:
    """The shared Q00 redaction policy, before any human or receipt output. An unavailable sanitizer releases nothing."""
    if not text:
        return ""
    try:
        return case_log.load(REPO).redact_text(text)
    except Exception:  # noqa: BLE001
        return "Diagnostic detail withheld: redaction is unavailable."


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def final_exit(counts: Dict[str, int], evidence: Any) -> int:
    code = 1 if counts[FAIL] else 3 if counts[BLOCKED] else 0
    return 1 if code == 0 and evidence is not None and not evidence.complete else code


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> "Any":
        self.print_usage(sys.stderr)
        self.exit(2, safe(f"{self.prog}: error: {message}") + "\n")


def main(argv: List[str]) -> int:
    ap = Parser(description="U02 end-to-end runner", epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--judge", action="append", metavar="LOG", help="a centrally produced `cargo test -p franken-update` log (repeatable)")
    ap.add_argument("--case", action="append", metavar="ID")
    ap.add_argument("--receipts", metavar="DIR")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    if args.tier == "soak":
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    cases = [c for c in CASES if args.tier == "full" or c[0] in SMOKE]
    if args.case:
        unknown = sorted(set(args.case) - {c[0] for c in cases})
        if unknown:
            print(safe(f"error: not a case of tier {args.tier}: {', '.join(unknown)}"), file=sys.stderr)
            return 2
        cases = [c for c in cases if c[0] in args.case]
    if args.list:
        for cid, title, _fn in cases:
            print(f"{cid}  {title}")
        return 0
    for path in args.judge or []:
        if not os.path.isfile(path):
            print(safe(f"error: {os.path.basename(path)} is not a file (the name only: a path is not echoed)"), file=sys.stderr)
            return 2
    counts = {PASS: 0, FAIL: 0, BLOCKED: 0}
    artifacts = {rel: (sha256_file(os.path.join(REPO, rel)) if os.path.isfile(os.path.join(REPO, rel)) else "missing") for rel in JUDGED_ARTIFACTS}
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": sys.version.split()[0], "tier": args.tier, "artifact_count": len(artifacts),
        "artifact_set_sha256": hashlib.sha256("".join("%s %s\n" % kv for kv in sorted(artifacts.items())).encode("utf-8")).hexdigest()})
    rows: List[Dict[str, Any]] = []
    for cid, title, fn in cases:
        started = time.monotonic()
        try:
            status, detail = fn(args.judge or [] if cid == "U02-E-006" else None)
        except Exception as err:  # noqa: BLE001 - a crashing case is a failed case
            status, detail = FAIL, f"{type(err).__name__}: {err}"
        detail = safe(detail)
        counts[status] += 1
        rows.append({"case": cid, "status": status, "detail": detail, "seconds": round(time.monotonic() - started, 2)})
        print(f"{status.upper():<8}{cid}  {title} -- {detail}")
        log.record(cid, "host" if cid != "U02-E-006" else "rust", status, detail)
    print(f"U02 cases: total={len(cases)} passed={counts[PASS]} failed={counts[FAIL]} blocked={counts[BLOCKED]}")
    evidence = log.finish({"passed": counts[PASS], "failed": counts[FAIL], "blocked": counts[BLOCKED]})
    print(evidence.summary)
    if not evidence.complete:
        print("[diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]")
    if evidence.path and not args.receipts:
        print("diagnostic log kept:", evidence.path)
    code = final_exit(counts, evidence)
    replay = "scripts/e2e/u02 --tier %s" % args.tier + "".join(" --case " + c[0] for c in cases) * bool(args.case) + "".join(" --judge LOG" for _ in args.judge or [])
    bad = [r for r in rows if r["status"] == FAIL] or [r for r in rows if r["status"] == BLOCKED]
    if bad:
        print(f"RETAINED FOR REPLAY. First {bad[0]['status']} case: {bad[0]['case']}: {bad[0]['detail']}")
        print("  replay: " + replay)
    verdict = "NOT QUALIFIED" if code else "PARTIAL (only the selected cases ran; never a qualification)" if args.case else "QUALIFIED"
    print(f"U02 e2e tier={args.tier}: {verdict}")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": args.tier,
               "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "counts": counts, "exit_code": code, "replay": replay, "artifacts": artifacts, "results": rows,
               "diagnostics": {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                               "file": os.path.basename(evidence.path) if evidence.path else None}}
        try:
            with open(os.path.join(args.receipts, "u02-%s.json" % run_id), "x", encoding="utf-8") as handle:
                json.dump(doc, handle, indent=1, sort_keys=True)
                handle.write("\n")
        except OSError as err:
            print(safe(f"error: the receipt could not be written: {type(err).__name__}"), file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
