#!/usr/bin/env python3
"""Run the P06 cases (tests/p06/test_*.py) and judge them (bead ffw-2nw).

    python3 -B -I tests/p06/run_cases.py [--tier smoke|full|soak] [--only CASE_ID] [--list] [--receipts DIR]
    scripts/e2e/p06 [the same options]

Tiers. The denominator of a run is the number of cases it decided, printed in the totals line; ``--list`` prints the case ids a tier plans.
  smoke  every case that reads only this repository: the independent models against the hand-written vectors, the Rust text, the
         ledger's shape, the lock and manifest isolation, the invariant-to-test mapping, and the diagnostic and runner cases.
  full   smoke plus the cases that need a source outside the repository: the upstream clones (pins, ancestry, the recorded upstream
         bytes, the errno oracle) and the ``libc`` crate's per-architecture files. A source that is not on this machine makes its
         cases BLOCKED. A blocked case is never a pass.
  soak   NOT SUPPORTED. The P06 acceptance names no soak requirement: the selected primitives are pure codecs with no long-running
         behavior, so there is nothing to soak. The tier does not run, reports one blocked case (P06-SOAK) and exits 3.

What this does not run: ``cargo`` (the Rust unit tests, clippy and the BE-target checks are central work, see ``scripts/e2e/p06 --plan``).

Every run also writes its own diagnostic log through the shared Q00 sink (``tests/p06/case_log.py``: ``ff.diag.v1`` JSONL, a CRITICAL begin
and end per decided case and a run summary, with counted drops, bounded and redacted). A run whose log lost critical evidence, or whose
log cannot be read back, is NOT QUALIFIED whatever the cases say. A mandatory test module that contributes no case to the run is a blocked
case, not a silent omission. A run that is not a pass prints its first failing (or blocked) case with the cause, the exact replay command,
the versions and the sha256 of every artifact it judged; the receipt (``--receipts DIR``) carries the same.

Exit codes: 0 every case passed and the log is complete; 1 a case failed or the diagnostic log lost critical evidence or the receipt could
not be written; 2 usage; 3 nothing failed but a case did not run (blocked, or an unsupported tier): not qualified.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import secrets
import sys
import traceback
import types
import unittest
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TIERS = ("smoke", "full", "soak")
RECEIPT_SCHEMA = "ffw.p06-receipt.v1"
SOAK_ID = "P06-SOAK"
SOAK_DETAIL = ("tier not supported: the P06 acceptance names no soak requirement (pure codecs, nothing long-running), so nothing was soaked; "
               "this is not a pass")
DETAIL_CAP = 600      # characters of one case's detail kept in the printed line, the log and the receipt
CAUSE_CAP = 300       # characters of an exception message kept as a case's cause
MANDATORY_MODULES = ("test_net_abi", "test_ledger", "test_durable", "test_case_log", "test_runner")
# Cases that need a source outside the repository (clones, the libc crate's files): full tier only. (module, class).
FULL_ONLY = (
    ("test_ledger", "ThePinsResolve"),
    ("test_ledger", "TheGenericErrnoTableIsNotAMipsTable"),
    ("test_net_abi", "OtherSourcesAgreeWithTheVectors"),
    ("test_durable", "LibcCrateAgreesWithTheVectors"),
)
# Files whose bytes decide a verdict, or that the verdict is about. Their sha256 goes into every receipt and every non-pass report.
JUDGED_ARTIFACTS = (
    "scripts/e2e/p06", "tests/p06/run_cases.py", "tests/p06/case_log.py", "tests/p06/cases.json", "tests/p06/ledger.json",
    "tests/p06/test_net_abi.py", "tests/p06/test_durable.py", "tests/p06/test_ledger.py", "tests/p06/test_case_log.py",
    "tests/p06/test_runner.py", "crates/franken-platform/tests/vectors/p06_net_abi.json",
    "crates/franken-platform/tests/vectors/p06_durable_abi.json", "crates/franken-platform/src/net.rs",
    "crates/franken-platform/src/durable.rs", "crates/franken-platform/src/lib.rs", "docs/contracts/p06.md", "Cargo.lock",
    "rust-toolchain.toml", "scripts/test/test_support/diagnostics.py",
)


class Result:
    """One decided case. status is 'passed', 'failed' or 'blocked' (did not run, or could not be decided)."""

    def __init__(self, case_id: str, group: str, status: str, detail: str = "") -> None:
        self.case_id, self.group, self.status, self.detail = case_id, group, status, bounded(detail)

    def as_dict(self) -> Dict[str, str]:
        return {"id": self.case_id, "group": self.group, "status": self.status, "detail": self.detail}


def bounded(text: str, cap: int = DETAIL_CAP) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= cap else text[:cap] + "...[%d more chars]" % (len(text) - cap)


def scrub(text: str) -> str:
    """Paths in a retained message are relative to the repository; the home directory is not printed."""
    out = str(text).replace(REPO, ".")
    home = os.path.expanduser("~")
    return out.replace(home, "~") if home and home != "/" else out


# ------------------------------------------------------------------------------------------------ cases

def flatten(suite: Any) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def parts(test: unittest.TestCase) -> Tuple[str, str]:
    """(module, class) of a test; a loader failure has the module name 'unittest'."""
    pieces = test.id().split(".")
    return (pieces[0], pieces[1] if len(pieces) > 2 else "")


def case_id(test: unittest.TestCase) -> str:
    return test.id()[:110]


def tier_of(test: unittest.TestCase) -> str:
    return "full" if parts(test) in FULL_ONLY else "smoke"


def discover() -> List[unittest.TestCase]:
    return list(flatten(unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=HERE)))


def select(tests: Sequence[unittest.TestCase], tier: str, only: Optional[str] = None) -> List[unittest.TestCase]:
    chosen = [t for t in tests if tier == "full" or tier_of(t) == "smoke"]
    if only is not None:
        chosen = [t for t in chosen if t.id() == only or case_id(t) == only]
    return chosen


def structural_blocks(tests: Sequence[unittest.TestCase], chosen: Sequence[unittest.TestCase], tier: str,
                      mandatory: Sequence[str]) -> List[Result]:
    """A case that should exist and does not is a blocked case. A mandatory module with nothing in this run (a deleted or renamed file,
    a loader that found none), or a tier rule that matches no case (a class renamed out from under it), is reported, never skipped."""
    out: List[Result] = []
    have = {parts(t)[0] for t in chosen}
    for module in mandatory:
        if module not in have:
            out.append(Result("P06-MANDATORY:" + module, "structure", "blocked",
                              "mandatory test module %s contributed no case to this %s run (missing file, or no case found)" % (module, tier)))
    if tier == "full":
        seen = {parts(t) for t in tests}
        for module, cls in FULL_ONLY:
            if (module, cls) not in seen:
                out.append(Result("P06-TIERS:%s.%s" % (module, cls), "structure", "blocked",
                                  "the full-only rule for %s.%s matches no case: renamed or removed, so the tier split is not trusted" % (module, cls)))
    return out


class Recording(unittest.TextTestResult):
    """The ordinary verbose unittest result, plus one structured record per decided case."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.records: List[Result] = []

    def _add(self, test: Any, status: str, detail: str) -> None:
        self.records.append(Result(case_id(test), parts(test)[0], status, detail))

    def addSuccess(self, test: Any) -> None:
        super().addSuccess(test)
        self._add(test, "passed", "")

    def addFailure(self, test: Any, err: Any) -> None:
        super().addFailure(test, err)
        self._add(test, "failed", cause(err))

    def addError(self, test: Any, err: Any) -> None:
        super().addError(test, err)
        self._add(test, "failed", cause(err))

    def addSkip(self, test: Any, reason: str) -> None:
        super().addSkip(test, reason)
        self._add(test, "blocked", scrub(reason))

    def addUnexpectedSuccess(self, test: Any) -> None:
        super().addUnexpectedSuccess(test)
        self._add(test, "failed", "unexpected success")

    def addSubTest(self, test: Any, subtest: Any, err: Any) -> None:
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._add(test, "failed", "subtest %s: %s" % (subtest._subDescription(), cause(err)))


def cause(err: Any) -> str:
    """The first causal event of a failed case: the exception, its first message line, and the innermost frame in the repository."""
    etype, value, tb = err
    last = None
    for frame in traceback.extract_tb(tb):
        if os.path.realpath(frame.filename).startswith(REPO + os.sep):
            last = frame
    message = str(value).strip().splitlines()[0] if str(value).strip() else ""
    where = " at %s:%d" % (os.path.relpath(os.path.realpath(last.filename), REPO), last.lineno) if last else ""
    return scrub("%s: %s%s" % (getattr(etype, "__name__", str(etype)), bounded(message, CAUSE_CAP), where))


def run_tests(tests: Sequence[unittest.TestCase], stream: Any) -> List[Result]:
    runner = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Recording)
    return runner.run(unittest.TestSuite(tests)).records


def summarize(results: Sequence[Result]) -> Dict[str, int]:
    return {"planned": len(results), "passed": sum(r.status == "passed" for r in results),
            "failed": sum(r.status == "failed" for r in results), "blocked": sum(r.status == "blocked" for r in results)}


def exit_code(results: Sequence[Result]) -> int:
    s = summarize(results)
    if s["failed"]:
        return 1
    return 3 if s["blocked"] or not results else 0


def final_exit(results: Sequence[Result], evidence: Any) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = exit_code(results)
    if code == 0 and evidence is not None and not evidence.complete:
        return 1
    return code


# ------------------------------------------------------------------------------------------------ evidence

def sha256_file(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


def artifact_digests(repo: str = REPO) -> Dict[str, str]:
    return {rel: sha256_file(os.path.join(repo, rel)) or "absent" for rel in JUDGED_ARTIFACTS}


def artifact_set_digest(artifacts: Dict[str, str]) -> str:
    return hashlib.sha256("\n".join("%s %s" % (k, artifacts[k]) for k in sorted(artifacts)).encode("utf-8")).hexdigest()


def versions(repo: str = REPO) -> Dict[str, Any]:
    cases_schema = None
    try:
        with open(os.path.join(repo, "tests", "p06", "cases.json"), encoding="utf-8") as handle:
            cases_schema = json.load(handle).get("schema")
    except (OSError, ValueError, AttributeError):
        pass
    return {"python": platform.python_version(), "receipt_schema": RECEIPT_SCHEMA, "cases_schema": cases_schema}


def load_case_log() -> Tuple[Any, str]:
    """tests/p06/case_log.py by path. A module that is missing or does not import is an unavailable log (the run goes on, unqualified)."""
    try:
        spec = importlib.util.spec_from_file_location("p06_case_log", os.path.join(HERE, "case_log.py"))
        if spec is None or spec.loader is None:
            return None, "case_log_unavailable:no_spec"
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module, ""
    except Exception as err:  # noqa: BLE001 - never a crash of the judge
        return None, "case_log_unavailable:%s" % type(err).__name__


def open_log(repo: str, run_id: str, tier: str, receipts: Optional[str], header_extra: Dict[str, Any]) -> Any:
    module, problem = load_case_log()
    if module is None:
        return types.SimpleNamespace(
            record=lambda *a, **k: None,
            finish=lambda totals: types.SimpleNamespace(complete=False, reasons=[problem], summary="diag: NO LOG (evidence INCOMPLETE)",
                                                        log=None, sink=None, path=None))
    return module.CaseLog.open(repo, run_id, tier, receipts, header_extra=header_extra)


# ------------------------------------------------------------------------------------------------ reporting

def replay_command(tier: str, only: Optional[str] = None) -> str:
    return "scripts/e2e/p06 --tier %s" % tier + (" --only %s" % only if only else "")


def retained_lines(results: Sequence[Result], tier: str, meta: Dict[str, Any], only: Optional[str]) -> List[str]:
    """What a run that is not a pass keeps: the first failure (or block) with its cause, the exact replay command, the versions and the
    digest of every artifact judged."""
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = ["RETAINED FOR REPLAY. First %s case: %s: %s" % (first.status, first.case_id, first.detail),
             "  replay: " + replay_command(tier, only if first.case_id.startswith("P06-") else first.case_id)]
    v = meta["versions"]
    lines.append("  versions: python %s; receipt %s; cases %s" % (v["python"], v["receipt_schema"], v["cases_schema"]))
    for rel, digest in meta["artifacts"].items():
        lines.append("  artifact %s sha256 %s" % (rel, digest))
    return lines


def report(results: Sequence[Result], tier: str, meta: Dict[str, Any], evidence: Any, only: Optional[str] = None,
           out: Any = None) -> None:
    out = out or sys.stdout
    s = summarize(results)
    print("P06 tier=%s" % tier, file=out)
    print("P06 cases: total=%d passed=%d failed=%d blocked=%d" % (s["planned"], s["passed"], s["failed"], s["blocked"]), file=out)
    for r in results:
        if r.status == "blocked":
            print("BLOCKED %s: %s" % (r.case_id, r.detail), file=out)
    for line in retained_lines(results, tier, meta, only):
        print(line, file=out)
    if evidence is not None:
        print(evidence.summary, file=out)
    code = exit_code(results)
    if code == 0 and evidence is not None and not evidence.complete:
        print("RESULT: NOT QUALIFIED: diagnostic evidence INCOMPLETE (%s)" % ", ".join(evidence.reasons), file=out)
    elif code == 3:
        print("NOT QUALIFIED: %d case(s) did not run; a case that did not run is not a case that passed" % s["blocked"], file=out)
    elif code == 1:
        print("RESULT: FAILED", file=out)
    else:
        print("RESULT: QUALIFIED (host simulation of the Python cases; the Rust is central work, no device claim)", file=out)


def write_receipt(directory: str, tier: str, results: Sequence[Result], meta: Dict[str, Any], run_id: str, evidence: Any,
                  code: int, only: Optional[str] = None) -> str:
    os.makedirs(directory, exist_ok=True)
    doc: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA, "tier": tier, "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "run_id": run_id, "summary": summarize(results), "results": [r.as_dict() for r in results],
        "evidence_class": "host-simulation", "versions": meta["versions"], "artifacts": meta["artifacts"],
        "exit_code": code, "replay": replay_command(tier, only),
    }
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                              "file": os.path.basename(evidence.path) if evidence.path else None}
    path = os.path.join(directory, "p06-receipt-%s.json" % run_id)
    with open(path, "x", encoding="utf-8") as handle:  # exclusive: a rerun never overwrites the first run's receipt
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def run_and_judge(tests: Sequence[unittest.TestCase], tier: str, receipts: Optional[str] = None, only: Optional[str] = None,
                  mandatory: Sequence[str] = MANDATORY_MODULES, repo: str = REPO, stream: Any = None,
                  out: Any = None, opener: Optional[Callable[..., Any]] = None, check_structure: bool = True) -> Tuple[int, List[Result], Any]:
    """Run `tests` as the `tier` run: decide each case, write the log, report, write the receipt. Returns (exit code, results, evidence)."""
    stream = stream if stream is not None else sys.stderr
    out = out if out is not None else sys.stdout
    chosen = select(tests, tier, only)
    results = run_tests(chosen, stream)
    if check_structure and only is None:
        results.extend(structural_blocks(tests, chosen, tier, mandatory))
    meta = {"versions": versions(repo), "artifacts": artifact_digests(repo)}
    run_id = secrets.token_hex(6)
    header = {"python": meta["versions"]["python"], "tier": tier, "artifact_count": len(meta["artifacts"]),
              "artifact_set_sha256": artifact_set_digest(meta["artifacts"])}
    log = (opener or open_log)(repo, run_id, tier, receipts, header)
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, tier, meta, evidence, only, out)
    code = final_exit(results, evidence)
    if receipts:
        try:
            print("receipt: " + write_receipt(receipts, tier, results, meta, run_id, evidence, code, only), file=out)
        except OSError as err:
            sys.stderr.write("error: the receipt could not be written under %s: %s\n" % (scrub(receipts), type(err).__name__))
            return code or 1, results, evidence
    return code, results, evidence


def soak(receipts: Optional[str], repo: str = REPO, out: Any = None) -> int:
    """The unsupported tier: one blocked case, recorded in the log and the receipt, exit 3. It never runs anything."""
    results = [Result(SOAK_ID, "tier", "blocked", SOAK_DETAIL)]
    out = out if out is not None else sys.stdout
    meta = {"versions": versions(repo), "artifacts": artifact_digests(repo)}
    run_id = secrets.token_hex(6)
    log = open_log(repo, run_id, "soak", receipts, {"python": meta["versions"]["python"], "tier": "soak",
                                                    "artifact_set_sha256": artifact_set_digest(meta["artifacts"])})
    log.record(SOAK_ID, "tier", "blocked", SOAK_DETAIL)
    evidence = log.finish(summarize(results))
    report(results, "soak", meta, evidence, None, out)
    code = final_exit(results, evidence)
    if receipts:
        try:
            print("receipt: " + write_receipt(receipts, "soak", results, meta, run_id, evidence, code), file=out)
        except OSError as err:
            sys.stderr.write("error: the receipt could not be written under %s: %s\n" % (scrub(receipts), type(err).__name__))
            return code or 1
    return code


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="P06 case runner and judge (ffw-2nw)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--only", metavar="CASE_ID", help="run one case (an id printed by --list or by a failure's replay line)")
    parser.add_argument("--list", action="store_true", help="print the case ids the tier plans")
    parser.add_argument("--receipts", metavar="DIR", help="write the diagnostic log and a JSON receipt here")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.tier == "soak":
        if args.list:
            print(SOAK_ID)
            return 0
        return soak(args.receipts)
    tests = discover()
    if args.list:
        for t in select(tests, args.tier, args.only):
            print(case_id(t))
        return 0
    chosen = select(tests, args.tier, args.only)
    if args.only is not None and not chosen:
        sys.stderr.write("run_cases: no such case in the %s tier: %s\n" % (args.tier, args.only))
        return 2
    code, _, _ = run_and_judge(tests, args.tier, args.receipts, args.only)
    return code


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
