#!/usr/bin/env python3
"""G03 (ffw-xvv) end-to-end runner and judge.

    run_cases.py [--tier smoke|full|soak] [--list] [--judge LOG [LOG ...]] [--receipts DIR] [--measure CHECKOUT]

Offline, standard library only; it builds and boots nothing and opens no network.

G03 is the fsonos compatibility adapter in ``crates/franken-control/src/fsonos/``. Two halves have to hold, and this runner judges both:

* OFFLINE - the Python side that needs no Rust: the independent reference model replays every golden vector
            (``tests/g03/reference.py --check``), the recorded action-usage matrix is consistent
            (``tests/g03/measure_usage.py --check-recorded``), and every ``tests/g03/test_*.py`` model check passes (the tier ``full``;
            each file is its own case). Each runs as a bounded subprocess: a hang is a failure, never an open-ended wait.
* RUST    - the unit tests of ``franken-control``'s ``fsonos`` modules, which only a centrally run ``cargo test`` can execute. They are
            judged from its output (``--judge LOG``): one case per invariant in ``tests/g03/cases.json`` (every Rust test the invariant
            names must report ``ok``), ``G03-REPLAY`` (the Rust replay of the golden vectors, ``fsonos::replay::*``) and
            ``G03-UNCLAIMED-UNIT`` (every other ``fsonos`` test, so that no test is skipped because no invariant names it). The set of
            required tests is derived from the sources, so a test added later is judged without editing this file.

A Rust case with no result is ``blocked``: counted, named, and the run is NOT QUALIFIED (exit 3). With no ``--judge`` log, every Rust case
is blocked. A test that ran and failed, a conflicting result, a claimed test that the sources do not define, a source file that no ``mod``
declares (so its tests can never run), or a log that reports ``fsonos`` tests the sources do not have (a log from other sources) is
``failed``. Neither is ever a pass, and the offline half passing never turns the Rust half into a pass.

NOT a client claim. A qualified run says the offline model agrees with the vectors and the Rust unit tests passed as logged. It does not
say an actual fsonos controller works against this endpoint: that gate is OPEN (docs/contracts/g03.md section 11.1) and no fixture,
replay or model stands in for it. The runner prints it as OPEN on every run.

The Rust suite runs only through the centralized RCH path (this runner never invokes cargo):

    RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- cargo test -p franken-control --locked
    (add `-- --nocapture` for the first causal event of a failure straight from the live stderr; the failure block is read either way)

Every run also writes its own diagnostic log through the shared Q00 sink (``tests/g03/case_log.py``: ``ff.diag.v1`` JSONL, a CRITICAL begin
and end per decided case and a run summary, with counted drops). A run whose log lost critical evidence is NOT QUALIFIED whatever the
cases say. A run that is not a pass prints how to replay it, which versions it ran under and the sha256 of every artifact it judged; the
receipt carries the same. A FAILED Rust test carries cargo's ``panicked at`` line and message as its first causal event.

Tiers: ``smoke`` (the offline vector and usage checks, the structure checks and the Rust cases) and ``full`` (smoke plus every
``tests/g03/test_*.py`` model check). ``soak`` is selectable and NOT RUN: it says why and exits 4.

Exit codes: 0 qualified, 1 a case failed or the diagnostic log lost critical evidence, 3 only blocked cases stand in the way, 4 the soak
tier (not run), 2 usage/malformed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import shlex
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TIERS = ("smoke", "full", "soak")
RUN_TIERS = ("smoke", "full")  # the tiers that judge anything; soak is selectable and not run
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "G03 soak: NOT RUN. Every G03 case is a finite, deterministic offline check (golden vectors against an independent model, the recorded "
    "usage matrix, named Rust unit tests), and the adapter itself opens no socket and reads no clock, so there is no long-running or "
    "randomized work here to soak. Subscription expiry, retries and real traffic belong to an actual fsonos client against the endpoint, "
    "which is the open gate (docs/contracts/g03.md section 11.1) and needs its own authorized receipt. This is not a pass.")
RECEIPT_SCHEMA = "ffw.g03.receipt.v1"
CASES_SCHEMA = "ffw.g03.cases.v1"
BEAD = "ffw-xvv"
MAX_PRINTED = 12
DETAIL_CHARS = 600           # a failing check's output kept in its detail (the log event caps it again)
OFFLINE_TIMEOUT_S = {"smoke": 120, "full": 300}
SELF_TEST = "test_run_cases.py"  # this runner's own tests run the judge; the full tier does not run them from inside the judge
CHILD_ENV = "G03_JUDGE_CHILD"    # set in every offline check's environment: a judge started by a check refuses to run checks (no recursion)
STEM = "franken_control"     # the cargo test binary (`Running unittests src/lib.rs (target/.../franken_control-<hash>)`)
CASES_REL = "tests/g03/cases.json"
FSONOS_REL = "crates/franken-control/src/fsonos"
LIB_REL = "crates/franken-control/src/lib.rs"
OPEN_GATES = [
    {"item": "actual_fsonos_client", "status": "OPEN",
     "detail": "this judge does not qualify actual-client integration; separate isolated runs and remaining acceptance "
               "are recorded in docs/contracts/g03.md section 11.1 and toolchain/results/g03/20261107-eventing/RUN.md; "
               "hand-written vectors and the independent model are not a client"},
    {"item": "network_and_time", "status": "not exercised",
     "detail": "the adapter opens no socket and reads no clock, so listener behaviour, timeouts and real subscription expiry "
               "are not exercised here"},
]
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+([A-Za-z0-9_]+)")
TESTS_MOD = re.compile(r"#\[cfg\(test\)\]\s*mod tests\b")
INVARIANT_ID = re.compile(r"G03-[A-Z]\d{2,}$")   # G03-Inn for the adapter's invariants; a later slice names its own letter (G03-Snn)
CLAIM = re.compile(r"[a-z][a-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*$")
JUDGED_ARTIFACTS = (
    "tests/g03/cases.json", "tests/g03/reference.py", "tests/g03/measure_usage.py", "tests/g03/usage_matrix.json",
    "tests/g03/run_cases.py", "tests/g03/case_log.py", "tests/d01/run_cases.py", "scripts/test/test_support/diagnostics.py",
    "docs/contracts/g03.md", "Cargo.lock", "rust-toolchain.toml", "crates/franken-control/Cargo.toml", LIB_REL,
)


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


case_log = _load(os.path.join(HERE, "case_log.py"), "g03_case_log")


def _load_d01_parser() -> Any:
    """D01's runner, for its cargo-log parser. Through RCH the ``Running`` headers (stderr) and the test sections (stdout) arrive as
    separate streams, so a test cannot be attributed to the nearest preceding header; D01's ``Logs`` pairs the n-th header with the n-th
    section and keeps exact-name matching as the fallback. G03 reuses it, as D03 and P06 do, rather than carrying a second copy."""
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        sys.stderr.write("run_cases: D01's runner (%s) is required for its cargo-log parser\n" % path)
        raise SystemExit(2)
    return _load(path, "d01_run_cases_for_g03")


d01 = _load_d01_parser()
NO_OBSERVATIONS = re.compile(r"\bG03-OBSERVED (\{.*\})\s*$")  # G03's Rust tests print no structured records; D01's pattern must not match here


class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, detail, group

    def as_dict(self) -> dict:
        return {"id": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


# ---- the Rust sources: which tests exist, and are they compiled at all ----------------------------------------------------------------


def fsonos_files(repo: str = REPO) -> List[str]:
    directory = os.path.join(repo, FSONOS_REL)
    try:
        return sorted(name for name in os.listdir(directory) if name.endswith(".rs"))
    except OSError:
        return []


def derive_tests(repo: str = REPO) -> Dict[str, dict]:
    """cargo test name -> {module, function, ignored}, for every ``#[test]`` in ``crates/franken-control/src/fsonos/*.rs``.

    A test after ``#[cfg(test)] mod tests`` is named ``fsonos::<file>::tests::<fn>``; a test in a file with no such module (replay.rs is test
    code from its first line) is ``fsonos::<file>::<fn>``. ``mod.rs`` is ``fsonos::``."""
    found: Dict[str, dict] = {}
    for fname in fsonos_files(repo):
        text = read_text(os.path.join(repo, FSONOS_REL, fname))
        if text is None:
            continue
        stem = fname[:-3]
        prefix = "fsonos::" if stem == "mod" else "fsonos::%s::" % stem
        marker = TESTS_MOD.search(text)
        for hit in TEST_FN.finditer(text):
            inside = marker is not None and hit.start() >= marker.start()
            name = prefix + ("tests::" if inside else "") + hit.group(2)
            found.setdefault(name, {"module": stem, "function": hit.group(2), "ignored": "ignore" in hit.group(1)})
    return found


def wiring_problems(repo: str = REPO) -> List[str]:
    """A test in a file that no ``mod`` declares is never compiled, so it can never be reported and its absence looks like a missing run.
    Said plainly instead: the crate declares ``pub mod fsonos;`` and ``fsonos/mod.rs`` declares every file in the directory."""
    problems: List[str] = []
    lib = read_text(os.path.join(repo, LIB_REL))
    if lib is None:
        problems.append("%s is unreadable" % LIB_REL)
    elif not re.search(r"^\s*pub mod fsonos;", lib, re.M):
        problems.append("%s does not declare `pub mod fsonos;`: no fsonos test is compiled" % LIB_REL)
    modrs = read_text(os.path.join(repo, FSONOS_REL, "mod.rs"))
    if modrs is None:
        problems.append("%s/mod.rs is unreadable" % FSONOS_REL)
        return problems
    for fname in fsonos_files(repo):
        stem = fname[:-3]
        if stem != "mod" and not re.search(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+%s\s*;" % re.escape(stem), modrs, re.M):
            problems.append("%s/%s is not declared in mod.rs: its tests are never compiled" % (FSONOS_REL, fname))
    return problems


# ---- the invariant map ----------------------------------------------------------------------------------------------------------------


def load_cases(repo: str = REPO) -> Tuple[Optional[dict], List[str]]:
    text = read_text(os.path.join(repo, CASES_REL))
    if text is None:
        return None, ["%s is missing or unreadable" % CASES_REL]
    try:
        doc = json.loads(text)
    except ValueError as err:
        return None, ["%s is not JSON: %s" % (CASES_REL, err)]
    return doc, cases_problems(doc)


def cases_problems(doc: Any) -> List[str]:
    """What makes an invariant map unfit to judge by: wrong schema or bead, a duplicate or malformed id, a statement that says nothing, and an
    invariant that names no Rust test (it could pass with nothing behind it)."""
    if not isinstance(doc, dict):
        return ["%s is not an object" % CASES_REL]
    problems: List[str] = []
    if doc.get("schema") != CASES_SCHEMA:
        problems.append("schema is %r, expected %s" % (doc.get("schema"), CASES_SCHEMA))
    if doc.get("bead") != BEAD:
        problems.append("bead is %r, expected %s" % (doc.get("bead"), BEAD))
    invariants = doc.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        return problems + ["no invariants"]
    seen: set = set()
    for index, inv in enumerate(invariants):
        if not isinstance(inv, dict):
            problems.append("invariant #%d is not an object" % index)
            continue
        iid = inv.get("id")
        if not isinstance(iid, str) or not INVARIANT_ID.match(iid):
            problems.append("invariant #%d: id %r is not G03-<letter><nn>" % (index, iid))
            continue
        if iid in seen:
            problems.append("%s: duplicate id" % iid)
        seen.add(iid)
        if not isinstance(inv.get("statement"), str) or not inv["statement"].strip():
            problems.append("%s: no statement" % iid)
        tests = inv.get("rust_tests")
        if not isinstance(tests, list) or not tests:
            problems.append("%s: names no Rust test" % iid)
        else:
            for claim in tests:
                if not isinstance(claim, str) or not CLAIM.match(claim):
                    problems.append("%s: rust test %r is not module::function" % (iid, claim))
            if len(set(map(str, tests))) != len(tests):
                problems.append("%s: lists a Rust test twice" % iid)
    return problems


def registry(doc: Optional[dict], tests: Dict[str, dict]) -> List[dict]:
    """The Rust-backed cases. ``tests`` are required cargo test names; ``undefined`` are claims the sources do not define."""
    by_claim = {"%s::%s" % (info["module"], info["function"]): name for name, info in tests.items()}
    cases: List[dict] = []
    claimed: set = set()
    if isinstance(doc, dict) and isinstance(doc.get("invariants"), list):
        for inv in doc["invariants"]:
            if not isinstance(inv, dict) or not isinstance(inv.get("id"), str):
                continue
            names: List[str] = []
            undefined: List[str] = []
            for claim in inv.get("rust_tests") if isinstance(inv.get("rust_tests"), list) else []:
                if claim in by_claim:
                    names.append(by_claim[claim])
                    claimed.add(by_claim[claim])
                else:
                    undefined.append(str(claim))
            cases.append(dict(id=inv["id"], group="invariant", tier="smoke", what=str(inv.get("statement", ""))[:160],
                              tests=names, undefined=undefined))
    replay = sorted(n for n, i in tests.items() if i["module"] == "replay")
    cases.append(dict(id="G03-REPLAY", group="replay", tier="smoke",
                      what="the Rust replay of the golden vectors (fsonos::replay::*) agrees with the vectors", tests=replay,
                      undefined=[] if replay else ["a #[test] in fsonos/replay.rs (it holds none)"]))
    claimed.update(replay)
    rest = sorted(n for n in tests if n not in claimed)
    if rest:
        cases.append(dict(id="G03-UNCLAIMED-UNIT", group="unit", tier="smoke",
                          what="every fsonos unit test that no invariant names still passes", tests=rest, undefined=[]))
    return cases


# ---- log parsing ----------------------------------------------------------------------------------------------------------------------


class Logs(d01.Logs):
    """D01's parser (header/section ordinal pairing; ambiguous names stay ambiguous; a conflicting status is reported, an identical
    repeat is not), without D01's observation records, which G03's tests do not print."""

    def _record_test(self, stem: Optional[str], name: str, status: str) -> None:
        """``ignored`` means "not run in this invocation" and says nothing about the test, so it yields to a real result from another log
        and never replaces one. ``ok`` against ``FAILED`` is still a conflict."""
        key = (stem, name)
        previous = self.tests.get(key)
        if previous == "ignored" and status != "ignored":
            self.tests[key] = status
            return
        if status == "ignored" and previous is not None:
            return
        super()._record_test(stem, name, status)

    def add(self, path: str) -> None:
        saved = d01.OBSERVED
        d01.OBSERVED = NO_OBSERVATIONS   # the parser looks the pattern up in its own module
        try:
            super().add(path)
        finally:
            d01.OBSERVED = saved


def foreign_tests(logs: Logs, tests: Dict[str, dict]) -> List[str]:
    """``fsonos`` tests a log reports that these sources do not define: the log was run on other sources."""
    out = {name for (stem, name) in logs.tests if name.startswith("fsonos::") and stem in (STEM, None) and name not in tests}
    return sorted(out)


# ---- offline checks: bounded subprocesses --------------------------------------------------------------------------------------------


def child_env() -> Dict[str, str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1", "PYTHONHASHSEED": "0",
           CHILD_ENV: "1"}
    if os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def _text(raw: Any) -> str:
    if raw is None:
        return ""
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def run_check(argv: List[str], cwd: str, timeout: float) -> Tuple[Optional[int], str, str]:
    """(exit code, stdout, stderr). The code is None when the check ran out of time (the child is killed); -1 when it could not start."""
    try:
        done = subprocess.run(argv, cwd=cwd, env=child_env(), stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        return done.returncode, _text(done.stdout), _text(done.stderr)
    except subprocess.TimeoutExpired as err:
        return None, _text(err.stdout), _text(err.stderr)
    except OSError as err:
        return -1, "", "cannot run %s: %s" % (os.path.basename(argv[0]) if argv else "?", type(err).__name__)


def bounded(output: str, limit: int = DETAIL_CHARS) -> str:
    """The part of a check's output worth keeping: its FAIL/ERROR lines (at most three) and its last two lines, capped."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    marks = [line for line in lines if re.match(r"(?:FAIL|ERROR)\b", line)][:3]
    tail = [line for line in lines[-2:] if line not in marks]
    text = " | ".join(marks + tail)
    return text if len(text) <= limit else text[:limit] + "...[%d more chars]" % (len(text) - limit)


def offline_checks(repo: str, measure: Optional[str] = None) -> List[dict]:
    """The Python checks, each a bounded subprocess. ``tests/g03/test_*.py`` is discovered, one case per file, so a model check added
    for a new part of G03 is judged without editing this list. This runner's own tests are left out (they run the judge)."""
    g03 = os.path.join(repo, "tests", "g03")
    py = sys.executable or "python3"
    checks = [
        dict(id="G03-META-USAGE-RECORDED", tier="smoke", argv=[py, "-B", "-I", os.path.join(g03, "measure_usage.py"), "--check-recorded"],
             what="the recorded action-usage matrix is consistent"),
        dict(id="G03-META-REFERENCE", tier="smoke", argv=[py, "-B", "-I", os.path.join(g03, "reference.py"), "--check"],
             what="the independent reference model replays every golden vector"),
    ]
    if measure:
        checks.append(dict(id="G03-META-USAGE-REMEASURED", tier="smoke", remeasure=measure,
                           argv=[py, "-B", "-I", os.path.join(g03, "measure_usage.py"), "--fsonos", measure],
                           what="the usage matrix re-measured from the checkout equals the recorded one"))
    try:
        files = sorted(name for name in os.listdir(g03) if name.startswith("test_") and name.endswith(".py") and name != SELF_TEST)
    except OSError:
        files = []
    for fname in files:
        label = fname[len("test_"):-len(".py")].upper().replace("_", "-")
        checks.append(dict(id="G03-META-UNIT-" + label, tier="full",
                           argv=[py, "-B", "-I", "-m", "unittest", "discover", "-s", g03, "-p", fname],
                           what="the %s checks pass" % fname, unittest=True))
    return checks


def judge_offline(check: dict, repo: str, tier: str) -> Result:
    group = "offline"
    if os.environ.get(CHILD_ENV):
        return Result(check["id"], "failed", "recursion: this judge was started by one of its own offline checks, and does not start more "
                                             "(a test file that runs the judge belongs in SELF_TEST, not in the discovered model checks)", group)
    timeout = OFFLINE_TIMEOUT_S.get(check["tier"], 300)
    code, out, err = run_check(check["argv"], repo, timeout)
    if code is None:
        return Result(check["id"], "failed", "timed out after %ds (killed); partial output: %s" % (timeout, bounded(out + "\n" + err) or "none"),
                      group)
    if code != 0:
        return Result(check["id"], "failed", "exit %d: %s" % (code, bounded(out + "\n" + err) or "no output"), group)
    if check.get("unittest") and re.search(r"^Ran 0 tests?\b", err + "\n" + out, re.M):
        return Result(check["id"], "failed", "ran no tests: %s" % bounded(out + "\n" + err), group)
    if check.get("remeasure"):
        recorded = read_text(os.path.join(repo, "tests", "g03", "usage_matrix.json"))
        try:
            same = recorded is not None and json.loads(out) == json.loads(recorded)
        except ValueError:
            return Result(check["id"], "failed", "the re-measurement did not print JSON", group)
        if not same:
            return Result(check["id"], "failed", "the re-measured usage matrix differs from tests/g03/usage_matrix.json", group)
        return Result(check["id"], "passed", "re-measured usage matrix: identical to the recorded one", group)
    return Result(check["id"], "passed", bounded(out + "\n" + err, 200) or check["what"], group)


# ---- run ------------------------------------------------------------------------------------------------------------------------------


def judge_case(case: dict, logs: Optional[Logs]) -> Result:
    # A claim the sources do not define is a defect in the map, found before any log is read.
    if case["undefined"]:
        return Result(case["id"], "failed", "map defect, the sources do not define: " + ", ".join(case["undefined"][:3]), case["group"])
    if logs is None:
        return Result(case["id"], "blocked", "no cargo test log supplied (--judge); " + case["what"], case["group"])
    failed_why: List[str] = []
    blocked_why: List[str] = []
    for name in case["tests"]:
        status = logs.test_status(STEM, name)
        if status == "ok":
            continue
        if status in ("FAILED", "CONFLICT"):
            cause = logs.failure_context.get(name) if status == "FAILED" else None
            failed_why.append("%s: %s%s" % (name, status, "; first causal event " + cause if cause else ""))
        elif status == "AMBIGUOUS":
            blocked_why.append("%s: in more than one test section and the log cannot say which binary ran it" % name)
        elif status == "ignored":
            blocked_why.append("%s: ignored (not run)" % name)
        else:
            blocked_why.append("%s: not reported" % name)
    if failed_why:
        return Result(case["id"], "failed", "; ".join((failed_why + blocked_why)[:MAX_PRINTED]), case["group"])
    if blocked_why:
        more = "" if len(blocked_why) <= 3 else " (+%d more)" % (len(blocked_why) - 3)
        return Result(case["id"], "blocked", "; ".join(blocked_why[:3]) + more, case["group"])
    return Result(case["id"], "passed", case["what"], case["group"])


def logs_results(logs: Logs, tests: Dict[str, dict]) -> List[Result]:
    """Checks on the logs themselves: no test reported two ways, and every ``fsonos`` test they report belongs to these sources."""
    bad_tests = sorted("%s %s" % (stem or "?", name) for stem, name in logs.conflicting_tests)
    notes = []
    if logs.repeated_inputs:
        notes.append("repeated log input read once: " + ", ".join(logs.repeated_inputs))
    if logs.unattributed_logs:
        notes.append("no header pairing, exact names used: " + "; ".join(logs.unattributed_logs))
    if logs.attribution_notes:
        notes.append("%d result(s) not attributed, first: %s" % (len(logs.attribution_notes), logs.attribution_notes[0][:200]))
    if bad_tests:
        consistent = Result("G03-META-LOGS-CONSISTENT", "failed", "conflicting results: " + ", ".join(bad_tests[:MAX_PRINTED]), "meta")
    else:
        consistent = Result("G03-META-LOGS-CONSISTENT", "passed", "no conflicting test status" + ("; " + "; ".join(notes) if notes else ""),
                            "meta")
    foreign = foreign_tests(logs, tests)
    if foreign:
        belongs = Result("G03-META-LOG-BELONGS", "failed",
                         "the log reports %d fsonos test(s) these sources do not define (a log from other sources): %s"
                         % (len(foreign), ", ".join(foreign[:MAX_PRINTED])), "meta")
    else:
        belongs = Result("G03-META-LOG-BELONGS", "passed", "every fsonos test the log reports is defined in these sources", "meta")
    return [consistent, belongs]


def run(tier: str, logs: Optional[Logs], repo: str = REPO, measure: Optional[str] = None, offline: bool = True) -> Tuple[List[Result], dict]:
    doc, problems = load_cases(repo)
    tests = derive_tests(repo)
    results: List[Result] = []
    if problems:
        results.append(Result("G03-META-CASES", "failed", "; ".join(problems[:MAX_PRINTED]), "meta"))
    else:
        results.append(Result("G03-META-CASES", "passed", "%d invariants, each with a statement and named Rust tests" % len(doc["invariants"]),
                              "meta"))
    wiring = wiring_problems(repo)
    if wiring:
        results.append(Result("G03-META-WIRED", "failed", "; ".join(wiring[:MAX_PRINTED]), "meta"))
    elif not tests:
        results.append(Result("G03-META-WIRED", "failed", "no #[test] found under %s" % FSONOS_REL, "meta"))
    else:
        results.append(Result("G03-META-WIRED", "passed", "pub mod fsonos; is declared and every fsonos file is declared in mod.rs "
                                                           "(%d tests in %d files)" % (len(tests), len(fsonos_files(repo))), "meta"))
    if offline:
        for check in offline_checks(repo, measure):
            if TIERS.index(check["tier"]) <= TIERS.index(tier):
                results.append(judge_offline(check, repo, tier))
    cases = registry(doc, tests) if not problems else []
    required = sorted({n for c in cases for n in c["tests"]})
    for case in cases:
        if TIERS.index(case["tier"]) <= TIERS.index(tier):
            results.append(judge_case(case, logs))
    if logs is not None:
        results.extend(logs_results(logs, tests))
    ok = sum(1 for n in required if logs is not None and logs.test_status(STEM, n) == "ok")
    meta = {"planned_rust_tests": len(required), "rust_tests_ok": ok, "invariants": len(doc["invariants"]) if doc and not problems else 0}
    return results, meta


def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "blocked")}


def exit_code(results: List[Result]) -> int:
    counts = summarize(results)
    if counts["failed"]:
        return 1
    return 3 if counts["blocked"] else 0


def final_exit(results: List[Result], evidence: Optional[Any]) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = exit_code(results)
    if code == 0 and evidence is not None and not evidence.complete:
        return 1
    return code


def artifact_digests(repo: str = REPO) -> Dict[str, str]:
    """sha256 of every file whose bytes decide a verdict: the judge and its parser, the model and vectors, the shared sink, the contract, the
    lock and every Rust source that holds a judged test. A file that cannot be read says so; it is never left out."""
    rels = list(JUDGED_ARTIFACTS)
    rels += ["%s/%s" % (FSONOS_REL, name) for name in fsonos_files(repo)]
    # what the offline checks run and what the Rust tests replay: every model check and reference in tests/g03, every G03 vector file
    for sub, wanted in (("tests/g03", lambda n: n.endswith(".py") and (n.startswith("test_") or n.endswith("reference.py"))),
                        ("crates/franken-control/tests/vectors", lambda n: n.startswith("g03_") and n.endswith(".json"))):
        try:
            names = sorted(os.listdir(os.path.join(repo, sub)))
        except OSError:
            names = []
        rels += ["%s/%s" % (sub, name) for name in names if wanted(name)]
    out: Dict[str, str] = {}
    for rel in sorted(dict.fromkeys(rels)):
        path = os.path.join(repo, rel)
        out[rel] = sha256_file(path) if os.path.isfile(path) else "missing"
    return out


def artifact_set_digest(digests: Dict[str, str]) -> str:
    """One digest over the sorted `path digest` lines, small enough for the log header."""
    return hashlib.sha256("".join("%s %s\n" % (rel, digest) for rel, digest in sorted(digests.items())).encode("utf-8")).hexdigest()


def versions(repo: str = REPO) -> Dict[str, Any]:
    doc, _ = load_cases(repo)
    return {"python": platform.python_version(), "receipt_schema": RECEIPT_SCHEMA,
            "cases_schema": doc.get("schema") if isinstance(doc, dict) else None}


def replay_command(tier: str, logs: Optional[Logs]) -> str:
    names = [os.path.basename(path) for path, _ in logs.files] if logs else []
    return "scripts/e2e/g03 --tier %s" % tier + (" --judge " + " ".join(shlex.quote(n) for n in names) if names else "")


def retained_lines(results: List[Result], tier: str, logs: Optional[Logs], meta: dict) -> List[str]:
    """What a run that is not a pass keeps: the first failure (or block) with its expected-versus-observed text, the exact replay
    command, the versions and the digest of every artifact judged. Paths are relative to the repository root."""
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = ["RETAINED FOR REPLAY. First %s case: %s: %s" % (first.status, first.case_id, first.detail), "  replay: " + replay_command(tier, logs)]
    for path, digest in (logs.files if logs else []):
        lines.append("  judged log %s sha256 %s" % (os.path.basename(path), digest))
    v = meta["versions"]
    lines.append("  versions: python %s; receipt %s; cases %s" % (v["python"], v["receipt_schema"], v["cases_schema"]))
    for rel, digest in meta["artifacts"].items():
        lines.append("  artifact %s sha256 %s" % (rel, digest))
    return lines


def report(results: List[Result], tier: str, logs: Optional[Logs] = None, meta: Optional[dict] = None, evidence: Optional[Any] = None) -> None:
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:MAX_PRINTED]:
            print("%-8s %s  %s" % (label, r.case_id, r.detail))
        if len(rows) > MAX_PRINTED:
            print("%-8s ... and %d more %s case(s)" % (label, len(rows) - MAX_PRINTED, status))
    for gate in OPEN_GATES:
        print("%-8s %s: %s" % (gate["status"].upper(), gate["item"], gate["detail"]))
    if meta is not None:
        for line in retained_lines(results, tier, logs, meta):
            print(line)
    code = final_exit(results, evidence)
    verdict = "QUALIFIED (offline side and Rust unit tests as logged; the actual-client gate stays OPEN)" if code == 0 else "NOT QUALIFIED"
    note = ""
    if evidence is not None:
        print(evidence.summary)
        if not evidence.complete:
            note = "  [diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]"
    rust = ""
    if meta is not None:
        rust = "  rust_tests=%d ok=%d" % (meta["planned_rust_tests"], meta["rust_tests_ok"])
    print("G03 e2e tier=%s: %s  planned=%d passed=%d failed=%d blocked=%d%s%s" % (
        tier, verdict, len(results), counts["passed"], counts["failed"], counts["blocked"], rust, note))


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs], run_id: Optional[str] = None,
                  evidence: Optional[Any] = None) -> str:
    os.makedirs(directory, exist_ok=True)
    run_id = run_id or secrets.token_hex(8)
    path = os.path.join(directory, "g03-%s.json" % run_id)
    doc = {
        "schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "counts": summarize(results), "exit_code": final_exit(results, evidence), "evidence_class": "host-offline-reference-and-rust-unit-logs",
        "open_gates": OPEN_GATES,
        "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
        "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
        "unattributed_logs": list(logs.unattributed_logs) if logs else [],
        "replay": replay_command(tier, logs),
        **meta, "results": [r.as_dict() for r in results],
    }
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                              "file": os.path.basename(evidence.path) if evidence.path else None}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="G03 end-to-end runner and judge (ffw-xvv)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="list the planned case ids and exit")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="cargo test output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt and the JSONL diagnostic log here")
    parser.add_argument("--measure", metavar="CHECKOUT", help="also re-measure the usage matrix from a frankensonos checkout (read only)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.tier not in RUN_TIERS:
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                sys.stderr.write("error: log not found: %s\n" % path)
                return 2
            logs.add(path)
    if args.list:
        doc, problems = load_cases(REPO)
        ids = ["G03-META-CASES", "G03-META-WIRED"]
        ids += [c["id"] for c in offline_checks(REPO, args.measure) if TIERS.index(c["tier"]) <= TIERS.index(args.tier)]
        ids += [c["id"] for c in (registry(doc, derive_tests(REPO)) if not problems else [])]
        ids += ["G03-META-LOGS-CONSISTENT", "G03-META-LOG-BELONGS"] if logs else []
        print("\n".join(ids))
        return 0
    results, meta = run(args.tier, logs, REPO, args.measure)
    meta["versions"], meta["artifacts"] = versions(), artifact_digests()
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": meta["versions"]["python"], "tier": args.tier, "artifact_count": len(meta["artifacts"]),
        "artifact_set_sha256": artifact_set_digest(meta["artifacts"]), "cases_sha256": meta["artifacts"].get(CASES_REL)})
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, args.tier, logs, meta, evidence)
    code = final_exit(results, evidence)
    if args.receipts:
        try:
            print("receipt: " + write_receipt(args.receipts, args.tier, results, meta, logs, run_id, evidence))
        except OSError as err:
            sys.stderr.write("error: the receipt could not be written under %s: %s\n" % (args.receipts, type(err).__name__))
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main())
