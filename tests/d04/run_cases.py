#!/usr/bin/env python3
"""D04 (ffw-5h5) host-side case runner.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR] [--judge LOG [LOG ...]]

What this runner is, so a pass is not over-read:
* It re-derives every scripted run with an independent model of the render loop's timing and
  classification (reference.py), checks the committed scenarios.json is exactly what that model
  says, proves the case set is not vacuous (each planted wrong rule must be caught), and checks
  that every required invariant maps to Rust tests that EXIST in render.rs. It does not run those
  tests: there is no local cargo, and the loop itself is verified only by the central
  `cargo test -p franken-speaker`.
* So the behavioral half is the case D04-RUST-CENTRAL. It is BLOCKED, counted and never passed,
  until the output of the central `cargo test -p franken-speaker` is supplied with `--judge LOG`;
  then every Rust test in render.rs and render_log.rs must be reported `ok` BY NAME in the
  franken_speaker unit-test binary (a test that is missing, ignored or unattributable stays
  BLOCKED, one that failed or contradicts another log FAILS). That judges the tests only: clippy,
  fmt and the two device builds are not read from a test log, and a pass says so. The log is bound
  to the registry by test name, not to the source by content; the receipt and the retained lines
  record the sha256 of the log and of the sources it was judged against. The run is NOT QUALIFIED
  while any case is blocked. Three more things are blocked, honestly: the driver and board CPU
  measurements (D04-EXT-BOARD), the P03 control runtime (D04-OPEN-P03) and the separate
  process-death mute qualification (D04-EXT-PROCDEATH).
* The model and the Rust loop share an author. Agreement shows the arithmetic was done twice by
  two routes; it does not show the contract is right. The sample path is checked by a differential
  test in Rust, not by this model, and docs/contracts/d04.md says so.

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage or a
malformed case file.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shlex
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import generate  # noqa: E402
import log_reference  # noqa: E402
import reference  # noqa: E402
import regress_reference  # noqa: E402

CASES_FILE = os.path.join(HERE, "cases.json")
SCENARIOS_FILE = os.path.join(HERE, "scenarios.json")
DOC_FILE = os.path.join(REPO, "docs", "contracts", "d04.md")
RENDER_RS = os.path.join(REPO, "crates", "franken-speaker", "src", "render.rs")
RENDER_LOG_RS = os.path.join(REPO, "crates", "franken-speaker", "src", "render_log.rs")
SPEAKER_LIB = os.path.join(REPO, "crates", "franken-speaker", "src", "lib.rs")
SESSION_RS = os.path.join(REPO, "crates", "franken-hal", "src", "session.rs")
LOG_GOLDEN = os.path.join(HERE, "log_golden.json")
REGRESS_GOLDEN = os.path.join(HERE, "regress_golden.json")
TEST_SUPPORT_RS = os.path.join(REPO, "crates", "franken-test-support", "src", "lib.rs")
SCHEMA = "ffw.d04.cases.v1"
TIERS = ("smoke", "full")
KINDS = ("scenario", "planted_defect", "meta_files", "meta_shared", "meta_generated", "meta_invariants",
         "meta_hygiene", "meta_no_unsafe", "meta_log", "log_golden", "log_defect", "regress_scenario", "regress_log",
         "regress_defect", "runner_selftest", "blocked", "central_rust")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
Result = Tuple[str, str]


class CaseError(Exception):
    pass


def load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise CaseError(f"cannot read {os.path.relpath(path, REPO)}: {e}") from e


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def render_test_names() -> List[str]:
    """Functions directly annotated #[test] in crates/franken-speaker/src/render.rs."""
    return re.findall(r"#\[test\]\s*\n\s*fn\s+(\w+)\s*\(", read(RENDER_RS))


def hal_test_names() -> List[str]:
    """`session::fn` for every #[test] in crates/franken-hal/src/session.rs. An invariant may name one; they are not
    all required to be mapped, because the session has its own contract and tests."""
    return [f"session::{n}" for n in re.findall(r"#\[test\]\s*\n\s*fn\s+(\w+)\s*\(", read(SESSION_RS))]


def all_rust_tests() -> List[str]:
    """`module::fn` for every #[test] in render.rs and render_log.rs."""
    out = [f"render::{n}" for n in render_test_names()]
    log_tests = re.findall(r"#\[test\]\s*\n\s*fn\s+(\w+)\s*\(", read(RENDER_LOG_RS))
    return out + [f"render_log::{n}" for n in log_tests]


# ------------------------------------------------------------------------------------- scenarios

def scenarios_doc() -> Dict[str, Any]:
    doc = load_json(SCENARIOS_FILE)
    if doc.get("schema") != generate.SCHEMA:
        raise CaseError(f"scenarios.json schema is {doc.get('schema')!r}, expected {generate.SCHEMA!r}")
    return doc


def run_scenario_model(doc: Dict[str, Any], sc: Dict[str, Any], defect: Optional[str] = None) -> Dict[str, Any]:
    return reference.simulate(doc["config"], reference.Scenario(sc), defect)


def check_scenario(doc: Dict[str, Any], sc: Dict[str, Any], defect: Optional[str] = None) -> Result:
    got = run_scenario_model(doc, sc, defect)
    want = sc["expect"]
    if got["finished"] != want["finished"]:
        return FAIL, f"blocks finished {got['finished']}, expected {want['finished']}"
    if got["state"] != want["state"] or got["now"] != want["now"]:
        return FAIL, f"ended {got['state']} at {got['now']}, expected {want['state']} at {want['now']}"
    bad = {k: (got["counters"][k], want["counters"][k]) for k in reference.COUNTER_KEYS
           if got["counters"][k] != want["counters"][k]}
    if bad:
        return FAIL, f"counters differ (got, expected): {bad}"
    problems = reference.identities_hold(got, doc["config"]["block_frames"])
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, ""


def run_scenario(c) -> Result:
    doc = scenarios_doc()
    sc = next((s for s in doc["scenarios"] if s["id"] == c["scenario"]), None)
    if sc is None:
        return FAIL, f"no scenario {c['scenario']}"
    return check_scenario(doc, sc)


def run_planted_defect(c) -> Result:
    doc = scenarios_doc()
    baseline = [s["id"] for s in doc["scenarios"] if check_scenario(doc, s)[0] != PASS]
    if baseline:
        return FAIL, f"baseline is not green, so no catch can be credited: {baseline}"
    caught = sorted(s["id"] for s in doc["scenarios"] if check_scenario(doc, s, c["defect"])[0] != PASS)
    missing = [i for i in c["caught_by"] if i not in caught]
    if missing:
        return FAIL, f"defect {c['defect']!r} was not caught by {missing}; caught by {caught}"
    return PASS, f"caught by {len(caught)} scenario(s)"


# ------------------------------------------------------------------------------------------- meta

def run_meta_files(c) -> Result:
    needed = [CASES_FILE, SCENARIOS_FILE, DOC_FILE, RENDER_RS, RENDER_LOG_RS, LOG_GOLDEN,
              os.path.join(HERE, "log_reference.py"), REGRESS_GOLDEN, SESSION_RS,
              os.path.join(HERE, "regress_reference.py"),
              os.path.join(HERE, "reference.py"), os.path.join(HERE, "generate.py"),
              os.path.join(REPO, "scripts", "e2e", "d04")]
    gone = [os.path.relpath(p, REPO) for p in needed if not os.path.isfile(p)]
    return (PASS, "") if not gone else (FAIL, f"missing: {gone}")


def run_meta_shared(c) -> Result:
    src = read(RENDER_RS)
    problems = []
    if 'include_str!("../../../tests/d04/scenarios.json")' not in src:
        problems.append("render.rs does not include tests/d04/scenarios.json")
    m = re.search(r"scenarios\.len\(\),\s*(\d+)", src)
    n = len(scenarios_doc()["scenarios"])
    if not m or int(m.group(1)) != n:
        problems.append(f"the Rust test expects {m.group(1) if m else 'no'} scenarios, the file has {n}")
    if problems:
        return FAIL, "; ".join(problems)
    lib = read(os.path.join(REPO, "crates", "franken-speaker", "src", "lib.rs"))
    if "pub mod render;" not in lib:
        # Not a defect of this slice: the supervisor wires the declaration. Counted, not passed.
        return BLOCKED, "render.rs is not declared in franken-speaker/src/lib.rs yet (the supervisor wires it)"
    return PASS, ""


def run_meta_generated(c) -> Result:
    current = read(SCENARIOS_FILE)
    wanted = generate.render(generate.build())
    return (PASS, "") if current == wanted else (FAIL, "scenarios.json is not what reference.py produces")


def expand(patterns: List[str], ids: List[str]) -> List[str]:
    out = []
    for p in patterns:
        if p.endswith("*"):
            out.extend(i for i in ids if i.startswith(p[:-1]))
        else:
            out.append(p)
    return out


def all_ids(doc: Dict[str, Any]) -> List[str]:
    return [x["id"] for x in doc["cases"]] + [s["id"] for s in scenarios_doc()["scenarios"]]


def check_invariants(doc: Dict[str, Any], ids: List[str], tests: List[str]) -> List[str]:
    problems, mapped = [], set()
    known = set(tests) | set(hal_test_names())
    for inv in doc["invariants"]:
        if not inv["rust_tests"] and not inv["cases"]:
            problems.append(f"{inv['id']} maps to nothing")
        for name in inv["rust_tests"]:
            if name not in known:
                problems.append(f"{inv['id']}: no #[test] fn {name} in render.rs, render_log.rs or session.rs")
        for ref in expand(inv["cases"], ids):
            if ref not in ids:
                problems.append(f"{inv['id']} names unknown case {ref}")
            mapped.add(ref)
    orphans = [i for i in ids if i not in mapped]
    if orphans:
        problems.append(f"cases covering no invariant: {orphans}")
    return problems


def run_meta_invariants(c) -> Result:
    doc = load_json(CASES_FILE)
    tests = all_rust_tests()
    problems = check_invariants(doc, all_ids(doc), tests)
    named = sum(len(i["rust_tests"]) for i in doc["invariants"])
    listed = {n for i in doc["invariants"] for n in i["rust_tests"]}
    total = len(tests)
    unmapped = sorted(set(tests) - listed)
    if unmapped:
        problems.append(f"{len(unmapped)} of the {total} Rust tests are in no invariant: {unmapped}")
    return (PASS, f"{len(doc['invariants'])} invariants, {named} named Rust tests, all {total} mapped") \
        if not problems else (FAIL, "; ".join(problems))


HYGIENE_FILES = ("cases.json", "scenarios.json", "reference.py", "generate.py", "run_cases.py", "log_golden.json",
                 "log_reference.py", "regress_golden.json", "regress_reference.py")


def run_meta_hygiene(c) -> Result:
    problems = []
    ipv4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    mac = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
    longhex = re.compile(r"\b[0-9a-fA-F]{40,}\b")
    for rel in HYGIENE_FILES:
        text = read(os.path.join(HERE, rel))
        for rx, what in ((ipv4, "an IPv4 address"), (mac, "a MAC address"), (longhex, "a long hex blob")):
            hit = rx.search(text)
            if hit:
                problems.append(f"{rel}: {what} {hit.group(0)!r}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def run_meta_no_unsafe(c) -> Result:
    problems = []
    rx = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b)")
    for label, path in (("render.rs", RENDER_RS), ("render_log.rs", RENDER_LOG_RS)):
        for n, line in enumerate(read(path).splitlines(), 1):
            if rx.search(line.split("//")[0]):
                problems.append(f"{label}:{n}: {line.strip()}")
    lib = read(os.path.join(REPO, "crates", "franken-speaker", "src", "lib.rs"))
    if "#![forbid(unsafe_code)]" not in lib:
        problems.append("franken-speaker no longer forbids unsafe_code")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def struct_fields(source: str, name: str) -> List[str]:
    """Field names of a Rust struct, in order, read from its source text."""
    m = re.search(r"(?:pub )?struct %s \{(.*?)\n\}" % re.escape(name), source, re.S)
    if not m:
        return []
    return [f.group(1) for f in re.finditer(r"^\s*(?:pub )?(\w+):\s", m.group(1), re.M)]


def run_meta_log(c) -> Result:
    """The line the diagnostics log writes has exactly the fields of the ffw.log.v1 schema type, in its order,
    reuses the HAL's schema string, keeps franken-test-support out of the production half, and states the
    golden it must reproduce. The Rust tests go further (they round-trip every line through the schema type);
    this catches a drift without compiling anything."""
    support = read(TEST_SUPPORT_RS)
    ours = read(RENDER_LOG_RS)
    want = struct_fields(support, "DiagnosticEvent")
    got = struct_fields(ours, "LogLine")
    problems = []
    if not want:
        problems.append("could not read DiagnosticEvent from franken-test-support")
    elif got != want:
        problems.append(f"LogLine fields {got} differ from DiagnosticEvent fields {want}")
    if list(log_reference.FIELD_ORDER) != want:
        problems.append("log_reference.FIELD_ORDER differs from the schema type")
    if "LOG_SCHEMA_VERSION" not in ours.split("#[cfg(test)]")[0] or "franken_hal::contract_log" not in ours:
        problems.append("render_log.rs does not reuse the HAL's ffw.log.v1 schema string")
    production = ours.split("#[cfg(test)]")[0]
    if "franken_test_support" in production:
        problems.append("the production half of render_log.rs names franken_test_support")
    if 'include_str!("../../../tests/d04/log_golden.json")' not in ours:
        problems.append("render_log.rs does not include tests/d04/log_golden.json")
    if "pub mod render_log;" not in read(SPEAKER_LIB):
        return BLOCKED, "render_log.rs is not declared in franken-speaker/src/lib.rs yet (the supervisor wires it)" \
            + ("; " + "; ".join(problems) if problems else "")
    return (PASS, f"{len(want)} fields in order") if not problems else (FAIL, "; ".join(problems))


def check_log_golden(golden, defect=None) -> Result:
    """The independent model reproduces the hand-typed lines and the hand-derived bounded scenario exactly."""
    got = log_reference.run(golden, defect)
    if got != golden["expected"]:
        first = next((i for i, (a, b) in enumerate(zip(got, golden["expected"])) if a != b), min(len(got), len(golden["expected"])))
        return FAIL, f"{len(got)} line(s) against {len(golden['expected'])} expected; first difference at line {first}"
    b = golden["bounded"]
    bounded = log_reference.run_bounded(golden, defect)
    if bounded != {"kept": b["expect_kept"], "stats": b["expect_stats"]}:
        return FAIL, f"bounded log kept {bounded['kept']} with {bounded['stats']}, expected {b['expect_kept']} with {b['expect_stats']}"
    for line in golden["expected"]:
        if list(json.loads(line).keys()) != [k for k in log_reference.FIELD_ORDER if k in json.loads(line)]:
            return FAIL, "an expected line is out of the schema's field order"
    return PASS, ""


def run_log_golden(c) -> Result:
    status, detail = check_log_golden(load_json(LOG_GOLDEN))
    return (PASS, f"{len(load_json(LOG_GOLDEN)['expected'])} lines and the bounded log reproduced") \
        if status == PASS else (status, detail)


def run_log_defect(c) -> Result:
    golden = load_json(LOG_GOLDEN)
    base = check_log_golden(golden)
    if base[0] != PASS:
        return FAIL, f"baseline is not green, so no catch can be credited: {base[1]}"
    if c["defect"] not in log_reference.DEFECTS:
        return FAIL, f"unknown defect {c['defect']!r}"
    status, detail = check_log_golden(golden, c["defect"])
    return (PASS, f"caught: {detail}") if status != PASS else (FAIL, f"defect {c['defect']!r} was not caught")


# --------------------------------------------------------------------------------- driver counter regress

def regress_doc() -> Dict[str, Any]:
    doc = load_json(REGRESS_GOLDEN)
    if doc.get("schema") != regress_reference.SCHEMA:
        raise CaseError(f"regress_golden.json schema is {doc.get('schema')!r}, expected {regress_reference.SCHEMA!r}")
    return doc


def check_regress_scenario(sc: Dict[str, Any], defect: Optional[str] = None) -> Result:
    """The independent model reproduces the hand-typed results and final state exactly."""
    want = sc["expect"]
    if set(want["final"]) != set(regress_reference.FINAL_KEYS):
        return FAIL, f"{sc['id']}: the expected final state names {sorted(want['final'])}, not {sorted(regress_reference.FINAL_KEYS)}"
    got = regress_reference.simulate(sc, defect)
    if got["results"] != want["results"]:
        step = next((i for i, (a, b) in enumerate(zip(got["results"], want["results"])) if a != b), 0)
        return FAIL, f"step {step} gave {got['results'][step:step + 1]}, expected {want['results'][step:step + 1]}"
    bad = {k: (got["final"][k], want["final"][k]) for k in regress_reference.FINAL_KEYS if got["final"][k] != want["final"][k]}
    if bad:
        return FAIL, f"final state differs (got, expected): {bad}"
    return PASS, ""


def check_regress_log(doc: Dict[str, Any], defect: Optional[str] = None) -> Result:
    """The log model reproduces the hand-typed lines of both runs (a regress, and the forward overclaim)."""
    for run in doc["log_runs"]:
        got = log_reference.run(run, defect)
        if got != run["expected"]:
            first = next((i for i, (a, b) in enumerate(zip(got, run["expected"])) if a != b), min(len(got), len(run["expected"])))
            return FAIL, f"run {run['name']}: {len(got)} line(s) against {len(run['expected'])}; first difference at line {first}"
    return PASS, ""


def regress_test_names_exist(doc: Dict[str, Any]) -> List[str]:
    known = set(all_rust_tests()) | set(hal_test_names())
    return [f"{sc['id']} names {sc['rust_test']}" for sc in doc["scenarios"] if sc["rust_test"] not in known]


def run_regress_scenario(c) -> Result:
    doc = regress_doc()
    sc = next((s for s in doc["scenarios"] if s["id"] == c["scenario"]), None)
    if sc is None:
        return FAIL, f"no regress scenario {c['scenario']}"
    missing = [m for m in regress_test_names_exist(doc) if m.startswith(sc["id"] + " ")]
    if missing:
        return FAIL, f"no such Rust test: {missing}"
    return check_regress_scenario(sc)


def run_regress_log(c) -> Result:
    doc = regress_doc()
    status, detail = check_regress_log(doc)
    return (PASS, f"{len(doc['log_runs'])} runs reproduced") if status == PASS else (status, detail)


def run_regress_defect(c) -> Result:
    doc = regress_doc()
    broken = [s["id"] for s in doc["scenarios"] if check_regress_scenario(s)[0] != PASS]
    base_log = check_regress_log(doc)
    if broken or base_log[0] != PASS:
        return FAIL, f"baseline is not green, so no catch can be credited: {broken} {base_log[1]}"
    if c["defect"] in regress_reference.DEFECTS:
        caught = sorted(s["id"] for s in doc["scenarios"] if check_regress_scenario(s, c["defect"])[0] != PASS)
    elif c["defect"] in log_reference.DEFECTS:
        caught = ["log_runs"] if check_regress_log(doc, c["defect"])[0] != PASS else []
    else:
        return FAIL, f"unknown defect {c['defect']!r}"
    missing = [i for i in c["caught_by"] if i not in caught]
    if missing:
        return FAIL, f"defect {c['defect']!r} was not caught by {missing}; caught by {caught}"
    return PASS, f"caught by {', '.join(caught)}"


def run_runner_selftest(c) -> Result:
    """The comparisons are not vacuous: a corrupted scenario, a missing Rust test name and an orphan
    case must each be seen."""
    doc = scenarios_doc()
    sc = copy.deepcopy(doc["scenarios"][1])
    if check_scenario(doc, sc)[0] != PASS:
        return FAIL, "a baseline scenario does not pass"
    sc["expect"]["finished"][0][1] += 1
    if check_scenario(doc, sc)[0] == PASS:
        return FAIL, "a corrupted finish tick was accepted"
    sc = copy.deepcopy(doc["scenarios"][1])
    sc["expect"]["counters"]["cpu_miss_blocks"] += 1
    if check_scenario(doc, sc)[0] == PASS:
        return FAIL, "a corrupted counter was accepted"
    bad = copy.deepcopy(load_json(CASES_FILE))
    bad["invariants"][0]["rust_tests"].append("render::a_test_that_does_not_exist")
    if not any("a_test_that_does_not_exist" in p
               for p in check_invariants(bad, all_ids(bad), all_rust_tests())):
        return FAIL, "a missing Rust test name was not detected"
    orphan = copy.deepcopy(load_json(CASES_FILE))
    orphan["cases"].append({"id": "D04-ORPHAN", "kind": "meta_files", "tier": "smoke"})
    if not any("D04-ORPHAN" in p for p in check_invariants(orphan, all_ids(orphan), all_rust_tests())):
        return FAIL, "a case covering no invariant was not detected"
    golden = load_json(LOG_GOLDEN)
    if check_log_golden(golden)[0] != PASS:
        return FAIL, "the diagnostics log baseline does not pass"
    corrupt = copy.deepcopy(golden)
    corrupt["expected"][4] = corrupt["expected"][4].replace('"latency_us":3000', '"latency_us":3')
    if check_log_golden(corrupt)[0] == PASS:
        return FAIL, "a corrupted expected log line was accepted"
    corrupt = copy.deepcopy(golden)
    corrupt["bounded"]["expect_kept"] = ["block-0", "block-1", "tick-10"]
    if check_log_golden(corrupt)[0] == PASS:
        return FAIL, "a corrupted bounded-log expectation was accepted"
    regress = regress_doc()
    if any(check_regress_scenario(s)[0] != PASS for s in regress["scenarios"]) or check_regress_log(regress)[0] != PASS:
        return FAIL, "the regress baseline does not pass"
    bad = copy.deepcopy(regress)
    bad["scenarios"][0]["expect"]["final"]["consumed"] += 1
    if check_regress_scenario(bad["scenarios"][0])[0] == PASS:
        return FAIL, "a corrupted regress final state was accepted"
    bad = copy.deepcopy(regress)
    bad["scenarios"][-1]["expect"]["results"][8] = "ok"
    if check_regress_scenario(bad["scenarios"][-1])[0] == PASS:
        return FAIL, "a corrupted regress step result was accepted"
    bad = copy.deepcopy(regress)
    bad["log_runs"][0]["expected"][1] = bad["log_runs"][0]["expected"][1].replace(" mapping_invalidated", "")
    if check_regress_log(bad)[0] == PASS:
        return FAIL, "a regress log line without its reaction was accepted"
    bad = copy.deepcopy(regress)
    bad["scenarios"][0]["rust_test"] = "render::a_test_that_does_not_exist"
    if not regress_test_names_exist(bad):
        return FAIL, "a regress scenario naming a missing Rust test was not detected"
    return PASS, ""


def run_blocked(c) -> Result:
    return BLOCKED, f"{c['blocker']} (owner: {c['owner']}): {c['needs']}"


# ------------------------------------------------------------------------------- central Rust log

RUST_CENTRAL = "D04-RUST-CENTRAL"
LIB_STEM = "franken_speaker"  # the unit-test binary of the franken-speaker lib, the stem of its `Running` header
TESTS_ONLY = "tests only: clippy, fmt and the two device builds are not judged here and stay in the supervisor's landing census"
MAX_SHOWN = 6
# Besides the logs, the files whose bytes decide a verdict or hold the judged tests; their sha256 goes into the receipt and
# into the lines a non-pass retains.
JUDGED_ARTIFACTS = (
    "crates/franken-speaker/src/render.rs", "crates/franken-speaker/src/render_log.rs", "crates/franken-speaker/src/lib.rs",
    "tests/d04/cases.json", "tests/d04/run_cases.py", "docs/contracts/d04.md", "Cargo.lock", "rust-toolchain.toml",
)
JUDGE_LOGS: Any = None  # the parsed `--judge` logs, set by main; None when no log was supplied


def load_logs(paths: List[str]) -> Any:
    """Parse cargo test output with D01's parser, which D03 and the other judged gates reuse rather than carry a copy. Through
    RCH the `Running` headers (stderr) and the test sections (stdout) arrive as separate streams, so a test cannot be given to
    the nearest preceding header; the parser pairs the n-th header with the n-th section and falls back to exact names."""
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        raise CaseError("--judge needs D01's runner for its cargo-log parser: tests/d01/run_cases.py is missing")
    spec = importlib.util.spec_from_file_location("d01_run_cases_for_d04", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    logs = module.Logs()
    for p in paths:
        if not os.path.isfile(p):
            raise CaseError(f"--judge: no such log {p!r}")
        logs.add(p)
    return logs


def cargo_names() -> List[Tuple[str, str]]:
    """(binary stem, cargo's full test name) for every Rust test the invariants rest on: the `#[test]` functions of render.rs
    and render_log.rs. Both files keep their tests in one `#[cfg(test)] mod tests`, so cargo names them `render::tests::<fn>`
    and `render_log::tests::<fn>` in the franken_speaker unit-test binary. A test moved into a nested module would be reported
    under another name and so stay BLOCKED; it can never be passed by accident."""
    return [(LIB_STEM, n.replace("::", "::tests::", 1)) for n in all_rust_tests()]


def _shown(items: List[str]) -> str:
    text = "; ".join(items[:MAX_SHOWN])
    return text + (f"; (+{len(items) - MAX_SHOWN} more)" if len(items) > MAX_SHOWN else "")


def judge_rust(logs: Any) -> Result:
    """The central `cargo test -p franken-speaker` log against the Rust tests the invariants name. A test that is missing,
    ignored or that the log cannot attribute to the franken_speaker binary stays BLOCKED; one that FAILED, or that two logs
    report differently, FAILS. Neither is ever a pass, and an empty registry is not a vacuous pass."""
    required = cargo_names()
    if not required:
        return FAIL, "no #[test] function was found in render.rs and render_log.rs, so there is nothing to judge"
    failed: List[str] = []
    blocked: List[str] = []
    for stem, name in required:
        status = logs.test_status(stem, name)
        if status == "ok":
            continue
        if status in ("FAILED", "CONFLICT"):
            cause = logs.failure_context.get(name) if status == "FAILED" else None
            failed.append(f"{name}: {status}" + (f"; first causal event {cause}" if cause else ""))
        elif status == "AMBIGUOUS":
            blocked.append(f"{name}: in more than one test section and the log cannot say which binary ran it")
        elif status == "ignored":
            blocked.append(f"{name}: ignored (not run)")
        else:
            blocked.append(f"{name}: not reported")
    total = len(required)
    if failed:
        more = f"; {len(blocked)} more not shown ok" if blocked else ""
        return FAIL, f"{len(failed)} of {total} required Rust test(s) FAILED: {_shown(failed)}{more}"
    if blocked:
        return BLOCKED, f"{len(blocked)} of {total} required Rust test(s) not shown ok in the supplied log(s): {_shown(blocked)}"
    notes = [TESTS_ONLY]
    ours = set(required)
    others = [n for (s, n), st in logs.tests.items() if st == "FAILED" and (s, n) not in ours and s in (LIB_STEM, None)]
    if others:
        notes.append(f"{len(others)} other test(s) FAILED in the log, not D04's")
    if logs.unattributed_logs:
        notes.append("no Running-header pairing, exact test names used: " + "; ".join(logs.unattributed_logs))
    return PASS, f"all {total} required Rust tests ok in the {LIB_STEM} unit-test binary; " + "; ".join(notes)


def run_central_rust(c) -> Result:
    if JUDGE_LOGS is None:
        return BLOCKED, (f"{c['blocker']} (owner: {c['owner']}): {c['needs']} Expect {len(all_rust_tests())} #[test] functions "
                         "in render.rs and render_log.rs. No log was supplied (--judge).")
    return judge_rust(JUDGE_LOGS)


RUNNERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "scenario": run_scenario, "planted_defect": run_planted_defect, "meta_files": run_meta_files,
    "meta_shared": run_meta_shared, "meta_generated": run_meta_generated,
    "meta_invariants": run_meta_invariants, "meta_hygiene": run_meta_hygiene,
    "meta_no_unsafe": run_meta_no_unsafe, "runner_selftest": run_runner_selftest, "blocked": run_blocked,
    "central_rust": run_central_rust, "meta_log": run_meta_log, "log_golden": run_log_golden, "log_defect": run_log_defect,
    "regress_scenario": run_regress_scenario, "regress_log": run_regress_log, "regress_defect": run_regress_defect,
}


# --------------------------------------------------------------------------------------------- main

def all_cases() -> List[Dict[str, Any]]:
    doc = load_json(CASES_FILE)
    if doc.get("schema") != SCHEMA:
        raise CaseError(f"cases.json schema is {doc.get('schema')!r}, expected {SCHEMA!r}")
    cases = list(doc["cases"])
    for sc in scenarios_doc()["scenarios"]:
        cases.append({"id": sc["id"], "kind": "scenario", "tier": "smoke", "scenario": sc["id"]})
    seen = set()
    for c in cases:
        if c["kind"] not in KINDS:
            raise CaseError(f"{c['id']}: unknown kind {c['kind']!r}")
        if c["tier"] not in TIERS:
            raise CaseError(f"{c['id']}: unknown tier {c['tier']!r}")
        if c["id"] in seen:
            raise CaseError(f"duplicate case id {c['id']}")
        seen.add(c["id"])
    return cases


def select(cases, tier: str, only: Optional[str]):
    if only:
        picked = [c for c in cases if c["id"] == only]
        if not picked:
            raise CaseError(f"no case {only!r}")
        return picked
    return [c for c in cases if tier == "full" or c["tier"] == "smoke"]


def artifact_digests() -> List[Tuple[str, str]]:
    return [(rel, sha256_file(os.path.join(REPO, rel))) for rel in JUDGED_ARTIFACTS if os.path.isfile(os.path.join(REPO, rel))]


def retained_lines(argv: List[str], logs: Any) -> List[str]:
    """What a run that is not a pass keeps, so it can be replayed and the inputs it judged identified: the replay command, the
    interpreter and schema, the sha256 of every judged log and of the sources and runner the verdict rests on."""
    lines = ["replay: " + " ".join(["scripts/e2e/d04"] + [shlex.quote(a) for a in argv]),
             f"versions: python {sys.version.split()[0]}; {SCHEMA}"]
    if logs is not None:
        lines += [f"judged log sha256 {digest}  {os.path.basename(path)}" for path, digest in logs.files]
        lines += [f"repeated log input read once: {name}" for name in logs.repeated_inputs]
    lines += [f"artifact sha256 {digest}  {rel}" for rel, digest in artifact_digests()]
    return lines


def main(argv: List[str]) -> int:
    global JUDGE_LOGS
    JUDGE_LOGS = None
    ap = argparse.ArgumentParser(description="D04 host-side case runner")
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--case", metavar="ID")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--receipts", metavar="DIR")
    ap.add_argument("--judge", nargs="+", metavar="LOG",
                    help="output of the central `cargo test -p franken-speaker` run, judged by D04-RUST-CENTRAL")
    args = ap.parse_args(argv)
    try:
        chosen = select(all_cases(), args.tier, args.case)
        if args.list:
            for c in chosen:
                print(f"{c['id']:<18} {c['tier']:<6} {c['kind']}")
            return 0
        if args.judge:
            JUDGE_LOGS = load_logs(args.judge)
        results = []
        for c in chosen:
            try:
                status, detail = RUNNERS[c["kind"]](c)
            except CaseError:
                raise
            except Exception as e:  # a crashing case is a failed case, never a skipped one
                status, detail = FAIL, f"crashed: {type(e).__name__}: {e}"
            results.append((c, status, detail))
            print(f"{status.upper():<7} {c['id']:<22} {c['kind']}{'  ' + detail if detail else ''}")
    except CaseError as e:
        print(f"D04 runner: {e}", file=sys.stderr)
        return 2
    counts = {s: sum(1 for _, st, _ in results if st == s) for s in (PASS, FAIL, BLOCKED)}
    # One selected case is never the run's verdict: a lone passing case would otherwise read as QUALIFIED.
    qualified = counts[FAIL] == 0 and counts[BLOCKED] == 0 and not args.case
    verdict = ("ONE CASE SELECTED, NOT A QUALIFICATION" if args.case else
               "QUALIFIED (host simulation only)" if qualified else "NOT QUALIFIED")
    print(f"\nD04 {args.tier}: {len(results)} case(s): {counts[PASS]} passed, {counts[FAIL]} failed, "
          f"{counts[BLOCKED]} blocked -- {verdict}")
    if counts[BLOCKED]:
        print("blocked cases are required invariants nothing here can verify; they are counted, not passed")
    if args.judge and not any(c["id"] == RUST_CENTRAL for c, _, _ in results):
        print(f"note: --judge was given but {RUST_CENTRAL} is not among the selected cases, so the log was not used")
    if counts[FAIL] or counts[BLOCKED]:
        print("\n".join(retained_lines(argv, JUDGE_LOGS)))
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        receipt = {
            "schema": "ffw.d04.receipt.v1",
            "kind": "host_check_and_central_rust_log_judged" if JUDGE_LOGS is not None else "host_check_only_rust_not_run",
            "command": "tests/d04/run_cases.py " + " ".join(argv),
            "utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": sys.version.split()[0], "tier": args.tier, "denominator": len(results), "counts": counts,
            "qualified": qualified, "rust_test_functions_expected": len(all_rust_tests()),
            "inputs": {os.path.relpath(p, REPO): sha256_file(p) for p in (CASES_FILE, SCENARIOS_FILE, LOG_GOLDEN, REGRESS_GOLDEN)},
            "cases": [{"id": c["id"], "status": st} for c, st, _ in results],
            "artifacts": dict(artifact_digests()),
            "judged_logs": [{"name": os.path.basename(p), "sha256": d} for p, d in (JUDGE_LOGS.files if JUDGE_LOGS else [])],
            "judged_scope": TESTS_ONLY if JUDGE_LOGS is not None else None,
        }
        path = os.path.join(args.receipts, f"d04-{args.tier}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1)
            f.write("\n")
        print(f"receipt: {path}")
    if counts[FAIL]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
