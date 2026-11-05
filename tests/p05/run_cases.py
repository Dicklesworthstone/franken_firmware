#!/usr/bin/env python3
"""P05 (ffw-ipz) slice 1 case runner: the semantic 64-bit replacement in crates/franken-atomic.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]
                 [--central-log FILE] [--upstream-clone DIR]

What this runner is, so a pass is not over-read:
* The offline half re-derives the checker corpus, the directed scripts and the seeded sweeps with an
  independent model (reference.py), checks the Rust tests read exactly the pinned vectors, shows the case
  set is not vacuous (each deliberately weakened checker rule and each planted wrong cell is caught,
  against a green baseline), and checks the documentation and the crate hygiene.
* It does not run the Rust. There is no local cargo. Each Rust test is judged BY NAME from a central test
  log passed with --central-log: `ok` passes, `FAILED` fails, absent is BLOCKED. Totals are never used, and
  a test missing from the log can not be hidden by a green total. Without a log every Rust case is blocked
  and the run is NOT QUALIFIED.
* Evidence label: model, host simulation. Nothing here ran on a big-endian MIPS or PowerPC target or a
  guest; those are blocked cases (P05-EXT-*), counted and never passed.

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage or a malformed
case file.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import reference  # noqa: E402
import scan_upstream  # noqa: E402

CRATE = os.path.join(REPO, "crates", "franken-atomic")
SRC = os.path.join(CRATE, "src")
CASES_FILE = os.path.join(HERE, "cases.json")
VECTORS_FILE = os.path.join(HERE, "vectors.txt")
SCAN_FILE = os.path.join(HERE, "upstream_scan.json")
DOC_FILE = os.path.join(REPO, "docs", "contracts", "p05.md")
E06_README = os.path.join(REPO, "toolchain", "results", "e06", "upstream", "README.md")
SCHEMA = "ffw.p05.cases.v1"
TIERS = ("smoke", "full")
KINDS = ("meta_files", "meta_crate", "meta_shared", "meta_invariants", "meta_doc", "meta_render_guard",
         "meta_hygiene", "runner_selftest", "upstream_facts", "checker_history", "planted_checker", "directed",
         "planted_cell", "vectors_match", "central_log", "upstream_rescan", "rust_test", "blocked")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
Result = Tuple[str, str]
OPTIONS: Dict[str, Optional[str]] = {"central_log": None, "upstream_clone": None}

# What the documentation must contain (checked by P05-META-005).
DOC_HEADINGS = ("## No-claim line", "## Inputs", "## Replacement map: 64-bit atomics", "## Module areas",
                "## Gated dependencies that are inactive on the big-endian targets",
                "## Semantics of the replacement", "## Evidence and its limits", "## Open items")
DOC_CLASSES = ("Identifier or generation counter", "Timestamp or deadline", "Statistic or event count",
               "Flag word", "Owner-local state", "Test-only use", "Signed gauge")
DOC_NO_CLAIM = "does not make Asupersync compile on the big-endian MIPS or PowerPC targets"
VECTOR_KEYS = ("profile_threads", "profile_ops_per_thread", "profile_first_seed", "profile_seeds",
               "good_violations", "good_inconclusive", "split_violations", "split_inconclusive",
               "split_violation_seeds", "split_clean_seeds", "trunc_violations", "trunc_inconclusive",
               "trunc_violation_seeds", "trunc_clean_seeds")
PRODUCTION_MODULES = ("lib.rs", "error.rs", "shared.rs", "counter.rs", "local.rs")
RENDER_PATH_CRATES = ("franken-dsp", "franken-hal")
RENDER_PATH_FILES = (os.path.join("crates", "franken-speaker", "src", "render.rs"),)


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


def code_lines(text: str) -> List[Tuple[int, str]]:
    """(line number, text) for lines with comments removed; whole-line and trailing // comments are dropped.
    Good enough for the token checks here: no source line in the crate puts `//` inside a string."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.split("//")[0]
        if stripped.strip():
            out.append((n, stripped))
    return out


def rust_test_names() -> List[str]:
    names: List[str] = []
    for fname in sorted(os.listdir(SRC)):
        if fname.endswith(".rs"):
            names += re.findall(r"#\[test\]\s*\n\s*fn\s+(\w+)\s*\(", read(os.path.join(SRC, fname)))
    return names


# ----------------------------------------------------------------------------------------- vectors

def parse_vectors(text: str) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, *nums = line.split()
        out[name] = [int(n) for n in nums]
    return out


def vectors_problems(vec: Dict[str, List[int]]) -> List[str]:
    """Compare the pinned vectors with what the independent reference predicts."""
    problems = [f"vectors.txt lacks {k}" for k in VECTOR_KEYS if k not in vec]
    if problems:
        return problems
    prof = reference.PROFILE
    for key, want in (("profile_threads", prof["threads"]), ("profile_ops_per_thread", prof["ops_per_thread"]),
                      ("profile_first_seed", prof["first_seed"]), ("profile_seeds", prof["seeds"])):
        if vec[key] != [want]:
            problems.append(f"{key} is {vec[key]}, reference profile says {want}")
    predicted = reference.predict()
    for kind in ("good", "split", "trunc"):
        if vec[f"{kind}_violations"] != [len(predicted[kind])]:
            problems.append(f"{kind}_violations pinned {vec[kind + '_violations']}, reference predicts {len(predicted[kind])}")
        if vec[f"{kind}_inconclusive"] != [len(predicted[kind + '_inconclusive'])]:
            problems.append(f"{kind}_inconclusive pinned {vec[kind + '_inconclusive']}, reference predicts "
                            f"{len(predicted[kind + '_inconclusive'])}")
    seeds = range(prof["first_seed"], prof["first_seed"] + prof["seeds"])
    for kind in ("split", "trunc"):
        bad = set(predicted[kind])
        first_bad = sorted(bad)[:4]
        first_clean = [s for s in seeds if s not in bad][:4]
        if vec[f"{kind}_violation_seeds"] != first_bad:
            problems.append(f"{kind}_violation_seeds pinned {vec[kind + '_violation_seeds']}, reference {first_bad}")
        if vec[f"{kind}_clean_seeds"] != first_clean:
            problems.append(f"{kind}_clean_seeds pinned {vec[kind + '_clean_seeds']}, reference {first_clean}")
    return problems


def run_vectors_match(c) -> Result:
    problems = vectors_problems(parse_vectors(read(VECTORS_FILE)))
    return (PASS, "reference reproduces every pinned count and seed") if not problems else (FAIL, "; ".join(problems))


# ------------------------------------------------------------------------------------ checker corpus

def to_tuple(x: Any) -> Any:
    return tuple(to_tuple(i) for i in x) if isinstance(x, list) else x


def events_of(c) -> List[reference.Event]:
    return [reference.Event(e[0], e[1], e[2], to_tuple(e[3]), to_tuple(e[4])) for e in c["events"]]


def history_verdict(c, mutant: Optional[str] = None) -> str:
    return reference.check(c["initial"], events_of(c), budget=c.get("budget", 200_000), mutant=mutant)


def run_checker_history(c) -> Result:
    got = history_verdict(c)
    if got != c["expect"]:
        return FAIL, f"{c['name']}: checker says {got}, hand-written expectation is {c['expect']}"
    if "with_default_budget" in c:
        again = reference.check(c["initial"], events_of(c))
        if again != c["with_default_budget"]:
            return FAIL, f"with the default budget the checker says {again}, expected {c['with_default_budget']}"
    return PASS, ""


def corpus(doc_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [c for c in doc_cases if c["kind"] == "checker_history"]


def check_mutant(mutant: str, caught_by: List[str], cases: List[Dict[str, Any]]) -> Result:
    """The corpus must be green unmutated (else no catch can be credited) and each named case must change
    its verdict under the mutant."""
    chk = corpus(cases)
    red = [c["id"] for c in chk if history_verdict(c) != c["expect"]]
    if red:
        return FAIL, f"baseline is not green, so no catch can be credited: {red}"
    ids = {c["id"]: c for c in chk}
    missing = [i for i in caught_by if i not in ids]
    if missing:
        return FAIL, f"caught_by names unknown cases {missing}"
    caught = sorted(c["id"] for c in chk if "budget" not in c and history_verdict(c, mutant) != c["expect"])
    not_caught = [i for i in caught_by if i not in caught]
    if not_caught:
        return FAIL, f"mutant {mutant!r} was not caught by {not_caught}; caught by {caught}"
    return PASS, f"caught by {len(caught)} case(s)"


def run_planted_checker(c) -> Result:
    if c["mutant"] not in reference.CHECKER_MUTANTS:
        return FAIL, f"unknown mutant {c['mutant']!r}"
    return check_mutant(c["mutant"], c["caught_by"], load_json(CASES_FILE)["cases"])


# ------------------------------------------------------------------------------- directed + planted cells

def run_directed(c) -> Result:
    events, verdict = reference.run_scenario(c["cell"], c["scenario"])
    loaded = reference.load_value(events)
    if verdict != c["expect"]:
        return FAIL, f"{c['scenario']} on {c['cell']}: verdict {verdict}, hand-written expectation {c['expect']}"
    if loaded != c["expect_loaded"]:
        return FAIL, f"{c['scenario']} on {c['cell']}: loaded {loaded:#x}, expected {c['expect_loaded']:#x}"
    return PASS, ""


def run_planted_cell(c) -> Result:
    p = reference.PROFILE
    args = (p["first_seed"], p["seeds"], p["threads"], p["ops_per_thread"])
    good, good_inc = reference.sweep("good", *args)
    if good or good_inc:
        return FAIL, f"the control (real cell) is not green: {len(good)} violation(s), {len(good_inc)} inconclusive"
    bad, inc = reference.sweep(c["cell"], *args)
    if inc:
        return FAIL, f"{len(inc)} inconclusive run(s) for the planted {c['cell']} cell"
    if not bad:
        return FAIL, f"the planted {c['cell']} cell was not caught by any of {p['seeds']} seeds"
    pinned = parse_vectors(read(VECTORS_FILE)).get(f"{c['cell']}_violations")
    if pinned != [len(bad)]:
        return FAIL, f"caught on {len(bad)} seeds, vectors.txt pins {pinned}"
    return PASS, f"control green on {p['seeds']} seeds; planted cell caught on {len(bad)}"


# ------------------------------------------------------------------------------------------------ meta

def run_meta_files(c) -> Result:
    needed = [CASES_FILE, VECTORS_FILE, SCAN_FILE, DOC_FILE, os.path.join(HERE, "reference.py"),
              os.path.join(HERE, "scan_upstream.py"), os.path.join(CRATE, "Cargo.toml"),
              os.path.join(REPO, "scripts", "e2e", "p05")] + [os.path.join(SRC, m) for m in PRODUCTION_MODULES] \
        + [os.path.join(SRC, m) for m in ("model.rs", "planted.rs", "tests.rs")]
    gone = [os.path.relpath(p, REPO) for p in needed if not os.path.isfile(p)]
    return (PASS, "") if not gone else (FAIL, f"missing: {gone}")


def run_meta_crate(c) -> Result:
    problems = []
    lib = read(os.path.join(SRC, "lib.rs"))
    if "#![forbid(unsafe_code)]" not in lib:
        problems.append("lib.rs does not forbid unsafe_code")
    manifest = read(os.path.join(CRATE, "Cargo.toml"))
    if not re.search(r"\[lints\]\s*\nworkspace\s*=\s*true", manifest):
        problems.append("Cargo.toml does not inherit the workspace lints")
    for section in ("[dependencies", "[dev-dependencies", "[build-dependencies", "[features", "[target."):
        if section in manifest:
            problems.append(f"Cargo.toml has a {section}] section; the crate is std-only with no edges")
    unsafe_rx = re.compile(r"\bunsafe\b")
    atomic64 = re.compile(r"\bAtomic(?:U|I)64\b")
    wide_atomics = re.compile(r"\bAtomic(?:Usize|Isize)\b")
    narrowing = re.compile(r"\bas\s+(?:u8|u16|u32|i8|i16|i32)\b")
    for fname in sorted(os.listdir(SRC)):
        if not fname.endswith(".rs"):
            continue
        for n, line in code_lines(read(os.path.join(SRC, fname))):
            if fname == "lib.rs" and "forbid(unsafe_code)" in line:
                continue
            if unsafe_rx.search(line):
                problems.append(f"{fname}:{n}: unsafe: {line.strip()}")
            if atomic64.search(line):
                problems.append(f"{fname}:{n}: names a 64-bit atomic type: {line.strip()}")
            if wide_atomics.search(line):
                problems.append(f"{fname}:{n}: names a pointer-width atomic (64-bit on some targets): {line.strip()}")
            if fname in PRODUCTION_MODULES and narrowing.search(line):
                problems.append(f"{fname}:{n}: narrowing cast in a production module: {line.strip()}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def run_meta_shared(c) -> Result:
    problems = []
    tests = read(os.path.join(SRC, "tests.rs"))
    if 'include_str!("../../../tests/p05/vectors.txt")' not in tests:
        problems.append("tests.rs does not include tests/p05/vectors.txt")
    vec = parse_vectors(read(VECTORS_FILE))
    for key in VECTOR_KEYS:
        if key not in vec:
            problems.append(f"vectors.txt lacks {key}")
    used = set(re.findall(r'scalar\("(\w+)"\)', tests)) | set(re.findall(r'vector\("(\w+)"\)', tests))
    used |= {f"{p}_{s}" for p in ("split", "trunc") for s in ("violations", "inconclusive", "violation_seeds", "clean_seeds")
             if f'"{p}"' in tests}
    unknown = sorted(k for k in used if k not in vec)
    if unknown:
        problems.append(f"tests.rs reads vectors that vectors.txt lacks: {unknown}")
    model = read(os.path.join(SRC, "model.rs"))
    for name, values in (("POOL", reference.POOL), ("DELTAS", reference.DELTAS)):
        m = re.search(r"const %s: \[u64; \d+\] = \[(.*?)\];" % name, model, re.S)
        found = [int(x.replace("_", ""), 0) for x in re.findall(r"0x[0-9A-Fa-f_]+|\b\d+\b", m.group(1))] if m else None
        if found != list(values):
            problems.append(f"model.rs {name} is {found}, reference.py has {list(values)}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def expand(patterns: List[str], ids: List[str]) -> List[str]:
    out: List[str] = []
    for p in patterns:
        out.extend(i for i in ids if i.startswith(p[:-1])) if p.endswith("*") else out.append(p)
    return out


def all_ids(doc: Dict[str, Any]) -> List[str]:
    return [x["id"] for x in doc["cases"]] + [x["id"] for x in rust_cases(doc)]


def rust_cases(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One case per distinct Rust test named by an invariant, in first-mention order."""
    names: List[str] = []
    for inv in doc["invariants"]:
        for n in inv["rust_tests"]:
            if n not in names:
                names.append(n)
    return [{"id": f"P05-RUST-{i:03d}", "kind": "rust_test", "tier": "full", "test": n}
            for i, n in enumerate(names, 1)]


def check_invariants(doc: Dict[str, Any], ids: List[str], tests: List[str]) -> List[str]:
    problems, mapped = [], set()
    for inv in doc["invariants"]:
        if not inv["rust_tests"] and not inv["cases"]:
            problems.append(f"{inv['id']} maps to nothing")
        for name in inv["rust_tests"]:
            if name not in tests:
                problems.append(f"{inv['id']}: no #[test] fn {name} in crates/franken-atomic/src")
        for ref in expand(inv["cases"], ids):
            if ref not in ids:
                problems.append(f"{inv['id']} names unknown case {ref}")
            mapped.add(ref)
    mapped |= {x["id"] for x in rust_cases(doc)}  # judged through the invariant that names the test
    orphans = [i for i in ids if i not in mapped]
    if orphans:
        problems.append(f"cases covering no invariant: {orphans}")
    return problems


def run_meta_invariants(c) -> Result:
    doc = load_json(CASES_FILE)
    tests = rust_test_names()
    problems = check_invariants(doc, all_ids(doc), tests)
    listed = {n for inv in doc["invariants"] for n in inv["rust_tests"]}
    unmapped = sorted(set(tests) - listed)
    if unmapped:
        problems.append(f"Rust tests in no invariant: {unmapped}")
    dup = sorted({n for n in tests if tests.count(n) > 1})
    if dup:
        problems.append(f"duplicate Rust test names (a log could not tell them apart): {dup}")
    bad_prefix = sorted(n for n in tests if not n.startswith("p05_"))
    if bad_prefix:
        problems.append(f"Rust tests without the p05_ prefix: {bad_prefix}")
    return (PASS, f"{len(doc['invariants'])} invariants, all {len(tests)} Rust tests mapped") \
        if not problems else (FAIL, "; ".join(problems))


def fixture_numbers() -> List[Tuple[str, int]]:
    d = load_json(SCAN_FILE)
    s, m = d["src"], d["methods_upper_bound"]
    return [("src mentions", s["mentions"]), ("src files naming a 64-bit atomic", s["files_naming_a_64bit_atomic"]),
            ("AtomicI64 mentions", s["atomic_i64_mentions"]), ("test-named files", s["test_named_files_among_them"]),
            ("files naming the facade", s["files_naming_the_crate_facade"]),
            ("statics", d["statics"]["total"]), ("fence calls", d["fence_calls_in_those_files"]),
            ("fetch_add", m["fetch_add"]), ("load", m["load"]), ("store", m["store"]),
            ("fetch_update", m["fetch_update"]), ("fetch_max", m["fetch_max"]), ("fetch_min", m["fetch_min"]),
            ("fetch_or", m["fetch_or"]), ("fetch_and", m["fetch_and"]),
            ("compare_exchange_weak", m["compare_exchange_weak"]), ("compare_exchange", m["compare_exchange"]),
            ("test-only area mentions", d["test_only_areas"]["mentions"])]


def doc_problems(doc_text: str) -> List[str]:
    problems = [f"missing heading {h!r}" for h in DOC_HEADINGS if h not in doc_text]
    problems += [f"missing classification {k!r}" for k in DOC_CLASSES if k not in doc_text]
    if DOC_NO_CLAIM not in doc_text:
        problems.append("the no-claim line is missing")
    # Each number is cited in a "Pinned facts" table row: `| label | value | ... |`. A bare substring test
    # would let a small number like 2 or 5 match anywhere.
    for label, value in fixture_numbers():
        row = r"^\|\s*" + re.escape(label) + r"\s*\|\s*" + re.escape(f"{value:,}") + r"\s*\|"
        if not re.search(row, doc_text, re.M):
            problems.append(f"no `| {label} | {value:,} |` row: the pinned scan's number is not cited")
    for area in load_json(SCAN_FILE)["areas_top"][:12]:
        if area["area"] not in doc_text:
            problems.append(f"module area {area['area']} is not in the table")
    return problems


def run_meta_doc(c) -> Result:
    problems = doc_problems(read(DOC_FILE))
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def run_meta_render_guard(c) -> Result:
    problems = []
    for crate in RENDER_PATH_CRATES:
        path = os.path.join(REPO, "crates", crate, "Cargo.toml")
        if os.path.isfile(path) and "franken-atomic" in read(path):
            problems.append(f"{crate} depends on franken-atomic: the shared fallback is not for the render path")
    for rel in RENDER_PATH_FILES:
        path = os.path.join(REPO, rel)
        if os.path.isfile(path):
            for n, line in code_lines(read(path)):
                if re.search(r"franken_atomic|\bSharedU64\b|\bSharedI64\b|\bSequence\b", line):
                    problems.append(f"{rel}:{n}: names the shared fallback: {line.strip()}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


HYGIENE_FILES = ("cases.json", "reference.py", "run_cases.py", "scan_upstream.py", "vectors.txt")


def run_meta_hygiene(c) -> Result:
    problems = []
    ipv4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    mac = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
    longhex = re.compile(r"\b[0-9a-fA-F]{64,}\b")
    paths = [os.path.join(HERE, f) for f in HYGIENE_FILES] + [DOC_FILE, SCAN_FILE]
    for path in paths:
        text = read(path)
        for rx, what in ((ipv4, "an IPv4 address"), (mac, "a MAC address"), (longhex, "a long hex blob")):
            hit = rx.search(text)
            if hit:
                problems.append(f"{os.path.relpath(path, REPO)}: {what} {hit.group(0)!r}")
        if "/Users/" in text or "/home/" in text:
            problems.append(f"{os.path.relpath(path, REPO)}: a local absolute path")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


# ----------------------------------------------------------------------------------------- central log

def judge_log(text: str, name: str) -> Result:
    hits = re.findall(r"\btest (?:\w+::)*" + re.escape(name) + r" \.\.\. (\w+)", text)
    if not hits:
        return BLOCKED, "not in the central log"
    if any(h == "FAILED" for h in hits):
        return FAIL, "FAILED in the central log"
    if any(h != "ok" for h in hits):
        return BLOCKED, f"reported {sorted(set(hits))}, not ok"
    return PASS, ""


def log_sanity(text: str, known: List[str]) -> Result:
    if "franken_atomic" not in text:
        return FAIL, "the log does not mention franken_atomic: it is not this crate's test run"
    if "test result:" not in text:
        return FAIL, "the log has no `test result:` line: the test binary did not finish"
    if re.search(r"test result: FAILED", text):
        return FAIL, "the log reports `test result: FAILED`"
    named = set(re.findall(r"\btest (?:\w+::)*(p05_\w+) \.\.\. ", text))
    extra = sorted(named - set(known))
    if extra:
        return FAIL, f"the log has p05_ tests no invariant maps (the case file has drifted): {extra}"
    return PASS, f"{len(named)} p05_ test(s) reported"


def run_central_log(c) -> Result:
    path = OPTIONS["central_log"]
    if not path:
        return BLOCKED, "no --central-log: the Rust tests have not been run centrally (RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-atomic)"
    try:
        text = read(path)
    except OSError as e:
        return FAIL, f"cannot read the central log: {e}"
    return log_sanity(text, rust_test_names())


def run_rust_test(c) -> Result:
    path = OPTIONS["central_log"]
    if not path:
        return BLOCKED, f"{c['test']}: no central log"
    try:
        text = read(path)
    except OSError as e:
        return FAIL, f"cannot read the central log: {e}"
    status, detail = judge_log(text, c["test"])
    return status, f"{c['test']}: {detail}" if detail else c["test"]


# ------------------------------------------------------------------------------------ upstream facts

def run_upstream_facts(c) -> Result:
    d = load_json(SCAN_FILE)
    problems = []
    if d.get("schema") != scan_upstream.SCHEMA:
        problems.append(f"fixture schema {d.get('schema')!r}")
    if d.get("revision") != scan_upstream.EXPECTED_REV:
        problems.append(f"fixture is for {d.get('revision')}, not the pinned revision")
    if d["src"]["files_with_a_direct_core_or_std_path"] != ["src/sync/atomic.rs"]:
        problems.append(f"E06's claim (no direct path outside the facade in src/) does not hold: "
                        f"{d['src']['files_with_a_direct_core_or_std_path']}")
    if sum(d["statics"]["by_class"].values()) != d["statics"]["total"]:
        problems.append("static classes do not add up to the static total")
    if d["src"]["atomic_u64_mentions"] + d["src"]["atomic_i64_mentions"] != d["src"]["mentions"]:
        problems.append("AtomicU64 and AtomicI64 mentions do not add up to the src total")
    e06 = read(E06_README)
    for label, text in (("files", f"{d['src']['files_naming_a_64bit_atomic']}"), ("mentions", f"{d['src']['mentions']:,}")):
        if text not in e06:
            problems.append(f"E06's inventory README does not state this scan's {label} ({text}): the two tools disagree")
    return (PASS, "the scan agrees with E06 on files and mentions") if not problems else (FAIL, "; ".join(problems))


def run_upstream_rescan(c) -> Result:
    clone = OPTIONS["upstream_clone"]
    if not clone:
        return BLOCKED, "no --upstream-clone: the pinned scan was not re-run against the Asupersync object database"
    result = scan_upstream.scan(clone, scan_upstream.EXPECTED_REV)
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"
    return (PASS, "re-scan reproduces upstream_scan.json exactly") if text == read(SCAN_FILE) \
        else (FAIL, "re-scan differs from upstream_scan.json")


def run_blocked(c) -> Result:
    return BLOCKED, f"{c['blocker']} (owner: {c['owner']}): {c['needs']}"


# ------------------------------------------------------------------------------------------ selftest

def run_runner_selftest(c) -> Result:
    """The comparisons are not vacuous. Each corruption below must be seen."""
    doc = load_json(CASES_FILE)
    chk = [x for x in doc["cases"] if x["id"] == "P05-CHK-003"][0]
    if run_checker_history(chk)[0] != PASS:
        return FAIL, "a baseline checker case does not pass"
    flipped = dict(chk, expect="linearizable")
    if run_checker_history(flipped)[0] == PASS:
        return FAIL, "a flipped checker expectation was accepted"
    # a mutant that is claimed to be caught by a case that does not catch it
    if check_mutant("strict_precedence", ["P05-CHK-003"], doc["cases"])[0] == PASS:
        return FAIL, "a mutant credited to a case that does not catch it was accepted"
    # a corpus with the catching case removed
    trimmed = [x for x in doc["cases"] if x["id"] != "P05-CHK-005"]
    if check_mutant("strict_precedence", ["P05-CHK-005"], trimmed)[0] == PASS:
        return FAIL, "a mutant was credited to a case that was removed"
    # a stale vectors file
    vec = parse_vectors(read(VECTORS_FILE))
    stale = copy.deepcopy(vec)
    stale["split_violations"] = [vec["split_violations"][0] + 1]
    if not vectors_problems(stale):
        return FAIL, "a stale violation count was accepted"
    stale = copy.deepcopy(vec)
    stale["trunc_clean_seeds"] = [vec["trunc_violation_seeds"][0]] + vec["trunc_clean_seeds"][1:]
    if not vectors_problems(stale):
        return FAIL, "a clean seed that is not clean was accepted"
    # invariants
    bad = copy.deepcopy(doc)
    bad["invariants"][0]["rust_tests"].append("p05_a_test_that_does_not_exist")
    if not any("p05_a_test_that_does_not_exist" in p for p in check_invariants(bad, all_ids(bad), rust_test_names())):
        return FAIL, "a missing Rust test name was not detected"
    orphan = copy.deepcopy(doc)
    orphan["cases"].append({"id": "P05-ORPHAN", "kind": "meta_files", "tier": "smoke"})
    if not any("P05-ORPHAN" in p for p in check_invariants(orphan, all_ids(orphan), rust_test_names())):
        return FAIL, "a case covering no invariant was not detected"
    # the central log
    name = "p05_vector_i64_signed_range"
    if judge_log(f"test shared::x::{name} ... ok\n", name)[0] != PASS:
        return FAIL, "an ok line was not accepted"
    if judge_log(f"test tests::{name} ... FAILED\n", name)[0] != FAIL:
        return FAIL, "a FAILED line was not a failure"
    if judge_log(f"test tests::{name} ... ok\ntest tests::{name} ... FAILED\n", name)[0] != FAIL:
        return FAIL, "a retried test laundered a failure"
    if judge_log("test result: ok. 99 passed; 0 failed\n", name)[0] != BLOCKED:
        return FAIL, "a green total stood in for a test that is missing from the log"
    if judge_log(f"test tests::{name} ... ignored\n", name)[0] == PASS:
        return FAIL, "an ignored test passed"
    if log_sanity("running 1 test\ntest result: ok.\n", rust_test_names())[0] != FAIL:
        return FAIL, "a log from another crate was accepted"
    # the documentation
    if not doc_problems("# nothing"):
        return FAIL, "an empty document passed the documentation check"
    return PASS, ""


RUNNERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "meta_files": run_meta_files, "meta_crate": run_meta_crate, "meta_shared": run_meta_shared,
    "meta_invariants": run_meta_invariants, "meta_doc": run_meta_doc, "meta_render_guard": run_meta_render_guard,
    "meta_hygiene": run_meta_hygiene, "runner_selftest": run_runner_selftest, "upstream_facts": run_upstream_facts,
    "checker_history": run_checker_history, "planted_checker": run_planted_checker, "directed": run_directed,
    "planted_cell": run_planted_cell, "vectors_match": run_vectors_match, "central_log": run_central_log,
    "upstream_rescan": run_upstream_rescan, "rust_test": run_rust_test, "blocked": run_blocked,
}


# --------------------------------------------------------------------------------------------- main

def all_cases() -> List[Dict[str, Any]]:
    doc = load_json(CASES_FILE)
    if doc.get("schema") != SCHEMA:
        raise CaseError(f"cases.json schema is {doc.get('schema')!r}, expected {SCHEMA!r}")
    cases = list(doc["cases"]) + rust_cases(doc)
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


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="P05 slice 1 case runner")
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--case", metavar="ID")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--receipts", metavar="DIR")
    ap.add_argument("--central-log", metavar="FILE", help="cargo test output from the central franken-atomic run")
    ap.add_argument("--upstream-clone", metavar="DIR", help="local Asupersync clone, read as git objects only")
    args = ap.parse_args(argv)
    OPTIONS["central_log"], OPTIONS["upstream_clone"] = args.central_log, args.upstream_clone
    try:
        chosen = select(all_cases(), args.tier, args.case)
        if args.list:
            for c in chosen:
                print(f"{c['id']:<24} {c['tier']:<6} {c['kind']}")
            return 0
        results = []
        for c in chosen:
            try:
                status, detail = RUNNERS[c["kind"]](c)
            except CaseError:
                raise
            except Exception as e:  # a crashing case is a failed case, never a skipped one
                status, detail = FAIL, f"crashed: {type(e).__name__}: {e}"
            results.append((c, status, detail))
            print(f"{status.upper():<7} {c['id']:<24} {c['kind']}{'  ' + detail if detail else ''}")
    except CaseError as e:
        print(f"P05 runner: {e}", file=sys.stderr)
        return 2
    counts = {s: sum(1 for _, st, _ in results if st == s) for s in (PASS, FAIL, BLOCKED)}
    qualified = counts[FAIL] == 0 and counts[BLOCKED] == 0
    print(f"\nP05 {args.tier}: {len(results)} case(s): {counts[PASS]} passed, {counts[FAIL]} failed, "
          f"{counts[BLOCKED]} blocked -- {'QUALIFIED (host simulation only)' if qualified else 'NOT QUALIFIED'}")
    if counts[BLOCKED]:
        print("blocked cases are required evidence nothing here can verify; they are counted, not passed")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        receipt = {
            "schema": "ffw.p05.receipt.v1", "kind": "host_check_rust_judged_from_log_only",
            "command": "tests/p05/run_cases.py " + " ".join(argv),
            "utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": sys.version.split()[0], "tier": args.tier, "denominator": len(results), "counts": counts,
            "qualified": qualified, "central_log_sha256": sha256_file(args.central_log) if args.central_log else None,
            "inputs": {os.path.relpath(p, REPO): sha256_file(p) for p in (CASES_FILE, VECTORS_FILE, SCAN_FILE)},
            "cases": [{"id": c["id"], "status": st} for c, st, _ in results],
        }
        path = os.path.join(args.receipts, f"p05-{args.tier}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1)
            f.write("\n")
        print(f"receipt: {path}")
    if counts[FAIL]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
