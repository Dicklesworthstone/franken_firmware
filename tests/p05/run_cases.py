#!/usr/bin/env python3
"""P05 (ffw-ipz) slice 1 case runner: the semantic 64-bit replacement in crates/franken-atomic.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]
                 [--central-log FILE] [--upstream-clone DIR] [--guest-elf FILE]

What this runner is, so a pass is not over-read:
* The offline half re-derives the checker corpus, the directed scripts and the seeded sweeps with an
  independent model (reference.py), checks the Rust tests read exactly the pinned vectors, shows the case
  set is not vacuous (each deliberately weakened checker rule and each planted wrong cell is caught,
  against a green baseline), and checks the documentation and the crate hygiene.
* It does not run the Rust. There is no local cargo. Each Rust test is judged BY NAME from a central test
  log passed with --central-log: `ok` passes, `FAILED` fails, absent is BLOCKED. Totals are never used, and
  a test missing from the log can not be hidden by a green total. Without a log every Rust case is blocked
  and the run is NOT QUALIFIED.
* Evidence label: model, host simulation, plus ONE QEMU guest receipt. This runner ran nothing on a target.
  P05-EXT-GUEST re-judges the COMMITTED serial log of a big-endian MIPS32 guest with the judge in
  toolchain/src/measure-p05-target.py, from the committed seed; it never trusts the receipt JSON (a receipt that
  disagrees with the log, the seed, the pins or the re-judged gates can only make it fail). With no committed log it is
  BLOCKED, never passed. P05-EXT-GUEST-PLANT changes one byte of that log nine ways and one byte of the receipt twelve
  ways and requires each to be refused by exactly its own gate or check, with the unplanted log and receipt as the
  controls. The ELF is not in the repository (only a 128-bit prefix of its sha256 is pinned), so
  the ELF-header gate is re-judged only with --guest-elf. Target builds, PowerPC, the Asupersync adaptation and the
  per-site audit stay blocked cases (P05-EXT-*), counted and never passed.

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage or a malformed
case file.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Set, Tuple

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
E06_INVENTORY = os.path.join(REPO, "toolchain", "results", "e06", "upstream", "asupersync-8940119023c0",
                             "default.inventory.json")
GUEST_JUDGE = os.path.join(REPO, "toolchain", "src", "measure-p05-target.py")
GUEST_TESTS = os.path.join(REPO, "toolchain", "tests", "test_measure_p05_target.py")
SCHEMA = "ffw.p05.cases.v1"
TIERS = ("smoke", "full")
KINDS = ("meta_files", "meta_crate", "meta_shared", "meta_invariants", "meta_doc", "meta_render_guard",
         "meta_hygiene", "runner_selftest", "upstream_facts", "checker_history", "planted_checker", "directed",
         "planted_cell", "vectors_match", "central_log", "upstream_rescan", "rust_test", "blocked", "gate_facts",
         "guest_receipt", "guest_plant")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
Result = Tuple[str, str]
OPTIONS: Dict[str, Optional[str]] = {"central_log": None, "upstream_clone": None, "guest_elf": None}

# What the documentation must contain (checked by P05-META-005).
DOC_RUNTIME_HEADING = "## The runtime probe and its single-owner profile"
DOC_HEADINGS = ("## No-claim line", "## Inputs", "## Replacement map: 64-bit atomics", "## Module areas",
                "## Gated dependencies that are inactive on the big-endian targets",
                "## Semantics of the replacement", "## Evidence and its limits",
                DOC_RUNTIME_HEADING, "## Open items")
# The single-owner profile's contract text: a declared unsupported row that is a declaration and never a pass, how it is selected
# and judged, and where its native test names are listed. Each must stay INSIDE that section (P05-META-005): a mention elsewhere,
# such as the open-items bullet, does not stand in for it.
DOC_RUNTIME_TERMS = ("--profile single-owner", "/ffw_p05_profile", "CALLER_DRIVEN_CURRENT_THREAD",
                     "reason_source=static_source_reading", "declaration, not a pass", "accepted_with_declared_unsupported",
                     "never `PASSED`", "the command-line exit is 4", "FIRST_USE_BACKGROUND",
                     "tests/p05/native_runtime38_names.txt")
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
              os.path.join(REPO, "scripts", "e2e", "p05"), GUEST_JUDGE, GUEST_TESTS] \
        + [os.path.join(SRC, m) for m in PRODUCTION_MODULES] \
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
            ("fetch_or", m["fetch_or"]), ("fetch_and", m["fetch_and"]), ("get_mut", m["get_mut"]),
            ("into_inner", m["into_inner"]),
            ("compare_exchange_weak", m["compare_exchange_weak"]), ("compare_exchange", m["compare_exchange"]),
            ("test-only area mentions", d["test_only_areas"]["mentions"]),
            ("statics identifier or counter", d["statics"]["by_class"]["identifier_or_counter"]),
            ("statics clock", d["statics"]["by_class"]["clock"]),
            ("statics statistic", d["statics"]["by_class"]["statistic"]),
            ("statics test only", d["statics"]["by_class"]["test_only"]),
            ("direct std imports outside src", sum(v["direct_std_import_files"] for v in d["outside_src"].values()))]


def runtime_section(doc_text: str) -> str:
    """The single-owner profile section: from its heading to the next `## ` heading, or "" when the heading is missing."""
    start = doc_text.find(DOC_RUNTIME_HEADING)
    if start < 0:
        return ""
    end = doc_text.find("\n## ", start + len(DOC_RUNTIME_HEADING))
    return doc_text[start:] if end < 0 else doc_text[start:end]


def doc_problems(doc_text: str) -> List[str]:
    problems = [f"missing heading {h!r}" for h in DOC_HEADINGS if h not in doc_text]
    problems += [f"missing classification {k!r}" for k in DOC_CLASSES if k not in doc_text]
    section = runtime_section(doc_text)
    problems += [f"missing single-owner profile term {t!r}" for t in DOC_RUNTIME_TERMS if t not in section]
    if DOC_NO_CLAIM not in doc_text:
        problems.append("the no-claim line is missing")
    # Each number is cited in a "Pinned facts" table row: `| label | value | ... |`. A bare substring test
    # would let a small number like 2 or 5 match anywhere.
    for label, value in fixture_numbers():
        row = r"^\|\s*" + re.escape(label) + r"\s*\|\s*" + re.escape(f"{value:,}") + r"\s*\|"
        if not re.search(row, doc_text, re.M):
            problems.append(f"no `| {label} | {value:,} |` row: the pinned scan's number is not cited")
    # The twelve largest module areas: a row `| `src/x` | mentions | files | test-named files | ...`.
    for a in load_json(SCAN_FILE)["areas_top"][:12]:
        row = (r"^\|\s*`" + re.escape(a["area"]) + r"`\s*\|\s*" + re.escape(f"{a['mentions']:,}") + r"\s*\|\s*"
               + str(a["files"]) + r"\s*\|\s*" + str(a["test_named_files"]) + r"\s*\|")
        if not re.search(row, doc_text, re.M):
            problems.append(f"no row for module area {a['area']} with {a['mentions']:,}/{a['files']}/{a['test_named_files']}")
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
        # Built from parts so this file does not contain what it forbids.
        if any(root in text for root in ("/" + "Users/", "/" + "home/")):
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


GATE_ROWS = ("wasm", "windows", "apple", "cpu-feature probe", "other operating system", "linux io-uring",
             "never-active marker", "dev-dependency")


def gate_group(detail: str, pred: str) -> str:
    """The group of a platform-gated dependency edge that cargo did not take on either big-endian target."""
    if detail.startswith("dev dependency"):
        return "dev-dependency"
    if "wasm" in pred:
        return "wasm"
    if "windows" in pred:
        return "windows"
    if "apple" in pred or "macos" in pred or "ios" in pred:
        return "apple"
    if "x86" in pred or "aarch64" in pred or "loongarch64" in pred:
        return "cpu-feature probe"
    if "io-uring" in detail:
        return "linux io-uring"
    if any(w in pred for w in ("hermit", "redox", "wasi", "freebsd", "netbsd", "uefi")):
        return "other operating system"
    if pred == "cfg(any())" or "loom" in pred or "fiat" in pred:
        return "never-active marker"
    return "unclassified"


def gate_counts() -> Dict[str, int]:
    """Counts from E06's committed inventory: every gated edge, those inactive on both big-endian targets by
    group, and those whose predicate the inventory truncated (their activity is not recorded)."""
    findings = [f for f in load_json(E06_INVENTORY)["findings"] if f["kind"] == "gated-dependency"]
    out = {"gated edges in the inventory": len(findings), "predicate truncated in the inventory": 0,
           "inactive on both big-endian targets": 0, "active on both big-endian targets": 0,
           "activity cut off for one target": 0}
    for g in GATE_ROWS + ("unclassified",):
        out[g] = 0
    for f in findings:
        detail = f["detail"]
        m = re.search(r"gated by (.*?); active on", detail)
        if not m:
            out["predicate truncated in the inventory"] += 1
            continue
        if "mips=no" in detail and "powerpc=no" in detail:
            out["inactive on both big-endian targets"] += 1
            out[gate_group(detail, m.group(1))] += 1
        elif "mips=yes" in detail and "powerpc=yes" in detail:
            out["active on both big-endian targets"] += 1
        else:
            out["activity cut off for one target"] += 1
    return out


def run_gate_facts(c) -> Result:
    counts = gate_counts()
    doc = read(DOC_FILE)
    problems = []
    if counts["unclassified"]:
        problems.append(f"{counts['unclassified']} inactive edge(s) fall in no group; extend gate_group")
    if sum(counts[g] for g in GATE_ROWS) != counts["inactive on both big-endian targets"]:
        problems.append("the groups do not add up to the inactive total")
    for label, value in counts.items():
        if label == "unclassified":
            continue
        row = r"^\|\s*" + re.escape(label) + r"\s*\|\s*" + str(value) + r"\s*\|"
        if not re.search(row, doc, re.M):
            problems.append(f"no `| {label} | {value} |` row in p05.md")
    return (PASS, f"{counts['inactive on both big-endian targets']} inactive edges, all grouped and cited") \
        if not problems else (FAIL, "; ".join(problems))


def run_upstream_rescan(c) -> Result:
    clone = OPTIONS["upstream_clone"]
    if not clone:
        return BLOCKED, "no --upstream-clone: the pinned scan was not re-run against the Asupersync object database"
    result = scan_upstream.scan(clone, scan_upstream.EXPECTED_REV)
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"
    return (PASS, "re-scan reproduces upstream_scan.json exactly") if text == read(SCAN_FILE) \
        else (FAIL, "re-scan differs from upstream_scan.json")


# ------------------------------------------------------------------------------------------- guest receipt

GUEST_LOG, GUEST_SEED, GUEST_RECEIPT, GUEST_CONSOLE = "p05-target.serial.log", "seed.txt", "receipt.json", "console.txt"
ELF_GATE = "P05T-ELF"
FORBIDDEN_IN_EVIDENCE = (
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "an IPv4 address"),
    (re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"), "a MAC address"),
    # Built from parts so this file does not contain what it forbids.
    (re.compile("/" + "Users/|/" + "home/|/" + "private/|/" + "Volumes/"), "a local absolute path"),
)
_MODULES: Dict[str, Any] = {}


def load_module(path: str, name: str) -> Any:
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _MODULES[name] = module
    return _MODULES[name]


def guest_judge_module() -> Any:
    return load_module(GUEST_JUDGE, "p05_guest_judge_for_runner")


RECEIPT_CHECKS = ("json", "schema", "revision", "hash", "seed", "elf", "kernel", "qemu", "result", "gates", "scope")


class Judged(NamedTuple):
    failed: Dict[str, Any]                # gate id -> Gate, for the gates that failed (the ELF gate only when the ELF was supplied)
    problem: Optional[str]                # something wrong with --guest-elf itself
    gate_ids: List[str]                   # the gates this verdict covers
    receipt_gates: List[Dict[str, Any]]   # what the receipt of a passing run records for every gate (the ELF entry is the judge's own for a MIPS ELF)
    elf_file: Optional[Tuple[str, int]]   # (sha256, size) of --guest-elf when it was supplied and accepted


def guest_case(c) -> Dict[str, Any]:
    """The P05-EXT-GUEST case. The plant case names it in `of`, so the evidence directory and every pin live in one place."""
    if c["kind"] == "guest_receipt":
        return c
    return next(x for x in load_json(CASES_FILE)["cases"] if x["id"] == c["of"])


def guest_folder(c, root: Optional[str]) -> str:
    return os.path.join(root or REPO, guest_case(c)["dir"])


def guest_evidence(c, root: Optional[str] = None) -> Tuple[Optional[str], Optional[int], List[str]]:
    """The committed serial log and seed, and what is wrong with the set. `(None, None, [])` when the log is absent."""
    folder = guest_folder(c, root)
    log_path = os.path.join(folder, GUEST_LOG)
    if not os.path.isfile(log_path):
        return None, None, []
    problems: List[str] = []
    seed: Optional[int] = None
    seed_path = os.path.join(folder, GUEST_SEED)
    if not os.path.isfile(seed_path):
        problems.append(f"{GUEST_SEED} is missing: a log without its seed cannot be re-judged")
    else:
        try:
            seed = int(read(seed_path).strip())
        except ValueError:
            problems.append(f"{GUEST_SEED} is not a number")
    for name in (GUEST_LOG, GUEST_SEED, GUEST_RECEIPT, GUEST_CONSOLE):
        file_path = os.path.join(folder, name)
        if os.path.isfile(file_path):
            for rx, what in FORBIDDEN_IN_EVIDENCE:
                hit = rx.search(read(file_path))
                if hit:
                    problems.append(f"{name}: {what} {hit.group(0)!r}")
    return read(log_path), seed, problems


def receipt_problems(pins, receipt_text: str, log_sha: str, seed: int, judged: Judged) -> List[Tuple[str, str]]:
    """(check, message) for everything in the receipt that disagrees with what the runner re-derived or with the case's pins.
    The receipt is NEVER what passes the case: it only adds failures. What it can be held to is the log's hash, the seed, the
    pinned ELF, kernel, QEMU and revision, the judge's own schema and no-claim text, and the verdict of every gate, which is
    compared with the re-judged gates (the ELF gate with the judge's entry for a MIPS ELF unless --guest-elf supplied the file).
    Not re-judgeable from the repository, so a changed byte there is not caught: the second half of the ELF's and the
    kernel's sha256 (only their 128-bit prefixes are pinned; with --guest-elf the whole ELF hash and size are compared),
    the ELF size without --guest-elf, and JSON whitespace."""
    try:
        receipt = json.loads(receipt_text)
    except ValueError:
        return [("json", f"{GUEST_RECEIPT} is not JSON")]
    if not isinstance(receipt, dict):
        return [("json", f"{GUEST_RECEIPT} is not a JSON object")]
    mod = guest_judge_module()
    elf = receipt.get("elf") if isinstance(receipt.get("elf"), dict) else {}
    elf_ok = str(elf.get("sha256")).startswith(pins["elf_sha256_prefix"]) and (
        judged.elf_file is None or (elf.get("sha256"), elf.get("bytes")) == judged.elf_file)
    checks = (
        ("schema", receipt.get("schema") == mod.SCHEMA, f"schema is {receipt.get('schema')!r}, the judge writes {mod.SCHEMA!r}"),
        ("revision", receipt.get("revision") == pins["revision"], f"revision is {receipt.get('revision')!r}, the case pins {pins['revision']!r}"),
        ("hash", receipt.get("transcript_sha256") == log_sha, "records a transcript hash that is not this log's"),
        ("seed", receipt.get("seed") == seed, f"records seed {receipt.get('seed')}, {GUEST_SEED} says {seed}"),
        ("elf", elf_ok, f"records an ELF other than the pinned one (sha256 prefix {pins['elf_sha256_prefix'][:16]}...; with --guest-elf, the file's own hash and size)"),
        ("kernel", str(receipt.get("kernel_sha256")).startswith(pins["kernel_sha256_prefix"]),
         f"records a kernel other than the pinned one (sha256 prefix {pins['kernel_sha256_prefix'][:16]}...)"),
        ("qemu", receipt.get("qemu") == pins["qemu"], f"records QEMU {receipt.get('qemu')!r}, the case pins {pins['qemu']!r}"),
        ("result", receipt.get("result") == "passed", f"result is {receipt.get('result')!r}"),
        ("gates", receipt.get("gates") == judged.receipt_gates, "records gate verdicts that are not the re-judged ones"),
        ("scope", receipt.get("scope") == mod.HONEST_FOOTER, "its no-claim text is not the judge's"),
    )
    return [(name, f"{GUEST_RECEIPT}: {what}") for name, ok, what in checks if not ok]


def record_problems(c, seed: int, judged: Judged, root: Optional[str]) -> List[str]:
    """The committed receipt's disagreements with the re-judged log; nothing when there is no receipt (it never passes a case)."""
    folder = guest_folder(c, root)
    receipt_path = os.path.join(folder, GUEST_RECEIPT)
    if not os.path.isfile(receipt_path):
        return []
    found = receipt_problems(guest_case(c), read(receipt_path), sha256_file(os.path.join(folder, GUEST_LOG)), seed, judged)
    return [message for _, message in found]


def guest_judge(c, text: str, seed: int) -> Judged:
    """Re-judge `text` with the judge. The ELF header gate can only be judged with the ELF, which is not in the repository (only a
    128-bit prefix of its sha256 is pinned): without --guest-elf it is left out of the verdict and the case says so; with it,
    the file must be the pinned one and the header must be 32-bit big-endian MIPS."""
    pins = guest_case(c)
    mod = guest_judge_module()
    elf, elf_file = None, None
    if OPTIONS["guest_elf"]:
        try:
            data = open(OPTIONS["guest_elf"], "rb").read()
        except OSError as e:
            return Judged({}, f"cannot read --guest-elf: {e}", [], [], None)
        digest = hashlib.sha256(data).hexdigest()
        if not digest.startswith(pins["elf_sha256_prefix"]):
            return Judged({}, f"--guest-elf has sha256 {digest[:16]}..., the case pins {pins['elf_sha256_prefix'][:16]}...", [], [], None)
        try:
            elf = mod.read_elf(pathlib.Path(OPTIONS["guest_elf"]))
        except mod.MeasurementError as e:
            return Judged({}, str(e), [], [], None)
        elf_file = (digest, len(data))
    report = mod.judge(text, elf, seed, pathlib.Path(REPO))
    failed = {g.gate_id: g for g in report["gates"] if g.status == "failed"}
    gate_ids = [g.gate_id for g in report["gates"]]
    receipt_gates = [vars(g) for g in report["gates"]]
    if elf is None:
        failed.pop(ELF_GATE, None)
        if ELF_GATE in gate_ids:   # a transcript that does not parse is judged by one gate alone
            gate_ids.remove(ELF_GATE)
            receipt_gates = [vars(mod.gate_elf({"machine": 8})) if g["gate_id"] == ELF_GATE else g for g in receipt_gates]
    return Judged(failed, None, gate_ids, receipt_gates, elf_file)


def run_guest_receipt(c, root: Optional[str] = None) -> Result:
    text, seed, problems = guest_evidence(c, root)
    if text is None:
        return BLOCKED, f"{c['blocker']} (owner: {c['owner']}): {c['needs']}"
    judged_gates = 0
    if seed is not None:
        judged = guest_judge(c, text, seed)
        judged_gates = len(judged.gate_ids)
        problems += [judged.problem] if judged.problem else []
        problems += [f"{gid}: {g.detail or g.title}" for gid, g in sorted(judged.failed.items())]
        problems += record_problems(c, seed, judged, root)
    if problems:
        return FAIL, "; ".join(problems)
    elf_note = "the ELF header was re-judged" if OPTIONS["guest_elf"] else \
        f"the ELF header is not re-judged (the ELF is not in the repository; pinned sha256 prefix {c['elf_sha256_prefix'][:16]}..., pass --guest-elf to check it)"
    receipt_note = "receipt.json agrees with it and decided nothing" if os.path.isfile(os.path.join(guest_folder(c, root), GUEST_RECEIPT)) \
        else "there is no receipt.json to cross-check"
    return PASS, f"re-judged from the committed log with seed {seed}: {judged_gates} gate(s) passed; {receipt_note}; {elf_note}"


def apply_plant(text: str, plant: Dict[str, str]) -> str:
    """Change exactly ONE byte: the character in the pattern's single capture group becomes `0` (or `1` if it was `0`)."""
    hits = list(re.finditer(plant["pattern"], text))
    if len(hits) != 1:
        raise ValueError(f"plant {plant['name']}: its pattern matches {len(hits)} place(s), not one")
    start, end = hits[0].span(1)
    if end - start != 1:
        raise ValueError(f"plant {plant['name']}: its capture group is not a single character")
    new = "0" if text[start] != "0" else "1"
    planted = text[:start] + new + text[end:]
    if len(planted) != len(text) or sum(1 for a, b in zip(text, planted) if a != b) != 1:
        raise ValueError(f"plant {plant['name']}: it did not change exactly one byte")
    return planted


def plant_outcome(what: str, name: str, got: Set[str], want: str) -> Optional[str]:
    """A plant is credited only when it trips EXACTLY the one gate or check meant to refuse it."""
    if got != {want}:
        return f"{what} plant {name} tripped {sorted(got) or 'nothing'}, wanted exactly [{want!r}]"
    return None


def run_guest_plant(c, root: Optional[str] = None) -> Result:
    pins = guest_case(c)
    text, seed, problems = guest_evidence(c, root)
    if text is None:
        return BLOCKED, "no committed guest log: there is nothing to plant a negative in (see P05-EXT-GUEST)"
    if problems or seed is None:
        return FAIL, "; ".join(problems or ["no seed"])
    base = guest_judge(c, text, seed)
    if base.problem or base.failed:
        return FAIL, "the unplanted log does not pass, so no catch can be credited: " + \
            "; ".join(([base.problem] if base.problem else []) + sorted(base.failed))
    uncovered = sorted(set(base.gate_ids) - {ELF_GATE} - {plant["gate"] for plant in c["plants"]})
    if uncovered:
        return FAIL, f"no one-byte plant for gate(s) {uncovered}: a gate that was never shown to refuse proves nothing"
    for plant in c["plants"]:
        try:
            planted = apply_plant(text, plant)
        except ValueError as e:
            return FAIL, str(e)
        bad = plant_outcome("log", plant["name"], set(guest_judge(c, planted, seed).failed), plant["gate"])
        if bad:
            return FAIL, bad
    # the receipt: the same discipline, one changed byte per check, against an unplanted receipt that passes
    folder = guest_folder(c, root)
    receipt_path = os.path.join(folder, GUEST_RECEIPT)
    if not os.path.isfile(receipt_path):
        return FAIL, f"{GUEST_RECEIPT} is missing, so its plants cannot run (the case passes without a receipt; this one credits only what it exercised)"
    receipt, log_sha = read(receipt_path), sha256_file(os.path.join(folder, GUEST_LOG))
    unplanted = receipt_problems(pins, receipt, log_sha, seed, base)
    if unplanted:
        return FAIL, "the unplanted receipt does not pass, so no catch can be credited: " + "; ".join(m for _, m in unplanted)
    uncovered_checks = sorted(set(RECEIPT_CHECKS) - {plant["check"] for plant in c["receipt_plants"]})
    if uncovered_checks:
        return FAIL, f"no one-byte receipt plant for check(s) {uncovered_checks}: a check that was never shown to refuse proves nothing"
    for plant in c["receipt_plants"]:
        try:
            planted = apply_plant(receipt, plant)
        except ValueError as e:
            return FAIL, str(e)
        got = {check for check, _ in receipt_problems(pins, planted, log_sha, seed, base)}
        bad = plant_outcome("receipt", plant["name"], got, plant["check"])
        if bad:
            return FAIL, bad
    return PASS, (f"{len(c['plants'])} one-byte plants in the log, each caught by exactly its own gate, and {len(c['receipt_plants'])} in the receipt, "
                  "each caught by exactly its own check; the unplanted log and receipt are the controls and pass")


def guest_selftest() -> Optional[str]:
    """The wiring is not vacuous. It runs on a SYNTHETIC evidence directory, so it works with no committed evidence, and with
    --guest-elf cleared: that option belongs to the real evidence, not to this fixture."""
    saved = OPTIONS["guest_elf"]
    OPTIONS["guest_elf"] = None
    try:
        return guest_selftest_body()
    finally:
        OPTIONS["guest_elf"] = saved


def guest_selftest_body() -> Optional[str]:
    doc = load_json(CASES_FILE)
    case = next(x for x in doc["cases"] if x["kind"] == "guest_receipt")
    plant_case = next(x for x in doc["cases"] if x["kind"] == "guest_plant")
    mod = guest_judge_module()
    seed_n = 987654321
    try:
        text = load_module(GUEST_TESTS, "p05_guest_tests_for_runner").baseline_text(seed_n)
    except Exception as e:  # noqa: BLE001
        return f"cannot build a synthetic transcript from the judge's tests: {e}"
    elf_sha = case["elf_sha256_prefix"] + "0" * 32

    def receipt_json(log_text, **changes) -> str:
        """A receipt exactly as the judge writes one for a GOOD run, with the hash of `log_text` and any field changed."""
        report = mod.judge(text, {"machine": 8, "sha256": elf_sha, "bytes": 1234}, seed_n, pathlib.Path(REPO))
        meta = {"kernel_sha256": case["kernel_sha256_prefix"] + "0" * 32, "qemu": case["qemu"]}
        with tempfile.TemporaryDirectory() as scratch_dir:
            path = pathlib.Path(scratch_dir) / "receipt.json"
            mod.write_receipt(path, report, {"sha256": elf_sha, "bytes": 1234}, meta, seed_n, case["revision"], log_text)
            body = json.loads(path.read_text(encoding="utf-8"))
        body.update(changes)
        return json.dumps(body, indent=1, sort_keys=True) + "\n"

    def lay(root, log=text, seed=f"{seed_n}\n", receipt="auto", console="the console output\n"):
        folder = os.path.join(root, case["dir"])
        os.makedirs(folder, exist_ok=True)
        if log is not None:
            open(os.path.join(folder, GUEST_LOG), "w", encoding="utf-8").write(log)
        if seed is not None:
            open(os.path.join(folder, GUEST_SEED), "w", encoding="utf-8").write(seed)
        if receipt == "auto":
            receipt = receipt_json(log or "")
        if receipt is not None:
            open(os.path.join(folder, GUEST_RECEIPT), "w", encoding="utf-8").write(receipt)
        open(os.path.join(folder, GUEST_CONSOLE), "w", encoding="utf-8").write(console)

    def status(root, c=case, runner=run_guest_receipt):
        return runner(c, root)[0]

    with tempfile.TemporaryDirectory() as scratch:
        def fresh(name):
            root = os.path.join(scratch, name)
            os.makedirs(root)
            return root

        # no log: BLOCKED, for both cases
        root = fresh("empty")
        if status(root) != BLOCKED or status(root, plant_case, run_guest_plant) != BLOCKED:
            return "an absent log did not leave the guest cases BLOCKED"
        # a good synthetic record passes both
        root = fresh("good")
        lay(root)
        if status(root) != PASS or status(root, plant_case, run_guest_plant) != PASS:
            return "a good synthetic guest record did not pass"
        # a log without its seed is a failure, not a block
        root = fresh("noseed")
        lay(root, seed=None)
        if status(root) != FAIL:
            return "a log without its seed did not fail"
        # a log the judge cannot use is a failure, not a crash: one with no markers, and one the parser rejects (a key twice in a line),
        # which the judge answers with a single gate
        for name, bad_log in (("no-markers", "this is not a transcript\n"), ("parser-rejects", "FFW_P05T_ALIVE a=1 a=2\n")):
            root = fresh("garbage-" + name)
            lay(root, log=bad_log)
            if status(root) != FAIL or status(root, plant_case, run_guest_plant) != FAIL:
                return f"a log that {name} did not fail both cases"
        # the receipt can never pass a bad log: a one-byte change with a receipt that records the NEW hash and says "passed"
        root = fresh("tampered")
        tampered = apply_plant(text, plant_case["plants"][0])
        lay(root, log=tampered)
        if status(root) != FAIL:
            return "a tampered log passed because its receipt said it passed"
        if status(root, plant_case, run_guest_plant) != FAIL:
            return "a plant was credited against a baseline that does not pass"
        # no receipt: the case still passes (a receipt only ever adds failures), but the receipt plants cannot run
        root = fresh("noreceipt")
        lay(root, receipt=None)
        if status(root) != PASS:
            return "a good log without a receipt did not pass"
        if status(root, plant_case, run_guest_plant) != FAIL:
            return "the plant case was credited with no receipt to plant in"
        # the receipt can only make a good log fail, one disagreement at a time: each change trips exactly its own check
        good_judged = guest_judge(case, text, seed_n)
        log_sha = hashlib.sha256(text.encode()).hexdigest()
        good = json.loads(receipt_json(text))
        if receipt_problems(case, receipt_json(text), log_sha, seed_n, good_judged):
            return "the unchanged synthetic receipt was refused"
        for name, changes in (("schema", {"schema": "ffw.p05.guest_receipt.v0"}), ("revision", {"revision": "0000000"}),
                              ("hash", {"transcript_sha256": "0" * 64}), ("seed", {"seed": 1}),
                              ("elf", {"elf": {"sha256": "1" * 64, "bytes": 1234}}),
                              ("kernel", {"kernel_sha256": "1" * 64}), ("qemu", {"qemu": "QEMU emulator version 0.0.1"}),
                              ("result", {"result": "not_passed"}), ("scope", {"scope": "everything works"}),
                              ("gates", {"gates": good["gates"][:-1]})):
            root = fresh("receipt-" + name)
            lay(root, receipt=receipt_json(text, **changes))
            if status(root) != FAIL:
                return f"a receipt with the wrong {name} did not fail the case"
            got = {check for check, _ in receipt_problems(case, receipt_json(text, **changes), log_sha, seed_n, good_judged)}
            if got != {name}:
                return f"a receipt with the wrong {name} tripped {sorted(got)}, wanted exactly ['{name}']"
        for name, body in (("not-json", "{not json"), ("a-list", "[]"), ("a-number", "42")):
            root = fresh("receipt-" + name)
            lay(root, receipt=body)
            if status(root) != FAIL:
                return f"a receipt that is {name} did not fail the case"
        # a gate the receipt calls passed that the judge now fails: the case fails on the judge, whatever the receipt says
        forged = copy.deepcopy(good)
        forged["gates"][4]["status"] = "failed"
        if {check for check, _ in receipt_problems(case, json.dumps(forged), log_sha, seed_n, good_judged)} != {"gates"}:
            return "a receipt gate verdict that disagrees with the judge was not refused"
        # site data in the committed evidence
        root = fresh("hygiene")
        lay(root, console="served from " + "10.1.2." + "3\n")
        if status(root) != FAIL:
            return "an IPv4 address in the committed evidence did not fail the case"
        # the plant machinery: a pattern that matches nothing, and a plant credited to the wrong gate or check
        try:
            apply_plant(text, {"name": "none", "pattern": "NO_SUCH_LINE(x)"})
            return "a plant whose pattern matches nothing was accepted"
        except ValueError:
            pass
        root = fresh("wronggate")
        lay(root)
        wrong = copy.deepcopy(plant_case)
        wrong["plants"].append(copy.deepcopy(wrong["plants"][0]))   # the real end_tag plant stays, so every gate is still covered
        wrong["plants"][0]["gate"] = "P05T-VECTORS"                  # ...and this copy is credited to the wrong gate
        if status(root, wrong, run_guest_plant) != FAIL:
            return "a plant credited to the wrong gate was accepted"
        wrong = copy.deepcopy(plant_case)
        wrong["receipt_plants"].append(copy.deepcopy(wrong["receipt_plants"][0]))
        wrong["receipt_plants"][0]["check"] = "scope"
        if status(root, wrong, run_guest_plant) != FAIL:
            return "a receipt plant credited to the wrong check was accepted"
        # every judged gate and every receipt check needs a plant: a case file with one removed must fail
        thinned = copy.deepcopy(plant_case)
        thinned["plants"] = [x for x in thinned["plants"] if x["gate"] != "P05T-VECTORS"]
        if status(root, thinned, run_guest_plant) != FAIL:
            return "a plant case with a gate left uncovered was accepted"
        thinned = copy.deepcopy(plant_case)
        thinned["receipt_plants"] = [x for x in thinned["receipt_plants"] if x["check"] != "kernel"]
        if status(root, thinned, run_guest_plant) != FAIL:
            return "a plant case with a receipt check left uncovered was accepted"
        # a red unplanted receipt credits nothing
        root = fresh("redreceipt")
        lay(root, receipt=receipt_json(text, result="not_passed"))
        if status(root, plant_case, run_guest_plant) != FAIL:
            return "receipt plants were credited against a receipt that does not pass"
        # a plant must trip EXACTLY its own gate: this one-byte change breaks the SEED line's tag, which trips the transcript gate too
        root = fresh("extra")
        lay(root)
        extra = copy.deepcopy(plant_case)
        extra["plants"].append({"name": "extra", "gate": "P05T-SEED", "pattern": r"FFW_P05T_SEE(D) value="})
        if status(root, extra, run_guest_plant) != FAIL:
            return "a plant that trips a second gate was credited"
        # a plant changes ONE byte and is found ONCE
        for name, pattern in (("two-character capture", r"FFW_P05T_(EN)D"), ("pattern found twice", r"kind=(s)plit")):
            try:
                apply_plant(text, {"name": name, "pattern": pattern})
                return f"a plant with a {name} was accepted"
            except ValueError:
                pass
        # --guest-elf: the pinned file is re-judged, another file is refused, a non-MIPS file is refused, and the receipt's whole ELF hash
        # and size are compared with the file
        with tempfile.TemporaryDirectory() as elf_dir:
            def fake_elf(machine, tweak=0):
                header = (b"\x7fELF" + bytes([1, 2, 1]) + bytes(9) + (2).to_bytes(2, "big") + machine.to_bytes(2, "big")
                          + bytes([tweak]) + bytes(35))
                file_path = os.path.join(elf_dir, f"elf{machine}-{tweak}")
                with open(file_path, "wb") as f:
                    f.write(header)
                return file_path, hashlib.sha256(header).hexdigest(), len(header)

            mips, mips_hash, mips_size = fake_elf(8)
            other_mips, _, _ = fake_elf(8, 1)        # also big-endian MIPS, different bytes: only the hash can refuse it
            nonmips, nonmips_hash, _ = fake_elf(20)
            root = fresh("elf")
            lay(root, receipt=None)
            pinned = copy.deepcopy(case)
            saved = OPTIONS["guest_elf"]
            try:
                pinned["elf_sha256_prefix"] = mips_hash[:32]
                OPTIONS["guest_elf"] = mips
                if run_guest_receipt(pinned, root)[0] != PASS:
                    return "the pinned ELF was not accepted by --guest-elf"
                OPTIONS["guest_elf"] = other_mips
                if run_guest_receipt(pinned, root)[0] != FAIL:
                    return "an ELF other than the pinned one was accepted"
                OPTIONS["guest_elf"] = nonmips
                pinned["elf_sha256_prefix"] = nonmips_hash[:32]
                if run_guest_receipt(pinned, root)[0] != FAIL:
                    return "a non-MIPS ELF was accepted"
                # the receipt's ELF entry against the real file: right, wrong size, and a hash that differs only after the pinned prefix
                pinned["elf_sha256_prefix"] = mips_hash[:32]
                OPTIONS["guest_elf"] = mips
                for label, elf_entry, want in (("matching", {"sha256": mips_hash, "bytes": mips_size}, PASS),
                                               ("wrong-size", {"sha256": mips_hash, "bytes": mips_size + 1}, FAIL),
                                               ("tail-differs", {"sha256": mips_hash[:32] + "f" * 32, "bytes": mips_size}, FAIL)):
                    root = fresh("elf-receipt-" + label)
                    lay(root, receipt=receipt_json(text, elf=elf_entry))
                    if run_guest_receipt(pinned, root)[0] != want:
                        return f"with --guest-elf, a receipt with a {label} ELF entry was not {want}"
                # and without the file only the prefix can be held, which the report says
                OPTIONS["guest_elf"] = None
                root = fresh("elf-receipt-nofile")
                lay(root, receipt=receipt_json(text, elf={"sha256": mips_hash[:32] + "f" * 32, "bytes": mips_size}))
                if run_guest_receipt(pinned, root)[0] != PASS:
                    return "without --guest-elf the receipt's ELF hash was held to more than the pinned prefix"
            finally:
                OPTIONS["guest_elf"] = saved
    return None


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
    # the guest receipt wiring, on a synthetic evidence directory
    problem = guest_selftest()
    if problem:
        return FAIL, problem
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
    "gate_facts": run_gate_facts, "guest_receipt": run_guest_receipt, "guest_plant": run_guest_plant,
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
    ap.add_argument("--guest-elf", metavar="FILE", help="the guest ELF, to re-judge its header (a prefix of its sha256 is pinned in the case)")
    args = ap.parse_args(argv)
    OPTIONS["central_log"], OPTIONS["upstream_clone"] = args.central_log, args.upstream_clone
    OPTIONS["guest_elf"] = args.guest_elf
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
