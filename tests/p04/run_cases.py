#!/usr/bin/env python3
"""P04 (ffw-0bh) host-side case runner.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]

What this runner is, so a pass is not over-read:
* It checks the wire-record vectors with an independent Python codec, proves the case set is not
  vacuous (a planted host-endian defect must be caught), and checks that every required invariant
  maps to Rust tests that EXIST in the source. It does not run those tests: there is no local cargo,
  and the behavior (ownership, quarantine, fail-muted, owner destruction) lives in
  crates/franken-hal and is verified only by the central `cargo test -p franken-hal`.
* So the behavioral half is the BLOCKED case P04-RUST-CENTRAL, counted and never passed, and the run
  is NOT QUALIFIED until that exists. A separate true-device ledger (P04-EXT-QUAL) is also blocked:
  the fake device is a model, and no real driver interface is admitted yet.
* Expected values are hand-written; the Python codec and the Rust codec share an author.

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage or a
malformed case file.
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

import abi_ref  # noqa: E402

CASES_FILE = os.path.join(HERE, "cases.json")
VECTORS_FILE = os.path.join(HERE, "abi_vectors.json")
DOC_FILE = os.path.join(REPO, "docs", "contracts", "p04.md")
RUST_DIR = os.path.join(REPO, "crates", "franken-hal", "src")
SCHEMA = "ffw.p04.cases.v1"
VECTORS_SCHEMA = "ffw.p04.abi_vectors.v1"
TIERS = ("smoke", "full")
KINDS = ("abi_vector", "planted_defect", "meta_files", "meta_shared_vectors", "meta_invariants",
         "meta_hygiene", "meta_no_unsafe", "runner_selftest", "blocked")
RUST_FILES = ("lib", "abi", "backend", "contract", "dma_sim", "session", "slots")
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


def rust_source(module: str) -> str:
    return read(os.path.join(RUST_DIR, f"{module}.rs"))


def rust_test_names(module: str) -> List[str]:
    """Names of the functions directly annotated #[test] in crates/franken-hal/src/<module>.rs."""
    return re.findall(r"#\[test\]\s*\n\s*fn\s+(\w+)\s*\(", rust_source(module))


def rust_test_total() -> int:
    return sum(len(rust_test_names(m)) for m in RUST_FILES)


# ----------------------------------------------------------------------------------------- vectors

def vectors() -> List[Dict[str, Any]]:
    doc = load_json(VECTORS_FILE)
    if doc.get("schema") != VECTORS_SCHEMA:
        raise CaseError(f"abi_vectors.json schema is {doc.get('schema')!r}, expected {VECTORS_SCHEMA!r}")
    return doc["vectors"]


def check_vector(v: Dict[str, Any], endian: str = "big") -> Result:
    data = bytes.fromhex(v["hex"])
    expect = v["expect"]
    decode = abi_ref.decode_event if v["codec"] == "event" else abi_ref.decode_geometry
    encode = abi_ref.encode_event if v["codec"] == "event" else abi_ref.encode_geometry
    try:
        got = decode(data, endian)
    except abi_ref.AbiError as e:
        return (PASS, "") if expect.get("error") == e.name else (FAIL, f"rejected as {e.name}, expected {expect}")
    if "error" in expect:
        return FAIL, f"decoded {got}, expected the error {expect['error']}"
    if got != expect:
        return FAIL, f"decoded {got}, expected {expect}"
    if encode(got, endian) != data:
        return FAIL, "re-encoding does not give the original bytes"
    return PASS, ""


def run_abi_vector(c) -> Result:
    return check_vector(c["vector"])


def run_planted_defect(c) -> Result:
    vs = vectors()
    baseline = [v["id"] for v in vs if check_vector(v)[0] != PASS]
    if baseline:
        return FAIL, f"baseline is not green, so no catch can be credited: {baseline}"
    caught = sorted(v["id"] for v in vs if check_vector(v, "little")[0] != PASS)
    missing = [i for i in c["caught_by"] if i not in caught]
    if missing:
        return FAIL, f"defect {c['defect']!r} was not caught by {missing}; caught by {caught}"
    return PASS, f"caught by {len(caught)} vector(s)"


# ------------------------------------------------------------------------------------------- meta

def run_meta_files(c) -> Result:
    needed = [CASES_FILE, VECTORS_FILE, DOC_FILE, os.path.join(HERE, "abi_ref.py"),
              os.path.join(REPO, "scripts", "e2e", "p04")]
    needed += [os.path.join(RUST_DIR, f"{m}.rs") for m in RUST_FILES]
    gone = [os.path.relpath(p, REPO) for p in needed if not os.path.isfile(p)]
    return (PASS, "") if not gone else (FAIL, f"missing: {gone}")


def run_meta_shared_vectors(c) -> Result:
    abi_rs = rust_source("abi")
    problems = []
    if 'include_str!("../../../tests/p04/abi_vectors.json")' not in abi_rs:
        problems.append("abi.rs does not include tests/p04/abi_vectors.json")
    m = re.search(r"vectors\.len\(\),\s*(\d+)", abi_rs)
    if not m or int(m.group(1)) != len(vectors()):
        problems.append(f"the Rust test expects {m.group(1) if m else 'no'} vectors, the file has {len(vectors())}")
    for module in ("session", "slots"):
        if not rust_test_names(module):
            problems.append(f"{module}.rs has no #[test] functions")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def expand(patterns: List[str], ids: List[str]) -> List[str]:
    out = []
    for p in patterns:
        if p.endswith("*"):
            out.extend(i for i in ids if i.startswith(p[:-1]))
        else:
            out.append(p)
    return out


def check_invariants(doc: Dict[str, Any], ids: List[str], tests: Dict[str, List[str]]) -> List[str]:
    problems, mapped = [], set()
    for inv in doc["invariants"]:
        if not inv["rust_tests"] and not inv["cases"]:
            problems.append(f"{inv['id']} maps to nothing")
        for name in inv["rust_tests"]:
            module, _, fn = name.partition("::")
            if fn not in tests.get(module, []):
                problems.append(f"{inv['id']}: no #[test] fn {fn} in {module}.rs")
        for ref in expand(inv["cases"], ids):
            if ref not in ids:
                problems.append(f"{inv['id']} names unknown case {ref}")
            mapped.add(ref)
    orphans = [i for i in ids if i not in mapped]
    if orphans:
        problems.append(f"cases covering no invariant: {orphans}")
    return problems


def all_test_names() -> Dict[str, List[str]]:
    return {m: rust_test_names(m) for m in RUST_FILES}


def run_meta_invariants(c) -> Result:
    doc = load_json(CASES_FILE)
    ids = [x["id"] for x in doc["cases"]] + [v["id"] for v in vectors()]
    problems = check_invariants(doc, ids, all_test_names())
    named = sum(len(i["rust_tests"]) for i in doc["invariants"])
    return (PASS, f"{len(doc['invariants'])} invariants, {named} named Rust tests") if not problems else (FAIL, "; ".join(problems))


HYGIENE_FILES = ("cases.json", "abi_vectors.json", "abi_ref.py", "run_cases.py")


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
    """The HAL crate stays #![forbid(unsafe_code)]; this slice adds no unsafe block, fn or impl."""
    problems = []
    if "#![forbid(unsafe_code)]" not in rust_source("lib"):
        problems.append("lib.rs no longer forbids unsafe_code")
    rx = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b|trait\b)")
    for m in RUST_FILES:
        for n, line in enumerate(rust_source(m).splitlines(), 1):
            if rx.search(line.split("//")[0]):
                problems.append(f"{m}.rs:{n}: {line.strip()}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def run_runner_selftest(c) -> Result:
    """The comparisons are not vacuous: corrupted vectors, a corrupted invariant map and a wrong
    byte order must each be seen."""
    vs = vectors()
    first = copy.deepcopy(next(v for v in vs if v["codec"] == "event" and "error" not in v["expect"]))
    if check_vector(first)[0] != PASS:
        return FAIL, "a baseline vector does not pass"
    first["hex"] = first["hex"][:-2] + "ff"
    if check_vector(first)[0] == PASS:
        return FAIL, "a corrupted vector was accepted"
    bad = copy.deepcopy(load_json(CASES_FILE))
    bad["invariants"][0]["rust_tests"].append("session::a_test_that_does_not_exist")
    ids = [x["id"] for x in bad["cases"]] + [v["id"] for v in vs]
    if not any("a_test_that_does_not_exist" in p for p in check_invariants(bad, ids, all_test_names())):
        return FAIL, "a missing Rust test name was not detected"
    orphan_doc = copy.deepcopy(load_json(CASES_FILE))
    orphan_doc["cases"].append({"id": "P04-ORPHAN", "kind": "meta_files", "tier": "smoke"})
    if not any("P04-ORPHAN" in p for p in check_invariants(orphan_doc, [x["id"] for x in orphan_doc["cases"]] + [v["id"] for v in vs], all_test_names())):
        return FAIL, "a case covering no invariant was not detected"
    return PASS, ""


def run_blocked(c) -> Result:
    extra = f" Expect {rust_test_total()} #[test] functions in crates/franken-hal." if c["id"] == "P04-RUST-CENTRAL" else ""
    return BLOCKED, f"{c['blocker']} (owner: {c['owner']}): {c['needs']}{extra}"


RUNNERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "abi_vector": run_abi_vector, "planted_defect": run_planted_defect, "meta_files": run_meta_files,
    "meta_shared_vectors": run_meta_shared_vectors, "meta_invariants": run_meta_invariants,
    "meta_hygiene": run_meta_hygiene, "meta_no_unsafe": run_meta_no_unsafe,
    "runner_selftest": run_runner_selftest, "blocked": run_blocked,
}


# --------------------------------------------------------------------------------------------- main

def all_cases() -> List[Dict[str, Any]]:
    doc = load_json(CASES_FILE)
    if doc.get("schema") != SCHEMA:
        raise CaseError(f"cases.json schema is {doc.get('schema')!r}, expected {SCHEMA!r}")
    cases = list(doc["cases"])
    for v in vectors():
        cases.append({"id": v["id"], "kind": "abi_vector", "tier": "smoke", "vector": v})
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
    ap = argparse.ArgumentParser(description="P04 host-side case runner")
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--case", metavar="ID")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--receipts", metavar="DIR")
    args = ap.parse_args(argv)
    try:
        chosen = select(all_cases(), args.tier, args.case)
        if args.list:
            for c in chosen:
                print(f"{c['id']:<18} {c['tier']:<6} {c['kind']}")
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
            print(f"{status.upper():<7} {c['id']:<18} {c['kind']}{'  ' + detail if detail else ''}")
    except CaseError as e:
        print(f"P04 runner: {e}", file=sys.stderr)
        return 2
    counts = {s: sum(1 for _, st, _ in results if st == s) for s in (PASS, FAIL, BLOCKED)}
    qualified = counts[FAIL] == 0 and counts[BLOCKED] == 0
    print(f"\nP04 {args.tier}: {len(results)} case(s): {counts[PASS]} passed, {counts[FAIL]} failed, "
          f"{counts[BLOCKED]} blocked -- {'QUALIFIED (host simulation only)' if qualified else 'NOT QUALIFIED'}")
    if counts[BLOCKED]:
        print("blocked cases are required invariants nothing here can verify; they are counted, not passed")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        receipt = {
            "schema": "ffw.p04.receipt.v1", "kind": "host_check_only_rust_not_run",
            "command": "tests/p04/run_cases.py " + " ".join(argv),
            "utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": sys.version.split()[0], "tier": args.tier, "denominator": len(results), "counts": counts,
            "qualified": qualified, "rust_test_functions_expected": rust_test_total(),
            "inputs": {os.path.relpath(p, REPO): sha256_file(p) for p in (CASES_FILE, VECTORS_FILE)},
            "cases": [{"id": c["id"], "status": st} for c, st, _ in results],
        }
        path = os.path.join(args.receipts, f"p04-{args.tier}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1)
            f.write("\n")
        print(f"receipt: {path}")
    if counts[FAIL]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
