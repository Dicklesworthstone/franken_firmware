#!/usr/bin/env python3
"""D01 (ffw-f3b) end-to-end runner and judge.

    run_cases.py [--tier smoke|full] [--list] [--write-vectors] [--judge LOG [LOG ...]]
                 [--receipts DIR]

What it does, offline and with the standard library only (it builds and boots nothing):

* META  - the hand-computed anchors hold in the Python reference; the committed
          ``vectors.json`` equals a fresh generation (a stale or hand-edited file fails); every
          invariant is covered by a vector or by a named Rust test.
* JUDGE - reads the ``cargo test`` output of the centrally run Rust suites (``--judge LOG``),
          compares every ``D01-OBSERVED`` line with the expected bytes from the independent
          reference, and checks every required Rust test reported ``ok``. On a mismatch it reports
          the first divergent frame, channel and format.

A case with no Rust observation is ``blocked``: counted, named, and the run is NOT QUALIFIED. It is
never passed and never dropped. The Rust suites run only through the centralized RCH path, e.g.

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-alloc-probe

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(HERE, "vectors.json")
TIERS = ("smoke", "full")
RECEIPT_SCHEMA = "ffw.d01.receipt.v1"
MAX_PRINTED = 12

# (path, binary stem, module prefix in cargo's test names)
RUST_SOURCES = [
    ("crates/franken-dsp/src/format.rs", "franken_dsp", "format::tests::"),
    ("crates/franken-dsp/src/convert.rs", "franken_dsp", "convert::tests::"),
    ("crates/franken-dsp/src/convert/soft_float_tests.rs", "franken_dsp", "convert::soft_float_tests::"),
    ("crates/franken-dsp/src/render_events/tests.rs", "franken_dsp", "render_events::tests::"),
    ("crates/franken-dsp/src/ring.rs", "franken_dsp", "ring::tests::"),
    ("crates/franken-dsp/src/lib.rs", "franken_dsp", "tests::"),
    ("crates/franken-dsp/tests/d01_vectors.rs", "d01_vectors", ""),
    ("crates/franken-alloc-probe/tests/render_path_no_alloc.rs", "render_path_no_alloc", ""),
    ("crates/franken-alloc-probe/tests/render_events_no_alloc.rs", "render_events_no_alloc", ""),
]
HARNESS_TEST = ("d01_vectors", "d01_vectors_match_the_independent_reference")
# cargo package -> test binaries whose `Running ... (target/.../<stem>-<hash>)` lines it may produce
PACKAGE_BINARIES = {
    "franken-dsp": ("franken_dsp", "d01_vectors"),
    "franken-alloc-probe": ("render_path_no_alloc", "render_events_no_alloc"),
}
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+([A-Za-z0-9_]+)")
OBSERVED = re.compile(r"D01-OBSERVED (\{.*\})\s*$")
TEST_LINE = re.compile(r"\btest (\S+) \.\.\. (ok|FAILED|ignored)\b")
# `Running unittests src/lib.rs (<any path>/<stem>-<hash>)`: the stem is the last path component.
RUNNING = re.compile(r"^\s*Running .*?\((?:[^()]*/)?([A-Za-z0-9_]+)-[0-9a-f]{6,}\)\s*$")
DOC_TESTS = re.compile(r"^\s*Doc-tests\s+(\S+)\s*$")
SECTION_START = re.compile(r"^running (\d+) tests?\s*$")
SECTION_RESULT = re.compile(r"^test result: (?:ok|FAILED)\.")


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d01_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
gen = _load("generate")
anchors = _load("anchors")


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


# ---- Rust tests derived from the sources -----------------------------------------------------


def derive_rust_tests(repo: str = REPO) -> List[Tuple[str, str]]:
    """(binary stem, cargo test name) for every ``#[test]`` in the D01 Rust sources."""
    required: List[Tuple[str, str]] = []
    for rel, stem, prefix in RUST_SOURCES:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for attrs, name in TEST_FN.findall(text):
            if "ignore" in attrs:
                continue  # an ignored test is not required (and would show as not-run if listed)
            required.append((stem, prefix + name))
    return required


# ---- log parsing ----------------------------------------------------------------------------


class Logs:
    """Parsed cargo-test output.

    Attribution of a test to its binary cannot rely on the nearest preceding ``Running`` header:
    through RCH the header lines (stderr) and the test sections (stdout) arrive as separate
    streams, so a header block can precede all of the tests and stray headers can land in the
    middle of a section. Both streams keep cargo's execution order, so the n-th header belongs to
    the n-th ``running N tests`` ... ``test result:`` section. That pairing is used only when the
    counts match and every section holds exactly the tests it declared; otherwise tests are
    matched by exact name, and a name seen in more than one section is ambiguous (stays blocked).

    Repeated inputs never change the denominator: a log with the same sha256 is read once, an
    identical repeated observation is ignored, and a *conflicting* one is reported on its own
    case, not as an extra case.
    """

    def __init__(self) -> None:
        self.observed: Dict[str, dict] = {}
        self.conflicting_observations: set = set()
        self.identical_repeats = 0
        self.repeated_inputs: List[str] = []
        self.tests: Dict[Tuple[Optional[str], str], str] = {}
        self.conflicting_tests: set = set()
        self.ambiguous_names: set = set()
        self.unattributed_logs: List[str] = []
        self.files: List[Tuple[str, str]] = []
        self._digests: set = set()

    def _record_observation(self, text: str) -> None:
        try:
            record = json.loads(text)
        except ValueError:
            return
        case_id = record.get("id")
        if case_id not in self.observed:
            self.observed[case_id] = record
        elif self.observed[case_id] == record:
            self.identical_repeats += 1
        else:
            self.conflicting_observations.add(case_id)

    def _record_test(self, stem: Optional[str], name: str, status: str) -> None:
        key = (stem, name)
        if key not in self.tests:
            self.tests[key] = status
        elif self.tests[key] != status:
            self.conflicting_tests.add(key)

    def add(self, path: str) -> None:
        digest = sha256_file(path)
        if digest in self._digests:
            self.repeated_inputs.append(os.path.basename(path))
            return
        self._digests.add(digest)
        self.files.append((path, digest))

        headers: List[str] = []
        sections: List[dict] = []
        orphans: List[Tuple[str, str]] = []
        current: Optional[dict] = None
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                running = RUNNING.match(line)
                if running:
                    headers.append(running.group(1))
                    continue
                doc = DOC_TESTS.match(line)
                if doc:
                    headers.append("doc:" + doc.group(1))
                    continue
                start = SECTION_START.match(line)
                if start:
                    current = {"declared": int(start.group(1)), "tests": []}
                    sections.append(current)
                    continue
                observed = OBSERVED.search(line)
                if observed:
                    self._record_observation(observed.group(1))
                    continue
                test = TEST_LINE.search(line)
                if test:
                    (current["tests"] if current is not None else orphans).append((test.group(1), test.group(2)))
                    continue
                if SECTION_RESULT.match(line):
                    current = None

        consistent = not orphans and all(len(s["tests"]) == s["declared"] for s in sections)
        if headers and len(headers) == len(sections) and consistent:
            for stem, section in zip(headers, sections):
                for name, status in section["tests"]:
                    self._record_test(stem, name, status)
            return
        # Attribution unavailable: keep exact names, flag names that appear more than once.
        self.unattributed_logs.append(
            f"{os.path.basename(path)}: {len(headers)} header(s), {len(sections)} section(s), "
            f"{len(orphans)} orphan test line(s)")
        seen: Dict[str, int] = {}
        for name, _ in orphans + [t for s in sections for t in s["tests"]]:
            seen[name] = seen.get(name, 0) + 1
        self.ambiguous_names.update(n for n, count in seen.items() if count > 1)
        for name, status in orphans + [t for s in sections for t in s["tests"]]:
            self._record_test(None, name, status)

    def test_status(self, stem: str, name: str) -> Optional[str]:
        """``ok`` / ``FAILED`` / ``ignored``; ``CONFLICT`` or ``AMBIGUOUS`` when the logs disagree
        or cannot say which binary ran it; ``None`` when no log reports the test."""
        for key in ((stem, name), (None, name)):
            if key in self.conflicting_tests:
                return "CONFLICT"
            if key in self.tests:
                if key[0] is None and name in self.ambiguous_names:
                    return "AMBIGUOUS"
                return self.tests[key]
        return None


# ---- judging ---------------------------------------------------------------------------------


def _describe_sample(spec: Any, raw: bytes) -> str:
    kind, value = ref.decode(raw, spec.fmt, spec.endian)
    return f"{raw.hex()} ({value!r})"


def byte_divergence(spec_dict: dict, frames: int, observed: bytes, expected: bytes, label: str) -> Optional[str]:
    """First divergent frame/channel/format between two byte strings, or None when equal."""
    if len(observed) != len(expected):
        return f"{label}: length differs, expected {len(expected)} bytes, observed {len(observed)}"
    offset = next((i for i, (a, b) in enumerate(zip(observed, expected)) if a != b), None)
    if offset is None:
        return None
    spec = ref.Spec.from_dict(spec_dict)
    place = ref.locate(spec, frames, offset)
    fmt = f"{spec.fmt} {spec.endian}"
    if place is None:
        return (f"{label}: first divergent byte {offset} is padding or guard in {fmt}: "
                f"expected {expected[offset]:02x}, observed {observed[offset]:02x}")
    frame, channel = place
    start = spec.offset(frame, channel)
    want = expected[start:start + spec.bps]
    got = observed[start:start + spec.bps]
    return (f"{label}: first divergence at frame {frame} channel {channel} ({fmt}): "
            f"expected {_describe_sample(spec, want)}, observed {_describe_sample(spec, got)}")


def _stats_problem(case: dict, obs: dict) -> Optional[str]:
    want = case["expected"]
    if obs.get("saturated") != want["saturated"] or obs.get("non_finite") != want["non_finite"]:
        return (f"stats differ: expected saturated={want['saturated']} non_finite={want['non_finite']}, "
                f"observed saturated={obs.get('saturated')} non_finite={obs.get('non_finite')}")
    return None


def _outcome_problem(case: dict, obs: dict) -> Optional[str]:
    expect = case["expect"]
    if "error" in expect:
        if obs.get("status") == "err" and obs.get("error") == expect["error"]:
            return None
        return f"expected error {expect['error']}, observed {obs.get('status')} {obs.get('error', '')}".strip()
    if obs.get("status") != "ok":
        return f"expected success, observed {obs.get('status')} {obs.get('error', '')}".strip()
    for key, value in expect.items():
        if key != "ok" and obs.get(key) != value:
            return f"expected {key}={value}, observed {obs.get(key)}"
    return None


def judge_case(case: dict, obs: dict) -> Optional[str]:
    """None when the Rust observation matches the reference, else the first divergence."""
    kind = case["kind"]
    if kind == "convert":
        if obs.get("status") != "ok":
            return f"unexpected error {obs.get('error')}"
        problem = byte_divergence(
            case["dst"], case["frames"], bytes.fromhex(obs["dst_hex"]), bytes.fromhex(case["dst_expected_hex"]),
            f"{case['src']['format']} {case['src']['endian']} -> {case['dst']['format']} {case['dst']['endian']}")
        return problem or _stats_problem(case, obs)
    if kind == "pipeline":
        if obs.get("status") != "ok":
            return f"unexpected error {obs.get('error')}"
        out_spec = ref.Spec.from_dict(case["out"])
        expected = bytes.fromhex(case["out_expected_hex"])
        problem = byte_divergence(case["out"], len(expected) // out_spec.bpf, bytes.fromhex(obs["out_hex"]),
                                  expected, f"pipeline {case['src']['format']} -> ring {case['ring']['format']} -> {case['out']['format']}")
        return problem or _stats_problem(case, obs)
    if kind == "ring":
        got, want = obs.get("results", []), case["expect"]
        for step, (g, w) in enumerate(zip(got, want)):
            if g != w:
                return f"ring step {step} {case['ops'][step][0]}: expected {w}, observed {g}"
        if len(got) != len(want):
            return f"ring: expected {len(want)} steps, observed {len(got)}"
        return None
    return _outcome_problem(case, obs)


# ---- the run -----------------------------------------------------------------------------------


def load_vectors() -> Tuple[Optional[dict], str]:
    try:
        with open(VECTORS, encoding="utf-8") as handle:
            text = handle.read()
        return json.loads(text), text
    except (OSError, ValueError):
        return None, ""


def smoke_ids(cases: List[dict]) -> List[str]:
    chosen: List[str] = []
    seen_kinds = set()
    for case in cases:
        if case["kind"] not in seen_kinds:
            seen_kinds.add(case["kind"])
            chosen.append(case["id"])
        if case["kind"] == "pipeline" and case["id"] not in chosen:
            chosen.append(case["id"])
    return chosen


def run(tier: str, logs: Optional[Logs]) -> Tuple[List[Result], dict]:
    results: List[Result] = []
    doc, text = load_vectors()
    fresh_doc = gen.build()
    fresh_text = gen.dumps(fresh_doc)

    # META
    problems = anchors.check()
    results.append(Result("D01-META-ANCHORS", "failed" if problems else "passed",
                          "; ".join(problems[:3]), "meta"))
    if doc is None:
        results.append(Result("D01-META-VECTORS-FRESH", "failed",
                              "tests/d01/vectors.json is missing or unreadable (run --write-vectors)", "meta"))
        doc = fresh_doc
    elif text != fresh_text:
        results.append(Result("D01-META-VECTORS-FRESH", "failed",
                              "vectors.json differs from a fresh generation (stale or edited by hand): "
                              "run --write-vectors and review the diff", "meta"))
    else:
        results.append(Result("D01-META-VECTORS-FRESH", "passed", "", "meta"))

    cases: List[dict] = doc["cases"]
    covered = {inv for case in cases for inv in case["invariants"]}
    declared = set(doc["invariants"])
    external = doc.get("external", {})
    uncovered = sorted(declared - covered - set(k for k, v in external.items() if v))
    unknown = sorted(covered - declared)
    results.append(Result("D01-META-INVARIANT-MAP", "failed" if uncovered or unknown else "passed",
                          f"uncovered={uncovered} unknown={unknown}" if uncovered or unknown else "", "meta"))

    required = derive_rust_tests()
    external_pairs: List[Tuple[str, str]] = []
    missing_named: List[str] = []
    for names in external.values():
        for entry in names:
            package, name = entry.split("::", 1)
            matches = [(stem, name) for stem in PACKAGE_BINARIES.get(package, ()) if (stem, name) in required]
            if matches:
                external_pairs.extend(matches)
            else:
                missing_named.append(entry)
    results.append(Result("D01-META-EXTERNAL-TESTS-EXIST", "failed" if missing_named else "passed",
                          f"named in the invariant map but not found in the Rust sources: {sorted(missing_named)}"
                          if missing_named else "", "meta"))

    selected = {c["id"] for c in cases} if tier == "full" else set(smoke_ids(cases))

    # Rust-backed vector cases
    for case in cases:
        if case["id"] not in selected:
            continue
        if logs is None or case["id"] not in logs.observed:
            results.append(Result(case["id"], "blocked", "no Rust observation (central cargo log not supplied "
                                  "or the case did not run)", "vector"))
            continue
        if case["id"] in logs.conflicting_observations:
            results.append(Result(case["id"], "failed", "the logs hold conflicting observations of this case", "vector"))
            continue
        problem = judge_case(case, logs.observed[case["id"]])
        results.append(Result(case["id"], "failed" if problem else "passed", problem or "", "vector"))

    # Rust tests that must have reported ok. Repeated inputs never add or remove entries here.
    needed = required if tier == "full" else [HARNESS_TEST] + external_pairs
    for stem, name in needed:
        case_id = f"RUST:{stem}::{name}"
        status = logs.test_status(stem, name) if logs is not None else None
        if status == "ok":
            results.append(Result(case_id, "passed", "", "rust"))
        elif status == "FAILED":
            results.append(Result(case_id, "failed", "cargo reported FAILED", "rust"))
        elif status == "CONFLICT":
            results.append(Result(case_id, "failed", "the logs report this test with conflicting statuses", "rust"))
        elif status == "AMBIGUOUS":
            results.append(Result(case_id, "blocked", "name appears in more than one test section and the log "
                                  "cannot attribute it to a binary", "rust"))
        elif status == "ignored":
            results.append(Result(case_id, "blocked", "reported ignored", "rust"))
        else:
            results.append(Result(case_id, "blocked", "not reported in the supplied logs", "rust"))

    meta = {"vectors_sha256": sha256_file(VECTORS) if os.path.isfile(VECTORS) else None,
            "planned_vectors": len(selected), "planned_rust_tests": len(needed)}
    return results, meta


def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "blocked")}


def exit_code(results: List[Result]) -> int:
    counts = summarize(results)
    if counts["failed"]:
        return 1
    if counts["blocked"]:
        return 3
    return 0


def report(results: List[Result], tier: str) -> None:
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:MAX_PRINTED]:
            print(f"{label:8s} {r.case_id}  {r.detail}")
        if len(rows) > MAX_PRINTED:
            print(f"{label:8s} ... and {len(rows) - MAX_PRINTED} more {status} case(s)")
    verdict = "QUALIFIED" if exit_code(results) == 0 else "NOT QUALIFIED"
    print(f"D01 e2e tier={tier}: {verdict}  planned={len(results)} passed={counts['passed']} "
          f"failed={counts['failed']} blocked={counts['blocked']}")


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs]) -> str:
    os.makedirs(directory, exist_ok=True)
    run_id = secrets.token_hex(8)
    path = os.path.join(directory, f"d01-{run_id}.json")
    doc = {
        "schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "counts": summarize(results), "exit_code": exit_code(results),
        "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
        "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
        "identical_repeated_observations": logs.identical_repeats if logs else 0,
        "unattributed_logs": list(logs.unattributed_logs) if logs else [],
        "replay": "scripts/e2e/d01 --tier " + tier + (" --judge <cargo-test-log>..." if logs else ""),
        **meta, "results": [r.as_dict() for r in results],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="D01 end-to-end runner and judge (ffw-f3b)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="list planned case ids and exit")
    parser.add_argument("--write-vectors", action="store_true", help="regenerate tests/d01/vectors.json")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="cargo test output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt here")
    args = parser.parse_args(argv)

    if args.write_vectors:
        with open(VECTORS, "w", encoding="utf-8") as handle:
            handle.write(gen.dumps(gen.build()))
        print(f"wrote {os.path.relpath(VECTORS, REPO)} ({sha256_file(VECTORS)[:16]}...)")
        return 0
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                print(f"error: log not found: {path}", file=sys.stderr)
                return 2
            logs.add(path)
    results, meta = run(args.tier, logs)
    if args.list:
        for r in results:
            print(r.case_id)
        return 0
    report(results, args.tier)
    if args.receipts:
        print("receipt:", write_receipt(args.receipts, args.tier, results, meta, logs))
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
