#!/usr/bin/env python3
"""N01 end-to-end runner with explicit tiers and a bounded diagnostic receipt (bead ffw-ey5).

    run_cases.py [--tier smoke|full|soak] [--list] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds and boots nothing and never invokes cargo. The Rust runs only through the centralized RCH path:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --locked -p franken-stream -- --nocapture

Tiers (explicit; ``full`` is the default of ``scripts/e2e/n01``):

  smoke  the independent references regenerate the committed vectors and every expectation holds, and the clause map is whole. Seconds.
  full   smoke, the unit tests of the references and judges, the committed fuzz record, and one case per clause of the acceptance
         (golden vectors across endianness, oversize, duplicate/replay, stale epoch, unknown critical fields, mutation before any
         state change, capped untrusted work) plus negotiation, loopback and "every N01 test", each decided from the named Rust tests in the
         centrally run ``cargo test`` log given with ``--judge``. Without a log those cases are BLOCKED: counted, named, never passed.
  soak   selectable, says why nothing runs, exits 4. It is never a pass.

A test the log does not report (or reports ignored, or whose name was printed with no result) is BLOCKED: evidence is missing. A test
reported FAILED, or reported with two different results by the logs, is FAILED, and its first causal event is cargo's panic location and
message. Every decided case writes a CRITICAL begin and end event through the shared Q00 sink (``case_log.py``); a run whose log lost critical
evidence is NOT QUALIFIED. A run that is not a pass prints RETAINED FOR REPLAY: the first failure or block, the replay command, the versions and
the sha256 of every artifact and log judged. ``--receipts DIR`` also writes a JSON receipt next to the diagnostic log.

Exit codes: 0 every case passed and the diagnostic log is complete; 1 a case failed or the log lost critical evidence; 3 the only non-passes are
blocked cases; 4 ``--tier soak``; 2 usage.

What a pass is not. The Rust tests run on a little-endian host; this runner does not say that any big-endian machine executed anything (that
is an optional experiment, NOT RUN: docs/contracts/n01.md section 7). The committed fuzz record is held to itself and warns, without failing,
when the source has moved past the run it describes (section 11).
"""
from __future__ import annotations

import argparse
import datetime
import glob
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
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CRATE = os.path.join("crates", "franken-stream")
TIERS = ("smoke", "full", "soak")
RUN_TIERS = ("smoke", "full")
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "N01 soak: NOT RUN. The coverage-guided fuzz of the parsers (docs/contracts/n01.md section 11) ran as a 120 s smoke per target with a control that "
    "found its planted bug; a soak would be a long central fuzz campaign (hours per target), and the bead asks for no long-run claim. Nothing "
    "here soaks. This is not a pass.")
RECEIPT_SCHEMA = "ffw.n01.receipt.v1"
MAX_PRINTED = 12
UNIT_TIMEOUT_S = 600
REF_TIMEOUT_S = 180
JUDGED_ARTIFACTS = (
    "tests/n01/run_cases.py", "tests/n01/case_log.py", "tests/n01/reference_frames.py", "tests/n01/reference_negotiation.py",
    "tests/n01/fuzz_record.py", "scripts/test/test_support/diagnostics.py", "docs/contracts/n01.md", "Cargo.lock", "rust-toolchain.toml",
    "crates/franken-stream/Cargo.toml", "crates/franken-stream/src/lib.rs", "crates/franken-stream/src/negotiation.rs",
    "crates/franken-stream/tests/n01_loopback.rs", "crates/franken-stream/tests/n01_wire_replay.rs",
    "crates/franken-stream/tests/vectors/n01_wire_vectors.json", "crates/franken-stream/tests/vectors/n01_negotiation_vectors.json",
)

# The acceptance, clause by clause, each decided from named Rust tests (libtest names: `tests::x` is lib.rs, `negotiation::tests::x` is
# negotiation.rs, a bare name is an integration test). Every name must exist in the sources (N01-META-MAP). "N01-RUST-ALL" below is the floor:
# every test of N01's own files, so a clause map cannot silently leave one out.
CLAUSES: List[Tuple[str, str, List[str]]] = [
    ("N01-W-LAYOUT", "golden wire vectors across endianness: the documented big-endian layout, byte-exact decode and re-encode of every vector, the golden scenarios, the host replay",
     ["tests::header_is_the_documented_big_endian_layout", "tests::golden_vectors_from_the_independent_python_reference_match_byte_for_byte",
      "tests::golden_scenarios_replay_through_the_receiver_exactly_as_the_reference_model_predicts", "tests::authenticated_packet_roundtrip_and_tamper_rejection",
      "the_committed_vectors_replay_with_no_mismatch_and_the_shape_the_judge_requires",
      "every_accepted_vector_decodes_to_the_references_fields_and_re_encodes_to_the_same_bytes", "the_byte_order_probe_describes_the_machine_that_ran_it"]),
    ("N01-W-OVERSIZE", "reject oversize, truncated, extended and mis-versioned datagrams before any MAC work",
     ["tests::every_truncation_and_extension_is_rejected_without_panicking", "tests::length_version_and_magic_rejections_happen_before_any_mac_work",
      "the_planted_rejections_are_refused_and_the_permitted_positives_are_accepted"]),
    ("N01-W-REPLAY", "reject duplicate and replayed datagrams; admit reordering inside the window; a forged far-future sequence cannot fence out the sender",
     ["tests::replay_window_rejects_stale_epochs_and_duplicate_sequences", "tests::replay_window_edges_reorder_depth_and_the_future_bound",
      "tests::reorder_inside_the_window_is_admitted_and_duplicates_are_not", "tests::the_window_matches_a_set_based_model_on_a_long_random_walk",
      "tests::a_forged_far_future_sequence_cannot_fence_out_the_real_sender"]),
    ("N01-W-EPOCH", "reject stale epochs without modifying the current stream; media never adopts a newer epoch",
     ["tests::replay_window_first_packet_is_bounded_by_the_origin_and_never_adopts_epochs",
      "tests::stale_future_and_foreign_traffic_is_ignored_without_touching_the_stream"]),
    ("N01-W-BIND", "a restarted or rekeyed stream opens a new sequence space; binding the identity already held reopens nothing and never rewinds the epoch",
     ["tests::restart_and_rekey_make_the_previous_stream_inert", "tests::rebinding_the_current_stream_does_not_reopen_its_replay_window",
      "tests::binding_the_current_stream_to_another_epoch_is_only_an_epoch_announcement", "tests::sender_sequence_epoch_and_identity_rules"]),
    ("N01-W-CRITICAL", "reject unknown critical fields; the ignorable bits are authenticated and preserved; the encoder refuses what the decoder would reject",
     ["tests::field_validation_rejects_authenticated_but_unacceptable_headers", "tests::an_ignorable_flag_bit_is_authenticated_preserved_and_accepted",
      "tests::the_encoder_refuses_every_frame_the_decoder_would_reject"]),
    ("N01-W-MUTATION", "authentication covers epoch, format, stream and payload; a mutated datagram is rejected before scheduling and changes no state",
     ["tests::a_tampered_datagram_never_consumes_a_sequence_number", "tests::tampered_epoch_format_and_stream_fields_fail_authentication",
      "tests::seeded_random_packets_roundtrip_and_any_single_bit_flip_is_rejected",
      "tests::accepted_traffic_feeds_the_jitter_buffer_and_rejected_traffic_never_reaches_it", "tests::counters_account_for_every_datagram_exactly_once"]),
    ("N01-W-UNTRUSTED", "untrusted parsing work is capped: garbage never panics and never authenticates; no key or payload byte reaches a diagnostic",
     ["tests::arbitrary_garbage_never_panics_and_never_authenticates", "tests::keys_and_payloads_never_appear_in_diagnostics",
      "negotiation::tests::arbitrary_garbage_is_never_a_negotiation_message", "negotiation::tests::malformed_capability_claims_are_rejected"]),
    ("N01-W-LOOPBACK", "two real endpoints exchange boundary-size datagrams over loopback UDP",
     ["two_endpoints_exchange_boundary_datagrams_over_loopback"]),
]
NEGOTIATION_CASE = ("N01-W-NEGOTIATION", "mixed-firmware negotiation: every negotiation test of negotiation.rs")
ALL_CASE = ("N01-RUST-ALL", "every test of N01's own files reported ok (lib.rs, negotiation.rs, the replay and the loopback test)")

# ---- the Rust tests defined in N01's own files ---------------------------------------------------------------------------------------
MOD_OPEN = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*\{")
FN_NAME = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")
OWN_FILES = (("src/lib.rs", ""), ("src/negotiation.rs", "negotiation"), ("tests/n01_loopback.rs", None), ("tests/n01_wire_replay.rs", None))


def test_functions(text: str) -> List[Tuple[str, Tuple[str, ...]]]:
    """Every `#[test]` function of one source file with the inline `mod x { ... }` blocks it sits in (tracked by brace depth)."""
    found: List[Tuple[str, Tuple[str, ...]]] = []
    stack: List[Tuple[str, int]] = []
    depth, armed = 0, False
    for line in text.splitlines():
        stripped = line.strip()
        opened = MOD_OPEN.match(stripped)
        if stripped.startswith("#[test]"):
            armed, stripped = True, stripped[len("#[test]"):].strip()
        if armed:
            named = FN_NAME.match(stripped)
            if named:
                found.append((named.group(1), tuple(n for n, _ in stack)))
                armed = False
        if opened:
            stack.append((opened.group(1), depth))
        depth += line.count("{") - line.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()
    return found


def own_tests(repo: str = REPO) -> Dict[str, List[str]]:
    """libtest name -> [] grouped by file: {"lib": [...], "negotiation": [...], "loopback": [...], "replay": [...]}."""
    groups: Dict[str, List[str]] = {"lib": [], "negotiation": [], "loopback": [], "replay": []}
    for rel, prefix in OWN_FILES:
        path = os.path.join(repo, CRATE, rel)
        with open(path, encoding="utf-8") as handle:
            tests = test_functions(handle.read())
        key = {"src/lib.rs": "lib", "src/negotiation.rs": "negotiation", "tests/n01_loopback.rs": "loopback", "tests/n01_wire_replay.rs": "replay"}[rel]
        for name, inline in tests:
            parts = ([prefix] if prefix else []) + list(inline) + [name]
            groups[key].append("::".join(parts))
    return groups


# ---- the cargo log, read the way libtest writes it -----------------------------------------------------------------------------------
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TEST_START = re.compile(r"^test (\S+) \.\.\. ?(.*)$")
RESULT_WORD = re.compile(r"^(ok|FAILED|ignored)\b")
SUMMARY = re.compile(r"^test result: ")
PANIC = re.compile(r"thread '([^']+)'(?: \(\d+\))? panicked at (.*)$")
MAX_PANIC_LINES, MAX_PANIC_CHARS = 6, 240


class Logs:
    """The central ``cargo test -- --nocapture`` log(s). libtest writes ``test NAME ... `` and, when the test ends, its result word, from one
    thread while other tests print from theirs, so the word may sit alone on a later line: it belongs to the one open name. A name that never
    gets its word is ``unterminated`` and never a pass; two different results for one test are ``conflict``, in either log order."""

    def __init__(self) -> None:
        self.files: List[Tuple[str, str]] = []
        self.results: Dict[str, List[str]] = {}
        self.unterminated: List[str] = []
        self.summaries = 0
        self.panics: Dict[str, List[str]] = {}

    def add(self, path: str) -> None:
        with open(path, "rb") as handle:
            raw = handle.read()
        self.files.append((path, hashlib.sha256(raw).hexdigest()))
        self.add_text(raw.decode("utf-8", errors="replace"))

    def add_text(self, text: str) -> None:
        pending: Optional[str] = None
        panic: Optional[List[Any]] = None
        for raw in text.splitlines():
            line = ANSI.sub("", raw)
            started = TEST_START.match(line)
            if started:
                if pending is not None:
                    self.unterminated.append(pending)
                    pending = None
                name, rest = started.groups()
                word = RESULT_WORD.match(rest.strip())
                if word:
                    self.results.setdefault(name, []).append(word.group(1))
                else:
                    pending = name
            elif pending is not None and line.strip() in ("ok", "FAILED", "ignored"):
                self.results.setdefault(pending, []).append(line.strip())
                pending = None
            if SUMMARY.match(line):
                self.summaries += 1
            found = PANIC.search(line)
            if found:
                where = found.group(2).strip()
                panic = [found.group(1), MAX_PANIC_LINES]
                self.panics.setdefault(panic[0], [where[:MAX_PANIC_CHARS]] if where else [])
            elif panic is not None:
                body = line.strip()
                if panic[1] <= 0 or not body or body.startswith("note:") or TEST_START.match(line) or body in ("ok", "FAILED", "ignored"):
                    panic = None
                else:
                    self.panics[panic[0]].append(body[:MAX_PANIC_CHARS])
                    panic[1] -= 1
        if pending is not None:
            self.unterminated.append(pending)

    def status(self, name: str) -> Optional[str]:
        seen = self.results.get(name)
        if not seen:
            return None
        return seen[0] if len(set(seen)) == 1 else "conflict"


# ---- cases ---------------------------------------------------------------------------------------------------------------------------
class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, detail, group

    def as_dict(self) -> dict:
        return {"case": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


Runner = Callable[[List[str], str, int], Tuple[int, str]]


def run_process(argv: List[str], cwd: str, timeout: int) -> Tuple[int, str]:
    """(exit code, stdout+stderr), bounded in time; a timeout is exit 124 with a sentence, never a hang."""
    try:
        done = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout} s"
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def tail(text: str, limit: int = 400) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else "..." + text[-limit:]


def unit_modules() -> List[str]:
    """The Python test modules of tests/n01 except this runner's own (which would run the runner)."""
    return sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(HERE, "test_*.py")) if os.path.basename(p) != "test_run_cases.py")


def load_fuzz_record() -> Any:
    sys.path.insert(0, HERE)
    spec = importlib.util.spec_from_file_location("n01_fuzz_record_for_runner", os.path.join(HERE, "fuzz_record.py"))
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def judge_fuzz_record() -> Result:
    """The committed fuzz record, held to itself. A moved source is a WARNING in the detail of a passed case, never a failure (5175)."""
    try:
        fr = load_fuzz_record()
        records = fr.cited_records(REPO)
        if not records:
            return Result("N01-FUZZ-RECORD", "failed", "the contract cites no fuzz record under toolchain/results/n01", "fuzz")
        problems: List[str] = []
        warnings: List[str] = []
        for directory in records:
            record, crash = fr.load(directory)
            problems += ["%s: %s" % (directory.name, p) for p in fr.record_problems(record, crash, REPO, directory.name)]
            warnings += fr.staleness_warnings(record, REPO)
    except Exception as err:  # noqa: BLE001 - a record that cannot be read is a failed case, not a traceback
        return Result("N01-FUZZ-RECORD", "failed", "the fuzz record could not be read: %s: %s" % (type(err).__name__, str(err)[:160]), "fuzz")
    if problems:
        return Result("N01-FUZZ-RECORD", "failed", "; ".join(problems[:3]), "fuzz")
    note = ("WARNING: %d file(s) moved past the recorded run, so it no longer covers the current source; first: %s" % (len(warnings), warnings[0].split(" (")[0])
            if warnings else "")
    return Result("N01-FUZZ-RECORD", "passed", note, "fuzz")


def reference_case(case_id: str, script: str, runner: Runner) -> Result:
    code, out = runner([sys.executable, "-B", "-I", os.path.join(HERE, script), "--check"], HERE, REF_TIMEOUT_S)
    return Result(case_id, "passed" if code == 0 else "failed", "" if code == 0 else "%s --check exit %d: %s" % (script, code, tail(out)), "reference")


def unit_case(runner: Runner) -> Result:
    modules = unit_modules()
    code, out = runner([sys.executable, "-B", "-m", "unittest"] + modules, HERE, UNIT_TIMEOUT_S)
    ran = re.search(r"Ran (\d+) tests?", out)
    if code == 0 and ran:
        return Result("N01-REF-UNITTESTS", "passed", "", "reference")
    return Result("N01-REF-UNITTESTS", "failed", "unittest of %d module(s) exit %d%s: %s" % (len(modules), code, (", ran " + ran.group(1)) if ran else "", tail(out)), "reference")


def judge_names(case_id: str, group: str, names: List[str], logs: Optional[Logs]) -> Result:
    """FAILED or conflicting -> failed (with the first causal event); anything unreported -> blocked; else passed."""
    if logs is None:
        return Result(case_id, "blocked", "no central cargo log supplied (--judge LOG)", group)
    failed = [n for n in names if logs.status(n) in ("FAILED", "conflict")]
    if failed:
        first = failed[0]
        why = "reported conflicting results by the logs" if logs.status(first) == "conflict" else "cargo reported FAILED"
        cause = logs.panics.get(first)
        extra = "; first causal event: " + " | ".join(cause[:MAX_PANIC_LINES]) if cause else ""
        more = " (+%d more)" % (len(failed) - 1) if len(failed) > 1 else ""
        return Result(case_id, "failed", "test %s %s%s%s" % (first, why, more, extra), group)
    missing = [n for n in names if logs.status(n) != "ok"]
    if missing:
        cut = "; the log has no `test result:` line, so the run was cut off or never reached the end" if logs.summaries == 0 else ""
        unfinished = [n for n in missing if n in logs.unterminated]
        why = "not reported ok in the supplied logs (%d of %d)" % (len(missing), len(names)) + (", %d with a name and no result" % len(unfinished) if unfinished else "")
        return Result(case_id, "blocked", "%s: %s%s" % (why, ", ".join(missing[:3]) + (" ..." if len(missing) > 3 else ""), cut), group)
    return Result(case_id, "passed", "", group)


def case_plan(repo: str = REPO) -> Tuple[List[Tuple[str, str, List[str]]], Dict[str, List[str]]]:
    """The Rust-backed cases (id, description, required names) and the tests N01's own files define."""
    groups = own_tests(repo)
    every = groups["lib"] + groups["negotiation"] + groups["loopback"] + groups["replay"]
    plan = [(i, d, list(n)) for i, d, n in CLAUSES]
    plan.append((NEGOTIATION_CASE[0], NEGOTIATION_CASE[1], list(groups["negotiation"])))
    plan.append((ALL_CASE[0], ALL_CASE[1], every))
    return plan, groups


def meta_map(plan: List[Tuple[str, str, List[str]]], groups: Dict[str, List[str]]) -> Result:
    defined = {n for names in groups.values() for n in names}
    problems: List[str] = []
    for case_id, _desc, names in plan:
        if not names:
            problems.append("%s names no test" % case_id)
        gone = sorted(set(names) - defined)
        if gone:
            problems.append("%s names tests that are not in the sources: %s" % (case_id, ", ".join(gone[:3])))
        dup = sorted({n for n in names if names.count(n) > 1})
        if dup:
            problems.append("%s lists %s twice" % (case_id, dup[0]))
    every = [n for names in groups.values() for n in names]
    twice = sorted({n for n in every if every.count(n) > 1})
    if twice:  # two tests with one libtest name could not be told apart in a log
        problems.append("the sources define %s more than once" % twice[0])
    return Result("N01-META-MAP", "failed" if problems else "passed", "; ".join(problems[:3]), "meta")


def run(tier: str, logs: Optional[Logs], runner: Optional[Runner] = None, repo: str = REPO) -> Tuple[List[Result], dict]:
    if tier not in RUN_TIERS:
        raise ValueError("tier %r judges nothing (the soak tier is not run)" % tier)
    runner = runner or run_process  # looked up at call time, so a test can replace it
    plan, groups = case_plan(repo)
    results = [meta_map(plan, groups),
               reference_case("N01-REF-FRAMES", "reference_frames.py", runner),
               reference_case("N01-REF-NEGOTIATION", "reference_negotiation.py", runner)]
    if tier == "full":
        results.append(unit_case(runner))
        results.append(judge_fuzz_record())
        for case_id, _desc, names in plan:
            results.append(judge_names(case_id, "rust", names, logs))
    return results, {"planned": len(results), "rust_tests_required": len(next(n for i, _d, n in plan if i == ALL_CASE[0]))}


def planned_ids(tier: str) -> List[str]:
    plan, _groups = case_plan()
    ids = ["N01-META-MAP", "N01-REF-FRAMES", "N01-REF-NEGOTIATION"]
    return ids + (["N01-REF-UNITTESTS", "N01-FUZZ-RECORD"] + [i for i, _d, _n in plan] if tier == "full" else [])


def descriptions() -> Dict[str, str]:
    out = {"N01-META-MAP": "every named test exists in the sources and the clause map is whole",
           "N01-REF-FRAMES": "the frame reference regenerates the committed wire vectors and every expectation holds",
           "N01-REF-NEGOTIATION": "the negotiation reference regenerates the committed vectors and every expectation holds",
           "N01-REF-UNITTESTS": "the unit tests of the references and the judges",
           "N01-FUZZ-RECORD": "the committed record of the central coverage-guided fuzz run, held to itself (a moved source warns)"}
    for case_id, desc, _names in CLAUSES + [(NEGOTIATION_CASE[0], NEGOTIATION_CASE[1], []), (ALL_CASE[0], ALL_CASE[1], [])]:
        out[case_id] = desc
    return out


# ---- reporting -----------------------------------------------------------------------------------------------------------------------
def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "blocked")}


def exit_code(results: List[Result]) -> int:
    counts = summarize(results)
    return 1 if counts["failed"] else 3 if counts["blocked"] else 0


def final_exit(results: List[Result], evidence: Optional[Any]) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = exit_code(results)
    return 1 if code == 0 and evidence is not None and not evidence.complete else code


def artifact_digests() -> Dict[str, str]:
    return {rel: (sha256_file(os.path.join(REPO, rel)) if os.path.isfile(os.path.join(REPO, rel)) else "missing") for rel in JUDGED_ARTIFACTS}


def artifact_set_digest(digests: Dict[str, str]) -> str:
    return hashlib.sha256("".join("%s %s\n" % (rel, d) for rel, d in sorted(digests.items())).encode("utf-8")).hexdigest()


def versions() -> Dict[str, Any]:
    schema = None
    try:
        with open(os.path.join(REPO, CRATE, "tests", "vectors", "n01_wire_vectors.json"), encoding="utf-8") as handle:
            schema = json.load(handle).get("schema")
    except (OSError, ValueError, AttributeError):
        pass
    return {"python": platform.python_version(), "receipt_schema": RECEIPT_SCHEMA, "vectors_schema": schema}


def replay_command(tier: str, logs: Optional[Logs]) -> str:
    names = [os.path.basename(path) for path, _ in logs.files] if logs else []
    return "scripts/e2e/n01 --tier %s" % tier + (" --judge " + " ".join(shlex.quote(n) for n in names) if names else "")


def retained_lines(results: List[Result], tier: str, logs: Optional[Logs], meta: dict) -> List[str]:
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = ["RETAINED FOR REPLAY. First %s case: %s: %s" % (first.status, first.case_id, first.detail), "  replay: " + replay_command(tier, logs)]
    for path, digest in (logs.files if logs else []):
        lines.append("  judged log %s sha256 %s" % (os.path.basename(path), digest))
    v = meta["versions"]
    lines.append("  versions: python %s; receipt %s; vectors %s" % (v["python"], v["receipt_schema"], v["vectors_schema"]))
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
    for r in results:
        if r.status == "passed" and r.detail:
            print("%-8s %s  %s" % ("NOTE", r.case_id, r.detail))
    if meta is not None:
        for line in retained_lines(results, tier, logs, meta):
            print(line)
    verdict = "QUALIFIED" if final_exit(results, evidence) == 0 else "NOT QUALIFIED"
    note = ""
    if evidence is not None:
        print(evidence.summary)
        if not evidence.complete:
            note = "  [diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]"
    print("N01 e2e tier=%s: %s  planned=%d passed=%d failed=%d blocked=%d%s" % (tier, verdict, len(results), counts["passed"], counts["failed"], counts["blocked"], note))


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs], run_id: str, evidence: Optional[Any]) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "n01-%s.json" % run_id)
    doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
           "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "counts": summarize(results), "exit_code": final_exit(results, evidence),
           "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
           "replay": replay_command(tier, logs), **meta, "results": [r.as_dict() for r in results]}
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                              "file": os.path.basename(evidence.path) if evidence.path else None}
    with open(path, "x", encoding="utf-8") as handle:  # never overwrites an earlier run's receipt
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def load_case_log() -> Any:
    sys.path.insert(0, HERE)
    import case_log  # noqa: PLC0415 - loaded by name from this directory
    return case_log


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="N01 end-to-end runner and judge (ffw-ey5)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="list the planned case ids of the tier and exit")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="centrally run `cargo test -- --nocapture` output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt and the JSONL diagnostic log here")
    args = parser.parse_args(argv)

    if args.tier not in RUN_TIERS:
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                print("error: log not found: %s" % path, file=sys.stderr)
                return 2
            logs.add(path)
    if args.list:
        text = descriptions()
        for case_id in planned_ids(args.tier):
            print("%-20s %s" % (case_id, text[case_id]))
        return 0
    results, meta = run(args.tier, logs)
    meta["versions"] = versions()
    meta["artifacts"] = artifact_digests()
    case_log = load_case_log()
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": meta["versions"]["python"], "tier": args.tier, "artifact_count": len(meta["artifacts"]),
        "artifact_set_sha256": artifact_set_digest(meta["artifacts"])})
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, args.tier, logs, meta, evidence)
    code = final_exit(results, evidence)
    if args.receipts:
        try:
            print("receipt:", write_receipt(args.receipts, args.tier, results, meta, logs, run_id, evidence))
        except OSError as err:
            print("error: the receipt could not be written under %s: %s" % (args.receipts, type(err).__name__), file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main())
