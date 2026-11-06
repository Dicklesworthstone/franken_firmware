#!/usr/bin/env python3
"""S02 (ffw-6dh) end-to-end runner and judge: negotiated source codecs and the 160/147 rate bridge.

    run_cases.py [--tier smoke|full|soak] [--list] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library for the verdict (numpy/scipy only for two META checks, which are BLOCKED, never passed, without them). It builds
and boots nothing and never invokes cargo.

* META  - the ledger of negotiated formats is intact (every requirement present, BLOCKED rows kept, no result recorded in it); the vector
          corpus is consistent with its manifest and its own bytes; the shipped coefficient table equals a fresh generation; the bridge
          vectors equal a fresh closed-form derivation; the table and the bridge output meet the pre-registered quality thresholds
          (including a scipy cross-check); the Python mirror of the Rust algorithm reproduces the vectors; every Rust test is registered
          and every registered test exists; the contract document names every ledger row.
* JUDGE - reads the ``cargo test`` output of the centrally run suites (``--judge LOG``) with D01's log parser (reused unchanged, as D03
          does) and requires every registered Rust test to report ``ok``. A case with no Rust result is ``blocked``: counted, named, and
          the run is NOT QUALIFIED. It is never passed and never dropped.

The Rust suites run only through the centralized RCH path (see docs/contracts/s02.md for the exact lines), for example

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --locked --offline --no-fail-fast -p franken-codec -j 1 -- --nocapture

Every run writes a diagnostic log through the shared Q00 sink (tests/s02/case_log.py); a run whose log lost critical evidence is NOT
QUALIFIED whatever the cases say. A run that is not a pass says how to replay it, which versions it ran under and the sha256 of every
artifact it judged.

What a pass means and does not: host decode evidence for each negotiated format and an exact, tested rate bridge. The receipt's per-row
table says ``host_decode_verified`` for a mandatory row whose linked cases all passed; it never says a row works on a device, with a
provider, or fast enough. ``blocked`` and ``not_requested_by_pin`` rows are carried through unchanged. The ``S02-STATS`` lines in the
judged logs are operation and byte counts of the adapters on the host, reported as ``host_counts``, not CPU, heap or stack measurements.

The ``soak`` tier is selectable and is NOT RUN: it says why, exits 4 and is never a pass.

Exit codes: 0 qualified, 1 a case failed or the log lost critical evidence, 3 only blocked cases stand in the way, 4 the soak tier (not
run), 2 usage/malformed.
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
CASES = os.path.join(HERE, "cases.json")
VECTOR_DIR = os.path.join(REPO, "crates", "franken-codec", "tests", "vectors")
MANIFEST = os.path.join(VECTOR_DIR, "s02_vectors.json")
BRIDGE_VECTORS = os.path.join(VECTOR_DIR, "s02_bridge_vectors.json")
RATE_TABLE = os.path.join(REPO, "crates", "franken-codec", "src", "rate_table.rs")
CONTRACT = os.path.join(REPO, "docs", "contracts", "s02.md")
TIERS = ("smoke", "full", "soak")
RUN_TIERS = ("smoke", "full")
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "S02 soak: NOT RUN. Every S02 case is a finite, deterministic offline check (decode vectors, seek, damage, caps, an exact bridge), so "
    "there is no long-running or randomized work here to soak. The campaigns that would matter (hours of provider playback, board CPU, "
    "heap and stack on the old CPUs, listening tests) are board or provider evidence and need separately authorized receipts. This is not "
    "a pass.")
RECEIPT_SCHEMA = "ffw.s02.receipt.v1"
MAX_PRINTED = 12
SUBPROCESS_TIMEOUT_S = 600
SMOKE_META = ("S02-META-LEDGER", "S02-META-TABLE", "S02-META-COVERAGE", "S02-META-CONTRACT", "S02-META-ADMISSION")

JUDGED_ARTIFACTS = (
    "tests/s02/run_cases.py", "tests/s02/case_log.py", "tests/s02/cases.json", "tests/s02/negotiated.json", "tests/s02/ledger_check.py",
    "tests/s02/oracle.py", "tests/s02/make_vectors.py", "tests/s02/vorbis_tool.py", "tests/s02/gen_rate_table.py", "tests/s02/bridge_reference.py",
    "tests/s02/bridge_mirror.py", "tests/d01/run_cases.py", "scripts/test/test_support/diagnostics.py", "docs/contracts/s02.md",
    "Cargo.lock", "rust-toolchain.toml",
    "crates/franken-codec/Cargo.toml", "crates/franken-codec/src/lib.rs", "crates/franken-codec/src/decode.rs",
    "crates/franken-codec/src/rate_bridge.rs", "crates/franken-codec/src/rate_table.rs",
    "crates/franken-codec/tests/s02_decode.rs", "crates/franken-codec/tests/s02_bridge.rs", "crates/franken-codec/tests/s02_admission.rs",
    "crates/franken-codec/src/admission.rs", "tests/s02/admission.json", "tests/s02/test_admission.py",
    "crates/franken-codec/tests/vectors/s02_vectors.json", "crates/franken-codec/tests/vectors/s02_bridge_vectors.json",
)
RUST_TEST_FILES = (("crates/franken-codec/tests/s02_decode.rs", "s02_decode"), ("crates/franken-codec/tests/s02_bridge.rs", "s02_bridge"),
                   ("crates/franken-codec/tests/s02_admission.rs", "s02_admission"))
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+([A-Za-z0-9_]+)")
MACRO_ENTRY = re.compile(r"^\s+(s02_[A-Za-z0-9_]+)\s*=>\s*\"[^\"]+\"\s*,?\s*$", re.M)
STATS_LINE = re.compile(r"S02-STATS id=(\S+)((?: [a-z_]+=\d+)+)")
ERR_LINE = re.compile(r"S02-ERR id=(\S+) max_abs_lsb=(\d+) rms_lsb=([0-9.]+)")


def _load(name: str, path: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_d01_parser() -> Any:
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        sys.stderr.write("run_cases: D01's runner (%s) is required for its cargo-log parser\n" % path)
        raise SystemExit(2)
    return _load("d01_run_cases_for_s02", path)


case_log = _load("s02_case_log", os.path.join(HERE, "case_log.py"))
ledger_check = _load("s02_ledger_check", os.path.join(HERE, "ledger_check.py"))
d01 = _load_d01_parser()
Logs = d01.Logs


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


def load_json(path: str) -> Tuple[Optional[Any], str]:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle), ""
    except (OSError, ValueError) as err:
        return None, "%s: %s" % (os.path.relpath(path, REPO), type(err).__name__)


def load_cases() -> Tuple[List[dict], str]:
    doc, problem = load_json(CASES)
    if problem:
        return [], problem
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list) or not cases:
        return [], "cases.json has no cases"
    ids = [c.get("id") for c in cases]
    if len(ids) != len(set(ids)):
        return [], "cases.json has duplicate case ids"
    for c in cases:
        if not (isinstance(c.get("tests"), list) and c["tests"] and c.get("stem")):
            return [], "case %s has no tests or no stem" % c.get("id")
    return cases, ""


def py(script: str, *args: str, repo: str = REPO) -> Tuple[int, str, str]:
    """Run a sibling script in isolated mode. stderr is returned and reported, never silenced."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([sys.executable, "-I", os.path.join(repo, "tests", "s02", script), *args], capture_output=True, text=True,
                          env=env, timeout=SUBPROCESS_TIMEOUT_S, cwd=repo)
    return done.returncode, done.stdout, done.stderr


def tail(text: str, n: int = 400) -> str:
    text = text.strip()
    return text if len(text) <= n else "..." + text[-n:]


# ---- META cases ------------------------------------------------------------------------------


def meta_ledger() -> Result:
    ledger, p1 = load_json(os.path.join(HERE, "negotiated.json"))
    manifest, p2 = load_json(MANIFEST)
    if p1 or p2:
        return Result("S02-META-LEDGER", "failed", p1 or p2, "meta")
    problems = ledger_check.check(ledger, manifest)
    if problems:
        return Result("S02-META-LEDGER", "failed", "; ".join(problems[:6]) + (" ..." if len(problems) > 6 else ""), "meta")
    return Result("S02-META-LEDGER", "passed", "%d ledger rows intact; BLOCKED and not-requested rows kept; no result recorded in the ledger" % len(ledger["rows"]), "meta")


def meta_manifest() -> Result:
    rc, out, err = py("make_vectors.py", "--out", VECTOR_DIR, "--check")
    if rc == 0:
        return Result("S02-META-MANIFEST", "passed", tail(out), "meta")
    return Result("S02-META-MANIFEST", "failed", "rc=%d %s %s" % (rc, tail(out), tail(err)), "meta")


def meta_table() -> Result:
    rc, out, err = py("gen_rate_table.py", "--check", RATE_TABLE)
    if rc == 0:
        return Result("S02-META-TABLE", "passed", "rate_table.rs is %s" % tail(out), "meta")
    return Result("S02-META-TABLE", "failed", "rc=%d %s %s" % (rc, tail(out), tail(err)), "meta")


def meta_bridge_vectors() -> Result:
    rc, out, err = py("bridge_reference.py", "--check-vectors", BRIDGE_VECTORS)
    if rc == 0:
        return Result("S02-META-BRIDGE-VECTORS", "passed", "bridge vectors are %s" % tail(out), "meta")
    if rc == 3:
        return Result("S02-META-BRIDGE-VECTORS", "blocked", tail(err) or "numpy unavailable", "meta")
    return Result("S02-META-BRIDGE-VECTORS", "failed", "rc=%d %s %s" % (rc, tail(out), tail(err)), "meta")


def meta_quality() -> Result:
    rc, out, err = py("bridge_reference.py", "--quality")
    if rc == 3:
        return Result("S02-META-QUALITY", "blocked", tail(out) or tail(err) or "numpy/scipy unavailable", "meta")
    try:
        report = json.loads(out)
    except ValueError:
        return Result("S02-META-QUALITY", "failed", "unreadable report rc=%d %s" % (rc, tail(err)), "meta")
    table, scipy_row = report.get("table", {}), report.get("scipy", {})
    tones = report.get("tones", [])
    detail = ("pass-band deviation %.2e (limit %.1e), stop-band %.1f dB (limit %.1f), worst tone gain error %.2e, worst spur %.1f dB, "
              "scipy rms difference %.2e" % (
                  table.get("passband_max_deviation", float("nan")), table.get("passband_limit", float("nan")),
                  table.get("stopband_max_db", float("nan")), table.get("stopband_limit_db", float("nan")),
                  max((abs(t["gain"] - 1.0) for t in tones), default=float("nan")), max((t["spur_db"] for t in tones), default=float("nan")),
                  scipy_row.get("rms_relative_difference", float("nan"))))
    return Result("S02-META-QUALITY", "passed" if rc == 0 else "failed", detail, "meta")


def meta_mirror() -> Result:
    rc, out, err = py("bridge_mirror.py")
    if rc == 0:
        return Result("S02-META-MIRROR", "passed", "the line-by-line Python mirror of the Rust algorithm reproduces all bridge vectors", "meta")
    if "numpy" in err and "No module" in err:
        return Result("S02-META-MIRROR", "blocked", "numpy unavailable", "meta")
    return Result("S02-META-MIRROR", "failed", "rc=%d %s %s" % (rc, tail(out), tail(err)), "meta")


def meta_admission() -> Result:
    """RedPuma's admission verdict table against the ledger, by its own unittest (run from the repository root, as its author specified)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run([sys.executable, "-B", "-W", "error", "-m", "unittest", "tests/s02/test_admission.py"], capture_output=True, text=True,
                          env=env, timeout=SUBPROCESS_TIMEOUT_S, cwd=REPO)
    if done.returncode == 0:
        return Result("S02-META-ADMISSION", "passed", "tests/s02/test_admission.py: " + tail(done.stderr.strip().splitlines()[-1] if done.stderr.strip() else "ok"), "meta")
    return Result("S02-META-ADMISSION", "failed", "rc=%d %s" % (done.returncode, tail(done.stderr)), "meta")


def derive_rust_tests(repo: str = REPO) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for rel, stem in RUST_TEST_FILES:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for attrs, name in TEST_FN.findall(text):
            if "ignore" not in attrs:
                found.append((stem, name))
        found.extend((stem, name) for name in MACRO_ENTRY.findall(text))
    return found


def meta_coverage(cases: List[dict]) -> Result:
    derived = derive_rust_tests()
    if len(derived) != len(set(derived)):
        return Result("S02-META-COVERAGE", "failed", "a Rust test name appears twice in the sources", "meta")
    registered = [(c["stem"], t) for c in cases for t in c["tests"]]
    if len(registered) != len(set(registered)):
        return Result("S02-META-COVERAGE", "failed", "a Rust test is registered under two cases", "meta")
    unregistered = sorted(set(derived) - set(registered))
    missing = sorted(set(registered) - set(derived))
    if unregistered or missing:
        parts = []
        if unregistered:
            parts.append("tests in the sources but in no case: " + ", ".join(n for _, n in unregistered[:4]))
        if missing:
            parts.append("cases naming tests the sources do not have: " + ", ".join(n for _, n in missing[:4]))
        return Result("S02-META-COVERAGE", "failed", "; ".join(parts), "meta")
    return Result("S02-META-COVERAGE", "passed", "%d Rust tests in the sources == %d registered" % (len(derived), len(registered)), "meta")


def meta_contract() -> Result:
    ledger, problem = load_json(os.path.join(HERE, "negotiated.json"))
    if problem:
        return Result("S02-META-CONTRACT", "failed", problem, "meta")
    if not os.path.isfile(CONTRACT):
        return Result("S02-META-CONTRACT", "failed", "docs/contracts/s02.md is missing", "meta")
    with open(CONTRACT, encoding="utf-8") as handle:
        text = handle.read()
    missing = [r["id"] for r in ledger["rows"] if r["id"] not in text]
    needed = ["BLOCKED", "160/147", "NOT claimed", "host_decode_verified", "scripts/e2e/s02", "franken-codec"]
    missing += [n for n in needed if n not in text]
    if missing:
        return Result("S02-META-CONTRACT", "failed", "the contract does not mention: " + ", ".join(missing), "meta")
    return Result("S02-META-CONTRACT", "passed", "the contract names every ledger row and its limits", "meta")


# ---- Rust-backed cases -----------------------------------------------------------------------


def judge_rust_case(case: dict, logs: Optional[Any]) -> Result:
    cid, group = case["id"], case.get("group", "")
    if logs is None:
        return Result(cid, "blocked", "no cargo test log was judged (run the Rust suite centrally, then --judge LOG)", group)
    problems, blocked = [], []
    for name in case["tests"]:
        status = logs.test_status(case["stem"], name)
        if status == "ok":
            continue
        if status == "FAILED":
            context = logs.failure_context.get(name, "")
            problems.append("%s FAILED%s" % (name, (" (" + context + ")") if context else ""))
        elif status in ("CONFLICT", "AMBIGUOUS"):
            blocked.append("%s: the logs %s" % (name, "disagree" if status == "CONFLICT" else "cannot say which binary ran it"))
        elif status == "ignored":
            blocked.append("%s: ignored, which is not a pass" % name)
        else:
            blocked.append("%s: not reported by any judged log" % name)
    if problems:
        return Result(cid, "failed", "; ".join(problems), group)
    if blocked:
        return Result(cid, "blocked", "; ".join(blocked), group)
    return Result(cid, "passed", "%d Rust test(s) ok" % len(case["tests"]), group)


def host_counts(logs: Optional[Any]) -> Dict[str, Any]:
    """The S02-STATS / S02-ERR lines of the judged logs. Counts and errors of the host run, not a measurement of any device."""
    counts: Dict[str, Dict[str, int]] = {}
    errors: Dict[str, Dict[str, float]] = {}
    for path, _digest in (logs.files if logs else []):
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        for track, rest in STATS_LINE.findall(text):
            counts[track] = {k: int(v) for k, v in (kv.split("=") for kv in rest.split())}
        for track, peak, rms in ERR_LINE.findall(text):
            errors[track] = {"max_abs_lsb": int(peak), "rms_lsb": float(rms)}
    worst = {}
    for key in ("max_block_frames", "max_out_capacity_samples", "bytes_in", "packets", "decode_errors"):
        values = [(v.get(key, 0), t) for t, v in counts.items()]
        if values:
            worst[key] = {"value": max(values)[0], "track": max(values)[1]}
    return {"scope": "host simulation counts; not CPU, heap or stack on a device", "tracks": counts, "errors": errors, "worst": worst}


def ledger_table(cases: List[dict], results: List[Result]) -> List[dict]:
    ledger, _ = load_json(os.path.join(HERE, "negotiated.json"))
    if not isinstance(ledger, dict):
        return []
    status_of = {r.case_id: r.status for r in results}
    table = []
    for row in ledger["rows"]:
        linked = [c["id"] for c in cases if row["id"] in c.get("rows", [])]
        if row["status"] == "blocked":
            state = "blocked"
        elif row["status"] == "not_requested_by_pin":
            state = "not_requested_by_pin"
        elif linked and all(status_of.get(cid) == "passed" for cid in linked):
            state = "host_decode_verified"
        else:
            state = "unproven"
        table.append({"row": row["id"], "ledger_status": row["status"], "state": state, "cases": linked,
                      "blocked_by": row.get("blocked_by", "")})
    return table


def run(tier: str, logs: Optional[Any]) -> Tuple[List[Result], dict]:
    cases, problem = load_cases()
    if problem:
        return [Result("S02-META-CASES", "failed", problem, "meta")], {"cases": 0}
    results: List[Result] = []
    metas = [("S02-META-LEDGER", meta_ledger), ("S02-META-MANIFEST", meta_manifest), ("S02-META-TABLE", meta_table),
             ("S02-META-BRIDGE-VECTORS", meta_bridge_vectors), ("S02-META-QUALITY", meta_quality), ("S02-META-MIRROR", meta_mirror),
             ("S02-META-COVERAGE", lambda: meta_coverage(cases)), ("S02-META-CONTRACT", meta_contract), ("S02-META-ADMISSION", meta_admission)]
    for cid, fn in metas:
        if tier == "smoke" and cid not in SMOKE_META:
            continue
        results.append(fn())
    for case in cases:
        results.append(judge_rust_case(case, logs))
    meta = {"cases_json_sha256": sha256_file(CASES), "host_counts": host_counts(logs), "ledger": ledger_table(cases, results)}
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


def artifact_digests() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rel in JUDGED_ARTIFACTS:
        path = os.path.join(REPO, rel)
        out[rel] = sha256_file(path) if os.path.isfile(path) else "missing"
    return out


def artifact_set_digest(digests: Dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{rel} {digest}\n" for rel, digest in sorted(digests.items())).encode("utf-8")).hexdigest()


def versions() -> Dict[str, Any]:
    return {"python": platform.python_version(), "receipt_schema": RECEIPT_SCHEMA}


def replay_command(tier: str, logs: Optional[Any]) -> str:
    names = [os.path.basename(path) for path, _ in logs.files] if logs else []
    return f"scripts/e2e/s02 --tier {tier}" + (" --judge " + " ".join(shlex.quote(n) for n in names) if names else "")


def final_exit(results: List[Result], evidence: Optional[Any]) -> int:
    code = exit_code(results)
    if code == 0 and evidence is not None and not evidence.complete:
        return 1
    return code


def retained_lines(results: List[Result], tier: str, logs: Optional[Any], meta: dict) -> List[str]:
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = [f"RETAINED FOR REPLAY. First {first.status} case: {first.case_id}: {first.detail}", f"  replay: {replay_command(tier, logs)}"]
    for path, digest in (logs.files if logs else []):
        lines.append(f"  judged log {os.path.basename(path)} sha256 {digest}")
    lines.append(f"  versions: python {meta['versions']['python']}; receipt {meta['versions']['receipt_schema']}")
    for rel, digest in meta["artifacts"].items():
        lines.append(f"  artifact {rel} sha256 {digest}")
    return lines


def report(results: List[Result], tier: str, logs: Optional[Any] = None, meta: Optional[dict] = None, evidence: Optional[Any] = None) -> None:
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:MAX_PRINTED]:
            print(f"{label:8s} {r.case_id}  {r.detail}")
        if len(rows) > MAX_PRINTED:
            print(f"{label:8s} ... and {len(rows) - MAX_PRINTED} more {status} case(s)")
    if meta is not None:
        for line in retained_lines(results, tier, logs, meta):
            print(line)
        for row in meta.get("ledger", []):
            print("ledger %-30s %s" % (row["row"], row["state"]))
        worst = meta.get("host_counts", {}).get("worst", {})
        for key, value in worst.items():
            print("host count (not a device measurement) %s = %s (%s)" % (key, value["value"], value["track"]))
    verdict = "QUALIFIED" if final_exit(results, evidence) == 0 else "NOT QUALIFIED"
    note = ""
    if evidence is not None:
        print(evidence.summary)
        if not evidence.complete:
            note = "  [diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]"
    print(f"S02 e2e tier={tier}: {verdict}  planned={len(results)} passed={counts['passed']} failed={counts['failed']} blocked={counts['blocked']}{note}")


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Any], run_id: Optional[str] = None,
                  evidence: Optional[Any] = None) -> str:
    os.makedirs(directory, exist_ok=True)
    run_id = run_id or secrets.token_hex(8)
    path = os.path.join(directory, f"s02-{run_id}.json")
    doc = {
        "schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "counts": summarize(results), "exit_code": final_exit(results, evidence),
        "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
        "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
        "identical_repeated_observations": logs.identical_repeats if logs else 0,
        "unattributed_logs": list(logs.unattributed_logs) if logs else [],
        "replay": replay_command(tier, logs),
        **meta, "results": [r.as_dict() for r in results],
    }
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                              "file": os.path.basename(evidence.path) if evidence.path else None}
    with open(path, "x", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="S02 end-to-end runner and judge (ffw-6dh)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="list planned case ids and exit")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="cargo test output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt and the JSONL diagnostic log here")
    args = parser.parse_args(argv)

    if args.tier not in RUN_TIERS:
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    logs: Optional[Any] = None
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
    meta["versions"] = versions()
    meta["artifacts"] = artifact_digests()
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": meta["versions"]["python"], "tier": args.tier, "artifact_count": len(meta["artifacts"]),
        "artifact_set_sha256": artifact_set_digest(meta["artifacts"]), "cases_json_sha256": meta.get("cases_json_sha256", "")})
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, args.tier, logs, meta, evidence)
    code = final_exit(results, evidence)
    if args.receipts:
        try:
            print("receipt:", write_receipt(args.receipts, args.tier, results, meta, logs, run_id, evidence))
        except OSError as err:
            print(f"error: the receipt could not be written under {args.receipts}: {type(err).__name__}", file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main())
