#!/usr/bin/env python3
"""E03 (ffw-q2p) host-side case runner.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]

Runs the named cases in ``cases.json`` against ``abi.py`` (the classifier) and prints one line per
case plus an exact denominator.  Exit 0 only if every selected case passed.  A case of kind
``blocked`` is a required invariant nothing can verify yet: it is counted, named with its owner, and
makes the run NOT QUALIFIED; it is never silently dropped or passed.  Exit codes: 0 qualified,
1 a case failed, 3 only blocked cases stand in the way, 2 usage or a malformed cases file.

What the cases are, so a pass is not over-read:
* REAL    - the committed Debian 4.19 MIPS / 4.9 PowerPC serial transcripts and receipt, or the root's
            own validator, read as they are.
* PLANTED - the same real transcripts with one line changed (each mutation must apply, so a planted
            case cannot pass vacuously).  Where a line is ADDED because the committed log predates it,
            the case says SYNTHETIC.
* TABLE   - pure inputs and independently written expected values.
Expected values in ``cases.json`` are written separately from the tables in ``abi.py``; they share one
author, so that is a cross-check, not independence from a second source.  Offline, no builds.
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
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RESULTS = os.path.join(REPO, "toolchain", "results")
CASES_FILE = os.path.join(HERE, "cases.json")
ABI_FILE = os.path.join(HERE, "abi.py")
ROOT_VALIDATOR = os.path.join(REPO, "toolchain", "src", "run-qemu-verification.py")
SCHEMA = "ffw.e03.cases.v1"
TIERS = ("smoke", "full")
KINDS = ("errno_table", "errno_reverse", "int_table", "io_table", "classify", "cli", "cross_validator",
         "identity", "meta", "runner_selftest", "blocked")
REAL = {"mips": "boot-mips-serial.log", "ppc": "boot-ppc-serial.log"}
ROOT_ARGS = {  # the root validator's expected hello / ENOSYS lines per arch
    "mips": ("FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32", "FFW_TEST:ERR_ENOSYS status=PASS errno=89"),
    "ppc": ("FFW_HELLO arch=powerpc-be endian=0x01020304 pid=1 ptr_bits=32", "FFW_TEST:ERR_ENOSYS status=PASS errno=38"),
}


class CaseError(Exception):
    pass


def load_module(path: str, name: str) -> Any:
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


A = load_module(ABI_FILE, "ffw_e03_abi")


def strict_loads(text: str) -> Any:
    def pairs(items):
        out: Dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key %r" % k)
            out[k] = v
        return out
    return json.loads(text, object_pairs_hook=pairs)


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ------------------------------------------------------------------ transcript sources and mutations


def real_text(which: str) -> str:
    if which not in REAL:
        raise CaseError("unknown real transcript %r" % which)
    with open(os.path.join(RESULTS, REAL[which]), "rb") as fh:
        return fh.read().decode("utf-8", errors="replace")


def mutate(text: str, ops: List[Dict[str, Any]]) -> str:
    """Apply planted mutations.  Every op must match, so a planted case cannot pass vacuously."""
    lines = text.split("\n")

    def find(prefix: str) -> List[int]:
        return [i for i, ln in enumerate(lines) if ln.strip().startswith(prefix)]

    for op in ops:
        kind = op["op"]
        if kind == "truncate_before_first":
            hits = find(op["prefix"])
            if not hits:
                raise CaseError("mutation matched nothing: %s" % json.dumps(op))
            lines = lines[: hits[0]]
            continue
        hits = find(op["prefix"])
        if kind in ("set_line", "insert_after", "duplicate", "truncate_after") and len(hits) != 1:
            raise CaseError("mutation needs exactly one line starting %r, found %d" % (op["prefix"], len(hits)))
        if kind == "drop" and not hits:
            raise CaseError("mutation matched nothing: %s" % json.dumps(op))
        if kind == "set_line":
            lines[hits[0]] = op["line"]
        elif kind == "insert_after":
            lines.insert(hits[0] + 1, op["line"])
        elif kind == "duplicate":
            lines.insert(hits[0] + 1, lines[hits[0]])
        elif kind == "truncate_after":
            lines = lines[: hits[0] + 1]
        elif kind == "drop":
            lines = [ln for i, ln in enumerate(lines) if i not in set(hits)]
        else:
            raise CaseError("unknown mutation %r" % kind)
    return "\n".join(lines)


def build_text(spec: Dict[str, Any]) -> str:
    src = spec["source"]
    if "real" in src:
        text = real_text(src["real"])
    elif "inline" in src:
        text = "\n".join(src["inline"]) + "\n"
    else:
        raise CaseError("source needs real or inline")
    return mutate(text, spec.get("mutations", []))


# ------------------------------------------------------------------ handlers


def h_errno_table(spec: Dict[str, Any]) -> None:
    bad = []
    for number, expected in spec["entries"]:
        got = A.errno_name(spec["arch"], number)
        if got != expected:
            bad.append("%s errno %s: expected %s, got %s" % (spec["arch"], number, expected, got))
    if bad:
        raise CaseError("; ".join(bad[:3]))


def h_errno_reverse(spec: Dict[str, Any]) -> None:
    bad = []
    for name, expected in spec["entries"]:
        got = A.errno_number(spec["arch"], name)
        if got != expected:
            bad.append("%s %s: expected %s, got %s" % (spec["arch"], name, expected, got))
    for name in spec.get("unknown_names", []):
        try:
            A.errno_number(spec["arch"], name)
            bad.append("unknown name %s was accepted" % name)
        except ValueError:
            pass
    for arch in spec.get("unknown_arches", []):
        try:
            A.errno_name(arch, 1)
            bad.append("unknown ABI %s was accepted" % arch)
        except ValueError:
            pass
    if bad:
        raise CaseError("; ".join(bad[:3]))


def h_int_table(spec: Dict[str, Any]) -> None:
    bad = []
    for text, expected in spec["valid"]:
        try:
            got = A.parse_i32(text)
        except ValueError:
            got = "rejected"
        if got != expected:
            bad.append("%r: expected %s, got %s" % (text, expected, got))
    for text in spec["invalid"]:
        try:
            A.parse_i32(text)
            bad.append("%r was accepted" % text)
        except ValueError:
            pass
    if bad:
        raise CaseError("; ".join(bad[:3]))


def h_io_table(spec: Dict[str, Any]) -> None:
    bad = []
    for result, kind, name in spec["entries"]:
        got = A.classify_io(spec["requested"], result, spec["arch"])
        if got != (kind, name):
            bad.append("%s req=%s result=%s: expected %s, got %s" % (spec["arch"], spec["requested"], result,
                                                                   (kind, name), got))
    for requested, result in spec.get("invalid_args", []):
        try:
            A.classify_io(requested, result, spec["arch"])
            bad.append("args (%r, %r) were accepted" % (requested, result))
        except ValueError:
            pass
    if bad:
        raise CaseError("; ".join(bad[:3]))


def _check_result(result: Dict[str, Any], expect: Dict[str, Any], text: str) -> None:
    if "expect_by_line" in expect:
        by = expect["expect_by_line"]
        present = any(ln.strip().startswith(by["line"]) for ln in text.split("\n"))
        expect = by["present"] if present else by["absent"]
    bad = []
    for field in ("evidence", "verdict"):
        if field in expect and result[field] != expect[field]:
            bad.append("%s: expected %s, got %s" % (field, expect[field], result[field]))
    if "calibration_ok" in expect and (result["calibration"]["ok"] and result["calibration"]["selftests_ok"]) != expect["calibration_ok"]:
        bad.append("calibration_ok: expected %s, got %s/%s" % (expect["calibration_ok"], result["calibration"]["ok"],
                                                              result["calibration"]["selftests_ok"]))
    for name, (status, why) in expect.get("probes", {}).items():
        got = result["probes"][name]
        if got["status"] != status or not got["reason"].startswith(why):
            bad.append("%s: expected %s/%s, got %s/%s" % (name, status, why, got["status"], got["reason"][:50]))
    if "all_probes" in expect:
        status, why = expect["all_probes"]
        for name, got in result["probes"].items():
            if got["status"] != status or not got["reason"].startswith(why):
                bad.append("%s: expected %s/%s, got %s/%s" % (name, status, why, got["status"], got["reason"][:50]))
                break
    if "supported_exactly" in expect:
        have = sorted(n for n, p in result["probes"].items() if p["status"] == "supported")
        if have != sorted(expect["supported_exactly"]):
            bad.append("supported set: expected %s, got %s" % (sorted(expect["supported_exactly"]), have))
    if "guest_status" in expect:
        for name, st in expect["guest_status"].items():
            if result["probes"][name]["guest_status"] != st:
                bad.append("%s guest_status: expected %s, got %s" % (name, st, result["probes"][name]["guest_status"]))
    if bad:
        raise CaseError("; ".join(bad[:4]))


def h_classify(spec: Dict[str, Any]) -> None:
    text = build_text(spec)
    result = A.classify_run(text, spec["profile"], spec.get("mode", "full-system"))
    _check_result(result, spec["expect"], text)
    if result["verdict"] == "green" and (result["evidence"] != "matching-guest" or any(
            p["status"] != "supported" for n, p in result["probes"].items() if n in A.REQUIRED)):
        raise CaseError("internal: green verdict without matching evidence and supported required probes")


def h_cli(spec: Dict[str, Any]) -> None:
    text = build_text(spec) if "source" in spec else ""
    with tempfile.TemporaryDirectory(prefix="ffw-e03-") as d:
        path = os.path.join(d, "transcript.log") if not spec.get("missing_file") else os.path.join(d, "absent.log")
        if not spec.get("missing_file"):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        argv = [sys.executable, "-B", ABI_FILE, "classify", path, "--profile", spec["profile"], "--json"]
        if spec.get("mode"):
            argv += ["--mode", spec["mode"]]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=d)
    if p.returncode != spec["exit"]:
        raise CaseError("exit %s, expected %s: %s" % (p.returncode, spec["exit"], (p.stderr or p.stdout)[:120]))
    if spec["exit"] != 2:
        doc = json.loads(p.stdout)
        if doc["verdict"] != spec["verdict"]:
            raise CaseError("verdict %s, expected %s" % (doc["verdict"], spec["verdict"]))


def h_cross_validator(spec: Dict[str, Any]) -> None:
    """The root's own validator and this classifier must agree on every variant of the same transcript."""
    root = load_module(ROOT_VALIDATOR, "ffw_e03_root_validator")
    bad = []
    for variant in spec["variants"]:
        text = build_text({"source": {"real": spec["real"]}, "mutations": variant["mutations"]})
        hello, enosys = ROOT_ARGS[spec["real"]]
        theirs = root.verify_serial_output(spec["real"], hello, enosys, text)["status"]
        ours = A.classify_run(text, spec["profile"])["verdict"]
        if theirs != variant["root"] or ours != variant["ours"]:
            bad.append("%s: root %s (want %s), ours %s (want %s)" % (variant["name"], theirs, variant["root"],
                                                                   ours, variant["ours"]))
        if (theirs == "PASS") != (ours == "green"):
            bad.append("%s: the two validators disagree" % variant["name"])
    if bad:
        raise CaseError("; ".join(bad[:3]))


def h_identity(spec: Dict[str, Any]) -> None:
    with open(os.path.join(RESULTS, "e07-e03-verification-receipt.json"), "rb") as fh:
        receipt = strict_loads(fh.read().decode("utf-8"))
    bad = []
    for arch in ("mips", "ppc"):
        guest = receipt["guests"][arch]
        path = os.path.join(RESULTS, REAL[arch])
        actual = sha256_file(path)
        if actual != guest["serial_log_sha256"]:
            bad.append("%s log sha256 %s differs from the receipt's %s" % (arch, actual[:12], guest["serial_log_sha256"][:12]))
        parsed = A.parse_transcript(real_text(arch))
        if parsed["kernel_release"] is None or not guest["kernel_version"].startswith("Linux version " + parsed["kernel_release"]):
            bad.append("%s kernel in the transcript is not the receipt's" % arch)
    if bad:
        raise CaseError("; ".join(bad))


def h_runner_selftest(spec: Dict[str, Any]) -> None:
    """The runner's own machinery (mutation ops, expectation checks, exit codes, document validation) is
    exercised against deliberately wrong inputs by test_run_cases.py; a run that finds fewer tests than
    ``min_tests`` (or none) fails, so deleting or emptying that file cannot pass."""
    p = subprocess.run([sys.executable, "-B", "-m", "unittest", "test_run_cases"], capture_output=True, text=True,
                       timeout=300, cwd=HERE)
    m = re.search(r"^Ran (\d+) tests?", p.stderr, re.M)
    ran = int(m.group(1)) if m else 0
    if p.returncode != 0 or not re.search(r"^OK\s*$", p.stderr, re.M):
        raise CaseError("runner self-tests failed (exit %s): %s" % (p.returncode, " ".join(p.stderr.split())[-160:]))
    if ran < spec["min_tests"]:
        raise CaseError("runner self-tests ran %d tests, expected at least %d" % (ran, spec["min_tests"]))


def h_meta(spec: Dict[str, Any], doc: Dict[str, Any]) -> None:
    ids = {c["id"] for c in doc["cases"]}
    bad = []
    for inv in doc["invariants"]:
        if inv["status"] not in ("covered", "partial", "blocked", "inapplicable"):
            bad.append("%s has unknown status %s" % (inv["id"], inv["status"]))
        if inv["status"] in ("covered", "partial", "blocked") and not inv.get("cases"):
            bad.append("%s claims %s but names no case" % (inv["id"], inv["status"]))
        if inv["status"] == "inapplicable" and not inv.get("note"):
            bad.append("%s is inapplicable without an explanation" % inv["id"])
        for cid in inv.get("cases", []):
            if cid not in ids:
                bad.append("%s names missing case %s" % (inv["id"], cid))
    named = {cid for inv in doc["invariants"] for cid in inv.get("cases", [])}
    for c in doc["cases"]:
        if c["kind"] not in ("meta",) and c["id"] not in named:
            bad.append("case %s covers no invariant" % c["id"])
    if bad:
        raise CaseError("; ".join(bad[:4]))


HANDLERS = {"errno_table": h_errno_table, "errno_reverse": h_errno_reverse, "int_table": h_int_table,
            "io_table": h_io_table, "classify": h_classify, "cli": h_cli, "cross_validator": h_cross_validator,
            "identity": h_identity, "runner_selftest": h_runner_selftest}


# ------------------------------------------------------------------ runner


def validate_doc(doc: Any) -> List[str]:
    errs: List[str] = []
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return ["cases.json must be an object with schema %s" % SCHEMA]
    seen = set()
    for c in doc.get("cases", []):
        cid = c.get("id")
        if not isinstance(cid, str) or not cid.startswith("E03-"):
            errs.append("bad case id %r" % (cid,))
        elif cid in seen:
            errs.append("duplicate case id %s" % cid)
        seen.add(cid)
        if c.get("kind") not in KINDS:
            errs.append("%s: unknown kind %r" % (cid, c.get("kind")))
        if not c.get("tiers") or any(t not in TIERS for t in c["tiers"]):
            errs.append("%s: tiers must be a non-empty subset of %s" % (cid, list(TIERS)))
        if c.get("kind") == "blocked" and not (c.get("reason") and c.get("owner")):
            errs.append("%s: a blocked case needs a reason and an owner" % cid)
    return errs


def run_case(case: Dict[str, Any], doc: Dict[str, Any]) -> Dict[str, Any]:
    cid, kind = case["id"], case["kind"]
    res = {"id": cid, "kind": kind, "invariant": case.get("title", ""), "status": "passed", "detail": ""}
    if kind == "blocked":
        res.update(status="blocked", detail="%s [owner: %s]" % (case["reason"], case["owner"]))
        return res
    try:
        if kind == "meta":
            h_meta(case.get("spec", {}), doc)
        else:
            HANDLERS[kind](case["spec"])
    except CaseError as exc:
        res.update(status="failed", detail=str(exc))
    except Exception as exc:    # a handler crash is a failure with its type, never a pass
        res.update(status="failed", detail="%s: %s" % (type(exc).__name__, str(exc)[:160]))
    return res


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="E03 host-side cases")
    ap.add_argument("--tier", required=True, choices=TIERS, help="explicit; there is no default")
    ap.add_argument("--case", action="append", default=[], metavar="ID", help="replay specific case ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--receipts", metavar="DIR", help="write a receipt here (a new file; never overwrites)")
    args = ap.parse_args(argv)
    try:
        with open(CASES_FILE, "rb") as fh:
            doc = strict_loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        print("run_cases: cannot read cases.json: %s" % exc, file=sys.stderr)
        return 2
    problems = validate_doc(doc)
    if problems:
        print("run_cases: malformed cases.json: %s" % "; ".join(problems[:4]), file=sys.stderr)
        return 2
    selected = [c for c in doc["cases"] if args.tier in c["tiers"]]
    if args.case:
        unknown = sorted(set(args.case) - {c["id"] for c in doc["cases"]})
        if unknown:
            print("run_cases: unknown case id(s): %s" % ", ".join(unknown), file=sys.stderr)
            return 2
        selected = [c for c in doc["cases"] if c["id"] in args.case]
    if args.list:
        for c in selected:
            print("%-14s %-16s %s" % (c["id"], c["kind"], c.get("title", "")))
        return 0

    results = [run_case(c, doc) for c in selected]
    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("passed", "failed", "blocked")}
    for r in results:
        tag = {"passed": "PASS   ", "failed": "FAIL   ", "blocked": "BLOCKED"}[r["status"]]
        print("%s %-14s %s" % (tag, r["id"], (r["invariant"] + (" -- " + r["detail"] if r["detail"] else ""))[:230]))
    inv = {}
    for i in doc["invariants"]:
        inv[i["status"]] = inv.get(i["status"], 0) + 1
    qualified = counts["failed"] == 0 and counts["blocked"] == 0 and not args.case
    print("E03 cases: tier=%s total=%d passed=%d failed=%d blocked=%d | invariants: %s -> %s" % (
        args.tier, len(results), counts["passed"], counts["failed"], counts["blocked"],
        ", ".join("%s=%d" % kv for kv in sorted(inv.items())),
        "QUALIFIED" if qualified else "NOT QUALIFIED"))
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(args.receipts, "e03-cases-%s-%s.json" % (stamp, secrets.token_hex(3)))
        evidence = {REAL[a]: sha256_file(os.path.join(RESULTS, REAL[a])) for a in REAL}
        receipt = {"schema": SCHEMA, "tier": args.tier, "command": [sys.executable.split(os.sep)[-1], "tests/e03/run_cases.py", "--tier", args.tier]
                   + [x for c in args.case for x in ("--case", c)], "python": sys.version.split()[0],
                   "cases_sha256": sha256_file(CASES_FILE), "abi_sha256": sha256_file(ABI_FILE),
                   "evidence_sha256": evidence, "counts": counts, "results": results,
                   "replay": {r["id"]: "python3 tests/e03/run_cases.py --tier %s --case %s" % (args.tier, r["id"])
                              for r in results if r["status"] != "passed"}}
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
        print("receipt: %s" % os.path.relpath(path, os.getcwd()))
    return 1 if counts["failed"] else (3 if counts["blocked"] else 0)


if __name__ == "__main__":
    sys.exit(main())
