#!/usr/bin/env python3
"""Turn one soft-float reading of franken-dsp into a COMMITTABLE record, mechanically redacted.

    softfloat-record.py --revision REV [--note TEXT ...] --out FILE ARTEFACT [ARTEFACT ...]

ARTEFACT is a kept build artefact (`libfranken_dsp-<hash>.rlib` or `franken_dsp-<hash>.o`) with the `MANIFEST.txt` and
`rustc-vV.txt` that toolchain/src/softfloat-build.sh leaves beside it. The script runs toolchain/src/check-softfloat-symbols.py's
judge on each artefact in-process and writes ONE JSON record: the toolchain identity, the build deviations from the shipped build,
the commands (local paths shown as `<...>`), each artefact's size and SHA-256, and the checker's verdict, helper call sites,
f64 users with their call paths, and limits.

WHY A GENERATOR. The checker's own `--json` and the build manifest carry the machine's paths (`file`, `artifact-found-at`, the
cargo cache) and a worker id appears in them. A committed record must not (raw RCH output is not committable: it holds worker
addresses and local paths). Hand-editing such a record is how a path or a number gets through, so the record is derived, and the
derivation REFUSES to write a file that still contains a local path, a worker id or an IP address (exit 2, nothing written).

Consumer: docs/contracts/d02.md (the soft-float row cites the committed record) and tests/d02/test_softfloat_record.py, which
checks the committed record's shape, its redaction, its arithmetic and that RESULT.md quotes its numbers. Defect class: a
soft-float claim with no committed evidence, or a record that leaks the machine it came from. Deletion condition: the nightly
guest lane ingests device objects through a gate that writes this evidence itself.

Exit: 0 written; 2 refused (an unreadable input, a checker refusal, or a redaction failure).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
CHECKER_PATH = os.path.join(HERE, "check-softfloat-symbols.py")
BUILD_SCRIPT_PATH = os.path.join(HERE, "softfloat-build.sh")
SCHEMA = "ffw.d02.softfloat.record.v1"

# What a committed record must not contain. A worker id or an address identifies the fleet; a path identifies the machine.
FORBIDDEN = [
    (r"/Users/", "a local home path"), (r"/private/", "a local temporary path"), (r"/tmp/", "a temporary path"),
    (r"/scratch/", "a worker scratch path"), (r"/home/", "a home path"), (r"/var/", "a system path"), (r"\.rch", "an rch path"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "an IP address"),
    (r"\b(?:trj|ts1|hz3|hz4|ovh-a|mminiold)\b", "a worker id"), (r"\bvmi\d+\b", "a worker id"),
]

COMMANDS = {
    "rlib": "cd <root> && RCH_CANONICAL_PROJECT_ROOT=<root> RCH_REQUIRE_REMOTE=1 rch exec --job --worker <nightly worker> "
            "--result-dir build/softfloat/rlib -- sh toolchain/src/softfloat-build.sh rlib build/softfloat/rlib",
    "obj": "cd <root> && RCH_CANONICAL_PROJECT_ROOT=<root> RCH_REQUIRE_REMOTE=1 rch exec --job --worker <nightly worker> "
           "--result-dir build/softfloat/obj -- sh toolchain/src/softfloat-build.sh obj build/softfloat/obj",
}
CHECK_COMMAND = "python3 -B -I toolchain/src/check-softfloat-symbols.py --json build/softfloat/<mode>/<artefact>"


class RecordError(Exception):
    pass


def load_checker():
    spec = importlib.util.spec_from_file_location("softfloat_record_checker", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def parse_rustc(text: str) -> dict:
    """The compiler's identity from `rustc -vV` + `cargo -V` + the recorded CARGO_HOME line, without the path."""
    out: Dict[str, object] = {"rustc": None, "cargo": None}
    keep = {"commit-hash": "commit_hash", "commit-date": "commit_date", "host": "host", "release": "release", "LLVM version": "llvm_version"}
    for line in text.splitlines():
        if line.startswith("rustc "):
            out["rustc"] = line.strip()
        elif line.startswith("cargo "):
            out["cargo"] = line.strip()
        elif line.startswith("CARGO_HOME:"):
            out["cargo_home"] = ("the worker's rch cargo cache (path not recorded)" if "rch-cargo-cache" in line
                                 else "unset: the worker default (path not recorded)" if "unset" in line else "set by the caller (path not recorded)")
        elif ": " in line and line.split(": ", 1)[0] in keep:
            key, value = line.split(": ", 1)
            out[keep[key]] = value.strip()
    return out


def parse_manifest(text: str) -> dict:
    lines = text.splitlines()
    pick = lambda prefix: next((ln[len(prefix):].strip() for ln in lines if ln.startswith(prefix)), None)  # noqa: E731
    messages = next((ln.split()[0] for ln in lines if ln.endswith("cargo-messages.jsonl") and re.match(r"^[0-9a-f]{64}\s", ln)), None)
    return {"mode": pick("mode:"), "target": pick("target:"), "cargo_config": pick("cargo-config:"),
            "deviations": [ln[len("deviation:"):].strip() for ln in lines if ln.startswith("deviation:")],
            "cargo_messages_sha256": messages, "found_by": pick("found-by:")}


def reading(checker, name: str, data: bytes) -> dict:
    """The checker's result for one artefact, labelled by file name only (no path ever enters the judge)."""
    result = checker.judge([(name, data)])
    member = lambda label: label[label.index("[") + 1:-1] if "[" in label else label  # noqa: E731
    return {
        "verdict": result["verdict"], "exit_code": 1 if result["violations"] else 0, "root": result["root"],
        "code_sections": result["code_sections"], "reachable_sections": result["reachable_sections"],
        "objects_with_code": [{"member": member(o["object"]), "sha256": o["sha256"], "code_sections": o["code_sections"], "fp_abi": o["fp_abi"],
                              "executable_words_scanned": o["executable_words_scanned"], "soft_float_evidence": o["soft_float_evidence"]}
                             for o in result["objects"]],
        "non_code_members": [{"member": member(n["member"]), "bytes": n["bytes"], "sha256": n["sha256"], "sections": n["sections"]}
                             for n in result["non_code_members"]],
        "skipped_metadata_members": [member(s) for s in result["skipped_metadata_members"]],
        "f64_helper_call_sites_on_the_path": result["f64_helper_call_sites_on_the_path"],
        "f64_users_on_the_path": [{"function": u["function"], "helpers": u["helpers"], "section_process_copies": u["section_process_copies"],
                                   "call_path": u["call_path"]} for u in result["f64_users_on_the_path"]],
        "convert_functions_on_the_path": result["convert_functions_on_the_path"],
        "f64_users_not_reachable_from_the_root": result["f64_users_not_reachable_from_the_root"],
        "coarse_sections_on_the_path": result["coarse_sections_on_the_path"],
        "violations": result["violations"], "allowed_helpers": result["allowed"],
    }


def build_record(checker, revision: str, notes: List[str], artefacts: List[str]) -> dict:
    items, readings, rustc, manifests = [], {}, None, []
    for path in artefacts:
        directory, name = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
        try:
            data = read_bytes(path)
            manifest = parse_manifest(read_bytes(os.path.join(directory, "MANIFEST.txt")).decode("utf-8"))
            rustc_text = read_bytes(os.path.join(directory, "rustc-vV.txt")).decode("utf-8")
        except OSError as exc:
            raise RecordError(f"{name}: needs MANIFEST.txt and rustc-vV.txt beside it: {exc.strerror}") from exc
        parsed = parse_rustc(rustc_text)
        if rustc is not None and parsed != rustc:
            raise RecordError("the artefacts were built by different compilers; one record cannot describe both")
        rustc = parsed
        manifests.append(manifest)
        kind = "rlib" if name.endswith(".rlib") else "obj"
        items.append({"kind": kind, "name": name, "bytes": len(data), "sha256": sha256(data), "build_mode": manifest["mode"]})
        try:
            readings[name] = reading(checker, name, data)
        except checker.Refusal as refusal:
            raise RecordError(f"{name}: the checker refused it ({refusal.code}); a refusal is not a reading, so it is not recorded") from refusal
    same = {(m["target"], m["cargo_config"], tuple(m["deviations"]), m["found_by"]) for m in manifests}
    if len(same) != 1:
        raise RecordError("the artefacts were built with different targets, cargo configurations or deviations; one record cannot describe both")
    by_kind = {}
    for item in items:
        by_kind.setdefault(item["kind"], readings[item["name"]])
    rlib, obj = by_kind.get("rlib"), by_kind.get("obj")
    cross = {}
    if rlib and obj and rlib["objects_with_code"] and obj["objects_with_code"]:
        a, b = rlib["objects_with_code"][0]["sha256"], obj["objects_with_code"][0]["sha256"]
        cross = {"rlib_code_member_sha256": a, "separately_built_object_sha256": b, "byte_equal": a == b,
                 "meaning": "two separate cargo invocations produced the same machine code for franken-dsp" if a == b else
                            "the rlib's code member differs from the separately built object"}
    return {
        "schema": SCHEMA, "revision": revision, "notes": notes,
        "scope": "host reading of compiled object code for soft-float big-endian MIPS32 (mips-unknown-linux-musl); no device, no execution, no timing",
        "toolchain": rustc,
        "build": {"target": manifests[0]["target"], "cargo_config": manifests[0]["cargo_config"], "deviations": manifests[0]["deviations"],
                  "found_by": manifests[0]["found_by"], "modes": sorted({m["mode"] for m in manifests}),
                  "cargo_messages_sha256": {i["name"]: m["cargo_messages_sha256"] for i, m in zip(items, manifests)},
                  "build_script": "toolchain/src/softfloat-build.sh", "build_script_sha256": sha256(read_bytes(BUILD_SCRIPT_PATH))},
        "commands": {**{k: COMMANDS[k] for k in sorted({i["kind"] for i in items})}, "check": CHECK_COMMAND},
        "artefacts": items,
        "checker": {"script": "toolchain/src/check-softfloat-symbols.py", "sha256": sha256(read_bytes(CHECKER_PATH)),
                    "exit_codes": {"0": "PASS", "1": "FAIL", "2": "REFUSED", "3": "INTERNAL ERROR"}},
        "readings": readings, "cross_check": cross, "limits": checker.LIMITS,
    }


def redaction_problems(text: str) -> List[str]:
    return sorted({f"{why}: {m.group(0)!r}" for pattern, why in FORBIDDEN for m in re.finditer(pattern, text)})


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Write a redacted, committable record of a soft-float reading")
    parser.add_argument("artefacts", nargs="+", metavar="ARTEFACT", help="a kept .rlib or .o with MANIFEST.txt and rustc-vV.txt beside it")
    parser.add_argument("--revision", required=True, help="the repository revision the artefacts were built from")
    parser.add_argument("--note", action="append", default=[], help="a line of context for the record (repeatable)")
    parser.add_argument("--out", required=True, help="where to write the record")
    args = parser.parse_args(argv)
    try:
        record = build_record(load_checker(), args.revision, args.note, args.artefacts)
        text = json.dumps(record, indent=1, sort_keys=True) + "\n"
        problems = redaction_problems(text)
        if problems:
            raise RecordError("the record would leak what a committed record must not hold, so nothing was written:\n  " + "\n  ".join(problems))
    except RecordError as exc:
        print(f"softfloat-record: REFUSED\n{exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"softfloat-record: wrote {args.out} ({len(text)} bytes, sha256 {sha256(text.encode())[:16]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
