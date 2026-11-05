#!/usr/bin/env python3
"""Read-only scan of the pinned Asupersync revision for 64-bit atomics (P05 / ffw-ipz).

    scan_upstream.py CLONE REV            print the scan as JSON
    scan_upstream.py CLONE REV --check    compare the scan with tests/p05/upstream_scan.json (exit 0/1)

It reads git OBJECTS only (`git ls-tree`, `git cat-file --batch`). It checks nothing out, writes nothing to the
clone and builds nothing. The result is a STATIC SOURCE SIGNAL: counts of names and of method tokens in text.
It does not know which receiver a method is called on, so every method count is an upper bound over all
atomic and non-atomic receivers in the files that name a 64-bit atomic. It is an input to a classification
(docs/contracts/p05.md), not a classification.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
FIXTURE = os.path.join(HERE, "upstream_scan.json")
SCHEMA = "ffw.p05.upstream_scan.v1"
EXPECTED_REV = "8940119023c0e01b4d6d3e2c1399f41417c2ad24"

NAME = re.compile(r"\bAtomic[UI]64\b")
U64 = re.compile(r"\bAtomicU64\b")
I64 = re.compile(r"\bAtomicI64\b")
DIRECT = re.compile(r"(?:std|core)::sync::atomic::Atomic[UI]64\b")
DIRECT_BRACED = re.compile(r"use\s+(?:::)?(?:std|core)::sync::atomic::\{[^}]*\bAtomic[UI]64\b[^}]*\}", re.S)
FACADE = re.compile(r"crate::sync::atomic|asupersync::sync::atomic")
TESTISH = re.compile(r"(^|/)tests?/|_tests?\.rs$|_tests?/|e2e|inline_tests|(^|/)benches/|(^|/)fuzz/")
METHODS = ("load", "store", "swap", "compare_exchange_weak", "compare_exchange", "fetch_add", "fetch_sub",
           "fetch_max", "fetch_min", "fetch_or", "fetch_and", "fetch_xor", "fetch_update", "into_inner", "get_mut")
METHOD_RX = re.compile(r"\.(" + "|".join(METHODS) + r")\(")
STATIC_RX = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?static\s+(\w+)\s*:\s*(?:[\w:]*::)?Atomic([UI])64\b")
# Whole-word tests on the underscore-separated parts of the name ("RUNTIME" is not "TIME").
CLOCK_NAME = re.compile(r"(^|_)(NOW|NANOS|CLOCK|OFFSET|TICK|TIME)(_|$)|_NS$|_MS$")
ID_NAME = re.compile(r"(^|_)(NEXT|COUNTER|ID|SEQ|GENERATION|ITER|NONCE|SEED)(_|$)")
TEST_NAME = re.compile(r"(^|_)TEST(_|$)")


def git(clone: str, *args: str) -> bytes:
    out = subprocess.run(["git", "-C", clone, *args], capture_output=True)
    if out.returncode != 0:
        raise SystemExit(out.stderr.decode("utf-8", "replace"))
    return out.stdout


def blobs(clone: str, rev: str) -> List[Tuple[str, str]]:
    listing = git(clone, "ls-tree", "-r", "-z", rev).decode("utf-8", "replace")
    rows = []
    for entry in listing.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        mode, kind, sha = meta.split()
        if kind == "blob" and path.endswith(".rs"):
            rows.append((sha, path))
    return rows


def stream(clone: str, shas: List[str]) -> Dict[str, str]:
    """One `git cat-file --batch` process for every blob."""
    proc = subprocess.run(["git", "-C", clone, "cat-file", "--batch"], input=("\n".join(shas) + "\n").encode(),
                          capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.decode("utf-8", "replace"))
    data, pos, out = proc.stdout, 0, {}
    for sha in shas:
        nl = data.index(b"\n", pos)
        header = data[pos:nl].decode().split()
        size = int(header[2])
        out[sha] = data[nl + 1:nl + 1 + size].decode("utf-8", "replace")
        pos = nl + 1 + size + 1
    return out


def top(path: str) -> str:
    parts = path.split("/")
    if parts[0] == "src" and len(parts) > 1:
        return "src/" + parts[1].replace(".rs", "")
    return parts[0]


def scan(clone: str, rev: str) -> Dict[str, Any]:
    if git(clone, "cat-file", "-t", rev).strip() != b"commit":
        raise SystemExit(f"{rev} is not a commit in {clone}")
    rows = blobs(clone, rev)
    text = stream(clone, [sha for sha, _ in rows])
    files = {path: text[sha] for sha, path in rows}

    all_mentions = all_files = 0
    src_rs = src_files = src_mentions = src_u64 = src_i64 = src_via_facade = src_testish = 0
    direct_src: List[str] = []
    outside: Dict[str, Dict[str, int]] = {}
    areas: Dict[str, Dict[str, int]] = {}
    methods = {m: 0 for m in METHODS}
    fences = 0
    statics: List[List[Any]] = []

    for path in sorted(files):
        body = files[path]
        n = len(NAME.findall(body))
        in_src = path.startswith("src/")
        if in_src:
            src_rs += 1
        if not n:
            continue
        all_mentions += n
        all_files += 1
        if in_src:
            src_files += 1
            src_mentions += n
            src_u64 += len(U64.findall(body))
            src_i64 += len(I64.findall(body))
            if FACADE.search(body):
                src_via_facade += 1
            if TESTISH.search(path):
                src_testish += 1
            if DIRECT.search(body) or DIRECT_BRACED.search(body):
                direct_src.append(path)
            for m in METHOD_RX.finditer(body):
                methods[m.group(1)] += 1
            fences += len(re.findall(r"\bfence\(", body))
            a = areas.setdefault(top(path), {"mentions": 0, "files": 0, "test_named_files": 0})
            a["mentions"] += n
            a["files"] += 1
            a["test_named_files"] += 1 if TESTISH.search(path) else 0
            for line_no, line in enumerate(body.splitlines(), 1):
                m = STATIC_RX.match(line)
                if m:
                    name = m.group(1)
                    if TESTISH.search(path) or TEST_NAME.search(name):
                        cls = "test_only"
                    elif CLOCK_NAME.search(name):
                        cls = "clock"
                    elif ID_NAME.search(name):
                        cls = "identifier_or_counter"
                    else:
                        cls = "statistic"
                    statics.append([path, line_no, name, "u64" if m.group(2) == "U" else "i64", cls])
        else:
            o = outside.setdefault(top(path), {"mentions": 0, "files": 0, "direct_std_import_files": 0})
            o["mentions"] += n
            o["files"] += 1
            if DIRECT.search(body) or DIRECT_BRACED.search(body):
                o["direct_std_import_files"] += 1

    by_class: Dict[str, int] = {}
    for row in statics:
        by_class[row[4]] = by_class.get(row[4], 0) + 1
    # An area whose every file is test-named is reported once, in aggregate, so the ranking shows modules.
    test_only = {k: v for k, v in areas.items() if v["test_named_files"] == v["files"]}
    modules = {k: v for k, v in areas.items() if k not in test_only}
    ranked = sorted(modules.items(), key=lambda kv: (-kv[1]["mentions"], kv[0]))
    return {
        "schema": SCHEMA,
        "revision": rev,
        "method": "git ls-tree + git cat-file --batch on the object database; nothing checked out or written",
        "caveat": "static text signal; method counts are upper bounds over every receiver in the files that "
                  "name a 64-bit atomic",
        "all_rs_files": len(files),
        "repo_wide": {"files_naming_a_64bit_atomic": all_files, "mentions": all_mentions},
        "src": {
            "rs_files": src_rs,
            "files_naming_a_64bit_atomic": src_files,
            "mentions": src_mentions,
            "atomic_u64_mentions": src_u64,
            "atomic_i64_mentions": src_i64,
            "files_naming_the_crate_facade": src_via_facade,
            "test_named_files_among_them": src_testish,
            "files_with_a_direct_core_or_std_path": sorted(direct_src),
        },
        "outside_src": {k: outside[k] for k in sorted(outside)},
        "areas_top": [{"area": k, **v} for k, v in ranked[:40]],
        "module_area_count": len(ranked),
        "test_only_areas": {"areas": len(test_only), "files": sum(v["files"] for v in test_only.values()),
                            "mentions": sum(v["mentions"] for v in test_only.values())},
        "methods_upper_bound": {m: methods[m] for m in METHODS},
        "fence_calls_in_those_files": fences,
        "statics": {"total": len(statics), "by_class": {k: by_class[k] for k in sorted(by_class)}, "rows": statics},
    }


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    clone, rev = argv[0], argv[1]
    if "--check" in argv[2:] and rev != EXPECTED_REV:
        print(f"the pinned fixture is for {EXPECTED_REV}, not {rev}", file=sys.stderr)
        return 2
    result = scan(clone, rev)
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"
    if "--check" in argv[2:]:
        with open(FIXTURE, encoding="utf-8") as f:
            pinned = f.read()
        if pinned == text:
            print("upstream scan reproduces tests/p05/upstream_scan.json exactly")
            return 0
        print("upstream scan DIFFERS from tests/p05/upstream_scan.json", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
