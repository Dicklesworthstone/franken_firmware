#!/usr/bin/env python3
"""Judge a captured `cargo test -p franken-update` log by TEST NAME (offline, stdlib only; it runs nothing).

    judge_log.py LOG [--root DIR]     judge LOG against the #[test] functions found under DIR/crates/franken-update
    judge_log.py --self-test          plant failures in synthetic logs and require each to be caught

Rules, the same as `tests/u01/judge_log.py`: a test counts only if its own line says `ok`; `FAILED` is a failure; a test that is `ignored` or does
not appear at all is blocked, never passed, and the totals (`test result:`) are never used. A name defined in two files must be run twice. Capture
BOTH streams (rch sends stdout to stderr). Exit: 0 all ok; 1 a failure; 3 only blocked names remain; 2 usage.

What a pass is: every Rust test of the crate passed centrally. It is not a device, a flash part or a big-endian guest.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from typing import Dict, List, Tuple

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")
_FN = re.compile(r"#\[test\][^{;]*?\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", re.S)


def source_tests(root: str) -> Dict[str, int]:
    """name -> number of definitions among the crate's #[test] functions."""
    names: Dict[str, int] = {}
    base = os.path.join(root, "crates", "franken-update")
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in ("target", "__pycache__"))
        for fname in sorted(filenames):
            if fname.endswith(".rs"):
                with open(os.path.join(dirpath, fname), encoding="utf-8") as f:
                    for name in _FN.findall(f.read()):
                        names[name] = names.get(name, 0) + 1
    return names


def log_results(text: str) -> Dict[str, List[str]]:
    seen: Dict[str, List[str]] = {}
    for raw in _ANSI.sub("", text).splitlines():
        m = _LINE.match(raw.strip())
        if m:
            seen.setdefault(m.group(1), []).append(m.group(2))
    return seen


def judge(text: str, required: Dict[str, int]) -> Tuple[int, List[str]]:
    seen = log_results(text)
    failed: List[str] = []
    blocked: List[str] = []
    ok = 0
    for name in sorted(required):
        statuses = [s for printed, ss in seen.items() if printed == name or printed.endswith("::" + name) for s in ss]
        if not statuses:
            blocked.append(f"{name}: not in the log")
        elif "FAILED" in statuses:
            failed.append(f"{name}: FAILED")
        elif "ignored" in statuses or len(statuses) < required[name]:
            blocked.append(f"{name}: {'ignored' if 'ignored' in statuses else f'{len(statuses)} of {required[name]} runs in the log'}")
        else:
            ok += 1
    lines = [f"FAIL    {m}" for m in failed] + [f"BLOCKED {m}" for m in blocked]
    verdict = 1 if failed else 3 if blocked else 0
    lines.append(f"U02 rust tests by name: {ok} ok, {len(failed)} failed, {len(blocked)} blocked of {len(required)} required"
                 + (" -> PASS" if verdict == 0 else " -> NOT QUALIFIED"))
    return verdict, lines


def synthetic_log(names: Dict[str, int], skip=(), fail=(), ignore=()) -> str:
    out = ["running tests"]
    for name in sorted(names):
        if name in skip:
            continue
        status = "FAILED" if name in fail else "ignored" if name in ignore else "ok"
        out += [f"test {name} ... {status}"] * names[name]
    out.append("test result: ok. totals are never used")
    return "\n".join(out) + "\n"


def self_test() -> int:
    with tempfile.TemporaryDirectory() as root:
        tdir = os.path.join(root, "crates", "franken-update", "tests")
        os.makedirs(tdir)
        with open(os.path.join(tdir, "a.rs"), "w", encoding="utf-8") as f:
            f.write("#[test]\nfn alpha() {}\n\n#[test]\n#[ignore]\nfn beta() {}\n\n#[test]\nfn gamma() {}\n")
        with open(os.path.join(tdir, "b.rs"), "w", encoding="utf-8") as f:
            f.write("#[test]\nfn gamma() {}\n")
        required = source_tests(root)
        assert required == {"alpha": 1, "beta": 1, "gamma": 2}, required
        problems: List[str] = []

        def expect(label: str, log: str, want: int) -> None:
            got, _ = judge(log, required)
            if got != want:
                problems.append(f"{label}: exit {got}, wanted {want}")

        expect("control: everything ok", synthetic_log(required), 0)
        expect("one failed test", synthetic_log(required, fail=("alpha",)), 1)
        expect("one absent test", synthetic_log(required, skip=("alpha",)), 3)
        expect("one ignored test", synthetic_log(required, ignore=("beta",)), 3)
        expect("a name defined twice but run once", synthetic_log(required).replace("test gamma ... ok\n", "", 1), 3)
        expect("a failure beats an absence", synthetic_log(required, skip=("alpha",), fail=("beta",)), 1)
        expect("a path-qualified name counts", synthetic_log(required).replace("test alpha ...", "test u02_vectors::alpha ..."), 0)
        expect("a suffix that is only part of a name does not count", synthetic_log(required, skip=("alpha",)) + "test notalpha ... ok\n", 3)
        expect("totals alone do not pass", "running 99 tests\ntest result: ok. 99 passed; 0 failed\n", 3)
        if problems:
            print("SELF-TEST FAILED:\n  " + "\n  ".join(problems))
            return 1
        print("self-test: 9 planted or control logs judged as intended")
        return 0


def main(argv: List[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    args = list(argv)
    if "--root" in args:
        i = args.index("--root")
        root = os.path.realpath(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        print(__doc__)
        return 2
    with open(args[0], encoding="utf-8", errors="replace") as f:
        verdict, lines = judge(f.read(), source_tests(root))
    print("\n".join(lines))
    return verdict


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
