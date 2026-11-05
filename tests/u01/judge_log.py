#!/usr/bin/env python3
"""Judge a captured `cargo test -p franken-journal` log by TEST NAME (offline, stdlib only; it runs nothing).

    judge_log.py LOG [--root DIR]     judge LOG against the #[test] functions found under DIR/crates/franken-journal
    judge_log.py --self-test          plant failures in synthetic logs and require each to be caught

Why this exists: the process-restart proof of U01 (`tests/u01_process.rs`, names `u01_proc_*`) runs on the central worker as an
ordinary integration test, because the example binary it drives is built there for the worker's OS and cannot be executed by
`tests/u01/e2e.py` on another host. Its result therefore reaches us only as a test log. Capture BOTH streams (rch sends stdout
to stderr).

Rules: a test counts only if its own line says `ok`. `FAILED` is a failure. A test that is `ignored` or does not appear at all
is blocked, never passed, and totals (`test result:`) are never used. One failure is read as BLOCKED, not as a defect: a test
whose panic message carries `U01_PROC_BLOCKED` (the `journal_crash` example was not built where the test looked for it), because
then the proof did not run. There is no fallback to a stand-in. The five `u01_proc_*` tests are required even if the
source scan does not find them, so a tree without the process proof cannot pass. Exit: 0 all ok; 1 a failure; 3 only blocked
names remain; 2 usage.

What a pass is: every Rust test of the crate passed centrally, including the real-process restart cases. It is not a power cut,
not flash, and not a device.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from typing import Dict, List, Tuple

REQUIRED_PROCESS_TESTS = (
    "u01_proc_a_clean_run_commits_every_step_and_a_fresh_process_recovers_the_exact_reference_bytes",
    "u01_proc_a_process_killed_at_sampled_bytes_recovers_exactly_the_old_or_the_new_state",
    "u01_proc_sigkill_after_an_acknowledged_step_recovers_exactly_the_old_or_the_new_state",
    "u01_proc_every_hostile_image_recovers_in_a_real_process_as_the_reference_says",
    "u01_proc_the_old_or_new_check_rejects_a_state_that_is_neither",
)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")
_THREAD = re.compile(r"thread '([^']+)'(?: \(\d+\))? panicked")
_HEADER = re.compile(r"^---- (\S+) stdout ----$")
BLOCKED_MARKER = "U01_PROC_BLOCKED"
_FN = re.compile(r"#\[test\][^{;]*?\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", re.S)
RANK = {"ok": 0, "ignored": 1, "FAILED": 2}


def source_tests(root: str) -> Dict[str, int]:
    """name -> number of definitions among the crate's #[test] functions."""
    names: Dict[str, int] = {}
    base = os.path.join(root, "crates", "franken-journal")
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in ("target", "__pycache__"))
        for fname in sorted(filenames):
            if fname.endswith(".rs"):
                with open(os.path.join(dirpath, fname), encoding="utf-8") as f:
                    for name in _FN.findall(f.read()):
                        names[name] = names.get(name, 0) + 1
    return names


def log_results(text: str) -> Tuple[Dict[str, List[str]], set]:
    """(test name as printed -> statuses seen, names of tests whose panic carried the blocked marker)."""
    seen: Dict[str, List[str]] = {}
    marked: set = set()
    current = ""
    for raw in _ANSI.sub("", text).splitlines():
        line = raw.strip()
        m = _LINE.match(line)
        if m:
            seen.setdefault(m.group(1), []).append(m.group(2))
            continue
        for rx in (_HEADER, _THREAD):
            h = rx.search(line)
            if h:
                current = h.group(1)
        if BLOCKED_MARKER in line and current:
            marked.add(current)
    return seen, marked


def judge(text: str, required: Dict[str, int]) -> Tuple[int, List[str]]:
    seen, marked = log_results(text)
    failed: List[str] = []
    blocked: List[str] = []
    ok = 0
    for name in sorted(required):
        statuses = [s for printed, ss in seen.items() if printed == name or printed.endswith("::" + name) for s in ss]
        if not statuses:
            blocked.append(f"{name}: not in the log")
        elif "FAILED" in statuses and any(m == name or m.endswith("::" + name) for m in marked):
            blocked.append(f"{name}: the journal_crash example was absent, so the proof did not run")
        elif "FAILED" in statuses:
            failed.append(f"{name}: FAILED")
        elif "ignored" in statuses or len(statuses) < required[name]:
            blocked.append(f"{name}: {'ignored' if 'ignored' in statuses else f'{len(statuses)} of {required[name]} runs in the log'}")
        else:
            ok += 1
    lines = [f"FAIL    {m}" for m in failed] + [f"BLOCKED {m}" for m in blocked]
    verdict = 1 if failed else 3 if blocked else 0
    lines.append(f"U01 rust tests by name: {ok} ok, {len(failed)} failed, {len(blocked)} blocked of {len(required)} required"
                 + (" -> PASS" if verdict == 0 else " -> NOT QUALIFIED"))
    return verdict, lines


def required_for(root: str) -> Dict[str, int]:
    required = source_tests(root)
    for name in REQUIRED_PROCESS_TESTS:
        required.setdefault(name, 1)
    return required


# --------------------------------------------------------------------------------------------------- self-test

def nocapture_log(names: Dict[str, int], marked=(), plain_fail=()) -> str:
    """The shape of a `cargo test -- --nocapture` log: panic text printed live (thread id after the name, the message on the
    next line, blank lines, a backtrace note), no `---- name stdout ----` blocks, then the summary lines."""
    out = ["running tests"]
    for name in marked:
        out += ["", f"thread '{name}' (3770299) panicked at crates/franken-journal/tests/u01_process.rs:140:5:",
                f"{BLOCKED_MARKER}: no examples/journal_crash within eight levels above the test executable /x/out/u01_process-h",
                "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"]
    for name in plain_fail:
        out += ["", f"thread '{name}' (3770301) panicked at crates/franken-journal/tests/u01_process.rs:300:9:",
                "assertion `left == right` failed: u01 s2: the file after a clean run must equal the reference's final medium"]
    out.append("error: test failed, to rerun pass `-p franken-journal --test u01_process`")
    for name in sorted(names):
        status = "FAILED" if name in marked or name in plain_fail else "ok"
        for _ in range(names[name]):
            out.append(f"test {name} ... {status}")
    out.append("test result: FAILED. 1 passed; 4 failed; 0 ignored")
    return "\n".join(out) + "\n"


def synthetic_log(names: Dict[str, int], skip=(), fail=(), ignore=(), absent_example=()) -> str:
    out = ["running tests"]
    for name in sorted(names):
        if name in skip:
            continue
        status = "FAILED" if name in fail or name in absent_example else "ignored" if name in ignore else "ok"
        for _ in range(names[name]):
            out.append(f"test {name} ... {status}")
    out.append("test result: ok. totals are never used")
    if absent_example:
        out.append("failures:")
        for name in absent_example:
            out += [f"---- {name} stdout ----", f"thread '{name}' panicked at tests/u01_process.rs:142:5:",
                    f"{BLOCKED_MARKER}: the journal_crash example is not built at target/debug/examples/journal_crash"]
    return "\n".join(out) + "\n"


def self_test() -> int:
    with tempfile.TemporaryDirectory() as root:
        tdir = os.path.join(root, "crates", "franken-journal", "tests")
        os.makedirs(tdir)
        with open(os.path.join(tdir, "a.rs"), "w", encoding="utf-8") as f:
            f.write("#[test]\nfn alpha() {}\n\n#[test]\n#[ignore]\nfn beta() {}\n\n#[test]\nfn gamma() {}\n")
        with open(os.path.join(tdir, "b.rs"), "w", encoding="utf-8") as f:
            f.write("#[test]\nfn gamma() {}\n")  # the same name in a second file: two runs are required
        required = required_for(root)
        assert required["gamma"] == 2 and "alpha" in required and set(REQUIRED_PROCESS_TESTS) <= set(required)
        problems: List[str] = []

        def expect(label: str, log: str, want: int) -> None:
            got, _ = judge(log, required)
            if got != want:
                problems.append(f"{label}: exit {got}, wanted {want}")

        expect("control: everything ok", synthetic_log(required), 0)
        expect("one failed test", synthetic_log(required, fail=("alpha",)), 1)
        expect("one absent test", synthetic_log(required, skip=("alpha",)), 3)
        expect("one ignored test", synthetic_log(required, ignore=("beta",)), 3)
        expect("the process proof missing (a log from before it)", synthetic_log(required, skip=REQUIRED_PROCESS_TESTS), 3)
        expect("a process test failed", synthetic_log(required, fail=(REQUIRED_PROCESS_TESTS[1],)), 1)
        expect("a name defined twice but run once", synthetic_log(required).replace("test gamma ... ok\n", "", 1), 3)
        expect("a failure beats an absence", synthetic_log(required, skip=("alpha",), fail=("beta",)), 1)
        expect("a path-qualified name counts", synthetic_log(required).replace("test alpha ...", "test tests::alpha ..."), 0)
        expect("a suffix that is only part of a name does not count", synthetic_log(required, skip=("alpha",)) + "test notalpha ... ok\n", 3)
        expect("totals alone do not pass", "running 99 tests\ntest result: ok. 99 passed; 0 failed\n", 3)
        expect("the example absent: the process tests fail with the marker -> blocked, not a defect",
               synthetic_log(required, absent_example=REQUIRED_PROCESS_TESTS[:4]), 3)
        expect("a marker for one test does not excuse another failure",
               synthetic_log(required, absent_example=REQUIRED_PROCESS_TESTS[:1], fail=("alpha",)), 1)
        expect("a process test failing WITHOUT the marker is a defect", synthetic_log(required, fail=(REQUIRED_PROCESS_TESTS[0],)), 1)
        expect("--nocapture: four process tests panic with the marker -> blocked, not failed",
               nocapture_log(required, marked=REQUIRED_PROCESS_TESTS[:4]), 3)
        expect("--nocapture: the same four panics WITHOUT the marker are failures",
               nocapture_log(required, plain_fail=REQUIRED_PROCESS_TESTS[:4]), 1)
        expect("--nocapture: a marked test and a plainly failing one -> the plain failure wins",
               nocapture_log(required, marked=REQUIRED_PROCESS_TESTS[:1], plain_fail=REQUIRED_PROCESS_TESTS[1:2]), 1)
        expect("the marker in the log with every test ok changes nothing",
               synthetic_log(required) + f"---- zzz stdout ----\n{BLOCKED_MARKER}: stray\n", 0)
        # The process proof must be required even when the tree has no source for it.
        bare = source_tests(root)
        if any(name in bare for name in REQUIRED_PROCESS_TESTS):
            problems.append("the synthetic tree should not define the process tests")
        if problems:
            print("SELF-TEST FAILED:\n  " + "\n  ".join(problems))
            return 1
        print("self-test: 18 planted or control logs judged as intended")
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
        verdict, lines = judge(f.read(), required_for(root))
    print("\n".join(lines))
    return verdict


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
