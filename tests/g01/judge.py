#!/usr/bin/env python3
"""Judge the log of a central run of the G01 Rust replay (bead ffw-kh0).

The Rust integration test crates/franken-session/tests/g01_replay.rs prints one `G01-OBSERVED {json}`
line per result. This reads the cargo output of

    RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \\
        cargo test -p franken-session --test g01_replay --locked -- --nocapture --test-threads=1

and checks it against the vector file and the reference model, WITHOUT trusting the Rust's own
assertions: it re-compares every reported scenario, schedule count and planted-fault result with the
hand-written expectations and the model's predictions, and it requires that cargo itself reported the
expected tests passing. A log that is missing a record, carries an extra one, shows a mismatch, or
whose counts differ from the model's fails.

    python3 -B -I tests/g01/judge.py LOG [LOG ...]       exit 0 only if every check passes

It never runs cargo. A green verdict is evidence about the Rust only to the extent the log is the real
output of that command on the revision named in the receipt.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as ref  # noqa: E402

CASES = Path(__file__).resolve().parent / "cases.json"
MARKER = "G01-OBSERVED "
TARGET = "tests/g01_replay.rs"


def expected_tests():
    return json.loads(CASES.read_text(encoding="utf-8"))["replay"]["tests"]


def parse(text):
    """The OBSERVED records in order (anywhere in a line: --nocapture puts them after `test NAME ... `)."""
    records, bad = [], []
    for number, line in enumerate(text.splitlines(), 1):
        start = line.find(MARKER)
        if start < 0:
            continue
        try:
            records.append(json.loads(line[start + len(MARKER):]))
        except json.JSONDecodeError as error:
            bad.append("line %d: unreadable record (%s)" % (number, error))
    return records, bad


def cargo_problems(text, tests):
    """Did cargo itself report the replay target's tests passing?"""
    problems = []
    if "FAILED" in text or "panicked" in text:
        problems.append("the log reports a failure (FAILED or panicked)")
    start = text.find("Running " + TARGET)
    if start < 0:
        return problems + ["the log has no `Running %s` section" % TARGET]
    rest = text[start:]
    end = min((i for i in (rest.find("Running ", 1), rest.find("Doc-tests")) if i > 0), default=len(rest))
    section = rest[:end]
    running = re.search(r"running (\d+) tests?", section)
    if not running or int(running.group(1)) != len(tests):
        problems.append("cargo ran %s tests, expected %d" % (running.group(1) if running else "no", len(tests)))
    result = re.search(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", section)
    if not result:
        problems.append("no `test result` line for %s" % TARGET)
    else:
        status, passed, failed, ignored = result.group(1), int(result.group(2)), int(result.group(3)), int(result.group(4))
        if (status, passed, failed, ignored) != ("ok", len(tests), 0, 0):
            problems.append("cargo reported %s, %d passed, %d failed, %d ignored; wanted ok, %d, 0, 0" % (
                status, passed, failed, ignored, len(tests)))
    for name in tests:
        if not re.search(r"test %s \.\.\." % re.escape(name), section):
            problems.append("cargo did not run the test %s" % name)
    return problems


def judge_records(doc, records):
    """Compare the records with the vector file. Returns problems."""
    problems = []
    by_kind = {}
    for record in records:
        by_kind.setdefault(record.get("kind"), []).append(record)
    unknown = sorted(k for k in by_kind if k not in {"scenario", "schedule", "plant", "corrupted", "vectors"})
    if unknown:
        problems.append("unknown record kinds: %s" % unknown)

    # scenarios: each exactly once, no mismatch, and every step run
    wanted = {s["id"]: len(ref.expand(s["steps"])) for s in doc["scenarios"]}
    seen = {}
    for record in by_kind.get("scenario", []):
        seen.setdefault(record.get("id"), []).append(record)
    for sid in sorted(set(wanted) - set(seen)):
        problems.append("scenario %s was not reported" % sid)
    for sid in sorted(set(seen) - set(wanted)):
        problems.append("scenario %s is not in the vector file" % sid)
    for sid, records_for in sorted(seen.items()):
        if sid not in wanted:
            continue
        if len(records_for) != 1:
            problems.append("scenario %s was reported %d times" % (sid, len(records_for)))
        record = records_for[0]
        if record.get("mismatches"):
            problems.append("scenario %s: the engine disagrees: %s" % (sid, record["mismatches"][:2]))
        if record.get("steps") != wanted[sid]:
            problems.append("scenario %s ran %s steps, the vector file has %d" % (sid, record.get("steps"), wanted[sid]))

    # schedule: every recorded run reproduced exactly, from the real engine
    runs = {(r["seed"], r["u"], r["max_offset"], r["skew_holder"]): r["counts"] for r in doc["schedule"]["runs"]}
    got = {}
    for record in by_kind.get("schedule", []):
        key = (record.get("seed"), record.get("u"), record.get("max_offset"), record.get("skew_holder"))
        got.setdefault(key, []).append(record)
    for key in sorted(set(runs) - set(got), key=str):
        problems.append("schedule run %s was not reported" % (key,))
    for key in sorted(set(got) - set(runs), key=str):
        problems.append("schedule run %s is not in the vector file" % (key,))
    for key, records_for in sorted(got.items(), key=lambda kv: str(kv[0])):
        if key not in runs:
            continue
        if len(records_for) != 1:
            problems.append("schedule run %s was reported %d times" % (key, len(records_for)))
        record = records_for[0]
        if record.get("error") is not None:
            problems.append("schedule run %s: the engine's driver failed: %s" % (key, record["error"]))
        elif record.get("counts") != runs[key]:
            diff = {k: (runs[key].get(k), (record.get("counts") or {}).get(k)) for k in runs[key]
                    if runs[key].get(k) != (record.get("counts") or {}).get(k)}
            problems.append("schedule run %s: model vs engine counts differ: %s" % (key, diff))
        if record.get("matches") is not True:
            problems.append("schedule run %s: the Rust did not report a match" % (key,))

    # planted faults: each reported once, noticed, and breaking exactly what the model says
    plants = {p["name"]: p["fails"] for p in doc["plants"]}
    reported = {}
    for record in by_kind.get("plant", []):
        reported.setdefault(record.get("name"), []).append(record)
    for name in sorted(set(plants) - set(reported)):
        problems.append("plant %s was not reported" % name)
    for name in sorted(set(reported) - set(plants)):
        problems.append("plant %s is not in the vector file" % name)
    for name, records_for in sorted(reported.items()):
        if name not in plants:
            continue
        if len(records_for) != 1:
            problems.append("plant %s was reported %d times" % (name, len(records_for)))
        record = records_for[0]
        if not record.get("broken"):
            problems.append("plant %s broke no scenario in the engine, so the replay cannot fail" % name)
        if record.get("broken") != plants[name]:
            problems.append("plant %s: the engine breaks %s, the model predicts %s" % (name, record.get("broken"), plants[name]))

    # the replay can fail at all
    corrupted = by_kind.get("corrupted", [])
    if len(corrupted) != 1 or not (corrupted[0].get("wrong_number_reported") and corrupted[0].get("wrong_code_reported")):
        problems.append("the replay did not show that a corrupted expectation is reported: %s" % corrupted)

    # the vector file the Rust read is the one the model has
    meta = by_kind.get("vectors", [])
    expected_meta = {
        "scenarios": len(doc["scenarios"]),
        "step_entries": sum(len(s["steps"]) for s in doc["scenarios"]),
        "schedule_runs": len(doc["schedule"]["runs"]),
        "plants": len(doc["plants"]),
    }
    if len(meta) != 1 or {k: meta[0].get(k) for k in expected_meta} != expected_meta:
        problems.append("the vector file the Rust read differs from this one: %s vs %s" % (meta, expected_meta))
    return problems


def judge(doc, texts, tests=None):
    """All problems with the logs (a list of strings); empty means the Rust half passed."""
    tests = tests if tests is not None else expected_tests()
    text = "\n".join(texts)
    records, bad = parse(text)
    return bad + cargo_problems(text, tests) + judge_records(doc, records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("logs", nargs="+", metavar="LOG", help="cargo test output of the central run")
    parser.add_argument("--vectors", type=Path, default=ref.DEFAULT_VECTORS)
    args = parser.parse_args(argv)
    doc = ref.load(args.vectors)
    texts = []
    for path in args.logs:
        try:
            texts.append(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError as error:
            print("FAIL cannot read %s: %s" % (path, error))
            return 1
    problems = judge(doc, texts)
    for problem in problems:
        print("FAIL %s" % problem)
    n = len(doc["scenarios"])
    print("Rust log: %d scenarios, %d schedule runs, %d plants: %s" % (
        n, len(doc["schedule"]["runs"]), len(doc["plants"]), "FAIL" if problems else "PASS"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
