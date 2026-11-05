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


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def cargo_problems(text, tests):
    """Did cargo itself report the replay target's tests passing?

    The command runs exactly one test target. A relay (RCH) writes cargo's stderr (`Finished`, `Running
    tests/...`) AFTER the test binary's stdout, so the order of the markers in the log carries no meaning and
    nothing here slices the log by position. Each marker is judged by how many times it appears in the whole
    log: exactly one `Running <target>`, one `running N tests`, one `test result:`, every expected test name once,
    and no block of any other target (a second target got in)."""
    text = ANSI.sub("", text)
    problems = []
    if "FAILED" in text or "panicked" in text:
        problems.append("the log reports a failure (FAILED or panicked)")

    started = re.findall(r"^\s*Running\s+(?:unittests\s+)?(\S+\.rs)\b", text, re.M)
    ours = [name for name in started if name == TARGET]
    others = [name for name in started if name != TARGET]
    if not ours:
        problems.append("the log has no `Running %s` line" % TARGET)
    elif len(ours) > 1:
        problems.append("the log has %d `Running %s` lines, expected exactly one" % (len(ours), TARGET))
    if others:
        problems.append("the log has a block for another target (%s); the command runs only %s" % (
            ", ".join(sorted(set(others))), TARGET))

    counts = re.findall(r"^\s*running (\d+) tests?\s*$", text, re.M)
    if len(counts) > 1:
        problems.append("cargo printed %d `running N tests` lines, expected exactly one" % len(counts))
    elif not counts or int(counts[0]) != len(tests):
        problems.append("cargo ran %s tests, expected %d" % (counts[0] if counts else "no", len(tests)))

    result_lines = re.findall(r"^\s*test result:.*$", text, re.M)
    if len(result_lines) != 1:
        problems.append("cargo printed %d `test result` lines, expected exactly one" % len(result_lines))
    result = re.search(
        r"^\s*test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
        text, re.M)
    if not result:
        problems.append("no `test result` line for %s" % TARGET)
    else:
        status = result.group(1)
        passed, failed, ignored, measured, filtered = (int(result.group(i)) for i in range(2, 7))
        if (status, passed, failed, ignored, measured, filtered) != ("ok", len(tests), 0, 0, 0, 0):
            problems.append("cargo reported %s, %d passed, %d failed, %d ignored, %d measured, %d filtered out; "
                            "wanted ok, %d, 0, 0, 0, 0" % (status, passed, failed, ignored, measured, filtered, len(tests)))

    for name in tests:
        seen = len(re.findall(r"(?<!\w)test %s \.\.\." % re.escape(name), text))
        if seen == 0:
            problems.append("cargo did not run the test %s" % name)
        elif seen > 1:
            problems.append("cargo ran the test %s %d times, expected once" % (name, seen))
    for name in sorted(set(re.findall(r"(?<!\w)test (\w+) \.\.\.", text)) - set(tests)):
        problems.append("cargo ran a test that is not in the replay's list: %s" % name)
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
        broken = record.get("broken")
        if not broken:
            problems.append("plant %s broke no scenario in the engine, so the replay cannot fail" % name)
            continue
        # "exactly the scenarios the model predicts" is a property of sets: the engine lists them in the
        # vector file's order and the model sorted, so order is not compared. A scenario named twice is
        # refused, so that comparing sets cannot hide it.
        if len(set(broken)) != len(broken):
            problems.append("plant %s: the engine names a scenario twice: %s" % (name, broken))
        if len(set(plants[name])) != len(plants[name]):
            problems.append("plant %s: the model names a scenario twice: %s" % (name, plants[name]))
        if set(broken) != set(plants[name]):
            problems.append("plant %s: the engine breaks %s, the model predicts %s (only the engine: %s; only the model: %s)" % (
                name, sorted(broken), sorted(plants[name]), sorted(set(broken) - set(plants[name])),
                sorted(set(plants[name]) - set(broken))))

    # the replay can fail at all
    corrupted = by_kind.get("corrupted", [])
    shown = ("wrong_number_reported", "wrong_code_reported", "dropped_details_reported",
             "null_for_empty_reported", "bare_refusal_is_an_empty_object", "reordered_sets_accepted",
             "one_id_missing_reported", "one_id_swapped_reported", "duplicate_reported")
    if len(corrupted) != 1 or not all(corrupted[0].get(field) is True for field in shown):
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
