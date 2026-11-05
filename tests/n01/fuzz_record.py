#!/usr/bin/env python3
"""Verify the committed N01 fuzz run record without its logs (docs/contracts/n01.md section 11).

    fuzz_record.py [DIR ...]     DIR holds record.json; default: the records docs/contracts/n01.md cites
                                 exit 0 only if every record verifies; one JSON line per record is printed

Why this exists: the raw libFuzzer and RCH logs of a central run carry worker paths and thousands of lines and are not committed. What
is committed is `record.json` (the sha256 of each log, the judge's outputs, the central lines, the predictions made before the run
and what was observed), with the 65-byte crash input the planted bug produced kept in it as hex so that it can be re-decoded. This
module is the consumer of that record. It checks that the record agrees with itself, that every number the contract may cite is in it, and
what it can re-derive from the repository alone:

  * the seed counts the judge read equal the counts re-derived from the committed vectors (so the record is for these vectors);
  * the crash input is, by the independent Python decoder, an accepted packet whose payload is the length the panic message named,
    inside the planted band, and its sha256 and SHA-1 are the ones recorded and the artifact name carries;
  * every clean run executed at least the judge's floor, for the whole budget, with no crash and no judge problem;
  * the remove-the-plant control failed as it must: the clean stream_decode log, judged as a control, is refused;
  * each prediction's verdict is recomputed from the observed value and a threshold fixed here (mail 5092), so a miss cannot be
    turned into a hit after the fact;
  * the bytes the run saw (the fuzz crate, the parsers, the vectors, the lock) are compared with the tree: each file that differs
    is PRINTED as a warning (stderr, and the "warnings" list of the JSON line) and the exit code is unchanged. A printed
    mismatch means the run no longer covers the current source; it is not a failure of the record.

It does not read a log, run a fuzzer or run Rust; it cannot show that the run happened, only that the record is whole and
consistent with the repository. The central log hashes are the supervisor's.
"""

import functools
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzz_judge as fj  # noqa: E402
import reference_frames as rf  # noqa: E402

SCHEMA = "ffw-n01-fuzz-run-record-1"
BUDGET = 120
RESULTS = Path("toolchain") / "results" / "n01"
FUZZ = "crates/franken-stream/fuzz"
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
LOGS = ("build.clean.log", "corpus-counts.txt", "lock-after.txt", "lock-before.txt", "negotiation_finish.clean.log",
        "negotiation_respond.clean.log", "rc.txt", "seeds.log", "seeds.stderr", "stream_decode.clean.log",
        "stream_decode.control.log", "stream_receiver.clean.log", "versions.txt")
CENTRAL = ("clippy", "clippy-control", "test", "test-control")
STEPS = ("seeds", "build-clean", "control") + tuple("clean-" + t for t in fj.TARGETS)
# Fixed by mail 5092, before the run. The verdicts in a record are recomputed against these, never read back.
PREDICTED_COVERAGE_ABOVE = 139
PREDICTED_CORPUS_AT_LEAST = 28
PREDICTED_CRASH_EXECUTIONS = (100_000, 2_000_000)
PREDICTED_CRASH_INPUT_MAX = 256
PREDICTION_IDS = ("seeds", "inited-coverage", "inited-corpus", "crash-executions", "panic-length", "crash-input-size", "refutation")
PERSONAL = ("/Users/", "/private/", "/home/", "C:\\")
UNSCANNED_PARTS = ("/target/", "/artifacts/", "__pycache__")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def seed_counts(root):
    """What `seed::all()` writes per target, re-derived from the committed vectors (the same rules, in Python)."""
    return dict(_seed_counts(str(root)))


@functools.lru_cache(maxsize=None)
def _seed_counts(root):
    vdir = Path(root) / "crates" / "franken-stream" / "tests" / "vectors"
    wire = json.loads((vdir / "n01_wire_vectors.json").read_text(encoding="utf-8"))
    neg = json.loads((vdir / "n01_negotiation_vectors.json").read_text(encoding="utf-8"))
    known = {bytes.fromhex(v["wire_hex"]) for v in wire["vectors"]}
    accepted = sum(1 for v in wire["vectors"] if v["expect"] == "ACCEPT")
    scenario_datagrams = 0
    for scenario in wire["scenarios"]:
        for step in scenario["steps"]:
            if step["op"] == "datagram":
                datagram = bytes.fromhex(step["wire_hex"])
                if datagram not in known:
                    known.add(datagram)
                    scenario_datagrams += 1
    rejections = neg["rejections"]
    return tuple({
        "stream_decode": len(wire["vectors"]) + 2 * accepted + scenario_datagrams,
        "stream_receiver": len(wire["scenarios"]),
        "negotiation_respond": 2 * len(neg["negotiations"]) + sum(1 for r in rejections if r["op"] == "respond"),
        "negotiation_finish": 2 * len(neg["negotiations"]) + sum(1 for r in rejections if r["op"] == "finish"),
    }.items())


def tracked_inputs(root):
    """The files whose bytes the record binds: the fuzz crate, the two parser sources, the manifest and the vectors."""
    root = Path(root)
    found = {}
    for prefix, pattern in (("crates/franken-stream", "Cargo.toml"), ("crates/franken-stream/src", "lib.rs"),
                            ("crates/franken-stream/src", "negotiation.rs"), ("crates/franken-stream/tests/vectors", "*.json"),
                            (FUZZ, "**/*")):
        for path in sorted((root / prefix).glob(pattern)):
            rel = path.relative_to(root).as_posix()
            if path.is_file() and not any(part in "/" + rel for part in UNSCANNED_PARTS):
                found[rel] = path
    return found


def _get(obj, *path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def _scope(rec, need):
    scope = rec.get("scope") or {}
    need(scope.get("kind") == "smoke", "the scope is not a smoke run")
    need(scope.get("budget_seconds") == BUDGET, "the budget is not %d s" % BUDGET)
    need(scope.get("soak") is False, "the record claims a soak")
    need(scope.get("hardware") is False, "the record claims hardware")
    need(scope.get("targets") == len(fj.TARGETS), "the record does not cover all %d targets" % len(fj.TARGETS))
    opens = rec.get("open")
    need(isinstance(opens, list) and any(str(x).startswith("No soak") for x in opens), "the record does not say that nothing is soaked")


def _hashes(rec, need):
    names = [row.get("file") for row in rec.get("fuzz_logs") or []]
    need(sorted(names) == sorted(LOGS), "the log hash table is not exactly the 13 files of the job's result directory")
    need(len(set(names)) == len(names), "a log is listed twice")
    for row in rec.get("fuzz_logs") or []:
        need(HEX64.fullmatch(str(row.get("sha256"))) is not None, "log %s has no sha256" % row.get("file"))
        need(isinstance(row.get("bytes"), int) and row["bytes"] > 0, "log %s has no size" % row.get("file"))
    central = rec.get("central_lines") or []
    need(sorted(row.get("name") for row in central) == sorted(CENTRAL), "the central lines are not clippy, clippy-control, test and test-control")
    for row in central:
        need(row.get("exit_code") == 0, "central line %s did not exit 0" % row.get("name"))
        need(HEX64.fullmatch(str(row.get("log_sha256"))) is not None, "central line %s has no log sha256" % row.get("name"))
        if row.get("name", "").startswith("test"):
            need(row.get("failed") == 0 and isinstance(row.get("passed"), int) and row["passed"] > 0, "central line %s: tests failed or none ran" % row.get("name"))
    job = rec.get("job") or {}
    need(job.get("exit_code") == 0, "the job did not exit 0")
    need(HEX64.fullmatch(str(job.get("script_sha256"))) is not None and HEX64.fullmatch(str(job.get("log_sha256"))) is not None, "the job has no script or log sha256")
    steps = job.get("steps") or []
    need([s.get("step") for s in steps] == list(STEPS), "the job's steps are not seeds, build, control and the four clean runs in order")
    for s in steps:
        want = 1 if s.get("step") == "control" else 0
        need(s.get("rc") == want, "step %s ended %s, expected %d%s" % (s.get("step"), s.get("rc"), want, " (the fuzzer exits non-zero on a crash)" if want else ""))
    need(HEX64.fullmatch(str(_get(rec, "driver_notes", "sha256"))) is not None, "the driver notes have no sha256")
    need(HEX64.fullmatch(str(_get(rec, "first_run", "control_log_sha256"))) is not None, "the first run's control log has no sha256")
    need(_get(rec, "first_run", "crashes") == 0, "the first run is not recorded as the run that found nothing")


def _judge(rec, crash, root, need):
    counts = seed_counts(root)
    seeds = _get(rec, "judge", "seeds") or {}
    out = seeds.get("output") or {}
    need(seeds.get("exit_code") == 0 and out.get("problems") == [], "the seed judge did not pass")
    need(out.get("seed_files") == counts, "the seed counts the judge read are not those of the committed vectors %s" % counts)
    ctl = _get(rec, "judge", "control") or {}
    out = ctl.get("output") or {}
    need(ctl.get("exit_code") == 0 and out.get("problems") == [], "the control judge did not pass")
    need(out.get("kind") == "control" and out.get("target") == "stream_decode" and out.get("budget_seconds") == BUDGET, "the control judgment is not stream_decode at the budget")
    need(out.get("crashes") == 1, "the control judgment does not report one crash")
    need(out.get("crash_source") == "file", "the control judgment did not use the crash file")
    need(out.get("seed_files_read") == counts["stream_decode"], "the control read another number of seed files than the corpus has")
    need(out.get("crash_bytes") == len(crash), "the crash file is not the size the judge saw")
    need(out.get("crash_sha256") == sha256(crash), "the crash file's sha256 is not the one the judge saw")
    need(out.get("artifact") == "crash-" + hashlib.sha1(crash).hexdigest(), "the artifact name is not the SHA-1 of the crash file")
    log_only = _get(rec, "judge", "control_without_the_crash_file") or {}
    out2 = log_only.get("output") or {}
    need(log_only.get("exit_code") == 0 and out2.get("problems") == [], "the control judge without the file did not pass")
    need(out2.get("crash_source") == "log" and out2.get("crash_sha256") == sha256(crash), "libFuzzer's Base64 line is not the crash file")
    need(_get(rec, "control", "crash", "base64_line_in_log") is True, "the control log did not carry the crash input")
    # the crash input, re-derived
    need(fj.triggers_the_plant(crash), "the crash input is not an accepted packet of a planted length")
    length = None
    datagram = fj.datagram_for(fj.load_key(), crash)
    if rf.decode(datagram, fj.load_key())[0] == "ACCEPT":
        length = len(datagram) - rf.HEADER_LEN - rf.TAG_LEN
    need(_get(rec, "control", "panic_payload_length") == length, "the panic named a payload length other than the crash input's (%s)" % length)
    need(_get(rec, "control", "crash", "mode_byte") == (crash[0] if crash else None), "the recorded mode byte is not the crash file's")
    if crash and crash[0] == fj.MODE_RESIGN_FIT and len(crash) >= 63:
        frames = int.from_bytes(crash[61:63], "big")
        need(_get(rec, "control", "crash", "frames") == frames and rf.BYTES_PER_FRAME * frames == length, "the recorded frame count is not the crash input's, or does not give its length")
    for name in ("sha256", "sha1"):
        want = sha256(crash) if name == "sha256" else hashlib.sha1(crash).hexdigest()
        need(_get(rec, "control", "crash", name) == want, "the recorded crash %s is not the file's" % name)
    need(_get(rec, "control", "crash", "bytes") == len(crash), "the recorded crash size is not the file's")
    clean_rows = _get(rec, "runs", "clean") or {}
    for target in fj.TARGETS:
        j = _get(rec, "judge", "clean", target) or {}
        out = j.get("output") or {}
        need(j.get("exit_code") == 0 and out.get("problems") == [], "the %s clean judgment did not pass" % target)
        need(out.get("kind") == "clean" and out.get("target") == target and out.get("budget_seconds") == BUDGET, "the %s clean judgment is not that target at the budget" % target)
        need(out.get("crashes") == 0, "a clean run of %s reports a crash" % target)
        need(isinstance(out.get("executions"), int) and out["executions"] >= fj.DEFAULT_MIN_EXECS, "%s executed fewer than the floor of %d" % (target, fj.DEFAULT_MIN_EXECS))
        need(isinstance(out.get("seconds"), int) and out["seconds"] >= BUDGET, "%s stopped before its budget" % target)
        need(isinstance(out.get("seed_files_read"), int) and out["seed_files_read"] >= counts[target], "%s read fewer seed files than the manifest" % target)
        row = clean_rows.get(target) or {}
        need(row.get("executions") == out.get("executions") and row.get("seconds") == out.get("seconds") and row.get("crashes") == out.get("crashes"), "the %s table row differs from its judge output" % target)
        need((row.get("final") or {}) == {"cov": out.get("coverage"), "ft": out.get("features"), "corp": out.get("corpus_units")}, "the %s coverage row differs from its judge output" % target)
    rm = _get(rec, "judge", "remove_the_plant") or {}
    out = rm.get("output") or {}
    need(rm.get("exit_code") == 1 and rm.get("expected_exit_code") == 1, "the remove-the-plant control did not fail as it must")
    need(out.get("kind") == "control" and out.get("target") == "stream_decode" and out.get("crashes") == 0, "the remove-the-plant control is not a clean log judged as a control")
    problems = " | ".join(map(str, out.get("problems") or []))
    need("finished without a crash" in problems and "no planted-bug panic" in problems, "the remove-the-plant control did not name the missing crash and panic")
    clean_sd = _get(rec, "judge", "clean", "stream_decode", "output") or {}
    need(out.get("coverage") == clean_sd.get("coverage") and out.get("features") == clean_sd.get("features"), "the remove-the-plant log is not the clean stream_decode log")


def _predictions(rec, root, need):
    pred = rec.get("predictions") or {}
    rows = {row.get("id"): row for row in pred.get("rows") or []}
    need(sorted(rows) == sorted(PREDICTION_IDS), "the prediction rows are not the seven made before the run")
    counts = seed_counts(root)
    inited = _get(rec, "control", "inited") or {}
    executions = _get(rec, "control", "executions_at_crash")
    length = _get(rec, "control", "panic_payload_length")
    size = _get(rec, "control", "crash", "bytes")
    observed = lambda pid: rows.get(pid, {}).get("observed")  # noqa: E731
    # (the value the control section records, whether the prediction holds for it)
    wanted = {
        "seeds": (counts, observed("seeds") == counts),
        "inited-coverage": (inited.get("cov"), isinstance(inited.get("cov"), int) and inited["cov"] > PREDICTED_COVERAGE_ABOVE),
        "inited-corpus": (inited.get("corp"), isinstance(inited.get("corp"), int) and inited["corp"] >= PREDICTED_CORPUS_AT_LEAST),
        "crash-executions": (executions, isinstance(executions, int) and PREDICTED_CRASH_EXECUTIONS[0] <= executions <= PREDICTED_CRASH_EXECUTIONS[1]),
        "panic-length": (length, isinstance(length, int) and length % 4 == 0 and fj.in_band(length)),
        "crash-input-size": (size, isinstance(size, int) and size <= PREDICTED_CRASH_INPUT_MAX),
    }
    missed = []
    for pid, (recorded, held) in wanted.items():
        need(observed(pid) == recorded, "prediction %s: the observed value is not the one the control section records" % pid)
        verdict = rows.get(pid, {}).get("verdict")
        need(verdict == ("met" if held else "missed"), "prediction %s: the verdict is %r but the observed value %s the prediction" % (pid, verdict, "meets" if held else "misses"))
        if not held:
            missed.append(pid)
    need(rows.get("refutation", {}).get("verdict") == "not triggered" and isinstance(executions, int) and executions > 0, "the refutation row is not 'not triggered' with a crash")
    miss = pred.get("miss")
    if missed:
        need(isinstance(miss, dict) and miss.get("id") == missed[0] and len(str(miss.get("explanation", ""))) > 40, "a missed prediction (%s) has no explanation" % ", ".join(missed))
    else:
        need(miss is None, "an explanation of a miss is recorded though no prediction missed")
    need(pred.get("mail") == 5092, "the predictions are not those of mail 5092")


def staleness_warnings(rec, root=rf.ROOT):
    """One line per bound file whose bytes in the tree are no longer those the run saw (changed or gone), and per tracked file the
    run did not see. A warning, never a problem: it does not change the exit code. It means the run no longer covers the current
    source; the record itself is still whole."""
    recorded = rec.get("inputs") or {}
    revision = str(rec.get("revision", ""))[:12]
    tail = " (the run at rev-%s no longer covers the current source)" % revision
    warnings = []
    for rel, want in sorted(recorded.items()):
        path = Path(root) / rel
        have = sha256(path.read_bytes()) if path.is_file() else None
        if have != want:
            warnings.append("%s %s%s" % (rel, "is gone, and the run saw it" if have is None else "differs from the bytes the run saw", tail))
    for rel in sorted(set(tracked_inputs(root)) - set(recorded)):
        warnings.append("%s exists now but the run did not see it%s" % (rel, tail))
    return warnings


def _inputs(rec, root, need):
    recorded = rec.get("inputs") or {}
    need(isinstance(recorded, dict) and recorded, "the record binds no input bytes")
    lock = rec.get("lock") or {}
    need(lock.get("sha256_before") == lock.get("sha256_after"), "the lock changed across the job")
    need(lock.get("sha256_before") == recorded.get(FUZZ + "/Cargo.lock"), "the lock the run used is not the bound Cargo.lock")


def record_problems(rec, crash, root=rf.ROOT, dirname=None):
    """Every reason this record does not verify; an empty list means it does."""
    problems = []

    def need(cond, message):
        if not cond:
            problems.append(message)

    if not isinstance(rec, dict):
        return ["the record is not a JSON object"]
    need(rec.get("schema") == SCHEMA, "the schema is not %s" % SCHEMA)
    rev = rec.get("revision")
    need(isinstance(rev, str) and HEX40.fullmatch(rev) is not None, "the revision is not a 40-hex commit id")
    if dirname is not None:
        need(isinstance(rev, str) and dirname == "rev-" + rev[:12], "the directory %s is not rev-<first 12 of the revision>" % dirname)
    text = json.dumps(rec, sort_keys=True)
    for needle in PERSONAL:
        need(needle not in text, "the record names a local path (%s)" % needle.strip("/\\"))
    sections = (("scope", lambda: _scope(rec, need)), ("hashes", lambda: _hashes(rec, need)), ("judge", lambda: _judge(rec, crash, root, need)),
                ("predictions", lambda: _predictions(rec, root, need)), ("inputs", lambda: _inputs(rec, root, need)))
    for name, section in sections:
        try:
            section()
        except (KeyError, TypeError, AttributeError, ValueError, IndexError) as exc:
            problems.append("the record is malformed in %s: %s" % (name, exc))
    return problems


def cited_records(root=rf.ROOT):
    """The record directories the contract cites. The contract's claim and its record are one thing: superseding a record is
    changing this citation, and an older directory then stays as history, unchecked."""
    text = (Path(root) / "docs" / "contracts" / "n01.md").read_text(encoding="utf-8")
    names = sorted(set(re.findall(r"toolchain/results/n01/(rev-[0-9a-f]{12})/", text)))
    return [Path(root) / RESULTS / name for name in names]


def load(directory):
    directory = Path(directory)
    record = json.loads((directory / "record.json").read_text(encoding="utf-8"))
    crash = bytes.fromhex(record["control"]["crash"]["hex"])
    return record, crash


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    dirs = [Path(a) for a in args] or cited_records()
    if not dirs:
        print(json.dumps({"problems": ["the contract cites no record under %s" % RESULTS]}))
        return 1
    bad = 0
    for d in dirs:
        warnings = []
        try:
            record, crash = load(d)
            problems = record_problems(record, crash, rf.ROOT, d.name)
            warnings = staleness_warnings(record, rf.ROOT)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems = ["cannot read the record: %r" % exc]
        print(json.dumps({"record": d.name, "problems": problems, "warnings": warnings}, sort_keys=True))
        for line in warnings:
            print("WARNING: %s" % line, file=sys.stderr)
        bad += bool(problems)  # warnings never count: the exit code is the record's self-consistency alone
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
