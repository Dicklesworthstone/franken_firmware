"""Tests of tests/n01/fuzz_record.py, the consumer of the committed N01 fuzz run record (docs/contracts/n01.md section 11).

The record is the only thing in the repository that says a central fuzz run happened, so these tests hold it to what can be
re-derived without the logs. The committed record must verify (the permitted positive for every rule below). Then each rule is
broken on its own, on a copy of the record, and must be refused for its own reason; then a mutation pass switches off each rule of
the verifier in memory and requires that some planted record slips through, on a baseline where none does. The contract's own
tables and its test counts are held to the record, and the phrases it used while nothing had run must be gone.
Nothing here runs a fuzzer, Rust or the network.
"""

import copy
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzz_judge as fj  # noqa: E402
import fuzz_record as fr  # noqa: E402
import reference_frames as rf  # noqa: E402

ROOT = rf.ROOT
DOC = (ROOT / "docs" / "contracts" / "n01.md").read_text(encoding="utf-8")
MODULE_PATH = Path(fr.__file__).resolve()
CITED = fr.cited_records(ROOT)
RECORD_DIR = CITED[0] if CITED else ROOT / fr.RESULTS / "rev-missing"
REC, CRASH = fr.load(RECORD_DIR)


def expected_warnings(rec):
    """The files that differ from the record's bindings, found by a plain loop (not by the code under test)."""
    revision = rec["revision"][:12]
    tail = " (the run at rev-%s no longer covers the current source)" % revision
    out = []
    for rel, want in sorted(rec["inputs"].items()):
        path = ROOT / rel
        if not path.is_file():
            out.append("%s is gone, and the run saw it%s" % (rel, tail))
        elif hashlib.sha256(path.read_bytes()).hexdigest() != want:
            out.append("%s differs from the bytes the run saw%s" % (rel, tail))
    for rel in sorted(fr.tracked_inputs(ROOT)):
        if rel not in rec["inputs"]:
            out.append("%s exists now but the run did not see it%s" % (rel, tail))
    return out


def problems_of(module, rec, crash=CRASH, dirname=None):
    return module.record_problems(rec, crash, ROOT, RECORD_DIR.name if dirname is None else dirname)


def has(problems, needle):
    return any(needle in p for p in problems)


def edited(fn):
    """A deep copy of the committed record with `fn` applied to it (fn mutates it in place)."""
    rec = copy.deepcopy(REC)
    fn(rec)
    return rec


def crash_with_frames(frames, mode=fj.MODE_RESIGN_FIT):
    return bytes([mode]) + CRASH[1:61] + frames.to_bytes(2, "big") + CRASH[63:]


def plants():
    """(label, record, crash, dirname, required substring). Each is the committed record with exactly one thing wrong."""
    first_log = REC["fuzz_logs"][0]["sha256"]
    other = crash_with_frames(170)
    mode_one = bytes([fj.MODE_RESIGN]) + CRASH[1:]
    def e(fn):
        return edited(fn)

    def swap_steps(r):
        s = r["job"]["steps"]
        s[0], s[1] = s[1], s[0]

    return [
        ("schema renamed", e(lambda r: r.update(schema="ffw-n01-fuzz-run-record-0")), CRASH, None, "the schema is not"),
        ("revision shortened", e(lambda r: r.update(revision=r["revision"][:39])), CRASH, None, "40-hex"),
        ("directory not named for the revision", REC, CRASH, "rev-000000000000", "is not rev-<first 12"),
        ("a soak claimed", e(lambda r: r["scope"].update(soak=True)), CRASH, None, "claims a soak"),
        ("hardware claimed", e(lambda r: r["scope"].update(hardware=True)), CRASH, None, "claims hardware"),
        ("budget of 60 s", e(lambda r: r["scope"].update(budget_seconds=60)), CRASH, None, "budget is not"),
        ("scope not a smoke run", e(lambda r: r["scope"].update(kind="soak")), CRASH, None, "not a smoke run"),
        ("open list without the soak caveat", e(lambda r: r.update(open=["Host synthetic evidence only."])), CRASH, None, "nothing is soaked"),
        ("a log hash cut short", e(lambda r: r["fuzz_logs"][0].update(sha256=first_log[:63])), CRASH, None, "has no sha256"),
        ("a log missing from the table", e(lambda r: r["fuzz_logs"].pop()), CRASH, None, "not exactly the 13 files"),
        ("a central line failed", e(lambda r: r["central_lines"][0].update(exit_code=1)), CRASH, None, "did not exit 0"),
        ("a central test failed", e(lambda r: [row.update(failed=1) for row in r["central_lines"] if row["name"] == "test"]), CRASH, None, "tests failed or none ran"),
        ("a central line missing", e(lambda r: r["central_lines"].pop(1)), CRASH, None, "central lines are not"),
        ("the control step that did not crash", e(lambda r: [s.update(rc=0) for s in r["job"]["steps"] if s["step"] == "control"]), CRASH, None, "ended 0, expected 1"),
        ("a clean step that failed", e(lambda r: [s.update(rc=1) for s in r["job"]["steps"] if s["step"] == "clean-stream_receiver"]), CRASH, None, "ended 1, expected 0"),
        ("steps out of order", e(swap_steps), CRASH, None, "steps are not"),
        ("the job did not exit 0", e(lambda r: r["job"].update(exit_code=3)), CRASH, None, "job did not exit 0"),
        ("seed counts that are not the vectors'", e(lambda r: r["judge"]["seeds"]["output"]["seed_files"].update(stream_decode=419)), CRASH, None, "seed counts"),
        ("the seed judge failed", e(lambda r: r["judge"]["seeds"]["output"].update(problems=["x"])), CRASH, None, "seed judge did not pass"),
        ("the control judge saw another crash file", e(lambda r: r["judge"]["control"]["output"].update(crash_sha256=first_log)), CRASH, None, "crash file's sha256"),
        ("the control judge saw no crash", e(lambda r: r["judge"]["control"]["output"].update(crashes=0)), CRASH, None, "one crash"),
        ("the artifact is not the crash file's SHA-1", e(lambda r: r["judge"]["control"]["output"].update(artifact="crash-" + "0" * 40)), CRASH, None, "artifact name"),
        ("the control judged from the log, not the file", e(lambda r: r["judge"]["control"]["output"].update(crash_source="log")), CRASH, None, "did not use the crash file"),
        ("the file-less judgment read another input", e(lambda r: r["judge"]["control_without_the_crash_file"]["output"].update(crash_sha256=first_log)), CRASH, None, "Base64 line is not the crash file"),
        ("the crash file is the same bytes in re-sign mode 1", REC, mode_one, None, "not an accepted packet"),
        ("the crash file is another planted input", REC, other, None, "other than the crash input's"),
        ("the panic named another length", e(lambda r: r["control"].update(panic_payload_length=700)), CRASH, None, "other than the crash input's"),
        ("the recorded mode byte is wrong", e(lambda r: r["control"]["crash"].update(mode_byte=1)), CRASH, None, "recorded mode byte"),
        ("a clean run below the floor", e(lambda r: r["judge"]["clean"]["stream_receiver"]["output"].update(executions=1000)), CRASH, None, "fewer than the floor"),
        ("a clean run that crashed", e(lambda r: r["judge"]["clean"]["negotiation_finish"]["output"].update(crashes=1)), CRASH, None, "reports a crash"),
        ("a clean run that stopped early", e(lambda r: r["judge"]["clean"]["negotiation_respond"]["output"].update(seconds=60)), CRASH, None, "before its budget"),
        ("a clean judgment with a problem", e(lambda r: r["judge"]["clean"]["stream_decode"]["output"].update(problems=["x"])), CRASH, None, "clean judgment did not pass"),
        ("a table row that is not its judge output", e(lambda r: r["runs"]["clean"]["stream_decode"].update(executions=r["runs"]["clean"]["stream_decode"]["executions"] + 1)), CRASH, None, "table row differs"),
        ("the remove-the-plant control passed", e(lambda r: r["judge"]["remove_the_plant"].update(exit_code=0)), CRASH, None, "did not fail as it must"),
        ("the remove-the-plant control named nothing", e(lambda r: r["judge"]["remove_the_plant"]["output"].update(problems=[])), CRASH, None, "did not name the missing crash"),
        ("a miss turned into a hit", e(lambda r: [row.update(verdict="met") for row in r["predictions"]["rows"] if row["id"] == "inited-corpus"]), CRASH, None, "misses the prediction"),
        ("the explanation of the miss removed", e(lambda r: r["predictions"].update(miss=None)), CRASH, None, "has no explanation"),
        ("the observed value edited to hide the miss", e(lambda r: [row.update(observed=28, verdict="met") for row in r["predictions"]["rows"] if row["id"] == "inited-corpus"]), CRASH, None, "control section records"),
        ("a hit turned into a miss", e(lambda r: [row.update(verdict="missed") for row in r["predictions"]["rows"] if row["id"] == "crash-executions"]), CRASH, None, "meets the prediction"),
        ("a prediction row dropped", e(lambda r: r["predictions"]["rows"].pop()), CRASH, None, "not the seven"),
        ("the lock changed across the job", e(lambda r: r["lock"].update(sha256_after=first_log)), CRASH, None, "lock changed"),
        ("a local path in the record", e(lambda r: r["job"].update(command=r["job"]["command"] + " /Users/someone/x")), CRASH, None, "names a local path"),
        ("the first run recorded as having crashed", e(lambda r: r["first_run"].update(crashes=1)), CRASH, None, "first run is not recorded"),
        ("the judge section deleted", e(lambda r: r.pop("judge")), CRASH, None, "seed judge did not pass"),
    ]


PLANTS = plants()


def warning_plants():
    """(label, record, required substring of a staleness warning). The bytes a record binds are compared with the tree and a
    difference is a printed warning, never a problem: each of these is the committed record with one binding altered."""
    plant_rs = "crates/franken-stream/fuzz/src/plant.rs"
    unseen = sorted(REC["inputs"])[0]
    changed = edited(lambda r: r["inputs"].update({plant_rs: "0" * 64}))
    gone = edited(lambda r: r["inputs"].update({"crates/franken-stream/src/no_such_file.rs": "0" * 64}))
    unlisted = edited(lambda r: r["inputs"].pop(unseen))
    return [
        ("an input changed since the run", changed, "%s differs from the bytes the run saw" % plant_rs),
        ("an input gone from the tree", gone, "crates/franken-stream/src/no_such_file.rs is gone, and the run saw it"),
        ("an input the run did not see", unlisted, "%s exists now but the run did not see it" % unseen),
    ]


WARN_PLANTS = warning_plants()


class Positives(unittest.TestCase):
    def test_the_committed_record_verifies(self):
        self.assertEqual(len(CITED), 1, "the contract must cite exactly one record under %s" % fr.RESULTS)
        self.assertEqual(problems_of(fr, REC), [])

    def test_the_command_line_verifies_the_cited_record_and_refuses_a_broken_copy(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(fr.main([]), 0)
            self.assertEqual(fr.main([str(RECORD_DIR)]), 0)
        self.assertEqual(json.loads(out.getvalue().splitlines()[0]), {"problems": [], "record": RECORD_DIR.name, "warnings": expected_warnings(REC)})
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / RECORD_DIR.name
            shutil.copytree(RECORD_DIR, broken)
            record = json.loads((broken / "record.json").read_text(encoding="utf-8"))
            record["scope"]["soak"] = True
            (broken / "record.json").write_text(json.dumps(record), encoding="utf-8")
            with redirect_stdout(io.StringIO()) as bad:
                self.assertEqual(fr.main([str(broken)]), 1)
            self.assertIn("claims a soak", bad.getvalue())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(fr.main([str(Path(tmp) / "absent")]), 1)

    def test_the_staleness_warnings_are_what_a_plain_comparison_of_the_tree_gives(self):
        # not that the tree equals the record (it need not: that is what a warning is for), but that the warnings are exactly the
        # files that differ, as an independent loop finds them
        self.assertEqual(fr.staleness_warnings(REC, ROOT), expected_warnings(REC))
        self.assertGreaterEqual(len(REC["inputs"]), 20)

    def test_a_mismatch_is_printed_by_file_and_leaves_the_exit_code_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / RECORD_DIR.name
            shutil.copytree(RECORD_DIR, stale)
            record = json.loads((stale / "record.json").read_text(encoding="utf-8"))
            # the tree may already differ from the record in places (that is what a warning is for), so alter two bindings that
            # still match and count only what those two add
            baseline = expected_warnings(REC)
            already = {w.split(" ")[0] for w in baseline}
            files = [rel for rel in sorted(record["inputs"]) if rel not in already][:2]
            self.assertEqual(len(files), 2)
            for rel in files:
                record["inputs"][rel] = "0" * 64
            (stale / "record.json").write_text(json.dumps(record), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = fr.main([str(stale)])
            line = json.loads(out.getvalue().splitlines()[0])
            self.assertEqual((code, line["problems"]), (0, []), "a stale record is not a failed record")
            self.assertEqual(line["warnings"], expected_warnings(record))
            self.assertEqual(len(line["warnings"]), len(baseline) + 2)
            for rel in files:
                self.assertTrue(any(w.startswith(rel + " differs from the bytes the run saw") for w in line["warnings"]), rel)
                self.assertIn("WARNING: %s differs from the bytes the run saw" % rel, err.getvalue())
                self.assertIn("no longer covers the current source", err.getvalue())
            # the permitted pairing: the same stale record with a broken self-consistency check still fails, and still warns
            record["scope"]["soak"] = True
            (stale / "record.json").write_text(json.dumps(record), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = fr.main([str(stale)])
            self.assertEqual(code, 1)
            self.assertEqual(len(json.loads(out.getvalue().splitlines()[0])["warnings"]), len(baseline) + 2)

    def test_the_seed_counts_are_rederived_from_the_committed_vectors(self):
        self.assertEqual(fr.seed_counts(ROOT), {"stream_decode": 420, "stream_receiver": 2, "negotiation_respond": 30, "negotiation_finish": 17})

    def test_the_crash_input_is_a_mode_two_packet_that_mode_one_would_refuse(self):
        key = fj.load_key()
        self.assertEqual((len(CRASH), CRASH[0]), (65, fj.MODE_RESIGN_FIT))
        self.assertTrue(fj.triggers_the_plant(CRASH, key))
        datagram = fj.datagram_for(key, CRASH)
        self.assertEqual(rf.decode(datagram, key)[0], "ACCEPT")
        self.assertEqual(len(datagram) - rf.HEADER_LEN - rf.TAG_LEN, 736)
        junk = int.from_bytes(CRASH[1 + 62:1 + 64], "big")
        self.assertNotEqual(junk, 736, "mode 2 overwrote a payload length field that disagreed with the frame count")
        self.assertEqual(hashlib.sha256(CRASH).hexdigest(), REC["control"]["crash"]["sha256"])
        # the permitted pairing: the same bytes under mode 1 keep the junk length and are refused
        self.assertFalse(fj.triggers_the_plant(bytes([fj.MODE_RESIGN]) + CRASH[1:], key))

    def test_the_prediction_made_before_the_run_that_missed_is_recorded_as_missed(self):
        rows = {row["id"]: row for row in REC["predictions"]["rows"]}
        self.assertEqual((rows["inited-corpus"]["threshold"], rows["inited-corpus"]["observed"], rows["inited-corpus"]["verdict"]), (28, 27, "missed"))
        self.assertEqual(sorted(row["verdict"] for row in rows.values()).count("met"), 5)
        self.assertEqual(REC["predictions"]["miss"]["id"], "inited-corpus")
        self.assertIn("Not known", REC["predictions"]["miss"]["explanation"])


class Negatives(unittest.TestCase):
    def test_each_planted_record_is_refused_for_its_own_reason(self):
        for label, rec, crash, dirname, needle in PLANTS:
            with self.subTest(label):
                problems = problems_of(fr, rec, crash, dirname)
                self.assertTrue(has(problems, needle), "%s: %r" % (label, problems))

    def test_there_are_enough_planted_records_and_each_has_its_own_label(self):
        self.assertGreaterEqual(len(PLANTS), 44)
        self.assertEqual(len({label for label, *_ in PLANTS}), len(PLANTS))

    def test_a_record_that_is_not_an_object_is_refused(self):
        self.assertEqual(problems_of(fr, []), ["the record is not a JSON object"])


class Mutations(unittest.TestCase):
    """Switch off one rule of the verifier in memory; some planted record must then get through. The baseline is green."""

    MUTANTS = [
        ("the crash input must trigger the plant", "need(fj.triggers_the_plant(crash),", "need(True,"),
        ("the panic length is the crash input's", 'need(_get(rec, "control", "panic_payload_length") == length,', "need(True,"),
        ("the recorded mode byte", 'need(_get(rec, "control", "crash", "mode_byte") ==', "need(True or"),
        ("clean runs reach the floor", 'out["executions"] >= fj.DEFAULT_MIN_EXECS', "True"),
        ("clean runs spend the budget", 'out["seconds"] >= BUDGET', "True"),
        ("clean runs have no crash", 'need(out.get("crashes") == 0, "a clean run of', 'need(True, "a clean run of'),
        ("clean judgments pass", 'need(j.get("exit_code") == 0 and out.get("problems") == [], "the %s clean judgment did not pass" % target)', "pass"),
        ("table rows are the judge's", 'row.get("executions") == out.get("executions") and', "True and"),
        ("the plant is removed and the control fails", 'need(rm.get("exit_code") == 1 and rm.get("expected_exit_code") == 1,', "need(True,"),
        ("the failure names the missing crash", 'need("finished without a crash" in problems and "no planted-bug panic" in problems,', "need(True,"),
        ("verdicts are recomputed", 'need(verdict == ("met" if held else "missed"),', "need(True,"),
        ("observed values are the control section's", "need(observed(pid) == recorded,", "need(True,"),
        ("a miss is explained", 'need(isinstance(miss, dict) and miss.get("id") == missed[0] and len(str(miss.get("explanation", ""))) > 40,', "need(True,"),
        ("the prediction rows are the seven", "need(sorted(rows) == sorted(PREDICTION_IDS),", "need(True,"),
        ("the lock is unchanged across the job", 'need(lock.get("sha256_before") == lock.get("sha256_after"),', "need(True,"),
        ("the seed counts are the vectors'", 'need(out.get("seed_files") == counts,', "need(True,"),
        ("the crash file is the one the judge saw", 'need(out.get("crash_sha256") == sha256(crash),', "need(True,"),
        ("the control found one crash", 'need(out.get("crashes") == 1,', "need(True,"),
        ("the control used the file", 'need(out.get("crash_source") == "file",', "need(True,"),
        ("the file-less judgment read the same input", 'need(out2.get("crash_source") == "log" and out2.get("crash_sha256") == sha256(crash),', "need(True,"),
        ("the artifact is the SHA-1", 'need(out.get("artifact") == "crash-" + hashlib.sha1(crash).hexdigest(),', "need(True,"),
        ("steps end as they must", 'need(s.get("rc") == want,', "need(True,"),
        ("steps are in order", 'need([s.get("step") for s in steps] == list(STEPS),', "need(True,"),
        ("central lines exit 0", 'need(row.get("exit_code") == 0, "central line', 'need(True, "central line'),
        ("central tests passed", 'need(row.get("failed") == 0 and isinstance(row.get("passed"), int) and row["passed"] > 0,', "need(True,"),
        ("no local path", "need(needle not in text,", "need(True,"),
        ("the log table is whole", "need(sorted(names) == sorted(LOGS),", "need(True,"),
        ("no soak is claimed", 'need(scope.get("soak") is False,', "need(True,"),
        ("the budget is 120 s", 'need(scope.get("budget_seconds") == BUDGET,', "need(True,"),
        ("the directory is named for the revision", 'need(isinstance(rev, str) and dirname == "rev-" + rev[:12],', "need(True,"),
        ("the first run is the run that found nothing", 'need(_get(rec, "first_run", "crashes") == 0,', "need(True,"),
    ]

    @staticmethod
    def mutated(old, new):
        source = MODULE_PATH.read_text(encoding="utf-8")
        if source.count(old) != 1:
            raise AssertionError("the mutant anchor occurs %d times: %r" % (source.count(old), old[:70]))
        namespace = {"__name__": "mutant", "__file__": str(MODULE_PATH)}
        exec(compile(source.replace(old, new), "mutant.py", "exec"), namespace)  # noqa: S102 - a planted mutant, run in memory
        return types.SimpleNamespace(**namespace)

    @staticmethod
    def undetected(module):
        """The planted records a verifier fails to refuse for their own reason. One that crashes has not refused it either."""
        missed = []
        for label, rec, crash, dirname, needle in PLANTS:
            try:
                found = has(problems_of(module, rec, crash, dirname), needle)
            except Exception:  # noqa: BLE001 - a mutated verifier may fail in any way
                found = False
            if not found:
                missed.append(label)
        return missed

    # The staleness rules print warnings instead of failing: their mutants are held against the warning plants.
    WARNING_MUTANTS = [
        ("a changed or gone input is warned about", "        if have != want:", "        if False:"),
        ("an input the run did not see is warned about", "for rel in sorted(set(tracked_inputs(root)) - set(recorded)):", "for rel in []:"),
    ]

    @staticmethod
    def undetected_warnings(module):
        missed = []
        for label, rec, needle in WARN_PLANTS:
            try:
                found = any(needle in w for w in module.staleness_warnings(rec, ROOT))
            except Exception:  # noqa: BLE001 - a mutated verifier may fail in any way
                found = False
            if not found:
                missed.append(label)
        return missed

    def test_the_baseline_verifier_misses_nothing(self):
        self.assertEqual(self.undetected(fr), [])
        self.assertEqual(self.undetected_warnings(fr), [])

    def test_each_rule_switched_off_lets_a_planted_record_through(self):
        self.assertGreaterEqual(len(self.MUTANTS), 31)
        for label, old, new in self.MUTANTS:
            with self.subTest(label):
                self.assertNotEqual(self.undetected(self.mutated(old, new)), [], label)

    def test_each_warning_rule_switched_off_lets_a_planted_binding_through(self):
        self.assertGreaterEqual(len(self.WARNING_MUTANTS), 2)
        for label, old, new in self.WARNING_MUTANTS:
            with self.subTest(label):
                self.assertNotEqual(self.undetected_warnings(self.mutated(old, new)), [], label)

    def test_a_warning_can_never_become_a_problem(self):
        # every warning plant leaves the record problem-free: staleness is not a failure
        for label, rec, needle in WARN_PLANTS:
            with self.subTest(label):
                self.assertEqual(problems_of(fr, rec), [], label)


def table_rows(prefix_pattern):
    return [re.match(prefix_pattern, line) for line in DOC.splitlines() if re.match(prefix_pattern, line)]


class TheContractAndTheRecord(unittest.TestCase):
    def test_the_contract_cites_the_record_and_names_its_consumer(self):
        self.assertIn("toolchain/results/n01/%s/" % RECORD_DIR.name, DOC)
        self.assertIn("tests/n01/fuzz_record.py", DOC)
        self.assertIn("scripts/e2e/n01 --verify-fuzz-record", DOC)
        self.assertTrue((RECORD_DIR / "record.json").is_file())

    def test_the_contracts_clean_run_table_is_the_records(self):
        rows = {m.group(1): m for m in table_rows(r"^\| `(\w+)` \| ([\d,]+) \| ([\d,]+) \| (\d+) \| ([\d,]+) \| (\d+) \|$")}
        self.assertEqual(sorted(rows), sorted(fj.TARGETS))
        number = lambda text: int(text.replace(",", ""))  # noqa: E731
        for target, m in rows.items():
            run = REC["runs"]["clean"][target]
            self.assertEqual((number(m.group(2)), number(m.group(3)), number(m.group(4)), number(m.group(5)), number(m.group(6))),
                             (run["executions"], run["execs_per_second"], run["final"]["cov"], run["final"]["ft"], run["crashes"]), target)

    def test_the_contracts_numbers_for_the_control_and_the_prediction_tables_are_the_records(self):
        control = REC["control"]
        for needle in ("execution %s" % format(control["executions_at_crash"], ","), "payload length %d" % control["panic_payload_length"],
                       "%d frames" % control["crash"]["frames"], "The crash input is %d bytes" % control["crash"]["bytes"], "mode byte %d" % control["crash"]["mode_byte"]):
            self.assertIn(needle, DOC)
        rows = {row["id"]: row for row in REC["predictions"]["rows"]}
        met = sum(1 for row in rows.values() if row["verdict"] == "met")
        missed = sum(1 for row in rows.values() if row["verdict"] == "missed")
        self.assertEqual((met, missed), (5, 1))
        self.assertIn("five met, one missed", DOC)
        self.assertIn("| control `INITED` corpus at least 28 | **%d** | **missed by one** |" % rows["inited-corpus"]["observed"], DOC)
        self.assertIn("The miss is kept as it was and the prediction is not adjusted", DOC)
        self.assertIn("I do not know why", DOC)
        self.assertEqual(rows["inited-corpus"]["observed"], control["inited"]["corp"])

    def test_the_contract_says_what_a_printed_mismatch_means(self):
        flat = " ".join(DOC.split())
        for needle in ("**The record describes the bytes at `%s`**" % RECORD_DIR.name, "22 files bound by sha256",
                       "prints a `WARNING` naming each such file and leaves the exit code unchanged",
                       "a printed mismatch means the run no longer covers the current source"):
            self.assertIn(needle, flat)
        self.assertEqual(len(REC["inputs"]), 22)

    def test_the_contract_says_what_the_run_does_not_show(self):
        for needle in ("**It is a smoke budget.**", "proves no soak", "120 s per target", "The bead stays open", "host evidence only",
                       "the big-endian guest replay has not run"):
            self.assertIn(needle, DOC)

    def test_the_phrases_from_when_nothing_had_run_are_gone(self):
        for stale in ("and has not run. Bead open", "**no run of it exists**", "no clean run, no control run, and no compile of it exists",
                      "**not run**; needs cargo-fuzz", "recorded here as unscanned", "central host build; **not run**",
                      "the fix in\nthis section has not been compiled or run", "(none was done: the control gates them)"):
            self.assertNotIn(stale, DOC)

    def test_the_harness_test_counts_are_the_records_and_the_contracts(self):
        harness = (ROOT / "crates" / "franken-stream" / "fuzz" / "tests" / "harness.rs").read_text(encoding="utf-8")
        total = len(re.findall(r"#\[test\]", harness))
        control_only = len(re.findall(r'#\[cfg\(feature = "control"\)\]\n#\[test\]', harness))
        clean_only = len(re.findall(r'#\[cfg\(not\(feature = "control"\)\)\]\n#\[test\]', harness))
        counts = {row["name"]: row["passed"] for row in REC["central_lines"] if "passed" in row}
        self.assertIn("%d tests in a clean build, %d with `--features control`" % (counts["test"], counts["test-control"]), DOC)
        now = {"test": total - control_only, "test-control": total - clean_only}
        if now != counts:
            # the record's counts are what the recorded run saw. A harness that has gained or lost a test since is a source that
            # moved, which the verifier must say by name (a warning, never a failing entry point: BeigeMaple 5175)
            self.assertTrue(any(w.startswith("crates/franken-stream/fuzz/tests/harness.rs differs from the bytes the run saw")
                                for w in expected_warnings(REC)), "the harness has %r tests, the record %r, and no warning names the file" % (now, counts))

    def test_the_record_holds_no_raw_log_and_no_local_path(self):
        self.assertEqual(sorted(p.name for p in RECORD_DIR.iterdir()), ["record.json"])
        text = (RECORD_DIR / "record.json").read_text(encoding="utf-8")
        for needle in fr.PERSONAL:
            self.assertNotIn(needle, text)
        self.assertLess(len(text), 64 * 1024)


if __name__ == "__main__":
    unittest.main()
