"""Tests of the Q01 judge (tests/q01/run_cases.py). Offline, standard library only.

The logs these tests judge are SYNTHETIC: they are built here, in memory, from the case table and the contract, and are never written
under the repository as if they were evidence. A synthetic log shows that the judge accepts what it should and names what it should
refuse; it says nothing about the Rust. Every plant is judged against the unplanted baseline first (it must pass), so a plant that
changes nothing cannot pass for a catch.
"""
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import run_cases as rc  # noqa: E402

MASK = (1 << 64) - 1


def independent_silent_digest(blocks, channels):
    """Written out as the loop it stands for, not through the judge's closed form."""
    h = 0xCBF29CE484222325
    for _ in range(blocks * channels * 256 * 2):
        h ^= 0
        h = (h * 0x100000001B3) & MASK
    return h


def contract_table():
    with open(rc.CONTRACT, encoding="utf-8") as handle:
        return rc.parse_limit_table(handle.read())


class Synthetic:
    """A well-formed log for the current case table and contract; `drop`, `fail` and `edit` plant one fault at a time."""

    def __init__(self):
        self.cases = rc.load_cases()
        self.table = contract_table()
        self.silent = {c: independent_silent_digest(rc.BLOCKS, c) for c in set(rc.FLEET.values())}

    def member_records(self):
        records = []
        for member, channels in rc.FLEET.items():
            for signal in rc.SIGNALS:
                behaviour, _basis = self.table[(member, signal)]
                nonzero = 0 if behaviour == "silent" else 231
                digest = self.silent[channels] if behaviour == "silent" else (hash((member, signal)) & MASK) | 1 << 62
                records.append({"signal": signal, "member": member, "seed": rc.SEED, "blocks": rc.BLOCKS, "channels": channels,
                                "rendered_blocks": rc.BLOCKS, "audible_authentic_blocks": 244, "rendered_nonzero_blocks": nonzero,
                                "digest": digest})
        return records

    def plant_records(self):
        records = [{"member": None, "planted": False, "outcome": "ok", "message": None}]
        for member in rc.FLEET:
            records.append({"member": member, "planted": True, "outcome": "error",
                            "message": "member_rendered_silence: %s: 244 authentic blocks sounded and every sample it rendered is zero" % member})
        return records

    def text(self, members=None, plants=None, drop=(), fail=(), noise=True, raw_lines=(), split=(), ansi=False):
        lines = ["running %d tests" % sum(len(c["tests"]) for c in self.cases)] if noise else []
        for case in self.cases:
            for test in case["tests"]:
                if test in drop:
                    continue
                result = "FAILED" if test in fail else "ok"
                if ansi:
                    result = "\x1b[%dm%s\x1b[0m" % (31 if test in fail else 32, result)
                if test in split:
                    # Another test thread printed between libtest's `test X ... ` and its result (cargo test -- --nocapture).
                    lines.append("test %s ... warning: output of another test thread" % test)
                    lines.append(result)
                else:
                    lines.append("test %s ... %s" % (test, result))
                if noise and test.endswith("measure_planted_silence_is_named_for_every_member"):
                    lines.append("warning: unused dependency `x` (cargo noise between lines)")
        for record in (self.member_records() if members is None else members):
            lines.append("Q01-MEMBER " + json.dumps(record, sort_keys=True))
        for record in (self.plant_records() if plants is None else plants):
            lines.append("Q01-PLANT " + json.dumps(record, sort_keys=True))
        lines += list(raw_lines)
        if noise:
            lines.append("test result: ok. %d passed; 0 failed" % sum(len(c["tests"]) for c in self.cases))
        return "\n".join(lines) + "\n"


def judge(text):
    log = rc.Log()
    log.add(text, "synthetic")
    results, notes, measured = rc.judge_cases(log)
    return results, notes, measured, log


def failing(results):
    return {r.case: r.detail for r in results if r.status == "fail"}


class Baseline(unittest.TestCase):
    def test_the_well_formed_synthetic_log_is_qualified(self):
        results, notes, measured, _ = judge(Synthetic().text())
        self.assertEqual({r.status for r in results}, {"pass"}, failing(results))
        self.assertEqual(rc.exit_code(results), 0)
        self.assertEqual(len(measured), 10)
        # The contract has no `by routing` cell left (the committed receipt measured them), so there is nothing to upgrade.
        self.assertEqual(notes, [])

    def test_no_log_blocks_every_case_and_never_passes_one(self):
        results, _, _ = rc.judge_cases(None)
        self.assertEqual({r.status for r in results}, {"blocked"})
        self.assertEqual(rc.exit_code(results), 3)

    def test_the_meta_checks_pass_on_this_repository(self):
        results = rc.meta_results()
        self.assertEqual({r.status for r in results}, {"pass"}, [(r.case, r.detail) for r in results if r.status != "pass"])
        self.assertEqual({r.case for r in results}, {"META-CASES", "META-CONTRACT", "META-DIGEST", "META-RECEIPTS"})


class TestsAndCases(unittest.TestCase):
    def setUp(self):
        self.s = Synthetic()
        self.assertEqual(set(r.status for r in judge(self.s.text())[0]), {"pass"})  # the unplanted control

    def a_test(self, case_id):
        return next(c for c in self.s.cases if c["id"] == case_id)["tests"][0]

    def test_a_failed_test_fails_its_case_by_name(self):
        test = self.a_test("Q01-C05")
        results, *_ = judge(self.s.text(fail={test}))
        self.assertEqual(list(failing(results)), ["Q01-C05"])
        self.assertIn(test, failing(results)["Q01-C05"])
        self.assertEqual(rc.exit_code(results), 1)

    def test_a_test_missing_from_the_log_blocks_its_case_and_is_not_a_pass(self):
        results, *_ = judge(self.s.text(drop={self.a_test("Q01-C12")}))
        status = {r.case: r.status for r in results}
        self.assertEqual(status["Q01-C12"], "blocked")
        self.assertEqual(sum(1 for s in status.values() if s != "pass"), 1)
        self.assertEqual(rc.exit_code(results), 3)

    def test_a_test_that_reports_both_ok_and_failed_is_a_conflict_and_fails(self):
        test = self.a_test("Q01-C08")
        results, *_ = judge(self.s.text(raw_lines=["test %s ... FAILED" % test]))
        self.assertIn("Q01-C08", failing(results))

    def test_an_ignored_test_is_not_a_pass(self):
        test = self.a_test("Q01-C10")
        text = self.s.text(drop={test}) + "test %s ... ignored\n" % test
        results, *_ = judge(text)
        self.assertEqual({r.case: r.status for r in results}["Q01-C10"], "blocked")

    def test_a_failed_measurement_test_fails_even_with_good_records(self):
        results, *_ = judge(self.s.text(fail={"harness::tests::q01_measure_what_every_member_renders_under_each_source"}))
        self.assertEqual(list(failing(results)), ["Q01-M01"])


class MemberRecords(unittest.TestCase):
    def setUp(self):
        self.s = Synthetic()
        self.base = self.s.member_records()
        self.assertEqual(set(r.status for r in judge(self.s.text())[0]), {"pass"})  # the unplanted control

    def plant(self, edit):
        records = [dict(r) for r in self.base]
        edit(records)
        results, notes, measured, _ = judge(self.s.text(members=records))
        return failing(results), notes

    def find(self, records, member, signal):
        return next(r for r in records if r["member"] == member and r["signal"] == signal)

    def assert_m01(self, problems, fragment):
        self.assertEqual(list(problems), ["Q01-M01"], problems)
        self.assertIn(fragment, problems["Q01-M01"])

    def test_a_counter_that_says_silent_with_a_digest_that_says_sound_is_refused(self):
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-kitchen-s12", "opposed").update(digest=12345))
        self.assert_m01(problems, "the counter says silent and the digest says sound")

    def test_a_digest_of_silence_with_a_counter_that_says_sound_is_refused(self):
        s5_channels = rc.FLEET["spk-office-s5"]
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-office-s5", "asymmetric").update(digest=self.s.silent[s5_channels]))
        self.assert_m01(problems, "the counter says sound and the digest says silent")

    def test_a_member_that_renders_nothing_under_the_asymmetric_source_is_refused(self):
        def edit(rs):
            record = self.find(rs, "spk-bedroom-s1", "asymmetric")
            record.update(rendered_nonzero_blocks=0, digest=self.s.silent[record["channels"]])
        problems, _ = self.plant(edit)
        self.assert_m01(problems, "under the asymmetric source a member must sound and render something")

    def test_a_member_that_never_sounded_under_the_asymmetric_source_is_refused(self):
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "asymmetric").update(audible_authentic_blocks=0))
        self.assert_m01(problems, "must sound")

    def test_a_missing_record_and_a_repeated_one_are_refused(self):
        problems, _ = self.plant(lambda rs: rs.remove(self.find(rs, "spk-living-sub", "opposed")))
        self.assert_m01(problems, "spk-living-sub under opposed: no record")
        problems, _ = self.plant(lambda rs: rs.append(dict(self.find(rs, "spk-living-sub", "opposed"))))
        self.assert_m01(problems, "reported twice")

    def test_a_record_of_another_campaign_or_another_profile_is_refused(self):
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(blocks=400))
        self.assert_m01(problems, "it is not the --virtual-house campaign")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(seed=1))
        self.assert_m01(problems, "it is not the --virtual-house campaign")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(channels=2))
        self.assert_m01(problems, "the profile has 3")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(rendered_blocks=249))
        self.assert_m01(problems, "rendered 249 of 250")

    def test_counts_that_cannot_be_true_are_refused(self):
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(rendered_nonzero_blocks=251))
        self.assert_m01(problems, "more non-zero blocks than rendered blocks")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(audible_authentic_blocks=999))
        self.assert_m01(problems, "more audible authentic blocks than rendered blocks")

    def test_malformed_records_are_refused(self):
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(extra=1))
        self.assert_m01(problems, "has the keys")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(member="spk-nobody"))
        self.assert_m01(problems, "unknown member")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(rendered_nonzero_blocks="many"))
        self.assert_m01(problems, "not a non-negative integer")
        problems, _ = self.plant(lambda rs: self.find(rs, "spk-den-s3", "opposed").update(member=["spk-den-s3"]))
        self.assert_m01(problems, "unknown member")

    def test_a_truncated_or_unparseable_record_line_is_refused(self):
        text = self.s.text(raw_lines=['Q01-MEMBER {"signal": "opposed", "member": "spk-den-s3", "seed"'])
        results, *_ = judge(text)
        self.assertIn("not valid JSON", failing(results)["Q01-M01"])
        results, *_ = judge(self.s.text(raw_lines=["Q01-MEMBER (nothing was printed)"]))
        self.assertIn("not valid JSON", failing(results)["Q01-M01"])
        results, *_ = judge(self.s.text(raw_lines=["Q01-PLANT"]))
        self.assertIn("not valid JSON", failing(results)["Q01-M02"])

    def test_the_contract_cannot_claim_a_measurement_the_log_contradicts(self):
        # The contract says S12 under the original source is silent (measured): a log that shows it rendering contradicts it.
        def edit(rs):
            record = self.find(rs, "spk-kitchen-s12", "opposed")
            record.update(rendered_nonzero_blocks=17, digest=777)
        problems, _ = self.plant(edit)
        self.assert_m01(problems, "says spk-kitchen-s12 under opposed is silent (measured), the log shows it renders")

    def by_routing_table(self):
        table = dict(self.s.table)
        for cell in (("spk-bedroom-s1", "opposed"), ("spk-den-s3", "opposed"), ("spk-living-sub", "opposed")):
            table[cell] = (table[cell][0], "by routing")
        return table

    def test_a_by_routing_claim_the_log_contradicts_is_a_failure_and_one_it_confirms_is_a_note(self):
        # The contract no longer has `by routing` cells (the committed receipt measured them), so the rule is held against a table that does.
        table = self.by_routing_table()
        problems, notes, _ = rc.check_members(self.base, table)
        self.assertEqual(problems, [])
        self.assertEqual(sum("confirmed by measurement" in n for n in notes), 3, notes)
        self.assertTrue(any("spk-bedroom-s1 under opposed: silent, confirmed by measurement" in n for n in notes), notes)
        records = [dict(r) for r in self.base]
        self.find(records, "spk-bedroom-s1", "opposed").update(rendered_nonzero_blocks=3, digest=4242)
        problems, _, _ = rc.check_members(records, table)
        self.assertTrue(any("spk-bedroom-s1 under opposed silent (by routing), the log contradicts it" in p for p in problems), problems)


class PlantRecords(unittest.TestCase):
    def setUp(self):
        self.s = Synthetic()
        self.base = self.s.plant_records()
        self.assertEqual(set(r.status for r in judge(self.s.text())[0]), {"pass"})  # the unplanted control

    def plant(self, edit):
        records = [dict(r) for r in self.base]
        edit(records)
        results, *_ = judge(self.s.text(plants=records))
        return failing(results)

    def assert_m02(self, problems, fragment):
        self.assertEqual(list(problems), ["Q01-M02"], problems)
        self.assertIn(fragment, problems["Q01-M02"])

    def test_a_missing_control_or_a_control_that_failed_is_refused(self):
        self.assert_m02(self.plant(lambda rs: rs.pop(0)), "exactly one remove-the-plant control")
        self.assert_m02(self.plant(lambda rs: rs[0].update(outcome="error", message="boom")), "the control (no plant) did not pass")

    def test_a_plant_that_was_not_named_is_refused(self):
        self.assert_m02(self.plant(lambda rs: rs[3].update(outcome="ok", message=None)), "was not named by the oracle")
        self.assert_m02(self.plant(lambda rs: rs[3].update(message="something else failed")), "was not named by the oracle")

    def test_a_plant_reported_against_the_wrong_member_or_with_no_blocks_is_refused(self):
        self.assert_m02(self.plant(lambda rs: rs[2].update(message=rs[1]["message"])), "was reported against")
        self.assert_m02(self.plant(lambda rs: rs[2].update(message=rs[2]["message"].replace("244", "0"))), "names 0 authentic blocks")
        self.assert_m02(self.plant(lambda rs: rs[2].update(message=rs[2]["message"].replace("244", "251"))), "names 251 authentic blocks")

    def test_a_missing_repeated_or_foreign_plant_is_refused(self):
        self.assert_m02(self.plant(lambda rs: rs.pop(5)), "no record of the plant on spk-living-sub")
        self.assert_m02(self.plant(lambda rs: rs.append(dict(rs[1]))), "reported twice")
        self.assert_m02(self.plant(lambda rs: rs.append({"member": "spk-nobody", "planted": True, "outcome": "error", "message": "x"})),
                        "not in the fleet")


class ContractTable(unittest.TestCase):
    GOOD = "\n".join([rc.LIMIT_BEGIN, "| member | original source | asymmetric |", "|---|---|---|"] + [
        "| `%s` | silent (by routing) | renders (measured) |" % m for m in rc.FLEET] + [rc.LIMIT_END])

    def test_a_well_formed_table_parses(self):
        table = rc.parse_limit_table(self.GOOD)
        self.assertEqual(len(table), 10)
        self.assertEqual(table[("spk-den-s3", "asymmetric")], ("renders", "measured"))

    def test_a_malformed_table_is_refused(self):
        bad = {
            "no table": "nothing here",
            "two tables": self.GOOD + "\n" + self.GOOD,
            "a cell with no basis": self.GOOD.replace("silent (by routing)", "silent", 1),
            "a basis that is neither": self.GOOD.replace("renders (measured)", "renders (guessed)", 1),
            "an unknown member": self.GOOD.replace("spk-den-s3", "spk-nobody"),
            "a member twice": self.GOOD.replace("spk-den-s3", "spk-office-s5"),
            "a member missing": "\n".join(l for l in self.GOOD.splitlines() if "spk-den-s3" not in l),
        }
        for name, text in bad.items():
            with self.assertRaises(ValueError, msg=name):
                rc.parse_limit_table(text)


class Digest(unittest.TestCase):
    def test_the_closed_form_equals_the_loop_it_stands_for(self):
        for blocks, channels in ((1, 1), (2, 3), (5, 2)):
            self.assertEqual(rc.silent_digest(blocks, channels), independent_silent_digest(blocks, channels), (blocks, channels))

    def test_it_reproduces_the_value_measured_centrally_in_b40(self):
        self.assertEqual(rc.silent_digest(400, 2), 5755000421370241829)

    def test_silence_of_a_different_length_is_a_different_digest(self):
        self.assertNotEqual(rc.silent_digest(250, 2), rc.silent_digest(250, 3))
        self.assertNotEqual(rc.silent_digest(250, 2), rc.silent_digest(251, 2))


class EntryPoint(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = rc.main(argv)
        return code, out.getvalue()

    def test_list_names_every_case(self):
        code, out = self.run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), len(rc.load_cases()))

    def test_a_log_is_judged_end_to_end_and_a_tampered_one_is_not_qualified(self):
        s = Synthetic()
        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "good.log")
            with open(good, "w", encoding="utf-8") as handle:
                handle.write(s.text())
            code, out = self.run_main(["--judge", good])
            self.assertEqual(code, 0, out)
            self.assertIn("measured (campaign seed", out)
            bad = os.path.join(tmp, "bad.log")
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write(s.text(fail={"harness::tests::the_campaign_is_deterministic"}))
            code, out = self.run_main(["--judge", bad])
            self.assertEqual(code, 1, out)

    def test_a_receipt_names_the_log_by_hash_holds_no_log_text_and_is_never_overwritten(self):
        s = Synthetic()
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "central.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(s.text(raw_lines=["/Users/someone/secret/path worker 203.0.113.9"]))
            receipts = os.path.join(tmp, "receipts")
            os.mkdir(receipts)
            code, out = self.run_main(["--judge", log, "--receipts", receipts])
            self.assertEqual(code, 0, out)
            (name,) = os.listdir(receipts)
            with open(os.path.join(receipts, name), encoding="utf-8") as handle:
                raw = handle.read()
            record = json.loads(raw)
            self.assertEqual(record["schema"], rc.RECEIPT_SCHEMA)
            self.assertEqual(record["evidence"], "simulation_only")
            self.assertEqual(record["logs"][0]["sha256"], rc.sha256_file(log))
            self.assertEqual(len(record["members"]), 10)
            self.assertNotIn("/Users/someone", raw)
            self.assertNotIn("203.0.113.9", raw)
            with self.assertRaises(FileExistsError):
                self.run_main(["--judge", log, "--receipts", receipts])

    def test_usage_errors_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _ = self.run_main(["--judge", os.path.join(tmp, "missing.log")])
            self.assertEqual(code, 2)
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            rc.main(["--receipts", "x"])
        self.assertEqual(raised.exception.code, 2)


COMMITTED_RECEIPT = "q01-measurement-d42d504d7ca1.json"
# The sha256 of the receipt file exactly as the central judge wrote it (b49); it is evidence and is never regenerated.
COMMITTED_RECEIPT_SHA256 = "19f9efc6c7667a92523c035bfbfc2168ddd1ce5a570c0d660bb2388691ac006d"
# The raw log it was judged from (not committable: it holds a worker address and local paths).
COMMITTED_RECEIPT_LOG_SHA256 = "8257a8af73cc303c3c84b06e5eaaa5f4e0d371fdd6591bf322d4f2d3fe015c96"


class Receipts(unittest.TestCase):
    """The receipt verifier. The receipts built here are synthetic (the synthetic log, run through the real writer); the committed one is not."""

    def setUp(self):
        self.s = Synthetic()
        self.table = contract_table()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        log = rc.Log()
        log.add(self.s.text(), "synthetic")
        results, _notes, measured = rc.judge_cases(log)
        self.path = rc.write_receipt(self.dir, [("synthetic.log", "ab" * 32, 4096)], results, measured, log.plants)
        with open(self.path, encoding="utf-8") as handle:
            self.record = json.load(handle)
        problems, _notes, _measured = rc.verify_receipt(self.path, self.table)
        self.assertEqual(problems, [], "the unplanted control must verify")

    def write(self, record, name=None):
        """Write `record` under its own seal (so only the semantic check can fire), or under `name`."""
        path = os.path.join(self.dir, name or "q01-measurement-%s.json" % rc.seal(record))
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
        return path

    def edited(self, edit):
        record = json.loads(json.dumps(self.record))
        edit(record)
        return self.write(record)

    def problems(self, edit):
        return rc.verify_receipt(self.edited(edit), self.table)[0]

    def test_a_receipt_the_judge_wrote_verifies_and_backs_every_cell(self):
        problems, _notes, measured = rc.verify_receipt(self.path, self.table)
        self.assertEqual((problems, len(measured)), ([], 10))

    def test_a_receipt_edited_after_it_was_sealed_is_refused(self):
        record = json.loads(json.dumps(self.record))
        record["members"][0]["digest"] += 1
        path = self.write(record, name=os.path.basename(self.path))
        problems, *_ = rc.verify_receipt(path, self.table)
        self.assertTrue(any("edited after it was sealed" in p for p in problems), problems)

    def test_a_receipt_with_a_malformed_name_or_content_is_refused(self):
        problems, *_ = rc.verify_receipt(self.write(self.record, name="receipt.json"), self.table)
        self.assertTrue(any("file name is not" in p for p in problems), problems)
        bad = os.path.join(self.dir, "q01-measurement-000000000000.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("not json")
        self.assertTrue(any("cannot be read as JSON" in p for p in rc.verify_receipt(bad, self.table)[0]))
        problems = self.problems(lambda r: r.update(extra=1))
        self.assertTrue(any("has the keys" in p for p in problems), problems)
        problems = self.problems(lambda r: r.pop("plants"))
        self.assertTrue(any("has the keys" in p for p in problems), problems)

    def test_a_receipt_of_the_wrong_kind_is_refused(self):
        for key, value, fragment in (("schema", "ffw.q01.measurement.v0", "unknown schema"), ("bead", "ffw-other", "not ffw-gmq"),
                                     ("evidence", "hardware", "not simulation_only"), ("campaign", {"seed": 1, "blocks": 250}, "not the --virtual-house campaign"),
                                     ("campaign", {"seed": rc.SEED, "blocks": 400}, "not the --virtual-house campaign")):
            problems = self.problems(lambda r, key=key, value=value: r.update({key: value}))
            self.assertTrue(any(fragment in p for p in problems), (key, problems))

    def test_a_receipt_must_name_its_log_by_hash_and_size(self):
        for logs in ([], [{"sha256": "xyz", "bytes": 10}], [{"sha256": "ab" * 32, "bytes": 0}], [{"sha256": "ab" * 32}], "a.log"):
            problems = self.problems(lambda r, logs=logs: r.update(logs=logs))
            self.assertTrue(any("by sha256 and size" in p for p in problems), (logs, problems))

    def test_a_receipt_records_only_qualified_runs(self):
        problems = self.problems(lambda r: r["verdicts"].update({"Q01-C05": "fail"}))
        self.assertTrue(any("verdicts that are not pass" in p and "Q01-C05" in p for p in problems), problems)
        problems = self.problems(lambda r: r.update(verdicts={}))
        self.assertTrue(any("none recorded" in p for p in problems), problems)

    def test_a_receipt_with_a_record_the_contract_cannot_hold_is_refused(self):
        def contradict(record):
            member = next(m for m in record["members"] if m["member"] == "spk-kitchen-s12" and m["signal"] == "opposed")
            member.update(rendered_nonzero_blocks=9, digest=31337)
        problems = self.problems(contradict)
        self.assertTrue(any("says spk-kitchen-s12 under opposed is silent (measured), the receipt shows it renders" in p for p in problems), problems)

        def drop(record):
            record["members"] = [m for m in record["members"] if not (m["member"] == "spk-den-s3" and m["signal"] == "asymmetric")]
        problems = self.problems(drop)
        self.assertTrue(any("spk-den-s3 under asymmetric: no record" in p for p in problems), problems)

        def disagree(record):
            member = next(m for m in record["members"] if m["member"] == "spk-office-s5" and m["signal"] == "opposed")
            member["digest"] = self.s.silent[member["channels"]]
        problems = self.problems(disagree)
        self.assertTrue(any("the counter says sound and the digest says silent" in p for p in problems), problems)

    def test_a_receipt_whose_plants_were_not_all_named_is_refused(self):
        problems = self.problems(lambda r: r.update(plants=[p for p in r["plants"] if p["member"] != "spk-living-sub"]))
        self.assertTrue(any("no record of the plant on spk-living-sub" in p for p in problems), problems)
        problems = self.problems(lambda r: r.update(plants=[p for p in r["plants"] if p["planted"]]))
        self.assertTrue(any("remove-the-plant control" in p for p in problems), problems)

    def test_an_earlier_contract_text_is_a_note_and_not_a_failure(self):
        path = self.edited(lambda r: r.update(contract_sha256="0" * 64))
        problems, notes, _ = rc.verify_receipt(path, self.table)
        self.assertEqual(problems, [])
        self.assertTrue(any("earlier text of the contract" in n for n in notes), notes)

    def test_the_contract_cannot_call_a_cell_measured_without_a_verified_receipt_behind_it(self):
        problems, summary = rc.check_receipts(self.dir, self.table)
        self.assertEqual(problems, [], problems)
        self.assertIn("1 receipt(s) verify and back all", summary)
        # No receipts at all: every measured cell is unbacked.
        with tempfile.TemporaryDirectory() as empty:
            problems, _ = rc.check_receipts(empty, self.table)
        self.assertTrue(any("have no verified receipt behind them" in p for p in problems), problems)
        # A receipt that does not verify backs nothing.
        self.edited(lambda r: r["members"].pop())
        os.unlink(self.path)
        problems, _ = rc.check_receipts(self.dir, self.table)
        self.assertTrue(any("have no verified receipt behind them" in p for p in problems), problems)
        self.assertTrue(any("no record" in p for p in problems), problems)

    def test_a_receipt_that_fails_backs_no_cell_even_when_its_records_are_fine(self):
        # All ten records are good; only a plant is missing. The receipt fails, so the contract's measured cells have nothing behind them.
        self.edited(lambda r: r.update(plants=[p for p in r["plants"] if p["member"] != "spk-living-sub"]))
        os.unlink(self.path)
        problems, _ = rc.check_receipts(self.dir, self.table)
        self.assertTrue(any("no record of the plant on spk-living-sub" in p for p in problems), problems)
        self.assertTrue(any("10 cell(s) the contract calls measured have no verified receipt behind them" in p for p in problems), problems)

    def test_a_table_with_no_measured_cell_needs_no_receipt(self):
        table = {cell: (behaviour, "by routing") for cell, (behaviour, _basis) in self.table.items()}
        with tempfile.TemporaryDirectory() as empty:
            problems, summary = rc.check_receipts(empty, table)
        self.assertEqual(problems, [])
        self.assertIn("back all 0 measured cells", summary)

    def test_the_command_line_verifies_a_receipt(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = rc.main(["--verify-receipt", self.path])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("PASS (10 of 10 cells)", out.getvalue())
        tampered = self.edited(lambda r: r["members"][0].update(digest=1))
        os.rename(tampered, os.path.join(self.dir, "q01-measurement-111111111111.json"))
        out = io.StringIO()
        with redirect_stdout(out):
            code = rc.main(["--verify-receipt", os.path.join(self.dir, "q01-measurement-111111111111.json")])
        self.assertEqual(code, 1)
        self.assertIn("problem:", out.getvalue())
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            rc.main(["--verify-receipt", self.path, "--list"])
        self.assertEqual(raised.exception.code, 2)


class CommittedReceipt(unittest.TestCase):
    """The real evidence: the receipt the central judge wrote for b49, committed exactly as it was written."""

    PATH = os.path.join(rc.RECEIPT_DIR, COMMITTED_RECEIPT)

    def test_it_is_the_file_the_central_judge_wrote_and_has_not_been_regenerated(self):
        self.assertEqual(rc.sha256_file(self.PATH), COMMITTED_RECEIPT_SHA256)
        with open(self.PATH, encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertEqual([l["sha256"] for l in record["logs"]], [COMMITTED_RECEIPT_LOG_SHA256])

    def test_it_holds_no_site_data(self):
        with open(self.PATH, encoding="utf-8") as handle:
            raw = handle.read()
        for needle in ("/Users/", "/private/", "/home/", "/tmp/", "@"):
            self.assertNotIn(needle, raw)
        self.assertIsNone(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", raw), "an IPv4 address")
        self.assertIsNone(re.search(r"\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b", raw), "a MAC address")

    def test_it_verifies_against_the_contract_and_backs_every_measured_cell(self):
        problems, notes, measured = rc.verify_receipt(self.PATH, contract_table())
        self.assertEqual(problems, [])
        self.assertEqual(len(measured), 10)
        # The receipt was sealed against the contract text of b1fef3b; flipping the cells changed that text, which is a note and not a failure.
        self.assertTrue(any("earlier text of the contract" in n for n in notes), notes)
        problems, summary = rc.check_receipts(rc.RECEIPT_DIR, contract_table())
        self.assertEqual(problems, [])

    def test_it_measured_what_the_contract_now_says(self):
        _problems, _notes, measured = rc.verify_receipt(self.PATH, contract_table())
        silent = {("spk-bedroom-s1", "opposed"), ("spk-kitchen-s12", "opposed"), ("spk-living-sub", "opposed")}
        for cell, record in measured.items():
            self.assertEqual(record["rendered_nonzero_blocks"] == 0, cell in silent, cell)
        table = contract_table()
        self.assertEqual({basis for _behaviour, basis in table.values()}, {"measured"})


class SplitLines(unittest.TestCase):
    """b52 showed that a test thread's --nocapture output can land between libtest's `test X ... ` and its result. The judge must read the
    result that follows, never mistake a split result for an absent one, and never hand one test another test's result."""

    MEASURE = "harness::tests::q01_measure_what_every_member_renders_under_each_source"

    def setUp(self):
        self.s = Synthetic()
        results, *_ = judge(self.s.text())
        self.assertEqual({r.status for r in results}, {"pass"})  # the unplanted control: a clean log is qualified

    def first_test(self, case_id):
        return next(c for c in self.s.cases if c["id"] == case_id)["tests"][0]

    def status(self, text):
        results, notes, _measured, log = judge(text)
        return {r.case: r.status for r in results}, notes, log

    def test_a_result_split_from_its_test_line_is_still_read(self):
        split = {self.first_test(c) for c in ("Q01-C05", "Q01-C12", "Q01-C15", "Q01-C23")}
        status, notes, log = self.status(self.s.text(split=split))
        self.assertEqual(set(status.values()), {"pass"}, status)
        self.assertEqual(log.unterminated, [])
        self.assertEqual(notes, [])

    def test_every_result_split_at_once_is_still_read(self):
        every = {t for c in self.s.cases for t in c["tests"]}
        status, _notes, _log = self.status(self.s.text(split=every))
        self.assertEqual(set(status.values()), {"pass"}, status)

    def test_a_split_failure_still_fails_its_case(self):
        test = self.first_test("Q01-C08")
        status, _notes, _log = self.status(self.s.text(split={test}, fail={test}))
        self.assertEqual(status["Q01-C08"], "fail")
        self.assertEqual([c for c, s in status.items() if s != "pass"], ["Q01-C08"])

    def test_a_record_printed_on_the_test_line_is_still_read(self):
        lines = self.s.text().splitlines()
        first = next(i for i, l in enumerate(lines) if l.startswith("Q01-MEMBER "))
        record = lines.pop(first)
        at = next(i for i, l in enumerate(lines) if l == "test %s ... ok" % self.MEASURE)
        lines[at:at + 1] = ["test %s ... %s" % (self.MEASURE, record), "ok"]
        status, _notes, log = self.status("\n".join(lines) + "\n")
        self.assertEqual(set(status.values()), {"pass"}, status)
        self.assertEqual(len(log.members), 10)

    def test_colour_does_not_hide_a_result(self):
        test = self.first_test("Q01-C05")
        status, _notes, _log = self.status(self.s.text(ansi=True, split={test}))
        self.assertEqual(set(status.values()), {"pass"}, status)
        status, _notes, _log = self.status(self.s.text(ansi=True, split={test}, fail={test}))
        self.assertEqual(status["Q01-C05"], "fail")

    def insert_before_the_first_test_line(self, text, new_lines):
        lines = text.splitlines()
        at = next(i for i, l in enumerate(lines) if l.startswith("test ") and l.endswith("... ok"))
        lines[at:at] = new_lines
        return "\n".join(lines) + "\n"

    def test_a_test_that_printed_its_name_and_never_got_a_result_is_blocked_and_a_stray_ok_is_not_credited_to_it(self):
        lonely, finished = self.first_test("Q01-C12"), self.first_test("Q01-C14")
        # `lonely` prints its name; a COMPLETE line for another test follows (so the wait is over); then an `ok` that belongs to nobody.
        text = self.insert_before_the_first_test_line(
            self.s.text(drop={lonely, finished}),
            ["test %s ... output of another thread" % lonely, "test %s ... ok" % finished, "ok"])
        status, notes, log = self.status(text)
        self.assertEqual({c: s for c, s in status.items() if s != "pass"}, {"Q01-C12": "blocked"}, status)
        self.assertEqual(log.unterminated, [lonely])
        self.assertNotIn(lonely, log.tests)
        self.assertTrue(any("printed their name and no result" in n for n in notes), notes)

    def test_a_second_test_name_before_any_result_takes_the_result_and_the_first_stays_blocked(self):
        lonely, second = self.first_test("Q01-C12"), self.first_test("Q01-C13")
        text = self.insert_before_the_first_test_line(
            self.s.text(drop={lonely, second}),
            ["test %s ... output of another thread" % lonely, "test %s ... more output" % second, "ok"])
        status, _notes, log = self.status(text)
        self.assertEqual({c: s for c, s in status.items() if s != "pass"}, {"Q01-C12": "blocked"}, status)
        self.assertEqual(log.unterminated, [lonely])
        self.assertEqual(log.tests[second], ["ok"])

    def test_a_log_that_ends_after_a_test_name_does_not_pass_that_test(self):
        test = self.first_test("Q01-C20")
        lines = self.s.text(drop={test}, noise=False).splitlines()
        lines.append("test %s ... " % test)
        status, _notes, log = self.status("\n".join(lines) + "\n")
        self.assertEqual(status["Q01-C20"], "blocked")
        self.assertEqual(log.unterminated, [test])

    def test_a_result_with_no_test_before_it_is_ignored(self):
        status, _notes, log = self.status("ok\nFAILED\nignored\n" + self.s.text())
        self.assertEqual(set(status.values()), {"pass"}, status)
        self.assertEqual(log.unterminated, [])


if __name__ == "__main__":
    unittest.main()
