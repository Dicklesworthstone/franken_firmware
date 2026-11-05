"""Tests of the Q01 judge (tests/q01/run_cases.py). Offline, standard library only.

The logs these tests judge are SYNTHETIC: they are built here, in memory, from the case table and the contract, and are never written
under the repository as if they were evidence. A synthetic log shows that the judge accepts what it should and names what it should
refuse; it says nothing about the Rust. Every plant is judged against the unplanted baseline first (it must pass), so a plant that
changes nothing cannot pass for a catch.
"""
import io
import json
import os
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

    def text(self, members=None, plants=None, drop=(), fail=(), noise=True, raw_lines=()):
        lines = ["running %d tests" % sum(len(c["tests"]) for c in self.cases)] if noise else []
        for case in self.cases:
            for test in case["tests"]:
                if test in drop:
                    continue
                lines.append("test %s ... %s" % (test, "FAILED" if test in fail else "ok"))
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
        # The three `by routing` cells the contract makes are confirmed, never silently upgraded.
        self.assertEqual(sum("confirmed by measurement" in n for n in notes), 3, notes)

    def test_no_log_blocks_every_case_and_never_passes_one(self):
        results, _, _ = rc.judge_cases(None)
        self.assertEqual({r.status for r in results}, {"blocked"})
        self.assertEqual(rc.exit_code(results), 3)

    def test_the_meta_checks_pass_on_this_repository(self):
        results = rc.meta_results()
        self.assertEqual({r.status for r in results}, {"pass"}, [(r.case, r.detail) for r in results if r.status != "pass"])
        self.assertEqual({r.case for r in results}, {"META-CASES", "META-CONTRACT", "META-DIGEST"})


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

    def test_a_by_routing_claim_the_log_contradicts_is_a_failure_and_one_it_confirms_is_a_note(self):
        def edit(rs):
            record = self.find(rs, "spk-bedroom-s1", "opposed")
            record.update(rendered_nonzero_blocks=3, digest=4242)
        problems, _ = self.plant(edit)
        self.assert_m01(problems, "spk-bedroom-s1 under opposed silent (by routing), the log contradicts it")
        _, notes = self.plant(lambda rs: None)
        self.assertTrue(any("spk-bedroom-s1 under opposed: silent, confirmed by measurement" in n for n in notes), notes)


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


if __name__ == "__main__":
    unittest.main()
