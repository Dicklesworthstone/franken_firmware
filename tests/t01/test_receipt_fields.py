"""Tests of the T01 runner receipt, schema v2 (bead ffw-32a, tests/t01/): "All tests publish exact build, target, profile, duration, seeds, denominator, maxima, failures and whether results
are host simulation, guest execution, real service or physical output." The runner receipt now publishes the run's and every case's duration, the profile version, each case's evidence kind and a
seeds statement, and refuses to be written without them. Standard library only, offline, no cargo.

Run: python3 -B -W error -m unittest tests/t01/test_receipt_fields.py   (from the repository root)

The evidence kind is DERIVED from what a case ran, never typed next to its name: a central case records the files it consumed (kind, path, sha256) and its kind is the strongest of theirs; a host
case consumes none. Each rule passes on the real receipt and reports a fault planted in a copy of it, and the unplanted copy passes again. What each real case consumes is held BY HAND below.
"""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import run_cases as rc  # noqa: E402
import t01lib as L  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
RECEIPTS = os.path.join(REPO, "toolchain", "results", "tailscale", "receipts")
BUILDS = os.path.join(REPO, "toolchain", "results", "tailscale", "builds")
MEASUREMENTS = os.path.join(REPO, "toolchain", "results", "tailscale", "measurements")

LEGACY_NAMES = ("t01-01665612603d232e.json", "t01-09ad140ddcc4f2c3.json", "t01-0db87ae2afa33766.json", "t01-71f9a235d148927a.json", "t01-8cdc69be60fccfa2.json", "t01-9f4270b321a6868a.json",
                "t01-d1fd5102fa96c248.json")
# What a real default `full` run (no --sources) ran, written from what each case does (contract section 7): the host cases ran on the host; the five source probes were blocked and ran nothing;
# T01-X01 judged captured `cargo check` logs; T01-X02 judged captured guest-run receipts.
EXPECTED_DEFAULT_FULL = {
    "T01-META-LEDGER": "host_simulation", "T01-META-PROFILE": "host_simulation", "T01-C01-classification": "host_simulation", "T01-C02-cell-rules": "host_simulation",
    "T01-C03-matrix": "host_simulation", "T01-C04-budget-rules": "host_simulation", "T01-C05-fixtures": "host_simulation", "T01-C06-native-requirement": "host_simulation",
    "T01-P01-tsrs-source": "none", "T01-P02-workspace-edges": "none", "T01-P03-awslc-targets": "none", "T01-P04-mio-reactor": "none", "T01-P05-ledger-vs-sources": "none",
    "T01-X01-legacy-isa-build": "compile_only", "T01-X02-target-resources": "guest_execution",
}
# The group of each case, written from what the case does: the independent expectation that cases.json `case_groups` and every real result must equal.
EXPECTED_GROUPS = {
    "T01-META-LEDGER": "meta", "T01-META-PROFILE": "meta", "T01-C01-classification": "rules", "T01-C02-cell-rules": "rules", "T01-C03-matrix": "rules", "T01-C04-budget-rules": "rules",
    "T01-C05-fixtures": "fixtures", "T01-C06-native-requirement": "contract", "T01-P01-tsrs-source": "probe", "T01-P02-workspace-edges": "probe", "T01-P03-awslc-targets": "probe",
    "T01-P04-mio-reactor": "probe", "T01-P05-ledger-vs-sources": "probe", "T01-X01-legacy-isa-build": "central", "T01-X02-target-resources": "central", "T01-RUNNER": "runner",
}
SHA = "ab" * 32


def rec(kind, path, sha=SHA):
    return {"kind": kind, "path": path, "sha256": sha}


def planted(problems, needle):
    return any(needle in p for p in problems)


def written(tier):
    """A real v2 receipt of a real run of the tier, as the writer wrote it."""
    with tempfile.TemporaryDirectory() as tmp:
        path = rc.write_receipt(tmp, tier, rc.run(tier), rc.artifact_digests(), None, "r2", None)
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)


class DeriveKind(unittest.TestCase):
    """The rule, as a hand-written truth table: (group, status, consumed kinds) -> what the case ran."""

    TABLE = (
        ("contract", "passed", (), "host_simulation"), ("contract", "failed", (), "host_simulation"), ("meta", "passed", (), "host_simulation"), ("rules", "passed", (), "host_simulation"),
        ("fixtures", "failed", (), "host_simulation"), ("probe", "passed", (), "host_simulation"), ("probe", "failed", (), "host_simulation"),
        ("probe", "blocked", (), "none"), ("contract", "blocked", (), "none"),
        ("central", "passed", (), "none"), ("central", "failed", (), "none"), ("central", "blocked", (), "none"), ("runner", "failed", (), "none"),
        ("central", "passed", ("compile_only",), "compile_only"), ("central", "blocked", ("compile_only", "compile_only"), "compile_only"), ("central", "failed", ("compile_only",), "compile_only"),
        ("central", "passed", ("guest_execution",), "guest_execution"), ("central", "blocked", ("guest_execution",), "guest_execution"),
        ("central", "blocked", ("host_simulation",), "host_simulation"),                                   # an analysis of a supplied transcript executed nothing
        ("central", "blocked", ("host_simulation", "guest_execution"), "guest_execution"),                  # the strongest consumed record decides
        ("central", "blocked", ("compile_only", "guest_execution"), "guest_execution"),
        ("central", "blocked", ("host_simulation", "compile_only"), "compile_only"),
    )

    def test_the_truth_table(self):
        for group, status, kinds, want in self.TABLE:
            consumed = [rec(k, "p") for k in kinds]
            self.assertEqual(rc.derive_kind(group, status, consumed), want, (group, status, kinds))

    def test_a_result_computes_its_own_kind_and_nobody_types_it(self):
        self.assertEqual(rc.Result("T01-C02-cell-rules", "passed", "", "contract").evidence_kind, "host_simulation")
        self.assertEqual(rc.Result("T01-P01-tsrs-source", "blocked", "", "probe").evidence_kind, "none")
        self.assertEqual(rc.Result("T01-X02-target-resources", "passed", "", "central", consumed=[rec("guest_execution", "p")]).evidence_kind, "guest_execution")
        with self.assertRaises(TypeError):
            rc.Result("T01-C02-cell-rules", "passed", "", "contract", evidence_kind="guest_execution")                       # there is no argument to type it into
        self.assertFalse(hasattr(rc, "CASE_EVIDENCE"))                                                                           # and no table by case id

    def test_a_host_group_and_a_central_group_are_the_two_kinds_of_case(self):
        self.assertEqual(set(rc.HOST_GROUPS), {"meta", "contract", "rules", "fixtures", "probe"})
        real = rc.run("full")
        groups = {r.case_id: r.group for r in real}
        self.assertEqual({g for case, g in groups.items() if g not in rc.HOST_GROUPS}, {"central"})
        self.assertEqual(sorted(case for case, g in groups.items() if g == "central"), ["T01-X01-legacy-isa-build", "T01-X02-target-resources"])

    def test_the_record_directories_are_the_ones_the_cases_read(self):
        self.assertEqual(rc.RECORD_DIRS["compile_only"], "/".join(rc.BUILD_DIR) + "/")
        self.assertEqual(rc.RECORD_DIRS["guest_execution"], "toolchain/results/tailscale/measurements/")
        self.assertEqual(set(rc.EVIDENCE_KINDS), {"none", "host_simulation", "compile_only", "guest_execution", "real_service", "physical_output"})
        self.assertEqual(set(rc.KIND_ORDER) & set(rc.NOT_CLAIMED_KINDS), set())                                                  # no record can be a service or a physical output


class WhatTheRealCasesConsumed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {r.case_id: r for r in rc.run("full")}

    def test_every_real_case_ran_what_the_hand_written_table_says(self):
        self.assertEqual(sorted(self.results), sorted(EXPECTED_DEFAULT_FULL))
        for case, kind in EXPECTED_DEFAULT_FULL.items():
            self.assertEqual(self.results[case].evidence_kind, kind, case)
        self.assertEqual({k for case, k in EXPECTED_DEFAULT_FULL.items() if rc.Result(case, "x").evidence_kind}, set(EXPECTED_DEFAULT_FULL.values()))

    def test_only_the_two_central_cases_consumed_anything_and_each_record_is_a_real_file_with_its_digest(self):
        for case, result in self.results.items():
            if case not in ("T01-X01-legacy-isa-build", "T01-X02-target-resources"):
                self.assertEqual(result.consumed, [], case)
        x01, x02 = self.results["T01-X01-legacy-isa-build"].consumed, self.results["T01-X02-target-resources"].consumed
        logs = sorted(n for n in os.listdir(BUILDS) if n.endswith(".log"))
        self.assertEqual(sorted(c["path"] for c in x01), ["toolchain/results/tailscale/builds/" + n for n in logs])
        self.assertEqual({c["kind"] for c in x01}, {"compile_only"})
        self.assertEqual(sorted(c["path"] for c in x02), ["toolchain/results/tailscale/measurements/x02-v3b-mips-20261108.json", "toolchain/results/tailscale/measurements/x02-v3b-powerpc-20261108.json"])
        self.assertEqual({c["kind"] for c in x02}, {"guest_execution"})
        for c in x01 + x02:
            with open(os.path.join(REPO, *c["path"].split("/")), "rb") as handle:
                self.assertEqual(L.sha256_bytes(handle.read()), c["sha256"], c["path"])

    def test_a_missing_record_directory_leaves_the_central_cases_with_no_kind_and_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual((rc.case_build(tmp).status, rc.case_build(tmp).evidence_kind), ("blocked", "none"))
            self.assertEqual((rc.case_resources(tmp).status, rc.case_resources(tmp).evidence_kind), ("blocked", "none"))

    def test_a_partial_build_account_is_blocked_yet_compile_only_for_the_logs_it_judged(self):
        names = ("x01-core-powerpc-unknown-linux-musl-20261107.log", "x01-core-mips-unknown-linux-musl-20261107.log")
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, *rc.BUILD_DIR))
            os.makedirs(os.path.join(tmp, "tests", "tailscale-fixtures", "x01"))
            with open(os.path.join(REPO, "tests", "tailscale-fixtures", "x01", "consumer.lock"), "rb") as handle:
                lock = handle.read()
            with open(os.path.join(tmp, "tests", "tailscale-fixtures", "x01", "consumer.lock"), "wb") as handle:
                handle.write(lock)
            for name in names:
                with open(os.path.join(BUILDS, name), "rb") as src, open(os.path.join(tmp, *rc.BUILD_DIR, name), "wb") as dst:
                    dst.write(src.read())
            result = rc.case_build(tmp, rc.inputs())
            self.assertEqual(result.status, "blocked")                                                                           # two of the four attempts: partial evidence only
            self.assertIn("INCOMPLETE", result.detail)
            self.assertEqual(sorted(c["path"] for c in result.consumed), ["toolchain/results/tailscale/builds/" + n for n in sorted(names)])
            self.assertEqual(result.evidence_kind, "compile_only")                                                               # blocked, but a captured type-check was judged
            self.assertEqual({c["kind"] for c in result.consumed}, {"compile_only"})

    def test_a_captured_run_that_is_blocked_is_still_guest_execution_and_a_receipt_that_failed_to_judge_is_not_recorded(self):
        blocked = rc.X.ReceiptJudgement("blocked", ["a reading is UNKNOWN"], "mips")
        with mock.patch.object(rc.X, "judge_receipt", return_value=blocked):
            result = rc.case_resources(REPO)
        self.assertEqual((result.status, result.evidence_kind), ("blocked", "guest_execution"))                                  # a captured run executed, whatever its footprint says
        self.assertEqual(len(result.consumed), 2)
        failed = rc.X.ReceiptJudgement("failed", ["not a valid receipt"], None)
        with mock.patch.object(rc.X, "judge_receipt", return_value=failed):
            result = rc.case_resources(REPO)
        self.assertEqual((result.status, result.consumed, result.evidence_kind), ("failed", [], "none"))                         # what could not be judged is not evidence of anything

    def test_a_supplied_transcript_analysis_is_host_simulation_and_never_a_guest_run(self):
        real = os.path.join(MEASUREMENTS, "x02-v3b-mips-20261108.json")
        with open(real, encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["evidence_kind"] = "supplied_transcript_analysis"
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "toolchain", "results", "tailscale", "measurements")
            os.makedirs(directory)
            with open(os.path.join(directory, "x02-analysis.json"), "w", encoding="utf-8") as handle:
                json.dump(doc, handle)
            result = rc.case_resources(tmp)
            self.assertEqual(result.status, "blocked")
            self.assertEqual([c["kind"] for c in result.consumed], ["host_simulation"])
            self.assertEqual(result.evidence_kind, "host_simulation")                                                            # judged, but nothing executed


class TheWrittenReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke, cls.full = written("smoke"), written("full")

    def test_a_real_receipt_publishes_every_field_and_passes_its_own_check_against_the_repository(self):
        for doc in (self.smoke, self.full):
            self.assertEqual(rc.check_receipt(doc, "t01-r2.json", REPO), [])
            self.assertEqual(doc["schema"], "ffw.t01.receipt.v2")
            self.assertEqual(doc["profile_version"], L.load_json(L.PROFILE)["profile_version"])
            self.assertEqual((doc["seeds"]["applies"], bool(doc["seeds"]["reason"])), (False, True))
            self.assertIn("not the duration of any build or guest run a case judged", doc["duration_note"])                          # T01-X01/X02 report the judging time, and the receipt says so
            self.assertTrue(doc["duration_s"] >= 0 and doc["duration_s"] < 86400)
            self.assertEqual(doc["counts"], {s: sum(1 for r in doc["results"] if r["status"] == s) for s in ("passed", "failed", "blocked")})
        self.assertEqual([r["case"] for r in self.smoke["results"]], rc.SMOKE_IDS)
        self.assertEqual([r["case"] for r in self.full["results"]], rc.planned_ids("full"))                                      # the denominator is the tier's plan

    def test_every_result_carries_the_kind_it_ran_the_files_it_consumed_and_a_duration(self):
        for r in self.full["results"]:
            self.assertEqual(r["evidence_kind"], EXPECTED_DEFAULT_FULL[r["case"]], r["case"])
            self.assertIsInstance(r["consumed"], list, r["case"])
            self.assertIsInstance(r["duration_s"], float, r["case"])
            self.assertTrue(0 <= r["duration_s"] < 600, r["case"])
        self.assertGreaterEqual(self.full["duration_s"] + rc.DURATION_SLACK_S, sum(r["duration_s"] for r in self.full["results"]))

    def check(self, mutate, base=None, repo=REPO):
        doc = copy.deepcopy(base or self.full)
        mutate(doc)
        return rc.check_receipt(doc, "t01-r2.json", repo)

    def result(self, d, case):
        return next(r for r in d["results"] if r["case"] == case)

    def test_a_host_case_labelled_guest_execution_is_refused_and_the_compile_only_case_is_the_control(self):
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control: the real receipt
        control = self.result(self.full, "T01-X01-legacy-isa-build")
        self.assertEqual((control["evidence_kind"], {c["kind"] for c in control["consumed"]}), ("compile_only", {"compile_only"}))
        for case in ("T01-C02-cell-rules", "T01-META-LEDGER", "T01-P01-tsrs-source"):
            problems = self.check(lambda d, case=case: self.result(d, case).update({"evidence_kind": "guest_execution"}))
            self.assertTrue(planted(problems, "%s: evidence_kind guest_execution, but what it consumed gives" % case), case)    # a label is not evidence
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"evidence_kind": "compile_only"})), "but what it consumed gives host_simulation"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-X01-legacy-isa-build").update({"evidence_kind": "host_simulation"})), "evidence_kind host_simulation, but what it consumed gives compile_only"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-X01-legacy-isa-build").update({"evidence_kind": "guest_execution"})), "but what it consumed gives compile_only"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-X02-target-resources").update({"evidence_kind": "compile_only"})), "but what it consumed gives guest_execution"))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_a_label_cannot_stand_without_the_files_that_make_it(self):
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-X01-legacy-isa-build").update({"consumed": []})), "but what it consumed gives none"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-X02-target-resources").update({"consumed": [], "evidence_kind": "host_simulation"})), "but what it consumed gives none"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"evidence_kind": "none"})), "but what it consumed gives host_simulation"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-P01-tsrs-source").update({"evidence_kind": "host_simulation"})), "but what it consumed gives none"))  # blocked: it ran nothing

    def test_a_host_case_cannot_have_consumed_a_recorded_file(self):
        guest = copy.deepcopy(self.result(self.full, "T01-X02-target-resources")["consumed"][0])
        group = self.result(self.full, "T01-C02-cell-rules")["group"]
        self.assertIn(group, rc.HOST_GROUPS)
        problems = self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"consumed": [guest], "evidence_kind": "guest_execution"}))
        self.assertTrue(planted(problems, "T01-C02-cell-rules: a host case (group %s) reads only files and hand-written tables" % group))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control

    def test_a_pass_that_ran_nothing_is_refused_and_none_stays_for_what_did_not_run(self):
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control: the real receipt, X01 and X02 passed with 8 and 2 consumed
        for case in ("T01-X01-legacy-isa-build", "T01-X02-target-resources"):
            # plant A: a central case recorded as passed on no evidence, with a label that matches what it consumed
            problems = self.check(lambda d, case=case: self.result(d, case).update({"consumed": [], "evidence_kind": "none"}))
            self.assertTrue(planted(problems, "%s: a passed result consumed nothing and ran nothing, so it passed on no evidence" % case), case)
            self.assertEqual(len(problems), 1, problems)                                                                         # and nothing else is wrong with it: the label matched
            self.assertTrue(planted(self.check(lambda d, case=case: self.result(d, case).update({"consumed": []})), "passed on no evidence"))      # with the old label too
        # `none` stays right wherever nothing ran: a blocked probe, a central case that failed or was blocked, and the crashed run
        probe = self.result(self.full, "T01-P01-tsrs-source")
        self.assertEqual((probe["status"], probe["evidence_kind"], probe["consumed"]), ("blocked", "none", []))

        def central_did_not_pass(d, status):
            self.result(d, "T01-X01-legacy-isa-build").update({"status": status, "consumed": [], "evidence_kind": "none"})
            d["counts"]["passed"] -= 1
            d["counts"][status] += 1
        for status in ("failed", "blocked"):
            self.assertEqual(self.check(lambda d, s=status: central_did_not_pass(d, s)), [], status)
        # a host case that passed ran on the host: it is never `none`
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"evidence_kind": "none"})), "but what it consumed gives host_simulation"))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_a_result_cannot_restate_its_cases_group(self):
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control: the real receipt
        # plant B: X01 relabelled a rules case, with nothing consumed and a host label, which every other check would accept
        problems = self.check(lambda d: self.result(d, "T01-X01-legacy-isa-build").update({"group": "rules", "consumed": [], "evidence_kind": "host_simulation"}))
        self.assertTrue(planted(problems, "T01-X01-legacy-isa-build: group 'rules', but the plan says 'central'"))
        # a host case relabelled central, with nothing and with a real guest record consumed
        guest = copy.deepcopy(self.result(self.full, "T01-X02-target-resources")["consumed"][0])
        problems = self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"group": "central", "consumed": [guest], "evidence_kind": "guest_execution"}))
        self.assertTrue(planted(problems, "T01-C02-cell-rules: group 'central', but the plan says 'rules'"))
        # every result, relabelled into every other group, is refused by the plan
        groups = sorted(set(EXPECTED_GROUPS.values()))
        for r in self.full["results"]:
            for other in groups:
                if other != EXPECTED_GROUPS[r["case"]]:
                    problems = self.check(lambda d, case=r["case"], other=other: self.result(d, case).update({"group": other}))
                    self.assertTrue(planted(problems, "%s: group %r, but the plan says %r" % (r["case"], other, EXPECTED_GROUPS[r["case"]])), (r["case"], other))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").pop("group")), "group None, but the plan says 'rules'"))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_each_consumed_record_must_be_a_real_file_with_its_digest_under_its_own_directory(self):
        x01 = lambda d: self.result(d, "T01-X01-legacy-isa-build")["consumed"]
        x02 = lambda d: self.result(d, "T01-X02-target-resources")["consumed"]
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"sha256": SHA})), "is not the file that was judged (sha256 differs)"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"path": "toolchain/results/tailscale/builds/no-such-record.log"})), "cannot be read"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"path": "toolchain/results/tailscale/measurements/x02-v3b-mips-20261108.json"})), "a compile_only record lives directly under"))
        self.assertTrue(planted(self.check(lambda d: x02(d)[0].update({"path": x01(d)[0]["path"]})), "a guest_execution record lives directly under"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"path": "toolchain/results/tailscale/builds/../builds/" + x01(d)[0]["path"].rsplit("/", 1)[1]})), "lives directly under"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"path": "/etc/passwd"})), "lives directly under"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"path": "toolchain/results/tailscale/builds/"})), "lives directly under"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"sha256": "ABC"})), "needs a kind"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].update({"kind": "real_service"})), "needs a kind"))
        self.assertTrue(planted(self.check(lambda d: x01(d)[0].pop("path")), "needs a kind"))
        self.assertTrue(planted(self.check(lambda d: x01(d).append("a string")), "needs a kind"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").update({"consumed": None})), "consumed must list the recorded files"))
        self.assertTrue(planted(self.check(lambda d: self.result(d, "T01-C02-cell-rules").pop("consumed")), "consumed must list the recorded files"))
        # without the repository only the shape is checked, so the same sha plant passes the shape check and a repository is what catches it
        self.assertEqual(self.check(lambda d: x01(d)[0].update({"sha256": SHA}), repo=None), [])
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control

    def test_a_log_supplied_from_outside_the_repository_is_named_by_position_and_is_only_ever_a_build_log(self):
        supplied = rec("compile_only", "supplied build log 1")
        self.assertEqual(self.check(lambda d: self.result(d, "T01-X01-legacy-isa-build")["consumed"].append(supplied)), [])
        problems = self.check(lambda d: self.result(d, "T01-X02-target-resources")["consumed"].append(rec("guest_execution", "supplied build log 2")))
        self.assertTrue(planted(problems, "only a build log can be supplied from outside the repository"))

    def test_each_planted_field_fault_is_reported_and_the_unplanted_copy_passes_again(self):
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control
        for label, value in (("missing", None), ("negative", -0.001), ("nan", float("nan")), ("inf", float("inf")), ("bool", True), ("string", "1.0"), ("beyond a day", 86400.5)):
            def plant(d, value=value):
                d["duration_s"] = value
            self.assertTrue(planted(self.check(plant), "the run: duration_s"), label)
        self.assertTrue(planted(self.check(lambda d: d.pop("duration_s")), "the run: duration_s"))
        for label, value in (("missing", None), ("negative", -1), ("nan", float("nan")), ("string", "0.1")):
            def plant(d, value=value):
                d["results"][3]["duration_s"] = value
            self.assertTrue(planted(self.check(plant), "T01-C02-cell-rules: duration_s"), label)
        self.assertTrue(planted(self.check(lambda d: d["results"][3].pop("duration_s")), "T01-C02-cell-rules: duration_s"))
        self.assertTrue(planted(self.check(lambda d: d.update({"duration_s": 0.0}) or d["results"][0].update({"duration_s": 5.0})), "is less than the"))
        self.assertTrue(planted(self.check(lambda d: d["results"][0].pop("evidence_kind")), "evidence_kind None is not one of"))
        self.assertTrue(planted(self.check(lambda d: d["results"][0].update({"evidence_kind": "simulated"})), "is not one of"))
        self.assertTrue(planted(self.check(lambda d: d["results"][0].update({"evidence_kind": "real_service"})), "T01 holds no real_service evidence"))
        self.assertTrue(planted(self.check(lambda d: d["results"][0].update({"evidence_kind": "physical_output"})), "T01 holds no physical_output evidence"))
        self.assertTrue(planted(self.check(lambda d: d.pop("duration_note")), "duration_note must say"))
        self.assertTrue(planted(self.check(lambda d: d.update({"duration_note": "seconds"})), "duration_note must say"))
        for value in (None, "latest", "t01-profile-2026-11-09", "T01-PROFILE-2026-11-09.1", 3):
            def plant(d, value=value):
                d["profile_version"] = value
            self.assertTrue(planted(self.check(plant), "profile_version"), repr(value))
        self.assertTrue(planted(self.check(lambda d: d.pop("profile_version")), "profile_version"))
        self.assertTrue(planted(self.check(lambda d: d.pop("seeds")), "seeds must state that none apply"))
        self.assertTrue(planted(self.check(lambda d: d["seeds"].update({"applies": True})), "seeds must state that none apply"))
        self.assertTrue(planted(self.check(lambda d: d["seeds"].update({"reason": "  "})), "seeds must state that none apply"))
        self.assertTrue(planted(self.check(lambda d: d.update({"seeds": []})), "seeds must state that none apply"))
        self.assertTrue(planted(self.check(lambda d: d["results"].pop()), "not the tier's planned cases"))
        self.assertTrue(planted(self.check(lambda d: d["results"].reverse()), "not the tier's planned cases"))
        self.assertTrue(planted(self.check(lambda d: d["counts"].update({"passed": 99})), "are not the results' own"))
        self.assertTrue(planted(self.check(lambda d: d["results"][0].update({"status": "skipped"})), "status 'skipped' is not passed, failed or blocked"))
        self.assertTrue(planted(self.check(lambda d: d.update({"schema": "ffw.t01.receipt.v3"})), "the receipt schema is"))
        self.assertTrue(planted(self.check(lambda d: d.update({"tier": "soak"})), "is not one that runs"))
        self.assertTrue(planted(self.check(lambda d: d.update({"results": []})), "lists no results"))
        self.assertEqual(rc.check_receipt([], "x"), ["the receipt is not a JSON object"])
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_the_failed_result_of_a_crashed_run_is_the_only_other_denominator(self):
        crash = {"schema": rc.RECEIPT_SCHEMA, "run_id": "r", "tier": "smoke", "duration_s": 0.01, "duration_note": rc.DURATION_NOTE, "profile_version": self.smoke["profile_version"], "seeds": self.smoke["seeds"],
                 "counts": {"passed": 0, "failed": 1, "blocked": 0},
                 "results": [{"case": "T01-RUNNER", "status": "failed", "evidence_kind": "none", "consumed": [], "duration_s": 0.01, "detail": "x", "group": "runner"}]}
        self.assertEqual(rc.check_receipt(crash, "t01-r.json", REPO), [])
        two = copy.deepcopy(crash)
        two["results"].append(copy.deepcopy(crash["results"][0]))
        two["counts"]["failed"] = 2
        self.assertTrue(planted(rc.check_receipt(two, "t01-r.json"), "not the tier's planned cases"))                           # runner results do not stand in for cases
        typed = copy.deepcopy(crash)
        typed["results"][0]["evidence_kind"] = "host_simulation"
        self.assertTrue(planted(rc.check_receipt(typed, "t01-r.json"), "but what it consumed gives none"))                       # a crashed run ran nothing
        passed = copy.deepcopy(crash)
        passed["results"][0]["status"] = "passed"
        passed["counts"] = {"passed": 1, "failed": 0, "blocked": 0}
        self.assertTrue(planted(rc.check_receipt(passed, "t01-r.json"), "T01-RUNNER: a passed result consumed nothing and ran nothing"))        # a crash record is never a pass
        regrouped = copy.deepcopy(crash)
        regrouped["results"][0]["group"] = "central"
        self.assertTrue(planted(rc.check_receipt(regrouped, "t01-r.json"), "group 'central', but the plan says 'runner'"))       # the crash record keeps its own group, and only that one


class ThePlanOfGroups(unittest.TestCase):
    """cases.json `case_groups` is the runner's plan: every result is in its case's group, including a case that raised and a run whose inputs could not be read."""

    def test_the_plan_is_the_hand_written_table(self):
        self.assertEqual(rc.plan_groups(), EXPECTED_GROUPS)
        self.assertEqual(sorted(EXPECTED_GROUPS), sorted(rc.planned_ids("full") + ["T01-RUNNER"]))
        self.assertEqual(sorted(k for k, v in EXPECTED_GROUPS.items() if v == "central"), ["T01-X01-legacy-isa-build", "T01-X02-target-resources"])
        self.assertEqual(set(EXPECTED_GROUPS.values()) - set(rc.HOST_GROUPS), {"central", "runner"})

    def test_every_real_result_carries_its_planned_group(self):
        for r in rc.run("full"):
            self.assertEqual(r.group, EXPECTED_GROUPS[r.case_id], r.case_id)

    def test_a_case_that_raises_and_unreadable_inputs_keep_the_planned_group_and_still_make_a_receipt(self):
        def boom(_data, _repo):
            raise RuntimeError("boom")
        with mock.patch.object(rc, "SMOKE_CASES", rc.SMOKE_CASES[:3] + (boom,) + rc.SMOKE_CASES[4:]):
            raised = rc.run("smoke")
        self.assertEqual((raised[3].case_id, raised[3].status, raised[3].group), ("T01-C02-cell-rules", "failed", "rules"))      # not the generic group the guard used to give
        with tempfile.TemporaryDirectory() as tmp:
            unreadable = rc.run("full", None, os.path.join(tmp, "nothing-here"))
            self.assertEqual({r.case_id: r.group for r in unreadable}, {k: v for k, v in EXPECTED_GROUPS.items() if k != "T01-RUNNER"})
            for results, tier, run_id in ((raised, "smoke", "r20"), (unreadable, "full", "r21")):
                path = rc.write_receipt(os.path.join(tmp, "r"), tier, results, {}, None, run_id, None)
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(rc.check_receipt(json.load(handle), os.path.basename(path), REPO), [], run_id)

    def test_a_central_case_that_raises_is_a_failed_central_case_that_ran_nothing(self):
        for name, case in (("T01-X01-legacy-isa-build", "case_build"), ("T01-X02-target-resources", "case_resources")):
            with mock.patch.object(rc, case, side_effect=RuntimeError("boom")):
                results = rc.run("full")
            result = {r.case_id: r for r in results}[name]
            self.assertEqual((result.status, result.group, result.evidence_kind, result.consumed), ("failed", "central", "none", []), name)    # failed with none is allowed; passed with none is not
            with tempfile.TemporaryDirectory() as tmp:
                path = rc.write_receipt(os.path.join(tmp, "r"), "full", results, {}, None, "r30", None)
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(rc.check_receipt(json.load(handle), os.path.basename(path), REPO), [], name)

    def test_a_plan_that_cannot_be_read_refuses_the_receipt_and_never_guesses_a_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = written("smoke")
            self.assertEqual(rc.check_receipt(doc, "t01-r2.json", REPO), [])                                                     # control
            for label, text in (("missing", None), ("not json", "{"), ("no table", "{}"), ("a list", '{"case_groups": []}'), ("a non-string group", '{"case_groups": {"T01-C01-classification": 3}}')):
                path = os.path.join(tmp, label.replace(" ", "-") + ".json")
                if text is not None:
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write(text)
                with mock.patch.object(rc, "PLAN_PATH", path):
                    problems = rc.check_receipt(doc, "t01-r2.json", REPO)
                self.assertTrue(any("the plan of case groups" in p and "cannot be read" in p for p in problems), label)
            def boom(_data, _repo):
                raise RuntimeError("boom")
            with mock.patch.object(rc, "PLAN_PATH", os.path.join(tmp, "missing.json")), mock.patch.object(rc, "SMOKE_CASES", rc.SMOKE_CASES[:3] + (boom,) + rc.SMOKE_CASES[4:]):
                results = rc.run("smoke")                                                                                        # without a plan a case that raises falls in the generic group
            self.assertEqual((results[3].case_id, results[3].group), ("T01-C02-cell-rules", "contract"))
            with self.assertRaises(rc.ReceiptRefused) as caught:                                                                 # and a receipt of that run is refused once the plan is back
                rc.write_receipt(os.path.join(tmp, "r"), "smoke", results, {}, None, "r22", None)
            self.assertIn("T01-C02-cell-rules: group 'contract', but the plan says 'rules'", str(caught.exception))
            self.assertEqual(rc.check_receipt(doc, "t01-r2.json", REPO), [])                                                     # and the unplanted state passes again


class LegacyReceipts(unittest.TestCase):
    def names(self):
        return sorted(n for n in os.listdir(RECEIPTS) if n.startswith("t01-") and n.endswith(".json") and not n.startswith("t01-diag-"))

    def load(self, name):
        with open(os.path.join(RECEIPTS, name), encoding="utf-8") as handle:
            return json.load(handle)

    def test_every_committed_receipt_passes_and_the_legacy_list_is_exactly_the_v1_ones(self):
        self.assertEqual(tuple(sorted(rc.LEGACY_RECEIPTS)), LEGACY_NAMES)                                                         # the list is the hand-written seven
        names = self.names()
        for name in names:
            doc = self.load(name)
            self.assertEqual(rc.check_receipt(doc, name, REPO), [], name)
            self.assertEqual(doc["schema"] == rc.LEGACY_RECEIPT_SCHEMA, name in LEGACY_NAMES, name)                              # v1 exactly when it is one of the seven
        self.assertTrue(set(LEGACY_NAMES) <= set(names))                                                                         # none of the seven was removed or renamed

    def test_a_new_receipt_cannot_pass_by_being_labelled_v1(self):
        real = self.load(LEGACY_NAMES[0])
        self.assertEqual(rc.check_receipt(real, LEGACY_NAMES[0]), [])                                                           # control: the real legacy receipt
        self.assertTrue(planted(rc.check_receipt(real, "t01-ffffffffffffffff.json"), "is valid only as one of the 7 committed before the v2 fields existed"))
        v2 = written("smoke")
        relabelled = copy.deepcopy(v2)
        relabelled["schema"] = rc.LEGACY_RECEIPT_SCHEMA
        self.assertTrue(planted(rc.check_receipt(relabelled, "t01-r2.json"), "is valid only as one of the 7"))
        self.assertTrue(planted(rc.check_receipt(relabelled, ""), "this receipt is not one of them"))
        self.assertEqual(rc.check_receipt(v2, "t01-r2.json"), [])                                                                # and the v2 receipt passes as v2

    def test_the_seven_legacy_receipts_lack_the_v2_fields_so_the_v2_check_would_refuse_them(self):
        for name in LEGACY_NAMES:
            relabelled = self.load(name)
            relabelled["schema"] = rc.RECEIPT_SCHEMA
            problems = rc.check_receipt(relabelled, name)
            self.assertTrue(planted(problems, "duration_s"), name)
            self.assertTrue(planted(problems, "seeds must state"), name)
            self.assertTrue(planted(problems, "consumed must list"), name)


class TheWriter(unittest.TestCase):
    def results(self, with_duration=True):
        return [rc.Result(case, "passed", "", EXPECTED_GROUPS[case], 0.001 if with_duration else None) for case in rc.SMOKE_IDS]

    def write(self, tmp, results, run_id="r3", duration=None, tier="smoke"):
        return rc.write_receipt(os.path.join(tmp, "r"), tier, results, {}, None, run_id, None, duration)

    def test_a_receipt_without_durations_is_refused_and_nothing_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(rc.ReceiptRefused) as caught:
                self.write(tmp, self.results(with_duration=False))
            self.assertIn("duration_s", str(caught.exception))
            self.assertFalse(os.path.exists(os.path.join(tmp, "r")))                                                             # not even the directory
            path = self.write(tmp, self.results())                                                                               # the control: the same results with durations
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(rc.check_receipt(json.load(handle), os.path.basename(path), REPO), [])

    def test_a_case_that_is_not_in_the_tiers_plan_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = self.results()
            results[0] = rc.Result("T01-NEW-case", "passed", "", "meta", 0.001)
            with self.assertRaises(rc.ReceiptRefused) as caught:
                self.write(tmp, results, "r4")
            self.assertIn("not the tier's planned cases", str(caught.exception))

    def test_a_host_case_that_consumed_a_guest_record_is_refused_at_the_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = rc.case_resources(REPO).consumed[0]
            results = self.results()
            results[3] = rc.Result(rc.SMOKE_IDS[3], "passed", "", EXPECTED_GROUPS[rc.SMOKE_IDS[3]], 0.001, consumed=[real])
            with self.assertRaises(rc.ReceiptRefused) as caught:
                self.write(tmp, results, "r9")
            self.assertIn("a host case (group rules) reads only files and hand-written tables", str(caught.exception))
            self.write(tmp, self.results(), "r9")                                                                                # the control, same run id: nothing was left behind by the refusal

    def full_results(self):
        results = rc.run("full")
        self.assertEqual([r.case_id for r in results], rc.planned_ids("full"))
        return results

    def test_a_record_that_is_not_the_file_that_was_judged_is_refused_at_the_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = self.full_results()
            self.write(tmp, results, "r10", tier="full")                                                                         # the control: the real run, with its real digests
            results = self.full_results()
            results[13].consumed[0]["sha256"] = SHA                                                                              # T01-X01 names a real log with a digest that is not its own
            with self.assertRaises(rc.ReceiptRefused) as caught:
                self.write(tmp, results, "r11", tier="full")
            self.assertIn("sha256 differs", str(caught.exception))

    def test_a_pass_that_ran_nothing_is_refused_at_the_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            for index in (13, 14):                                                                                               # T01-X01 and T01-X02, both central and both passed in the real run
                results = self.full_results()
                self.assertEqual((results[index].status, len(results[index].consumed) > 0), ("passed", True))
                results[index].consumed = []
                with self.assertRaises(rc.ReceiptRefused) as caught:
                    self.write(tmp, results, "r12%d" % index, tier="full")
                self.assertIn("passed on no evidence", str(caught.exception))
            self.write(tmp, self.full_results(), "r12", tier="full")                                                             # and the real run is written

    def test_an_explicit_run_duration_is_published_and_a_shorter_one_than_the_cases_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write(tmp, self.results(), "r5", 2.5)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["duration_s"], 2.5)
            slow = self.results()
            slow[0].duration_s = 9.0
            with self.assertRaises(rc.ReceiptRefused) as caught:
                self.write(tmp, slow, "r6", 1.0)
            self.assertIn("is less than the", str(caught.exception))

    def test_a_second_receipt_of_the_same_run_still_never_overwrites_the_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write(tmp, self.results(), "r7")
            with self.assertRaises(FileExistsError):
                self.write(tmp, self.results(), "r7")


class TheTimer(unittest.TestCase):
    def test_a_case_is_timed_to_the_millisecond_from_the_monotonic_clock(self):
        with mock.patch.object(rc.time, "monotonic", side_effect=[10.0, 12.5004]):
            result = rc.timed(lambda: rc.Result("T01-X", "passed"))
        self.assertEqual(result.duration_s, 2.5)
        self.assertEqual(result.as_dict()["duration_s"], 2.5)

    def test_a_case_that_raises_is_a_failed_timed_case_and_the_run_goes_on(self):
        def boom(_data, _repo):
            raise RuntimeError("boom")
        with mock.patch.object(rc, "SMOKE_CASES", (boom,) + rc.SMOKE_CASES[1:]):
            results = rc.run("smoke")
        self.assertEqual(results[0].status, "failed")
        self.assertEqual(results[0].evidence_kind, "host_simulation")                                                            # a host case that raised still ran on the host
        self.assertIsInstance(results[0].duration_s, float)
        self.assertTrue(all(isinstance(r.duration_s, float) and r.duration_s >= 0 for r in results))

    def test_unreadable_inputs_fail_every_case_with_no_time_and_still_make_a_receipt_that_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = rc.run("full", None, os.path.join(tmp, "nothing-here"))
            self.assertEqual({r.status for r in results}, {"failed"})
            self.assertEqual({r.duration_s for r in results}, {0.0})
            path = rc.write_receipt(os.path.join(tmp, "r"), "full", results, {}, None, "r8", None)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(rc.check_receipt(json.load(handle), os.path.basename(path), REPO), [])


class TheEntryPoint(unittest.TestCase):
    def run_main(self, tmp, argv, **patches):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(rc, name, **value))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = rc.main(argv + ["--receipts", tmp])
        return code, out.getvalue(), err.getvalue()

    def receipt(self, tmp):
        names = [n for n in os.listdir(tmp) if n.startswith("t01-") and n.endswith(".json")]
        self.assertEqual(len(names), 1, names)
        with open(os.path.join(tmp, names[0]), encoding="utf-8") as handle:
            return names[0], json.load(handle)

    def test_the_command_line_run_writes_a_v2_receipt_with_the_measured_duration(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_main(tmp, ["--tier", "smoke"])
            self.assertEqual(code, 0, out)
            name, doc = self.receipt(tmp)
            self.assertEqual(rc.check_receipt(doc, name, REPO), [])
            self.assertGreater(doc["duration_s"], 0)
            self.assertEqual(doc["schema"], rc.RECEIPT_SCHEMA)

    def test_a_full_command_line_run_records_the_files_its_central_cases_judged(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_main(tmp, ["--tier", "full"])
            name, doc = self.receipt(tmp)
            self.assertEqual(rc.check_receipt(doc, name, REPO), [])
            kinds = {r["case"]: r["evidence_kind"] for r in doc["results"]}
            self.assertEqual(kinds, EXPECTED_DEFAULT_FULL)

    def test_a_crashed_run_still_gets_a_receipt_that_says_how_long_it_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_main(tmp, ["--tier", "smoke"], run={"side_effect": RuntimeError("boom")})
            self.assertEqual(code, 1)
            name, doc = self.receipt(tmp)
            self.assertEqual([r["case"] for r in doc["results"]], ["T01-RUNNER"])
            self.assertEqual(rc.check_receipt(doc, name, REPO), [])
            self.assertEqual(doc["results"][0]["evidence_kind"], "none")
            self.assertIsInstance(doc["results"][0]["duration_s"], float)

    def test_a_refused_receipt_is_reported_without_a_traceback_and_no_receipt_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.run_main(tmp, ["--tier", "smoke"], current_profile_version={"return_value": "latest"})
            self.assertEqual(code, 1)                                                                                            # a run that would have passed is not reported as written
            self.assertNotIn("Traceback", out + err)
            self.assertIn("the receipt was refused, and none was written", err)
            self.assertIn("profile_version", err)
            self.assertEqual([n for n in os.listdir(tmp) if n.endswith(".json")], [])
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_main(tmp, ["--tier", "smoke"])                                                                 # the control: unpatched
            self.assertEqual(code, 0)
            self.assertEqual(len([n for n in os.listdir(tmp) if n.endswith(".json")]), 1)


class TheProfileVersion(unittest.TestCase):
    def test_an_unreadable_profile_is_stated_in_the_receipt_and_never_invented(self):
        with mock.patch.object(L, "load_json", side_effect=OSError("gone")):
            self.assertEqual(rc.current_profile_version(), rc.PROFILE_UNREADABLE)
        self.assertEqual(rc.current_profile_version(), L.load_json(L.PROFILE)["profile_version"])
        with mock.patch.object(L, "load_json", return_value={"profile_version": 7}):
            self.assertEqual(rc.current_profile_version(), rc.PROFILE_UNREADABLE)


if __name__ == "__main__":
    unittest.main()
