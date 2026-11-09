"""Tests of the binding of a `measured` figure to its receipt (bead ffw-32a, tests/t01/). A `measured` item must name a real receipt (test_closure_map.py::MeasuredNeedsARealReceipt); it must also be BOUND to
it: the receipt judges as a passed captured guest run now (x02_judge.judge_receipt, whose re-derived `resources` are the only source of the figure), it measured the core probe and ran in a harness guest, its
digest and architecture fit, the item's field is the one the table fixes for that item and nothing else, and its value equals the receipt's after the unit's scale. Standard library only, offline, no cargo.

Run: python3 -B -W error -m unittest tests/t01/test_figure_binding.py   (from the repository root)

No row is measured today and no row exists for the core probe (root, 17433), so the controls here plant a probe row `t01-core-probe/<target>` in a COPY of the profile. Each rule passes on the real committed
receipts and reports a fault planted in a copy, and the unplanted copy passes again. The figures the receipts must hold are written BY HAND below from contract section 9, not read from the judge.
"""
import copy
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
import x02_judge as X  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
PROFILE = L.load_json(L.PROFILE)
LEDGER = L.load_json(L.LEDGER)
DIR = "toolchain/results/tailscale/measurements/"
PROBE = "t01-core-probe"
RECEIPT = {"mips": "x02-v3b-mips-20261108.json", "powerpc": "x02-v3b-powerpc-20261108.json"}
TARGET = {"mips": "mips32be_harness", "powerpc": "ppc32be_harness"}
# The resources of the two committed receipts (contract section 9, "What ran"): VmHWM and VmRSS in kB, utime and stime in raw clock ticks.
RESOURCES = {"mips": {"VmHWM": 924, "VmRSS": 904, "utime": 29, "stime": 191}, "powerpc": {"VmHWM": 772, "VmRSS": 756, "utime": 10, "stime": 1}}
# What the table must bind each item to, written by hand: rss_peak_bytes is VmHWM in bytes (kB x 1024); cpu is utime + stime in clock ticks.
FIELD = {"rss_peak_bytes": "verdict.resources.VmHWM", "cpu": "verdict.resources.utime+verdict.resources.stime"}
UNIT = {"rss_peak_bytes": "bytes", "cpu": "clock_ticks"}
VALUE = {"mips": {"rss_peak_bytes": 924 * 1024, "cpu": 29 + 191}, "powerpc": {"rss_peak_bytes": 772 * 1024, "cpu": 10 + 1}}
ITEMS = ("rss_peak_bytes", "cpu")
ARCHES = ("mips", "powerpc")


def planted(problems, needle):
    return any(needle in p for p in problems)


def receipt_bytes(arch):
    with open(os.path.join(REPO, *(DIR + RECEIPT[arch]).split("/")), "rb") as handle:
        return handle.read()


def sha(arch):
    return L.sha256_bytes(receipt_bytes(arch))


def doctored_text(tmp):
    with open(os.path.join(tmp, *DIR.rstrip("/").split("/"), "x02-doctored.json"), encoding="utf-8") as handle:
        return handle.read()


def probe_doc():
    """A COPY of the profile with a row for the core probe on each target, every item pending: the one kind of row a probe's receipt may back."""
    doc = copy.deepcopy(PROFILE)
    for target in PROFILE["targets"]:
        doc["measurements"][PROBE + "/" + target] = {name: {"state": "pending", "blocker": "the control's probe row"} for name in ("build", "binary_bytes", "rss_peak_bytes", "cpu") + L.SCENARIO_ITEMS}
    return doc


def bound_item(arch, name, **over):
    item = {"state": "measured", "receipt": DIR + RECEIPT[arch], "receipt_sha256": sha(arch), "field": FIELD[name], "unit": UNIT[name], "value": VALUE[arch][name]}
    item.update(over)
    return item


def bind(doc, row, name, arch, **over):
    doc["measurements"][row][name] = bound_item(arch, name, **over)
    return doc


def check(doc, repo=REPO):
    return L.check_profile(doc, LEDGER, repo)


def figure(row, name):
    return "measurement %s/%s is 'measured', but its figure " % (row, name)


def numeric_leaves(node, path=""):
    """Every numeric leaf of a JSON document, as (dotted path, value); booleans are not numbers."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from numeric_leaves(value, path + "." + key if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from numeric_leaves(value, "%s[%d]" % (path, index))
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        yield path, node


class TheTable(unittest.TestCase):
    def test_the_table_is_the_hand_written_one_and_the_receipts_hold_the_hand_written_figures(self):
        self.assertEqual(L.FIGURE_RULES, {"rss_peak_bytes": {"field": FIELD["rss_peak_bytes"], "parts": ("VmHWM",), "scale": 1024, "unit": "bytes"},
                                          "cpu": {"field": FIELD["cpu"], "parts": ("utime", "stime"), "scale": 1, "unit": "clock_ticks"}})
        self.assertTrue(set(part for rule in L.FIGURE_RULES.values() for part in rule["parts"]) <= set(X.RESOURCE_ORDER))
        self.assertEqual(L.FIGURE_SOURCE, {"subject": PROBE, "target_state": "harness_guest_only", "triples": {"mips": "mips-", "powerpc": "powerpc-"}})
        for arch in ARCHES:
            verdict = X.judge_receipt(receipt_bytes(arch).decode("utf-8"))
            self.assertEqual((verdict.state, verdict.arch, verdict.resources), ("passed", arch, RESOURCES[arch]), arch)       # what the judge re-derives is what is written here
        for arch in ARCHES:
            self.assertEqual(VALUE[arch]["rss_peak_bytes"], RESOURCES[arch]["VmHWM"] * 1024)
            self.assertEqual(VALUE[arch]["cpu"], RESOURCES[arch]["utime"] + RESOURCES[arch]["stime"])

    def test_no_row_is_measured_today_and_no_row_exists_for_the_probe(self):
        self.assertEqual([(k, n) for k, row in PROFILE["measurements"].items() for n, i in row.items() if i["state"] == "measured"], [])
        self.assertEqual([k for k in PROFILE["measurements"] if k.startswith(PROBE)], [])                                        # root, 17433: a row for the probe is a separate decision
        self.assertEqual(check(PROFILE), [])


class TheControls(unittest.TestCase):
    def test_each_real_receipt_backs_each_bound_item_on_the_probe_row_of_its_own_harness_target(self):
        for arch in ARCHES:
            for name in ITEMS:
                doc = bind(probe_doc(), PROBE + "/" + TARGET[arch], name, arch)
                self.assertEqual(check(doc), [], (arch, name))                                                                   # with the repository: digest, judgement, architecture and value
                self.assertEqual(check(doc, None), [], (arch, name))                                                             # and without it, where only the item and the profile are read
        both = probe_doc()
        for arch in ARCHES:
            for name in ITEMS:
                bind(both, PROBE + "/" + TARGET[arch], name, arch)
        self.assertEqual(check(both), [])

    def test_the_runners_profile_case_and_the_budget_case_pass_with_the_control(self):
        data = rc.inputs()
        data["profile"] = bind(probe_doc(), PROBE + "/mips32be_harness", "rss_peak_bytes", "mips")
        self.assertEqual(rc.case_profile(data, REPO).status, "passed")
        self.assertEqual(rc.case_budget(data, REPO).status, "passed")                                                            # a bound figure is still not a cap: nothing here allocates a budget


class ThePlants(unittest.TestCase):
    ROW = PROBE + "/mips32be_harness"

    def refused(self, doc, row, name, needle, repo=REPO):
        problems = check(doc, repo)
        self.assertTrue(planted(problems, figure(row, name) + needle), (row, name, needle, problems))
        return problems

    def test_a_value_that_is_not_the_receipts_is_refused_for_every_item_and_receipt(self):
        for arch in ARCHES:
            for name in ITEMS:
                row, real = PROBE + "/" + TARGET[arch], VALUE[arch][name]
                for wrong in (real + 1, real - 1, real * 2, 1, RESOURCES[arch]["VmHWM"], RESOURCES[arch]["VmRSS"] * 1024, RESOURCES[arch]["utime"], RESOURCES[arch]["stime"],
                              RESOURCES[arch]["VmHWM"] * 1000, RESOURCES[arch]["utime"] * 100):
                    if wrong == real:
                        continue
                    self.refused(bind(probe_doc(), row, name, arch, value=wrong), row, name, "has the value %d, but the receipt's %s is %d %s" % (wrong, FIELD[name], real, UNIT[name]))
                self.assertEqual(check(bind(probe_doc(), row, name, arch)), [])                                                  # control, each time

    def test_a_value_that_is_not_a_positive_integer_is_refused(self):
        for name in ITEMS:
            for wrong in (0, -1, -VALUE["mips"][name], True, False, 1.5, float(VALUE["mips"][name]), "946176", None, [1], {"v": 1}):
                for repo in (REPO, None):
                    self.refused(bind(probe_doc(), self.ROW, name, "mips", value=wrong), self.ROW, name, "has the value %s, which is not a positive integer" % repr(wrong)[:40], repo)

    def test_a_unit_that_is_not_the_tables_is_refused(self):
        for name in ITEMS:
            for wrong in ("kB", "KB", "kilobytes", "seconds", "ms", "ticks", "", None, 1, "clock_ticks" if name == "rss_peak_bytes" else "bytes"):
                for repo in (REPO, None):
                    self.refused(bind(probe_doc(), self.ROW, name, "mips", unit=wrong), self.ROW, name, "has the unit %s, but this item's is %s" % (repr(wrong)[:40], UNIT[name]), repo)

    def test_an_item_cannot_name_another_field_and_every_numeric_field_of_the_real_receipt_is_the_plant(self):
        for arch in ARCHES:
            leaves = list(numeric_leaves(json.loads(receipt_bytes(arch))))
            paths = {path for path, _ in leaves}
            self.assertGreater(len(leaves), 20)                                                                                  # the walk is not vacuous
            for needed in ("verdict.resources.VmHWM", "verdict.resources.VmRSS", "verdict.resources.utime", "verdict.resources.stime", "elf.bytes", "execution.exit_code"):
                self.assertIn(needed, paths)
            for name in ITEMS:
                row = PROBE + "/" + TARGET[arch]
                others = [(p, v) for p, v in leaves if p != FIELD[name]]                                                         # rss's own field is a leaf and is the control; cpu's field is a sum, so every leaf is another field
                self.assertEqual(len(others), len(leaves) - (1 if name == "rss_peak_bytes" else 0))
                for path, value in others:
                    for planted_value in {value, value * 1024} if isinstance(value, int) else {value}:                           # the value set to equal that field, as the field is and as it would be in bytes
                        doc = bind(probe_doc(), row, name, arch, field=path, value=planted_value)
                        self.refused(doc, row, name, "names the field %s, but this item binds to %s and nothing else" % (repr(path), FIELD[name]), None)
                for path in ("verdict.resources.VmRSS", "verdict.resources.utime", "verdict.resources.stime", "verdict.resources.VmSize", "verdict.resources.VmHWM+verdict.resources.VmRSS",
                             FIELD["cpu" if name == "rss_peak_bytes" else "rss_peak_bytes"], "VmHWM", "verdict.resources.vmhwm", "verdict.resources.VmHWM ", "", None, 3):
                    if path == FIELD[name]:
                        continue
                    self.refused(bind(probe_doc(), row, name, arch, field=path), row, name, "names the field %s, but this item binds to %s and nothing else" % (repr(path)[:80], FIELD[name]))
                self.assertEqual(check(bind(probe_doc(), row, name, arch)), [])                                                  # control: the table's own field

    def test_each_item_cites_the_one_field_that_holds_its_figure_so_a_smaller_field_cannot_pass(self):
        for arch in ARCHES:
            row = PROBE + "/" + TARGET[arch]
            smaller = RESOURCES[arch]["VmRSS"] * 1024                                                                             # what rss_peak_bytes would claim if it cited the current size
            self.assertLessEqual(RESOURCES[arch]["VmRSS"], RESOURCES[arch]["VmHWM"])
            self.refused(bind(probe_doc(), row, "rss_peak_bytes", arch, field="verdict.resources.VmRSS", value=smaller), row, "rss_peak_bytes", "names the field 'verdict.resources.VmRSS'")
            self.refused(bind(probe_doc(), row, "cpu", arch, field="verdict.resources.utime", value=RESOURCES[arch]["utime"]), row, "cpu", "names the field 'verdict.resources.utime'")
            self.refused(bind(probe_doc(), row, "cpu", arch, field="verdict.resources.stime", value=RESOURCES[arch]["stime"]), row, "cpu", "names the field 'verdict.resources.stime'")

    def test_a_digest_that_is_not_the_receipts_is_refused_including_the_other_real_receipts(self):
        for arch, other in (("mips", "powerpc"), ("powerpc", "mips")):
            row = PROBE + "/" + TARGET[arch]
            for name in ITEMS:
                self.refused(bind(probe_doc(), row, name, arch, receipt_sha256=sha(other)), row, name, "has a receipt_sha256 that is not the sha256 of its receipt")         # a sha copied from the other receipt
                for wrong in ("0" * 64, "f" * 64, sha(arch)[:-1] + ("0" if sha(arch)[-1] != "0" else "1")):
                    self.refused(bind(probe_doc(), row, name, arch, receipt_sha256=wrong), row, name, "has a receipt_sha256 that is not the sha256 of its receipt")
                for malformed in (sha(arch).upper(), sha(arch)[:63], sha(arch) + "0", "", None, 7, ["x"]):
                    for repo in (REPO, None):
                        self.refused(bind(probe_doc(), row, name, arch, receipt_sha256=malformed), row, name, "has a receipt_sha256 that is not a lowercase sha256", repo)
                self.assertEqual(check(bind(probe_doc(), row, name, arch)), [])                                                  # control

    def test_the_mips_receipt_on_a_powerpc_target_and_the_reverse_is_refused_even_with_its_own_digest_and_values(self):
        for arch, other in (("mips", "powerpc"), ("powerpc", "mips")):
            row = PROBE + "/" + TARGET[other]
            for name in ITEMS:
                triple = PROFILE["targets"][TARGET[other]]["rust_triple"]
                self.refused(bind(probe_doc(), row, name, arch), row, name, "rests on a %s receipt, but target %s builds for %s" % (arch, TARGET[other], triple))
            self.assertEqual(check(bind(probe_doc(), PROBE + "/" + TARGET[arch], "cpu", arch)), [])                              # control: the receipt on its own target

    def test_a_harness_receipt_cannot_back_a_stock_kernel(self):
        for target in ("mips32r2be_stock", "ppc32be_stock"):
            arch = "mips" if target.startswith("mips") else "powerpc"
            row = PROBE + "/" + target
            self.assertEqual(PROFILE["targets"][target]["kernel_state"], "unqualified")
            for name in ITEMS:
                needle = "rests on a harness-guest receipt, which cannot back a figure for target %s (its kernel is unqualified)" % target
                self.refused(bind(probe_doc(), row, name, arch), row, name, needle)
                self.refused(bind(probe_doc(), row, name, arch), row, name, needle, None)

    def test_a_probe_receipt_cannot_back_a_client_figure_for_any_candidate_on_any_harness_target(self):
        for candidate in PROFILE["candidates"]:
            for arch in ARCHES:
                row = candidate + "/" + TARGET[arch]
                for name in ITEMS:
                    doc = probe_doc()
                    doc["measurements"].setdefault(row, {n: {"state": "pending", "blocker": "x"} for n in ("build", "binary_bytes", "rss_peak_bytes", "cpu") + L.SCENARIO_ITEMS})
                    bind(doc, row, name, arch)
                    self.refused(doc, row, name, "rests on a receipt that measured the core probe (%s), not %s" % (PROBE, candidate))
                    self.refused(doc, row, name, "rests on a receipt that measured the core probe (%s), not %s" % (PROBE, candidate), None)

    def test_the_headline_plant_a_real_probe_receipt_on_the_real_tailscale_rs_row_is_refused(self):
        row = "tailscale-rs-0.6.1/mips32be_harness"
        self.assertIn(row, PROFILE["measurements"])
        for name in ITEMS:
            doc = bind(copy.deepcopy(PROFILE), row, name, "mips")                                                                # every field right: the real digest, field, unit and the receipt's own value
            problems = self.refused(doc, row, name, "rests on a receipt that measured the core probe (%s), not tailscale-rs-0.6.1" % PROBE)
            self.assertEqual(len([p for p in problems if "is 'measured'" in p]), 1, problems)                                   # and for that reason alone
        control = bind(probe_doc(), PROBE + "/mips32be_harness", "cpu", "mips")
        self.assertEqual(check(control), [])                                                                                     # the same figure on the probe's own row passes

    def test_an_item_with_no_binding_rule_cannot_be_measured(self):
        for name in ("build", "binary_bytes") + L.SCENARIO_ITEMS:
            for arch in ARCHES:
                row = PROBE + "/" + TARGET[arch]
                elf_bytes = json.loads(receipt_bytes(arch))["elf"]["bytes"]
                doc = probe_doc()
                doc["measurements"][row][name] = {"state": "measured", "receipt": DIR + RECEIPT[arch], "receipt_sha256": sha(arch), "field": "elf.bytes", "unit": "bytes", "value": elf_bytes}
                self.refused(doc, row, name, "has no binding rule (only cpu, rss_peak_bytes can be measured), so it cannot be 'measured'")
                self.refused(doc, row, name, "has no binding rule (only cpu, rss_peak_bytes can be measured), so it cannot be 'measured'", None)
        self.assertEqual(sorted(L.FIGURE_RULES), ["cpu", "rss_peak_bytes"])

    def test_a_missing_key_is_named(self):
        for name in ITEMS:
            for key in ("field", "unit", "value", "receipt_sha256"):
                doc = probe_doc()
                item = bound_item("mips", name)
                del item[key]
                doc["measurements"][self.ROW][name] = item
                problems = self.refused(doc, self.ROW, name, "lacks %s" % key)
                self.assertEqual(len([p for p in problems if "its figure" in p]), 1, (key, problems))                          # only that is wrong with it
        self.assertEqual(check(bind(probe_doc(), self.ROW, "cpu", "mips")), [])                                                 # control

    def test_a_bad_receipt_is_the_only_problem_and_no_figure_problem_follows_it(self):
        for receipt in ("x", DIR + "no-such-receipt.json", "docs/tailscale/profiles.json"):
            doc = bind(probe_doc(), self.ROW, "cpu", "mips", receipt=receipt)
            problems = [p for p in check(doc) if "measurement %s/cpu" % self.ROW in p]
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("but its receipt", problems[0])


class TheJudgement(unittest.TestCase):
    """The figure rests on a receipt that judges as a passed captured guest run NOW. Doctored copies live in a throwaway repository with their own correct digest, so only the judgement can refuse them."""
    ROW = PROBE + "/mips32be_harness"

    def repo_with(self, tmp, mutate):
        doc = json.loads(receipt_bytes("mips"))
        mutate(doc)
        directory = os.path.join(tmp, *DIR.rstrip("/").split("/"))
        os.makedirs(directory, exist_ok=True)
        data = json.dumps(doc).encode("utf-8")
        with open(os.path.join(directory, "x02-doctored.json"), "wb") as handle:
            handle.write(data)
        return L.sha256_bytes(data)

    def doc_for(self, digest, name):
        return bind(probe_doc(), self.ROW, name, "mips", receipt=DIR + "x02-doctored.json", receipt_sha256=digest)

    def test_an_unchanged_copy_is_the_control_and_each_doctored_one_is_refused_for_its_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = self.repo_with(tmp, lambda d: None)
            for name in ITEMS:
                self.assertEqual(check(self.doc_for(digest, name), tmp), [], name)                                               # control: the same bytes, re-judged, still bind
        for label, mutate in (("a supplied-transcript analysis", lambda d: d.update({"evidence_kind": "supplied_transcript_analysis"})),
                              ("a result that contradicts its facts", lambda d: d.update({"result": "not_passed"})),
                              ("an UNKNOWN reading", lambda d: d["verdict"]["resources"].update({"VmHWM": "UNKNOWN"})),
                              ("a missing phase", lambda d: d["verdict"]["phases"].pop()),
                              ("a changed phase status", lambda d: d["verdict"]["phases"][0].update({"status": "fail"}))):
            with tempfile.TemporaryDirectory() as tmp:
                digest = self.repo_with(tmp, mutate)
                judged = X.judge_receipt(doctored_text(tmp))
                self.assertNotEqual(judged.state, "passed", label)
                for name in ITEMS:
                    problems = check(self.doc_for(digest, name), tmp)
                    self.assertTrue(planted(problems, figure(self.ROW, name) + "rests on a receipt that does not judge as a passed captured guest run (%s:" % judged.state), (label, problems))

    def test_each_judge_state_but_passed_refuses_the_figure(self):
        real = X.ReceiptJudgement
        for state in ("blocked", "failed", "analysis_only"):
            verdict = real(state, ["a reason"], "mips", {"VmHWM": 924, "VmRSS": 904, "utime": 29, "stime": 191})
            with mock.patch.object(X, "judge_receipt", return_value=verdict):
                for name in ITEMS:
                    self.assertTrue(planted(check(bind(probe_doc(), self.ROW, name, "mips")), figure(self.ROW, name) + "rests on a receipt that does not judge as a passed captured guest run (%s: a reason)" % state), state)
        passed_without_resources = real("passed", [], "mips", None)
        with mock.patch.object(X, "judge_receipt", return_value=passed_without_resources):
            self.assertTrue(planted(check(bind(probe_doc(), self.ROW, "cpu", "mips")), "does not judge as a passed captured guest run"))
        self.assertEqual(check(bind(probe_doc(), self.ROW, "cpu", "mips")), [])                                                  # and the unmocked judge passes it again

    def test_the_value_is_the_judges_re_derived_figure_and_not_the_raw_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = self.repo_with(tmp, lambda d: d["verdict"]["resources"].update({"VmHWM": 1}))                               # the raw field now says 1 kB, which the recorded phases contradict
            judged = X.judge_receipt(doctored_text(tmp))
            self.assertNotEqual(judged.state, "passed")
            self.assertTrue(planted(check(self.doc_for(digest, "rss_peak_bytes"), tmp), "does not judge as a passed captured guest run"))
        verdict = X.ReceiptJudgement("passed", [], "mips", {"VmHWM": 5, "VmRSS": 4, "utime": 1, "stime": 2})                      # a judge that says otherwise than the receipt's raw field decides
        with mock.patch.object(X, "judge_receipt", return_value=verdict):
            self.assertTrue(planted(check(bind(probe_doc(), self.ROW, "rss_peak_bytes", "mips")), "has the value %d, but the receipt's verdict.resources.VmHWM is %d bytes" % (VALUE["mips"]["rss_peak_bytes"], 5 * 1024)))
            self.assertEqual(check(bind(probe_doc(), self.ROW, "rss_peak_bytes", "mips", value=5 * 1024)), [])
            self.assertEqual(check(bind(probe_doc(), self.ROW, "cpu", "mips", value=3)), [])                                     # the sum of the judge's utime and stime

    def test_an_unreadable_file_is_refused_where_the_receipt_rule_has_not_already_and_stays_quiet_where_it_has(self):
        real_read = L.read_bounded_file
        with mock.patch.object(L, "read_bounded_file", side_effect=OSError("gone")):
            problems = check(bind(probe_doc(), self.ROW, "cpu", "mips"), REPO)
        self.assertTrue(planted(problems, "but its receipt names"))                                                              # the receipt rule speaks first
        self.assertFalse(planted(problems, "its figure"))                                                                        # and the figure rule stays quiet
        calls = []

        def vanishes_after_the_first_read(path, *args):
            calls.append(path)
            if len(calls) > 1:
                raise OSError("gone")                                                                                            # the receipt rule saw the file; by the figure's read it is gone
            return real_read(path, *args)
        with mock.patch.object(L, "read_bounded_file", side_effect=vanishes_after_the_first_read):
            problems = check(bind(probe_doc(), self.ROW, "cpu", "mips"), REPO)
        self.assertTrue(planted(problems, figure(self.ROW, "cpu") + "names a receipt that cannot be read"), problems)
        self.assertEqual(check(bind(probe_doc(), self.ROW, "cpu", "mips")), [])                                                  # control


class TheGate(unittest.TestCase):
    def test_the_runners_profile_case_refuses_a_client_figure_and_names_the_figure(self):
        data = rc.inputs()
        row = "tailscale-rs-0.6.1/mips32be_harness"
        data["profile"] = bind(copy.deepcopy(PROFILE), row, "rss_peak_bytes", "mips")
        result = rc.case_profile(data, REPO)
        self.assertEqual(result.status, "failed")
        self.assertIn("is 'measured', but its figure rests on a receipt that measured the core probe", result.detail)
        data["profile"] = bind(probe_doc(), PROBE + "/mips32be_harness", "rss_peak_bytes", "mips")
        self.assertEqual(rc.case_profile(data, REPO).status, "passed")                                                          # control: the probe's own row

    def test_the_entry_point_gate_is_red_for_the_headline_plant_and_green_without_it(self):
        data = rc.inputs()
        data["profile"] = bind(copy.deepcopy(PROFILE), "tailscale-rs-0.6.1/mips32be_harness", "cpu", "mips")
        results = [rc.case_profile(data, REPO)]
        self.assertEqual((rc.exit_code(results), results[0].case_id), (1, "T01-META-PROFILE"))
        self.assertEqual(rc.exit_code([rc.case_profile(rc.inputs(), REPO)]), 0)


if __name__ == "__main__":
    unittest.main()
