"""Unit tests for the P01 host tooling (reference, facts, plan, runner). Stdlib unittest only.

These test the tools' own machinery against hand-written values; the contract rules are pinned by the shared
vectors and the named cases in cases.json.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import facts  # noqa: E402
import fixtures  # noqa: E402
import pipeline  # noqa: E402
import plan  # noqa: E402
import reference as ref  # noqa: E402
import run_cases  # noqa: E402


def small_contract():
    return run_cases.contract()


class CanonicalFormTests(unittest.TestCase):
    def test_keys_are_sorted_and_the_text_is_compact(self):
        doc = {"b": 1, "a": [2, {"d": None, "c": True}]}
        self.assertEqual(ref.canonical_json(doc), '{"a":[2,{"c":true,"d":null}],"b":1}')

    def test_digest_matches_an_independent_sha256(self):
        # printf '%s' '{"a":[2,{"c":true,"d":null}],"b":1}' | shasum -a 256
        pinned = "8e03186084c73edae27ad25e24e52e388504e4afca81cce926461127ca99dd43"
        self.assertEqual(ref.digest({"b": 1, "a": [2, {"d": None, "c": True}]}), pinned)

    def test_digest_ignores_key_order(self):
        self.assertEqual(ref.digest({"x": 1, "y": 2}), ref.digest({"y": 2, "x": 1}))

    def test_hex64_accepts_only_lowercase_sha256(self):
        self.assertTrue(ref.is_hex64("ab" * 32))
        self.assertFalse(ref.is_hex64("AB" * 32))
        self.assertFalse(ref.is_hex64("ab" * 31))


class ShapeTests(unittest.TestCase):
    def test_the_declared_contract_has_the_declared_shape(self):
        ref.parse_contract(small_contract())

    def test_unknown_missing_and_mistyped_fields_are_all_parse_errors(self):
        for ops in ([{"op": "set", "path": "/crates/name=franken-hal/extra", "value": 1}],
                    [{"op": "remove", "path": "/crates/name=franken-hal/owner"}],
                    [{"op": "set", "path": "/crates/name=franken-hal/layer", "value": "4"}],
                    [{"op": "set", "path": "/crates/name=franken-hal/layer", "value": True}],
                    [{"op": "set", "path": "/crates/name=franken-hal/layer", "value": -1}],
                    [{"op": "set", "path": "/crates/name=franken-hal/layer", "value": 2 ** 32}]):
            with self.subTest(ops=ops):
                with self.assertRaises(ref.ParseError):
                    ref.parse_contract(ref.apply_ops(small_contract(), ops))

    def test_a_u32_boundary_value_is_accepted(self):
        doc = ref.apply_ops(small_contract(), [{"op": "set", "path": "/crates/name=franken-hal/layer",
                                                "value": 2 ** 32 - 1}])
        ref.parse_contract(doc)


class MutationTests(unittest.TestCase):
    def test_set_remove_and_push_do_what_they_say(self):
        doc = {"a": [{"id": "x", "v": 1}, {"id": "y", "v": 2}], "b": {"c": 3}}
        out = ref.apply_ops(doc, [
            {"op": "set", "path": "/a/id=y/v", "value": 9},
            {"op": "push", "path": "/a", "value": {"id": "z", "v": 3}},
            {"op": "remove", "path": "/a/id=x"},
            {"op": "set", "path": "/b/d", "value": 4}])
        self.assertEqual(out, {"a": [{"id": "y", "v": 9}, {"id": "z", "v": 3}], "b": {"c": 3, "d": 4}})
        self.assertEqual(doc["a"][0]["v"], 1, "the input must not be modified")

    def test_a_slash_inside_a_selector_value_is_escaped_as_tilde_one(self):
        doc = {"assets": [{"path": "crates/x", "owner": "A"}]}
        out = ref.apply_ops(doc, [{"op": "set", "path": "/assets/path=crates~1x/owner", "value": "B"}])
        self.assertEqual(out["assets"][0]["owner"], "B")

    def test_a_path_that_matches_nothing_is_an_error_not_a_silent_no_op(self):
        for op in ({"op": "set", "path": "/a/id=nope/v", "value": 1}, {"op": "remove", "path": "/a/id=nope"},
                   {"op": "push", "path": "/b", "value": 1}, {"op": "frob", "path": "/a"}):
            with self.subTest(op=op):
                with self.assertRaises(ValueError):
                    ref.apply_ops({"a": [{"id": "x"}], "b": {}}, [op])


class GraphTests(unittest.TestCase):
    def test_cycles_closure_and_self_loops(self):
        graph = {"a": {"b"}, "b": {"c"}, "c": {"a"}, "d": {"a"}, "e": {"e"}}
        self.assertEqual(ref.cycles(graph), {("a", "b", "c")})
        self.assertEqual(ref.closure(graph, "d"), {"a", "b", "c", "d"})
        self.assertEqual(ref.cycles({"a": {"b"}, "b": set()}), set())

    def test_the_facts_module_finds_the_same_cycles(self):
        self.assertEqual(facts._cycles({"a": {"b"}, "b": {"a"}, "c": set()}), [("a", "b")])


class ValidationTests(unittest.TestCase):
    def test_the_declared_contract_has_no_violations(self):
        self.assertEqual(ref.validate(small_contract()), [])

    def test_no_artifact_in_the_declared_contract_is_qualified(self):
        doc = small_contract()
        for art in doc["artifacts"]:
            self.assertFalse(ref.admission(doc, art["id"])["qualified"], art["id"])

    def test_admission_of_an_unknown_artifact_is_none(self):
        self.assertIsNone(ref.admission(small_contract(), "no-such-artifact"))

    def test_verify_observed_require_all_names_every_missing_artifact(self):
        doc = small_contract()
        pairs = ref.verify_observed(doc, [], require_all=True)
        self.assertEqual(len(pairs), len(doc["artifacts"]))
        self.assertEqual(ref.codes(pairs), ["artifact_not_observed"])
        self.assertEqual(ref.verify_observed(doc, [], require_all=False), [])


class IdentityTests(unittest.TestCase):
    def test_elf_identity_reads_the_header_with_the_right_byte_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, machine, big in (("ppc", 20, True), ("mips", 8, True), ("le", 20, False)):
                path = os.path.join(tmp, name)
                with open(path, "wb") as f:
                    f.write(run_cases.fake_elf(machine, b"x", big=big))
                ident = plan.elf_identity(path)
                self.assertEqual((ident["elf_machine"], ident["elf_class"], ident["elf_big_endian"]),
                                 (machine, 1, big), name)
            plain = os.path.join(tmp, "plain")
            with open(plain, "wb") as f:
                f.write(b"not an elf at all, just text")
            self.assertEqual(plan.elf_identity(plain)["elf_machine"], 0)
            self.assertFalse(plan.elf_identity(plain)["elf_big_endian"])

    def test_elf_identity_digest_is_the_file_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f")
            with open(path, "wb") as f:
                f.write(b"abc")
            # printf abc | shasum -a 256
            self.assertEqual(plan.elf_identity(path)["sha256"],
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_rustc_verbose_version_is_parsed(self):
        parsed = plan.parse_rustc_vv(run_cases.RUSTC_VV)
        self.assertEqual(parsed["release"], "1.101.0-nightly")
        self.assertEqual(parsed["host"], "x86_64-unknown-linux-gnu")
        self.assertEqual(plan.parse_rustc_vv("garbage"), {})


class PlanTests(unittest.TestCase):
    def test_a_plan_with_no_steps_has_no_violations(self):
        self.assertEqual(plan.check_plan([], REPO_ROOT, small_contract()), [])

    def test_every_step_of_the_real_plan_is_remote_locked_and_offline(self):
        _root, _t, steps = run_cases._plan()
        for step in steps:
            self.assertEqual(step["argv"][:3], ["rch", "exec", "--"], step["id"])
            if step["argv"][3] == "cargo":
                self.assertIn("--locked", step["argv"], step["id"])
                self.assertIn("--offline", step["argv"], step["id"])
                self.assertTrue(os.path.isabs(step["argv"][step["argv"].index("--manifest-path") + 1]))


REPO_ROOT = os.path.realpath(run_cases.REPO)


class FixtureTests(unittest.TestCase):
    def test_the_baseline_synthetic_workspace_matches_its_contract(self):
        spec = fixtures.base_spec()
        with tempfile.TemporaryDirectory() as tmp:
            fixtures.materialize(tmp, spec)
            self.assertEqual(facts.compare(fixtures.mini_contract(spec), facts.extract(tmp), root=tmp), [])

    def test_facts_do_not_contain_the_root_path(self):
        spec = fixtures.base_spec()
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            fixtures.materialize(one, spec)
            fixtures.materialize(two, spec)
            self.assertEqual(facts.facts_digest(facts.extract(one)), facts.facts_digest(facts.extract(two)))
            self.assertNotIn(one, json.dumps(facts.extract(one)))


class RunnerTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_cases.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_a_blocked_case_exits_3_and_is_never_counted_as_passed(self):
        code, out, _ = self.run_main("--tier", "smoke", "--case", "P01-BLK-001")
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED", out)
        self.assertIn("passed=0", out)
        self.assertIn("NOT QUALIFIED", out)

    def test_a_passing_case_exits_0(self):
        code, out, _ = self.run_main("--tier", "smoke", "--case", "P01-V-001")
        self.assertEqual(code, 0)
        self.assertIn("passed=1 failed=0 blocked=0", out)

    def test_an_unknown_case_is_a_usage_error(self):
        code, _out, err = self.run_main("--tier", "smoke", "--case", "P01-NOPE")
        self.assertEqual(code, 2)
        self.assertIn("no case", err)

    def test_the_tier_has_no_default(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                run_cases.main([])

    def test_the_full_tier_contains_the_smoke_tier(self):
        cases = run_cases.all_cases()
        smoke = {c["id"] for c in run_cases.select(cases, "smoke", None)}
        full = {c["id"] for c in run_cases.select(cases, "full", None)}
        self.assertTrue(smoke < full)

    def test_every_vector_becomes_a_case_and_ids_are_unique(self):
        cases = run_cases.all_cases()
        ids = [c["id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        vectors = run_cases.load_json(run_cases.VECTORS_FILE)["vectors"]
        self.assertTrue(set(v["id"] for v in vectors) < set(ids))
        self.assertGreaterEqual(len(vectors), 90)

    def test_pattern_expansion_matches_prefixes_only(self):
        self.assertEqual(run_cases.expand(["A-*", "B-1"], ["A-1", "A-2", "B-1", "B-2", "XA-3"]), ["A-1", "A-2", "B-1"])

    def test_receipts_are_new_files_and_an_earlier_one_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_main("--tier", "smoke", "--case", "P01-V-001", "--receipts", tmp)[0], 0)
            first = sorted(os.listdir(tmp))
            self.assertEqual(len(first), 1)
            before = open(os.path.join(tmp, first[0]), "rb").read()
            self.assertEqual(self.run_main("--tier", "smoke", "--case", "P01-V-001", "--receipts", tmp)[0], 0)
            after = sorted(os.listdir(tmp))
            self.assertEqual(len(after), 2)
            self.assertEqual(open(os.path.join(tmp, first[0]), "rb").read(), before)
            doc = json.load(open(os.path.join(tmp, first[0])))
            self.assertEqual(doc["totals"], {"total": 1, "passed": 1, "failed": 0, "blocked": 0})
            self.assertEqual(doc["contract_digest"], ref.digest(small_contract()))

    def test_exclusive_create_refuses_an_existing_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan._write_new(tmp, "same-id")
            with self.assertRaises(FileExistsError):
                plan._write_new(tmp, "same-id")

    def test_a_crashing_case_is_a_failed_case_never_a_pass(self):
        original = run_cases.HANDLERS["vector"]
        try:
            run_cases.HANDLERS["vector"] = lambda c: (_ for _ in ()).throw(RuntimeError("boom"))
            code, out, _ = self.run_main("--tier", "smoke", "--case", "P01-V-001")
        finally:
            run_cases.HANDLERS["vector"] = original
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("RuntimeError: boom", out)


class PipelineTests(unittest.TestCase):
    def run_pipeline(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pipeline.main(list(argv))
        return code, out.getvalue()

    def write_artifacts(self, target_dir, wrong_machine_for=()):
        # speaker-*-full and speaker-*-min are one build and one file, so a wrong ISA must reach both ids
        doc = small_contract()
        for art in doc["artifacts"]:
            path = plan.artifact_path(target_dir, art)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            machine = ref.TARGETS[art["target"]][2]
            if art["id"] in wrong_machine_for:
                machine = 8
            with open(path, "wb") as f:
                f.write(run_cases.fake_elf(machine, art["crate"].encode() + art["target"].encode())
                        if art["target"] != "host" else b"host-binary" + art["crate"].encode())

    def test_print_plan_prints_seven_acceptable_steps(self):
        code, out = self.run_pipeline("print-plan")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual((len(doc["steps"]), doc["violations"]), (7, []))
        self.assertEqual(doc["contract_digest"], ref.digest(small_contract()))

    def test_collect_with_nothing_built_is_incomplete_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self.run_pipeline("collect", "--target-dir", os.path.join(tmp, "none"),
                                          "--receipts", os.path.join(tmp, "r"))
            self.assertEqual(code, 3)
            self.assertIn("status incomplete", out)
            receipt = json.load(open(os.path.join(tmp, "r", os.listdir(os.path.join(tmp, "r"))[0])))
            self.assertEqual((receipt["status"], len(receipt["artifacts"]), len(receipt["missing"])), ("incomplete", 0, 7))

    def test_collect_of_a_correct_tree_is_complete_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "t")
            self.write_artifacts(target)
            code, _out = self.run_pipeline("collect", "--target-dir", target, "--receipts", os.path.join(tmp, "r"))
            self.assertEqual(code, 0)
            receipt = json.load(open(os.path.join(tmp, "r", os.listdir(os.path.join(tmp, "r"))[0])))
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(plan.check_receipt(small_contract(), receipt), [])

    def test_collect_refuses_a_powerpc_artifact_that_is_really_mips(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "t")
            self.write_artifacts(target, wrong_machine_for=("speaker-ppc-full", "speaker-ppc-min"))
            code, out = self.run_pipeline("collect", "--target-dir", target, "--receipts", os.path.join(tmp, "r"))
            self.assertEqual(code, 1)
            self.assertIn("elf_machine_mismatch [speaker-ppc-full]", out)

    def test_execute_refuses_to_run_a_plan_that_breaks_its_own_rules(self):
        original = plan.plan_steps
        try:
            plan.plan_steps = lambda *a, **k: [dict(s, argv=[x for x in s["argv"] if x != "--locked"])
                                               for s in original(*a, **k)]
            code, _ = self.run_pipeline("execute", "--receipts", tempfile.gettempdir() + "/p01-never-written")
        finally:
            plan.plan_steps = original
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(tempfile.gettempdir() + "/p01-never-written"))


if __name__ == "__main__":
    unittest.main()
