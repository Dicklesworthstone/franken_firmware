"""Unit tests for the P01 host tooling (reference, facts, plan, runner). Stdlib unittest only.

These test the tools' own machinery against hand-written values; the contract rules are pinned by the shared
vectors and the named cases in cases.json.
"""
from __future__ import annotations

import contextlib
import copy
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
import metadata_check  # noqa: E402
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


class MetadataTests(unittest.TestCase):
    PK = ["franken-speaker", "franken-hal", "franken-test-support"]

    def doc(self, deps):
        return metadata_check.build_metadata({"packages": self.PK, "deps": deps})

    def test_dev_edges_are_not_part_of_the_normal_closure(self):
        meta = self.doc({"franken-speaker": [["franken-hal", "normal"], ["franken-test-support", "dev"]]})
        self.assertEqual(metadata_check.normal_closure(meta, "franken-speaker"), {"franken-speaker", "franken-hal"})

    def test_a_build_dependency_is_not_a_normal_edge_either(self):
        meta = self.doc({"franken-speaker": [["franken-test-support", "build"]]})
        self.assertEqual(metadata_check.normal_closure(meta, "franken-speaker"), {"franken-speaker"})

    def test_the_closure_follows_transitive_normal_edges(self):
        meta = self.doc({"franken-speaker": [["franken-hal", "normal"]], "franken-hal": [["franken-test-support", "normal"]]})
        self.assertIn("franken-test-support", metadata_check.normal_closure(meta, "franken-speaker"))

    def test_a_malformed_document_raises_rather_than_passing(self):
        with self.assertRaises(metadata_check.MetadataError):
            metadata_check.normal_closure({"packages": []}, "franken-speaker")
        with self.assertRaises(metadata_check.MetadataError):
            metadata_check.normal_closure(self.doc({}), "franken-nonexistent")

    def test_check_metadata_cli_exits_by_verdict(self):
        good_default = self.doc({"franken-speaker": [["franken-hal", "normal"]]})
        good_harness = self.doc({"franken-speaker": [["franken-hal", "normal"], ["franken-test-support", "normal"]]})
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, doc in (("d", good_default), ("h", good_harness), ("bad", good_harness)):
                paths[name] = os.path.join(tmp, name + ".json")
                with open(paths[name], "w") as f:
                    json.dump(doc, f)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(pipeline.main(["check-metadata", "--default", paths["d"], "--harness", paths["h"]]), 0)
                self.assertEqual(pipeline.main(["check-metadata", "--default", paths["bad"], "--harness", paths["h"]]), 1)
            self.assertIn("metadata_default_has_edge", out.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pipeline.main(["check-metadata", "--default", os.path.join(tmp, "missing.json"),
                                                "--harness", paths["h"]]), 2)


def cargo_shaped(tree, versions, crate, gate_feature, harness, external=("serde", "1.0.0")):
    """A `cargo metadata`-shaped document built from the static resolve of `tree`: normal edges are the declared normal
    dependencies, plus the gated optional ones when `harness`; a dev dependency shares its entry with a normal one
    (two `dep_kinds` rows) as cargo prints it; an optional external package hangs off the first member. A test helper: the
    real documents come from cargo, centrally."""
    names = [m["name"] for m in tree["members"]]
    ident = {n: f"path+file:///ws/{n}#{versions[n]}" for n in names}
    if external:
        ident[external[0]] = f"registry+https://example.invalid/index#{external[0]}@{external[1]}"
    nodes = []
    for m in tree["members"]:
        normal = set(m["deps"]["normal"])
        if harness and m["name"] == crate:
            normal |= set(m["deps"]["optional"])
        deps = []
        for dep in sorted(normal | set(m["deps"]["dev"])):
            kinds = ([{"kind": None, "target": None}] if dep in normal else []) + \
                    ([{"kind": "dev", "target": None}] if dep in m["deps"]["dev"] else [])
            deps.append({"name": dep.replace("-", "_"), "pkg": ident[dep], "dep_kinds": kinds})
        if external and m["name"] == names[0]:
            deps.append({"name": external[0], "pkg": ident[external[0]], "dep_kinds": [{"kind": None, "target": None}]})
        feats = ["default"] + ([gate_feature] if harness and m["name"] == crate else [])
        nodes.append({"id": ident[m["name"]], "dependencies": [d["pkg"] for d in deps], "deps": deps, "features": feats})
    packages = [{"id": ident[n], "name": n, "version": versions[n]} for n in names]
    if external:
        nodes.append({"id": ident[external[0]], "dependencies": [], "deps": [], "features": ["default"]})
        packages.append({"id": ident[external[0]], "name": external[0], "version": external[1]})
    return {"packages": packages, "workspace_members": [ident[n] for n in names],
            "resolve": {"nodes": nodes, "root": None}, "version": 1}


class JudgeTests(unittest.TestCase):
    """metadata_check.judge and its planted faults, on a small tree where every plant has something to bite on:
    app -> a_util, lib; lib -> a_util, deep; app -> tsup only with the `harness` feature (and as a dev-dependency)."""
    CRATE, FORBIDDEN, FEATURE = "app", "tsup", "harness"

    @staticmethod
    def member(name, normal=(), optional=(), dev=(), table=None):
        return {"name": name, "deps": {"normal": list(normal), "optional": list(optional), "dev": list(dev), "build": []},
                "feature_table": table or {}}

    def setUp(self):
        m = self.member
        self.tree = {"members": [
            m("app", ["a_util", "lib"], ["tsup"], ["tsup"], {"harness": ["dep:tsup"]}),
            m("lib", ["a_util", "deep"]), m("a_util"), m("deep"), m("tsup")]}
        self.versions = {n["name"]: "0.1.0" for n in self.tree["members"]}
        self.lock = {(n, "0.1.0") for n in self.versions} | {("serde", "1.0.0")}
        self.default = cargo_shaped(self.tree, self.versions, self.CRATE, self.FEATURE, False)
        self.harness = cargo_shaped(self.tree, self.versions, self.CRATE, self.FEATURE, True)

    def judge(self, default=None, harness=None, lock="lock"):
        return metadata_check.judge(default or self.default, harness or self.harness, self.tree,
                                    self.lock if lock == "lock" else lock, self.CRATE, self.FORBIDDEN, self.FEATURE)

    def test_the_unplanted_pair_is_clean_and_its_dev_edge_is_not_a_leak(self):
        self.assertEqual(self.judge(), [])
        entry = next(d for d in metadata_check._node(self.default, "app")["deps"] if d["name"] == "tsup")
        self.assertEqual([k["kind"] for k in entry["dep_kinds"]], ["dev"], "the default document carries only the dev edge")

    def test_every_plant_is_caught_with_its_expected_codes_and_the_run_reports_none_missed(self):
        self.assertEqual(self.judge(), [], "remove-the-plant control: the unplanted pair is clean")
        for plant in metadata_check.PLANTS:
            with self.subTest(plant.name):
                ctx = {"crate": self.CRATE, "forbidden": self.FORBIDDEN, "feature": self.FEATURE}
                d, h = plant.apply(copy.deepcopy(self.default), copy.deepcopy(self.harness), ctx)
                got = metadata_check.codes(self.judge(d, h))
                self.assertTrue(set(plant.expect) <= set(got), f"{plant.name}: want {plant.expect}, got {got}")
        self.assertEqual(metadata_check.run_plants(self.default, self.harness, self.tree, self.lock,
                                                   self.CRATE, self.FORBIDDEN, self.FEATURE), [])

    def test_a_judgement_too_weak_to_catch_a_plant_is_reported_by_name(self):
        problems = metadata_check.run_plants(self.default, self.harness, self.tree, None,
                                             self.CRATE, self.FORBIDDEN, self.FEATURE)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("stale_lock: not caught"), problems)

    def test_a_plant_that_cannot_be_planted_is_a_problem_not_a_pass(self):
        flat = {"members": [self.member("app", [], ["tsup"], ["tsup"], {"harness": ["dep:tsup"]}), self.member("tsup")]}
        d = cargo_shaped(flat, {"app": "0.1.0", "tsup": "0.1.0"}, "app", "harness", False)
        h = cargo_shaped(flat, {"app": "0.1.0", "tsup": "0.1.0"}, "app", "harness", True)
        problems = metadata_check.run_plants(d, h, flat, {("app", "0.1.0"), ("tsup", "0.1.0"), ("serde", "1.0.0")},
                                             "app", "tsup", "harness")
        self.assertTrue(any(p.startswith("leak_transitive: could not be planted") for p in problems), problems)
        self.assertTrue(any(p.startswith("stale_edge: could not be planted") for p in problems), problems)
        self.assertTrue(any(p.startswith("member_missing: could not be planted") for p in problems), problems)
        self.assertTrue(all(": could not be planted" in p or ": not caught" in p for p in problems), problems)

    def test_the_transitive_leak_goes_through_a_crate_the_app_does_not_depend_on_directly(self):
        self.assertEqual(metadata_check._intermediate(self.default, "app", "tsup"), "deep")

    def test_a_dropped_edge_must_shrink_the_closure_so_it_is_not_a_no_op(self):
        self.assertEqual(metadata_check._droppable_edge(self.default, "app", "tsup"), "lib",
                         "a_util is also reached through lib, so removing app -> a_util changes nothing")

    def test_plants_edit_a_shared_dependency_entry_the_way_cargo_prints_it(self):
        meta = copy.deepcopy(self.default)
        metadata_check.add_normal_edge(meta, "app", "tsup")
        entries = [d for d in metadata_check._node(meta, "app")["deps"] if d["name"] == "tsup"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(sorted(str(k["kind"]) for k in entries[0]["dep_kinds"]), ["None", "dev"])
        metadata_check.remove_normal_edge(meta, "app", "tsup")
        entries = [d for d in metadata_check._node(meta, "app")["deps"] if d["name"] == "tsup"]
        self.assertEqual([k["kind"] for k in entries[0]["dep_kinds"]], ["dev"])
        self.assertIn(entries[0]["pkg"], metadata_check._node(meta, "app")["dependencies"])

    def test_a_document_of_another_tree_names_what_differs_and_stays_bounded(self):
        many = {"members": self.tree["members"] + [self.member(f"extra{i}") for i in range(10)]}
        pairs = metadata_check.bind_to_tree("default", self.default, many, None, False, self.CRATE, self.FEATURE)
        (code, subject), = [p for p in pairs if p[0] == "metadata_members_differ_from_tree"]
        self.assertIn("only_in_tree=extra0,extra1,extra2,extra3,extra4,extra5,+4 more", subject)
        self.assertNotIn("/", subject, "subjects carry no paths")

    def test_a_default_document_that_resolved_the_gate_feature_is_refused(self):
        d = copy.deepcopy(self.default)
        metadata_check._node(d, "app")["features"].append("harness")
        self.assertIn("metadata_feature_resolved_by_default", metadata_check.codes(self.judge(d)))

    def test_a_malformed_document_is_malformed_not_a_pass(self):
        got = self.judge(default={"packages": []})
        self.assertIn(("metadata_malformed", "default"), got)


class MetadataRealCaseTests(unittest.TestCase):
    """The runner wiring of P01-BLK-007 against the live tree, with documents synthesized from that tree's own manifests.
    That proves the wiring (flags, blocked/judged/failed, exit codes, receipt), not cargo's resolver: the independent
    comparison is made only on the documents cargo produced centrally."""
    CASE = ["--tier", "full", "--case", "P01-BLK-007"]

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_cases.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        tree = facts.extract(run_cases.REPO)
        lock = metadata_check.lock_packages(os.path.join(run_cases.REPO, "Cargo.lock"))
        member_names = {m["name"] for m in tree["members"]}
        versions = {name: version for name, version in lock if name in member_names}
        external = next(iter(sorted(pair for pair in lock if pair[0] not in member_names)), None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.paths = {}
        for kind, harness in (("default", False), ("harness", True)):
            doc = cargo_shaped(tree, versions, metadata_check.GATE_CRATE, metadata_check.GATE_FEATURE, harness, external)
            self.paths[kind] = os.path.join(tmp.name, kind + ".json")
            with open(self.paths[kind], "w") as f:
                json.dump(doc, f)
        self.tmp = tmp.name

    def flags(self, default=None, harness=None):
        return ["--metadata-default", default or self.paths["default"], "--metadata-harness", harness or self.paths["harness"]]

    def test_without_documents_the_case_is_blocked_counted_and_never_a_pass(self):
        code, out, _ = self.run_main(*self.CASE)
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED", out)
        self.assertIn("blocked=1", out)
        self.assertNotIn("PASS", out)

    def test_one_document_alone_is_a_usage_error_not_a_silent_skip(self):
        code, out, err = self.run_main(*self.CASE, "--metadata-default", self.paths["default"])
        self.assertEqual((code, out), (2, ""))
        self.assertIn("go together", err)

    def test_supplied_documents_are_judged_and_the_receipt_names_them_by_digest_only(self):
        receipts = os.path.join(self.tmp, "receipts")
        code, out, _ = self.run_main(*self.CASE, *self.flags(), "--receipts", receipts)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)
        self.assertIn("planted faults caught", out)
        (name,) = os.listdir(receipts)
        with open(os.path.join(receipts, name)) as f:
            receipt = json.load(f)
        self.assertEqual(receipt["metadata_inputs"], {
            "default_sha256": metadata_check.sha256_file(self.paths["default"]),
            "harness_sha256": metadata_check.sha256_file(self.paths["harness"])})
        self.assertNotIn(self.tmp, json.dumps(receipt), "the receipt carries digests, not paths")

    def test_swapped_unreadable_and_non_json_documents_fail_rather_than_block_or_pass(self):
        for label, flags in (("swapped", self.flags(self.paths["harness"], self.paths["default"])),
                             ("unreadable", self.flags(os.path.join(self.tmp, "none.json"))),
                             ("not json", self.flags(run_cases.__file__))):
            with self.subTest(label):
                code, out, _ = self.run_main(*self.CASE, *flags)
                self.assertEqual(code, 1, out)
                self.assertIn("FAIL", out)

    def test_a_planted_leak_in_the_supplied_default_document_fails_the_case(self):
        with open(self.paths["default"]) as f:
            doc = json.load(f)
        metadata_check.add_normal_edge(doc, metadata_check.GATE_CRATE, metadata_check.FORBIDDEN)
        leaked = os.path.join(self.tmp, "leaked.json")
        with open(leaked, "w") as f:
            json.dump(doc, f)
        code, out, _ = self.run_main(*self.CASE, *self.flags(default=leaked))
        self.assertEqual(code, 1)
        self.assertIn("metadata_default_has_edge", out)

    def test_the_case_is_in_both_tiers_so_it_cannot_be_dropped_from_a_run(self):
        cases = {c["id"]: c for c in run_cases.all_cases()}
        self.assertEqual(sorted(cases["P01-BLK-007"]["tiers"]), ["full", "smoke"])
        self.assertEqual(cases["P01-BLK-007"]["kind"], "metadata_real")


class ResolveTests(unittest.TestCase):
    def facts_for(self, ops):
        spec = ref.apply_ops(fixtures.base_spec(), ops)
        with tempfile.TemporaryDirectory() as tmp:
            fixtures.materialize(tmp, spec)
            return facts.extract(tmp)

    def test_weak_features_apply_only_to_an_already_active_dependency(self):
        data = {"members": [
            {"name": "x", "deps": {"normal": ["y"], "optional": []}, "feature_table": {"f": ["y?/g"]}},
            {"name": "y", "deps": {"normal": [], "optional": ["z"]}, "feature_table": {"g": ["dep:z"]}},
            {"name": "z", "deps": {"normal": [], "optional": []}, "feature_table": {}}]}
        self.assertEqual(facts.resolve_normal_closure(data, "x", ["f"]), {"x", "y", "z"})
        self.assertEqual(facts.resolve_normal_closure(data, "x"), {"x", "y"})

    def test_a_feature_implied_by_another_enables_its_dependency(self):
        data = {"members": [
            {"name": "x", "deps": {"normal": [], "optional": ["y"]}, "feature_table": {"a": ["b"], "b": ["dep:y"]}},
            {"name": "y", "deps": {"normal": [], "optional": []}, "feature_table": {}}]}
        self.assertEqual(facts.resolve_normal_closure(data, "x", ["a"]), {"x", "y"})
        self.assertEqual(facts.resolve_normal_closure(data, "x"), {"x"})

    def test_an_unknown_start_crate_resolves_to_nothing(self):
        self.assertEqual(facts.resolve_normal_closure({"members": []}, "nope"), set())

    def test_the_real_speaker_default_build_has_no_test_support_edge(self):
        data = facts.extract(run_cases.REPO)
        self.assertNotIn("franken-test-support", facts.resolve_normal_closure(data, "franken-speaker"))
        self.assertIn("franken-test-support", facts.resolve_normal_closure(data, "franken-speaker", ["harness"]))


if __name__ == "__main__":
    unittest.main()
