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
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import central  # noqa: E402
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
        # blocked by construction: a synthetic case of the static `blocked` kind, so this test cannot depend on which
        # central-run evidence happens to be committed (P01-BLK-001/002/003 are judged from it and may pass)
        synthetic = {"id": "P01-TEST-BLOCKED", "kind": "blocked", "title": "a case nothing here can verify",
                     "tiers": ["smoke", "full"], "reason": "needs a central run", "owner": "nobody"}
        original = run_cases.all_cases
        run_cases.all_cases = lambda: [synthetic]
        try:
            code, out, _ = self.run_main("--tier", "smoke", "--case", "P01-TEST-BLOCKED")
        finally:
            run_cases.all_cases = original
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED", out)
        self.assertIn("passed=0 failed=0 blocked=1", out)
        self.assertIn("NOT QUALIFIED", out)

    def test_the_committed_evidence_cases_are_computed_not_static(self):
        cases = {c["id"]: c for c in run_cases.all_cases()}
        for cid in ("P01-BLK-001", "P01-BLK-002", "P01-BLK-003"):
            self.assertEqual(cases[cid]["kind"], "central_evidence", cid)
        self.assertEqual([cases[c]["judge"] for c in ("P01-BLK-001", "P01-BLK-002", "P01-BLK-003")],
                         ["steps", "device_artifacts", "replay"])

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
            before = run_cases._read_bytes(os.path.join(tmp, first[0]))
            self.assertEqual(self.run_main("--tier", "smoke", "--case", "P01-V-001", "--receipts", tmp)[0], 0)
            after = sorted(os.listdir(tmp))
            self.assertEqual(len(after), 2)
            self.assertEqual(run_cases._read_bytes(os.path.join(tmp, first[0])), before)
            doc = json.loads(run_cases._read_text(os.path.join(tmp, first[0])))
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
                abi = (32, 2, 3) if art["target"] == "mips_be" and art["crate"] == "franken-speaker" else None
                f.write(run_cases.fake_elf(machine, art["crate"].encode() + art["target"].encode(), mips_abi=abi)
                        if art["target"] != "host" else b"host-binary" + art["crate"].encode())

    def test_print_plan_prints_eight_acceptable_steps(self):
        code, out = self.run_pipeline("print-plan")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual((len(doc["steps"]), doc["violations"]), (8, []))
        self.assertEqual(doc["contract_digest"], ref.digest(small_contract()))

    def test_collect_with_nothing_built_is_incomplete_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self.run_pipeline("collect", "--target-dir", os.path.join(tmp, "none"),
                                          "--receipts", os.path.join(tmp, "r"))
            self.assertEqual(code, 3)
            self.assertIn("status incomplete", out)
            receipt = json.loads(run_cases._read_text(os.path.join(tmp, "r", os.listdir(os.path.join(tmp, "r"))[0])))
            self.assertEqual((receipt["status"], len(receipt["artifacts"]), len(receipt["missing"])), ("incomplete", 0, 7))

    def test_collect_of_a_correct_tree_is_complete_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "t")
            self.write_artifacts(target)
            code, _out = self.run_pipeline("collect", "--target-dir", target, "--receipts", os.path.join(tmp, "r"))
            self.assertEqual(code, 0)
            receipt = json.loads(run_cases._read_text(os.path.join(tmp, "r", os.listdir(os.path.join(tmp, "r"))[0])))
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


class PlanJobsTests(unittest.TestCase):
    """The `-j` parameter, the default-toolchain step and the foreign-artifacts guard in plan.py."""

    def setUp(self):
        self.root = os.path.realpath(run_cases.REPO)
        self.doc = run_cases.contract()
        self.cwd = os.path.join(self.root, "crates", "franken-board-profile")

    def steps(self, **kw):
        return plan.plan_steps(self.root, self.cwd, "/nonexistent/target", self.doc, **kw)

    def cargo_steps(self, steps):
        return [s for s in steps if plan.inner_command(s["argv"])[0] == "cargo"]

    def test_every_cargo_step_ends_with_the_job_count_and_the_default_is_two(self):
        for jobs, steps in ((2, self.steps()), (3, self.steps(jobs=3))):
            self.assertEqual(len(self.cargo_steps(steps)), 6)
            for step in self.cargo_steps(steps):
                self.assertEqual(step["argv"][-2:], ["-j", str(jobs)], step["id"])
            self.assertEqual(plan.check_plan(steps, self.root, self.doc), [])

    def test_toolchain_queries_are_not_cargo_steps_and_carry_no_job_count(self):
        queries = {s["id"]: s["argv"] for s in self.steps() if plan.inner_command(s["argv"])[0] == "rustc"}
        self.assertEqual(queries, {"toolchain": ["rch", "exec", "--", "rustc", "+nightly", "-vV"],
                                   "toolchain-default": ["rch", "exec", "--", "rustc", "-vV"]})

    def test_a_missing_or_malformed_job_count_is_refused_and_both_spellings_are_accepted(self):
        for label, edit, want in (
                ("dropped", lambda a: a[:-2], ["plan_missing_jobs"]),
                ("zero", lambda a: a[:-1] + ["0"], ["plan_missing_jobs"]),
                ("not a number", lambda a: a[:-1] + ["many"], ["plan_missing_jobs"]),
                ("no value", lambda a: a[:-1], ["plan_missing_jobs"]),
                ("long spelling", lambda a: a[:-2] + ["--jobs", "4"], []),
                ("a larger count", lambda a: a[:-1] + ["8"], [])):
            with self.subTest(label):
                steps = self.steps()
                target = next(s for s in steps if s["id"] == "workspace-test")
                target["argv"] = edit(target["argv"])
                got = [code for code, sid in plan.check_plan(steps, self.root, self.doc) if sid == "workspace-test"]
                self.assertEqual(got, want)

    def test_the_foreign_artifacts_variable_is_only_on_the_host_build(self):
        steps = self.steps()
        carrying = [s["id"] for s in steps if plan.FOREIGN_ARTIFACTS_ENV in s["env"]]
        self.assertEqual(carrying, ["build-franken-speaker-host"])
        self.assertEqual(plan.check_plan(steps, self.root, self.doc), [])
        for sid in ("build-franken-speaker-mips_be", "toolchain", "workspace-test"):
            with self.subTest(sid):
                bad = self.steps()
                next(s for s in bad if s["id"] == sid)["env"][plan.FOREIGN_ARTIFACTS_ENV] = "1"
                self.assertEqual([c for c, s in plan.check_plan(bad, self.root, self.doc) if s == sid],
                                 ["plan_foreign_artifacts_misplaced"])

    def test_a_receipt_keeps_the_nightly_and_the_default_compiler_apart(self):
        text_nightly, text_default = run_cases.RUSTC_VV, run_cases.RUSTC_VV_DEFAULT
        self.assertEqual(plan.parse_rustc_vv(text_nightly)["release"], "1.101.0-nightly")
        self.assertEqual(plan.parse_rustc_vv(text_default)["release"], "1.90.0")


def fake_rch_log(command, exit_code=0, worker="ts1", trailer=True, local=False, extra="", duplicate=False):
    """What an rch log carries for one remote command, with ANSI colour, a worker address and local paths that a
    sanitized record must not keep."""
    shown = shlex.join(command)
    if trailer and command and command[0].lstrip("+") != "rustc" and command[0] == "cargo":
        shown += " --config 'env.RCH_BUILD_SOURCE.value=\"unknown\"' --config 'env.RCH_BUILD_SOURCE.force=true'"
    line = f"  2026-11-05T03:31:40.928215Z \x1b[32m INFO\x1b[0m rch::hook::transfer_orchestration: Executing command remotely: {shown}\n"
    return (f"  2026-11-05T03:31:30.080475Z \x1b[32m INFO\x1b[0m rch::hook: Selected worker: {worker} at builder@198.51.100.7 (2 slots)\n"
            + line * (2 if duplicate else 1) + extra
            + f"  2026-11-05T03:31:41.000000Z  INFO rch::hook::transfer_orchestration: Remote command finished: exit={exit_code} in 1234ms\n"
            + ("[RCH] local\n" if local else f"[RCH] remote {worker} (1.2s)\n"))


class CentralEvidenceTests(unittest.TestCase):
    """central.build_evidence / central.judge on synthetic rch logs generated for the CURRENT plan, so the tests never
    depend on what evidence happens to be committed. Every rejection starts from the passing baseline."""

    def setUp(self):
        self.root = os.path.realpath(run_cases.REPO)
        self.doc = run_cases.contract()
        self.export = "/srv/export-a1b2c3/ffw"
        self.cwd = os.path.join(self.export, "crates", "franken-board-profile")
        self.planned = plan.plan_steps(self.export, self.cwd, "/srv/export-a1b2c3/ffw/build/p01-target", self.doc)
        self.now = plan.plan_steps(self.root, os.path.join(self.root, "crates", "franken-board-profile"),
                                   "/nonexistent/target", self.doc)
        self.roots_now = central.roots_for(self.root)
        self.logs = {}
        for step in self.planned:
            if step["id"] not in central.BLK001_STEPS:
                continue
            inner = plan.inner_command(step["argv"])
            extra = ""
            if step["kind"] == "toolchain":
                extra = run_cases.RUSTC_VV
            if step["kind"] == "toolchain_default":
                extra = run_cases.RUSTC_VV_DEFAULT
            if step["kind"] == "test":
                extra = "test result: ok. 530 passed; 0 failed; 1 ignored; 0 measured\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured\n"
            self.logs[step["id"]] = fake_rch_log(inner, extra=extra)
        self.rows = []

    def build(self, logs=None, **kw):
        args = dict(contract=self.doc, planned=self.planned, logs=logs if logs is not None else self.logs,
                    revision="a" * 40, lock_sha256="b" * 64, export_root=self.export, rows=[], missing=[], sizes={},
                    attested_env={})
        args.update(kw)
        return central.build_evidence(**args)

    def judge(self, evidence, doc=None, steps=None):
        return central.judge(evidence, doc or self.doc, steps or self.now, self.roots_now)

    def test_a_faithful_run_of_the_current_plan_is_a_pass(self):
        evidence = self.build()
        verdict, detail = self.judge(evidence)
        self.assertEqual(verdict, "pass", detail)
        self.assertIn("6 steps ran the current plan", detail)
        self.assertEqual(evidence["tests"], {"result_blocks": 2, "passed": 533, "failed": 0, "ignored": 1})
        self.assertEqual((evidence["toolchain"]["release"], evidence["toolchain_default"]["release"]),
                         ("1.101.0-nightly", "1.90.0"))
        self.assertEqual(evidence["workers"], ["ts1"])
        self.assertEqual(evidence["ran_at_utc"], "2026-11-05T03:31:30Z")

    def test_the_record_keeps_no_address_user_path_or_export_directory(self):
        text = json.dumps(self.build())
        for needle in ("198.51.100.7", "builder@", "/srv/export", "a1b2c3", "\x1b", "slots"):
            self.assertNotIn(needle, text)
        self.assertIn("<repo>/Cargo.toml", text)

    def test_rch_own_config_trailer_is_not_part_of_the_command_but_a_users_config_is(self):
        tokens = ["cargo", "test", "--config", "build.incremental=false", "-j", "2",
                  "--config", "env.RCH_BUILD_SOURCE.value=\"unknown\"", "--config", "env.RCH_BUILD_SOURCE.force=true"]
        self.assertEqual(central.strip_rch_trailer(tokens), ["cargo", "test", "--config", "build.incremental=false", "-j", "2"])

    def test_normalizing_replaces_the_root_only_at_a_path_boundary(self):
        got = central.normalize(["/srv/e/Cargo.toml", "/srv/e", "/srv/extra/x", "/srv/e2", "plain"], ["/srv/e"])
        self.assertEqual(got, ["<repo>/Cargo.toml", "<repo>", "/srv/extra/x", "/srv/e2", "plain"])

    def test_a_step_that_never_ran_makes_the_evidence_stale_not_failed_and_names_it(self):
        logs = {k: v for k, v in self.logs.items() if k != "toolchain-default"}
        verdict, detail = self.judge(self.build(logs))
        self.assertEqual(verdict, "blocked")
        self.assertIn("5 of 6 steps ran the current plan", detail)
        self.assertIn("step toolchain-default has not run", detail)

    def test_evidence_for_another_plan_is_stale_and_names_the_step(self):
        verdict, detail = self.judge(self.build(), steps=plan.plan_steps(
            self.root, os.path.join(self.root, "crates", "franken-board-profile"), "/nonexistent/target", self.doc, jobs=4))
        self.assertEqual(verdict, "blocked")
        self.assertIn("ran a different command than the current plan", detail)

    def test_evidence_for_another_contract_is_stale(self):
        other = json.loads(json.dumps(self.doc))
        other["crates"][0]["owner"] = other["crates"][0]["owner"] + "-changed"
        verdict, detail = self.judge(self.build(), doc=other)
        self.assertEqual(verdict, "blocked")
        self.assertIn("contract digest", detail)

    def test_a_failed_step_fails_the_evidence_and_is_not_laundered_into_stale(self):
        for sid in ("workspace-test", "build-ffw-hello-init-mips_be"):
            with self.subTest(sid):
                logs = dict(self.logs)
                inner = plan.inner_command(next(s for s in self.planned if s["id"] == sid)["argv"])
                logs[sid] = fake_rch_log(inner, exit_code=101)
                verdict, detail = self.judge(self.build(logs))
                self.assertEqual(verdict, "fail")
                self.assertIn(sid, detail)

    def test_a_command_that_differs_from_the_plan_or_ran_locally_or_twice_is_a_failed_step(self):
        sid = "workspace-test"
        inner = plan.inner_command(next(s for s in self.planned if s["id"] == sid)["argv"])
        for label, log in (("no --locked", fake_rch_log([a for a in inner if a != "--locked"])),
                           ("ran locally", fake_rch_log(inner, local=True)),
                           ("remote marker but a local fallback line too", fake_rch_log(inner, extra="[RCH] local fallback\n")),
                           ("two command lines", fake_rch_log(inner, duplicate=True)),
                           ("no job count", fake_rch_log(inner[:-2]))):
            with self.subTest(label):
                logs = dict(self.logs, **{sid: log})
                evidence = self.build(logs)
                step = next(s for s in evidence["steps"] if s["id"] == sid)
                self.assertEqual(step["status"], "failed", label)
                self.assertTrue(step["problems"])
                self.assertEqual(self.judge(evidence)[0], "fail")

    def test_failed_workspace_tests_fail_the_evidence_even_when_cargo_exited_zero(self):
        logs = dict(self.logs)
        inner = plan.inner_command(next(s for s in self.planned if s["id"] == "workspace-test")["argv"])
        logs["workspace-test"] = fake_rch_log(inner, extra="test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured\n")
        verdict, detail = self.judge(self.build(logs))
        self.assertEqual((verdict, "2 workspace test(s) failed" in detail), ("fail", True))

    def test_a_malformed_or_unbound_record_fails(self):
        base = self.build()
        for label, edit in (("schema", lambda e: e.update(schema="x")),
                            ("short revision", lambda e: e.update(revision="abc123")),
                            ("no contract digest", lambda e: e.update(contract_digest="")),
                            ("steps not a list", lambda e: e.update(steps={})),
                            ("row bound to another digest", lambda e: e["artifacts"].append(
                                {"id": "hello-init-mips", "contract_digest": "c" * 64}))):
            with self.subTest(label):
                evidence = json.loads(json.dumps(base))
                edit(evidence)
                self.assertEqual(self.judge(evidence)[0], "fail")

    def test_artifact_identity_is_held_to_the_current_contract_when_the_evidence_is_current(self):
        art = next(a for a in self.doc["artifacts"] if a["id"] == "hello-init-mips")
        good = plan.observed_row(self.doc, art, {"sha256": "d" * 64, "elf_machine": 8, "elf_class": 1, "elf_big_endian": True,
                                                     "elf_dynamic": False, "isa_revision": "", "fp_abi": ""})
        bad = dict(good, elf_machine=20)
        self.assertEqual(self.judge(self.build(rows=[good]))[0], "pass")
        verdict, detail = self.judge(self.build(rows=[bad]))
        self.assertEqual(verdict, "fail")
        self.assertIn("elf_machine_mismatch", detail)

    def test_the_ingest_command_writes_one_record_and_refuses_to_overwrite_it(self):
        try:
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=run_cases.REPO, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git is unavailable")
        if head.returncode != 0:
            self.skipTest("no git history here")
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for sid, text in self.logs.items():
                paths[sid] = os.path.join(tmp, sid + ".log")
                with open(paths[sid], "w") as f:
                    f.write(text)
            export = os.path.join(tmp, "export")
            os.makedirs(export)
            # the logs above name /srv/export-a1b2c3/ffw, so ingest against that root's spelling is what must match
            args = ["ingest", "--revision", "HEAD", "--export-root", self.export, "--target-dir", os.path.join(tmp, "t"),
                    "--out", os.path.join(tmp, "out")] + [a for sid, p in paths.items() for a in ("--step", f"{sid}={p}")]
            out, err = io.StringIO(), io.StringIO()
            real_git_show = pipeline._git_show

            def working_tree_show(revision, path):
                with open(os.path.join(run_cases.REPO, *path.split("/")), "rb") as handle:
                    return handle.read()
            pipeline._git_show = working_tree_show
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = pipeline.main(args)
                    again = pipeline.main(args)
            finally:
                pipeline._git_show = real_git_show
            self.assertEqual((code, again), (0, 2), out.getvalue() + err.getvalue())
            self.assertIn("refusing to overwrite", err.getvalue())
            (name,) = os.listdir(os.path.join(tmp, "out"))
            self.assertTrue(name.startswith("rev-" + head.stdout.strip()[:12]))
            with open(os.path.join(tmp, "out", name, "receipt.json")) as f:
                record = json.load(f)
            self.assertEqual(record["revision"], head.stdout.strip())
            self.assertEqual([s["status"] for s in record["steps"] if s["id"] in central.BLK001_STEPS], ["ok"] * 6)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pipeline.main(["ingest", "--revision", "HEAD", "--export-root", self.export,
                                                "--target-dir", tmp, "--out", os.path.join(tmp, "o2"),
                                                "--step", "no-such-step=x"]), 2)

    def test_every_committed_evidence_record_is_well_formed_and_carries_no_site_data(self):
        pattern = re.compile(r"/Users/|/private/|/home/|/var/folders|jemanuel|claude-501|@|\x1b|\b\d{1,3}(?:\.\d{1,3}){3}\b")
        for path in central.find_evidence(run_cases.REPO):
            with self.subTest(os.path.basename(os.path.dirname(path))):
                text = run_cases._read_text(path)
                self.assertIsNone(pattern.search(text), "an evidence record must not carry paths, users or addresses")
                record = json.loads(text)
                self.assertEqual(record["schema"], central.EVIDENCE_SCHEMA)
                self.assertRegex(record["revision"], r"^[0-9a-f]{40}$")
                self.assertTrue(path.split(os.sep)[-2] == "rev-" + record["revision"][:12])
                for step in record["steps"]:
                    if step["status"] != "not_run":
                        self.assertRegex(step["log_sha256"], r"^[0-9a-f]{64}$")


class ElfFactsTests(unittest.TestCase):
    """plan.elf_program_facts reads static/dynamic and the MIPS ABI flags from the program headers, never the sections."""

    def facts(self, **kw):
        return plan.elf_program_facts(run_cases.fake_elf(8, b"payload", **kw))

    def test_a_static_soft_float_mips32r2_file(self):
        self.assertEqual(self.facts(mips_abi=(32, 2, 3)), (False, "mips32r2", "soft"))

    def test_an_interpreter_or_dynamic_segment_makes_a_file_dynamic(self):
        self.assertEqual(self.facts(dynamic=True, mips_abi=(32, 2, 3)), (True, "mips32r2", "soft"))

    def test_a_dynamic_segment_without_an_interpreter_also_makes_a_file_dynamic(self):
        data = bytearray(run_cases.fake_elf(8, b"", dynamic=True, mips_abi=(32, 2, 3)))
        data[52:56] = (2).to_bytes(4, "big")  # the first segment is PT_DYNAMIC, not PT_INTERP
        self.assertEqual(plan.elf_program_facts(bytes(data)), (True, "mips32r2", "soft"))
        data[52:56] = (1).to_bytes(4, "big")  # PT_LOAD: neither
        self.assertEqual(plan.elf_program_facts(bytes(data)), (False, "mips32r2", "soft"))

    def test_the_float_abi_values_cargo_can_declare_and_the_ones_it_cannot(self):
        for value, name in ((1, "hard"), (3, "soft"), (0, ""), (2, "single"), (5, "xx"), (6, "fp64"), (9, "fp9")):
            with self.subTest(value):
                self.assertEqual(self.facts(mips_abi=(32, 2, value))[2], name)

    def test_isa_revision_is_spelled_from_level_and_revision(self):
        self.assertEqual(self.facts(mips_abi=(32, 1, 3))[1], "mips32r1")
        self.assertEqual(self.facts(mips_abi=(32, 0, 3))[1], "mips32")
        self.assertEqual(self.facts(mips_abi=(64, 6, 3))[1], "mips64r6")

    def test_a_file_without_program_headers_is_static_with_no_marker(self):
        self.assertEqual(self.facts(), (False, "", ""))

    def test_a_program_header_table_that_cannot_be_read_is_not_reported_static(self):
        data = bytearray(run_cases.fake_elf(8, b"", mips_abi=(32, 2, 3)))
        for label, blob in (("truncated table", bytes(data[:60])),
                            ("phnum beyond the file", bytes(data[:44]) + (200).to_bytes(2, "big") + bytes(data[46:]))):
            with self.subTest(label):
                self.assertEqual(plan.elf_program_facts(blob), (True, "", ""))

    def test_an_abiflags_segment_that_points_outside_the_file_is_not_trusted(self):
        data = bytearray(run_cases.fake_elf(8, b"", mips_abi=(32, 2, 3)))
        data[52 + 4:52 + 8] = (10 ** 6).to_bytes(4, "big")
        self.assertEqual(plan.elf_program_facts(bytes(data)), (True, "", ""))

    def test_non_elf_and_the_wrong_class_report_nothing(self):
        self.assertEqual(plan.elf_program_facts(b"\xcf\xfa\xed\xfe" + bytes(80)), (False, "", ""))
        self.assertEqual(plan.elf_program_facts(b""), (False, "", ""))

    def test_a_64_bit_little_endian_file_with_an_interpreter_is_dynamic(self):
        header = bytearray(64 + 56)
        header[0:4] = b"\x7fELF"
        header[4], header[5] = 2, 1
        header[32:40] = (64).to_bytes(8, "little")
        header[54:56] = (56).to_bytes(2, "little")
        header[56:58] = (1).to_bytes(2, "little")
        header[64:68] = (3).to_bytes(4, "little")
        self.assertEqual(plan.elf_program_facts(bytes(header)), (True, "", ""))
        header[64:68] = (1).to_bytes(4, "little")  # PT_LOAD only
        self.assertEqual(plan.elf_program_facts(bytes(header)), (False, "", ""))

    def test_elf_identity_carries_the_facts_into_a_receipt_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "speaker")
            with open(path, "wb") as f:
                f.write(run_cases.fake_elf(8, b"x", mips_abi=(32, 2, 3)))
            ident = plan.elf_identity(path)
        self.assertEqual((ident["elf_machine"], ident["elf_dynamic"], ident["isa_revision"], ident["fp_abi"]),
                         (8, False, "mips32r2", "soft"))


class LinkerPlanTests(unittest.TestCase):
    """The device speaker steps link static through the contract's wrapper; the bootstrap probe does not."""

    def setUp(self):
        self.root = os.path.realpath(run_cases.REPO)
        self.doc = run_cases.contract()
        self.steps = {s["id"]: s for s in plan.plan_steps(
            self.root, os.path.join(self.root, "crates", "franken-board-profile"), "/nonexistent/target", self.doc)}

    def configs(self, sid):
        inner = plan.inner_command(self.steps[sid]["argv"])
        return [inner[i + 1] for i, tok in enumerate(inner[:-1]) if tok == "--config"]

    def test_the_device_speaker_tokens_are_exactly_the_hand_written_ones(self):
        for sid, triple, wrapper in (("build-franken-speaker-mips_be", "mips-unknown-linux-musl", "zig-cc-mips-be"),
                                     ("build-franken-speaker-powerpc_be", "powerpc-unknown-linux-musl", "zig-cc-powerpc-be")):
            with self.subTest(sid):
                self.assertEqual(self.configs(sid), [
                    f'target.{triple}.linker="{self.root}/toolchain/linker/{wrapper}"',
                    f'target.{triple}.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'])

    def test_the_host_build_and_the_bootstrap_probe_carry_no_linker_tokens(self):
        self.assertEqual(self.configs("build-franken-speaker-host"), [])
        for sid in ("build-ffw-hello-init-mips_be", "build-ffw-hello-init-powerpc_be"):
            self.assertEqual([c for c in self.configs(sid) if "linker" in c or "rustflags" in c], [], sid)

    def test_the_wrapper_in_the_plan_is_the_wrapper_the_contract_declares(self):
        for ln in self.doc["linkers"]:
            triple = plan.ref.TARGETS[ln["target"]][0]
            want = f'target.{triple}.linker="{os.path.join(self.root, ln["wrapper"])}"'
            self.assertIn(want, [c for sid in self.steps for c in self.configs(sid)])

    def test_a_plan_that_omits_either_token_is_refused_and_the_unmutated_plan_is_not(self):
        steps = list(self.steps.values())
        self.assertEqual(plan.check_plan(steps, self.root, self.doc), [])
        for label, drop, code in (("linker", ".linker=", "plan_device_without_linker"),
                                  ("crt-static", ".rustflags=", "plan_device_not_static")):
            with self.subTest(label):
                broken = json.loads(json.dumps(steps))
                step = next(s for s in broken if s["id"] == "build-franken-speaker-mips_be")
                argv, kept, i = step["argv"], [], 0
                while i < len(argv):
                    if argv[i] == "--config" and drop in argv[i + 1] and argv[i + 1].startswith("target."):
                        i += 2
                        continue
                    kept.append(argv[i])
                    i += 1
                step["argv"] = kept
                self.assertEqual([c for c, s in plan.check_plan(broken, self.root, self.doc)
                                  if s == "build-franken-speaker-mips_be"], [code])

    def test_only_the_steps_that_name_a_linker_run_from_the_workspace_root(self):
        at_root = sorted(sid for sid, s in self.steps.items() if os.path.realpath(s["cwd"]) == self.root)
        self.assertEqual(at_root, ["build-franken-speaker-mips_be", "build-franken-speaker-powerpc_be"])
        for sid in ("toolchain", "toolchain-default", "workspace-test", "build-franken-speaker-host",
                    "build-ffw-hello-init-mips_be", "build-ffw-hello-init-powerpc_be"):
            self.assertEqual(os.path.basename(self.steps[sid]["cwd"]), "franken-board-profile", sid)

    def test_the_cwd_rules_each_have_their_positive_twin(self):
        board = os.path.join(self.root, "crates", "franken-board-profile")
        for sid, cwd, want in (
                ("build-franken-speaker-mips_be", board, ["plan_linker_step_not_from_root"]),
                ("build-franken-speaker-powerpc_be", self.root, []),
                ("build-franken-speaker-host", self.root, ["plan_cwd_is_root"]),
                ("build-ffw-hello-init-mips_be", self.root, ["plan_cwd_is_root"]),
                ("workspace-test", self.root, ["plan_cwd_is_root"]),
                ("build-franken-speaker-host", board, []),
                ("build-franken-speaker-mips_be", os.path.join(self.root, "no-such-directory"), ["plan_cwd_missing"])):
            with self.subTest(f"{sid} from {os.path.basename(cwd)}"):
                steps = json.loads(json.dumps(list(self.steps.values())))
                next(s for s in steps if s["id"] == sid)["cwd"] = cwd
                self.assertEqual([c for c, s in plan.check_plan(steps, self.root, self.doc) if s == sid], want)

    def test_a_linker_declared_for_a_crate_with_no_such_step_changes_nothing_for_other_crates(self):
        doc = json.loads(json.dumps(self.doc))
        doc["linkers"] = [ln for ln in doc["linkers"] if ln["target"] != "powerpc_be"]
        steps = plan.plan_steps(self.root, os.path.join(self.root, "crates", "franken-board-profile"),
                                "/nonexistent/target", doc)
        ppc = next(s for s in steps if s["id"] == "build-franken-speaker-powerpc_be")
        self.assertNotIn("--config", plan.inner_command(ppc["argv"]), "no declared linker, no tokens")


class LinkerEvidenceTests(unittest.TestCase):
    """A device speaker step's logged command carries the export directory inside a quoted --config value; ingest must
    still recognize it, and must refuse a different wrapper."""

    def setUp(self):
        self.doc = run_cases.contract()
        self.export = "/srv/export-a1b2c3/ffw"
        self.planned = plan.plan_steps(self.export, self.export + "/crates/franken-board-profile",
                                       self.export + "/build/p01-target", self.doc)

    def evidence_for(self, sid, command):
        return central.build_evidence(self.doc, self.planned, {sid: fake_rch_log(command)}, "a" * 40, "b" * 64,
                                      self.export, [], [], {}, {})

    def test_a_faithful_device_speaker_command_matches_the_plan_with_the_export_path_replaced(self):
        sid = "build-franken-speaker-mips_be"
        step = next(s for s in self.planned if s["id"] == sid)
        evidence = self.evidence_for(sid, plan.inner_command(step["argv"]))
        record = next(s for s in evidence["steps"] if s["id"] == sid)
        self.assertEqual((record["status"], record["matches_plan"]), ("ok", True), record.get("problems"))
        joined = " ".join(record["command"])
        self.assertIn('linker="<repo>/toolchain/linker/zig-cc-mips-be"', joined)
        self.assertNotIn("a1b2c3", joined)

    def test_a_different_wrapper_or_no_static_flag_is_a_command_the_plan_did_not_ask_for(self):
        sid = "build-franken-speaker-mips_be"
        step = next(s for s in self.planned if s["id"] == sid)
        inner = plan.inner_command(step["argv"])
        for label, command in (
                ("other wrapper", [tok.replace("zig-cc-mips-be", "cc") for tok in inner]),
                ("no static", [tok.replace("target-feature=+crt-static", "target-feature=-crt-static") for tok in inner])):
            with self.subTest(label):
                record = next(s for s in self.evidence_for(sid, command)["steps"] if s["id"] == sid)
                self.assertEqual((record["status"], record["matches_plan"]), ("failed", False))


def libtest_block(statuses, header_lines=()):
    """A libtest result block as a combined stdout+stderr log shows it: cargo's own `Running ...` header lines (stderr) may
    land between the `test ... ok` lines (stdout)."""
    lines = [f"running {len(statuses)} tests"]
    items = list(statuses.items())
    for i, (name, status) in enumerate(items):
        lines.append(f"test {name} ... {status}")
        if i < len(header_lines):
            lines.append(header_lines[i])
    failed = sum(1 for _n, s in items if s == "FAILED")
    ignored = sum(1 for _n, s in items if s == "ignored")
    lines += ["", f"test result: {'FAILED' if failed else 'ok'}. {len(items) - failed - ignored} passed; {failed} failed; "
                  f"{ignored} ignored; 0 measured; 0 filtered out; finished in 0.11s", ""]
    return "\n".join(lines) + "\n"


class TestBlockParsingTests(unittest.TestCase):
    def test_a_block_is_recognized_by_its_stdout_markers_whatever_stderr_headers_land_inside_it(self):
        other = libtest_block({"group::tests::a": "ok", "group::tests::b": "ok"})
        mine = libtest_block({"first": "ok", "second": "ok", "third": "ok"},
                             header_lines=["     Running tests/other.rs (target/debug/deps/other-abc)",
                                           "     Running unittests src/lib.rs (target/debug/deps/clock-def)"])
        blocks = central.parse_test_blocks(other + "\x1b[32m   Compiling x\x1b[0m\n" + mine)
        self.assertEqual([sorted(b["tests"]) for b in blocks], [["group::tests::a", "group::tests::b"], ["first", "second", "third"]])
        self.assertEqual([(b["declared"], b["passed"], b["failed"]) for b in blocks], [(2, 2, 0), (3, 3, 0)])

    def test_failed_and_ignored_tests_are_kept_with_their_status(self):
        (block,) = central.parse_test_blocks(libtest_block({"a": "ok", "b": "FAILED", "c": "ignored"}))
        self.assertEqual(block["tests"], {"a": "ok", "b": "FAILED", "c": "ignored"})
        self.assertEqual((block["result"], block["passed"], block["failed"], block["ignored"]), ("FAILED", 1, 1, 1))

    def test_a_test_name_with_spaces_and_text_outside_a_block_are_handled(self):
        text = "test stray ... ok\n" + libtest_block({"src/lib.rs - docs (line 3)": "ok"})
        (block,) = central.parse_test_blocks(text)
        self.assertEqual(list(block["tests"]), ["src/lib.rs - docs (line 3)"])

    def test_rust_test_names_see_tests_with_other_attributes_and_ignore_helpers(self):
        source = "fn helper() {}\n#[test]\nfn plain() {}\n#[test]\n#[should_panic(expected = \"x\")]\nfn panics() {}\n#[test]\npub fn public() {}\n"
        self.assertEqual(central.rust_test_names(source), ["panics", "plain", "public"])


class CentralJudgementTests(unittest.TestCase):
    """BLK-002 (device artifacts) and BLK-003 (the replay) judged from the same kind of record as BLK-001, on synthetic
    logs and rows. Every rejection starts from the passing baseline."""
    NAMES = ["every_vector_id_is_unique", "the_declared_contract_is_valid", "the_digest_is_pinned", "the_shared_vectors_replay"]
    SHA = {"test_file_sha256": "a" * 64, "vectors_sha256": "b" * 64}

    def setUp(self):
        self.doc = run_cases.contract()
        self.root = os.path.realpath(run_cases.REPO)
        self.export = "/srv/export-a1b2c3/ffw"
        self.planned = plan.plan_steps(self.export, self.export + "/crates/franken-board-profile",
                                       self.export + "/build/p01-target", self.doc)
        self.now = plan.plan_steps(self.root, os.path.join(self.root, "crates", "franken-board-profile"), "/nonexistent/target", self.doc)
        self.roots_now = central.roots_for(self.root)
        self.logs = {}
        for step in self.planned:
            inner = plan.inner_command(step["argv"])
            extra = {"toolchain": run_cases.RUSTC_VV, "toolchain_default": run_cases.RUSTC_VV_DEFAULT}.get(step["kind"], "")
            if step["kind"] == "test":
                extra = (libtest_block({"group::tests::a": "ok"}) + libtest_block({n: "ok" for n in self.NAMES}, header_lines=[
                    "     Running tests/p01_contract.rs (target/debug/deps/p01_contract-aa)"]))
            self.logs[step["id"]] = fake_rch_log(inner, extra=extra)
        self.rows = self.good_rows()
        self.device_ids = central.device_std_artifacts(self.doc)

    def good_rows(self):
        out = {}
        for art in self.doc["artifacts"]:
            if not art["bin"]:
                continue
            device = art["target"] != "host"
            isa = "mips32r2" if art["target"] == "mips_be" else ""
            fp = "soft" if art["target"] == "mips_be" else ""
            ident = {"sha256": hashlib_sha(art["target"] + art["crate"]), "elf_machine": {"host": 62, "mips_be": 8, "powerpc_be": 20}[art["target"]],
                     "elf_class": 1 if device else 2, "elf_big_endian": device, "elf_dynamic": not device, "isa_revision": isa, "fp_abi": fp}
            out[art["id"]] = plan.observed_row(self.doc, art, ident)
        return out

    def build(self, rows=None, logs=None, sources="default", **kw):
        sources = dict(names=self.NAMES, **self.SHA) if sources == "default" else sources
        return central.build_evidence(self.doc, self.planned, logs if logs is not None else self.logs, "a" * 40, "b" * 64,
                                      self.export, list((rows or self.rows).values()), [], {}, {}, replay_sources=sources, **kw)

    def judge_devices(self, evidence, doc=None):
        return central.judge(evidence, doc or self.doc, self.now, self.roots_now, scope=central.BLK002_STEPS, artifacts=self.device_ids)

    def judge_replay(self, evidence, now=None, doc=None):
        return central.judge(evidence, doc or self.doc, self.now, self.roots_now, scope=central.BLK003_STEPS, replay=now or self.SHA)

    # ---- BLK-002: the device speaker artifacts
    def test_the_four_device_speakers_pass_when_static_and_carrying_the_declared_abi(self):
        verdict, detail = self.judge_devices(self.build())
        self.assertEqual(verdict, "pass", detail)
        self.assertEqual(len(self.device_ids), 4)
        self.assertIn("speaker-ppc-full", detail)

    def test_a_dynamic_a_hard_float_or_a_wrong_machine_device_artifact_fails(self):
        for label, edit, code in (
                ("dynamic mips", lambda r: r["speaker-mips-full"].update(elf_dynamic=True), "artifact_not_static"),
                ("dynamic ppc", lambda r: r["speaker-ppc-full"].update(elf_dynamic=True), "artifact_not_static"),
                ("hard float", lambda r: r["speaker-mips-min"].update(fp_abi="hard"), "float_abi_mismatch"),
                ("isa revision", lambda r: r["speaker-mips-full"].update(isa_revision="mips32r1"), "isa_revision_mismatch"),
                ("no abi marker on a measured target", lambda r: r["speaker-mips-full"].update(isa_revision="", fp_abi=""), "float_abi_mismatch"),
                ("ppc says mips", lambda r: r["speaker-ppc-full"].update(elf_machine=8), "elf_machine_mismatch"),
                ("little endian", lambda r: r["speaker-ppc-min"].update(elf_big_endian=False), "elf_not_32bit_big_endian")):
            with self.subTest(label):
                rows = json.loads(json.dumps(self.rows))
                edit(rows)
                verdict, detail = self.judge_devices(self.build(rows))
                self.assertEqual(verdict, "fail", detail)
                self.assertIn(code, detail)

    def test_a_missing_device_row_after_an_exit_0_build_fails_and_an_unrun_build_only_blocks(self):
        rows = {k: v for k, v in self.rows.items() if k != "speaker-ppc-full"}
        verdict, detail = self.judge_devices(self.build(rows))
        self.assertEqual(verdict, "fail")
        self.assertIn("speaker-ppc-full", detail)
        logs = {k: v for k, v in self.logs.items() if k != "build-franken-speaker-powerpc_be"}
        verdict, detail = self.judge_devices(self.build(rows, logs))
        self.assertEqual(verdict, "blocked")
        self.assertIn("build-franken-speaker-powerpc_be has not run", detail)

    def test_device_evidence_for_another_contract_is_stale_and_one_digest_for_both_isas_is_a_universal_claim(self):
        other = json.loads(json.dumps(self.doc))
        other["crates"][0]["owner"] += "-changed"
        self.assertEqual(self.judge_devices(self.build(), doc=other)[0], "blocked")
        rows = json.loads(json.dumps(self.rows))
        rows["speaker-ppc-full"]["sha256"] = rows["speaker-mips-full"]["sha256"]
        verdict, detail = self.judge_devices(self.build(rows))
        self.assertEqual((verdict, "universal_artifact_claim" in detail), ("fail", True))

    # ---- BLK-003: the replay tests, by name
    def test_the_replay_passes_by_name_against_the_current_test_file_and_vectors(self):
        evidence = self.build()
        self.assertTrue(evidence["replay"]["found"])
        self.assertEqual(sorted(evidence["replay"]["tests"]), sorted(self.NAMES))
        verdict, detail = self.judge_replay(evidence)
        self.assertEqual(verdict, "pass", detail)
        self.assertIn("the_shared_vectors_replay", detail)

    def test_a_failed_replay_test_fails_even_when_the_rest_of_the_workspace_passed(self):
        statuses = {n: "ok" for n in self.NAMES}
        statuses["the_shared_vectors_replay"] = "FAILED"
        logs = dict(self.logs)
        inner = plan.inner_command(next(s for s in self.planned if s["id"] == "workspace-test")["argv"])
        logs["workspace-test"] = fake_rch_log(inner, extra=libtest_block(statuses))
        verdict, detail = self.judge_replay(self.build(logs=logs))
        self.assertEqual(verdict, "fail")
        self.assertIn("the_shared_vectors_replay", detail)

    def test_a_log_without_the_exact_replay_tests_blocks_rather_than_passing_on_totals(self):
        inner = plan.inner_command(next(s for s in self.planned if s["id"] == "workspace-test")["argv"])
        for label, extra in (("a replay test absent", libtest_block({n: "ok" for n in self.NAMES[:-1]})),
                             ("an extra test in the block", libtest_block({**{n: "ok" for n in self.NAMES}, "surprise": "ok"})),
                             ("no block at all", "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured\n")):
            with self.subTest(label):
                logs = dict(self.logs, **{"workspace-test": fake_rch_log(inner, extra=extra)})
                verdict, detail = self.judge_replay(self.build(logs=logs))
                self.assertEqual(verdict, "blocked", detail)
                self.assertIn("no test block with exactly the current replay tests", detail)

    def test_a_replay_of_an_older_test_file_or_older_vectors_is_stale(self):
        evidence = self.build()
        for label, now, text in (("test file", {**self.SHA, "test_file_sha256": "c" * 64}, "replay test file has changed"),
                                 ("vectors", {**self.SHA, "vectors_sha256": "c" * 64}, "shared vectors have changed")):
            with self.subTest(label):
                verdict, detail = self.judge_replay(evidence, now=now)
                self.assertEqual(verdict, "blocked")
                self.assertIn(text, detail)

    def test_a_record_from_before_replay_capture_is_stale_not_passed(self):
        evidence = self.build(sources=None)
        self.assertNotIn("replay", evidence)
        verdict, detail = self.judge_replay(evidence)
        self.assertEqual(verdict, "blocked")
        self.assertIn("predates replay capture", detail)

    # ---- the cases that read the committed records
    def test_each_evidence_judgement_is_blocked_when_no_record_is_committed(self):
        original = central.find_evidence
        central.find_evidence = lambda repo: []
        try:
            for judgement in ("steps", "device_artifacts", "replay"):
                with self.subTest(judgement):
                    status, detail = run_cases.run_central_evidence({"judge": judgement, "reason": "r", "owner": "o"})
                    self.assertEqual(status, run_cases.BLOCKED)
                    self.assertIn("no central-run evidence is committed", detail)
        finally:
            central.find_evidence = original

    def test_an_unknown_judgement_is_an_error_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "rev-" + "a" * 12, "receipt.json")
            os.makedirs(os.path.dirname(path))
            with open(path, "w") as f:
                json.dump(self.build(), f)
            original = central.find_evidence
            central.find_evidence = lambda repo: [path]
            try:
                with self.assertRaises(run_cases.CaseError):
                    run_cases.run_central_evidence({"judge": "nonsense", "reason": "r", "owner": "o"})
            finally:
                central.find_evidence = original

    def test_ingest_records_the_replay_tests_by_name_from_the_log_and_binds_them_to_the_files(self):
        try:
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=run_cases.REPO, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("git is unavailable")
        if head.returncode != 0:
            self.skipTest("no git history here")
        names = central.rust_test_names(run_cases._read_text(os.path.join(run_cases.REPO, *central.REPLAY_TEST_FILE.split("/"))))
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for sid, text in self.logs.items():
                if sid == "workspace-test":
                    inner = plan.inner_command(next(s for s in self.planned if s["id"] == sid)["argv"])
                    text = fake_rch_log(inner, extra=libtest_block({n: "ok" for n in names}))
                paths[sid] = os.path.join(tmp, sid + ".log")
                with open(paths[sid], "w") as f:
                    f.write(text)
            real = pipeline._git_show

            def working_tree_show(revision, path):
                with open(os.path.join(run_cases.REPO, *path.split("/")), "rb") as handle:
                    return handle.read()
            pipeline._git_show = working_tree_show
            try:
                args = ["ingest", "--revision", "HEAD", "--export-root", self.export, "--target-dir", os.path.join(tmp, "t"),
                        "--out", os.path.join(tmp, "out")] + [a for sid, p in paths.items() for a in ("--step", f"{sid}={p}")]
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(pipeline.main(args), 0)
            finally:
                pipeline._git_show = real
            (name,) = os.listdir(os.path.join(tmp, "out"))
            with open(os.path.join(tmp, "out", name, "receipt.json")) as f:
                record = json.load(f)
        replay = record["replay"]
        self.assertTrue(replay["found"])
        self.assertEqual(sorted(replay["tests"]), names)
        self.assertEqual(replay["test_file_sha256"], metadata_check.sha256_file(os.path.join(run_cases.REPO, *central.REPLAY_TEST_FILE.split("/"))))
        self.assertEqual(replay["vectors_sha256"], metadata_check.sha256_file(os.path.join(run_cases.REPO, *central.REPLAY_VECTORS_FILE.split("/"))))


def hashlib_sha(text):
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


class SelftestVerdictTests(unittest.TestCase):
    """P01-META-006 used to require a bare `OK`, so it failed in every git-archive export (no .git, two tests skip) and the runner's
    own machinery was never verified centrally. The verdict now reads the verbose run: it accepts a skip only for the two tests
    that need git history, with their documented reasons, when this checkout has none; everything else is refused."""

    NAMES = sorted(run_cases.EXPORT_SKIPS)

    @staticmethod
    def run_text(ran=119, skipped=(), summary=None, failures=0):
        lines = ["test_a_ordinary_one (test_p01.X.test_a_ordinary_one) ... ok"]
        for name, reason in skipped:
            lines.append(f"{name} (test_p01.Y.{name}) ... skipped '{reason}'")
        lines += ["", "-" * 70, f"Ran {ran} tests in 0.3s", ""]
        if failures:
            lines.append(f"FAILED (failures={failures})")
        elif summary is not None:
            lines.append(summary)
        else:
            lines.append(f"OK (skipped={len(skipped)})" if skipped else "OK")
        return "\n".join(lines) + "\n"

    def judge(self, text, rc=0, min_tests=20, history=False):
        return run_cases.judge_selftest(rc, text, min_tests, history)

    def both_skips(self, reason="no git history here"):
        return [(n, reason) for n in self.NAMES]

    def test_a_clean_run_in_a_checkout_with_history_passes(self):
        self.assertEqual(self.judge(self.run_text(), history=True), "119 unit tests")

    def test_the_two_documented_skips_pass_only_in_an_export_without_history(self):
        text = self.run_text(skipped=self.both_skips())
        self.assertIn("2 skipped", self.judge(text, history=False))
        with self.assertRaisesRegex(run_cases.CaseError, "has git history"):
            self.judge(text, history=True)  # the plant: the same skips where they have no excuse

    def test_either_documented_reason_is_accepted(self):
        for reason in ("git is unavailable", "no git history here"):
            self.judge(self.run_text(skipped=self.both_skips(reason)), history=False)

    def test_a_skip_of_any_other_test_is_refused(self):
        text = self.run_text(skipped=[("test_something_else_entirely", "no git history here")])
        with self.assertRaisesRegex(run_cases.CaseError, "only .* may skip"):
            self.judge(text, history=False)
        self.judge(self.run_text(skipped=[(self.NAMES[0], "no git history here")]), history=False)  # control: a documented one

    def test_an_undocumented_reason_is_refused_for_a_documented_test(self):
        text = self.run_text(skipped=[(self.NAMES[0], "this machine is slow")])
        with self.assertRaisesRegex(run_cases.CaseError, "undocumented reason"):
            self.judge(text, history=False)

    def test_a_summary_that_declares_more_skips_than_the_lines_show_is_refused(self):
        text = self.run_text(skipped=[(self.NAMES[0], "no git history here")], summary="OK (skipped=2)")
        with self.assertRaisesRegex(run_cases.CaseError, "declares 2 skipped"):
            self.judge(text, history=False)
        # a skip line the parser cannot read (a docstring splits the line) cannot hide behind the summary either
        hidden = self.run_text(summary="OK (skipped=1)")
        with self.assertRaisesRegex(run_cases.CaseError, "declares 1 skipped"):
            self.judge(hidden, history=False)

    def test_a_failure_an_error_exit_or_a_summary_with_extra_outcomes_is_refused(self):
        with self.assertRaisesRegex(run_cases.CaseError, "unit tests failed"):
            self.judge(self.run_text(failures=1))
        with self.assertRaisesRegex(run_cases.CaseError, "unit tests failed"):
            self.judge(self.run_text(), rc=1)
        with self.assertRaisesRegex(run_cases.CaseError, "unit tests failed"):
            self.judge(self.run_text(summary="OK (expected failures=1)"))
        self.judge(self.run_text())  # control: the unplanted text passes

    def test_too_few_tests_is_refused_and_skips_do_not_count_toward_the_floor_silently(self):
        with self.assertRaisesRegex(run_cases.CaseError, "only 10 unit tests ran"):
            self.judge(self.run_text(ran=10), min_tests=20)
        self.assertIn("117 executed", self.judge(self.run_text(ran=119, skipped=self.both_skips()), history=False))

    def test_the_skip_names_are_exactly_the_tests_that_skip_in_this_file(self):
        """The allow-list cannot drift from the tests: every test that skips for missing git history is listed, and every
        listed test exists. (The needle is built in two pieces so this test's own text does not contain it.)"""
        needle = "self.skip" + "Test("
        source = run_cases._read_text(os.path.join(run_cases.HERE, "test_p01.py"))
        skipping = set()
        for match in re.finditer(r"    def (test_\w+)\(self\):(.*?)(?=\n    def |\nclass |\Z)", source, re.S):
            if needle in match.group(2):
                skipping.add(match.group(1))
        self.assertEqual(skipping, set(run_cases.EXPORT_SKIPS))


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
