#!/usr/bin/env python3
"""E05 evidence, input-validation, CLI and hygiene cases.

Fixtures carry only semantics of how a boot chain consumes a hook, each fact observed (with a source)
or unknown (with a named blocker).  Case IDs are the docstring prefixes.
"""
import ast
import copy
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402

bm, tc = c.bm, c.tc


def ast_imports(path):
    names = set()
    for node in ast.walk(ast.parse(c.read(path))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names
BENIGN = c.profile("synthetic-benign")
R5723 = c.profile("57.23")
CONTRACT = os.path.join(c.ROOT, "docs", "contracts", "e05.md")


class Fixtures(unittest.TestCase):
    def test_57_23_is_six_observed_and_five_unknown(self):
        """E05-EVID-5723: the extracted S1-line profile has exactly the hand-listed observed and unknown facts, each unknown with its own blocker."""
        observed = {f for f, v in R5723["facts"].items() if v["status"] == "observed"}
        self.assertEqual(observed, {"hook_gate_existence_only", "hook_interpreted", "hook_runs_synchronously",
                                    "jffs_noexec", "watchdog_restarts_daemon", "hook_survives_update"})
        unknown = {f: v["blocker"] for f, v in R5723["facts"].items() if v["status"] == "unknown"}
        self.assertEqual(unknown, {"hook_failure_nonfatal": "EXT-E05-RCS", "stock_stop_effective": "EXT-E05-STOP",
                                   "watchdog_covers_boot_stall": "EXT-E05-WDOG", "fs_rename_atomic": "EXT-E05-FS",
                                   "update_interrupted_preserves_hook": "EXT-E05-UPDATE"})
        for fid in observed:
            self.assertIn("sibling research", R5723["facts"][fid]["source"], fid)
            self.assertTrue(R5723["facts"][fid]["value"], fid)

    def test_86_10_has_no_hook_evidence(self):
        """E05-EVID-S2: every 86.10 fact is unknown with blocker EXT-E05-S2; nothing about the second generation is invented."""
        p = c.profile("86.10")
        self.assertEqual({v["status"] for v in p["facts"].values()}, {"unknown"})
        self.assertEqual({v["blocker"] for v in p["facts"].values()}, {"EXT-E05-S2"})

    def test_synthetic_profile_is_labelled_and_extracted_ones_are_not_synthetic(self):
        """E05-EVID-SYNTHETIC: the benign profile is kind synthetic with every fact observed-true and a source saying so; the real ones are kind extracted."""
        self.assertEqual(BENIGN["kind"], "synthetic")
        for v in BENIGN["facts"].values():
            self.assertEqual((v["status"], v["value"]), ("observed", True))
            self.assertIn("synthetic", v["source"])
        self.assertEqual((R5723["kind"], c.profile("86.10")["kind"]), ("extracted", "extracted"))

    def test_facts_are_exactly_the_eleven_named(self):
        """E05-EVID-FACTS: the model's fact list is the eleven documented facts, in every profile."""
        self.assertEqual(len(bm.FACT_IDS), 11)
        for name in c.PROFILE_NAMES:
            self.assertEqual(set(c.profile(name)["facts"]), set(bm.FACT_IDS), name)


class Validation(unittest.TestCase):
    def doc(self):
        return copy.deepcopy(BENIGN)

    def test_good_profile_validates(self):
        """E05-VALID-OK: the committed profiles all validate."""
        for name in c.PROFILE_NAMES:
            bm.validate_profile(c.profile(name))

    def test_malformed_profiles_are_refused(self):
        """E05-VALID-BAD: each structural defect is a ModelError, never a verdict."""
        def mutate(fn):
            d = self.doc()
            fn(d)
            return d
        bad = {
            "schema": mutate(lambda d: d.update(schema="x")),
            "extra top-level key": mutate(lambda d: d.update(extra=1)),
            "kind": mutate(lambda d: d.update(kind="real")),
            "empty image": mutate(lambda d: d.update(image="")),
            "missing fact": mutate(lambda d: d["facts"].pop("jffs_noexec")),
            "extra fact": mutate(lambda d: d["facts"].update(bogus={"status": "unknown", "blocker": "EXT-E05-X"})),
            "no source": mutate(lambda d: d["facts"]["jffs_noexec"].update(source="  ")),
            "non-bool value": mutate(lambda d: d["facts"]["jffs_noexec"].update(value="yes")),
            "observed with blocker": mutate(lambda d: d["facts"]["jffs_noexec"].update(blocker="EXT-E05-X")),
            "bad status": mutate(lambda d: d["facts"]["jffs_noexec"].update(status="maybe")),
            "unknown without blocker": mutate(lambda d: d["facts"].update(jffs_noexec={"status": "unknown"})),
            "bad blocker id": mutate(lambda d: d["facts"].update(jffs_noexec={"status": "unknown", "blocker": "later"})),
            "unknown with value": mutate(lambda d: d["facts"].update(jffs_noexec={"status": "unknown", "blocker": "EXT-E05-X", "value": True})),
            "not an object": [],
        }
        for label, doc in bad.items():
            with self.subTest(defect=label):
                with self.assertRaises(bm.ModelError):
                    bm.validate_profile(doc)

    def test_overrides(self):
        """E05-VALID-OVERRIDE: with_facts accepts booleans and 'unknown', refuses anything else, and leaves the original untouched."""
        before = json.dumps(BENIGN, sort_keys=True)
        p = bm.with_facts(BENIGN, {"jffs_noexec": False, "fs_rename_atomic": "unknown"})
        self.assertEqual(p["facts"]["jffs_noexec"]["value"], False)
        self.assertEqual(p["facts"]["fs_rename_atomic"], {"status": "unknown", "blocker": "EXT-E05-OVERRIDE"})
        self.assertEqual(json.dumps(BENIGN, sort_keys=True), before)
        for bad in ({"nope": True}, {"jffs_noexec": 1}, {"jffs_noexec": "no"}):
            with self.assertRaises(bm.ModelError):
                bm.with_facts(BENIGN, bad)

    def test_policy_and_fault_parsing(self):
        """E05-VALID-ARGS: policies and faults are parsed strictly; a power_loss without a step is refused."""
        pol = bm.policy_from_pairs(["attempt_cap=none", "backoff=false", "unmute=at_ready", "binary_location=jffs"])
        self.assertEqual((pol.attempt_cap, pol.backoff, pol.unmute, pol.binary_location), (None, False, "at_ready", "jffs"))
        for bad in (["nokey=1"], ["backoff=maybe"], ["attempt_cap=0"], ["attempt_cap=x"], ["unmute=never"],
                    ["binary_location=cloud"], ["backoff"]):
            with self.subTest(policy=bad):
                with self.assertRaises(bm.ModelError):
                    bm.policy_from_pairs(bad)
        for bad in (["power_loss"], ["power_loss@nowhere"], ["gremlins"], ["hook_missing@preflight"]):
            with self.subTest(fault=bad):
                with self.assertRaises(bm.ModelError):
                    bm.simulate(BENIGN, bm.Policy(), bad)
        ok = bm.simulate(BENIGN, bm.Policy(), ["hook_missing@hook_gate", "power_loss@jffs_mount"])
        self.assertEqual(ok["verdict"]["reason"], "hook_absent")
        with self.assertRaises(bm.ModelError):
            bm.simulate(BENIGN, bm.Policy(), provision="rename", update="none")
        with self.assertRaises(bm.ModelError):
            bm.simulate(BENIGN, bm.Policy(atomic_write=False), provision="rename")      # not a step of the in-place discipline
        with self.assertRaises(bm.ModelError):
            bm.simulate(BENIGN, bm.Policy(), max_boots=0)


class Cli(unittest.TestCase):
    P = os.path.join(c.PROFILES, "%s.json")

    def lines(self, out):
        return [json.loads(x) for x in out.splitlines()]

    def test_trace_ok_exit_zero(self):
        """E05-CLI-OK: a clean benign boot exits 0; output is JSONL with strictly increasing event numbers and a final verdict line."""
        rc, out, err = c.run_cli(["trace", "--profile", self.P % "synthetic-benign"])
        self.assertEqual((rc, err), (0, ""))
        recs = self.lines(out)
        events, final = recs[:-1], recs[-1]
        self.assertEqual([e["n"] for e in events], list(range(len(events))))
        self.assertEqual((final["verdict"]["kind"], final["violations"]), ("CUSTOM_OK", []))

    def test_unqualified_exit_three_names_blockers(self):
        """E05-CLI-UNQUALIFIED: the real image's clean boot exits 3 (never 0) and names the unknown fact and blocker."""
        rc, out, _ = c.run_cli(["trace", "--profile", self.P % "57.23"])
        self.assertEqual(rc, 3)
        v = self.lines(out)[-1]["verdict"]
        self.assertEqual((v["kind"], v["facts"], v["blockers"]), ("UNQUALIFIED", ["stock_stop_effective"], ["EXT-E05-STOP"]))

    def test_failed_and_violations_exit_one(self):
        """E05-CLI-FAILED: a planted in-place write exits 1 with the violation listed."""
        rc, out, _ = c.run_cli(["trace", "--profile", self.P % "synthetic-benign", "--policy", "atomic_write=false",
                                "--provision", "write"])
        self.assertEqual(rc, 1)
        final = self.lines(out)[-1]
        self.assertEqual(final["verdict"]["reason"], "partial_hook_executed")
        self.assertEqual([v["kind"] for v in final["violations"]], ["partial_hook_executed"])

    def test_scenario_flags_reach_the_model(self):
        """E05-CLI-FLAGS: --fault, --policy, --update and --prior change the result exactly as the model API does."""
        rc, out, _ = c.run_cli(["trace", "--profile", self.P % "synthetic-benign", "--fault", "power_loss@hook_run",
                                "--fault", "binary_missing"])
        final = self.lines(out)[-1]
        self.assertEqual((rc, final["verdict"]["reason"], final["boots"]), (0, "binary_missing", 2))
        rc, out, _ = c.run_cli(["trace", "--profile", self.P % "synthetic-benign", "--update", "none", "--prior", "absent"])
        self.assertEqual(self.lines(out)[-1]["verdict"]["reason"], "hook_absent")

    def test_bad_input_exits_two_without_a_verdict(self):
        """E05-CLI-USAGE: usage errors, a missing or malformed profile, bad faults and bad policies all exit 2 with a message and no verdict."""
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as fh:
                fh.write('{"schema": "nope"}')
            garbage = os.path.join(d, "garbage.json")
            with open(garbage, "w") as fh:
                fh.write("{not json")
            good = self.P % "synthetic-benign"
            for args in ([], ["trace"], ["trace", "--profile", os.path.join(d, "absent.json")],
                         ["trace", "--profile", bad], ["trace", "--profile", garbage],
                         ["trace", "--profile", good, "--fault", "gremlins"],
                         ["trace", "--profile", good, "--fault", "power_loss"],
                         ["trace", "--profile", good, "--policy", "nokey=1"],
                         ["trace", "--profile", good, "--provision", "rename", "--update", "none"],
                         ["trace", "--profile", good, "--prior", "maybe"],
                         ["matrix", "--profile", good, "--cases", os.path.join(d, "none.json")],
                         ["bogus"]):
                with self.subTest(args=args[:3]):
                    rc, out, err = c.run_cli(args, cwd=d)
                    self.assertEqual(rc, 2, (out, err))
                    self.assertNotIn('"verdict"', out)

    def test_matrix_benign_and_real(self):
        """E05-CLI-MATRIX: the matrix command reproduces the hand-written totals: benign 19/13/2 exit 0; 57.23 5/2/27 exit 3 with blockers 19/2/1/4/1; 86.10 34 unqualified."""
        rc, out, _ = c.run_cli(["matrix", "--profile", self.P % "synthetic-benign"])
        m = json.loads(out)
        self.assertEqual((rc, m["cells"], m["mismatches"], m["counts"]), (0, 34, 0, {"CUSTOM_OK": 19, "STOCK_OK": 13, "FAILED": 2}))
        rc, out, _ = c.run_cli(["matrix", "--profile", self.P % "57.23"])
        m = json.loads(out)
        self.assertEqual((rc, m["mismatches"], m["counts"]), (3, 0, {"STOCK_OK": 5, "FAILED": 2, "UNQUALIFIED": 27}))
        self.assertEqual(m["blocked_by"], {"EXT-E05-FS": 4, "EXT-E05-RCS": 2, "EXT-E05-STOP": 19,
                                           "EXT-E05-UPDATE": 1, "EXT-E05-WDOG": 1})
        rc, out, _ = c.run_cli(["matrix", "--profile", self.P % "86.10"])
        m = json.loads(out)
        self.assertEqual((rc, m["counts"], m["blocked_by"]), (3, {"UNQUALIFIED": 34}, {"EXT-E05-S2": 34}))

    def test_matrix_is_not_a_rubber_stamp(self):
        """E05-CLI-MATRIX-MISMATCH: a cases file with one wrong expectation makes matrix exit 1 and name the cell."""
        doc = c.cases()
        doc["cells"][0]["expect"]["synthetic-benign"]["verdict"] = "STOCK_OK"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cases.json")
            with open(p, "w") as fh:
                json.dump(doc, fh)
            rc, out, _ = c.run_cli(["matrix", "--profile", self.P % "synthetic-benign", "--cases", p], cwd=d)
        m = json.loads(out)
        self.assertEqual((rc, m["mismatches"]), (1, 1))
        self.assertEqual([r["cell"] for r in m["rows"] if r["as_expected"] is False], ["E05-CELL-01"])

    def test_cli_writes_nothing_and_needs_no_repo_cwd(self):
        """E05-CLI-NO-WRITES: run from an empty directory outside the repo, the CLI leaves that directory empty (stdout only)."""
        with tempfile.TemporaryDirectory() as d:
            for args in (["trace", "--profile", self.P % "57.23"], ["matrix", "--profile", self.P % "57.23"]):
                c.run_cli(args, cwd=d)
            self.assertEqual(os.listdir(d), [])


class Hygiene(unittest.TestCase):
    def files(self, with_contract=True):
        out = []
        for base in (c.SCRIPTS, c.HERE):
            for dirpath, dirs, names in os.walk(base):
                dirs[:] = [x for x in dirs if x != "__pycache__"]
                out += [os.path.join(dirpath, n) for n in names if n.endswith((".py", ".json"))]
        for extra in (os.path.join(c.ROOT, "scripts", "e2e", "e05"), os.path.join(c.ROOT, "scripts", "test", "e05.suite.json")):
            if os.path.exists(extra):
                out.append(extra)
        if with_contract and os.path.exists(CONTRACT):
            out.append(CONTRACT)
        return sorted(set(out))

    def test_no_private_identifiers(self):
        """E05-HYGIENE-PRIVATE: no IPv4 address, MAC address or long hex run (serial/hash) in any committed E05 file."""
        patterns = {"ipv4": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
                    "mac": re.compile(r"\b[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}\b"),
                    "hex": re.compile(r"\b[0-9a-fA-F]{16,}\b")}
        files = self.files()
        self.assertGreater(len(files), 8)
        for path in files:
            text = c.read(path)
            for label, rx in patterns.items():
                self.assertIsNone(rx.search(text), "%s in %s" % (label, os.path.relpath(path, c.ROOT)))

    def test_no_write_primitives_or_access_routes(self):
        """E05-HYGIENE-SCOPE: fixtures and code carry no write-primitive, feed or access-route vocabulary; E05 models consumption of a hook only."""
        banned = re.compile(r"telnet|dropbear|devmode|exploit|shellcode|payload|forg(e|ed|ery)|SetString|unlocked_build|getaa",
                            re.IGNORECASE)
        for path in self.files(with_contract=False):
            if os.path.basename(path) == "test_evidence.py":
                continue      # this file names the banned words
            self.assertIsNone(banned.search(c.read(path)), os.path.relpath(path, c.ROOT))

    def test_model_is_offline_and_read_only(self):
        """E05-OFFLINE-STATIC: the model and checker import no network or process module and every open() is a literal read-only call."""
        banned_modules = {"socket", "urllib", "http", "ssl", "ftplib", "smtplib", "subprocess", "requests", "asyncio", "shutil"}
        for name in ("boot_model.py", "trace_check.py"):
            tree = ast.parse(c.read(os.path.join(c.SCRIPTS, name)))
            imported = set()
            opens = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
                elif isinstance(node, ast.Call):
                    fn = node.func
                    called = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                    if called == "open":
                        opens += 1
                        mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                        self.assertIsInstance(mode, ast.Constant, "%s: open() mode must be a literal" % name)
                        self.assertEqual(mode.value, "r", "%s: open() must be read-only" % name)
                    if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id in ("os", "shutil", "pathlib"):
                        self.assertNotIn(called, ("system", "popen", "remove", "unlink", "rmdir", "rename", "replace",
                                                  "mkdir", "makedirs", "write", "chmod", "symlink", "link"), name)
            self.assertEqual(imported & banned_modules, set(), name)
            self.assertEqual(opens, 2 if name == "boot_model.py" else 0, name)       # the two profile/cases readers
        self.assertNotIn("boot_model", ast_imports(os.path.join(c.SCRIPTS, "trace_check.py")))


class ContractSync(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(CONTRACT), "docs/contracts/e05.md is required by the bead")
        self.text = c.read(CONTRACT)

    def test_contract_documents_facts_blockers_and_rules(self):
        """E05-DOC-SYNC: the contract names every fact, every blocker in the profiles, every invariant, every checker rule and every fault."""
        for fid in bm.FACT_IDS:
            self.assertIn(fid, self.text, fid)
        blockers = {v["blocker"] for n in c.PROFILE_NAMES for v in c.profile(n)["facts"].values() if v["status"] == "unknown"}
        for b in blockers:
            self.assertIn(b, self.text, b)
        for inv in ("INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6", "PRED"):
            self.assertIn(inv, self.text, inv)
        kinds = set(re.findall(r'_v\("([a-z_]+)"', c.read(os.path.join(c.SCRIPTS, "trace_check.py"))))
        self.assertEqual(len(kinds), 13)
        for k in kinds:
            self.assertIn(k, self.text, k)
        for step, faults in bm.FAULT_TABLE.items():
            self.assertIn(step, self.text, step)
            for f in faults:
                self.assertIn(f, self.text, f)
        for sub in sum(bm.PROVISION_SUBS.values(), ()):
            self.assertIn(sub, self.text, sub)

    def test_contract_names_the_unknowns_it_will_not_invent(self):
        """E05-DOC-UNKNOWNS: stop-marker semantics and second-generation hook semantics are stated as unknown, with the blocker ids."""
        self.assertIn("stop marker", self.text.lower().replace("-", " "))
        self.assertIn("EXT-E05-S2", self.text)
        self.assertIn("EXT-E05-STOP", self.text)


if __name__ == "__main__":
    unittest.main()
