"""E06 committed-evidence consistency (toolchain/results/e06/rev-5b8d56966da5).

The directory holds a plan, the verified redacted records of the 24 central cargo checks, the audit report that folded
them in, and a RUN.md that states what they do and do not show. These tests make the four files agree with each other
and with the revision they name, and they keep personal data out: the raw RCH logs are deliberately not committed
because they carry a worker address and local paths.

Expected values here are written from the plan's structure (12 workspace crates x 2 targets), not read back from the
files under test.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
EVIDENCE = os.path.join(ROOT, "toolchain", "results", "e06", "rev-5b8d56966da5")
REV = "5b8d56966da5dc1050c074adf21fdb738ad4a408"
CRATES = ["franken-alloc-probe", "franken-baseline", "franken-board-profile", "franken-clock", "franken-control",
          "franken-dsp", "franken-hal", "franken-platform", "franken-session", "franken-speaker", "franken-stream",
          "franken-test-support"]
TARGETS = ["mips-unknown-linux-musl", "powerpc-unknown-linux-musl"]
RECORD_KEYS = {"cargo_seconds", "command", "crate", "errors", "evidence", "note", "profile", "raw_log_bytes",
               "raw_log_sha256", "rc", "remote_ms", "rev", "status", "target", "units", "warnings", "worker"}
# Independent of scripts/e06/checks.py::redact, on purpose: what must not be in a committed file.
LEAKS = re.compile(r"/Users/|/home/|/private/|/tmp/|jemanuel|claude-501|ubuntu|scratchpad|\b\d{1,3}(?:\.\d{1,3}){3}\b")


def read(name):
    with open(os.path.join(EVIDENCE, name), encoding="utf-8") as fh:
        return fh.read()


@unittest.skipUnless(os.path.isdir(EVIDENCE), "the committed E06 evidence directory is not present")
class CommittedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("ffw_e06_checks_for_evidence", os.path.join(ROOT, "scripts", "e06", "checks.py"))
        cls.CK = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.CK)
        cls.plan_lines = [ln for ln in read("plan.txt").splitlines() if ln.strip()]
        cls.records = [json.loads(ln) for ln in read("checks.jsonl").splitlines() if ln.strip()]
        cls.audit = json.loads(read("audit.json"))

    def test_the_plan_is_the_whole_denominator_and_every_line_has_the_agreed_shape(self):
        self.assertEqual(len(self.plan_lines), 24)
        expected = sorted((c, t) for t in TARGETS for c in CRATES)
        plan, problems = self.CK.parse_plan(self.plan_lines)
        self.assertEqual(problems, [])
        self.assertEqual(sorted((p["crate"], p["target"]) for p in plan), expected)
        for line in self.plan_lines:
            self.assertTrue(line.startswith("RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p "), line)
            self.assertTrue(line.endswith(" -Z build-std=std,panic_abort -j 2"), line)

    def test_every_record_is_a_verified_pass_for_exactly_the_planned_command(self):
        self.assertEqual(len(self.records), 24)
        by = {(r["crate"], r["target"]): r for r in self.records}
        self.assertEqual(len(by), 24, "a planned check appears twice")
        self.assertEqual(sorted(by), sorted((c, t) for t in TARGETS for c in CRATES))
        for key, r in by.items():
            self.assertEqual(set(r), RECORD_KEYS, key)
            self.assertEqual((r["status"], r["rc"], r["rev"], r["worker"], r["profile"]), ("pass", 0, REV, "ts1", "release"), key)
            self.assertEqual((r["warnings"], r["errors"]), (0, 0), key)
            self.assertIn(r["command"], self.plan_lines, key)
            self.assertRegex(r["raw_log_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(r["raw_log_sha256"], r["evidence"])
            self.assertIn("not committed", r["evidence"])
            self.assertGreater(r["raw_log_bytes"], 0)
            self.assertGreater(r["remote_ms"], 0)
        self.assertEqual(len({r["raw_log_sha256"] for r in self.records}), 24, "two checks share one log")

    def test_no_committed_file_carries_a_path_an_address_or_a_user_name(self):
        for name in ("plan.txt", "checks.jsonl", "audit.json", "RUN.md"):
            for number, line in enumerate(read(name).splitlines(), 1):
                self.assertIsNone(LEAKS.search(line), "%s:%d: %s" % (name, number, line[:120]))

    def test_the_audit_report_folded_exactly_these_records(self):
        rows = self.audit["build_checks"]["rows"]
        self.assertEqual(self.audit["build_checks"]["planned"], 24)
        self.assertEqual(self.audit["build_checks"]["counts"], {"pass": 24, "fail": 0, "not-run": 0, "conflicting": 0})
        self.assertEqual(self.audit["build_checks"]["rejected_results"], [])
        self.assertEqual(sorted(r["command"] for r in rows), sorted(self.plan_lines))
        by = {(r["crate"], r["target"]): r for r in self.records}
        for row in rows:
            record = by[(row["crate"], row["target"])]
            self.assertEqual((row["status"], row["evidence"], row["note"]), (record["status"], record["evidence"], record["note"]))

    def test_the_audit_ran_on_the_revision_the_checks_ran_on(self):
        lock = subprocess.run(["git", "-C", ROOT, "show", REV + ":Cargo.lock"], capture_output=True, timeout=60)
        if lock.returncode != 0:
            self.skipTest("revision %s is not in this repository" % REV[:12])
        import hashlib
        self.assertEqual(self.audit["lock"]["sha256"], hashlib.sha256(lock.stdout).hexdigest())

    def test_the_audit_reports_what_was_resolved_and_what_was_not_evaluated(self):
        self.assertEqual({k: v["outcome"] for k, v in self.audit["platforms"].items()},
                         {"host": "resolved", "mips": "resolved", "powerpc": "resolved"})
        self.assertEqual(self.audit["summary"]["counts"]["blocker"], 0)
        status = {c["name"]: c["status"] for c in self.audit["candidates"]}
        for name in ("asupersync", "franken_kernel", "libc candidates", "codecs"):
            self.assertEqual(status[name], "not in graph; unevaluated", name)
        # The Rust libc crate must not be mistaken for a libc candidate: on this revision it is the host's only.
        self.assertTrue(status["libc crate (Rust FFI binding table)"].startswith("present only on the reference platform"))

    def test_run_md_states_its_numbers_from_the_data_and_its_limits_plainly(self):
        text = read("RUN.md")
        counts = self.audit["summary"]["counts"]
        self.assertIn("%d blockers, %d review items, %d info" % (counts["blocker"], counts["review"], counts["info"]), text)
        self.assertIn(self.audit["lock"]["sha256"][:16], text)
        self.assertIn("%d entries" % self.audit["lock"]["entries"], text)
        total_s = round(sum(r["remote_ms"] for r in self.records) / 1000)
        self.assertIn("%d s in total" % total_s, text)
        self.assertIn(REV, text)
        for must in ("type-check", "does not show that\nanything links, runs or boots", "P01-BLK-002",
                     "YellowBrook did not run them", "raw logs are not committed", "sha256 and size"):
            self.assertIn(must, text, must)


UPSTREAM = os.path.join(ROOT, "toolchain", "results", "e06", "upstream")
ASUP = os.path.join(UPSTREAM, "asupersync-8940119023c0")
LIBC = os.path.join(UPSTREAM, "frankenlibc-76d7f3469f5f")
ASUP_REV = "8940119023c0e01b4d6d3e2c1399f41417c2ad24"
LIBC_REV = "76d7f3469f5f5251661b3662926d3d6a2b36d494"
ASUP_CONFIGS = ("default", "no-default-features", "runtime-core-only", "runtime-core-and-native-runtime", "franken-support-crates")


def jload(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return json.load(fh)


def finding_key(inv):
    return sorted((f["kind"], f["severity"], f["package"], f["detail"]) for f in inv["findings"])


def linked(inv, platform):
    return [p for p in inv["packages"] if p["platforms"][platform]["role"] in ("member", "linked")]


@unittest.skipUnless(os.path.isdir(UPSTREAM), "the committed upstream evidence is not present")
class UpstreamEvidenceTests(unittest.TestCase):
    """Third-party inventories at pinned revisions: the files agree with each other, with their README and with what the
    README claims, and carry no path, address or user name. Read-only evidence: the upstream repositories are not needed."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("ffw_e06_checks_upstream_ev", os.path.join(ROOT, "scripts", "e06", "checks.py"))
        cls.CK = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.CK)
        cls.asup = {c: jload(ASUP, c + ".inventory.json") for c in ASUP_CONFIGS}
        cls.libc = jload(LIBC, "runtime-crates.inventory.json")
        cls.consumers = jload(ASUP, "consumers.json")
        cls.edits = jload(LIBC, "export-edits.json")
        with open(os.path.join(UPSTREAM, "README.md"), encoding="utf-8") as fh:
            cls.readme = fh.read()

    def test_every_inventory_names_its_subject_and_the_exact_revision(self):
        for config, inv in self.asup.items():
            self.assertEqual(inv["schema"], "ffw.e06.inventory.v1", config)
            self.assertEqual(inv["subject"], {"name": "asupersync", "rev": ASUP_REV}, config)
            self.assertEqual(inv["lock"]["origin"], "repository", config)
            self.assertEqual(inv["policy_inputs"]["subject"], "upstream", config)
            self.assertEqual({k: v["outcome"] for k, v in inv["platforms"].items()}, {"host": "resolved", "mips": "resolved", "powerpc": "resolved"})
        self.assertEqual(self.libc["subject"], {"name": "frankenlibc", "rev": LIBC_REV})
        self.assertEqual(self.libc["lock"]["origin"], "generated-offline")

    def test_the_consumer_locks_keep_every_registry_pin_of_the_upstream_lock(self):
        self.assertEqual(self.consumers["upstream_rev"], ASUP_REV)
        self.assertEqual(sorted(self.consumers["configs"]), sorted(ASUP_CONFIGS))
        for config, rec in self.consumers["configs"].items():
            lock = rec["lock"]
            self.assertEqual(lock["not_in_upstream_lock"], [], "%s drifted from the upstream pins" % config)
            self.assertEqual(lock["also_in_upstream_lock_exactly"], lock["registry_packages_in_consumer_lock"], config)
            self.assertGreater(lock["registry_packages_in_consumer_lock"], 0)
            self.assertEqual(lock["upstream_lock_registry_packages"] > 0, True)
            self.assertEqual(lock["consumer_lock_sha256"], self.asup[config]["lock"]["sha256"], "%s: inventory is of another lock" % config)

    def test_the_four_asupersync_configurations_differ_only_where_cargo_says_they_do(self):
        default, bare, core, both = (self.asup[c] for c in ASUP_CONFIGS[:4])
        keys = lambda inv: {p["key"] for p in inv["packages"]}
        self.assertEqual(sorted(keys(default) - keys(bare)), ["asupersync-macros@0.6.0"])     # proc-macros, and nothing else
        self.assertEqual(keys(bare) - keys(default), set())
        for other in (core, both):
            self.assertEqual(keys(other), keys(bare))
            self.assertEqual(finding_key(other), finding_key(bare))
        # what cargo enabled really differs, so the selection was applied and the sameness is not an artefact
        enabled = lambda inv: next(p for p in inv["packages"] if p["name"] == "asupersync")["platforms"]["mips"]["features"]
        self.assertEqual(enabled(bare), [])
        self.assertEqual(enabled(core), ["runtime-core"])
        self.assertEqual(enabled(both), ["native-runtime", "runtime-core"])
        self.assertEqual(sorted(enabled(default)), ["default", "native-runtime", "nightly-outcome-try", "proc-macros", "runtime-core"])

    def test_runtime_core_and_native_runtime_are_empty_markers_in_cargo_toml(self):
        declared = next(p for p in self.asup["default"]["packages"] if p["name"] == "asupersync")["declared_features"]
        self.assertEqual((declared["runtime-core"], declared["native-runtime"]), ([], []))
        self.assertEqual(declared["proc-macros"], ["dep:asupersync-macros"])

    def test_the_bare_asupersync_closure_and_its_unsafe_match_what_the_readme_states(self):
        bare = self.asup["no-default-features"]
        for platform in ("mips", "powerpc"):
            members = linked(bare, platform)
            deps = [p for p in members if p["source_kind"] != "workspace"]
            self.assertEqual(len(members), 115, platform)
            self.assertEqual(sum(1 for p in members if p["source_kind"] == "registry"), 110, platform)
            self.assertEqual(sum(1 for p in deps if p["unsafe_tokens"]), 76, platform)
            self.assertEqual(sum(p["unsafe_tokens"] for p in deps), 15548, platform)
        self.assertEqual(next(p for p in bare["packages"] if p["name"] == "asupersync")["unsafe_tokens"], 562)
        self.assertEqual([p["key"] for p in bare["packages"] if p["links"]], [])           # no native `links` key anywhere
        for text in ("145 packages", "115 linked packages", "113 dependencies", "76 of the linked dependencies", "15,548", "562",
                     "431 source files", "3,197 mentions", "no_std`, 56 `std`, 2 undecided"):
            self.assertIn(text, self.readme, text)

    def test_franken_kernel_is_no_std_but_effectively_std_because_of_serde(self):
        fk = next(p for p in self.asup["franken-support-crates"]["packages"] if p["name"] == "franken-kernel")
        self.assertEqual((fk["platforms"]["mips"]["std"], fk["platforms"]["mips"]["effective_std"]), ("no_std", "std"))
        self.assertTrue(fk["references_alloc"])                                              # no_std is not no allocation
        serde = next(p for p in self.asup["franken-support-crates"]["packages"] if p["name"] == "serde")
        self.assertIn("std", serde["platforms"]["mips"]["features"])
        for name in ("franken-kernel", "franken-evidence", "franken-decision"):
            crate = next(p for p in self.asup["franken-support-crates"]["packages"] if p["name"] == name)
            self.assertEqual(crate["unsafe_tokens"], 0, name)
            self.assertTrue(any(d.startswith("forbid") for d in crate["unsafe_declared"]), name)
            self.assertEqual(crate["license"], "LicenseRef-MIT-OpenAI-Anthropic-Rider", name)
        self.assertIn("effective mode is `std`", self.readme)

    def test_the_frankenlibc_lock_is_the_committed_generated_file_and_is_reported_as_not_a_pin(self):
        import hashlib
        with open(os.path.join(LIBC, "Cargo.lock.generated"), "rb") as fh:
            data = fh.read()
        self.assertEqual(self.libc["lock"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.libc["lock"]["entries"], data.decode().count("\n[[package]]") + data.decode().startswith("[[package]]"))
        kinds = [(f["kind"], f["severity"]) for f in self.libc["findings"]]
        self.assertIn(("lock-generated-not-an-upstream-pin", "review"), kinds)
        self.assertIn("not an upstream pin", self.readme.replace("*", ""))
        abi = next(p for p in self.libc["packages"] if p["name"] == "frankenlibc-abi")
        self.assertEqual((abi["unsafe_tokens"], abi["unsafe_declared"]), (23858, []))
        self.assertEqual(self.libc["policy_inputs"]["scope_crates"], ["frankenlibc-abi", "frankenlibc-core", "frankenlibc-membrane"])
        self.assertEqual((len(linked(self.libc, "mips")), len(linked(self.libc, "powerpc"))), (28, 28))
        self.assertIn("23,858", self.readme)

    def test_the_recorded_export_edits_are_exactly_the_two_the_readme_describes(self):
        edits = self.edits["edits"]
        self.assertEqual([e["file"] for e in edits], ["Cargo.toml", "crates/frankenlibc-membrane/Cargo.toml"])
        self.assertEqual(len(edits[1]["removed_lines"]), 7)
        self.assertTrue(all(l.startswith(("asupersync-conformance", "ftui-")) for l in edits[1]["removed_lines"]))
        for e in edits:
            self.assertNotEqual(e["sha256_before"], e["sha256_after"])
        self.assertIn("never to the upstream repository", self.edits["note"])
        with open(os.path.join(LIBC, "unreduced-attempt.txt"), encoding="utf-8") as fh:
            attempt = fh.read()
        self.assertIn("exit status 1", attempt)
        self.assertIn("resolver-failed", attempt)

    def test_the_proposed_check_lines_are_well_formed_and_cover_what_the_readme_lists(self):
        expected = {
            os.path.join(ASUP, "plan-default.txt"): (2, "-p asupersync --target"),
            os.path.join(ASUP, "plan-no-default-features.txt"): (2, "-p asupersync --no-default-features --target"),
            os.path.join(ASUP, "plan-runtime-core-only.txt"): (2, "-p asupersync --no-default-features --features runtime-core --target"),
            os.path.join(ASUP, "plan-runtime-core-and-native-runtime.txt"): (2, "-p asupersync --no-default-features --features runtime-core,native-runtime --target"),
            os.path.join(ASUP, "plan-franken-support-crates.txt"): (6, "--target"),
            os.path.join(LIBC, "plan-runtime-crates.txt"): (6, "--target"),
        }
        for path, (count, fragment) in expected.items():
            with open(path, encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            plan, problems = self.CK.parse_plan(lines)
            self.assertEqual((problems, len(plan)), ([], count), path)
            self.assertTrue(all(fragment in ln and ln.endswith(" -Z build-std=std,panic_abort -j 2") for ln in lines), path)
            self.assertEqual({p["target"] for p in plan}, {"mips-unknown-linux-musl", "powerpc-unknown-linux-musl"}, path)
        self.assertEqual({p["crate"] for p in self.CK.parse_plan(open(os.path.join(LIBC, "plan-runtime-crates.txt")).read().splitlines())[0]},
                         {"frankenlibc-core", "frankenlibc-abi", "frankenlibc-membrane"})

    def test_the_contract_states_the_same_upstream_numbers_as_the_inventories(self):
        with open(os.path.join(ROOT, "docs", "contracts", "e06.md"), encoding="utf-8") as fh:
            contract = fh.read()
        bare = self.asup["no-default-features"]
        members = linked(bare, "mips")
        for text in ("145 packages", "115 linked on each big-endian target", "113 dependencies", ASUP_REV[:12], LIBC_REV[:12],
                     "not an upstream pin", "`runtime-core = []` and `native-runtime = []`", "toolchain/results/e06/upstream/"):
            self.assertIn(text, contract, text)
        self.assertEqual((len(bare["packages"]), len(members), len(members) - 2), (145, 115, 113))
        # S02 needs E06's codec inventory and E06 needs S02's selection: the contract records that cycle and how it was resolved (named candidates)
        self.assertIn("That looked like a dependency cycle", contract)
        self.assertIn("toolchain/results/e06/codecs/", contract)

    def test_no_upstream_evidence_file_carries_a_path_an_address_or_a_user_name(self):
        checked = 0
        for folder in (UPSTREAM, ASUP, LIBC):
            for name in sorted(os.listdir(folder)):
                path = os.path.join(folder, name)
                if not os.path.isfile(path):
                    continue
                checked += 1
                with open(path, encoding="utf-8") as fh:
                    for number, line in enumerate(fh, 1):
                        self.assertIsNone(LEAKS.search(line), "%s:%d: %s" % (os.path.relpath(path, ROOT), number, line[:120]))
        self.assertGreater(checked, 15)

    def test_the_readme_names_both_revisions_in_full_and_states_what_is_not_established(self):
        for rev in (ASUP_REV, LIBC_REV):
            self.assertIn(rev, self.readme)
        for must in ("read-only and offline", "never wrote to them", "is not an inventory of one configuration", "Not established",
                     "`runtime-core` is a marker", "nothing here was run"):
            self.assertIn(must.lower(), self.readme.lower(), must)


if __name__ == "__main__":
    unittest.main()
