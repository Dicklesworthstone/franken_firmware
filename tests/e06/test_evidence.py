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
        lock = subprocess.run(["git", "-C", ROOT, "show", REV + ":Cargo.lock"], capture_output=True)
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


if __name__ == "__main__":
    unittest.main()
