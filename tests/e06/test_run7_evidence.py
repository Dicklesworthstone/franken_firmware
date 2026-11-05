"""E06 run7 committed-evidence consistency (toolchain/results/e06/rev-08d5a00266d4).

The directory holds the supervisor's whole-batch record of run7 (50 lines under one manifest), the rows the judge wrote for `audit.py ingest`, the verified
record `ingest` wrote, the judge's printed table and the manifest the record binds. These tests make the five files agree with each other, with the pinned
hashes the supervisor reported, and with docs/contracts/e06.md, and they keep personal data out: the raw RCH logs are deliberately not committed because they
carry a worker address and local paths.

Expected values are written from the batch's structure (15 workspace crates x 2 targets, the Asupersync and FrankenLibC lines, the eight failures the manifest
predicted), not read back from the files under test.  The checker is `problems()`: the real directory must give [], and each planted corruption of a COPY must
give exactly the problem it plants.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
EVIDENCE = os.path.join(ROOT, "toolchain", "results", "e06", "rev-08d5a00266d4")
DOC = os.path.join(ROOT, "docs", "contracts", "e06.md")
REV = "08d5a00266d4d7634e7374dc04402709151940e6"
PINS = {  # sha256 of each committed file, as the supervisor reported them (mail 5044)
    "record-run7.json": "77efea56cb309637aadb49e285c1bd7b9d15417d64a4f130e8fac48c0ab079cb",
    "rows-run7.jsonl": "78ab26ca495b8b875b8c680646122e5d058c84ce2f01de3d45a7af391db8e431",
    "ingest-run7.json": "5bff27610a3ddedb25a3a143f13c5af2635269cbcd2150b8087e620519ce0fb6",
    "judge-run7.out": "54cc42afa092030e96d360989e90f2a9e8196ab2611c065e06d50c10f0130058",
    "manifest.json": "8e05960021aa555171a84e5131a845dc3619eaed65a3ab02138eb00a46f1fbf2",
}
CRATES = ["franken-alloc-probe", "franken-atomic", "franken-baseline", "franken-board-profile", "franken-clock", "franken-control", "franken-dsp", "franken-hal",
          "franken-journal", "franken-platform", "franken-platform-linux", "franken-session", "franken-speaker", "franken-stream", "franken-test-support"]
TARGETS = ["mips", "powerpc"]
TRIPLE = {"mips": "mips-unknown-linux-musl", "powerpc": "powerpc-unknown-linux-musl"}
WORKSPACE_IDS = {"workspace.%s.%s" % (c, t) for c in CRATES for t in TARGETS}
UPSTREAM_PASS_IDS = ({"asupersync.%s.asupersync.%s" % (cfg, t) for cfg in ("no-default-features", "runtime-core-only", "runtime-core-and-native-runtime") for t in TARGETS}
                     | {"asupersync.franken-support-crates.%s.%s" % (c, t) for c in ("franken-decision", "franken-evidence", "franken-kernel") for t in TARGETS})
FAIL_IDS = ({"asupersync.default.asupersync.%s" % t for t in TARGETS}
            | {"frankenlibc.runtime-crates.%s.%s" % (c, t) for c in ("frankenlibc-abi", "frankenlibc-core", "frankenlibc-membrane") for t in TARGETS})
ALL_IDS = WORKSPACE_IDS | UPSTREAM_PASS_IDS | FAIL_IDS
# Independent of scripts/e06/checks.py::redact, on purpose: what must not be in a committed file.
LEAKS = re.compile(r"/Users/|/home/|/private/|/tmp/|jemanuel|claude-501|ubuntu|scratchpad|\b\d{1,3}(?:\.\d{1,3}){3}\b")
JUDGE_ROW = re.compile(r"^\s+(\S+)\s+(pass|fail)\s+expected (pass|fail)\s+(as-predicted|unexpected-\S+|not-a-result)\b")


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def load_lines(path):
    return [json.loads(ln) for ln in read_text(path).splitlines() if ln.strip()]


def problems(directory, check_pins=True):
    """Everything wrong with the run7 evidence in `directory`, as short strings; [] means consistent."""
    out = []
    p = lambda name: os.path.join(directory, name)
    for name in PINS:
        if not os.path.isfile(p(name)):
            return ["missing file %s" % name]
    if check_pins:
        out += ["pinned hash differs: %s" % name for name in PINS if sha(p(name)) != PINS[name]]
    texts = {name: read_text(p(name)) for name in PINS}
    out += ["leak in %s: %s" % (name, m.group(0)) for name, t in texts.items() for m in [LEAKS.search(t)] if m]
    rec = json.loads(texts["record-run7.json"])
    lines = rec.get("lines", [])
    if rec.get("schema") != "ffw.e06.batch-record.v1" or rec.get("exit") != 0:
        out.append("record schema or exit: %r %r" % (rec.get("schema"), rec.get("exit")))
    if rec.get("workspace_rev") != REV:
        out.append("record workspace_rev is %r" % rec.get("workspace_rev"))
    if rec.get("manifest_sha256") != sha(p("manifest.json")):
        out.append("record manifest_sha256 is not the sha256 of manifest.json")
    ids = [l.get("id") for l in lines]
    if len(ids) != 50 or set(ids) != ALL_IDS:
        out.append("record ids: %d lines, missing %s, extra %s" % (len(ids), sorted(ALL_IDS - set(ids))[:3], sorted(set(ids) - ALL_IDS)[:3]))
    bad = [l["id"] for l in lines if l.get("verdict") != "as-predicted" or l.get("expected") != l.get("observed") or l.get("worker") != "trj"]
    if bad:
        out.append("record lines not as-predicted on trj: %s" % bad[:3])
    if {l["id"] for l in lines if l.get("expected") == "fail"} != FAIL_IDS:
        out.append("record: the predicted-failure set is not the eight named lines")
    if {l["id"] for l in lines if l.get("observed") == "fail"} != FAIL_IDS:
        out.append("record: the observed-failure set is not the eight named lines")
    # the judge's printed table agrees with the record, line by line
    table = {m.group(1): m.groups()[1:] for ln in texts["judge-run7.out"].splitlines() for m in [JUDGE_ROW.match(ln)] if m}
    for l in lines:
        if table.get(l.get("id")) != (l.get("observed"), l.get("expected"), l.get("verdict")):
            out.append("judge table disagrees with the record for %s" % l.get("id"))
            break
    if "as-predicted=50" not in texts["judge-run7.out"] or not texts["judge-run7.out"].rstrip().splitlines()[-1].startswith("EXIT 0:"):
        out.append("judge output is not 50 as-predicted with EXIT 0")
    # rows: one per workspace crate and target, all pass, on the closing revision
    rows = load_lines(p("rows-run7.jsonl"))
    want = {(c, TRIPLE[t]) for c in CRATES for t in TARGETS}
    if len(rows) != 30 or {(r.get("crate"), r.get("target")) for r in rows} != want or {r.get("status") for r in rows} != {"pass"}:
        out.append("rows: not 30 passing rows for 15 crates x 2 targets")
    rev_by_target = {"mips": "mips-unknown-linux-musl", "powerpc": "powerpc-unknown-linux-musl"}
    for r in rows:
        t = [k for k, v in rev_by_target.items() if v == r.get("target")]
        if not t or r.get("evidence") != "workspace.%s.%s.log" % (r.get("crate"), t[0]) or REV not in r.get("note", "") or "worker=trj" not in r.get("note", ""):
            out.append("rows: bad evidence name or note for %s" % r.get("crate"))
            break
    # ingest: the verified records, bound to the same raw logs as the record
    ing = load_lines(p("ingest-run7.json"))
    log_of_line = {l["id"]: l.get("log_sha256") for l in lines}
    if len(ing) != 30 or {r.get("status") for r in ing} != {"pass"} or {r.get("rc") for r in ing} != {0} or sum(r.get("errors", 0) for r in ing) or {r.get("rev") for r in ing} != {REV}:
        out.append("ingest: not 30 passing, error-free records at the closing revision")
    inv = {v: k for k, v in rev_by_target.items()}
    for r in ing:
        lid = "workspace.%s.%s" % (r.get("crate"), inv.get(r.get("target")))
        if log_of_line.get(lid) != r.get("raw_log_sha256") or not r.get("raw_log_sha256"):
            out.append("ingest raw_log_sha256 differs from the record's log_sha256 for %s" % lid)
            break
    return out


@unittest.skipUnless(os.path.isdir(EVIDENCE), "the committed E06 run7 evidence directory is not present")
class Run7EvidenceTests(unittest.TestCase):
    def test_the_committed_evidence_is_consistent(self):
        self.assertEqual(problems(EVIDENCE), [])

    def test_the_directory_holds_exactly_the_five_files(self):
        self.assertEqual(sorted(os.listdir(EVIDENCE)), sorted(PINS))

    def test_the_two_warning_checks_are_the_speaker_on_both_targets(self):
        warned = sorted((r["crate"], r["target"].split("-")[0], r["warnings"]) for r in load_lines(os.path.join(EVIDENCE, "ingest-run7.json")) if r["warnings"])
        self.assertEqual(warned, [("franken-speaker", "mips", 3), ("franken-speaker", "powerpc", 3)])

    def test_the_contract_states_what_the_files_say(self):
        doc = read_text(DOC)
        self.assertIn("### What run7 observed: the whole batch under one manifest", doc)
        self.assertIn("toolchain/results/e06/rev-08d5a00266d4/", doc)
        for name, full in PINS.items():
            self.assertIn(full[:16], doc, name)
        for fact in ("**50 of 50 `as-predicted`**", "42 predicted pass and observed pass", "8 predicted fail and observed fail", "`verified=30 pass=30 fail=0 problems=0`",
                     "Every line ran on `trj`", "the other eight are run6's logs", "the audit report is still the one for `5b8d5696`"):
            self.assertIn(fact, doc, fact)
        rec = json.loads(read_text(os.path.join(EVIDENCE, "record-run7.json")))
        self.assertIn(rec["manifest_sha256"][:8], doc)
        self.assertIn(rec["sources"]["asupersync"][:12], doc)
        self.assertIn(rec["sources"]["frankenlibc"][:12], doc)


@unittest.skipUnless(os.path.isdir(EVIDENCE), "the committed E06 run7 evidence directory is not present")
class PlantedRun7CorruptionTests(unittest.TestCase):
    """Each case corrupts a COPY of the directory in one way and expects the checker to name it; the real directory passes above."""

    def corrupted(self, filename, edit):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        copy = os.path.join(tmp.name, "rev")
        shutil.copytree(EVIDENCE, copy)
        path = os.path.join(copy, filename)
        text = read_text(path)
        new = edit(text)
        self.assertNotEqual(new, text, "the plant changed nothing")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new)
        return copy

    def test_a_flipped_row_status_is_named(self):
        copy = self.corrupted("rows-run7.jsonl", lambda t: t.replace('"status": "pass"', '"status": "fail"', 1))
        self.assertTrue(any(m.startswith("rows: not 30 passing") for m in problems(copy, check_pins=False)), problems(copy, check_pins=False))

    def test_a_verdict_changed_in_the_record_is_named(self):
        copy = self.corrupted("record-run7.json", lambda t: t.replace('"verdict": "as-predicted"', '"verdict": "unexpected-fail"', 1))
        got = problems(copy, check_pins=False)
        self.assertTrue(any(m.startswith("record lines not as-predicted") for m in got) and any(m.startswith("judge table disagrees") for m in got), got)

    def test_a_failing_line_rewritten_as_a_predicted_and_observed_pass_is_named(self):
        # Prediction and observation edited together, so the per-line verdict check stays quiet: only the failure-set checks can see it.
        copy = self.corrupted("record-run7.json", lambda t: t.replace('"expected": "fail"', '"expected": "pass"', 1).replace('"observed": "fail"', '"observed": "pass"', 1))
        got = problems(copy, check_pins=False)
        self.assertIn("record: the predicted-failure set is not the eight named lines", got)
        self.assertIn("record: the observed-failure set is not the eight named lines", got)
        self.assertFalse(any(m.startswith("record lines not as-predicted") for m in got), got)

    def test_a_log_hash_changed_in_the_record_breaks_the_cross_binding_with_ingest(self):
        rec = json.loads(read_text(os.path.join(EVIDENCE, "record-run7.json")))
        victim = next(l for l in rec["lines"] if l["id"] == "workspace.franken-clock.mips")["log_sha256"]
        copy = self.corrupted("record-run7.json", lambda t: t.replace(victim, "0" * 64, 1))
        self.assertTrue(any(m.startswith("ingest raw_log_sha256 differs") for m in problems(copy, check_pins=False)), problems(copy, check_pins=False))

    def test_a_failing_ingest_record_is_named(self):
        copy = self.corrupted("ingest-run7.json", lambda t: t.replace('"status": "pass"', '"status": "fail"', 1))
        self.assertTrue(any(m.startswith("ingest: not 30 passing") for m in problems(copy, check_pins=False)), problems(copy, check_pins=False))

    def test_a_judge_output_that_does_not_end_in_exit_0_is_named(self):
        copy = self.corrupted("judge-run7.out", lambda t: t.replace("EXIT 0: every line resolved", "EXIT 3: every line resolved", 1))
        self.assertIn("judge output is not 50 as-predicted with EXIT 0", problems(copy, check_pins=False))

    def test_a_dropped_record_line_is_named(self):
        def drop(t):
            rec = json.loads(t)
            rec["lines"] = rec["lines"][1:]
            return json.dumps(rec, sort_keys=True)
        copy = self.corrupted("record-run7.json", drop)
        self.assertTrue(any(m.startswith("record ids: 49 lines") for m in problems(copy, check_pins=False)), problems(copy, check_pins=False))

    def test_a_local_path_in_a_committed_file_is_named(self):
        copy = self.corrupted("judge-run7.out", lambda t: t + "  see /Users/someone/scratch\n")
        self.assertTrue(any(m.startswith("leak in judge-run7.out") for m in problems(copy, check_pins=False)), problems(copy, check_pins=False))

    def test_an_edited_manifest_breaks_both_the_pin_and_the_records_binding(self):
        copy = self.corrupted("manifest.json", lambda t: t.replace("trj,hz3", "trj,hz4", 1))
        got = problems(copy)
        self.assertIn("pinned hash differs: manifest.json", got)
        self.assertIn("record manifest_sha256 is not the sha256 of manifest.json", got)


if __name__ == "__main__":
    unittest.main()
