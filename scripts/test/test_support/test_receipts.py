#!/usr/bin/env python3
"""Tests for receipts.py: every rejection test has a near-identical accepted twin.

Streams are built from raw canonical lines plus an independently written
footer (not through StreamWriter), so the writer is checked against the spec
rather than against itself. Stdlib only; loopback/network is never touched.

Run:  python3 -B -m unittest scripts/test/test_support/test_receipts.py
"""

import errno
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import receipts as R  # noqa: E402

RECEIPTS_PATH = os.path.join(HERE, "receipts.py")
RUN_SEED = 20261104
SUBJECT_SHA = hashlib.sha256(b"subject-binary").hexdigest()
SUITE_SHA = hashlib.sha256(b"suite-source").hexdigest()
LOG_SHA = hashlib.sha256(b"case-log").hexdigest()
ARTIFACTS = [
    {"name": "subject.bin", "sha256": SUBJECT_SHA, "size": 14},
    {"name": "suite.py", "sha256": SUITE_SHA, "size": 12},
]
VERSIONS = {"python": "3", "runner": "test"}
EXTERNAL_REF = {"authorization_id": "auth-0001", "receipt_sha256": hashlib.sha256(b"ext").hexdigest()}

EXPECTED = {
    "q00.sample.loss": {"mandatory": True, "proof_class": "host-simulation"},
    "q00.canary.stale-epoch": {"mandatory": True, "proof_class": "host-simulation", "canary": True,
                               "oracle": "epoch", "violation": "stale_epoch_applied"},
    "e07.boot.guest": {"mandatory": True, "proof_class": "guest-execution"},
    "n01.loopback": {"mandatory": False, "proof_class": "loopback-integration"},
}
SMALL = {
    "a.one": {"mandatory": True, "proof_class": "host-simulation"},
    "a.two": {"mandatory": False, "proof_class": "host-simulation"},
}


def dumps(obj):
    """Canonical JSON for test streams. Unlike receipts.canonical_json it
    allows NaN so tests can plant it."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def seal(lines, case_records=None):
    """Append a correct footer, computed independently of StreamWriter."""
    body = b"".join(line + b"\n" for line in lines)
    footer = {
        "schema": R.SCHEMA,
        "kind": "run_footer",
        "case_records": len(lines) - 1 if case_records is None else case_records,
        "lines": len(lines),
        "stream_sha256": hashlib.sha256(body).hexdigest(),
    }
    return body + dumps(footer) + b"\n"


class Run:
    """Builds a self-consistent run (header, case records, footer)."""

    def __init__(self, expected, run_id="run-a", seed=RUN_SEED, tier="smoke"):
        self.expected = expected
        self.run_id = run_id
        self.seed = seed
        self.tier = tier
        self.norm = R.normalize_expected(expected)

    def header(self, **over):
        h = {
            "schema": R.SCHEMA, "kind": "run_header", "run_id": self.run_id, "suite": "suite-x",
            "tier": self.tier, "seed": self.seed, "timebase": "monotonic_ns",
            "registry_digest": R.registry_digest(self.expected), "expected_cases": len(self.expected),
            "versions": dict(VERSIONS), "artifacts": [dict(a) for a in ARTIFACTS],
        }
        h.update(over)
        return h

    def rec(self, cid, outcome="pass", attempt=1, **over):
        sp = self.norm[cid]
        pclass, canary = sp.proof_class, sp.canary
        case_seed = R.derive_case_seed(self.seed, cid)
        r = {
            "schema": R.SCHEMA, "kind": "case", "run_id": self.run_id, "case_id": cid,
            "attempt": attempt, "outcome": outcome, "proof_class": pclass, "canary": canary,
            "origin": "external" if pclass in R.EXTERNAL_CLASSES and outcome in R.RAN_OUTCOMES else "local",
            "seed": case_seed,
            "replay": {
                "argv": ["run-suite", "--tier", self.tier, "--seed", str(self.seed), "--case", cid],
                "case_id": cid, "run_seed": self.seed, "case_seed": case_seed,
            },
        }
        if pclass in R.EXTERNAL_CLASSES and outcome in R.RAN_OUTCOMES:
            r["external"] = dict(EXTERNAL_REF)
        if outcome in R.RAN_OUTCOMES:
            r["process"] = {"exit_code": 0, "timed_out": False}
            r["started_mono_ns"] = 1000
            r["ended_mono_ns"] = 2000
            r["log"] = {"sha256": LOG_SHA, "events": 10, "dropped": 0, "bytes": 512,
                        "truncated": False, "critical_lost": False}
            r["artifacts"] = [{"name": "subject.bin", "sha256": SUBJECT_SHA}]
        if outcome == "pass":
            if canary:
                r["oracle"] = oracle_block(sp.oracle, status="failed", kinds={sp.violation: 1}, kind="state")
                r["process"]["exit_code"] = 1  # the planted-defect subject is expected to fail
            else:
                r["oracle"] = oracle_block()
        elif outcome in R.FAILURE_OUTCOMES:
            r["failure"] = {"oracle": "oracle.sample", "expected": {"samples": 8},
                            "observed": {"samples": 7},
                            "first_causal_event": {"log_seq": 3, "kind": "sample.gap"}}
            r["process"]["exit_code"] = {"fail": 1, "timeout": -9, "crash": -11}[outcome]
            r["process"]["timed_out"] = outcome == "timeout"
        else:
            r["reason"] = "external_evidence_required" if outcome == "blocked" else f"test {outcome}"
            if outcome == "cancelled":
                r["process"]["exit_code"] = -15
        r.update(over)
        return r

    def all_pass(self, skip=()):
        return [self.rec(c) for c in self.expected if c not in skip]

    def lines(self, records, header=True):
        out = [dumps(self.header())] if header else []
        return out + [dumps(r) for r in records]

    def build(self, records):
        return seal(self.lines(records))


def oracle_block(name="oracle.sample", *, status="passed", kinds=None, finalized=True, reasons=None,
                 checks=8, kind="sample"):
    """A pass record's oracle block, built field by field (not via the adapter)."""
    kinds = {} if kinds is None else dict(kinds)
    return {"name": name, "kind": kind, "independent": True, "checks": checks,
            "mismatches": sum(kinds.values()), "status": status, "finalized": finalized,
            "incomplete_reasons": [] if reasons is None else list(reasons), "violation_kinds": kinds}


def verdict(oracle="epoch", status="failed", kinds=None, finalized=True, reasons=None, relevant=44):
    """Shaped like scripts/test/test_support/oracles.py output (ffw.oracle_verdict.v1).
    Synthetic: this test file deliberately does not import the peer module."""
    kinds = {} if kinds is None else dict(kinds)
    reasons = [] if reasons is None else list(reasons)
    if not finalized and "not_finalized" not in reasons:
        reasons.insert(0, "not_finalized")
    return {"schema": R.VERDICT_SCHEMA, "oracle": oracle, "status": status, "finalized": finalized,
            "events_relevant": relevant, "violation_count": sum(kinds.values()),
            "violation_kinds": kinds, "incomplete_reasons": reasons}


def agg(data, expected=EXPECTED, **kw):
    return R.aggregate(data, expected, **kw)


def codes(summary):
    return {p["code"] for p in summary["problems"]}


def case_codes(summary, cid):
    return {p["code"] for p in summary["problems"] if p.get("case_id") == cid}


class Base(unittest.TestCase):
    def setUp(self):
        self.run_ = Run(EXPECTED)

    def assertUnqualified(self, s, *want_codes):
        self.assertFalse(s["qualified"], s["unqualified_reasons"])
        for c in want_codes:
            self.assertIn(c, codes(s), f"missing {c}; have {sorted(codes(s))}")

    def assertInvalid(self, s, cid, code):
        self.assertFalse(s["qualified"])
        self.assertEqual(s["cases"][cid]["verdict"], "invalid", s["problems"])
        self.assertIn(code, case_codes(s, cid), f"{code} not in {sorted(case_codes(s, cid))}")


class TestAcceptedRuns(Base):
    def test_valid_run_qualifies_with_exact_denominator(self):
        data = self.run_.build(self.run_.all_pass())
        s = agg(data)
        self.assertTrue(s["qualified"], s["problems"])
        self.assertTrue(s["complete"])
        self.assertEqual(s["problems_total"], 0)
        self.assertEqual(s["denominator"], {"total": 4, "mandatory": 3, "optional": 1, "executed": 4})
        self.assertEqual(s["counts"]["pass"], 4)
        self.assertEqual(sum(s["counts"].values()), 4)
        self.assertEqual(s["tier"], "smoke")
        self.assertEqual(s["identity"]["artifacts"], ARTIFACTS)
        self.assertEqual(s["identity"]["seed"], RUN_SEED)
        self.assertEqual(s["evidence_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(s["by_proof_class"]["host-simulation"]["pass"], 2)
        self.assertEqual(s["by_proof_class"]["guest-execution"]["total"], 1)
        text = R.render_summary(s)
        self.assertIn("RECEIPTS QUALIFIED", text)
        self.assertIn("executed=4", text)

    def test_writer_output_matches_independent_footer_spec(self):
        recs = self.run_.all_pass()
        buf = io.BytesIO()
        w = R.StreamWriter(buf)
        w.write_header(run_id="run-a", suite="suite-x", tier="smoke", seed=RUN_SEED,
                       expected=EXPECTED, versions=VERSIONS, artifacts=ARTIFACTS)
        for r in recs:
            fields = {k: v for k, v in r.items() if k not in ("schema", "kind")}
            w.write_case(**fields)
        w.write_footer()
        self.assertEqual(buf.getvalue(), self.run_.build(recs))
        self.assertTrue(agg(buf.getvalue())["qualified"])

    def test_every_non_pass_outcome_is_valid_evidence_and_blocks_only_when_mandatory(self):
        for outcome in R.OUTCOMES:
            if outcome == "pass":
                continue
            for mandatory in (True, False):
                with self.subTest(outcome=outcome, mandatory=mandatory):
                    exp = {"base": {"mandatory": True, "proof_class": "host-simulation"},
                           "x": {"mandatory": mandatory, "proof_class": "host-simulation"}}
                    run = Run(exp)
                    s = agg(run.build([run.rec("base"), run.rec("x", outcome)]), exp)
                    self.assertEqual(s["problems_total"], 0, s["problems"])
                    self.assertEqual(s["cases"]["x"]["verdict"], outcome)
                    self.assertEqual(s["qualified"], not mandatory, s["unqualified_reasons"])
                    ran = outcome in R.RAN_OUTCOMES
                    self.assertEqual(s["denominator"]["executed"], 2 if ran else 1)

    def test_summary_is_deterministic(self):
        data = self.run_.build(self.run_.all_pass())
        a, b = agg(data), agg(data)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(R.render_summary(a), R.render_summary(b))


class TestTruncationAndStreamIntegrity(Base):
    def test_every_proper_prefix_is_unqualified_and_the_whole_qualifies(self):
        run = Run(SMALL)
        data = run.build(run.all_pass())
        self.assertTrue(agg(data, SMALL)["qualified"])
        for n in range(len(data)):
            s = agg(data[:n], SMALL)
            self.assertFalse(s["qualified"], f"prefix {n} qualified")
            self.assertFalse(s["complete"], f"prefix {n} reported complete")

    def test_missing_footer_and_torn_tail_have_specific_codes(self):
        lines = self.run_.lines(self.run_.all_pass())
        no_footer = b"".join(line + b"\n" for line in lines)
        self.assertUnqualified(agg(no_footer), "footer_missing")
        sealed = seal(lines)
        self.assertUnqualified(agg(sealed[:-1]), "stream_truncated")
        self.assertTrue(agg(sealed)["qualified"])

    def test_edit_after_sealing_is_caught_by_digest_only(self):
        lines = self.run_.lines(self.run_.all_pass())
        sealed = seal(lines)
        tampered = sealed.replace(b'"checks":8', b'"checks":9', 1)
        self.assertNotEqual(tampered, sealed)
        s = agg(tampered)
        self.assertUnqualified(s, "footer_digest_mismatch")
        # The edited record is itself well-formed; resealing it would qualify.
        edited = [line.replace(b'"checks":8', b'"checks":9', 1) for line in lines]
        self.assertTrue(agg(seal(edited))["qualified"])

    def test_footer_count_must_match(self):
        lines = self.run_.lines(self.run_.all_pass())
        self.assertUnqualified(agg(seal(lines, case_records=len(lines))), "footer_count_mismatch")
        self.assertTrue(agg(seal(lines, case_records=len(lines) - 1))["qualified"])

    def test_record_after_footer_and_duplicate_footer_and_duplicate_header(self):
        lines = self.run_.lines(self.run_.all_pass())
        sealed = seal(lines)
        extra = dumps(self.run_.rec("n01.loopback", attempt=2)) + b"\n"
        self.assertUnqualified(agg(sealed + extra, max_attempts=2), "footer_misplaced")
        footer_line = sealed.splitlines()[-1] + b"\n"
        self.assertUnqualified(agg(sealed + footer_line), "footer_misplaced")
        self.assertUnqualified(agg(seal([lines[0]] + lines)), "header_misplaced")

    def test_missing_header_makes_every_record_untrusted(self):
        lines = self.run_.lines(self.run_.all_pass(), header=False)
        s = agg(seal(lines, case_records=len(lines)))
        self.assertUnqualified(s, "header_missing", "no_valid_header")
        self.assertEqual(s["counts"]["invalid"], 4)
        self.assertEqual(s["counts"]["pass"], 0)

    def test_schema_version_bump_is_rejected_not_guessed(self):
        recs = self.run_.all_pass()
        bad_header = [dumps(self.run_.header(schema="ffw.receipt-stream/2"))] + [dumps(r) for r in recs]
        s = agg(seal(bad_header))
        self.assertUnqualified(s, "bad_schema")
        self.assertEqual(s["counts"]["pass"], 0)
        recs[0]["schema"] = "ffw.receipt-stream/2"
        self.assertInvalid(agg(self.run_.build(recs)), recs[0]["case_id"], "bad_schema")

    def test_duplicate_json_key_cannot_launder_an_outcome(self):
        lines = self.run_.lines(self.run_.all_pass())
        planted = [line.replace(b'"outcome":"pass"', b'"outcome":"fail","outcome":"pass"', 1) for line in lines]
        self.assertNotEqual(planted, lines)
        self.assertUnqualified(agg(seal(planted)), "duplicate_json_key")
        self.assertNotIn("footer_digest_mismatch", codes(agg(seal(planted))))
        self.assertTrue(agg(seal(lines))["qualified"])

    def test_non_finite_numbers_garbage_blank_and_bad_encoding(self):
        lines = self.run_.lines(self.run_.all_pass())
        for needle, code in ((b'"checks":8', "non_finite_number"),):
            for bad in (b'"checks":NaN', b'"checks":Infinity', b'"checks":1e999'):
                planted = [line.replace(needle, bad, 1) for line in lines]
                self.assertUnqualified(agg(seal(planted)), code)
        for extra, code in ((b"", "blank_line"), (b"\xff\xfe", "bad_encoding"),
                            (b"{not json", "bad_json"), (b"[1,2]", "not_object")):
            s = agg(seal(lines + [extra]))
            self.assertUnqualified(s, code)
        self.assertTrue(agg(seal(lines))["qualified"])

    def test_oversized_line_is_flagged(self):
        lines = self.run_.lines(self.run_.all_pass())
        self.assertUnqualified(agg(seal(lines), max_line_bytes=300), "line_too_long")
        self.assertTrue(agg(seal(lines), max_line_bytes=R.MAX_LINE_BYTES)["qualified"])

    def test_registry_pin_detects_a_shrunk_or_edited_denominator(self):
        shrunk = {k: v for k, v in EXPECTED.items() if k != "n01.loopback"}
        run = Run(shrunk)
        data = run.build(run.all_pass())
        self.assertTrue(agg(data, shrunk)["qualified"])
        self.assertUnqualified(agg(data, EXPECTED), "registry_mismatch")
        flipped = {**EXPECTED, "n01.loopback": {"mandatory": True, "proof_class": "loopback-integration"}}
        data2 = self.run_.build(self.run_.all_pass())
        self.assertUnqualified(agg(data2, flipped), "registry_mismatch")
        canary_flip = {**EXPECTED, "q00.sample.loss": {"mandatory": True, "proof_class": "host-simulation",
                                                          "canary": True, "oracle": "sample", "violation": "lost_samples"}}
        self.assertUnqualified(agg(data2, canary_flip), "registry_mismatch")


class TestCaseEvidenceCompleteness(Base):
    def test_missing_mandatory_case_counts_as_not_run_and_blocks(self):
        s = agg(self.run_.build(self.run_.all_pass(skip=("e07.boot.guest",))))
        self.assertFalse(s["qualified"])
        self.assertTrue(s["complete"], "footer was consistent, so only the case is missing")
        self.assertEqual(s["cases"]["e07.boot.guest"]["verdict"], "not_run")
        self.assertEqual(s["counts"]["not_run"], 1)
        self.assertEqual(s["denominator"]["total"], 4)
        self.assertIn("mandatory_not_passed:1", s["unqualified_reasons"])
        self.assertEqual(s["failures"][0]["case_id"], "e07.boot.guest")
        self.assertEqual(s["failures"][0]["original"], {"reason": "no_receipt"})

    def test_missing_optional_case_is_counted_but_does_not_block(self):
        s = agg(self.run_.build(self.run_.all_pass(skip=("n01.loopback",))))
        self.assertTrue(s["qualified"])
        self.assertEqual(s["counts"]["not_run"], 1)
        self.assertEqual(s["denominator"]["executed"], 3)

    def test_duplicate_evidence_identical_and_conflicting(self):
        recs = self.run_.all_pass()
        same = recs + [dict(recs[0])]
        s = agg(self.run_.build(same))
        self.assertInvalid(s, recs[0]["case_id"], "duplicate_case_evidence")
        self.assertIn("identical", [p for p in s["problems"] if p["code"] == "duplicate_case_evidence"][0]["detail"])
        other = self.run_.rec(recs[0]["case_id"], "fail")
        s2 = agg(self.run_.build(recs + [other]))
        self.assertInvalid(s2, recs[0]["case_id"], "duplicate_case_evidence")
        self.assertIn("conflicting", [p for p in s2["problems"] if p["code"] == "duplicate_case_evidence"][0]["detail"])

    def test_second_attempt_is_not_a_duplicate_but_is_bounded(self):
        recs = self.run_.all_pass() + [self.run_.rec("q00.sample.loss", attempt=2)]
        self.assertTrue(agg(self.run_.build(recs), max_attempts=2)["qualified"])
        self.assertInvalid(agg(self.run_.build(recs), max_attempts=1), "q00.sample.loss", "attempts_exceeded")

    def test_attempt_gap_is_missing_evidence(self):
        recs = self.run_.all_pass() + [self.run_.rec("q00.sample.loss", attempt=3)]
        self.assertInvalid(agg(self.run_.build(recs), max_attempts=3), "q00.sample.loss", "attempt_gap")
        recs = self.run_.all_pass() + [self.run_.rec("q00.sample.loss", attempt=2)]
        self.assertTrue(agg(self.run_.build(recs), max_attempts=3)["qualified"])

    def test_retry_never_launders_a_failure(self):
        for first, second in (("fail", "pass"), ("pass", "fail"), ("crash", "pass"), ("timeout", "pass")):
            with self.subTest(first=first, second=second):
                recs = self.run_.all_pass(skip=("q00.sample.loss",))
                recs += [self.run_.rec("q00.sample.loss", first, 1), self.run_.rec("q00.sample.loss", second, 2)]
                s = agg(self.run_.build(recs), max_attempts=2)
                c = s["cases"]["q00.sample.loss"]
                self.assertEqual(c["verdict"], first if first != "pass" else second)
                self.assertTrue(c["flaky"])
                self.assertFalse(s["qualified"])
                f = [x for x in s["failures"] if x["case_id"] == "q00.sample.loss"][0]
                self.assertEqual(f["attempt_outcomes"], [first, second])
                self.assertEqual(f["original"]["failure"]["observed"], {"samples": 7})
                self.assertIn("--case", f["replay"])
        recs = self.run_.all_pass() + [self.run_.rec("q00.sample.loss", attempt=2)]
        s = agg(self.run_.build(recs), max_attempts=2)
        self.assertTrue(s["qualified"])
        self.assertFalse(s["cases"]["q00.sample.loss"]["flaky"])

    def test_unexpected_case_record_is_a_problem_not_a_denominator_change(self):
        extra = Run({**EXPECTED, "zz.extra": {"mandatory": True, "proof_class": "host-simulation"}})
        recs = self.run_.all_pass() + [extra.rec("zz.extra")]
        s = agg(self.run_.build(recs))
        self.assertUnqualified(s, "unexpected_case")
        self.assertEqual(s["unexpected_records"], 1)
        self.assertEqual(s["denominator"]["total"], 4)
        self.assertEqual(sum(s["counts"].values()), 4)

    def test_record_from_a_parallel_run_is_rejected(self):
        other = Run(EXPECTED, run_id="run-b", seed=RUN_SEED + 1)
        recs = self.run_.all_pass(skip=("e07.boot.guest",)) + [other.rec("e07.boot.guest")]
        s = agg(self.run_.build(recs))
        self.assertInvalid(s, "e07.boot.guest", "run_id_mismatch")
        self.assertTrue(agg(other.build(other.all_pass()))["qualified"])
        self.assertTrue(agg(self.run_.build(self.run_.all_pass()))["qualified"])

    def test_all_optional_registry_cannot_qualify_vacuously(self):
        exp = {"o.one": {"mandatory": False, "proof_class": "host-simulation"}}
        run = Run(exp)
        s = agg(run.build(run.all_pass()), exp)
        self.assertEqual(s["problems_total"], 0)
        self.assertFalse(s["qualified"])
        self.assertIn("no_mandatory_cases", s["unqualified_reasons"])


class TestProofClasses(Base):
    def setUp(self):
        self.exp = {
            "h.case": {"mandatory": True, "proof_class": "host-simulation"},
            "g.case": {"mandatory": True, "proof_class": "guest-execution"},
            "p.case": {"mandatory": True, "proof_class": "physical"},
            "r.case": {"mandatory": True, "proof_class": "real-service"},
        }
        self.run_ = Run(self.exp)

    def test_external_classes_pass_only_with_authorization_reference(self):
        s = agg(self.run_.build(self.run_.all_pass()), self.exp)
        self.assertTrue(s["qualified"], s["problems"])
        self.assertEqual(s["by_proof_class"]["physical"]["pass"], 1)
        self.assertEqual(s["by_proof_class"]["real-service"]["pass"], 1)

    def test_host_simulation_cannot_stand_in_for_guest_execution(self):
        recs = self.run_.all_pass(skip=("g.case",))
        recs.append(self.run_.rec("g.case", proof_class="host-simulation"))
        self.assertInvalid(agg(self.run_.build(recs), self.exp), "g.case", "proof_class_mismatch")
        recs[-1] = self.run_.rec("g.case")
        self.assertTrue(agg(self.run_.build(recs), self.exp)["qualified"])

    def test_physical_without_external_reference_is_invalid(self):
        for mutate, code in (
            (lambda r: r.pop("external"), "missing_external"),
            (lambda r: r.update(origin="local"), "origin_mismatch"),
            (lambda r: r["external"].update(receipt_sha256="abc"), "bad_field"),
            (lambda r: r["external"].update(authorization_id=""), "bad_field"),
        ):
            with self.subTest(code=code):
                recs = self.run_.all_pass(skip=("p.case",))
                p = self.run_.rec("p.case")
                mutate(p)
                s = agg(self.run_.build(recs + [p]), self.exp)
                self.assertInvalid(s, "p.case", code)

    def test_local_class_cannot_claim_external_authorization(self):
        recs = self.run_.all_pass(skip=("h.case",))
        h = self.run_.rec("h.case")
        h["external"] = dict(EXTERNAL_REF)
        self.assertInvalid(agg(self.run_.build(recs + [h]), self.exp), "h.case", "unexpected_external")
        h2 = self.run_.rec("h.case", origin="external")
        self.assertInvalid(agg(self.run_.build(recs + [h2]), self.exp), "h.case", "origin_mismatch")

    def test_offline_blocked_external_cases_stay_separate_from_passing_classes(self):
        recs = self.run_.all_pass(skip=("p.case", "r.case"))
        recs += [self.run_.rec("p.case", "blocked"), self.run_.rec("r.case", "blocked")]
        s = agg(self.run_.build(recs), self.exp)
        self.assertEqual(s["problems_total"], 0)
        self.assertFalse(s["qualified"])
        self.assertEqual(s["by_proof_class"]["physical"]["blocked"], 1)
        self.assertEqual(s["by_proof_class"]["real-service"]["blocked"], 1)
        self.assertEqual(s["by_proof_class"]["host-simulation"]["pass"], 1)
        self.assertEqual(s["by_proof_class"]["guest-execution"]["pass"], 1)
        self.assertEqual(s["denominator"]["executed"], 2)

    def test_unlaunched_external_class_records_are_local_and_carry_no_authorization(self):
        for outcome in ("blocked", "not_run"):
            with self.subTest(outcome=outcome):
                base = self.run_.all_pass(skip=("p.case",))
                good = self.run_.rec("p.case", outcome)
                self.assertEqual(good["origin"], "local")
                self.assertNotIn("external", good)
                s = agg(self.run_.build(base + [good]), self.exp)
                self.assertEqual(s["problems_total"], 0, s["problems"])
                self.assertEqual(s["cases"]["p.case"]["verdict"], outcome)
                claimed = self.run_.rec("p.case", outcome, origin="external", external=dict(EXTERNAL_REF))
                self.assertInvalid(agg(self.run_.build(base + [claimed]), self.exp), "p.case", "origin_mismatch")
                smuggled = self.run_.rec("p.case", outcome, external=dict(EXTERNAL_REF))
                self.assertInvalid(agg(self.run_.build(base + [smuggled]), self.exp), "p.case", "unexpected_external")


class TestIdentity(Base):
    def case_with(self, mutate, cid="q00.sample.loss", outcome="pass"):
        r = self.run_.rec(cid, outcome)
        mutate(r)
        recs = [x for x in self.run_.all_pass() if x["case_id"] != cid] + [r]
        return agg(self.run_.build(recs))

    def test_artifact_digest_must_match_header_exactly(self):
        flip = SUBJECT_SHA[:-1] + ("0" if SUBJECT_SHA[-1] != "0" else "1")
        s = self.case_with(lambda r: r["artifacts"].__setitem__(0, {"name": "subject.bin", "sha256": flip}))
        self.assertInvalid(s, "q00.sample.loss", "artifact_mismatch")
        s = self.case_with(lambda r: r["artifacts"].__setitem__(0, {"name": "other.bin", "sha256": SUBJECT_SHA}))
        self.assertInvalid(s, "q00.sample.loss", "artifact_mismatch")
        s = self.case_with(lambda r: r["artifacts"].__setitem__(0, {"name": "subject.bin", "sha256": SUBJECT_SHA.upper()}))
        self.assertInvalid(s, "q00.sample.loss", "bad_artifacts")
        s = self.case_with(lambda r: r.update(artifacts=[]))
        self.assertInvalid(s, "q00.sample.loss", "bad_artifacts")
        self.assertTrue(self.case_with(lambda r: r["artifacts"].append({"name": "suite.py", "sha256": SUITE_SHA}))["qualified"])

    def test_header_artifact_digest_shape_is_enforced_by_writer_and_reader(self):
        bad = [{"name": "subject.bin", "sha256": SUBJECT_SHA[:-1], "size": 1}]
        with self.assertRaises(R.ReceiptError):
            R.StreamWriter(io.BytesIO()).write_header(run_id="r", suite="s", tier="smoke", seed=1,
                                                      expected=EXPECTED, versions=VERSIONS, artifacts=bad)
        lines = [dumps(self.run_.header(artifacts=bad))] + [dumps(r) for r in self.run_.all_pass()]
        self.assertUnqualified(agg(seal(lines)), "bad_artifacts")

    def test_seed_must_be_the_derived_case_seed(self):
        def shift(r):
            r["seed"] += 1
            r["replay"]["case_seed"] += 1
        self.assertInvalid(self.case_with(shift), "q00.sample.loss", "seed_not_derived")
        self.assertTrue(self.case_with(lambda r: None)["qualified"])

    def test_seed_type_traps(self):
        for bad in (True, "123", -1, R.U64, 1.0, None):
            with self.subTest(seed=bad):
                s = self.case_with(lambda r: r.update(seed=bad))
                self.assertInvalid(s, "q00.sample.loss", "bad_field")

    def test_replay_identity_must_name_case_and_seeds(self):
        cid = "q00.sample.loss"
        cases = {
            "replay.case_id": lambda r: r["replay"].update(case_id="other.case"),
            "replay.run_seed": lambda r: r["replay"].update(run_seed=RUN_SEED + 1),
            "replay.case_seed": lambda r: r["replay"].update(case_seed=r["seed"] + 1),
            "argv lacks case": lambda r: r["replay"].update(argv=["run-suite", "--seed", str(RUN_SEED)]),
            "argv lacks seed": lambda r: r["replay"].update(argv=["run-suite", "--case", cid]),
            "argv empty": lambda r: r["replay"].update(argv=[]),
            "argv non-str": lambda r: r["replay"].update(argv=["run-suite", 7, cid, str(RUN_SEED)]),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                self.assertInvalid(self.case_with(mutate), cid, "bad_replay")
        eq_form = lambda r: r["replay"].update(argv=["run-suite", f"--case={cid}", f"--seed={RUN_SEED}"])
        self.assertTrue(self.case_with(eq_form)["qualified"])

    def test_derive_case_seed_is_pure_distinct_and_range_checked(self):
        a = R.derive_case_seed(RUN_SEED, "x.one")
        self.assertEqual(a, R.derive_case_seed(RUN_SEED, "x.one"))
        self.assertNotEqual(a, R.derive_case_seed(RUN_SEED, "x.two"))
        self.assertNotEqual(a, R.derive_case_seed(RUN_SEED + 1, "x.one"))
        self.assertTrue(0 <= a < R.U64)
        for bad in (True, -1, R.U64, "1", 1.5):
            with self.assertRaises(R.ReceiptError):
                R.derive_case_seed(bad, "x.one")


class TestOracleAndOutcomeIntegrity(Base):
    def case_with(self, mutate, cid="q00.sample.loss", outcome="pass"):
        r = self.run_.rec(cid, outcome)
        mutate(r)
        recs = [x for x in self.run_.all_pass() if x["case_id"] != cid] + [r]
        return agg(self.run_.build(recs))

    def test_pass_needs_an_independent_oracle_that_actually_checked(self):
        cid = "q00.sample.loss"
        bad = {
            "vacuous_pass": lambda r: r["oracle"].update(checks=0),
            "bad_oracle": lambda r: r["oracle"].update(independent=False),
            "log_only_oracle": lambda r: r["oracle"].update(kind="log"),
            "pass_with_mismatches": lambda r: r["oracle"].update(mismatches=1),
        }
        for code, mutate in bad.items():
            with self.subTest(code):
                self.assertInvalid(self.case_with(mutate), cid, code)
        self.assertInvalid(self.case_with(lambda r: r["oracle"].update(kind="banana")), cid, "bad_oracle")
        self.assertInvalid(self.case_with(lambda r: r.pop("oracle")), cid, "missing_field")
        self.assertTrue(self.case_with(lambda r: r["oracle"].update(checks=1))["qualified"])

    def test_canary_pass_means_the_oracle_detected_the_defect(self):
        cid = "q00.canary.stale-epoch"
        self.assertTrue(self.case_with(lambda r: None, cid)["qualified"])
        self.assertInvalid(self.case_with(lambda r: r["oracle"].update(mismatches=0), cid), cid, "canary_not_detected")
        s = self.case_with(lambda r: r["process"].update(exit_code=None), cid)
        self.assertInvalid(s, cid, "contradiction")
        # An oracle that missed the planted defect is a failure, validly reported.
        blind = self.run_.rec(cid, "fail")
        blind["failure"].update(expected="oracle rejects stale epoch", observed="oracle accepted stale epoch")
        recs = [x for x in self.run_.all_pass() if x["case_id"] != cid] + [blind]
        s = agg(self.run_.build(recs))
        self.assertEqual(s["problems_total"], 0)
        self.assertEqual(s["cases"][cid]["verdict"], "fail")
        self.assertFalse(s["qualified"])

    def test_canary_flag_cannot_be_self_declared(self):
        s = self.case_with(lambda r: r.update(canary=True))
        self.assertInvalid(s, "q00.sample.loss", "canary_mismatch")
        s = self.case_with(lambda r: r.update(canary=False), "q00.canary.stale-epoch")
        self.assertInvalid(s, "q00.canary.stale-epoch", "canary_mismatch")

    def test_pass_contradicted_by_process_or_log_is_not_a_pass(self):
        cid = "q00.sample.loss"
        self.assertInvalid(self.case_with(lambda r: r["process"].update(exit_code=1)), cid, "contradiction")
        self.assertInvalid(self.case_with(lambda r: r["process"].update(exit_code=None)), cid, "contradiction")
        self.assertInvalid(self.case_with(lambda r: r["process"].update(timed_out=True)), cid, "contradiction")
        for flag in ("truncated", "critical_lost"):
            s = self.case_with(lambda r: r["log"].update({flag: True}))
            self.assertInvalid(s, cid, "critical_evidence_lost")
            self.assertFalse(s["complete"])

    def test_lossy_log_on_a_failure_keeps_the_failure_and_marks_run_incomplete(self):
        s = self.case_with(lambda r: r["log"].update(critical_lost=True), "q00.sample.loss", "fail")
        self.assertEqual(s["cases"]["q00.sample.loss"]["verdict"], "fail")
        self.assertFalse(s["complete"])
        self.assertIn("critical_evidence_lost", codes(s))
        s = self.case_with(lambda r: r["log"].update(dropped=5), "q00.sample.loss", "fail")
        self.assertTrue(s["complete"], "dropped non-critical events are reported, not fatal")

    def test_failure_records_must_carry_expected_observed_and_first_cause(self):
        cid = "q00.sample.loss"
        same = lambda r: r["failure"].update(observed=r["failure"]["expected"])
        self.assertInvalid(self.case_with(same, cid, "fail"), cid, "bad_failure")
        self.assertInvalid(self.case_with(lambda r: r["failure"].pop("first_causal_event"), cid, "fail"), cid, "missing_field")
        self.assertInvalid(self.case_with(lambda r: r["failure"]["first_causal_event"].update(log_seq=10), cid, "fail"), cid, "bad_failure")
        self.assertInvalid(self.case_with(lambda r: r["failure"]["first_causal_event"].update(log_seq=-1), cid, "fail"), cid, "bad_failure")
        self.assertInvalid(self.case_with(lambda r: r.pop("failure"), cid, "fail"), cid, "missing_field")
        s = self.case_with(lambda r: r["log"].update(dropped=5), cid, "fail")
        self.assertEqual(s["cases"][cid]["verdict"], "fail")
        s = self.case_with(lambda r: r["failure"].update(expected=1, observed=True), cid, "fail")
        self.assertEqual(s["problems_total"], 0, "1 and true are different values")

    def test_outcome_and_process_must_agree(self):
        cid = "q00.sample.loss"
        self.assertInvalid(self.case_with(lambda r: r["process"].update(timed_out=False), cid, "timeout"), cid, "contradiction")
        self.assertInvalid(self.case_with(lambda r: r["process"].update(exit_code=0), cid, "crash"), cid, "contradiction")
        self.assertInvalid(self.case_with(lambda r: r["process"].update(timed_out=True), cid, "fail"), cid, "contradiction")
        self.assertInvalid(self.case_with(lambda r: r["process"].update(timed_out=True), cid, "cancelled"), cid, "contradiction")
        self.assertEqual(self.case_with(lambda r: None, cid, "crash")["cases"][cid]["verdict"], "crash")

    def test_structure_is_strict(self):
        cid = "q00.sample.loss"
        self.assertInvalid(self.case_with(lambda r: r.update(extra="x")), cid, "unknown_field")
        self.assertInvalid(self.case_with(lambda r: r.pop("seed")), cid, "missing_field")
        self.assertInvalid(self.case_with(lambda r: r.update(outcome="passed")), cid, "bad_outcome")
        self.assertInvalid(self.case_with(lambda r: r.update(outcome=["pass"])), cid, "bad_outcome")
        self.assertInvalid(self.case_with(lambda r: r.update(started_mono_ns=5000)), cid, "bad_time")
        self.assertInvalid(self.case_with(lambda r: r.update(started_mono_ns=True)), cid, "bad_time")
        self.assertInvalid(self.case_with(lambda r: r.update(process={"exit_code": 0}), "q00.sample.loss"), cid, "missing_field")
        blocked = self.case_with(lambda r: r.update(process={"exit_code": 0, "timed_out": False}), cid, "blocked")
        self.assertInvalid(blocked, cid, "unknown_field")
        self.assertInvalid(self.case_with(lambda r: r.pop("reason"), cid, "blocked"), cid, "missing_field")
        self.assertInvalid(self.case_with(lambda r: r.update(reason=""), cid, "blocked"), cid, "bad_field")
        self.assertEqual(self.case_with(lambda r: None, cid, "blocked")["cases"][cid]["verdict"], "blocked")

    def test_single_field_corruption_of_a_pass_record_never_qualifies(self):
        cid = "q00.sample.loss"
        base = self.run_.rec(cid)
        others = [r for r in self.run_.all_pass() if r["case_id"] != cid]
        self.assertTrue(agg(self.run_.build(others + [base]))["qualified"])
        junk = (None, True, "", "x", [], {})
        checked = 0
        for key in sorted(base):
            variants = [("delete", None)] + [("set", j) for j in junk]
            for how, value in variants:
                mutated = json.loads(json.dumps(base))
                if how == "delete":
                    del mutated[key]
                else:
                    if mutated[key] == value and type(mutated[key]) is type(value):
                        continue
                    mutated[key] = value
                with self.subTest(key=key, how=how, value=value):
                    s = agg(self.run_.build(others + [mutated]))
                    self.assertFalse(s["qualified"])
                    self.assertEqual(sum(s["counts"].values()), s["denominator"]["total"])
                    checked += 1
        self.assertGreater(checked, 100)


class TestWriter(Base):
    def header_kwargs(self):
        return dict(run_id="run-a", suite="s", tier="smoke", seed=RUN_SEED,
                    expected=EXPECTED, versions=VERSIONS, artifacts=ARTIFACTS)

    def test_state_machine(self):
        w = R.StreamWriter(io.BytesIO())
        with self.assertRaises(R.ReceiptError):
            w.write_case(case_id="x")
        with self.assertRaises(R.ReceiptError):
            w.write_footer()
        w.write_header(**self.header_kwargs())
        with self.assertRaises(R.ReceiptError):
            w.write_header(**self.header_kwargs())
        with self.assertRaises(R.ReceiptError):
            w.write_case(schema="x", case_id="x")
        w.write_footer()
        with self.assertRaises(R.ReceiptError):
            w.write_case(case_id="x")
        with self.assertRaises(R.ReceiptError):
            w.write_footer()

    def test_invalid_header_is_refused(self):
        for over in ({"tier": "nightly"}, {"seed": True}, {"seed": R.U64}, {"versions": {}},
                     {"run_id": ""}, {"artifacts": []}):
            with self.subTest(over=over):
                buf = io.BytesIO()
                with self.assertRaises(R.ReceiptError):
                    R.StreamWriter(buf).write_header(**{**self.header_kwargs(), **over})
                self.assertEqual(buf.getvalue(), b"")

    def test_unserializable_and_oversized_records_leave_the_writer_usable_and_the_run_unqualified(self):
        buf = io.BytesIO()
        w = R.StreamWriter(buf, max_line_bytes=4096)
        w.write_header(**self.header_kwargs())
        before = len(buf.getvalue())
        good = [{k: v for k, v in r.items() if k not in ("schema", "kind")} for r in self.run_.all_pass()]
        with self.assertRaises(R.ReceiptError):
            w.write_case(**{**good[0], "note": float("nan")})
        with self.assertRaises(R.ReceiptError):
            w.write_case(**{**good[0], "note": "x" * 5000})
        self.assertEqual(len(buf.getvalue()), before, "nothing was written for refused records")
        for g in good[1:]:
            w.write_case(**g)
        w.write_footer()
        s = agg(buf.getvalue())
        self.assertFalse(s["qualified"])
        self.assertEqual(s["cases"][good[0]["case_id"]]["verdict"], "not_run")

    def test_full_disk_at_any_byte_poisons_the_writer_and_never_qualifies(self):
        run = Run(SMALL)
        recs = [{k: v for k, v in r.items() if k not in ("schema", "kind")} for r in run.all_pass()]

        def emit(fp):
            w = R.StreamWriter(fp)
            w.write_header(run_id="run-a", suite="s", tier="smoke", seed=RUN_SEED,
                           expected=SMALL, versions=VERSIONS, artifacts=ARTIFACTS)
            for r in recs:
                w.write_case(**r)
            w.write_footer()
            return w

        reference = io.BytesIO()
        emit(reference)
        full = reference.getvalue()
        self.assertTrue(agg(full, SMALL)["qualified"], "unlimited writer output must qualify")

        class Limited:
            def __init__(self, limit):
                self.buf = bytearray()
                self.limit = limit

            def write(self, b):
                room = self.limit - len(self.buf)
                if len(b) > room:
                    self.buf += b[: max(room, 0)]  # torn partial write
                    raise OSError(errno.ENOSPC, "No space left on device")
                self.buf += b
                return len(b)

            def flush(self):
                pass

        for limit in list(range(0, len(full) - 1, 13)) + [len(full) - 1]:
            f = Limited(limit)
            with self.assertRaises(OSError, msg=f"limit {limit}"):
                emit(f)
            s = agg(bytes(f.buf), SMALL)
            self.assertFalse(s["qualified"], f"limit {limit} produced a qualified stream")
        # The poisoned writer refuses to continue, so a footer can never be appended.
        f = Limited(len(full) // 2)
        w = R.StreamWriter(f)
        with self.assertRaises(OSError):
            w.write_header(run_id="run-a", suite="s", tier="smoke", seed=RUN_SEED,
                           expected=SMALL, versions=VERSIONS, artifacts=ARTIFACTS)
            for r in recs:
                w.write_case(**r)
        with self.assertRaises(R.ReceiptError):
            w.write_footer()
        with self.assertRaises(R.ReceiptError):
            w.write_case(**recs[0])

    def test_flush_failure_also_poisons_the_writer(self):
        class FlushFails(io.BytesIO):
            def flush(self):
                raise OSError(errno.ENOSPC, "No space left on device")

        w = R.StreamWriter(FlushFails())
        with self.assertRaises(OSError):
            w.write_header(**self.header_kwargs())
        with self.assertRaises(R.ReceiptError):
            w.write_footer()

    def test_durable_file_roundtrip_in_a_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="ffw receipts ") as d:
            path = os.path.join(d, "run dir", "stream.jsonl")
            os.makedirs(os.path.dirname(path))
            with open(path, "wb") as fh:
                w = R.StreamWriter(fh, durable=True)
                w.write_header(**self.header_kwargs())
                for r in self.run_.all_pass():
                    w.write_case(**{k: v for k, v in r.items() if k not in ("schema", "kind")})
                w.write_footer()
            self.assertTrue(R.aggregate_path(path, EXPECTED)["qualified"])


class TestReportingAndBounds(Base):
    def test_failure_detail_is_bounded_but_counts_stay_exact(self):
        exp = {f"bulk.{i:03d}": {"mandatory": True, "proof_class": "host-simulation"} for i in range(300)}
        run = Run(exp)
        s = agg(run.build([run.rec(c, "fail") for c in exp]), exp, max_failures=10)
        self.assertEqual(s["counts"]["fail"], 300)
        self.assertEqual(len(s["failures"]), 10)
        self.assertEqual(s["failures_omitted"], 290)
        text = R.render_summary(s)
        self.assertIn("290 more", text)
        self.assertLessEqual(len(text.splitlines()), 60)

    def test_problem_list_is_bounded_but_total_is_exact(self):
        lines = self.run_.lines(self.run_.all_pass()) + [b"garbage"] * 500
        s = agg(seal(lines), max_problems=20)
        self.assertEqual(len(s["problems"]), 20)
        self.assertGreaterEqual(s["problems_total"], 500)
        self.assertEqual(s["problems_omitted"], s["problems_total"] - 20)
        self.assertIn("more problems omitted", R.render_summary(s))

    def test_human_summary_shows_replay_expected_observed_and_first_cause(self):
        argv = ["run-suite", "--out", "/tmp/a b/c", "--seed", str(RUN_SEED), "--case", "q00.sample.loss"]
        bad = self.run_.rec("q00.sample.loss", "fail")
        bad["replay"]["argv"] = argv
        recs = self.run_.all_pass(skip=("q00.sample.loss",)) + [bad]
        s = agg(self.run_.build(recs))
        text = R.render_summary(s)
        self.assertIn("NOT QUALIFIED", text)
        self.assertIn("'/tmp/a b/c'", text, "replay command must be shell-quoted")
        self.assertIn('expected={"samples": 8}', text)
        self.assertIn('observed={"samples": 7}', text)
        self.assertIn("first_cause=log#3:sample.gap", text)
        self.assertIn("fail=1", text)

    def test_bad_caller_input_raises_instead_of_guessing(self):
        good = self.run_.build(self.run_.all_pass())
        for bad in (0, -1, True, None):
            with self.assertRaises(R.ReceiptError):
                agg(good, max_attempts=bad)
        with self.assertRaises(R.ReceiptError):
            R.aggregate("not bytes", EXPECTED)
        self.assertTrue(agg(good, max_attempts=1)["qualified"])

    def test_expected_set_validation(self):
        ok = {"a": {"mandatory": True, "proof_class": "host-simulation"}}
        self.assertEqual(R.normalize_expected(ok), {"a": R.Spec(True, "host-simulation", False, None, None)})
        canary_ok = {"c": {"mandatory": True, "proof_class": "host-simulation", "canary": True,
                           "oracle": "epoch", "violation": "stale_epoch_applied"}}
        self.assertEqual(R.normalize_expected(canary_ok)["c"].violation, "stale_epoch_applied")
        bad_sets = [
            {}, [], None,
            {"": ok["a"]}, {" a": ok["a"]}, {"a b": ok["a"]},
            {"a": {"mandatory": True}},
            {"a": {"proof_class": "host-simulation"}},
            {"a": {"mandatory": "yes", "proof_class": "host-simulation"}},
            {"a": {"mandatory": True, "proof_class": "fixture"}},
            {"a": {"mandatory": True, "proof_class": "unit"}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "canary": 1}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "extra": 1}},
            # a canary must say which oracle and violation it expects; non-canaries must not
            {"a": {"mandatory": True, "proof_class": "host-simulation", "canary": True}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "canary": True, "oracle": "epoch"}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "canary": True, "violation": "x"}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "canary": True, "oracle": "", "violation": "x"}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "oracle": "epoch"}},
            {"a": {"mandatory": True, "proof_class": "host-simulation", "violation": "x"}},
        ]
        for bad in bad_sets:
            with self.subTest(bad=bad), self.assertRaises(R.ReceiptError):
                R.normalize_expected(bad)

    def test_registry_digest_is_order_independent_and_sensitive(self):
        a = R.registry_digest(EXPECTED)
        self.assertEqual(a, R.registry_digest(dict(reversed(list(EXPECTED.items())))))
        for case in EXPECTED:
            changed = {**EXPECTED, case: {**EXPECTED[case], "mandatory": not EXPECTED[case]["mandatory"]}}
            self.assertNotEqual(a, R.registry_digest(changed), case)
        renamed = {("x." + k): v for k, v in EXPECTED.items()}
        self.assertNotEqual(a, R.registry_digest(renamed))
        canary = "q00.canary.stale-epoch"
        for field, value in (("oracle", "command"), ("violation", "double_applied")):
            changed = {**EXPECTED, canary: {**EXPECTED[canary], field: value}}
            self.assertNotEqual(a, R.registry_digest(changed), field)


class TestPathsAndCli(Base):
    def run_cli(self, cwd, *args):
        return subprocess.run([sys.executable, "-B", "-I", RECEIPTS_PATH, *args], cwd=cwd,
                              capture_output=True, text=True, timeout=120)

    def test_unreadable_oversized_and_directory_paths_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="ffw receipts ") as d:
            s = R.aggregate_path(os.path.join(d, "missing.jsonl"), EXPECTED)
            self.assertUnqualified(s, "stream_unreadable")
            s = R.aggregate_path(d, EXPECTED)
            self.assertUnqualified(s, "stream_unreadable")
            path = os.path.join(d, "big.jsonl")
            data = self.run_.build(self.run_.all_pass())
            with open(path, "wb") as fh:
                fh.write(data)
            self.assertUnqualified(R.aggregate_path(path, EXPECTED, max_bytes=100), "stream_too_large")
            self.assertTrue(R.aggregate_path(path, EXPECTED)["qualified"])
            for s in (R.aggregate_path(os.path.join(d, "missing.jsonl"), EXPECTED),):
                self.assertEqual(sum(s["counts"].values()), 4)
                self.assertEqual(s["counts"]["not_run"], 4)

    def test_cli_exit_codes_from_a_foreign_cwd_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="ffw cli ") as d:
            work = os.path.join(d, "some dir")
            os.makedirs(work)
            stream = os.path.join(work, "stream.jsonl")
            expected = os.path.join(work, "expected.json")
            with open(expected, "w", encoding="utf-8") as fh:
                json.dump(EXPECTED, fh)
            data = self.run_.build(self.run_.all_pass())
            with open(stream, "wb") as fh:
                fh.write(data)
            ok = self.run_cli(work, "verify", stream, "--expected", expected, "--no-floor")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("RECEIPTS QUALIFIED", ok.stdout)

            js = self.run_cli(work, "verify", stream, "--expected", expected, "--no-floor", "--json")
            self.assertEqual(js.returncode, 0)
            self.assertTrue(json.loads(js.stdout)["qualified"])

            with open(stream, "wb") as fh:
                fh.write(data[:-40])
            bad = self.run_cli(work, "verify", stream, "--expected", expected, "--no-floor")
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            self.assertIn("NOT QUALIFIED", bad.stdout)

            dup = os.path.join(work, "dup.json")
            with open(dup, "w", encoding="utf-8") as fh:
                fh.write('{"a.one":{"mandatory":true,"proof_class":"host-simulation"},'
                         '"a.one":{"mandatory":false,"proof_class":"host-simulation"}}')
            # --no-floor on each, so the exit 2 can only come from the cause under test
            self.assertEqual(self.run_cli(work, "verify", stream, "--expected", dup, "--no-floor").returncode, 2)
            self.assertEqual(self.run_cli(work, "verify", stream, "--expected", os.path.join(work, "nope.json"), "--no-floor").returncode, 2)
            self.assertEqual(self.run_cli(work, "verify", stream, "--expected", expected, "--no-floor", "--max-attempts", "0").returncode, 2)

    def test_verify_requires_an_explicit_floor_decision(self):
        with tempfile.TemporaryDirectory(prefix="ffw floor decision ") as d:
            stream, expected, floor = (os.path.join(d, n) for n in ("s.jsonl", "e.json", "f.json"))
            with open(stream, "wb") as fh:
                fh.write(self.run_.build(self.run_.all_pass()))
            with open(expected, "w", encoding="utf-8") as fh:
                json.dump(EXPECTED, fh)
            with open(floor, "w", encoding="utf-8") as fh:
                json.dump([c for c, sp in EXPECTED.items() if sp["mandatory"]], fh)   # a floor names mandatory cases only
            # planted negatives: forgetting the floor, or asking for both, is a usage error, never a verdict
            forgot = self.run_cli(d, "verify", stream, "--expected", expected)
            self.assertEqual(forgot.returncode, 2, forgot.stdout + forgot.stderr)
            self.assertIn("--require", forgot.stderr)
            self.assertIn("--no-floor", forgot.stderr)
            self.assertNotIn("QUALIFIED", forgot.stdout)
            both = self.run_cli(d, "verify", stream, "--expected", expected, "--require", floor, "--no-floor")
            self.assertEqual(both.returncode, 2, both.stdout + both.stderr)
            self.assertNotIn("QUALIFIED", both.stdout)
            # permitted positives on the same stream: either explicit choice verifies, and says which it made
            with_floor = self.run_cli(d, "verify", stream, "--expected", expected, "--require", floor)
            self.assertEqual(with_floor.returncode, 0, with_floor.stdout + with_floor.stderr)
            self.assertIn("required floor: 3 cases", with_floor.stdout)
            without = self.run_cli(d, "verify", stream, "--expected", expected, "--no-floor", "--json")
            self.assertEqual(without.returncode, 0, without.stdout + without.stderr)
            self.assertIsNone(json.loads(without.stdout)["required"], "a floorless verdict must say it had no floor")


class TestIncompleteOracleCanaries(Base):
    """An oracle that did not finish, or fired the wrong thing, proves nothing.

    The reproductions behind these tests used real oracles.py verdicts: a
    hand mapping that turned "incomplete" into mismatches >= 1 was accepted as
    a canary detection, as was a verdict with finalized=False.
    """

    CID = "q00.canary.stale-epoch"

    def canary(self, block):
        r = self.run_.rec(self.CID)
        r["oracle"] = block
        recs = [x for x in self.run_.all_pass() if x["case_id"] != self.CID] + [r]
        return agg(self.run_.build(recs))

    def good_block(self, **over):
        return oracle_block("epoch", status="failed", kinds={"stale_epoch_applied": 1}, kind="state", **over)

    def test_genuine_detection_is_still_a_pass(self):
        self.assertTrue(self.canary(self.good_block())["qualified"])
        extra = oracle_block("epoch", status="failed", kinds={"stale_epoch_applied": 2, "phantom_application": 1}, kind="state")
        self.assertTrue(self.canary(extra)["qualified"], "extra consequential kinds are allowed")
        via_adapter = R.oracle_block_from_verdict(verdict(status="failed", kinds={"stale_epoch_applied": 1}), kind="state")
        self.assertTrue(self.canary(via_adapter)["qualified"])

    def test_incomplete_oracle_is_not_a_detection_even_with_mismatches_claimed(self):
        hand_mapped = oracle_block("epoch", status="incomplete", reasons=["fence_not_exercised"], kind="state")
        hand_mapped["mismatches"] = 1  # the "incomplete -> mismatches >= 1" mapping
        s = self.canary(hand_mapped)
        self.assertInvalid(s, self.CID, "oracle_incomplete")
        self.assertIn("canary_not_detected", case_codes(s, self.CID))
        honest = R.oracle_block_from_verdict(
            verdict(status="incomplete", reasons=["fence_not_exercised"]), kind="state")
        s = self.canary(honest)
        self.assertInvalid(s, self.CID, "oracle_incomplete")
        self.assertIn("canary_not_detected", case_codes(s, self.CID))

    def test_never_finalized_oracle_with_a_violation_is_not_a_detection(self):
        unfinal = R.oracle_block_from_verdict(
            verdict(status="failed", kinds={"stale_epoch_applied": 1}, finalized=False), kind="state")
        self.assertEqual(unfinal["incomplete_reasons"], ["not_finalized"])
        self.assertInvalid(self.canary(unfinal), self.CID, "oracle_incomplete")
        lost_tracking = R.oracle_block_from_verdict(
            verdict(status="failed", kinds={"stale_epoch_applied": 1}, reasons=["tracking_overflow"]), kind="state")
        self.assertInvalid(self.canary(lost_tracking), self.CID, "oracle_incomplete")

    def test_wrong_oracle_or_wrong_violation_kind_is_not_the_planted_defect(self):
        wrong_oracle = oracle_block("command", status="failed", kinds={"stale_epoch_applied": 1}, kind="state")
        self.assertInvalid(self.canary(wrong_oracle), self.CID, "canary_wrong_oracle")
        wrong_kind = oracle_block("epoch", status="failed", kinds={"malformed_event": 1}, kind="state")
        self.assertInvalid(self.canary(wrong_kind), self.CID, "canary_wrong_violation")
        self.assertTrue(self.canary(self.good_block())["qualified"])

    def test_canary_needs_a_failed_status_and_at_least_one_violation(self):
        for block in (oracle_block("epoch", status="passed", kind="state"),
                      oracle_block("epoch", status="failed", kind="state")):
            with self.subTest(status=block["status"]):
                self.assertInvalid(self.canary(block), self.CID, "canary_not_detected")

    def test_each_incompleteness_signal_is_sufficient_alone(self):
        kinds = {"stale_epoch_applied": 1}
        for name, block in (
            ("status only", oracle_block("epoch", status="incomplete", kinds=kinds, kind="state")),
            ("unfinalized only", oracle_block("epoch", status="failed", kinds=kinds, finalized=False, kind="state")),
            ("reasons only", oracle_block("epoch", status="failed", kinds=kinds, reasons=["tracking_overflow"], kind="state")),
        ):
            with self.subTest(name):
                self.assertInvalid(self.canary(block), self.CID, "oracle_incomplete")
        self.assertTrue(self.canary(oracle_block("epoch", status="failed", kinds=kinds, kind="state"))["qualified"])

    def test_oracle_block_fields_must_be_internally_consistent(self):
        cases = {
            "mismatches != sum(kinds)": lambda b: b.update(mismatches=3),
            "zero count kind": lambda b: b.update(violation_kinds={"stale_epoch_applied": 0}, mismatches=0),
            "kinds not a mapping": lambda b: b.update(violation_kinds=["stale_epoch_applied"]),
            "reasons not a list": lambda b: b.update(incomplete_reasons="none"),
            "reason not a string": lambda b: b.update(incomplete_reasons=[7]),
            "finalized not a bool": lambda b: b.update(finalized="yes"),
            "finalized missing": lambda b: b.pop("finalized"),
            "status unknown": lambda b: b.update(status="done"),
            "status missing": lambda b: b.pop("status"),
            "kinds missing": lambda b: b.pop("violation_kinds"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                block = self.good_block()
                mutate(block)
                self.assertFalse(self.canary(block)["qualified"])
        self.assertTrue(self.canary(self.good_block())["qualified"])

    def test_old_hand_mapped_block_without_status_fields_is_rejected(self):
        old = {"name": "epoch", "kind": "state", "independent": True, "checks": 5, "mismatches": 1}
        s = self.canary(old)
        self.assertInvalid(s, self.CID, "missing_field")

    def test_non_canary_pass_also_needs_a_finished_passing_oracle(self):
        cid = "q00.sample.loss"

        def case(block):
            r = self.run_.rec(cid)
            r["oracle"] = block
            recs = [x for x in self.run_.all_pass() if x["case_id"] != cid] + [r]
            return agg(self.run_.build(recs))

        self.assertTrue(case(oracle_block())["qualified"])
        self.assertInvalid(case(oracle_block(status="incomplete", reasons=["no_evidence"])), cid, "oracle_incomplete")
        self.assertInvalid(case(oracle_block(finalized=False, reasons=["not_finalized"])), cid, "oracle_incomplete")
        self.assertInvalid(case(oracle_block(reasons=["completeness_unchecked_total_frames_unknown"])), cid, "oracle_incomplete")
        # Each signal is sufficient on its own: an oracle cannot clear them by omitting the others.
        self.assertInvalid(case(oracle_block(status="incomplete")), cid, "oracle_incomplete")
        self.assertInvalid(case(oracle_block(finalized=False)), cid, "oracle_incomplete")
        self.assertInvalid(case(oracle_block(status="failed", kinds={"lost_samples": 1})), cid, "pass_with_mismatches")
        self.assertInvalid(case(oracle_block(kinds={"lost_samples": 1})), cid, "pass_with_mismatches")

    def test_honestly_reported_incomplete_canary_is_valid_evidence_that_blocks(self):
        blocked = self.run_.rec(self.CID, "blocked", reason="oracle_incomplete: fence_not_exercised")
        failed = self.run_.rec(self.CID, "fail")
        failed["failure"].update(expected="oracle detects stale epoch", observed="oracle incomplete: fence_not_exercised")
        for rec, verdict_name in ((blocked, "blocked"), (failed, "fail")):
            with self.subTest(verdict=verdict_name):
                recs = [x for x in self.run_.all_pass() if x["case_id"] != self.CID] + [rec]
                s = agg(self.run_.build(recs))
                self.assertEqual(s["problems_total"], 0, s["problems"])
                self.assertEqual(s["cases"][self.CID]["verdict"], verdict_name)
                self.assertFalse(s["qualified"])


class TestOracleBlockFromVerdict(unittest.TestCase):
    def test_copies_what_the_oracle_reported(self):
        v = verdict(oracle="epoch", status="failed", kinds={"stale_epoch_applied": 2}, relevant=44)
        b = R.oracle_block_from_verdict(v, kind="state")
        self.assertEqual(b, {
            "name": "epoch", "kind": "state", "independent": True, "checks": 44, "mismatches": 2,
            "status": "failed", "finalized": True, "incomplete_reasons": [],
            "violation_kinds": {"stale_epoch_applied": 2}})
        self.assertEqual(R.oracle_block_from_verdict(v, kind="state", checks=7)["checks"], 7)
        b["violation_kinds"]["x"] = 1  # the block is a copy, not a view of the verdict
        self.assertEqual(v["violation_kinds"], {"stale_epoch_applied": 2})

    def test_incomplete_and_passed_verdicts_map_without_inventing_mismatches(self):
        inc = R.oracle_block_from_verdict(verdict(status="incomplete", reasons=["no_evidence"], relevant=0), kind="sample")
        self.assertEqual((inc["status"], inc["mismatches"], inc["incomplete_reasons"]), ("incomplete", 0, ["no_evidence"]))
        ok = R.oracle_block_from_verdict(verdict(status="passed"), kind="sample")
        self.assertEqual((ok["status"], ok["mismatches"], ok["violation_kinds"]), ("passed", 0, {}))

    def test_contradictory_or_malformed_verdicts_are_refused(self):
        good = verdict(status="failed", kinds={"k": 1})
        bad = {
            "wrong schema": {**good, "schema": "ffw.oracle_verdict.v2"},
            "unknown status": {**good, "status": "done"},
            "count != kinds": {**good, "violation_count": 2},
            "failed without violations": verdict(status="failed"),
            "violations but passed": {**good, "status": "passed"},
            "violations but incomplete": {**good, "status": "incomplete"},
            "passed with reasons": verdict(status="passed", reasons=["no_evidence"]),
            "passed not finalized": {**verdict(status="passed"), "finalized": False},
            "incomplete without reason": verdict(status="incomplete"),
            "finalized not bool": {**good, "finalized": 1},
            "kinds zero count": {**good, "violation_kinds": {"k": 0}, "violation_count": 0},
            "reasons not list": {**good, "incomplete_reasons": "x"},
            "missing oracle": {k: v for k, v in good.items() if k != "oracle"},
        }
        for name, v in bad.items():
            with self.subTest(name), self.assertRaises(R.ReceiptError):
                R.oracle_block_from_verdict(v, kind="state")
        with self.assertRaises(R.ReceiptError):
            R.oracle_block_from_verdict("not a mapping", kind="state")
        for kw in ({"kind": "log"}, {"kind": "banana"}, {"kind": "state", "independent": "yes"},
                   {"kind": "state", "checks": -1}, {"kind": "state", "checks": True}):
            with self.subTest(kw=kw), self.assertRaises(R.ReceiptError):
                R.oracle_block_from_verdict(good, **kw)
        R.oracle_block_from_verdict(good, kind="state")


class TestRequiredFloor(Base):
    """A registry shrunk or weakened by whoever also writes the stream is
    self-consistent; only an independent floor can see it."""

    GUEST = "e07.boot.guest"
    CANARY = "q00.canary.stale-epoch"
    FLOOR = {GUEST: {"proof_class": "guest-execution"},
             CANARY: {"canary": True, "oracle": "epoch", "violation": "stale_epoch_applied"},
             "q00.sample.loss": {}}

    def stream_for(self, registry, skip=()):
        run = Run(registry)
        return run.build([run.rec(c) for c in registry if c not in skip])

    def test_floor_met_qualifies_and_is_reported(self):
        s = agg(self.run_.build(self.run_.all_pass()), required=self.FLOOR)
        self.assertTrue(s["qualified"], s["problems"])
        self.assertEqual(s["required"], {"count": 3, "dropped": 0, "demoted": 0, "altered": 0})
        self.assertIn("required floor: 3 cases dropped=0", R.render_summary(s))
        s = agg(self.run_.build(self.run_.all_pass()), required=list(self.FLOOR))
        self.assertTrue(s["qualified"], "a plain list of ids is accepted")
        s = agg(self.run_.build(self.run_.all_pass()))
        self.assertIsNone(s["required"])
        self.assertIn("none supplied", R.render_summary(s))

    def test_silently_dropped_case_is_invisible_without_a_floor_and_caught_with_one(self):
        shrunk = {k: v for k, v in EXPECTED.items() if k != self.GUEST}
        data = self.stream_for(shrunk)
        s = agg(data, shrunk)
        self.assertTrue(s["qualified"], "documented limit: the registry alone cannot know what is missing")
        self.assertEqual(s["denominator"]["total"], 3)
        s = agg(data, shrunk, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_dropped")
        self.assertIn("required_cases_violated:1", s["unqualified_reasons"])
        self.assertEqual(s["required"]["dropped"], 1)
        self.assertTrue(s["complete"], "a floor violation is not a damaged stream")
        self.assertEqual(s["denominator"]["total"], 3, "the denominator stays the supplied registry")

    def test_demoting_a_required_case_to_optional_is_caught(self):
        demoted = {**EXPECTED, self.GUEST: {"mandatory": False, "proof_class": "guest-execution"}}
        data = self.stream_for(demoted, skip=(self.GUEST,))
        s = agg(data, demoted)
        self.assertTrue(s["qualified"], "optional and never run: nothing blocks without a floor")
        self.assertEqual(s["cases"][self.GUEST]["verdict"], "not_run")
        s = agg(data, demoted, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_demoted")
        self.assertEqual(s["required"]["demoted"], 1)

    def test_weakening_a_required_case_is_caught(self):
        weaker_class = {**EXPECTED, self.GUEST: {"mandatory": True, "proof_class": "host-simulation"}}
        s = agg(self.stream_for(weaker_class), weaker_class, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_altered")
        self.assertIn("proof_class", [p for p in s["problems"] if p["code"] == "required_case_altered"][0]["detail"])
        no_canary = {**EXPECTED, self.CANARY: {"mandatory": True, "proof_class": "host-simulation"}}
        s = agg(self.stream_for(no_canary), no_canary, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_altered")
        weaker_kind = {**EXPECTED, self.CANARY: {**EXPECTED[self.CANARY], "violation": "malformed_event"}}
        s = agg(self.stream_for(weaker_kind), weaker_kind, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_altered")
        other_oracle = {**EXPECTED, self.CANARY: {**EXPECTED[self.CANARY], "oracle": "sample"}}
        s = agg(self.stream_for(other_oracle), other_oracle, required=self.FLOOR)
        self.assertUnqualified(s, "required_case_altered")
        self.assertEqual(s["required"]["altered"], 1)

    def test_registry_may_grow_beyond_the_floor(self):
        bigger = {**EXPECTED, "z.extra": {"mandatory": True, "proof_class": "host-simulation"}}
        s = agg(self.stream_for(bigger), bigger, required=self.FLOOR)
        self.assertTrue(s["qualified"], s["problems"])

    def test_floor_is_validated_not_guessed(self):
        data = self.run_.build(self.run_.all_pass())
        for bad in ([], {}, "q00.sample.loss", b"x", 5, [""], ["a b"], [7],
                    {"q00.sample.loss": {"mandatory": True}},
                    {"q00.sample.loss": {"proof_class": "fixture"}},
                    {"q00.sample.loss": {"canary": 1}},
                    {"q00.sample.loss": {"oracle": ""}},
                    {"q00.sample.loss": "x"}):
            with self.subTest(bad=bad), self.assertRaises(R.ReceiptError):
                agg(data, required=bad)
        self.assertTrue(agg(data, required={"q00.sample.loss": None})["qualified"])

    def test_floor_applies_through_aggregate_path(self):
        shrunk = {k: v for k, v in EXPECTED.items() if k != self.GUEST}
        with tempfile.TemporaryDirectory(prefix="ffw floor ") as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "wb") as fh:
                fh.write(self.stream_for(shrunk))
            self.assertTrue(R.aggregate_path(path, shrunk)["qualified"])
            s = R.aggregate_path(path, shrunk, required=[self.GUEST])
            self.assertUnqualified(s, "required_case_dropped")

    def test_cli_require_flag(self):
        shrunk = {k: v for k, v in EXPECTED.items() if k != self.GUEST}
        with tempfile.TemporaryDirectory(prefix="ffw cli floor ") as d:
            def write(name, text):
                path = os.path.join(d, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                return path

            def cli(*args):
                return subprocess.run([sys.executable, "-B", "-I", RECEIPTS_PATH, "verify", *args], cwd=d,
                                      capture_output=True, text=True, timeout=120)

            full_stream = os.path.join(d, "full.jsonl")
            with open(full_stream, "wb") as fh:
                fh.write(self.run_.build(self.run_.all_pass()))
            shrunk_stream = os.path.join(d, "shrunk.jsonl")
            with open(shrunk_stream, "wb") as fh:
                fh.write(self.stream_for(shrunk))
            full_exp, shrunk_exp = write("full.json", json.dumps(EXPECTED)), write("shrunk.json", json.dumps(shrunk))
            floor = write("floor.json", json.dumps(self.FLOOR))

            ok = cli(full_stream, "--expected", full_exp, "--require", floor)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("required floor: 3 cases", ok.stdout)
            self.assertEqual(cli(shrunk_stream, "--expected", shrunk_exp, "--no-floor").returncode, 0, "no floor, no catch")
            bad = cli(shrunk_stream, "--expected", shrunk_exp, "--require", floor)
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            self.assertIn("required_case_dropped", bad.stdout)
            for name, text in (("empty.json", "[]"), ("dup.json", '{"a.b":{},"a.b":{}}'),
                               ("unknown.json", '{"a.b":{"mandatory":true}}'), ("notjson.json", "{")):
                self.assertEqual(cli(full_stream, "--expected", full_exp, "--require", write(name, text)).returncode, 2, name)
            self.assertEqual(cli(full_stream, "--expected", full_exp, "--require", os.path.join(d, "missing.json")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
