"""E06 central-check ingest tests (scripts/e06/checks.py).

The logs here are SYNTHETIC: built in the shape RCH prints (colour codes, a worker line, the remote command with its
trailing --config pair, a cargo Finished line, a remote exit line) with documentation-range addresses and made-up
paths, so no real worker address or local path is in this repository. They show what the verifier does with each
kind of claim; the real run's logs are verified by running the ingest on them (docs/contracts/e06.md), not here.
"""
import importlib.util
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AU = load("ffw_e06_audit_for_checks", os.path.join(ROOT, "scripts", "e06", "audit.py"))
CK = sys.modules["checks"]

REV = "a" * 40
MIPS, PPC = "mips-unknown-linux-musl", "powerpc-unknown-linux-musl"
ESC = "\x1b"


def planned(crate, target, std="std,panic_abort", jobs=2):
    return "RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p %s --target %s -Z build-std=%s%s" % (
        crate, target, std, "" if jobs is None else " -j %d" % jobs)


def log(crate, target, rc=0, std="std,panic_abort", jobs=2, worker="w1", finished="Finished `release` profile [optimized] target(s) in 7.22s",
        extra_config=(), errors=(), warnings=0, second_command=False, drop=()):
    """A synthetic RCH log. `drop` names the line kinds to leave out."""
    cmd = "cargo +nightly check --locked --release -p %s --target %s -Z '%s'%s" % (
        crate, target, "build-std=" + std, "" if jobs is None else " -j %d" % jobs)
    cmd += " --config 'env.RCH_BUILD_SOURCE.value=\"unknown\"' --config 'env.RCH_BUILD_SOURCE.force=true'"
    for item in extra_config:
        cmd += " --config '%s'" % item
    lines = ["", "--- stderr ---"]
    if "worker" not in drop:
        lines.append("  %s[2m2026-01-01T00:00:00Z%s[0m %s[32m INFO%s[0m rch::hook: Selected worker: %s at ubuntu@192.0.2.7 (0 slots remaining)" % (
            ESC, ESC, ESC, ESC, worker))
    if "command" not in drop:
        lines.append("  2026-01-01T00:00:01Z  INFO rch::hook::transfer_orchestration: Executing command remotely: " + cmd)
        if second_command:
            lines.append("  2026-01-01T00:00:02Z  INFO rch::hook::transfer_orchestration: Executing command remotely: " + cmd)
    lines.append("   Syncing /private/tmp/synthetic/home/ws (made-up path) and /home/ubuntu/.rustup/toolchains/nightly")
    lines += ["    %sChecking%s dep-a v0.1.0" % (ESC + "[1;32m", ESC + "[0m"), "    Checking dep-b v0.2.0 (/private/tmp/synthetic/ws/dep-b)"]
    lines += ["warning: unused import `x`"] * warnings
    lines += [e for e in errors]
    if "finished" not in drop and finished:
        lines.append("    " + finished)
    if "exit" not in drop:
        lines.append("  2026-01-01T00:00:09Z  INFO rch::hook::transfer_orchestration: Remote command finished: exit=%d in 8844ms" % rc)
    return "\n".join(lines) + "\n"


def row(crate, target, status="pass", rc=0, worker="w1", rev=REV, evidence=None, note=None):
    return {"crate": crate, "target": target, "status": status,
            "evidence": evidence or "out/%s-%s.log" % (crate, target),
            "note": note if note is not None else "rc=%d worker=%s rev=%s" % (rc, worker, rev)}


POOL = "0123456789abcdef0123456789abcdef"
MANAGED_TARGET = "/data/tmp/rch/fixture/.rch-target-w1-pool-" + POOL


def source_receipt(worker="w1", project="fixture", pool=POOL):
    """Synthetic source-pair receipt; no file list here is evidence of a real source transfer."""
    return {"schema": "rch.source_content_receipt.v1", "worker_id": worker, "build_id": "12345",
            "command_sha256": "a" * 64, "command_exit_code": 0, "root_count": 1,
            "roots": [{"schema": "rch.source_content_root.v1", "ordinal": 0, "project_id": project,
                       "local_root": "/synthetic/fixture", "remote_root": "/data/tmp/rch/source-content-pair-" + pool + "/projects",
                       "root_hash": "b" * 64, "is_primary": True, "mode": "full", "filter_policy": {},
                       "file_count": 0, "byte_count": 0, "files": []}]}


def receipt_line(receipt):
    preimage = {key: receipt[key] for key in ("schema", "worker_id", "build_id", "command_sha256", "command_exit_code", "root_count", "roots")}
    receipt = dict(receipt, receipt_root=hashlib.sha256(json.dumps(preimage, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())
    return "[RCH] source content receipt: " + json.dumps(receipt, ensure_ascii=False, separators=(",", ":"))


def managed_log(crate="alpha", target=MIPS, receipt=None, path=MANAGED_TARGET, passthrough=""):
    """Model the independently inspected RCH rewrite, not an expanded expected plan."""
    text = log(crate, target)
    pair = " --config 'build.build-dir=\"%s\"' --target-dir %s" % (path, path)
    text = text.replace(" --config 'env.RCH_BUILD_SOURCE.value", pair + " --config 'env.RCH_BUILD_SOURCE.value", 1)
    if passthrough:
        text = "\n".join(line + passthrough if "Executing command remotely:" in line else line for line in text.splitlines()) + "\n"
    return (text + "INFO rch::transfer: Rewriting CARGO_TARGET_DIR for remote execution (worker-scoped path): "
            "/synthetic/target -> " + path + "\n" + receipt_line(receipt if receipt is not None else source_receipt()) + "\n")


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.plan, plan_problems = CK.parse_plan([planned("alpha", MIPS), planned("beta", PPC)])
        self.assertEqual(plan_problems, [])

    def put(self, crate, target, text):
        with open(os.path.join(self.dir, "%s-%s.log" % (crate, target)), "w", encoding="utf-8") as fh:
            fh.write(text)

    def good(self):
        self.put("alpha", MIPS, log("alpha", MIPS))
        self.put("beta", PPC, log("beta", PPC))
        return [row("alpha", MIPS), row("beta", PPC)]

    def verify(self, results, rev=REV):
        return CK.verify(self.plan, results, self.dir, rev)

    def only_problem(self, results, needle, rev=REV):
        records, problems = self.verify(results, rev)
        self.assertTrue(any(needle in p for p in problems), (needle, problems))
        return records, problems


class ParsePlanTests(unittest.TestCase):
    def test_a_well_formed_plan_is_read_in_order(self):
        plan, problems = CK.parse_plan([planned("a", MIPS), "", planned("b", PPC, std="core,alloc", jobs=None)])
        self.assertEqual(problems, [])
        self.assertEqual([(p["crate"], p["target"]) for p in plan], [("a", MIPS), ("b", PPC)])

    def test_a_line_that_is_not_a_planned_check_an_empty_plan_and_a_repeat_are_problems(self):
        _, problems = CK.parse_plan([planned("a", MIPS), "cargo build --release"])
        self.assertTrue(any("not a planned cargo check" in p for p in problems), problems)
        _, problems = CK.parse_plan([planned("a", MIPS), planned("a", MIPS)])
        self.assertTrue(any("repeats" in p for p in problems), problems)
        plan, problems = CK.parse_plan(["", "  "])
        self.assertEqual((plan, len(problems)), ([], 1))
        self.assertIn("empty", problems[0])

    def test_a_plan_line_is_not_trusted_to_be_a_different_command_in_disguise(self):
        for bad in (planned("a", MIPS) + " && rm -rf x", planned("a", MIPS).replace("check", "build"),
                    planned("a", MIPS).replace("--locked ", ""), "x " + planned("a", MIPS)):
            plan, problems = CK.parse_plan([bad])
            self.assertEqual(plan, [], bad)
            self.assertTrue(problems, bad)


class ParseLogTests(unittest.TestCase):
    def test_colour_codes_are_stripped_and_every_fact_is_read(self):
        facts = CK.parse_log(log("alpha", MIPS, worker="ts1"))
        self.assertEqual((facts["worker"], facts["rc"], facts["remote_ms"]), ("ts1", 0, 8844))
        self.assertEqual(facts["finished"], ("release", 7.22))
        self.assertEqual((facts["units"], facts["warnings"], facts["errors"], facts["problems"]), (2, 0, [], []))

    def test_rchs_own_config_trailer_is_removed_and_any_other_config_is_kept(self):
        facts = CK.parse_log(log("alpha", MIPS))
        self.assertEqual(facts["argv"], CK.plan_argv(planned("alpha", MIPS)))
        other = CK.parse_log(log("alpha", MIPS, extra_config=("build.jobs=1",)))
        self.assertNotEqual(other["argv"], CK.plan_argv(planned("alpha", MIPS)))
        self.assertEqual(other["argv"][-2:], ["--config", "build.jobs=1"])

    def test_rchs_fixed_debug_env_prefix_preserves_the_exact_cargo_command(self):
        prefix = "env 'CARGO_PROFILE_DEV_DEBUG=line-tables-only' 'CARGO_PROFILE_TEST_DEBUG=line-tables-only' "
        for observed in (prefix, prefix.removeprefix("env ")):
            raw = log("alpha", MIPS).replace("Executing command remotely: cargo ", "Executing command remotely: " + observed + "cargo ")
            facts = CK.parse_log(raw)
            self.assertEqual(facts["problems"], [])
            self.assertEqual(facts["argv"], CK.plan_argv(planned("alpha", MIPS)))

    def test_remote_env_changes_cannot_disguise_a_different_build(self):
        for prefix in ("env RUSTFLAGS=-Awarnings ", "env CARGO_PROFILE_RELEASE_DEBUG=0 ", "RUSTFLAGS=-Awarnings ", "CARGO_PROFILE_DEV_DEBUG=0 ",
                       "env CARGO_PROFILE_DEV_DEBUG=0 ", "env -i ",
                       "env CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_DEV_DEBUG=line-tables-only "):
            raw = log("alpha", MIPS).replace("Executing command remotely: cargo ", "Executing command remotely: " + prefix + "cargo ")
            facts = CK.parse_log(raw)
            self.assertIsNone(facts["argv"], prefix)
            self.assertTrue(any("cannot be read" in p for p in facts["problems"]), prefix)
        for command in ("env cargo check", "env CARGO_PROFILE_DEV_DEBUG=line-tables-only"):
            with self.assertRaises(ValueError):
                CK.remote_argv(command)

    def test_env_prefix_does_not_hide_a_second_command_or_extra_cargo_configuration(self):
        prefix = "env CARGO_PROFILE_DEV_DEBUG=line-tables-only "
        raw = log("alpha", MIPS, second_command=True).replace("Executing command remotely: cargo ", "Executing command remotely: " + prefix + "cargo ")
        self.assertTrue(any("2 command lines" in p for p in CK.parse_log(raw)["problems"]))
        raw = log("alpha", MIPS, extra_config=("build.rustflags=['-Awarnings']",)).replace(
            "Executing command remotely: cargo ", "Executing command remotely: " + prefix + "cargo ")
        self.assertNotEqual(CK.parse_log(raw)["argv"], CK.plan_argv(planned("alpha", MIPS)))

    def test_cargo_prints_long_builds_in_minutes_and_hours(self):
        for text, seconds in (("in 1m 02s", 62.0), ("in 1h 02m 03s", 3723.0), ("in 0.31s", 0.31), ("in 12m 59s", 779.0)):
            facts = CK.parse_log(log("a", MIPS, finished="Finished `release` profile [optimized] target(s) " + text))
            self.assertEqual(facts["finished"], ("release", seconds), text)

    def test_a_log_that_concatenates_two_runs_vouches_for_neither(self):
        facts = CK.parse_log(log("alpha", MIPS, second_command=True))
        self.assertTrue(any("2 command lines" in p for p in facts["problems"]), facts["problems"])

    def test_missing_lines_are_problems_not_defaults(self):
        for kind, word in (("worker", "worker"), ("command", "command"), ("exit", "exit")):
            facts = CK.parse_log(log("alpha", MIPS, drop=(kind,)))
            self.assertTrue(any("0 %s lines" % word in p for p in facts["problems"]), (kind, facts["problems"]))


class ManagedOutputTests(unittest.TestCase):
    def assert_unreadable(self, text):
        facts = CK.parse_log(text)
        self.assertIsNone(facts["argv"])
        self.assertTrue(any("cannot be read" in p for p in facts["problems"]), facts["problems"])

    def test_only_the_exact_witness_bound_pair_is_removed(self):
        facts = CK.parse_log(managed_log())
        self.assertEqual(facts["problems"], [])
        self.assertEqual(facts["argv"], CK.plan_argv(planned("alpha", MIPS)))
        # A bare command string has no independent authority for an output-path exception.
        command = next(line.split("Executing command remotely: ", 1)[1] for line in managed_log().splitlines()
                       if "Executing command remotely:" in line)
        self.assertNotEqual(CK.remote_argv(command), CK.plan_argv(planned("alpha", MIPS)))

    def test_the_cargo_separator_and_all_compiler_arguments_survive(self):
        tail = " -- --no-deps -F unsafe_code --config 'env.RCH_LITERAL.force=true'"
        text = managed_log(passthrough=tail).replace("cargo +nightly check ", "cargo +nightly clippy ")
        facts = CK.parse_log(text)
        self.assertEqual(facts["problems"], [])
        expected = CK.plan_argv(planned("alpha", MIPS).replace(" check ", " clippy "))
        self.assertEqual(facts["argv"], expected + ["--", "--no-deps", "-F", "unsafe_code", "--config", "env.RCH_LITERAL.force=true"])
        # A compiler argument that looks like Cargo's output override is never stripped or used as authority.
        text = log("alpha", MIPS)
        text = "\n".join(line + " -- --config 'build.build-dir=\"/literal\"'" if "Executing command remotely:" in line else line
                         for line in text.splitlines())
        facts = CK.parse_log(text)
        self.assertEqual(facts["problems"], [])
        self.assertEqual(facts["argv"][-3:], ["--", "--config", 'build.build-dir="/literal"'])

    def test_each_missing_or_duplicate_witness_prevents_normalization(self):
        text = managed_log()
        markers = ("Selected worker:", "Rewriting CARGO_TARGET_DIR", "[RCH] source content receipt:", "Remote command finished:")
        for marker in markers:
            witness = next(line for line in text.splitlines() if marker in line)
            for bad in (text.replace(witness + "\n", ""), text + witness + "\n"):
                with self.subTest(marker=marker, duplicated=bad.startswith(text)):
                    self.assert_unreadable(bad)
        self.assert_unreadable(text + "INFO rch::transfer: Rewriting CARGO_TARGET_DIR for remote execution (worker-scoped path): malformed\n")

    def test_a_different_worker_pool_project_or_base_cannot_bind_the_pair(self):
        variants = [managed_log().replace("Selected worker: w1 at", "Selected worker: w2 at"),
                    managed_log(path=MANAGED_TARGET.replace("w1-pool", "w2-pool")),
                    managed_log(path=MANAGED_TARGET.replace(POOL, "f" * 32)),
                    managed_log(path=MANAGED_TARGET.replace("/data/tmp/rch/", "/elsewhere/rch/")),
                    managed_log(receipt=source_receipt(worker="w2")),
                    managed_log(receipt=source_receipt(project="other")),
                    managed_log(receipt=source_receipt(pool="f" * 32))]
        for bad in variants:
            with self.subTest(index=variants.index(bad)):
                self.assert_unreadable(bad)

    def test_the_two_output_options_must_agree_and_be_adjacent(self):
        text = managed_log()
        for old, new in (("--target-dir " + MANAGED_TARGET, "--target-dir /unmanaged"),
                         ("--target-dir " + MANAGED_TARGET, ""),
                         ("--target-dir " + MANAGED_TARGET, "--target-dir=" + MANAGED_TARGET),
                         ("--target-dir " + MANAGED_TARGET, "--target-dir " + MANAGED_TARGET + " --target-dir " + MANAGED_TARGET),
                         ("--target-dir " + MANAGED_TARGET, "--config 'build.jobs=1' --target-dir " + MANAGED_TARGET)):
            with self.subTest(new=new):
                self.assert_unreadable(text.replace(old, new, 1))

    def test_paths_with_traversal_empty_components_backslashes_or_toml_injection_are_not_managed(self):
        for path in (MANAGED_TARGET.replace("/fixture/", "/fixture/../fixture/"),
                     MANAGED_TARGET.replace("/fixture/", "/fixture//"),
                     MANAGED_TARGET.replace("/fixture/", "/./fixture/"),
                     MANAGED_TARGET.replace("/fixture/", "/fixture\\evil/"),
                     "relative/" + MANAGED_TARGET.lstrip("/")):
            with self.subTest(path=path):
                self.assert_unreadable(managed_log(path=path))
        self.assert_unreadable(managed_log().replace('build.build-dir="' + MANAGED_TARGET + '"',
                                                    'build.build-dir="' + MANAGED_TARGET + '"\nbuild.rustflags=["-Awarnings"]', 1))

    def test_receipt_digest_shape_status_and_primary_are_not_advisory(self):
        for field, value in (("schema", "unknown"), ("root_count", 2), ("root_count", True), ("command_exit_code", 101),
                             ("command_exit_code", False), ("command_sha256", "not-a-hash"), ("build_id", "unknown")):
            receipt = source_receipt(); receipt[field] = value
            with self.subTest(field=field, value=value):
                self.assert_unreadable(managed_log(receipt=receipt))
        for primary in (False, "true", 1):
            receipt = source_receipt(); receipt["roots"][0]["is_primary"] = primary
            self.assert_unreadable(managed_log(receipt=receipt))
        receipt = source_receipt(); receipt["roots"].append(dict(receipt["roots"][0])); receipt["root_count"] = 2
        self.assert_unreadable(managed_log(receipt=receipt))
        # Change a valid hash without repairing its independent canonical receipt digest.
        self.assert_unreadable(managed_log().replace('"command_sha256":"' + "a" * 64, '"command_sha256":"' + "c" * 64))
        # Duplicate JSON fields cannot silently use last-value-wins parsing.
        self.assert_unreadable(managed_log().replace('"worker_id":"w1"', '"worker_id":"w1","worker_id":"w1"'))

    def test_an_unrecognized_config_or_compiler_change_remains_visible_to_the_plan(self):
        pair = " --config 'build.build-dir=\"" + MANAGED_TARGET + "\"'"
        for extra in (" --config 'build.rustflags=[\"-Awarnings\"]'", " --config 'build.jobs=1'", " --target other-isa"):
            facts = CK.parse_log(managed_log().replace(pair, extra + pair, 1))
            self.assertEqual(facts["problems"], [])
            self.assertNotEqual(facts["argv"], CK.plan_argv(planned("alpha", MIPS)))
            self.assertIn(extra.split()[0], facts["argv"])
        # A duplicate managed config is not merely stripped twice.
        self.assert_unreadable(managed_log().replace(pair, pair + pair, 1))


class VerifyAcceptTests(Base):
    def test_supported_claims_become_records_with_the_logs_own_facts(self):
        records, problems = self.verify(self.good())
        self.assertEqual(problems, [])
        self.assertEqual([(r["crate"], r["target"], r["status"]) for r in records], [("alpha", MIPS, "pass"), ("beta", PPC, "pass")])
        r = records[0]
        self.assertEqual((r["rc"], r["worker"], r["rev"], r["remote_ms"], r["cargo_seconds"], r["units"], r["warnings"], r["errors"]),
                         (0, "w1", REV, 8844, 7.22, 2, 0, 0))
        self.assertEqual(r["command"], planned("alpha", MIPS))
        self.assertEqual(len(r["raw_log_sha256"]), 64)
        self.assertEqual(r["raw_log_bytes"], len(log("alpha", MIPS).encode()))
        self.assertIn(r["raw_log_sha256"], r["evidence"])

    def test_a_genuine_failure_with_a_log_that_says_so_is_a_record_not_a_problem(self):
        self.put("alpha", MIPS, log("alpha", MIPS, rc=101, finished="", errors=[
            "error[E0432]: unresolved import `x` in /private/tmp/synthetic/ws/alpha/src/lib.rs on ubuntu@192.0.2.7"]))
        self.put("beta", PPC, log("beta", PPC))
        results = [row("alpha", MIPS, status="fail", rc=101), row("beta", PPC)]
        records, problems = self.verify(results)
        self.assertEqual(problems, [])
        failed = records[0]
        self.assertEqual((failed["status"], failed["rc"], failed["errors"]), ("fail", 101, 1))
        self.assertIn("error[E0432]", failed["diagnostic"])
        self.assertLessEqual(len(failed["diagnostic"]), CK.DIAGNOSTIC_LIMIT)
        for leaked in ("/private", "192.0.2.7", "ubuntu"):
            self.assertNotIn(leaked, failed["diagnostic"])

    def test_the_record_carries_no_address_path_or_log_line(self):
        records, _ = self.verify(self.good())
        text = json.dumps(records)
        for leaked in ("192.0.2.7", "ubuntu", "/private", "/home", "synthetic", "Selected worker", "Syncing"):
            self.assertNotIn(leaked, text, leaked)

    def test_a_verified_source_pair_still_uses_the_independent_plan_and_redacts_the_witness(self):
        rows = self.good()
        self.put("alpha", MIPS, managed_log())
        records, problems = self.verify(rows)
        self.assertEqual(problems, [])
        self.assertEqual(records[0]["command"], planned("alpha", MIPS))
        public = json.dumps(records)
        for private in (MANAGED_TARGET, "source-content-pair-", "build.build-dir", "receipt_root", "/synthetic"):
            self.assertNotIn(private, public)
        pair = " --config 'build.build-dir=\"" + MANAGED_TARGET + "\"'"
        self.put("alpha", MIPS, managed_log().replace(pair, " --config 'build.jobs=1'" + pair, 1))
        self.only_problem(rows, "not the planned command")


class VerifyRejectTests(Base):
    def test_pass_with_a_nonzero_remote_exit_is_rejected_and_fail_with_exit_zero_is_rejected(self):
        self.good()
        self.put("alpha", MIPS, log("alpha", MIPS, rc=101))
        self.only_problem([row("alpha", MIPS, status="pass", rc=101), row("beta", PPC)], "says pass but the remote exit status is 101")
        self.put("alpha", MIPS, log("alpha", MIPS, rc=0))
        self.only_problem([row("alpha", MIPS, status="fail", rc=0), row("beta", PPC)], "says fail but the remote exit status is 0")

    def test_pass_without_a_finished_line_or_with_error_lines_is_rejected(self):
        self.good()
        self.put("alpha", MIPS, log("alpha", MIPS, drop=("finished",)))
        self.only_problem([row("alpha", MIPS), row("beta", PPC)], "no Finished line")
        self.put("alpha", MIPS, log("alpha", MIPS, errors=["error: could not compile `alpha`"]))
        self.only_problem([row("alpha", MIPS), row("beta", PPC)], "error line(s)")

    def test_a_log_for_another_command_is_rejected(self):
        self.good()
        for kwargs in ({"std": "core,alloc"}, {"jobs": 4}, {"jobs": None}, {"extra_config": ("build.jobs=1",)}):
            self.put("alpha", MIPS, log("alpha", MIPS, **kwargs))
            self.only_problem([row("alpha", MIPS), row("beta", PPC)], "not the planned command")
        self.put("alpha", MIPS, log("other", MIPS))                      # a log of a different crate under alpha's name
        self.only_problem([row("alpha", MIPS), row("beta", PPC)], "not the planned command")
        self.put("alpha", MIPS, log("alpha", PPC))                       # the right crate for the other target
        self.only_problem([row("alpha", MIPS), row("beta", PPC)], "not the planned command")

    def test_a_note_that_disagrees_with_the_log_or_the_expected_revision_is_rejected(self):
        self.good()
        self.only_problem([row("alpha", MIPS, rc=1), row("beta", PPC)], "rc=1")
        self.only_problem([row("alpha", MIPS, worker="w2"), row("beta", PPC)], "worker=w2")
        self.only_problem([row("alpha", MIPS, rev="b" * 40), row("beta", PPC)], "rev=" + "b" * 40)
        self.only_problem([row("alpha", MIPS, note="all good"), row("beta", PPC)], "the note has no rc=")
        # and the revision expected by the caller is what the note is held to
        self.only_problem(self.good(), "rev=" + "a" * 40, rev="c" * 40)

    def test_the_denominator_must_match_the_plan_exactly(self):
        results = self.good()
        self.only_problem(results[:1], "beta/%s: planned, but no result" % PPC)
        self.only_problem(results + [row("alpha", MIPS)], "2 results were supplied")
        self.only_problem(results + [row("gamma", MIPS)], "gamma/%s: a result for a check that is not in the plan" % MIPS)
        self.only_problem([dict(results[0], status="skipped"), results[1]], "status must be pass or fail")

    def test_a_missing_unreadable_or_oversized_log_is_a_problem(self):
        results = self.good()
        os.remove(os.path.join(self.dir, "alpha-%s.log" % MIPS))
        self.only_problem(results, "the log cannot be read")
        self.only_problem([dict(results[0], evidence=None), results[1]], "names no evidence log")
        self.put("alpha", MIPS, "x" * (CK.MAX_LOG_BYTES + 1))
        self.only_problem(results, "over the")

    def test_a_row_pointing_outside_the_logs_directory_reads_only_the_basename(self):
        self.good()
        with tempfile.TemporaryDirectory() as elsewhere:
            with open(os.path.join(elsewhere, "alpha-%s.log" % MIPS), "w") as fh:
                fh.write(log("alpha", MIPS, rc=101))                      # a decoy that would contradict the claim
            results = [row("alpha", MIPS, evidence=os.path.join(elsewhere, "..", "..", "alpha-%s.log" % MIPS)), row("beta", PPC)]
            records, problems = self.verify(results)
        self.assertEqual(problems, [])
        self.assertEqual(records[0]["rc"], 0)


class RedactionTests(unittest.TestCase):
    def test_paths_addresses_and_length_are_handled(self):
        text = "error at /Users/someone/ws/a.rs and /home/ubuntu/.rustup/x on ubuntu@100.64.0.9 via 10.0.0.1 " + "y" * 400
        out = CK.redact(text)
        for leaked in ("/Users", "someone", "/home", "100.64.0.9", "10.0.0.1", "ubuntu"):
            self.assertNotIn(leaked, out)
        self.assertIn("<path>", out)
        self.assertIn("<addr>", out)
        self.assertLessEqual(len(out), CK.DIAGNOSTIC_LIMIT)

    def test_version_numbers_are_not_mistaken_for_addresses(self):
        self.assertEqual(CK.redact("rustc 1.101.0-nightly, serde 1.0.229"), "rustc 1.101.0-nightly, serde 1.0.229")


class CommandLineTests(Base):
    def run_cli(self, *extra, results=None, plan=None, rev=REV):
        results = self.good() if results is None else results
        plan_path = os.path.join(self.dir, "plan.txt")
        with open(plan_path, "w") as fh:
            fh.write("\n".join(plan or [planned("alpha", MIPS), planned("beta", PPC)]) + "\n")
        res_path = os.path.join(self.dir, "results.jsonl")
        with open(res_path, "w") as fh:
            fh.write("\n".join(json.dumps(r) for r in results) + "\n")
        out = os.path.join(self.dir, "records.jsonl")
        argv = ["ingest", "--plan-file", plan_path, "--results", res_path, "--logs-dir", self.dir, "--out", out]
        if rev is not None:
            argv += ["--rev", rev]
        argv += list(extra)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = AU.main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), out

    def test_success_writes_the_records_and_reports_the_denominator(self):
        code, out, _, path = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("verified=2 pass=2 fail=0 problems=0", out)
        with open(path) as fh:
            self.assertEqual(len([json.loads(line) for line in fh]), 2)

    def test_one_unsupported_claim_exits_1_and_writes_nothing_not_a_partial_record(self):
        results = self.good()
        results[0] = dict(results[0], status="fail")                     # the log says exit 0
        code, out, _, path = self.run_cli(results=results)
        self.assertEqual(code, 1)
        self.assertIn("PROBLEM", out)
        self.assertFalse(os.path.exists(path))

    def test_usage_errors_exit_2_and_an_existing_output_is_never_overwritten(self):
        self.assertEqual(self.run_cli(rev="not-a-sha")[0], 2)
        code, _, _, path = self.run_cli()
        self.assertEqual(code, 0)
        with open(path) as fh:
            before = fh.read()
        with open(os.path.join(self.dir, "results.jsonl"), "w") as fh:
            fh.write("not json\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(AU.main(["ingest", "--plan-file", os.path.join(self.dir, "plan.txt"), "--results",
                                      os.path.join(self.dir, "results.jsonl"), "--logs-dir", self.dir, "--out", path]), 2)
        with open(path) as fh:
            self.assertEqual(fh.read(), before, "an existing record was touched")

    def test_a_bad_plan_is_a_problem_before_any_log_is_read(self):
        code, out, _, path = self.run_cli(plan=["cargo build"])
        self.assertEqual(code, 1)
        self.assertIn("not a planned cargo check", out)
        self.assertFalse(os.path.exists(path))

    def test_the_audit_folds_verified_records_and_still_rejects_what_the_plan_does_not_contain(self):
        # The records are in the --build-results shape, so the existing fold accepts them unchanged.
        code, _, _, path = self.run_cli()
        self.assertEqual(code, 0)
        with open(path) as fh:
            rows = [json.loads(line) for line in fh]
        findings = AU._Findings()
        plan = [{"crate": r["crate"], "target": r["target"], "platform": "x", "command": r["command"]} for r in rows]
        folded = AU.fold_build_results(plan, rows, findings)
        self.assertEqual(folded["counts"], {"pass": 2, "fail": 0, "not-run": 0, "conflicting": 0})
        self.assertEqual(folded["rows"][0]["evidence"], rows[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
