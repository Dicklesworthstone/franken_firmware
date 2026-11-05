"""franken-speaker smoke (E07 runner change): the verifier, the expectation and the orchestration.

Everything here checks the verifier, the source-derived expectation and the runner's plumbing against synthetic
transcripts. No guest booted and no speaker ran; these fixtures are not guest proof. Each negative plants exactly
one fault next to an unplanted positive baseline of the same shape, so a test cannot pass by failing for an
unrelated reason.
"""

import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))
import test_serial_validator as base  # noqa: E402  (a module, not re-exported: its TestCases are not collected here)
import mkinitramfs as M  # noqa: E402
import speaker_expect as E  # noqa: E402

VERIFIER = base.VERIFIER
REPO = HERE.parents[1]
SOURCE_TEXT = (REPO / E.CATALOG_SOURCE).read_text(encoding="utf-8")
EXPECTED = E.expected_catalog(SOURCE_TEXT)
CTX = {"expected": EXPECTED}

# The same example lines the Rust unit tests in ffw-hello-init/src/speaker_judge.rs assert byte for byte.
EXIT_EXAMPLE_OK = "FFW_SPEAKER_EXIT status=0 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef"
EXIT_EXAMPLES_FAILING = [
    "FFW_SPEAKER_EXIT status=3 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT signal=11 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT spawn=pipe errno=24",
    "FFW_SPEAKER_EXIT spawn=fork errno=11",
    "FFW_SPEAKER_EXIT spawn=exec errno=2",
    "FFW_SPEAKER_EXIT read_error=5 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT wait_error=10 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT wait_status=4991 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT exec_probe_error=1 stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef",
    "FFW_SPEAKER_EXIT status=0 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325",   # exit 0, nothing printed
]


# ---- synthetic catalog and transcripts ---------------------------------------------------------------------


def synthetic_row(want):
    """A BoardProfile-shaped row (field order as the Rust struct) for one expected row, digest included."""
    routing = [{"array_mid_woofer": 0}, {"array_tweeter": 1}] if want["model_number"] == "S9" else ["woofer_mono", "tweeter_mono"]
    row = {
        "schema_version": want["schema_version"],
        "profile_id": want["profile_id"],
        "model_number": want["model_number"],
        "model_name": want["model_name"],
        "supported_hw_rev": want["supported_hw_rev"],
        "legacy_sw_gen_hint": want["legacy_sw_gen_hint"],
        "cpu_isa": want["cpu_isa"],
        "float_abi": "unverified",
        "max_atomic_width_bits": 32,
        "nominal_ram_mib": want["nominal_ram_mib"],
        "nominal_flash_mib": want["nominal_flash_mib"],
        "kernel_capability_profile": "unverified",
        "audio_driver_abi": "unverified",
        "hardware_channels": len(routing),
        "channel_routing": routing,
        "amplifier_policy": "forbidden_fail_muted",
        "calibrated_output_delay_us": 0,
        "calibration_uncertainty_us": 0,
        "provenance": "assessment_hypothesis",
        "facts": {
            "hardware_revision": "hypothesis", "isa": want["facts.isa"], "nominal_capacity": "device_reported",
            "calibration": "unknown", "driver_and_routing": "hypothesis", "kernel_capability": "unknown",
        },
        "integrity_sha256": "",
    }
    row["integrity_sha256"] = E.integrity_digest(row)
    return row


def rows_for(expected):
    return [synthetic_row(want) for want in expected["rows"]]


def catalog_bytes(rows):
    """What `serde_json::to_string_pretty` plus `println!` produce for these rows (2-space indent, final newline)."""
    return (json.dumps(rows, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def reseal(row):
    row["integrity_sha256"] = E.integrity_digest(row)
    return row


def exit_line_for(data):
    return f"FFW_SPEAKER_EXIT status=0 stdout_bytes={len(data)} stdout_fnv1a64={E.fnv1a64(data):016x}"


def speaker_block(data, exit_line=None, crlf=True):
    """The console view of the speaker step: BEGIN, the forwarded bytes (CRLF if the console did that), EXIT."""
    newline = "\r\n" if crlf else "\n"
    body = data.decode("utf-8").replace("\n", newline)
    return E.BEGIN_LINE + "\n" + body + (exit_line or exit_line_for(data)) + "\n"


def transcript(block, ppc=False, failure=False):
    """base.POSITIVE with the speaker block placed before the summary, as the guest prints it."""
    text = base.POSITIVE
    marker = "FFW_MARKER:TEST_SUCCESS failures=0\n"
    assert marker in text
    if failure:
        text = text.replace(marker, "FFW_MARKER:TEST_FAILURE failures=1\n")
        marker = "FFW_MARKER:TEST_FAILURE failures=1\n"
    text = text.replace(marker, block + marker)
    return base.ppc_transcript(text) if ppc else text


GOOD_ROWS = rows_for(EXPECTED)
GOOD_DATA = catalog_bytes(GOOD_ROWS)
GOOD_BLOCK = speaker_block(GOOD_DATA)
GOOD_TEXT = transcript(GOOD_BLOCK)


def verify(text, arch="mips", speaker=CTX):
    if arch == "mips":
        return VERIFIER.verify_serial_output("mips", base.HELLO, base.ENOSYS, text, base.MIPS_TRIPLE, speaker=speaker)
    return VERIFIER.verify_serial_output("ppc", base.PPC_HELLO, base.PPC_ENOSYS, text, base.PPC_TRIPLE, speaker=speaker)


# ---- the Rust helpers replicated in Python ------------------------------------------------------------------


class ReplicationTests(unittest.TestCase):
    def test_fnv1a64_matches_the_vectors_the_rust_tests_assert(self):
        for data, want in ((b"", 0xCBF29CE484222325), (b"a", 0xAF63DC4C8601EC8C),
                           (b"foobar", 0x85944171F73967E8), (b"FFW_SPEAKER", 0x76BE40694ADE6F20)):
            self.assertEqual(E.fnv1a64(data), want, data)

    def test_serde_snake_case_follows_serde_for_digits_and_camel_case(self):
        self.assertEqual(E.serde_snake_case("PowerPc32BigEndian"), "power_pc32_big_endian")
        self.assertEqual(E.serde_snake_case("Mips32R2BigEndian"), "mips32_r2_big_endian")
        self.assertEqual(E.serde_snake_case("Arm32LittleEndianUnverified"), "arm32_little_endian_unverified")
        self.assertEqual(E.serde_snake_case("Unknown"), "unknown")

    def test_profile_id_matches_the_two_independently_committed_goldens(self):
        # crates/franken-board-profile/src/lib.rs `profile_ids_use_the_shared_formula_with_golden_vectors` and
        # inventory/test_identity.py, both computed independently of any Rust.
        self.assertEqual(E.profile_id_for("S5", "1.8.3.1-2"), "bp-a54934d5ce72d8e7")
        self.assertEqual(E.profile_id_for("S5", "1.20.1.6-2"), "bp-592228c461a48f9b")

    def test_profile_id_uses_the_canonical_forms(self):
        self.assertEqual(E.profile_id_for("Sub", "1.8.2.4-2"), E.profile_id_for("SUB", "1.8.2.4-2"))
        self.assertEqual(E.profile_id_for("S5", "01.8.3.1-02"), E.profile_id_for("S5", "1.8.3.1-2"))

    def test_canonical_grammar_refuses_what_rust_refuses(self):
        for model in ("", "-S5", "S 5", "x" * 25):
            with self.subTest(model=model), self.assertRaises(ValueError):
                E.canonical_model_number(model)
        for rev in ("", "1.2.3.4.5.6.7", "1.2-3.4.5.6.7", "1.a", "1..2", "123456.1"):
            with self.subTest(rev=rev), self.assertRaises(ValueError):
                E.canonical_hardware_revision(rev)

    def test_integrity_digest_ignores_the_stored_digest_and_binds_every_other_field(self):
        row = copy.deepcopy(GOOD_ROWS[0])
        digest = E.integrity_digest(row)
        self.assertEqual(row["integrity_sha256"], digest)
        self.assertEqual(E.integrity_digest({**row, "integrity_sha256": "f" * 64}), digest)
        self.assertNotEqual(E.integrity_digest({**row, "model_name": "other"}), digest)
        self.assertNotEqual(E.integrity_digest({**row, "nominal_ram_mib": row["nominal_ram_mib"] + 1}), digest)


# ---- the expectation, read from the real Rust source ---------------------------------------------------------


class ExpectedCatalogTests(unittest.TestCase):
    def test_the_nine_rows_come_out_of_the_source_in_order(self):
        rows = EXPECTED["rows"]
        self.assertEqual(len(rows), 9, "canonical_board_catalog changed: update the claim in the docs and the mail")
        self.assertEqual([(r["model_number"], r["supported_hw_rev"]) for r in rows], [
            ("S5", "1.16.3.1-2"), ("S1", "1.8.3.7-1"), ("S1", "1.8.3.7-2"), ("S12", "1.20.1.6-2"),
            ("S3", "1.8.1.2-1"), ("S3", "1.8.1.2-2"), ("Sub", "1.8.2.4-2"), ("S9", "1.9.1.10-2"),
            ("ZB100", "1.5.0.0-1")])
        self.assertEqual(EXPECTED["schema_version"], "ffw.board_profile.v2")
        self.assertEqual(EXPECTED["source"], E.CATALOG_SOURCE)
        self.assertEqual(EXPECTED["source_sha256"], hashlib.sha256(SOURCE_TEXT.encode()).hexdigest())

    def test_row_fields_follow_the_literals_and_the_capacity_table(self):
        first, sub, bridge = EXPECTED["rows"][0], EXPECTED["rows"][6], EXPECTED["rows"][8]
        self.assertEqual((first["cpu_isa"], first["facts.isa"], first["legacy_sw_gen_hint"]),
                         ("power_pc32_big_endian", "hypothesis", 1))
        self.assertEqual((first["nominal_ram_mib"], first["nominal_flash_mib"]), (32, 32))
        # The literal is "Sub"; the capacity table and the id use the canonical SUB, the printed field does not.
        self.assertEqual((sub["model_number"], sub["nominal_ram_mib"], sub["nominal_flash_mib"]), ("Sub", 128, 64))
        self.assertEqual(sub["profile_id"], E.profile_id_for("SUB", "1.8.2.4-2"))
        self.assertEqual((bridge["nominal_ram_mib"], bridge["nominal_flash_mib"], bridge["cpu_isa"]), (8, 8, "unknown"))

    def test_a_catalog_the_extractor_cannot_read_is_an_error_not_a_shorter_expectation(self):
        row_start = SOURCE_TEXT.index("hypothesis_profile(HypothesisSpec {")
        cases = {
            "unreadable revision": SOURCE_TEXT.replace('hw_rev: "1.16.3.1-2"', 'hw_rev: "bogus"', 1),
            "missing field": SOURCE_TEXT[:row_start] + SOURCE_TEXT[row_start:].replace("sw_gen_hint:", "gen_hint:", 1),
            "a row that is not a HypothesisSpec literal": SOURCE_TEXT.replace(
                "hypothesis_profile(HypothesisSpec {", "hypothesis_profile(other_spec),\n        hypothesis_profile(HypothesisSpec {", 1),
        }
        for label, text in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                E.expected_catalog(text)
        E.expected_catalog(SOURCE_TEXT)       # the unplanted baseline reads fine


# ---- judging a catalog ---------------------------------------------------------------------------------------


class JudgeCatalogTests(unittest.TestCase):
    def judge(self, rows=None, data=None):
        return E.judge_catalog(data if data is not None else catalog_bytes(rows), EXPECTED)

    def test_the_unplanted_catalog_holds(self):
        self.assertEqual(self.judge(GOOD_ROWS), [])

    def planted(self, label, mutate, expect):
        rows = copy.deepcopy(GOOD_ROWS)
        mutate(rows)
        problems = self.judge(rows)
        self.assertTrue(any(expect in p for p in problems), f"{label}: {problems}")
        self.assertEqual(self.judge(GOOD_ROWS), [], "baseline")       # remove the plant: it holds again

    def test_each_planted_fault_is_named(self):
        def edit(index, **fields):
            def go(rows):
                rows[index].update(fields)
            return go

        self.planted("wrong revision", edit(0, supported_hw_rev="1.16.3.1-3"), "row0.supported_hw_rev")
        self.planted("wrong name", edit(1, model_name="Play:1 (Rev 3)"), "row1.model_name")
        self.planted("wrong isa", edit(3, cpu_isa="mips32_r2_big_endian"), "row3.cpu_isa")
        self.planted("wrong generation hint", edit(4, legacy_sw_gen_hint=1), "row4.legacy_sw_gen_hint")
        self.planted("wrong capacity", edit(5, nominal_ram_mib=64), "row5.nominal_ram_mib")
        self.planted("wrong profile id", edit(6, profile_id="bp-0000000000000000"), "row6.profile_id")
        self.planted("wrong schema", edit(7, schema_version="ffw.board_profile.v1"), "row7.schema_version")
        self.planted("stale digest", edit(2, integrity_sha256="0" * 64), "row2.integrity_sha256")
        self.planted("fact status", lambda rows: rows[0]["facts"].update(isa="attested"), "row0.facts.isa")

    def test_a_field_changed_without_resealing_breaks_the_digest_even_when_every_expected_field_matches(self):
        rows = copy.deepcopy(GOOD_ROWS)
        rows[0]["float_abi"] = "hard"                      # not a field the source literals state
        self.assertEqual(self.judge(rows), ["row0.integrity_sha256"])
        reseal(rows[0])
        self.assertEqual(self.judge(rows), [])             # resealed: a different, self-consistent row is accepted

    def test_row_count_and_order(self):
        self.assertTrue(any("row_count" in p for p in self.judge(GOOD_ROWS[:-1])))
        self.assertTrue(any("row_count" in p for p in self.judge(GOOD_ROWS + [GOOD_ROWS[0]])))
        swapped = [GOOD_ROWS[1], GOOD_ROWS[0], *GOOD_ROWS[2:]]
        self.assertTrue(any(p.startswith("row0.") for p in self.judge(swapped)))

    def test_output_that_is_not_the_catalog_at_all(self):
        self.assertEqual(self.judge(data=b"\xff\xfe"), ["not_utf8"])
        self.assertTrue(self.judge(data=b"not json")[0].startswith("json_invalid:"))
        self.assertEqual(self.judge(data=b'{"a": 1}'), ["json_not_a_list"])
        self.assertEqual(self.judge(data=b"[]"), [f"row_count:0!={len(EXPECTED['rows'])}"])
        truncated = GOOD_DATA[: len(GOOD_DATA) // 2]
        self.assertTrue(self.judge(data=truncated)[0].startswith("json_invalid:"))
        self.assertTrue(any("not_an_object" in p for p in self.judge(rows=[1, *GOOD_ROWS[1:]])))


# ---- the wire grammar and the console region ---------------------------------------------------------------


class GrammarTests(unittest.TestCase):
    def test_exactly_one_form_is_success(self):
        self.assertIsNotNone(E.EXIT_OK.fullmatch(EXIT_EXAMPLE_OK))
        for line in EXIT_EXAMPLES_FAILING:
            with self.subTest(line=line):
                self.assertIsNone(E.EXIT_OK.fullmatch(line))
                self.assertIsNotNone(E.EXIT_FAILURE.fullmatch(line))

    def test_malformed_exit_lines_are_neither_success_nor_a_named_failure(self):
        for line in (EXIT_EXAMPLE_OK + " ", EXIT_EXAMPLE_OK.replace("status=0", "status=00"),
                     EXIT_EXAMPLE_OK.replace("stdout_bytes=17812", "stdout_bytes=017812"),
                     EXIT_EXAMPLE_OK.replace("0123456789abcdef", "0123456789ABCDEF"),
                     EXIT_EXAMPLE_OK.replace("0123456789abcdef", "0123456789abcde"),
                     "FFW_SPEAKER_EXIT status=0", "FFW_SPEAKER_EXIT spawn=exec", "FFW_SPEAKER_EXIT spawn=dup errno=2",
                     "FFW_SPEAKER_EXIT status=1 stdout_bytes=1", "FFW_SPEAKER_EXIT"):
            with self.subTest(line=line):
                self.assertIsNone(E.EXIT_OK.fullmatch(line))
                self.assertIsNone(E.EXIT_FAILURE.fullmatch(line))

    def test_region_maps_console_crlf_back_and_keeps_indentation(self):
        data = b"[\n  {\n    \"a\": 1\n  }\n]\n"
        region, reason = E.stdout_region(speaker_block(data, crlf=True))
        self.assertEqual((region, reason), (data, None))
        self.assertEqual(E.stdout_region(speaker_block(data, crlf=False)), (data, None))

    def test_region_is_empty_for_a_silent_speaker_and_refuses_ambiguity(self):
        silent = E.BEGIN_LINE + "\nFFW_SPEAKER_EXIT status=0 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325\n"
        self.assertEqual(E.stdout_region(silent), (b"", None))
        two_begins = E.BEGIN_LINE + "\n" + E.BEGIN_LINE + "\n" + EXIT_EXAMPLE_OK + "\n"
        self.assertEqual(E.stdout_region(two_begins), (None, "begin_or_exit_not_exactly_once"))
        reversed_ = EXIT_EXAMPLE_OK + "\n" + E.BEGIN_LINE + "\n"
        self.assertEqual(E.stdout_region(reversed_), (None, "exit_before_begin"))
        self.assertEqual(E.stdout_region(E.BEGIN_LINE + "\n�\n" + EXIT_EXAMPLE_OK + "\n"), (None, "not_utf8"))
        self.assertEqual(E.stdout_region("nothing here\n"), (None, "begin_or_exit_not_exactly_once"))


# ---- verify_serial_output with a speaker ------------------------------------------------------------------------


class SpeakerTranscriptTests(unittest.TestCase):
    def status(self, text, **kw):
        return verify(text, **kw)["status"]

    def errors(self, text, **kw):
        return verify(text, **kw)["validation_errors"]

    def test_the_unplanted_transcript_passes_on_both_architectures(self):
        for arch in ("mips", "ppc"):
            with self.subTest(arch=arch):
                result = verify(transcript(GOOD_BLOCK, ppc=arch == "ppc"), arch=arch)
                self.assertEqual((result["status"], result["validation_errors"], result["missing_markers"]), ("PASS", [], []))
                speaker = result["speaker"]
                self.assertEqual(speaker["outcome"], "exited_0")
                self.assertEqual(speaker["reported"], speaker["console_region"])
                self.assertEqual(speaker["catalog"], {"rows_expected": 9, "problems": []})

    def test_without_a_speaker_the_verifier_is_what_it_was_and_speaker_lines_are_unknown_markers(self):
        plain = verify(base.POSITIVE, speaker=None)
        self.assertEqual(plain["status"], "PASS")
        self.assertNotIn("speaker", plain)
        planted = verify(GOOD_TEXT, speaker=None)
        self.assertEqual(planted["status"], "FAIL")
        self.assertEqual(sorted(planted["validation_errors"]), ["invalid:FFW_SPEAKER_BEGIN", "invalid:FFW_SPEAKER_EXIT"])

    def test_a_missing_marker_fails_by_name(self):
        no_begin = GOOD_TEXT.replace(E.BEGIN_LINE + "\n", "")
        result = verify(no_begin)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_SPEAKER_BEGIN", result["missing_markers"])
        no_exit = GOOD_TEXT.replace(exit_line_for(GOOD_DATA) + "\n", "")
        result = verify(no_exit)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_SPEAKER_EXIT", result["missing_markers"])
        self.assertEqual(result["speaker"]["outcome"], "not_run")
        self.assertEqual(self.status(GOOD_TEXT), "PASS")           # baseline

    def test_every_failure_form_is_a_named_speaker_failure_and_fails_the_guest(self):
        for line in EXIT_EXAMPLES_FAILING:
            with self.subTest(line=line):
                result = verify(GOOD_TEXT.replace(exit_line_for(GOOD_DATA), line))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("speaker_failed:" + line[len("FFW_SPEAKER_EXIT "):], result["validation_errors"])
                self.assertEqual(result["speaker"]["outcome"], "failed")

    def test_a_garbled_exit_line_is_invalid_not_failed(self):
        result = verify(GOOD_TEXT.replace(exit_line_for(GOOD_DATA), "FFW_SPEAKER_EXIT status=ok"))
        self.assertIn("invalid:FFW_SPEAKER_EXIT", result["validation_errors"])
        self.assertEqual(result["speaker"]["outcome"], "invalid")

    def test_console_bytes_that_differ_from_what_the_guest_measured_do_not_verify(self):
        flipped = GOOD_BLOCK.replace('"model_name": "Play:5 (Gen 1)"', '"model_name": "Play:5 (Gen 2)"')
        self.assertNotEqual(flipped, GOOD_BLOCK)
        errors = self.errors(transcript(flipped))
        self.assertIn("speaker_stdout_mismatch:fnv1a64", errors)         # same length, different bytes
        self.assertNotIn("speaker_stdout_mismatch:bytes", errors)
        dropped = GOOD_BLOCK.replace('    "float_abi": "unverified",\r\n', "", 1)
        self.assertNotEqual(dropped, GOOD_BLOCK)
        errors = self.errors(transcript(dropped))
        self.assertIn("speaker_stdout_mismatch:bytes", errors)

    def test_kernel_noise_inside_the_region_is_caught_by_the_measurement(self):
        noisy = GOOD_BLOCK.replace("  {\r\n", "  {\r\n[    3.141592] random: crng init done\r\n", 1)
        self.assertNotEqual(noisy, GOOD_BLOCK)
        self.assertIn("speaker_stdout_mismatch:bytes", self.errors(transcript(noisy)))

    def test_a_catalog_that_hashes_consistently_but_is_the_wrong_catalog_fails_on_content(self):
        rows = copy.deepcopy(GOOD_ROWS)
        rows[0]["supported_hw_rev"] = "1.16.3.1-3"
        reseal(rows[0])
        data = catalog_bytes(rows)                         # guest measurement and console agree; the content is wrong
        errors = self.errors(transcript(speaker_block(data)))
        self.assertEqual(errors, ["speaker_catalog:row0.supported_hw_rev:'1.16.3.1-3'!='1.16.3.1-2'"])

    def test_a_digest_the_guest_got_wrong_is_caught_independently(self):
        rows = copy.deepcopy(GOOD_ROWS)
        rows[4]["integrity_sha256"] = "00" * 32            # what a broken big-endian SHA-256 would print
        errors = self.errors(transcript(speaker_block(catalog_bytes(rows))))
        self.assertEqual(errors, ["speaker_catalog:row4.integrity_sha256"])

    def test_order_duplicates_and_placement(self):
        exit_ = exit_line_for(GOOD_DATA) + "\n"
        after_success = GOOD_TEXT.replace(exit_, "").replace(
            "FFW_MARKER:REBOOT_REQUEST", exit_ + "FFW_MARKER:REBOOT_REQUEST")
        self.assertFalse(verify(after_success)["marker_order_ok"])
        self.assertEqual(self.status(after_success), "FAIL")
        self.assertIn("duplicate:FFW_SPEAKER_EXIT", self.errors(GOOD_TEXT.replace(exit_, exit_ * 2)))
        swapped = GOOD_TEXT.replace(GOOD_BLOCK, GOOD_BLOCK.replace(E.BEGIN_LINE + "\n", "").rstrip("\n") + "\n" + E.BEGIN_LINE + "\n")
        self.assertEqual(self.status(swapped), "FAIL")

    def test_a_host_catalog_must_equal_the_guest_exactly(self):
        host = {"stdout_bytes": len(GOOD_DATA), "stdout_fnv1a64": f"{E.fnv1a64(GOOD_DATA):016x}"}
        ok = verify(GOOD_TEXT, speaker={**CTX, "host": host})
        self.assertEqual((ok["status"], ok["speaker"]["host_catalog"]), ("PASS", host))
        wrong = {**host, "stdout_fnv1a64": "0" * 16}
        self.assertEqual(self.errors(GOOD_TEXT, speaker={**CTX, "host": wrong}), ["speaker_stdout_differs_from_host"])


# ---- controls ------------------------------------------------------------------------------------------------------


def control_text(errno):
    block = E.BEGIN_LINE + f"\nFFW_SPEAKER_EXIT spawn=exec errno={errno}\n"
    return transcript(block, failure=True)


class ControlJudgementTests(unittest.TestCase):
    def judged(self, text, errno, stop=None, rc=0):
        return VERIFIER.judge_speaker_control(verify(text), errno, stop, rc)

    def test_a_planted_fault_that_fails_for_exactly_the_planted_reason_is_caught(self):
        for name, spec in VERIFIER.SPEAKER_CONTROLS.items():
            with self.subTest(name=name):
                judged = self.judged(control_text(spec["errno"]), spec["errno"])
                self.assertTrue(judged["caught"], judged)
                self.assertEqual(set(judged["checks"].values()), {True})

    def test_the_unplanted_baseline_is_not_a_caught_control(self):
        judged = self.judged(GOOD_TEXT, 2)
        self.assertFalse(judged["caught"])
        self.assertFalse(judged["checks"]["guest_failed"])

    def test_failing_for_a_different_reason_is_not_caught(self):
        self.assertFalse(self.judged(control_text(13), 2)["caught"])                      # wrong errno
        extra = control_text(2).replace("FFW_PROBE:ENTROPY status=PASS fd=4", "FFW_PROBE:ENTROPY status=FAIL errno=5")
        judged = self.judged(extra, 2)
        self.assertFalse(judged["caught"])
        self.assertFalse(judged["checks"]["only_the_planted_error"])
        no_failure_marker = control_text(2).replace("FFW_MARKER:TEST_FAILURE failures=1", "FFW_MARKER:SOMETHING")
        self.assertFalse(self.judged(no_failure_marker, 2)["caught"])
        # A kernel panic is not an FFW_ line, so it adds no validation error: only the forbidden-marker check sees
        # it. The planted error is still exactly the planted one.
        panicked = self.judged(control_text(2) + "Kernel panic - not syncing: oops\n", 2)
        self.assertFalse(panicked["caught"])
        self.assertTrue(panicked["checks"]["only_the_planted_error"])
        self.assertFalse(panicked["checks"]["only_the_guest_failure_marker"])

    def test_an_unclean_capture_is_not_a_caught_control(self):
        self.assertFalse(self.judged(control_text(2), 2, stop="timeout")["caught"])
        self.assertFalse(self.judged(control_text(2), 2, rc=1)["caught"])
        self.assertTrue(self.judged(control_text(2), 2)["caught"])                          # baseline


# ---- the initramfs ------------------------------------------------------------------------------------------------


class ExtraFilesTests(unittest.TestCase):
    INIT = b"\x7fELF-init-bytes"
    SPEAKER = b"\x7fELF-speaker-bytes-1234"

    def build(self, scratch, extras=()):
        init = Path(scratch) / "init"
        init.write_bytes(self.INIT)
        out = Path(scratch) / "out.cpio.gz"
        receipt = M.build(init, out, extra_files=extras)
        return receipt, out.read_bytes()

    def test_without_extras_the_archive_is_byte_identical_to_what_it_always_was(self):
        with tempfile.TemporaryDirectory() as scratch:
            receipt, written = self.build(scratch)
        self.assertEqual(written, M.compress_deterministic_gzip(M.build_cpio_bytes(self.INIT)))
        self.assertNotIn("extra_files", receipt)

    def test_an_extra_file_is_packed_with_its_mode_and_bytes_and_read_back(self):
        extras = [("franken-speaker", M.S_IFREG | 0o755, self.SPEAKER)]
        with tempfile.TemporaryDirectory() as scratch:
            receipt, written = self.build(scratch, extras)
        entries = {e["name"]: e for e in M.parse_cpio_bytes(gzip.decompress(written))}
        self.assertEqual(entries["franken-speaker"]["data"], self.SPEAKER)
        self.assertEqual(entries["franken-speaker"]["mode"], M.S_IFREG | 0o755)
        self.assertEqual(receipt["extra_files"]["franken-speaker"], {
            "mode": oct(M.S_IFREG | 0o755), "size": len(self.SPEAKER),
            "sha256": hashlib.sha256(self.SPEAKER).hexdigest()})
        self.assertEqual(entries["init"]["data"], self.INIT)                    # init is untouched
        self.assertEqual(receipt["init_sha256"], hashlib.sha256(self.INIT).hexdigest())

    def test_the_archive_is_deterministic(self):
        extras = [("franken-speaker", M.S_IFREG | 0o755, self.SPEAKER)]
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            self.assertEqual(self.build(one, extras)[1], self.build(two, extras)[1])

    def test_unsafe_or_colliding_names_and_modes_are_refused(self):
        regular = M.S_IFREG | 0o755
        # The early, named error is what is asserted: later layers also happen to raise ValueError for several of
        # these (an init digest mismatch, a device node of the wrong type), with messages that do not say why.
        for name, mode, why in (("init", regular, "collides"), ("dev/null", regular, "collides"),
                                ("proc", regular, "collides"), ("TRAILER!!!", regular, "collides"),
                                ("/franken-speaker", regular, "plain relative path"),
                                ("../franken-speaker", regular, "plain relative path"),
                                ("a//b", regular, "plain relative path"), ("", regular, "plain relative path"),
                                (".", regular, "plain relative path"),
                                ("franken-speaker", M.S_IFDIR | 0o755, "regular file mode"),
                                ("franken-speaker", M.S_IFCHR | 0o600, "regular file mode")):
            with self.subTest(name=name, mode=oct(mode)), tempfile.TemporaryDirectory() as scratch:
                with self.assertRaisesRegex(ValueError, why):
                    self.build(scratch, [(name, mode, self.SPEAKER)])
        with tempfile.TemporaryDirectory() as scratch, self.assertRaisesRegex(ValueError, "collides"):
            self.build(scratch, [("a", regular, b"1"), ("a", regular, b"2")])
        with tempfile.TemporaryDirectory() as scratch:
            self.build(scratch, [("franken-speaker", regular, self.SPEAKER)])    # baseline: the plain name is fine


# ---- the runner end to end, with patched guests --------------------------------------------------------------------


class RunnerSpeakerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.mips_speaker = self.root / "speaker-mips"
        self.ppc_speaker = self.root / "speaker-ppc"
        self.mips_speaker.write_bytes(base.elf32(8) + b"mips-speaker")
        self.ppc_speaker.write_bytes(base.elf32(20) + b"ppc-speaker")

    @staticmethod
    def capture(text):
        return {"stdout": text.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}

    def lay_out(self, target_name="target"):
        target = self.root / target_name
        for triple, machine in ((base.MIPS_TRIPLE, 8), (base.PPC_TRIPLE, 20)):
            binary = target / triple / "release/ffw-hello-init"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(base.elf32(machine))
        for kernel in ("kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta", "kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc"):
            (self.root / kernel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / kernel).write_bytes(b"synthetic-kernel-not-executed")
        return target

    def run_main(self, captures, argv, explicit_target=True, build=False):
        """Drive VERIFIER.main with patched guests; nothing is executed. With build=True every subprocess call is
        recorded in self.builds instead of run."""
        self.builds = []

        def fake_run(cmd, **kwargs):
            self.builds.append((list(cmd), kwargs))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        target = self.lay_out("target" if explicit_target else "hello-init-speaker-target")
        self.runs = getattr(self, "runs", 0) + 1
        output = self.output = self.root / ("result" if self.runs == 1 else f"result{self.runs}")   # never reused
        full = ["--results-dir", str(output), *argv] if build else ["--skip-build", "--results-dir", str(output), *argv]
        if explicit_target:
            full += ["--target-dir", str(target)]
        with patch.object(VERIFIER.mkinitramfs, "resolve_default_build_dir", return_value=self.root), \
             patch.object(VERIFIER, "capture_guest", side_effect=captures), \
             contextlib.ExitStack() as stack:
            if build:
                stack.enter_context(patch.object(VERIFIER.subprocess, "run", side_effect=fake_run))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            result = VERIFIER.main(full)
        return result, json.loads((output / "e07-e03-verification-receipt.json").read_text())

    def speaker_argv(self, *extra):
        return ["--speaker-mips", str(self.mips_speaker), "--speaker-ppc", str(self.ppc_speaker), *extra]

    def sequence(self, controls=True, mutate=None):
        """Captures in call order: per architecture, the real run then each control."""
        captures = []
        for ppc in (False, True):
            captures.append(self.capture(transcript(GOOD_BLOCK, ppc=ppc)))
            if controls:
                for spec in VERIFIER.SPEAKER_CONTROLS.values():
                    captures.append(self.capture(control_text(spec["errno"]) if not ppc else base.ppc_transcript(control_text(spec["errno"]))))
        if mutate is not None:
            mutate(captures)
        return captures

    # -- the run ----------------------------------------------------------------------------------------------------

    def test_a_clean_run_with_controls_passes_and_records_everything(self):
        result, receipt = self.run_main(self.sequence(), self.speaker_argv("--speaker-controls"))
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        for arch in ("mips", "ppc"):
            guest = receipt["guests"][arch]
            speaker = guest["speaker"]
            self.assertEqual((guest["status"], guest["validation_errors"]), ("PASS", []))
            self.assertEqual(speaker["outcome"], "exited_0")
            self.assertEqual(speaker["binary"]["archive_entry"]["sha256"], speaker["binary"]["sha256"])
            self.assertTrue(speaker["binary"]["static_elf"]["static"])
            self.assertEqual(sorted(speaker["controls"]), sorted(VERIFIER.SPEAKER_CONTROLS))
            for name, control in speaker["controls"].items():
                self.assertTrue(control["caught"], (arch, name, control["checks"]))
                self.assertEqual(control["speaker_exit_line"], f"FFW_SPEAKER_EXIT spawn=exec errno={control['expected_errno']}")
            self.assertEqual(guest["build_manifest"].get("features"), ["speaker-smoke"])
            self.assertIn("nothing about the float ABI", speaker["qualification_boundary"])
        smoke = receipt["speaker_smoke"]
        self.assertEqual((smoke["feature"], smoke["controls_requested"], smoke["expected_source"]["rows"]),
                         ("speaker-smoke", True, 9))
        self.assertEqual(smoke["expected_source"]["sha256"], EXPECTED["source_sha256"])

    def test_the_control_archives_hold_exactly_the_planted_fault(self):
        # Read back from the archives the runner actually wrote, not from the runner's own bookkeeping.
        _, receipt = self.run_main(self.sequence(), self.speaker_argv("--speaker-controls"))
        results = self.output
        own, other = {"mips": self.mips_speaker, "ppc": self.ppc_speaker}, {"mips": self.ppc_speaker, "ppc": self.mips_speaker}
        for arch in ("mips", "ppc"):
            def entries(name):
                data = gzip.decompress((results / f"initramfs-{arch}-control-{name}.cpio.gz").read_bytes())
                return {e["name"]: e for e in M.parse_cpio_bytes(data)}
            self.assertNotIn("franken-speaker", entries("missing"))
            non_exec = entries("non_executable")["franken-speaker"]
            self.assertEqual((non_exec["mode"], non_exec["data"]), (M.S_IFREG | 0o644, own[arch].read_bytes()))
            wrong = entries("wrong_isa")["franken-speaker"]
            self.assertEqual((wrong["mode"], wrong["data"]), (M.S_IFREG | 0o755, other[arch].read_bytes()))
            real = M.parse_cpio_bytes(gzip.decompress((results / f"initramfs-{arch}.cpio.gz").read_bytes()))
            self.assertEqual({e["name"]: e for e in real}["franken-speaker"]["data"], own[arch].read_bytes())

    def test_a_control_that_is_not_caught_fails_the_run(self):
        # The "missing" control boots a guest that, wrongly, still runs the speaker: the verifier must not credit it.
        def mutate(captures):
            captures[1] = self.capture(transcript(GOOD_BLOCK))        # the real run's transcript in a control slot
        result, receipt = self.run_main(self.sequence(mutate=mutate), self.speaker_argv("--speaker-controls"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        mips = receipt["guests"]["mips"]
        self.assertEqual(mips["status"], "FAIL")
        self.assertEqual(mips["validation_errors"], ["speaker_control_not_caught:missing"])
        self.assertEqual(receipt["guests"]["ppc"]["status"], "PASS")

    def test_a_failing_baseline_skips_the_controls_and_says_so(self):
        broken = GOOD_BLOCK.replace('"model_name": "Play:5 (Gen 1)"', '"model_name": "Play:5 (Gen 2)"')
        captures = [self.capture(transcript(broken)), self.capture(transcript(GOOD_BLOCK, ppc=True)),
                    *[self.capture(base.ppc_transcript(control_text(s["errno"]))) for s in VERIFIER.SPEAKER_CONTROLS.values()]]
        result, receipt = self.run_main(captures, self.speaker_argv("--speaker-controls"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        mips = receipt["guests"]["mips"]
        self.assertEqual(mips["speaker"]["controls"], {n: {"skipped": "baseline_failed"} for n in VERIFIER.SPEAKER_CONTROLS})
        self.assertEqual(sorted(e for e in mips["validation_errors"] if e.startswith("speaker_control")),
                         [f"speaker_control_not_run:{n}" for n in sorted(VERIFIER.SPEAKER_CONTROLS)])

    def test_the_speaker_failing_in_the_guest_fails_the_run_with_the_guests_own_words(self):
        block = E.BEGIN_LINE + "\nFFW_SPEAKER_EXIT spawn=exec errno=2\n"
        captures = [self.capture(transcript(block, failure=True)), self.capture(transcript(GOOD_BLOCK, ppc=True))]
        result, receipt = self.run_main(captures, self.speaker_argv())
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        # The speaker's own failure, then the guest's TEST_FAILURE line that follows from it (a line this verifier
        # has always reported as an unknown marker).
        self.assertEqual(receipt["guests"]["mips"]["validation_errors"],
                         ["speaker_failed:spawn=exec errno=2", "invalid:FFW_MARKER:TEST_FAILURE"])
        self.assertEqual(receipt["guests"]["mips"]["speaker"]["outcome"], "failed")

    def test_a_packed_entry_that_is_not_the_named_binary_fails_the_guest(self):
        real_build = VERIFIER.mkinitramfs.build

        def forged(init_path, out_path, extra_files=()):
            receipt = real_build(init_path, out_path, extra_files=extra_files)
            if receipt.get("extra_files"):
                receipt["extra_files"]["franken-speaker"]["sha256"] = "0" * 64
            return receipt

        with patch.object(VERIFIER.mkinitramfs, "build", side_effect=forged):
            result, receipt = self.run_main(self.sequence(controls=False), self.speaker_argv())
        self.assertEqual((result, receipt["guests"]["mips"]["status"]), (1, "FAIL"))
        self.assertIn("speaker_entry_differs_from_binary", receipt["guests"]["mips"]["validation_errors"])

    def test_a_host_catalog_that_equals_the_guest_is_recorded(self):
        host = self.root / "host-catalog.json"
        host.write_bytes(GOOD_DATA)
        _, receipt = self.run_main(self.sequence(controls=False), self.speaker_argv("--speaker-host-catalog", str(host)))
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["speaker_smoke"]["host_catalog"]["stdout_bytes"], len(GOOD_DATA))
        self.assertEqual(receipt["guests"]["ppc"]["speaker"]["host_catalog"], receipt["speaker_smoke"]["host_catalog"])

    # -- the build and the defaults ------------------------------------------------------------------------------------

    def test_the_build_command_adds_the_feature_before_the_job_count(self):
        _, receipt = self.run_main(self.sequence(controls=False), self.speaker_argv("--jobs", "2"), build=True)
        ran = [cmd for cmd, _ in self.builds if cmd[:1] == ["rch"]]
        for triple, cmd in zip((base.MIPS_TRIPLE, base.PPC_TRIPLE), ran):
            self.assertEqual(cmd, ["rch", "exec", "--source-content-receipt", "--", "cargo", "+nightly", "build",
                                   "--release", "--target", triple, "-Z", "build-std=core,panic_abort",
                                   "--features", "speaker-smoke", "-j", "2"])
        self.assertEqual(len(ran), 2)
        self.assertEqual(receipt["guests"]["mips"]["build_manifest"]["command"], ran[0])
        self.assertEqual(receipt["guests"]["mips"]["build_manifest"]["target"]["build_std"], "core,panic_abort")

    def test_speaker_mode_defaults_to_its_own_target_directory_and_never_the_e07_one(self):
        self.run_main(self.sequence(controls=False), self.speaker_argv(), explicit_target=False)
        self.assertTrue((self.root / "hello-init-speaker-target").is_dir())
        self.assertFalse((self.root / "hello-init-target").exists())

    def test_a_default_run_is_exactly_what_it_was(self):
        captures = [self.capture(base.POSITIVE), self.capture(base.ppc_transcript(base.POSITIVE))]
        result, receipt = self.run_main(captures, [])
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertNotIn("speaker_smoke", receipt)
        for guest in receipt["guests"].values():
            self.assertNotIn("speaker", guest)
            self.assertNotIn("features", guest["build_manifest"])
        _, built = self.run_main([self.capture(base.POSITIVE), self.capture(base.ppc_transcript(base.POSITIVE))], [],
                                 build=True)
        self.assertEqual(len([c for c, _ in self.builds if c[:1] == ["rch"]]), 2)
        self.assertNotIn("--features", [a for c, _ in self.builds for a in c])

    def test_no_speaker_receipt_field_leaks_an_absolute_path(self):
        _, receipt = self.run_main(self.sequence(), self.speaker_argv("--speaker-controls"))
        text = json.dumps(receipt)
        self.assertNotIn(str(self.root.resolve()), text)
        self.assertNotIn(self.scratch.name, text)
        self.assertNotIn(str(Path.home()), text)

    # -- arguments are refused before anything runs ------------------------------------------------------------------------

    def refused(self, argv):
        target = self.root / "never-created"
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as caught:
            VERIFIER.main([*argv, "--results-dir", str(target)])
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(target.exists())
        return err.getvalue()

    def test_bad_speaker_arguments_are_refused_with_a_reason(self):
        dynamic = self.root / "dynamic"
        dynamic.write_bytes(base.elf32(8, ptypes=(3, 1)))
        wrong_machine = self.root / "wrong-machine"
        wrong_machine.write_bytes(base.elf32(20))
        not_elf = self.root / "not-elf"
        not_elf.write_bytes(b"hello")
        cases = {
            "only one ISA": ["--speaker-mips", str(self.mips_speaker)],
            "controls without a speaker": ["--speaker-controls"],
            "host catalog without a speaker": ["--speaker-host-catalog", str(self.root / "x")],
            "not a file": ["--speaker-mips", str(self.root / "absent"), "--speaker-ppc", str(self.ppc_speaker)],
            "dynamic binary": ["--speaker-mips", str(dynamic), "--speaker-ppc", str(self.ppc_speaker)],
            "ppc binary given as mips": ["--speaker-mips", str(wrong_machine), "--speaker-ppc", str(self.ppc_speaker)],
            "not an ELF": ["--speaker-mips", str(not_elf), "--speaker-ppc", str(self.ppc_speaker)],
        }
        for label, argv in cases.items():
            with self.subTest(label):
                self.refused(argv)

    def test_a_host_catalog_that_fails_the_check_is_refused_before_any_guest(self):
        tampered = copy.deepcopy(GOOD_ROWS)
        tampered[0]["profile_id"] = "bp-0000000000000000"
        host = self.root / "host-catalog.json"
        host.write_bytes(catalog_bytes(tampered))
        message = self.refused(self.speaker_argv("--speaker-host-catalog", str(host)))
        self.assertIn("does not satisfy the catalog check", message)
        self.assertIn("row0.profile_id", message)

    # -- --check-catalog -------------------------------------------------------------------------------------------------------

    def check(self, data):
        path = self.root / "catalog.json"
        path.write_bytes(data)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = VERIFIER.main(["--check-catalog", str(path)])
        return code, json.loads(out.getvalue())

    def test_check_catalog_passes_the_unplanted_catalog_and_reports_what_a_guest_must_equal(self):
        code, report = self.check(GOOD_DATA)
        self.assertEqual((code, report["status"], report["problems"]), (0, "PASS", []))
        self.assertEqual((report["stdout_bytes"], report["stdout_fnv1a64"]),
                         (len(GOOD_DATA), f"{E.fnv1a64(GOOD_DATA):016x}"))
        self.assertEqual(report["rows_expected"], 9)

    def test_check_catalog_fails_a_planted_fault_with_the_problem_named(self):
        rows = copy.deepcopy(GOOD_ROWS)
        rows[3]["nominal_flash_mib"] = 1
        code, report = self.check(catalog_bytes(rows))
        self.assertEqual((code, report["status"]), (1, "FAIL"))
        self.assertTrue(any("row3.nominal_flash_mib" in p for p in report["problems"]))

    def test_check_catalog_stands_alone(self):
        self.refused(["--check-catalog", str(self.root / "x"), "--speaker-controls"])
        self.refused(["--check-catalog", str(self.root / "no-such-file")])


if __name__ == "__main__":
    unittest.main()
