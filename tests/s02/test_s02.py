#!/usr/bin/env python3
"""Tests of the S02 judge and its oracles (stdlib unittest; numpy/scipy tests skip loudly, never pass silently).

Each rule has a green control and a plant: the unmodified input passes, and a copy with exactly one thing wrong makes exactly that check fail.

    python3 -I tests/s02/test_s02.py
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

import bridge_reference as br  # noqa: E402
import ledger_check  # noqa: E402
import make_vectors as mv  # noqa: E402
import run_cases as rc  # noqa: E402

try:
    import numpy  # noqa: F401
    import scipy  # noqa: F401
    HAVE_NUMPY = True
except Exception:  # noqa: BLE001
    HAVE_NUMPY = False

STEMS = {"s02_decode", "s02_bridge", "s02_admission"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fabricate_log(directory, name, statuses, stems=STEMS):
    """A libtest-shaped log: one `Running` header and one section per binary, with the given {(stem, test): status}."""
    lines = []
    for stem in sorted(stems):
        tests = sorted(t for (s, t) in statuses if s == stem)
        lines.append("     Running tests/%s.rs (target/debug/deps/%s-0123456789abcdef)" % (stem, stem))
        lines.append("running %d tests" % len(tests))
        for t in tests:
            lines.append("test %s ... %s" % (t, statuses[(stem, t)]))
        lines.append("")
        lines.append("test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s" % len(tests))
        lines.append("")
    path = os.path.join(directory, name)
    with open(path, "x", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = load(rc.os.path.join(HERE, "negotiated.json"))
        self.manifest = load(rc.MANIFEST)

    def test_green_control(self):
        self.assertEqual(ledger_check.check(self.ledger, self.manifest), [])

    def test_deleting_the_blocked_multichannel_row_fails(self):
        bad = copy.deepcopy(self.ledger)
        bad["rows"] = [r for r in bad["rows"] if r["id"] != "airplay.aac_lc_multichannel"]
        problems = ledger_check.check(bad, self.manifest)
        self.assertTrue(any("airplay.aac_lc_multichannel" in p and "missing" in p for p in problems), problems)

    def test_recording_a_pass_in_the_ledger_fails(self):
        bad = copy.deepcopy(self.ledger)
        next(r for r in bad["rows"] if r["id"] == "spotify.mp3")["status"] = "passed"
        problems = ledger_check.check(bad, self.manifest)
        self.assertTrue(any("spotify.mp3" in p and "status" in p for p in problems), problems)

    def test_unblocking_without_a_test_fails(self):
        bad = copy.deepcopy(self.ledger)
        next(r for r in bad["rows"] if r["id"] == "airplay.aac_lc_multichannel")["status"] = "decode_path_unproven"
        self.assertTrue(ledger_check.check(bad, self.manifest))

    def test_blocked_row_needs_a_reason(self):
        bad = copy.deepcopy(self.ledger)
        next(r for r in bad["rows"] if r["id"] == "airplay.aac_lc_multichannel")["blocked_by"] = ""
        self.assertTrue(any("without a stated reason" in p for p in ledger_check.check(bad, self.manifest)))

    def test_a_mandatory_row_without_a_vector_fails(self):
        bad = copy.deepcopy(self.ledger)
        next(r for r in bad["rows"] if r["id"] == "airplay.alac_48000_s24")["vectors"] = []
        self.assertTrue(any("without vectors" in p for p in ledger_check.check(bad, self.manifest)))

    def test_a_vector_with_the_wrong_rate_fails(self):
        bad = copy.deepcopy(self.ledger)
        next(r for r in bad["rows"] if r["id"] == "airplay.alac_44100_s16")["vectors"] = ["alac_48000_24"]
        self.assertTrue(any("rate" in p for p in ledger_check.check(bad, self.manifest)))

    def test_the_rate_boundary_must_name_the_bridge(self):
        bad = copy.deepcopy(self.ledger)
        bad["rate_boundary"]["rule"] = "resample somehow"
        self.assertTrue(any("160/147" in p for p in ledger_check.check(bad, self.manifest)))


class CaseRegistryTests(unittest.TestCase):
    def test_every_rust_test_is_registered_exactly_once(self):
        cases, problem = rc.load_cases()
        self.assertEqual(problem, "")
        result = rc.meta_coverage(cases)
        self.assertEqual(result.status, "passed", result.detail)

    def test_an_unregistered_rust_test_fails_coverage(self):
        cases, _ = rc.load_cases()
        with tempfile.TemporaryDirectory() as tmp:
            for rel, _stem in rc.RUST_TEST_FILES:
                os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
                shutil.copy(os.path.join(rc.REPO, rel), os.path.join(tmp, rel))
            extra = os.path.join(tmp, rc.RUST_TEST_FILES[0][0])
            with open(extra, "a", encoding="utf-8") as f:
                f.write("\n#[test]\nfn s02_a_test_nobody_registered() {}\n")
            derived = rc.derive_rust_tests(tmp)
        registered = {(c["stem"], t) for c in cases for t in c["tests"]}
        self.assertEqual(sorted(set(derived) - registered), [("s02_decode", "s02_a_test_nobody_registered")])

    def test_a_registered_test_that_does_not_exist_fails_coverage(self):
        cases, _ = rc.load_cases()
        bad = copy.deepcopy(cases)
        bad[0]["tests"] = ["s02_no_such_test"]
        result = rc.meta_coverage(bad)
        self.assertEqual(result.status, "failed")
        self.assertIn("s02_no_such_test", result.detail)

    def test_the_macro_generated_bridge_tests_are_found(self):
        names = {n for _, n in rc.derive_rust_tests()}
        self.assertIn("s02_bridge_vector_noise_tri", names)
        self.assertIn("s02_bridge_vector_tone_18000", names)


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.cases, _ = rc.load_cases()
        self.all_ok = {(c["stem"], t): "ok" for c in self.cases for t in c["tests"]}
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def judge(self, statuses, name="log.txt"):
        logs = rc.Logs()
        logs.add(fabricate_log(self.tmp.name, name, statuses))
        return {c["id"]: rc.judge_rust_case(c, logs) for c in self.cases}, logs

    def test_green_control_every_case_passes_and_every_ledger_row_resolves(self):
        results, _ = self.judge(self.all_ok)
        self.assertEqual({r.status for r in results.values()}, {"passed"})
        table = {row["row"]: row["state"] for row in rc.ledger_table(self.cases, list(results.values()))}
        self.assertEqual(table["airplay.aac_lc_multichannel"], "blocked")
        self.assertEqual(table["spotify.aac"], "not_requested_by_pin")
        for row in ("spotify.ogg_vorbis", "spotify.mp3", "airplay.alac_44100_s16", "airplay.alac_48000_s24", "airplay.aac_lc_stereo",
                    "airplay.pcm_s16be"):
            self.assertEqual(table[row], "host_decode_verified", row)

    def test_no_log_blocks_everything(self):
        for case in self.cases:
            self.assertEqual(rc.judge_rust_case(case, None).status, "blocked")

    def test_one_failed_test_fails_its_case_only_and_unverifies_its_rows(self):
        statuses = dict(self.all_ok)
        statuses[("s02_decode", "s02_mp3_44100_decodes_within_tolerance_with_the_gapless_length")] = "FAILED"
        results, _ = self.judge(statuses)
        self.assertEqual(results["S02-DEC-MP3-44100"].status, "failed")
        self.assertEqual([i for i, r in results.items() if r.status == "failed"], ["S02-DEC-MP3-44100"])
        table = {row["row"]: row["state"] for row in rc.ledger_table(self.cases, list(results.values()))}
        self.assertEqual(table["spotify.mp3"], "unproven")
        self.assertEqual(table["spotify.ogg_vorbis"], "host_decode_verified")

    def test_a_test_missing_from_the_log_blocks_its_case(self):
        statuses = dict(self.all_ok)
        del statuses[("s02_bridge", "s02_bridge_dc_is_exact_once_the_history_is_full")]
        results, _ = self.judge(statuses)
        self.assertEqual(results["S02-BRG-DC"].status, "blocked")
        self.assertEqual(sum(1 for r in results.values() if r.status != "passed"), 1)

    def test_an_ignored_test_is_not_a_pass(self):
        statuses = dict(self.all_ok)
        statuses[("s02_bridge", "s02_bridge_reset_restores_a_fresh_start")] = "ignored"
        results, _ = self.judge(statuses)
        self.assertEqual(results["S02-BRG-RESET"].status, "blocked")

    def test_a_test_reported_under_the_wrong_binary_does_not_count(self):
        statuses = dict(self.all_ok)
        moved = ("s02_bridge", "s02_bridge_reset_restores_a_fresh_start")
        del statuses[moved]
        statuses[("s02_decode", moved[1])] = "ok"
        results, _ = self.judge(statuses)
        self.assertNotEqual(results["S02-BRG-RESET"].status, "passed")

    def test_host_counts_are_read_from_the_log_and_labelled(self):
        _, logs = self.judge(self.all_ok, "counts.txt")
        with open(logs.files[0][0], "a", encoding="utf-8") as f:
            f.write("test x ... S02-STATS id=vorbis_44100 packets=40 blocks=30 frames=22080 bytes_in=21295 decode_errors=0 empty_packets=1 "
                    "max_block_frames=1024 max_out_capacity_samples=2048\n")
            f.write("S02-ERR id=vorbis_44100 max_abs_lsb=2 rms_lsb=0.7100\n")
        counts = rc.host_counts(logs)
        self.assertIn("not CPU, heap or stack", counts["scope"])
        self.assertEqual(counts["tracks"]["vorbis_44100"]["max_block_frames"], 1024)
        self.assertEqual(counts["errors"]["vorbis_44100"]["max_abs_lsb"], 2)
        self.assertEqual(counts["worst"]["max_block_frames"]["track"], "vorbis_44100")


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def pair_errors(a, b):
    """(largest absolute error, rms error) between two interleaved little-endian 16-bit byte strings of equal length."""
    import struct
    assert len(a) == len(b) and len(a) % 2 == 0
    xs, ys = struct.unpack("<%dh" % (len(a) // 2), a), struct.unpack("<%dh" % (len(b) // 2), b)
    peak, acc = 0, 0
    for x, y in zip(xs, ys):
        d = x - y
        peak = max(peak, abs(d))
        acc += d * d
    return peak, (acc / len(xs)) ** 0.5


OLD_BAD_REFERENCE_SHA256 = {
    "vorbis_44100": "5aff53cc8c24e823383429c707effc81ed937339488f50f6c76e618f5baadb25",
    "vorbis_48000": "6bd94c5212edac48aa81e30d52700ae7f962b3bf037f39d8b523b8a9532d7862",
}
ORIGINAL_OGG_SHA256 = {
    "vorbis_44100.ogg": "4b53d3e8499deb4f776fc420f52b20ccd8d6c7f7e9d3bad0f723d8276dce2b04",
    "vorbis_48000.ogg": "de7d8f0c485ca2e3708523f9b27b60c23130b0101d0b9cc8bd63968699d53139",
    "chain_vorbis_44100_48000.ogg": "cabbbb671734d1545b50739b0370907a6cd48453b4649dd9828a213dd41d9a28",
}


class VectorProvenanceTests(unittest.TestCase):
    """Independent decoders corroborate the corrected references; the old bytes remain a failing control, not a Rust PCM equality claim."""

    @classmethod
    def setUpClass(cls):
        cls.manifest = load(rc.MANIFEST)
        cls.vec = rc.VECTOR_DIR
        cls.tracks = {t["id"]: t for t in cls.manifest["tracks"]}

    def test_the_original_ogg_inputs_and_their_lengths_are_unchanged(self):
        import hashlib
        for name, digest in ORIGINAL_OGG_SHA256.items():
            self.assertEqual(hashlib.sha256(read_bytes(os.path.join(self.vec, name))).hexdigest(), digest, name)
        self.assertEqual((self.tracks["vorbis_44100"]["expected_frames"], self.tracks["vorbis_48000"]["expected_frames"]), (22080, 24000))
        self.assertEqual(self.tracks["chain_vorbis_44100_48000"]["first_part_frames"], 22080)

    def test_every_lossy_track_names_two_distinct_reference_decoders_that_agree(self):
        lossy = [t for t in self.manifest["tracks"] if "tolerance" in t]
        self.assertEqual(sorted(t["id"] for t in lossy), ["aac_lc_44100", "aac_lc_48000", "mp3_44100", "mp3_48000", "vorbis_44100", "vorbis_48000"])
        for t in lossy:
            inter = t["inter_reference"]
            self.assertEqual(len(inter["decoders"]), 2, t["id"])
            self.assertEqual(len(set(inter["decoders"])), 2, t["id"])
            self.assertLessEqual(inter["max_abs"], 1, t["id"])
            self.assertEqual(inter["frames_a"], inter["frames_b"], t["id"])
            self.assertEqual((t["tolerance"]["max_abs_lsb"], t["tolerance"]["rms_lsb"]), (4, 1.5), t["id"])
        for tid in ("vorbis_44100", "vorbis_48000"):
            self.assertEqual(self.tracks[tid]["inter_reference"]["decoders"], ["ffmpeg -cpuflags 0 (scalar)", "libvorbis"])
            self.assertEqual(self.tracks[tid]["reference"]["decoder"], "ffmpeg -cpuflags 0 (scalar)")

    def test_the_retained_bad_reference_is_the_one_the_failing_run_used_and_is_not_the_new_reference(self):
        for tid, digest in OLD_BAD_REFERENCE_SHA256.items():
            t = self.tracks[tid]
            retained = t["retained_bad_reference"]
            self.assertEqual(retained["sha256"], digest, tid)
            self.assertEqual(retained["failing_run"]["log_sha256"], "ad773e96b123eed8279e25f0728fdb0b43dd3077a8a9ce153c76e0d58e869270")
            self.assertNotEqual(retained["sha256"], t["reference"]["sha256"], tid)
            self.assertEqual(oracle_sha(read_bytes(os.path.join(self.vec, retained["file"]))), retained["sha256"])
            self.assertEqual(oracle_sha(read_bytes(os.path.join(self.vec, t["reference"]["file"]))), t["reference"]["sha256"])

    def test_discrimination_control_the_old_reference_fails_the_unchanged_tolerance_against_the_new_one(self):
        # Independently measured old-reference versus scalar-reference errors.
        # Matching rounded summaries never establishes equality with Rust PCM.
        independent_errors = {"vorbis_44100": (6095, 950.8378), "vorbis_48000": (6272, 922.7782)}
        for tid, (want_peak, want_rms) in independent_errors.items():
            t = self.tracks[tid]
            peak, rms = pair_errors(read_bytes(os.path.join(self.vec, t["retained_bad_reference"]["file"])), read_bytes(os.path.join(self.vec, t["reference"]["file"])))
            self.assertEqual(peak, want_peak, tid)
            self.assertAlmostEqual(rms, want_rms, places=3, msg=tid)
            self.assertGreater(peak, t["tolerance"]["max_abs_lsb"], tid)
            self.assertGreater(rms, t["tolerance"]["rms_lsb"], tid)

    def test_the_new_reference_equals_scalar_ffmpeg_byte_for_byte(self):
        import shutil
        import subprocess
        if shutil.which("ffmpeg") is None:
            self.skipTest("BLOCKED, not passed: ffmpeg is not installed")
        for tid in ("vorbis_44100", "vorbis_48000"):
            t = self.tracks[tid]
            out = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-cpuflags", "0", "-i", os.path.join(self.vec, t["file"]), "-f", "s16le",
                                  "-acodec", "pcm_s16le", "-"], capture_output=True, check=True, timeout=30).stdout
            self.assertEqual(out, read_bytes(os.path.join(self.vec, t["reference"]["file"])), tid)

    def test_the_new_reference_is_within_one_lsb_of_libvorbis(self):
        import subprocess
        import tempfile
        python = os.environ.get("S02_VORBIS_PYTHON")
        if not python:
            self.skipTest("BLOCKED, not passed: S02_VORBIS_PYTHON (a Python with numpy and soundfile) is not set")
        for tid in ("vorbis_44100", "vorbis_48000"):
            t = self.tracks[tid]
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "libvorbis.s16")
                subprocess.run([python, os.path.join(HERE, "vorbis_tool.py"), "decode", os.path.join(self.vec, t["file"]), out], check=True, timeout=30)
                peak, rms = pair_errors(read_bytes(out), read_bytes(os.path.join(self.vec, t["reference"]["file"])))
            self.assertLessEqual(peak, 1, tid)
            self.assertLess(rms, 0.1, tid)

    def test_a_flipped_bit_in_the_new_reference_is_not_the_manifest_hash(self):
        t = self.tracks["vorbis_44100"]
        blob = bytearray(read_bytes(os.path.join(self.vec, t["reference"]["file"])))
        blob[1000] ^= 1
        self.assertNotEqual(oracle_sha(bytes(blob)), t["reference"]["sha256"])


def oracle_sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


class ReferenceGeneratorPolicyTests(unittest.TestCase):
    """Command-policy and custody tests; codec agreement is tested above with actual decoders."""

    def test_vorbis_alone_is_scalar_and_default_ogg_decode_is_refused(self):
        self.assertEqual(mv.SCALAR_REFERENCE_CODECS, ("vorbis",))
        with mock.patch.object(mv, "run") as run:
            with self.assertRaisesRegex(ValueError, "requires scalar=True"):
                mv.ffmpeg_decode("probe.ogg")
            run.assert_not_called()

    def test_scalar_flag_precedes_input_and_other_codec_defaults_stay_unchanged(self):
        with mock.patch.object(mv, "run", return_value=mock.Mock(stdout=b"pcm")) as run:
            self.assertEqual(mv.ffmpeg_decode("probe.ogg", scalar=True), b"pcm")
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("-cpuflags") + 1], "0")
            self.assertLess(command.index("-cpuflags"), command.index("-i"))
            for path in ("probe.mp3", "probe.aac"):
                self.assertEqual(mv.ffmpeg_decode(path), b"pcm")
                self.assertNotIn("-cpuflags", run.call_args.args[0])

    def test_exact_reused_input_copies_the_observed_bad_control_without_decoding(self):
        track = next(t for t in load(rc.MANIFEST)["tracks"] if t["id"] == "vorbis_44100")
        stream = read_bytes(os.path.join(rc.VECTOR_DIR, track["file"]))
        with mock.patch.object(mv, "REUSE_VORBIS_DIR", rc.VECTOR_DIR), mock.patch.object(mv, "run") as run:
            record, bad = mv.reused_bad_vorbis_reference(track, stream)
            self.assertEqual(record, track["retained_bad_reference"])
            self.assertEqual(oracle_sha(bad), OLD_BAD_REFERENCE_SHA256[track["id"]])
            run.assert_not_called()
        with mock.patch.object(mv, "REUSE_VORBIS_DIR", None):
            self.assertIsNone(mv.reused_bad_vorbis_reference(track, stream))

    def test_changed_input_control_or_filename_cannot_inherit_the_archived_control(self):
        track = next(t for t in load(rc.MANIFEST)["tracks"] if t["id"] == "vorbis_44100")
        stream = read_bytes(os.path.join(rc.VECTOR_DIR, track["file"]))
        bad = read_bytes(os.path.join(rc.VECTOR_DIR, track["retained_bad_reference"]["file"]))
        for defect in ("stream", "control", "filename"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as tmp:
                row = copy.deepcopy(track)
                if defect == "filename":
                    row["retained_bad_reference"]["file"] = "../unrelated.s16"
                with open(os.path.join(tmp, mv.MANIFEST), "x", encoding="utf-8") as handle:
                    json.dump({"tracks": [row]}, handle)
                with open(os.path.join(tmp, track["retained_bad_reference"]["file"]), "xb") as handle:
                    handle.write(bad[:-1] + bytes([bad[-1] ^ 1]) if defect == "control" else bad)
                with mock.patch.object(mv, "REUSE_VORBIS_DIR", tmp), mock.patch.object(mv, "run") as run:
                    with self.assertRaises(RuntimeError):
                        mv.reused_bad_vorbis_reference(track, stream + b"changed" if defect == "stream" else stream)
                    run.assert_not_called()


class MetaPlantTests(unittest.TestCase):
    def test_the_contract_must_name_every_ledger_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "s02.md")
            with open(rc.CONTRACT, encoding="utf-8") as f:
                text = f.read()
            with open(bad, "x", encoding="utf-8") as f:
                f.write(text.replace("airplay.aac_lc_multichannel", "airplay.something_else"))
            saved = rc.CONTRACT
            rc.CONTRACT = bad
            try:
                result = rc.meta_contract()
            finally:
                rc.CONTRACT = saved
        self.assertEqual(result.status, "failed")
        self.assertIn("airplay.aac_lc_multichannel", result.detail)
        self.assertEqual(rc.meta_contract().status, "passed")

    def test_a_hand_edited_coefficient_table_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "rate_table.rs")
            with open(rc.RATE_TABLE, encoding="ascii") as f:
                text = f.read()
            self.assertIn("1001177500", text)
            with open(bad, "x", encoding="ascii") as f:
                f.write(text.replace("1001177500", "1001177501", 1))
            code, _out, err = rc.py("gen_rate_table.py", "--check", bad)
            self.assertEqual(code, 1, err)
            code, _out, err = rc.py("gen_rate_table.py", "--check", rc.RATE_TABLE)
            self.assertEqual(code, 0, err)

    def test_a_table_whose_phase_does_not_sum_to_one_is_refused_by_the_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "rate_table.rs")
            with open(rc.RATE_TABLE, encoding="ascii") as f:
                text = f.read()
            with open(bad, "x", encoding="ascii") as f:
                f.write(text.replace("1001177500", "1001177501", 1))
            with self.assertRaises(ValueError):
                br.load_table(bad)
        self.assertEqual(len(br.load_table()), 10240)

    def test_the_published_manifest_check_passes_and_a_stray_file_is_named(self):
        self.assertEqual(rc.meta_manifest().status, "passed")


@unittest.skipUnless(HAVE_NUMPY, "numpy/scipy unavailable: the bridge checks are BLOCKED, not passed")
class BridgePlantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = br.load_table()
        cls.committed = load(rc.BRIDGE_VECTORS)

    def test_the_committed_vectors_equal_a_fresh_derivation(self):
        fresh = br.derive(self.table)
        with open(rc.BRIDGE_VECTORS, encoding="utf-8") as handle:
            self.assertEqual(br.render(fresh), handle.read())

    def test_a_small_coefficient_error_that_keeps_the_phase_sum_changes_the_vectors(self):
        # 2^14 of Q30 is 1.5e-5 (-96 dB) of one tap. A single Q30 unit is below the Q23 output resolution and is caught by the table hash
        # (S02-META-TABLE) and the phase-sum check instead; the vectors are what notice anything audible.
        bad = list(self.table)
        bad[5 * br.K + 7] += 1 << 14
        bad[5 * br.K + 8] -= 1 << 14
        fresh = br.derive(bad)
        by_id = {c["id"]: c for c in fresh["cases"]}
        differing = [c["id"] for c in self.committed["cases"] if by_id[c["id"]]["out_sha256"] != c["out_sha256"]]
        self.assertTrue(differing, "no vector noticed a changed tap")

    def test_a_wrong_ratio_changes_the_vectors(self):
        saved = br.M
        br.M = 146
        try:
            fresh = br.derive(self.table)
        finally:
            br.M = saved
        by_id = {c["id"]: c for c in fresh["cases"]}
        same = [c["id"] for c in self.committed["cases"] if by_id[c["id"]]["frames_out"] == c["frames_out"] and
                by_id[c["id"]]["out_sha256"] == c["out_sha256"]]
        self.assertEqual(same, [], "a case survived a wrong ratio: %s" % same)

    def test_quality_judge_green_control_and_a_broken_filter(self):
        self.assertTrue(br.judge_table(self.table)["ok"])
        self.assertTrue(all(br.judge_tone(self.table, f, 0.0)["ok"] for f in (1000.0, 18000.0)))
        broken = list(self.table)
        for r in range(br.L):  # a filter that is still unity at DC but rings: move weight from one tap to its neighbour in every phase
            broken[r * br.K + 3] += 3_000_000
            broken[r * br.K + 4] -= 3_000_000
        self.assertFalse(br.judge_table(broken)["ok"] and all(br.judge_tone(broken, f, 0.0)["ok"] for f in (1000.0, 10000.0, 18000.0)))

    def test_the_mirror_reproduces_the_vectors_and_catches_a_wrong_advance(self):
        import bridge_mirror as mir
        self.assertEqual(mir.main(), 0)
        saved = mir.DOWN
        mir.DOWN = 146
        try:
            self.assertEqual(mir.main(), 1)
        finally:
            mir.DOWN = saved

    def test_the_bridge_delay_in_the_reference_is_the_stated_32_frames(self):
        impulse = [0] * 300
        impulse[100] = 1 << 22
        out = br.bridge(self.table, [impulse])[0][0]
        peak = max(range(len(out)), key=lambda i: abs(out[i]))
        self.assertLessEqual(abs(peak - (100 + br.DELAY_IN_FRAMES) * br.L / br.M), 1.0)

    def test_output_counts_follow_the_closed_form(self):
        for frames in (0, 1, 2, 146, 147, 148, 1000):
            outs, _ = br.bridge(self.table, [[0] * frames]) if frames else ([[]], 0)
            self.assertEqual(len(outs[0]), br.outputs_after(frames))


if __name__ == "__main__":
    unittest.main(verbosity=1)
