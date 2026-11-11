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

STEMS = {"s02_decode", "s02_bridge", "s02_admission", "s02_reader"}


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



def heap_records():
    """Synthetic controls shaped like the producer, never native evidence."""
    result = []
    for tid, (frames, rate, size, lossless) in rc.HEAP_TRACKS.items():
        first = "process_first_use" if tid == "vorbis_44100" else "track_first_use_after_shared"
        for phase in (first, "warm"):
            result.append({"schema": "s02.codec-heap.v1", "id": tid, "phase": phase, "scope": rc.HEAP_SCOPE,
                           "release": "net_zero", "frames": frames, "decoded_fnv1a64": lossless or "1234567890abcdef",
                           "bridge_frames": (frames * 160 + 146) // 147 if rate == 44100 else frames,
                           "bridge_fnv1a64": "1234567890abcdef", "peak_requested_bytes": size,
                           "net_requested_bytes": 0, "allocations": 1, "reallocations": 0,
                           "deallocations": 1, "bytes_requested": size, "elapsed_ms": 0})
    return result


def heap_log(directory, name, status="ok", records=None):
    path = fabricate_log(directory, name, {(rc.HEAP_STEM, rc.HEAP_TEST): status}, stems={rc.HEAP_STEM})
    with open(path, "a", encoding="utf-8") as f:
        for record in heap_records() if records is None else records:
            f.write(rc.HEAP_MARKER + json.dumps(record) + "\n")
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
    def test_original_case_mapping_is_unchanged(self):
        import hashlib
        cases, problem = rc.load_cases()
        self.assertEqual(problem, "")
        self.assertEqual(len(cases), 62)
        original = [(c["id"], c["stem"], c["tests"], c["rows"]) for c in cases
                    if c["id"] not in ("S02-HEAP-PROBE", "S02-READER")]
        self.assertEqual(len(original), 60)
        digest = hashlib.sha256(json.dumps(original, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, "fc2b88c928d431fc24e62ad7daf807cfdec803b78d333ab224f65aa21b28b743")

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
            os.chmod(extra, os.stat(extra).st_mode | 0o200)
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

    def test_ignored_new_rust_test_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            for rel, _stem in rc.RUST_TEST_FILES:
                os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
                shutil.copy(os.path.join(rc.REPO, rel), os.path.join(tmp, rel))
            extra = os.path.join(tmp, rc.RUST_TEST_FILES[-1][0])
            os.chmod(extra, os.stat(extra).st_mode | 0o200)
            with open(extra, "a", encoding="utf-8") as f:
                f.write("\n#[test]\n#[ignore]\nfn unregistered_ignored_probe() {}\n")
            self.assertIn((rc.HEAP_STEM, "unregistered_ignored_probe"), rc.derive_rust_tests(tmp))

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
        status = statuses.get((rc.HEAP_STEM, rc.HEAP_TEST))
        if status is not None:
            logs.add(heap_log(self.tmp.name, "heap-" + name, status))
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
        path = fabricate_log(self.tmp.name, "counts.txt", self.all_ok)
        with open(path, "a", encoding="utf-8") as f:
            f.write("test x ... S02-STATS id=vorbis_44100 packets=40 blocks=30 frames=22080 bytes_in=21295 decode_errors=0 empty_packets=1 "
                    "max_block_frames=1024 max_out_capacity_samples=2048\n")
            f.write("S02-ERR id=vorbis_44100 max_abs_lsb=2 rms_lsb=0.7100\n")
        logs = rc.Logs()
        logs.add(path)
        counts = rc.host_counts(logs)
        self.assertIn("not CPU, heap or stack", counts["scope"])
        self.assertEqual(counts["tracks"]["vorbis_44100"]["max_block_frames"], 1024)
        self.assertEqual(counts["errors"]["vorbis_44100"]["max_abs_lsb"], 2)
        self.assertEqual(counts["worst"]["max_block_frames"]["track"], "vorbis_44100")



class ReaderEvidenceTests(unittest.TestCase):
    def setUp(self):
        cases, problem = rc.load_cases()
        self.assertEqual(problem, "")
        self.case = next(case for case in cases if case["id"] == "S02-READER")
        self.names = self.case["tests"]
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_exact_reader_source_is_registered_and_attributed(self):
        derived = [name for stem, name in rc.derive_rust_tests() if stem == "s02_reader"]
        self.assertEqual(len(derived), 8)
        self.assertEqual(derived, self.names)
        path = "crates/franken-codec/tests/s02_reader.rs"
        self.assertIn(path, rc.JUDGED_ARTIFACTS)
        self.assertEqual(rc.artifact_digests()[path], rc.sha256_file(os.path.join(rc.REPO, path)))
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, path)
            os.makedirs(os.path.dirname(target))
            shutil.copyfile(os.path.join(rc.REPO, path), target)
            with mock.patch.object(rc, "REPO", tmp):
                before = rc.artifact_digests()[path]
                with open(target, "a", encoding="utf-8") as output:
                    output.write("\n// changed source control\n")
                self.assertNotEqual(rc.artifact_digests()[path], before)

    def test_each_reader_verdict_requires_one_attributed_ok(self):
        for name in self.names:
            for variation in ("ok", "missing", "ignored", "FAILED", "duplicate ok", "ok then failed", "failed then ok", "repeated input"):
                with self.subTest(name=name, variation=variation):
                    statuses = {("s02_reader", item): "ok" for item in self.names}
                    if variation == "missing":
                        del statuses[("s02_reader", name)]
                    elif variation in ("ignored", "FAILED"):
                        statuses[("s02_reader", name)] = variation
                    elif variation == "failed then ok":
                        statuses[("s02_reader", name)] = "FAILED"
                    path = fabricate_log(self.tmp.name, "%s-%s.log" % (name, variation.replace(" ", "-")),
                                         statuses, stems={"s02_reader"})
                    if variation in ("duplicate ok", "ok then failed", "failed then ok"):
                        verdict = "FAILED" if variation == "ok then failed" else "ok"
                        with open(path, "a", encoding="utf-8") as output:
                            output.write("     Running tests/s02_reader.rs (target/debug/deps/s02_reader-0123456789abcdef)\n"
                                         "running 1 test\ntest %s ... %s\ntest result: ok.\n" % (name, verdict))
                    logs = rc.Logs()
                    logs.add(path)
                    if variation == "repeated input":
                        logs.add(path)
                    result = rc.judge_rust_case(self.case, logs)
                    if variation == "ok":
                        self.assertEqual(result.status, "passed", result.detail)
                    elif variation == "FAILED":
                        self.assertEqual(result.status, "failed", result.detail)
                    else:
                        self.assertEqual(result.status, "blocked", result.detail)
                    if variation in ("duplicate ok", "ok then failed", "failed then ok", "repeated input"):
                        self.assertEqual(logs.test_status("s02_reader", name), "AMBIGUOUS")

    def test_missing_reader_evidence_keeps_linked_rows_unproven(self):
        cases, _ = rc.load_cases()
        results = [rc.Result(case["id"], "passed") for case in cases]
        next(result for result in results if result.case_id == "S02-READER").status = "blocked"
        table = {row["row"]: row["state"] for row in rc.ledger_table(cases, results)}
        self.assertEqual(self.case["rows"], ["spotify.ogg_vorbis", "spotify.mp3"])
        for row in self.case["rows"]:
            self.assertEqual(table[row], "unproven", row)
        for row in ("airplay.alac_44100_s16", "airplay.alac_48000_s24", "airplay.aac_lc_stereo", "airplay.pcm_s16be"):
            self.assertEqual(table[row], "host_decode_verified", row)
            dependency = next(case["id"] for case in cases if row in case["rows"])
            own_result = next(result for result in results if result.case_id == dependency)
            own_result.status = "failed"
            affected = {entry["row"]: entry["state"] for entry in rc.ledger_table(cases, results)}
            self.assertEqual(affected[row], "unproven", row)
            own_result.status = "passed"
        self.assertEqual(table["airplay.aac_lc_multichannel"], "blocked")
        self.assertEqual(table["spotify.aac"], "not_requested_by_pin")

    def test_reader_name_in_another_binary_does_not_count(self):
        statuses = {("s02_decode", name): "ok" for name in self.names}
        path = fabricate_log(self.tmp.name, "wrong-binary.log", statuses, stems={"s02_decode"})
        logs = rc.Logs()
        logs.add(path)
        self.assertEqual(rc.judge_rust_case(self.case, logs).status, "blocked")

    def test_unattributed_reader_names_never_prove_which_binary_ran(self):
        lines = "".join("test %s ... ok\n" % name for name in self.names)
        headers = {
            "wrong binary malformed count": "     Running tests/s02_decode.rs (target/debug/deps/s02_decode-0123456789abcdef)\nrunning 9 tests\n",
            "reader binary malformed count": "     Running tests/s02_reader.rs (target/debug/deps/s02_reader-0123456789abcdef)\nrunning 9 tests\n",
            "headerless section": "running 8 tests\n",
            "orphan lines": "",
        }
        for label, header in headers.items():
            with self.subTest(label=label):
                path = os.path.join(self.tmp.name, label.replace(" ", "-") + ".log")
                with open(path, "x", encoding="utf-8") as output:
                    output.write(header + lines + "test result: ok.\n")
                logs = rc.Logs()
                logs.add(path)
                self.assertTrue(logs.unattributed_logs)
                self.assertEqual(rc.judge_rust_case(self.case, logs).status, "blocked")
                for name in self.names:
                    self.assertIn((None, name), logs.tests)
                    self.assertIsNone(logs.test_status("s02_reader", name))


class BoundedLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_real_regular_log_captured_with_original_path_and_digest(self):
        import hashlib
        path = fabricate_log(self.tmp.name, "regular.log", {("s02_decode", "small_test"): "ok"}, stems={"s02_decode"})
        with open(path, "rb") as f:
            original = f.read()
        logs = rc.Logs()
        logs.add(path)
        self.assertEqual(logs.files, [(path, hashlib.sha256(original).hexdigest())])
        self.assertEqual(logs.test_status("s02_decode", "small_test"), "ok")
        self.assertEqual(logs.captured[logs.files[0]][0], original.decode("utf-8"))

    def test_fifo_directory_oversize_and_invalid_utf8_are_refused(self):
        fifo = self.path("fifo")
        os.mkfifo(fifo)
        oversized = self.path("large.log")
        with open(oversized, "wb") as f:
            f.truncate(rc.MAX_LOG_BYTES + 1)
        invalid = self.path("invalid.log")
        with open(invalid, "wb") as f:
            f.write(b"\xff")
        for path in (fifo, self.tmp.name, oversized, invalid):
            with self.subTest(path=path):
                with self.assertRaises((ValueError, OSError)):
                    rc.Logs().add(path)
        permitted = self.path("small.log")
        with open(permitted, "wb") as f:
            f.write(b"valid UTF-8\n")
        self.assertEqual(rc.read_log(permitted)[1], "valid UTF-8\n")

    def test_growing_past_the_limit_is_refused_even_after_small_stat(self):
        oversized = self.path("grew.log")
        with open(oversized, "wb") as f:
            f.truncate(rc.MAX_LOG_BYTES + 1)
        real = os.stat(oversized)
        claimed = mock.Mock(st_mode=real.st_mode, st_size=1)
        with mock.patch.object(rc.os, "fstat", return_value=claimed):
            with self.assertRaisesRegex(ValueError, "grew beyond"):
                rc.read_log(oversized)
        with open(self.path("good.log"), "wb") as f:
            f.write(b"good")
        self.assertEqual(rc.read_log(self.path("good.log"))[0], b"good")

    def test_changed_original_does_not_change_result_heap_or_counts(self):
        path = heap_log(self.tmp.name, "heap-captured.log")
        with open(path, "a", encoding="utf-8") as f:
            f.write("S02-STATS id=vorbis_44100 packets=40 bytes_in=21295\n")
        logs = rc.Logs()
        logs.add(path)
        prior = list(logs.files)
        with open(path, "w", encoding="utf-8") as f:
            f.write("changed original; not the captured log\n")
        self.assertEqual(logs.files, prior)
        self.assertEqual(logs.test_status(rc.HEAP_STEM, rc.HEAP_TEST), "ok")
        self.assertEqual(rc.heap_evidence(logs)[0].status, "passed")
        self.assertEqual(rc.host_counts(logs)["tracks"]["vorbis_44100"]["packets"], 40)
        self.assertNotEqual(prior[0][1], rc.sha256_file(path))

    def test_actual_aggregate_byte_limit_counts_duplicates_and_refuses_one_over(self):
        full = self.path("eight-mib.log")
        with open(full, "wb") as f:
            f.write(b"#" * (rc.MAX_LOG_BYTES - 1) + b"\n")
        one = self.path("one-byte.log")
        with open(one, "wb") as f:
            f.write(b"x")
        logs = rc.Logs()
        for _ in range(rc.MAX_JUDGED_BYTES // rc.MAX_LOG_BYTES):
            logs.add(full)
        self.assertEqual(logs.judged_bytes, rc.MAX_JUDGED_BYTES)
        self.assertEqual(logs.judged_inputs, 4)
        self.assertEqual(len(logs.files), 1)
        self.assertEqual(len(logs.repeated_inputs), 3)
        self.assertEqual(len(logs.private_snapshot_directories), 1)
        with self.assertRaisesRegex(ValueError, "aggregate"):
            logs.add(one)
        self.assertEqual(logs.judged_bytes, rc.MAX_JUDGED_BYTES)
        self.assertEqual(len(logs.files), 1)
        self.assertEqual(len(logs.private_snapshot_directories), 1)

    def test_actual_count_limit_allows_64_repeated_inputs_and_refuses_65th(self):
        path = fabricate_log(self.tmp.name, "bounded-count.log", {("s02_decode", "small_test"): "ok"}, stems={"s02_decode"})
        logs = rc.Logs()
        for _ in range(rc.MAX_JUDGED_INPUTS):
            logs.add(path)
        self.assertEqual(logs.judged_inputs, 64)
        self.assertEqual(logs.judged_bytes, os.stat(path).st_size * 64)
        self.assertEqual(len(logs.repeated_inputs), 63)
        self.assertEqual(logs.test_status("s02_decode", "small_test"), "ok")
        with self.assertRaisesRegex(ValueError, "count limit"):
            logs.add(path)
        self.assertEqual(logs.judged_inputs, 64)
        self.assertEqual(len(logs.private_snapshot_directories), 1)

    def test_excess_cli_input_fails_without_judging_partial_logs(self):
        import io
        path = fabricate_log(self.tmp.name, "cli.log", {("s02_decode", "small_test"): "ok"}, stems={"s02_decode"})
        with mock.patch.object(rc, "run") as run, mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(rc.main(["--judge"] + [path] * 65), 2)
            run.assert_not_called()
            self.assertIn("count limit", err.getvalue())
            self.assertIn("private snapshot retained:", err.getvalue())

    def test_actual_two_logs_preserve_codec_and_heap_attribution(self):
        codec = fabricate_log(self.tmp.name, "codec.log", {("s02_decode", "small_test"): "ok"}, stems={"s02_decode"})
        probe = heap_log(self.tmp.name, "heap.log")
        logs = rc.Logs()
        logs.add(codec)
        logs.add(probe)
        self.assertEqual(logs.judged_inputs, 2)
        self.assertEqual(logs.judged_bytes, os.stat(codec).st_size + os.stat(probe).st_size)
        self.assertEqual(logs.test_status("s02_decode", "small_test"), "ok")
        self.assertEqual(rc.heap_evidence(logs)[0].status, "passed")
        self.assertEqual(len(logs.private_snapshot_directories), 2)
        for directory in logs.private_snapshot_directories:
            self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)

    def test_aggregate_growth_after_stat_is_refused(self):
        path = self.path("growing-aggregate.log")
        with open(path, "wb") as f:
            f.write(b"ab")
        info = os.stat(path)
        with mock.patch.object(rc.os, "fstat", return_value=mock.Mock(st_mode=info.st_mode, st_size=1)):
            with self.assertRaisesRegex(ValueError, "aggregate"):
                rc.read_log(path, 1)
        self.assertEqual(rc.read_log(path, 2)[0], b"ab")

    def test_receipt_names_retained_private_snapshot_directories(self):
        path = fabricate_log(self.tmp.name, "recorded.log", {("s02_decode", "small_test"): "ok"}, stems={"s02_decode"})
        logs = rc.Logs()
        logs.add(path)
        receipt_path = rc.write_receipt(self.tmp.name, "full", [rc.Result("control", "passed")], {}, logs, run_id="snapshot-control")
        receipt = load(receipt_path)
        self.assertEqual(receipt["private_snapshot_directories"], logs.private_snapshot_directories)
        self.assertEqual(receipt["judged_logs"][0]["path"], "recorded.log")
        self.assertEqual(receipt["judged_logs"][0]["sha256"], logs.files[0][1])

    def test_same_path_different_capture_retains_d01_conflict_and_repeats(self):
        path = fabricate_log(self.tmp.name, "versions.log", {("s02_decode", "same_test"): "ok"}, stems={"s02_decode"})
        logs = rc.Logs()
        logs.add(path)
        logs.add(path)
        self.assertEqual(logs.repeated_inputs, ["versions.log"])
        with open(path, "w", encoding="utf-8") as f:
            f.write("     Running tests/s02_decode.rs (target/debug/deps/s02_decode-0123456789abcdef)\n"
                    "running 1 tests\ntest same_test ... FAILED\n"
                    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
        logs.add(path)
        self.assertEqual(len(logs.files), 2)
        self.assertNotEqual(logs.files[0][1], logs.files[1][1])
        self.assertEqual(logs.test_status("s02_decode", "same_test"), "CONFLICT")
        self.assertIn("... ok", logs.captured[logs.files[0]][0])
        self.assertIn("... FAILED", logs.captured[logs.files[1]][0])


class ReplayFidelityTests(unittest.TestCase):
    """Exercise the real existing CLI over retained snapshots, not an equivalent-input recipe."""

    def setUp(self):
        import subprocess  # noqa: F401
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = os.path.join(self.tmp.name, "private runtime")
        self.root = root
        os.makedirs(os.path.join(root, "tests"))
        shutil.copytree(os.path.join(rc.REPO, "tests", "s02"), os.path.join(root, "tests", "s02"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        os.symlink(os.path.join(rc.REPO, "tests", "d01"), os.path.join(root, "tests", "d01"))
        os.symlink(os.path.join(rc.REPO, "crates"), os.path.join(root, "crates"))
        os.symlink(os.path.join(rc.REPO, "docs"), os.path.join(root, "docs"))
        os.makedirs(os.path.join(root, "scripts", "e2e"))
        os.symlink(os.path.join(rc.REPO, "scripts", "test"), os.path.join(root, "scripts", "test"))
        self.runner = os.path.join(root, "scripts", "e2e", "s02")
        shutil.copy(os.path.join(rc.REPO, "scripts", "e2e", "s02"), self.runner)
        for name in ("Cargo.lock", "rust-toolchain.toml"):
            original = os.path.join(rc.REPO, name)
            if os.path.isfile(original):
                os.symlink(original, os.path.join(root, name))
        for folder in ("codec", "probe"):
            os.makedirs(os.path.join(self.tmp.name, folder))
        cases, problem = rc.load_cases()
        self.assertEqual(problem, "")
        statuses = {(c["stem"], test): "ok" for c in cases for test in c["tests"]}
        self.codec = fabricate_log(os.path.join(self.tmp.name, "codec"), "same name.log", statuses)
        self.probe = heap_log(os.path.join(self.tmp.name, "probe"), "same name.log")

    def actual_run(self, command, directory):
        import subprocess
        os.mkdir(directory)
        done = subprocess.run(command + ["--receipts", directory], cwd=self.tmp.name,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        receipts = [x for x in os.listdir(directory) if x.startswith("s02-") and x.endswith(".json")]
        self.assertEqual(len(receipts), 1, done.stderr + done.stdout)
        return done, load(os.path.join(directory, receipts[0]))

    def test_replay_actual_two_logs_after_mutation_with_same_basename(self):
        import shlex
        first, receipt = self.actual_run([self.runner, "--tier", "smoke", "--judge", self.codec, self.probe],
                                         os.path.join(self.tmp.name, "first receipt"))
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        case = next(r for r in receipt["results"] if r["id"] == "S02-HEAP-PROBE")
        self.assertEqual(case["status"], "passed")
        attempts = receipt["judged_attempts"]
        self.assertEqual([a["original_path"] for a in attempts], [self.codec, self.probe])
        self.assertEqual([a["duplicate"] for a in attempts], [False, False])
        self.assertNotEqual(attempts[0]["snapshot_path"], attempts[1]["snapshot_path"])
        self.assertEqual(os.path.basename(attempts[0]["snapshot_path"]), "same name.log")
        for attempt in attempts:
            self.assertTrue(os.path.isabs(attempt["snapshot_path"]))
            self.assertEqual(rc.sha256_file(attempt["snapshot_path"]), attempt["sha256"])
        with open(self.codec, "w", encoding="utf-8") as f:
            f.write("changed codec original\n")
        with open(self.probe, "w", encoding="utf-8") as f:
            f.write("changed probe original\n")
        replay_args = shlex.split(receipt["replay"])
        self.assertEqual(os.path.realpath(replay_args[0]), os.path.realpath(self.runner))
        self.assertEqual(replay_args[replay_args.index("--judge") + 1:], [a["snapshot_path"] for a in attempts])
        second, replayed = self.actual_run(replay_args, os.path.join(self.tmp.name, "second receipt"))
        self.assertEqual(second.returncode, first.returncode, second.stderr + second.stdout)
        self.assertEqual(replayed["counts"], receipt["counts"])
        self.assertEqual(replayed["results"], receipt["results"])
        self.assertEqual(replayed["host_heap"], receipt["host_heap"])

    def test_replay_preserves_duplicate_refusal_and_order(self):
        import shlex
        first, receipt = self.actual_run([self.runner, "--tier", "smoke", "--judge", self.codec, self.probe, self.codec],
                                         os.path.join(self.tmp.name, "duplicate first"))
        self.assertEqual(first.returncode, 3, first.stderr + first.stdout)
        original = next(r for r in receipt["results"] if r["id"] == "S02-HEAP-PROBE")
        self.assertEqual(original["status"], "blocked")
        attempts = receipt["judged_attempts"]
        self.assertEqual([a["original_path"] for a in attempts], [self.codec, self.probe, self.codec])
        self.assertEqual([a["duplicate"] for a in attempts], [False, False, True])
        self.assertEqual(attempts[0]["snapshot_path"], attempts[2]["snapshot_path"])
        args = shlex.split(receipt["replay"])
        self.assertEqual(args[args.index("--judge") + 1:], [a["snapshot_path"] for a in attempts])
        second, replayed = self.actual_run(args, os.path.join(self.tmp.name, "duplicate second"))
        self.assertEqual(second.returncode, 3, second.stderr + second.stdout)
        self.assertEqual(replayed["counts"], receipt["counts"])
        self.assertEqual(replayed["results"], receipt["results"])
        self.assertEqual([a["duplicate"] for a in replayed["judged_attempts"]], [False, False, True])


class HeapEvidenceTests(unittest.TestCase):
    """Paired synthetic controls for the actual frozen record schema and D01 attribution."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.counter = 0

    def evidence(self, records, status="ok"):
        self.counter += 1
        path = heap_log(self.tmp.name, "heap%d.txt" % self.counter, status, records)
        logs = rc.Logs()
        logs.add(path)
        return rc.heap_evidence(logs)

    def test_permitted_first_and_warm_records_with_unknown_first_net(self):
        records = heap_records()
        records[0]["net_requested_bytes"] = 37
        records[0]["release"] = "unknown_nonzero_net"
        result, evidence = self.evidence(records)
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(len(evidence["records"]), 18)
        self.assertIn("not streaming steady-state, RSS or board admission", evidence["scope"])

    def test_missing_duplicate_unknown_and_wrong_phase_are_not_passes(self):
        original = heap_records()
        variants = [original[:-1], original + [copy.deepcopy(original[0])]]
        for field, value in (("id", "unknown"), ("phase", "process_first_use")):
            bad = copy.deepcopy(original)
            bad[2][field] = value
            variants.append(bad)
        for bad in variants:
            self.assertNotEqual(self.evidence(bad)[0].status, "passed")
        self.assertEqual(self.evidence(original)[0].status, "passed")

    def test_bad_fields_and_wrong_values_fail_with_paired_good_record(self):
        original = heap_records()
        variants = []
        for field, value in (("schema", "wrong"), ("scope", "board"), ("frames", 0),
                             ("bridge_frames", 0), ("allocations", 0), ("peak_requested_bytes", 0),
                             ("bytes_requested", 0), ("decoded_fnv1a64", "oops"),
                             ("release", "net_zero"), ("net_requested_bytes", True)):
            bad = copy.deepcopy(original)
            bad[1][field] = value
            if field == "release":
                bad[1]["net_requested_bytes"] = 1
            variants.append(bad)
        for bad in variants:
            self.assertEqual(self.evidence(bad)[0].status, "failed")
        bad = copy.deepcopy(original)
        bad[1]["bridge_fnv1a64"] = "0000000000000000"
        self.assertEqual(self.evidence(bad)[0].status, "failed")
        self.assertEqual(self.evidence(original)[0].status, "passed")

    def test_lossless_digest_and_output_pair_are_checked(self):
        original = heap_records()
        bad = copy.deepcopy(original)
        next(x for x in bad if x["id"] == "alac_44100_16")["decoded_fnv1a64"] = "0000000000000000"
        self.assertEqual(self.evidence(bad)[0].status, "failed")
        self.assertEqual(self.evidence(original)[0].status, "passed")

    def test_failed_ignored_and_missing_native_test_never_qualify(self):
        case = {"id": "S02-HEAP-PROBE", "group": "heap", "stem": rc.HEAP_STEM, "tests": [rc.HEAP_TEST]}
        self.assertEqual(rc.judge_rust_case(case, None).status, "blocked")
        for status, wanted in (("FAILED", "failed"), ("ignored", "blocked"), ("ok", "passed")):
            self.counter += 1
            path = heap_log(self.tmp.name, "test%d.txt" % self.counter, status)
            logs = rc.Logs()
            logs.add(path)
            self.assertEqual(rc.judge_rust_case(case, logs).status, wanted)

    def test_repeated_input_and_ambiguous_probe_are_blocked(self):
        self.counter += 1
        path = heap_log(self.tmp.name, "repeat%d.txt" % self.counter)
        logs = rc.Logs()
        logs.add(path)
        self.assertEqual(rc.heap_evidence(logs)[0].status, "passed")
        logs.add(path)
        self.assertEqual(rc.heap_evidence(logs)[0].status, "blocked")
        logs = rc.Logs()
        logs.add(path)
        case = {"id": "S02-HEAP-PROBE", "group": "heap", "stem": rc.HEAP_STEM, "tests": [rc.HEAP_TEST]}
        logs.conflicting_tests.add((rc.HEAP_STEM, rc.HEAP_TEST))
        self.assertEqual(rc.judge_rust_case(case, logs).status, "blocked")
        logs.conflicting_tests.clear()
        logs.tests = {(None, rc.HEAP_TEST): "ok"}
        logs.ambiguous_names.add(rc.HEAP_TEST)
        self.assertEqual(rc.judge_rust_case(case, logs).status, "blocked")

    def test_actual_q00_critical_loss_prevents_qualification(self):
        diag = rc.case_log.load(rc.REPO)
        result = rc.Result("S02-HEAP-PROBE", "passed", "synthetic control", "heap")
        for capacity, complete in ((None, True), (100, False)):
            target = diag.FaultableSink(capacity_bytes=capacity)
            log = rc.case_log.CaseLog.open(rc.REPO, "heap-control", "full", target=target)
            log.record(result.case_id, result.group, result.status, result.detail)
            evidence = log.finish(rc.summarize([result]))
            self.assertEqual(evidence.complete, complete, evidence.reasons)
            self.assertEqual(rc.final_exit([result], evidence), 0 if complete else 1)

    def test_malformed_and_duplicate_json_keys_fail(self):
        for raw in ('{', '{"id":"x","id":"y"}'):
            self.counter += 1
            path = heap_log(self.tmp.name, "bad%d.txt" % self.counter)
            with open(path, "a", encoding="utf-8") as f:
                f.write(rc.HEAP_MARKER + raw + "\n")
            logs = rc.Logs()
            logs.add(path)
            self.assertEqual(rc.heap_evidence(logs)[0].status, "failed")
        self.assertEqual(self.evidence(heap_records())[0].status, "passed")


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
