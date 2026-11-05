"""Tests of tests/n01/fuzz_judge.py, the judge of the central N01 fuzz logs (docs/contracts/n01.md section 11).

The judge reads text a fuzzer left behind, so every test here feeds it hand-written libFuzzer-shaped logs: good ones it must
accept, and planted-bad ones it must refuse, each for its own reason (the permitted positive for every rule is the good log
the planted one was made from). A mutation pass then switches off each rule of the judge in memory and requires that some
planted log slips through, on a baseline where none does. Nothing here runs a fuzzer or Rust; the agreement tests read the
Rust sources and fail if the judge's constants drift from them.
"""

import base64
import hashlib
import re
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzz_judge as fj  # noqa: E402
import reference_frames as rf  # noqa: E402

FUZZ = rf.ROOT / "crates" / "franken-stream" / "fuzz"
JUDGE_PATH = Path(fj.__file__).resolve()
KEY = fj.load_key()
WIRE = rf.DEFAULT_VECTORS


def golden(vector_id):
    import json
    doc = json.loads(WIRE.read_text(encoding="utf-8"))
    return next(bytes.fromhex(v["wire_hex"]) for v in doc["vectors"] if v["id"] == vector_id)


def with_payload_len(length):
    """`1 || header` asking the target to re-sign a header that declares `length` payload bytes."""
    header = bytearray(golden("N01-GV-002")[: rf.HEADER_LEN])
    header[60:62] = (length // 4).to_bytes(2, "big")
    header[62:64] = length.to_bytes(2, "big")
    return bytes([fj.MODE_RESIGN]) + bytes(header)


CRASH = with_payload_len(fj.CONTROL_PAYLOAD_LEN)
CRASH_NAME = "crash-" + hashlib.sha1(CRASH).hexdigest()

SEEDS_LOG = "\n".join("N01-FUZZ-SEEDS %s files=%d max_bytes=%d" % (t, n, m) for t, n, m in (
    ("stream_decode", 52, 1105), ("stream_receiver", 2, 3400), ("negotiation_respond", 16, 117),
    ("negotiation_finish", 16, 117))) + "\n"


def clean_log(execs=210000, seconds=10, cov0=321, cov=330, files=52, extra=""):
    return """INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3141592
INFO: Loaded 1 modules   (1432 inline 8-bit counters): 1432 [0x55d0, 0x5b78),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 8192 bytes
INFO: seed corpus: files: %(files)d min: 4b max: 1104b total: 15032b rss: 40Mb
#%(files1)d\tINITED cov: %(cov0)d ft: 612 corp: 40/6Kb exec/s: 0 rss: 41Mb
#4096\tpulse  cov: %(cov0)d ft: 640 corp: 41/6Kb lim: 4096 exec/s: 2048 rss: 42Mb
#%(execs)d\tDONE   cov: %(cov)d ft: 701 corp: 48/9Kb lim: 8192 exec/s: 21000 rss: 45Mb
%(extra)sDone %(execs)d runs in %(seconds)d second(s)
stat::number_of_executed_units: %(execs)d
""" % {"files": files, "files1": files + 1, "cov0": cov0, "cov": cov, "execs": execs, "seconds": seconds, "extra": extra}


def control_log(artifact=CRASH_NAME, message="planted decoder bug: payload length 516", extra_tail="", printed=CRASH):
    """`printed` is the input libFuzzer prints as 'Base64:' under the artifact line (it does so for inputs of at most 256 bytes);
    None leaves the line out."""
    base64_line = "" if printed is None else "Base64: %s\n" % base64.b64encode(printed).decode()
    return """INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1
INFO: seed corpus: files: 52 min: 1b max: 1104b total: 15032b rss: 40Mb
#53\tINITED cov: 321 ft: 612 corp: 40/6Kb exec/s: 0 rss: 41Mb
#81234\tNEW    cov: 340 ft: 700 corp: 45/7Kb lim: 8192 exec/s: 40000 rss: 43Mb L: 600/1100 MS: 3 ChangeBit-InsertByte-CrossOver-
thread '<unnamed>' panicked at src/stream.rs:60:13:
%s
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
==4242== ERROR: libFuzzer: deathly signal
SUMMARY: libFuzzer: deathly signal
artifact_prefix='./artifacts/'; Test unit written to ./artifacts/stream_decode/%s
%s%s""" % (message, artifact, base64_line, extra_tail)


class Anchors(unittest.TestCase):
    def test_the_re_sign_rule_gives_back_every_accepted_golden_vector(self):
        import json
        doc = json.loads(WIRE.read_text(encoding="utf-8"))
        accepted = [bytes.fromhex(v["wire_hex"]) for v in doc["vectors"] if v["expect"] == "ACCEPT"]
        self.assertGreaterEqual(len(accepted), 7)
        for datagram in accepted:
            self.assertEqual(fj.resign(KEY, datagram[: -rf.TAG_LEN]), datagram)
            self.assertEqual(fj.datagram_for(KEY, bytes([1]) + datagram[: -rf.TAG_LEN]), datagram)
            self.assertEqual(fj.datagram_for(KEY, bytes([0]) + datagram), datagram)

    def test_the_re_sign_rule_follows_the_declared_length_and_caps_it(self):
        body = golden("N01-GV-002")[: -rf.TAG_LEN]
        declared = int.from_bytes(body[62:64], "big")
        self.assertEqual(len(fj.resign(KEY, body + b"\x07" * 40)), rf.HEADER_LEN + declared + rf.TAG_LEN)
        self.assertEqual(len(fj.resign(KEY, body[: rf.HEADER_LEN + 2])), rf.HEADER_LEN + declared + rf.TAG_LEN)
        self.assertEqual(len(fj.resign(KEY, b"")), rf.HEADER_LEN + rf.TAG_LEN)
        huge = body[:62] + b"\xff\xff" + body[64:]
        self.assertEqual(len(fj.resign(KEY, huge)), rf.HEADER_LEN + 2 * rf.MAX_PAYLOAD + rf.TAG_LEN)

    def test_only_an_accepted_packet_of_the_planted_length_triggers_the_plant(self):
        self.assertTrue(fj.triggers_the_plant(CRASH, KEY))
        # the paired positives: a neighbouring length, and the same length with a forged tag
        self.assertFalse(fj.triggers_the_plant(with_payload_len(512), KEY))
        self.assertFalse(fj.triggers_the_plant(with_payload_len(520), KEY))
        raw = bytearray(fj.resign(KEY, CRASH[1:]))
        self.assertTrue(fj.triggers_the_plant(bytes([0]) + bytes(raw), KEY))
        raw[-1] ^= 1
        self.assertFalse(fj.triggers_the_plant(bytes([0]) + bytes(raw), KEY))
        # the same length but a header the contract refuses (frame count that does not match)
        bad = bytearray(CRASH)
        bad[1 + 61] ^= 0x01
        self.assertFalse(fj.triggers_the_plant(bytes(bad), KEY))
        self.assertFalse(fj.triggers_the_plant(b"", KEY))
        self.assertFalse(fj.triggers_the_plant(bytes([1]), KEY))

    def test_the_planted_length_is_one_no_golden_vector_has(self):
        import json
        doc = json.loads(WIRE.read_text(encoding="utf-8"))
        lengths = {len(bytes.fromhex(v["wire_hex"])) - 80 for v in doc["vectors"] if v["expect"] == "ACCEPT"}
        self.assertNotIn(fj.CONTROL_PAYLOAD_LEN, lengths)
        self.assertEqual(fj.CONTROL_PAYLOAD_LEN % 4, 0)
        self.assertLessEqual(fj.CONTROL_PAYLOAD_LEN, rf.MAX_PAYLOAD)


class Positives(unittest.TestCase):
    def test_a_real_looking_clean_log_passes_for_every_target(self):
        for target in fj.TARGETS:
            problems, record = fj.judge_run(clean_log(), target, "clean", 10, seed_files=52)
            self.assertEqual(problems, [], target)
            self.assertEqual((record["executions"], record["crashes"], record["coverage"]), (210000, 0, 330))

    def test_a_control_log_with_the_planted_crash_passes(self):
        problems, record = fj.judge_run(control_log(), "stream_decode", "control", 10, crash=CRASH)
        self.assertEqual(problems, [])
        self.assertEqual((record["crashes"], record["artifact"]), (1, CRASH_NAME))
        self.assertEqual(record["crash_sha256"], hashlib.sha256(CRASH).hexdigest())

    def test_a_control_log_that_printed_the_crash_input_passes_without_a_file(self):
        problems, record = fj.judge_run(control_log(), "stream_decode", "control", 10)
        self.assertEqual(problems, [])
        self.assertEqual((record["crash_source"], record["crash_bytes"]), ("log", len(CRASH)))
        self.assertEqual(fj.judge_run(control_log(), "stream_decode", "control", 10, crash=CRASH)[1]["crash_source"], "file")
        self.assertEqual(fj.crash_in_log(control_log().replace("\n", "\r\n")), CRASH)
        self.assertEqual(len(CRASH), 65, "the smallest crash input of the plant: mode byte plus one header")

    def test_the_seed_manifest_passes(self):
        problems, files = fj.judge_seeds(SEEDS_LOG)
        self.assertEqual(problems, [])
        self.assertEqual(files, {"stream_decode": 52, "stream_receiver": 2, "negotiation_respond": 16, "negotiation_finish": 16})

    def test_console_noise_and_crlf_do_not_matter(self):
        noisy = "boot noise\r\n" + clean_log().replace("\n", "\r\n")
        self.assertEqual(fj.judge_run(noisy, "stream_decode", "clean", 10)[0], [])

    def test_the_command_line_exits_zero_on_a_good_log_and_one_on_a_bad_one(self):
        import io
        import tempfile
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            good, bad, seeds, crash = (Path(tmp) / n for n in ("good.log", "bad.log", "seeds.log", "crash.bin"))
            good.write_text(clean_log())
            bad.write_text(clean_log(execs=10, seconds=10))
            seeds.write_text(SEEDS_LOG)
            crash.write_bytes(CRASH)
            control = Path(tmp) / "control.log"
            control.write_text(control_log())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(fj.main(["run", str(good), "--target", "stream_decode", "--kind", "clean", "--budget", "10",
                                          "--seeds-log", str(seeds)]), 0)
                self.assertEqual(fj.main(["run", str(bad), "--target", "stream_decode", "--kind", "clean", "--budget", "10"]), 1)
                self.assertEqual(fj.main(["run", str(control), "--target", "stream_decode", "--kind", "control", "--budget", "10",
                                          "--crash", str(crash)]), 0)
                self.assertEqual(fj.main(["seeds", str(seeds)]), 0)


def run_clean(m, text, target="stream_decode", budget=10, seed_files=None, kind="clean", min_execs=50000):
    return m.judge_run(text, target, kind, budget, min_execs, seed_files)[0]


def run_control(m, text, crash=CRASH, target="stream_decode"):
    return m.judge_run(text, target, "control", 10, 50000, None, crash)[0]


def negative_cases():
    """(label, runner(module) -> problems, required substring). Each is a good log with exactly one thing wrong."""
    other_crash = with_payload_len(512)
    raw_forged = bytearray(fj.resign(KEY, CRASH[1:]))
    raw_forged[-1] ^= 1
    forged = bytes([0]) + bytes(raw_forged)
    forged_name = "crash-" + hashlib.sha1(forged).hexdigest()
    return [
        ("clean run with a libFuzzer crash", lambda m: run_clean(m, clean_log(extra="==9== ERROR: libFuzzer: deathly signal\n")), "shows a crash"),
        ("clean run with a panic", lambda m: run_clean(m, clean_log(extra="thread 'main' panicked at x.rs:1:1:\n")), "shows a crash"),
        ("clean run that never finished", lambda m: run_clean(m, re.sub(r"^Done.*\n", "", clean_log(), flags=re.M)), "did not finish"),
        ("too few executions", lambda m: run_clean(m, clean_log(execs=900)), "fewer than the floor"),
        ("budget not spent", lambda m: run_clean(m, clean_log(seconds=3)), "before its 10 s budget"),
        ("no coverage lines", lambda m: run_clean(m, re.sub(r"^#.*\n", "", clean_log(), flags=re.M)), "no coverage status"),
        ("zero coverage", lambda m: run_clean(m, clean_log(cov0=0, cov=0)), "coverage is zero"),
        ("seed corpus never loaded", lambda m: run_clean(m, re.sub(r"^#\d+\tINITED.*\n", "", clean_log(), flags=re.M)), "never loaded"),
        ("coverage fell", lambda m: run_clean(m, clean_log(cov0=400, cov=330)), "coverage fell"),
        ("no seeds line", lambda m: run_clean(m, re.sub(r"^INFO: seed corpus.*\n", "", clean_log(), flags=re.M)), "without seeds"),
        ("fewer seed files than the manifest", lambda m: run_clean(m, clean_log(files=10), seed_files=52), "seed files"),
        ("unknown target", lambda m: run_clean(m, clean_log(), target="stream_other"), "unknown target"),
        ("control kind on a target without a plant", lambda m: run_control(m, control_log(), target="stream_receiver"), "has no control"),
        ("control run that found nothing", lambda m: run_control(m, clean_log()), "without a crash"),
        ("control run without the planted message", lambda m: run_control(m, control_log(message="boom")), "no planted-bug panic"),
        ("control run with another payload length", lambda m: run_control(m, control_log(message="planted decoder bug: payload length 512")), "not 516"),
        ("control run that crashed on something else", lambda m: run_control(m, control_log(extra_tail="thread 'x' panicked at a.rs:1:1:\nstream_decode: oracle violated\n").replace("planted decoder bug: payload length 516", "stream_decode: oracle violated")), "not on the planted bug"),
        ("control run libFuzzer never reported", lambda m: run_control(m, control_log().replace("ERROR: libFuzzer", "oops").replace("deathly signal", "dead")), "did not report"),
        ("control run that kept no artifact", lambda m: run_control(m, re.sub(r"^.*Test unit written.*\n", "", control_log(), flags=re.M)), "was not kept"),
        ("control run with no crash input anywhere", lambda m: run_control(m, control_log(printed=None), crash=None), "no crash input"),
        ("control run whose printed input is not base64", lambda m: run_control(m, re.sub(r"^Base64: .*$", "Base64: !!!!", control_log(), flags=re.M), crash=None), "no crash input"),
        ("control run whose printed input has bad padding", lambda m: run_control(m, re.sub(r"^Base64: .*$", "Base64: AQ=", control_log(), flags=re.M), crash=None), "no crash input"),
        ("printed input that is not the named artifact", lambda m: run_control(m, control_log(printed=other_crash), crash=None), "SHA-1 differs"),
        ("printed input that does not trigger the plant", lambda m: run_control(m, control_log(artifact="crash-" + hashlib.sha1(other_crash).hexdigest(), printed=other_crash), crash=None), "is not an accepted packet"),
        ("crash file that is not the named artifact", lambda m: run_control(m, control_log(), crash=other_crash), "SHA-1 differs"),
        ("crash input that does not trigger the plant", lambda m: run_control(m, control_log(artifact="crash-" + hashlib.sha1(other_crash).hexdigest()), crash=other_crash), "is not an accepted packet"),
        ("crash input with a forged tag", lambda m: run_control(m, control_log(artifact=forged_name), crash=forged), "is not an accepted packet"),
        ("manifest without a target", lambda m: m.judge_seeds(SEEDS_LOG.replace("negotiation_finish", "negotiation_other"))[0], "no line for negotiation_finish"),
        ("manifest naming a target twice", lambda m: m.judge_seeds(SEEDS_LOG + "N01-FUZZ-SEEDS stream_decode files=1 max_bytes=1\n")[0], "twice"),
        ("manifest with an empty target", lambda m: m.judge_seeds(SEEDS_LOG.replace("files=16 max_bytes=117\n", "files=0 max_bytes=0\n", 1))[0], "no seeds"),
        ("manifest with an unknown target", lambda m: m.judge_seeds(SEEDS_LOG + "N01-FUZZ-SEEDS stream_extra files=1 max_bytes=1\n")[0], "unknown target"),
    ]


def has(problems, needle):
    return any(needle in p for p in problems)


class Negatives(unittest.TestCase):
    def test_each_planted_bad_log_is_refused_for_its_own_reason(self):
        for label, runner, needle in negative_cases():
            with self.subTest(label):
                problems = runner(fj)
                self.assertTrue(has(problems, needle), "%s: %r" % (label, problems))

    def test_there_are_enough_planted_cases_and_each_has_a_distinct_reason(self):
        cases = negative_cases()
        self.assertGreaterEqual(len(cases), 30)
        self.assertEqual(len({label for label, _, _ in cases}), len(cases))


class Mutations(unittest.TestCase):
    """Switch off one rule of the judge in memory; some planted log must then get through. The baseline is green."""

    MUTANTS = [
        ("clean run crash check", '        if crashed:\n            problems.append("a clean run shows a crash', '        if False:\n            problems.append("a clean run shows a crash'),
        ("Done line required", '        if not done:\n            problems.append("no \'Done N runs\' line', '        if False:\n            problems.append("no \'Done N runs\' line'),
        ("execution floor", "if int(done.group(1)) < min_execs:", "if False:"),
        ("budget spent", "if int(done.group(2)) < budget:", "if False:"),
        ("status lines required", "        if not status:\n            problems.append(\"no coverage status lines\")", "        if False:\n            problems.append(\"no coverage status lines\")"),
        ("coverage non-zero", "elif status[-1][2] < 1:", "elif False:"),
        ("seeds loaded", "        if status and not initial:", "        if False:"),
        ("coverage not falling", "elif initial and status[-1][2] < initial[0][2]:", "elif False:"),
        ("seed line required", "        if not corpus:\n            problems.append(\"no 'seed corpus", "        if False:\n            problems.append(\"no 'seed corpus"),
        ("seed files vs manifest", "elif seed_files is not None and int(corpus.group(1)) < seed_files:", "elif False:"),
        ("control must crash", "        if done:\n            problems.append(\"the control run finished", "        if False:\n            problems.append(\"the control run finished"),
        ("other panic is not the plant", '        if "panicked at" in text and not planted:', "        if False:"),
        ("plant message required", "        if not planted:\n            problems.append(\"no planted-bug", "        if False:\n            problems.append(\"no planted-bug"),
        ("plant length", "elif int(planted.group(1)) != CONTROL_PAYLOAD_LEN:", "elif False:"),
        ("libFuzzer report", 'if "ERROR: libFuzzer" not in text and "deathly signal" not in text:', "if False:"),
        ("artifact kept", "        if not artifact:\n            problems.append(\"no 'Test unit", "        if False:\n            problems.append(\"no 'Test unit"),
        ("crash input supplied", "        if crash is None:\n            problems.append(\"no crash input", "        if False:\n            problems.append(\"no crash input"),
        ("crash input read from the log", 'crash, crash_source = crash_in_log(text), "log"', 'crash, crash_source = None, "log"'),
        ("a bad base64 line is no input", "    except ValueError:\n        return None", "    except ValueError:\n        raise"),
        ("crash file is the artifact", "if artifact and hashlib.sha1(crash)", "if False and hashlib.sha1(crash)"),
        ("crash input triggers the plant", "if not triggers_the_plant(crash):", "if False:"),
        ("trigger needs an accepted packet", 'return verdict == "ACCEPT" and len(datagram)', "return len(datagram)"),
        ("target without a control", "if kind == \"control\" and target != CONTROL_TARGET:", "if False:"),
        ("unknown target", "    if target not in TARGETS:\n        problems.append(\"unknown target", "    if False:\n        problems.append(\"unknown target"),
        ("manifest duplicates", "        if target in files:", "        if False:"),
        ("manifest missing target", "        if target not in files:", "        if False:"),
        ("manifest empty target", "        elif files[target] < 1:", "        elif False:"),
        ("manifest unknown target", "        if target not in TARGETS:\n            problems.append(\"seed manifest names an unknown", "        if False:\n            problems.append(\"seed manifest names an unknown"),
    ]

    @staticmethod
    def mutated(old, new):
        source = JUDGE_PATH.read_text(encoding="utf-8")
        if source.count(old) != 1:
            raise AssertionError("the mutant anchor occurs %d times: %r" % (source.count(old), old[:60]))
        namespace = {"__name__": "mutant", "__file__": str(JUDGE_PATH)}
        exec(compile(source.replace(old, new), "mutant.py", "exec"), namespace)  # noqa: S102 - a planted mutant, run in memory
        return types.SimpleNamespace(**namespace)

    @staticmethod
    def undetected(module):
        """The planted cases a judge fails to report. A judge that crashes on one has not reported it either."""
        missed = []
        for label, runner, needle in negative_cases():
            try:
                found = has(runner(module), needle)
            except Exception:  # noqa: BLE001 - a mutated judge may fail in any way
                found = False
            if not found:
                missed.append(label)
        return missed

    def test_the_baseline_judge_misses_nothing(self):
        self.assertEqual(self.undetected(fj), [])

    def test_each_rule_switched_off_lets_a_planted_log_through(self):
        self.assertGreaterEqual(len(self.MUTANTS), 27)
        for label, old, new in self.MUTANTS:
            with self.subTest(label):
                self.assertNotEqual(self.undetected(self.mutated(old, new)), [], label)


def source_of(path):
    return (FUZZ / path).read_text(encoding="utf-8")


def manifest_sections():
    sections, current = {}, None
    for raw in source_of("Cargo.toml").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line.strip("[]")
            sections.setdefault(current, [])
        elif line and not line.startswith("#") and current is not None:
            sections[current].append(line)
    return sections


class RustAgreement(unittest.TestCase):
    """The Rust sources and this judge cannot drift apart unseen. These read the source; they do not run it."""

    def test_the_planted_constant_and_message_are_the_judges(self):
        plant = source_of("src/plant.rs")
        self.assertIn("pub const CONTROL_PAYLOAD_LEN: usize = %d;" % fj.CONTROL_PAYLOAD_LEN, plant)
        self.assertIn(fj.PLANT_MESSAGE + " {CONTROL_PAYLOAD_LEN}", plant)
        self.assertIn('cfg!(feature = "control")', plant)

    def test_the_re_sign_mode_and_cap_are_the_judges(self):
        wire = source_of("src/wire.rs")
        self.assertIn("pub const MODE_RESIGN: u8 = %d;" % fj.MODE_RESIGN, wire)
        self.assertIn(".min(2 * MAX_PAYLOAD)", wire)
        self.assertEqual(fj.RESIGN_PAYLOAD_CAP, 2 * 1024)

    def test_the_target_names_are_the_judges_and_each_has_a_libfuzzer_binary(self):
        seed = source_of("src/seed.rs")
        names = re.findall(r'pub const (STREAM_DECODE|STREAM_RECEIVER|NEGOTIATION_RESPOND|NEGOTIATION_FINISH): &str = "(\w+)";', seed)
        self.assertEqual(tuple(name for _, name in names), fj.TARGETS)
        calls = {"stream_decode": "stream::run_decode", "stream_receiver": "stream::run_receiver",
                 "negotiation_respond": "hello::run_respond", "negotiation_finish": "hello::run_finish"}
        for target in fj.TARGETS:
            text = source_of("fuzz_targets/%s.rs" % target)
            self.assertIn("franken_stream_fuzz::" + calls[target] + "(data)", text)
            self.assertIn("#![no_main]", text)

    def test_the_manifest_declares_the_targets_the_control_feature_and_its_own_workspace(self):
        sections = manifest_sections()
        self.assertIn("workspace", sections, "the fuzz crate must be its own workspace root")
        self.assertIn("control = []", sections["features"])
        bins = [line.split("=", 1)[1].strip().strip('"') for line in sections["bin"] if line.startswith("name")]
        self.assertEqual(sorted(bins), sorted(list(fj.TARGETS) + ["seed_corpus"]))
        deps = sorted(line.split("=")[0].strip() for line in sections["dependencies"])
        self.assertEqual(deps, ["franken-stream", "hmac", "libfuzzer-sys", "serde_json", "sha2"])
        self.assertNotIn("dev-dependencies", sections)
        self.assertIn('franken-stream = { path = ".." }', sections["dependencies"])

    def test_the_repository_workspace_does_not_list_the_fuzz_crate(self):
        root = (rf.ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertNotIn("franken-stream/fuzz", root)
        self.assertNotIn("franken-stream-fuzz", root)

    def test_the_seed_manifest_line_is_the_judges_format(self):
        text = source_of("src/bin/seed_corpus.rs")
        self.assertIn('"N01-FUZZ-SEEDS {target} files={files} max_bytes={max_bytes}"', text)
        self.assertTrue(fj.SEEDS_RE.match("N01-FUZZ-SEEDS stream_decode files=3 max_bytes=9"))

    def test_no_production_code_carries_the_plant(self):
        for rel in ("src/lib.rs", "src/negotiation.rs"):
            text = (rf.ROOT / "crates" / "franken-stream" / rel).read_text(encoding="utf-8")
            self.assertNotIn("planted", text, rel)
            self.assertNotIn("control_payload", text.lower(), rel)


if __name__ == "__main__":
    unittest.main()
