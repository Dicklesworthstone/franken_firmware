"""Checks on the N01 guest-transcript judge (bead ffw-ey5), run by scripts/e2e/n01.

They establish that the judge can tell a correct replay from a broken one: its anchors are independent (published FNV
vectors, the plants' verdicts derived by the Python reference AND written by hand), it passes a correct transcript for
both byte orders, it fails each planted-bad transcript for its own reason, and every one of its rules, switched off in
turn, is noticed. They do not run the Rust and do not see a guest.
"""

import sys
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guest_transcript as gt  # noqa: E402
import reference_frames as rf  # noqa: E402

WIRE = gt.load(gt.WIRE_VECTORS)
NEG = gt.load(gt.NEG_VECTORS)


def good(endian="big", bits=32):
    return "\n".join(gt.expected_lines(WIRE, NEG, endian, bits)) + "\n"


def problems(text, expect=None, judge=None):
    return (judge or gt.judge)(text, WIRE, NEG, expect)


def rewrite(text, startswith, change):
    """Apply `change(line) -> line or None (drop)` to every line that starts with `startswith`."""
    out = []
    for line in text.splitlines():
        if line.startswith(startswith):
            line = change(line)
            if line is None:
                continue
        out.append(line)
    return "\n".join(out) + "\n"


def with_pair(line, key, value):
    return " ".join("%s=%s" % (key, value) if t.startswith(key + "=") else t for t in line.split(" "))


def has(found, needle):
    return any(needle in p for p in found)


class Anchors(unittest.TestCase):
    def test_fnv_matches_the_published_test_vectors(self):
        self.assertEqual(gt.fnv1a64(b""), 0xCBF29CE484222325)
        self.assertEqual(gt.fnv1a64(b"a"), 0xAF63DC4C8601EC8C)
        self.assertEqual(gt.fnv1a64(b"foobar"), 0x85944171F73967E8)

    def test_the_probe_renderings_are_what_the_value_requires(self):
        value = 0x0102030405060708
        self.assertEqual(value.to_bytes(8, "big").hex(), gt.PROBE_BE)
        self.assertEqual(value.to_bytes(8, "little").hex(), gt.PROBE_LE)
        self.assertNotEqual(gt.PROBE_BE, gt.PROBE_LE)

    def test_the_planted_verdicts_written_by_hand_are_the_ones_the_python_decoder_derives(self):
        self.assertEqual(gt.derived_plant_verdicts(WIRE), gt.PLANT_EXPECTED)

    def test_the_resigning_control_reproduces_a_genuine_datagram_and_the_swap_is_the_byte_order_bug(self):
        key, wires = gt.plant_wires(WIRE)
        self.assertEqual(wires["resigned_untouched"], wires["untouched"])
        base = wires["untouched"]
        swapped = wires["frame_count_little_endian_resigned"]
        # the planted frame count: 256 written big-endian (01 00) became 00 01 = 1, against a 1024-byte payload
        self.assertEqual(int.from_bytes(base[60:62], "big"), 256)
        self.assertEqual(int.from_bytes(swapped[60:62], "big"), 1)
        self.assertEqual(int.from_bytes(swapped[62:64], "big"), 1024)
        # and it is authentic: the tag verifies, so only the structure refuses it
        self.assertEqual(swapped[-16:], rf.tag(key, swapped[:64], swapped[64:-16]))
        self.assertNotEqual(base, swapped)
        self.assertEqual(rf.decode(swapped, key)[0], "FRAME_COUNT_MISMATCH")

    def test_the_vector_files_are_the_size_the_judge_assumes(self):
        self.assertGreaterEqual(len(WIRE["vectors"]), 37)
        self.assertGreaterEqual(len(WIRE["scenarios"]), 2)
        self.assertGreaterEqual(len(NEG["negotiations"]), 4)
        self.assertGreaterEqual(len(NEG["rejections"]), 31)
        self.assertEqual(len(gt.PLANT_EXPECTED), 5)


class Positives(unittest.TestCase):
    def test_a_correct_transcript_passes_for_each_byte_order(self):
        self.assertEqual(problems(good("big", 32), "big"), [])
        self.assertEqual(problems(good("little", 64), "little"), [])
        self.assertEqual(problems(good("big", 32)), [])

    def test_console_noise_and_line_endings_around_the_transcript_are_ignored(self):
        noisy = ("FFW_SPEAKER_BEGIN path=/x\r\n" + good().replace("\n", "\r\n") + "random: crng init done\r\n"
                 "FFW_SPEAKER_EXIT status=0\r\n")
        self.assertEqual(problems(noisy, "big"), [])
        indented = "".join("   " + line + "\n" for line in good().splitlines())
        self.assertEqual(problems(indented, "big"), [])

    def test_the_format_is_pinned_by_hand_so_the_rust_and_the_judge_cannot_drift_together(self):
        lines = gt.expected_lines(WIRE, NEG, "big", 32)
        self.assertEqual(lines[0], "N01-GUEST v=1 endian=big pointer_bits=32 probe_native=0102030405060708 "
                                   "probe_be=0102030405060708 probe_le=0807060504030201")
        self.assertTrue(lines[1].startswith("N01-WIRE " + WIRE["vectors"][0]["id"] + " verdict="))
        self.assertRegex(lines[1], r" fields=(ok|na) reencode=(ok|na) fnv=[0-9a-f]{16}$")
        self.assertEqual([l for l in lines if l.startswith("N01-PLANT")], [
            "N01-PLANT untouched verdict=ACCEPT",
            "N01-PLANT resigned_untouched verdict=ACCEPT",
            "N01-PLANT payload_bit_flipped verdict=AUTH_FAILED",
            "N01-PLANT tag_bit_flipped verdict=AUTH_FAILED",
            "N01-PLANT frame_count_little_endian_resigned verdict=FRAME_COUNT_MISMATCH",
        ])
        self.assertEqual(lines[-1], "N01-DONE wire=%d scen=%d neg=%d negrej=%d plant=5 mismatches=0" % (
            len(WIRE["vectors"]), len(WIRE["scenarios"]), len(NEG["negotiations"]), len(NEG["rejections"])))


def first_accepted_id():
    return next(v["id"] for v in WIRE["vectors"] if v["expect"] == "ACCEPT")


def first_rejected_id():
    return next(v["id"] for v in WIRE["vectors"] if v["expect"] != "ACCEPT")


def negative_cases():
    """(label, log, required endian or None, a substring the judge must report)."""
    g = good()
    accepted, rejected = first_accepted_id(), first_rejected_id()
    scen = WIRE["scenarios"][0]["id"]
    neg = NEG["negotiations"][0]["id"]
    rej = NEG["rejections"][0]["id"]
    return [
        ("a wire vector is missing", rewrite(g, "N01-WIRE %s " % accepted, lambda l: None), None, "is missing"),
        ("a wire vector appears twice", g + g.splitlines()[1] + "\n", None, "more than once"),
        ("a vector the file does not have", g.replace("N01-DONE", "N01-WIRE N01-GV-999 verdict=ACCEPT fields=ok reencode=ok fnv=0000000000000000\nN01-DONE"), None, "is not in the vector file"),
        ("an accepted vector is rejected", rewrite(g, "N01-WIRE %s " % accepted, lambda l: with_pair(l, "verdict", "AUTH_FAILED")), None, "required ACCEPT"),
        ("a rejected vector is accepted", rewrite(g, "N01-WIRE %s " % rejected, lambda l: with_pair(l, "verdict", "ACCEPT")), None, "required"),
        ("the re-encode differs", rewrite(g, "N01-WIRE %s " % accepted, lambda l: with_pair(l, "reencode", "differ")), None, "reencode=differ"),
        ("the decoded fields differ", rewrite(g, "N01-WIRE %s " % accepted, lambda l: with_pair(l, "fields", "differ")), None, "fields=differ"),
        ("the datagram fingerprint is another's", rewrite(g, "N01-WIRE %s " % accepted, lambda l: with_pair(l, "fnv", "0123456789abcdef")), None, "fnv="),
        ("a scenario is missing", rewrite(g, "N01-SCEN %s " % scen, lambda l: None), None, "is missing"),
        ("a scenario's outcomes differ", rewrite(g, "N01-SCEN %s " % scen, lambda l: with_pair(l, "outcomes_fnv", "0000000000000001")), None, "outcomes_fnv"),
        ("a scenario's accepted count differs", rewrite(g, "N01-SCEN %s " % scen, lambda l: with_pair(l, "accepted", "0")), None, "accepted="),
        ("a scenario skipped steps", rewrite(g, "N01-SCEN %s " % scen, lambda l: with_pair(l, "steps", "1")), None, "steps="),
        ("a negotiation is missing", rewrite(g, "N01-NEG %s " % neg, lambda l: None), None, "is missing"),
        ("the transcript digest differs", rewrite(g, "N01-NEG %s " % neg, lambda l: with_pair(l, "transcript", "differ")), None, "transcript=differ"),
        ("the round trip failed", rewrite(g, "N01-NEG %s " % neg, lambda l: with_pair(l, "roundtrip", "differ")), None, "roundtrip=differ"),
        ("a rejection verdict is wrong", rewrite(g, "N01-NEGREJ %s " % rej, lambda l: with_pair(l, "verdict", "ACCEPT")), None, "required"),
        ("a rejection is judged by the wrong end", rewrite(g, "N01-NEGREJ %s " % rej, lambda l: with_pair(l, "op", "finish" if " op=respond" in l else "respond")), None, "op="),
        ("a planted datagram is missing", rewrite(g, "N01-PLANT tag_bit_flipped", lambda l: None), None, "planted datagram tag_bit_flipped is missing"),
        ("the planted bit flip is accepted", rewrite(g, "N01-PLANT payload_bit_flipped", lambda l: with_pair(l, "verdict", "ACCEPT")), None, "planted payload_bit_flipped"),
        ("the permitted positive is refused", rewrite(g, "N01-PLANT untouched", lambda l: with_pair(l, "verdict", "AUTH_FAILED")), None, "planted untouched"),
        ("the byte-order plant is refused for the wrong reason", rewrite(g, "N01-PLANT frame_count", lambda l: with_pair(l, "verdict", "AUTH_FAILED")), None, "FRAME_COUNT_MISMATCH"),
        ("the run was cut short", "\n".join(g.splitlines()[:-1]) + "\n", None, "N01-DONE"),
        ("the count line is wrong", rewrite(g, "N01-DONE", lambda l: with_pair(l, "wire", "36")), None, "N01-DONE wire=36"),
        ("the program reports its own mismatch", g.replace("N01-DONE", "N01-MISMATCH wire vector X: wanted ACCEPT\nN01-DONE"), None, "reported a mismatch of its own"),
        ("the done line is not last", g + "N01-WIRE N01-GV-001 verdict=ACCEPT fields=ok reencode=ok fnv=0000000000000000\n", None, "not the last record"),
        ("two probe lines", g + g.splitlines()[0] + "\n", None, "exactly one N01-GUEST"),
        ("no probe line", rewrite(g, "N01-GUEST", lambda l: None), None, "exactly one N01-GUEST"),
        ("a claim of big-endian with the little-endian bytes", rewrite(good("little"), "N01-GUEST", lambda l: with_pair(l, "endian", "big")), None, "native bytes"),
        ("a claim of little-endian with the big-endian bytes", rewrite(g, "N01-GUEST", lambda l: with_pair(l, "endian", "little")), None, "native bytes"),
        ("the probe's own renderings are wrong", rewrite(g, "N01-GUEST", lambda l: with_pair(l, "probe_le", "0102030405060708")), None, "renderings are wrong"),
        ("a little-endian run offered as the big-endian one", good("little"), "big", "a big-endian run was required"),
        ("a big-endian run offered as the little-endian one", good("big"), "little", "a little-endian run was required"),
        ("an odd pointer width", rewrite(g, "N01-GUEST", lambda l: with_pair(l, "pointer_bits", "16")), None, "pointer_bits"),
        ("another transcript version", rewrite(g, "N01-GUEST", lambda l: with_pair(l, "v", "2")), None, "transcript version"),
        ("an unreadable line", g + "N01-WIRE N01-GV-001 verdict=ACCEPT verdict=ACCEPT\n", None, "unreadable"),
        ("an unknown record kind", g + "N01-SURPRISE x=1\n", None, "unknown record kind"),
    ]


class Negatives(unittest.TestCase):
    def test_every_planted_bad_transcript_is_refused_for_its_own_reason(self):
        for label, log, endian, needle in negative_cases():
            with self.subTest(label):
                found = problems(log, endian)
                self.assertTrue(has(found, needle), (label, needle, found[:3]))

    def test_the_unplanted_transcripts_are_the_paired_positives(self):
        self.assertEqual(problems(good("big"), "big"), [])
        self.assertEqual(problems(good("little"), "little"), [])

    def test_a_little_endian_log_never_satisfies_a_big_endian_requirement(self):
        # "Across endianness" cannot be shown by running twice on the same byte order.
        self.assertTrue(problems(good("little", 64), "big"))
        self.assertTrue(problems(good("little", 32), "big"))


class Mutations(unittest.TestCase):
    """Switch each rule of the judge off, in memory, and require a planted-bad transcript to go undetected."""

    MUTANTS = {
        "duplicates are ignored": ('problems.append("%s %s appears more than once" % (what, ident))', "pass"),
        "missing vectors are ignored": ('problems.append("%s %s is missing" % (what, ident))', "pass"),
        "unknown vectors are ignored": ('problems.append("%s %s is not in the vector file" % (what, ident))', "pass"),
        "wire verdicts are ignored": ('if got.get("verdict") != v["expect"]:', "if False:"),
        "re-encode is ignored": ('if got.get("reencode") != ("ok" if accept else "na"):', "if False:"),
        "decoded fields are ignored": ('if got.get("fields") != ("ok" if accept else "na"):', "if False:"),
        "the datagram fingerprint is ignored": ('if got.get("fnv") != want_fnv:', "if False:"),
        "scenario fingerprints are ignored": ('            if got.get(key) != value:\n                problems.append("%s: %s=%s, required %s" % (sc["id"], key, got.get(key), value))',
                                              '            pass'),
        "negotiation flags are ignored": ('if got.get(flag) != "ok":', "if False:"),
        "rejection verdicts are ignored": ('if got.get("verdict") != r["expect"]:', "if False:"),
        "planted verdicts are ignored": ('if got is not None and got.get("verdict") != want:', "if False:"),
        "the probe is not checked against the claim": ('if want_native is not None and g.get("probe_native") != want_native:', "if False:"),
        "the required byte order is ignored": ('if expect_endian is not None and endian != expect_endian:', "if False:"),
        "the program's own mismatches are ignored": ('problems.append("the program reported a mismatch of its own: %s" % pairs.get("text", "")[:100])', "pass"),
        "the done counts are ignored": ('if d.get(key) != str(value):', "if False:"),
        "a done line that is not last is accepted": ('if records and records[-1][0] != "N01-DONE":', "if False:"),
        "a missing done line is accepted": ('if len(done) != 1:', "if False:"),
    }

    @staticmethod
    def mutated_judge(old, new):
        import types
        source = Path(gt.__file__).read_text(encoding="utf-8")
        assert source.count(old) == 1, (old[:60], source.count(old))
        module = types.ModuleType("mutant_guest_transcript")
        module.__dict__["__file__"] = gt.__file__
        exec(compile(source.replace(old, new), "mutant.py", "exec"), module.__dict__)
        return module.judge

    @staticmethod
    def undetected(judge):
        """The planted cases a judge fails to report. A judge that crashes on one has not reported it either."""
        missed = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            for label, log, endian, needle in negative_cases():
                try:
                    found = judge(log, WIRE, NEG, endian)
                except Exception:  # noqa: BLE001 - a mutated judge may fail in any way
                    found = []
                if not has(found, needle):
                    missed.append(label)
        return missed

    def test_the_unmutated_judge_detects_every_planted_case_first(self):
        self.assertEqual(self.undetected(gt.judge), [])

    def test_each_rule_switched_off_lets_a_planted_transcript_through(self):
        for label, (old, new) in self.MUTANTS.items():
            with self.subTest(label):
                self.assertNotEqual(self.undetected(self.mutated_judge(old, new)), [], label)


REPLAY = gt.ROOT / "crates" / "franken-stream" / "src" / "bin" / "n01_wire_guest" / "replay.rs"
MAIN = REPLAY.parent / "main.rs"
MANIFEST = gt.ROOT / "crates" / "franken-stream" / "Cargo.toml"
INTEGRATION_TEST = gt.ROOT / "crates" / "franken-stream" / "tests" / "n01_wire_replay.rs"


def manifest_sections():
    sections, current = {}, None
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line.strip("[]")
            sections.setdefault(current, [])
        elif line and not line.startswith("#") and current is not None:
            sections[current].append(line)
    return sections


class RustAgreement(unittest.TestCase):
    """The Rust source and this judge cannot drift apart unseen. These read the source; they do not run it."""

    def source(self):
        return REPLAY.read_text(encoding="utf-8")

    def test_each_line_template_has_the_keys_the_judge_expects_in_the_same_order(self):
        import re
        source = self.source()
        samples = {}
        for line in gt.expected_lines(WIRE, NEG):
            samples.setdefault(line.split(" ", 1)[0], line)
        for tag, sample in samples.items():
            template = next((m for m in re.findall(r'"(%s [^"]*)"' % re.escape(tag), source)), None)
            self.assertIsNotNone(template, "no format template for %s in replay.rs" % tag)
            self.assertEqual(re.findall(r"(\w+)=", template), re.findall(r"(\w+)=", sample), tag)
        self.assertIn('"N01-MISMATCH {}"', source)

    def test_the_constants_are_the_contracts(self):
        source = self.source()
        self.assertIn("const HEADER_BYTES: usize = %d;" % rf.HEADER_LEN, source)
        self.assertIn("const TAG_BYTES: usize = %d;" % rf.TAG_LEN, source)
        self.assertIn("const FRAME_COUNT_OFFSET: usize = 60;", source)
        self.assertIn('const PLANT_BASE: &str = "%s";' % gt.PLANT_BASE, source)
        self.assertIn("const PROBE: u64 = 0x0102_0304_0506_0708;", source)
        # the frame count sits at offset 60 in the reference's own header layout
        self.assertEqual(rf.HEADER.size, rf.HEADER_LEN)
        self.assertEqual(rf.HEADER.size - 2 - 2, 60)

    def test_the_plant_table_is_the_judges_in_the_same_order(self):
        import re
        source = self.source()
        table = source[source.index("const PLANTS"):]
        table = table[:table.index("];")]
        self.assertEqual(re.findall(r'\("(\w+)", "(\w+)"\)', table), list(gt.PLANT_EXPECTED.items()))

    def test_the_replay_imports_only_the_packages_normal_dependencies(self):
        """P01: franken-stream is in the device closure. No dev-dependency (franken-test-support, franken-clock) may be
        reached by the guest, which is why it is a [[bin]] and not an example."""
        import re
        deps = {line.split(".")[0].split("=")[0].strip().replace("-", "_") for line in manifest_sections()["dependencies"]}
        roots = set(re.findall(r"^use ([a-z_0-9]+)::", self.source(), re.M)) | set(re.findall(r"^use ([a-z_0-9]+)::", MAIN.read_text(encoding="utf-8"), re.M))
        allowed = deps | {"franken_stream", "std"}
        self.assertEqual(sorted(roots - allowed), [], "the guest imports a crate that is not a normal dependency")
        dev = {line.split(".")[0].split("=")[0].strip().replace("-", "_") for line in manifest_sections()["dev-dependencies"]}
        self.assertEqual(sorted(dev & roots), [])
        self.assertIn("franken_stream", roots)

    def test_the_manifest_declares_the_bin_and_adds_no_dependency(self):
        sections = manifest_sections()
        self.assertEqual(sections["bin"], ['name = "n01_wire_guest"', 'path = "src/bin/n01_wire_guest/main.rs"'])
        self.assertTrue(MAIN.is_file())
        names = sorted(line.split(".")[0].split("=")[0].strip() for line in sections["dependencies"])
        self.assertEqual(names, ["franken-dsp", "hmac", "serde", "serde_json", "sha2", "thiserror"])

    def test_the_integration_test_compiles_the_very_file_the_guest_does(self):
        text = INTEGRATION_TEST.read_text(encoding="utf-8")
        self.assertIn('#[path = "../src/bin/n01_wire_guest/replay.rs"]', text)
        self.assertIn("mod replay;", MAIN.read_text(encoding="utf-8"))
        self.assertTrue(REPLAY.is_file())

    def test_the_vector_documents_are_included_from_the_committed_paths(self):
        source = self.source()
        self.assertIn('include_str!("../../../tests/vectors/n01_wire_vectors.json")', source)
        self.assertIn('include_str!("../../../tests/vectors/n01_negotiation_vectors.json")', source)
        self.assertTrue((REPLAY.parent / "../../../tests/vectors/n01_wire_vectors.json").resolve().is_file())
        self.assertTrue((REPLAY.parent / "../../../tests/vectors/n01_negotiation_vectors.json").resolve().is_file())


if __name__ == "__main__":
    unittest.main()
