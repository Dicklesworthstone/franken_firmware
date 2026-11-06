"""Holds tests/s02/admission.json (the hand-written admission verdicts) to the S02 ledger, tests/s02/negotiated.json, and to the Rust source's own
constants. Stdlib only; it does not run the Rust, it checks that the file the Rust is replayed against says what the ledger requires:

* every mandatory ledger row is admitted at exactly the rates, channels and widths the ledger gives, and nothing outside the ledger is admitted;
* every row the pin enumerates but never requests, and every blocked row, is refused with its own code;
* removing the Vorbis row from the ledger changes no other expected verdict (no Vorbis-only assumption);
* ELD, HE-AAC, LD and Opus, rates 88200 and 96000, 0 and 1 channels, absent cookie and ASC, oversize names and configs are all present;
* a config that is not plain AAC-LC is a refusal whose twin (same offer, plain LC config) is admitted, so nothing is "downgraded to LC";
* the codes in the file are exactly the codes in admission.rs, and the limits and pins it states are the ones the Rust states.

Run: python3 -B -W error -m unittest tests/s02/test_admission.py   (from the repository root)
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RUST = os.path.join(ROOT, "crates", "franken-codec", "src", "admission.rs")

CODEC = {"vorbis": "Vorbis", "mp3": "Mp3", "alac": "Alac", "aac": "AacLc", "pcm": "PcmS16Be"}
ASC_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350]
REQUIRED_COVERS = {
    "profile:eld", "profile:he-aac", "profile:ld", "profile:main", "profile:960", "profile:pce", "profile:by-name", "family:not-a-source-format",
    "rate", "ledger-row-rate", "channels", "bits", "config:missing", "config:unexpected", "config:too-large", "config:alac", "config:aac", "config:mismatch",
    "no-downmix", "no-downgrade", "name:too-long", "name:unknown", "echo:redacted", "boundary:name-length", "boundary:config-length",
    "boundary:cookie-frame-length",
}


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def rust_text():
    with open(RUST, encoding="utf-8") as fh:
        return fh.read()


def rates_for(fmt, row):
    """The rates one format name admits: AAC and ALAC names carry their own rate, the others use the row's list."""
    named = re.match(r"^(?:AAC|ALAC)_(\d+)_", fmt)
    if named:
        rate = int(named.group(1))
        assert rate in row["rate_hz"], "%s: the rate in its name is not in the ledger row %s" % (fmt, row["id"])
        return [rate]
    return list(row["rate_hz"])


def derived(rows):
    """From the ledger alone: the set of (format, rate, channels, bits, codec) that must be admitted, and the refusals by format."""
    admit, refuse = set(), {}
    for row in rows:
        status = row["status"]
        if row["mandatory"] and status == "blocked":
            for fmt in row["formats"]:
                refuse[fmt] = "BLOCKED_MULTICHANNEL"
        elif row["mandatory"]:
            assert status == "decode_path_unproven", "unknown mandatory ledger status %r in %s" % (status, row["id"])
            for fmt in row["formats"]:
                for rate in rates_for(fmt, row):
                    for channels in row["channels"]:
                        admit.add((fmt, rate, channels, row.get("bits", 0), CODEC[row["codec"]]))
        else:
            assert status == "not_requested_by_pin", "unknown optional ledger status %r in %s" % (status, row["id"])
            for fmt in row["formats"]:
                refuse[fmt] = "NOT_REQUESTED_BY_PIN"
    return admit, refuse


class AdmissionFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load("admission.json")
        cls.ledger = load("negotiated.json")
        cls.cases = cls.doc["cases"]
        cls.by_id = {c["id"]: c for c in cls.cases}

    def admits(self):
        return [c for c in self.cases if c["expect"]["verdict"] == "admit"]

    def refusals(self):
        return [c for c in self.cases if c["expect"]["verdict"] == "refuse"]

    def test_the_file_is_well_formed(self):
        self.assertEqual(self.doc["schema"], "ffw.s02.admission.v1")
        self.assertEqual(len(self.by_id), len(self.cases), "case ids are not unique")
        for case in self.cases:
            with self.subTest(case=case["id"]):
                self.assertRegex(case["id"], r"^ADM-[PN]-")
                self.assertEqual(case["id"].startswith("ADM-P-"), case["expect"]["verdict"] == "admit")
                self.assertIsInstance(case["format"], str)
                for key in ("rate_hz", "channels", "bits"):
                    self.assertIsInstance(case[key], int)
                    self.assertGreaterEqual(case[key], 0)
                self.assertLessEqual(case["channels"], 255)
                self.assertLessEqual(case["bits"], 255)
                self.assertLess(case["rate_hz"], 2 ** 32)
                self.assertRegex(case["config_hex"], r"^([0-9a-f]{2})*$")
                self.assertIsInstance(case["covers"], list)
                self.assertTrue(case["covers"])

    def test_the_codes_are_exactly_the_codes_the_rust_source_has(self):
        in_rust = set(re.findall(r'Self::\w+ => "([A-Z_]+)"', rust_text()))
        in_file = set(self.doc["codes"])
        used = {c["expect"]["code"] for c in self.refusals()}
        self.assertEqual(len(self.doc["codes"]), len(in_file))
        self.assertEqual(in_file, used, "a code with no case, or a case with an unlisted code")
        self.assertEqual(in_rust - {"Vorbis", "Mp3", "Alac", "AacLc", "PcmS16Be"}, in_file)

    def test_the_limits_and_pins_are_the_ones_the_rust_source_states(self):
        text = rust_text()
        self.assertEqual(self.doc["limits"]["format_name_max"], int(re.search(r"pub const FORMAT_NAME_MAX: usize = (\d+);", text).group(1)))
        self.assertEqual(self.doc["limits"]["config_max"], int(re.search(r"pub const CONFIG_MAX: usize = (\d+);", text).group(1)))
        for key in ("spotify", "airplay", "decoder_library"):
            commit = self.ledger["pins"][key]["commit"]
            self.assertIn(commit[:12], text, "admission.rs does not name the %s pin %s" % (key, commit[:12]))

    def test_every_mandatory_ledger_row_is_admitted_and_nothing_else_is(self):
        want, _ = derived(self.ledger["rows"])
        got = {(c["format"], c["rate_hz"], c["channels"], c["bits"], c["expect"]["codec"]) for c in self.admits()}
        self.assertEqual(got, want)
        for case in self.admits():
            self.assertEqual(case["expect"]["needs_bridge"], case["rate_hz"] == 44100, case["id"])
            for key in ("rate_hz", "channels", "bits"):
                self.assertEqual(case["expect"][key], case[key], case["id"])

    def test_every_unrequested_or_blocked_ledger_format_is_refused_with_its_own_code(self):
        _, refuse = derived(self.ledger["rows"])
        by_format = {}
        for case in self.refusals():
            by_format.setdefault(case["format"], set()).add(case["expect"]["code"])
        for fmt, code in sorted(refuse.items()):
            with self.subTest(format=fmt):
                self.assertIn(code, by_format.get(fmt, set()))

    def test_every_ledger_row_is_covered_by_name(self):
        covered = {t[4:] for c in self.cases for t in c["covers"] if t.startswith("row:")}
        self.assertEqual(covered, {row["id"] for row in self.ledger["rows"]})

    def test_removing_the_vorbis_row_changes_no_other_expectation(self):
        rows = self.ledger["rows"]
        without = [r for r in rows if r["codec"] != "vorbis"]
        self.assertEqual(len(without), len(rows) - 1)
        all_admit, all_refuse = derived(rows)
        less_admit, less_refuse = derived(without)
        self.assertEqual(less_admit, {t for t in all_admit if t[4] != "Vorbis"})
        self.assertEqual(less_refuse, all_refuse, "the Vorbis row carries no refusal, and no other row's refusal depends on it")
        got = {(c["format"], c["rate_hz"], c["channels"], c["bits"], c["expect"]["codec"]) for c in self.admits() if c["expect"]["codec"] != "Vorbis"}
        self.assertEqual(got, less_admit)
        self.assertTrue(any(c["expect"]["codec"] == "Alac" for c in self.admits()))
        self.assertTrue(any(c["expect"]["codec"] == "AacLc" for c in self.admits()))

    def test_the_families_and_boundaries_the_bead_names_are_all_present(self):
        covers = {t for c in self.cases for t in c["covers"]}
        self.assertFalse(REQUIRED_COVERS - covers, sorted(REQUIRED_COVERS - covers))
        refused = self.refusals()
        for rate in (0, 88200, 96000):
            self.assertTrue(any(c["rate_hz"] == rate and c["expect"]["code"] == "RATE_NOT_NEGOTIATED" for c in refused), rate)
        for channels in (0, 1):
            self.assertTrue(any(c["channels"] == channels and c["expect"]["code"] == "CHANNELS_NOT_NEGOTIATED" for c in refused), channels)
        for fmt in ("AAC_ELD_44100_F24_2", "HE_AAC_44100_F24_2", "AAC_LD_48000_F24_2", "OPUS"):
            self.assertTrue(any(c["format"] == fmt for c in refused), fmt)
        for cid, code in (("ADM-N-name-33-bytes", "FORMAT_NAME_TOO_LONG"), ("ADM-N-name-32-bytes-unknown", "UNKNOWN_FORMAT"),
                          ("ADM-N-config-65-bytes", "CONFIG_TOO_LARGE"), ("ADM-N-config-64-bytes-is-not-too-large", "CONFIG_UNEXPECTED"),
                          ("ADM-N-alac-cookie-frame-length-0", "CONFIG_INVALID"), ("ADM-N-alac-cookie-frame-length-65537", "CONFIG_INVALID")):
            self.assertEqual(self.by_id[cid]["expect"]["code"], code, cid)
        for cid in ("ADM-P-ALAC_44100_S16_2-pin-frame-length", "ADM-P-ALAC_44100_S16_2-max-frame-length"):
            self.assertEqual(self.by_id[cid]["expect"]["verdict"], "admit", cid)

    def test_a_config_that_is_not_plain_lc_is_refused_and_its_lc_twin_is_admitted(self):
        pairs = 0
        for case in self.cases:
            if "twin_of" not in case:
                continue
            twin = self.by_id[case["twin_of"]]
            with self.subTest(case=case["id"]):
                self.assertEqual(twin["expect"]["verdict"], "admit")
                self.assertEqual(case["expect"]["verdict"], "refuse")
                self.assertEqual(case["differs_in"], "config_hex")
                for key in ("format", "rate_hz", "channels", "bits"):
                    self.assertEqual(case[key], twin[key], key)
                self.assertNotEqual(case["config_hex"], twin["config_hex"])
                pairs += 1
        self.assertGreaterEqual(pairs, 15)
        for profile in ("profile:eld", "profile:he-aac", "profile:ld"):
            self.assertTrue(any(profile in c["covers"] and "twin_of" in c for c in self.cases), profile)

    def test_the_cover_tags_agree_with_the_codes_the_cases_expect(self):
        """A case tagged as a kind of refusal must expect that kind's code, so a flipped code cannot hide behind a code other cases use."""
        allowed = {
            "profile:eld": {"UNSUPPORTED_PROFILE"}, "profile:he-aac": {"UNSUPPORTED_PROFILE"}, "profile:ld": {"UNSUPPORTED_PROFILE"},
            "profile:main": {"UNSUPPORTED_PROFILE"}, "profile:960": {"UNSUPPORTED_PROFILE"}, "profile:pce": {"UNSUPPORTED_PROFILE"},
            "profile:by-name": {"UNSUPPORTED_PROFILE"}, "family:not-a-source-format": {"NOT_A_SOURCE_FORMAT"},
            "rate": {"RATE_NOT_NEGOTIATED"}, "channels": {"CHANNELS_NOT_NEGOTIATED"}, "bits": {"BITS_MISMATCH"},
            "config:missing": {"CONFIG_MISSING"}, "config:unexpected": {"CONFIG_UNEXPECTED"},
            "config:too-large": {"CONFIG_TOO_LARGE", "CONFIG_UNEXPECTED"}, "config:mismatch": {"CONFIG_MISMATCH"},
            "name:too-long": {"FORMAT_NAME_TOO_LONG"}, "name:unknown": {"UNKNOWN_FORMAT"},
            "row:spotify.mp3_160_enc": {"NOT_REQUESTED_BY_PIN"}, "row:spotify.aac": {"NOT_REQUESTED_BY_PIN"},
            "row:spotify.flac": {"NOT_REQUESTED_BY_PIN"}, "row:airplay.aac_lc_multichannel": {"BLOCKED_MULTICHANNEL"},
        }
        tagged = 0
        for case in self.refusals():
            for tag in case["covers"]:
                if tag in allowed:
                    tagged += 1
                    self.assertIn(case["expect"]["code"], allowed[tag], "%s is tagged %s" % (case["id"], tag))
        self.assertGreaterEqual(tagged, 60)

    def test_the_echo_expectations_follow_the_documented_rule(self):
        seen = 0
        for case in self.cases:
            if "expect_echo_format" not in case:
                continue
            seen += 1
            raw = case["format"].encode("utf-8")[:32]
            want = "".join(chr(b) if (chr(b).isascii() and (chr(b).isalnum() or chr(b) in "_.-")) else "?" for b in raw)
            self.assertEqual(case["expect_echo_format"], want, case["id"])
            self.assertLessEqual(len(want), 32)
        self.assertGreaterEqual(seen, 6)
        self.assertTrue(any("echo:redacted" in c["covers"] and "expect_echo_format" in c for c in self.cases))

    def test_the_admitted_offers_carry_configs_that_agree_with_themselves(self):
        """Checks the INPUTS, independently of the Rust: an admitted ALAC cookie and AAC config say what the offer says."""
        checked = 0
        for case in self.admits():
            cfg = bytes.fromhex(case["config_hex"])
            codec = case["expect"]["codec"]
            with self.subTest(case=case["id"]):
                if codec == "Alac":
                    self.assertEqual(len(cfg), 24)
                    self.assertEqual(cfg[4], 0)
                    self.assertTrue(0 < int.from_bytes(cfg[0:4], "big") <= 65536)
                    self.assertEqual((cfg[5], cfg[9], int.from_bytes(cfg[20:24], "big")), (case["bits"], case["channels"], case["rate_hz"]))
                    checked += 1
                elif codec == "AacLc":
                    self.assertEqual(len(cfg), 2)
                    head = (cfg[0] << 8) | cfg[1]
                    self.assertEqual(head >> 11, 2)
                    self.assertEqual(ASC_RATES[(head >> 7) & 0xF], case["rate_hz"])
                    self.assertEqual((head >> 3) & 0xF, case["channels"])
                    self.assertEqual(head & 0b111, 0)
                    checked += 1
                else:
                    self.assertEqual(cfg, b"")
        self.assertGreaterEqual(checked, 6)


if __name__ == "__main__":
    unittest.main()
