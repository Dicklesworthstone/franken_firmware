"""Re-judges the COMMITTED T01-X02 guest evidence (bead ffw-32a): the two receipts and the two raw serial transcripts under
toolchain/results/tailscale/measurements/, which the operator's central build and local QEMU runs of 2026-11-08 produced. Standard library only, offline, no cargo, no QEMU.

Run: python3 -B -W error -m unittest tests/t01/test_x02_evidence.py   (from the repository root)

What each test does with real bytes:
  * the committed receipt passes `x02_judge.judge_receipt` and the runner case `T01-X02-target-resources`;
  * the committed transcript hashes to the sha256 its receipt recorded, and `scripts/e2e/t01 --x02 analyze --log ... --supervisor ...` (the same `x02_judge.main`) judges it
    through the E07 supervisor envelope and writes a verdict, transcript hash and child hash equal to the committed receipt's;
  * each planted fault is made in a COPY of the committed bytes and must be refused for the named reason, beside a control (the unplanted copy passes again).
The supervisor ELF is not committed, so `analyze` is given a header-only stand-in of the right class, byte order and machine; it records the stand-in's identity in the analysis
receipt it writes into a temporary directory, and that identity is never compared with the guest run's. This proves the committed transcripts satisfy the committed judge. It
proves nothing about the ELFs, the kernels or the guests, which the receipts only record.
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "toolchain", "tests"))
import run_cases as rc  # noqa: E402
import x02_judge as J  # noqa: E402

MEASUREMENTS = os.path.join(REPO, "toolchain", "results", "tailscale", "measurements")
STEMS = {"mips": "x02-v3b-mips-20261108", "powerpc": "x02-v3b-powerpc-20261108"}   # hand-written: a renamed or missing file must fail here, not follow silently
MACHINE = {"mips": 8, "powerpc": 20}                                               # ELF e_machine, big-endian 32-bit
CONTRACT = os.path.join(REPO, "docs", "contracts", "t01.md")


def receipt_text(arch):
    with open(os.path.join(MEASUREMENTS, STEMS[arch] + ".json"), encoding="utf-8") as handle:
        return handle.read()


def transcript(arch):
    with open(os.path.join(MEASUREMENTS, STEMS[arch] + ".serial.txt"), "rb") as handle:
        return handle.read()


def header_only_elf(arch):
    """A 64-byte ELF header the P05 parser accepts for `arch` (32-bit, big-endian, the right machine); never executable evidence."""
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4], data[5], data[6] = 1, 2, 1
    data[18:20] = MACHINE[arch].to_bytes(2, "big")
    return bytes(data)


def analyze(arch, log):
    """`x02_judge.main(["analyze", "--log", L, "--arch", A, "--supervisor", S, "--receipt", R])` on `log`; the exit code, the receipt it wrote and its stderr."""
    with tempfile.TemporaryDirectory() as tmp:
        log_path, supervisor, out = (os.path.join(tmp, name) for name in ("transcript.txt", "supervisor.elf", "analysis.json"))
        with open(log_path, "wb") as handle:
            handle.write(log)
        with open(supervisor, "wb") as handle:
            handle.write(header_only_elf(arch))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = J.main(["analyze", "--log", log_path, "--arch", arch, "--supervisor", supervisor, "--receipt", out])
        doc = None
        if os.path.exists(out):
            with open(out, encoding="utf-8") as handle:
                doc = json.load(handle)
        return code, doc, stderr.getvalue()


def problems_of(doc):
    """gate id -> detail, for the gates of an analysis receipt that did not pass."""
    return {gate["gate_id"]: gate["detail"] for gate in doc["gates"] if gate["status"] != "passed"}


def replaced_once(raw, old, new):
    assert raw.count(old) == 1, (old, raw.count(old))      # a plant that matches twice or never would test nothing
    return raw.replace(old, new, 1)


class CommittedReceipts(unittest.TestCase):
    def test_each_committed_receipt_passes_the_receipt_judge_and_the_runner_case_passes_on_both(self):
        for arch in J.ARCHES:
            judged = J.judge_receipt(receipt_text(arch))
            self.assertEqual((judged.state, judged.arch, judged.problems), ("passed", arch, []), arch)
            doc = json.loads(receipt_text(arch))
            self.assertEqual((doc["schema"], doc["evidence_kind"], doc["result"]), (J.RECEIPT_SCHEMA, "captured_guest_execution", "passed"))
            self.assertEqual(sorted(g["gate_id"] for g in doc["gates"]), sorted(J.REQUIRED_GATES))
            self.assertEqual({g["status"] for g in doc["gates"]}, {"passed"})
        result = rc.case_resources(REPO)
        self.assertEqual(result.status, "passed", result.detail)
        for arch in J.ARCHES:
            self.assertIn(f"{arch}: PASSED", result.detail)

    def test_each_committed_transcript_is_the_one_its_receipt_recorded(self):
        for arch in J.ARCHES:
            doc = json.loads(receipt_text(arch))
            digest = hashlib.sha256(transcript(arch)).hexdigest()
            self.assertEqual((doc["transcript_sha256"], doc["execution"]["stdout_sha256"]), (digest, digest), arch)

    def test_the_numbers_the_contract_quotes_are_the_receipts(self):
        for arch in J.ARCHES:
            verdict = json.loads(receipt_text(arch))["verdict"]
            self.assertEqual((verdict["end"], verdict["counted"]), ({"ok": 8, "fail": 0, "unknown": 0},) * 2, arch)
            facts = {phase["name"]: phase["facts"] for phase in verdict["phases"]}
            self.assertEqual(facts["TS_TUNNEL"]["wire_bytes"], "348", arch)
            self.assertEqual(facts["CRYPTO_KAT"]["plant"], "caught", arch)
            self.assertEqual([phase["status"] for phase in verdict["phases"]], ["ok"] * 8)


class ReJudgingTheCommittedTranscripts(unittest.TestCase):
    def test_analyze_reproduces_the_committed_verdict_for_each_architecture(self):
        for arch in J.ARCHES:
            code, doc, stderr = analyze(arch, transcript(arch))
            self.assertEqual((code, stderr), (0, ""), arch)
            committed = json.loads(receipt_text(arch))
            self.assertEqual(doc["evidence_kind"], "supplied_transcript_analysis")          # an analysis is never execution evidence
            self.assertEqual(problems_of(doc), {}, arch)
            self.assertEqual([g["gate_id"] for g in doc["gates"]], ["P05R-SUPERVISOR", "X02-FRAMING", "X02-PHASES", "X02-RESOURCES", "X02-END"])
            self.assertEqual(doc["verdict"], committed["verdict"], arch)
            self.assertEqual((doc["transcript_sha256"], doc["child_sha256"]), (committed["transcript_sha256"], committed["child_sha256"]), arch)

    def test_a_phase_flipped_to_fail_is_refused_as_that_phase_and_the_unplanted_copy_passes_again(self):
        for arch in J.ARCHES:
            raw = transcript(arch)
            planted = replaced_once(raw, b"T01X02 PHASE TS_KEYS ok ", b"T01X02 PHASE TS_KEYS fail ")
            code, doc, _ = analyze(arch, planted)
            problems = problems_of(doc)
            self.assertEqual(code, 1, arch)
            self.assertIn("phase TS_KEYS reports fail", problems["X02-PHASES"])
            self.assertIn("contradicts", problems["X02-END"])                               # the totals no longer match the one fail the judge counts
            self.assertEqual(sorted(problems), ["P05R-SUPERVISOR", "X02-END", "X02-PHASES"])  # the supervisor envelope sees the changed child bytes too
            self.assertEqual(analyze(arch, raw)[0], 0)                                      # control: the plant removed

    def test_end_totals_off_by_one_are_refused_as_a_contradiction_and_the_unplanted_copy_passes_again(self):
        for arch in J.ARCHES:
            raw = transcript(arch)
            planted = replaced_once(raw, b"T01X02 END ok=8 fail=0 unknown=0", b"T01X02 END ok=7 fail=0 unknown=0")
            code, doc, _ = analyze(arch, planted)
            problems = problems_of(doc)
            self.assertEqual(code, 1, arch)
            self.assertIn("contradicts the", problems["X02-END"])
            self.assertEqual(sorted(problems), ["P05R-SUPERVISOR", "X02-END"], arch)       # every phase is still ok: only the totals are wrong
            self.assertEqual(analyze(arch, raw)[0], 0)                                      # control

    def test_a_missing_end_line_is_refused_not_passed(self):
        for arch in J.ARCHES:
            raw = transcript(arch)
            planted = replaced_once(raw, b"T01X02 END ok=8 fail=0 unknown=0", b"T01X02 ENX ok=8 fail=0 unknown=0")
            code, doc, _ = analyze(arch, planted)
            self.assertEqual(code, 1, arch)
            self.assertIn("X02-FRAMING", problems_of(doc))                                  # an unrecognized T01X02 line
            self.assertEqual(analyze(arch, raw)[0], 0)                                      # control

    def test_a_byte_changed_outside_the_judged_lines_still_judges_but_no_longer_matches_the_receipt(self):
        for arch in J.ARCHES:
            raw = transcript(arch)
            marker = b"[    0.000000] Linux version"                                       # the kernel's first dmesg line: before the supervised child, so not judged
            self.assertGreaterEqual(raw.count(marker), 1)
            planted = raw.replace(marker, b"[    0.000000] Linux Version", 1)
            self.assertNotEqual(planted, raw)
            doc = json.loads(receipt_text(arch))
            self.assertNotEqual(hashlib.sha256(planted).hexdigest(), doc["transcript_sha256"])
            code, analysis, _ = analyze(arch, planted)
            self.assertEqual(code, 0, arch)                                                 # the judge looks at the child region only,
            self.assertNotEqual(analysis["transcript_sha256"], doc["transcript_sha256"])    # so the hash binding is what refuses a swapped transcript
            self.assertEqual(analysis["verdict"], doc["verdict"])                           # and the verdict alone would not have noticed


class ReJudgingTheCommittedReceipts(unittest.TestCase):
    def test_a_receipt_that_disagrees_with_its_own_facts_is_failed_for_the_named_reason(self):
        for arch in J.ARCHES:
            text = receipt_text(arch)
            flipped = json.loads(text)
            flipped["verdict"]["phases"][0]["status"] = "fail"
            judged = J.judge_receipt(json.dumps(flipped))
            self.assertEqual(judged.state, "failed")
            self.assertEqual(judged.problems, ["verdict.status 'passed' disagrees with its recorded facts, which judge as failed"])
            wrong_end = json.loads(text)
            wrong_end["verdict"]["end"]["ok"] = 7
            self.assertEqual(J.judge_receipt(json.dumps(wrong_end)).state, "failed")
            wrong_hash = json.loads(text)
            wrong_hash["transcript_sha256"] = "0" * 64
            judged = J.judge_receipt(json.dumps(wrong_hash))
            self.assertEqual((judged.state, judged.problems), ("failed", ["transcript_sha256 is not the captured stdout hash"]))
            self.assertEqual(J.judge_receipt(text).state, "passed")                         # control: nothing planted

    def test_the_runner_case_needs_a_passed_run_on_each_target_and_names_a_bad_receipt(self):
        def repo_with(tmp, archs, altered=None):
            directory = os.path.join(tmp, "toolchain", "results", "tailscale", "measurements")
            os.makedirs(directory)
            for arch in archs:
                with open(os.path.join(directory, STEMS[arch] + ".json"), "w", encoding="utf-8") as handle:
                    handle.write((altered or {}).get(arch, receipt_text(arch)))
            return tmp

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rc.case_resources(repo_with(tmp, J.ARCHES)).status, "passed")                # control: both targets
        with tempfile.TemporaryDirectory() as tmp:
            one = rc.case_resources(repo_with(tmp, ("mips",)))                                              # planted: powerpc is missing
            self.assertEqual(one.status, "blocked")
            self.assertIn("powerpc: NOT RECORDED", one.detail)
        with tempfile.TemporaryDirectory() as tmp:
            bad = json.loads(receipt_text("powerpc"))
            bad["verdict"]["phases"][0]["status"] = "fail"
            broken = rc.case_resources(repo_with(tmp, J.ARCHES, {"powerpc": json.dumps(bad)}))             # planted: a receipt that disagrees with itself
            self.assertEqual(broken.status, "failed")
            self.assertIn(STEMS["powerpc"] + ".json", broken.detail)


class TheContractRecordsTheEvidence(unittest.TestCase):
    """docs/contracts/t01.md section 9 ("What ran") quotes the hashes and figures the receipts recorded; the strings are read from the receipts, so the contract cannot drift."""

    @staticmethod
    def quoted(arch):
        doc = json.loads(receipt_text(arch))
        resources = doc["verdict"]["resources"]
        return [STEMS[arch] + ".json", STEMS[arch] + ".serial.txt", doc["elf"]["sha256"], doc["supervisor_elf"]["sha256"], doc["execution"]["kernel_sha256"],
                f"{doc['elf']['bytes']} B", f"`VmHWM` {resources['VmHWM']} kB" if arch == "mips" else f"{resources['VmHWM']} kB"]

    def missing(self, text):
        return [needle for arch in J.ARCHES for needle in self.quoted(arch) if needle not in text]

    def test_the_contract_names_every_hash_file_and_figure_the_receipts_recorded(self):
        with open(CONTRACT, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(self.missing(text), [])
        other = json.loads(receipt_text("mips"))["elf"]["sha256"]
        planted = text.replace(other, "0" * 64, 1)                                         # planted: the contract quotes a hash that is not the receipt's
        self.assertEqual(self.missing(planted), [other])
        self.assertEqual(self.missing(text), [])                                           # control


if __name__ == "__main__":
    unittest.main()
