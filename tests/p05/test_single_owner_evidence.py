"""Contract-versus-evidence for the single-owner guest runs of the P05 runtime probe (bead ffw-ipz). Standard library only, offline, no cargo, no QEMU.

Run: python3 -B -W error -m unittest discover -s tests/p05 -p test_single_owner_evidence.py   (from the repository root)

The evidence is the pair of receipts and the pair of raw serial transcripts under toolchain/results/p05/20261109-single-owner-guest/, which the build owner's local
QEMU runs produced. What each test does with those real bytes:
  * the "What ran" record in docs/contracts/p05.md must equal them (probe and supervisor ELF hashes, kernel hashes, verdict, END counts, the settle rows), and must no
    longer carry the old "no run is recorded" claims; one function, `contract_problems`, so each planted fault runs the very same rules on a changed copy;
  * each receipt must agree with its own transcript and with itself (the transcript hash, the packaged ELF and supervisor hashes, the profile marker, the nine gates,
    no absolute host path);
  * `measure-p05-target.py analyze-runtime --profile single-owner` re-judges each committed transcript and must reach the receipt's verdict, transcript hash and gate
    results. The probe and supervisor binaries are not committed, so it is given header-only stand-in ELFs of the right class, byte order and machine; the supervisor
    envelope is satisfied by the text alone. `P05R-CAPTURE` is the one gate this cannot repeat: it needs the live capture.
Each planted fault is made in a COPY and must be refused for the named reason, beside a control (the unplanted copy passes again). This proves the committed text and
transcripts satisfy the committed judge and each other. It proves nothing about the ELFs, the kernels or the guests, which the receipts only record.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
EVIDENCE = os.path.join(REPO, "toolchain", "results", "p05", "20261109-single-owner-guest")
CONTRACT = os.path.join(REPO, "docs", "contracts", "p05.md")
STEMS = {"mips": "single-owner-mips-20261109", "powerpc": "single-owner-powerpc-20261109"}   # hand-written: a renamed or missing file must fail here
KERNELS = {"mips": "4.19.0-21-4kc-malta", "powerpc": "4.9.0-0.bpo.6-powerpc"}
MACHINE = {"mips": 8, "powerpc": 20}                                                     # ELF e_machine, big-endian 32-bit
GATES = ("P05R-TRANSCRIPT", "P05R-ENV", "P05R-PHASES", "P05R-DECLARED", "P05R-CLEANUP", "P05R-CENSUS", "P05R-END", "P05R-SUPERVISOR", "P05R-CAPTURE")
DECLARED = "CALLER_DRIVEN_CURRENT_THREAD"
ABSOLUTE = re.compile(r"(?<![A-Za-z0-9_.~<>-])/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
HOST_ROOTS = re.compile(r"/(?:Users|home|private|Volumes|tmp)/")

SPEC = importlib.util.spec_from_file_location("p05_judge_for_evidence", os.path.join(REPO, "toolchain", "src", "measure-p05-target.py"))
J = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = J
SPEC.loader.exec_module(J)


def evidence_bytes(arch, suffix):
    with open(os.path.join(EVIDENCE, STEMS[arch] + suffix), "rb") as handle:
        return handle.read()


def receipt(arch):
    return json.loads(evidence_bytes(arch, ".receipt.json").decode("utf-8"))


def transcript(arch):
    return evidence_bytes(arch, ".serial.txt")


def lines_of(log):
    return log.decode("utf-8").replace("\r", "").split("\n")


def facts(arch, doc=None, log=None):
    """The figures the contract records for `arch`, read from the receipt `doc` and the transcript `log` (the committed ones unless given)."""
    doc = receipt(arch) if doc is None else doc
    rows = lines_of(transcript(arch) if log is None else log)
    end = [line.split(" ", 2)[2] for line in rows if line.startswith("FFW_P05_RUNTIME:END ")]
    settle = [line for line in rows if line.startswith("FFW_P05_RUNTIME:CENSUS ") and "settle=settled" in line]
    return {"elf": doc["elf"]["sha256"], "elf_bytes": doc["elf"]["bytes"], "supervisor": doc["supervisor_elf"]["sha256"],
            "kernel": doc["execution"]["kernel_sha256"], "result": doc["result"],
            "passed": sum(gate["status"] == "passed" for gate in doc["gates"]), "gates": len(doc["gates"]),
            "end": end[0] if len(end) == 1 else f"{len(end)} END lines",
            "threads": sorted({re.search(r"settle_threads=(\d+)", row)[1] for row in settle}),
            "polls": [re.search(r"settle_polls=(\d+)", row)[1] for row in settle]}


class ContractText(unittest.TestCase):
    """docs/contracts/p05.md records what ran in the words of the committed evidence: the figures below are read from the receipts and transcripts."""

    # The claims this text used to make, before the guest runs were recorded. Any of them present means the contract went back to "nothing ran".
    STALE = ("No run of the single-owner profile, natively or in a guest, is recorded by this section",
             "stay open until receipts exist",
             "nothing in this section is such a record",
             "The one runtime receipt is a QEMU guest run on big-endian MIPS32",
             "PowerPC has no guest run",
             "and a PowerPC guest run.")
    RECORDED = ("toolchain/results/p05/20261109-single-owner-guest/", "**What ran.**", "**Not claimed.**", "One run per architecture, on the harness Debian kernels",
                "not the speakers' stock kernels, not a board", "bind bytes, not\nsource provenance", "not_attested_by_this_runner", "is not a pass",
                "P05 and its runtime acceptance item stay open", "`CALLER_DRIVEN_CURRENT_THREAD`", "(`P05-EXT-TARGET-BUILD`) stays open",
                "tests/p05/test_single_owner_evidence.py")

    @classmethod
    def rows(cls, mips, powerpc):
        """The table rows of the "What ran" paragraph, cell for cell, from the facts of the two architectures."""
        m, p = mips, powerpc
        verdict = lambda f: f"`{f['result']}`, exit {J.EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED}, {f['passed']} of {f['gates']} gates"   # noqa: E731
        settle = lambda f: f"`settle=settled`, `settle_threads={'/'.join(f['threads'])}`, `settle_polls` {' and '.join(f['polls'])}"   # noqa: E731
        return (("Probe ELF row", f"| Probe ELF sha256 | `{m['elf'][:16]}…` ({m['elf_bytes']:,} bytes) | `{p['elf'][:16]}…` ({p['elf_bytes']:,} bytes) |"),
                ("Supervisor ELF row", f"| Supervisor ELF sha256 | `{m['supervisor'][:8]}…` | `{p['supervisor'][:8]}…` |"),
                ("Guest kernel row", f"| Guest kernel (Debian, sha256) | `{KERNELS['mips']}`, `{m['kernel'][:8]}…` | `{KERNELS['powerpc']}`, `{p['kernel'][:8]}…` |"),
                ("Verdict row", f"| Verdict | {verdict(m)} | {verdict(p)} |"),
                ("END row", f"| `END` | `{m['end']}` | `{p['end']}` |"),
                ("Settle row", f"| Settle rows | {settle(m)} | {settle(p)} |"))

    @classmethod
    def contract_problems(cls, text, mips, powerpc):
        problems = [f"stale claim still present: {stale}" for stale in cls.STALE if stale in text]
        problems += [f"the record is missing: {label}" for label, row in cls.rows(mips, powerpc) if row not in text]
        problems += [f"the record is missing: {needle}" for needle in cls.RECORDED if needle not in text]
        return problems

    def setUp(self):
        with open(CONTRACT, encoding="utf-8") as handle:
            self.text = handle.read()
        self.mips, self.powerpc = facts("mips"), facts("powerpc")

    def test_the_contract_records_what_ran_equal_to_the_committed_evidence_and_no_longer_says_nothing_did(self):
        self.assertEqual(self.contract_problems(self.text, self.mips, self.powerpc), [])
        problems = lambda text, mips=None, powerpc=None: self.contract_problems(text, mips or self.mips, powerpc or self.powerpc)   # noqa: E731

        def changed(old, new):
            self.assertIn(old, self.text, "the plant would test nothing")
            return self.text.replace(old, new, 1)

        # planted: the old sentences are back
        for stale in self.STALE:
            with self.subTest(stale=stale):
                self.assertEqual(problems(self.text + f"\n{stale}.\n"), [f"stale claim still present: {stale}"])
        # planted: a figure of the record is changed in the contract (one nibble of the MIPS ELF hash; the MIPS END; the PowerPC settle polls)
        for label, old, new in (("Probe ELF row", f"`{self.mips['elf'][:16]}…`", f"`{self.mips['elf'][:15]}0…`"),
                                ("END row", "unsupported=1 partial=0", "unsupported=2 partial=0"),
                                ("Settle row", f"{self.powerpc['polls'][0]} and {self.powerpc['polls'][1]} |", "1 and 3 |"),
                                ("Verdict row", "9 of 9 gates", "8 of 9 gates")):
            with self.subTest(figure=label):
                self.assertEqual(problems(changed(old, new)), [f"the record is missing: {label}"])
        # planted: the same figure changed on the EVIDENCE side (a receipt copy whose probe ELF hash differs by one nibble), the contract untouched
        doc = receipt("mips")
        doc["elf"]["sha256"] = doc["elf"]["sha256"][:15] + ("0" if doc["elf"]["sha256"][15] != "0" else "1") + doc["elf"]["sha256"][16:]
        self.assertEqual(problems(self.text, mips=facts("mips", doc=doc)), ["the record is missing: Probe ELF row"])
        # planted: the limits are lost
        self.assertEqual(problems(changed("on the harness Debian kernels", "on kernels")),
                         ["the record is missing: One run per architecture, on the harness Debian kernels"])
        self.assertEqual(problems(changed("is not a pass", "is a pass")), ["the record is missing: is not a pass"])
        # control: with every plant removed the real text passes again
        self.assertEqual(self.contract_problems(self.text, self.mips, self.powerpc), [])


def receipt_problems(arch, doc, log):
    """What is wrong with receipt `doc` as the record of the run whose transcript is `log`; [] for the committed pair."""
    problems = []
    execution = doc.get("execution") or {}
    image = execution.get("initramfs") or {}
    extra = image.get("extra_files") or {}
    if doc.get("transcript_sha256") != hashlib.sha256(log).hexdigest() or execution.get("stdout_sha256") != hashlib.sha256(log).hexdigest():
        problems.append("the receipt's transcript hash is not the transcript's")
    for key, want in (("schema", "ffw.p05.runtime_receipt.v1"), ("evidence_kind", "captured_guest_execution"), ("profile", "single-owner"),
                      ("result", "accepted_with_declared_unsupported"), ("arch", arch)):
        if doc.get(key) != want:
            problems.append(f"{key} is {doc.get(key)!r}, not {want!r}")
    if doc.get("declared_unsupported") != [DECLARED]:
        problems.append("the declared unsupported row is not exactly the caller-driven mode")
    if (doc.get("elf") or {}).get("sha256") != (extra.get("franken-speaker") or {}).get("sha256"):
        problems.append("the probe ELF hash is not the packaged franken-speaker's")
    if (doc.get("supervisor_elf") or {}).get("sha256") != image.get("init_sha256"):
        problems.append("the supervisor ELF hash is not the packaged init's")
    marker = extra.get("ffw_p05_profile") or {}
    if (marker.get("sha256"), marker.get("size")) != (hashlib.sha256(b"single-owner\n").hexdigest(), 13):
        problems.append("the profile marker is not exactly `single-owner` and a newline")
    kernel = execution.get("kernel_sha256")
    if (execution.get("inputs_after_capture") or {}).get("kernel") != kernel or (execution.get("inputs_after_capture") or {}).get("initramfs") != image.get("archive_sha256"):
        problems.append("an input changed during capture, or its hash was not kept")
    bound = {(entry.get("path"), entry.get("sha256")) for entry in doc.get("path_hashes") or []}
    for name, digest in (("vmlinux.runtime-snapshot", kernel), ("runtime.cpio.gz", image.get("archive_sha256")), ("ffw-hello-init", image.get("init_sha256"))):
        if (f"<outside-repo>/{name}", digest) not in bound:
            problems.append(f"path_hashes does not bind <outside-repo>/{name} to its hash")
    gates = [(gate.get("gate_id"), gate.get("status")) for gate in doc.get("gates") or []]
    if gates != [(gate_id, "passed") for gate_id in GATES]:
        problems.append("the nine gates are not all present, in order, and passed")
    if execution.get("exit_code") != 0 or execution.get("stop_reason") is not None:
        problems.append("the capture did not exit cleanly")
    text = json.dumps(doc)
    if ABSOLUTE.search(text) or HOST_ROOTS.search(text):
        problems.append("the receipt carries an absolute host path")
    rows = lines_of(log)
    exits = [row for row in rows if row.startswith("FFW_SPEAKER_EXIT ")]
    if sum(row.startswith("FFW_P05_RUNTIME:END ") for row in rows) != 1 or len(exits) != 1 or not exits[0].startswith("FFW_SPEAKER_EXIT status=0 "):
        problems.append("the transcript lacks exactly one END line, or the child did not exit 0")
    return problems


FILE_LINES = ("mips/ffw-p05-runtime:    ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, stripped",
              "powerpc/ffw-p05-runtime: ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), statically linked, stripped")


def run_notes_problems(text):
    """What is wrong with RUN.md as the index of the four files: each must be listed with the sha256 it really has, and the `file(1)` lines must be there."""
    problems = []
    for arch in STEMS:
        for suffix in (".receipt.json", ".serial.txt"):
            name = STEMS[arch] + suffix
            if f"| `{name}` | `{hashlib.sha256(evidence_bytes(arch, suffix)).hexdigest()}` |" not in text:
                problems.append(f"RUN.md does not give the sha256 of {name}")
    problems += [f"RUN.md lacks the file(1) line {line.split(':')[0]}" for line in FILE_LINES if line not in text]
    return problems


class CommittedPair(unittest.TestCase):
    def test_run_md_lists_the_four_files_with_their_real_hashes_and_the_file_lines(self):
        with open(os.path.join(EVIDENCE, "RUN.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(run_notes_problems(text), [])
        wrong = text.replace(hashlib.sha256(transcript("powerpc")).hexdigest(), "0" * 64, 1)                 # planted: a hash in the table is wrong
        self.assertEqual(run_notes_problems(wrong), [f"RUN.md does not give the sha256 of {STEMS['powerpc']}.serial.txt"])
        lost = text.replace(FILE_LINES[0], "mips/ffw-p05-runtime: ELF", 1)                                    # planted: a file(1) line is lost
        self.assertEqual(run_notes_problems(lost), ["RUN.md lacks the file(1) line mips/ffw-p05-runtime"])
        self.assertEqual(run_notes_problems(text), [])                                                       # control: the real RUN.md passes again

    def test_each_committed_receipt_agrees_with_its_transcript_and_a_planted_fault_is_named(self):
        for arch in STEMS:
            doc, log = receipt(arch), transcript(arch)
            with self.subTest(arch=arch):
                self.assertEqual(receipt_problems(arch, doc, log), [])
                # planted: one nibble of the packaged probe ELF hash changed (the receipt no longer ties its two ELF hashes together)
                bad = json.loads(json.dumps(doc))
                packed = bad["execution"]["initramfs"]["extra_files"]["franken-speaker"]["sha256"]
                bad["execution"]["initramfs"]["extra_files"]["franken-speaker"]["sha256"] = packed[:-1] + ("0" if packed[-1] != "0" else "1")
                self.assertEqual(receipt_problems(arch, bad, log), ["the probe ELF hash is not the packaged franken-speaker's"])
                # planted: one byte of the transcript changed
                flipped = log.replace(b"settle_polls=1", b"settle_polls=7", 1)
                self.assertNotEqual(flipped, log)
                self.assertEqual(receipt_problems(arch, doc, flipped), ["the receipt's transcript hash is not the transcript's"])
                # planted: a host path comes back in the init_path field
                leaky = json.loads(json.dumps(doc))
                leaky["execution"]["initramfs"]["init_path"] = "/Users/someone/work/ffw-hello-init"
                self.assertEqual(receipt_problems(arch, leaky, log), ["the receipt carries an absolute host path"])
                # control: the unplanted pair passes again
                self.assertEqual(receipt_problems(arch, receipt(arch), transcript(arch)), [])


def header_only_elf(arch):
    """A 64-byte ELF header the P05 parser accepts for `arch` (32-bit, big-endian, the right machine); never executable evidence."""
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4], data[5], data[6] = 1, 2, 1
    data[18:20] = MACHINE[arch].to_bytes(2, "big")
    return bytes(data)


def analyze(arch, log):
    """`measure-p05-target.py analyze-runtime --profile single-owner` on `log`: the exit code and the analysis receipt it wrote."""
    with tempfile.TemporaryDirectory() as tmp:
        paths = {name: os.path.join(tmp, name) for name in ("transcript.txt", "runtime.elf", "supervisor.elf", "analysis.json")}
        with open(paths["transcript.txt"], "wb") as handle:
            handle.write(log)
        for name in ("runtime.elf", "supervisor.elf"):
            with open(paths[name], "wb") as handle:
                handle.write(header_only_elf(arch))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = J.main(["analyze-runtime", "--arch", arch, "--profile", "single-owner", "--elf", paths["runtime.elf"],
                           "--supervisor", paths["supervisor.elf"], "--log", paths["transcript.txt"], "--receipt", paths["analysis.json"]])
        with open(paths["analysis.json"], encoding="utf-8") as handle:
            return code, json.load(handle)


def failed_gates(doc):
    return {gate["gate_id"] for gate in doc["gates"] if gate["status"] != "passed"}


class Rejudge(unittest.TestCase):
    def test_the_committed_transcripts_rejudge_to_the_receipts_verdict_and_planted_faults_are_refused(self):
        for arch in STEMS:
            doc, log = receipt(arch), transcript(arch)
            with self.subTest(arch=arch):
                code, again = analyze(arch, log)
                self.assertEqual(code, J.EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED)
                self.assertEqual((again["result"], again["evidence_kind"], again["profile"]), (doc["result"], "supplied_transcript_analysis", doc["profile"]))
                self.assertEqual(again["transcript_sha256"], doc["transcript_sha256"])
                self.assertEqual([(g["gate_id"], g["status"]) for g in again["gates"]],
                                 [(g["gate_id"], g["status"]) for g in doc["gates"] if g["gate_id"] != "P05R-CAPTURE"])
                # planted, each in a COPY: an END total off by one; a settle row that says pending; the settle pairs gone (the shape of a probe built before the settle)
                for label, old, new, gate in (("END total", b"ok=32 failed=0", b"ok=31 failed=0", "P05R-END"),
                                              ("settle pending", b"settle=settled settle_threads=1 settle_polls=1", b"settle=pending settle_threads=1 settle_polls=1", "P05R-CENSUS"),
                                              ("no settle pairs", b" settle=settled settle_threads=1 settle_polls=1", b"", "P05R-CENSUS")):
                    planted = log.replace(old, new, 1)
                    self.assertNotEqual(planted, log, f"{label}: the plant would test nothing")
                    bad_code, bad = analyze(arch, planted)
                    self.assertNotEqual(bad_code, J.EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED, label)
                    # the child's bytes changed, so the supervisor's size/hash check may fail as well; the named gate must fail too
                    self.assertIn(gate, failed_gates(bad), label)
                # control: the unplanted copy is accepted again
                self.assertEqual(analyze(arch, bytes(log))[0], J.EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()
