"""Tests of the T01-X02 transcript judge and its guest-run front end (tests/t01/x02_judge.py, bead ffw-32a). Standard library only, offline, no cargo.

Run: python3 -B -W error -m unittest tests/t01/test_x02_judge.py   (from the repository root)

Every transcript here is SYNTHETIC: it tests the judge, not the target, QEMU or the probe. Each planted fault is presented beside a green control (the unplanted
transcript passes), and the faulty transcript is built so that the rule under test is the ONLY one it breaks wherever that is possible. The guest itself is
replaced at exactly one seam (x02_judge.capture_guest_run); the P05 runtime layer, the supervisor envelope and the hash checks run for real.
"""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "t01")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "toolchain", "tests"))
import run_cases as rc  # noqa: E402  (the consumer under test: case_resources)
import x02_judge as J  # noqa: E402
import test_serial_validator as serial_fixture  # noqa: E402  (the frozen E07 supervisor transcript the P05 runtime tests also wrap)

P = J._p05()

# Hand-written on purpose: a change to the judge's tables must fail here, not follow it silently.
PHASE_NAMES = ["TS_KEYS", "TS_NOISE", "TS_TUNNEL", "TS_CONTROL_SERDE", "TS_PACKETFILTER_STATE", "TS_DISCO_PROTOCOL", "TS_OVERLAY_ROUTER", "CRYPTO_KAT"]
PHASES = [  # the agreed order (TealSeal 15473); the facts are plausible shapes, the judge reads only the status word and the fact syntax
    "T01X02 PHASE TS_KEYS ok nodes=3 keys=10",
    "T01X02 PHASE TS_NOISE ok init_bytes=96 resp_bytes=48 sessions=2",
    "T01X02 PHASE TS_TUNNEL ok peers=2 rekeyed=1 removed=1",
    "T01X02 PHASE TS_CONTROL_SERDE ok regions=2 servers=3 reachable=2",
    "T01X02 PHASE TS_PACKETFILTER_STATE ok peers=3 rules=5 cases=9",
    "T01X02 PHASE TS_DISCO_PROTOCOL ok messages=3 ping_bytes=48 endpoints=2",
    "T01X02 PHASE TS_OVERLAY_ROUTER ok routers=2 batches=0",
    "T01X02 PHASE CRYPTO_KAT ok x25519=2/2 chacha20poly1305=1/1 blake2s=3/3",
]
N = len(PHASES)  # the number of phases; every END total below is written relative to it, so a planted total is never accidentally right
RES = {"VmHWM": "5120", "VmRSS": "4096", "utime": "12", "stime": "3"}


def resources(**over):
    merged = {**RES, **over}
    return [f"T01X02 {key} {merged[key]}" for key in ("VmHWM", "VmRSS", "utime", "stime")]


def end(ok=N, fail=0, unknown=0):
    return f"T01X02 END ok={ok} fail={fail} unknown={unknown}"


def build(phases=None, res=None, final=None, sep="\n"):
    lines = list(PHASES if phases is None else phases) + list(resources() if res is None else res) + [end() if final is None else final]
    return sep.join(lines) + sep


GOOD = build()


def swap(text, old, new):
    assert old in text, old  # a plant that changes nothing must not be mistaken for a rule that holds
    return text.replace(old, new, 1)


def failing(verdict):
    return [g.gate_id for g in verdict.gates if g.status == "failed"]


def blocked(verdict):
    return [g.gate_id for g in verdict.gates if g.status == "blocked"]


class Good(unittest.TestCase):
    def test_the_judges_tables_equal_the_hand_written_ones(self):
        self.assertEqual(list(J.EXPECTED_PHASES), PHASE_NAMES)
        self.assertEqual(J.RESOURCE_ORDER, ("VmHWM", "VmRSS", "utime", "stime"))
        self.assertEqual([line.split()[2] for line in PHASES], PHASE_NAMES)

    def test_one_good_synthetic_transcript_passes(self):
        verdict = J.judge_transcript(GOOD)
        self.assertEqual(verdict.status, "passed", [vars(g) for g in verdict.gates])
        self.assertEqual(J.exit_code(verdict.gates), 0)
        self.assertEqual(N, 8)
        self.assertEqual(verdict.counted, {"ok": 8, "fail": 0, "unknown": 0})
        self.assertEqual(verdict.end, {"ok": 8, "fail": 0, "unknown": 0})
        self.assertEqual(verdict.resources, {"VmHWM": 5120, "VmRSS": 4096, "utime": 12, "stime": 3})
        self.assertEqual([p["name"] for p in verdict.phases], PHASE_NAMES)

    def test_crlf_and_foreign_console_lines_are_accepted(self):
        self.assertEqual(J.judge_transcript(build(sep="\r\n")).status, "passed")
        noisy = "OpenBIOS booting\n[    0.1] kernel line\n" + GOOD.replace("T01X02 VmRSS", "FFW_SPEAKER_BEGIN noise\nT01X02 VmRSS") + "FFW_MARKER:REBOOT_REQUEST\n"
        self.assertEqual(J.judge_transcript(noisy).status, "passed")

    def test_boundary_integers_are_accepted(self):
        for token in ("0", "18446744073709551615"):
            with self.subTest(utime=token):
                self.assertEqual(J.judge_transcript(build(res=resources(utime=token, stime=token))).status, "passed")
        self.assertEqual(J.judge_transcript(build(res=resources(VmHWM="4096"))).status, "passed")  # peak equal to current


class Framing(unittest.TestCase):
    def test_only_lf_and_crlf_are_line_boundaries(self):
        self.assertEqual(J.judge_transcript(GOOD).status, "passed")
        for separator in ("\r", "\x0b", "\x0c", "\x85", "\N{LINE SEPARATOR}", "\N{PARAGRAPH SEPARATOR}", "\r\r\n", "\x00"):
            with self.subTest(separator=repr(separator)):
                verdict = J.judge_transcript(swap(GOOD, "\n", separator))
                self.assertEqual(verdict.status, "failed")
                self.assertIn("X02-FRAMING", failing(verdict))
        self.assertIn("X02-FRAMING", failing(J.judge_transcript(GOOD + "\N{REPLACEMENT CHARACTER}\n")))  # a lossy decode

    def test_a_stray_separator_or_control_in_a_foreign_line_is_refused_too(self):
        # The control may sit in a line that is not a T01X02 line, where the line grammar alone would never see it.
        self.assertEqual(J.judge_transcript(swap(GOOD, "T01X02 END", "noise\tnoise\nT01X02 END")).status, "passed")  # a tab is not a separator
        for separator in ("\r", "\x0b", "\x0c", "\x1b", "\x85", "\N{LINE SEPARATOR}", "\N{PARAGRAPH SEPARATOR}", "\x00", "\x7f"):
            with self.subTest(separator=repr(separator)):
                verdict = J.judge_transcript(swap(GOOD, "T01X02 END", f"noise{separator}noise\nT01X02 END"))
                self.assertEqual(failing(verdict), ["X02-FRAMING"], [vars(g) for g in verdict.gates])

    def test_a_child_region_already_mapped_to_lf_refuses_any_cr(self):
        crlf = build(sep="\r\n")
        self.assertEqual(J.judge_transcript(crlf).status, "passed")
        verdict = J.judge_transcript(crlf, crlf_ok=False)
        self.assertEqual(verdict.status, "failed")
        self.assertIn("X02-FRAMING", failing(verdict))

    def test_an_echoed_or_prefixed_marker_is_refused(self):
        for old, new in (("T01X02 PHASE TS_KEYS", "echo T01X02 PHASE TS_KEYS"), ("T01X02 PHASE TS_KEYS", " T01X02 PHASE TS_KEYS"),
                         ("T01X02 PHASE TS_KEYS", "xT01X02 PHASE TS_KEYS"), ("T01X02 END", "# T01X02 END"), ("T01X02 VmRSS", "$ T01X02 VmRSS")):
            with self.subTest(new=new):
                self.assertEqual(J.judge_transcript(swap(GOOD, old, new)).status, "failed")
        self.assertEqual(J.judge_transcript(GOOD + "T01X02\n").status, "failed")

    def test_unrecognized_and_malformed_lines_are_refused(self):
        for extra in ("T01X02 FOO bar", "T01X02 VmSwap 1", "T01X02 VmRSS", "T01X02 VmRSS  1", "T01X02  VmRSS 1", "T01X02 vmrss 1", "T01X02 VmRSS_kB 1", "T01X02 VmHWM_kB 5120", "T01X02 utime_ticks 1",
                      "T01X02 VmHWM=5120", "T01X02 RES VmHWM=5120", "T01X02 RES VmHWM_kB=5120",  # the first-cut `RES name=value` form was dropped
                      "T01X02 PHASE 1KEYS ok k=1", "T01X02 PHASE keys_parse ok k=1", "T01X02 PHASE TS-KEYS ok k=1", "T01X02 PHASE TS_KEYS maybe", "T01X02 PHASE TS_KEYS",
                      "T01X02 END", f"T01X02  END ok={N} fail=0 unknown=0", "T01X02 PHASE TS_KEYS ok key"):
            with self.subTest(extra=extra):
                verdict = J.judge_transcript(swap(GOOD, "T01X02 END", extra + "\nT01X02 END"))
                self.assertEqual(verdict.status, "failed")
                self.assertIn("X02-FRAMING", failing(verdict))
        self.assertIn("X02-FRAMING", failing(J.judge_transcript(swap(GOOD, "T01X02 PHASE TS_KEYS ok", "T01X02\tPHASE TS_KEYS ok"))))


class Phases(unittest.TestCase):
    def only_phases(self, text):
        verdict = J.judge_transcript(text)
        self.assertEqual(failing(verdict), ["X02-PHASES"], [vars(g) for g in verdict.gates])
        self.assertEqual(verdict.status, "failed")

    def test_each_missing_phase_fails(self):
        self.assertEqual(J.judge_transcript(GOOD).status, "passed")
        for index, name in enumerate(PHASE_NAMES):
            with self.subTest(missing=name):
                self.only_phases(build(phases=PHASES[:index] + PHASES[index + 1:], final=end(ok=N - 1)))

    def test_each_duplicate_phase_fails(self):
        for index, name in enumerate(PHASE_NAMES):
            with self.subTest(duplicate=name):
                self.only_phases(build(phases=PHASES[:index + 1] + PHASES[index:], final=end(ok=N + 1)))

    def test_an_extra_phase_fails(self):
        self.only_phases(build(phases=PHASES + ["T01X02 PHASE EXTRA_PHASE ok x=1"], final=end(ok=N + 1)))
        self.only_phases(build(phases=PHASES[:-1], final=end(ok=N - 1)))  # a probe that has not wired CRYPTO_KAT yet prints seven phases: refused, never stubbed

    def test_phases_out_of_order_fail(self):
        swapped = PHASES[:1] + [PHASES[2], PHASES[1]] + PHASES[3:]
        self.only_phases(build(phases=swapped))
        self.only_phases(build(phases=list(reversed(PHASES))))

    def test_a_phase_after_the_resource_lines_fails(self):
        self.only_phases(build(phases=PHASES[:-1], res=resources()[:1] + [PHASES[-1]] + resources()[1:]))

    def test_each_failed_phase_fails_even_with_consistent_end_totals(self):
        for index, name in enumerate(PHASE_NAMES):
            flipped = PHASES[:index] + [PHASES[index].replace(" ok ", " fail ")] + PHASES[index + 1:]
            with self.subTest(failed=name):
                self.only_phases(build(phases=flipped, final=end(ok=N - 1, fail=1)))
                self.assertEqual(J.judge_transcript(build(phases=flipped)).status, "failed")  # and with the stale totals

    def test_the_probes_own_failure_line_fails(self):
        for index, line in ((1, "T01X02 PHASE TS_NOISE fail reason=handshake"), (7, "T01X02 PHASE CRYPTO_KAT fail failed=rfc7748_5_2_vec1")):  # TealSeal's and DarkPeak's shapes
            failed = PHASES[:index] + [line] + PHASES[index + 1:]
            with self.subTest(line=line):
                self.only_phases(build(phases=failed, final=end(ok=N - 1, fail=1)))
                verdict = J.judge_transcript(build(phases=failed, final=end(ok=N - 1, fail=1)))
                self.assertIn(line.split(" fail ")[1], dict((g.gate_id, g.detail) for g in verdict.gates)["X02-PHASES"])  # the reason reaches the report

    def test_fact_syntax_is_exact(self):
        for bad in ("T01X02 PHASE TS_KEYS ok Key=1", "T01X02 PHASE TS_KEYS ok k=a=b", "T01X02 PHASE TS_KEYS ok k=1 k=2", "T01X02 PHASE TS_KEYS ok k=",
                    "T01X02 PHASE TS_KEYS ok k=\N{LATIN SMALL LETTER E WITH ACUTE}"):
            with self.subTest(bad=bad):
                self.assertEqual(J.judge_transcript(build(phases=[bad] + PHASES[1:])).status, "failed")


class Resources(unittest.TestCase):
    def test_unknown_is_blocked_never_a_pass(self):
        for key in ("VmHWM", "VmRSS", "utime", "stime"):
            with self.subTest(unknown=key):
                verdict = J.judge_transcript(build(res=resources(**{key: "UNKNOWN"}), final=end(unknown=1)))
                self.assertEqual(verdict.status, "blocked", [vars(g) for g in verdict.gates])
                self.assertEqual(blocked(verdict), ["X02-RESOURCES"])
                self.assertEqual(failing(verdict), [])
                self.assertEqual(J.exit_code(verdict.gates), 3)
                # END that denies the UNKNOWN contradicts what the judge counted: that is a failure, not a block.
                self.assertEqual(J.judge_transcript(build(res=resources(**{key: "UNKNOWN"}))).status, "failed")
        everything = build(res=resources(VmHWM="UNKNOWN", VmRSS="UNKNOWN", utime="UNKNOWN", stime="UNKNOWN"), final=end(unknown=4))
        self.assertEqual(J.judge_transcript(everything).status, "blocked")

    def test_a_missing_resource_line_is_blocked_never_a_pass(self):
        for index, key in enumerate(("VmHWM", "VmRSS", "utime", "stime")):
            lines = resources()
            with self.subTest(missing=key):
                verdict = J.judge_transcript(build(res=lines[:index] + lines[index + 1:]))
                self.assertEqual(verdict.status, "blocked", [vars(g) for g in verdict.gates])
                self.assertEqual(blocked(verdict), ["X02-RESOURCES"])
                self.assertEqual(J.judge_transcript(build(res=lines[:index] + lines[index + 1:], final=end(unknown=1))).status, "failed")
        self.assertEqual(J.judge_transcript(build(res=[])).status, "blocked")

    def test_a_failure_outranks_a_block(self):
        flipped = PHASES[:1] + [PHASES[1].replace(" ok ", " fail ")] + PHASES[2:]
        verdict = J.judge_transcript(build(phases=flipped, res=resources(utime="UNKNOWN"), final=end(ok=N - 1, fail=1, unknown=1)))
        self.assertEqual(verdict.status, "failed")
        self.assertEqual(blocked(verdict), ["X02-RESOURCES"])

    def test_only_the_exact_unknown_token_is_unknown(self):
        for token in ("unknown", "Unknown", "UNKNOWN ", "N/A", "-", "", "none", "null"):
            with self.subTest(token=token):
                self.assertEqual(J.judge_transcript(build(res=resources(utime=token), final=end(unknown=1))).status, "failed")

    def test_integers_must_be_canonical(self):
        wide = "1" * 21
        for token in ("007", "00", "+5", "-5", "1_0", "5kB", "1e3", "0x10", "5.0", "\N{ARABIC-INDIC DIGIT THREE}", "\N{FULLWIDTH DIGIT ZERO}", "18446744073709551616", wide, "5\N{NO-BREAK SPACE}"):
            with self.subTest(token=token):
                verdict = J.judge_transcript(build(res=resources(utime=token)))
                self.assertEqual(verdict.status, "failed")
                self.assertIn("X02-RESOURCES", failing(verdict))
            self.assertIsNone(J.canonical_uint(token))
        for token, value in (("0", 0), ("7", 7), ("18446744073709551615", (1 << 64) - 1)):
            self.assertEqual(J.canonical_uint(token), value)

    def test_duplicate_and_out_of_order_resource_lines_fail(self):
        lines = resources()
        for res in (lines + [lines[1]], lines[:2] + [lines[1]] + lines[2:]):
            self.assertEqual(J.judge_transcript(build(res=res)).status, "failed")
        swapped = [lines[0], lines[1], lines[3], lines[2]]
        verdict = J.judge_transcript(build(res=swapped))
        self.assertEqual(failing(verdict), ["X02-RESOURCES"])

    def test_the_peak_cannot_be_below_the_current_size_and_neither_can_be_zero(self):
        for over in ({"VmHWM": "4095"}, {"VmRSS": "5121"}, {"VmRSS": "0"}, {"VmHWM": "0", "VmRSS": "0"}, {"VmHWM": "0"}):
            with self.subTest(over=over):
                verdict = J.judge_transcript(build(res=resources(**over)))
                self.assertEqual(verdict.status, "failed")
                self.assertEqual(failing(verdict), ["X02-RESOURCES"])


class End(unittest.TestCase):
    def only_end(self, text):
        verdict = J.judge_transcript(text)
        self.assertEqual(failing(verdict), ["X02-END"], [vars(g) for g in verdict.gates])

    def test_contradictory_totals_fail_beside_a_green_control(self):
        self.assertEqual(J.judge_transcript(GOOD).status, "passed")
        for final in (end(ok=N - 1), end(ok=N + 1), end(fail=1), end(unknown=1), end(ok=N - 1, fail=1), end(ok=0, fail=N), end(ok=N, fail=0, unknown=4)):
            with self.subTest(final=final):
                self.only_end(build(final=final))

    def test_end_must_exist_once_and_come_last(self):
        without_end = "\n".join(PHASES + resources()) + "\n"
        verdict = J.judge_transcript(without_end)
        self.assertEqual(failing(verdict), ["X02-END"], [vars(g) for g in verdict.gates])  # the probe did not finish
        self.only_end(GOOD + end() + "\n")  # a second END
        for trailing in ("T01X02 stime 3\n", PHASES[0] + "\n"):  # anything after END
            verdict = J.judge_transcript(GOOD + trailing)
            self.assertEqual(verdict.status, "failed")
            self.assertIn("X02-END", failing(verdict))
        self.assertEqual(J.judge_transcript(GOOD + GOOD).status, "failed")  # two runs back to back
        self.assertEqual(J.judge_transcript(end() + "\n").status, "failed")  # END alone is not a transcript

    def test_end_integers_are_canonical_and_the_field_list_exact(self):
        self.assertEqual(J.judge_transcript(build(final=f"T01X02 END ok={N} fail=0 unknown=0")).status, "passed")  # the control the plants below are cut from
        for final in (f"T01X02 END ok=0{N} fail=0 unknown=0", "T01X02 END ok=-1 fail=0 unknown=0", f"T01X02 END ok={N} fail=0", f"T01X02 END fail=0 ok={N} unknown=0",
                      f"T01X02 END ok={N} fail=0 unknown=0 extra=1", f"T01X02 END ok={N} fail=0 unknown=0 ", "T01X02 END ok= fail=0 unknown=0",
                      f"T01X02 END ok={N} fail=0 unknown=18446744073709551616", f"T01X02 END ok={N} fail=00 unknown=0", f"T01X02 END ok={N} fail=0 unknown=\N{ARABIC-INDIC DIGIT ZERO}"):
            with self.subTest(final=final):
                self.assertEqual(J.judge_transcript(build(final=final)).status, "failed")

    def test_no_proper_prefix_of_a_good_transcript_passes(self):
        lines = GOOD.splitlines()
        for cut in range(len(lines)):
            with self.subTest(cut=cut):
                self.assertNotEqual(J.judge_transcript("\n".join(lines[:cut]) + "\n").status, "passed")
        self.assertNotEqual(J.judge_transcript("").status, "passed")
        self.assertEqual(J.judge_transcript(GOOD[:-1]).status, "passed")  # a complete END line without its final LF is still a whole line
        self.assertNotEqual(J.judge_transcript(GOOD[:-8]).status, "passed")  # but a cut inside the END line is not


class Capture(unittest.TestCase):
    ELF = {"sha256": "e" * 64}
    SUP = {"sha256": "5" * 64}

    def meta(self, **over):
        meta = {"stop_reason": None, "exit_code": 0, "kernel_sha256": "k" * 64,
                "initramfs": {"init_sha256": "5" * 64, "archive_sha256": "a" * 64, "extra_files": {"franken-speaker": {"sha256": "e" * 64}}},
                "inputs_after_capture": {"kernel": "k" * 64, "initramfs": "a" * 64}}
        meta.update(over)
        return meta

    def problems(self, meta, after=None):
        return J.capture_problems(meta, self.ELF, self.SUP, after or {"probe ELF": "e" * 64, "supervisor ELF": "5" * 64})

    def test_a_clean_capture_has_no_problem(self):
        self.assertEqual(self.problems(self.meta()), [])

    def test_a_timeout_or_output_limit_is_a_failure(self):
        for reason in ("timeout", "output_limit"):
            with self.subTest(reason=reason):
                self.assertTrue(any(reason in p for p in self.problems(self.meta(stop_reason=reason, exit_code=-9))))

    def test_a_qemu_exit_other_than_zero_is_a_failure(self):
        for code in (1, -9, None):
            with self.subTest(code=code):
                self.assertTrue(self.problems(self.meta(exit_code=code)))

    def test_every_hash_that_changes_is_a_failure(self):
        bad_pack = self.meta()
        bad_pack["initramfs"] = {**bad_pack["initramfs"], "init_sha256": "0" * 64}
        self.assertIn("supervisor bytes changed before packaging", self.problems(bad_pack))
        bad_elf = self.meta()
        bad_elf["initramfs"] = {**bad_elf["initramfs"], "extra_files": {"franken-speaker": {"sha256": "0" * 64}}}
        self.assertIn("probe ELF bytes changed before packaging", self.problems(bad_elf))
        for name, value in (("kernel", "0" * 64), ("kernel", None), ("initramfs", "0" * 64), ("initramfs", None)):
            with self.subTest(after=name, value=value):
                meta = self.meta()
                meta["inputs_after_capture"] = {**meta["inputs_after_capture"], name: value}
                self.assertTrue(self.problems(meta))
        for name in ("probe ELF", "supervisor ELF"):
            for value in ("0" * 64, None):
                with self.subTest(after=name, value=value):
                    after = {"probe ELF": "e" * 64, "supervisor ELF": "5" * 64, name: value}
                    self.assertTrue(self.problems(self.meta(), after))


def elf_header(arch):
    """A header-only ELF the P05 parser accepts; never executable evidence."""
    cls, endian, machine, _ = P.RUNTIME_ARCHES[arch]
    data = bytearray(52 if cls == 1 else 64)
    data[:4] = b"\x7fELF"
    data[4:7] = bytes((cls, endian, 1))
    data[18:20] = machine.to_bytes(2, "big" if endian == 2 else "little")
    return bytes(data)


def fnv(data):
    value = 14695981039346656037
    for byte in data:
        value = (value ^ byte) * 1099511628211 % (1 << 64)
    return value


def wrapped(child, arch="mips"):
    """The frozen E07 supervisor transcript with the child's stdout in the speaker-smoke slot (the way the P05 runtime tests wrap theirs)."""
    base = serial_fixture.POSITIVE
    if arch == "powerpc":
        base = base.replace("arch=mips-be", "arch=powerpc-be").replace("mips-unknown", "powerpc-unknown").replace("errno=89", "errno=38")
    data = child.encode()
    region = "FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog\n" + child + f"FFW_SPEAKER_EXIT status=0 stdout_bytes={len(data)} stdout_fnv1a64={fnv(data):016x}\n"
    return swap(base, "FFW_MARKER:TEST_SUCCESS", region + "FFW_MARKER:TEST_SUCCESS")


KERNEL_SHA, ARCHIVE_SHA = "c" * 64, "d" * 64  # real-looking hex digests; the fixture guest has no kernel or archive of its own


def fixture_meta(elf_path, sup_path, serial, **over):
    """What measure-p05-target.run_runtime returns for a clean run, with the hashes of the two ELF files actually on disk."""
    elf_sha = hashlib.sha256(pathlib.Path(elf_path).read_bytes()).hexdigest()
    sup_sha = hashlib.sha256(pathlib.Path(sup_path).read_bytes()).hexdigest()
    logs = pathlib.Path(elf_path).parent  # absolute paths, as the P05 layer records them: the receipt writer has to rewrite every one
    meta = {"command": ["qemu-system-mips", "-M", "malta", "-kernel", str(logs / "vmlinux.runtime-snapshot"), "-initrd", str(logs / "runtime.cpio.gz"),
                        "-append", "console=ttyS0,38400 rdinit=/init panic=-1"],
            "qemu": "fixture", "kernel_sha256": KERNEL_SHA,
            "initramfs": {"init_sha256": sup_sha, "archive_sha256": ARCHIVE_SHA, "extra_files": {"franken-speaker": {"sha256": elf_sha}},
                          "init_path": str(sup_path), "out_path": str(logs / "runtime.cpio.gz")},
            "exit_code": 0, "inputs_after_capture": {"kernel": KERNEL_SHA, "initramfs": ARCHIVE_SHA}, "stop_reason": None,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stdout_sha256": hashlib.sha256(serial.encode()).hexdigest(), "stderr_bytes": 0,
            "scope": "fixture"}
    meta.update(over)
    return meta


class Supervised(unittest.TestCase):
    def status(self, text, arch="mips"):
        verdict, gates, child = J._judge_supervised(text, arch)
        return J.exit_status(gates), gates, child

    def test_the_existing_supervisor_envelope_carries_the_probe_for_both_big_endian_targets(self):
        for arch in ("mips", "powerpc"):
            with self.subTest(arch=arch):
                status, gates, child = self.status(wrapped(GOOD, arch), arch)
                self.assertEqual(status, "passed", [vars(g) for g in gates])
                self.assertEqual(child, GOOD)
                self.assertEqual(self.status("OpenBIOS\rbooting\x0c\x1b[0m\n" + wrapped(GOOD, arch), arch)[0], "passed")  # firmware preamble tolerated
                self.assertEqual(self.status(wrapped(GOOD, arch).replace("\n", "\r\n"), arch)[0], "passed")  # the console's CRLF is mapped back

    def test_a_missing_reboot_fails_beside_the_green_control(self):
        good = wrapped(GOOD)
        self.assertEqual(self.status(good)[0], "passed")
        self.assertEqual(self.status(swap(good, "FFW_MARKER:REBOOT_REQUEST\n", ""))[0], "failed")
        self.assertEqual(self.status(swap(good, "FFW_MARKER:REBOOT_REQUEST", "FFW_MARKER:REBOOT_REQUESTED"))[0], "failed")

    def test_a_truncated_or_unwrapped_child_fails(self):
        good = wrapped(GOOD)
        self.assertEqual(self.status(swap(good, "FFW_SPEAKER_EXIT status=0", "FFW_SPEAKER_EXIT status=7"))[0], "failed")
        self.assertEqual(self.status(swap(good, "stdout_bytes=", "stdout_bytes=9"))[0], "failed")
        self.assertEqual(self.status(swap(good, "FFW_SPEAKER_BEGIN path=", "FFW_SPEAKER_BEGIN path=/wrong"))[0], "failed")
        self.assertEqual(self.status(serial_fixture.POSITIVE)[0], "failed")  # no child at all

    def test_a_cr_the_child_itself_printed_fails(self):
        # The child wrote CRLF, so the console shows CR-CR-LF; the supervisor envelope refuses it before the judge sees a byte.
        self.assertEqual(self.status(wrapped(GOOD.replace("\n", "\r\n")).replace("\n", "\r\n"))[0], "failed")
        self.assertEqual(self.status(wrapped(swap(GOOD, "T01X02 END", "\rT01X02 END")))[0], "failed")  # a bare CR inside a line

    def test_the_judge_rules_apply_inside_the_envelope(self):
        fail_phase = build(phases=PHASES[:1] + [PHASES[1].replace(" ok ", " fail ")] + PHASES[2:], final=end(ok=N - 1, fail=1))
        self.assertEqual(self.status(wrapped(fail_phase))[0], "failed")
        self.assertEqual(self.status(wrapped(build(final=end(ok=N - 1))))[0], "failed")
        unknown = build(res=resources(VmRSS="UNKNOWN"), final=end(unknown=1))
        status, gates, _ = self.status(wrapped(unknown))
        self.assertEqual(status, "blocked", [vars(g) for g in gates])


class RunFlow(unittest.TestCase):
    """`run` in-process with the guest replaced at the one seam; the P05 layer, envelope, hash checks and receipt are real."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ffw-t01-x02-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.elf = self.root / "t01-core-probe.mips"
        self.sup = self.root / "ffw-hello-init.mips"
        self.elf.write_bytes(elf_header("mips") + b"probe")
        self.sup.write_bytes(elf_header("mips") + b"supervisor")
        self.log_dir = self.root / "logs"
        self.receipt = self.root / "receipt.json"

    def meta(self, serial, **over):
        return fixture_meta(self.elf, self.sup, serial, **over)

    def run_main(self, serial, *, receipt=True, **meta_over):
        """`run` with the guest replaced: returns (exit code, stdout, stderr, the namespaces the guest seam was called with)."""
        calls = []

        def fake(p05, namespace, elf, supervisor):
            calls.append(namespace)
            return serial, self.meta(serial, **meta_over)

        out, err = io.StringIO(), io.StringIO()
        argv = ["run", "--arch", "mips", "--elf", str(self.elf), "--supervisor", str(self.sup), "--log-dir", str(self.log_dir), "--revision", "claimed-rev"]
        if receipt:
            argv += ["--receipt", str(self.receipt)]
        with mock.patch.object(J, "capture_guest_run", fake), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = J.main(argv)
        return code, out.getvalue(), err.getvalue(), calls

    def run_with_meta(self, serial, **over):
        code, out, err, _ = self.run_main(serial, **over)
        return code, out + err

    def receipt_json(self):
        return json.loads(self.receipt.read_text())

    def test_a_good_run_passes_and_writes_a_labelled_receipt(self):
        code, out = self.run_with_meta(wrapped(GOOD))
        self.assertEqual(code, 0, out)
        receipt = self.receipt_json()
        self.assertEqual(receipt["schema"], J.RECEIPT_SCHEMA)
        self.assertEqual(receipt["result"], "passed")
        self.assertEqual(receipt["evidence_kind"], "captured_guest_execution")
        self.assertEqual(receipt["revision_claim"], "claimed-rev")
        self.assertEqual(receipt["verdict"]["resources"], {"VmHWM": 5120, "VmRSS": 4096, "utime": 12, "stime": 3})
        self.assertEqual(receipt["elf"]["sha256"], hashlib.sha256(self.elf.read_bytes()).hexdigest())
        self.assertEqual(receipt["child_sha256"], hashlib.sha256(GOOD.encode()).hexdigest())
        self.assertIn("T01-X02 stays pending", receipt["scope"])
        self.assertIn("PASSED", out)

    def test_a_complete_transcript_with_a_timeout_is_never_a_pass(self):
        code, out = self.run_with_meta(wrapped(GOOD), stop_reason="timeout", exit_code=-9)
        self.assertEqual(code, 1, out)
        receipt = self.receipt_json()
        self.assertEqual(receipt["result"], "not_passed")
        self.assertEqual([g["gate_id"] for g in receipt["gates"] if g["status"] == "failed"], ["X02-CAPTURE"])

    def test_a_complete_transcript_without_the_reboot_is_never_a_pass(self):
        code, out = self.run_with_meta(swap(wrapped(GOOD), "FFW_MARKER:REBOOT_REQUEST\n", ""))
        self.assertEqual(code, 1, out)
        self.assertEqual(self.receipt_json()["result"], "not_passed")

    def test_a_changed_hash_is_never_a_pass(self):
        for over in ({"inputs_after_capture": {"kernel": "0" * 64, "initramfs": ARCHIVE_SHA}}, {"inputs_after_capture": {"kernel": KERNEL_SHA, "initramfs": None}}):
            with self.subTest(over=over):
                self.receipt.unlink(missing_ok=True)
                self.assertEqual(self.run_with_meta(wrapped(GOOD), **over)[0], 1)

    def test_an_elf_that_changes_on_disk_during_the_run_is_never_a_pass(self):
        serial = wrapped(GOOD)

        def fake(p05, namespace, elf, supervisor):
            meta = self.meta(serial)
            self.elf.write_bytes(self.elf.read_bytes() + b"!")
            return serial, meta

        with mock.patch.object(J, "capture_guest_run", fake), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = J.main(["run", "--arch", "mips", "--elf", str(self.elf), "--supervisor", str(self.sup), "--log-dir", str(self.log_dir), "--receipt", str(self.receipt)])
        self.assertEqual(code, 1)
        self.assertIn("probe ELF changed on disk", self.receipt.read_text())

    def test_unknown_resources_make_the_run_blocked(self):
        code, out = self.run_with_meta(wrapped(build(res=resources(VmHWM="UNKNOWN"), final=end(unknown=1))))
        self.assertEqual(code, 3, out)
        self.assertEqual(self.receipt_json()["result"], "blocked")
        self.assertIn("BLOCKED", out)

    def test_an_existing_receipt_or_a_missing_directory_stops_before_any_guest_starts(self):
        self.receipt.write_text("precious\n")
        code, out, err, calls = self.run_main(wrapped(GOOD))
        self.assertEqual((code, calls), (2, []), err)
        self.assertEqual(self.receipt.read_text(), "precious\n")
        self.receipt = self.root / "nowhere" / "receipt.json"
        code, out, err, calls = self.run_main(wrapped(GOOD))
        self.assertEqual((code, calls), (2, []), err)

    def test_the_default_bounds_are_the_p05_ones_and_the_real_p05_layer_is_called(self):
        self.assertEqual(J.CAPTURE_BYTES, P.RUNTIME_CAPTURE_BYTES)
        self.assertEqual(J.DEFAULT_TIMEOUT, 180.0)
        code, out, err, calls = self.run_main(wrapped(GOOD), receipt=False)
        self.assertEqual((code, len(calls)), (0, 1), out + err)
        self.assertEqual((calls[0].timeout, calls[0].arch, calls[0].log_dir), (180.0, "mips", self.log_dir))
        # Unreplaced, the seam is the P05 function itself; with no kernel it refuses before any QEMU starts.
        source = pathlib.Path(J.__file__).read_text()
        self.assertIn("p05.run_runtime(", source)
        for forked in ("qemu-system", "capture_guest(", "mkinitramfs", "Popen"):
            self.assertNotIn(forked, source)
        empty = self.root / "no-build"
        empty.mkdir()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"FFW_BUILD_DIR": str(empty)}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = J.main(["run", "--arch", "mips", "--elf", str(self.elf), "--supervisor", str(self.sup), "--log-dir", str(self.root / "real-logs")])
        self.assertEqual(code, 2)
        self.assertIn("kernel", err.getvalue())

    def test_a_wrong_architecture_elf_is_refused_before_the_guest(self):
        self.elf.write_bytes(elf_header("powerpc"))
        code, out, err, calls = self.run_main(wrapped(GOOD))
        self.assertEqual((code, calls), (2, []), err)


class Cli(unittest.TestCase):
    """The shell entry point and `analyze`, as a person runs them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ffw-t01-x02-cli-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def t01(self, *args):
        return subprocess.run([ENTRY, "--x02", *args], cwd=REPO, capture_output=True, text=True, timeout=120)

    def write(self, name, text):
        path = self.root / name
        path.write_bytes(text.encode() if isinstance(text, str) else text)
        return str(path)

    def test_analyze_a_good_transcript_is_labelled_a_supplied_transcript_analysis(self):
        log, receipt = self.write("good.log", GOOD), str(self.root / "r.json")
        done = self.t01("analyze", "--log", log, "--receipt", receipt)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("supplied_transcript_analysis", done.stdout)
        self.assertIn("PASSED", done.stdout)
        body = json.loads(pathlib.Path(receipt).read_text())
        self.assertEqual((body["result"], body["evidence_kind"], body["execution"]), ("passed", "supplied_transcript_analysis", None))
        self.assertEqual(body["transcript_sha256"], hashlib.sha256(GOOD.encode()).hexdigest())
        again = self.t01("analyze", "--log", log, "--receipt", receipt)
        self.assertEqual(again.returncode, 2)  # exclusive: never overwritten
        self.assertEqual(json.loads(pathlib.Path(receipt).read_text()), body)

    def test_exit_codes_pass_fail_blocked_and_usage(self):
        cases = ((GOOD, 0), (swap(GOOD, f"ok={N}", f"ok={N - 1}"), 1), (build(res=resources(utime="UNKNOWN"), final=end(unknown=1)), 3), (build(res=[]), 3), ("", 1))
        for index, (text, want) in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(self.t01("analyze", "--log", self.write(f"c{index}.log", text)).returncode, want)
        self.assertEqual(self.t01("analyze").returncode, 3)  # no transcript supplied: blocked, nothing claimed
        self.assertEqual(self.t01("analyze", "--log", str(self.root / "absent.log")).returncode, 2)
        self.assertEqual(self.t01("analyze", "--log", self.write("big.log", b"x" * (J.CAPTURE_BYTES + 1))).returncode, 2)
        self.assertEqual(self.t01("analyze", "--log", self.write("g.log", GOOD), "--supervisor", self.write("s", b"")).returncode, 2)  # --supervisor needs --arch
        self.assertEqual(self.t01().returncode, 2)
        self.assertEqual(self.t01("bogus").returncode, 2)

    def test_analyze_a_full_serial_log_through_the_supervisor_envelope(self):
        sup = self.write("sup.elf", elf_header("mips") + b"s")
        probe = self.write("probe.elf", elf_header("mips") + b"p")
        good = self.write("serial.log", wrapped(GOOD))
        done = self.t01("analyze", "--log", good, "--arch", "mips", "--supervisor", sup, "--elf", probe)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("supplied_transcript_analysis", done.stdout)
        bad = self.write("noreboot.log", swap(wrapped(GOOD), "FFW_MARKER:REBOOT_REQUEST\n", ""))
        self.assertEqual(self.t01("analyze", "--log", bad, "--arch", "mips", "--supervisor", sup).returncode, 1)
        self.assertEqual(self.t01("analyze", "--log", good, "--arch", "powerpc", "--supervisor", sup).returncode, 2)  # a mips ELF is not powerpc

    def test_the_existing_entry_point_is_unchanged(self):
        done = subprocess.run([ENTRY, "--list"], cwd=REPO, capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("T01-X02-target-resources", done.stdout)


DELETE = object()  # `planted` deletes the field instead of replacing it


class ReceiptPaths(unittest.TestCase):
    """The writer: no absolute host path survives into a receipt, and the hashes of the rewritten paths still bind the files they named."""

    FORBIDDEN = ("/Users/", "/home/", "/private/tmp/", "/var/folders/")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ffw-t01-x02-paths-")
        self.addCleanup(self.tmp.cleanup)
        self.work = pathlib.Path(self.tmp.name)

    def produce(self, arch="mips", revision=None, over=None, serial=None):
        """`run` with the guest replaced; returns (exit code, stderr, receipt path). `over(elf, sup)` returns meta overrides."""
        elf, sup = self.work / f"probe.{arch}", self.work / f"sup.{arch}"
        elf.write_bytes(elf_header(arch) + b"probe")
        sup.write_bytes(elf_header(arch) + b"supervisor")
        serial = wrapped(GOOD, arch) if serial is None else serial
        receipt = self.work / f"receipt.{arch}.json"
        extra = over(elf, sup) if over else {}

        def fake(p05, namespace, elf_identity, sup_identity):
            return serial, fixture_meta(elf, sup, serial, **extra)

        argv = ["run", "--arch", arch, "--elf", str(elf), "--supervisor", str(sup), "--log-dir", str(self.work / f"logs.{arch}"), "--receipt", str(receipt)]
        if revision is not None:
            argv += ["--revision", revision]
        err = io.StringIO()
        with mock.patch.object(J, "capture_guest_run", fake), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = J.main(argv)
        return code, err.getvalue(), receipt

    def test_a_run_receipt_carries_no_absolute_path_and_its_hashes_still_bind_the_files(self):
        kernel, archive = self.work / "vmlinux.runtime-snapshot", self.work / "runtime.cpio.gz"
        kernel.write_bytes(b"kernel bytes " * 100)
        archive.write_bytes(b"archive bytes " * 100)
        kernel_sha, archive_sha = hashlib.sha256(kernel.read_bytes()).hexdigest(), hashlib.sha256(archive.read_bytes()).hexdigest()
        script = J.HERE / "x02_judge.py"

        def over(elf, sup):
            return {"kernel_sha256": kernel_sha, "inputs_after_capture": {"kernel": kernel_sha, "initramfs": archive_sha},
                    "command": ["qemu-system-mips", "-kernel", str(kernel), "-initrd", str(archive), "-append", "console=ttyS0,38400 rdinit=/init panic=-1"],
                    "initramfs": {"init_sha256": hashlib.sha256(sup.read_bytes()).hexdigest(), "archive_sha256": archive_sha,
                                  "extra_files": {"franken-speaker": {"sha256": hashlib.sha256(elf.read_bytes()).hexdigest()}},
                                  "init_path": str(sup), "out_path": str(archive)},
                    "harness": str(script)}  # a path inside the repository

        code, err, path = self.produce(over=over)
        self.assertEqual(code, 0, err)
        text = path.read_text()
        for prefix in self.FORBIDDEN + (str(self.work), os.path.realpath(self.work), str(J.REPO) + "/"):
            self.assertNotIn(prefix, text)
        self.assertIsNone(J.ABSOLUTE_PATH.search(text))
        body = json.loads(text)
        execution = body["execution"]
        self.assertEqual(execution["command"][1:6], ["-kernel", "<outside-repo>/vmlinux.runtime-snapshot", "-initrd", "<outside-repo>/runtime.cpio.gz", "-append"])
        self.assertEqual(execution["command"][-1], "console=ttyS0,38400 rdinit=/init panic=-1")  # the guest's own command line is untouched
        self.assertEqual((execution["initramfs"]["init_path"], execution["initramfs"]["out_path"]), ("<outside-repo>/sup.mips", "<outside-repo>/runtime.cpio.gz"))
        self.assertEqual(execution["harness"], "tests/t01/x02_judge.py")  # under the repository: repo-relative
        bound = {entry["path"]: entry["sha256"] for entry in body["path_hashes"]}
        self.assertEqual(bound["<outside-repo>/vmlinux.runtime-snapshot"], kernel_sha)
        self.assertEqual(bound["<outside-repo>/vmlinux.runtime-snapshot"], execution["kernel_sha256"])  # the file's hash is the receipt's own kernel hash
        self.assertEqual(bound["<outside-repo>/runtime.cpio.gz"], archive_sha)
        self.assertEqual(bound["<outside-repo>/runtime.cpio.gz"], execution["initramfs"]["archive_sha256"])
        self.assertEqual(bound["<outside-repo>/sup.mips"], body["supervisor_elf"]["sha256"])
        self.assertEqual(bound["tests/t01/x02_judge.py"], hashlib.sha256(script.read_bytes()).hexdigest())
        self.assertEqual(J.judge_receipt(text).problems, [])  # and the consumer reads it
        self.assertEqual(J.judge_receipt(text).state, "passed")

    def test_the_scrub_rewrites_every_host_root_and_leaves_lookalikes_alone(self):
        seen = []
        rewritten = {"/Users/a/b": "<outside-repo>/b", "-kernel=/home/x/k": "-kernel=<outside-repo>/k", "'/private/tmp/x/y.log'": "'<outside-repo>/y.log'",
                     "(/tmp/z)": "(<outside-repo>/z)", "/var/folders/ab/T/q": "<outside-repo>/q", "see /Users/a and /Users/b": "see <outside-repo>/a and <outside-repo>/b",
                     "/Volumes/d/x": "<outside-repo>/x", "/root/x": "<outside-repo>/x", "/mnt/x": "<outside-repo>/x", "/srv/x": "<outside-repo>/x",
                     "/data/x": "<outside-repo>/x", "/bulk/x": "<outside-repo>/x", "/tmp": "<outside-repo>/tmp", "a,/Users/q/r;b": "a,<outside-repo>/r;b",
                     str(J.REPO): ".", str(J.REPO / "tests" / "t01"): "tests/t01", str(J.REPO / "tests" / "t01" / ".." / "t01" / "x"): "tests/t01/x"}
        for text, want in rewritten.items():
            with self.subTest(text=text):
                self.assertEqual(J._scrub(text, seen), want)
        for text in ("8/8", "x25519=2/2", "rdinit=/init", "console=ttyS0,38400 rdinit=/init panic=-1", "toolchain/var/x", "usr/home/x", "a/tmp/b", "/init", "2026-11-08",
                     "<outside-repo>/x", "tests/t01/x02_judge.py", "https://example.invalid/Users/x", "~/home/x", "/usr/bin/qemu-system-mips"):
            with self.subTest(text=text):
                self.assertEqual(J._scrub(text, []), text)
        self.assertEqual(J._scrub({"/Users/k/a": ["/home/x/y", 3, None, {"n": "/tmp/q"}]}, []), {"<outside-repo>/a": ["<outside-repo>/y", 3, None, {"n": "<outside-repo>/q"}]})

    def test_the_writer_refuses_to_write_a_receipt_in_which_a_path_survives(self):
        code, err, path = self.produce()
        self.assertEqual(code, 0, err)
        path.unlink()
        with mock.patch.object(J, "_scrub", lambda value, seen: value):  # the scrub is gone: the guard behind it must still hold
            code, err, path = self.produce()
        self.assertEqual(code, 2)
        self.assertIn("refusing to write a receipt that still carries an absolute path", err)
        self.assertFalse(path.exists())

    def test_a_revision_claim_that_is_a_path_is_rewritten_too(self):
        code, err, path = self.produce(revision="/Users/someone/work/rev1")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(path.read_text())["revision_claim"], "<outside-repo>/rev1")

    @staticmethod
    def with_command(*extra):
        """`over` for `produce`: the QEMU command line is the fixed prefix and then `extra`."""
        return lambda elf, sup: {"command": ["qemu-system-mips", "-M", "malta", *extra]}

    def produced(self, **kwargs):
        """`produce` once more; the receipt of the last call is removed first so the writer does not meet an existing file."""
        (self.work / "receipt.mips.json").unlink(missing_ok=True)
        return self.produce(**kwargs)

    def test_the_writer_rewrites_a_host_path_under_any_listed_root_and_refuses_one_under_an_unlisted_root(self):
        # Rewritten: the roots added beside the original eleven. Before this each was written into the receipt as it was.
        for root in ("opt", "Library", "Applications", "System", "nix", "run", "media", "net", "export", "workspace", "work", "builds"):
            with self.subTest(root=root):
                code, err, path = self.produced(over=self.with_command("-drive", f"file=/{root}/someone/tree/disk.img"))
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(path.read_text())["execution"]["command"][-1], "file=<outside-repo>/disk.img")
        # Refused: a root nobody listed. The rewrite cannot bind it to a file, so nothing is written, and the message names the root only.
        for text in ("/zzz/someone/tree/disk.img", "file=/lost-and-found/someone/disk.img"):
            with self.subTest(text=text):
                code, err, path = self.produced(over=self.with_command("-drive", text))
                self.assertEqual(code, 2)
                self.assertIn("refusing to write a receipt that still carries an absolute path under /", err)
                self.assertNotIn("someone", err)
                self.assertFalse(path.exists())
        # Control: system and guest paths, the guest's own command line and the rewritten labels are not host paths and are written as they are.
        keep = ["/usr/bin/qemu-system-mips", "-M", "malta", "-append", "console=ttyS0,38400 rdinit=/init panic=-1", "/proc/self/task", "/dev/ttyS0"]
        code, err, path = self.produced(over=lambda elf, sup: {"command": keep})
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(path.read_text())["execution"]["command"], keep)

    def test_the_writer_refuses_a_relative_path_that_leaves_the_repository(self):
        # `--log-dir ../out/run` puts `../out/run/vmlinux.runtime-snapshot` on the command line, and no absolute path is in it.
        for text in ("../out/someone/run/vmlinux.runtime-snapshot", "../../private-sibling-someone/x", "../.."):
            with self.subTest(text=text):
                code, err, path = self.produced(over=self.with_command("-kernel", text))
                self.assertEqual(code, 2)
                self.assertIn("relative path that leaves the repository", err)
                self.assertNotIn("someone", err)
                self.assertFalse(path.exists())
        # Control: a path that stays under its directory, or only mentions two dots, is written as it is.
        keep = ["qemu-system-mips", "-kernel", "src/../x", "-initrd", "./out/run/archive.cpio.gz", "-append", "wait... a..b"]
        code, err, path = self.produced(over=lambda elf, sup: {"command": keep})
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(path.read_text())["execution"]["command"], keep)

    def test_two_different_files_with_one_basename_do_not_share_one_name_in_the_receipt(self):
        one, two = self.work / "one", self.work / "two"
        one.mkdir()
        two.mkdir()
        (one / "blob").write_bytes(b"AAAA")
        (two / "blob").write_bytes(b"BBBB")
        (one / "kernel.bin").write_bytes(b"KKKK")
        # Plant: both would be `<outside-repo>/blob` with two different hashes, and the name could not say which file it binds.
        code, err, path = self.produced(over=self.with_command("-kernel", str(one / "blob"), "-initrd", str(two / "blob")))
        self.assertEqual(code, 2)
        self.assertIn("two different files would both be named <outside-repo>/blob", err)
        self.assertFalse(path.exists())
        # A path that exists and one that does not, under one name, are as ambiguous.
        code, err, path = self.produced(over=self.with_command("-kernel", str(one / "blob"), "-initrd", str(self.work / "gone" / "blob")))
        self.assertEqual(code, 2)
        self.assertFalse(path.exists())
        # Control: the same file named twice, and two files under two basenames, are written, each name bound to its own bytes.
        code, err, path = self.produced(over=self.with_command("-kernel", str(one / "blob"), "-initrd", f"x={one / 'blob'}", "-dtb", str(one / "kernel.bin")))
        self.assertEqual(code, 0, err)
        bound = {entry["path"]: entry["sha256"] for entry in json.loads(path.read_text())["path_hashes"]}
        self.assertEqual(bound["<outside-repo>/blob"], hashlib.sha256(b"AAAA").hexdigest())
        self.assertEqual(bound["<outside-repo>/kernel.bin"], hashlib.sha256(b"KKKK").hexdigest())

    def test_two_keys_that_the_rewrite_would_make_one_are_refused_and_not_silently_merged(self):
        with self.assertRaises(J.X02Error) as caught:
            J._scrub({"/tmp/one/x.bin": 1, "/var/two/x.bin": 2}, [])  # the second entry must not replace the first
        self.assertIn("would both be keyed '<outside-repo>/x.bin'", str(caught.exception))
        # Control: the same value under both spellings loses nothing, and distinct names stay distinct.
        self.assertEqual(J._scrub({"/tmp/one/x.bin": 1, "/var/two/x.bin": 1, "/tmp/one/y.bin": 2}, []), {"<outside-repo>/x.bin": 1, "<outside-repo>/y.bin": 2})

    def test_an_analysis_receipt_carries_no_path_either(self):
        log, receipt = self.work / "transcript.log", self.work / "analysis.json"
        log.write_text(GOOD)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(J.main(["analyze", "--log", str(log), "--arch", "mips", "--receipt", str(receipt)]), 0)
        text = receipt.read_text()
        self.assertIsNone(J.ABSOLUTE_PATH.search(text))
        self.assertNotIn(str(self.work), text)
        self.assertEqual(json.loads(text)["path_hashes"], [])


class Consumer(unittest.TestCase):
    """`run_cases.case_resources` reading X02 receipts. Every receipt is written by the real producer (`x02_judge.main run|analyze`, the guest replaced at its one seam),
    so the consumer is tested against what the producer really writes; each plant is a copy of a real receipt with one field changed, beside the unplanted pair that passes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ffw-t01-x02-consumer-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.measurements = self.repo / "toolchain" / "results" / "tailscale" / "measurements"
        self.measurements.mkdir(parents=True)
        self.work = self.root / "work"
        self.work.mkdir()
        self.count = 0

    def real(self, arch, serial=None, **meta_over):
        """A receipt exactly as `run` writes it for a captured run on `arch`; returns the parsed JSON."""
        self.count += 1
        elf, sup = self.work / f"probe.{arch}.{self.count}", self.work / f"sup.{arch}.{self.count}"
        elf.write_bytes(elf_header(arch) + f"probe {arch}".encode())
        sup.write_bytes(elf_header(arch) + f"supervisor {arch}".encode())
        serial = wrapped(GOOD, arch) if serial is None else serial
        receipt = self.work / f"receipt.{arch}.{self.count}.json"

        def fake(p05, namespace, elf_identity, sup_identity):
            return serial, fixture_meta(elf, sup, serial, **meta_over)

        with mock.patch.object(J, "capture_guest_run", fake), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            J.main(["run", "--arch", arch, "--elf", str(elf), "--supervisor", str(sup), "--log-dir", str(self.work / f"logs.{self.count}"), "--receipt", str(receipt)])
        return json.loads(receipt.read_text())

    def analysis(self, arch, text=GOOD):
        """A receipt exactly as `analyze` writes it for a supplied transcript."""
        self.count += 1
        log, receipt = self.work / f"transcript.{self.count}.log", self.work / f"analysis.{self.count}.json"
        log.write_text(text)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            J.main(["analyze", "--log", str(log), "--arch", arch, "--receipt", str(receipt)])
        return json.loads(receipt.read_text())

    def put(self, name, body):
        (self.measurements / name).write_text(body if isinstance(body, str) else json.dumps(body, indent=2, sort_keys=True) + "\n")

    def case(self):
        return rc.case_resources(str(self.repo))

    def pair(self, mips=None, powerpc=None):
        self.put("mips.json", mips or self.real("mips"))
        self.put("powerpc.json", powerpc or self.real("powerpc"))

    def planted(self, body, path, value):
        """A deep copy of `body` with the field at `path` replaced (or deleted when value is the sentinel DELETE)."""
        copy = json.loads(json.dumps(body))
        node = copy
        for key in path[:-1]:
            node = node[key]
        assert path[-1] in node if isinstance(node, dict) else path[-1] < len(node), path
        if value is DELETE:
            del node[path[-1]]
        elif callable(value):
            node[path[-1]] = value(node[path[-1]])
        else:
            node[path[-1]] = value
        return copy

    def assert_fails_naming(self, name, *needles):
        result = self.case()
        self.assertEqual(result.status, "failed", result.detail)
        self.assertIn(name, result.detail)
        for needle in needles:
            self.assertIn(needle, result.detail)
        self.assertEqual(rc.exit_code([result]), 1)

    # ---- the green controls ----

    def test_no_receipt_is_blocked(self):
        result = self.case()
        self.assertEqual(result.status, "blocked")
        self.assertIn("no measurement receipt", result.detail)
        self.assertEqual(rc.exit_code([result]), 3)

    def test_a_captured_run_on_each_legacy_target_passes_with_its_figures_and_its_bound(self):
        self.pair()
        result = self.case()
        self.assertEqual((result.status, result.group), ("passed", "central"), result.detail)
        self.assertEqual(rc.exit_code([result]), 0)
        for said in ("mips: PASSED, VmHWM 5120 kB, VmRSS 4096 kB, utime 12, stime 3 ticks", "powerpc: PASSED", "indicative", "harness guests only", "native requirement and the closure of T01 are untouched"):
            self.assertIn(said, result.detail)

    def test_the_real_tree_has_no_receipt_so_the_case_stays_blocked(self):
        if rc.receipt_files("measurements", rc.REPO):
            self.skipTest("a measurement receipt is committed; the controls above cover the judged paths")
        self.assertEqual(rc.case_resources(rc.REPO).status, "blocked")

    # ---- one target is not both ----

    def test_a_single_target_is_blocked_and_named_never_a_pass(self):
        self.pair()
        for arch, other in (("mips", "powerpc"), ("powerpc", "mips")):
            with self.subTest(only=arch):
                (self.measurements / f"{other}.json").unlink()
                result = self.case()
                self.put(f"{other}.json", self.real(other))  # restore the pair first, so a failed assertion cannot leak into the next subtest
                self.assertEqual(result.status, "blocked", result.detail)
                self.assertIn(f"{other}: NOT RECORDED", result.detail)
                self.assertIn(f"{arch}: PASSED", result.detail)
        self.assertEqual(self.case().status, "passed")

    def test_two_passed_runs_of_one_target_do_not_stand_in_for_the_other(self):
        self.put("mips-a.json", self.real("mips"))
        self.put("mips-b.json", self.real("mips"))
        result = self.case()
        self.assertEqual(result.status, "blocked", result.detail)
        self.assertIn("(+1 earlier passed)", result.detail)
        self.assertIn("powerpc: NOT RECORDED", result.detail)

    # ---- a supplied transcript analysis is never execution evidence ----

    def test_supplied_transcript_analyses_never_pass_whatever_they_declare(self):
        mips, powerpc = self.analysis("mips"), self.analysis("powerpc")
        self.assertEqual((mips["result"], mips["evidence_kind"]), ("passed", "supplied_transcript_analysis"))  # the real analyze receipt says passed ...
        self.pair(mips, powerpc)
        result = self.case()
        self.assertEqual(result.status, "blocked", result.detail)  # ... and the consumer still refuses to count it
        self.assertIn("supplied transcript analysis", result.detail)
        self.assertIn("mips: NOT RECORDED", result.detail)
        self.pair(self.real("mips"), powerpc)  # one real run beside one analysis: still not both targets
        self.assertEqual(self.case().status, "blocked")
        self.pair()  # control: two real runs pass
        self.assertEqual(self.case().status, "passed")

    def test_a_captured_receipt_relabelled_as_an_analysis_or_the_reverse_does_not_pass(self):
        good = self.real("powerpc")
        self.pair(powerpc=self.planted(good, ("evidence_kind",), "supplied_transcript_analysis"))
        self.assertEqual(self.case().status, "blocked")
        self.pair(powerpc=good)
        self.assertEqual(self.case().status, "passed")
        relabelled = self.planted(self.analysis("powerpc"), ("evidence_kind",), "captured_guest_execution")  # an analysis has no execution record to back the claim
        self.pair(powerpc=relabelled)
        self.assert_fails_naming("powerpc.json", "execution")

    # ---- a captured run that did not pass ----

    def test_a_captured_run_that_did_not_pass_fails_by_name(self):
        self.pair()
        self.assertEqual(self.case().status, "passed")
        for label, over, serial in (("timeout", {"stop_reason": "timeout", "exit_code": -9}, None), ("output limit", {"stop_reason": "output_limit", "exit_code": -9}, None),
                                    ("exit code", {"exit_code": 1}, None), ("no reboot", {}, swap(wrapped(GOOD), "FFW_MARKER:REBOOT_REQUEST\n", "")),
                                    ("failed phase", {}, wrapped(build(phases=PHASES[:1] + [PHASES[1].replace(" ok ", " fail ")] + PHASES[2:], final=end(ok=N - 1, fail=1)))),
                                    ("kernel changed", {"inputs_after_capture": {"kernel": "0" * 64, "initramfs": ARCHIVE_SHA}}, None)):
            with self.subTest(label=label):
                self.put("mips.json", self.real("mips", serial, **over))
                try:
                    self.assert_fails_naming("mips.json", "did not pass")
                finally:
                    self.put("mips.json", self.real("mips"))
        self.assertEqual(self.case().status, "passed")

    def test_a_failed_run_is_not_outvoted_by_a_later_pass(self):
        self.pair()
        self.put("mips-0-failed.json", self.real("mips", None, stop_reason="timeout", exit_code=-9))
        self.assert_fails_naming("mips-0-failed.json", "did not pass")  # the failed receipt stays until the operator replaces it; nothing here deletes it

    def test_an_envelope_failure_is_a_failed_run_not_a_malformed_receipt(self):
        self.pair(mips=self.real("mips", serial_fixture.POSITIVE))  # no child at all: the real writer records verdict null
        body = json.loads((self.measurements / "mips.json").read_text())
        self.assertIsNone(body["verdict"])
        self.assert_fails_naming("mips.json", "did not pass")

    # ---- blocked ----

    def test_an_unknown_reading_makes_the_run_blocked_until_a_known_run_replaces_it(self):
        unknown = self.real("powerpc", wrapped(build(res=resources(VmRSS="UNKNOWN"), final=end(unknown=1)), "powerpc"))
        self.assertEqual(unknown["result"], "blocked")
        self.pair(powerpc=unknown)
        result = self.case()
        self.assertEqual(result.status, "blocked", result.detail)
        self.assertIn("powerpc.json (powerpc) is blocked", result.detail)
        self.assertIn("powerpc: NOT RECORDED", result.detail)
        self.assertEqual(rc.exit_code([result]), 3)
        self.put("powerpc-2.json", self.real("powerpc"))  # a later known run of the same target completes the pair
        self.assertEqual(self.case().status, "passed")

    # ---- malformed, foreign or oversize files fail by name ----

    def test_malformed_or_foreign_files_fail_by_name_beside_the_passing_pair(self):
        good = self.real("mips")
        cases = {"empty": "", "braces": "{}\n", "array": "[]\n", "text": "not json\n", "nan": '{"x": NaN}\n', "duplicate key": '{"schema": "a", "schema": "b"}\n',
                 "other schema": json.dumps({**good, "schema": "ffw.t01.x02_receipt.v2"}), "no schema": json.dumps({k: v for k, v in good.items() if k != "schema"}),
                 "other grammar": json.dumps({**good, "grammar": "ffw.t01.x02_transcript.v0-draft"}), "schema is a list": json.dumps({**good, "schema": ["ffw.t01.x02_receipt.v1"]}),
                 "other receipt kind": json.dumps({"schema": "ffw.p05.runtime_receipt.v1", "result": "passed"})}
        text = json.dumps(good, indent=2, sort_keys=True) + "\n"
        cases["NaN in an unused field"] = swap(text, '"stderr_bytes": 0', '"stderr_bytes": NaN')
        cases["Infinity in an unused field"] = swap(text, '"stderr_bytes": 0', '"stderr_bytes": Infinity')
        cases["a repeated key with the same value"] = swap(text, '"arch": "mips",', '"arch": "mips",\n  "arch": "mips",')
        self.pair()
        self.assertEqual(self.case().status, "passed")
        for label, text in cases.items():
            with self.subTest(label=label):
                self.put("zz-foreign.json", text)
                try:
                    self.assert_fails_naming("zz-foreign.json")
                finally:
                    (self.measurements / "zz-foreign.json").unlink()
        for name, plant, needle in (("zz-bytes.json", lambda path: path.write_bytes(b"\xff\xfe{}"), None),
                                    ("zz-big.json", lambda path: path.write_text(" " * (J.MAX_RECEIPT_BYTES + 1)), "byte cap"),
                                    ("zz-link.json", lambda path: os.symlink(self.measurements / "mips.json", path), "plain regular file")):
            with self.subTest(file=name):
                plant(self.measurements / name)
                try:
                    self.assert_fails_naming(name, *([needle] if needle else []))
                finally:
                    (self.measurements / name).unlink()
        self.assertEqual(self.case().status, "passed")

    def test_the_schema_message_names_the_schema_it_found(self):
        self.put("old.json", {**self.real("mips"), "schema": "ffw.t01.x02_receipt.v0"})
        self.assert_fails_naming("old.json", "schema 'ffw.t01.x02_receipt.v0' is not ffw.t01.x02_receipt.v1")

    # ---- a receipt is not trusted for its own `result` ----

    def test_a_receipt_that_declares_passed_but_whose_recorded_facts_do_not_hold_fails(self):
        good = self.real("mips")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")
        plants = {
            "a phase failed": (("verdict", "phases", 2, "status"), "fail"), "a phase removed": (("verdict", "phases", 7), DELETE),
            "a phase renamed": (("verdict", "phases", 0, "name"), "TS_KEYS2"), "facts broke the syntax": (("verdict", "phases", 0, "facts"), {"k": "a b"}),
            "VmRSS unknown": (("verdict", "resources", "VmRSS"), "UNKNOWN"), "VmRSS missing": (("verdict", "resources", "VmRSS"), None),
            "peak below current": (("verdict", "resources", "VmHWM"), 1), "VmRSS zero": (("verdict", "resources", "VmRSS"), 0),
            "utime as text": (("verdict", "resources", "utime"), "12"), "utime negative": (("verdict", "resources", "utime"), -1),
            "utime fractional": (("verdict", "resources", "utime"), 1.5), "utime boolean": (("verdict", "resources", "utime"), True),
            "END contradicts": (("verdict", "end", "ok"), 7), "END dropped": (("verdict", "end"), None), "END malformed": (("verdict", "end"), {"ok": 8}),
            "verdict status blocked": (("verdict", "status"), "blocked"), "verdict status failed": (("verdict", "status"), "failed"),
            "a gate failed": (("gates", 5, "status"), "failed"), "a gate blocked": (("gates", 1, "status"), "blocked"), "a gate removed": (("gates", 4), DELETE),
            "the envelope gate removed": (("gates", 0), DELETE), "the capture gate removed": (("gates", 5), DELETE),
            "a gate repeated": (("gates",), lambda gates: gates + [gates[0]]),
            "gates not a list": (("gates",), {}), "result unknown": (("result",), "bogus"), "kind unknown": (("evidence_kind",), "bogus"), "arch unknown": (("arch",), "x86_64"),
            "arch swapped": (("arch",), "powerpc"), "probe sha removed": (("elf", "sha256"), DELETE), "probe sha uppercase": (("elf", "sha256"), "A" * 64),
            "probe sha short": (("elf", "sha256"), "abc"), "probe arch wrong": (("elf", "arch"), "powerpc"), "supervisor sha removed": (("supervisor_elf", "sha256"), DELETE),
            "kernel sha removed": (("execution", "kernel_sha256"), DELETE), "kernel sha malformed": (("execution", "kernel_sha256"), "k" * 64),
            "initramfs sha removed": (("execution", "initramfs", "archive_sha256"), DELETE), "kernel changed after": (("execution", "inputs_after_capture", "kernel"), "0" * 64),
            "initramfs gone after": (("execution", "inputs_after_capture", "initramfs"), None),
            "packaged supervisor differs": (("execution", "initramfs", "init_sha256"), "0" * 64),
            "packaged probe differs": (("execution", "initramfs", "extra_files", "franken-speaker", "sha256"), "0" * 64),
            "exit code 1": (("execution", "exit_code"), 1), "exit code false": (("execution", "exit_code"), False), "stop reason set": (("execution", "stop_reason"), "timeout"),
            "stop reason removed": (("execution", "stop_reason"), DELETE), "execution null": (("execution",), None), "transcript hash differs": (("transcript_sha256",), "0" * 64),
        }
        for label, (path, value) in plants.items():
            with self.subTest(label=label):
                self.put("mips.json", self.planted(good, path, value))
                result = self.case()
                self.assertEqual(result.status, "failed", result.detail)
                self.assertIn("mips.json", result.detail)
        self.put("mips.json", good)
        self.assertEqual(self.case().status, "passed")  # remove the plant: green again

    def test_a_hash_that_is_not_a_lowercase_sha256_fails_even_when_every_copy_agrees(self):
        good = self.real("mips")
        self.pair(mips=good)
        plants = {"probe": (("elf", "sha256"), ("execution", "initramfs", "extra_files", "franken-speaker", "sha256")),
                  "supervisor": (("supervisor_elf", "sha256"), ("execution", "initramfs", "init_sha256")),
                  "kernel": (("execution", "kernel_sha256"), ("execution", "inputs_after_capture", "kernel")),
                  "initramfs": (("execution", "initramfs", "archive_sha256"), ("execution", "inputs_after_capture", "initramfs")),
                  "transcript": (("transcript_sha256",), ("execution", "stdout_sha256"))}
        for label, (first, second) in plants.items():
            for bad in ("A" * 64, "abc", "k" * 64, "0" * 63, ""):
                with self.subTest(label=label, bad=bad):
                    self.put("mips.json", self.planted(self.planted(good, first, bad), second, bad))
                    try:
                        self.assert_fails_naming("mips.json", "hash is missing or malformed" if label != "probe" and label != "supervisor" else "identity")
                    finally:
                        self.put("mips.json", good)
        self.assertEqual(self.case().status, "passed")

    def test_a_blocked_receipt_whose_gates_disagree_with_its_facts_fails(self):
        blocked_receipt = self.real("powerpc", wrapped(build(res=resources(VmRSS="UNKNOWN"), final=end(unknown=1)), "powerpc"))
        index = [g["gate_id"] for g in blocked_receipt["gates"]].index("X02-RESOURCES")
        self.pair(powerpc=blocked_receipt)
        self.assertEqual(self.case().status, "blocked")
        self.pair(powerpc=self.planted(blocked_receipt, ("gates", index, "status"), "passed"))
        self.assert_fails_naming("powerpc.json", "X02-RESOURCES is recorded passed but its facts judge blocked")

    def test_a_receipt_carrying_an_absolute_host_path_fails_by_name_and_never_repeats_it(self):
        good = self.real("mips")
        self.assertIn("rdinit=/init", json.dumps(good))  # a guest path that merely looks absolute is not a host path and stays
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")
        secret = "zebra-secret-user"
        plants = {
            "a command argument": (("execution", "command"), lambda c: c + ["-drive", f"file=/Users/{secret}/disk.img"]),
            "the supervisor path": (("execution", "initramfs", "init_path"), f"/private/tmp/claude-501/{secret}/sup"),
            "the archive path": (("execution", "initramfs", "out_path"), f"/var/folders/ab/{secret}/T/runtime.cpio.gz"),
            "the revision claim": (("revision_claim",), f"built in /home/{secret}/work"),
            "a gate detail": (("gates", 0, "detail"), f"see /tmp/{secret}/log"),
            "the scope text": (("scope",), f"measured at /Volumes/{secret}/x"),
            "a verdict fact": (("verdict", "phases", 0, "facts"), {"path": f"/root/{secret}"}),
            "a path_hashes label": (("path_hashes",), [{"path": f"/mnt/{secret}/x", "sha256": None}]),
            "a bare root": (("revision_claim",), "/tmp"), "a worker data mount": (("revision_claim",), f"/data/{secret}"),
            "a quoted path": (("revision_claim",), f"'/Users/{secret}'"), "an assignment": (("revision_claim",), f"root=/home/{secret}"),
        }
        for label, (path, value) in plants.items():
            with self.subTest(label=label):
                self.put("mips.json", self.planted(good, path, value))
                try:
                    result = self.case()
                    self.assertEqual(result.status, "failed", result.detail)
                    self.assertIn("mips.json", result.detail)
                    self.assertIn("absolute path under /", result.detail)
                    self.assertNotIn(secret, result.detail)  # the report says where, never the path itself
                finally:
                    self.put("mips.json", good)
        keyed = json.loads(json.dumps(good))
        keyed[f"/Users/{secret}/key"] = 1
        self.put("mips.json", keyed)
        self.assert_fails_naming("mips.json", "absolute path under /Users/ at the receipt.<key>")
        self.pair(mips=good, powerpc=self.planted(self.analysis("powerpc"), ("revision_claim",), f"/home/{secret}"))  # an analysis receipt is held to it too
        self.assert_fails_naming("powerpc.json", "absolute path under /home/")
        self.pair()
        self.assertEqual(self.case().status, "passed")  # remove the plants: green again

    def test_a_receipt_with_a_host_path_under_an_unlisted_root_or_a_relative_path_that_leaves_the_repository_fails_by_name_and_never_repeats_it(self):
        good = self.real("mips")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")
        secret = "zebra-secret-user"
        absolute = {"an opt tree": (("revision_claim",), f"/opt/{secret}/x"), "a nix path": (("revision_claim",), f"/nix/store/{secret}/bin/q"),
                    "a workspace": (("revision_claim",), f"built in /workspace/{secret}/tree"), "a build tree": (("scope",), f"measured at /builds/{secret}/x"),
                    "an unlisted root": (("revision_claim",), f"/zzz/{secret}/x"),
                    "a command argument": (("execution", "command"), lambda c: c + ["-drive", f"file=/lost-and-found/{secret}/disk.img"])}
        relative = {"a claim": (("revision_claim",), f"../../{secret}/x"), "a command argument": (("execution", "command"), lambda c: c + ["-kernel", f"../{secret}/vmlinux"]),
                    "a gate detail": (("gates", 0, "detail"), f"see ../{secret}/log")}
        for label, (path, value) in {**{f"abs {k}": v for k, v in absolute.items()}, **{f"rel {k}": v for k, v in relative.items()}}.items():
            with self.subTest(label=label):
                self.put("mips.json", self.planted(good, path, value))
                try:
                    result = self.case()
                    self.assertEqual(result.status, "failed", result.detail)
                    self.assertIn("mips.json", result.detail)
                    self.assertIn("relative path that leaves the repository" if label.startswith("rel ") else "absolute path under /", result.detail)
                    self.assertNotIn(secret, result.detail)  # the report says where, never the path itself
                finally:
                    self.put("mips.json", good)
        # Control: what is not a host path stays accepted: a system tool path, a guest path, and a relative path that stays under its directory.
        for text in ("/usr/bin/qemu-system-mips", "/proc/self/task and /dev/ttyS0", "src/../x and ./out/run/archive.cpio.gz", "a..b and wait..."):
            with self.subTest(text=text):
                self.pair(mips=self.planted(good, ("revision_claim",), text))
                self.assertEqual(self.case().status, "passed")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")  # remove the plants: green again

    def test_path_hashes_must_not_bind_one_name_to_two_different_hashes(self):
        good = self.real("mips")
        entries = [{"path": "<outside-repo>/blob", "sha256": "a" * 64}, {"path": "<outside-repo>/blob", "sha256": "b" * 64}]
        self.pair(mips=self.planted(good, ("path_hashes",), entries))
        self.assert_fails_naming("mips.json", "path_hashes binds one name to two different hashes")
        for label, entries in {"a hash and an absent file": [{"path": "<outside-repo>/blob", "sha256": "a" * 64}, {"path": "<outside-repo>/blob", "sha256": None}]}.items():
            with self.subTest(label=label):
                self.pair(mips=self.planted(good, ("path_hashes",), entries))
                self.assert_fails_naming("mips.json", "path_hashes binds one name to two different hashes")
        # Control: two names with two hashes, and one name with one hash, are accepted.
        self.pair(mips=self.planted(good, ("path_hashes",), [{"path": "<outside-repo>/blob", "sha256": "a" * 64}, {"path": "<outside-repo>/other", "sha256": "b" * 64}]))
        self.assertEqual(self.case().status, "passed")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")

    def test_path_hashes_must_be_relative_paths_with_a_lowercase_sha256_or_null(self):
        good = self.real("mips")
        self.assertTrue(good["path_hashes"])
        for label, value in {"not a list": {}, "an entry that is not an object": ["x"], "a missing sha256": [{"path": "a"}], "an extra key": [{"path": "a", "sha256": None, "x": 1}],
                             "uppercase sha256": [{"path": "a", "sha256": "A" * 64}], "short sha256": [{"path": "a", "sha256": "abc"}], "a numeric sha256": [{"path": "a", "sha256": 1}],
                             "an empty path": [{"path": "", "sha256": None}], "a parent segment": [{"path": "../a", "sha256": None}],
                             "a path that is not text": [{"path": 1, "sha256": None}]}.items():
            with self.subTest(label=label):
                self.pair(mips=self.planted(good, ("path_hashes",), value))
                self.assert_fails_naming("mips.json", "path_hashes is malformed")
        self.pair(mips=self.planted(good, ("path_hashes",), []))  # an empty list is fine: it only lists what was rewritten
        self.assertEqual(self.case().status, "passed")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")

    def test_declared_blocked_or_not_passed_must_agree_with_the_facts(self):
        good = self.real("mips")
        for result_word in ("blocked", "not_passed"):
            with self.subTest(declared=result_word):
                self.pair(mips=self.planted(good, ("result",), result_word))
                self.assert_fails_naming("mips.json")
        self.pair(mips=good)
        self.assertEqual(self.case().status, "passed")

    def test_the_runner_lists_x02_with_the_judged_wording_and_hashes_the_judge(self):
        self.assertEqual(rc.FULL_IDS[-1], "T01-X02-target-resources")
        self.assertIn("EACH legacy target", rc.DESCRIPTIONS["T01-X02-target-resources"])
        self.assertIn("tests/t01/x02_judge.py", rc.JUDGED_ARTIFACTS)  # the run's receipt records the sha256 of the judge it used


class ContractText(unittest.TestCase):
    """docs/contracts/t01.md describes X02 in the code's own words: the strings below are read from the code, so the contract cannot drift from it unnoticed."""

    def setUp(self):
        with open(os.path.join(REPO, "docs", "contracts", "t01.md"), encoding="utf-8") as handle:
            self.text = handle.read()

    def test_the_x02_block_names_what_exists(self):
        for needle in (J.GRAMMAR, J.RECEIPT_SCHEMA, J.OUTSIDE_REPO, "path_hashes", "scripts/e2e/t01 --x02 run|analyze", "tests/t01/x02_judge.py", "toolchain/src/t01-core-probe/",
                       "T01-X02-target-resources", "supplied_transcript_analysis", "captured_guest_execution", "**eight phases**", "known-answer module `kat.rs`",
                       "T01X02 PHASE <NAME> ok|fail <k=v ...>", "T01X02 VmHWM <uint>|UNKNOWN", "T01X02 END ok=<n> fail=<n> unknown=<n>", "each** legacy target (mips and powerpc)"):
            self.assertIn(needle, self.text)
        start = self.text.index("**eight phases**")  # CRYPTO_KAT is named earlier, in the acceptance table; the order that counts is the probe bullet's
        positions = [self.text.index(f"`{name}`", start) for name in J.EXPECTED_PHASES]
        self.assertEqual(positions, sorted(positions), "the contract lists the phases in the judge's order")

    def test_the_no_claims_are_the_codes_own_sentences_verbatim(self):
        self.assertIn(J.SCOPE, self.text)
        self.assertIn(rc.X02_BOUND, self.text)

    # Landing set (the two committed guest runs): the contract used to pin "nothing was run in a guest". It now records what ran, and these rules refuse a text that
    # went back to the old claim or lost the record. One function, so the planted negative runs the very same rules on a changed copy of the text.
    STALE = ("nothing in it is built or run by this contract", "This contract records no build and no run of it", "none of it has been run in a guest", "no crypto probe was run",
             "has not been made", "source and tests only, and no probe has been run in a guest", "T01-X02 is BLOCKED until a measurement receipt exists",
             "nothing built, nothing measured on a target")
    RECORDED = ("INCOMPLETE and pending", "**What ran**", "wire_bytes=348", "plant=caught", "END ok=8 fail=0 unknown=0", "toolchain/results/tailscale/measurements/",
                "T01 (`ffw-32a`) stays open", "not the Sonos 2.6.35 / 2.6.14 kernels", "no real board, no network, no peer", "not `tailscaled`, not the whole library",
                "not a tailnet client, and not the speaker's resource budget")

    @classmethod
    def contract_problems(cls, text):
        problems = [f"stale claim still present: {stale}" for stale in cls.STALE if stale in text]
        if "no probe has been run in a guest" in text.lower():
            problems.append("stale claim still present: no probe has been run in a guest")
        problems += [f"the record is missing: {needle}" for needle in cls.RECORDED if needle not in text]
        return problems

    def test_the_contract_records_what_ran_in_a_guest_and_no_longer_says_nothing_did(self):
        self.assertEqual(self.contract_problems(self.text), [])
        old_claim = self.text + "\nNo probe has been run in a guest.\n"                       # planted: the old sentence is back
        self.assertEqual(self.contract_problems(old_claim), ["stale claim still present: no probe has been run in a guest"])
        old_status = self.text + "\nStatus: nothing built, nothing measured on a target.\n"    # planted: the old status line is back
        self.assertEqual(self.contract_problems(old_status), ["stale claim still present: nothing built, nothing measured on a target"])
        lost = self.text.replace("wire_bytes=348", "wire_bytes=0", 1)                          # planted: the record lost a figure
        self.assertEqual(self.contract_problems(lost), ["the record is missing: wire_bytes=348"])
        no_claim = self.text.replace("no real board, no network, no peer", "a board", 1)       # planted: the no-claim paragraph lost its limits
        self.assertEqual(self.contract_problems(no_claim), ["the record is missing: no real board, no network, no peer"])
        self.assertEqual(self.contract_problems(self.text), [])                                # control: with the plants removed the real text passes again

    def test_the_judges_phase_table_equals_the_probe_source_when_the_source_is_present(self):
        source = os.path.join(REPO, "toolchain", "src", "t01-core-probe", "src", "main.rs")
        if not os.path.isfile(source):
            self.skipTest("the probe source is not in this tree")
        with open(source, encoding="utf-8") as handle:
            match = re.search(r"const PHASES: \[&str; (\d+)\] = \[(.*?)\];", handle.read(), re.S)
        self.assertIsNotNone(match, "main.rs no longer declares `const PHASES`")
        names = re.findall(r'"([A-Za-z0-9_]+)"', match[2])
        self.assertEqual(int(match[1]), len(names))
        self.assertEqual(tuple(names), J.EXPECTED_PHASES, "the judge's phase table must equal what the built probe prints")


if __name__ == "__main__":
    unittest.main()
