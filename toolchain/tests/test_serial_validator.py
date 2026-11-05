"""Independent E07 serial-evidence regressions; fixtures are not guest proof."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "src" / "run-qemu-verification.py"
SPEC = importlib.util.spec_from_file_location("ffw_serial_verifier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

HELLO = "FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32"
ENOSYS = "FFW_TEST:ERR_ENOSYS status=PASS errno=89"
MIPS_TRIPLE = "mips-unknown-linux-musl"
PPC_TRIPLE = "powerpc-unknown-linux-musl"
BUILD = "FFW_BUILD target=mips-unknown-linux-musl rustc=1.101.0-nightly rustc_commit=48f4b0553 linker_flavor=ld.lld libc=none runtime=no_std"
# Frozen protocol transcript, authored independently of parser patterns.
# This checks the parser only; it establishes no boot or hardware capability.
POSITIVE = """FFW_MARKER:USERSPACE_START
FFW_GUEST:CONSOLE_LEVEL status=PASS rc=0
FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32
FFW_BUILD target=mips-unknown-linux-musl rustc=1.101.0-nightly rustc_commit=48f4b0553 linker_flavor=ld.lld libc=none runtime=no_std
FFW_RUSTC release=1.101.0-nightly commit=48f4b05538b8eca412137042d9647a61e692c6b3 date=2026-10-23 host=aarch64-apple-darwin llvm=23.1.4
FFW_KERNEL_VERSION: Linux version 4.19.0-fixture
FFW_TEST:ERR_ENOENT status=PASS errno=2
FFW_TEST:ERR_EBADF status=PASS errno=9
FFW_TEST:ERR_ENOSYS status=PASS errno=89
FFW_TEST:POS_FD_SHORT_WRITE status=PASS fd=4
FFW_TEST:PARTIAL_WRITE status=PASS bytes=4096
FFW_PROBE:CLOCK_MONOTONIC status=PASS res_ns=1
FFW_PROBE:NONBLOCK_PIPE status=PASS rc=0
FFW_PROBE:POLL status=PASS rc=1
FFW_PROBE:EPOLL status=PASS fd=4
FFW_PROBE:SOCKET_UDP status=PASS fd=4
FFW_PROBE:ENTROPY status=PASS fd=4
FFW_PROBE:ATOMICS_32 status=PASS ok=1
FFW_PROBE:GETRANDOM status=PASS rc=16
FFW_PROBE:EVENTFD2 status=PASS fd=5
FFW_PROBE:TIMERFD status=PASS fd=6
FFW_PROBE:FUTEX status=PASS rc=0
FFW_PROBE:LOOPBACK_UP status=PASS rc=0
FFW_PROBE:UDP_LOOPBACK status=PASS rc=24
FFW_PROBE:ACCEPT4 status=PASS fd=8
FFW_PROBE:REACTOR_WAKE status=PASS rc=1
FFW_PROBE:CHARDEV_POLL status=PASS rc=2
FFW_PROBE:ATOMIC_WIDTH status=PASS bits=32
FFW_PROBE:ALLOC status=PASS rc=0
FFW_PROBE:MEM_PEAK status=PASS kb=312
FFW_PROBE:FS_RENAME status=PASS rc=0
FFW_PROBE:SIGNAL status=PASS rc=0
FFW_PROBE:TIMER_SIGNALS status=PASS rc=0
FFW_PROBE:EINTR_READ status=PASS rc=-4
FFW_PROBE:THREADS status=PASS tid=2
FFW_PROBE:TLS status=PASS tp=305419896
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
"""
PPC_HELLO = "FFW_HELLO arch=powerpc-be endian=0x01020304 pid=1 ptr_bits=32"
PPC_ENOSYS = "FFW_TEST:ERR_ENOSYS status=PASS errno=38"
# name -> (detail key, success value) exactly as POSITIVE spells them; each line is hand-written above.
OPTIONAL = {"GETRANDOM": ("rc", "16"), "EVENTFD2": ("fd", "5"), "TIMERFD": ("fd", "6"), "FUTEX": ("rc", "0"),
            "ACCEPT4": ("fd", "8"), "THREADS": ("tid", "2"), "TLS": ("tp", "305419896")}
# Runtime behaviors: exact PASS only (an ENOSYS line is as invalid as any other FAIL), spelled as POSITIVE spells them.
REQUIRED = {"LOOPBACK_UP": ("rc", "0"), "UDP_LOOPBACK": ("rc", "24"), "REACTOR_WAKE": ("rc", "1"),
            "CHARDEV_POLL": ("rc", "2"), "ATOMIC_WIDTH": ("bits", "32"), "ALLOC": ("rc", "0"),
            "MEM_PEAK": ("kb", "312"), "FS_RENAME": ("rc", "0"), "SIGNAL": ("rc", "0"),
            "TIMER_SIGNALS": ("rc", "0"), "EINTR_READ": ("rc", "-4")}
RUSTC = "FFW_RUSTC release=1.101.0-nightly commit=48f4b05538b8eca412137042d9647a61e692c6b3 date=2026-10-23 host=aarch64-apple-darwin llvm=23.1.4"


def elf32(machine, ptypes=(1,), big=True, elf_class=1):
    """Minimal ELF32 image (header plus one 32-byte program header per type) for the parser tests.
    It is never executed and says nothing about any boot."""
    order = "big" if big else "little"
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = elf_class, (2 if big else 1), 1
    header[16:18] = (2).to_bytes(2, order)            # ET_EXEC
    header[18:20] = machine.to_bytes(2, order)
    header[28:32] = (52).to_bytes(4, order)           # e_phoff
    header[40:42] = (52).to_bytes(2, order)           # e_ehsize
    header[42:44] = (32).to_bytes(2, order)           # e_phentsize
    header[44:46] = len(ptypes).to_bytes(2, order)    # e_phnum
    return bytes(header) + b"".join(t.to_bytes(4, order) + bytes(28) for t in ptypes)


class SerialEvidenceTests(unittest.TestCase):
    def verify(self, text, triple=MIPS_TRIPLE):
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, triple)

    def status(self, text):
        return self.verify(text)["status"]

    def test_complete_transcript_passes(self):
        self.assertEqual(self.status(POSITIVE), "PASS")

    def test_full_write_does_not_prove_partial_write(self):
        self.assertEqual(self.status(POSITIVE.replace("bytes=4096", "bytes=8192")), "FAIL")

    def test_zero_write_does_not_prove_partial_write(self):
        self.assertEqual(self.status(POSITIVE.replace("bytes=4096", "bytes=0")), "FAIL")

    def test_missing_probe_fails(self):
        text = POSITIVE.replace("FFW_PROBE:ENTROPY status=PASS fd=4\n", "")
        self.assertEqual(self.status(text), "FAIL")

    def test_kernel_panic_fails(self):
        self.assertEqual(self.status(POSITIVE + "Kernel panic - not syncing"), "FAIL")

    def test_conflicting_probe_after_success_fails(self):
        text = POSITIVE + "FFW_PROBE:ENTROPY status=FAIL errno=5\n"
        self.assertEqual(self.status(text), "FAIL")

    def test_nonzero_failure_count_is_not_zero_prefix(self):
        self.assertEqual(self.status(POSITIVE.replace("failures=0", "failures=01")), "FAIL")

    def test_errno_prefix_is_not_exact_errno(self):
        self.assertEqual(self.status(POSITIVE.replace("errno=89", "errno=890")), "FAIL")

    def test_echoed_transcript_is_not_userspace_output(self):
        text = "\n".join("echo " + line for line in POSITIVE.splitlines())
        self.assertEqual(self.status(text), "FAIL")

    def test_duplicate_boot_transcript_fails(self):
        self.assertEqual(self.status(POSITIVE + POSITIVE), "FAIL")

    def test_probe_after_success_fails(self):
        probe = "FFW_PROBE:ENTROPY status=PASS fd=4\n"
        self.assertEqual(self.status(POSITIVE.replace(probe, "") + probe), "FAIL")

    def test_truncated_reboot_marker_fails(self):
        text = POSITIVE.replace("FFW_MARKER:REBOOT_REQUEST", "FFW_MARKER:REBOOT_REQUE")
        self.assertEqual(self.status(text), "FAIL")


class ConsoleLevelTests(unittest.TestCase):
    """The guest raises the console log level before anything else, so a kernel printk cannot land inside a marker. On the
    first PowerPC smoke one did: `FFW_MARKER:TEST_SUCCESS fai[    3.303530] random: crng init done` and then `lures=0`. The
    parser stays strict (a lenient one could pass a marker the guest never wrote whole); these pin that strictness and the
    new line. Fixtures check the parser only: no guest ran and no kernel answered.
"""

    GOOD = "FFW_GUEST:CONSOLE_LEVEL status=PASS rc=0"

    def verify(self, text, ppc=False):
        if ppc:
            return VERIFIER.verify_serial_output("ppc", PPC_HELLO, PPC_ENOSYS, text, PPC_TRIPLE)
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, MIPS_TRIPLE)

    def test_the_green_baseline_carries_the_line_on_both_guests(self):
        self.assertIn(self.GOOD + "\n", POSITIVE)
        self.assertEqual(self.verify(POSITIVE)["status"], "PASS")
        self.assertEqual(self.verify(ppc_transcript(POSITIVE), ppc=True)["status"], "PASS")

    def test_the_exact_split_the_powerpc_guest_printed_is_refused(self):
        split = POSITIVE.replace(
            "FFW_MARKER:TEST_SUCCESS failures=0\n",
            "FFW_MARKER:TEST_SUCCESS fai[    3.303530] random: crng init done\nlures=0\n")
        self.assertNotEqual(split, POSITIVE, "the plant must change the fixture")
        result = self.verify(ppc_transcript(split), ppc=True)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("invalid:FFW_MARKER:TEST_SUCCESS", result["validation_errors"])

    def test_a_kernel_line_between_whole_lines_is_not_a_failure(self):
        between = POSITIVE.replace(
            "FFW_MARKER:TEST_SUCCESS failures=0\n",
            "[    3.303530] random: crng init done\nFFW_MARKER:TEST_SUCCESS failures=0\n")
        self.assertNotEqual(between, POSITIVE)
        self.assertEqual(self.verify(between)["status"], "PASS")

    def test_the_line_is_required(self):
        result = self.verify(POSITIVE.replace(self.GOOD + "\n", ""))
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_GUEST:CONSOLE_LEVEL", result["missing_markers"])

    def test_a_refused_call_is_named_by_what_the_kernel_answered(self):
        for rc in ("-1", "-38", "-89", "7", "0"):
            with self.subTest(rc=rc):
                result = self.verify(POSITIVE.replace(self.GOOD, f"FFW_GUEST:CONSOLE_LEVEL status=FAIL rc={rc}"))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(f"console_level_refused:status=FAIL rc={rc}", result["validation_errors"])

    def test_a_refusal_line_with_trailing_text_is_invalid_not_named(self):
        result = self.verify(POSITIVE.replace(self.GOOD, "FFW_GUEST:CONSOLE_LEVEL status=FAIL rc=-1 extra=1"))
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("invalid:FFW_GUEST:CONSOLE_LEVEL", result["validation_errors"])
        self.assertFalse(any(e.startswith("console_level_refused:") for e in result["validation_errors"]))

    def test_only_the_exact_pass_line_in_the_right_place_passes(self):
        bad = {
            "rc=1": POSITIVE.replace(self.GOOD, "FFW_GUEST:CONSOLE_LEVEL status=PASS rc=1"),
            "rc=00": POSITIVE.replace(self.GOOD, "FFW_GUEST:CONSOLE_LEVEL status=PASS rc=00"),
            "trailing text": POSITIVE.replace(self.GOOD, self.GOOD + " extra=1"),
            "another name": POSITIVE.replace(self.GOOD, self.GOOD.replace("CONSOLE_LEVEL", "CONSOLE_LEVELS")),
            "a probe prefix": POSITIVE.replace(self.GOOD, self.GOOD.replace("FFW_GUEST", "FFW_PROBE")),
            "duplicated": POSITIVE.replace(self.GOOD, self.GOOD + "\n" + self.GOOD),
            "before the start marker": POSITIVE.replace(self.GOOD + "\n", "").replace(
                "FFW_MARKER:USERSPACE_START\n", self.GOOD + "\nFFW_MARKER:USERSPACE_START\n"),
            "after the success marker": POSITIVE.replace(self.GOOD + "\n", "").replace(
                "FFW_MARKER:REBOOT_REQUEST", self.GOOD + "\nFFW_MARKER:REBOOT_REQUEST"),
        }
        for label, text in bad.items():
            with self.subTest(label):
                self.assertNotEqual(text, POSITIVE)
                self.assertEqual(self.verify(text)["status"], "FAIL")

    def test_the_setup_line_is_not_an_e03_probe(self):
        # It must not reach the capability matrix: the recorded probes are FFW_TEST and FFW_PROBE lines only.
        result = self.verify(POSITIVE)
        self.assertNotIn("FFW_GUEST:CONSOLE_LEVEL", result["probes"])
        self.assertEqual(set(VERIFIER.GUEST_SETUP), {"CONSOLE_LEVEL"})
        self.assertFalse(set(VERIFIER.GUEST_SETUP) & set(VERIFIER.REQUIRED_PROBES))


class BuildIdentityTests(unittest.TestCase):
    """The probe's FFW_BUILD line: positive record first, then each way it must be refused."""

    def verify(self, text, triple=MIPS_TRIPLE):
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, triple)

    def status(self, text):
        return self.verify(text)["status"]

    def test_positive_record_is_returned_field_by_field(self):
        result = self.verify(POSITIVE)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["build_identity"], {
            "target": MIPS_TRIPLE, "rustc": "1.101.0-nightly", "rustc_commit": "48f4b0553",
            "linker_flavor": "ld.lld", "libc": "none", "runtime": "no_std"})

    def test_missing_identity_fails_and_records_none(self):
        result = self.verify(POSITIVE.replace(BUILD + "\n", ""))
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_BUILD", result["missing_markers"])
        self.assertIsNone(result["build_identity"])

    def test_triple_of_another_target_is_refused(self):
        # A PowerPC-built probe cannot stand in for the MIPS run the runner believes it booted.
        self.assertEqual(self.verify(POSITIVE, triple=PPC_TRIPLE)["status"], "FAIL")
        self.assertEqual(self.verify(POSITIVE.replace(MIPS_TRIPLE, PPC_TRIPLE), triple=PPC_TRIPLE)["status"], "PASS")

    def test_triple_is_matched_exactly_not_by_prefix(self):
        self.assertEqual(self.status(POSITIVE.replace("target=mips-unknown-linux-musl ", "target=mips-unknown-linux-musl2 ")), "FAIL")

    def test_a_libc_other_than_none_is_refused(self):
        self.assertEqual(self.status(POSITIVE.replace("libc=none", "libc=musl")), "FAIL")

    def test_unreadable_compiler_or_flavor_is_not_an_identity(self):
        for old, new in (("rustc=1.101.0-nightly", "rustc=unknown"),
                         ("rustc_commit=48f4b0553", "rustc_commit=unknown"),
                         ("linker_flavor=ld.lld", "linker_flavor=unspecified")):
            with self.subTest(new=new):
                result = self.verify(POSITIVE.replace(old, new))
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(any(e.startswith("unidentified:") for e in result["validation_errors"]))

    def test_duplicate_or_truncated_identity_fails(self):
        self.assertEqual(self.status(POSITIVE.replace(BUILD, BUILD + "\n" + BUILD)), "FAIL")
        self.assertEqual(self.status(POSITIVE.replace("runtime=no_std", "runtime=no_")), "FAIL")

    def test_identity_after_success_marker_fails(self):
        moved = POSITIVE.replace(BUILD + "\n", "").replace("FFW_MARKER:REBOOT_REQUEST", BUILD + "\nFFW_MARKER:REBOOT_REQUEST")
        self.assertEqual(self.status(moved), "FAIL")

    def test_identity_with_extra_fields_or_spaces_is_refused(self):
        self.assertEqual(self.status(POSITIVE.replace("runtime=no_std", "runtime=no_std extra=1")), "FAIL")
        self.assertEqual(self.status(POSITIVE.replace("rustc=1.101.0-nightly", "rustc=1.101.0 nightly")), "FAIL")


def good_line(name):
    key, value = OPTIONAL[name]
    return f"FFW_PROBE:{name} status=PASS {key}={value}"


def swap(name, new_line, text=POSITIVE):
    """Replace one optional probe line. The line must be present, so a mutation can never be a no-op."""
    old = good_line(name)
    assert old + "\n" in text, f"fixture lost {old!r}"
    return text.replace(old, new_line)


def ppc_transcript(text):
    return (text.replace(HELLO, PPC_HELLO).replace(ENOSYS, PPC_ENOSYS)
            .replace("target=mips-unknown-linux-musl", "target=powerpc-unknown-linux-musl"))


class OptionalProbeTests(unittest.TestCase):
    """GETRANDOM, EVENTFD2, TIMERFD and FUTEX: a pass, an explicit -ENOSYS, and every way a line must be refused.
    Fixtures check the parser only; no probe ran and no kernel behavior is shown by this class."""

    def verify(self, text):
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, MIPS_TRIPLE)

    def verify_ppc(self, text):
        return VERIFIER.verify_serial_output("ppc", PPC_HELLO, PPC_ENOSYS, text, PPC_TRIPLE)

    def test_fixture_and_verifier_name_the_same_probes(self):
        # Guards drift: a probe added to the verifier but not to the fixture (or the reverse) fails here.
        self.assertEqual(set(OPTIONAL), set(VERIFIER.OPTIONAL_PROBES))
        for name in OPTIONAL:
            self.assertIn(good_line(name) + "\n", POSITIVE)

    def test_green_baseline_precedes_every_mutation(self):
        self.assertEqual(self.verify(POSITIVE)["status"], "PASS")
        self.assertEqual(self.verify_ppc(ppc_transcript(POSITIVE))["status"], "PASS")

    def test_supported_probes_are_recorded_supported_with_nothing_unsupported(self):
        result = self.verify(POSITIVE)
        self.assertEqual(result["unsupported_capabilities"], [])
        for name in OPTIONAL:
            record = result["probes"][f"FFW_PROBE:{name}"]
            self.assertEqual((record["status"], record["capability"]), ("PASS", "supported"), name)

    def test_explicit_enosys_is_well_formed_and_recorded_as_unsupported_not_pass(self):
        for name, (key, _) in OPTIONAL.items():
            with self.subTest(name=name):
                result = self.verify(swap(name, f"FFW_PROBE:{name} status=FAIL {key}=-89"))
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["validation_errors"], [])
                record = result["probes"][f"FFW_PROBE:{name}"]
                # The receipt must not call the guest's own FAIL a PASS.
                self.assertEqual((record["status"], record["capability"]), ("FAIL", "unsupported"))
                self.assertEqual(result["unsupported_capabilities"], [name])

    def test_all_four_absent_at_once_are_all_listed(self):
        text = POSITIVE
        for name, (key, _) in OPTIONAL.items():
            text = swap(name, f"FFW_PROBE:{name} status=FAIL {key}=-89", text)
        result = self.verify(text)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["unsupported_capabilities"], sorted(OPTIONAL))

    def test_a_probe_that_did_not_run_is_missing_not_unsupported(self):
        for name in OPTIONAL:
            with self.subTest(name=name):
                result = self.verify(POSITIVE.replace(good_line(name) + "\n", ""))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(f"FFW_PROBE:{name}", result["missing_markers"])
                self.assertEqual(result["unsupported_capabilities"], [])

    def test_any_failure_that_is_not_enosys_is_refused(self):
        # Another errno, the other ABI's ENOSYS, an ENOSYS-prefixed number, a zero or a success value
        # under FAIL: the call exists or is unproven, so it is never an explicit capability failure.
        for name, (key, value) in OPTIONAL.items():
            for bad in ("-11", "-38", "-890", "-22", "-8", "0", value):
                with self.subTest(name=name, bad=bad):
                    result = self.verify(swap(name, f"FFW_PROBE:{name} status=FAIL {key}={bad}"))
                    self.assertEqual(result["status"], "FAIL")
                    self.assertIn(f"invalid:FFW_PROBE:{name}", result["validation_errors"])

    def test_pass_needs_the_exact_success_value_and_key(self):
        bad_lines = {
            "GETRANDOM": ["status=PASS rc=15", "status=PASS rc=160", "status=PASS rc=-16", "status=PASS fd=16"],
            "EVENTFD2": ["status=PASS fd=0", "status=PASS fd=-5", "status=PASS fd=05", "status=PASS rc=5"],
            "TIMERFD": ["status=PASS fd=0", "status=PASS fd=-6", "status=PASS fd=06", "status=PASS rc=6"],
            "FUTEX": ["status=PASS rc=1", "status=PASS rc=00", "status=PASS rc=-1", "status=PASS fd=0"],
            "ACCEPT4": ["status=PASS fd=0", "status=PASS fd=-8", "status=PASS fd=08", "status=PASS rc=8"],
            "THREADS": ["status=PASS tid=0", "status=PASS tid=-2", "status=PASS tid=02", "status=PASS rc=2"],
            "TLS": ["status=PASS tp=0", "status=PASS tp=305419897", "status=PASS tp=0x12345678", "status=PASS rc=305419896"],
        }
        self.assertEqual(set(bad_lines), set(OPTIONAL))
        for name, tails in bad_lines.items():
            for tail in tails:
                with self.subTest(name=name, tail=tail):
                    result = self.verify(swap(name, f"FFW_PROBE:{name} {tail}"))
                    self.assertEqual(result["status"], "FAIL")
                    self.assertIn(f"invalid:FFW_PROBE:{name}", result["validation_errors"])

    def test_trailing_text_or_extra_fields_are_refused(self):
        self.assertEqual(self.verify(swap("GETRANDOM", "FFW_PROBE:GETRANDOM status=PASS rc=16 extra=1"))["status"], "FAIL")
        self.assertEqual(self.verify(swap("FUTEX", "FFW_PROBE:FUTEX status=FAIL rc=-89x"))["status"], "FAIL")

    def test_enosys_number_is_the_guests_own_abi(self):
        ppc = ppc_transcript(POSITIVE)
        # PowerPC's ENOSYS is 38: accepted there, and MIPS's 89 is refused there ...
        accepted = self.verify_ppc(ppc.replace(good_line("EVENTFD2"), "FFW_PROBE:EVENTFD2 status=FAIL fd=-38"))
        self.assertEqual((accepted["status"], accepted["unsupported_capabilities"]), ("PASS", ["EVENTFD2"]))
        refused = self.verify_ppc(ppc.replace(good_line("EVENTFD2"), "FFW_PROBE:EVENTFD2 status=FAIL fd=-89"))
        self.assertEqual(refused["status"], "FAIL")
        # ... and the reverse on MIPS.
        self.assertEqual(self.verify(swap("EVENTFD2", "FFW_PROBE:EVENTFD2 status=FAIL fd=-38"))["status"], "FAIL")

    def test_duplicate_or_late_probe_line_fails(self):
        for name in OPTIONAL:
            with self.subTest(name=name):
                line = good_line(name) + "\n"
                self.assertEqual(self.verify(POSITIVE.replace(line, line + line))["status"], "FAIL")
                late = POSITIVE.replace(line, "").replace("FFW_MARKER:REBOOT_REQUEST", line + "FFW_MARKER:REBOOT_REQUEST")
                self.assertEqual(self.verify(late)["status"], "FAIL")

    def test_guest_reported_failure_marker_still_fails_the_transcript(self):
        # An ambiguous probe makes the guest print TEST_FAILURE instead of TEST_SUCCESS.
        text = swap("EVENTFD2", "FFW_PROBE:EVENTFD2 status=FAIL fd=5").replace(
            "FFW_MARKER:TEST_SUCCESS failures=0", "FFW_MARKER:TEST_FAILURE failures=1")
        result = self.verify(text)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_MARKER:TEST_FAILURE", result["forbidden_hits"])

    def test_an_unreadable_enosys_expectation_fails_closed(self):
        for broken in ("FFW_TEST:ERR_ENOSYS status=PASS errno=0x59", "FFW_TEST:ERR_ENOSYS status=PASS errno=0",
                       "FFW_TEST:ERR_ENOSYS status=PASS errno=089", "FFW_TEST:ERR_ENOSYS status=PASS errno=89 "):
            with self.subTest(broken=broken):
                with self.assertRaises(ValueError):
                    VERIFIER.verify_serial_output("mips", HELLO, broken, POSITIVE, MIPS_TRIPLE)


class UnseededProbeTests(unittest.TestCase):
    """GETRANDOM alone may report `UNSEEDED rc=-11`: the call exists (a bad flag gave exactly -EINVAL) but the kernel's
    entropy pool is not yet seeded when PID 1 runs. It is not a pass, not an absence and not a misbehaving call.
    Fixtures check the parser only; no probe ran."""

    LINE = "FFW_PROBE:GETRANDOM status=UNSEEDED rc=-11"

    def verify(self, text, ppc=False):
        if ppc:
            return VERIFIER.verify_serial_output("ppc", PPC_HELLO, PPC_ENOSYS, text, PPC_TRIPLE)
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, MIPS_TRIPLE)

    def test_the_unseeded_line_passes_the_transcript_as_its_own_state(self):
        result = self.verify(swap("GETRANDOM", self.LINE))
        self.assertEqual((result["status"], result["validation_errors"]), ("PASS", []))
        record = result["probes"]["FFW_PROBE:GETRANDOM"]
        # The guest's own token is kept: it is neither PASS (no entropy was obtained) nor FAIL (the call exists).
        self.assertEqual((record["status"], record["capability"]), ("UNSEEDED", "unseeded"))
        self.assertEqual(result["unseeded_capabilities"], ["GETRANDOM"])
        self.assertEqual(result["unsupported_capabilities"], [])             # present, never filed as an absence

    def test_unseeded_is_accepted_on_both_abis_because_eagain_is_11_on_both(self):
        ppc = ppc_transcript(swap("GETRANDOM", self.LINE))
        self.assertEqual(self.verify(ppc, ppc=True)["status"], "PASS")
        self.assertEqual(self.verify(ppc_transcript(POSITIVE), ppc=True)["unseeded_capabilities"], [])

    def test_a_seeded_or_absent_getrandom_is_not_reported_unseeded(self):
        self.assertEqual(self.verify(POSITIVE)["unseeded_capabilities"], [])
        absent = self.verify(swap("GETRANDOM", "FFW_PROBE:GETRANDOM status=FAIL rc=-89"))
        self.assertEqual((absent["unseeded_capabilities"], absent["unsupported_capabilities"]), ([], ["GETRANDOM"]))

    def test_no_other_probe_may_report_unseeded(self):
        names = [n for n in OPTIONAL if n != "GETRANDOM"] + list(REQUIRED)
        for name in names:
            with self.subTest(name=name):
                old = good_line(name) if name in OPTIONAL else required_line(name)
                key = (OPTIONAL.get(name) or REQUIRED[name])[0]
                result = self.verify(POSITIVE.replace(old, f"FFW_PROBE:{name} status=UNSEEDED {key}=-11"))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(f"invalid:FFW_PROBE:{name}", result["validation_errors"])
                self.assertEqual(result["unseeded_capabilities"], [])

    def test_the_unseeded_value_and_key_are_exact(self):
        for tail in ("rc=-12", "rc=11", "rc=0", "rc=16", "rc=-89", "rc=-110", "rc=-011", "fd=-11", "rc=-11 extra=1",
                     "rc=-11x"):
            with self.subTest(tail=tail):
                result = self.verify(swap("GETRANDOM", f"FFW_PROBE:GETRANDOM status=UNSEEDED {tail}"))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("invalid:FFW_PROBE:GETRANDOM", result["validation_errors"])
                self.assertEqual(result["unseeded_capabilities"], [])

    def test_the_status_token_is_matched_exactly(self):
        for token in ("unseeded", "UNSEEDED2", "UNSEED", "SEEDED"):
            with self.subTest(token=token):
                result = self.verify(swap("GETRANDOM", f"FFW_PROBE:GETRANDOM status={token} rc=-11"))
                self.assertEqual(result["status"], "FAIL")

    def test_a_duplicate_unseeded_line_fails(self):
        self.assertEqual(self.verify(swap("GETRANDOM", self.LINE + "\n" + self.LINE))["status"], "FAIL")


def required_line(name):
    key, value = REQUIRED[name]
    return f"FFW_PROBE:{name} status=PASS {key}={value}"


class RequiredProbeTests(unittest.TestCase):
    """Runtime behaviors that cannot legitimately be absent on the 4.9/4.19 harness kernels: the exact PASS line or
    the guest fails. Fixtures check the parser only; no probe ran and no kernel behavior is shown here."""

    def verify(self, text, ppc=False):
        if ppc:
            return VERIFIER.verify_serial_output("ppc", PPC_HELLO, PPC_ENOSYS, text, PPC_TRIPLE)
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, MIPS_TRIPLE)

    def test_fixture_and_verifier_name_the_same_required_probes(self):
        self.assertEqual(set(REQUIRED), set(VERIFIER.REQUIRED_PROBES))
        self.assertFalse(set(REQUIRED) & set(VERIFIER.OPTIONAL_PROBES))        # a probe is one or the other
        for name in REQUIRED:
            self.assertIn(required_line(name) + "\n", POSITIVE)

    def test_every_exact_pass_line_is_accepted_on_both_abis(self):
        self.assertEqual(self.verify(POSITIVE)["status"], "PASS")
        self.assertEqual(self.verify(ppc_transcript(POSITIVE), ppc=True)["status"], "PASS")

    def test_an_enosys_line_is_refused_here_though_the_optional_probes_accept_it(self):
        # The contrast that defines the class: -ENOSYS is a classified absence for getrandom or futex, but for a
        # signal, an allocator or a rename it is a defect on these kernels.
        for name, (key, _) in REQUIRED.items():
            for ppc, enosys in ((False, 89), (True, 38)):
                with self.subTest(name=name, enosys=enosys):
                    text = ppc_transcript(POSITIVE) if ppc else POSITIVE
                    result = self.verify(text.replace(required_line(name), f"FFW_PROBE:{name} status=FAIL {key}=-{enosys}"), ppc)
                    self.assertEqual(result["status"], "FAIL")
                    self.assertIn(f"invalid:FFW_PROBE:{name}", result["validation_errors"])
                    self.assertEqual(result["unsupported_capabilities"], [])    # never filed as a classified absence
        accepted = self.verify(POSITIVE.replace(good_line("FUTEX"), "FFW_PROBE:FUTEX status=FAIL rc=-89"))
        self.assertEqual((accepted["status"], accepted["unsupported_capabilities"]), ("PASS", ["FUTEX"]))

    def test_wrong_values_wrong_keys_and_any_fail_are_refused(self):
        bad_tails = {
            "LOOPBACK_UP": ["status=PASS rc=1", "status=PASS rc=-1", "status=PASS fd=0"],
            "UDP_LOOPBACK": ["status=PASS rc=16", "status=PASS rc=240", "status=PASS rc=024", "status=PASS bytes=24"],
            "REACTOR_WAKE": ["status=PASS rc=0", "status=PASS rc=2", "status=PASS rc=01"],
            "CHARDEV_POLL": ["status=PASS rc=1", "status=PASS rc=3", "status=PASS rc=02"],
            "ATOMIC_WIDTH": ["status=PASS bits=64", "status=PASS bits=16", "status=PASS bits=032", "status=PASS rc=32"],
            "ALLOC": ["status=PASS rc=1", "status=PASS rc=-12", "status=PASS rc=00"],
            "MEM_PEAK": ["status=PASS kb=0", "status=PASS kb=-2", "status=PASS kb=0312", "status=FAIL kb=-2"],
            "FS_RENAME": ["status=PASS rc=1", "status=FAIL rc=-5", "status=PASS rc=-5"],
            "SIGNAL": ["status=PASS rc=1", "status=FAIL rc=-22"],
            "TIMER_SIGNALS": ["status=PASS rc=2", "status=FAIL rc=-4"],
            "EINTR_READ": ["status=PASS rc=0", "status=PASS rc=4", "status=PASS rc=-04", "status=PASS rc=-40",
                           "status=FAIL rc=-4"],
        }
        self.assertEqual(set(bad_tails), set(REQUIRED))
        for name, tails in bad_tails.items():
            for tail in tails:
                with self.subTest(name=name, tail=tail):
                    result = self.verify(POSITIVE.replace(required_line(name), f"FFW_PROBE:{name} {tail}"))
                    self.assertEqual(result["status"], "FAIL")
                    self.assertIn(f"invalid:FFW_PROBE:{name}", result["validation_errors"])

    def test_a_required_probe_that_did_not_run_fails(self):
        for name in REQUIRED:
            with self.subTest(name=name):
                result = self.verify(POSITIVE.replace(required_line(name) + "\n", ""))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(f"FFW_PROBE:{name}", result["missing_markers"])

    def test_a_duplicate_or_late_required_line_fails(self):
        for name in REQUIRED:
            with self.subTest(name=name):
                line = required_line(name) + "\n"
                self.assertEqual(self.verify(POSITIVE.replace(line, line + line))["status"], "FAIL")
                late = POSITIVE.replace(line, "").replace("FFW_MARKER:REBOOT_REQUEST", line + "FFW_MARKER:REBOOT_REQUEST")
                self.assertEqual(self.verify(late)["status"], "FAIL")


class RustcIdentityTests(unittest.TestCase):
    """E07: `rustc -vV` as seen by the compiler that built the booted bytes, recorded as observed provenance."""

    def verify(self, text):
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text, MIPS_TRIPLE)

    def test_positive_record_is_returned_field_by_field(self):
        result = self.verify(POSITIVE)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["rustc_identity"], {
            "release": "1.101.0-nightly", "commit_hash": "48f4b05538b8eca412137042d9647a61e692c6b3",
            "commit_date": "2026-10-23", "host": "aarch64-apple-darwin", "llvm": "23.1.4"})

    def test_a_missing_line_fails_and_records_none(self):
        result = self.verify(POSITIVE.replace(RUSTC + "\n", ""))
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("FFW_RUSTC", result["missing_markers"])
        self.assertIsNone(result["rustc_identity"])

    def test_each_malformed_field_is_refused(self):
        full = "48f4b05538b8eca412137042d9647a61e692c6b3"
        for old, new in ((full, full[:39]), (full, full.upper()), (full, full + "0"), ("date=2026-10-23", "date=26-10-23"),
                         ("date=2026-10-23", "date=2026-10-2x"), (" llvm=23.1.4", ""), (" host=aarch64-apple-darwin", ""),
                         ("llvm=23.1.4", "llvm=23.1.4 extra=1")):
            with self.subTest(new=new):
                result = self.verify(POSITIVE.replace(old, new, 1) if old != full else POSITIVE.replace(old, new))
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("invalid:FFW_RUSTC", result["validation_errors"])

    def test_an_unreadable_release_host_or_llvm_is_not_an_identity(self):
        for old, new in (("release=1.101.0-nightly", "release=unknown"), ("host=aarch64-apple-darwin", "host=unknown"),
                         ("llvm=23.1.4", "llvm=unknown")):
            with self.subTest(new=new):
                result = self.verify(POSITIVE.replace(old, new))
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(any(e.startswith("unidentified:FFW_RUSTC") for e in result["validation_errors"]))

    def test_the_two_compiler_reports_must_describe_the_same_compiler(self):
        # FFW_BUILD says 1.101.0-nightly / 48f4b0553; a FFW_RUSTC that disagrees on either is a different compiler.
        # Mutate the FFW_RUSTC line only: "commit=48f4b0553" also occurs inside FFW_BUILD's rustc_commit=48f4b0553.
        other_release = POSITIVE.replace(RUSTC, RUSTC.replace("release=1.101.0-nightly", "release=1.102.0-nightly"))
        other_commit = POSITIVE.replace(RUSTC, RUSTC.replace("commit=48f4b0553", "commit=0000b0553"))
        for label, text in (("release", other_release), ("commit", other_commit)):
            with self.subTest(label=label):
                self.assertNotEqual(text, POSITIVE)                            # the mutation really applied
                self.assertIn("rustc_commit=48f4b0553", text)                  # and left FFW_BUILD alone
                result = self.verify(text)
                self.assertEqual(result["status"], "FAIL")
                self.assertIn("inconsistent:FFW_BUILD_vs_FFW_RUSTC", result["validation_errors"])

    def test_a_duplicate_line_fails(self):
        self.assertEqual(self.verify(POSITIVE.replace(RUSTC, RUSTC + "\n" + RUSTC))["status"], "FAIL")


class StaticElfTests(unittest.TestCase):
    """The ELF facts that back `libc=none`. Fixtures are byte strings; none is executed."""

    def inspect(self, data, arch="mips"):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "bin"
            path.write_bytes(data)
            return VERIFIER.inspect_static_elf(path, arch)

    def test_static_big_endian_mips_is_accepted(self):
        result = self.inspect(elf32(8, ptypes=(1, 1)))
        self.assertEqual(result["problems"], [])
        self.assertTrue(result["static"])
        self.assertTrue(result["machine_matches_arch"])

    def test_static_big_endian_powerpc_is_accepted(self):
        self.assertEqual(self.inspect(elf32(20), arch="ppc")["problems"], [])

    def test_interpreter_is_refused(self):
        result = self.inspect(elf32(8, ptypes=(3, 1)))
        self.assertTrue(result["has_interp"])
        self.assertIn("dynamic_or_interpreted", result["problems"])

    def test_dynamic_section_is_refused(self):
        result = self.inspect(elf32(8, ptypes=(1, 2)))
        self.assertTrue(result["has_dynamic"])
        self.assertIn("dynamic_or_interpreted", result["problems"])

    def test_wrong_machine_is_refused(self):
        self.assertIn("machine_does_not_match_arch", self.inspect(elf32(20), arch="mips")["problems"])
        self.assertIn("machine_does_not_match_arch", self.inspect(elf32(8), arch="ppc")["problems"])

    def test_non_elf_little_endian_and_64_bit_are_refused(self):
        self.assertIn("not_elf", self.inspect(b"synthetic-not-an-elf" * 4)["problems"])
        self.assertIn("not_elf", self.inspect(b"\x7fELF")["problems"])
        self.assertIn("not_elf32_big_endian", self.inspect(elf32(8, big=False))["problems"])
        self.assertIn("not_elf32_big_endian", self.inspect(elf32(8, elf_class=2))["problems"])

    def test_program_headers_beyond_the_file_are_refused(self):
        self.assertIn("program_headers_unreadable", self.inspect(elf32(8, ptypes=(1,))[:60])["problems"])


class ConfiguredLinkerTests(unittest.TestCase):
    CRATE = SCRIPT.parent / "ffw-hello-init"

    def test_committed_config_names_rust_lld_for_both_targets(self):
        for triple in (MIPS_TRIPLE, PPC_TRIPLE):
            with self.subTest(triple=triple):
                record = VERIFIER.configured_linker(self.CRATE, triple)
                self.assertEqual((record["linker"], record["flavor"]), ("rust-lld", "ld.lld"))
                self.assertFalse(record["attested"])

    def test_unknown_triple_or_missing_config_is_reported_not_guessed(self):
        unknown = VERIFIER.configured_linker(self.CRATE, "sparc-unknown-linux-musl")
        self.assertEqual((unknown["linker"], unknown["flavor"], unknown["error"]), (None, None, "KeyError"))
        with tempfile.TemporaryDirectory() as scratch:
            missing = VERIFIER.configured_linker(Path(scratch), MIPS_TRIPLE)
        self.assertEqual((missing["linker"], missing["error"]), (None, "FileNotFoundError"))


class BuildManifestTests(unittest.TestCase):
    """E07: the receipt pins what produced the binary, not just the binary."""

    CRATE = SCRIPT.parent / "ffw-hello-init"

    def copy_crate(self, scratch):
        dest = Path(scratch) / "crate"
        shutil.copytree(self.CRATE, dest, ignore=shutil.ignore_patterns("target", "__pycache__"))
        return dest

    def test_digests_cover_manifest_lockfile_config_build_script_and_every_source(self):
        digests = VERIFIER.source_digests(self.CRATE)
        for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", "build.rs", "src/main.rs", "src/lib.rs"):
            self.assertRegex(digests[name] or "", r"^[0-9a-f]{64}$", name)
        self.assertEqual(digests, VERIFIER.source_digests(self.CRATE))                 # deterministic
        # None omitted, listed by a walk that shares no code with the implementation (the earlier check used the
        # same shallow glob as the code it tested, so it could not see a subdirectory module).
        on_disk = sorted(
            os.path.relpath(os.path.join(root, name), self.CRATE).replace(os.sep, "/")
            for root, _dirs, files in os.walk(self.CRATE / "src") for name in files)
        self.assertEqual(sorted(k for k in digests if k.startswith("src/")), on_disk)
        for nested in ("src/e03_probes/net.rs", "src/e03_judge/net.rs"):      # the two the first central run missed
            self.assertRegex(digests.get(nested) or "", r"^[0-9a-f]{64}$", nested)

    def test_a_change_in_a_subdirectory_module_changes_the_digest_set(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.copy_crate(scratch)
            before = VERIFIER.source_digests(crate)
            net = crate / "src" / "e03_probes" / "net.rs"
            net.write_bytes(net.read_bytes() + b"\n// one more byte\n")
            after = VERIFIER.source_digests(crate)
        self.assertEqual([k for k in before if before[k] != after[k]], ["src/e03_probes/net.rs"])
        self.assertEqual(set(before), set(after))

    def test_files_added_at_any_depth_or_of_any_kind_enter_the_digest_set(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.copy_crate(scratch)
            before = VERIFIER.source_digests(crate)
            deep = crate / "src" / "a" / "b"
            deep.mkdir(parents=True)
            (deep / "c.rs").write_text("// nested\n")
            (crate / "src" / "table.bin").write_bytes(b"\x00\x01")                 # include_bytes! can name any file
            after = VERIFIER.source_digests(crate)
            (deep / "c.rs").unlink()
            removed = VERIFIER.source_digests(crate)
        self.assertEqual(sorted(set(after) - set(before)), ["src/a/b/c.rs", "src/table.bin"])
        self.assertEqual(set(before) - set(after), set())
        self.assertEqual(sorted(set(after) - set(removed)), ["src/a/b/c.rs"])      # deleting one shrinks the set again

    def test_a_symlinked_source_directory_is_refused_not_skipped(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.copy_crate(scratch)
            target = Path(scratch) / "elsewhere"
            target.mkdir()
            (target / "hidden.rs").write_text("// would be compiled but never digested\n")
            try:
                os.symlink(target, crate / "src" / "linked", target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("this filesystem cannot create symlinks")
            with self.assertRaisesRegex(ValueError, "symlinked directory"):
                VERIFIER.source_digests(crate)

    def test_the_listing_is_sorted_and_relative_so_two_machines_agree(self):
        keys = [k for k in VERIFIER.source_digests(self.CRATE) if k.startswith("src/")]
        self.assertEqual(keys, sorted(keys))
        self.assertFalse(any(k.startswith("/") or ".." in k.split("/") or "\\" in k for k in keys))

    def minimal_crate(self, scratch):
        """The smallest crate with a module in a subdirectory: src/a.rs and src/sub/b.rs, nothing else."""
        crate = Path(scratch) / "tiny"
        (crate / "src" / "sub").mkdir(parents=True)
        (crate / "src" / "a.rs").write_bytes(b"// a\n")
        (crate / "src" / "sub" / "b.rs").write_bytes(b"// b\n")
        return crate

    def test_a_minimal_crate_yields_a_key_for_the_top_level_and_the_nested_module(self):
        with tempfile.TemporaryDirectory() as scratch:
            digests = VERIFIER.source_digests(self.minimal_crate(scratch))
        self.assertEqual([k for k in digests if k.startswith("src/")], ["src/a.rs", "src/sub/b.rs"])
        # The values are checked against hashlib directly, not against the runner's own helper.
        self.assertEqual(digests["src/a.rs"], hashlib.sha256(b"// a\n").hexdigest())
        self.assertEqual(digests["src/sub/b.rs"], hashlib.sha256(b"// b\n").hexdigest())

    def test_changing_only_the_nested_module_changes_only_its_digest(self):
        # The planted negative: a shallow `src/*.rs` listing never sees this edit, so before == after there.
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.minimal_crate(scratch)
            before = VERIFIER.source_digests(crate)
            (crate / "src" / "sub" / "b.rs").write_bytes(b"// b, changed\n")
            after = VERIFIER.source_digests(crate)
        self.assertNotEqual(before, after)
        self.assertEqual(set(before), set(after))
        self.assertEqual([k for k in before if before[k] != after[k]], ["src/sub/b.rs"])

    def test_the_same_bytes_at_a_different_path_is_a_different_digest_set(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.minimal_crate(scratch)
            before = VERIFIER.source_digests(crate)
            (crate / "src" / "sub" / "b.rs").rename(crate / "src" / "sub" / "c.rs")
            after = VERIFIER.source_digests(crate)
        self.assertEqual(before["src/sub/b.rs"], after["src/sub/c.rs"])
        self.assertNotIn("src/sub/b.rs", after)
        self.assertNotEqual(before, after)

    def test_an_unreadable_source_directory_is_an_error_not_a_gap(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can read any directory")
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.minimal_crate(scratch)
            sub = crate / "src" / "sub"
            os.chmod(sub, 0)
            try:
                try:
                    os.listdir(sub)
                except PermissionError:
                    pass
                else:
                    self.skipTest("this filesystem does not enforce directory permissions")
                # `os.walk` alone would skip the directory and return only src/a.rs.
                with self.assertRaises(PermissionError):
                    VERIFIER.source_digests(crate)
            finally:
                os.chmod(sub, 0o755)                       # so the scratch directory can be cleaned up

    def test_a_crate_with_no_src_directory_has_an_empty_source_set(self):
        with tempfile.TemporaryDirectory() as scratch:
            digests = VERIFIER.source_digests(Path(scratch))
        self.assertEqual([k for k in digests if k.startswith("src/")], [])
        self.assertEqual(sorted(digests), sorted(VERIFIER.MANIFEST_FILES))

    def test_a_changed_file_changes_exactly_its_own_digest(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = self.copy_crate(scratch)
            before = VERIFIER.source_digests(crate)
            self.assertEqual(before, VERIFIER.source_digests(self.CRATE))              # the copy is faithful
            main = crate / "src" / "main.rs"
            main.write_bytes(main.read_bytes() + b"\n// one more byte\n")
            after = VERIFIER.source_digests(crate)
        self.assertEqual([k for k in before if before[k] != after[k]], ["src/main.rs"])

    def test_a_missing_file_is_recorded_as_none_not_omitted(self):
        with tempfile.TemporaryDirectory() as scratch:
            crate = Path(scratch)
            (crate / "Cargo.toml").write_text("x")
            digests = VERIFIER.source_digests(crate)
        self.assertRegex(digests["Cargo.toml"], r"^[0-9a-f]{64}$")
        self.assertEqual([digests[n] for n in ("Cargo.lock", ".cargo/config.toml", "build.rs")], [None, None, None])

    def test_committed_config_is_a_builtin_target_with_no_cpu_override(self):
        target = VERIFIER.build_manifest(self.CRATE, MIPS_TRIPLE, None, {}, Path(self.CRATE))["target"]
        self.assertTrue(target["builtin_target"])
        self.assertIsNone(target["target_json"])
        self.assertFalse(target["cpu_features_overridden"])
        self.assertIn("link-arg=--static", target["rustflags"])

    def test_a_cpu_or_feature_override_in_the_config_is_detected(self):
        for flag in ("target-cpu=24kf", "target-feature=+soft-float"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as scratch:
                crate = Path(scratch)
                (crate / ".cargo").mkdir()
                (crate / ".cargo" / "config.toml").write_text(
                    f'[target.{MIPS_TRIPLE}]\nrustflags = ["-C", "{flag}"]\n')
                target = VERIFIER.build_manifest(crate, MIPS_TRIPLE, None, {}, crate)["target"]
            self.assertTrue(target["cpu_features_overridden"])
            self.assertEqual(target["rustflags"], ["-C", flag])

    def test_repo_relative_never_returns_an_absolute_path(self):
        self.assertEqual(VERIFIER.repo_relative(VERIFIER.REPO_ROOT / "build" / "x"), "build/x")
        with tempfile.TemporaryDirectory() as scratch:
            self.assertEqual(VERIFIER.repo_relative(Path(scratch)), VERIFIER.OUTSIDE_REPO)


class CaptureTests(unittest.TestCase):
    def capture(self, code, timeout=2, max_bytes=1024):
        return VERIFIER.capture_guest([sys.executable, "-c", code],
                                      os.environ.copy(), timeout, max_bytes)

    def test_exact_binary_streams(self):
        result = self.capture("import os; os.write(1,b'one\\r\\n\\xff'); os.write(2,b'two\\x00')")
        self.assertEqual(result["stdout"], b"one\r\n\xff")
        self.assertEqual(result["stderr"], b"two\x00")
        self.assertEqual(result["returncode"], 0)
        self.assertIsNone(result["stop_reason"])

    def test_timeout_preserves_prefix(self):
        result = self.capture("import os,time; os.write(1,b'partial'); time.sleep(10)", timeout=0.3)
        self.assertEqual(result["stdout"], b"partial")
        self.assertEqual(result["stop_reason"], "timeout")
        self.assertNotEqual(result["returncode"], 0)

    def test_unbounded_writer_is_capped(self):
        result = self.capture("import os\nwhile True: os.write(1,b'x'*4096)", max_bytes=100)
        self.assertEqual(len(result["stdout"]) + len(result["stderr"]), 100)
        self.assertEqual(result["stop_reason"], "output_limit")

    def test_nonzero_exit_preserves_stderr(self):
        result = self.capture("import os; os.write(2,b'crash detail'); raise SystemExit(7)")
        self.assertEqual(result["stderr"], b"crash detail")
        self.assertEqual(result["returncode"], 7)

    def test_child_holding_pipe_cannot_hang_capture(self):
        result = self.capture("import os,time\npid=os.fork()\nif pid==0: time.sleep(10)\nelse: os._exit(0)", timeout=0.3)
        self.assertEqual(result["stop_reason"], "timeout")

    def test_exception_receipt_replaces_incomplete(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "fresh"
            with patch.object(VERIFIER, "run_verification", side_effect=RuntimeError("fixture")):
                self.assertEqual(VERIFIER.main(["--results-dir", str(output)]), 1)
            receipt = json.loads((output / "e07-e03-verification-receipt.json").read_text())
            self.assertEqual(receipt["status"], "FAIL")
            self.assertEqual(receipt["error_type"], "RuntimeError")
            self.assertTrue(receipt["run_id"])

    def test_existing_results_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / "marker"
            marker.write_bytes(b"previous run")
            with self.assertRaises(FileExistsError):
                VERIFIER.main(["--results-dir", scratch])
            self.assertEqual(marker.read_bytes(), b"previous run")

    def run_main(self, scratch, binary_bytes, captures, build=False, extra_argv=()):
        """Drive run_verification with synthetic bytes and a patched guest capture. Orchestration and
        receipt-field plumbing only: nothing is executed and no guest qualification is supplied.
        With ``build=True`` the runner takes its build path and every subprocess call is recorded in
        ``self.builds`` instead of run (no rch, no cargo)."""
        self.builds = []

        def fake_run(cmd, **kwargs):
            self.builds.append((list(cmd), kwargs))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        root = Path(scratch)
        target = root / "target"
        for triple, machine in ((MIPS_TRIPLE, 8), (PPC_TRIPLE, 20)):
            binary = target / triple / "release/ffw-hello-init"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(binary_bytes.get(triple, elf32(machine)))
        kernel = root / "kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta"
        kernel.parent.mkdir(parents=True)
        kernel.write_bytes(b"synthetic-kernel-not-executed")
        output = root / "result"
        argv = ["--target-dir", str(target), "--results-dir", str(output), *extra_argv]
        with patch.object(VERIFIER.mkinitramfs, "resolve_default_build_dir", return_value=root), \
             patch.object(VERIFIER, "capture_guest", side_effect=captures), \
             contextlib.ExitStack() as stack:
            if build:
                stack.enter_context(patch.object(VERIFIER.subprocess, "run", side_effect=fake_run))
            result = VERIFIER.main(argv if build else ["--skip-build", *argv])
        return result, json.loads((output / "e07-e03-verification-receipt.json").read_text())

    def test_second_guest_exception_retains_first_guest_receipt(self):
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            result, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
            self.assertEqual(result, 1)
            self.assertEqual(receipt["status"], "FAIL")
            self.assertEqual(receipt["error_type"], "FileNotFoundError")
            self.assertEqual(receipt["guests"]["mips"]["status"], "PASS")
            self.assertNotIn("ppc", receipt["guests"])

    def test_guest_record_carries_triple_libc_linker_and_probe_identity(self):
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
            guest = receipt["guests"]["mips"]
            self.assertEqual(guest["status"], "PASS")
            self.assertEqual(guest["target_triple"], MIPS_TRIPLE)
            self.assertEqual(guest["build_identity"]["target"], MIPS_TRIPLE)
            # What is PROVEN is a static executable with no loader; "no libc" is only the build's own claim.
            self.assertEqual(guest["libc"]["conclusion"], "static_no_loader")
            self.assertEqual(guest["libc"]["reported_by_probe"], "none")
            self.assertEqual(guest["booted_init_sha256"], guest["binary_sha256"])      # the init QEMU ran is this binary
            self.assertTrue(guest["libc"]["static_elf"]["static"])
            self.assertEqual((guest["linker_configured"]["linker"], guest["linker_configured"]["flavor"]), ("rust-lld", "ld.lld"))
            self.assertFalse(guest["linker_configured"]["attested"])

    def test_guest_record_lists_unseeded_separately_from_unsupported(self):
        # Receipt plumbing only: the guest's own UNSEEDED token reaches the written record, in its own list.
        with tempfile.TemporaryDirectory() as scratch:
            stdout = swap("GETRANDOM", "FFW_PROBE:GETRANDOM status=UNSEEDED rc=-11").encode()
            capture = {"stdout": stdout, "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
        guest = receipt["guests"]["mips"]
        self.assertEqual(guest["status"], "PASS")
        self.assertEqual(guest["unseeded_capabilities"], ["GETRANDOM"])
        self.assertEqual(guest["unsupported_capabilities"], [])
        self.assertEqual(guest["probes"]["FFW_PROBE:GETRANDOM"]["status"], "UNSEEDED")

    def test_skip_build_manifest_has_no_command_and_is_not_bound_to_the_binary(self):
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
        manifest = receipt["guests"]["mips"]["build_manifest"]
        self.assertIsNone(manifest["command"])
        self.assertIsNone(manifest["environment"])
        self.assertFalse(manifest["sources_bound_to_binary"])        # the tree may not be what built the binary
        self.assertEqual(manifest["target"]["triple"], MIPS_TRIPLE)
        self.assertIsNone(manifest["target"]["build_std"])
        self.assertRegex(manifest["sources_sha256"]["src/main.rs"], r"^[0-9a-f]{64}$")

    def test_a_runner_build_records_the_exact_command_that_ran_and_binds_the_sources(self):
        expected = ["rch", "exec", "--source-content-receipt", "--", "cargo", "+nightly", "build", "--release",
                    "--target", MIPS_TRIPLE, "-Z", "build-std=core,panic_abort"]
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")], build=True)
        manifest = receipt["guests"]["mips"]["build_manifest"]
        ran = [(cmd, kwargs) for cmd, kwargs in self.builds if cmd[:1] == ["rch"]]
        self.assertEqual(manifest["command"], expected)
        self.assertIn(expected, [cmd for cmd, _ in ran])             # the recorded command is the one that ran
        self.assertEqual(len(ran), 2)                                # one build per target, no more
        self.assertTrue(all(kw["env"]["RCH_REQUIRE_REMOTE"] == "1" and kw["check"] for _, kw in ran))
        self.assertTrue(manifest["sources_bound_to_binary"])
        self.assertEqual(manifest["environment"],
                         {"RCH_REQUIRE_REMOTE": "1", "CARGO_TARGET_DIR": VERIFIER.OUTSIDE_REPO})
        self.assertEqual(manifest["target"]["build_std"], "core,panic_abort")

    BASE_BUILD = ["rch", "exec", "--source-content-receipt", "--", "cargo", "+nightly", "build", "--release",
                  "--target", None, "-Z", "build-std=core,panic_abort"]

    def expected_build(self, triple, jobs=None):
        cmd = [triple if part is None else part for part in self.BASE_BUILD]
        return cmd + ([] if jobs is None else ["-j", str(jobs)])

    def test_jobs_appends_dash_j_to_the_command_that_ran_and_to_the_recorded_command(self):
        # RCH refused a 4-core estimate on a 3-slot worker ("pass -j 3 (or fewer)") and ignores CARGO_BUILD_JOBS, so
        # the count must be in the argv itself, and the receipt must show the argv that actually ran.
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")], build=True,
                                       extra_argv=["--jobs", "2"])
        ran = [cmd for cmd, _ in self.builds if cmd[:1] == ["rch"]]
        self.assertEqual(ran, [self.expected_build(MIPS_TRIPLE, 2), self.expected_build(PPC_TRIPLE, 2)])
        manifest = receipt["guests"]["mips"]["build_manifest"]
        self.assertEqual(manifest["command"], self.expected_build(MIPS_TRIPLE, 2))
        self.assertEqual(manifest["command"][-2:], ["-j", "2"])                     # appended, after -Z build-std
        self.assertEqual(manifest["target"]["build_std"], "core,panic_abort")       # still recognised with -j present

    def test_omitting_jobs_leaves_the_command_exactly_as_before(self):
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")], build=True)
        ran = [cmd for cmd, _ in self.builds if cmd[:1] == ["rch"]]
        self.assertEqual(ran, [self.expected_build(MIPS_TRIPLE), self.expected_build(PPC_TRIPLE)])
        self.assertNotIn("-j", receipt["guests"]["mips"]["build_manifest"]["command"])

    def test_each_job_count_reaches_the_command_unchanged(self):
        for jobs in (1, 3, 256):
            with self.subTest(jobs=jobs), tempfile.TemporaryDirectory() as scratch:
                capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
                _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")], build=True,
                                           extra_argv=["--jobs", str(jobs)])
                self.assertEqual(receipt["guests"]["mips"]["build_manifest"]["command"][-2:], ["-j", str(jobs)])

    def test_a_bad_jobs_value_or_jobs_without_a_build_is_refused_before_anything_runs(self):
        for argv in (["--jobs", "0"], ["--jobs", "-1"], ["--jobs", "257"], ["--jobs", "two"], ["--jobs"],
                     ["--jobs", "2", "--skip-build"]):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as scratch:
                target = Path(scratch) / "never-created"
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    VERIFIER.main([*argv, "--results-dir", str(target)])
                self.assertEqual(caught.exception.code, 2)
                self.assertFalse(target.exists())                                   # no results dir, no build, no receipt

    def test_no_receipt_field_leaks_an_absolute_path(self):
        for build in (False, True):
            with self.subTest(build=build), tempfile.TemporaryDirectory() as scratch:
                capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
                _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")], build=build)
                text = json.dumps(receipt)
                self.assertNotIn(str(Path(scratch).resolve()), text)
                self.assertNotIn(scratch, text)
            self.assertNotIn(str(Path.home()), text)

    def test_guest_record_lists_unsupported_capabilities_without_failing_the_guest(self):
        # Receipt plumbing only: an explicit -ENOSYS reaches the per-guest record as unsupported, not as a pass.
        with tempfile.TemporaryDirectory() as scratch:
            stdout = swap("EVENTFD2", "FFW_PROBE:EVENTFD2 status=FAIL fd=-89").encode()
            capture = {"stdout": stdout, "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
            guest = receipt["guests"]["mips"]
            self.assertEqual(guest["status"], "PASS")
            self.assertEqual(guest["unsupported_capabilities"], ["EVENTFD2"])
            self.assertEqual(guest["probes"]["FFW_PROBE:EVENTFD2"]["status"], "FAIL")

    def test_a_binary_that_is_not_the_packed_init_fails_the_guest(self):
        # The receipt names binary_sha256 and says it describes the booted bytes; if the archive's init entry hashes
        # to something else (the binary changed between packing and receipt), the claim is false and the guest fails.
        real_build = VERIFIER.mkinitramfs.build

        def forged(init_path, out_path):
            return {**real_build(init_path, out_path), "init_sha256": "0" * 64}

        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            with patch.object(VERIFIER.mkinitramfs, "build", side_effect=forged):
                result, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
        guest = receipt["guests"]["mips"]
        self.assertEqual(result, 1)
        self.assertEqual(guest["status"], "FAIL")
        self.assertIn("initramfs_init_differs_from_binary", guest["validation_errors"])
        self.assertNotEqual(guest["booted_init_sha256"], guest["binary_sha256"])      # both are kept, not hidden

    def test_dynamic_binary_fails_the_guest_even_with_a_clean_transcript(self):
        # A clean serial transcript must not launder a libc claim the booted ELF contradicts.
        with tempfile.TemporaryDirectory() as scratch:
            capture = {"stdout": POSITIVE.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}
            dynamic = {MIPS_TRIPLE: elf32(8, ptypes=(3, 1))}
            result, receipt = self.run_main(scratch, dynamic, [capture, FileNotFoundError("second guest")])
            guest = receipt["guests"]["mips"]
            self.assertEqual(result, 1)
            self.assertEqual(guest["status"], "FAIL")
            self.assertEqual(guest["libc"]["conclusion"], "unverified")
            self.assertTrue(any(e.startswith("libc_claim_unsupported_by_elf") for e in guest["validation_errors"]))

    def test_probe_flavor_that_contradicts_the_committed_config_fails_the_guest(self):
        with tempfile.TemporaryDirectory() as scratch:
            stdout = POSITIVE.replace("linker_flavor=ld.lld", "linker_flavor=gnu-lld").encode()
            capture = {"stdout": stdout, "stderr": b"", "returncode": 0, "stop_reason": None}
            _, receipt = self.run_main(scratch, {}, [capture, FileNotFoundError("second guest")])
            guest = receipt["guests"]["mips"]
            self.assertEqual(guest["status"], "FAIL")
            self.assertIn("linker_flavor_differs_from_committed_config", guest["validation_errors"])


if __name__ == "__main__":
    unittest.main()
