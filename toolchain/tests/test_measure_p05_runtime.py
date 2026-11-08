"""P05 runtime capture/verification regressions.

Transcript and ELF fixtures below test the checker, not Asupersync or QEMU.
Capture tests execute real, bounded Python subprocesses, not firmware.
Scratch evidence remains in the system temporary directory; this suite deletes no files.
"""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import math
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_serial_validator as serial_fixture

SPEC = importlib.util.spec_from_file_location("p05_runtime_under_test", HERE.parent / "src/measure-p05-target.py")
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


def fixture(arch="mips", *, cleanup=True):
    """Handwritten operation sequence; deliberately does not iterate the judge's expected-order table."""
    def c(phase):
        return (f"FFW_P05_RUNTIME:CENSUS status=ok phase={phase} threads_task_dir_before=4 threads_task_dir_after=4 "
                "task_dir_stable=true threads_status=4 sources_agree=true vm_rss_kb=5000 vm_hwm_kb=6000 mem_available_kb=9000")

    bits, endian = (64, "little") if arch == "x86_64" else (32, "big")
    drain = ("outcome=Quiescent expected_outcome=Quiescent live_tasks=0 pending_obligations=0 live_regions=0 "
             "expected_live_regions=0 queued_finalizers=0 pending_spawns=0 pending_obligation_posts=false")
    abort_cleanup = " cleanup_resumed=1 cleanup_unique=1 cleanup_cancelled=1 cleanup_before_deadline=1" if cleanup else ""
    drain_cleanup = " cleanup_resumed=4 cleanup_unique=4 cleanup_cancelled=4 cleanup_before_deadline=4" if cleanup else ""
    return "\n".join([
        f"FFW_P05_RUNTIME:BEGIN status=start pid=17 arch={arch} endian={endian} pointer_bits={bits} threads_available_to_std=1",
        c("start"),
        "FFW_P05_RUNTIME:PROFILE_ACCEPT status=ok violations=0 worst_case_stack_bytes=2621440 budget=2621440",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_ZERO_WORKERS status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_UNBOUNDED_QUEUE status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_OVER_BUDGET status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:REACTOR status=ok kind=platform",
        "FFW_P05_RUNTIME:RUNTIME_AUDIT status=ok audit_ok=true workers=2/2 blocking_threads=1/1 global_queue=256/256 blocking_queue=1/1 (carried/stated)",
        c("after_build"),
        "FFW_P05_RUNTIME:SPAWN_JOIN status=ok children=8 joined=8 sum=140 expected=140",
        c("after_spawn_join"),
        "FFW_P05_RUNTIME:ABORT_TIMER_PARKED status=ok parked=true pending_timers_before=1 pending_timers_after=0 abort_to_join_ms=2 join_result=Ok expected_join_result=Ok threads_during_task_dir=4 threads_during_status=4" + abort_cleanup,
        c("after_abort_timer_parked"),
        "FFW_P05_RUNTIME:ABORT_BLIND_VALUE status=ok join_result=Cancelled expected_join_result=Cancelled ok_value=None",
        c("after_abort_blind_value"),
        "FFW_P05_RUNTIME:TIMER_WAKE status=ok wanted_ms=50 slept_ms=50",
        c("after_timer_wake"),
        "FFW_P05_RUNTIME:UDP_LOOPBACK status=ok bytes=19 payload_equal=true peer_is_sender=true",
        c("after_udp"),
        "FFW_P05_RUNTIME:BLOCKING_POOL status=ok idle_threads=0 first_admitted=true first_started=true second_admitted=true third_refused=Some(Saturated) active_threads_while_held=1 pending_while_held=1 threads_held_task_dir=5 threads_held_status=5 first_finished=true second_finished=true ran=2",
        c("after_blocking_pool"),
        "FFW_P05_RUNTIME:DRAIN status=ok tasks_spawned=4/4 tasks_parked_before_drain=4 snapshot_before_drain=(admitted=4 unfinished=4 timers_pending=4) " + drain + " elapsed_ms=2 bound_ms=5000" + drain_cleanup + " repeat: " + drain,
        c("after_drain"), c("after_runtime_drop"),
        "FFW_P05_RUNTIME:END status=done ops=23 ok=23 failed=0 unsupported=0 partial=0 unknown=0 census_samples=10",
    ]) + "\n"


def fnv(data):
    value = 14695981039346656037
    for byte in data:
        value = (value ^ byte) * 1099511628211 % (1 << 64)
    return value


def wrapped(child, arch="mips"):
    base = serial_fixture.POSITIVE
    if arch == "powerpc":
        base = base.replace("arch=mips-be", "arch=powerpc-be").replace("mips-unknown", "powerpc-unknown")
        base = base.replace("errno=89", "errno=38")
    data = child.encode()
    region = ("FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog\n" + child +
              f"FFW_SPEAKER_EXIT status=0 stdout_bytes={len(data)} stdout_fnv1a64={fnv(data):016x}\n")
    return base.replace("FFW_MARKER:TEST_SUCCESS", region + "FFW_MARKER:TEST_SUCCESS")


def elf_fixture(arch):
    """Header-only parser fixture; never executable evidence."""
    cls, endian, machine, _ = M.RUNTIME_ARCHES[arch]
    data = bytearray(52 if cls == 1 else 64)
    data[:4] = b"\x7fELF"
    data[4:7] = bytes((cls, endian, 1))
    data[18:20] = machine.to_bytes(2, "big" if endian == 2 else "little")
    return bytes(data)


class RuntimeTranscriptTests(unittest.TestCase):
    def judge(self, text, arch="mips", supervised=False):
        return M.judge_runtime(text, arch, {"arch": arch}, supervised=supervised)

    def test_exact_complete_fixture_passes_for_each_architecture(self):
        for arch in ("mips", "powerpc", "x86_64"):
            with self.subTest(arch=arch):
                report = self.judge(fixture(arch), arch)
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["observed_statuses"], dict(ok=23, failed=0, unsupported=0, partial=0, unknown=0))

    def test_only_lf_or_crlf_are_serial_line_boundaries(self):
        good = fixture()
        self.assertTrue(self.judge(good)["ok"])
        self.assertTrue(self.judge(good.replace("\n", "\r\n"))["ok"])
        for separator in ("\r", "\x0b", "\x0c", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                self.assertFalse(self.judge(good.replace("\n", separator))["ok"])
                self.assertFalse(self.judge(good.replace("\n", separator, 1))["ok"])

    def test_numbers_use_canonical_ascii_decimal_not_python_integer_extensions(self):
        good = fixture()
        for old, new in (
            ("pid=17", "pid=+17"), ("pid=17", "pid=1_7"), ("pid=17", "pid=017"), ("pid=17", "pid=١٧"),
            ("threads_status=4", "threads_status=٤"), ("vm_rss_kb=5000", "vm_rss_kb=5_000"),
            ("vm_hwm_kb=6000", "vm_hwm_kb=06000"), ("slept_ms=50", "slept_ms=٥٠"),
            ("elapsed_ms=2", "elapsed_ms=+2"), ("timers_pending=4)", "timers_pending=04)"),
            ("mem_available_kb=9000", "mem_available_kb=18446744073709551616"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(good.replace(old, new, 1))["ok"])

    def test_missing_cleanup_witnesses_block_legacy_evidence_instead_of_inventing_a_pass(self):
        legacy = self.judge(fixture(cleanup=False))
        self.assertFalse(legacy["ok"])
        self.assertTrue(legacy["blocked"])
        self.assertEqual(M.exit_code(legacy), 3)
        self.assertEqual([g.gate_id for g in legacy["gates"] if g.status == "blocked"], ["P05R-CLEANUP"])
        self.assertFalse(any(g.status == "failed" for g in legacy["gates"]))
        self.assertTrue(self.judge(fixture())["ok"])

    def test_failed_or_partial_cleanup_witnesses_are_red_even_with_quiescent_counts(self):
        for wanted in (1, 4):
            for key in ("cleanup_resumed", "cleanup_unique", "cleanup_cancelled", "cleanup_before_deadline"):
                with self.subTest(wanted=wanted, field=key):
                    report = self.judge(fixture().replace(f"{key}={wanted}", f"{key}=0", 1))
                    self.assertFalse(report["ok"])
                    self.assertEqual(M.exit_code(report), 1)

    def test_every_required_line_is_required_once(self):
        good = fixture().splitlines(keepends=True)
        self.assertTrue(self.judge("".join(good))["ok"])
        for index in range(len(good)):
            with self.subTest(missing=index):
                self.assertFalse(self.judge("".join(good[:index] + good[index + 1:]))["ok"])
            with self.subTest(duplicate=index):
                self.assertFalse(self.judge("".join(good[:index] + [good[index]] + good[index:]))["ok"])

    def test_each_adjacent_reordering_is_refused(self):
        good = fixture().splitlines(keepends=True)
        for index in range(len(good) - 1):
            changed = good.copy()
            changed[index:index + 2] = reversed(changed[index:index + 2])
            with self.subTest(index=index):
                self.assertFalse(self.judge("".join(changed))["ok"])

    def test_no_failed_partial_unsupported_or_unknown_phase_can_hide_behind_green_totals(self):
        self.assertTrue(self.judge(fixture())["ok"])
        for status in ("failed", "unsupported", "partial", "unknown"):
            for name in M.RUNTIME_PHASES:
                with self.subTest(status=status, name=name):
                    text = fixture().replace(f"{name} status=ok", f"{name} status={status}")
                    self.assertFalse(self.judge(text)["ok"])

    def test_census_must_be_readable_consistent_and_correctly_named(self):
        for old, new in (
            ("threads_task_dir_before=4", "threads_task_dir_before=unknown"),
            ("threads_task_dir_after=4", "threads_task_dir_after=3"),
            ("threads_status=4", "threads_status=0"),
            ("vm_rss_kb=5000", "vm_rss_kb=-1"),
            ("vm_hwm_kb=6000", "vm_hwm_kb=4000"),
            ("mem_available_kb=9000", "mem_available_kb=unknown"),
            ("task_dir_stable=true", "task_dir_stable=false"),
            ("sources_agree=true", "sources_agree=unknown"),
            ("phase=start", "phase=after_build"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(fixture().replace(old, new, 1))["ok"])

    def test_drain_checks_both_original_and_repeated_counts(self):
        self.assertTrue(self.judge(fixture())["ok"])
        for key in ("live_tasks", "pending_obligations", "live_regions", "queued_finalizers", "pending_spawns"):
            for occurrence in (0, 1):
                text = fixture()
                head, tail = text.split(" repeat: ")
                if occurrence == 0:
                    head = head.replace(f"{key}=0", f"{key}=1")
                else:
                    tail = tail.replace(f"{key}=0", f"{key}=1")
                with self.subTest(key=key, occurrence=occurrence):
                    self.assertFalse(self.judge(head + " repeat: " + tail)["ok"])
        self.assertFalse(self.judge(fixture().replace("outcome=Quiescent", "outcome=TimedOut"))["ok"])
        self.assertFalse(self.judge(fixture().replace("pending_obligation_posts=false", "pending_obligation_posts=true"))["ok"])

    def test_wrong_platform_missing_elf_or_pid1_as_child_is_refused(self):
        self.assertFalse(self.judge(fixture("x86_64"))["ok"])
        self.assertFalse(M.judge_runtime(fixture(), "mips", None)["ok"])
        self.assertFalse(self.judge(fixture().replace("pid=17", "pid=1"), supervised=True)["ok"])
        self.assertTrue(self.judge(fixture(), supervised=True)["ok"])

    def test_contradictory_or_missing_phase_details_cannot_pass_with_ok_status(self):
        # Independent protocol field inventory: diagnostics such as thread-count snapshots are not acceptance predicates.
        required = {
            "PROFILE_ACCEPT": "violations worst_case_stack_bytes budget",
            "PROFILE_REFUSES_ZERO_WORKERS": "named_violation builder_refused",
            "PROFILE_REFUSES_UNBOUNDED_QUEUE": "named_violation builder_refused",
            "PROFILE_REFUSES_OVER_BUDGET": "named_violation builder_refused",
            "REACTOR": "kind",
            "RUNTIME_AUDIT": "audit_ok workers blocking_threads global_queue blocking_queue",
            "SPAWN_JOIN": "children joined sum expected",
            "ABORT_TIMER_PARKED": "parked pending_timers_before pending_timers_after abort_to_join_ms join_result expected_join_result cleanup_resumed cleanup_unique cleanup_cancelled cleanup_before_deadline",
            "ABORT_BLIND_VALUE": "join_result expected_join_result ok_value",
            "TIMER_WAKE": "wanted_ms slept_ms",
            "UDP_LOOPBACK": "bytes payload_equal peer_is_sender",
            "BLOCKING_POOL": "idle_threads first_admitted first_started second_admitted third_refused active_threads_while_held pending_while_held first_finished second_finished ran",
            "DRAIN": "tasks_spawned tasks_parked_before_drain elapsed_ms bound_ms cleanup_resumed cleanup_unique cleanup_cancelled cleanup_before_deadline",
        }
        good = fixture()
        self.assertTrue(self.judge(good)["ok"])
        for name, keys in required.items():
            original = next(line for line in good.splitlines() if line.startswith(f"FFW_P05_RUNTIME:{name} "))
            for key in keys.split():
                token = re.search(r"\b" + key + r"=\S+", original)[0]
                for replacement in ("", key + "=contradiction"):
                    with self.subTest(name=name, key=key, replacement=replacement):
                        self.assertFalse(self.judge(good.replace(original, original.replace(token, replacement, 1)))["ok"])

    def test_declared_time_and_live_timer_boundaries(self):
        for old, accepted, refused in (
            ("abort_to_join_ms=2", "abort_to_join_ms=999", "abort_to_join_ms=1000"),
            ("slept_ms=50", "slept_ms=45", "slept_ms=44"),
            ("slept_ms=50", "slept_ms=4999", "slept_ms=5000"),
            ("elapsed_ms=2", "elapsed_ms=4999", "elapsed_ms=5000"),
            ("timers_pending=4)", "timers_pending=5)", "timers_pending=3)"),
        ):
            with self.subTest(boundary=old):
                self.assertTrue(self.judge(fixture().replace(old, accepted))["ok"])
                self.assertFalse(self.judge(fixture().replace(old, refused))["ok"])

    def test_end_alone_atomic_output_duplicates_echoes_and_panics_never_pass(self):
        for text in (
            fixture().splitlines()[-1] + "\n", "FFW_P05T_END failures=0\n", fixture() * 2,
            fixture().replace("ok=23", "ok=22"), fixture().replace("ops=23", "ops=23 ops=23"),
            "\n".join("echo " + line for line in fixture().splitlines()),
            fixture() + "FFW_UNKNOWN bad=1\n", fixture() + "Kernel panic - not syncing\n",
            fixture() + "\ufffd\n",
        ):
            with self.subTest(text=text[-120:]):
                self.assertFalse(self.judge(text)["ok"])


class SupervisorEnvelopeTests(unittest.TestCase):
    def judge(self, text, arch="mips"):
        child, gates = M.runtime_envelope(text, arch)
        report = M.judge_runtime(child, arch, {"arch": arch}, supervised=True)
        return all(g.status == "passed" for g in gates) and report["ok"]

    def test_existing_bootstrap_supervises_runtime_child_for_both_be_targets(self):
        for arch in ("mips", "powerpc"):
            with self.subTest(arch=arch):
                self.assertTrue(self.judge(wrapped(fixture(arch), arch), arch))

    def test_outer_protocol_framing_is_strict_without_rejecting_firmware_preamble(self):
        for arch in ("mips", "powerpc"):
            good = wrapped(fixture(arch), arch)
            with self.subTest(arch=arch):
                self.assertTrue(self.judge(good, arch))
                self.assertTrue(self.judge(good.replace("\n", "\r\n"), arch))
                self.assertTrue(self.judge("OpenBIOS\rbooting\x0c\x1b[0m\n" + good, arch))
                self.assertTrue(self.judge("OpenBIOS\rbooting\x0c\x1b[0m\r\n" + good.replace("\n", "\r\n"), arch))
            for separator in ("\r", "\r\r\n", "\x0b", "\x0c", "\x85", "\u2028", "\u2029"):
                with self.subTest(arch=arch, separator=repr(separator)):
                    self.assertFalse(self.judge(good.replace(
                        "FFW_MARKER:USERSPACE_START\n", "FFW_MARKER:USERSPACE_START" + separator, 1), arch))
                    self.assertFalse(self.judge(good.replace(
                        "FFW_PROBE:ATOMICS_32 status=PASS ok=1\n",
                        "FFW_PROBE:ATOMICS_32 status=PASS ok=1" + separator, 1), arch))

    def test_runtime_child_cannot_precede_remaining_supervisor_probes(self):
        good = wrapped(fixture())
        self.assertTrue(self.judge(good))
        begin, end = good.index("FFW_SPEAKER_BEGIN "), good.index("FFW_MARKER:TEST_SUCCESS")
        region = good[begin:end]
        before_child = good.replace(region, "")
        setup = "FFW_PROBE:LOOPBACK_UP status=PASS rc=0\n"
        moved = before_child.replace(setup, setup + region, 1)
        self.assertFalse(self.judge(moved), "the real supervisor launches its child after every probe")

    def test_child_failure_missing_end_and_bad_hash_fail_beside_green_control(self):
        good = wrapped(fixture())
        self.assertTrue(self.judge(good))
        for old, new in (
            ("FFW_SPEAKER_EXIT status=0", "FFW_SPEAKER_EXIT status=7"),
            ("stdout_bytes=", "stdout_bytes=9"),
            ("stdout_fnv1a64=", "stdout_fnv1a64=f"),
            ("FFW_P05_RUNTIME:END", "TRUNCATED_END"),
            ("FFW_SPEAKER_BEGIN path=", "FFW_SPEAKER_BEGIN path=/wrong"),
            ("FFW_SPEAKER_BEGIN ", " FFW_SPEAKER_BEGIN "),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(good.replace(old, new, 1)))

    def test_bootstrap_remains_strict_outside_only_the_child_region(self):
        good = wrapped(fixture())
        for old, new in (
            ("FFW_MARKER:REBOOT_REQUEST", ""),
            ("TEST_SUCCESS failures=0", "TEST_SUCCESS failures=1"),
            ("FFW_PROBE:LOOPBACK_UP status=PASS rc=0", "FFW_PROBE:LOOPBACK_UP status=FAIL rc=-1"),
            ("FFW_RUSTC release=", "FFW_UNKNOWN release="),
            ("FFW_MARKER:REBOOT_REQUEST", "FFW_PLATFORM_STEP_BEGIN unexpected=1\nFFW_MARKER:REBOOT_REQUEST"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(good.replace(old, new, 1)))
        self.assertFalse(self.judge(good + "FFW_P05_RUNTIME:END status=done\n"))

    def test_summary_before_child_duplicate_wrapper_or_missing_setup_is_refused(self):
        good = wrapped(fixture())
        summary = "FFW_MARKER:TEST_SUCCESS failures=0\n"
        moved = good.replace(summary, "").replace("FFW_SPEAKER_BEGIN", summary + "FFW_SPEAKER_BEGIN")
        self.assertFalse(self.judge(moved))
        self.assertFalse(self.judge(good.replace("FFW_SPEAKER_BEGIN", "FFW_SPEAKER_BEGIN x=1\nFFW_SPEAKER_BEGIN", 1)))
        setup = "FFW_PROBE:LOOPBACK_UP status=PASS rc=0\n"
        moved = good.replace(setup, "").replace("FFW_SPEAKER_BEGIN", setup + "FFW_SPEAKER_BEGIN")
        self.assertTrue(self.judge(moved))
        moved = good.replace(setup, "").replace(summary, setup + summary)
        self.assertFalse(self.judge(moved))


class CaptureTests(unittest.TestCase):
    """Real host subprocesses exercise custody/timeout behavior; none is a QEMU or runtime stand-in."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ffw-p05-capture-test-"))
        self.paths = {name: self.root / (name + ".bin") for name in ("stdout", "stderr")}

    def capture(self, code, timeout=5, cap=4096):
        return M.boot_runner().capture_guest([sys.executable, "-c", code], dict(os.environ), timeout,
                                            max_bytes=cap, capture_paths=self.paths)

    def test_real_subprocess_preserves_both_raw_streams_and_exit(self):
        result = self.capture("import os;os.write(1,b'out\\xff\\r\\n');os.write(2,b'err\\x00\\n')")
        self.assertEqual((result["returncode"], result["stop_reason"]), (0, None))
        for name in ("stdout", "stderr"):
            self.assertEqual(self.paths[name].read_bytes(), result[name])
        self.assertEqual(result["stdout"], b"out\xff\r\n")
        self.assertEqual(result["stderr"], b"err\x00\n")

    def test_real_timeout_keeps_prefix_and_does_not_kill_unrelated_group(self):
        peer = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True)
        try:
            result = self.capture("import os,time;os.write(1,b'partial\\n');time.sleep(30)", timeout=2)
            self.assertEqual(result["stop_reason"], "timeout")
            self.assertNotEqual(result["returncode"], 0)
            self.assertEqual(self.paths["stdout"].read_bytes(), b"partial\n")
            self.assertIsNone(peer.poll(), "capture must only signal its own isolated process group")
        finally:
            peer.terminate()
            peer.wait(timeout=5)

    def test_raw_prefix_is_readable_while_the_captured_process_is_still_running(self):
        result = []
        worker = threading.Thread(target=lambda: result.append(self.capture(
            "import os,time;os.write(1,b'visible before exit\\n');time.sleep(30)", timeout=2)))
        worker.start()
        try:
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                if self.paths["stdout"].exists() and self.paths["stdout"].read_bytes() == b"visible before exit\n":
                    break
                time.sleep(0.01)
            self.assertTrue(worker.is_alive(), "the positive must observe the prefix before process completion")
            self.assertEqual(self.paths["stdout"].read_bytes(), b"visible before exit\n")
        finally:
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0]["stop_reason"], "timeout")

    def test_real_output_limit_bounds_combined_memory_and_persisted_bytes(self):
        result = self.capture("import os;os.write(1,b'x'*1000000)", cap=64)
        self.assertEqual(result["stop_reason"], "output_limit")
        self.assertEqual(sum(len(result[name]) for name in self.paths), 64)
        self.assertEqual(sum(self.paths[name].stat().st_size for name in self.paths), 64)

    def test_nonzero_exit_is_not_hidden_by_a_printed_completion_marker(self):
        result = self.capture("print('FFW_P05_RUNTIME:END status=done',flush=True);raise SystemExit(7)")
        self.assertEqual(result["returncode"], 7)
        self.assertIsNone(result["stop_reason"])

    def test_existing_evidence_is_never_overwritten(self):
        self.paths["stdout"].write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.capture("raise Exception('must not run')")
        self.assertEqual(self.paths["stdout"].read_bytes(), b"keep")

    def test_selector_initialization_failure_still_reaps_the_actual_owned_child(self):
        boot = M.boot_runner()
        original_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child

        for index, failure in enumerate(("create", "register")):
            self.paths = {name: self.root / f"{index}-{name}.bin" for name in ("stdout", "stderr")}
            selector = boot.selectors.DefaultSelector()
            try:
                factory = patch.object(boot.selectors, "DefaultSelector", side_effect=OSError("selector unavailable")) if (
                    failure == "create") else patch.object(boot.selectors, "DefaultSelector", return_value=selector)
                with factory, patch.object(selector, "register", side_effect=OSError("registration unavailable")), patch.object(
                        boot.subprocess, "Popen", side_effect=launch), self.assertRaises(OSError):
                    self.capture("import time;time.sleep(30)")
            finally:
                selector.close()
            self.assertEqual(len(children), index + 1)
            self.assertIsNotNone(children[-1].poll(), "no owned child may survive selector setup failure")
            self.assertTrue(children[-1].stdout.closed)
            self.assertTrue(children[-1].stderr.closed)

    def test_bad_capture_limits_and_missing_stream_path_are_refused_before_launch(self):
        for timeout in (0, -1, math.inf, math.nan):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.capture("raise Exception('must not run')", timeout=timeout)
        with self.assertRaises(ValueError):
            M.boot_runner().capture_guest(["must-not-launch"], {}, 1, capture_paths={"stdout": self.paths["stdout"]})
        self.assertFalse(any(self.root.iterdir()))


class RuntimeCliTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ffw-p05-runtime-cli-test-"))

    def test_elf_header_checks_all_supported_architectures_and_rejects_wrong_bytes(self):
        for arch in ("mips", "powerpc", "x86_64"):
            elf = self.root / arch
            elf.write_bytes(elf_fixture(arch))
            self.assertEqual(M.runtime_elf(elf, arch)["arch"], arch)
            with self.assertRaises(M.MeasurementError):
                M.runtime_elf(elf, "x86_64" if arch != "x86_64" else "mips")
        bad = self.root / "truncated"
        bad.write_bytes(b"\x7fELF")
        with self.assertRaises(M.MeasurementError):
            M.runtime_elf(bad, "mips")

    def test_missing_runtime_log_is_blocked_instead_of_reading_atomic_evidence(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["analyze-runtime", "--arch", "mips"]), 3)

    def test_public_p05_entrypoint_reaches_runtime_mode_and_rejects_wrong_subcommand(self):
        script = HERE.parents[1] / "scripts/e2e/p05"
        for argv, expected in ((["analyze", "--arch", "x86_64"], 3), (["wrong"], 2), ([], 2)):
            with self.subTest(argv=argv):
                run = subprocess.run([str(script), "--runtime", *argv], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, expected, run.stdout + run.stderr)

    def test_native_analysis_needs_elf_and_does_not_overwrite_receipts(self):
        log = self.root / "native.log"
        log.write_text(fixture("x86_64"))
        elf = self.root / "native.elf"
        elf.write_bytes(elf_fixture("x86_64"))
        receipt = self.root / "receipt.json"
        args = ["analyze-runtime", "--arch", "x86_64", "--log", str(log)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(M.main(args), 1)
            self.assertEqual(M.main(args + ["--elf", str(elf), "--receipt", str(receipt)]), 0)
            original = receipt.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(M.main(args + ["--elf", str(elf), "--receipt", str(receipt)]), 2)
            self.assertNotIn("PASSED", output.getvalue())
        self.assertEqual(receipt.read_bytes(), original)

    def test_receipt_persistence_failure_never_publishes_a_pass(self):
        log, elf = self.root / "native.log", self.root / "native.elf"
        log.write_text(fixture("x86_64"))
        elf.write_bytes(elf_fixture("x86_64"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            result = M.main(["analyze-runtime", "--arch", "x86_64", "--elf", str(elf), "--log", str(log),
                             "--receipt", str(self.root / "absent-parent" / "receipt.json")])
        self.assertEqual(result, 2)
        self.assertNotIn("PASSED", output.getvalue())

    def test_analysis_refuses_oversize_and_nonregular_inputs(self):
        log, elf = self.root / "oversize.log", self.root / "native.elf"
        elf.write_bytes(elf_fixture("x86_64"))
        log.write_bytes(b"x" * (M.RUNTIME_CAPTURE_BYTES + 1))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for source in (log, self.root):
                with self.subTest(source=source.name):
                    self.assertEqual(M.main(["analyze-runtime", "--arch", "x86_64", "--elf", str(elf),
                                             "--log", str(source)]), 2)
        with self.assertRaises(M.MeasurementError):
            M.runtime_elf(self.root, "x86_64")

    def test_streamed_elf_identity_hashes_the_entire_artifact(self):
        data = elf_fixture("mips") + b"tail" * (1024 * 1024)
        elf = self.root / "streamed.elf"
        elf.write_bytes(data)
        result = M.runtime_elf(elf, "mips")
        self.assertEqual(result["bytes"], len(data))
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())

    def test_analysis_hashes_exact_crlf_bytes_and_detects_a_raw_byte_change(self):
        log, elf = self.root / "native-crlf.log", self.root / "native.elf"
        elf.write_bytes(elf_fixture("x86_64"))
        raw = fixture("x86_64").replace("\n", "\r\n").encode()
        digests = []
        for index, content in enumerate((raw, raw.replace(b"threads_available_to_std=1", b"threads_available_to_std=2"))):
            log.write_bytes(content)
            receipt = self.root / f"receipt-{index}.json"
            with contextlib.redirect_stdout(io.StringIO()):
                result = M.main(["analyze-runtime", "--arch", "x86_64", "--elf", str(elf), "--log", str(log),
                                 "--receipt", str(receipt)])
            self.assertEqual(result, 0)
            observed = json.loads(receipt.read_text())["transcript_sha256"]
            self.assertEqual(observed, hashlib.sha256(content).hexdigest())
            digests.append(observed)
        self.assertNotEqual(*digests)


class RuntimePackagingTests(unittest.TestCase):
    """Real archive and subprocess plumbing with synthetic bytes, explicitly not a QEMU execution."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ffw-p05-runtime-packing-test-"))
        self.boot = M.boot_runner()
        self.capture = self.boot.capture_guest

    def invoke(self, arch="mips", mode="normal", mutate=None):
        elf, supervisor = self.root / "runtime.elf", self.root / "supervisor.elf"
        elf.write_bytes(elf_fixture(arch) + b"SYNTHETIC CHILD; NOT EXECUTABLE")
        supervisor.write_bytes(elf_fixture(arch) + b"SYNTHETIC SUPERVISOR; NOT EXECUTABLE")
        kernel = self.root / ("kernels/xm/boot/" + M.KERNEL_NAME if arch == "mips" else
                              "kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc")
        kernel.parent.mkdir(parents=True)
        if mode == "kernel-directory":
            kernel.mkdir()
        else:
            kernel.write_bytes(b"SYNTHETIC KERNEL; NOT EXECUTABLE")
        logs, receipt = self.root / "logs", self.root / "receipt.json"
        text = wrapped(fixture(arch), arch)
        if mode == "crlf":
            text = text.replace("\n", "\r\n")
        calls = []

        def synthetic_capture(command, env, timeout, **kwargs):
            calls.append(command)
            self.assertEqual(command[:5], ["qemu-system-mips" if arch == "mips" else "qemu-system-ppc",
                "-M", "malta" if arch == "mips" else "g3beige", "-cpu", "24Kf" if arch == "mips" else "G3"])
            self.assertEqual(command[command.index("-nic") + 1], "none", "loopback only, with no emulated LAN NIC")
            self.assertEqual(command[command.index("-m") + 1], "64M")
            self.assertEqual(command[command.index("-append") + 1],
                "console=" + ("ttyS0" if arch == "mips" else "ttyPZ0") + ",38400 rdinit=/init panic=-1")
            snapshot = Path(command[command.index("-kernel") + 1])
            self.assertEqual(snapshot, logs / "vmlinux.runtime-snapshot")
            self.assertEqual(snapshot.read_bytes(), b"SYNTHETIC KERNEL; NOT EXECUTABLE")
            if mutate == "kernel-cache":
                kernel.write_bytes(b"NEW CACHE CONTENTS; RUN MUST USE ITS SNAPSHOT")
            if mutate in ("kernel-snapshot", "initramfs"):
                target = snapshot if mutate == "kernel-snapshot" else Path(env["FFW_INITRAMFS"])
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" CHANGED DURING CAPTURE")
            self.assertEqual(Path(env["FFW_BUILD_DIR"]), self.root)
            self.assertEqual(Path(env["FFW_INITRAMFS"]), (logs / "runtime.cpio.gz").resolve())
            # The planted archive mutation keeps a valid gzip prefix but changes the artifact identity.
            archive_data = Path(env["FFW_INITRAMFS"]).read_bytes().split(b" CHANGED DURING CAPTURE")[0]
            image = self.boot.mkinitramfs.parse_cpio_bytes(gzip.decompress(archive_data))
            members = {entry["name"]: entry for entry in image}
            self.assertEqual(members["franken-speaker"]["data"], elf.read_bytes())
            self.assertEqual(members["init"]["data"], supervisor.read_bytes())
            if mode == "timeout":
                code = "import os,time;os.write(1,b'partial synthetic boot\\n');time.sleep(30)"
            elif mode == "overflow":
                code = "import os;os.write(1,b'x'*2000000)"
            else:
                code = "import sys;sys.stdout.write(" + repr(text) + ");sys.stdout.flush();raise SystemExit(" + (
                    "7" if mode == "nonzero" else "0") + ")"
            return self.capture([sys.executable, "-c", code], env, timeout, **kwargs)

        original_run = M.run_runtime

        def changed_source(args, *identities):
            if mutate in ("runtime", "supervisor"):
                selected = args.elf if mutate == "runtime" else args.supervisor
                selected.write_bytes(selected.read_bytes() + b" CHANGED BEFORE PACKAGING")
            return original_run(args, *identities)

        original_build = self.boot.mkinitramfs.build

        def competing_archive(init_path, out_path, *args, **kwargs):
            if mode == "archive-race":
                Path(out_path).write_bytes(b"OTHER WRITER'S ARCHIVE; PRESERVE")
            return original_build(init_path, out_path, *args, **kwargs)

        args = ["run-runtime", "--arch", arch, "--elf", str(elf), "--supervisor", str(supervisor),
                "--log-dir", str(logs), "--receipt", str(receipt), "--timeout", "2"]
        with patch.dict(os.environ, {"FFW_BUILD_DIR": str(self.root)}), patch.object(
                self.boot, "capture_guest", side_effect=synthetic_capture), patch.object(
                self.boot, "cmd_version", return_value="SYNTHETIC; NO QEMU RAN"), patch.object(
                M, "run_runtime", side_effect=changed_source), patch.object(
                self.boot.mkinitramfs, "build", side_effect=competing_archive), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = M.main(args)
        self.assertEqual(len(calls), 0 if mutate in ("runtime", "supervisor") or mode in ("archive-race", "kernel-directory") else 1)
        return result, json.loads(receipt.read_text()) if receipt.exists() else None, logs

    def test_mips_routing_archive_and_receipt_bind_distinct_child_and_supervisor(self):
        result, receipt, logs = self.invoke()
        self.assertEqual(result, 0)
        self.assertEqual(receipt["result"], "passed")
        self.assertNotEqual(receipt["elf"]["sha256"], receipt["supervisor_elf"]["sha256"])
        self.assertIn("NO QEMU RAN", receipt["execution"]["qemu"])
        self.assertEqual((logs / "runtime.serial.log").read_text(), wrapped(fixture()))

    def test_powerpc_argv_matches_boot_machine_cpu_console_and_runtime_contract(self):
        result, receipt, _ = self.invoke("powerpc")
        self.assertEqual(result, 0)
        self.assertEqual(receipt["arch"], "powerpc")

    def test_run_and_analyze_receipts_hash_identical_crlf_capture_bytes(self):
        result, receipt, logs = self.invoke(mode="crlf")
        self.assertEqual(result, 0)
        raw = (logs / "runtime.serial.log").read_bytes()
        self.assertIn(b"\r\n", raw)
        self.assertEqual(receipt["transcript_sha256"], hashlib.sha256(raw).hexdigest())
        analyzed = self.root / "analyzed.json"
        with contextlib.redirect_stdout(io.StringIO()):
            result = M.main(["analyze-runtime", "--arch", "mips", "--elf", str(self.root / "runtime.elf"),
                "--supervisor", str(self.root / "supervisor.elf"), "--log", str(logs / "runtime.serial.log"),
                "--receipt", str(analyzed)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(analyzed.read_text())["transcript_sha256"], receipt["transcript_sha256"])

    def test_nonzero_capture_exit_is_red_even_when_all_stdout_markers_pass(self):
        result, receipt, _ = self.invoke(mode="nonzero")
        self.assertEqual(result, 1)
        self.assertEqual(receipt["execution"]["exit_code"], 7)
        self.assertEqual([g["gate_id"] for g in receipt["gates"] if g["status"] == "failed"], ["P05R-CAPTURE"])

    def test_timeout_returns_red_receipt_and_keeps_raw_partial_transcript(self):
        result, receipt, logs = self.invoke(mode="timeout")
        self.assertEqual(result, 1)
        self.assertEqual(receipt["execution"]["stop_reason"], "timeout")
        self.assertEqual((logs / "runtime.serial.log").read_bytes(), b"partial synthetic boot\n")

    def test_output_overflow_is_bounded_and_recorded_as_failure(self):
        result, receipt, logs = self.invoke(mode="overflow")
        self.assertEqual(result, 1)
        self.assertEqual(receipt["execution"]["stop_reason"], "output_limit")
        self.assertEqual((logs / "runtime.serial.log").stat().st_size, 1024 * 1024)

    def test_runtime_change_between_header_inspection_and_packaging_is_refused(self):
        result, receipt, logs = self.invoke(mutate="runtime")
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertFalse((logs / "runtime.serial.log").exists(), "corrupted input must be refused before launching")

    def test_supervisor_change_between_header_inspection_and_packaging_is_refused(self):
        result, receipt, logs = self.invoke(mutate="supervisor")
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertFalse((logs / "runtime.serial.log").exists())

    def test_kernel_cache_change_does_not_change_the_guest_snapshot(self):
        result, receipt, _ = self.invoke(mutate="kernel-cache")
        self.assertEqual(result, 0)
        self.assertEqual(receipt["execution"]["kernel_sha256"], hashlib.sha256(b"SYNTHETIC KERNEL; NOT EXECUTABLE").hexdigest())

    def test_nonregular_kernel_is_refused_without_a_guest_or_execution_receipt(self):
        result, receipt, logs = self.invoke(mode="kernel-directory")
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertFalse((logs / "vmlinux.runtime-snapshot").exists())
        self.assertFalse((logs / "runtime.serial.log").exists())

    def test_kernel_snapshot_change_during_capture_is_not_a_green_receipt(self):
        result, receipt, _ = self.invoke(mutate="kernel-snapshot")
        self.assertEqual(result, 1)
        self.assertIn("kernel capture input changed", str(receipt["gates"]))

    def test_archive_change_during_capture_is_not_a_green_receipt(self):
        result, receipt, _ = self.invoke(mutate="initramfs")
        self.assertEqual(result, 1)
        self.assertIn("initramfs capture input changed", str(receipt["gates"]))

    def test_competing_archive_created_after_directory_check_is_preserved(self):
        result, receipt, logs = self.invoke(mode="archive-race")
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertEqual((logs / "runtime.cpio.gz").read_bytes(), b"OTHER WRITER'S ARCHIVE; PRESERVE")

    def test_exclusive_builder_preserves_existing_output_and_accepts_a_fresh_one(self):
        init, archive = self.root / "init", self.root / "output.cpio.gz"
        init.write_bytes(b"SYNTHETIC INIT; NOT EXECUTABLE")
        made = self.boot.mkinitramfs.build(init, archive, exclusive=True)
        original = archive.read_bytes()
        self.assertEqual(made["init_sha256"], hashlib.sha256(init.read_bytes()).hexdigest())
        with self.assertRaises(FileExistsError):
            self.boot.mkinitramfs.build(init, archive, exclusive=True)
        self.assertEqual(archive.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
