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

    def invoke(self, arch="mips", mode="normal", mutate=None, writer=None):
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
                self.boot.mkinitramfs, "build", side_effect=competing_archive), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), patch.object(
                M, "write_runtime_receipt", wraps=writer or M.write_runtime_receipt) as spy:
            result = M.main(args)
        self.spy = spy  # the receipt writer as called: call_args[0] is (path, the body BEFORE any rewrite)
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

    # ---- receipt path hygiene: a path outside the repo is written as <outside-repo>/<basename> (the X02 rule) -----------------------
    # The rewrite changes no verdict and proves nothing new about the guest; it only lets a receipt be committed.

    @staticmethod
    def strings(node):
        """Every string in a JSON value, keys included."""
        if isinstance(node, str):
            yield node
        elif isinstance(node, list):
            for item in node:
                yield from RuntimePackagingTests.strings(item)
        elif isinstance(node, dict):
            for key, item in node.items():
                yield from RuntimePackagingTests.strings(key)
                yield from RuntimePackagingTests.strings(item)

    @staticmethod
    def sha_entries(node, where=""):
        """(location, value) of every `*sha256` entry, in order."""
        if isinstance(node, list):
            for index, item in enumerate(node):
                yield from RuntimePackagingTests.sha_entries(item, f"{where}[{index}]")
        elif isinstance(node, dict):
            for key, item in node.items():
                if isinstance(item, (dict, list)):
                    yield from RuntimePackagingTests.sha_entries(item, f"{where}.{key}")
                elif key.endswith("sha256"):
                    yield f"{where}.{key}", item

    def assert_no_host_path(self, receipt):
        """No string anywhere in `receipt` (keys included) holds a host directory or starts with, or contains, an absolute path."""
        hosts = [str(self.root), str(self.root.resolve())]
        if str(Path.home()) not in ("", "/"):
            hosts.append(str(Path.home()))
        absolute = re.compile(r"(?<![A-Za-z0-9_.~<>-])/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+")
        for text in self.strings(receipt):
            for host in hosts:
                self.assertNotIn(host, text, "a host directory survived in the receipt")
            self.assertIsNone(absolute.search(text), "an absolute path survived in the receipt")
            self.assertFalse(text.startswith("/"), "a string in the receipt starts with an absolute path")

    def assert_portable(self, receipt, logs):
        """The receipt-hygiene checks on a receipt that a synthetic run-runtime wrote. Raises AssertionError naming what leaked."""
        self.assert_no_host_path(receipt)
        execution, command = receipt["execution"], receipt["execution"]["command"]
        self.assertEqual(execution["initramfs"]["init_path"], "<outside-repo>/supervisor.elf")
        self.assertEqual(execution["initramfs"]["out_path"], "<outside-repo>/runtime.cpio.gz")
        self.assertEqual(command[command.index("-kernel") + 1], "<outside-repo>/vmlinux.runtime-snapshot")
        self.assertEqual(command[command.index("-initrd") + 1], "<outside-repo>/runtime.cpio.gz")
        # The hashes are the ones of the bytes, and they are the ones the writer was handed: the rewrite touches names only.
        kernel = hashlib.sha256(b"SYNTHETIC KERNEL; NOT EXECUTABLE").hexdigest()
        archive = hashlib.sha256((logs / "runtime.cpio.gz").read_bytes()).hexdigest()
        supervisor = hashlib.sha256((self.root / "supervisor.elf").read_bytes()).hexdigest()
        self.assertEqual(execution["kernel_sha256"], kernel)
        self.assertEqual(execution["initramfs"]["archive_sha256"], archive)
        self.assertEqual(execution["initramfs"]["init_sha256"], supervisor)
        self.assertEqual(receipt["supervisor_elf"]["sha256"], supervisor)
        raw = self.spy.call_args[0][1]
        self.assertIn(str(self.root), json.dumps(raw), "control: the body handed to the writer does carry the host paths")
        before = dict(self.sha_entries(raw))
        self.assertGreaterEqual(len(before), 8)
        self.assertEqual(before, dict(self.sha_entries({k: v for k, v in receipt.items() if k != "path_hashes"})))
        # And each new name is bound to the bytes of the file it replaced.
        bound = {(entry["path"], entry["sha256"]) for entry in receipt["path_hashes"]}
        for name, digest in (("vmlinux.runtime-snapshot", kernel), ("runtime.cpio.gz", archive), ("supervisor.elf", supervisor)):
            self.assertIn((f"<outside-repo>/{name}", digest), bound)

    @staticmethod
    def writer_skipping(field):
        """A copy of the receipt writer that rewrites every path except the value stored under `field`, and does not refuse."""
        def put_back(clean, original):
            if isinstance(clean, dict) and isinstance(original, dict):
                return {key: original[key] if key == field and key in original else put_back(value, original.get(key))
                        for key, value in clean.items()}
            if isinstance(clean, list) and isinstance(original, list) and len(clean) == len(original):
                return [put_back(c, o) for c, o in zip(clean, original)]
            return clean

        def write(path, body):
            with path.open("x", encoding="utf-8") as handle:
                json.dump(put_back(M.scrub_receipt(body), body), handle, indent=2, sort_keys=True)
                handle.write("\n")
        return write

    def fresh_root(self):
        self.root = Path(tempfile.mkdtemp(prefix="ffw-p05-runtime-packing-test-"))

    def test_run_runtime_receipt_has_no_absolute_host_path_and_keeps_every_hash_bound_to_the_new_names(self):
        result, receipt, logs = self.invoke()
        self.assertEqual(result, 0)
        self.assertEqual(self.spy.call_count, 1)
        self.assertFalse(self.root.resolve().is_relative_to(M.REPO.resolve()), "the temp dir must be outside the repo")
        self.assert_portable(receipt, logs)

    def test_a_writer_that_skips_the_rewrite_of_one_field_fails_the_check_and_the_real_writer_passes_it(self):
        for field, leaked in (("init_path", "supervisor.elf"), ("out_path", "runtime.cpio.gz"),
                              ("command", "vmlinux.runtime-snapshot")):
            with self.subTest(skipped=field):
                self.fresh_root()
                result, receipt, logs = self.invoke(writer=self.writer_skipping(field))
                self.assertEqual(result, 0, "the plant changes no verdict")
                with self.assertRaises(AssertionError) as caught:
                    self.assert_portable(receipt, logs)
                self.assertIn(leaked, str(caught.exception), "the check names the field that leaked")
                # Control: remove the plant and the same run, with the real writer, passes the same check.
                self.fresh_root()
                result, receipt, logs = self.invoke()
                self.assertEqual(result, 0)
                self.assert_portable(receipt, logs)

    def test_the_writer_refuses_a_receipt_in_which_a_path_survives_and_writes_nothing(self):
        body = {"execution": {"initramfs": {"init_path": "/Users/someone/work/ffw-hello-init"}}}
        written = self.root / "written.json"
        M.write_runtime_receipt(written, body)
        saved = json.loads(written.read_text())
        self.assertEqual(saved["execution"]["initramfs"]["init_path"], "<outside-repo>/ffw-hello-init")
        self.assertEqual(saved["path_hashes"], [{"path": "<outside-repo>/ffw-hello-init", "sha256": None}])
        refused = self.root / "refused.json"
        with patch.object(M, "scrub_receipt", side_effect=lambda b: {**b, "path_hashes": []}):  # a regressed rewrite
            with self.assertRaises(M.MeasurementError) as caught:
                M.write_runtime_receipt(refused, body)
        self.assertIn("nothing was written", str(caught.exception))
        self.assertIn("under /Users/", str(caught.exception))
        self.assertNotIn("someone", str(caught.exception), "the message names the root, never the path")
        self.assertFalse(refused.exists())
        with self.assertRaises(FileExistsError):
            M.write_runtime_receipt(written, body)  # an existing receipt is never overwritten

    def test_the_rewrite_follows_the_x02_rule_for_every_root_and_every_place_a_path_can_sit(self):
        outside = self.root / "kernel.bin"
        outside.write_bytes(b"BOUND BYTES")
        inside = M.REPO / "toolchain/src/measure-p05-target.py"
        keep = ["rdinit=/init", "/proc/self/task", "src/runtime/builder.rs:3911-3914", "asupersync_460306de:src/runtime/legacy_profile.rs:406",
                7, None, True]
        body = {"a": str(outside), "b": [f"-kernel {outside} -initrd /private/tmp/gone/archive.cpio.gz tail"],
                "/Users/someone/key/other.bin": 1, "n": {"deep": [{"p": str(inside)}]}, "keep": keep}
        clean = M.scrub_receipt(body)
        self.assertEqual(clean["a"], "<outside-repo>/kernel.bin")
        self.assertEqual(clean["b"], ["-kernel <outside-repo>/kernel.bin -initrd <outside-repo>/archive.cpio.gz tail"])
        self.assertEqual(clean["<outside-repo>/other.bin"], 1, "a path used as a key is rewritten too")
        self.assertEqual(clean["n"]["deep"][0]["p"], "toolchain/src/measure-p05-target.py", "under the repo: repo-relative")
        self.assertEqual(clean["keep"], keep, "guest paths, relative paths and non-strings are left alone")
        bound = {(entry["path"], entry["sha256"]) for entry in clean["path_hashes"]}
        self.assertIn(("<outside-repo>/kernel.bin", hashlib.sha256(b"BOUND BYTES").hexdigest()), bound)
        self.assertIn(("<outside-repo>/archive.cpio.gz", None), bound)
        self.assertIn(("toolchain/src/measure-p05-target.py", hashlib.sha256(inside.read_bytes()).hexdigest()), bound)
        for root in ("Users", "home", "private", "var", "tmp", "root", "Volumes", "mnt", "srv", "data", "bulk"):
            with self.subTest(root=root):
                self.assertEqual(M.scrub_receipt({"p": f"/{root}/a/b.bin"})["p"], "<outside-repo>/b.bin")

    def test_analyze_runtime_writes_through_the_same_writer_and_its_receipt_is_portable(self):
        result, _, logs = self.invoke()
        self.assertEqual(result, 0)
        analyzed = self.root / "analyzed.json"
        with patch.object(M, "write_runtime_receipt", wraps=M.write_runtime_receipt) as spy, contextlib.redirect_stdout(io.StringIO()):
            result = M.main(["analyze-runtime", "--arch", "mips", "--elf", str(self.root / "runtime.elf"),
                "--supervisor", str(self.root / "supervisor.elf"), "--log", str(logs / "runtime.serial.log"),
                "--receipt", str(analyzed)])
        self.assertEqual(result, 0)
        self.assertEqual(spy.call_count, 1, "analyze-runtime has no writer of its own")
        saved = json.loads(analyzed.read_text())
        self.assertEqual(saved["evidence_kind"], "supplied_transcript_analysis")
        self.assertEqual(saved["path_hashes"], [], "an analysis names no host path")
        self.assert_no_host_path(saved)

    def written_or_refused(self, body):
        """What `write_runtime_receipt` does with `body`: the receipt it wrote, or the refusal (nothing is written then)."""
        out = self.root / f"receipt-{len(list(self.root.iterdir()))}.json"
        try:
            M.write_runtime_receipt(out, body)
        except M.MeasurementError as refusal:
            self.assertFalse(out.exists(), "a refused receipt leaves no file")
            self.assertIn("nothing was written", str(refusal))
            return str(refusal)
        return json.loads(out.read_text())

    def test_the_writer_never_writes_an_absolute_host_path_whatever_its_first_directory(self):
        # Rewritten: more host roots than the X02 list names. Before this, each of these was written into the receipt as it was.
        for root in ("opt", "usr", "Library", "Applications", "System", "nix", "run", "media", "net", "export", "workspace", "work",
                     "builds"):
            with self.subTest(root=root):
                saved = self.written_or_refused({"p": f"/{root}/someone/tree/qemu-system-mips"})
                self.assertEqual(saved["p"], "<outside-repo>/qemu-system-mips")
        # Refused: a root nobody listed. The rewrite cannot bind it to a file, so the receipt is not written.
        for text in ("/etc/ssh/config", "/zzz/someone/tree/kernel.bin", "-kernel /lost-and-found/a/b.bin tail"):
            with self.subTest(text=text):
                refusal = self.written_or_refused({"p": text})
                self.assertIsInstance(refusal, str, "an absolute path under an unlisted root must be refused")
                self.assertIn("an absolute path under /", refusal)
                self.assertNotIn("someone", refusal, "the message names the root, never the path")
        # Control: what the guest prints, the rewritten labels and a URL are not host paths, and are written as they are.
        keep = {"p": "rdinit=/init", "proc": "/proc/self/task", "dev": "/dev/ttyS0", "label": "<outside-repo>/init",
                "url": "https://example.invalid/some/where", "relative": "toolchain/results/p05/x.json", "ratio": "workers=1/1"}
        self.assertEqual({k: v for k, v in self.written_or_refused(keep).items() if k != "path_hashes"}, keep)

    def test_the_writer_refuses_a_relative_path_that_leaves_the_repository(self):
        # `--log-dir ../out/run` puts `../out/run/vmlinux.runtime-snapshot` on the QEMU command line, and no absolute path is in it.
        for text in ["../out/run/vmlinux.runtime-snapshot", "../../private-sibling/archive.cpio.gz", "../.."]:
            with self.subTest(text=text):
                refusal = self.written_or_refused({"execution": {"command": ["qemu-system-mips", "-kernel", text]}})
                self.assertIsInstance(refusal, str, "a relative path that leaves the repository must be refused")
                self.assertIn("relative path that leaves the repository", refusal)
                self.assertNotIn("out/run", refusal, "the message does not repeat the path")
        refusal = self.written_or_refused({"c": "-initrd ../a/b.cpio.gz tail"})
        self.assertIsInstance(refusal, str)
        # Control: a relative path that stays under its directory, or only mentions two dots, is written as it is.
        keep = {"a": "toolchain/results/p05/x.json", "b": "src/../x", "c": "./out/run/archive.cpio.gz", "d": "wait... what", "e": "a..b"}
        self.assertEqual({k: v for k, v in self.written_or_refused(keep).items() if k != "path_hashes"}, keep)

    def test_two_different_files_with_one_basename_do_not_share_one_name_in_the_receipt(self):
        first, second = self.root / "one", self.root / "two"
        first.mkdir()
        second.mkdir()
        (first / "ffw-hello-init").write_bytes(b"AAAA")
        (second / "ffw-hello-init").write_bytes(b"BBBB")
        (first / "kernel.bin").write_bytes(b"KKKK")
        # Plant: both would be `<outside-repo>/ffw-hello-init`, with two different hashes; the name could not say which is which.
        refusal = self.written_or_refused({"supervisor": str(first / "ffw-hello-init"), "probe": str(second / "ffw-hello-init")})
        self.assertIsInstance(refusal, str, "two different files under one new name must be refused")
        self.assertIn("two different files would both be named <outside-repo>/ffw-hello-init", refusal)
        # A path that does not exist and one that does, under one name, are as ambiguous.
        refusal = self.written_or_refused({"a": str(first / "ffw-hello-init"), "b": str(self.root / "gone" / "ffw-hello-init")})
        self.assertIsInstance(refusal, str)
        # Control: the same file named twice, and two files with two basenames, are written, each bound to its own bytes.
        saved = self.written_or_refused({"a": str(first / "ffw-hello-init"), "b": f"-initrd {first / 'ffw-hello-init'}",
                                         "c": str(first / "kernel.bin")})
        self.assertEqual(saved["a"], "<outside-repo>/ffw-hello-init")
        self.assertEqual(sorted((e["path"], e["sha256"]) for e in saved["path_hashes"]),
                         sorted([("<outside-repo>/ffw-hello-init", hashlib.sha256(b"AAAA").hexdigest()),
                                 ("<outside-repo>/kernel.bin", hashlib.sha256(b"KKKK").hexdigest())]))

    def test_two_keys_that_the_rewrite_would_make_one_are_refused_and_not_silently_merged(self):
        refusal = self.written_or_refused({"/tmp/one/x.bin": 1, "/var/two/x.bin": 2})
        self.assertIsInstance(refusal, str, "the second entry must not overwrite the first")
        self.assertIn("would both be keyed '<outside-repo>/x.bin'", refusal)
        # Control: the same value under both spellings loses nothing, and distinct names stay distinct.
        saved = self.written_or_refused({"/tmp/one/x.bin": 1, "/var/two/x.bin": 1, "/tmp/one/y.bin": 2})
        self.assertEqual({k: v for k, v in saved.items() if k != "path_hashes"}, {"<outside-repo>/x.bin": 1, "<outside-repo>/y.bin": 2})


# ---- the single-owner profile (the probe's second run: one scheduler worker through LegacyProfile) -----------------------------

SO = M.RUNTIME_SINGLE_OWNER
DECLARED = "CALLER_DRIVEN_CURRENT_THREAD"
DEFAULT_APPEND = {"mips": "console=ttyS0,38400 rdinit=/init panic=-1", "powerpc": "console=ttyPZ0,38400 rdinit=/init panic=-1"}


# What the probe prints on the two census rows that follow a runtime drop (this fixture's start row has 4 threads).
SETTLE_ROWS = ("after_runtime_drop", "after_byte_budget")
SETTLE_PAIRS = {"after_runtime_drop": " settle=settled settle_threads=4 settle_polls=1",
                "after_byte_budget": " settle=settled settle_threads=4 settle_polls=3"}


def single_owner_fixture(arch="mips", *, cleanup=True, settle=True):
    """Handwritten row-by-row single-owner transcript. Deliberately not built from the judge's expected-order tables.
    `settle=False` is the shape a probe built before the settle printed: the same rows without the settle pairs."""
    def c(phase):
        return (f"FFW_P05_RUNTIME:CENSUS status=ok phase={phase} threads_task_dir_before=4 threads_task_dir_after=4 "
                "task_dir_stable=true threads_status=4 sources_agree=true vm_rss_kb=5000 vm_hwm_kb=6000 mem_available_kb=9000"
                + (SETTLE_PAIRS.get(phase, "") if settle else ""))

    bits, endian = (64, "little") if arch == "x86_64" else (32, "big")
    drain = ("outcome=Quiescent expected_outcome=Quiescent live_tasks=0 pending_obligations=0 live_regions=0 "
             "expected_live_regions=0 queued_finalizers=0 pending_spawns=0 pending_obligation_posts=false")
    abort_cleanup = " cleanup_resumed=1 cleanup_unique=1 cleanup_cancelled=1 cleanup_before_deadline=1" if cleanup else ""
    drain_cleanup = " cleanup_resumed=4 cleanup_unique=4 cleanup_cancelled=4 cleanup_before_deadline=4" if cleanup else ""
    return "\n".join([
        f"FFW_P05_RUNTIME:BEGIN status=start pid=17 arch={arch} endian={endian} pointer_bits={bits} threads_available_to_std=1 topology=single_owner",
        c("start"),
        "FFW_P05_RUNTIME:SINGLE_OWNER_PROFILE status=ok claimed=single_owner stated_worker_threads=1 required_worker_threads=1",
        "FFW_P05_RUNTIME:PROFILE_ACCEPT status=ok violations=0 worst_case_stack_bytes=1572864 budget=1572864",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_ZERO_WORKERS status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_UNBOUNDED_QUEUE status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:PROFILE_REFUSES_OVER_BUDGET status=ok named_violation=true builder_refused=true",
        "FFW_P05_RUNTIME:REACTOR status=ok kind=platform",
        "FFW_P05_RUNTIME:RUNTIME_AUDIT status=ok audit_ok=true workers=1/1 blocking_threads=1/1 global_queue=256/256 blocking_queue=1/1 (carried/stated)",
        c("after_build"),
        "FFW_P05_RUNTIME:SINGLE_OWNER_RUNTIME status=ok carried_workers=1 stated_workers=1 audit_ok=true children_joined=8 task_threads=1 tasks_on_caller_thread=false",
        "FFW_P05_RUNTIME:CALLER_DRIVEN_CURRENT_THREAD status=unsupported reason=profile_builder_cannot_build_caller_driven_mode reason_source=static_source_reading evidence=asupersync_460306de:src/runtime/legacy_profile.rs:406,src/runtime/builder.rs:3911-3914 observed_tasks_on_caller_thread=false",
        c("after_single_owner_threads"),
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
        "FFW_P05_RUNTIME:SINGLE_OWNER_BLOCKING_OFFLOAD status=ok held_admitted=true held_started=true async_phase=ok held_job_unfinished_during_async=true held_job_finished_after_release=true async_detail=(children=8 joined=8 sum=140 expected=140)",
        c("after_blocking_offload"),
        "FFW_P05_RUNTIME:DRAIN status=ok tasks_spawned=4/4 tasks_parked_before_drain=4 snapshot_before_drain=(admitted=4 unfinished=4 timers_pending=4) " + drain + " elapsed_ms=2 bound_ms=5000" + drain_cleanup + " repeat: " + drain,
        c("after_drain"), c("after_runtime_drop"),
        "FFW_P05_RUNTIME:BYTE_BUDGET_REFUSAL status=ok audit_ok=true policy=BoundedBytes { max_queued: 1, max_live_bytes: 4096 } reactor=none budget_bytes=4096 declared_heap_bytes=4097 refusal=Some(ChargeTooLarge) expected_refusal=Some(ChargeTooLarge) pool_threads_after_refusal=0 refused_job_ran=false",
        "FFW_P05_RUNTIME:FIRST_USE_BACKGROUND status=ok pool_threads_before_first_job=0 pool_threads_while_job_runs=1 job_started=true job_finished=true os_threads_before=4 os_threads_during=5",
        "FFW_P05_RUNTIME:RUNTIME_USABLE_AFTER_REFUSAL status=ok spawn_join=ok " + drain,
        c("after_byte_budget"),
        "FFW_P05_RUNTIME:END status=done ops=33 ok=32 failed=0 unsupported=1 partial=0 unknown=0 census_samples=13",
    ]) + "\n"


def wrapped_single_owner(child, arch="mips", *, status=0, summary="FFW_MARKER:TEST_SUCCESS failures=0"):
    """The unchanged supervisor's view of the single-owner child. The probe exits 0 for exactly its one declared unsupported
    row, so this is the ordinary view (status=0, TEST_SUCCESS); `status` and `summary` exist only to plant deviations, such as the
    old exit-2 accounting (status=2, TEST_FAILURE failures=1), which this profile must refuse."""
    base = serial_fixture.POSITIVE
    if arch == "powerpc":
        base = base.replace("arch=mips-be", "arch=powerpc-be").replace("mips-unknown", "powerpc-unknown")
        base = base.replace("errno=89", "errno=38")
    data = child.encode()
    region = ("FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog\n" + child +
              f"FFW_SPEAKER_EXIT status={status} stdout_bytes={len(data)} stdout_fnv1a64={fnv(data):016x}\n")
    return base.replace("FFW_MARKER:TEST_SUCCESS failures=0", region + summary)


class SingleOwnerTranscriptTests(unittest.TestCase):
    def judge(self, text, arch="mips", supervised=False):
        return M.judge_runtime(text, arch, {"arch": arch}, supervised=supervised, profile=SO)

    @staticmethod
    def failed(report):
        return {g.gate_id for g in report["gates"] if g.status == "failed"}

    def test_exact_complete_fixture_is_accepted_with_one_declared_unsupported_row_for_each_architecture(self):
        for arch in ("mips", "powerpc", "x86_64"):
            with self.subTest(arch=arch):
                report = self.judge(single_owner_fixture(arch), arch)
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["observed_statuses"], dict(ok=32, failed=0, unsupported=1, partial=0, unknown=0))
                self.assertEqual(report["declared_unsupported"], [DECLARED])
                self.assertEqual(report["profile"], SO)
                self.assertIn("P05R-DECLARED", [g.gate_id for g in report["gates"]])

    def test_the_two_profiles_refuse_each_others_transcripts(self):
        single, threaded = single_owner_fixture(), fixture()
        plain = lambda text: M.judge_runtime(text, "mips", {"arch": "mips"})["ok"]  # noqa: E731 - the default profile
        self.assertTrue(plain(threaded))
        self.assertTrue(self.judge(single)["ok"])
        self.assertFalse(plain(single))
        self.assertFalse(M.judge_runtime(single, "mips", {"arch": "mips"}, profile=M.RUNTIME_THREADED)["ok"])
        self.assertFalse(self.judge(threaded)["ok"])
        # A topology claim can be neither added to the threaded run nor removed from the single-owner one.
        self.assertFalse(plain(threaded.replace("threads_available_to_std=1", "threads_available_to_std=1 topology=single_owner", 1)))
        self.assertFalse(self.judge(single.replace(" topology=single_owner", "", 1))["ok"])
        self.assertFalse(self.judge(single.replace("topology=single_owner", "topology=threaded", 1))["ok"])

    def test_an_ok_caller_driven_row_is_refused_and_so_is_every_other_non_unsupported_status(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"])
        for status in ("ok", "failed", "partial", "unknown"):
            with self.subTest(status=status):
                report = self.judge(good.replace(f"{DECLARED} status=unsupported", f"{DECLARED} status={status}"))
                self.assertFalse(report["ok"])
                self.assertIn("P05R-PHASES", self.failed(report))
                self.assertEqual(M.exit_code(report), 1)

    def test_workers_two_over_two_is_refused_wherever_the_count_appears(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"])
        for old, new in (
            ("workers=1/1", "workers=2/2"),
            ("carried_workers=1", "carried_workers=2"),
            ("stated_workers=1", "stated_workers=2"),
            ("stated_worker_threads=1", "stated_worker_threads=2"),
            ("worst_case_stack_bytes=1572864 budget=1572864", "worst_case_stack_bytes=2621440 budget=2621440"),
            ("task_threads=1", "task_threads=2"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(good.replace(old, new, 1))["ok"])

    def test_every_row_is_required_exactly_once_and_no_adjacent_pair_may_swap(self):
        good = single_owner_fixture().splitlines(keepends=True)
        self.assertEqual(len(good), 35)
        self.assertTrue(self.judge("".join(good))["ok"])
        for index in range(len(good)):
            with self.subTest(missing=index):
                self.assertFalse(self.judge("".join(good[:index] + good[index + 1:]))["ok"])
            with self.subTest(duplicate=index):
                self.assertFalse(self.judge("".join(good[:index] + [good[index]] + good[index:]))["ok"])
        for index in range(len(good) - 1):
            changed = good.copy()
            changed[index:index + 2] = reversed(changed[index:index + 2])
            with self.subTest(swap=index):
                self.assertFalse(self.judge("".join(changed))["ok"])

    def test_exit_two_caused_by_a_different_unsupported_row_is_refused(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"])
        both = good.replace("UDP_LOOPBACK status=ok", "UDP_LOOPBACK status=unsupported").replace(
            "ok=32 failed=0 unsupported=1", "ok=31 failed=0 unsupported=2")
        swapped = good.replace(f"{DECLARED} status=unsupported", f"{DECLARED} status=ok").replace(
            "UDP_LOOPBACK status=ok", "UDP_LOOPBACK status=unsupported")
        for name, text in (("declared plus a second unsupported row", both), ("a different row instead of the declared one", swapped)):
            with self.subTest(case=name):
                report = self.judge(text)
                self.assertFalse(report["ok"])
                self.assertTrue({"P05R-PHASES", "P05R-DECLARED"} <= self.failed(report), self.failed(report))

    def test_required_fields_of_the_new_rows_cannot_be_missing_or_contradicted(self):
        required = {
            "SINGLE_OWNER_PROFILE": "claimed stated_worker_threads required_worker_threads",
            "SINGLE_OWNER_RUNTIME": "carried_workers stated_workers audit_ok children_joined task_threads tasks_on_caller_thread",
            DECLARED: "reason reason_source evidence observed_tasks_on_caller_thread",
            "SINGLE_OWNER_BLOCKING_OFFLOAD": "held_admitted held_started async_phase held_job_unfinished_during_async held_job_finished_after_release",
            "BYTE_BUDGET_REFUSAL": "audit_ok policy reactor budget_bytes declared_heap_bytes refusal expected_refusal pool_threads_after_refusal refused_job_ran",
            "FIRST_USE_BACKGROUND": "pool_threads_before_first_job pool_threads_while_job_runs job_started job_finished os_threads_before os_threads_during",
            "RUNTIME_USABLE_AFTER_REFUSAL": "spawn_join outcome live_tasks pending_obligations live_regions queued_finalizers pending_spawns pending_obligation_posts",
        }
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"])
        for name, keys in required.items():
            original = next(line for line in good.splitlines() if line.startswith(f"FFW_P05_RUNTIME:{name} "))
            for key in keys.split():
                token = re.search(r"\b" + key + r"=\S+", original)[0]
                for replacement in ("", key + "=contradiction"):
                    with self.subTest(name=name, key=key, replacement=replacement):
                        self.assertFalse(self.judge(good.replace(original, original.replace(token, replacement, 1)))["ok"])

    def test_first_use_needs_a_visible_os_thread_and_the_offload_needs_all_eight_children(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good.replace("os_threads_during=5", "os_threads_during=6"))["ok"])
        for planted in ("os_threads_during=4", "os_threads_during=3"):
            with self.subTest(planted=planted):
                self.assertFalse(self.judge(good.replace("os_threads_during=5", planted))["ok"])
        offload = "async_detail=(children=8 joined=8 sum=140 expected=140)"
        self.assertTrue(offload in good)
        for planted in ("async_detail=(children=8 joined=7 sum=140 expected=140)", "async_detail=(children=8 joined=8 sum=139 expected=140)"):
            with self.subTest(planted=planted):
                self.assertFalse(self.judge(good.replace(offload, planted))["ok"])

    def test_cleanup_and_census_checks_still_apply_in_the_single_owner_profile(self):
        good = single_owner_fixture()
        legacy = self.judge(single_owner_fixture(cleanup=False))
        self.assertFalse(legacy["ok"])
        self.assertEqual(M.exit_code(legacy), 3)
        for wanted in (1, 4):
            for key in ("cleanup_resumed", "cleanup_unique", "cleanup_cancelled", "cleanup_before_deadline"):
                with self.subTest(wanted=wanted, field=key):
                    report = self.judge(good.replace(f"{key}={wanted}", f"{key}=0", 1))
                    self.assertFalse(report["ok"])
                    self.assertEqual(M.exit_code(report), 1)
        for old, new in (
            ("phase=after_byte_budget", "phase=after_drain"),
            ("phase=after_single_owner_threads", "phase=after_build"),
            ("threads_status=4", "threads_status=0"),
            ("task_dir_stable=true", "task_dir_stable=false"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.judge(good.replace(old, new, 1))["ok"])

    def test_no_failed_partial_unsupported_or_unknown_row_can_hide_in_the_single_owner_profile(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"])
        for status in ("failed", "unsupported", "partial", "unknown"):
            for name in M.SINGLE_OWNER_PHASES:
                if name == DECLARED:
                    continue
                with self.subTest(status=status, name=name):
                    text = good.replace(f"{name} status=ok", f"{name} status={status}")
                    self.assertNotEqual(text, good)
                    report = self.judge(text)
                    self.assertFalse(report["ok"])
                    # The END totals also give a changed row away, so assert the per-row gate itself caught it.
                    self.assertIn("P05R-PHASES", self.failed(report))

    def test_an_unknown_profile_is_an_error_and_never_a_pass(self):
        with self.assertRaises(M.MeasurementError):
            M.judge_runtime(single_owner_fixture(), "mips", {"arch": "mips"}, profile="threadless")


def census_line(text, phase):
    return next(line for line in text.splitlines()
                if line.startswith("FFW_P05_RUNTIME:CENSUS ") and f" phase={phase} " in line)


class SingleOwnerSettleTests(unittest.TestCase):
    """The settle pairs that the single-owner probe prints on the census rows after each runtime drop are judged, not read past.

    Every plant edits one row, is refused by the census gate alone and for a named reason, and is accepted again once the edit is
    reverted. The threaded profile is judged as before."""

    def judge(self, text, arch="mips"):
        return M.judge_runtime(text, arch, {"arch": arch}, profile=SO)

    @staticmethod
    def failed(report):
        return {g.gate_id for g in report["gates"] if g.status == "failed"}

    @staticmethod
    def census_detail(report):
        return next(g.detail for g in report["gates"] if g.gate_id == "P05R-CENSUS")

    def planted(self, good, phase, old, new):
        """The transcript with `old` replaced by `new` on the census row of `phase`, and that row before and after."""
        line = census_line(good, phase)
        self.assertIn(old, line)
        changed = line.replace(old, new, 1)
        return good.replace(line, changed), changed, line

    COUNTS = "threads_task_dir_before=4 threads_task_dir_after=4 task_dir_stable=true threads_status=4"

    def counts(self, good, *, start, rows, settle_threads=None):
        """`good` with the thread count of the start row, of the two rows after a drop, and (if given) their `settle_threads`."""
        text = good
        for phase, count in (("start", start), *((phase, rows) for phase in SETTLE_ROWS)):
            line = census_line(text, phase)
            self.assertIn(self.COUNTS, line)
            text = text.replace(line, line.replace(self.COUNTS, self.COUNTS.replace("=4", f"={count}")))
        if settle_threads is not None:
            text = text.replace("settle_threads=4", f"settle_threads={settle_threads}")
        return text

    def plants(self):
        out = []
        for phase in SETTLE_ROWS:
            pairs = SETTLE_PAIRS[phase]
            polls = pairs.rsplit("=", 1)[1]
            out += [
                (f"F1: {phase} shows 5 stable threads, above the start count", phase, self.COUNTS,
                 self.COUNTS.replace("=4", "=5"), f"{phase}: the row shows 5 threads, above the start count 4"),
                (f"a: {phase} is ok but pending", phase, "settle=settled", "settle=pending",
                 f"{phase}: status=ok contradicts settle=pending"),
                (f"a: {phase} is ok but unmeasured", phase, pairs, " settle=unmeasured",
                 f"{phase}: status=ok contradicts settle=unmeasured"),
                (f"b: {phase} settle_threads above the start count", phase, "settle_threads=4", "settle_threads=5",
                 f"{phase}: settle_threads=5 is above the start count 4"),
                (f"c: {phase} has no settle pairs", phase, pairs, "",
                 f"{phase}: the settle pairs are missing (settle, settle_threads, settle_polls)"),
                (f"c: {phase} lacks the word", phase, " settle=settled", "",
                 f"{phase}: the settle pairs are missing (settle)"),
                (f"c: {phase} lacks settle_threads", phase, " settle_threads=4", "",
                 f"{phase}: settle=settled without settle_threads"),
                (f"c: {phase} lacks settle_polls", phase, f" settle_polls={polls}", "",
                 f"{phase}: settle=settled without settle_polls"),
                (f"d: {phase} settled after zero polls", phase, f"settle_polls={polls}", "settle_polls=0",
                 f"{phase}: settle_polls=0 is not at least 1"),
                (f"d: {phase} polls is not a canonical count", phase, f"settle_polls={polls}", "settle_polls=01",
                 f"{phase}: settle_polls=01 is not at least 1"),
                (f"{phase} settle_threads is not a count", phase, "settle_threads=4", "settle_threads=four",
                 f"{phase}: settle_threads=four is not a count"),
                (f"e: {phase} settle_threads is zero", phase, "settle_threads=4", "settle_threads=0",
                 f"{phase}: settle_threads=0 is impossible: a running process has at least one thread"),
            ]
        return out

    def test_settled_pairs_within_the_start_count_are_accepted(self):
        good = single_owner_fixture()
        for phase in SETTLE_ROWS:
            self.assertIn(SETTLE_PAIRS[phase], good)
        for arch in ("mips", "powerpc", "x86_64"):
            with self.subTest(arch=arch):
                self.assertTrue(self.judge(single_owner_fixture(arch), arch)["ok"])
        # Any count from 1 up to the start count, and any number of polls from 1 up to the probe's bound of 1000.
        for threads, polls in ((4, 1), (3, 2), (1, 1), (1, 1000), (4, 1000)):
            for phase in SETTLE_ROWS:
                text, _, _ = self.planted(
                    good, phase, SETTLE_PAIRS[phase], f" settle=settled settle_threads={threads} settle_polls={polls}")
                with self.subTest(phase=phase, threads=threads, polls=polls):
                    report = self.judge(text)
                    self.assertTrue(report["ok"], self.census_detail(report))
        # The ceiling is this run's own start row, not a constant. The two rows after a drop show the start count here (so a row count
        # equal to the start count is accepted), and only `settle_threads` moves against it.
        for count, threads, accepted in ((4, 4, True), (2, 2, True), (6, 6, True), (2, 4, False), (3, 4, False), (6, 7, False)):
            text = self.counts(good, start=count, rows=count, settle_threads=threads)
            with self.subTest(start_threads=count, settle_threads=threads):
                report = self.judge(text)
                self.assertEqual(report["ok"], accepted, self.census_detail(report))
                if not accepted:
                    self.assertEqual(self.failed(report), {"P05R-CENSUS"})
                    self.assertIn(f"settle_threads={threads} is above the start count {count}", self.census_detail(report))

    def test_a_row_that_shows_more_threads_than_the_start_is_refused_whatever_the_pairs_claim(self):
        # The leak shape: start 1, the row shows 2 stable threads, and the pairs still say settled at 1.
        control = self.counts(single_owner_fixture(), start=1, rows=1, settle_threads=1)
        self.assertTrue(self.judge(control)["ok"], "control: the row at the start count")
        for phase in SETTLE_ROWS:
            with self.subTest(phase=phase):
                text, changed, original = self.planted(
                    control, phase, self.COUNTS.replace("=4", "=1"), self.COUNTS.replace("=4", "=2"))
                self.assertIn(" settle=settled settle_threads=1 ", changed)
                report = self.judge(text)
                self.assertFalse(report["ok"])
                self.assertEqual(self.failed(report), {"P05R-CENSUS"})
                self.assertEqual(self.census_detail(report), f"{phase}: the row shows 2 threads, above the start count 1")
                self.assertEqual(M.exit_code(report), 1)
                self.assertTrue(self.judge(text.replace(changed, original))["ok"], "the plant removed")
        # Threads that left after the settle reading make the row count LOWER than settle_threads: harmless, accepted. So is a row
        # count equal to the start count (the default fixture, and start 2 with rows at 2).
        for rows, threads in ((1, 3), (1, 4), (3, 4), (4, 4)):
            with self.subTest(start=4, rows=rows, settle_threads=threads):
                self.assertTrue(self.judge(self.counts(single_owner_fixture(), start=4, rows=rows, settle_threads=threads))["ok"])
        self.assertTrue(self.judge(self.counts(single_owner_fixture(), start=2, rows=2, settle_threads=2))["ok"])
        # A row whose own count moved during its reading is the census gate's business (it is refused there), not a second report
        # from this rule: only a STABLE count above the start count is reported as "the row shows".
        good = single_owner_fixture()
        moved = self.COUNTS.replace("before=4", "before=5")
        text, _, _ = self.planted(good, "after_byte_budget", self.COUNTS, moved)
        report = self.judge(text)
        self.assertFalse(report["ok"])
        self.assertIn("after_byte_budget: inconsistent thread or memory readings", self.census_detail(report))
        self.assertNotIn("the row shows", self.census_detail(report))

    def test_a_start_row_without_a_stable_positive_thread_count_gives_the_rule_nothing_to_compare_with(self):
        good = single_owner_fixture()
        start = census_line(good, "start")
        for label, moved in (
            ("zero threads", "threads_task_dir_before=0 threads_task_dir_after=0 task_dir_stable=true threads_status=0"),
            ("before and after differ", "threads_task_dir_before=3 threads_task_dir_after=4 task_dir_stable=true threads_status=4"),
            ("the status count differs", "threads_task_dir_before=4 threads_task_dir_after=4 task_dir_stable=true threads_status=3"),
        ):
            with self.subTest(start=label):
                text = good.replace(start, start.replace(self.COUNTS, moved))
                self.assertNotEqual(text, good)
                report = self.judge(text)
                self.assertFalse(report["ok"])
                detail = self.census_detail(report)
                for phase in SETTLE_ROWS:
                    self.assertIn(f"{phase}: the start row has no stable thread count to compare settle_threads with", detail)
                self.assertNotIn("above the start count", detail)
        self.assertTrue(self.judge(good)["ok"], "control")

    def test_each_planted_deviation_is_refused_for_its_reason_and_accepted_again_when_removed(self):
        good = single_owner_fixture()
        self.assertTrue(self.judge(good)["ok"], "control")
        plants = self.plants()
        self.assertEqual(len(plants), 24)
        for label, phase, old, new, reason in plants:
            with self.subTest(plant=label):
                text, changed, original = self.planted(good, phase, old, new)
                self.assertNotEqual(text, good)
                report = self.judge(text)
                self.assertFalse(report["ok"])
                self.assertEqual(self.failed(report), {"P05R-CENSUS"})
                self.assertIn(reason, self.census_detail(report))
                self.assertEqual(M.exit_code(report), 1)
                restored = text.replace(changed, original)
                self.assertEqual(restored, good)
                self.assertTrue(self.judge(restored)["ok"], "the plant removed")

    def test_a_transcript_from_a_probe_built_before_the_settle_is_refused_and_never_read_as_settled(self):
        before = single_owner_fixture(settle=False)
        self.assertFalse(any("settle" in line for line in before.splitlines()))
        report = self.judge(before)
        self.assertFalse(report["ok"])
        self.assertEqual(self.failed(report), {"P05R-CENSUS"})
        self.assertEqual(M.exit_code(report), 1)
        for phase in SETTLE_ROWS:
            self.assertIn(f"{phase}: the settle pairs are missing", self.census_detail(report))
        for arch in ("mips", "powerpc", "x86_64"):
            with self.subTest(arch=arch):
                self.assertFalse(self.judge(single_owner_fixture(arch, settle=False), arch)["ok"])
                self.assertTrue(self.judge(single_owner_fixture(arch), arch)["ok"], "control: the pairs the probe now prints")

    def test_the_row_the_probe_prints_for_a_thread_that_never_left_is_refused_by_two_gates(self):
        good = single_owner_fixture()
        leak = ("FFW_P05_RUNTIME:CENSUS status=failed phase=after_byte_budget threads_task_dir_before=5 threads_task_dir_after=5 "
                "task_dir_stable=true threads_status=5 sources_agree=true vm_rss_kb=5000 vm_hwm_kb=6000 mem_available_kb=9000 "
                "settle=pending settle_threads=5 settle_polls=1000 reason=threads_not_released_after_runtime_drop")
        text = good.replace(census_line(good, "after_byte_budget"), leak).replace("ok=32 failed=0", "ok=31 failed=1")
        report = self.judge(text)
        self.assertFalse(report["ok"])
        # The END tallies give a failed row away as well; the two per-row gates are the ones this test is about.
        self.assertLessEqual({"P05R-PHASES", "P05R-CENSUS"}, self.failed(report))
        self.assertIn("after_byte_budget: settle=pending is not settled", self.census_detail(report))

    def test_the_gate_title_names_the_settle_for_single_owner_only_and_the_threaded_profile_is_judged_as_before(self):
        title = lambda report: next(g.title for g in report["gates"] if g.gate_id == "P05R-CENSUS")  # noqa: E731
        single = self.judge(single_owner_fixture())
        self.assertEqual(title(single), "thirteen complete, consistent census samples, each runtime drop settled")
        threaded = fixture()
        plain = lambda text: M.judge_runtime(text, "mips", {"arch": "mips"})  # noqa: E731 - the default profile
        self.assertTrue(plain(threaded)["ok"])
        self.assertEqual(title(plain(threaded)), "ten complete, consistent census samples")
        # The probe's threaded run now prints the pairs on its after_runtime_drop row too; that row is accepted with them.
        line = census_line(threaded, "after_runtime_drop")
        settled = threaded.replace(line, line + " settle=settled settle_threads=4 settle_polls=2")
        self.assertTrue(plain(settled)["ok"])
        # Scope, stated by the assignment (16286): the rule reads the single-owner profile only. The threaded settle word is not
        # judged, exactly as before this rule; this line pins that boundary and is not an endorsement of it.
        pending = threaded.replace(line, line + " settle=pending settle_threads=9 settle_polls=1000")
        self.assertTrue(plain(pending)["ok"])


class SingleOwnerEnvelopeTests(unittest.TestCase):
    """The single-owner profile uses the UNMODIFIED standard supervisor envelope: status=0 and TEST_SUCCESS, nothing rewritten."""
    def verdict(self, text, arch="mips", profile=SO):
        child, gates = M.runtime_envelope(text, arch)
        report = M.judge_runtime(child, arch, {"arch": arch}, supervised=True, profile=profile)
        return all(g.status == "passed" for g in gates) and report["ok"]

    def test_unchanged_bootstrap_supervises_the_single_owner_child_for_both_be_targets(self):
        for arch in ("mips", "powerpc"):
            with self.subTest(arch=arch):
                self.assertTrue(self.verdict(wrapped_single_owner(single_owner_fixture(arch), arch), arch))

    def test_each_profile_accepts_its_own_supervised_transcript_and_refuses_the_others(self):
        single, threaded = wrapped_single_owner(single_owner_fixture()), wrapped(fixture())
        self.assertTrue(self.verdict(single, profile=SO))
        self.assertTrue(self.verdict(threaded, profile=M.RUNTIME_THREADED))
        self.assertFalse(self.verdict(single, profile=M.RUNTIME_THREADED))
        self.assertFalse(self.verdict(threaded, profile=SO))

    def test_exit_two_or_a_failure_summary_is_a_fail_for_the_single_owner_profile(self):
        """Planted negatives. There is no accepted non-zero child exit: the old exit-2 accounting is red, in every form."""
        child = single_owner_fixture()
        good = wrapped_single_owner(child)
        self.assertTrue(self.verdict(good), "control: the ordinary supervisor view of the single-owner child")
        plants = {
            "the old accounting: status=2 with TEST_FAILURE failures=1":
                wrapped_single_owner(child, status=2, summary="FFW_MARKER:TEST_FAILURE failures=1"),
            "status=2 under a success summary": wrapped_single_owner(child, status=2),
            "status=0 under a failure summary": wrapped_single_owner(child, summary="FFW_MARKER:TEST_FAILURE failures=1"),
            "status=1": wrapped_single_owner(child, status=1),
            "status=3": wrapped_single_owner(child, status=3),
            "two failures": wrapped_single_owner(child, status=2, summary="FFW_MARKER:TEST_FAILURE failures=2"),
            "no summary": wrapped_single_owner(child, summary=""),
            "both summaries": wrapped_single_owner(
                child, summary="FFW_MARKER:TEST_SUCCESS failures=0\nFFW_MARKER:TEST_FAILURE failures=1"),
            "killed by a signal": good.replace("status=0 stdout_bytes", "signal=11 stdout_bytes", 1),
            "wrong byte count": good.replace("stdout_bytes=", "stdout_bytes=9", 1),
            "wrong hash": good.replace("stdout_fnv1a64=", "stdout_fnv1a64=f", 1),
            "wrong path": good.replace("FFW_SPEAKER_BEGIN path=", "FFW_SPEAKER_BEGIN path=/wrong", 1),
        }
        for name, text in plants.items():
            with self.subTest(plant=name):
                self.assertFalse(self.verdict(text))
        for name in ("the old accounting: status=2 with TEST_FAILURE failures=1", "status=2 under a success summary"):
            child_text, gates = M.runtime_envelope(plants[name], "mips")
            self.assertEqual([g.status for g in gates], ["failed"], name)

    def test_the_strict_verifier_reads_the_log_unmodified_and_the_bootstrap_stays_strict(self):
        good = wrapped_single_owner(single_owner_fixture())
        boot = M.boot_runner()
        seen = []
        original = boot.verify_serial_output

        def recording(arch, hello, enosys, raw_log, *args, **kwargs):
            seen.append(raw_log)
            return original(arch, hello, enosys, raw_log, *args, **kwargs)

        with patch.object(boot, "verify_serial_output", side_effect=recording):
            _, gates = M.runtime_envelope(good, "mips")
        self.assertEqual([g.status for g in gates], ["passed"])
        # What the verifier saw is exactly the log with the child's region cut out: every other line, byte for byte.
        lines = good.splitlines()
        begin = next(i for i, line in enumerate(lines) if line.startswith("FFW_SPEAKER_BEGIN "))
        exit_line = next(i for i, line in enumerate(lines) if line.startswith("FFW_SPEAKER_EXIT "))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].rstrip("\n").split("\n"), lines[:begin] + lines[exit_line + 1:])
        self.assertIn("FFW_MARKER:TEST_SUCCESS failures=0", seen[0])
        self.assertNotIn("TEST_FAILURE", seen[0])
        for old, new in (
            ("FFW_MARKER:REBOOT_REQUEST", ""),
            ("FFW_PROBE:LOOPBACK_UP status=PASS rc=0", "FFW_PROBE:LOOPBACK_UP status=FAIL rc=-1"),
            ("FFW_RUSTC release=", "FFW_UNKNOWN release="),
            ("FFW_MARKER:REBOOT_REQUEST", "FFW_PLATFORM_STEP_BEGIN unexpected=1\nFFW_MARKER:REBOOT_REQUEST"),
            ("TEST_SUCCESS failures=0", "TEST_SUCCESS failures=1"),
        ):
            with self.subTest(plant=new):
                self.assertFalse(self.verdict(good.replace(old, new, 1)))
        self.assertFalse(self.verdict(good + "FFW_P05_RUNTIME:END status=done\n"))


class SingleOwnerRunTests(unittest.TestCase):
    """Real archive and subprocess plumbing with synthetic bytes, explicitly not a QEMU execution."""
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ffw-p05-single-owner-test-"))
        self.boot = M.boot_runner()

    def invoke(self, *extra, arch="mips", transcript=None, drop_marker=False, qemu_exit=0, marker_bytes=None, add_marker=False):
        elf, supervisor = self.root / "runtime.elf", self.root / "supervisor.elf"
        elf.write_bytes(elf_fixture(arch) + b"SYNTHETIC CHILD; NOT EXECUTABLE")
        supervisor.write_bytes(elf_fixture(arch) + b"SYNTHETIC SUPERVISOR; NOT EXECUTABLE")
        kernel = self.root / ("kernels/xm/boot/" + M.KERNEL_NAME if arch == "mips" else
                              "kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc")
        kernel.parent.mkdir(parents=True, exist_ok=True)
        kernel.write_bytes(b"SYNTHETIC KERNEL; NOT EXECUTABLE")
        logs, receipt = self.root / "logs", self.root / "receipt.json"
        text = transcript if transcript is not None else wrapped_single_owner(single_owner_fixture(arch), arch)
        seen = {}
        original_capture, original_build = self.boot.capture_guest, self.boot.mkinitramfs.build

        def synthetic_capture(command, env, timeout, **kwargs):
            seen["command"] = command
            archive = gzip.decompress(Path(env["FFW_INITRAMFS"]).read_bytes())
            seen["members"] = {entry["name"]: entry for entry in self.boot.mkinitramfs.parse_cpio_bytes(archive)}
            code = "import sys;sys.stdout.write(" + repr(text) + ");sys.stdout.flush();raise SystemExit(" + str(qemu_exit) + ")"
            return original_capture([sys.executable, "-c", code], env, timeout, **kwargs)

        def build(init_path, out_path, extra_files=(), **kwargs):
            files = []
            for item in extra_files:
                if item[0] == M.SINGLE_OWNER_MARKER_NAME:
                    if drop_marker:
                        continue
                    if marker_bytes is not None:
                        item = (item[0], item[1], marker_bytes)
                files.append(item)
            if add_marker:
                files.append((M.SINGLE_OWNER_MARKER_NAME, 0o100644, b"single-owner\n"))
            return original_build(init_path, out_path, files, **kwargs)

        args = ["run-runtime", "--arch", arch, "--elf", str(elf), "--supervisor", str(supervisor),
                "--log-dir", str(logs), "--receipt", str(receipt), "--timeout", "2", *extra]
        output = io.StringIO()
        with patch.dict(os.environ, {"FFW_BUILD_DIR": str(self.root)}), patch.object(
                self.boot, "capture_guest", side_effect=synthetic_capture), patch.object(
                self.boot, "cmd_version", return_value="SYNTHETIC; NO QEMU RAN"), patch.object(
                self.boot.mkinitramfs, "build", side_effect=build), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            result = M.main(args)
        return result, (json.loads(receipt.read_text()) if receipt.exists() else None), output.getvalue(), seen, logs

    def test_the_run_packs_the_marker_and_the_receipt_says_accepted_with_a_declared_unsupported_row(self):
        for arch in ("mips", "powerpc"):
            with self.subTest(arch=arch):
                self.setUp()
                result, receipt, output, seen, logs = self.invoke("--profile", SO, arch=arch)
                self.assertEqual(result, M.EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED)
                self.assertEqual(result, 4)
                self.assertEqual(receipt["result"], "accepted_with_declared_unsupported")
                self.assertNotEqual(receipt["result"], "passed")
                self.assertEqual((receipt["profile"], receipt["declared_unsupported"]), (SO, [DECLARED]))
                self.assertEqual(receipt["execution"]["profile"], SO)
                marker = seen["members"]["ffw_p05_profile"]
                self.assertEqual((marker["data"], marker["mode"]), (b"single-owner\n", 0o100644))
                packed = receipt["execution"]["initramfs"]["extra_files"]["ffw_p05_profile"]
                self.assertEqual(packed["sha256"], hashlib.sha256(b"single-owner\n").hexdigest())
                self.assertIn("franken-speaker", seen["members"])
                self.assertEqual(seen["command"][seen["command"].index("-append") + 1], DEFAULT_APPEND[arch],
                                 "the kernel command line is the default one: the marker is the only difference")
                lines = output.splitlines()
                self.assertNotIn("PASSED", lines)
                self.assertTrue(any(line.startswith("ACCEPTED WITH DECLARED UNSUPPORTED: " + DECLARED) for line in lines))
                self.assertIn("never a full pass", receipt["scope"])

    def test_the_default_run_packs_no_marker_and_keeps_its_plain_pass(self):
        result, receipt, output, seen, _ = self.invoke(transcript=wrapped(fixture()))
        self.assertEqual(result, 0)
        self.assertEqual(receipt["result"], "passed")
        self.assertNotIn("ffw_p05_profile", seen["members"])
        self.assertNotIn("ffw_p05_profile", receipt["execution"]["initramfs"]["extra_files"])
        self.assertEqual(receipt["execution"]["profile"], M.RUNTIME_THREADED)
        self.assertIn("PASSED", output.splitlines())
        self.assertNotIn("declared_unsupported", receipt)

    def test_the_wrong_profile_for_the_transcript_is_red_in_both_directions(self):
        result, receipt, output, _, _ = self.invoke()  # single-owner transcript, default (threaded) profile
        self.assertEqual(result, 1)
        self.assertEqual(receipt["result"], "not_passed")
        self.assertNotIn("ACCEPTED", output)
        self.setUp()
        result, receipt, output, _, _ = self.invoke("--profile", SO, transcript=wrapped(fixture()))
        self.assertEqual(result, 1)
        self.assertEqual(receipt["result"], "not_passed")
        self.assertNotIn("ACCEPTED", output)

    def test_a_missing_marker_in_the_archive_stops_before_the_guest_is_launched(self):
        result, receipt, _, seen, logs = self.invoke("--profile", SO, drop_marker=True)
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertNotIn("command", seen)
        self.assertFalse((logs / "runtime.serial.log").exists())

    def test_the_old_exit_two_accounting_is_red_end_to_end_for_the_single_owner_profile(self):
        old = wrapped_single_owner(single_owner_fixture(), status=2, summary="FFW_MARKER:TEST_FAILURE failures=1")
        result, receipt, output, _, _ = self.invoke("--profile", SO, transcript=old)
        self.assertEqual(result, 1)
        self.assertEqual(receipt["result"], "not_passed")
        self.assertIn("P05R-SUPERVISOR", [g["gate_id"] for g in receipt["gates"] if g["status"] == "failed"])
        self.assertNotIn("ACCEPTED", output)

    def test_a_marker_with_other_bytes_is_red_and_never_accepted(self):
        result, receipt, output, seen, _ = self.invoke("--profile", SO, marker_bytes=b"threaded\n")
        self.assertEqual(result, 1)
        self.assertEqual(receipt["result"], "not_passed")
        self.assertEqual(seen["members"]["ffw_p05_profile"]["data"], b"threaded\n")
        failed = [g for g in receipt["gates"] if g["status"] == "failed"]
        self.assertEqual([g["gate_id"] for g in failed], ["P05R-CAPTURE"])
        self.assertIn("single-owner marker", failed[0]["detail"])
        self.assertNotIn("ACCEPTED", output)

    def test_a_marker_in_a_default_run_stops_before_the_guest_is_launched(self):
        result, receipt, _, seen, logs = self.invoke(transcript=wrapped(fixture()), add_marker=True)
        self.assertEqual(result, 2)
        self.assertIsNone(receipt)
        self.assertNotIn("command", seen)
        self.assertFalse((logs / "runtime.serial.log").exists())

    def test_a_nonzero_qemu_exit_is_red_even_for_the_declared_single_owner_transcript(self):
        result, receipt, output, _, _ = self.invoke("--profile", SO, qemu_exit=7)
        self.assertEqual(result, 1)
        self.assertEqual(receipt["result"], "not_passed")
        self.assertIn("P05R-CAPTURE", [g["gate_id"] for g in receipt["gates"] if g["status"] == "failed"])
        self.assertNotIn("ACCEPTED", output)

    def test_analysis_of_the_saved_log_agrees_with_the_run_and_is_never_a_plain_pass(self):
        result, run_receipt, _, _, logs = self.invoke("--profile", SO)
        self.assertEqual(result, 4)
        analysis = ["analyze-runtime", "--arch", "mips", "--elf", str(self.root / "runtime.elf"),
                    "--supervisor", str(self.root / "supervisor.elf"), "--log", str(logs / "runtime.serial.log")]
        accepted = self.root / "analysis.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(analysis + ["--profile", SO, "--receipt", str(accepted)]), 4)
            self.assertEqual(M.main(analysis), 1, "the default profile refuses the single-owner transcript")
        body = json.loads(accepted.read_text())
        self.assertEqual(body["result"], "accepted_with_declared_unsupported")
        self.assertEqual(body["transcript_sha256"], run_receipt["transcript_sha256"])

    def test_native_analysis_of_a_single_owner_transcript_is_accepted_with_the_declared_row_only(self):
        log, elf, receipt = self.root / "native.log", self.root / "native.elf", self.root / "native.json"
        log.write_text(single_owner_fixture("x86_64"))
        elf.write_bytes(elf_fixture("x86_64"))
        args = ["analyze-runtime", "--arch", "x86_64", "--elf", str(elf), "--log", str(log)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(args + ["--profile", SO, "--receipt", str(receipt)]), 4)
            self.assertEqual(M.main(args), 1)
        self.assertEqual(json.loads(receipt.read_text())["result"], "accepted_with_declared_unsupported")

    def test_the_public_p05_entrypoint_accepts_the_profile_argument_and_refuses_an_unknown_one(self):
        script = HERE.parents[1] / "scripts/e2e/p05"
        accepted = subprocess.run([str(script), "--runtime", "analyze", "--arch", "x86_64", "--profile", SO],
                                  capture_output=True, text=True, timeout=10)
        self.assertEqual(accepted.returncode, 3, accepted.stdout + accepted.stderr)  # no log: BLOCKED, as before
        refused = subprocess.run([str(script), "--runtime", "analyze", "--arch", "x86_64", "--profile", "threadless"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)


if __name__ == "__main__":
    unittest.main()
