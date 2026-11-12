"""Synthetic transcript controls and real owned-child deadline checks; no guest proof."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("s02_guest", Path(__file__).with_name("run-s02-cost.py"))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


def valid_transcript():
    lines = ["FFW_S02COST_ALIVE",
             "FFW_S02COST_BEGIN version=1 codec=mp3_48000 frames_expected=24000 reps=3 "
             "input_fnv=da1589c2833424c5 reference_fnv=46a8dd21d7b5b39e"]
    for phase in ("before", "after"):
        lines.append(f"FFW_S02COST_EMPTY phase={phase} ticks={[1] * 8}")
        for rep in range(2):
            for shape, sizes in guest.SPINS.items():
                for size in sizes:
                    lines.append(f"FFW_S02COST_RULER phase={phase} rep={rep} shape={shape} "
                                 f"iterations={size} ticks={size}")
    for rep in range(3):
        lines.append(f"FFW_S02COST_RUN rep={rep} frames=24000 blocks=94 pull_ticks_sum=9400 "
                     "pull_ticks_max=100 eof_ticks=10 peak_lsb=1 sum_sq_lsb=200 samples=48000")
    lines.extend(["FFW_S02COST_END checked_reps=3 counter_wrap_unresolved=1 "
                  "stack_unmeasured=1 allocator_unmeasured=1", "reboot: Restarting system"])
    return "\n".join(lines) + "\n"


class TranscriptTests(unittest.TestCase):
    def check_bad(self, text, stderr="", code=0):
        with self.assertRaises(ValueError):
            guest.check_transcript(text, stderr, code)

    def test_complete_positive_is_functional_only(self):
        out = guest.check_transcript(valid_transcript(), "", 0)
        self.assertTrue(out["functional_passed"])
        self.assertEqual(len(out["runs"]), 3)
        self.assertFalse(out["instruction_count_qualified"])
        self.assertTrue(out["counter_wrap_unresolved"])

    def test_missing_or_wrong_sample_count_and_bad_pcm(self):
        for old, new in [("frames=24000", "frames=23999"), ("samples=48000", "samples=47999"),
                         ("peak_lsb=1", "peak_lsb=5"), ("sum_sq_lsb=200", "sum_sq_lsb=108001")]:
            with self.subTest(old=old):
                self.check_bad(valid_transcript().replace(old, new, 1))

    def test_missing_duplicate_or_unordered_runs(self):
        text = valid_transcript()
        for candidate in [text.replace("RUN rep=1", "RUN rep=0"), text.replace("RUN rep=0", "RUN rep=2"),
                          "\n".join(l for l in text.splitlines() if "RUN rep=1 " not in l)]:
            self.check_bad(candidate)

    def test_complete_end_is_not_clean_shutdown(self):
        text = valid_transcript()
        self.check_bad(text.replace("reboot: Restarting system\n", ""))
        self.check_bad("reboot: Restarting system\n" + text.replace("reboot: Restarting system\n", ""))
        self.check_bad(text, code=1)

    def test_real_kernel_timestamp_prefix_and_invalid_prefix_control(self):
        # Exact kernel line observed in the retained first real MIPS guest.
        text = valid_transcript().replace("reboot: Restarting system", "[  226.353929] reboot: Restarting system")
        self.assertTrue(guest.check_transcript(text, "", 0)["functional_passed"])
        self.check_bad(text.replace("[  226.353929]", "[not-a-kernel-time]"))
        self.check_bad(text.replace("[  226.353929]", "arbitrary prefix"))

    def test_failure_panics_and_wrong_stream_are_fatal(self):
        for failure in ("Kernel panic", "Attempted to kill init", "FFW_S02COST_FAIL reason=x",
                        "FFW_S02COST_REFUSED reason=x", "FFW_S02COST_FLUSH_FAILED",
                        "FFW_S02COST_REBOOT_FAILED status=-1"):
            self.check_bad(valid_transcript(), stderr=failure)
        self.check_bad(valid_transcript(), stderr="FFW_S02COST_END x")

    def test_duplicate_fields_and_contradictory_end(self):
        text = valid_transcript()
        self.check_bad(text.replace("RUN rep=0", "RUN rep=0 rep=0"))
        self.check_bad(text.replace("counter_wrap_unresolved=1", "counter_wrap_unresolved=0"))
        self.check_bad(text + "FFW_S02COST_ALIVE\n")
        self.check_bad(text.replace("FFW_S02COST_BEGIN", "prefix FFW_S02COST_BEGIN"))

    def test_missing_duplicate_invalid_ruler_or_empty(self):
        text = valid_transcript()
        first = next(l for l in text.splitlines() if "RULER " in l)
        for candidate in (text.replace(first + "\n", ""), text.replace(first, first + "\n" + first),
                          text.replace("iterations=1300000", "iterations=1300001", 1),
                          text.replace("ticks=[1, 1, 1, 1, 1, 1, 1, 1]", "ticks=[true]", 1)):
            self.check_bad(candidate)

    def test_strict_integer_notation_and_counter_bounds(self):
        text = valid_transcript()
        for replacement in ("-1", "01", str(1 << 64)):
            self.check_bad(text.replace("pull_ticks_sum=9400", "pull_ticks_sum=" + replacement))
        self.check_bad(text.replace("pull_ticks_max=100", "pull_ticks_max=4294967296"))


def elf_fixture(kind=1):
    ident = b"\x7fELF\x01\x02\x01" + b"\x00" * 9
    return struct.pack(">16sHHIIIIIHHHHHH", ident, 2, 8, 1, 0x1000, 52, 0, 0, 52, 32, 1, 40, 0, 0) + \
        struct.pack(">IIIIIIII", kind, 0, 0, 0, 84, 84, 5, 4)


class ExecutionTests(unittest.TestCase):
    def fresh(self):
        return Path(tempfile.mkdtemp(prefix="ffw-s02-guest-control-"))

    def test_static_elf_positive_dynamic_truncation_and_wrong_arch_refused(self):
        guest.require_static_mips(elf_fixture())
        for candidate in (elf_fixture(3), elf_fixture()[:-1], b"x", elf_fixture().replace(b"\x00\x08", b"\x00\x14", 1)):
            with self.assertRaises(ValueError):
                guest.require_static_mips(candidate)

    def test_real_child_positive_and_bounded_timeout(self):
        out = self.fresh()
        code, reason = guest.capture([sys.executable, "-c", "print('real child')"], out, 2)
        self.assertEqual((code, reason), (0, "completed"))
        self.assertEqual((out / "serial.log").read_text(), "real child\n")
        out = self.fresh()
        started = time.monotonic()
        code, reason = guest.capture([sys.executable, "-c", "import time;print('alive',flush=True);time.sleep(30)"], out, .15)
        self.assertEqual(reason, "timeout")
        self.assertLess(code, 0)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual((out / "serial.log").read_text(), "alive\n")

    def test_output_cap_stays_bounded_and_logs_retained(self):
        out = self.fresh()
        code, reason = guest.capture([sys.executable, "-c", "import os;os.write(1,b'x'*3000000)"], out, 3)
        self.assertEqual(reason, "output_limit")
        self.assertLessEqual((out / "serial.log").stat().st_size, guest.MAX_LOG)
        self.assertTrue((out / "stderr.log").exists())

    def test_nofollow_regular_file_capture(self):
        out = self.fresh()
        real = out / "data"; real.write_bytes(b"real")
        alias = out / "alias"; alias.symlink_to(real)
        self.assertEqual(guest.read_input(real), b"real")
        with self.assertRaises(OSError):
            guest.read_input(alias)
        with self.assertRaises(ValueError):
            guest.read_input(out)

    def test_completed_leader_does_not_leave_owned_descendant(self):
        out = self.fresh()
        code = ("import subprocess,sys; child=subprocess.Popen([sys.executable,'-c',"
                "'import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL);print(child.pid,flush=True)")
        status, reason = guest.capture([sys.executable, "-c", code], out, 3)
        self.assertEqual((status, reason), (0, "completed"))
        pid = int((out / "serial.log").read_text().strip())
        # A reparented killed process can briefly remain as a zombie; it must
        # never remain running. Inspect the actual process, not a forged PID.
        import subprocess
        deadline = time.monotonic() + 2
        while True:
            state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                                   capture_output=True, text=True, check=False).stdout.strip()
            if not state or state.startswith("Z"):
                break
            self.assertLess(time.monotonic(), deadline, "owned descendant survived")
            time.sleep(.02)

    def test_group_retirement_precedes_reaping_leader(self):
        import os
        import subprocess
        events = []
        original_waitid, original_killpg = os.waitid, os.killpg
        original_wait = subprocess.Popen.wait

        def observe(kind, pid, flags):
            self.assertTrue(flags & os.WNOWAIT)
            events.append("observe")
            return original_waitid(kind, pid, flags)

        def retire(pid, sig):
            # The owned leader must remain waitable (and so cannot have had
            # its PID reused) at this exact signal boundary.
            self.assertIsNotNone(original_waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            events.append("retire")
            return original_killpg(pid, sig)

        def reap(process, *args, **kwargs):
            events.append("reap")
            return original_wait(process, *args, **kwargs)

        with patch.object(os, "waitid", side_effect=observe), patch.object(
                os, "killpg", side_effect=retire), patch.object(subprocess.Popen, "wait", reap):
            self.assertEqual(guest.capture([sys.executable, "-c", "print('done')"], self.fresh(), 2),
                             (0, "completed"))
        self.assertIn("observe", events)
        self.assertLess(events.index("retire"), events.index("reap"))

    def test_group_signal_failure_stays_bounded_and_reaps_owned_child(self):
        import os
        import subprocess
        out = self.fresh()
        command = [sys.executable, "-c", "import os,time;print(os.getpid(),flush=True);time.sleep(30)"]
        started = time.monotonic()
        with patch.object(os, "killpg", side_effect=PermissionError("injected group signal refusal")):
            with self.assertRaises(PermissionError):
                guest.capture(command, out, .15)
        self.assertLess(time.monotonic() - started, 3)
        pid = int((out / "serial.log").read_text().strip())
        state = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                               capture_output=True, text=True, check=False).stdout.strip()
        self.assertFalse(state, "owned direct child was not reaped")

    def test_helper_refusal_retains_failed_result(self):
        # Synthetic kernel identity is injected ONLY in this unit control; this
        # does not execute QEMU or earn guest/kernel qualification.
        out = self.fresh()
        elf = out / "synthetic-elf"; elf.write_bytes(elf_fixture())
        kernel = out / "synthetic-kernel"; kernel.write_bytes(b"synthetic kernel control")
        import hashlib
        repo = Path.cwd()
        self.assertTrue((repo / "toolchain/src/measure-d02-cost.py").is_file())
        result_dir = out / "run"
        argv = ["run-s02-cost", "--elf", str(elf), "--kernel", str(kernel),
                "--repo", str(repo), "--output-dir", str(result_dir)]
        with patch.object(sys, "argv", argv), patch.object(
                guest, "KERNEL_SHA", hashlib.sha256(kernel.read_bytes()).hexdigest()):
            status = guest.main()
        self.assertEqual(status, 1)
        result = json.loads((result_dir / "result.json").read_text())
        self.assertFalse(result["functional_passed"])
        self.assertIn("no section headers", result["error"])
        self.assertNotIn("command", result)

    def test_real_elf_helper_accepts_valid_soft_float_sections(self):
        # A minimal synthetic static ELF tests the real helper's acceptance;
        # it is deliberately never run or called a decoder/guest executable.
        names = b"\0.shstrtab\0.MIPS.abiflags\0.text\0"
        body = bytearray(84) + names + b"\x00" * 7 + b"\x03" + b"\x00" * 4
        names_offset, abi_offset, text_offset = 84, 84 + len(names), 92 + len(names)
        shoff = len(body)
        sections = [(0,) * 10,
                    (1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
                    (11, 1, 0, 0, abi_offset, 8, 0, 0, 4, 0),
                    (26, 1, 4, 0x1000, text_offset, 4, 0, 0, 4, 0)]
        for section in sections:
            body.extend(struct.pack(">IIIIIIIIII", *section))
        body[:52] = struct.pack(">16sHHIIIIIHHHHHH", b"\x7fELF\x01\x02\x01" + b"\0" * 9,
                                2, 8, 1, 0x1000, 52, shoff, 0, 52, 32, 1, 40, 4, 1)
        body[52:84] = struct.pack(">IIIIIIII", 1, 0, 0, 0, len(body), len(body), 5, 4)
        path = self.fresh() / "synthetic-elf"; path.write_bytes(body)
        guest.require_static_mips(body)
        helper = guest.load(Path.cwd() / "toolchain/src/measure-d02-cost.py", "s02_unit_real_helper")
        facts = helper.read_elf(path)
        self.assertEqual(facts["fp_abi"], 3)
        self.assertEqual(facts["fpu_words"], [])
        self.assertEqual(facts["exec_words"], 1)


if __name__ == "__main__":
    unittest.main()
