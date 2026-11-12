"""Canaries for the process runner's independent sample oracle."""
import json
import os
import signal
import struct
import sys
import tempfile
import subprocess
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from run_loopback import (
    Children, OracleError, VECTORS, compare_capture, compare_pcm,
    loopback_address, read_bounded, track_spec,
)


def endian_swap(data: bytes) -> bytes:
    return b"".join(struct.pack(">h", value) for (value,) in struct.iter_unpack("<h", data))


class SampleOracleTests(unittest.TestCase):
    def setUp(self):
        self.track = track_spec("vorbis_48000")
        self.reference = read_bounded(VECTORS / self.track["reference"]["file"])
        self.wire = endian_swap(self.reference)
        self.frames = self.track["expected_frames"]

    def test_permitted_reference_and_original_tolerance(self):
        result = compare_pcm(self.wire, self.reference, self.frames)
        self.assertEqual(result["frames"], 24000)
        self.assertEqual(result["samples"], 48000)
        self.assertEqual(result["peak_lsb"], 0)
        # A non-identical near reference is allowed at the fixed original limit.
        near = bytearray(self.wire)
        first = struct.unpack(">h", near[:2])[0]
        struct.pack_into(">h", near, 0, first + (1 if first < 32767 else -1))
        self.assertEqual(compare_pcm(bytes(near), self.reference, self.frames)["peak_lsb"], 1)

    def test_missing_and_duplicated_tail_are_not_trimmed(self):
        for bad in (self.wire[:-4], self.wire + self.wire[-4:]):
            with self.subTest(length=len(bad)), self.assertRaises(OracleError):
                compare_pcm(bad, self.reference, self.frames)

    def test_frame_shift_channel_swap_and_wrong_endian_fail(self):
        channels = b"".join(self.wire[i + 2 : i + 4] + self.wire[i : i + 2]
                            for i in range(0, len(self.wire), 4))
        for bad in (self.wire[4:] + self.wire[:4], channels, self.reference):
            with self.subTest(prefix=bad[:8].hex()), self.assertRaises(OracleError):
                compare_pcm(bad, self.reference, self.frames)

    def test_silence_does_not_pass_a_nonzero_track(self):
        with self.assertRaises(OracleError):
            compare_pcm(bytes(len(self.wire)), self.reference, self.frames)

    def test_known_bad_optimized_reference_stays_rejected(self):
        bad = read_bounded(VECTORS / self.track["retained_bad_reference"]["file"])
        with self.assertRaises(OracleError):
            compare_pcm(endian_swap(bad), self.reference, self.frames)

    def test_mp3_reference_is_a_permitted_independent_positive(self):
        track = track_spec("mp3_48000")
        reference = read_bounded(VECTORS / track["reference"]["file"])
        self.assertEqual(compare_pcm(endian_swap(reference), reference, track["expected_frames"])["peak_lsb"], 0)

    def test_long_mp3_reference_exceeds_n04_capacity_without_a_threshold_change(self):
        track = track_spec("mp3_48000_long")
        self.assertEqual(track["expected_frames"], 72000)
        self.assertGreater(track["expected_frames"], 94 * 256)
        self.assertEqual(len(track["_reference_bytes"]), 288000)
        self.assertEqual(compare_pcm(endian_swap(track["_reference_bytes"]),
                                     track["_reference_bytes"], track["expected_frames"])["peak_lsb"], 0)

    def test_empty_and_44100_are_not_qualified_by_48000_oracle(self):
        with self.assertRaises(OracleError):
            compare_pcm(b"", b"", 0)
        with self.assertRaises(OracleError):
            track_spec("vorbis_44100")

    def test_capture_positions_and_partial_final_block(self):
        directory = Path(tempfile.mkdtemp(prefix="ffw-source-oracle-"))
        path = directory / "capture.jsonl"
        anchor = 1_000_000_000
        records = []
        for start in range(0, self.frames, 256):
            count = min(256, self.frames - start)
            records.append({"start_frame": start, "frames": count,
                            "presentation_ns": anchor + start * 1_000_000_000 // 48000,
                            "pcm_be16_hex": self.wire[start * 4:(start + count) * 4].hex()})

        def write(rows):
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))

        write(records)
        result = compare_capture(path, self.track, anchor)
        self.assertEqual(result["blocks"], 94)
        self.assertEqual(records[-1]["frames"], 192)
        # Every mutation preserves plausible JSON and must still be rejected.
        for field, value in (("start_frame", 257), ("presentation_ns", records[1]["presentation_ns"] + 1),
                             ("frames", True), ("pcm_be16_hex", "00")):
            mutated = [dict(row) for row in records]
            mutated[1][field] = value
            write(mutated)
            with self.subTest(field=field), self.assertRaises(OracleError):
                compare_capture(path, self.track, anchor)
        write(records[:-1])
        with self.assertRaises(OracleError):
            compare_capture(path, self.track, anchor)
        write(records + [records[-1]])
        with self.assertRaises(OracleError):
            compare_capture(path, self.track, anchor)
        write(records)
        content = path.read_text()
        path.write_text(content.replace('{"start_frame": 0,', '{"start_frame": 999,"start_frame": 0,', 1))
        with self.assertRaises(OracleError):
            compare_capture(path, self.track, anchor)


class ProcessSupervisorTests(unittest.TestCase):
    """Real tiny Python children test supervision, not the audio implementation."""

    def directory(self):
        # Retained for failure replay; no deletion is authorized by the runner.
        return Path(tempfile.mkdtemp(prefix="ffw-source-child-"))

    def test_valid_child_event_and_exit_are_observed(self):
        with Children(self.directory(), 2) as supervisor:
            child = supervisor.spawn("canary", [sys.executable, "-c",
                                      'print(\'{"event":"ready","counter":1}\', flush=True)'])
            self.assertEqual(supervisor.event(child, "ready")["counter"], 1)
            supervisor.completed(child)
        self.assertEqual(child["process"].returncode, 0)

    def test_zero_exit_without_required_event_is_not_success(self):
        with Children(self.directory(), 2) as supervisor:
            child = supervisor.spawn("canary", [sys.executable, "-c", "pass"])
            with self.assertRaises(OracleError):
                supervisor.event(child, "ready")

    def test_delayed_duplicate_and_duplicate_keys_do_not_pass_completion(self):
        scripts = (
            'import time;print(\'{"event":"ready"}\',flush=True);'
            'time.sleep(.02);print(\'{"event":"ready"}\',flush=True)',
            'print(\'{"event":"bad","event":"ready"}\',flush=True)',
        )
        for script in scripts:
            with self.subTest(script=script), self.assertRaises(OracleError):
                with Children(self.directory(), 2) as supervisor:
                    child = supervisor.spawn("canary", [sys.executable, "-c", script])
                    supervisor.event(child, "ready")
                    supervisor.completed(child)

    def test_nonzero_exit_is_not_a_positive(self):
        with Children(self.directory(), 2) as supervisor:
            child = supervisor.spawn("canary", [sys.executable, "-c", "raise SystemExit(7)"])
            with self.assertRaises(OracleError):
                supervisor.completed(child)

    def test_hung_child_deadline_and_own_process_cleanup(self):
        with self.assertRaises(OracleError):
            with Children(self.directory(), 0.08) as supervisor:
                child = supervisor.spawn("canary", [sys.executable, "-c", "import time;time.sleep(5)"])
                supervisor.event(child, "ready")
        self.assertIsNotNone(child["process"].returncode)

    def test_exited_parent_does_not_leave_owned_descendant_running(self):
        with self.assertRaises(OracleError):
            with Children(self.directory(), 0.15) as supervisor:
                child = supervisor.spawn("canary", [sys.executable, "-c",
                    'import subprocess,sys,json;'
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(5)"]);'
                    'print(json.dumps({"event":"ready","descendant":p.pid}),flush=True)'])
                descendant = supervisor.event(child, "ready")["descendant"]
                # The descendant inherited pipes; zero parent exit cannot close
                # them or turn an incomplete run into a positive.
                supervisor.completed(child)
        deadline = time.monotonic() + 1
        while True:
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(descendant)],
                                   capture_output=True, text=True, timeout=1).stdout.strip()
            if not state or state.startswith("Z"):
                break  # A zombie is not running; the host's reaper owns it.
            if time.monotonic() >= deadline:
                self.fail(f"owned descendant remains running: {state}")
            time.sleep(0.01)

    def test_normal_leader_exit_retires_detached_pipe_descendant_before_reap(self):
        signals = []
        real_killpg = os.killpg
        def audited(pgid, sig):
            observed = os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            signals.append((pgid, sig, observed is not None))
            return real_killpg(pgid, sig)
        with patch("run_loopback.os.killpg", side_effect=audited):
            with Children(self.directory(), 3) as supervisor:
                child = supervisor.spawn("canary", [sys.executable, "-c",
                    'import subprocess,sys,json;'
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(15)"],'
                    'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                    'print(json.dumps({"event":"ready","descendant":p.pid}),flush=True)'])
                descendant = supervisor.event(child, "ready")["descendant"]
                supervisor.completed(child)
                self.assertIsNone(child["process"].returncode, "leader must remain unreaped")
            self.assertEqual(child["process"].returncode, 0)
        self.assertEqual(signals, [(child["pgid"], signal.SIGKILL, True)])
        deadline = time.monotonic() + 2
        while True:
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(descendant)],
                                   capture_output=True, text=True, timeout=1).stdout.strip()
            if not state or state.startswith("Z"):
                break
            if time.monotonic() >= deadline:
                self.fail(f"owned descendant remains running: {state}")
            time.sleep(.01)

    def test_signal_error_fails_closed_and_retires_other_owned_child(self):
        real_killpg = os.killpg
        groups = []
        direct = []
        real_kill = os.kill
        def injected(pgid, sig):
            groups.append(pgid)
            if len(groups) == 1:
                raise OSError("injected group failure")
            return real_killpg(pgid, sig)
        def direct_child(pid, sig):
            direct.append((pid, sig))
            self.assertIsNone(os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            return real_kill(pid, sig)
        directory = self.directory()
        with patch("run_loopback.os.killpg", side_effect=injected), patch("run_loopback.os.kill", side_effect=direct_child):
            with self.assertRaisesRegex(OracleError, "group retirement"):
                with Children(directory, 3) as supervisor:
                    first = supervisor.spawn("first", [sys.executable, "-c", "import time;time.sleep(15)"])
                    second = supervisor.spawn("second", [sys.executable, "-c", "import time;time.sleep(15)"])
            self.assertEqual(groups, [first["pgid"], second["pgid"]])
            self.assertEqual(direct, [(first["process"].pid, signal.SIGKILL)])
            self.assertIsNotNone(first["process"].returncode)
            self.assertIsNotNone(second["process"].returncode)
            self.assertIn("injected group failure", (directory / "cleanup-errors.json").read_text())

    def test_unterminated_and_overlong_output_fail(self):
        for text in ('print("broken", end="", flush=True)', 'print("x"*17000, flush=True)'):
            with self.subTest(text=text), self.assertRaises((OracleError, ValueError)):
                with Children(self.directory(), 2) as supervisor:
                    child = supervisor.spawn("canary", [sys.executable, "-c", text])
                    supervisor.event(child, "ready")
            self.assertIsNotNone(child["process"].returncode)

    def test_loopback_endpoint_and_regular_file_guards(self):
        self.assertEqual(loopback_address("127.0.0.1:40000"), "127.0.0.1:40000")
        for address in ("0.0.0.0:40000", "192.0.2.1:40000", "127.0.0.1:0", None):
            with self.subTest(address=address), self.assertRaises(OracleError):
                loopback_address(address)
        directory = self.directory()
        data = directory / "bounded"
        data.write_bytes(b"12345")
        self.assertEqual(read_bounded(data, 5), b"12345")
        with self.assertRaises(OracleError):
            read_bounded(data, 4)
        if hasattr(os, "O_NOFOLLOW"):
            link = directory / "symlink"
            link.symlink_to(data)
            with self.assertRaises(OSError):
                read_bounded(link)


if __name__ == "__main__":
    unittest.main()
