#!/usr/bin/env python3
"""Offline, real-process finite-source check; consumes a prebuilt speaker.

Encoded input and scalar reference PCM are committed S02 fixtures, not Spotify
or AirPlay sessions. Captured PCM proves this host path, never a DAC or radio.
This script never compiles code, discovers devices, or contacts a provider.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "crates/franken-codec/tests/vectors"
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_PROCESS_BYTES = 4 * 1024 * 1024
MANIFEST_SHA256 = "e30d9af8998ceff21c9b498c090b3b0d74e04f9a06daca66f3cdf4c9c7dbf4eb"
LONG_MANIFEST_SHA256 = "c99120fb69f26332091c8ea83b75ade56f48be2a1e1f921d442bd41c8f4f5128"


class OracleError(ValueError):
    """An independent sample, custody, or process invariant failed."""


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OracleError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def read_bounded(path: Path, cap: int = MAX_CAPTURE_BYTES) -> bytes:
    """Reject overlarge data before reading it completely."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise OracleError("artifact is not a bounded regular file")
        data = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise OracleError("artifact changed while reading")
    if len(data) > cap:
        raise OracleError(f"artifact exceeds {cap}-byte bound")
    return data


def track_spec(track_id: str) -> dict:
    vectors, filename, digest = VECTORS, "s02_vectors.json", MANIFEST_SHA256
    if track_id == "mp3_48000_long":
        vectors, filename, digest = Path(__file__).parent / "vectors", "long_vectors.json", LONG_MANIFEST_SHA256
    manifest_bytes = read_bounded(vectors / filename)
    if hashlib.sha256(manifest_bytes).hexdigest() != digest:
        raise OracleError("reviewed vector manifest changed")
    manifest = strict_json(manifest_bytes)
    matches = [row for row in manifest["tracks"] if row["id"] == track_id]
    if len(matches) != 1:
        raise OracleError("track identity is missing or ambiguous")
    row = matches[0]
    row["_manifest_sha256"] = digest
    if row["rate_hz"] != 48000 or row["channels"] != 2:
        raise OracleError("this direct scalar oracle requires stereo 48 kHz")
    # These are the original S02 thresholds. This consumer cannot retune them.
    if row["tolerance"]["max_abs_lsb"] != 4 or row["tolerance"]["rms_lsb"] != 1.5:
        raise OracleError("original sample thresholds changed")
    for field, expected, captured in (
        (row, row["bytes"], "_source_bytes"),
        (row["reference"], row["reference"]["bytes"], "_reference_bytes"),
    ):
        filename = Path(field["file"])
        if len(filename.parts) != 1 or filename.name != str(filename):
            raise OracleError("fixture must be a direct child of the vector directory")
        data = read_bounded(vectors / filename)
        if len(data) != expected or hashlib.sha256(data).hexdigest() != field["sha256"]:
            raise OracleError("committed fixture length or digest mismatch")
        row[captured] = data
    if row["expected_frames"] != row["reference"]["frames"]:
        raise OracleError("reference frame count disagrees with encoded manifest")
    return row


def compare_pcm(captured_be: bytes, reference_le: bytes, frames: int) -> dict:
    """Compare *every* stereo sample; no alignment search, trim, or rescaling."""
    expected_bytes = frames * 2 * 2
    if frames <= 0 or expected_bytes > MAX_CAPTURE_BYTES:
        raise OracleError("invalid oracle frame bound")
    if len(captured_be) != expected_bytes or len(reference_le) != expected_bytes:
        raise OracleError(
            f"sample length: expected {expected_bytes} bytes, "
            f"captured {len(captured_be)}, reference {len(reference_le)}"
        )
    peak = 0
    squared = 0
    for (actual,), (expected,) in zip(
        struct.iter_unpack(">h", captured_be), struct.iter_unpack("<h", reference_le), strict=True
    ):
        error = abs(actual - expected)
        peak = max(peak, error)
        squared += error * error
    rms = math.sqrt(squared / (frames * 2))
    if peak > 4 or rms > 1.5:
        raise OracleError(f"PCM differs: peak {peak} LSB, RMS {rms:.6f} LSB")
    return {"frames": frames, "samples": frames * 2, "peak_lsb": peak, "rms_lsb": rms}


def compare_capture(path: Path, row: dict, origin_ns: int) -> dict:
    """Validate exact packet/sample positions, not an implementation's counters."""
    data = read_bounded(path)
    pcm = bytearray()
    position = 0
    records = data.splitlines()
    if not records or len(records) > 1024:
        raise OracleError("missing or excessive capture records")
    for line in records:
        if not line or len(line) > MAX_LINE_BYTES:
            raise OracleError("empty or excessive capture record")
        item = strict_json(line)
        if not isinstance(item, dict):
            raise OracleError("capture record must be an object")
        if set(item) != {"start_frame", "presentation_ns", "frames", "pcm_be16_hex"}:
            raise OracleError("unexpected capture schema")
        for field in ("start_frame", "presentation_ns", "frames"):
            if type(item[field]) is not int:
                raise OracleError("capture position must be an integer")
        count = item["frames"]
        if not 1 <= count <= 256 or position + count > row["expected_frames"]:
            raise OracleError("capture frame count exceeds track/block")
        if count < 256 and position + count != row["expected_frames"]:
            raise OracleError("partial block is not the final block")
        if item["start_frame"] != position:
            raise OracleError(f"capture frame gap, duplicate, or reordering: expected {position}, observed {item['start_frame']}")
        if item["presentation_ns"] != origin_ns + position * 1_000_000_000 // 48_000:
            raise OracleError("capture does not follow the admitted presentation timeline")
        raw = item["pcm_be16_hex"]
        if not isinstance(raw, str) or len(raw) != count * 8:
            raise OracleError("capture sample encoding has the wrong length")
        try:
            block = bytes.fromhex(raw)
        except ValueError as error:
            raise OracleError("capture is not hexadecimal PCM") from error
        if len(block) != count * 4:
            raise OracleError("capture block has the wrong decoded length")
        pcm.extend(block)
        position += count
    reference = row["_reference_bytes"]
    result = compare_pcm(bytes(pcm), reference, row["expected_frames"])
    result.update(blocks=len(records), capture_sha256=hashlib.sha256(data).hexdigest())
    return result


def loopback_address(value: str) -> str:
    try:
        host, port = value.rsplit(":", 1)
        ip = ipaddress.ip_address(host)
        if ip.version != 4 or not ip.is_loopback or not 1 <= int(port) <= 65535:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as error:
        raise OracleError("subprocess announced an invalid IPv4 loopback endpoint") from error
    return value


class Children:
    """Bounded pipe supervision; signals only processes this instance created."""

    def __init__(self, artifacts: Path, timeout: float):
        if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
            raise OracleError("safe child supervision requires waitid/WNOWAIT")
        self.artifacts = artifacts
        self.deadline = time.monotonic() + timeout
        self.selector = selectors.DefaultSelector()
        self.children: list[dict] = []

    def __enter__(self):
        return self

    def spawn(self, name: str, args: list[str]) -> dict:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        child = {"name": name, "process": process, "pgid": process.pid, "events": [], "bytes": 0,
                 "raw_stdout": bytearray(),
                 "stdout": bytearray(), "stderr": bytearray(), "open": 2}
        self.children.append(child)
        for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, (child, label))
        return child

    def command(self, child: dict, text: str):
        data = text.encode("ascii")
        if len(data) > 256:
            raise OracleError("supervisor command is overlong")
        try:
            child["process"].stdin.write(data)
            child["process"].stdin.flush()
        except (OSError, ValueError) as error:
            raise OracleError(f"{child['name']} closed its command pipe") from error

    def pump(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise OracleError("overall process deadline expired")
        for key, _ in self.selector.select(min(remaining, 0.025)):
            child, label = key.data
            try:
                data = os.read(key.fileobj.fileno(), 8192)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(key.fileobj)
                child["open"] -= 1
                if label == "stdout" and child[label]:
                    raise OracleError(f"{child['name']} ended with an incomplete JSON line")
                continue
            child["bytes"] += len(data)
            if child["bytes"] > MAX_PROCESS_BYTES:
                raise OracleError(f"{child['name']} exceeded its diagnostic bound")
            child[label].extend(data)
            if label == "stderr":
                continue
            child["raw_stdout"].extend(data)
            while b"\n" in child[label]:
                line, _, rest = child[label].partition(b"\n")
                child[label] = bytearray(rest)
                if not line or len(line) > MAX_LINE_BYTES or len(child["events"]) >= 256:
                    raise OracleError(f"{child['name']} emitted invalid/excessive diagnostic records")
                item = strict_json(line)
                if not isinstance(item, dict) or not isinstance(item.get("event"), str):
                    raise OracleError(f"{child['name']} emitted an invalid event")
                name = item["event"]
                if name not in {"ready", "started", "done", "summary", "stopped", "error", "peer_drained", "capture_state"}:
                    raise OracleError(f"{child['name']} emitted an unknown control event")
                if name == "peer_drained":
                    peer_id = item.get("peer_id")
                    if (type(peer_id) is not int or not 1 <= peer_id <= 0x00ff_ffff
                            or sum(row["event"] == name for row in child["events"]) >= 8):
                        raise OracleError(f"{child['name']} emitted invalid/excessive peer completion")
                if any(row["event"] == name and (name != "peer_drained"
                                                or row["peer_id"] == item["peer_id"])
                       for row in child["events"]):
                    raise OracleError(f"{child['name']} emitted a duplicate {name} event")
                terminals = {"done", "summary", "stopped"}
                if name in terminals and any(row["event"] in terminals for row in child["events"]):
                    raise OracleError(f"{child['name']} emitted contradictory completion events")
                child["events"].append(item)
            if len(child[label]) > MAX_LINE_BYTES:
                raise OracleError(f"{child['name']} emitted an overlong diagnostic line")

    @staticmethod
    def status(child: dict):
        # WNOWAIT preserves the leader PID/PGID until the owned group is retired.
        return os.waitid(os.P_PID, child["process"].pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def event(self, child: dict, name: str, peer_id: int | None = None) -> dict:
        while True:
            matches = [row for row in child["events"] if row["event"] == name
                       and (peer_id is None or row.get("peer_id") == peer_id)]
            if len(matches) > 1:
                raise OracleError(f"duplicate {name} event")
            if matches:
                return matches[0]
            if self.status(child) is not None and child["open"] == 0:
                raise OracleError(f"{child['name']} exited without {name}")
            self.pump()

    def completed(self, child: dict, expected: int = 0):
        while (status := self.status(child)) is None or child["open"]:
            self.pump()
        code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
        if code != expected:
            raise OracleError(f"{child['name']} exit {code}, expected {expected}")

    def failure_diagnostics(self) -> dict:
        """Bounded observations after cleanup, never command or stdin contents."""
        scalar_fields = {
            "captured_frames", "real_blocks", "concealed_blocks", "muted_blocks",
            "media_read", "media_accepted", "media_rejected", "rejected_authentication",
            "playout_rejected", "peer_id", "published_frames", "anchor_ns",
            "expired_blocks", "skipped_fenced", "skipped_mtu", "skipped_stalled",
            "skipped_capacity", "skipped_sequence", "saturated",
        }
        counter_fields = {
            "media_sent_packets", "media_submitted_packets", "reports_accepted",
            "media_dropped_late_packets", "media_dropped_overflow_packets",
            "media_dropped_aggregate_packets", "media_dropped_fenced_packets",
            "media_dropped_send_error_packets", "window_stalled_pumps",
        }
        def scalars(item, fields):
            return {key: item[key] for key in fields
                    if key in item and (type(item[key]) in (int, bool) or item[key] is None)}

        observations = []
        for child in self.children:
            # Parse only bounded actual stdout, including data drained during
            # cleanup. Malformed/partial lines remain in the existing artifact.
            lines = child["raw_stdout"].splitlines()
            terminals = []
            terminals_omitted = 0
            capture_states = []
            capture_states_omitted = 0
            for line in lines[:256]:
                if len(line) > MAX_LINE_BYTES:
                    continue
                try:
                    row = strict_json(line)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    continue
                if not isinstance(row, dict) or row.get("event") not in ("done", "summary", "stopped", "error", "capture_state"):
                    continue
                event = {"event": row["event"], **scalars(row, scalar_fields)}
                if row["event"] == "capture_state":
                    event.update(scalars(row, {"expected_frames", "decided_blocks"}))
                    first = row.get("first_non_real")
                    if "first_non_real" in row and first is None:
                        event["first_non_real"] = None
                    elif isinstance(first, dict):
                        event["first_non_real"] = scalars(first, {"block", "start_frame", "presentation_ns", "late_by_ns"})
                        outcome = first.get("outcome")
                        if type(outcome) is str and outcome in {"real", "concealed", "muted_gap",
                                                               "muted_nohistory", "muted_overdue", "skipped"}:
                            event["first_non_real"]["outcome"] = outcome
                    if not capture_states:
                        capture_states.append(event)
                    else:
                        capture_states_omitted += 1
                    continue
                peers = row.get("peers")
                if isinstance(peers, list):
                    event["peers"] = []
                    for peer in peers[:8]:
                        if isinstance(peer, dict):
                            view = scalars(peer, {"peer", "in_flight", "queued_packets", "reported_next", "sent_next"})
                            if isinstance(peer.get("counters"), dict):
                                view["counters"] = scalars(peer["counters"], counter_fields)
                            event["peers"].append(view)
                    event["peers_omitted"] = max(0, len(peers) - 8)
                if len(terminals) < 4:
                    terminals.append(event)
                else:
                    terminals_omitted += 1
            stderr = bytes(child["stderr"]).decode("utf-8", errors="replace")
            stderr = re.sub(r"(?i)\bkey(?:\s+|[=:]\s*)\S+|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])",
                            "[redacted]", stderr)
            stderr_limit = 2048
            observations.append({
                "child": child["name"],
                "pre_teardown_status": child.get("pre_teardown_status", {"kind": "unknown"}),
                "post_teardown_returncode": child["process"].returncode,
                "teardown_group_signal_sent": child.get("teardown_group_signal_sent", False),
                "teardown_direct_signal_sent": child.get("teardown_direct_signal_sent", False),
                "terminal_events": terminals,
                "terminal_events_omitted": terminals_omitted,
                "capture_states": capture_states,
                "capture_states_omitted": capture_states_omitted,
                "stdout_lines_unexamined": max(0, len(lines) - 256),
                "stderr": stderr[:stderr_limit],
                "stderr_omitted_chars": max(0, len(stderr) - stderr_limit),
            })
        return {"artifact_dir": str(self.artifacts.resolve()), "children": observations}

    def __exit__(self, exc_type, *_):
        errors = []

        def retire_owned(child):
            process = child["process"]
            try:
                os.killpg(child["pgid"], signal.SIGKILL)
                child["teardown_group_signal_sent"] = True
            except ProcessLookupError:
                pass
            except PermissionError:
                # On Darwin killpg can report EPERM for an all-zombie group.
                # The unreaped leader pins the group ID throughout this check.
                if sys.platform != "darwin" or self.status(child) is None:
                    raise
                observation = subprocess.run(
                    ["/bin/ps", "-g", str(child["pgid"]), "-o", "pid=,pgid=,stat="],
                    capture_output=True, text=True, timeout=2, check=False)
                members = [line.split() for line in observation.stdout.splitlines()]
                if (observation.returncode or not members or not any(
                        len(row) == 3 and row[0] == str(process.pid) for row in members) or any(
                        len(row) != 3 or row[1] != str(child["pgid"]) or not row[2].startswith("Z")
                        for row in members)):
                    raise

        try:
            for child in self.children:
                process = child["process"]
                # Observe without reaping; a live process stays explicitly unknown.
                try:
                    observed = self.status(child)
                    if observed is None:
                        child["pre_teardown_status"] = {"kind": "unknown"}
                    elif observed.si_code == os.CLD_EXITED:
                        child["pre_teardown_status"] = {"kind": "exit", "code": observed.si_status}
                    else:
                        child["pre_teardown_status"] = {"kind": "signal", "signal": observed.si_status}
                except OSError:
                    child["pre_teardown_status"] = {"kind": "unknown"}
                try:
                    # Signal before wait/reap: no recycled PGID can be targeted.
                    retire_owned(child)
                except (OSError, subprocess.TimeoutExpired) as error:
                    errors.append(f"{child['name']} group retirement: {error}")
                    # The unreaped leader is still our child, never a recycled PID.
                    try:
                        os.kill(process.pid, signal.SIGKILL)
                        child["teardown_direct_signal_sent"] = True
                    except ProcessLookupError:
                        pass
                    except OSError as fallback:
                        errors.append(f"{child['name']} child fallback: {fallback}")
                try:
                    process.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError) as error:
                    errors.append(f"{child['name']} wait: {error}")
                try:
                    for label in ("stdout", "stderr"):
                        stream = getattr(process, label)
                        while child["bytes"] < MAX_PROCESS_BYTES:
                            try:
                                data = os.read(stream.fileno(), min(8192, MAX_PROCESS_BYTES - child["bytes"]))
                            except BlockingIOError:
                                break
                            if not data:
                                break
                            child["bytes"] += len(data)
                            child["raw_stdout" if label == "stdout" else label].extend(data)
                    # Preserve bounded diagnostics on failure as well. The raw
                    # stream is retained so malformed records are inspectable.
                    (self.artifacts / f"{child['name']}.events.json").write_text(
                        json.dumps(child["events"], sort_keys=True) + "\n"
                    )
                    (self.artifacts / f"{child['name']}.stdout.txt").write_bytes(child["raw_stdout"])
                    (self.artifacts / f"{child['name']}.stderr.txt").write_bytes(child["stderr"])
                except OSError as error:
                    errors.append(f"{child['name']} diagnostics: {error}")
                finally:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        try:
                            stream.close()
                        except OSError as error:
                            errors.append(f"{child['name']} close: {error}")
        finally:
            self.selector.close()
        if errors:
            try:
                (self.artifacts / "cleanup-errors.json").write_text(json.dumps(errors) + "\n")
            except OSError:
                pass  # The following exception still makes success impossible.
            if exc_type is None:
                raise OracleError("; ".join(errors))


def provision(children: Children, binary: Path, directory: Path, track: dict,
              *, wrong_key: bool = False) -> tuple[dict, dict, int, Path]:
    """Use OS-assigned loopback ports, then admit exactly one shared anchor."""
    source = directory / "input.container"
    with source.open("xb") as stream:
        stream.write(track["_source_bytes"])
    source.chmod(0o444)
    capture = directory / "captured.jsonl"
    # Deliberately public synthetic values, unrelated to any account or site.
    key = "07" * 32
    common = ["--timeout-ms", "2000" if wrong_key else "10000",
              "--stream-id", "504403158265495553", "--epoch", "1"]
    receiver = children.spawn("receiver", [str(binary), "--source-loopback-receive",
                              "--output", str(capture), *common])
    children.command(receiver, f"KEY {'08' * 32 if wrong_key else key}\n")
    ready = children.event(receiver, "ready")
    media = loopback_address(ready.get("media"))
    control = loopback_address(ready.get("control"))
    if media == control:
        raise OracleError("receiver announced aliased media/control ports")
    sender = children.spawn("sender", [str(binary), "--source-loopback-send",
                            "--input", str(source), "--codec", "mp3" if track["codec"] == "mp3" else "ogg-vorbis",
                            "--media", media,
                            "--control", control, *common])
    children.command(sender, f"KEY {key}\n")
    sender_ready = children.event(sender, "ready")
    sender_control = loopback_address(sender_ready.get("control"))
    if sender_control in (media, control):
        raise OracleError("sender endpoint aliases a receiver endpoint")
    # Unix time is only a shared *host fixture* mapping. Each child samples it
    # once with a declared bound and advances with Instant, not wall time.
    anchor = time.time_ns() + (200_000_000 if wrong_key else 2_000_000_000)
    # Declare the finite capture horizon before N04 begins; END below remains
    # a separate permission after the actual sender has drained its credit.
    children.command(receiver, f"START {sender_control} {anchor} {track['expected_frames']}\n")
    started = children.event(receiver, "started")
    if (started.get("anchor_ns") != anchor
            or started.get("expected_frames") != track["expected_frames"]
            or type(started.get("host_ns")) is not int or not 0 < started["host_ns"] < anchor
            or type(started.get("uncertainty_ns")) is not int
            or not 0 < started["uncertainty_ns"] <= 2_000_000):
        raise OracleError("receiver did not admit the shared bounded host mapping")
    children.command(sender, f"GO {anchor}\n")
    return sender, receiver, anchor, capture


def delay_end_permission(children: Children, receivers: list[dict]):
    """Keep actual receivers alive after sender drain, beyond its 250 ms lead.

    A continuous N04 engine would invent post-track gaps during this wait.
    The finite consumer must prepare only its admitted horizon and keep its
    control/credit loop alive until the controller subsequently sends END.
    """
    until = time.monotonic() + 0.75
    while time.monotonic() < until:
        children.pump()
        for receiver in receivers:
            if (children.status(receiver) is not None
                    or any(row["event"] in {"done", "summary", "stopped"}
                           for row in receiver["events"])):
                raise OracleError("receiver completed before explicit END permission")


def run_case(binary: Path, directory: Path, track_id: str, wrong_key: bool = False) -> dict:
    track = track_spec(track_id)
    directory.mkdir()
    result = {"case": f"{track_id}-{'wrong-key' if wrong_key else 'pcm'}",
              "boundary": "host-process/local-provisioning/encoded-fixture/PCM-file-sink",
              "input_sha256": track["sha256"], "reference_sha256": track["reference"]["sha256"],
              "manifest_sha256": track["_manifest_sha256"], "status": "failed"}
    children = None
    try:
        with Children(directory, 20) as children:
            sender, receiver, anchor, capture = provision(
                children, binary, directory, track, wrong_key=wrong_key
            )
            if wrong_key:
                children.completed(sender, expected=2)
                children.completed(receiver, expected=2)
                summaries = [row for row in receiver["events"] if row["event"] == "summary"]
                if len(summaries) != 1:
                    raise OracleError("wrong-key attempt has no unique receiver summary")
                summary = summaries[0]
                if (any(type(summary.get(field)) is not int for field in
                        ("media_read", "media_rejected", "rejected_authentication", "media_accepted", "captured_frames"))
                        or summary["media_read"] <= 0
                        or summary["media_rejected"] <= 0
                        or summary["rejected_authentication"] <= 0
                        or summary.get("media_accepted") != 0
                        or summary.get("captured_frames") != 0):
                    raise OracleError("wrong-key control did not reach actual authentication refusal")
                if read_bounded(capture):
                    raise OracleError("wrong-key receiver exposed PCM")
                result.update(rejected=summary["media_rejected"],
                              rejected_authentication=summary["rejected_authentication"], captured_frames=0)
            else:
                sent = children.event(sender, "done")
                children.completed(sender)
                if sent.get("published_frames") != track["expected_frames"] or sent.get("anchor_ns") != anchor:
                    raise OracleError("sender completion did not account for the admitted full track")
                # A clock delay alone does not establish preparation readiness.
                # Retain the actual N04 outcome snapshot even if PCM fails.
                result["capture_state"] = children.event(receiver, "capture_state")
                delay_end_permission(children, [receiver])
                prepared = compare_capture(capture, track, anchor)
                children.command(receiver, f"END {track['expected_frames']}\n")
                final = children.event(receiver, "done")
                children.completed(receiver)
                if final.get("captured_frames") != track["expected_frames"]:
                    raise OracleError("receiver completion did not account for the full track")
                if (final.get("real_blocks") != (track["expected_frames"] + 255) // 256
                        or final.get("concealed_blocks") != 0
                        or final.get("playout_rejected") != 0):
                    raise OracleError("positive track concealed or rejected media instead of preparing every block")
                comparison = compare_capture(capture, track, anchor)
                if prepared != comparison:
                    raise OracleError("capture changed after the finite horizon while awaiting END")
                result.update(comparison, delayed_end_ms=750)
            # Input remains the exact immutable owned capture the child opened.
            if hashlib.sha256(read_bounded(directory / "input.container")).hexdigest() != track["sha256"]:
                raise OracleError("child input changed after provisioning")
        result["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["failure_diagnostics"] = (children.failure_diagnostics() if children is not None
                                         else {"artifact_dir": str(directory.resolve()), "children": []})
    (directory / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="centrally prebuilt speaker; never compiled here")
    parser.add_argument("--output-dir", required=True, type=Path, help="new directory; artifacts are retained")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must name an executable regular file")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    binary_bytes = read_bounded(binary, 256 * 1024 * 1024)
    binary_sha = hashlib.sha256(binary_bytes).hexdigest()
    owned_binary = args.output_dir / "speaker.binary"
    with owned_binary.open("xb") as stream:
        stream.write(binary_bytes)
    owned_binary.chmod(0o555)
    results = [run_case(owned_binary.resolve(), args.output_dir / name, track, wrong)
               for name, track, wrong in (
                   ("vorbis", "vorbis_48000", False),
                   ("mp3-long", "mp3_48000_long", False),
                   ("wrong-key", "vorbis_48000", True),
               )]
    report = {"schema": "ffw.source-loopback.v1", "planned": 3,
              "passed": sum(row["status"] == "passed" for row in results),
              "failed": sum(row["status"] != "passed" for row in results),
              "binary_sha256": binary_sha,
              "results": results,
              "not_qualified": ["native providers", "legacy guest runtime", "physical audio",
                                "radio performance", "full Q07 service journeys", "target budgets"]}
    if hashlib.sha256(read_bounded(owned_binary, 256 * 1024 * 1024)).hexdigest() != binary_sha:
        report["failed"] += 1
        report["error"] = "owned executable changed during the run"
    (args.output_dir / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("FFW_SOURCE_LOOPBACK: " + json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["passed"] == report["planned"] and report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
