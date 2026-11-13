#!/usr/bin/env python3
"""Run one finite local source into two or three real receiver processes.

The input and key are public fixtures. This exercises localhost process, byte,
and presentation-timeline behavior only; it does not establish physical sync,
a provider session, a distributed clock, or target-device performance.
The speaker executable must already be built by the central verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from run_loopback import (Children, OracleError, compare_capture, delay_end_permission,
                          loopback_address, read_bounded, track_spec)


def compare_group(captures: dict[int, Path], expected_ids: tuple[int, ...], track: dict, anchor: int) -> dict:
    """Require each expected member, an independent PCM oracle, and equal captures."""
    if (not expected_ids or len(set(expected_ids)) != len(expected_ids)
            or set(captures) != set(expected_ids)
            or len(set(captures.values())) != len(expected_ids)):
        raise OracleError("missing, duplicate, or aliased receiver capture")
    results = {}
    first = None
    for peer_id in expected_ids:
        path = captures[peer_id]
        results[str(peer_id)] = compare_capture(path, track, anchor)
        data = read_bounded(path)
        if hashlib.sha256(data).hexdigest() != results[str(peer_id)]["capture_sha256"]:
            raise OracleError("receiver capture changed between oracle checks")
        if first is None:
            first = data
        elif data != first:
            raise OracleError("receiver captures differ in samples or timeline")
    return results


def sender_views(summary: dict, peer_ids: tuple[int, ...], frames: int, anchor: int) -> dict:
    if (type(summary.get("published_frames")) is not int
            or summary["published_frames"] != frames or summary.get("anchor_ns") != anchor):
        raise OracleError("sender did not publish the full track at the shared anchor")
    views = summary.get("peers")
    if not isinstance(views, list) or len(views) != len(peer_ids):
        raise OracleError("sender omitted per-peer diagnostics")
    found = {}
    for view in views:
        if not isinstance(view, dict) or type(view.get("peer")) is not int:
            raise OracleError("invalid peer diagnostic")
        peer_id = view["peer"]
        counts = view.get("counters")
        if (peer_id not in peer_ids or peer_id in found or not isinstance(counts, dict)
                or type(counts.get("media_sent_packets")) is not int
                or counts["media_sent_packets"] <= 0
                or type(counts.get("reports_accepted")) is not int):
            raise OracleError("missing, duplicate, or inactive peer diagnostic")
        found[peer_id] = view
    if set(found) != set(peer_ids):
        raise OracleError("sender peer diagnostics do not match configured group")
    return found


def provision(children: Children, binary: Path, directory: Path, track: dict,
              peer_ids: tuple[int, ...], bad_peer: int | None):
    source = directory / "input.container"
    with source.open("xb") as stream:
        stream.write(track["_source_bytes"])
    source.chmod(0o444)
    key = "07" * 32
    common = ["--timeout-ms", "12000", "--stream-id", "504403158265495553", "--epoch", "1"]
    receivers = {}
    captures = {}
    endpoints = set()
    peers = []
    for peer_id in peer_ids:
        capture = directory / f"capture-{peer_id}.jsonl"
        receiver = children.spawn(f"receiver-{peer_id}", [str(binary), "--source-loopback-receive",
                                  "--output", str(capture), "--peer-id", str(peer_id), *common])
        children.command(receiver, f"KEY {'08' * 32 if peer_id == bad_peer else key}\n")
        ready = children.event(receiver, "ready")
        if type(ready.get("peer_id")) is not int or ready["peer_id"] != peer_id:
            raise OracleError("receiver ready identifies the wrong peer")
        media, control = loopback_address(ready.get("media")), loopback_address(ready.get("control"))
        if media == control or media in endpoints or control in endpoints:
            raise OracleError("receiver endpoints alias")
        endpoints.update((media, control))
        peers.append(f"{peer_id}@{media}@{control}")
        receivers[peer_id], captures[peer_id] = receiver, capture
    sender = children.spawn("sender", [str(binary), "--source-loopback-send", "--input", str(source),
                            "--codec", "mp3" if track["codec"] == "mp3" else "ogg-vorbis",
                            "--peers", ",".join(peers), *common])
    children.command(sender, f"KEY {key}\n")
    ready = children.event(sender, "ready")
    sender_control = loopback_address(ready.get("control"))
    if sender_control in endpoints or ready.get("peer_ids") != list(peer_ids):
        raise OracleError("sender ready did not bind the intended group")
    anchor = time.time_ns() + 2_000_000_000
    for receiver in receivers.values():
        # The trusted local manifest supplies the finite preparation horizon;
        # END is independent controller permission, not a guessed media EOF.
        children.command(receiver, f"START {sender_control} {anchor} {track['expected_frames']}\n")
    for receiver in receivers.values():
        started = children.event(receiver, "started")
        if (started.get("anchor_ns") != anchor
                or started.get("expected_frames") != track["expected_frames"]
                or type(started.get("host_ns")) is not int or not 0 < started["host_ns"] < anchor
                or type(started.get("uncertainty_ns")) is not int
                or not 0 < started["uncertainty_ns"] <= 2_000_000):
            raise OracleError("receiver did not admit the common bounded host anchor")
    children.command(sender, f"GO {anchor}\n")
    return sender, receivers, captures, anchor


def good_receiver(children: Children, receiver: dict, peer_id: int, frames: int):
    final = children.event(receiver, "done")
    children.completed(receiver)
    if (type(final.get("peer_id")) is not int or final["peer_id"] != peer_id
            or type(final.get("captured_frames")) is not int or final["captured_frames"] != frames
            or final.get("real_blocks") != (frames + 255) // 256
            or final.get("concealed_blocks") != 0 or final.get("playout_rejected") != 0):
        raise OracleError("healthy receiver did not capture every real block")
    return final


def require_peer_drained(event: dict, peer_id: int, frames: int, anchor: int):
    """Controller permission must follow the actual good peer's final credit.

    A wrong-key member can prevent global drain. Earlier reports from a good
    peer cannot stand in for its last report, even when its PCM is complete.
    This is sender-side credit evidence, not packet-by-packet receipt or playback.
    """
    view = event.get("peer")
    blocks = (frames + 255) // 256
    if (event.get("event") != "peer_drained" or type(event.get("peer_id")) is not int
            or event["peer_id"] != peer_id or type(event.get("published_frames")) is not int
            or event["published_frames"] != frames or event.get("anchor_ns") != anchor
            or not isinstance(view, dict) or type(view.get("peer")) is not int or view["peer"] != peer_id
            or "fence" not in view or view["fence"] is not None):
        raise OracleError("peer completion does not identify the admitted finite stream")
    expected = {"queued_packets": 0, "queued_bytes": 0, "in_flight": 0,
                "sent_next": blocks, "reported_next": blocks}
    if any(type(view.get(key)) is not int or view[key] != value for key, value in expected.items()):
        raise OracleError("peer still has queued or unacknowledged final media")
    counts = view.get("counters")
    if (not isinstance(counts, dict) or type(counts.get("reports_accepted")) is not int
            or counts["reports_accepted"] <= 0):
        raise OracleError("peer has no authenticated delivery feedback")
    expected_counts = {"media_submitted_packets": blocks, "media_sent_packets": blocks,
                       "media_dropped_overflow_packets": 0, "media_dropped_aggregate_packets": 0,
                       "media_dropped_late_packets": 0, "media_dropped_fenced_packets": 0,
                       "media_dropped_send_error_packets": 0}
    if any(type(counts.get(key)) is not int or counts[key] != value for key, value in expected_counts.items()):
        raise OracleError("peer sender counters do not account for the admitted finite stream")


def bad_receiver(children: Children, receiver: dict, peer_id: int, capture: Path):
    children.completed(receiver, expected=2)
    summary = children.event(receiver, "summary")
    fields = ("media_read", "media_rejected", "rejected_authentication", "media_accepted", "captured_frames")
    if (type(summary.get("peer_id")) is not int or summary["peer_id"] != peer_id
            or any(type(summary.get(field)) is not int for field in fields)
            or summary["media_read"] <= 0 or summary["media_rejected"] <= 0
            or summary["rejected_authentication"] <= 0 or summary["media_accepted"] != 0
            or summary["captured_frames"] != 0 or read_bounded(capture)):
        raise OracleError("wrong-key member did not reject actual media without PCM")
    return summary


def run_case(binary: Path, directory: Path, track_id: str, count: int, bad_peer: int | None = None) -> dict:
    track = track_spec(track_id)
    directory.mkdir()
    peer_ids = tuple(range(1, count + 1))
    good_ids = tuple(peer_id for peer_id in peer_ids if peer_id != bad_peer)
    result = {"case": directory.name, "status": "failed", "peers": list(peer_ids),
              "capture_states": {},
              "wrong_key_peer": bad_peer, "input_sha256": track["sha256"],
              "reference_sha256": track["reference"]["sha256"],
              "manifest_sha256": track["_manifest_sha256"]}
    children = None
    try:
        with Children(directory, 22) as children:
            sender, receivers, captures, anchor = provision(children, binary, directory, track, peer_ids, bad_peer)
            frames = track["expected_frames"]
            if bad_peer is None:
                sent = children.event(sender, "done")
                children.completed(sender)
                views = sender_views(sent, peer_ids, frames, anchor)
                for peer_id in good_ids:
                    result["capture_states"][str(peer_id)] = children.event(receivers[peer_id], "capture_state")
                delay_end_permission(children, list(receivers.values()))
                prepared = compare_group(captures, good_ids, track, anchor)
                for peer_id in good_ids:
                    require_peer_drained(children.event(sender, "peer_drained", peer_id), peer_id, frames, anchor)
                    children.command(receivers[peer_id], f"END {frames}\n")
            else:
                # Healthy receivers finish only after their own last credit;
                # the wrong-key peer still cannot make the group complete.
                for peer_id in good_ids:
                    require_peer_drained(children.event(sender, "peer_drained", peer_id), peer_id, frames, anchor)
                    result["capture_states"][str(peer_id)] = children.event(receivers[peer_id], "capture_state")
                    children.command(receivers[peer_id], f"END {frames}\n")
            summaries = {str(peer_id): good_receiver(children, receivers[peer_id], peer_id, frames)
                         for peer_id in good_ids}
            comparisons = compare_group({peer_id: captures[peer_id] for peer_id in good_ids},
                                        good_ids, track, anchor)
            if bad_peer is None and prepared != comparisons:
                raise OracleError("group capture changed after the finite horizon while awaiting END")
            if bad_peer is not None:
                children.completed(sender, expected=2)
                sent = children.event(sender, "summary")
                views = sender_views(sent, peer_ids, frames, anchor)
                result["wrong_key_summary"] = bad_receiver(children, receivers[bad_peer], bad_peer,
                                                            captures[bad_peer])
                if views[bad_peer]["counters"]["reports_accepted"] != 0:
                    raise OracleError("wrong-key peer provided accepted feedback")
            if any(views[peer_id]["counters"]["reports_accepted"] <= 0 for peer_id in good_ids):
                raise OracleError("healthy peer did not return authenticated feedback")
            if hashlib.sha256(read_bounded(directory / "input.container")).hexdigest() != track["sha256"]:
                raise OracleError("owned source input changed")
            result.update(anchor_ns=anchor, sender_summary=sent, receiver_summaries=summaries,
                          comparisons=comparisons)
        result["status"] = "passed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["failure_diagnostics"] = (children.failure_diagnostics() if children is not None
                                         else {"artifact_dir": str(directory.resolve()), "children": []})
    (directory / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error("--binary must name an executable regular file")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    data = read_bounded(binary, 256 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    owned = args.output_dir / "speaker.binary"
    with owned.open("xb") as stream:
        stream.write(data)
    owned.chmod(0o555)
    cases = (("vorbis-two", "vorbis_48000", 2, None),
             ("mp3-long-three", "mp3_48000_long", 3, None),
             ("wrong-key-three", "vorbis_48000", 3, 3))
    results = [run_case(owned.resolve(), args.output_dir / name, track, count, bad)
               for name, track, count, bad in cases]
    report = {"schema": "ffw.source-group.v1", "planned": len(cases),
              "passed": sum(row["status"] == "passed" for row in results),
              "failed": sum(row["status"] != "passed" for row in results),
              "binary_sha256": digest, "results": results,
              "not_qualified": ["provider sessions", "physical audio or synchronization",
                                "mixed-board operation", "distributed clocks", "target budgets"]}
    if hashlib.sha256(read_bounded(owned, 256 * 1024 * 1024)).hexdigest() != digest:
        report["failed"] += 1
        report["error"] = "owned executable changed during the run"
    (args.output_dir / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("FFW_SOURCE_GROUP: " + json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["passed"] == report["planned"] and report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
