#!/usr/bin/env python3
"""Write (or check) the shared U01 vectors that crates/franken-journal replays.

    make_vectors.py            write crates/franken-journal/tests/vectors/u01_vectors.json
    make_vectors.py --check    exit 1 if the file on disk differs from what the reference produces

The scripted scenarios, hostile images and cut-point digests come from the Python reference; the expected recovered states
of the image cases are derived from scripted runs in images.py, not from the scanner under test. Rust must reproduce the
media bytes after every scenario, the digest of the media after every power cut, and the result of opening every image.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict

import images
import reference as ref
import scenarios as sc

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(REPO, "crates", "franken-journal", "tests", "vectors", "u01_vectors.json")
SCHEMA = "ffw.u01.vectors.v1"


def limits_doc(lim: ref.Limits) -> Dict[str, Any]:
    return {"segment_bytes": lim.segment_bytes, "max_txn_payload": lim.max_txn_payload,
            "min_flush_interval_ticks": lim.min_flush_interval_ticks, "max_segment_gen": lim.max_segment_gen,
            "worst_snapshot_payload": lim.worst_snapshot_payload(),
            "namespaces": {str(ns): list(lim.ns[ns]) for ns in ref.NS_ORDER}}


def script_doc(vid: str, name: str, steps) -> Dict[str, Any]:
    lim = ref.TINY
    media = ref.Media(lim.segment_bytes)
    journal, _rec = ref.Journal.open(media, lim)
    states, outcomes = [ref.state_hex(journal.state)], []
    for step in steps:
        try:
            outcomes.append(getattr(journal, step[0])(*step[1:]) or "ok")
        except ref.JournalError as err:
            outcomes.append("error:" + err.code)
        states.append(ref.state_hex(journal.state))
    forward = ref.enumerate_cuts(lim, steps)
    backward = ref.enumerate_cuts(lim, steps, reverse=True)
    return {
        "id": vid, "scenario": name, "steps": [sc.step_to_json(s) for s in steps], "outcomes": outcomes,
        "states_hex": states, "final_media_sha256": hashlib.sha256(bytes(media.media)).hexdigest(),
        "frames_written": journal.frames_written, "compactions": journal.compactions,
        "bytes_programmed": journal.bytes_programmed, "storage_ops": media.ops_done,
        "cuts_forward": {k: forward[k] for k in ("cuts", "old", "new", "total_ops", "digest")},
        "cuts_reverse": {k: backward[k] for k in ("cuts", "old", "new", "total_ops", "digest")},
    }


def image_doc(case: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(case)
    media = ref.Media(ref.TINY.segment_bytes)
    media.media[:] = bytes.fromhex(case["image_hex"])
    media.view[:] = media.media
    try:
        ref.Journal.open(media, ref.TINY)
    except ref.JournalError:
        pass  # an error case leaves the medium as it was
    out["media_after_sha256"] = hashlib.sha256(bytes(media.media)).hexdigest()
    return out


def build() -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "format": {"frame_magic": ref.FRAME_MAGIC, "segment_header": ref.SEG_HEADER, "frame_header": ref.FRAME_HEADER,
                   "version": ref.FORMAT_VERSION, "legacy_version": ref.LEGACY_VERSION},
        "limits": {"tiny": limits_doc(ref.TINY), "standard": limits_doc(ref.STANDARD)},
        "scripts": [script_doc(f"U01-S-{i:03d}", name, steps) for i, (name, steps) in enumerate(sc.SCENARIOS.items(), start=1)],
        "images": [image_doc(c) for c in images.build()],
    }


def main(argv) -> int:
    text = json.dumps(build(), indent=1, sort_keys=True) + "\n"
    if "--check" in argv:
        try:
            same = open(OUT, encoding="utf-8").read() == text
        except OSError:
            same = False
        print("u01 vectors: up to date" if same else "u01 vectors: OUT OF DATE (run make_vectors.py)")
        return 0 if same else 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    doc = json.loads(text)
    print(f"wrote {len(doc['scripts'])} scripts and {len(doc['images'])} images to {os.path.relpath(OUT, REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
