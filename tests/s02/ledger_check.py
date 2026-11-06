#!/usr/bin/env python3
"""Checks the S02 ledger of negotiated formats (`tests/s02/negotiated.json`) against the vector manifest. Stdlib only.

The ledger is a list of REQUIREMENTS derived from the pinned clients, each with a status. This check keeps the ledger honest:

* the set of rows is fixed here, so deleting a row (above all the BLOCKED multichannel row) is a failure, not a tidy-up;
* a status can only be `decode_path_unproven` (mandatory, nothing proves it yet), `blocked` (with a stated reason) or `not_requested_by_pin`;
  `passed`/`supported` never appear in the ledger, because the ledger holds no decode result (the receipt computes per-row host results);
* every mandatory row names vectors that exist in the manifest, with the row's rate and channels;
* the rate boundary row states the bridge and its baseline.

    ledger_check.py [--ledger PATH] [--manifest PATH]       exit 0 consistent, 1 problems (printed)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LEDGER = os.path.join(HERE, "negotiated.json")
MANIFEST = os.path.join(REPO, "crates", "franken-codec", "tests", "vectors", "s02_vectors.json")

EXPECTED_ROWS = {
    "spotify.ogg_vorbis": ("mandatory", "decode_path_unproven"),
    "spotify.mp3": ("mandatory", "decode_path_unproven"),
    "spotify.mp3_160_enc": ("optional", "not_requested_by_pin"),
    "spotify.aac": ("optional", "not_requested_by_pin"),
    "spotify.flac": ("optional", "not_requested_by_pin"),
    "airplay.alac_44100_s16": ("mandatory", "decode_path_unproven"),
    "airplay.alac_48000_s24": ("mandatory", "decode_path_unproven"),
    "airplay.aac_lc_stereo": ("mandatory", "decode_path_unproven"),
    "airplay.aac_lc_multichannel": ("mandatory", "blocked"),
    "airplay.pcm_s16be": ("mandatory", "decode_path_unproven"),
}
STATUSES = {"decode_path_unproven", "blocked", "not_requested_by_pin"}
PIN_COMMITS = {
    "spotify": "d36f9f1907e8cc9d68a93f8ebc6b627b1bf7267d",
    "airplay": "0a34fbda83724cc06266aadcf7c88acc8fef4e7d",
    "decoder_library": "ee35874b571a35a9a6e15d3bc9a3aaf8f11fbeee",
}


def check(ledger: Dict[str, Any], manifest: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if ledger.get("schema") != "ffw.s02.negotiated.v1":
        problems.append("schema is not ffw.s02.negotiated.v1")
    pins = ledger.get("pins", {})
    for name, commit in PIN_COMMITS.items():
        if pins.get(name, {}).get("commit") != commit:
            problems.append(f"pin {name} is not at {commit[:12]}")
    rows = ledger.get("rows")
    if not isinstance(rows, list):
        return problems + ["rows is not a list"]
    ids = [r.get("id") for r in rows if isinstance(r, dict)]
    if len(ids) != len(set(ids)):
        problems.append("duplicate row ids")
    for missing in sorted(set(EXPECTED_ROWS) - set(ids)):
        problems.append(f"row {missing} is missing (a requirement is never deleted; an unsupported one is BLOCKED)")
    for extra in sorted(set(ids) - set(EXPECTED_ROWS)):
        problems.append(f"row {extra} is not in the checked set; add it to ledger_check.EXPECTED_ROWS and the contract")
    tracks = {t["id"]: t for t in manifest.get("tracks", []) if isinstance(t, dict) and "id" in t}
    for row in rows:
        if not isinstance(row, dict) or row.get("id") not in EXPECTED_ROWS:
            continue
        rid = row["id"]
        kind, status = EXPECTED_ROWS[rid]
        if row.get("status") not in STATUSES:
            problems.append(f"{rid}: status {row.get('status')!r} is not one of {sorted(STATUSES)}")
        elif row["status"] != status:
            problems.append(f"{rid}: status is {row['status']!r}, the checked ledger says {status!r}")
        if bool(row.get("mandatory")) != (kind == "mandatory"):
            problems.append(f"{rid}: mandatory flag is {row.get('mandatory')!r}, expected {kind == 'mandatory'}")
        if not row.get("cite"):
            problems.append(f"{rid}: no source citation")
        if not row.get("formats"):
            problems.append(f"{rid}: no negotiated format names")
        if status == "blocked" and not str(row.get("blocked_by", "")).strip():
            problems.append(f"{rid}: BLOCKED without a stated reason")
        if kind == "mandatory":
            vectors = row.get("vectors")
            if not vectors:
                problems.append(f"{rid}: a mandatory row without vectors")
                continue
            for vid in row.get("extra_vectors", []):
                if vid not in tracks:
                    problems.append(f"{rid}: extra vector {vid} is not in the manifest")
            for vid in row.get("negative_vectors", []):
                if not tracks.get(vid, {}).get("negative"):
                    problems.append(f"{rid}: negative vector {vid} is missing or not marked negative")
            for vid in vectors:
                track = tracks.get(vid)
                if track is None:
                    problems.append(f"{rid}: vector {vid} is not in the manifest")
                    continue
                if track.get("negative"):
                    continue
                if track.get("rate_hz") not in row.get("rate_hz", []):
                    problems.append(f"{rid}: vector {vid} rate {track.get('rate_hz')} is not in the row's rates")
                if row.get("channels") and track.get("channels") not in row["channels"]:
                    problems.append(f"{rid}: vector {vid} has {track.get('channels')} channels, the row says {row['channels']}")
                if row.get("bits") and track.get("bits") != row["bits"]:
                    problems.append(f"{rid}: vector {vid} is {track.get('bits')} bit, the row says {row['bits']}")
    boundary = ledger.get("rate_boundary", {})
    if boundary.get("baseline_rate_hz") != 48000 or boundary.get("native_rates_hz") != [44100, 48000]:
        problems.append("rate_boundary must state baseline 48000 and native rates [44100, 48000]")
    if "160/147" not in str(boundary.get("rule", "")):
        problems.append("rate_boundary.rule must name the exact 160/147 bridge")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=LEDGER)
    ap.add_argument("--manifest", default=MANIFEST)
    args = ap.parse_args()
    with open(args.ledger, encoding="utf-8") as f:
        ledger = json.load(f)
    with open(args.manifest, encoding="utf-8") as f:
        manifest = json.load(f)
    problems = check(ledger, manifest)
    for p in problems:
        print("LEDGER:", p)
    print("ledger: %d problem(s)" % len(problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
