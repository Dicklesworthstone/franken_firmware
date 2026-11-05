#!/usr/bin/env python3
"""Measures which fsonos control actions are actually used (bead ffw-xvv, G03 action matrix).

    python3 -B -I tests/g03/measure_usage.py --fsonos /path/to/frankensonos      read the external checkout, print the matrix
    python3 -B -I tests/g03/measure_usage.py --fsonos /path/to/frankensonos --write
                                                                                  rewrite tests/g03/usage_matrix.json
    python3 -B -I tests/g03/measure_usage.py --check-recorded                     verify the recorded file (no checkout needed)

The bead asks for "an action matrix from actual usage before committing the compatibility surface".
This is that measurement, reproducible and read-only: it reads the checkout, never writes to it, and
records exactly what it counted, from where, at which revision.

What is counted. For every function of `fsonos-proto`'s `control` module and the topology read, the
number of PRODUCTION call sites in the source of five consumer crates (`fsonos-core`, `-api`, `-cli`,
`-mcp`, `-sim`): calls spelled `soap::<fn>` (the alias the consumers give `fsonos_proto::control`),
`fsonos_proto::control::<fn>` or `proto::control::<fn>`, and, for the topology read,
`topology::get_zone_group_state` or `get_zone_group_state(`. Everything from the first
`#[cfg(test)]` of a file onwards is excluded, so inline unit tests do not count as usage. This is a
LOWER BOUND on calls through other spellings and an UPPER BOUND on calls that are never reached at
run time: it counts call sites in the source, not executions.

Each function maps to the SOAP action it sends. Three of them reach their action through another
function (`join_group`, `leave_group` and `play_from_queue` all call `set_av_transport_uri`, so their
action is `SetAVTransportURI`); those three are mapped by hand below and every other mapping is
checked against the literal action name in the source, so a rename upstream is noticed.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORDED = Path(__file__).resolve().parent / "usage_matrix.json"

CRATES = ["fsonos-core", "fsonos-api", "fsonos-cli", "fsonos-mcp", "fsonos-sim"]

# function -> (service, action, indirect). `indirect` marks the three that reach their action through
# `set_av_transport_uri`; for every other function the literal action must appear in its body.
FUNCTIONS = {
    "play": ("AVTransport", "Play", False),
    "pause": ("AVTransport", "Pause", False),
    "stop": ("AVTransport", "Stop", False),
    "next": ("AVTransport", "Next", False),
    "previous": ("AVTransport", "Previous", False),
    "seek_track": ("AVTransport", "Seek", False),
    "seek_position": ("AVTransport", "Seek", False),
    "set_av_transport_uri": ("AVTransport", "SetAVTransportURI", False),
    "set_normal_play_mode": ("AVTransport", "SetPlayMode", False),
    "play_from_queue": ("AVTransport", "SetAVTransportURI", True),
    "add_uri_to_queue": ("AVTransport", "AddURIToQueue", False),
    "remove_all_tracks_from_queue": ("AVTransport", "RemoveAllTracksFromQueue", False),
    "enqueue_uri": ("AVTransport", "AddURIToQueue", False),
    "remove_track_range_from_queue": ("AVTransport", "RemoveTrackRangeFromQueue", False),
    "join_group": ("AVTransport", "SetAVTransportURI", True),
    "leave_group": ("AVTransport", "SetAVTransportURI", True),
    "delegate_group": ("AVTransport", "DelegateGroupCoordinationTo", False),
    "delegate_group_and_rejoin": ("AVTransport", "DelegateGroupCoordinationTo", False),
    "get_volume": ("RenderingControl", "GetVolume", False),
    "set_volume": ("RenderingControl", "SetVolume", False),
    "set_relative_volume": ("RenderingControl", "SetRelativeVolume", False),
    "get_mute": ("RenderingControl", "GetMute", False),
    "set_mute": ("RenderingControl", "SetMute", False),
    "get_bass": ("RenderingControl", "GetBass", False),
    "set_bass": ("RenderingControl", "SetBass", False),
    "get_treble": ("RenderingControl", "GetTreble", False),
    "set_treble": ("RenderingControl", "SetTreble", False),
    "get_loudness": ("RenderingControl", "GetLoudness", False),
    "set_loudness": ("RenderingControl", "SetLoudness", False),
    "ramp_to_volume": ("RenderingControl", "RampToVolume", False),
    "get_group_volume": ("GroupRenderingControl", "GetGroupVolume", False),
    "set_group_volume": ("GroupRenderingControl", "SetGroupVolume", False),
    "set_relative_group_volume": ("GroupRenderingControl", "SetRelativeGroupVolume", False),
    "get_transport_info": ("AVTransport", "GetTransportInfo", False),
    "get_position_info": ("AVTransport", "GetPositionInfo", False),
    "get_media_info": ("AVTransport", "GetMediaInfo", False),
    "configure_sleep_timer": ("AVTransport", "ConfigureSleepTimer", False),
    "get_remaining_sleep_timer": ("AVTransport", "GetRemainingSleepTimerDuration", False),
}
# `set_group_volume` and `set_relative_group_volume` each also send SnapshotGroupVolume first.
SNAPSHOT_CALLERS = ["set_group_volume", "set_relative_group_volume"]
TOPOLOGY_FN = "get_zone_group_state"


def production_text(path):
    return path.read_text(errors="replace").split("#[cfg(test)]")[0]


def function_bodies(control_rs):
    text = control_rs.read_text()
    bodies = {}
    for chunk in re.split(r"\npub fn ", "\n" + text):
        m = re.match(r"(\w+)", chunk)
        if m:
            bodies[m.group(1)] = chunk.split("\n// ----")[0]
    return bodies


def call_site_pattern(name):
    return re.compile(r"(?:\bsoap|fsonos_proto::control|\bproto::control)::" + re.escape(name) + r"\b")


def topology_pattern():
    return re.compile(r"(?:topology|proto)::get_zone_group_state\b|\bget_zone_group_state\(")


def git_rev(path):
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short=8", "HEAD"],
                         capture_output=True, text=True, check=False)
    return out.stdout.strip() or "unknown"


def measure(fsonos):
    fsonos = Path(fsonos)
    bodies = function_bodies(fsonos / "crates" / "fsonos-proto" / "src" / "control.rs")
    problems = []
    for name, (_, action, indirect) in FUNCTIONS.items():
        if name not in bodies:
            problems.append(f"{name}: not found in control.rs")
        elif not indirect and f'"{action}"' not in bodies[name]:
            problems.append(f"{name}: the action {action!r} is not in its body any more")
    files = [p for crate in CRATES for p in sorted((fsonos / "crates" / crate / "src").rglob("*.rs"))]
    texts = {p: production_text(p) for p in files}
    functions = []
    for name, (service, action, indirect) in FUNCTIONS.items():
        pat = call_site_pattern(name)
        per_crate = {}
        for p, text in texts.items():
            n = len(pat.findall(text))
            if n:
                crate = p.relative_to(fsonos / "crates").parts[0]
                per_crate[crate] = per_crate.get(crate, 0) + n
        functions.append({"function": name, "service": service, "action": action, "indirect": indirect,
                          "sites": sum(per_crate.values()), "crates": sorted(per_crate)})
    pat = topology_pattern()
    per_crate = {}
    for p, text in texts.items():
        n = len(pat.findall(text))
        if n:
            crate = p.relative_to(fsonos / "crates").parts[0]
            per_crate[crate] = per_crate.get(crate, 0) + n
    functions.append({"function": TOPOLOGY_FN, "service": "ZoneGroupTopology", "action": "GetZoneGroupState",
                      "indirect": False, "sites": sum(per_crate.values()), "crates": sorted(per_crate)})
    return {
        "schema": "ffw.g03.usage-matrix.v1",
        "source": {
            "repository": "frankensonos (a sibling checkout; read only)",
            "git_rev": git_rev(fsonos),
            "crates": CRATES,
            "files_scanned": len(files),
            "counted": "production call sites; everything from the first #[cfg(test)] of a file onwards is excluded",
            "patterns": ["soap::<fn>", "fsonos_proto::control::<fn>", "proto::control::<fn>",
                         "topology::get_zone_group_state / get_zone_group_state("],
            "note": "a lower bound for other spellings, an upper bound for calls never reached; call sites, not executions",
        },
        "problems": problems,
        "functions": functions,
        "actions": aggregate(functions),
    }


def aggregate(functions):
    by_action = {}
    for f in functions:
        key = (f["service"], f["action"])
        row = by_action.setdefault(key, {"service": f["service"], "action": f["action"], "sites": 0, "functions": []})
        row["sites"] += f["sites"]
        row["functions"].append(f["function"])
    # SnapshotGroupVolume is sent by two functions in addition to their own action.
    snapshot_sites = sum(f["sites"] for f in functions if f["function"] in SNAPSHOT_CALLERS)
    by_action[("GroupRenderingControl", "SnapshotGroupVolume")] = {
        "service": "GroupRenderingControl", "action": "SnapshotGroupVolume", "sites": snapshot_sites,
        "functions": list(SNAPSHOT_CALLERS)}
    return sorted(by_action.values(), key=lambda r: (-r["sites"], r["service"], r["action"]))


def check_recorded():
    data = json.loads(RECORDED.read_text(encoding="utf-8"))
    problems = list(data.get("problems", []))
    if data["actions"] != aggregate(data["functions"]):
        problems.append("the recorded action totals do not follow from the recorded function counts")
    for f in data["functions"]:
        if f["function"] != TOPOLOGY_FN and FUNCTIONS[f["function"]][:2] != (f["service"], f["action"]):
            problems.append(f"{f['function']}: recorded service/action differ from this script's mapping")
    names = {f["function"] for f in data["functions"]}
    if names != set(FUNCTIONS) | {TOPOLOGY_FN}:
        problems.append("the recorded functions are not the set this script measures")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--fsonos", help="path to a frankensonos checkout (read only)")
    parser.add_argument("--write", action="store_true", help="rewrite the recorded matrix from the checkout")
    parser.add_argument("--check-recorded", action="store_true")
    args = parser.parse_args(argv)
    if args.check_recorded:
        problems = check_recorded()
        for line in problems:
            print("PROBLEM", line, file=sys.stderr)
        data = json.loads(RECORDED.read_text(encoding="utf-8"))
        status = "FAIL" if problems else "PASS"
        print(f"G03 usage matrix (recorded, rev {data['source']['git_rev']}): {status} "
              f"({len(data['functions'])} functions, {len(data['actions'])} actions, "
              f"{data['source']['files_scanned']} files)")
        return 1 if problems else 0
    if not args.fsonos:
        parser.error("--fsonos is required unless --check-recorded")
    data = measure(args.fsonos)
    for line in data["problems"]:
        print("PROBLEM", line, file=sys.stderr)
    if data["problems"]:
        return 1
    text = json.dumps(data, indent=2) + "\n"
    if args.write:
        RECORDED.write_text(text, encoding="utf-8")
        print(f"wrote {RECORDED}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
