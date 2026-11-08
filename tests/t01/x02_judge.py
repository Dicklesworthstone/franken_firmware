#!/usr/bin/env python3
"""T01-X02 on-target footprint: the transcript judge and the guest-run front end (bead ffw-32a).

Reached as `scripts/e2e/t01 --x02 run|analyze ...`. Standard library only. It compiles nothing, contacts nothing and never runs cargo.

What the probe prints (GRAMMAR below; agreed with TealSeal in thread ffw-32a, their mail 15473, 2026-11-08T20:55Z)
    T01X02 PHASE <NAME> ok|fail <k=v ...>   once per expected phase, in EXPECTED_PHASES order; facts are `key=value` pairs (a failure is `fail reason=<word>`)
    T01X02 VmHWM <uint>|UNKNOWN             kB as /proc/self/status reports them, then VmRSS (kB), utime and stime (raw /proc clock ticks), each exactly once
    T01X02 END ok=<n> fail=<n> unknown=<n>  last T01X02 line; ok/fail count the PHASE lines, unknown counts the resource lines that read UNKNOWN
The probe exits 0 whenever it printed END (the verdict is the transcript, judged here), so the supervisor envelope sees a clean child exit.

Verdicts (a FAIL outranks BLOCKED, BLOCKED outranks PASS; exit 1, 3, 0)
    FAIL     framing other than LF/CRLF, a control character or U+FFFD; a marker that is not at the start of a line (an echo); an unrecognized or
             malformed T01X02 line; a missing, duplicate, extra or out-of-order PHASE; any PHASE `fail`; a non-canonical integer; a duplicate
             resource line; VmHWM below VmRSS or either of them 0 (a running process has resident pages and VmHWM is the peak of VmRSS); a missing,
             duplicate or non-final END; END totals that contradict what the judge counted itself; and, for a captured run, a timeout or output
             limit, a QEMU exit other than 0, a missing reboot or any hash that changed between before and after.
    BLOCKED  a resource line that reads UNKNOWN or is missing. Never a pass: the footprint is then not measured.
    PASS     everything above is clean. A pass says only that this transcript has the grammar and the arithmetic.

Evidence kinds: `captured_guest_execution` (this module booted the ELF) and `supplied_transcript_analysis` (a transcript somebody supplied; it
proves nothing about which ELF produced it). A synthetic transcript tests the judge, not the target. T01-X02 stays pending until a real guest run.

The guest run is NOT re-implemented here: the E07 speaker-smoke supervisor slot, the 1 MiB / 180 s capture bounds, the exclusive log directory
and receipt, the kernel snapshot and the ELF/kernel/initramfs hash checks all come from toolchain/src/measure-p05-target.py (which wraps
run-qemu-verification.py), loaded by path.
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
P05_RUNTIME = REPO / "toolchain" / "src" / "measure-p05-target.py"

PREFIX = "T01X02"
GRAMMAR = "ffw.t01.x02_transcript.v1"
RECEIPT_SCHEMA = "ffw.t01.x02_receipt.v1"
# The agreed phase table: one phase per tailscale-rs core crate (tests/t01/cases.json "core_crates"), then DarkPeak's crypto known-answer phase last
# (kat.rs, thread ffw-32a). Until kat.rs is wired into the probe it prints seven phases and `END ok=7`, which this eight-phase table correctly refuses.
EXPECTED_PHASES = ("TS_KEYS", "TS_NOISE", "TS_TUNNEL", "TS_CONTROL_SERDE", "TS_PACKETFILTER_STATE", "TS_DISCO_PROTOCOL", "TS_OVERLAY_ROUTER", "CRYPTO_KAT")
RESOURCE_ORDER = ("VmHWM", "VmRSS", "utime", "stime")
CAPTURE_BYTES = 1024 * 1024  # the same bound as measure-p05-target.RUNTIME_CAPTURE_BYTES (pinned by a test)
DEFAULT_TIMEOUT = 180.0
ARCHES = ("mips", "powerpc")
UINT_MAX = (1 << 64) - 1

_FACT = r"[a-z][a-z0-9_]*=[\x21-\x3c\x3e-\x7e]+"
_PHASE = re.compile(rf"{PREFIX} PHASE ([A-Z][A-Z0-9_]*) (ok|fail)((?: {_FACT})*)")
_RESOURCE = re.compile(rf"{PREFIX} (VmHWM|VmRSS|utime|stime) ([^ ]+)")
_END = re.compile(rf"{PREFIX} END ok=([^ ]+) fail=([^ ]+) unknown=([^ ]+)")
_CANONICAL = re.compile(r"0|[1-9][0-9]*")
# Everything but LF (and a tab) that a serial contract treats as a line break or a control, and U+FFFD from a lossy decode.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}\N{REPLACEMENT CHARACTER}]")

SCOPE = (
    "A pass judges the T01X02 grammar and arithmetic of one transcript. A synthetic transcript tests the judge, not the target. A captured run is "
    "one full-system QEMU guest on the harness's Debian kernel, not a Sonos 2.6.14 PowerPC or 2.6.35 MIPS kernel and not a board, so its figures "
    "are indicative only. T01-X02 stays pending until a real guest run is judged and the bead owner closes it; this tool closes nothing."
)


class X02Error(Exception):
    """The request cannot be judged; the message says why (exit 2)."""


@dataclasses.dataclass
class Gate:
    gate_id: str
    title: str
    status: str  # passed | failed | blocked
    detail: str = ""


def make_gate(gate_id: str, title: str, failures: list[str], blocks: list[str] | None = None) -> Gate:
    blocks = blocks or []
    status = "failed" if failures else "blocked" if blocks else "passed"
    return Gate(gate_id, title, status, "; ".join(failures + blocks))


def canonical_uint(token: str) -> int | None:
    """ASCII decimal as the probe prints it: no sign, no leading zero, no underscore, no Unicode digit, at most 2^64-1."""
    if len(token) > 20 or _CANONICAL.fullmatch(token) is None:
        return None
    value = int(token)
    return value if value <= UINT_MAX else None


@dataclasses.dataclass
class Verdict:
    gates: list[Gate]
    phases: list[dict[str, Any]]
    resources: dict[str, int | str | None]
    end: dict[str, int] | None
    counted: dict[str, int]

    @property
    def status(self) -> str:
        return exit_status(self.gates)

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status, "phases": self.phases, "resources": self.resources, "end": self.end, "counted": self.counted,
                "grammar": GRAMMAR}


def exit_status(gates: list[Gate]) -> str:
    if any(g.status == "failed" for g in gates):
        return "failed"
    return "blocked" if any(g.status == "blocked" for g in gates) else "passed"


def exit_code(gates: list[Gate]) -> int:
    return {"passed": 0, "failed": 1, "blocked": 3}[exit_status(gates)]


def judge_transcript(text: str, *, crlf_ok: bool = True) -> Verdict:
    """Judge the T01X02 lines of one transcript. `crlf_ok=False` is for a child region already mapped back to LF, where any CR is a defect."""
    framing: list[str] = []
    phase_fail: list[str] = []
    res_fail: list[str] = []
    res_block: list[str] = []
    end_fail: list[str] = []
    body = text.replace("\r\n", "\n") if crlf_ok else text  # one normalization only: a leftover CR (CR-CR-LF) stays visible
    if _CONTROL.search(body):
        framing.append("control character, line separator other than LF/CRLF, or invalid UTF-8")
    events: list[tuple[str, Any]] = []
    for number, line in enumerate(body.split("\n"), 1):
        if PREFIX not in line:
            continue
        if not line.startswith(PREFIX + " "):
            framing.append(f"line {number}: {PREFIX} is not at the start of the line (an echo or a prefixed line)")
            continue
        if (m := _PHASE.fullmatch(line)) is not None:
            facts: dict[str, str] = {}
            for token in m[3].split():
                key, value = token.split("=", 1)
                if key in facts:
                    phase_fail.append(f"line {number}: {m[1]} repeats the fact key {key}")
                facts[key] = value
            events.append(("phase", {"name": m[1], "status": m[2], "facts": facts}))
        elif (m := _RESOURCE.fullmatch(line)) is not None:
            events.append(("resource", (m[1], m[2])))
        elif (m := _END.fullmatch(line)) is not None:
            events.append(("end", m.groups()))
        else:
            framing.append(f"line {number}: unrecognized or malformed {PREFIX} line {line[:60]!r}")

    phases = [payload for kind, payload in events if kind == "phase"]
    names = [p["name"] for p in phases]
    missing = [n for n in EXPECTED_PHASES if n not in names]
    duplicated = sorted({n for n in names if names.count(n) > 1})
    extra = [n for n in names if n not in EXPECTED_PHASES]
    phase_fail += [f"phase {n} is missing" for n in missing] + [f"phase {n} appears more than once" for n in duplicated]
    phase_fail += [f"phase {n} is not an expected phase" for n in extra]
    if not (missing or duplicated or extra) and names != list(EXPECTED_PHASES):
        phase_fail.append(f"phases are out of order: {names}")
    phase_fail += [f"phase {p['name']} reports fail ({' '.join(f'{k}={v}' for k, v in p['facts'].items())})" for p in phases if p["status"] == "fail"]
    kinds = [kind for kind, _ in events]
    if "phase" in kinds and any(kind != "phase" for kind in kinds[:max(i for i, k in enumerate(kinds) if k == "phase")]):
        phase_fail.append("a PHASE line follows a resource or END line")

    resources: dict[str, int | str | None] = {key: None for key in RESOURCE_ORDER}
    observed = [payload for kind, payload in events if kind == "resource"]
    seen_keys = [key for key, _ in observed]
    for key in RESOURCE_ORDER:
        tokens = [token for k, token in observed if k == key]
        if not tokens:
            res_block.append(f"{key} line is missing")
        elif len(tokens) > 1:
            res_fail.append(f"{key} appears more than once")
        elif tokens[0] == "UNKNOWN":
            resources[key] = "UNKNOWN"
            res_block.append(f"{key} is UNKNOWN")
        elif (value := canonical_uint(tokens[0])) is None:
            res_fail.append(f"{key} is not a canonical integer: {tokens[0]!r}")
        else:
            resources[key] = value
    if len(seen_keys) == len(set(seen_keys)) and seen_keys != [k for k in RESOURCE_ORDER if k in seen_keys]:
        res_fail.append(f"resource lines are out of order: {seen_keys}")
    hwm, rss = resources["VmHWM"], resources["VmRSS"]
    for key, value in (("VmHWM", hwm), ("VmRSS", rss)):
        if value == 0:
            res_fail.append(f"{key} is 0, but a running process has resident pages")
    if isinstance(hwm, int) and isinstance(rss, int) and hwm < rss:
        res_fail.append(f"VmHWM {hwm} is below VmRSS {rss}, but VmHWM is the peak of VmRSS")

    counted = {"ok": sum(p["status"] == "ok" for p in phases), "fail": sum(p["status"] == "fail" for p in phases),
               "unknown": sum(token == "UNKNOWN" for _, token in observed)}
    ends = [payload for kind, payload in events if kind == "end"]
    end: dict[str, int] | None = None
    if not ends:
        end_fail.append("END line is missing (the probe did not finish)")
    else:
        if len(ends) > 1:
            end_fail.append("END appears more than once")
        if kinds[-1] != "end":
            end_fail.append("T01X02 lines follow END, or END is not the last T01X02 line")
        values = [canonical_uint(token) for token in ends[0]]
        if None in values:
            end_fail.append(f"END holds a non-canonical integer: {list(ends[0])}")
        else:
            end = dict(zip(("ok", "fail", "unknown"), values))
            if end != counted:
                end_fail.append(f"END {end} contradicts the {counted} the judge counted")
    gates = [make_gate("X02-FRAMING", "LF/CRLF framing, markers at line start, only recognized lines", framing),
             make_gate("X02-PHASES", "every expected phase exactly once, in order, all ok", phase_fail),
             make_gate("X02-RESOURCES", "VmHWM, VmRSS, utime, stime each once, canonical, known and consistent", res_fail, res_block),
             make_gate("X02-END", "one final END whose totals equal the judge's own count", end_fail)]
    return Verdict(gates, [{"name": p["name"], "status": p["status"], "facts": p["facts"]} for p in phases], resources, end, counted)


def capture_problems(meta: dict[str, Any], elf: dict[str, Any], supervisor: dict[str, Any], after: dict[str, str | None]) -> list[str]:
    """Custody of one captured run. `after` holds the sha256 of the named ELF and supervisor re-read AFTER the run (None if unreadable)."""
    problems = []
    if meta.get("stop_reason") is not None:
        problems.append(f"the capture was stopped ({meta['stop_reason']}); a timeout or an output limit is never a pass")
    if meta.get("exit_code") != 0:
        problems.append(f"QEMU exited {meta.get('exit_code')}, not 0 (no reboot-driven shutdown)")
    initramfs = meta.get("initramfs", {})
    if initramfs.get("init_sha256") != supervisor["sha256"]:
        problems.append("supervisor bytes changed before packaging")
    if initramfs.get("extra_files", {}).get("franken-speaker", {}).get("sha256") != elf["sha256"]:
        problems.append("probe ELF bytes changed before packaging")
    for name, expected in (("kernel", meta.get("kernel_sha256")), ("initramfs", initramfs.get("archive_sha256"))):
        if expected is None or meta.get("inputs_after_capture", {}).get(name) != expected:
            problems.append(f"{name} changed or became unreadable during the run")
    for name, identity in (("probe ELF", elf), ("supervisor ELF", supervisor)):
        if after.get(name) != identity["sha256"]:
            problems.append(f"{name} changed on disk after the run or became unreadable")
    return problems


# ---- the consumer: judging a receipt this module wrote --------------------------------------------------------------------------------------------------
# tests/t01/run_cases.py `case_resources` reads every receipt under toolchain/results/tailscale/measurements/ through judge_receipt. A receipt is never trusted for
# its own `result`: the recorded phases, resources and END are rebuilt into a transcript and judged again by judge_transcript (one rule set, not two), and the
# hashes and the gate list must agree with each other.

MAX_RECEIPT_BYTES = 1024 * 1024
RECEIPT_KINDS = ("captured_guest_execution", "supplied_transcript_analysis")
RECEIPT_RESULTS = ("passed", "not_passed", "blocked")
REQUIRED_GATES = ("P05R-SUPERVISOR", "X02-FRAMING", "X02-PHASES", "X02-RESOURCES", "X02-END", "X02-CAPTURE")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclasses.dataclass
class ReceiptJudgement:
    state: str  # passed | failed | blocked | analysis_only
    problems: list[str]
    arch: str | None = None
    resources: dict[str, int] | None = None


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= UINT_MAX


def _dig(obj: Any, *path: str) -> Any:
    for key in path:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def _strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in items}) != len(items):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError("non-finite number " + name)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _absolute_path_in(node: Any, where: str = "the receipt") -> tuple[str, str] | None:
    """Where, and under which root directory, the first absolute host path in any string or key of `node` sits. The path itself is never repeated."""
    if isinstance(node, str):
        match = ABSOLUTE_PATH.search(node)
        return (where, match.group(0).split("/")[1]) if match else None
    if isinstance(node, list):
        for index, item in enumerate(node):
            hit = _absolute_path_in(item, f"{where}[{index}]")
            if hit:
                return hit
    if isinstance(node, dict):
        for key, item in node.items():
            hit = _absolute_path_in(key, f"{where}.<key>") if isinstance(key, str) else None
            hit = hit or _absolute_path_in(item, f"{where}.{str(key)[:30]}")
            if hit:
                return hit
    return None


def _rebuild(verdict: dict[str, Any]) -> tuple[list[str], list[str]]:
    """The T01X02 lines a receipt's recorded verdict stands for, and what is malformed about it."""
    lines: list[str] = []
    bad: list[str] = []
    phases = verdict.get("phases")
    if not isinstance(phases, list):
        bad.append("verdict.phases is not a list")
        phases = []
    for phase in phases:
        facts = phase.get("facts") if isinstance(phase, dict) else None
        if not (isinstance(phase, dict) and isinstance(phase.get("name"), str) and phase.get("status") in ("ok", "fail") and isinstance(facts, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in facts.items())):
            bad.append("a verdict phase record is malformed")
            continue
        lines.append(f"{PREFIX} PHASE {phase['name']} {phase['status']}" + "".join(f" {k}={v}" for k, v in facts.items()))
    resources = verdict.get("resources")
    if not isinstance(resources, dict) or set(resources) != set(RESOURCE_ORDER):
        bad.append("verdict.resources does not hold exactly " + ", ".join(RESOURCE_ORDER))
    else:
        for key in RESOURCE_ORDER:
            value = resources[key]
            if value is None:
                continue  # the line was missing from the transcript
            if value != "UNKNOWN" and not _is_uint(value):
                bad.append(f"verdict.resources.{key} is not a canonical integer or UNKNOWN")
                continue
            lines.append(f"{PREFIX} {key} {value}")
    end = verdict.get("end")
    if end is not None:
        if isinstance(end, dict) and set(end) == {"ok", "fail", "unknown"} and all(_is_uint(v) for v in end.values()):
            lines.append(f"{PREFIX} END ok={end['ok']} fail={end['fail']} unknown={end['unknown']}")
        else:
            bad.append("verdict.end is malformed")
    return lines, bad


def judge_receipt(text: str) -> ReceiptJudgement:
    """Judge one receipt written by `run` or `analyze`. `failed` carries the reasons by name; `analysis_only` is a supplied-transcript analysis, which is never
    execution evidence; `blocked` is a captured run whose footprint is not fully measured; `passed` only for a captured run that holds up under every check."""
    def failed(*problems: str, arch: str | None = None) -> ReceiptJudgement:
        return ReceiptJudgement("failed", list(problems), arch)

    try:
        body = _strict_json(text)
    except (ValueError, RecursionError) as err:
        return failed(f"not a valid JSON receipt ({str(err)[:60]})")
    if not isinstance(body, dict):
        return failed("the receipt is not a JSON object")
    for key, want in (("schema", RECEIPT_SCHEMA), ("grammar", GRAMMAR)):
        if body.get(key) != want:
            return failed(f"{key} {str(body.get(key))[:50]!r} is not {want}")
    found = _absolute_path_in(body)
    if found is not None:
        return failed(f"the receipt carries an absolute path under /{found[1]}/ at {found[0]}; a committed receipt holds repo-relative or {OUTSIDE_REPO} paths only")
    hashes = body.get("path_hashes")
    if hashes is not None and not (isinstance(hashes, list) and all(
            isinstance(entry, dict) and set(entry) == {"path", "sha256"} and isinstance(entry["path"], str) and entry["path"] and not entry["path"].startswith("/")
            and ".." not in entry["path"].split("/") and (entry["sha256"] is None or _is_sha(entry["sha256"])) for entry in hashes)):
        return failed("path_hashes is malformed (each entry is a relative path and a lowercase sha256 or null)")
    kind, declared, arch = body.get("evidence_kind"), body.get("result"), body.get("arch")
    if kind not in RECEIPT_KINDS:
        return failed(f"evidence_kind {str(kind)[:50]!r} is not one of {', '.join(RECEIPT_KINDS)}")
    if declared not in RECEIPT_RESULTS:
        return failed(f"result {str(declared)[:50]!r} is not one of {', '.join(RECEIPT_RESULTS)}")
    if kind == "supplied_transcript_analysis":
        if arch is not None and arch not in ARCHES:
            return failed(f"arch {str(arch)[:30]!r} is not one of {', '.join(ARCHES)}")
        return ReceiptJudgement("analysis_only", [f"supplied_transcript_analysis (declared {declared}) is a judged transcript, not a guest run"], arch)
    if arch not in ARCHES:
        return failed(f"arch {str(arch)[:30]!r} is not one of {', '.join(ARCHES)}")

    problems: list[str] = []  # the receipt is malformed or does not hold together
    custody: list[str] = []  # the run itself was not clean; for a receipt that says so, these are the reason it did not pass, not a defect of the receipt
    for label in ("elf", "supervisor_elf"):
        if not _is_sha(_dig(body, label, "sha256")) or _dig(body, label, "arch") != arch:
            problems.append(f"{label} identity (sha256 and arch {arch}) is missing or malformed")
    run = body.get("execution")
    if not isinstance(run, dict):
        problems.append("the execution record is missing (a captured run carries one)")
    else:
        if type(run.get("exit_code")) is not int or run.get("exit_code") != 0 or "stop_reason" not in run or run.get("stop_reason") is not None:
            custody.append(f"the capture did not end cleanly (exit_code {str(run.get('exit_code'))[:12]}, stop_reason {str(run.get('stop_reason'))[:20]})")
        shas = {"kernel_sha256": run.get("kernel_sha256"), "initramfs.archive_sha256": _dig(run, "initramfs", "archive_sha256"),
                "initramfs.init_sha256": _dig(run, "initramfs", "init_sha256"), "stdout_sha256": run.get("stdout_sha256"),
                "initramfs.extra_files.franken-speaker.sha256": _dig(run, "initramfs", "extra_files", "franken-speaker", "sha256"),
                "inputs_after_capture.kernel": _dig(run, "inputs_after_capture", "kernel"),
                "inputs_after_capture.initramfs": _dig(run, "inputs_after_capture", "initramfs")}
        problems += [f"{name} hash is missing or malformed" for name, value in shas.items() if not _is_sha(value)]
        for name, left, right in (("kernel hash differs before and after the run", shas["kernel_sha256"], shas["inputs_after_capture.kernel"]),
                                  ("initramfs hash differs before and after the run", shas["initramfs.archive_sha256"], shas["inputs_after_capture.initramfs"]),
                                  ("the packaged supervisor is not the named supervisor ELF", shas["initramfs.init_sha256"], _dig(body, "supervisor_elf", "sha256")),
                                  ("the packaged probe is not the named probe ELF", shas["initramfs.extra_files.franken-speaker.sha256"], _dig(body, "elf", "sha256"))):
            if _is_sha(left) and _is_sha(right) and left != right:
                custody.append(name)
        if _is_sha(body.get("transcript_sha256")) and _is_sha(shas["stdout_sha256"]) and body["transcript_sha256"] != shas["stdout_sha256"]:
            problems.append("transcript_sha256 is not the captured stdout hash")
        elif not _is_sha(body.get("transcript_sha256")):
            problems.append("transcript_sha256 is missing or malformed")
    if declared != "not_passed":
        problems += custody
    verdict = body.get("verdict")
    rebuilt = None
    if verdict is None and declared == "not_passed":
        pass  # the supervisor envelope yielded no child transcript, so the run has no verdict to rebuild; it is a failure either way
    elif not isinstance(verdict, dict):
        problems.append("the verdict record is missing")
    else:
        lines, bad = _rebuild(verdict)
        problems += bad
        if not bad:
            rebuilt = judge_transcript("\n".join(lines) + "\n", crlf_ok=False)
            if verdict.get("status") != rebuilt.status:
                problems.append(f"verdict.status {str(verdict.get('status'))[:12]!r} disagrees with its recorded facts, which judge as {rebuilt.status}")
    gates = body.get("gates")
    recorded: dict[str, str] = {}
    if not (isinstance(gates, list) and all(isinstance(g, dict) and isinstance(g.get("gate_id"), str) and g.get("status") in ("passed", "failed", "blocked") for g in gates)):
        problems.append("the gate list is missing or malformed")
    else:
        ids = [g["gate_id"] for g in gates]
        required = REQUIRED_GATES if declared != "not_passed" else ("X02-CAPTURE",)
        problems += [f"gate {name} is missing or repeated" for name in required if ids.count(name) != 1]
        recorded = {g["gate_id"]: g["status"] for g in gates}
    if problems:
        return failed(*problems, arch=arch)

    if declared == "not_passed":
        why = [f"{g['gate_id']}: {str(g.get('detail', ''))[:80]}" for g in gates if g["status"] == "failed"]
        if not why:
            return failed("the receipt declares not_passed but records no failed gate", arch=arch)
        return failed("a captured run did not pass (" + "; ".join(why[:2]) + ")", arch=arch)  # `custody` above is the same story told by the hashes
    assert rebuilt is not None
    statuses = set(recorded.values())
    disagreements = [f"gate {g.gate_id} is recorded {recorded.get(g.gate_id)} but its facts judge {g.status}" for g in rebuilt.gates if recorded.get(g.gate_id) != g.status]
    if disagreements:
        return failed(*disagreements, arch=arch)
    if declared == "passed":
        if rebuilt.status != "passed" or statuses != {"passed"}:
            return failed("the receipt declares passed but a recorded gate or fact does not", arch=arch)
        return ReceiptJudgement("passed", [], arch, {key: int(rebuilt.resources[key]) for key in RESOURCE_ORDER})  # type: ignore[arg-type]
    if rebuilt.status != "blocked" or "failed" in statuses:
        return failed("the receipt declares blocked but its facts do not judge as blocked", arch=arch)
    return ReceiptJudgement("blocked", [g.detail for g in rebuilt.gates if g.status == "blocked"], arch)


@functools.lru_cache(maxsize=1)
def _p05() -> Any:
    """The P05 runtime layer, loaded by path (its file name has a hyphen). Nothing in it is copied here."""
    name = "t01_x02_p05_runtime"
    spec = importlib.util.spec_from_file_location(name, P05_RUNTIME)
    if spec is None or spec.loader is None:
        raise X02Error(f"cannot load {P05_RUNTIME}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def capture_guest_run(p05: Any, namespace: argparse.Namespace, elf: dict[str, Any], supervisor: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Boot the ELF in the existing E07 speaker-smoke slot. A single seam, so tests can replace the guest and nothing else."""
    return p05.run_runtime(namespace, elf, supervisor)


def _gates_from(p05_gates: list[Any]) -> list[Gate]:
    return [Gate(g.gate_id, g.title, g.status, g.detail) for g in p05_gates]


def _read_bounded(path: pathlib.Path) -> bytes:
    if not path.is_file():
        raise X02Error("a regular transcript file is required")
    with path.open("rb") as source:
        raw = source.read(CAPTURE_BYTES + 1)
    if len(raw) > CAPTURE_BYTES:
        raise X02Error("transcript exceeds the bounded capture size")
    return raw


# ---- receipt path hygiene --------------------------------------------------------------------------------------------------------------------------------
# A receipt meant for toolchain/results/tailscale/measurements/ is committed, so it must not carry the home directory, the scratch directory or a worker mount of whoever
# ran the guest. The P05 layer records absolute paths (the QEMU command line, the initramfs build record); the writer rewrites them here, in the receipt only: a path
# under the repository becomes repo-relative, any other becomes `<outside-repo>/<basename>`, and each rewritten path is listed in `path_hashes` with the sha256 of the
# file it named, so the receipt still binds the bytes. The writer refuses to write a receipt in which an absolute path survives; the consumer refuses to read one.

PATH_ROOTS = ("Users", "home", "private", "var", "tmp", "root", "Volumes", "mnt", "srv", "data", "bulk")
ABSOLUTE_PATH = re.compile(rf"(?<![A-Za-z0-9_.~-])/(?:{'|'.join(PATH_ROOTS)})(?=/|[\s\"'<>,;)=]|$)(?:/[^\s\"'<>,;)=]*)?")
OUTSIDE_REPO = "<outside-repo>"
HASH_CAP = 512 * 1024 * 1024


def _file_sha256(path: str) -> str | None:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > HASH_CAP:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            while chunk := source.read(1 << 20):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _relocate(path: str, seen: list[dict[str, Any]]) -> str:
    clean = os.path.normpath(path)
    label = None
    for base in dict.fromkeys((REPO.as_posix(), REPO.resolve().as_posix())):
        if clean == base:
            label = "."
        elif clean.startswith(base + "/"):
            label = clean[len(base) + 1:]
    if label is None:
        label = f"{OUTSIDE_REPO}/{os.path.basename(clean) or 'root'}"
    entry = {"path": label, "sha256": _file_sha256(path)}
    if entry not in seen:
        seen.append(entry)
    return label


def _scrub(value: Any, seen: list[dict[str, Any]]) -> Any:
    """`value` with every absolute host path in any string (and any key) rewritten; `seen` collects the path/sha256 pairs."""
    if isinstance(value, str):
        return ABSOLUTE_PATH.sub(lambda match: _relocate(match.group(0), seen), value)
    if isinstance(value, list):
        return [_scrub(item, seen) for item in value]
    if isinstance(value, dict):
        return {(_scrub(key, seen) if isinstance(key, str) else key): _scrub(item, seen) for key, item in value.items()}
    return value


def _finish(args: argparse.Namespace, gates: list[Gate], verdict: Verdict | None, kind: str, elf: dict[str, Any] | None,
            supervisor: dict[str, Any] | None, meta: dict[str, Any] | None, transcript_sha256: str, child_sha256: str | None) -> int:
    code = exit_code(gates)
    outcome = {0: "passed", 1: "not_passed", 3: "blocked"}[code]
    if args.receipt is not None:
        body = {"schema": RECEIPT_SCHEMA, "grammar": GRAMMAR, "result": outcome, "arch": args.arch, "evidence_kind": kind,
                "revision_claim": args.revision, "elf": elf, "supervisor_elf": supervisor, "execution": meta,
                "transcript_sha256": transcript_sha256, "child_sha256": child_sha256,
                "verdict": verdict.to_json() if verdict is not None else None, "gates": [dataclasses.asdict(g) for g in gates],
                "scope": SCOPE}
        seen: list[dict[str, Any]] = []
        body = _scrub(body, seen)
        body["path_hashes"] = seen
        leftover = ABSOLUTE_PATH.search(json.dumps(body))
        if leftover is not None:
            raise X02Error("refusing to write a receipt that still carries an absolute path under /" + leftover.group(0).split("/")[1] + "/; nothing was written")
        with args.receipt.open("x", encoding="utf-8") as handle:  # exclusive: an existing receipt is never overwritten
            json.dump(body, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(f"T01-X02 {kind}")
    for g in gates:
        print(f"{g.status.upper()} {g.gate_id}: {g.title}" + (f" — {g.detail}" if g.detail else ""))
    print({0: "PASSED", 1: "NOT PASSED", 3: "BLOCKED"}[code])
    print(SCOPE)
    return code


def _judge_supervised(text: str, arch: str) -> tuple[Verdict | None, list[Gate], str]:
    p05 = _p05()
    try:
        child, envelope = p05.runtime_envelope(text, arch)
    except UnicodeDecodeError:
        child, envelope = "", [Gate("P05R-SUPERVISOR", "complete smoke-slot child envelope", "failed", "child region is not valid UTF-8")]
    gates = _gates_from(envelope)
    if not child:
        return None, gates + [Gate("X02-TRANSCRIPT", "a child transcript to judge", "failed", "the supervisor envelope yielded no child region")], ""
    verdict = judge_transcript(child, crlf_ok=False)
    return verdict, gates + verdict.gates, child


def run_command(args: argparse.Namespace) -> int:
    p05 = _p05()
    if args.receipt is not None:
        if os.path.lexists(args.receipt):
            raise X02Error("receipt already exists; no guest execution started")
        if not (args.receipt.parent.is_dir() or args.receipt.parent.resolve() == args.log_dir.resolve()):
            raise X02Error("the receipt's directory does not exist; no guest execution started")
    elf = p05.runtime_elf(args.elf, args.arch)
    supervisor = p05.runtime_elf(args.supervisor, args.arch)
    namespace = argparse.Namespace(arch=args.arch, elf=args.elf, supervisor=args.supervisor, log_dir=args.log_dir, timeout=args.timeout)
    text, meta = capture_guest_run(p05, namespace, elf, supervisor)
    after: dict[str, str | None] = {}
    for name, path in (("probe ELF", args.elf), ("supervisor ELF", args.supervisor)):
        try:
            after[name] = p05.runtime_file_identity(path)[1]["sha256"]
        except (OSError, p05.MeasurementError):
            after[name] = None
    verdict, gates, child = _judge_supervised(text, args.arch)
    gates.append(make_gate("X02-CAPTURE", "bounded complete capture, clean exit and unchanged inputs", capture_problems(meta, elf, supervisor, after)))
    child_sha = hashlib.sha256(child.encode("utf-8")).hexdigest() if child else None
    return _finish(args, gates, verdict, "captured_guest_execution", elf, supervisor, meta, meta["stdout_sha256"], child_sha)


def analyze_command(args: argparse.Namespace) -> int:
    if args.log is None:
        print("BLOCKED: no X02 transcript supplied (nothing is claimed)")
        return 3
    if args.receipt is not None and os.path.lexists(args.receipt):
        raise X02Error("receipt already exists; no analysis started")
    if args.supervisor is not None and args.arch is None:
        raise X02Error("--supervisor needs --arch")
    raw = _read_bounded(args.log)
    text = raw.decode("utf-8", "replace")
    p05 = _p05() if (args.supervisor is not None or args.elf is not None) else None
    elf = p05.runtime_elf(args.elf, args.arch) if args.elf is not None and args.arch is not None else None
    if args.elf is not None and args.arch is None:
        raise X02Error("--elf needs --arch")
    supervisor = p05.runtime_elf(args.supervisor, args.arch) if args.supervisor is not None else None
    if supervisor is not None:
        verdict, gates, child = _judge_supervised(text, args.arch)
    else:
        verdict = judge_transcript(text)
        gates, child = verdict.gates, text
    child_sha = hashlib.sha256(child.encode("utf-8")).hexdigest() if child else None
    return _finish(args, gates, verdict, "supplied_transcript_analysis", elf, supervisor, None, hashlib.sha256(raw).hexdigest(), child_sha)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scripts/e2e/t01 --x02", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="boot an already-built probe ELF under the existing QEMU guest and judge its transcript; no compilation")
    run.add_argument("--arch", choices=ARCHES, required=True)
    run.add_argument("--elf", type=pathlib.Path, required=True, help="the t01-core-probe ELF for the architecture")
    run.add_argument("--supervisor", type=pathlib.Path, required=True, help="the matching ffw-hello-init built with speaker-smoke only")
    run.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial and QEMU logs")
    run.add_argument("--receipt", type=pathlib.Path, help="exclusive-create JSON receipt")
    run.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    run.add_argument("--revision", help="operator-supplied source claim; not a build attestation")
    analyze = sub.add_parser("analyze", help="judge a supplied transcript (supplied_transcript_analysis)")
    analyze.add_argument("--log", type=pathlib.Path)
    analyze.add_argument("--arch", choices=ARCHES)
    analyze.add_argument("--elf", type=pathlib.Path, help="records the ELF identity; needs --arch")
    analyze.add_argument("--supervisor", type=pathlib.Path, help="judge a full serial log through the E07 supervisor envelope; needs --arch")
    analyze.add_argument("--receipt", type=pathlib.Path)
    analyze.add_argument("--revision")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors: tuple[type[BaseException], ...] = (X02Error, OSError, ValueError, subprocess.CalledProcessError)
    try:
        if args.command == "run" or args.supervisor is not None or args.elf is not None:
            errors += (_p05().MeasurementError,)
        return run_command(args) if args.command == "run" else analyze_command(args)
    except errors as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
