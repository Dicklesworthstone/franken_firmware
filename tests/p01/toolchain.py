"""P01-BLK-004: the toolchain the build asks for, and the one it was built by. Read-only, stdlib only.

Three questions, each with its own findings (stable codes):

1. THE PIN FILE (`judge_pin`). The repository's `rust-toolchain.toml` names exactly one thing, `[toolchain] channel`, and that is an
   EXACT release `X.Y.Z`: not `nightly`, `stable` or `beta`, not a dated nightly, not `X.Y`. Nothing else is in the file (no
   `components`, `targets`, `profile`: only the bare channel has been shown to work on the workers), and no legacy `rust-toolchain`
   file stands beside it.
2. THE PLAN (`judge_plan`). Every device build line asks for the one DATED nightly `plan.DEVICE_TOOLCHAIN` (a floating `+nightly` is
   whatever each worker had that day), every host line asks for no selector at all (it resolves the pin), and no `rustc +X` line
   exists (rch drops the `+X` and prints the default compiler, so such a line proves nothing about X).
3. THE RECEIPT (`judge_identity`). A central record names the compiler that built what it holds: the bare `rustc -vV` release equals
   the pin, each host artifact carries `rustc version <the pin>` in its own bytes, and each device artifact carries EXACTLY
   `plan.DEVICE_RUSTC_VERSION`. A floating nightly (the worker's default) fails that; so does a record whose artifacts disagree. A record
   made before the pin, or before artifact compilers were recorded, is not a receipt for this compiler: BLOCKED, never a pass.

`plan.DEVICE_RUSTC_VERSION` is MEASURED, not derived and not read from a receipt: a dated nightly is immutable, and `rustc
+nightly-2026-08-31 -V` prints it on any host that has the toolchain. It has not yet been seen in a central receipt, so the first receipt
is its test. `judge_plan` keeps the two constants in step: the string's commit date must be within three days before the toolchain's date
(measured on five dated nightlies: one day before on four, three on the one that follows a holiday weekend) and never after it.

What a pass does not show: that the compiler is the right one for the hardware, that a build on it is correct, or anything about a
guest or a device. It shows that the pin file, the plan and a central record agree about which compiler was used.
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover
    raise SystemExit("python 3.11+ is required (tomllib)")

import plan as plan_mod
import reference as ref

PIN_FILE = plan_mod.PIN_FILE
WINDOW_DAYS = 3
Finding = Tuple[str, str]
Verdict = Tuple[str, List[Finding], str]
_EXACT = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DATED = re.compile(r"^nightly-([0-9]{4})-([0-9]{2})-([0-9]{2})$")
_VERSION = re.compile(r"^([0-9]+\.[0-9]+\.[0-9]+)(-nightly|-beta\.[0-9]+)? \(([0-9a-f]{7,12}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)")


def read_pin(text: Optional[str]) -> Tuple[Optional[str], List[Finding]]:
    """(channel or None, findings) for the text of `rust-toolchain.toml` (None for a missing file)."""
    if text is None:
        return None, [("pin_missing", PIN_FILE)]
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None, [("pin_unreadable", PIN_FILE)]
    findings: List[Finding] = []
    other = sorted(k for k in data if k != "toolchain")
    table = data.get("toolchain")
    if not isinstance(table, dict):
        return None, [("pin_no_toolchain_table", PIN_FILE)]
    extra = [f"toolchain.{k}" for k in sorted(table) if k != "channel"] + other
    if extra:
        findings.append(("pin_extra_content", ",".join(extra)))
    channel = table.get("channel")
    if not isinstance(channel, str):
        return None, findings + [("pin_no_channel", PIN_FILE)]
    if not _EXACT.match(channel):
        findings.append(("pin_channel_not_exact", channel))
    return channel, findings


def judge_pin(text: Optional[str], legacy_file_present: bool = False) -> Tuple[Optional[str], List[Finding]]:
    channel, findings = read_pin(text)
    if legacy_file_present:
        findings.append(("pin_legacy_file_present", "rust-toolchain"))
    return channel, sorted(set(findings))


def judge_plan(steps: Sequence[Dict[str, Any]], device_toolchain: str, device_rustc: str) -> List[Finding]:
    """Findings for a plan's toolchain selectors. `device_toolchain` and `device_rustc` are the constants the plan was built from
    (`plan.DEVICE_TOOLCHAIN`, `plan.DEVICE_RUSTC_VERSION`)."""
    findings: List[Finding] = []
    if not _DATED.match(device_toolchain):
        findings.append(("plan_device_toolchain_not_dated", device_toolchain))
    elif not _device_ok(device_rustc, _device_window(device_toolchain)):
        findings.append(("plan_device_rustc_not_from_the_toolchain_date", device_rustc))
    for step in steps:
        inner = plan_mod.inner_command(step["argv"])
        if not inner:
            continue
        selector = inner[1] if len(inner) > 1 and inner[1].startswith("+") else None
        if inner[0] == "rustc" and selector:
            findings.append(("plan_rustc_selector", step["id"]))
        elif inner[0] == "cargo":
            if "--target" in inner:
                if selector != "+" + device_toolchain:
                    findings.append(("plan_device_toolchain_not_exact", step["id"]))
            elif selector is not None:
                findings.append(("plan_host_toolchain_overridden", step["id"]))
    return sorted(set(findings))


def _device_window(device_toolchain: str) -> Optional[Tuple[datetime.date, datetime.date]]:
    match = _DATED.match(device_toolchain)
    if not match:
        return None
    day = datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return day - datetime.timedelta(days=WINDOW_DAYS), day


def _host_ok(version: str, pin: str) -> bool:
    match = _VERSION.match(version)
    return bool(match) and match.group(1) == pin and match.group(2) is None


def _device_ok(version: str, window: Optional[Tuple[datetime.date, datetime.date]]) -> bool:
    match = _VERSION.match(version)
    if not match or match.group(2) != "-nightly" or window is None:
        return False
    try:
        committed = datetime.date.fromisoformat(match.group(4))
    except ValueError:
        return False
    return window[0] <= committed <= window[1]


def judge_identity(evidence: Dict[str, Any], contract: Dict[str, Any], pin_channel: str, device_rustc: str) -> Verdict:
    """The compiler a central record says built what it holds, against the pin and the plan. Does not judge the record's steps
    (that is `central.judge`, run first by the caller): only whose compiler it was."""
    revision = str(evidence.get("revision", ""))[:12]
    compilers = evidence.get("artifact_compilers")
    if "toolchain_pin" not in evidence or not isinstance(compilers, dict):
        return "blocked", [("receipt_without_compiler_identity", revision)], (
            f"no receipt for this compiler: the newest committed record (revision {revision}) records no pin file and no artifact "
            "compilers, so it was made before the pin and before the compiler of each artifact was read from its bytes; run the plan "
            "centrally on a revision that has the pin, then `ingest`")
    record_pin = evidence["toolchain_pin"]
    recorded = record_pin.get("channel") if isinstance(record_pin, dict) else None
    if recorded != pin_channel:
        return "blocked", [("receipt_pin_is_not_the_current_pin", f"{recorded}->{pin_channel}")], (
            f"no receipt for this compiler: the record (revision {revision}) was made "
            + (f"under pin {recorded}" if recorded else "on a revision with no pin file") + f", the pin is now {pin_channel}")
    findings: List[Finding] = []
    release = (evidence.get("toolchain_default") or {}).get("release")
    if release != pin_channel:
        findings.append(("receipt_bare_cargo_not_pin", str(release)))
    device_strings = set()
    host_strings = set()
    for art in contract["artifacts"]:
        if not art["bin"]:
            continue
        strings = compilers.get(art["id"])
        if not isinstance(strings, list) or not strings or not all(isinstance(x, str) for x in strings):
            findings.append(("artifact_compiler_not_recorded", art["id"]))
            continue
        if ref.TARGETS[art["target"]][3]:
            device_strings.update(strings)
            if strings != [device_rustc]:
                findings.append(("device_artifact_not_built_by_the_pinned_nightly", f"{art['id']}: {', '.join(strings)}"))
        else:
            host_strings.update(strings)
            if not all(_host_ok(x, pin_channel) for x in strings):
                findings.append(("host_artifact_not_built_by_the_pin", f"{art['id']}: {', '.join(strings)}"))
    if len(device_strings) > 1:
        findings.append(("device_artifacts_disagree", "; ".join(sorted(device_strings))))
    if findings:
        return "fail", sorted(set(findings)), "the record's compiler is not the pinned one: " + "; ".join(f"{c}[{s}]" for c, s in sorted(set(findings))[:4])
    return "pass", [], (
        f"revision {revision}: bare `cargo` resolved {release} = the pin {pin_channel}; host artifacts carry `rustc version {', '.join(sorted(host_strings))}`; "
        f"device artifacts carry exactly `rustc version {device_rustc}`, the compiler of the dated nightly the plan asks for")


def codes(findings: Sequence[Finding]) -> List[str]:
    return sorted({c for c, _ in findings})
