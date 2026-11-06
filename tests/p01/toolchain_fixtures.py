"""Synthetic worlds for the toolchain cases (P01-TC-*): a pin file, a plan and a central record that agree. A plant changes exactly one
thing and names the verdict and the finding codes `toolchain` must then report, written out by hand from the rules in toolchain.py.
Nothing here reads the real pin file, the real plan's state on disk or a real receipt: the permitted positive and every planted
negative hold on data that exists only in this file, so the verdict cannot depend on what a worker last printed.

The compiler strings are HAND-WRITTEN here, not asked of plan.py: they are what `rustc -V` prints for the two toolchains (the pin and
`nightly-2026-08-31`), measured on a host that has both, so a wrong constant in plan.py cannot make these worlds agree with it."""
from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Tuple

import plan as plan_mod
import reference as ref
import toolchain

PIN = "1.99.0"
PIN_TEXT = '[toolchain]\nchannel = "1.99.0"\n'
DEVICE = "nightly-2026-08-31"
HOST_STRING = "1.99.0 (b940084d7 2026-09-28)"
DEVICE_STRING = "1.100.0-nightly (908501772 2026-08-30)"
OTHER_DATED_STRING = "1.100.0-nightly (e7769602a 2026-08-24)"     # what nightly-2026-08-25 prints
FLOATING_STRING = "1.101.0-nightly (708c94ef0 2026-11-03)"        # what a worker's default nightly printed


def plan_of(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The real plan for the real contract, on a made-up root: only its argv is judged here."""
    return plan_mod.plan_steps("/srv/export/ffw", "/srv/export/ffw/crates/franken-board-profile", "/srv/export/target", doc)


def evidence_of(doc: Dict[str, Any]) -> Dict[str, Any]:
    compilers = {}
    for art in doc["artifacts"]:
        if art["bin"]:
            compilers[art["id"]] = [DEVICE_STRING] if ref.TARGETS[art["target"]][3] else [HOST_STRING]
    return {"revision": "ab" * 20, "toolchain_default": {"release": PIN, "host": "x86_64-unknown-linux-gnu"},
            "toolchain_pin": {"file": plan_mod.PIN_FILE, "sha256": "cd" * 32, "channel": PIN}, "artifact_compilers": compilers}


# (pin file text, plan steps, central record, the device compiler string the plan declares)
World = Tuple[Any, List[Dict[str, Any]], Dict[str, Any], str]


def world(doc: Dict[str, Any]) -> World:
    return PIN_TEXT, plan_of(doc), evidence_of(doc), DEVICE_STRING


def _first(doc: Dict[str, Any], device: bool) -> str:
    return next(a["id"] for a in doc["artifacts"] if a["bin"] and ref.TARGETS[a["target"]][3] == device)


def _step(steps: List[Dict[str, Any]], pick: Callable[[List[str]], bool]) -> Dict[str, Any]:
    return next(s for s in steps if pick(plan_mod.inner_command(s["argv"])))


def _device_step(steps):
    return _step(steps, lambda i: i[0] == "cargo" and "--target" in i)


def _host_step(steps):
    return _step(steps, lambda i: i[0] == "cargo" and "--target" not in i)


def _set_selector(step: Dict[str, Any], selector) -> None:
    argv = step["argv"]
    at = argv.index("cargo") + 1
    if argv[at].startswith("+"):
        del argv[at]
    if selector:
        argv.insert(at, selector)


Edit = Callable[[Dict[str, Any], World], World]
Plant = Tuple[str, str, Edit, str, List[str]]


def _text(new: Any) -> Edit:
    return lambda doc, w: (new, w[1], w[2], w[3])


def _plan_edit(edit: Callable[[List[Dict[str, Any]]], None]) -> Edit:
    def run(doc, w):
        steps = copy.deepcopy(w[1])
        edit(steps)
        return w[0], steps, w[2], w[3]
    return run


def _declared(rustc: str) -> Edit:
    return lambda doc, w: (w[0], w[1], w[2], rustc)


def _evidence_edit(edit: Callable[[Dict[str, Any], Dict[str, Any]], None]) -> Edit:
    def run(doc, w):
        evidence = copy.deepcopy(w[2])
        edit(doc, evidence)
        return w[0], w[1], evidence, w[3]
    return run


def _device_all(doc: Dict[str, Any], evidence: Dict[str, Any], strings: List[str]) -> None:
    for art in doc["artifacts"]:
        if art["bin"] and ref.TARGETS[art["target"]][3]:
            evidence["artifact_compilers"][art["id"]] = list(strings)


def _add_rustc_selector(steps):
    steps.append({"id": "toolchain", "kind": "toolchain", "artifacts": [], "cwd": "/x", "env": {},
                  "argv": ["rch", "exec", "--", "rustc", "+" + DEVICE, "-vV"]})


PLANTS: List[Plant] = [
    # ---- the pin file
    ("pin_file", "the channel is `nightly`", _text('[toolchain]\nchannel = "nightly"\n'), "fail", ["pin_channel_not_exact"]),
    ("pin_file", "the channel is `stable`", _text('[toolchain]\nchannel = "stable"\n'), "fail", ["pin_channel_not_exact"]),
    ("pin_file", "the channel is a dated nightly", _text('[toolchain]\nchannel = "nightly-2026-08-31"\n'), "fail", ["pin_channel_not_exact"]),
    ("pin_file", "the channel is only X.Y", _text('[toolchain]\nchannel = "1.99"\n'), "fail", ["pin_channel_not_exact"]),
    ("pin_file", "the file also names components", _text('[toolchain]\nchannel = "1.99.0"\ncomponents = ["clippy"]\n'), "fail", ["pin_extra_content"]),
    ("pin_file", "the file also names another table", _text('[toolchain]\nchannel = "1.99.0"\n\n[override]\nx = 1\n'), "fail", ["pin_extra_content"]),
    ("pin_file", "the file names no channel", _text('[toolchain]\n'), "fail", ["pin_no_channel"]),
    ("pin_file", "the file has no toolchain table", _text('channel = "1.99.0"\n'), "fail", ["pin_no_toolchain_table"]),
    ("pin_file", "the file is not TOML", _text('[toolchain\nchannel = '), "fail", ["pin_unreadable"]),
    ("pin_file", "the file is missing", _text(None), "fail", ["pin_missing"]),
    # ---- the plan
    ("plan", "a device line asks for the floating `+nightly`", _plan_edit(lambda s: _set_selector(_device_step(s), "+nightly")), "fail",
     ["plan_device_toolchain_not_exact"]),
    ("plan", "a device line asks for no toolchain", _plan_edit(lambda s: _set_selector(_device_step(s), None)), "fail",
     ["plan_device_toolchain_not_exact"]),
    ("plan", "a device line asks for another dated nightly", _plan_edit(lambda s: _set_selector(_device_step(s), "+nightly-2026-09-01")), "fail",
     ["plan_device_toolchain_not_exact"]),
    ("plan", "a host line overrides the pin", _plan_edit(lambda s: _set_selector(_host_step(s), "+stable")), "fail", ["plan_host_toolchain_overridden"]),
    ("plan", "a `rustc +X -vV` step is back", _plan_edit(_add_rustc_selector), "fail", ["plan_rustc_selector"]),
    ("plan", "the device compiler string is for another date than the toolchain", _declared(OTHER_DATED_STRING), "fail",
     ["plan_device_rustc_not_from_the_toolchain_date"]),
    ("plan", "the device compiler string is dated after the toolchain", _declared("1.100.0-nightly (e7769602a 2026-09-01)"), "fail",
     ["plan_device_rustc_not_from_the_toolchain_date"]),
    ("plan", "the device compiler string is a stable release", _declared("1.100.0 (908501772 2026-08-30)"), "fail",
     ["plan_device_rustc_not_from_the_toolchain_date"]),
    # ---- the receipt: it names a compiler that is not the pinned one -> fail
    ("receipt_fail", "bare cargo resolved a floating nightly", _evidence_edit(lambda d, e: e["toolchain_default"].update(release="1.101.0-nightly")),
     "fail", ["receipt_bare_cargo_not_pin"]),
    ("receipt_fail", "the host artifact was built by the floating nightly",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, False): [FLOATING_STRING]})), "fail", ["host_artifact_not_built_by_the_pin"]),
    ("receipt_fail", "the host artifact was built by a NIGHTLY of the pin's release number",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, False): ["1.99.0-nightly (aaaaaaaaa 2026-09-28)"]})), "fail",
     ["host_artifact_not_built_by_the_pin"]),
    ("receipt_fail", "the host artifact was built by another stable release",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, False): ["1.98.0 (aaaaaaaaa 2026-08-12)"]})), "fail",
     ["host_artifact_not_built_by_the_pin"]),
    ("receipt_fail", "a device artifact was built by the floating nightly (the worker's default)",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, True): [FLOATING_STRING]})), "fail",
     ["device_artifact_not_built_by_the_pinned_nightly", "device_artifacts_disagree"]),
    ("receipt_fail", "a device artifact was built by the stable pin",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, True): [HOST_STRING]})), "fail",
     ["device_artifact_not_built_by_the_pinned_nightly", "device_artifacts_disagree"]),
    ("receipt_fail", "every device artifact was built by another dated nightly",
     _evidence_edit(lambda d, e: _device_all(d, e, [OTHER_DATED_STRING])), "fail", ["device_artifact_not_built_by_the_pinned_nightly"]),
    ("receipt_fail", "every device artifact was built by a STABLE release with the nightly's commit date",
     _evidence_edit(lambda d, e: _device_all(d, e, ["1.100.0 (908501772 2026-08-30)"])), "fail", ["device_artifact_not_built_by_the_pinned_nightly"]),
    ("receipt_fail", "every device artifact names the nightly's release but another commit",
     _evidence_edit(lambda d, e: _device_all(d, e, ["1.100.0-nightly (000000000 2026-08-30)"])), "fail", ["device_artifact_not_built_by_the_pinned_nightly"]),
    ("receipt_fail", "two device artifacts were built by two nightlies",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, True): [OTHER_DATED_STRING]})), "fail",
     ["device_artifact_not_built_by_the_pinned_nightly", "device_artifacts_disagree"]),
    ("receipt_fail", "one of a device artifact's strings is the floating nightly",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, True): [DEVICE_STRING, FLOATING_STRING]})), "fail",
     ["device_artifact_not_built_by_the_pinned_nightly", "device_artifacts_disagree"]),
    ("receipt_fail", "an artifact carries no compiler string",
     _evidence_edit(lambda d, e: e["artifact_compilers"].update({_first(d, True): []})), "fail", ["artifact_compiler_not_recorded"]),
    ("receipt_fail", "an artifact is missing from the record's compilers",
     _evidence_edit(lambda d, e: e["artifact_compilers"].pop(_first(d, False))), "fail", ["artifact_compiler_not_recorded"]),
    # ---- the receipt is not for this compiler -> blocked, never a pass
    ("receipt_blocked", "the record predates artifact compilers", _evidence_edit(lambda d, e: e.pop("artifact_compilers")), "blocked",
     ["receipt_without_compiler_identity"]),
    ("receipt_blocked", "the record predates the pin", _evidence_edit(lambda d, e: e.pop("toolchain_pin")), "blocked",
     ["receipt_without_compiler_identity"]),
    ("receipt_blocked", "the record's revision had no pin file", _evidence_edit(lambda d, e: e.update(toolchain_pin=None)), "blocked",
     ["receipt_pin_is_not_the_current_pin"]),
    ("receipt_blocked", "the record was made under an older pin",
     _evidence_edit(lambda d, e: e["toolchain_pin"].update(channel="1.98.0")), "blocked", ["receipt_pin_is_not_the_current_pin"]),
]
GROUPS = ("pin_file", "plan", "receipt_fail", "receipt_blocked")


def _judge(doc: Dict[str, Any], w: World, legacy: bool = False) -> Tuple[str, List[str]]:
    """The whole judgement of a world: the pin, then the plan, then the record. fail beats blocked beats pass."""
    channel, findings = toolchain.judge_pin(w[0], legacy)
    findings = findings + toolchain.judge_plan(w[1], plan_mod.DEVICE_TOOLCHAIN, w[3])
    if findings:
        return "fail", toolchain.codes(findings)
    verdict, identity, _detail = toolchain.judge_identity(w[2], doc, channel, w[3])
    return verdict, toolchain.codes(identity)


def judge_positive(doc: Dict[str, Any]) -> str:
    """The unaltered world passes, and so do the variations that are allowed to differ."""
    base = world(doc)
    got = _judge(doc, base)
    assert got == ("pass", []), f"the unaltered world is {got}"
    spaced = _judge(doc, ('# the pin\n[toolchain]\nchannel   =   "1.99.0"   # exact\n',) + base[1:])
    assert spaced == ("pass", []), f"a pin file with comments and spacing is {spaced}"
    twice = copy.deepcopy(base[2])
    for art in doc["artifacts"]:
        if art["bin"] and not ref.TARGETS[art["target"]][3]:
            twice["artifact_compilers"][art["id"]] = [HOST_STRING, HOST_STRING]
    again = _judge(doc, (base[0], base[1], twice, base[3]))
    assert again == ("pass", []), f"an artifact that carries the same string twice is {again}"
    for rustc, label in (("1.98.0-nightly (11223344 2026-08-28)", "three days before the toolchain's date"),
                         ("1.98.0-nightly (11223344 2026-08-31)", "on the toolchain's date")):
        assert toolchain.judge_plan(base[1], DEVICE, rustc) == [], f"a device compiler string committed {label} is refused by the plan check"
    return ("the unaltered world, a commented pin file, a repeated string, and device compiler strings committed on the toolchain's date and "
            "three days before it all pass")


def judge_group(doc: Dict[str, Any], group: str) -> str:
    """Every plant of `group` gets exactly its verdict and code set; the unplanted control passes first."""
    base = world(doc)
    assert _judge(doc, base) == ("pass", []), "the unplanted control does not pass"
    plants = [p for p in PLANTS if p[0] == group]
    assert plants, f"no plants in group {group}"
    wrong = []
    for _g, label, edit, verdict, want in plants:
        got = _judge(doc, edit(doc, copy.deepcopy(base)))
        if got != (verdict, sorted(want)):
            wrong.append(f"`{label}`: {got}, want {(verdict, sorted(want))}")
    assert not wrong, "; ".join(wrong)
    if group == "pin_file":
        legacy = _judge(doc, base, legacy=True)
        assert legacy == ("fail", ["pin_legacy_file_present"]), f"a legacy rust-toolchain file is {legacy}"
    return f"{len(plants)} plants each get exactly their verdict and codes; the control passes"
