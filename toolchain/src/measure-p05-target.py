#!/usr/bin/env python3
"""Judge P05's atomic-cell and real Asupersync runtime transcripts independently.

The original prepare/run/analyze commands below concern atomic cells only.
run-runtime/analyze-runtime cover toolchain/src/p05-runtime instead. The BE
runtime runs as the existing E07 speaker-smoke supervisor's child, after proc
mounting and loopback setup; its /franken-speaker --catalog alias is explicit,
and its main ignores argv. These modes compile nothing and never qualify the
production firmware or physical audio. See RUNTIME_SCOPE for their proof boundary.

--profile single-owner judges the probe's second run (one scheduler worker through LegacyProfile). The unchanged supervisor cannot
pass it an argument, so the runner packs a marker file the probe reads. That run has one declared unsupported row, the caller-driven
mode; the probe exits 0 only for exactly that row, so the supervisor's own accounting is the ordinary one (status=0, TEST_SUCCESS)
and the supervisor envelope is the UNMODIFIED standard one: no line of the log is changed before the strict verifier reads it. The
result is "accepted_with_declared_unsupported" (command-line exit 4), never a plain pass.

--profile caller-driven judges the probe's third run: a runtime built with LegacyProfile::caller_driven, driven by the thread that
calls block_on, with no worker, blocking or helper thread. It is selected the same way (a marker, here `caller-driven`), declares
nothing unsupported, and holds every census row to the starting thread count. Its result is a plain "passed" (exit 0).

Bead ffw-ipz, the open item `P05-EXT-GUEST`. The guest (`toolchain/src/p05-target`, PID 1 of the existing Debian/Malta guest)
compiles the FROZEN `crates/franken-atomic` source files unchanged and prints `FFW_P05T_*` lines; this script runs it and JUDGES
the transcript. The question answered is narrow: does the same source behave on a 32-bit big-endian guest exactly as the
independent reference says, under real preemption? Every expected value comes from somewhere other than the Rust:

  VECTORS    hand-written results of operations on SharedU64, SharedI64, Sequence and LocalU64 (this file, `VECTOR_EXPECTED`).
  PINNED     the seeded-schedule sweep over the pinned profile (`tests/p05/vectors.txt`): the counts 0 / 198 / 231 and the leading
             seeds, AND the full per-seed history-and-verdict digest re-derived by `tests/p05/reference.py`, a separate model.
  SEEDED     the same sweep from THIS RUN's seed (replay defence): counts, leading seeds and digest re-derived by the reference.
  DIRECTED   nine scripted interleavings: verdict and loaded value against the hand-written table, history against the reference.
  THREADS    real threads on the real cell: outcomes that are exact for any correct cell whatever the schedule (a sum, unique
             tickets, an exact set of overflow results, monotone reads, linearizable histories).
  ENV / ELF  the guest says it is 32-bit big-endian MIPS and the kernel's `uname` agrees, and the ELF header says the same.
  SOURCES    an FNV-1a digest of each included source file, equal to the repository's text.

REPLAY DEFENCE. The host picks a per-run seed and packs it into the initramfs. The seeded sweeps start at that seed, so a transcript
from another run, or one that prints canned lines, carries the wrong histories. `run --plant replay` boots a guest that replays an
earlier run's seeded sweep lines and requires this judge to refuse it.

PLANTED NEGATIVES, each credited only against a green baseline and each with its remove-the-plant control (the unplanted
transcript passes): `--plant host` presents a little-endian / host transcript as the guest's; `replay` presents an earlier run's
seeded sweeps; `truncate` drops the transcript's end; `order` swaps one adjacent pair of events in one scripted history. With no
guest transcript there is no receipt, and the case is BLOCKED (exit 3), never passed.

WHAT A PASS SAYS, AND DOES NOT SAY: see `HONEST_FOOTER`.

    measure-p05-target.py prepare --work-dir DIR        snapshot HEAD + the guest crate; print the central command
    measure-p05-target.py run --elf E --log-dir D [--seed N] [--plant host|replay|truncate|order] [--receipt F]
    measure-p05-target.py analyze [--log L --elf E --seed N] [--receipt F]       no --log: BLOCKED
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BENCH_REL = "toolchain/src/p05-target"
TARGET = "mips-unknown-linux-musl"
KERNEL_NAME = "vmlinux-4.19.0-21-4kc-malta"
KERNEL_SHA256_PREFIX = "3803357e"  # the digest every committed E07/E03 receipt records
KERNEL_RELEASE = "4.19.0-21-4kc-malta"  # `uname -r` of that kernel
S_IFREG_644 = 0o100644
SCHEMA = "ffw.p05.guest_receipt.v1"

# The frozen sources the guest includes (relative to the repository root), in the order the guest prints them.
SOURCE_FILES = (("error.rs", "crates/franken-atomic/src/error.rs"), ("shared.rs", "crates/franken-atomic/src/shared.rs"),
                ("counter.rs", "crates/franken-atomic/src/counter.rs"), ("local.rs", "crates/franken-atomic/src/local.rs"),
                ("model.rs", "crates/franken-atomic/src/model.rs"), ("planted.rs", "crates/franken-atomic/src/planted.rs"),
                ("vectors.txt", "tests/p05/vectors.txt"))

BUDGET = 200_000
KINDS = ("good", "split", "trunc")
HEAD_LEN = 8
M64 = (1 << 64) - 1


def _load(path: pathlib.Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class MeasurementError(Exception):
    """The transcript cannot be trusted; the message says why."""


@functools.lru_cache(maxsize=1)
def boot_runner() -> Any:
    return _load(HERE / "run-qemu-verification.py", "p05_boot_runner")


def reference(repo: pathlib.Path = REPO) -> Any:
    """The independent Python model. Loaded once per repository root."""
    return _load_reference(str(repo))


@functools.lru_cache(maxsize=None)
def _load_reference(repo: str) -> Any:
    return _load(pathlib.Path(repo) / "tests" / "p05" / "reference.py", "p05_reference_for_target")


# ---- the canonical text both sides implement ----------------------------------------------------------------------------


def fnv1a64(data: bytes, state: int = 0xCBF29CE484222325) -> int:
    for byte in data:
        state ^= byte
        state = (state * 0x100000001B3) & M64
    return state


def op_text(op: tuple) -> str:
    kind = op[0]
    if kind == "load":
        return "L"
    if kind == "store":
        return f"S{op[1]:x}"
    if kind == "cas":
        return f"C{op[1]:x}.{op[2]:x}"
    if kind == "add":
        return f"A{op[1]:x}"
    raise ValueError(op)


def resp_text(resp: tuple) -> str:
    kind = resp[0]
    if kind == "value":
        return f"V{resp[1]:x}"
    if kind == "stored":
        return "T"
    if kind == "cas_ok":
        return f"Co{resp[1]:x}"
    if kind == "cas_err":
        return f"Ce{resp[1]:x}"
    if kind == "add_ok":
        return f"Ao{resp[1]:x}"
    if kind == "add_overflow":
        return f"Af{resp[1]:x}.{resp[2]:x}"
    raise ValueError(resp)


def history_text(events: Any) -> str:
    return ";".join(f"t{e.thread}:{e.inv}:{e.res}:{op_text(e.op)}:{resp_text(e.resp)}" for e in events)


VERDICT_MARK = {"linearizable": "L", "not_linearizable": "N", "inconclusive": "I"}


@dataclass(frozen=True)
class SweepFacts:
    violations: int
    inconclusive: int
    head: str
    digest: str


@functools.lru_cache(maxsize=None)
def expected_sweep(repo: str, kind: str, first_seed: int, seeds: int, threads: int, ops: int) -> SweepFacts:
    """What the reference says the sweep prints: counts, the leading violating seeds and the per-seed digest."""
    ref = reference(pathlib.Path(repo))
    digest = 0xCBF29CE484222325
    violations: list[int] = []
    inconclusive = 0
    for seed in range(first_seed, first_seed + seeds):
        events = ref.seeded_run(kind, seed, threads, ops)
        verdict = ref.check(ref.INITIAL, events, BUDGET)
        if verdict == ref.NOT_LINEARIZABLE:
            violations.append(seed)
        elif verdict == ref.INCONCLUSIVE:
            inconclusive += 1
        record = f"{seed:x}|{VERDICT_MARK[verdict]}|{history_text(events)}\n"
        digest = fnv1a64(record.encode("ascii"), digest)
    head = ",".join(str(s) for s in violations[:HEAD_LEN]) or "-"
    return SweepFacts(len(violations), inconclusive, head, f"{digest:016x}")


# ---- hand-written expectations ------------------------------------------------------------------------------------------
# Each list is the guest's printed results for one vector program, derived by hand from the cells' documented contract and the
# assertions of the host tests (`crates/franken-atomic/src/tests.rs`), NOT from running anything. Tokens: `v:` a value, `ok:`
# a checked result's previous value, `of:`/`uf:` an overflow/underflow with `current/delta`, `cx_ok:`/`cx_err:` a
# compare-exchange, `ex` an exhausted sequence. All numbers are lower-case hex of the 64-bit two's-complement pattern.

_ROUNDTRIP_VALUES = (0, 1, 0xFFFFFFFF, 0x100000000, 0x100000001, 0xFFFFFFFF00000000, 0x8000000000000000, 0x0123456789ABCDEF,
                     M64)


def _roundtrip() -> list[str]:
    tokens: list[str] = []
    previous = 0
    for value in _ROUNDTRIP_VALUES:
        # store then load returns the value; swap returns the stored value; the cell then holds the old one
        tokens += [f"v:{value:x}", f"v:{value:x}", f"v:{previous:x}"]
        previous = value
    return tokens + ["v:0", "v:abcdef0123456789", "v:100000007"]


VECTOR_EXPECTED: dict[str, list[str]] = {
    "load_store_roundtrip": _roundtrip(),
    "add_carry": ["ok:ffffffff", "v:100000000", "ok:5", "v:100000005", "ok:1fffffff0", "v:200000010"],
    "add_overflow": ["ok:fffffffffffffffe", "v:ffffffffffffffff", "of:ffffffffffffffff/1", "v:ffffffffffffffff",
                     "ok:ffffffffffffffff", "of:1/ffffffffffffffff", "v:1"],
    "sub_underflow": ["ok:1", "v:0", "uf:0/1", "v:0", "ok:0", "ok:100000000", "v:ffffffff"],
    "wrapping": ["v:ffffffffffffffff", "v:1", "v:0", "v:ffffffffffffffff", "of:ffffffffffffffff/2", "v:ffffffffffffffff"],
    "cas_full_width": ["cx_err:100000001", "v:100000001", "cx_ok:100000001", "v:9", "cx_ok:9", "cx_err:9"],
    "max_min_bits": ["v:5", "v:100000000", "v:100000000", "v:100000000", "v:100000000", "v:7", "v:7", "v:7",
                     "v:f0f0f0f0f0f0f0f0", "v:f0f0f0f000000000", "v:f0f0f0f000000000", "v:f0f0f0f00f0f0f0f"],
    "i64_range": ["of:7fffffffffffffff/1", "ok:7fffffffffffffff", "v:7ffffffffffffffe", "ok:7ffffffffffffffe",
                  "of:7fffffffffffffff/ffffffffffffffff", "uf:8000000000000000/ffffffffffffffff",
                  "uf:8000000000000000/1", "v:8000000000000000", "ok:8000000000000000", "v:8000000000000001",
                  "cx_err:ffffffff", "v:ffffffff00000000", "v:ffffffff00000000"],
    "sequence": ["ok:0", "ok:1", "ok:2", "ok:fffffffffffffffd", "ok:fffffffffffffffe", "v:ffffffffffffffff", "ex", "ex",
                 "v:ffffffffffffffff", "ex"],
    "local_u64": ["ok:fffffffffffffffe", "of:ffffffffffffffff/1", "v:ffffffffffffffff", "v:ffffffffffffffff", "v:1",
                  "v:100000000", "v:0", "v:100000001"],
}

# (scenario, kind) -> (verdict mark, the value the load returned), from the table in tests.rs / tests/p05/cases.json.
DIRECTED_EXPECTED: dict[tuple[str, str], tuple[str, int]] = {
    ("torn_store", "good"): ("L", 0x100000000),
    ("torn_store", "split"): ("N", 0x1FFFFFFF0),
    ("torn_store", "trunc"): ("N", 0),
    ("torn_carry", "good"): ("L", 0x100000000),
    ("torn_carry", "split"): ("N", 0),
    ("torn_carry", "trunc"): ("N", 0),
    ("truncated_store", "good"): ("L", 0x100000001),
    ("truncated_store", "split"): ("L", 0x100000001),
    ("truncated_store", "trunc"): ("N", 1),
}

# How many lines of each tag a complete transcript has.
TAG_COUNTS = {"ALIVE": 1, "BEGIN": 1, "ENV": 1, "SYS": 1, "SRC": len(SOURCE_FILES), "SEED": 1, "VEC": len(VECTOR_EXPECTED),
              "SWEEP": 6, "DIRECTED": 9, "THREADED": 1, "TICKETS": 1, "CASLOOP": 1, "OVERFLOWRACE": 1, "SEQRACE": 1,
              "MONOTONE": 1, "INFO": 1, "END": 1}
FATAL_TAGS = ("HOST_BUILD", "REBOOT_FAILED", "REPLAY_MISSING")

# ---- parsing --------------------------------------------------------------------------------------------------------------

MARKER = re.compile(r"FFW_P05T_([A-Z_0-9]+)(?: (.*))?$")
PAIRS = re.compile(r"(\w+)=(\S+)")


def parse_pairs(rest: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for key, value in PAIRS.findall(rest or ""):
        if key in pairs:
            raise MeasurementError(f"key {key} appears twice in one line: {rest[:80]!r}")
        pairs[key] = value
    return pairs


def parse_transcript(text: str) -> dict[str, Any]:
    """Marker lines by tag, in order. Kernel messages and blank lines are ignored; a repeated tag is kept, not merged."""
    lines: dict[str, list[dict[str, str]]] = {}
    order: list[str] = []
    for raw in text.replace("\r", "").split("\n"):
        match = MARKER.search(raw)
        if not match:
            continue
        tag = match.group(1)
        lines.setdefault(tag, []).append(parse_pairs(match.group(2)))
        order.append(tag)
    return {"lines": lines, "order": order}


def _one(t: dict[str, Any], tag: str) -> dict[str, str] | None:
    found = t["lines"].get(tag, [])
    return found[0] if len(found) == 1 else None


def _int(value: str | None, base: int = 10) -> int | None:
    try:
        return int(value, base) if value is not None else None
    except ValueError:
        return None


# ---- ELF ------------------------------------------------------------------------------------------------------------------


def read_elf(path: pathlib.Path) -> dict[str, Any]:
    """Header facts. The guest is only meaningful as a 32-bit big-endian MIPS executable."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise MeasurementError(f"{path.name} is not an ELF file")
    if data[4] != 1 or data[5] != 2:
        raise MeasurementError(f"{path.name} is not a 32-bit big-endian ELF (class {data[4]}, data {data[5]})")
    (_ident, e_type, machine, _ver, _entry, _phoff, _shoff, flags, *_rest) = struct.unpack(">16sHHIIIIIHHHHHH", data[:52])
    if machine != 8:
        raise MeasurementError(f"{path.name} is not MIPS (e_machine {machine})")
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "e_type": e_type, "machine": machine,
            "e_flags": flags}


# ---- the gates ------------------------------------------------------------------------------------------------------------


@dataclass
class Gate:
    gate_id: str
    title: str
    status: str  # passed | failed | blocked
    detail: str = ""


def _gate(gate_id: str, title: str, problems: list[str]) -> Gate:
    return Gate(gate_id, title, "failed" if problems else "passed", "; ".join(problems[:6]) +
                (f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""))


def gate_transcript(t: dict[str, Any]) -> Gate:
    problems: list[str] = []
    for tag in FATAL_TAGS:
        if tag in t["lines"]:
            problems.append(f"the guest printed {tag}")
    for tag, want in TAG_COUNTS.items():
        got = len(t["lines"].get(tag, []))
        if got != want:
            problems.append(f"{tag}: {got} line(s), expected {want}")
    unknown = sorted(set(t["lines"]) - set(TAG_COUNTS) - set(FATAL_TAGS))
    if unknown:
        problems.append(f"unknown tag(s) {unknown}")
    order = t["order"]
    if order and (order[0] != "ALIVE" or order[-1] != "END"):
        problems.append("the transcript does not run from ALIVE to END")
    if "BEGIN" in order and "END" in order and order.index("BEGIN") > order.index("END"):
        problems.append("BEGIN comes after END")
    return _gate("P05T-TRANSCRIPT", "a complete transcript: every line the guest prints, ALIVE first and END last", problems)


def gate_elf(elf: dict[str, Any] | None) -> Gate:
    if elf is None:
        return Gate("P05T-ELF", "the program is a 32-bit big-endian MIPS executable", "failed", "no ELF was supplied")
    problems = [] if (elf.get("machine") == 8) else [f"e_machine {elf.get('machine')} is not MIPS"]
    return _gate("P05T-ELF", "the program is a 32-bit big-endian MIPS executable", problems)


def gate_env(t: dict[str, Any]) -> Gate:
    problems: list[str] = []
    env, sysinfo = _one(t, "ENV"), _one(t, "SYS")
    if env is None:
        problems.append("no single ENV line")
    else:
        for key, want in (("target_arch", "mips"), ("target_endian", "big"), ("pointer_width", "32"), ("target_os", "linux"),
                          ("size_usize", "4"), ("size_u64", "8"), ("ne_u32", "01020304"), ("ne_u64", "0102030405060708")):
            if env.get(key) != want:
                problems.append(f"ENV {key}={env.get(key)!r}, a big-endian MIPS32 guest prints {want!r}")
    if sysinfo is None:
        problems.append("no single SYS line")
    else:
        if sysinfo.get("sysname") != "Linux":
            problems.append(f"uname sysname {sysinfo.get('sysname')!r} is not Linux")
        if sysinfo.get("machine") != "mips":
            problems.append(f"uname machine {sysinfo.get('machine')!r}: big-endian MIPS reports 'mips' ('mipsel' is little-endian)")
        if sysinfo.get("release") != KERNEL_RELEASE:
            problems.append(f"uname release {sysinfo.get('release')!r} is not the committed guest kernel {KERNEL_RELEASE!r}")
    return _gate("P05T-ENV", "the guest says it is 32-bit big-endian MIPS and the kernel's uname agrees", problems)


def gate_sources(t: dict[str, Any], repo: pathlib.Path) -> Gate:
    problems: list[str] = []
    printed = {line.get("file"): line for line in t["lines"].get("SRC", [])}
    for name, rel in SOURCE_FILES:
        line = printed.get(name)
        data = (repo / rel).read_bytes()
        if line is None:
            problems.append(f"no SRC line for {name}")
            continue
        want = f"{fnv1a64(data):016x}"
        if line.get("fnv") != want or _int(line.get("bytes")) != len(data):
            problems.append(f"{name}: the guest compiled fnv {line.get('fnv')} ({line.get('bytes')} bytes), "
                            f"the repository's file is {want} ({len(data)} bytes)")
    return _gate("P05T-SOURCES", "the guest compiled exactly the repository's frozen sources and shared vectors", problems)


def gate_seed(t: dict[str, Any], seed: int | None) -> Gate:
    line = _one(t, "SEED")
    if seed is None:
        return Gate("P05T-SEED", "the run's seed is echoed", "failed", "no seed was supplied to judge against")
    problems = [] if (line is not None and line.get("value") == str(seed)) else \
        [f"the guest echoed seed {None if line is None else line.get('value')!r}, this run used {seed}"]
    return _gate("P05T-SEED", "the guest echoes this run's seed", problems)


def gate_vectors(t: dict[str, Any]) -> Gate:
    problems: list[str] = []
    printed = {line.get("id"): line for line in t["lines"].get("VEC", [])}
    for name, want in VECTOR_EXPECTED.items():
        line = printed.get(name)
        if line is None:
            problems.append(f"no VEC line for {name}")
            continue
        got = line.get("r", "").split(",")
        if got != want:
            at = next((i for i, (a, b) in enumerate(zip(got, want)) if a != b), min(len(got), len(want)))
            problems.append(f"{name}: result {at} is {got[at] if at < len(got) else '(missing)'}, "
                            f"expected {want[at] if at < len(want) else '(none)'}")
    for name in printed:
        if name not in VECTOR_EXPECTED:
            problems.append(f"unknown vector {name}")
    return _gate("P05T-VECTORS", "the hand-written results of the cells' operations", problems)


def read_profile(repo: pathlib.Path) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {}
    for line in (repo / "tests" / "p05" / "vectors.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, *numbers = line.split()
            values[name] = [int(n) for n in numbers]
    return values


def _sweep_problems(t: dict[str, Any], repo: pathlib.Path, group: str, first_seed: int, profile: dict[str, list[int]]) -> list[str]:
    problems: list[str] = []
    threads, ops, seeds = profile["profile_threads"][0], profile["profile_ops_per_thread"][0], profile["profile_seeds"][0]
    printed = {line.get("kind"): line for line in t["lines"].get("SWEEP", []) if line.get("set") == group}
    for kind in KINDS:
        line = printed.get(kind)
        if line is None:
            problems.append(f"no {group} sweep line for {kind}")
            continue
        want = expected_sweep(str(repo), kind, first_seed, seeds, threads, ops)
        got = SweepFacts(_int(line.get("violations")) if line.get("violations") is not None else -1,
                         _int(line.get("inconclusive")) if line.get("inconclusive") is not None else -1,
                         line.get("head", ""), line.get("digest", ""))
        if _int(line.get("first_seed")) != first_seed or _int(line.get("seeds")) != seeds:
            problems.append(f"{group}/{kind}: first_seed {line.get('first_seed')} seeds {line.get('seeds')}, "
                            f"expected {first_seed} and {seeds}")
        if got != want:
            problems.append(f"{group}/{kind}: the guest printed {got.violations} violation(s), {got.inconclusive} "
                            f"inconclusive, head {got.head}, digest {got.digest}; the reference says {want.violations}, "
                            f"{want.inconclusive}, {want.head}, {want.digest}")
    return problems


def gate_pinned(t: dict[str, Any], repo: pathlib.Path) -> Gate:
    profile = read_profile(repo)
    first = profile["profile_first_seed"][0]
    problems = _sweep_problems(t, repo, "pinned", first, profile)
    # The hand-pinned numbers in tests/p05/vectors.txt, independent of the Python model.
    printed = {line.get("kind"): line for line in t["lines"].get("SWEEP", []) if line.get("set") == "pinned"}
    for kind, prefix in (("good", "good"), ("split", "split"), ("trunc", "trunc")):
        line = printed.get(kind)
        if line is None:
            continue
        for key, name in (("violations", f"{prefix}_violations"), ("inconclusive", f"{prefix}_inconclusive")):
            if _int(line.get(key)) != profile[name][0]:
                problems.append(f"pinned/{kind}: {key} {line.get(key)} but tests/p05/vectors.txt pins {profile[name][0]}")
        pinned_seeds = profile.get(f"{prefix}_violation_seeds")
        if pinned_seeds and line.get("head", "").split(",")[: len(pinned_seeds)] != [str(s) for s in pinned_seeds]:
            problems.append(f"pinned/{kind}: head {line.get('head')} does not start with the pinned seeds {pinned_seeds}")
    return _gate("P05T-PINNED", "the pinned sweep: vectors.txt's counts and seeds, and the reference's per-seed digest", problems)


def gate_seeded(t: dict[str, Any], repo: pathlib.Path, seed: int | None) -> Gate:
    if seed is None:
        return Gate("P05T-SEEDED", "the seeded sweep matches the reference for this run's seed", "failed", "no seed supplied")
    problems = _sweep_problems(t, repo, "seeded", seed, read_profile(repo))
    return _gate("P05T-SEEDED", "the seeded sweep matches the reference for this run's seed", problems)


def gate_directed(t: dict[str, Any], repo: pathlib.Path) -> Gate:
    ref = reference(repo)
    problems: list[str] = []
    printed = {(line.get("name"), line.get("kind")): line for line in t["lines"].get("DIRECTED", [])}
    for (name, kind), (mark, loaded) in DIRECTED_EXPECTED.items():
        line = printed.get((name, kind))
        if line is None:
            problems.append(f"no DIRECTED line for {name}/{kind}")
            continue
        initial, plans, picks = ref.scenario(name)
        events = ref.scripted_run(kind, initial, plans, picks)
        want_history = history_text(events)
        if line.get("verdict") != mark or _int(line.get("loaded"), 16) != loaded:
            problems.append(f"{name}/{kind}: verdict {line.get('verdict')} loaded {line.get('loaded')}, "
                            f"the hand-written table says {mark} and {loaded:x}")
        if line.get("history") != want_history:
            problems.append(f"{name}/{kind}: history {line.get('history')} is not the reference's {want_history}")
    return _gate("P05T-DIRECTED", "nine scripted interleavings: verdict and loaded value by hand, history by the reference",
                 problems)


def gate_threads(t: dict[str, Any], seed: int | None) -> Gate:
    problems: list[str] = []
    th = _one(t, "THREADED")
    if th is None:
        problems.append("no THREADED line")
    else:
        seeds = _int(th.get("seeds"))
        if (_int(th.get("linearizable")), _int(th.get("not")), _int(th.get("inconclusive"))) != (seeds, 0, 0) or not seeds:
            problems.append(f"THREADED: {th.get('linearizable')} linearizable, {th.get('not')} not, {th.get('inconclusive')} "
                            f"inconclusive of {th.get('seeds')}")
        if seed is not None and _int(th.get("first_seed")) != seed:
            problems.append(f"THREADED first_seed {th.get('first_seed')} is not this run's seed {seed}")
    tk = _one(t, "TICKETS")
    if tk is None:
        problems.append("no TICKETS line")
    else:
        want = {"total": "8000", "duplicates": "0", "out_of_range": "0", "complete": "1", "increasing": "1", "final": "1f40"}
        for key, value in want.items():
            if tk.get(key) != value:
                problems.append(f"TICKETS {key}={tk.get(key)!r}, expected {value!r}")
    cas = _one(t, "CASLOOP")
    if cas is None:
        problems.append("no CASLOOP line")
    else:
        # 0xFFFF_F000 + 4 threads x 2000 increments = 0x1_0000_0F40
        for key, value in {"start": "fffff000", "final": "100000f40", "crossed": "1"}.items():
            if cas.get(key) != value:
                problems.append(f"CASLOOP {key}={cas.get(key)!r}, expected {value!r}")
    race = _one(t, "OVERFLOWRACE")
    if race is None:
        problems.append("no OVERFLOWRACE line")
    else:
        want = {"oks": "fffffffffffffffc,fffffffffffffffd,fffffffffffffffe", "errors": "77", "all_typed": "1",
                "final": "ffffffffffffffff"}
        for key, value in want.items():
            if race.get(key) != value:
                problems.append(f"OVERFLOWRACE {key}={race.get(key)!r}, expected {value!r}")
    seq = _one(t, "SEQRACE")
    if seq is None:
        problems.append("no SEQRACE line")
    else:
        for key, value in {"issued": "100", "exact": "1", "next_err": "1", "peek": "ffffffffffffffff"}.items():
            if seq.get(key) != value:
                problems.append(f"SEQRACE {key}={seq.get(key)!r}, expected {value!r}")
    mono = _one(t, "MONOTONE")
    if mono is None:
        problems.append("no MONOTONE line")
    else:
        # 0xFFFF_FF00 + 512 = 0x1_0000_0100
        for key, value in {"start": "ffffff00", "adds": "512", "backwards": "0", "final": "100000100", "crossed": "1"}.items():
            if mono.get(key) != value:
                problems.append(f"MONOTONE {key}={mono.get(key)!r}, expected {value!r}")
        if (_int(mono.get("reads")) or 0) < 1:
            problems.append("MONOTONE: the reader never read")
    return _gate("P05T-THREADS", "real threads on the real cell: outcomes exact for any correct cell", problems)


def judge(text: str, elf: dict[str, Any] | None, seed: int | None, repo: pathlib.Path = REPO) -> dict[str, Any]:
    try:
        t = parse_transcript(text)
    except MeasurementError as exc:
        return {"ok": False, "gates": [Gate("P05T-TRANSCRIPT", "a parseable transcript", "failed", str(exc))], "info": None}
    gates = [gate_transcript(t), gate_elf(elf), gate_env(t), gate_sources(t, repo), gate_seed(t, seed), gate_vectors(t),
             gate_pinned(t, repo), gate_seeded(t, repo, seed), gate_directed(t, repo), gate_threads(t, seed)]
    info = _one(t, "INFO")
    return {"ok": all(g.status == "passed" for g in gates), "gates": gates, "info": info, "env": _one(t, "ENV"),
            "sys": _one(t, "SYS")}


def blocked_report() -> dict[str, Any]:
    return {"ok": False, "blocked": True, "info": None,
            "gates": [Gate("P05-EXT-GUEST", "a guest receipt for the semantic cells on big-endian MIPS", "blocked",
                           "no guest transcript was supplied, so there is no receipt; nothing is claimed")]}


def exit_code(report: dict[str, Any]) -> int:
    if any(g.status == "failed" for g in report["gates"]):
        return 1
    if report.get("blocked") or any(g.status == "blocked" for g in report["gates"]):
        return 3
    return 0


HONEST_FOOTER = (
    "What this shows: the frozen franken-atomic source, compiled for 32-bit big-endian MIPS and run as PID 1, produced exactly the\n"
    "results the hand-written vectors and the independent Python reference require, including the per-seed history digests of\n"
    "every scheduled run in both sweeps, and real threads got exact outcomes. What it does NOT show: the stock board kernel (this is the Debian\n"
    "4.19 Malta kernel), true parallelism (QEMU's 24Kf is one CPU, so this is preemption), PowerPC, any physical board, or\n"
    "behaviour under a futex implementation older than this kernel's. The naive-tear line is information only and is counted\n"
    "nowhere. The reference and the Rust share an author; tests do not prove perfection.")


def render(report: dict[str, Any], revision: str | None) -> str:
    out = ["P05 guest receipt" + (f" (revision {revision})" if revision else "")]
    for g in report["gates"]:
        out.append(f"  {g.status.upper():<8} {g.gate_id:<16} {g.title}" + (f"\n             {g.detail}" if g.detail else ""))
    info = report.get("info")
    if info:
        out.append(f"  info     (not judged) naive two-word store: {info.get('reads')} reads, {info.get('torn')} torn")
    out.append("RESULT: " + ("PASSED" if report["ok"] else ("BLOCKED" if report.get("blocked") else "NOT PASSED")))
    out.append(HONEST_FOOTER)
    return "\n".join(out)


# ---- planted negatives (text level) --------------------------------------------------------------------------------------


def plant_host(text: str) -> str:
    """A transcript from a little-endian host run, presented as the guest's: the machine lines say so, the rest is unchanged."""
    out = []
    for line in text.split("\n"):
        if "FFW_P05T_ENV " in line:
            line = ("FFW_P05T_ENV target_arch=x86_64 target_endian=little pointer_width=64 target_os=macos size_usize=8 "
                    "size_u64=8 ne_u32=04030201 ne_u64=0807060504030201")
        elif "FFW_P05T_SYS " in line:
            line = "FFW_P05T_SYS sysname=Darwin release=24.0.0 machine=arm64"
        out.append(line)
    return "\n".join(out)


def plant_truncate(text: str) -> str:
    """The end of the transcript is missing: the guest died, or the log was cut."""
    return "\n".join(line for line in text.split("\n") if "FFW_P05T_END" not in line)


def plant_order(text: str) -> str:
    """One adjacent pair of events swapped in one scripted history: the right values in one different order."""
    out, done = [], False
    for line in text.split("\n"):
        if not done and "FFW_P05T_DIRECTED " in line and "history=" in line:
            head, history = line.split("history=", 1)
            events = history.strip().split(";")
            if len(events) >= 2 and events[0] != events[1]:
                events[0], events[1] = events[1], events[0]
                line = head + "history=" + ";".join(events)
                done = True
        out.append(line)
    if not done:
        raise MeasurementError("no scripted history with two events to reorder")
    return "\n".join(out)


def seeded_sweep_lines(text: str) -> list[str]:
    return [ln for ln in text.replace("\r", "").split("\n") if "FFW_P05T_SWEEP " in ln and "set=seeded" in ln]


def plant_replay(text: str, earlier: str) -> str:
    """This run's transcript with its seeded sweep lines replaced by an earlier run's, the seed echo left honest."""
    replaced = iter(seeded_sweep_lines(earlier))
    out = []
    for line in text.split("\n"):
        if "FFW_P05T_SWEEP " in line and "set=seeded" in line:
            line = next(replaced)
        out.append(line)
    return "\n".join(out)


PLANTS = {  # name -> (the gates it must fail, the only gates it may fail)
    "host": ({"P05T-ENV"}, {"P05T-ENV"}),
    "truncate": ({"P05T-TRANSCRIPT"}, {"P05T-TRANSCRIPT"}),
    "order": ({"P05T-DIRECTED"}, {"P05T-DIRECTED"}),
    "replay": ({"P05T-SEEDED"}, {"P05T-SEEDED"}),
}


def plant_verdict(name: str, report: dict[str, Any]) -> tuple[bool, str]:
    """Caught means exactly the gates the plant is meant to trip failed, and no others: a plant that trips several
    detectors at once would stay red after one of them were deleted."""
    must, only = PLANTS[name]
    failed = {g.gate_id for g in report["gates"] if g.status == "failed"}
    caught = must <= failed and failed <= only
    return caught, f"failed gates {sorted(failed) or 'none'}; wanted exactly {sorted(must)}"


# ---- running the guest -----------------------------------------------------------------------------------------------------


def kernel_path() -> pathlib.Path:
    import os
    build = os.environ.get("FFW_BUILD_DIR")
    if not build:
        raise MeasurementError("FFW_BUILD_DIR is not set; it must contain kernels/xm/boot/ (the committed receipts "
                               f"record kernel digest {KERNEL_SHA256_PREFIX}...)")
    return pathlib.Path(build) / "kernels" / "xm" / "boot" / KERNEL_NAME


def run_guest(elf: pathlib.Path, work: pathlib.Path, label: str, timeout: float, extra_files: list[tuple[str, int, bytes]]
              ) -> tuple[str, dict[str, Any]]:
    """Pack `elf` as the guest's /init (plus `extra_files`), boot it under QEMU, return the transcript."""
    kernel = kernel_path()
    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if not digest.startswith(KERNEL_SHA256_PREFIX):
        raise MeasurementError(f"kernel digest {digest[:16]}... is not the committed {KERNEL_SHA256_PREFIX}...")
    mkinitramfs = _load(HERE / "mkinitramfs.py", "mkinitramfs_for_p05_target")
    initramfs = work / f"{label}.cpio.gz"
    mkinitramfs.build(elf, initramfs, extra_files=extra_files)
    command = ["qemu-system-mips", "-M", "malta", "-cpu", "24Kf", "-m", "64M", "-nographic", "-no-reboot",
               "-icount", "shift=0,align=off,sleep=off", "-kernel", str(kernel), "-initrd", str(initramfs),
               "-append", "console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3"]
    version = subprocess.run(["qemu-system-mips", "--version"], capture_output=True, text=True, check=False).stdout
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout,
                                   stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        text = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
        raise MeasurementError(f"{label}: QEMU did not finish within {timeout:.0f}s; last output: {text[-400:]!r}") from exc
    return completed.stdout, {"command": command, "qemu": version.splitlines()[0] if version else "unknown",
                              "kernel_sha256": digest, "exit_code": completed.returncode}


def central_commands(snapshot: pathlib.Path, label: str) -> str:
    target_dir = snapshot / "build" / "p05-target-target"
    config_linker = f'target.{TARGET}.linker="{snapshot}/toolchain/linker/zig-cc-mips-be"'
    config_flags = f'target.{TARGET}.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
    return (f"cd {snapshot} && RCH_CANONICAL_PROJECT_ROOT={snapshot} RCH_REQUIRE_REMOTE=1 "
            f"RCH_WORKER=hz4,hz3,ts1 CARGO_TARGET_DIR={target_dir} rch exec -- cargo +nightly build --offline --release "
            f"--manifest-path {BENCH_REL}/Cargo.toml --target {TARGET} -Z build-std=core,alloc,std,panic_abort "
            f"--config '{config_linker}' --config '{config_flags}' -j 2"
            f"   # {label}; ELF: {target_dir}/{TARGET}/release/ffw-p05-target")


def prepare(work_dir: pathlib.Path) -> str:
    """Snapshot HEAD plus the guest crate (it may be uncommitted yet). Nothing is built; nothing is deleted."""
    if work_dir.exists() and any(work_dir.iterdir()):
        raise MeasurementError(f"{work_dir} exists and is not empty; choose a fresh directory (nothing is deleted)")
    plain = work_dir / "plain"
    plain.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=REPO, capture_output=True, check=True)
    with tempfile.TemporaryFile() as handle:
        handle.write(archive.stdout)
        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:") as tar:
            tar.extractall(plain, filter="data")
    shutil.copytree(REPO / BENCH_REL, plain / BENCH_REL, dirs_exist_ok=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
    return "\n".join([
        f"snapshot of HEAD {head} plus {BENCH_REL}: {plain}",
        "",
        "Central guest build (RCH only; run from the snapshot root). The guest has no dependencies, so it needs no lockfile:",
        central_commands(plain, "P05 target guest"),
        "",
        "Then:  FFW_BUILD_DIR=<kernel cache> python3 toolchain/src/measure-p05-target.py run --elf <ELF> "
        "--log-dir <fresh dir> --plant host --plant order --plant truncate --plant replay --revision " + head])


def write_receipt(path: pathlib.Path, report: dict[str, Any], elf: dict[str, Any] | None, meta: dict[str, Any] | None,
                  seed: int | None, revision: str | None, transcript: str | None) -> None:
    body = {"schema": SCHEMA, "revision": revision, "seed": seed, "result": "passed" if report["ok"] else (
        "blocked" if report.get("blocked") else "not_passed"),
        "elf": None if elf is None else {"sha256": elf["sha256"], "bytes": elf["bytes"]},
        "kernel_sha256": None if meta is None else meta["kernel_sha256"], "qemu": None if meta is None else meta["qemu"],
        "transcript_sha256": None if transcript is None else hashlib.sha256(transcript.encode()).hexdigest(),
        "gates": [vars(g) for g in report["gates"]], "scope": HONEST_FOOTER}
    path.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", encoding="utf-8")


# ---- the real Asupersync runtime consumer (distinct from the atomic-cell guest above) ---------------------------------------

RUNTIME_PHASES = (
    "PROFILE_ACCEPT", "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE",
    "PROFILE_REFUSES_OVER_BUDGET", "REACTOR", "RUNTIME_AUDIT", "SPAWN_JOIN", "ABORT_TIMER_PARKED",
    "ABORT_BLIND_VALUE", "TIMER_WAKE", "UDP_LOOPBACK", "BLOCKING_POOL", "DRAIN",
)
RUNTIME_CENSUS = (
    "start", "after_build", "after_spawn_join", "after_abort_timer_parked", "after_abort_blind_value",
    "after_timer_wake", "after_udp", "after_blocking_pool", "after_drain", "after_runtime_drop",
)
RUNTIME_ORDER = (
    "BEGIN", "CENSUS", *RUNTIME_PHASES[:6], "CENSUS",
    *(tag for phase in RUNTIME_PHASES[6:] for tag in (phase, "CENSUS")), "CENSUS", "END",
)
RUNTIME_THREADED = "threaded"
RUNTIME_SINGLE_OWNER = "single-owner"
RUNTIME_CALLER_DRIVEN = "caller-driven"
RUNTIME_PROFILES = (RUNTIME_THREADED, RUNTIME_SINGLE_OWNER, RUNTIME_CALLER_DRIVEN)
# What each profile's BEGIN row says about its topology (the threaded run says nothing).
RUNTIME_TOPOLOGY = {RUNTIME_THREADED: None, RUNTIME_SINGLE_OWNER: "single_owner", RUNTIME_CALLER_DRIVEN: "caller_driven"}
# The single-owner profile, written out row by row from the probe's second run (toolchain/src/p05-runtime `run_probe_for` with
# `Topology::SingleOwner`), not derived from the threaded tuples above.
SINGLE_OWNER_DECLARED_UNSUPPORTED = "CALLER_DRIVEN_CURRENT_THREAD"
SINGLE_OWNER_PHASES = (
    "SINGLE_OWNER_PROFILE", "PROFILE_ACCEPT", "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE",
    "PROFILE_REFUSES_OVER_BUDGET", "REACTOR", "RUNTIME_AUDIT", "SINGLE_OWNER_RUNTIME", SINGLE_OWNER_DECLARED_UNSUPPORTED,
    "SPAWN_JOIN", "ABORT_TIMER_PARKED", "ABORT_BLIND_VALUE", "TIMER_WAKE", "UDP_LOOPBACK", "BLOCKING_POOL",
    "SINGLE_OWNER_BLOCKING_OFFLOAD", "DRAIN", "BYTE_BUDGET_REFUSAL", "FIRST_USE_BACKGROUND", "RUNTIME_USABLE_AFTER_REFUSAL",
)
SINGLE_OWNER_CENSUS = (
    "start", "after_build", "after_single_owner_threads", "after_spawn_join", "after_abort_timer_parked",
    "after_abort_blind_value", "after_timer_wake", "after_udp", "after_blocking_pool", "after_blocking_offload",
    "after_drain", "after_runtime_drop", "after_byte_budget",
)
# The census rows that follow a runtime drop. There the single-owner probe waits, bounded, for the process to be back at the thread
# count it started with, and prints how the wait ended on the row: `settle`, `settle_threads`, `settle_polls`
# (toolchain/src/p05-runtime, `settle_threads`). A join returns before the kernel has unlisted the joined thread, so without this
# a census can read a thread that is still leaving (the first mips run).
SINGLE_OWNER_SETTLE_ROWS = ("after_runtime_drop", "after_byte_budget")
SINGLE_OWNER_ORDER = (
    "BEGIN", "CENSUS",
    "SINGLE_OWNER_PROFILE", "PROFILE_ACCEPT", "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE",
    "PROFILE_REFUSES_OVER_BUDGET", "REACTOR", "RUNTIME_AUDIT", "CENSUS",
    "SINGLE_OWNER_RUNTIME", SINGLE_OWNER_DECLARED_UNSUPPORTED, "CENSUS",
    "SPAWN_JOIN", "CENSUS", "ABORT_TIMER_PARKED", "CENSUS", "ABORT_BLIND_VALUE", "CENSUS", "TIMER_WAKE", "CENSUS",
    "UDP_LOOPBACK", "CENSUS", "BLOCKING_POOL", "CENSUS", "SINGLE_OWNER_BLOCKING_OFFLOAD", "CENSUS",
    "DRAIN", "CENSUS", "CENSUS",
    "BYTE_BUDGET_REFUSAL", "FIRST_USE_BACKGROUND", "RUNTIME_USABLE_AFTER_REFUSAL", "CENSUS",
    "END",
)
# The caller-driven profile, written out row by row from the probe's third run (toolchain/src/p05-runtime `Topology::CallerDriven`),
# not derived from the tuples above. It is a runtime built with `LegacyProfile::caller_driven()`: one scheduler worker that no thread
# owns (`block_on` runs every task, timer and reactor turn on the calling thread), no blocking thread and no helper thread, so the
# profile's OS-thread ceiling is 0 and no census row may show a thread above the starting count. Every row is `ok`: unlike the
# single-owner run it declares nothing unsupported. It needs an Asupersync that has `LegacyProfile::caller_driven`; the pin of the
# committed single-owner evidence (460306de) does not.
CALLER_DRIVEN_PHASES = (
    "CALLER_DRIVEN_PROFILE", "PROFILE_ACCEPT", "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE",
    "PROFILE_REFUSES_OVER_BUDGET", "CALLER_DRIVEN_REFUSES_TWO_WORKERS", "CALLER_DRIVEN_REFUSES_BLOCKING_THREADS", "REACTOR",
    "RUNTIME_AUDIT", "CALLER_DRIVEN_RUNTIME", "SPAWN_JOIN", "ABORT_TIMER_PARKED", "ABORT_BLIND_VALUE", "TIMER_WAKE",
    "UDP_LOOPBACK", "CALLER_DRIVEN_BLOCKING_REFUSED", "CALLER_DRIVEN_HANDLE_SPAWN_WAITS", "DRAIN",
)
CALLER_DRIVEN_CENSUS = (
    "start", "after_build", "after_caller_driven_tasks", "after_spawn_join", "after_abort_timer_parked",
    "after_abort_blind_value", "after_timer_wake", "after_udp", "after_blocking_refused", "after_handle_spawn",
    "after_drain", "after_runtime_drop",
)
CALLER_DRIVEN_SETTLE_ROWS = ("after_runtime_drop",)
CALLER_DRIVEN_ORDER = (
    "BEGIN", "CENSUS",
    "CALLER_DRIVEN_PROFILE", "PROFILE_ACCEPT", "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE",
    "PROFILE_REFUSES_OVER_BUDGET", "CALLER_DRIVEN_REFUSES_TWO_WORKERS", "CALLER_DRIVEN_REFUSES_BLOCKING_THREADS",
    "REACTOR", "RUNTIME_AUDIT", "CENSUS",
    "CALLER_DRIVEN_RUNTIME", "CENSUS", "SPAWN_JOIN", "CENSUS", "ABORT_TIMER_PARKED", "CENSUS", "ABORT_BLIND_VALUE", "CENSUS",
    "TIMER_WAKE", "CENSUS", "UDP_LOOPBACK", "CENSUS", "CALLER_DRIVEN_BLOCKING_REFUSED", "CENSUS",
    "CALLER_DRIVEN_HANDLE_SPAWN_WAITS", "CENSUS", "DRAIN", "CENSUS", "CENSUS",
    "END",
)
# Per profile: the phases whose fields are judged, the exact marker order, the census phases, and the END tallies.
RUNTIME_SHAPES = {
    RUNTIME_THREADED: {"phases": RUNTIME_PHASES, "order": RUNTIME_ORDER, "census": RUNTIME_CENSUS,
                       "ops": 23, "ok": 23, "unsupported": 0, "census_samples": 10},
    RUNTIME_SINGLE_OWNER: {"phases": SINGLE_OWNER_PHASES, "order": SINGLE_OWNER_ORDER, "census": SINGLE_OWNER_CENSUS,
                           "ops": 33, "ok": 32, "unsupported": 1, "census_samples": 13},
    RUNTIME_CALLER_DRIVEN: {"phases": CALLER_DRIVEN_PHASES, "order": CALLER_DRIVEN_ORDER, "census": CALLER_DRIVEN_CENSUS,
                            "ops": 30, "ok": 30, "unsupported": 0, "census_samples": 12},
}
# The initramfs file that selects the single-owner run (the probe reads `/ffw_p05_profile`, as the other guests read `/ffw_seed`).
SINGLE_OWNER_MARKER_NAME = "ffw_p05_profile"
SINGLE_OWNER_MARKER_BYTES = b"single-owner\n"
CALLER_DRIVEN_MARKER_BYTES = b"caller-driven\n"
# The same file with other content selects the caller-driven run; the threaded run packs no marker at all.
RUNTIME_MARKER_BYTES = {RUNTIME_SINGLE_OWNER: SINGLE_OWNER_MARKER_BYTES, RUNTIME_CALLER_DRIVEN: CALLER_DRIVEN_MARKER_BYTES}
# The single-owner run's one declared row says why the caller-driven mode is not run in it. Two declarations are valid, each only with
# its own source: the one made at Asupersync 460306de (whose `LegacyProfile` cannot build the mode at all, read from that source), and
# the one made once the mode exists, which points to the separate caller-driven profile (the single-owner profile has a blocking pool,
# which the caller-driven mode forbids). A declaration paired with the other one's source is refused.
DECLARED_REASON_AT_PIN = "profile_builder_cannot_build_caller_driven_mode"
DECLARED_EVIDENCE_AT_PIN = "asupersync_460306de:"
DECLARED_REASON_SPLIT = "caller_driven_mode_is_the_separate_caller_driven_profile"
DECLARED_EVIDENCE_SPLIT = "LegacyProfile::caller_driven"
# Command-line exit for a single-owner run that is accepted WITH its one declared unsupported row. Not 0 (that is a full pass), not 1
# (failed), 2 (usage or error) or 3 (blocked).
EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED = 4
RUNTIME_ARCHES = {"mips": (1, 2, 8, 32), "powerpc": (1, 2, 20, 32), "x86_64": (2, 1, 62, 64)}
RUNTIME_SCHEMA = "ffw.p05.runtime_receipt.v1"
RUNTIME_CAPTURE_BYTES = 1024 * 1024
RUNTIME_SCOPE = (
    "A runtime transcript is distinct from the atomic-cell guest. Native execution does not qualify BE execution. "
    "A supplied ELF hash binds bytes, not their compiler/source provenance. The supplied revision is an operator claim, "
    "not an attestation. Analysis only validates supplied transcript bytes; command exit and execution custody require "
    "the original execution receipt. This runner compiles nothing. Synthetic checker tests are not runtime or QEMU proof. "
    "A guest pass covers the named phases under the recorded QEMU kernel, not stock kernels, 32 MiB memory fit, "
    "physical drivers/audio, provider integrations, or completion of P05/P03."
)
SINGLE_OWNER_SCOPE = (
    "This is the single-owner run: one scheduler worker through LegacyProfile, selected by an initramfs marker because the "
    "unchanged supervisor passes the probe no argument. The caller-driven current-thread mode is not run in this profile, so "
    "that row is DECLARED unsupported, not passed (the reason it prints says why, and the declaration is read from source, not "
    "observed): the result is accepted with exactly that one row, never a full pass. The probe exits 0 only for exactly that "
    "row, so the supervisor log is the ordinary one and is judged unmodified."
)
CALLER_DRIVEN_SCOPE = (
    "This is the caller-driven run: a runtime built with LegacyProfile::caller_driven, whose one scheduler worker is driven by the "
    "thread that calls block_on, with no blocking thread and no helper thread, selected by an initramfs marker because the "
    "unchanged supervisor passes the probe no argument. Its rows are observations on one such runtime in one guest: that its tasks, "
    "timers and drain ran on the calling thread, that no census row showed a thread above the starting count, that blocking work "
    "is refused, and that work spawned through a handle between block_on calls waits for the next block_on. It does not show that "
    "the mode is suitable for the speaker's I/O load, or that it is deadlock-free: a synchronous block inside a task stalls the "
    "whole runtime by design. Every row is ok and nothing is declared unsupported."
)


def runtime_file_identity(path: pathlib.Path) -> tuple[bytes, dict[str, Any]]:
    """Read a regular artifact once with bounded memory; detect a concurrent size/timestamp change."""
    if not path.is_file():
        raise MeasurementError("a regular artifact file is required")
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise MeasurementError("a regular artifact file is required")
        remaining = before.st_size
        header = source.read(min(64, remaining))
        remaining -= len(header)
        digest = hashlib.sha256(header)
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise MeasurementError("artifact was truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise MeasurementError("artifact changed while reading")
    return header, {"sha256": digest.hexdigest(), "bytes": before.st_size}


def runtime_uint(value: str | None) -> int | None:
    """Canonical ASCII decimal emitted by the probe, never Unicode digits, signs or Python underscores."""
    if value is None or len(value) > 20 or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        return None
    number = int(value)
    return number if number <= (1 << 64) - 1 else None


def runtime_lines(text: str) -> list[str]:
    # splitlines() also treats VT/FF/Unicode separators as newlines; the serial contract permits LF/CRLF only.
    return text.replace("\r\n", "\n").split("\n")


def runtime_has_nonserial(text: str) -> bool:
    """Inspect text already normalized exactly once; normalizing again would hide CR-CR-LF."""
    return re.search(r"[\x00-\x08\x0b-\x1f\x7f\x85\u2028\u2029]", text) is not None


def runtime_elf(path: pathlib.Path, arch: str) -> dict[str, Any]:
    """Header/byte identity only; actual loading, static linkage and source custody need their own evidence."""
    data, identity = runtime_file_identity(path)
    cls, endian, machine, bits = RUNTIME_ARCHES[arch]
    if len(data) < (52 if cls == 1 else 64) or data[:4] != b"\x7fELF":
        raise MeasurementError("runtime/supervisor ELF header is absent or truncated")
    actual_machine = int.from_bytes(data[18:20], "big" if data[5] == 2 else "little")
    if (data[4], data[5], actual_machine) != (cls, endian, machine):
        raise MeasurementError(f"ELF class/endian/machine {(data[4], data[5], actual_machine)} does not match {arch}")
    return {**identity, "arch": arch, "pointer_bits": bits,
            "source_provenance": "not_attested_by_this_runner"}


def declared_row_problems(name: str, pairs: dict[str, str]) -> list[str]:
    """The single-owner run's declared row must carry one of the two valid declarations, each with its own source and no other.

    The declaration made at Asupersync 460306de says the profile builder cannot build the mode and cites that revision's source, so it
    is valid only with that revision named: the committed single-owner receipts are judged by it. Once the mode exists the probe
    declares instead that the mode is the separate caller-driven profile, and cites that profile's constructor. Neither is an
    observation, and a reason paired with the other one's source is refused."""
    reason, source, evidence = pairs.get("reason"), pairs.get("reason_source"), pairs.get("evidence", "")
    if (reason, source) == (DECLARED_REASON_AT_PIN, "static_source_reading"):
        if not evidence.startswith(DECLARED_EVIDENCE_AT_PIN):
            return [f"{name}: the declaration of {DECLARED_REASON_AT_PIN} names no {DECLARED_EVIDENCE_AT_PIN} source evidence"]
        # The revision alone is not evidence: the declaration is a reading of that source, so it must cite where (`path:line`).
        if re.match(r"[^\s:,]+:[0-9]+", evidence[len(DECLARED_EVIDENCE_AT_PIN):]) is None:
            return [f"{name}: the declaration of {DECLARED_REASON_AT_PIN} cites no source location (path:line) after "
                    f"{DECLARED_EVIDENCE_AT_PIN}"]
        return []
    if (reason, source) == (DECLARED_REASON_SPLIT, "profile_split"):
        if evidence != DECLARED_EVIDENCE_SPLIT:
            return [f"{name}: the declaration of {DECLARED_REASON_SPLIT} does not cite {DECLARED_EVIDENCE_SPLIT}"]
        return []
    return [f"{name}: reason={reason or 'missing'} reason_source={source or 'missing'} is not one of the two valid declarations"]


def runtime_phase_problems(name: str, pairs: dict[str, str], detail: str, profile: str = RUNTIME_THREADED) -> list[str]:
    """Hand-stated observable predicates, independent of the probe's status bit and summary."""
    exact = {
        "PROFILE_ACCEPT": {"violations": "0", "worst_case_stack_bytes": "2621440", "budget": "2621440"},
        **{name: {"named_violation": "true", "builder_refused": "true"} for name in (
            "PROFILE_REFUSES_ZERO_WORKERS", "PROFILE_REFUSES_UNBOUNDED_QUEUE", "PROFILE_REFUSES_OVER_BUDGET")},
        "REACTOR": {"kind": "platform"},
        "RUNTIME_AUDIT": {"audit_ok": "true", "workers": "2/2", "blocking_threads": "1/1",
                          "global_queue": "256/256", "blocking_queue": "1/1"},
        "SPAWN_JOIN": {"children": "8", "joined": "8", "sum": "140", "expected": "140"},
        "ABORT_TIMER_PARKED": {"parked": "true", "join_result": "Ok", "expected_join_result": "Ok"},
        "ABORT_BLIND_VALUE": {"join_result": "Cancelled", "expected_join_result": "Cancelled", "ok_value": "None"},
        "TIMER_WAKE": {"wanted_ms": "50"},
        "UDP_LOOPBACK": {"bytes": "19", "payload_equal": "true", "peer_is_sender": "true"},
        "BLOCKING_POOL": {"idle_threads": "0", "first_admitted": "true", "first_started": "true",
                          "second_admitted": "true", "third_refused": "Some(Saturated)",
                          "active_threads_while_held": "1", "pending_while_held": "1",
                          "first_finished": "true", "second_finished": "true", "ran": "2"},
        "DRAIN": {"tasks_spawned": "4/4", "tasks_parked_before_drain": "4", "bound_ms": "5000"},
    }
    if profile == RUNTIME_SINGLE_OWNER:
        # One scheduler worker: the caps differ from the threaded profile only in the worker count, so the stack figure
        # (1 MiB worker + 0.5 MiB blocking thread) and the carried/stated workers differ; every other shared row is the same.
        exact = {
            **exact,
            "PROFILE_ACCEPT": {"violations": "0", "worst_case_stack_bytes": "1572864", "budget": "1572864"},
            "RUNTIME_AUDIT": {"audit_ok": "true", "workers": "1/1", "blocking_threads": "1/1",
                              "global_queue": "256/256", "blocking_queue": "1/1"},
            "SINGLE_OWNER_PROFILE": {"claimed": "single_owner", "stated_worker_threads": "1", "required_worker_threads": "1"},
            "SINGLE_OWNER_RUNTIME": {"carried_workers": "1", "stated_workers": "1", "audit_ok": "true",
                                     "children_joined": "8", "task_threads": "1", "tasks_on_caller_thread": "false"},
            # The reason and its source are a declaration, not an observation; the two valid pairs are checked below.
            SINGLE_OWNER_DECLARED_UNSUPPORTED: {"observed_tasks_on_caller_thread": "false"},
            "SINGLE_OWNER_BLOCKING_OFFLOAD": {"held_admitted": "true", "held_started": "true", "async_phase": "ok",
                                              "held_job_unfinished_during_async": "true",
                                              "held_job_finished_after_release": "true"},
            "BYTE_BUDGET_REFUSAL": {"audit_ok": "true", "policy": "BoundedBytes", "reactor": "none", "budget_bytes": "4096",
                                    "declared_heap_bytes": "4097", "refusal": "Some(ChargeTooLarge)",
                                    "expected_refusal": "Some(ChargeTooLarge)", "pool_threads_after_refusal": "0",
                                    "refused_job_ran": "false"},
            "FIRST_USE_BACKGROUND": {"pool_threads_before_first_job": "0", "pool_threads_while_job_runs": "1",
                                     "job_started": "true", "job_finished": "true"},
            "RUNTIME_USABLE_AFTER_REFUSAL": {"spawn_join": "ok", "outcome": "Quiescent", "live_tasks": "0",
                                             "pending_obligations": "0", "live_regions": "0", "queued_finalizers": "0",
                                             "pending_spawns": "0", "pending_obligation_posts": "false"},
        }
    if profile == RUNTIME_CALLER_DRIVEN:
        # One worker that no thread owns, no blocking thread, no helper thread. The figures below are the probe's stated caps, not
        # measurements: the 1 MiB stack is the one worker's stated stack, an over-count that binds no thread. The rows shared with the
        # other profiles keep their exact fields, except the two that state the caps.
        exact = {
            **exact,
            "PROFILE_ACCEPT": {"violations": "0", "worst_case_stack_bytes": "1048576", "budget": "1048576"},
            "RUNTIME_AUDIT": {"audit_ok": "true", "workers": "1/1", "blocking_threads": "0/0",
                              "global_queue": "256/256", "blocking_queue": "0/0"},
            "CALLER_DRIVEN_PROFILE": {"claimed": "caller_driven", "stated_worker_threads": "1", "required_worker_threads": "1",
                                      "blocking_max_threads": "0", "os_thread_ceiling": "0"},
            "CALLER_DRIVEN_REFUSES_TWO_WORKERS": {"named_violation": "true", "builder_refused": "true",
                                                  "stated_worker_threads": "2"},
            "CALLER_DRIVEN_REFUSES_BLOCKING_THREADS": {"named_violation": "true", "builder_refused": "true",
                                                       "stated_blocking_max_threads": "1"},
            "CALLER_DRIVEN_RUNTIME": {"carried_workers": "1", "stated_workers": "1", "audit_ok": "true", "os_thread_ceiling": "0",
                                      "children_joined": "8", "task_threads": "1", "tasks_on_caller_thread": "true"},
            "CALLER_DRIVEN_BLOCKING_REFUSED": {"policy": "Forbidden", "refusal": "Some(Forbidden)",
                                               "expected_refusal": "Some(Forbidden)", "charged_refusal": "Some(Forbidden)",
                                               "pool_threads_after_refusal": "0", "refused_job_ran": "false"},
            "CALLER_DRIVEN_HANDLE_SPAWN_WAITS": {"ran_before_block_on": "false", "ran_after_block_on": "true",
                                                 "ran_on_caller": "true"},
        }
    problems = [f"{name}.{key}={pairs.get(key, 'missing')} expected={value}"
                for key, value in exact.get(name, {}).items() if pairs.get(key) != value]
    if profile == RUNTIME_SINGLE_OWNER:
        if name == SINGLE_OWNER_DECLARED_UNSUPPORTED:
            problems.extend(declared_row_problems(name, pairs))
        if name == "SINGLE_OWNER_BLOCKING_OFFLOAD" and not re.search(
                r"\basync_detail=\(children=8 joined=8 sum=140 expected=140\)", detail):
            problems.append(f"{name}: the async phase that ran beside the held blocking job did not join all 8 children")
        if name == "FIRST_USE_BACKGROUND":
            before, during = (runtime_uint(pairs.get(key)) for key in ("os_threads_before", "os_threads_during"))
            if before is None or during is None or not before < during:
                problems.append(f"{name}: no OS thread appeared (os_threads_before={pairs.get('os_threads_before', 'missing')}"
                                f" os_threads_during={pairs.get('os_threads_during', 'missing')})")
    if name == "ABORT_TIMER_PARKED":
        before, after, elapsed = (runtime_uint(pairs.get(key)) for key in (
            "pending_timers_before", "pending_timers_after", "abort_to_join_ms"))
        if before is None or before < 1 or after is None or after < 0 or after + 1 != before:
            problems.append("ABORT_TIMER_PARKED: exactly one registered timer must retire")
        if elapsed is None or not 0 <= elapsed < 1000:
            problems.append("ABORT_TIMER_PARKED: missing/out-of-bound abort latency")
    if name == "TIMER_WAKE":
        elapsed = runtime_uint(pairs.get("slept_ms"))
        if elapsed is None or not 45 <= elapsed < 5000:
            problems.append("TIMER_WAKE: wake is earlier than tolerance or outside the bound")
    if name == "DRAIN":
        snapshot = re.search(r"\bsnapshot_before_drain=\(admitted=([0-9]+) unfinished=([0-9]+) timers_pending=([0-9]+)\)", detail)
        snapshot_values = tuple(runtime_uint(value) for value in snapshot.groups()) if snapshot else ()
        if len(snapshot_values) != 3 or snapshot_values[:2] != (4, 4) or snapshot_values[2] is None or snapshot_values[2] < 4:
            problems.append("DRAIN: four admitted tasks must still be parked on live timers")
        elapsed = runtime_uint(pairs.get("elapsed_ms"))
        if elapsed is None or not 0 <= elapsed < 5000:
            problems.append("DRAIN: missing/out-of-bound drain latency")
    return problems


def runtime_settle_problems(census_rows: dict[str, dict[str, str]],
                            settle_rows: tuple[str, ...] = SINGLE_OWNER_SETTLE_ROWS) -> list[str]:
    """The single-owner rule for the census rows that follow a runtime drop; `census_rows` maps each row's phase to its pairs.

    Each such row must say `settle=settled`, give a `settle_threads` no larger than this run's own `start` row, and a
    `settle_polls` of at least 1, and the row's own stable thread count may not be above the start count either. A row that is
    `ok` while its wait did not settle contradicts itself. The judge reads the probe's report; it cannot see the wait. The pairs may not be
    absent: a transcript from a probe built before the settle cannot show that the drop was awaited (the same bytes failed once
    on mips), so it is refused and never read as settled. A missing row is the census phase list's business, not this rule's."""
    start = census_rows.get("start", {})
    figures = [runtime_uint(start.get(key)) for key in ("threads_task_dir_before", "threads_task_dir_after", "threads_status")]
    floor = figures[0] if None not in figures and figures[0] == figures[1] == figures[2] and figures[0] > 0 else None
    problems = []
    for phase in settle_rows:
        row = census_rows.get(phase)
        if row is None:
            continue
        word = row.get("settle")
        if word is None:
            absent = [key for key in ("settle", "settle_threads", "settle_polls") if key not in row]
            problems.append(f"{phase}: the settle pairs are missing ({', '.join(absent)}); nothing shows the drop was awaited")
            continue
        if word != "settled":
            if row.get("status") == "ok" and word in ("pending", "unmeasured"):
                problems.append(f"{phase}: status=ok contradicts settle={word}")
            else:
                problems.append(f"{phase}: settle={word} is not settled")
            continue
        absent = [key for key in ("settle_threads", "settle_polls") if key not in row]
        if absent:
            problems.append(f"{phase}: settle=settled without {', '.join(absent)}")
            continue
        threads, polls = runtime_uint(row["settle_threads"]), runtime_uint(row["settle_polls"])
        if threads is None:
            problems.append(f"{phase}: settle_threads={row['settle_threads']} is not a count")
        elif threads < 1:
            problems.append(f"{phase}: settle_threads={threads} is impossible: a running process has at least one thread")
        elif floor is None:
            problems.append(f"{phase}: the start row has no stable thread count to compare settle_threads with")
        elif threads > floor:
            problems.append(f"{phase}: settle_threads={threads} is above the start count {floor}")
        if polls is None or polls < 1:
            problems.append(f"{phase}: settle_polls={row['settle_polls']} is not at least 1")
        # The row's own stable count is the figure the printed pairs cannot hide: threads that left after the settle reading
        # leave it lower than `settle_threads` (harmless), a thread still there leaves it above the start count.
        own = [runtime_uint(row.get(key)) for key in ("threads_task_dir_before", "threads_task_dir_after", "threads_status")]
        if floor is not None and None not in own and own[0] == own[1] == own[2] and own[0] > floor:
            problems.append(f"{phase}: the row shows {own[0]} threads, above the start count {floor}")
    return problems


def stable_thread_count(pairs: dict[str, str]) -> int | None:
    """The thread count of a census row when its two directory readings and the status reading are equal and positive, else None."""
    figures = [runtime_uint(pairs.get(key)) for key in ("threads_task_dir_before", "threads_task_dir_after", "threads_status")]
    return figures[0] if None not in figures and figures[0] == figures[1] == figures[2] and figures[0] > 0 else None


def runtime_caller_driven_problems(ops: list[tuple[str, dict[str, str]]], census_rows: dict[str, dict[str, str]]) -> list[str]:
    """The caller-driven rule: no thread above the starting count, anywhere the transcript counts threads.

    The profile's OS-thread ceiling is 0 (no worker thread, no blocking thread, no helper thread), so the process may not hold
    more threads than it started with. This is the thread-side half of "the runtime is driven by the caller": the other half is
    that the tasks were seen on the calling thread. Each census row must print that ceiling and show a stable count no larger than
    the `start` row's; so must the two places a thread count is read inside a running task (`ABORT_TIMER_PARKED`, which prints
    both of its readings, and `CALLER_DRIVEN_RUNTIME`). A start row with no stable count leaves nothing to hold the rest to, and
    is refused."""
    floor = stable_thread_count(census_rows.get("start", {}))
    if floor is None:
        return ["start: no stable thread count, so no row can be held to the starting count"]
    problems = []
    for phase, row in census_rows.items():
        if row.get("os_thread_ceiling") != "0":
            problems.append(f"{phase}: os_thread_ceiling={row.get('os_thread_ceiling', 'missing')} is not the ceiling 0")
        own = stable_thread_count(row)
        if own is not None and own > floor:
            problems.append(f"{phase}: the row shows {own} threads, above the starting count {floor}")
    rows = {name: pairs for name, pairs in ops if name in ("ABORT_TIMER_PARKED", "CALLER_DRIVEN_RUNTIME")}
    readings = (("ABORT_TIMER_PARKED", "threads_during_task_dir"), ("ABORT_TIMER_PARKED", "threads_during_status"),
                ("CALLER_DRIVEN_RUNTIME", "threads_during"))
    for name, key in readings:
        seen = runtime_uint(rows.get(name, {}).get(key))
        if seen is None:
            problems.append(f"{name}: {key} is missing or not a count")
        elif seen < 1:
            problems.append(f"{name}: {key}={seen} is impossible: a reading taken inside a running task counts at least "
                            "the thread that runs it")
        elif seen > floor:
            problems.append(f"{name}: {key}={seen} is above the starting count {floor}")
    start_threads = runtime_uint(rows.get("CALLER_DRIVEN_RUNTIME", {}).get("start_threads"))
    if start_threads != floor:
        problems.append(f"CALLER_DRIVEN_RUNTIME: start_threads={start_threads if start_threads is not None else 'missing'} "
                        f"is not the start row's {floor}")
    return problems


def judge_runtime(text: str, arch: str, elf: dict[str, Any] | None, *, supervised: bool = False,
                  profile: str = RUNTIME_THREADED) -> dict[str, Any]:
    """Judge exact phase/census identity, order and observed tallies; never accept an END total by itself.

    `profile` selects which of the probe's three runs the transcript must be (default: the threaded run, unchanged). The
    single-owner profile has exactly one declared unsupported row, and `ok` then means "accepted with that one row", never a
    full pass: the caller reads `report["declared_unsupported"]`. The caller-driven profile declares nothing: every row is ok,
    and no census row may show a thread above the starting count."""
    if profile not in RUNTIME_SHAPES:
        raise MeasurementError(f"unknown runtime profile {profile!r}")
    shape = RUNTIME_SHAPES[profile]
    single_owner = profile == RUNTIME_SINGLE_OWNER
    caller_driven = profile == RUNTIME_CALLER_DRIVEN
    gates, rows, malformed, semantic_errors = [], [], [], []
    if runtime_has_nonserial(text.replace("\r\n", "\n")):
        malformed.append("non_serial_control_character_or_line_separator")
    for line in runtime_lines(text):
        if "FFW_P05_RUNTIME:" not in line:
            continue
        match = re.fullmatch(r"FFW_P05_RUNTIME:([A-Z_]+) (.+)", line)
        if not match:
            malformed.append("malformed_or_echoed_runtime_marker")
            continue
        try:
            detail, separator, repeat = match[2].partition(" repeat: ") if match[1] == "DRAIN" else (match[2], "", "")
            pairs = parse_pairs(detail)
            if match[1] in shape["phases"]:
                semantic_errors.extend(runtime_phase_problems(match[1], pairs, detail, profile))
            if match[1] == "DRAIN":
                repeated = parse_pairs(repeat)
                for report in (pairs, repeated):
                    if report.get("outcome") != "Quiescent" or any(report.get(key) != "0" for key in (
                            "live_tasks", "pending_obligations", "live_regions", "queued_finalizers", "pending_spawns")) or (
                            report.get("pending_obligation_posts") != "false"):
                        malformed.append("drain_counts_or_outcome_not_quiescent")
                if not separator:
                    malformed.append("missing_repeat_drain_report")
            rows.append((match[1], pairs))
        except MeasurementError as error:
            malformed.append(str(error))
    if any(token in text for token in ("\ufffd", "FFW_PANIC", "Kernel panic - not syncing")):
        malformed.append("invalid_utf8_or_guest_panic")
    if any(line.startswith("FFW_") and not line.startswith("FFW_P05_RUNTIME:") for line in runtime_lines(text)):
        malformed.append("unexpected_child_marker")
    names = [name for name, _ in rows]
    # DRAIN contains separately named snapshots and a repeated report: those detail keys are allowed there.
    # Its runtime result is still required, and the complete stdout bytes are retained by the caller.
    gates.append(_gate("P05R-TRANSCRIPT", f"all {len(shape['order'])} runtime markers in the declared order",
                       malformed + ([] if tuple(names) == shape["order"] else [f"observed marker order: {names}"])))
    begin = rows[0][1] if rows and rows[0][0] == "BEGIN" else {}
    _, endian, _, bits = RUNTIME_ARCHES[arch]
    pid = runtime_uint(begin.get("pid"))
    env_errors = []
    if begin.get("status") != "start" or begin.get("arch") != arch or begin.get("endian") != (
            "big" if endian == 2 else "little") or begin.get("pointer_bits") != str(bits):
        env_errors.append("BEGIN platform identity does not match selected architecture")
    if begin.get("topology") != RUNTIME_TOPOLOGY[profile]:
        env_errors.append(f"BEGIN topology={begin.get('topology', 'absent')} does not match the {profile} profile")
    if pid is None or pid < (2 if supervised else 1):
        env_errors.append("missing/invalid PID (a supervised runtime must be a child, not PID 1)")
    if elf is None or elf.get("arch") != arch:
        env_errors.append("missing or mismatched runtime ELF")
    gates.append(_gate("P05R-ENV", "runtime BEGIN and supplied ELF agree", env_errors))
    ops = [(name, pairs) for name, pairs in rows if name not in ("BEGIN", "END")]
    statuses = {status: sum(p.get("status") == status for _, p in ops)
                for status in ("ok", "failed", "unsupported", "partial", "unknown")}
    declared = SINGLE_OWNER_DECLARED_UNSUPPORTED if single_owner else None
    phase_errors = semantic_errors + [f"{name}: status={pairs.get('status', 'missing')}" for name, pairs in ops
                                      if name != declared and pairs.get("status") != "ok"]
    # A pre-userspace boot failure has no operations to contradict. That absence must
    # fail this gate too, rather than vacuously claiming that every operation ran.
    for phase in shape["phases"]:
        count = sum(name == phase for name, _ in ops)
        if count != 1:
            phase_errors.append(f"{phase}: required operation must appear exactly once (observed {count})")
    if single_owner:
        declared_rows = [pairs for name, pairs in ops if name == declared]
        if len(declared_rows) != 1 or declared_rows[0].get("status") != "unsupported":
            phase_errors.append(f"{declared}: must be exactly one row with status=unsupported "
                                f"(observed {[row.get('status', 'missing') for row in declared_rows]})")
    gates.append(_gate("P05R-PHASES", "every required operation reports ok, except the one declared unsupported row"
                       if single_owner else "every required operation actually reports ok", phase_errors))
    if single_owner:
        unsupported_names = [name for name, pairs in ops if pairs.get("status") == "unsupported"]
        gates.append(_gate("P05R-DECLARED", "exactly one unsupported row, the declared caller-driven mode",
                           [] if unsupported_names == [declared] else
                           [f"unsupported rows {unsupported_names}; only [{declared!r}] is declared"]))
    witness_errors, missing_witnesses = [], []
    for phase, wanted in (("ABORT_TIMER_PARKED", 1), ("DRAIN", 4)):
        found = [pairs for name, pairs in ops if name == phase]
        fields = ("cleanup_resumed", "cleanup_unique", "cleanup_cancelled", "cleanup_before_deadline")
        if len(found) != 1 or all(key not in found[0] for key in fields):
            missing_witnesses.append(f"{phase}: child-side cleanup witnesses absent")
        elif any(found[0].get(key) != str(wanted) for key in fields):
            witness_errors.append(f"{phase}: expected {wanted} unique children resumed under cancellation before natural expiry")
    gates.append(Gate("P05R-CLEANUP", "child-side cancellation cleanup is actually observed",
                      "failed" if witness_errors else "blocked" if missing_witnesses else "passed",
                      "; ".join(witness_errors + missing_witnesses)))
    census_errors, phases, census_rows = [], [], {}
    for name, pairs in ops:
        if name != "CENSUS":
            continue
        phases.append(pairs.get("phase"))
        census_rows[pairs.get("phase")] = pairs
        numbers = [runtime_uint(pairs.get(key)) for key in ("threads_task_dir_before", "threads_task_dir_after", "threads_status",
                                                   "vm_rss_kb", "vm_hwm_kb", "mem_available_kb")]
        if any(n is None or n < 0 for n in numbers):
            census_errors.append(f"{pairs.get('phase')}: unreadable or negative census figure")
        elif not (numbers[0] == numbers[1] == numbers[2] and numbers[0] > 0 and numbers[4] >= numbers[3]):
            census_errors.append(f"{pairs.get('phase')}: inconsistent thread or memory readings")
        if pairs.get("task_dir_stable") != "true" or pairs.get("sources_agree") != "true":
            census_errors.append(f"{pairs.get('phase')}: incomplete census")
    if tuple(phases) != shape["census"]:
        census_errors.append(f"observed census phases: {phases}")
    if single_owner:
        census_errors.extend(runtime_settle_problems(census_rows))
    if caller_driven:
        census_errors.extend(runtime_settle_problems(census_rows, CALLER_DRIVEN_SETTLE_ROWS))
        census_errors.extend(runtime_caller_driven_problems(ops, census_rows))
    census_title = (f"{'ten' if profile == RUNTIME_THREADED else 'thirteen' if single_owner else 'twelve'} complete, consistent "
                    "census samples" + (", each runtime drop settled" if single_owner else "") +
                    (", none above the start count, the runtime drop settled" if caller_driven else ""))
    gates.append(_gate("P05R-CENSUS", census_title, census_errors))
    end = rows[-1][1] if rows and rows[-1][0] == "END" else {}
    expected_end = {"status": "done", "ops": str(shape["ops"]), "ok": str(shape["ok"]), "failed": "0",
                    "unsupported": str(shape["unsupported"]), "partial": "0", "unknown": "0",
                    "census_samples": str(shape["census_samples"])}
    tally_errors = [] if end == expected_end and len(ops) == shape["ops"] and statuses == {
        "ok": shape["ok"], "failed": 0, "unsupported": shape["unsupported"], "partial": 0, "unknown": 0
    } else [f"END={end}; observed={statuses}"]
    gates.append(_gate("P05R-END", "END matches independently counted operations", tally_errors))
    result = {"ok": all(g.status == "passed" for g in gates), "blocked": any(g.status == "blocked" for g in gates),
              "gates": gates, "observed_statuses": statuses, "profile": profile}
    if single_owner:
        result["declared_unsupported"] = [declared]
    return result


def runtime_envelope(text: str, arch: str) -> tuple[str, list[Gate]]:
    """Only the bounded, hash-checked child region is excluded from the unchanged strict bootstrap judge."""
    lines = runtime_lines(text)
    starts = [i for i, line in enumerate(lines) if line == "FFW_MARKER:USERSPACE_START"]
    # OpenBIOS emits bare CR in its preamble. Keep that preamble, but never let the legacy splitlines()
    # parser manufacture protocol boundaries from controls or Unicode separators in userspace evidence.
    if len(starts) != 1 or runtime_has_nonserial("\n".join(lines[starts[0]:])):
        return "", [Gate("P05R-SUPERVISOR", "strict userspace serial framing", "failed",
                         "missing/duplicate standalone userspace start or invalid protocol line separator/control")]
    boot = boot_runner()
    speaker = boot.speaker_expect
    child, error = speaker.stdout_region(text)
    if error:
        return "", [Gate("P05R-SUPERVISOR", "complete smoke-slot child envelope", "failed", error)]
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("FFW_SPEAKER_BEGIN "))
    end = next(i for i, line in enumerate(lines) if line.strip().startswith("FFW_SPEAKER_EXIT "))
    errors = []
    exit_match = speaker.EXIT_OK.fullmatch(lines[end])
    if lines[start] != speaker.BEGIN_LINE or exit_match is None:
        errors.append("wrong child path/argv or child did not exit zero")
    elif int(exit_match[1]) != len(child) or int(exit_match[2], 16) != speaker.fnv1a64(child):
        errors.append("child stdout size/hash mismatch")
    if not any(line == "FFW_PROBE:LOOPBACK_UP status=PASS rc=0" for line in lines[:start]):
        errors.append("loopback was not observed UP before the runtime started")
    # Keep every supervisor marker outside this one region, including any unexpected FFW_* line.
    envelope = "\n".join(lines[:start] + lines[end + 1:]) + "\n"
    tag, errno = ("mips-be", "89") if arch == "mips" else ("powerpc-be", "38")
    checked = boot.verify_serial_output("mips" if arch == "mips" else "ppc",
        f"FFW_HELLO arch={tag} endian=0x01020304 pid=1 ptr_bits=32",
        f"FFW_TEST:ERR_ENOSYS status=PASS errno={errno}", envelope, f"{arch}-unknown-linux-musl")
    if checked["status"] != "PASS":
        errors.append(f"bootstrap: {json.dumps(checked, sort_keys=True)}")
    # Summary/reboot before the child would otherwise survive removal of the region.
    if any(line.startswith("FFW_MARKER:TEST_SUCCESS") or line == "FFW_MARKER:REBOOT_REQUEST" for line in lines[:end]):
        errors.append("supervisor summary/reboot precedes child completion")
    if any(line.strip().startswith("FFW_") and line.strip() not in (
            "FFW_MARKER:TEST_SUCCESS failures=0", "FFW_MARKER:REBOOT_REQUEST") for line in lines[end + 1:]):
        errors.append("supervisor probes/setup must all precede the runtime child")
    return child.decode("utf-8"), [_gate("P05R-SUPERVISOR", "bootstrap setup, child hash/exit and ordered reboot", errors)]


def run_runtime(args: argparse.Namespace, expected_elf: dict[str, Any],
                expected_supervisor: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Reuse E07's speaker-smoke child slot; the existing supervisor mounts proc and brings loopback up.

    The slot's `/franken-speaker --catalog` alias is deliberate: the default run ignores argv. The single-owner run is selected by
    a marker file packed into the initramfs (`ffw_p05_profile`), because the unchanged supervisor cannot pass an argument; the
    threaded run packs no marker. Do not enable speaker-platform: that would invoke this runtime twice. No compiler runs here.
    """
    profile = getattr(args, "profile", RUNTIME_THREADED)
    marker_bytes = RUNTIME_MARKER_BYTES.get(profile)
    guest_memory_mib = getattr(args, "guest_memory_mib", 64)
    if type(guest_memory_mib) is not int or guest_memory_mib not in (32, 64):
        raise MeasurementError("guest memory must be 32 or 64 MiB")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise MeasurementError("a finite positive timeout is required")
    if args.log_dir.exists() and any(args.log_dir.iterdir()):
        raise MeasurementError("log directory must be fresh; no existing evidence is overwritten")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    boot = boot_runner()
    build_dir = boot.mkinitramfs.resolve_default_build_dir(REPO)
    is_mips = args.arch == "mips"
    kernel = build_dir / ("kernels/xm/boot/" + KERNEL_NAME if is_mips else
                          "kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc")
    if not kernel.is_file():
        raise MeasurementError("runtime kernel must be a readable regular file")
    # The snapshot is also an exclusive output-name claim: concurrent invocations cannot share this directory.
    # Its name matches the existing vmlinux* Git ignore rule; no kernel bytes enter the public source tree.
    kernel_snapshot = args.log_dir / "vmlinux.runtime-snapshot"
    with kernel.open("rb") as source, kernel_snapshot.open("xb") as output:
        shutil.copyfileobj(source, output, 1024 * 1024)
    kernel_snapshot.chmod(0o400)
    _, kernel_identity = runtime_file_identity(kernel_snapshot)
    kernel_sha256 = kernel_identity["sha256"]
    archive = args.log_dir / "runtime.cpio.gz"
    extras = [("franken-speaker", 0o100755, args.elf.read_bytes())]
    if marker_bytes is not None:
        extras.append((SINGLE_OWNER_MARKER_NAME, S_IFREG_644, marker_bytes))
    image = boot.mkinitramfs.build(args.supervisor, archive, extras, exclusive=True)
    if image["init_sha256"] != expected_supervisor["sha256"]:
        raise MeasurementError("supervisor bytes changed before packaging; guest not launched")
    if image["extra_files"]["franken-speaker"]["sha256"] != expected_elf["sha256"]:
        raise MeasurementError("runtime bytes changed before packaging; guest not launched")
    if (SINGLE_OWNER_MARKER_NAME in image["extra_files"]) != (marker_bytes is not None):
        raise MeasurementError("the profile marker must be packed for the single-owner and caller-driven runs and for no other; "
                               "guest not launched")
    env = dict(os.environ, FFW_BUILD_DIR=str(build_dir), FFW_INITRAMFS=str(archive.resolve()))
    # Match the existing boot scripts' machine/CPU/console, with NICs explicitly disabled.
    # The guest's own loopback remains available; no emulated NIC can contact a real LAN.
    qemu = "qemu-system-mips" if is_mips else "qemu-system-ppc"
    command = [qemu, "-M", "malta" if is_mips else "g3beige", "-cpu", "24Kf" if is_mips else "G3",
               "-m", f"{guest_memory_mib}M", "-nographic", "-no-reboot", "-nic", "none", "-kernel", str(kernel_snapshot), "-initrd", str(archive),
               "-append", "console=" + ("ttyS0" if is_mips else "ttyPZ0") + ",38400 rdinit=/init panic=-1"]
    capture = boot.capture_guest(command, env, args.timeout, max_bytes=RUNTIME_CAPTURE_BYTES,
        capture_paths={"stdout": args.log_dir / "runtime.serial.log", "stderr": args.log_dir / "qemu.stderr.log"})
    inputs_after_capture = {}
    for name, path in (("kernel", kernel_snapshot), ("initramfs", archive)):
        try:
            inputs_after_capture[name] = runtime_file_identity(path)[1]["sha256"]
        except (OSError, MeasurementError):
            inputs_after_capture[name] = None
    # Keep failures and partial output too. Natural QEMU exit follows the supervisor's reboot;
    # a runtime END alone never triggers termination or earns success.
    return capture["stdout"].decode("utf-8", "replace"), {
        "command": command, "qemu": boot.cmd_version(["qemu-system-mips" if is_mips else "qemu-system-ppc", "--version"]),
        "kernel_sha256": kernel_sha256, "initramfs": image, "exit_code": capture["returncode"],
        "inputs_after_capture": inputs_after_capture,
        "stop_reason": capture["stop_reason"], "stderr_sha256": hashlib.sha256(capture["stderr"]).hexdigest(),
        "stdout_sha256": hashlib.sha256(capture["stdout"]).hexdigest(),
        "stderr_bytes": len(capture["stderr"]), "scope": "E07 supervisor child, not runtime as PID 1",
        "profile": profile, "guest_memory_mib": guest_memory_mib}


# ---- receipt path hygiene --------------------------------------------------------------------------------------------------------
# A runtime receipt is meant to be committed, so it must not carry the home directory, the scratch directory or a worker mount of
# whoever ran the guest. The writer rewrites every absolute host path in the receipt (never in the log files): a path under the
# repository becomes repo-relative, any other becomes `<outside-repo>/<basename>`, and each rewritten path is listed in
# `path_hashes` with the sha256 of the file it named (null when it cannot be read), so the new names stay bound to the bytes. The
# hashes the receipt already records (`kernel_sha256`, `initramfs.*_sha256`, ...) are untouched. The writer refuses to write a
# receipt in which an absolute path survives. This restates the rule of tests/t01/x02_judge.py (and the OUTSIDE_REPO marker of
# run-qemu-verification.py); it imports nothing from them. It changes no verdict.

RECEIPT_PATH_ROOTS = ("Users", "home", "private", "var", "tmp", "root", "Volumes", "mnt", "srv", "data", "bulk",
                      # more host roots than the X02 rule lists: a tree under any of these was written into a receipt as it was
                      "opt", "usr", "Library", "Applications", "System", "nix", "run", "media", "net", "export", "workspace", "work",
                      "builds")
ABSOLUTE_PATH = re.compile(rf"(?<![A-Za-z0-9_.~-])/(?:{'|'.join(RECEIPT_PATH_ROOTS)})(?=/|[\s\"'<>,;)=]|$)(?:/[^\s\"'<>,;)=]*)?")
# What the writer refuses after the rewrite, for the places the root list does not know: an absolute path of two or more components
# whose first component is not one the guest itself prints (`/proc/self/task`, `/dev/...`; a lone `/init` is one component), and a
# relative path that starts by leaving its directory (`../`). Neither can be bound to a file by the rewrite, so neither may be written.
GUEST_PATH_ROOTS = ("proc", "sys", "dev")
LEFTOVER_PATH = re.compile(rf"(?<![A-Za-z0-9_.~<>/-])/(?!(?:{'|'.join(GUEST_PATH_ROOTS)})/)[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+"
                           r"|(?<![A-Za-z0-9_.~<>/-])\.\./")
OUTSIDE_REPO = "<outside-repo>"
PATH_HASH_CAP = 512 * 1024 * 1024


def path_file_sha256(path: str) -> str | None:
    """sha256 of the regular file at `path`, or None when it is absent, not a regular file, too large or unreadable."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > PATH_HASH_CAP:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            while chunk := source.read(1 << 20):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def relocate_path(path: str, seen: list[dict[str, Any]]) -> str:
    """The receipt's name for the host path `path`: repo-relative under the repository, `<outside-repo>/<basename>` elsewhere."""
    clean = os.path.normpath(path)
    label = None
    for base in dict.fromkeys((REPO.as_posix(), REPO.resolve().as_posix())):
        if clean == base:
            label = "."
        elif clean.startswith(base + "/"):
            label = clean[len(base) + 1:]
    if label is None:
        label = f"{OUTSIDE_REPO}/{os.path.basename(clean) or 'root'}"
    entry = {"path": label, "sha256": path_file_sha256(path)}
    if entry not in seen:
        seen.append(entry)
    return label


def scrub_receipt_value(value: Any, seen: list[dict[str, Any]]) -> Any:
    """`value` with every absolute host path in any string, and in any key, rewritten; `seen` collects the path/sha256 pairs."""
    if isinstance(value, str):
        return ABSOLUTE_PATH.sub(lambda match: relocate_path(match.group(0), seen), value)
    if isinstance(value, list):
        return [scrub_receipt_value(item, seen) for item in value]
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = scrub_receipt_value(key, seen) if isinstance(key, str) else key
            new_item = scrub_receipt_value(item, seen)
            if new_key in out and out[new_key] != new_item:
                raise MeasurementError(f"two different entries would both be keyed {new_key!r} once host paths are rewritten; "
                                       "nothing was written")
            out[new_key] = new_item
        return out
    return value


def scrub_receipt(body: dict[str, Any]) -> dict[str, Any]:
    """A copy of the receipt body with host paths rewritten, plus `path_hashes`: each path it now names and the sha256 of its file.

    A new name that two different files would share is refused: `<outside-repo>/init` could not say which of them it binds."""
    seen: list[dict[str, Any]] = []
    clean = scrub_receipt_value(body, seen)
    named: dict[str, str | None] = {}
    for entry in seen:
        if entry["path"] in named and named[entry["path"]] != entry["sha256"]:
            raise MeasurementError(f"two different files would both be named {entry['path']} in the receipt; nothing was written")
        named[entry["path"]] = entry["sha256"]
    clean["path_hashes"] = seen
    return clean


def write_runtime_receipt(path: pathlib.Path, body: dict[str, Any]) -> None:
    """Write the runtime receipt exclusively, after the rewrite. Both `run-runtime` and `analyze-runtime` come through here. If an
    absolute host path, or a relative path that leaves the repository, would still be in it, nothing is written."""
    clean = scrub_receipt(body)
    dumped = json.dumps(clean)
    leftover = ABSOLUTE_PATH.search(dumped) or LEFTOVER_PATH.search(dumped)
    if leftover is not None:
        if leftover.group(0).startswith("/"):
            raise MeasurementError("refusing to write a receipt that still carries an absolute path under /"
                                   + leftover.group(0).split("/")[1] + "/; nothing was written")
        raise MeasurementError("refusing to write a receipt that still carries a relative path that leaves the repository; "
                               "nothing was written")
    with path.open("x", encoding="utf-8") as handle:
        json.dump(clean, handle, indent=2, sort_keys=True)
        handle.write("\n")


def runtime_main(args: argparse.Namespace) -> int:
    if args.command == "analyze-runtime" and args.log is None:
        print("BLOCKED: no runtime transcript supplied (atomic-cell evidence is not runtime evidence)")
        return 3
    if args.receipt is not None and os.path.lexists(args.receipt):
        raise MeasurementError("receipt already exists; no analysis or guest execution started")
    if args.arch != "x86_64" and args.supervisor is None:
        raise MeasurementError("BE runtime evidence requires the matching E07 speaker-smoke supervisor ELF")
    if args.arch == "x86_64" and args.supervisor is not None:
        raise MeasurementError("native analysis does not use the BE bootstrap supervisor")
    elf = runtime_elf(args.elf, args.arch) if args.elf else None
    supervisor = runtime_elf(args.supervisor, args.arch) if args.supervisor else None
    meta = None
    if args.command == "run-runtime":
        text, meta = run_runtime(args, elf, supervisor)
        transcript_sha256 = meta["stdout_sha256"]
    else:
        if not args.log.is_file():
            raise MeasurementError("a regular runtime transcript file is required")
        with args.log.open("rb") as source:
            raw = source.read(RUNTIME_CAPTURE_BYTES + 1)
        if len(raw) > RUNTIME_CAPTURE_BYTES:
            raise MeasurementError("runtime transcript exceeds the bounded capture size")
        text = raw.decode("utf-8", "replace")
        transcript_sha256 = hashlib.sha256(raw).hexdigest()
    profile = getattr(args, "profile", RUNTIME_THREADED)
    single_owner = profile == RUNTIME_SINGLE_OWNER
    child, extra = runtime_envelope(text, args.arch) if supervisor is not None else (text, [])
    report = judge_runtime(child, args.arch, elf, supervised=supervisor is not None, profile=profile)
    report["gates"].extend(extra)
    if meta is not None:
        capture_errors = []
        if meta["exit_code"] != 0 or meta["stop_reason"] is not None:
            capture_errors.append(f"exit={meta['exit_code']} stop_reason={meta['stop_reason']}")
        if meta["initramfs"]["init_sha256"] != supervisor["sha256"]:
            capture_errors.append("supervisor bytes changed before packaging")
        # Check the child's own initramfs membership independently of the transcript.
        packaged = meta["initramfs"]["extra_files"]
        if packaged.get("franken-speaker", {}).get("sha256") != elf["sha256"]:
            capture_errors.append("runtime bytes changed before packaging")
        # The profile marker is part of the packaged identity: present with exactly the selecting bytes for the single-owner and
        # the caller-driven run, each its own, and absent for the threaded run.
        marker = packaged.get(SINGLE_OWNER_MARKER_NAME)
        marker_bytes = RUNTIME_MARKER_BYTES.get(profile)
        if marker_bytes is not None and (marker is None or marker.get("sha256") != hashlib.sha256(marker_bytes).hexdigest()):
            capture_errors.append(f"the {profile} marker is missing from the initramfs or its bytes differ")
        if marker_bytes is None and marker is not None:
            capture_errors.append("an unexpected profile marker was packaged for a run that did not select a profile")
        for name, expected in (("kernel", meta["kernel_sha256"]), ("initramfs", meta["initramfs"]["archive_sha256"])):
            if meta["inputs_after_capture"][name] != expected:
                capture_errors.append(f"{name} capture input changed or became unreadable during execution")
        report["gates"].append(_gate("P05R-CAPTURE", "bounded complete capture and packaged ELF identity", capture_errors))
    report["ok"] = all(g.status == "passed" for g in report["gates"])
    # The single-owner run is never a plain pass: its one unsupported row is declared, so an accepted run is named for that.
    accepted = "accepted_with_declared_unsupported" if single_owner else "passed"
    outcome = accepted if report["ok"] else "blocked" if exit_code(report) == 3 else "not_passed"
    scope = RUNTIME_SCOPE + {RUNTIME_THREADED: "", RUNTIME_SINGLE_OWNER: " " + SINGLE_OWNER_SCOPE,
                             RUNTIME_CALLER_DRIVEN: " " + CALLER_DRIVEN_SCOPE}[profile]
    if args.receipt:
        body = {"schema": RUNTIME_SCHEMA, "result": outcome, "arch": args.arch,
                "evidence_kind": "captured_guest_execution" if meta is not None else "supplied_transcript_analysis",
                "revision_claim": args.revision, "elf": elf, "supervisor_elf": supervisor, "execution": meta,
                "transcript_sha256": transcript_sha256, "gates": [vars(g) for g in report["gates"]],
                "scope": scope}
        if profile != RUNTIME_THREADED:
            body["profile"] = profile
        if single_owner:
            body["declared_unsupported"] = report["declared_unsupported"]
        write_runtime_receipt(args.receipt, body)
    # Do not publish a green result if persisting its requested receipt failed.
    for gate in report["gates"]:
        print(f"{gate.status.upper()} {gate.gate_id}: {gate.title}" + (f" — {gate.detail}" if gate.detail else ""))
    if single_owner and report["ok"]:
        print("ACCEPTED WITH DECLARED UNSUPPORTED: " + ", ".join(report["declared_unsupported"]) + " (not a full pass)")
    else:
        print("PASSED" if report["ok"] else "BLOCKED" if outcome == "blocked" else "NOT PASSED")
    print(scope)
    return EXIT_ACCEPTED_WITH_DECLARED_UNSUPPORTED if single_owner and report["ok"] else exit_code(report)


# ---- command line ------------------------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run-runtime", "analyze-runtime"):
        p = sub.add_parser(name, help="real Asupersync runtime; distinct from the atomic-cell guest")
        p.add_argument("--arch", choices=tuple(RUNTIME_ARCHES) if name == "analyze-runtime" else ("mips", "powerpc"),
                       required=True)
        p.add_argument("--elf", type=pathlib.Path, required=(name == "run-runtime"))
        p.add_argument("--supervisor", type=pathlib.Path, required=(name == "run-runtime"),
                       help="matching ffw-hello-init built with speaker-smoke only; mounts proc and brings lo up")
        p.add_argument("--receipt", type=pathlib.Path)
        p.add_argument("--revision", help="operator-supplied source claim; not build attestation")
        p.add_argument("--profile", choices=RUNTIME_PROFILES, default=RUNTIME_THREADED,
                       help="which run the probe made: threaded (default); single-owner, which has one declared "
                            "unsupported row and is accepted, never passed (command-line exit 4); or caller-driven, whose "
                            "runtime is driven by the calling thread, shows no thread above the starting count and declares "
                            "nothing unsupported")
        if name == "run-runtime":
            p.add_argument("--log-dir", type=pathlib.Path, required=True)
            p.add_argument("--timeout", type=float, default=180.0)
            p.add_argument("--guest-memory-mib", type=int, choices=(32, 64), default=64,
                           help="QEMU guest memory in MiB (default: 64); a probe experiment, not a production RAM budget")
        else:
            p.add_argument("--log", type=pathlib.Path)
    p = sub.add_parser("prepare")
    p.add_argument("--work-dir", type=pathlib.Path, required=True)
    for name in ("run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--elf", type=pathlib.Path, required=(name == "run"))
        p.add_argument("--revision", help="the git revision the ELF was built from (recorded in the output)")
        p.add_argument("--receipt", type=pathlib.Path, help="write the judged result as a JSON receipt")
        if name == "run":
            p.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial logs")
            p.add_argument("--timeout", type=float, default=1800.0)
            p.add_argument("--seed", type=int, help="the run's seed (default: random)")
            p.add_argument("--plant", action="append", choices=sorted(PLANTS), default=[],
                           help="also present a planted negative and require it to be caught (repeatable)")
        else:
            p.add_argument("--log", type=pathlib.Path)
            p.add_argument("--seed", type=int)
    args = parser.parse_args(argv)
    try:
        if args.command in ("run-runtime", "analyze-runtime"):
            return runtime_main(args)
        if args.command == "prepare":
            print(prepare(args.work_dir))
            return 0
        if args.command == "analyze" and args.log is None:
            report = blocked_report()
            print(render(report, args.revision))
            if args.receipt:
                write_receipt(args.receipt, report, None, None, None, args.revision, None)
            return exit_code(report)
        elf = read_elf(args.elf) if args.elf else None
        meta, plants_ok, transcript = None, True, None
        if args.command == "run":
            if args.log_dir.exists() and any(args.log_dir.iterdir()):
                raise MeasurementError(f"{args.log_dir} is not empty; choose a fresh directory (nothing is deleted)")
            args.log_dir.mkdir(parents=True, exist_ok=True)
            seed = args.seed if args.seed is not None else secrets.randbits(62)
            with tempfile.TemporaryDirectory() as scratch:
                transcript, meta = run_guest(args.elf, pathlib.Path(scratch), "run", args.timeout,
                                             [("ffw_seed", S_IFREG_644, f"{seed}\n".encode())])
                (args.log_dir / "p05-target.serial.log").write_text(transcript)
                (args.log_dir / "seed.txt").write_text(f"{seed}\n")
                print(f"{meta['qemu']}; kernel {meta['kernel_sha256'][:8]}...; exit {meta['exit_code']}; "
                      f"{len(transcript.splitlines())} serial lines; seed {seed}")
                report = judge(transcript, elf, seed)
                if args.plant and not report["ok"]:
                    print("PLANTS NOT RUN: the unplanted transcript did not pass, so no catch can be credited")
                    plants_ok = False
                elif args.plant:
                    for name in args.plant:
                        if name == "replay":
                            other = secrets.randbits(62)
                            earlier, _ = run_guest(args.elf, pathlib.Path(scratch), "earlier", args.timeout,
                                                   [("ffw_seed", S_IFREG_644, f"{other}\n".encode())])
                            (args.log_dir / "plant-replay-earlier.serial.log").write_text(earlier)
                            planted = plant_replay(transcript, earlier)
                        else:
                            planted = {"host": plant_host, "truncate": plant_truncate, "order": plant_order}[name](transcript)
                        (args.log_dir / f"plant-{name}.serial.log").write_text(planted)
                        caught, why = plant_verdict(name, judge(planted, elf, seed))
                        print(f"PLANT {name}: {'CAUGHT' if caught else 'NOT CAUGHT'} ({why}); control: the unplanted run "
                              f"{'passes' if report['ok'] else 'FAILS'}")
                        plants_ok = plants_ok and caught
        else:
            transcript = args.log.read_text(errors="replace")
            seed = args.seed
            report = judge(transcript, elf, seed)
    except (MeasurementError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(report, getattr(args, "revision", None)))
    if args.receipt:
        write_receipt(args.receipt, report, elf, meta, seed, args.revision, transcript)
    code = exit_code(report)
    return code if plants_ok else 1


if __name__ == "__main__":
    sys.exit(main())
