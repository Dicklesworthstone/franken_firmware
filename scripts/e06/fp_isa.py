#!/usr/bin/env python3
"""E06 (bead ffw-unk): establish what floating-point ABI the toolchain targets, per big-endian target.  Offline.

A compiler target spec alone cannot answer this for every target.  MIPS says ``+soft-float`` in its ``features``;
PowerPC says nothing about floating point at all, which could mean "hard float by default" or "not recorded".  So this
also compiles a one-line float add and multiply to ASSEMBLY (``rustc --emit=asm``: no cargo, no link, no run) and reads
which instructions the compiler chose: a hardware FP instruction (``fadds``, ``add.s``) or a call into the soft-float
library (``__addsf3``).  Where zig is installed it also asks zig's own preprocessor which float-ABI macros each of its
musl target spellings defines, because the linker's libc must have the same float ABI as the Rust objects.

What this does NOT establish: that any board has an FPU.  A hard-float binary on a CPU without one fails at its first
FP instruction (or is rescued by kernel emulation that nothing here observed).  The board's CPU is a different
question, answered by an observation of the board, not by the compiler.

Usage: fp_isa.py [--json OUT] [--no-zig]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

SCHEMA = "ffw.e06.fp_isa.v1"
TARGETS = {"mips": "mips-unknown-linux-musl", "powerpc": "powerpc-unknown-linux-musl"}

# A `no_core` crate, so the probe needs neither std nor a built sysroot. The operators are the minimum a no_core crate
# needs for primitive arithmetic; the two functions are the whole probe.
PROBE_SOURCE = """\
#![feature(no_core, lang_items)]
#![allow(internal_features)]
#![no_core]
#![crate_type = "lib"]
#[lang = "pointee_sized"]
pub trait PointeeSized {}
#[lang = "meta_sized"]
pub trait MetaSized: PointeeSized {}
#[lang = "sized"]
pub trait Sized: MetaSized {}
#[lang = "copy"]
pub trait Copy {}
impl Copy for f32 {}
impl Copy for f64 {}
#[lang = "add"]
pub trait Add<Rhs = Self> {
    type Output;
    fn add(self, rhs: Rhs) -> Self::Output;
}
#[lang = "mul"]
pub trait Mul<Rhs = Self> {
    type Output;
    fn mul(self, rhs: Rhs) -> Self::Output;
}
impl Add for f32 { type Output = f32; fn add(self, rhs: f32) -> f32 { self + rhs } }
impl Mul for f64 { type Output = f64; fn mul(self, rhs: f64) -> f64 { self * rhs } }
#[no_mangle]
pub fn add_f32(a: f32, b: f32) -> f32 { a + b }
#[no_mangle]
pub fn mul_f64(a: f64, b: f64) -> f64 { a * b }
"""

# Mnemonics a hardware FP add/multiply uses, and the compiler-rt routines a soft-float build calls instead.
HARDWARE = {"powerpc": {"add_f32": ("fadds", "fadd"), "mul_f64": ("fmul", "fmuls")},
            "mips": {"add_f32": ("add.s",), "mul_f64": ("mul.d",)}}
SOFT_CALLS = {"add_f32": "__addsf3", "mul_f64": "__muldf3"}
# What zig's preprocessor defines when a target's float ABI is soft.
ZIG_SOFT_MACROS = ("_SOFT_FLOAT", "__NO_FPRS__", "_SOFT_DOUBLE", "__mips_soft_float", "__SOFT_FP__")
ZIG_SPELLINGS = {"mips": ["mips-linux-musl", "mips-linux-musleabi", "mips-linux-musleabihf"],
                 "powerpc": ["powerpc-linux-musl", "powerpc-linux-musleabi", "powerpc-linux-musleabihf"]}


def function_bodies(asm: str) -> Dict[str, List[str]]:
    """The instruction lines of each function label in an assembly listing (labels ``name:`` up to the next label
    that is another function; local ``.L`` labels and directives are skipped)."""
    bodies: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for raw in asm.splitlines():
        line = raw.strip()
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):$", line)
        if m:
            current = m.group(1)
            bodies[current] = []
            continue
        if current is None or not line or line.startswith((".", "#", "@")):
            continue
        bodies[current].append(line)
    return bodies


def classify_asm(asm: str, arch: str) -> Dict[str, Any]:
    """``hard`` when both probe functions use hardware FP instructions and call no soft-float routine, ``soft`` when
    both call the soft-float routine and use no hardware instruction, otherwise ``unknown`` (never guessed)."""
    bodies = function_bodies(asm)
    per: Dict[str, str] = {}
    evidence: Dict[str, str] = {}
    for fn, mnemonics in HARDWARE[arch].items():
        body = bodies.get(fn)
        if not body:
            per[fn] = "missing"
            continue
        used = [ln for ln in body if re.match(r"^(%s)\b" % "|".join(re.escape(m) for m in mnemonics), ln)]
        called = [ln for ln in body if SOFT_CALLS[fn] in ln]
        if used and not called:
            per[fn], evidence[fn] = "hard", used[0]
        elif called and not used:
            per[fn], evidence[fn] = "soft", called[0]
        else:
            per[fn] = "unknown"
    verdicts = set(per.values())
    overall = verdicts.pop() if len(verdicts) == 1 and verdicts <= {"hard", "soft"} else "unknown"
    return {"overall": overall, "functions": per, "evidence": evidence}


def classify_zig_macros(defined: List[str]) -> str:
    return "soft" if any(m in defined for m in ZIG_SOFT_MACROS) else "hard"


def _run(argv: List[str], timeout: float = 120.0, **kw: Any) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)


def spec_facts(triple: str, rustc: str = "rustc") -> Dict[str, Any]:
    proc = _run([rustc, "+nightly", "-Z", "unstable-options", "--print", "target-spec-json", "--target", triple])
    if proc.returncode != 0:
        return {"outcome": "unavailable", "detail": proc.stderr.strip().splitlines()[-1][:160] if proc.stderr.strip() else ""}
    spec = json.loads(proc.stdout)
    features = spec.get("features") or ""
    return {"outcome": "captured", "cpu": spec.get("cpu"), "features": spec.get("features"),
            "llvm_floatabi": spec.get("llvm-floatabi"), "llvm_abiname": spec.get("llvm-abiname"),
            "rustc_abi": spec.get("rustc-abi"),
            "says_soft_float": "+soft-float" in features.split(","),
            # Silent means no float entry at all: it cannot be read as "hard" or as "not recorded" from the spec.
            "says_anything_about_float": bool(spec.get("llvm-floatabi")) or bool(re.search(r"float|fpu|vfp|neon", features))}


def codegen_facts(arch: str, triple: str, rustc: str = "rustc") -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ffw-e06-fp-") as scratch:
        src, out = os.path.join(scratch, "fp_probe.rs"), os.path.join(scratch, "fp_probe.s")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(PROBE_SOURCE)
        proc = _run([rustc, "+nightly", "--target", triple, "--emit=asm", "-C", "opt-level=1", "-C", "panic=abort", src, "-o", out])
        if proc.returncode != 0 or not os.path.exists(out):
            tail = [ln for ln in proc.stderr.splitlines() if ln.startswith("error")][:1]
            return {"outcome": "failed", "detail": (tail[0] if tail else "rustc failed")[:160]}
        with open(out, encoding="utf-8") as fh:
            asm = fh.read()
    result = classify_asm(asm, arch)
    result["outcome"] = "compiled"
    return result


def zig_facts(arch: str, zig: str = "zig") -> Dict[str, Any]:
    if shutil.which(zig) is None:
        return {"outcome": "not-installed"}
    version = _run([zig, "version"]).stdout.strip()
    spellings = {}
    for name in ZIG_SPELLINGS[arch]:
        proc = _run([zig, "cc", "-target", name, "-dM", "-E", "-x", "c", os.devnull])
        if proc.returncode != 0:
            spellings[name] = {"outcome": "rejected"}
            continue
        defined = [ln.split()[1] for ln in proc.stdout.splitlines() if ln.startswith("#define ") and len(ln.split()) > 1]
        spellings[name] = {"outcome": "accepted", "float_abi": classify_zig_macros(defined),
                           "soft_macros": sorted(m for m in ZIG_SOFT_MACROS if m in defined)}
    return {"outcome": "captured", "version": version, "spellings": spellings}


def record(use_zig: bool = True, rustc: str = "rustc") -> Dict[str, Any]:
    version = _run([rustc, "+nightly", "-vV"]).stdout
    rec: Dict[str, Any] = {"schema": SCHEMA,
                           "rustc": next((ln.split(": ", 1)[1] for ln in version.splitlines() if ln.startswith("release:")), None),
                           "rustc_commit": next((ln.split(": ", 1)[1] for ln in version.splitlines() if ln.startswith("commit-hash:")), None),
                           "targets": {}}
    for arch, triple in TARGETS.items():
        entry: Dict[str, Any] = {"triple": triple, "spec": spec_facts(triple, rustc), "codegen": codegen_facts(arch, triple, rustc)}
        if use_zig:
            entry["zig"] = zig_facts(arch)
        rust_abi = entry["codegen"].get("overall")
        entry["rust_float_abi"] = rust_abi if entry["codegen"].get("outcome") == "compiled" else "unknown"
        # A spec that says +soft-float while the compiler emitted hardware FP (or the reverse) is a contradiction to
        # surface, not average away. A silent spec (PowerPC) cannot contradict anything.
        entry["spec_consistent"] = (not entry["spec"].get("says_soft_float")) or entry["rust_float_abi"] == "soft"
        if use_zig and entry["zig"].get("outcome") == "captured" and rust_abi in ("hard", "soft"):
            entry["zig_spellings_matching_rust"] = sorted(n for n, s in entry["zig"]["spellings"].items()
                                                          if s.get("float_abi") == rust_abi)
            entry["zig_spellings_mismatching_rust"] = sorted(n for n, s in entry["zig"]["spellings"].items()
                                                             if s.get("float_abi") not in (None, rust_abi))
        entry["board_fpu"] = "not established by this tool: the compiler's choice says nothing about a board's CPU"
        rec["targets"][arch] = entry
    return rec


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="E06 floating-point ABI probe (rustc spec + assembly, zig macros; no build)")
    ap.add_argument("--json", metavar="OUT", help="write the record here (a new file)")
    ap.add_argument("--no-zig", action="store_true")
    args = ap.parse_args(argv)
    if args.json and os.path.exists(args.json):
        print("fp_isa.py: %s already exists; records are never overwritten" % args.json, file=sys.stderr)
        return 2
    rec = record(use_zig=not args.no_zig)
    if args.json:
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(rec, fh, indent=1, sort_keys=True)
            fh.write("\n")
    for arch, t in rec["targets"].items():
        print("%-8s %-28s rust float ABI: %-7s spec: %s" % (
            arch, t["triple"], t["rust_float_abi"],
            "says +soft-float" if t["spec"].get("says_soft_float") else "silent on float"))
        for key in ("zig_spellings_matching_rust", "zig_spellings_mismatching_rust"):
            if key in t:
                print("         %-32s %s" % (key, ", ".join(t[key]) or "-"))
    print("board FPU is not established by this tool.")
    return 0 if all(t["rust_float_abi"] != "unknown" for t in rec["targets"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
